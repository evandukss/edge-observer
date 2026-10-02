package attach

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

// These cases run decoded events through the attachment's own delivery, the
// delivery gate, capture, the volatile intake and a real worker, to the lines
// it hands to output. Only the producer is modelled: events carry the
// published numbering (probe.Sequence) and no kernel is attached.

// overloadLines keeps every line the worker hands to output.
type overloadLines struct {
	mutex sync.Mutex
	lines []processing.Artifact
}

func (o *overloadLines) WriteApproved(_ context.Context, a processing.Approved) error {
	var line processing.Artifact
	if err := json.Unmarshal(a.Bytes(), &line); err != nil {
		return err
	}
	o.mutex.Lock()
	o.lines = append(o.lines, line)
	o.mutex.Unlock()
	return nil
}

// targets is the request target of every exchange line written.
func (o *overloadLines) targets() []string {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	var targets []string
	for _, line := range o.lines {
		if line.Route.Pipeline != config.ExchangesPipeline || line.Reconstruction == nil {
			continue
		}
		for _, exchange := range line.Reconstruction.Exchanges {
			if exchange.Request.Message != nil {
				targets = append(targets, exchange.Request.Message.Target)
			}
		}
	}
	return targets
}

type overloadOccupancy struct {
	id             uint64
	born           bool
	sent, received uint64
}

type overloadChain struct {
	t         *testing.T
	store     *intake.Store
	gate      *probe.DeliveryGate
	capture   *capture.Session
	attached  *ebpfAttachment
	worker    *processing.Worker
	out       *overloadLines
	outcome   processing.Outcome
	stamp     uint64
	unlocated uint64
	next      uint64
	open      map[uint64]*overloadOccupancy
}

// overloadNew composes the chain as activation does: one intake both capture
// sinks write to, and a gate sharing the intake's exhaustion signal.
// connectionInput is the worker's per-connection held-input bound, zero for its
// default.
func overloadNew(t *testing.T, events uint64, intakeBytes int64, connectionInput int) *overloadChain {
	t.Helper()
	compiled, findings := config.Compile([]byte(`{"version": "observer.config/1", "output": "/var/lib/observer", `+
		`"watch": [{"name": "api", "exe": "/usr/bin/php"}]}`), "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: the configuration was refused: %+v", findings)
	}
	store, err := intake.New(intakeBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: events, IntakeExhausted: store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	c := &overloadChain{t: t, store: store, gate: gate, capture: capture.Recording(store, store),
		out: &overloadLines{}, open: map[uint64]*overloadOccupancy{}}
	c.worker, err = processing.New(processing.Options{Plan: compiled.Plan, PolicyRevision: "overload", Session: "overload",
		Intake: store, Gate: gate, Output: c.out, ConnectionInput: connectionInput})
	if err != nil {
		t.Fatalf("wiring, not the property: the worker did not start: %v", err)
	}
	t.Cleanup(func() { _ = c.worker.Close() })
	c.attached = &ebpfAttachment{gate: gate, sink: c.capture, procfs: t.TempDir(), known: map[int32]identity{}}
	return c
}

func (c *overloadChain) begin(handle uint64, born bool) {
	c.next++
	c.open[handle] = &overloadOccupancy{id: c.next, born: born}
}

func (c *overloadChain) event(kind ebpf.Kind, handle uint64) ebpf.Event {
	c.stamp++
	return ebpf.Event{Kind: kind, Stamp: c.stamp, PID: 441, NamespacePID: 441, SSL: handle,
		Namespace: admission.Namespace{Device: 3, Inode: 4}, Generation: 1, At: time.Unix(100, int64(c.stamp))}
}

// send delivers one call on handle's occupancy, numbered skip past the next.
func (c *overloadChain) send(handle uint64, direction fragment.Direction, payload string, skip uint64) {
	o := c.open[handle]
	number := &o.sent
	if direction == fragment.Received {
		number = &o.received
	}
	*number += 1 + skip
	e := c.event(ebpf.Transfer, handle)
	e.Direction, e.Measured, e.Length, e.Payload = direction, true, uint32(len(payload)), []byte(payload)
	e.Sequence = probe.Sequence{Occupancy: o.id, Number: *number, Born: o.born, Unlocated: c.unlocated}
	c.attached.deliverEvent(e)
}

func (c *overloadChain) exchange(handle uint64, target string) {
	c.send(handle, fragment.Sent, "GET "+target+" HTTP/1.1\r\nHost: test\r\n\r\n", 0)
	c.send(handle, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", 0)
}

func (c *overloadChain) close(handle uint64) {
	o := c.open[handle]
	delete(c.open, handle)
	e := c.event(ebpf.Closed, handle)
	e.Sequence = probe.Sequence{Occupancy: o.id, Born: o.born, Unlocated: c.unlocated}
	e.Final = probe.Final{Known: true, Sent: probe.Terminal{Last: o.sent}, Received: probe.Terminal{Last: o.received}}
	c.attached.deliverEvent(e)
}

// drain lets the worker process everything the intake holds, as it would
// between deliveries. A worker that cannot is the session not going on, not
// wiring.
func (c *overloadChain) drain() {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	outcome, err := c.worker.Drain(ctx)
	c.outcome = outcome
	if err != nil {
		c.t.Errorf("the worker could not process what it held: %v, outcome %+v", err, outcome)
	}
}

func (c *overloadChain) refusals() int64 {
	c.attached.mutex.Lock()
	defer c.attached.mutex.Unlock()
	var n int64
	for _, count := range c.attached.gateRefused {
		n += count
	}
	return n
}

// goesOn requires the capture to be going on: no withdrawal requested, and the
// written lines to hold every target in written and none in withheld.
func (c *overloadChain) goesOn(written, withheld []string) {
	c.t.Helper()
	select {
	case <-c.gate.Withdrawal():
		c.t.Errorf("the gate requested withdrawal of the whole capture: %+v", c.gate.Snapshot())
	default:
	}
	targets := c.out.targets()
	for _, want := range written {
		if !slices.Contains(targets, want) {
			c.t.Errorf("%s was not written; written: %v", want, targets)
		}
	}
	for _, unwanted := range withheld {
		if slices.Contains(targets, unwanted) {
			c.t.Errorf("%s was written, after its connection's loss; written: %v", unwanted, targets)
		}
	}
}

// A burst over the held-event bound: one connection's calls take every slot
// and its next is refused. That connection's suffix is incomplete and counted;
// another connection open across the burst, and a fresh one begun after it,
// are written.
func TestIndependentABurstOverTheHeldEventBoundCostsOnlyItsConnection(t *testing.T) {
	c := overloadNew(t, 6, 1<<20, 0)
	c.begin(1, true)
	c.exchange(1, "/other")
	c.begin(2, true)
	c.exchange(2, "/burst-before")
	c.exchange(2, "/burst-fill")
	c.exchange(2, "/burst-refused")
	if c.refusals() == 0 {
		t.Fatalf("wiring, not the property: no event was refused, so the burst never passed the bound: %+v", c.gate.Snapshot())
	}
	c.drain()
	c.exchange(2, "/burst-after")
	c.close(1)
	c.drain()
	c.begin(3, true)
	c.exchange(3, "/fresh")
	c.close(3)
	c.drain()
	c.close(2)
	c.drain()

	if got := c.gate.Snapshot().InputRefused; got == 0 {
		t.Errorf("%d events were refused at the bound and the gate counts none", c.refusals())
	}
	if stats := c.capture.Stats(); stats.GateRefused == 0 || stats.Cut == 0 {
		t.Errorf("the refused connection's loss is not counted: gate_refused %d, cut %d", stats.GateRefused, stats.Cut)
	}
	c.goesOn([]string{"/other", "/fresh"}, []string{"/burst-refused", "/burst-after"})
}

// Intake exhaustion: one connection's call does not fit the volatile intake.
// That connection's suffix is incomplete and counted; another connection open
// across it, and a fresh one begun after it, are written.
func TestIndependentAFullIntakeCostsOnlyTheConnectionItRefused(t *testing.T) {
	c := overloadNew(t, 64, 4096, 0)
	c.begin(1, true)
	c.exchange(1, "/other")
	c.begin(2, true)
	c.exchange(2, "/intake-before")
	c.send(2, fragment.Sent, "GET /intake-refused HTTP/1.1\r\nX-Fill: "+strings.Repeat("x", 4000)+"\r\n\r\n", 0)
	if refused := c.store.Stats().FragmentsRefused; refused == 0 {
		t.Fatalf("wiring, not the property: the intake refused nothing, so it was never full: %+v", c.store.Stats())
	}
	c.send(2, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", 0)
	c.drain()
	c.exchange(2, "/intake-after")
	c.close(1)
	c.drain()
	c.begin(3, true)
	c.exchange(3, "/fresh")
	c.close(3)
	c.drain()
	c.close(2)
	c.drain()

	if stats := c.capture.Stats(); stats.IntakeRefused == 0 || stats.Cut == 0 {
		t.Errorf("the refused connection's loss is not counted: intake_refused %d, cut %d", stats.IntakeRefused, stats.Cut)
	}
	c.goesOn([]string{"/other", "/fresh"}, []string{"/intake-refused", "/intake-after"})
}

// A per-connection bound: one open connection holds more input than one
// connection may. Its input is cut and counted; another connection and a
// fresh one are written.
func TestIndependentAPerConnectionBoundCostsOnlyThatConnection(t *testing.T) {
	c := overloadNew(t, 64, 1<<20, 4)
	c.begin(1, true)
	c.exchange(1, "/other")
	c.begin(2, true)
	for _, target := range []string{"/bound-1", "/bound-2", "/bound-3"} {
		c.exchange(2, target)
	}
	c.drain()
	c.exchange(2, "/bound-after")
	c.close(1)
	c.begin(3, true)
	c.exchange(3, "/fresh")
	c.close(3)
	c.drain()
	if c.outcome.ConnectionsCut == 0 {
		t.Fatalf("wiring, not the property: no connection reached the bound of 4 entries: %+v", c.outcome)
	}
	c.close(2)
	c.drain()

	c.goesOn([]string{"/other", "/fresh"}, []string{"/bound-3", "/bound-after"})
}

// A located loss: a number of one connection's direction never arrives. That
// connection is written up to the hole and not past it; another connection and
// a fresh one are written.
func TestIndependentALocatedLossCostsOnlyItsConnectionsSuffix(t *testing.T) {
	c := overloadNew(t, 64, 1<<20, 0)
	c.begin(1, true)
	c.exchange(1, "/other")
	c.begin(2, true)
	c.exchange(2, "/located-before")
	c.send(2, fragment.Sent, "GET /located-after-the-hole HTTP/1.1\r\nHost: test\r\n\r\n", 1)
	c.send(2, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", 0)
	c.close(1)
	c.begin(3, true)
	c.exchange(3, "/fresh")
	c.close(3)
	c.close(2)
	c.drain()
	if lost := c.capture.Stats().Lost; lost != 1 {
		t.Fatalf("wiring, not the property: the hole reached capture as %d lost transfers, want 1", lost)
	}

	c.goesOn([]string{"/other", "/located-before", "/fresh"}, []string{"/located-after-the-hole"})
}

// An unattributable loss: the producer counts a loss it could place in no
// occupancy. A connection's exchange completed before it stays written; a
// connection born at an observed birth after it is written; one first
// observed at a call after it is not, since what it moved before that call may
// be the loss.
func TestIndependentAnUnlocatedLossLeavesAFreshConnectionEligible(t *testing.T) {
	c := overloadNew(t, 64, 1<<20, 0)
	c.begin(1, true)
	c.exchange(1, "/before-the-loss")
	c.unlocated = 1
	c.begin(2, true)
	c.exchange(2, "/fresh")
	c.begin(3, false)
	c.exchange(3, "/first-call")
	c.close(2)
	c.close(3)
	c.close(1)
	c.drain()
	if got := c.capture.Stats().Unlocated; got != 1 {
		t.Fatalf("wiring, not the property: capture took the unlocated count as %d, want 1", got)
	}

	c.goesOn([]string{"/before-the-loss", "/fresh"}, []string{"/first-call"})
}

// The control: an unknown length still ends the capture. Withdrawal is
// requested and nothing begun after it is written.
func TestIndependentAnUnknownLengthStillEndsTheCapture(t *testing.T) {
	c := overloadNew(t, 64, 1<<20, 0)
	c.begin(1, true)
	c.exchange(1, "/before")
	c.close(1)
	c.drain()
	if !slices.Contains(c.out.targets(), "/before") {
		t.Fatalf("wiring, not the property: the control exchange was not written: %v", c.out.targets())
	}
	e := c.event(ebpf.Transfer, 9)
	e.Direction, e.Length = fragment.Sent, 4
	c.attached.deliverEvent(e)
	c.begin(2, true)
	c.exchange(2, "/after")
	c.close(2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = c.worker.Drain(ctx)

	select {
	case <-c.gate.Withdrawal():
	default:
		t.Errorf("an unknown length did not request withdrawal: %+v", c.gate.Snapshot())
	}
	if reason := c.gate.Snapshot().Reason; string(reason) != "unknown_length" {
		t.Errorf("the gate gives %q, want unknown_length", reason)
	}
	if slices.Contains(c.out.targets(), "/after") {
		t.Errorf("an exchange begun after the unknown length was written: %v", c.out.targets())
	}
}
