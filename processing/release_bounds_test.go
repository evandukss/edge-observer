package processing_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/sink"
)

// Capture is modelled as sequential, complete transfers from a known birth.
// Each snapshot is made before any later input exists and checked against the
// public fragment contract. These cases measure the consumer, not capture.
type boundsFixture struct {
	t        *testing.T
	ctx      context.Context
	store    *intake.Store
	gate     *probe.DeliveryGate
	worker   *processing.Worker
	identity fragment.Identity
	evidence fragment.Evidence
	slots    []*boundsSlot
	charges  []int64
	taken    int
	turns    []processing.Turn
	output   *boundsOutput
}

type boundsOutput struct {
	lines  [][]byte
	refuse bool
}

type boundsSlot struct {
	held.Slot
	refunds  int
	returned bool
}

func (s *boundsSlot) Refund(path held.Path) bool {
	s.refunds++
	s.returned = s.Slot.Refund(path)
	return s.returned
}

func (o *boundsOutput) WriteApproved(_ context.Context, a processing.Approved) error {
	o.lines = append(o.lines, a.Bytes())
	if o.refuse {
		return sink.ErrQueueFull
	}
	return nil
}

func boundsPlan(t *testing.T, rules string) *config.ProcessingPlan {
	t.Helper()
	document := `{"version":"observer.config/1","output":"/var/lib/observer","watch":[{"name":"api","exe":"/usr/bin/php"}]`
	if rules != "" {
		document += "," + rules
	}
	c, findings := config.Compile([]byte(document+"}"), "")
	if c == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: plan refused: %+v", findings)
	}
	return c.Plan
}

func newBoundsFixture(t *testing.T, bound int, rules string, before func(), output processing.Output, configure ...func(*processing.Options)) *boundsFixture {
	t.Helper()
	f := &boundsFixture{t: t, output: &boundsOutput{}}
	var cancel context.CancelFunc
	f.ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	var err error
	f.store, err = intake.New(1 << 24)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	f.gate, err = probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1024, BeforeAuthorize: before})
	if err != nil {
		t.Fatal(err)
	}
	i := admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42, Start: admission.Determinate(7), Generation: 1}
	f.identity = fragment.Identity{Connection: 1, Process: fragment.Process{PID: 42, StartTime: 7}, Instance: i,
		Address: 7, Generation: 1, FirstSeen: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	f.evidence = fragment.Evidence{Identity: &f.identity, Occupancy: 1, Origin: fragment.OriginBirth}
	if output == nil {
		output = f.output
	}
	options := processing.Options{Plan: boundsPlan(t, rules), PolicyRevision: "bounds", Session: "bounds",
		Intake: f.store, Gate: f.gate, Output: output, ConnectionInput: bound,
		Taken: func(int, fragment.Process, fragment.ConnectionID) { f.taken++ }}
	for _, apply := range configure {
		apply(&options)
	}
	f.worker, err = processing.New(processing.ObserveTurns(options, func(turn processing.Turn) { f.turns = append(f.turns, turn) }))
	if err != nil {
		t.Fatalf("wiring, not the property: worker refused: %v", err)
	}
	t.Cleanup(func() { _ = f.worker.Close() })
	return f
}

func (f *boundsFixture) feed(direction fragment.Direction, text string) {
	f.t.Helper()
	d := f.gate.Admit(probe.DeliveryTransfer, true)
	if !d.Admitted || d.Slot == nil {
		f.t.Fatalf("wiring, not the property: input not admitted: %+v", d)
	}
	slot := &boundsSlot{Slot: d.Slot}
	one := &f.evidence.Sent
	if direction == fragment.Received {
		one = &f.evidence.Received
	}
	offset := one.Limit
	one.Limit += uint64(len(text))
	one.Numbered++
	one.Resolved++
	one.First = 1
	f.evidence.Through++
	r := fragment.Record{Process: f.identity.Process, Connection: f.identity.Connection, Direction: direction,
		Sequence: f.evidence.Through, Offset: offset, Length: uint32(len(text)), Produced: one.Numbered,
		Payload: []byte(text), At: f.identity.FirstSeen.Add(time.Duration(f.evidence.Through) * time.Millisecond),
		Evidence: f.evidence, Slot: slot}
	if err := r.Evidenced(); err != nil {
		f.t.Fatalf("wiring, not the property: invalid source evidence: %v", err)
	}
	before := f.store.Stats()
	if err := f.store.Write(r); err != nil {
		f.t.Fatalf("wiring, not the property: intake refused: %v", err)
	}
	after := f.store.Stats()
	if after.Queued != before.Queued+1 || after.Bytes <= before.Bytes || !d.Slot.Kept() {
		f.t.Fatal("wiring, not the property: source did not reach charged intake")
	}
	f.slots = append(f.slots, slot)
	f.charges = append(f.charges, after.Bytes-before.Bytes)
}

func (f *boundsFixture) retire(how connection.Ending) {
	f.t.Helper()
	r := connection.Record{ID: f.identity.Connection, Process: f.identity.Process, Instance: f.identity.Instance,
		Handle:    connection.Handle{Instance: f.identity.Instance.Key(), Address: 7, Generation: 1},
		FirstSeen: f.identity.FirstSeen, How: how, Ended: f.identity.FirstSeen.Add(time.Second),
		Fragments: connection.Counted(int64(f.evidence.Through))}
	for _, dir := range []fragment.Direction{fragment.Sent, fragment.Received} {
		if f.evidence.Of(dir).Limit > 0 {
			r.Placements = append(r.Placements, connection.Placement{Connection: 1, Direction: dir,
				Positions: connection.PositionsEstablished, Lost: connection.Counted(0)})
		}
	}
	if err := r.Validate(); err != nil {
		f.t.Fatalf("wiring, not the property: invalid retirement: %v", err)
	}
	if err := r.Agrees(f.evidence); err != nil {
		f.t.Fatalf("wiring, not the property: retirement contradicts source: %v", err)
	}
	if _, err := record.FromConnection(r); err != nil {
		f.t.Fatalf("wiring, not the property: unpublishable retirement: %v", err)
	}
	if err := f.store.Connection(r); err != nil {
		f.t.Fatalf("wiring, not the property: retirement not received: %v", err)
	}
}

func (f *boundsFixture) drain() processing.Outcome {
	f.t.Helper()
	queued := int(f.store.Stats().Queued)
	before := f.taken
	o, err := f.worker.Drain(f.ctx)
	if err != nil {
		f.t.Fatalf("drain: %v", err)
	}
	if f.taken-before != queued || len(f.turns) == 0 {
		f.t.Fatalf("wiring, not the property: worker took %d of %d queued entries, turns=%d", f.taken-before, queued, len(f.turns))
	}
	return o
}

func (f *boundsFixture) refunds(heldCount uint64, bytes int64) {
	f.t.Helper()
	s := f.gate.Snapshot()
	if s.Held != heldCount || s.DoubleRefunds != 0 || s.Charged != s.Held+s.Refunded.Unretained+s.Refunded.Processed+s.Refunded.Discarded+s.Refunded.Cut {
		f.t.Errorf("reservations: %+v; want held=%d, no duplicate refund, conserved", s, heldCount)
	}
	if st := f.store.Stats(); st.Bytes != bytes || st.Leased+st.Queued != int64(heldCount) {
		f.t.Errorf("intake retains %+v; want %d owned events costing %d bytes", st, heldCount, bytes)
	}
	// The partial-input fixtures own only their first event across a drain.
	for n, slot := range f.slots {
		want := 1
		if heldCount == 1 && n == 0 {
			want = 0
		}
		if slot.refunds != want || (want == 1 && !slot.returned) {
			f.t.Errorf("event %d refund calls=%d returned=%t, want %d successful refunds", n, slot.refunds, slot.returned, want)
		}
	}
}

func (f *boundsFixture) exchanges() []processing.Artifact {
	f.t.Helper()
	var out []processing.Artifact
	for _, line := range f.output.lines {
		var a processing.Artifact
		if err := json.Unmarshal(line, &a); err != nil {
			f.t.Fatal(err)
		}
		if a.Record == processing.ArtifactExchange {
			out = append(out, a)
		}
	}
	return out
}

func (f *boundsFixture) pairs(paths ...string) {
	f.t.Helper()
	a := f.exchanges()
	if len(a) != len(paths) {
		f.t.Fatalf("released %d exchanges, want %d before retirement", len(a), len(paths))
	}
	for n, path := range paths {
		if a[n].ReconstructionUnplaced != nil {
			f.t.Errorf("exchange %d carries the connection's final unplaced total: %+v", n, a[n].ReconstructionUnplaced)
		}
		if a[n].Reconstruction == nil || len(a[n].Reconstruction.Exchanges) != 1 {
			f.t.Fatalf("exchange %d has no single pair", n)
		}
		e := a[n].Reconstruction.Exchanges[0]
		if e.Request.Message == nil || e.Response.Message == nil || e.Request.Message.Target != path || !e.Complete ||
			a[n].Index == nil || *a[n].Index != n || a[n].ExchangeID != strconv.Itoa(n+1) {
			f.t.Errorf("pair %d: %+v, id=%s index=%v; want %s and id %d", n, e, a[n].ExchangeID, a[n].Index, path, n+1)
		}
	}
}

const boundsResponse = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"

func boundsRequest(path string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: example.test\r\n\r\n"
}

func TestReleaseBoundsRetiredFixtureControl(t *testing.T) {
	f := newBoundsFixture(t, 16, "", nil, nil)
	f.feed(fragment.Sent, boundsRequest("/control-one"))
	f.feed(fragment.Received, boundsResponse)
	f.feed(fragment.Sent, boundsRequest("/control-two"))
	f.feed(fragment.Received, boundsResponse)
	f.retire(connection.HandleReleasedEnding)
	f.drain()
	f.pairs("/control-one", "/control-two")
	f.refunds(0, 0)
}

func TestReleaseBoundsHalfMessageKeepsItsReservationAcrossDrains(t *testing.T) {
	for _, ending := range []string{"complete", "discard", "cut"} {
		t.Run(ending, func(t *testing.T) {
			f := newBoundsFixture(t, 4, "", nil, nil)
			f.feed(fragment.Sent, "GET /half HTTP/1.1\r\nHo")
			charge := f.charges[0]
			for range 4 {
				f.drain()
				f.refunds(1, charge)
			}
			if len(f.output.lines) != 0 {
				t.Fatal("unfinished message released")
			}
			switch ending {
			case "complete":
				f.feed(fragment.Sent, "st: example.test\r\n\r\n")
				f.feed(fragment.Received, boundsResponse)
				f.drain()
				f.pairs("/half")
			case "discard":
				if err := f.worker.Close(); err != nil {
					t.Fatal(err)
				}
			case "cut":
				f.feed(fragment.Sent, "st: example.test\r\n\r\n"+boundsRequest("/two")+boundsRequest("/three")+boundsRequest("/four"))
				if o := f.drain(); o.ConnectionsCut != 1 {
					t.Errorf("four pending requests did not cut at the ceiling: %+v", o)
				}
				if got := f.gate.Snapshot().Refunded.Cut; got != uint64(len(f.slots)) {
					t.Errorf("cut returned %d events along Cut, want all %d source events", got, len(f.slots))
				}
			}
			f.refunds(0, 0)
			if err := f.worker.Close(); err != nil {
				t.Fatal(err)
			}
			f.refunds(0, 0)
		})
	}
}

func TestReleaseBoundsSharedFragmentRefundsOnlyAfterItsLastExchange(t *testing.T) {
	f := newBoundsFixture(t, 8, "", nil, nil)
	f.feed(fragment.Sent, boundsRequest("/one")+"GET /two HTTP/1.1\r\nHo")
	shared := f.charges[0]
	f.feed(fragment.Received, boundsResponse)
	f.drain()
	f.pairs("/one")
	f.refunds(1, shared)
	for range 3 {
		f.drain()
		f.refunds(1, shared)
	}
	f.feed(fragment.Sent, "st: example.test\r\n\r\n")
	f.feed(fragment.Received, boundsResponse)
	f.drain()
	f.pairs("/one", "/two")
	f.refunds(0, 0)
	f.retire(connection.HandleReleasedEnding)
	f.drain()
	f.pairs("/one", "/two")
	f.refunds(0, 0)
}

func TestReleaseBoundsDescriptorsDoNotCountConsumedFragments(t *testing.T) {
	f := newBoundsFixture(t, 4, "", nil, nil)
	request := boundsRequest("/fragmented")
	for _, b := range []byte(request) {
		f.feed(fragment.Sent, string(b))
		o := f.drain()
		if o.ConnectionsCut != 0 {
			t.Fatalf("one pending message cut after %d source fragments: %+v", len(f.slots), o)
		}
		connections := processing.Connections(f.worker)
		if len(connections) != 1 || connections[0].Pending >= 4 {
			t.Fatalf("one fragmented message exceeded its descriptor bound: %+v", connections)
		}
	}
	f.feed(fragment.Received, boundsResponse)
	f.drain()
	f.pairs("/fragmented")
	f.refunds(0, 0)
}

func TestReleaseBoundsCutKeepsReleasedOffsetsIndexesAndCounts(t *testing.T) {
	f := newBoundsFixture(t, 4, "", nil, nil)
	for _, path := range []string{"/first", "/second"} {
		f.feed(fragment.Sent, boundsRequest(path))
		f.feed(fragment.Received, boundsResponse)
		f.drain()
	}
	f.pairs("/first", "/second")
	boundaries := map[string]uint64{"sent": f.evidence.Sent.Limit, "received": f.evidence.Received.Limit}
	prior := append([]byte(nil), bytes.Join(f.output.lines, nil)...)
	for n := 0; n < 4; n++ {
		f.feed(fragment.Sent, boundsRequest(fmt.Sprintf("/pending-%d", n)))
		o := f.drain()
		for _, c := range processing.Connections(f.worker) {
			if c.Pending >= 4 {
				t.Errorf("pending=%d reaches ceiling after turn", c.Pending)
			}
		}
		if n < 3 && o.ConnectionsCut != 0 {
			t.Fatalf("cut before descriptor ceiling: %+v", o)
		}
		if n == 3 && o.ConnectionsCut != 1 {
			t.Fatalf("did not cut on reaching descriptor ceiling: %+v", o)
		}
	}
	f.retire(connection.HandleReleasedEnding)
	f.drain()
	f.pairs("/first", "/second")
	if !bytes.Equal(prior, bytes.Join(f.output.lines[:2], nil)) {
		t.Error("cut changed released lines")
	}
	var finals []processing.Artifact
	for _, line := range f.output.lines {
		var a processing.Artifact
		if err := json.Unmarshal(line, &a); err != nil {
			t.Fatal(err)
		}
		if a.Record == processing.ArtifactConnection {
			finals = append(finals, a)
		}
	}
	if len(finals) != 1 {
		t.Fatalf("cut wrote %d retirement lines, want one", len(finals))
	}
	a := finals[0]
	wantUnplaced := record.Count{State: record.Undetermined, Unit: record.Bytes, Why: processing.TruncationConnectionCut}
	if a.ReconstructionUnplaced == nil || *a.ReconstructionUnplaced != wantUnplaced {
		t.Errorf("cut retirement unplaced total = %+v, want %+v", a.ReconstructionUnplaced, wantUnplaced)
	}
	if a.Connection.Fragments.Value != strconv.FormatUint(f.evidence.Through, 10) {
		t.Errorf("retirement lost earlier fragment count: %+v", a.Connection.Fragments)
	}
	if a.ReconstructionTruncation == nil || len(a.ReconstructionTruncation.Stops) != 2 {
		t.Fatalf("cut has no two-direction suffix: %+v", a.ReconstructionTruncation)
	}
	for _, stop := range a.ReconstructionTruncation.Stops {
		want, ok := boundaries[stop.Direction]
		if !ok {
			t.Fatalf("unexpected stop direction %q", stop.Direction)
		}
		end := f.evidence.Sent.Limit
		if stop.Direction == "received" {
			end = f.evidence.Received.Limit
		}
		if stop.Offset != strconv.FormatUint(want, 10) || stop.EvidenceOffset != strconv.FormatUint(end, 10) || stop.Reason != processing.TruncationConnectionCut {
			t.Errorf("stop=%+v, want first unreleased %d, input reach %d, connection cut", stop, want, end)
		}
		delete(boundaries, stop.Direction)
	}
	if len(boundaries) != 0 {
		t.Errorf("missing stop directions: %v", boundaries)
	}
	f.refunds(0, 0)
}

func TestReleaseBoundsNormalStopSettlesBeforeItsAuthorizationCutoff(t *testing.T) {
	f := newBoundsFixture(t, 16, "", nil, nil)
	f.feed(fragment.Sent, boundsRequest("/early"))
	f.feed(fragment.Received, boundsResponse)
	f.drain()
	f.pairs("/early")
	f.feed(fragment.Sent, boundsRequest("/at-stop")+"GET /unfinished HTTP/1.1\r\n")
	f.drain()
	f.feed(fragment.Received, boundsResponse)
	f.retire(connection.StillOpen)
	before := f.taken
	queued := int(f.store.Stats().Queued)
	_, err := f.worker.Finish(f.ctx, processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil {
		t.Fatal(err)
	}
	if f.taken-before != queued {
		t.Fatal("wiring, not the property: stop did not consume final capture entries")
	}
	f.pairs("/early", "/at-stop")
	retirements := 0
	for _, line := range f.output.lines {
		var a processing.Artifact
		if err := json.Unmarshal(line, &a); err != nil {
			t.Fatal(err)
		}
		if a.Record == processing.ArtifactConnection {
			retirements++
		}
	}
	if retirements != 1 {
		t.Errorf("normal stop settled %d connection lines, want one", retirements)
	}
	f.refunds(0, 0)
	lines := len(f.output.lines)
	if _, err = f.worker.Drain(f.ctx); !errors.Is(err, processing.ErrFinished) {
		t.Errorf("post-settlement drain=%v", err)
	}
	if len(f.output.lines) != lines {
		t.Error("processing authorized after final settlement")
	}
	f.refunds(0, 0)
}

func TestReleaseBoundsUnsettledStopReleasesOnlyItsCertifiedPrefix(t *testing.T) {
	for _, final := range []processing.Finalization{{}, {Withdrawn: true}, {Drained: true}} {
		t.Run(fmt.Sprintf("withdrawn_%t_drained_%t", final.Withdrawn, final.Drained), func(t *testing.T) {
			f := newBoundsFixture(t, 16, "", nil, nil)
			f.feed(fragment.Sent, boundsRequest("/certified")+"GET /unfinished HTTP/1.1\r\n")
			f.feed(fragment.Received, boundsResponse)
			f.retire(connection.StillOpen)
			if f.store.Stats().Queued != 3 || f.taken != 0 || len(f.output.lines) != 0 {
				t.Fatal("wiring, not the property: the certified pair and unfinished suffix were not queued at stop")
			}
			out, err := f.worker.Finish(f.ctx, final)
			if err != nil {
				t.Fatal(err)
			}
			if f.taken != 3 {
				t.Fatal("wiring, not the property: Finish did not read the final queue")
			}
			f.pairs("/certified")
			for _, line := range f.output.lines {
				var a processing.Artifact
				if err := json.Unmarshal(line, &a); err != nil {
					t.Fatal(err)
				}
				if a.Record == processing.ArtifactConnection {
					t.Error("stop without both finalization facts published settled connection metadata")
				}
			}
			if out.Withheld.Known || out.Withheld.Why != "unsettled_input" || out.Pending != 0 {
				t.Errorf("unfinished suffix was not discarded as unsettled: %+v", out)
			}
			f.refunds(0, 0)
		})
	}
}

func TestReleaseBoundsInvalidationBeforePrefixEnqueueForbidsAuthorization(t *testing.T) {
	var f *boundsFixture
	entered := 0
	f = newBoundsFixture(t, 16, "", func() {
		entered++
		if entered == 1 {
			d := f.gate.Admit(probe.DeliveryTransfer, false)
			if d.Slot != nil {
				d.Slot.Refund(held.Unretained)
			}
		}
	}, nil)
	f.feed(fragment.Sent, boundsRequest("/never-enqueued"))
	f.feed(fragment.Received, boundsResponse)
	f.drain()
	if entered == 0 {
		t.Fatal("wiring, not the property: prefix did not reach BeforeAuthorize on the open connection")
	}
	if f.gate.Snapshot().Reason != probe.GateUnknownLength {
		t.Fatal("wiring, not the property: terminal invalidation absent")
	}
	if len(f.output.lines) != 0 {
		t.Fatal("prefix authorized after terminal invalidation")
	}
	f.refunds(0, 0)
}

func TestReleaseBoundsCancellationDiscardsPendingInput(t *testing.T) {
	f := newBoundsFixture(t, 16, "", nil, nil)
	f.feed(fragment.Sent, boundsRequest("/before-cancel"))
	f.feed(fragment.Received, boundsResponse)
	f.drain()
	f.pairs("/before-cancel")
	f.feed(fragment.Sent, "GET /cancelled HTTP/1.1\r\n")
	f.drain()
	if f.taken != 3 || f.store.Stats().Leased != 1 {
		t.Fatal("wiring, not the property: cancellation did not find one owned half-message")
	}
	f.feed(fragment.Sent, "Host: example.test\r\n\r\n")
	f.feed(fragment.Received, boundsResponse)
	f.retire(connection.StillOpen)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.worker.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	f.pairs("/before-cancel")
	f.refunds(0, 0)
	before := len(f.output.lines)
	if _, err := f.worker.Drain(context.Background()); !errors.Is(err, processing.ErrFinished) {
		t.Errorf("processing resumed after cancellation: %v", err)
	}
	if len(f.output.lines) != before {
		t.Error("new authorization after cancellation")
	}
}

func TestReleaseBoundsProcessingFailureNeverFallsBackToRaw(t *testing.T) {
	parsed := 0
	f := newBoundsFixture(t, 16, `"remove":{"headers":["X-Secret"],"bodies":["request","response"]}`, nil, nil,
		func(options *processing.Options) {
			options.BeforeParse = func(context.Context) error { parsed++; return errors.New("injected processing failure") }
		})
	f.feed(fragment.Sent, "POST /failure HTTP/1.1\r\nX-Secret: SECRET-HEADER\r\nContent-Length: 11\r\n\r\nSECRET-BODY")
	f.feed(fragment.Received, boundsResponse)
	o, err := f.worker.Drain(f.ctx)
	if parsed == 0 || f.taken != 2 {
		t.Fatal("wiring, not the property: captured prefix never reached the failing processing boundary")
	}
	if err == nil && o.ProcessingFailures == 0 {
		t.Errorf("processing failure neither returned nor counted: %+v", o)
	}
	for _, line := range f.output.lines {
		var a processing.Artifact
		if decode := json.Unmarshal(line, &a); decode != nil {
			t.Errorf("unframed raw fallback: %q", line)
			continue
		}
		if a.Record == processing.ArtifactExchange || bytes.Contains(line, []byte("SECRET-")) {
			t.Errorf("failed processing released content: %s", line)
		}
	}
	if err := f.worker.Close(); err != nil {
		t.Fatal(err)
	}
	f.refunds(0, 0)
}

type boundsHeldSink struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	lines   [][]byte
}

func (s *boundsHeldSink) Write(_ context.Context, p []byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	s.lines = append(s.lines, append([]byte(nil), p...))
	return len(p), nil
}
func (*boundsHeldSink) Reopen(context.Context) error { return nil }
func (*boundsHeldSink) Close(context.Context) error  { return nil }

func TestReleaseBoundsEnqueuedPrefixWritesAfterInvalidation(t *testing.T) {
	s := &boundsHeldSink{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(s.release) }) }
	defer unblock()
	w, err := processing.OpenWriter(processing.WriterOptions{Directory: t.TempDir(), QueueBytes: 1 << 20, OpenSink: func(string) sink.Sink { return s }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unblock(); _ = w.Close() })
	f := newBoundsFixture(t, 16, "", nil, w)
	f.feed(fragment.Sent, boundsRequest("/already-enqueued"))
	f.feed(fragment.Received, boundsResponse)
	f.drain()
	select {
	case <-s.entered:
	case <-f.ctx.Done():
		t.Fatal("wiring, not the property: open-connection prefix never reached held sink write")
	}
	if stats := w.DeliveryStats(); stats.Pending != 1 || stats.Written != 0 {
		t.Fatalf("wiring, not the property: held write not established: %+v", stats)
	}
	d := f.gate.Admit(probe.DeliveryTransfer, false)
	if d.Slot != nil {
		d.Slot.Refund(held.Unretained)
	}
	if f.gate.Snapshot().Reason != probe.GateUnknownLength {
		t.Fatal("wiring, not the property: invalidation absent")
	}
	unblock()
	if err := w.Drain(f.ctx); err != nil {
		t.Fatal(err)
	}
	if stats := w.DeliveryStats(); stats.Written != 1 || stats.Pending != 0 || stats.Failed != 0 || stats.Dropped != 0 {
		t.Errorf("authorized prefix revoked: %+v", stats)
	}
	if len(s.lines) != 1 || !bytes.Contains(s.lines[0], []byte("/already-enqueued")) {
		t.Errorf("wrong prefix written: %q", s.lines)
	}
	f.refunds(0, 0)
}

func TestReleaseBoundsFragmentedRemovalAcrossConsecutiveReleases(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("refuse_%t", refuse), func(t *testing.T) {
			f := newBoundsFixture(t, 16, `"remove":{"headers":["X-Secret"],"bodies":["request","response"]}`, nil, nil)
			f.output.refuse = refuse
			for n := 0; n < 3; n++ {
				path := fmt.Sprintf("/removed-%d", n)
				request := "POST " + path + " HTTP/1.1\r\nX-Keep: KEEP-PUBLIC\r\nX-Secret: SECRET-HEADER\r\nTransfer-Encoding: chunked\r\n\r\nf\r\nSECRET-REQ-BODY\r\n0\r\nX-Secret: SECRET-TRAILER\r\n\r\n"
				response := "HTTP/1.1 200 OK\r\nX-Secret: SECRET-RESPONSE\r\nContent-Length: 17\r\n\r\nSECRET-RESP-BODY!"
				for _, part := range []struct {
					dir  fragment.Direction
					wire string
				}{{fragment.Sent, request}, {fragment.Received, response}} {
					for off := 0; off < len(part.wire); off += 3 {
						f.feed(part.dir, part.wire[off:min(off+3, len(part.wire))])
						f.drain()
					}
				}
				if len(f.output.lines) != n+1 {
					t.Fatalf("wiring, not the property: fragmented pair %d reached %d enqueue attempts", n, len(f.output.lines))
				}
			}
			f.pairs("/removed-0", "/removed-1", "/removed-2")
			for _, line := range f.output.lines {
				if bytes.Contains(line, []byte("SECRET-")) {
					t.Errorf("removal sentinel in encoded output: %s", line)
				}
			}
			for _, a := range f.exchanges() {
				var rendered bytes.Buffer
				if err := processing.RenderArtifact(&rendered, a); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(rendered.String(), "KEEP-PUBLIC") {
					t.Fatal("wiring, not the property: permitted header did not reach projection")
				}
				if strings.Contains(rendered.String(), "SECRET-") {
					t.Errorf("removal sentinel in approved projection: %s", rendered.String())
				}
			}
			if refuse && f.drain().OutputFailures != 3 {
				t.Error("output refusals were not counted once per exchange")
			}
			f.refunds(0, 0)
		})
	}
}
