package processing_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/sink"
)

// call is one library call's bytes in one direction.
type call struct {
	direction fragment.Direction
	text      string
}

func wrote(text string) call { return call{fragment.Sent, text} }
func read(text string) call  { return call{fragment.Received, text} }

// conversation is one connection as capture records it: its fragments in
// order, each carrying the evidence capture establishes at it, and the
// retirement that ends it.
type conversation struct {
	fragments  []fragment.Record
	retirement connection.Record
}

// converse records the calls as one connection with id, from the observed
// process's side: a client writes requests. A fragment capture gave no
// evidence is given what capture establishes at it: every byte and number of
// each direction so far, uncut.
func converse(t *testing.T, id fragment.ConnectionID, calls ...call) conversation {
	t.Helper()
	var b capturedBatch
	s := capture.Recording(&b, &b)
	at := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	i := admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42, Start: admission.Determinate(7), Generation: 1}
	p := fragment.Process{PID: 42, StartTime: 7}
	var numbers [3]uint64
	for n, one := range calls {
		numbers[one.direction]++
		s.Transfer(probe.Transfer{Process: p, Instance: i, Endpoint: 7, Direction: one.direction, Measured: true,
			Length: uint32(len(one.text)), Payload: []byte(one.text), Stamp: uint64(n + 1),
			Sequence: probe.Sequence{Occupancy: 1, Number: numbers[one.direction], Born: true}, At: at})
	}
	s.Closed(probe.Connection{Process: p, Instance: i, Endpoint: 7, Stamp: uint64(len(calls) + 1),
		Sequence: probe.Sequence{Occupancy: 1, Born: true},
		Final: probe.Final{Known: true, Sent: probe.Terminal{Last: numbers[fragment.Sent]},
			Received: probe.Terminal{Last: numbers[fragment.Received]}}, At: at})
	if len(b.fragments) != len(calls) || len(b.records) != 1 {
		t.Fatalf("wiring, not the property: capture recorded %d fragments and %d retirements for %d calls",
			len(b.fragments), len(b.records), len(calls))
	}
	r := b.records[0]
	r.ID = id
	for n := range r.Associations {
		r.Associations[n].Connection = id
	}
	for n := range r.Placements {
		r.Placements[n].Connection = id
	}
	identity := &fragment.Identity{Connection: id, Process: r.Process, Instance: r.Instance, Address: r.Handle.Address,
		Generation: uint64(r.Handle.Generation), NetworkDevice: r.Network.Device, NetworkInode: r.Network.Inode,
		FirstSeen: r.FirstSeen}
	if r.OpenedKnown {
		identity.Opened = r.Opened
	}
	var limit, numbered [3]uint64
	var relabelled *fragment.Identity
	for n := range b.fragments {
		f := &b.fragments[n]
		f.Connection = id
		limit[f.Direction], numbered[f.Direction] = f.End(), f.Produced
		if f.Evidence.Taken() {
			if relabelled == nil {
				one := *f.Evidence.Identity
				one.Connection = id
				relabelled = &one
			}
			f.Evidence.Identity = relabelled
		} else {
			direction := func(d fragment.Direction) fragment.DirectionEvidence {
				if numbered[d] == 0 {
					return fragment.DirectionEvidence{}
				}
				return fragment.DirectionEvidence{Limit: limit[d], First: 1, Numbered: numbered[d], Resolved: numbered[d]}
			}
			f.Evidence = fragment.Evidence{Identity: identity, Occupancy: 1, Origin: fragment.OriginBirth,
				Through: f.Sequence, Sent: direction(fragment.Sent), Received: direction(fragment.Received)}
		}
		if err := f.Evidenced(); err != nil {
			t.Fatalf("wiring, not the property: fragment %d does not carry evidence taken at it: %v", f.Sequence, err)
		}
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := r.Agrees(b.fragments[len(b.fragments)-1].Evidence); err != nil {
		t.Fatalf("wiring, not the property: the retirement contradicts the evidence: %v", err)
	}
	return conversation{fragments: b.fragments, retirement: r}
}

// pair is one request and its response, each in one call.
func pair(target string) []call {
	return []call{wrote("GET " + target + " HTTP/1.1\r\nHost: a\r\n\r\n"),
		read("HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(target)) + "\r\n\r\n" + target)}
}

func pairs(targets ...string) []call {
	var out []call
	for _, target := range targets {
		out = append(out, pair(target)...)
	}
	return out
}

// releasing is one worker with what it was given and what it wrote.
type releasing struct {
	t        *testing.T
	worker   *processing.Worker
	store    *intake.Store
	gate     *probe.DeliveryGate
	out      *outputLog
	approved []processing.Approved
	turns    []processing.Turn
	outcome  processing.Outcome
}

type releasingOptions struct {
	connectionInput int
	output          processing.Output
	beforeAuthorize func()
	maxEvents       uint64
}

func newReleasing(t *testing.T, o releasingOptions) *releasing {
	t.Helper()
	store, err := intake.New(16 << 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if o.maxEvents == 0 {
		o.maxEvents = 4096
	}
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: o.maxEvents, IntakeExhausted: store.Exhausted(),
		BeforeAuthorize: o.beforeAuthorize})
	if err != nil {
		t.Fatal(err)
	}
	r := &releasing{t: t, store: store, gate: gate, out: &outputLog{}}
	output := o.output
	if output == nil {
		output = outputFunc(func(ctx context.Context, a processing.Approved) error {
			r.approved = append(r.approved, a)
			return r.out.WriteApproved(ctx, a)
		})
	}
	options := processing.ObserveTurns(processing.Options{Session: "release", Plan: rulesPlan(t, ""),
		PolicyRevision: "release-policy", Intake: store, Gate: gate, Output: output, ConnectionInput: o.connectionInput},
		func(one processing.Turn) { r.turns = append(r.turns, one) })
	r.worker, err = processing.New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.worker.Close() })
	return r
}

func (r *releasing) give(fragments ...fragment.Record) {
	r.t.Helper()
	for _, f := range fragments {
		if err := r.store.Write(f); err != nil {
			r.t.Fatal(err)
		}
	}
}

func (r *releasing) retire(c connection.Record) {
	r.t.Helper()
	if err := r.store.Connection(c); err != nil {
		r.t.Fatal(err)
	}
}

func (r *releasing) drain() processing.Outcome {
	r.t.Helper()
	o, err := r.worker.Drain(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	r.outcome = o
	return o
}

// lines is the written lines of one record kind for connection id, in the
// order written.
func (r *releasing) lines(kind string, id fragment.ConnectionID) []processing.Artifact {
	var out []processing.Artifact
	for _, a := range r.out.artifacts {
		if a.Record == kind && a.Connection.ID == strconv.FormatUint(uint64(id), 10) {
			out = append(out, a)
		}
	}
	return out
}

func target(t *testing.T, a processing.Artifact) string {
	t.Helper()
	if a.Reconstruction == nil || len(a.Reconstruction.Exchanges) != 1 || a.Reconstruction.Exchanges[0].Request.Message == nil {
		t.Fatalf("an exchange line without one request: %+v", a)
	}
	return a.Reconstruction.Exchanges[0].Request.Message.Target
}

// readBack is every line written, read through the shipped reader as one
// file.
func (r *releasing) readBack() ([]processing.Artifact, error) {
	var file []byte
	for _, line := range r.out.lines {
		file = append(file, line...)
	}
	var visited []processing.Artifact
	err := processing.ReadArtifacts(fstest.MapFS{processing.ArtifactName: {Data: file}}, func(a processing.Artifact) error {
		visited = append(visited, a)
		return nil
	})
	return visited, err
}

// A keep-alive connection's pairs are each written while it is open, the last
// one while it idles, and its connection line, written once at retirement,
// repeats none of them.
func TestEveryPairOfAnOpenConnectionIsWrittenWhileItIsOpen(t *testing.T) {
	r := newReleasing(t, releasingOptions{})
	targets := []string{"/one", "/two", "/three"}
	c := converse(t, 1, pairs(targets...)...)
	for n, want := range targets {
		r.give(c.fragments[2*n], c.fragments[2*n+1])
		r.drain()
		if n == 0 && (len(r.turns) == 0 || r.turns[0].Taken != 2) {
			t.Fatalf("wiring, not the property: the first pair's two entries did not reach the worker: %+v", r.turns)
		}
		exchanges := r.lines(processing.ArtifactExchange, 1)
		if len(exchanges) != n+1 {
			t.Fatalf("after pair %d of an open connection, %d exchange lines are written, want %d", n+1, len(exchanges), n+1)
		}
		if got := target(t, exchanges[n]); got != want || *exchanges[n].Index != n || exchanges[n].ExchangeID != strconv.Itoa(n+1) {
			t.Fatalf("exchange line %d is %s index %d id %s, want %s index %d id %d", n, got, *exchanges[n].Index,
				exchanges[n].ExchangeID, want, n, n+1)
		}
		if len(r.lines(processing.ArtifactConnection, 1)) != 0 {
			t.Fatal("a connection line was written before the connection retired")
		}
	}
	for idle := 0; idle < 5; idle++ {
		r.drain()
	}
	if got := len(r.out.lines); got != len(targets) {
		t.Fatalf("an idle open connection wrote %d lines, want the %d exchange lines alone", got, len(targets))
	}
	r.retire(c.retirement)
	r.drain()
	exchanges, retirements := r.lines(processing.ArtifactExchange, 1), r.lines(processing.ArtifactConnection, 1)
	if len(exchanges) != len(targets) || len(retirements) != 1 {
		t.Fatalf("after retirement %d exchange lines and %d connection lines, want %d and 1", len(exchanges),
			len(retirements), len(targets))
	}
	final := retirements[0].Connection
	if final.Provisional || final.Lifecycle() != [6]bool{true, true, true, true, true, true} {
		t.Fatalf("the connection line does not carry the final record: %+v", final)
	}
	if retirements[0].ReconstructionTruncation != nil {
		t.Fatalf("a connection whose every byte was released has a truncation: %+v", retirements[0].ReconstructionTruncation)
	}
	for _, a := range exchanges {
		if a.Version != processing.ArtifactVersion4 || !a.Connection.Provisional {
			t.Fatalf("an exchange line is version %s, provisional %t", a.Version, a.Connection.Provisional)
		}
		if fmt.Sprint(a.Connection) != fmt.Sprint(final.Identified()) {
			t.Fatalf("an exchange line's record is not the final record's identity:\n%+v\n%+v", a.Connection, final.Identified())
		}
		if a.Reconstruction.Unplaced != (record.Count{State: record.Undetermined, Unit: record.Bytes, Why: record.WhyProvisional}) {
			t.Fatalf("an exchange line states its connection's unplaced total: %+v", a.Reconstruction.Unplaced)
		}
	}
	visited, err := r.readBack()
	if err != nil || len(visited) != len(targets)+1 {
		t.Fatalf("the shipped reader read %d of %d lines: %v", len(visited), len(targets)+1, err)
	}
	for n, a := range r.approved {
		if !bytes.Equal(a.Bytes(), r.out.lines[n]) {
			t.Fatalf("released line %d changed after later input:\n%s\n%s", n, r.out.lines[n], a.Bytes())
		}
	}
}

// A pair whose last entry a turn takes is released in that turn, while the
// worker's queue still holds input, however much input is queued behind it.
func TestAReadyPairIsReleasedInTheTurnThatTakesItsLastEntry(t *testing.T) {
	r := newReleasing(t, releasingOptions{})
	const before, after = 300, 300
	filler := func(id fragment.ConnectionID) fragment.Record {
		return converse(t, id, wrote("GET /pending HTTP/1.1\r\nHost: a")).fragments[0]
	}
	for n := range before {
		r.give(filler(fragment.ConnectionID(1000 + n)))
	}
	c := converse(t, 1, pair("/ready")...)
	r.give(c.fragments...)
	last := before + len(c.fragments)
	for n := range after {
		r.give(filler(fragment.ConnectionID(2000 + n)))
	}
	r.drain()
	taken := 0
	for _, one := range r.turns {
		if one.Taken > processing.TurnEntries {
			t.Fatalf("turn %d took %d entries, past the bound of %d", one.Number, one.Taken, processing.TurnEntries)
		}
		previous := taken
		taken += one.Taken
		for _, released := range one.Released {
			if released.Connection != 1 {
				continue
			}
			if released.Index != 0 || released.Outcome != processing.ReleaseEnqueued {
				t.Fatalf("the pair was released as %+v (%s)", released, released.Outcome)
			}
			if previous >= last || taken < last {
				t.Fatalf("the pair whose last entry is entry %d was released in turn %d, which took entries %d to %d",
					last, one.Number, previous+1, taken)
			}
			if !one.Backlog {
				t.Fatalf("the turn that released the pair ended with the queue empty: nothing was behind it")
			}
			return
		}
	}
	if taken != before+len(c.fragments)+after {
		t.Fatalf("wiring, not the property: the turns took %d entries of %d queued", taken, before+len(c.fragments)+after)
	}
	t.Fatalf("the pair was never released over %d turns", len(r.turns))
}

// A connection cut after two releases keeps them: its connection line's
// truncation starts at the first byte it did not release, and the ids and
// indexes it issued stay issued.
func TestACutAfterReleasesKeepsWhatWasReleased(t *testing.T) {
	r := newReleasing(t, releasingOptions{connectionInput: 4})
	request := func(target string) call { return wrote("GET " + target + " HTTP/1.1\r\nHost: a\r\n\r\n") }
	c := converse(t, 1, append(pairs("/one", "/two"), request("/3"), request("/4"), request("/5"), request("/6"))...)
	r.give(c.fragments...)
	r.drain()
	if got := len(r.lines(processing.ArtifactExchange, 1)); got != 2 {
		t.Fatalf("wiring, not the property: %d of the two pairs before the pipelined requests were released", got)
	}
	if r.outcome.ConnectionsCut != 1 {
		t.Fatalf("four pending requests on a connection bounded at four were not cut: %+v", r.outcome)
	}
	r.retire(c.retirement)
	r.drain()
	exchanges, retirements := r.lines(processing.ArtifactExchange, 1), r.lines(processing.ArtifactConnection, 1)
	if len(exchanges) != 2 || len(retirements) != 1 {
		t.Fatalf("after the cut connection retired, %d exchange lines and %d connection lines, want 2 and 1",
			len(exchanges), len(retirements))
	}
	for n, a := range exchanges {
		if *a.Index != n || a.ExchangeID != strconv.Itoa(n+1) {
			t.Fatalf("exchange line %d has index %d id %s", n, *a.Index, a.ExchangeID)
		}
	}
	firstUnreleased := map[string]uint64{
		"sent":     c.fragments[2].End(),
		"received": c.fragments[3].End(),
	}
	ran := map[string]uint64{"sent": c.fragments[len(c.fragments)-1].End(), "received": c.fragments[3].End()}
	truncation := retirements[0].ReconstructionTruncation
	if truncation == nil || len(truncation.Stops) != 2 {
		t.Fatalf("the cut connection's line has truncation %+v, want a stop in each direction", truncation)
	}
	for _, stop := range truncation.Stops {
		if stop.Reason != processing.TruncationConnectionCut || stop.Offset != strconv.FormatUint(firstUnreleased[stop.Direction], 10) ||
			stop.EvidenceOffset != strconv.FormatUint(ran[stop.Direction], 10) {
			t.Fatalf("the %s stop is %+v, want connection_cut at %d with evidence at %d", stop.Direction, stop,
				firstUnreleased[stop.Direction], ran[stop.Direction])
		}
	}
	if r.outcome.ExchangeIDs != 2 {
		t.Fatalf("the run issued %d ids, want the 2 released", r.outcome.ExchangeIDs)
	}
	next := converse(t, 2, pair("/after")...)
	r.give(next.fragments...)
	r.drain()
	if after := r.lines(processing.ArtifactExchange, 2); len(after) != 1 || after[0].ExchangeID != "3" || *after[0].Index != 0 {
		t.Fatalf("the next connection's exchange is %+v, want id 3 index 0", after)
	}
}

// Terminal invalidation ordered before an enqueue forbids its authorization;
// an enqueue authorized first is written on a healthy sink although
// invalidation follows it.
func TestInvalidationOrdersAgainstTheEnqueueOfAnEarlyLine(t *testing.T) {
	t.Run("before", func(t *testing.T) {
		var gate *probe.DeliveryGate
		invalidate := false
		r := newReleasing(t, releasingOptions{beforeAuthorize: func() {
			if invalidate {
				gate.Admit(probe.DeliveryKind(255), true)
			}
		}})
		gate = r.gate
		control := converse(t, 1, pair("/control")...)
		r.give(control.fragments...)
		r.drain()
		if len(r.lines(processing.ArtifactExchange, 1)) != 1 {
			t.Fatal("wiring, not the property: the control pair was not written, so a missing line below proves nothing")
		}
		invalidate = true
		c := converse(t, 2, pair("/refused")...)
		r.give(c.fragments...)
		r.drain()
		if got := len(r.lines(processing.ArtifactExchange, 2)); got != 0 || r.gate.Snapshot().Reason == "" {
			t.Fatalf("an exchange invalidated before its enqueue wrote %d lines, gate reason %q", got, r.gate.Snapshot().Reason)
		}
		turn := r.turns[len(r.turns)-1]
		if len(turn.Released) != 1 || turn.Released[0].Outcome != processing.ReleaseUnauthorized {
			t.Fatalf("the refused exchange's release is reported as %+v", turn.Released)
		}
	})
	t.Run("after", func(t *testing.T) {
		dir := t.TempDir()
		held := &holdingSink{entered: make(chan struct{}), release: make(chan struct{})}
		writer, err := processing.OpenWriter(processing.WriterOptions{Directory: dir, QueueBytes: 1 << 20,
			OpenSink: func(path string) sink.Sink {
				held.inner = sink.NewFile(path)
				return held
			}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = writer.Close() })
		r := newReleasing(t, releasingOptions{output: writer})
		c := converse(t, 1, pair("/authorized")...)
		r.give(c.fragments...)
		r.drain()
		select {
		case <-held.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("wiring, not the property: the exchange line never reached the sink")
		}
		r.gate.Admit(probe.DeliveryKind(255), true)
		if r.gate.Snapshot().Reason == "" {
			t.Fatal("wiring, not the property: the gate was not invalidated")
		}
		close(held.release)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := writer.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		var lines []processing.Artifact
		if err := processing.ReadArtifactFiles(os.DirFS(dir), []string{processing.ArtifactName}, "",
			func(a processing.Artifact) error { lines = append(lines, a); return nil }); err != nil {
			t.Fatal(err)
		}
		if len(lines) != 1 || lines[0].Record != processing.ArtifactExchange || target(t, lines[0]) != "/authorized" {
			t.Fatalf("the line authorized before invalidation was not written: %+v", lines)
		}
		if stats := writer.DeliveryStats(); stats.Written != 1 {
			t.Fatalf("the writer counts %+v", stats)
		}
	})
}

// holdingSink holds its first write until released.
type holdingSink struct {
	inner   sink.Sink
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (h *holdingSink) Write(ctx context.Context, line []byte) (int, error) {
	h.once.Do(func() {
		close(h.entered)
		<-h.release
	})
	return h.inner.Write(ctx, line)
}
func (h *holdingSink) Reopen(ctx context.Context) error { return h.inner.Reopen(ctx) }
func (h *holdingSink) Close(ctx context.Context) error  { return h.inner.Close(ctx) }

// A connection whose pairs are released as they complete holds no more than
// its unfinished work, so it is never cut for its length: a bound of eight
// once cut a connection at its eighth fragment.
func TestALongConnectionIsNotCutUnderItsCeiling(t *testing.T) {
	const bound, count = 8, 40
	r := newReleasing(t, releasingOptions{connectionInput: bound})
	var targets []string
	for n := range count {
		targets = append(targets, "/"+strconv.Itoa(n))
	}
	c := converse(t, 1, pairs(targets...)...)
	for n := range count {
		r.give(c.fragments[2*n], c.fragments[2*n+1])
		r.drain()
		held := processing.Connections(r.worker)
		if len(held) != 1 {
			t.Fatalf("wiring, not the property: after pair %d the worker holds %d connections", n+1, len(held))
		}
		if held[0].Pending >= bound || held[0].Entries != 0 {
			t.Fatalf("after pair %d the connection holds %+v", n+1, held[0])
		}
	}
	if r.outcome.ConnectionsCut != 0 || len(r.lines(processing.ArtifactExchange, 1)) != count {
		t.Fatalf("a connection of %d pairs, %d fragments, at a bound of %d: %d cut, %d lines", count, 2*count, bound,
			r.outcome.ConnectionsCut, len(r.lines(processing.ArtifactExchange, 1)))
	}
}

// slotted gives each fragment an event slot from the gate, as capture's
// delivery does.
func slotted(t *testing.T, gate *probe.DeliveryGate, fragments []fragment.Record) []fragment.Record {
	t.Helper()
	out := make([]fragment.Record, len(fragments))
	for n, f := range fragments {
		decision := gate.Admit(probe.DeliveryTransfer, true)
		if !decision.Admitted || decision.Slot == nil {
			t.Fatalf("wiring, not the property: the gate gave fragment %d no slot", f.Sequence)
		}
		f.Slot = decision.Slot
		out[n] = f
	}
	return out
}

// An event's slot is held while any byte of it is held for unfinished work,
// and returned once, as processed, when its last byte goes.
func TestAHalfMessageKeepsItsEventsUntilItsExchangeIsReleased(t *testing.T) {
	r := newReleasing(t, releasingOptions{})
	c := converse(t, 1, wrote("GET /half HTTP/1.1\r\n"), wrote("Host: a\r\n"), wrote("\r\n"),
		read("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	fragments := slotted(t, r.gate, c.fragments)
	for n, f := range fragments[:3] {
		r.give(f)
		r.drain()
		state := r.gate.Snapshot()
		if state.Charged != 4 || state.Held != 4 || state.Refunded.Processed != 0 {
			t.Fatalf("after %d parts of an unanswered request, the gate holds %+v: want all 4 events held, none returned",
				n+1, state)
		}
		if len(r.out.lines) != 0 {
			t.Fatalf("a line was written for a request with no response")
		}
	}
	r.give(fragments[3])
	r.drain()
	state := r.gate.Snapshot()
	if len(r.lines(processing.ArtifactExchange, 1)) != 1 {
		t.Fatalf("wiring, not the property: the completed exchange was not released")
	}
	if state.Held != 0 || state.Refunded.Processed != 4 || state.DoubleRefunds != 0 || r.store.Stats().Leased != 0 {
		t.Fatalf("after the exchange was released the gate holds %+v and intake leases %d", state, r.store.Stats().Leased)
	}
}

// A fragment carrying the end of one exchange and the start of the next is
// held until its last byte goes with the second.
func TestAFragmentSpanningTwoExchangesIsReturnedWithTheSecond(t *testing.T) {
	r := newReleasing(t, releasingOptions{})
	first := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	second := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
	c := converse(t, 1, wrote("GET /one HTTP/1.1\r\nHost: a\r\n\r\n"), wrote("GET /two HTTP/1.1\r\nHost: a\r\n\r\n"),
		read(first+second[:10]), read(second[10:]))
	fragments := slotted(t, r.gate, c.fragments)
	r.give(fragments[:3]...)
	r.drain()
	state := r.gate.Snapshot()
	if len(r.lines(processing.ArtifactExchange, 1)) != 1 {
		t.Fatalf("wiring, not the property: the first exchange was not released")
	}
	if state.Held != 3 || state.Refunded.Processed != 1 {
		t.Fatalf("after the first exchange the gate holds %+v: want the first request returned, the second request "+
			"and the spanning fragment held, with the last fragment not yet given", state)
	}
	r.give(fragments[3])
	r.drain()
	state = r.gate.Snapshot()
	if len(r.lines(processing.ArtifactExchange, 1)) != 2 {
		t.Fatalf("wiring, not the property: the second exchange was not released")
	}
	if state.Held != 0 || state.Refunded.Processed != 4 || state.DoubleRefunds != 0 {
		t.Fatalf("after both exchanges the gate holds %+v", state)
	}
}

// A connection whose fragments carry no evidence is released when its
// retirement vouches for them, as before, and in the same form.
func TestAConnectionWithoutEvidenceIsReleasedAtItsRetirement(t *testing.T) {
	r := newReleasing(t, releasingOptions{})
	c := converse(t, 1, pair("/later")...)
	for n := range c.fragments {
		c.fragments[n].Evidence = fragment.Evidence{}
	}
	r.give(c.fragments...)
	r.drain()
	if got := len(r.out.lines); got != 0 {
		t.Fatalf("a pair nothing vouches for wrote %d lines before its retirement", got)
	}
	if held := processing.Connections(r.worker); len(held) != 1 || held[0].Entries != 2 {
		t.Fatalf("wiring, not the property: the fragments did not reach the worker: %+v", held)
	}
	r.retire(c.retirement)
	r.drain()
	exchanges, retirements := r.lines(processing.ArtifactExchange, 1), r.lines(processing.ArtifactConnection, 1)
	if len(exchanges) != 1 || len(retirements) != 1 || target(t, exchanges[0]) != "/later" {
		t.Fatalf("at retirement %d exchange and %d connection lines", len(exchanges), len(retirements))
	}
	if fmt.Sprint(exchanges[0].Connection) != fmt.Sprint(retirements[0].Connection.Identified()) {
		t.Fatalf("the exchange line's record is not the provisional form of the final one")
	}
}

// Evidence that takes back what earlier evidence established is refused: what
// was released stays, and nothing more is.
func TestEvidenceTakingBackAnEstablishedOffsetStopsRelease(t *testing.T) {
	r := newReleasing(t, releasingOptions{})
	c := converse(t, 1, pairs("/one", "/two")...)
	r.give(c.fragments[:2]...)
	r.drain()
	if len(r.lines(processing.ArtifactExchange, 1)) != 1 {
		t.Fatalf("wiring, not the property: the first pair was not released")
	}
	contradicting := c.fragments[2]
	evidence := contradicting.Evidence
	evidence.Received = fragment.DirectionEvidence{Limit: evidence.Received.Limit, Cut: true, From: 1, First: 1,
		Numbered: evidence.Received.Numbered, Resolved: evidence.Received.Resolved}
	contradicting.Evidence = evidence
	if err := contradicting.Evidenced(); err != nil {
		t.Fatalf("wiring, not the property: the contradicting evidence is refused on its own: %v", err)
	}
	r.give(contradicting, c.fragments[3])
	r.retire(c.retirement)
	r.drain()
	if got := len(r.lines(processing.ArtifactExchange, 1)); got != 1 {
		t.Fatalf("after evidence cut a direction below what was released, %d exchange lines, want the 1 before it", got)
	}
	if r.outcome.Withheld != connection.Uncounted("invalid_input") || r.outcome.ProcessingFailures == 0 {
		t.Fatalf("the contradicting evidence was not refused as invalid input: withheld %+v, %d processing failures",
			r.outcome.Withheld, r.outcome.ProcessingFailures)
	}
	if got := len(r.lines(processing.ArtifactConnection, 1)); got != 0 {
		t.Fatalf("a connection whose evidence contradicted itself wrote %d connection lines", got)
	}
}

// Once an exchange is not released, nothing after it on the connection is,
// however well formed: the suffix from it is one indeterminate stretch. Each
// still takes an id and an index.
func TestNothingAfterAnUnreleasedExchangeIsReleased(t *testing.T) {
	r := newReleasing(t, releasingOptions{})
	gzipped := "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nOK"
	calls := append(pair("/one"), wrote("GET /two HTTP/1.1\r\nHost: a\r\n\r\n"), read(gzipped))
	c := converse(t, 1, append(calls, pair("/three")...)...)
	r.give(c.fragments...)
	r.drain()
	var released []processing.Released
	for _, one := range r.turns {
		released = append(released, one.Released...)
	}
	if len(released) != 3 {
		t.Fatalf("wiring, not the property: the reading handed over %d of the connection's 3 exchanges", len(released))
	}
	for n, want := range []processing.ReleaseOutcome{processing.ReleaseEnqueued, processing.ReleaseExcluded, processing.ReleaseExcluded} {
		if released[n].Index != n || released[n].ID != uint64(n+1) || released[n].Outcome != want {
			t.Fatalf("exchange %d was released as %+v (%s), want index %d id %d %s", n, released[n], released[n].Outcome,
				n, n+1, want)
		}
	}
	if exchanges := r.lines(processing.ArtifactExchange, 1); len(exchanges) != 1 || target(t, exchanges[0]) != "/one" {
		t.Fatalf("the exchange lines are %+v, want /one alone", exchanges)
	}
	r.retire(c.retirement)
	r.drain()
	if r.outcome.Withheld != connection.Counted(2) {
		t.Fatalf("the two framed exchanges after the first were withheld as %+v, want 2", r.outcome.Withheld)
	}
}

// A line the output refuses keeps its exchange's id and index: the next
// exchange is not renumbered into its place.
func TestADroppedLineKeepsItsIndexAndID(t *testing.T) {
	var r *releasing
	dropped := 0
	r = newReleasing(t, releasingOptions{output: outputFunc(func(ctx context.Context, a processing.Approved) error {
		var line processing.Artifact
		if err := json.Unmarshal(a.Bytes(), &line); err != nil {
			return err
		}
		if line.Record == processing.ArtifactExchange && dropped == 0 {
			dropped++
			return sink.ErrQueueFull
		}
		return r.out.WriteApproved(ctx, a)
	})})
	c := converse(t, 1, pairs("/dropped", "/kept")...)
	r.give(c.fragments...)
	r.drain()
	if dropped != 1 || r.outcome.OutputFailures != 1 {
		t.Fatalf("wiring, not the property: the output refused %d lines and %d failures were counted", dropped, r.outcome.OutputFailures)
	}
	exchanges := r.lines(processing.ArtifactExchange, 1)
	if len(exchanges) != 1 || target(t, exchanges[0]) != "/kept" || *exchanges[0].Index != 1 || exchanges[0].ExchangeID != "2" {
		t.Fatalf("after a dropped line the next exchange is %+v, want /kept at index 1 with id 2", exchanges)
	}
	turn := r.turns[len(r.turns)-1]
	if len(turn.Released) != 2 || turn.Released[0].Outcome != processing.ReleaseDropped || turn.Released[1].Outcome != processing.ReleaseEnqueued {
		t.Fatalf("the releases are reported as %+v", turn.Released)
	}
}
