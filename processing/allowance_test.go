package processing_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/reconstruct"
	"github.com/evandukss/edge-observer/sink"
)

// entryCharge is the intake's charge for a fragment of payload, in its own
// unit: the entry and record structures and the payload (intake.Store).
func entryCharge(payload string) int64 {
	return int64(unsafe.Sizeof(intake.Entry{})+unsafe.Sizeof(fragment.Record{})) + int64(len(payload))
}

// named is a header or trailer, by its name and value.
type named struct{ name, value string }

// content is what a copy of one message costs, as the package documentation
// states it: a descriptor, the lengths of its method, target, protocol and
// reason, each header and trailer as a field plus its name and value, and its
// body.
func content(method, target, protocol, reason string, fields []named, body string) int64 {
	n := processing.MessageCharge + int64(len(method)+len(target)+len(protocol)+len(reason)+len(body))
	for _, f := range fields {
		n += processing.FieldCharge + int64(len(f.name)+len(f.value))
	}
	return n
}

// metered is one worker over a store of limit bytes writing to a log, with
// the store's charges read as each line reached the output.
type metered struct {
	t       *testing.T
	store   *intake.Store
	worker  *processing.Worker
	out     *outputLog
	at      []intake.Stats
	outcome processing.Outcome
}

func newMetered(t *testing.T, limit int64, plan *config.ProcessingPlan, connectionInput int) *metered {
	t.Helper()
	store, err := intake.New(limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4096, IntakeExhausted: store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	m := &metered{t: t, store: store, out: &outputLog{}}
	output := outputFunc(func(ctx context.Context, a processing.Approved) error {
		m.at = append(m.at, store.Stats())
		return m.out.WriteApproved(ctx, a)
	})
	m.worker, err = processing.New(processing.Options{Session: "allowance", Plan: plan, PolicyRevision: "allowance-policy",
		Intake: store, Gate: gate, Output: output, ConnectionInput: connectionInput})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.worker.Close() })
	return m
}

func (m *metered) give(fragments ...fragment.Record) {
	m.t.Helper()
	for _, f := range fragments {
		if err := m.store.Write(f); err != nil {
			m.t.Fatalf("wiring, not the property: the intake refused a fragment of the fixture: %v", err)
		}
	}
}

func (m *metered) retire(c connection.Record) {
	m.t.Helper()
	if err := m.store.Connection(c); err != nil {
		m.t.Fatalf("wiring, not the property: the intake refused the fixture's retirement: %v", err)
	}
}

func (m *metered) drain() processing.Outcome {
	m.t.Helper()
	o, err := m.worker.Drain(context.Background())
	if err != nil {
		m.t.Fatal(err)
	}
	m.outcome = o
	return o
}

// kind is the log's lines of one record kind for connection id.
func (o *outputLog) kind(kind string, id fragment.ConnectionID) []processing.Artifact {
	var out []processing.Artifact
	for _, a := range o.artifacts {
		if a.Record == kind && a.Connection.ID == fmt.Sprint(uint64(id)) {
			out = append(out, a)
		}
	}
	return out
}

// requireAllowanceCutLine requires one connection line for id, truncated in
// every direction it names from offset 0 with reason connection_cut.
func requireAllowanceCutLine(t *testing.T, out *outputLog, id fragment.ConnectionID) {
	t.Helper()
	lines := out.kind(processing.ArtifactConnection, id)
	if len(lines) != 1 || lines[0].ReconstructionTruncation == nil || len(lines[0].ReconstructionTruncation.Stops) == 0 {
		t.Fatalf("the cut connection's line: %+v", lines)
	}
	for _, stop := range lines[0].ReconstructionTruncation.Stops {
		if stop.Reason != processing.TruncationConnectionCut || stop.Offset != "0" {
			t.Fatalf("a stop of the cut connection's line: %+v", stop)
		}
	}
}

// While an exchange is released its sources and its copies all exist and each
// is charged: the entries holding its bytes, the parser's copy of them handed
// over with it, and the pipeline's copy of it. Once it is let go its copies'
// charges are given back, and the entry still holding the next request's
// first bytes stays charged: giving back a copy gives back nothing of a source.
func TestASourceAndItsCopiesAreEachChargedWhileTheyCoexist(t *testing.T) {
	first := "GET /a HTTP/1.1\r\nHost: a\r\n\r\nGET /b HTTP/1.1\r\nHo"
	answer := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n/a"
	m := newMetered(t, 1<<20, rulesPlan(t, ""), 0)
	c := converse(t, 1, wrote(first), read(answer))
	m.give(c.fragments...)
	sources := m.store.Stats().Bytes
	if sources != entryCharge(first)+entryCharge(answer) {
		t.Fatalf("wiring, not the property: the two fragments are charged %d, want %d", sources,
			entryCharge(first)+entryCharge(answer))
	}
	m.drain()
	lines := m.out.kind(processing.ArtifactExchange, 1)
	if len(lines) != 1 || target(t, lines[0]) != "/a" || len(m.at) != 1 {
		t.Fatalf("wiring, not the property: /a's release reached the output as %d lines read at %d moments, so "+
			"nothing below measured a coexistence", len(lines), len(m.at))
	}
	during := m.at[0]
	copyOfA := content("GET", "/a", "HTTP/1.1", "", []named{{"Host", "a"}}, "") +
		content("", "", "HTTP/1.1", "OK", []named{{"Content-Length", "2"}}, "/a")
	if during.Policy != copyOfA {
		t.Errorf("as /a's line was written the pipeline's copy of it was charged %d, want its content %d", during.Policy,
			copyOfA)
	}
	low := processing.ReadingCharge + 3*processing.MessageCharge + 1
	high := processing.ReadingCharge + 3*processing.MessageCharge + int64(len(first)+len(answer))
	if during.Parsing < low || during.Parsing > high {
		t.Errorf("as /a's line was written the reading held %d, want the reading state, /a's two messages and /b's "+
			"begun, with their bytes: from %d to %d", during.Parsing, low, high)
	}
	if during.Bytes != sources {
		t.Errorf("as /a's line was written its source entries were charged %d, want %d", during.Bytes, sources)
	}
	after := m.store.Stats()
	if after.Policy != 0 {
		t.Errorf("/a's copy was let go and Policy still holds %d", after.Policy)
	}
	if after.Bytes != entryCharge(first) {
		t.Errorf("the entry holding /b's first bytes is charged %d once /a was let go, want %d", after.Bytes,
			entryCharge(first))
	}
	low = processing.ReadingCharge + processing.MessageCharge + 1
	high = processing.ReadingCharge + processing.MessageCharge + int64(len("GET /b HTTP/1.1\r\nHo"))
	if after.Parsing < low || after.Parsing > high {
		t.Errorf("once /a was let go the reading held %d, want the reading state and /b begun: from %d to %d",
			after.Parsing, low, high)
	}
	held := processing.Connections(m.worker)
	if len(held) != 1 || held[0].Bytes != after.Bytes || held[0].Parsing != after.Parsing {
		t.Errorf("the connection's own charges %+v disagree with the store's %+v", held, after)
	}
}

// One allowance holds for every connection and every worker at once:
// twenty-four connections each holding an unanswered upload across four
// workers ask for more than the allowance, and what the entries and the work
// hold together never passes it. Each connection's reading is charged to it,
// and once the run is over every charge is given back.
func TestTheAllowanceIsOneAcrossConnectionsAndWorkers(t *testing.T) {
	const connections, workers, parts, part = 24, 4, 4, 1000
	const limit = int64(64 << 10)
	store, err := intake.New(limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4096, IntakeExhausted: store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	var mutex sync.Mutex
	var peak, parsing int64
	took := map[int]bool{}
	observe := func() {
		s := store.Stats()
		mutex.Lock()
		defer mutex.Unlock()
		peak = max(peak, s.Bytes+s.Parsing+s.Policy)
		parsing = max(parsing, s.Parsing)
	}
	options := processing.ObserveTurns(processing.Options{Session: "allowance", Plan: rulesPlan(t, ""),
		PolicyRevision: "allowance-policy", Intake: store, Gate: gate, Output: &lines{}, Workers: workers,
		Taken: func(worker int, _ fragment.Process, _ fragment.ConnectionID) {
			mutex.Lock()
			took[worker] = true
			mutex.Unlock()
		}}, func(processing.Turn) { observe() })
	run, err := processing.Start(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = run.Close() })
	var demand int64
	refused := 0
	for id := 1; id <= connections; id++ {
		head := fmt.Sprintf("POST /up/%d HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n", id, parts*part+1)
		calls := []call{wrote(head)}
		for range parts {
			calls = append(calls, wrote(strings.Repeat("x", part)))
		}
		c := converse(t, fragment.ConnectionID(id), calls...)
		for _, f := range c.fragments {
			demand += entryCharge(string(f.Payload))
			if err := store.Write(f); errors.Is(err, intake.ErrLimit) {
				refused++
			} else if err != nil {
				t.Fatal(err)
			}
		}
		run.Route()
		observe()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := run.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true}); err != nil {
		t.Fatal(err)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if len(took) < 2 || demand <= limit {
		t.Fatalf("wiring, not the property: %d workers took input and the fixture asked for %d of %d, so the "+
			"allowance was not shared under pressure", len(took), demand, limit)
	}
	if parsing < processing.ReadingCharge {
		t.Errorf("no reading was charged to the shared allowance: Parsing peaked at %d", parsing)
	}
	if peak > limit {
		t.Errorf("entries and work held %d together, past the one allowance of %d", peak, limit)
	}
	s := store.Stats()
	if refused+int(s.ParsingRefused+s.PolicyRefused) == 0 {
		t.Errorf("an allowance asked for %d of %d refused nothing: %+v", demand, limit, s)
	}
	if s.Bytes != 0 || s.Parsing != 0 || s.Policy != 0 {
		t.Errorf("after the run every charge is given back: %+v", s)
	}
}

// A growth refused where no new input will come, at Finish, is settled at
// once: the connection is cut as the allowance's, the refusal is counted
// against Parsing, and the connection keeps nothing of the allowance.
func TestAGrowthRefusedWithNoNewInputCutsItsConnectionAndKeepsNothing(t *testing.T) {
	head := "POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 5000\r\n\r\n"
	m := newMetered(t, 1<<20, rulesPlan(t, ""), 0)
	c := converse(t, 1, wrote(head+strings.Repeat("x", 1000)), wrote(strings.Repeat("y", 1000)),
		wrote(strings.Repeat("y", 1000)), wrote(strings.Repeat("y", 1000)))
	m.give(c.fragments[0])
	m.drain()
	rest := c.fragments[1:]
	for n := range rest {
		// Nothing vouches for these until the retirement, so they wait for it.
		rest[n].Evidence = fragment.Evidence{}
	}
	m.give(rest...)
	retirement := c.retirement
	retirement.How, retirement.Ended = connection.StillOpen, time.Time{}
	m.retire(retirement)
	m.drain()
	held := processing.Connections(m.worker)
	if len(held) != 1 || held[0].Entries != 5 {
		t.Fatalf("wiring, not the property: the connection holds %+v, not its four fragments and its retirement "+
			"waiting for Finish, so nothing grows there", held)
	}
	s := m.store.Stats()
	left := s.LimitBytes - s.Bytes - s.Parsing - s.Policy
	if !m.store.Reserve(intake.Policy, left) {
		t.Fatalf("wiring, not the property: the fixture could not take the %d left", left)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	o, err := m.worker.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil {
		t.Fatalf("Finish with a refused growth: %v", err)
	}
	if o.AllowanceCut != 1 || o.ConnectionsCut != 1 {
		t.Fatalf("a growth refused at Finish: AllowanceCut %d, ConnectionsCut %d, want 1 and 1: %+v", o.AllowanceCut,
			o.ConnectionsCut, o)
	}
	after := m.store.Stats()
	if after.ParsingRefused == 0 || after.Parsing != 0 || after.Bytes != 0 || after.Policy != left {
		t.Fatalf("after the refusal the store holds %+v: want a counted parsing refusal, nothing of the connection, "+
			"and only the fixture's %d", after, left)
	}
	if lines := m.out.kind(processing.ArtifactExchange, 1); len(lines) != 0 {
		t.Fatalf("the cut connection wrote exchange lines: %+v", lines)
	}
	requireAllowanceCutLine(t, m.out, 1)
}

// A cut at the connection's own bound is a cut and not one the shared
// allowance made: the causes stay apart in the counts.
func TestACutAtTheConnectionsOwnBoundIsNotAnAllowanceCut(t *testing.T) {
	m := newMetered(t, 1<<20, rulesPlan(t, ""), 3)
	var calls []call
	for n := range 4 {
		calls = append(calls, wrote(fmt.Sprintf("GET /%d HTTP/1.1\r\nHost: a\r\n\r\n", n)))
	}
	c := converse(t, 1, calls...)
	m.give(c.fragments...)
	o := m.drain()
	s := m.store.Stats()
	if o.ConnectionsCut != 1 {
		t.Fatalf("wiring, not the property: four unanswered requests at a bound of 3 cut %d connections", o.ConnectionsCut)
	}
	if o.AllowanceCut != 0 || s.ParsingRefused != 0 || s.PolicyRefused != 0 {
		t.Fatalf("a cut at the connection's bound was counted as the allowance's: AllowanceCut %d, refusals %d and %d",
			o.AllowanceCut, s.ParsingRefused, s.PolicyRefused)
	}
	if s.Parsing != 0 {
		t.Fatalf("the cut connection still holds %d of reading", s.Parsing)
	}
}

// A copy whose slot grows it past what the allowance has left is never kept:
// its exchange takes no id and writes no line, the exchange handed over in the
// same step is let go with it, its connection is cut as the allowance's, and
// the refusal is counted against Policy. With room, the same copy is charged
// at its grown content.
func TestAnExchangeWhoseCopyCannotGrowIsNotReleased(t *testing.T) {
	mask := strings.Repeat("m", 4096)
	plan := rulesPlan(t, `"mask": {"headers": {"x-mask": "`+mask+`"}}`)
	request := "GET /m HTTP/1.1\r\nHost: a\r\nX-Mask: v\r\n\r\nGET /n HTTP/1.1\r\nHost: a\r\nX-Mask: v\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n/mHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n/n"
	grown := content("GET", "/m", "HTTP/1.1", "", []named{{"Host", "a"}, {"X-Mask", mask}}, "") +
		content("", "", "HTTP/1.1", "OK", []named{{"Content-Length", "2"}}, "/m")

	measured := newMetered(t, 1<<20, plan, 0)
	measured.give(converse(t, 1, wrote(request), read(response)).fragments...)
	measured.drain()
	if lines := measured.out.kind(processing.ArtifactExchange, 1); len(lines) != 2 || len(measured.at) != 2 ||
		target(t, lines[0]) != "/m" {
		t.Fatalf("wiring, not the property: with room the two exchanges wrote %d lines read at %d moments",
			len(lines), len(measured.at))
	}
	at := measured.at[0]
	if at.Policy != grown {
		t.Fatalf("the masked copy was charged %d as its line was written, want its grown content %d", at.Policy, grown)
	}

	m := newMetered(t, 1<<20, plan, 0)
	hold := int64(1<<20) - (at.Bytes + at.Parsing + at.Policy - 2000)
	if !m.store.Reserve(intake.Policy, hold) {
		t.Fatalf("wiring, not the property: the fixture could not hold %d", hold)
	}
	c := converse(t, 1, wrote(request), read(response))
	m.give(c.fragments...)
	o := m.drain()
	s := m.store.Stats()
	if lines := m.out.kind(processing.ArtifactExchange, 1); len(lines) != 0 || o.ExchangeIDs != 0 {
		t.Fatalf("an exchange whose copy could not grow wrote %d lines and took %d ids", len(lines), o.ExchangeIDs)
	}
	if o.AllowanceCut != 1 || o.ConnectionsCut != 1 || s.PolicyRefused != 1 || s.ParsingRefused != 0 {
		t.Fatalf("a refused copy growth: AllowanceCut %d, ConnectionsCut %d, refusals Policy %d Parsing %d",
			o.AllowanceCut, o.ConnectionsCut, s.PolicyRefused, s.ParsingRefused)
	}
	if s.Policy != hold || s.Parsing != 0 {
		t.Fatalf("after the refusal the connection keeps Policy %d and Parsing %d beside the fixture's %d", s.Policy-hold,
			s.Parsing, hold)
	}
	m.retire(c.retirement)
	m.drain()
	requireAllowanceCutLine(t, m.out, 1)
}

// extensionBinary builds the test extension.
func extensionBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "test-extension")
	out, err := exec.Command("go", "build", "-o", bin, "github.com/evandukss/edge-observer/internal/cmd/broken-extension").CombinedOutput()
	if err != nil {
		t.Fatalf("wiring, not the property: building the test extension: %v: %s", err, out)
	}
	return bin
}

// extended is a run of one worker whose plan holds one extension, writing
// through a Writer, with the store's charges read as each line reached it and
// as each call was about to be submitted.
type extended struct {
	t      *testing.T
	store  *intake.Store
	run    *processing.Run
	writer *processing.Writer
	audit  string
	out    *lines

	mutex   sync.Mutex
	refuse  func(processing.Approved) bool
	atLine  []intake.Stats
	calls   []processing.Submission
	atCall  []intake.Stats
	onCall  func()
	refused int
}

type extendedOptions struct {
	limit  int64
	mode   string
	args   []string
	limits reconstruct.Limits
	sink   func(path string) sink.Sink
}

func newExtended(t *testing.T, o extendedOptions) *extended {
	t.Helper()
	e := &extended{t: t, out: &lines{}}
	dir := t.TempDir()
	e.audit = filepath.Join(dir, "received.jsonl")
	entries, err := json.Marshal([]any{map[string]any{"name": "held", "fields": []string{"request.line", "request.body"},
		"command":    append([]string{extensionBinary(t), "--mode", o.mode, "--record", e.audit}, o.args...),
		"timeout_ms": 5000}})
	if err != nil {
		t.Fatal(err)
	}
	e.store, err = intake.New(o.limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4096, IntakeExhausted: e.store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	e.writer, err = processing.OpenWriter(processing.WriterOptions{Directory: dir, QueueBytes: 1 << 20, OpenSink: o.sink})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.writer.Close() })
	output := outputFunc(func(ctx context.Context, a processing.Approved) error {
		e.mutex.Lock()
		e.atLine = append(e.atLine, e.store.Stats())
		refuse := e.refuse != nil && e.refuse(a)
		if refuse {
			e.refused++
		}
		e.mutex.Unlock()
		if refuse {
			return sink.ErrQueueFull
		}
		if err := e.writer.WriteApproved(ctx, a); err != nil {
			return err
		}
		return e.out.WriteApproved(ctx, a)
	})
	ready := make(chan struct{}, 1)
	options := processing.ObserveSubmits(processing.Options{Session: "extended", Plan: rulesPlan(t, `"extensions":`+string(entries)),
		PolicyRevision: "extended-policy", Intake: e.store, Gate: gate, Output: output, Derived: e.writer, Workers: 1,
		Limits: o.limits,
		Supervision: func(one extension.Event) {
			if one.Kind == extension.Ready {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		}}, func(s processing.Submission) {
		e.mutex.Lock()
		e.calls = append(e.calls, s)
		e.atCall = append(e.atCall, e.store.Stats())
		onCall := e.onCall
		e.mutex.Unlock()
		if onCall != nil {
			onCall()
		}
	})
	e.run, err = processing.Start(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.run.Close() })
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("wiring, not the property: the extension never answered ready")
	}
	return e
}

func (e *extended) give(c conversation) {
	e.t.Helper()
	for _, f := range c.fragments {
		if err := e.store.Write(f); err != nil {
			e.t.Fatalf("wiring, not the property: the intake refused a fragment of the fixture: %v", err)
		}
	}
	if err := e.store.Connection(c.retirement); err != nil {
		e.t.Fatalf("wiring, not the property: the intake refused the fixture's retirement: %v", err)
	}
	e.run.Route()
}

// until waits for done, failing the case as wiring with what after five
// seconds.
func (e *extended) until(what string, done func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			e.t.Fatalf("wiring, not the property: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// received counts the exchanges the extension recorded receiving.
func (e *extended) received() int {
	content, err := os.ReadFile(e.audit)
	if err != nil {
		return 0
	}
	return strings.Count(string(content), `"type":"exchange"`)
}

func (e *extended) finish() processing.Outcome {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	o, err := e.run.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil {
		e.t.Fatal(err)
	}
	return o
}

// A connection handed to a slow extension and then to a sink whose write is
// held stays the worker's until the worker lets it go. Before the supervisor
// accepts its call, while the extension holds the call, after a call it
// refused and after a line the output refused, the worker's charges are the
// same; once its lines are enqueued it holds nothing while the sink still
// holds a line; settled, nothing is held. A call's charge, which the waiting
// bound reads, is never the length of its message.
func TestAHandOverKeepsTheWorkersChargesUntilItLetsGo(t *testing.T) {
	held := &holdingSink{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(held.release) }) })
	e := newExtended(t, extendedOptions{limit: 256 << 10, mode: "unchanged", args: []string{"--delay", "1s"},
		limits: reconstruct.Limits{HTTP: http1.Limits{MaxBodyBytes: 16}},
		sink: func(path string) sink.Sink {
			if filepath.Base(path) != processing.ArtifactName {
				return sink.NewFile(path)
			}
			held.inner = sink.NewFile(path)
			return held
		}})

	// Accepted: before, while the extension holds it, and enqueued to a held sink.
	e.give(converse(t, 1, pair("/slow")...))
	e.until("the extension never received the exchange", func() bool { return e.received() == 1 })
	holding := e.store.Stats()
	e.mutex.Lock()
	if len(e.calls) != 1 {
		e.mutex.Unlock()
		t.Fatalf("wiring, not the property: %d calls were submitted for one exchange", len(e.calls))
	}
	sub, before := e.calls[0], e.atCall[0]
	e.mutex.Unlock()
	if before.Policy == 0 || before.Parsing < processing.ReadingCharge {
		t.Fatalf("before the supervisor accepted the call the worker held Policy %d and Parsing %d", before.Policy,
			before.Parsing)
	}
	if holding.Policy != before.Policy || holding.Parsing != before.Parsing || holding.Bytes != before.Bytes {
		t.Fatalf("submitting moved the worker's charges: before %+v, while the extension holds the call %+v", before,
			holding)
	}
	if sub.Bytes != sub.Charged || sub.Message <= 0 || int64(sub.Message) == sub.Bytes {
		t.Fatalf("the call waits on %d bytes with the connection's charge %d, and its message is %d long", sub.Bytes,
			sub.Charged, sub.Message)
	}
	if sub.Charged != before.Bytes+before.Parsing+before.Policy {
		t.Fatalf("the connection's charge read at its call is %d, want its entries, reading and copy: %d", sub.Charged,
			before.Bytes+before.Parsing+before.Policy)
	}
	select {
	case <-held.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("wiring, not the property: no line reached the held sink")
	}
	e.until("the worker kept its charges after its lines were enqueued", func() bool {
		s := e.store.Stats()
		return s.Bytes == 0 && s.Parsing == 0 && s.Policy == 0
	})
	if pending := e.writer.Stats().PendingBytes; pending <= 0 {
		t.Fatalf("wiring, not the property: the sink holds no line (%d pending bytes), so the worker letting go was "+
			"not measured against a held write", pending)
	}
	once.Do(func() { close(held.release) })

	// Refused by the supervisor: the waiting bound reads the connection's charge,
	// past half the allowance here, while its message stays small.
	// A pair, then an upload, with the connection left open. Capture stamps
	// each record with its evidence and writes it to the intake after
	// releasing its lock, so a record can reach the intake after later ones;
	// here the first arrives last. Nothing of the connection is vouched for
	// until it does, and then all of it is, so every fragment is placed before
	// any is read and the pair's call is made while the upload's entries are
	// held.
	calls := append(pair("/small"), wrote("POST /big HTTP/1.1\r\nHost: a\r\nContent-Length: 150000\r\n\r\n"))
	for range 150 {
		calls = append(calls, wrote(strings.Repeat("b", 1000)))
	}
	open := converse(t, 2, calls...)
	for _, f := range append(open.fragments[1:], open.fragments[0]) {
		if err := e.store.Write(f); err != nil {
			t.Fatalf("wiring, not the property: the intake refused a fragment of the fixture: %v", err)
		}
	}
	e.run.Route()
	e.until("the refused connection's line was not written", func() bool {
		return len(e.out.allFor(2)) > 0
	})
	e.mutex.Lock()
	if len(e.calls) != 2 {
		e.mutex.Unlock()
		t.Fatalf("wiring, not the property: %d calls were submitted, want the second connection's", len(e.calls))
	}
	sub, before = e.calls[1], e.atCall[1]
	afterRefusal := e.atLine[len(e.atLine)-1]
	e.mutex.Unlock()
	if sub.Charged != before.Bytes+before.Parsing+before.Policy {
		t.Fatalf("the connection's charge read at its call is %d, want its entries, reading and copy: %d", sub.Charged,
			before.Bytes+before.Parsing+before.Policy)
	}
	if int64(sub.Message) >= (256<<10)/2 || sub.Charged <= (256<<10)/2 {
		t.Fatalf("wiring, not the property: a %d-byte message on a connection charged %d cannot tell the waiting "+
			"bound's reading apart", sub.Message, sub.Charged)
	}
	if sub.Bytes != sub.Charged || e.received() != 1 {
		t.Fatalf("the call waits on %d bytes, its connection's charge is %d, and the extension received %d "+
			"exchanges: the waiting bound reads the connection's charge and refuses this call", sub.Bytes, sub.Charged,
			e.received())
	}
	if afterRefusal.Policy != before.Policy || afterRefusal.Parsing != before.Parsing || afterRefusal.Bytes != before.Bytes {
		t.Fatalf("a refused call moved the worker's charges before it let go: before %+v, at its line %+v", before,
			afterRefusal)
	}

	// Refused by the output: the worker's charges stay until it lets go.
	e.mutex.Lock()
	first := true
	e.refuse = func(processing.Approved) bool {
		refuse := first
		first = false
		return refuse
	}
	lineBefore := len(e.atLine)
	e.mutex.Unlock()
	e.give(converse(t, 3, pairs("/one", "/two")...))
	e.until("the third connection's lines were not all offered", func() bool {
		e.mutex.Lock()
		defer e.mutex.Unlock()
		return len(e.atLine)-lineBefore >= 3
	})
	e.mutex.Lock()
	refusedAt, nextAt := e.atLine[lineBefore], e.atLine[lineBefore+1]
	refused := e.refused
	e.mutex.Unlock()
	if refused != 1 {
		t.Fatalf("wiring, not the property: the output refused %d lines", refused)
	}
	// Each exchange is let go once its own lines are written, so by the next
	// line, /two's, exactly /one's copy and /one's two entries have gone and
	// its reading charge is lower, with /two's still held.
	one := content("GET", "/one", "HTTP/1.1", "", []named{{"Host", "a"}}, "") +
		content("", "", "HTTP/1.1", "OK", []named{{"Content-Length", "4"}}, "/one")
	oneEntries := entryCharge("GET /one HTTP/1.1\r\nHost: a\r\n\r\n") +
		entryCharge("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n/one")
	if refusedAt.Policy == 0 || nextAt.Policy != refusedAt.Policy-one || nextAt.Bytes != refusedAt.Bytes-oneEntries ||
		nextAt.Parsing >= refusedAt.Parsing || nextAt.Parsing == 0 {
		t.Fatalf("a refused line moved the worker's charges before it let go: at the refusal %+v, at the next line %+v",
			refusedAt, nextAt)
	}

	o := e.finish()
	s := e.store.Stats()
	if s.Bytes != 0 || s.Parsing != 0 || s.Policy != 0 || o.AllowanceCut != 0 {
		t.Fatalf("settled, the store holds %+v and the run cut %d for the allowance", s, o.AllowanceCut)
	}
}

// allFor is every line written for connection id, by the id its record
// carries.
func (l *lines) allFor(id fragment.ConnectionID) [][]byte {
	var out [][]byte
	for _, one := range l.all() {
		var a processing.Artifact
		if json.Unmarshal(one, &a) == nil && a.Connection.ID == fmt.Sprint(uint64(id)) {
			out = append(out, one)
		}
	}
	return out
}

// A connection whose copy cannot be charged before its chain begins issues no
// id and sends an extension nothing; with room, the same copy is charged at its
// content before the call is submitted.
func TestACopyRefusedBeforeTheChainSendsNothing(t *testing.T) {
	copyOfPair := content("GET", "/first", "HTTP/1.1", "", []named{{"Host", "a"}}, "") +
		content("", "", "HTTP/1.1", "OK", []named{{"Content-Length", "6"}}, "/first")

	measured := newExtended(t, extendedOptions{limit: 1 << 20, mode: "unchanged"})
	measured.give(converse(t, 1, pair("/first")...))
	measured.finish()
	measured.mutex.Lock()
	calls, at := len(measured.calls), measured.atCall
	measured.mutex.Unlock()
	if calls != 1 {
		t.Fatalf("wiring, not the property: %d calls were submitted for one exchange", calls)
	}
	if at[0].Policy != copyOfPair {
		t.Fatalf("before its call the dispatch's copy was charged %d, want its content %d", at[0].Policy, copyOfPair)
	}
	peak := at[0].Bytes + at[0].Parsing + at[0].Policy

	e := newExtended(t, extendedOptions{limit: 1 << 20, mode: "unchanged"})
	hold := int64(1<<20) - (peak - 1)
	if !e.store.Reserve(intake.Policy, hold) {
		t.Fatalf("wiring, not the property: the fixture could not hold %d", hold)
	}
	e.give(converse(t, 1, pair("/first")...))
	o := e.finish()
	s := e.store.Stats()
	if e.received() != 0 || o.ExchangeIDs != 0 || len(e.calls) != 0 {
		t.Fatalf("a copy refused before the chain: %d exchanges reached the extension, %d ids, %d calls", e.received(),
			o.ExchangeIDs, len(e.calls))
	}
	if o.AllowanceCut != 1 || s.PolicyRefused != 1 || s.ParsingRefused != 0 {
		t.Fatalf("a copy refused before the chain: AllowanceCut %d, refusals Policy %d Parsing %d", o.AllowanceCut,
			s.PolicyRefused, s.ParsingRefused)
	}
	got := e.out.all()
	if len(got) != 1 || !strings.Contains(string(got[0]), processing.TruncationConnectionCut) {
		t.Fatalf("a copy refused before the chain wrote %d lines: %s", len(got), got)
	}
	if s.Bytes != 0 || s.Parsing != 0 || s.Policy != hold {
		t.Fatalf("after the refusal the store holds %+v beside the fixture's %d", s, hold)
	}
}
