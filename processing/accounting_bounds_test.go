package processing_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/extension"
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
type accountingFixture struct {
	t        *testing.T
	ctx      context.Context
	store    *intake.Store
	gate     *probe.DeliveryGate
	worker   *processing.Worker
	identity fragment.Identity
	evidence fragment.Evidence
	slots    []*accountingSlot
	charges  []int64
	taken    int
	turns    []processing.Turn
	output   *accountingOutput
}

type accountingOutput struct {
	mutex  sync.Mutex
	lines  [][]byte
	refuse bool
}

type accountingSlot struct {
	held.Slot
	mutex    sync.Mutex
	refunds  int
	returned bool
}

func (s *accountingSlot) Refund(path held.Path) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.refunds++
	s.returned = s.Slot.Refund(path)
	return s.returned
}

func (s *accountingSlot) refundRecord() (int, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.refunds, s.returned
}

func (o *accountingOutput) WriteApproved(_ context.Context, a processing.Approved) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	o.lines = append(o.lines, a.Bytes())
	if o.refuse {
		return sink.ErrQueueFull
	}
	return nil
}

func accountingPlan(t *testing.T, rules string) *config.ProcessingPlan {
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

func newAccountingFixture(t *testing.T, limit int64, bound int, rules string, before func(), output processing.Output, configure ...func(*processing.Options)) *accountingFixture {
	t.Helper()
	f := &accountingFixture{t: t, output: &accountingOutput{}}
	var cancel context.CancelFunc
	f.ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	var err error
	f.store, err = intake.New(limit)
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
	options := processing.Options{Plan: accountingPlan(t, rules), PolicyRevision: "accounting", Session: "accounting",
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

func (f *accountingFixture) feed(direction fragment.Direction, text string) {
	f.t.Helper()
	d := f.gate.Admit(probe.DeliveryTransfer, true)
	if !d.Admitted || d.Slot == nil {
		f.t.Fatalf("wiring, not the property: input not admitted: %+v", d)
	}
	slot := &accountingSlot{Slot: d.Slot}
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

func (f *accountingFixture) retire(how connection.Ending) {
	f.t.Helper()
	r := connection.Record{ID: f.identity.Connection, Process: f.identity.Process, Instance: f.identity.Instance,
		Handle:    connection.Handle{Instance: f.identity.Instance.Key(), Address: 7, Generation: 1},
		FirstSeen: f.identity.FirstSeen, How: how, Ended: f.identity.FirstSeen.Add(time.Second),
		Fragments: connection.Counted(int64(f.evidence.Through))}
	for _, dir := range []fragment.Direction{fragment.Sent, fragment.Received} {
		if f.evidence.Of(dir).Limit > 0 {
			r.Placements = append(r.Placements, connection.Placement{Connection: f.identity.Connection, Direction: dir,
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

func (f *accountingFixture) drain() processing.Outcome {
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

const accountingResponse = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"

func accountingRequest(path string) string { return "GET " + path + " HTTP/1.1\r\nHost: x\r\n\r\n" }
func accountingWait(t *testing.T, why string, ready func() bool) {
	t.Helper()
	for end := time.Now().Add(8 * time.Second); time.Now().Before(end); {
		if ready() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("wiring, not the property: %s", why)
}
func accountingTotal(s intake.Stats) int64 { return s.Bytes + s.Parsing + s.Policy }
func accountingZero(t *testing.T, f *accountingFixture) {
	t.Helper()
	s := f.store.Stats()
	g := f.gate.Snapshot()
	if s.Bytes != 0 || s.Parsing != 0 || s.Policy != 0 || s.Queued+s.Leased != 0 {
		t.Errorf("settlement retains work: %+v", s)
	}
	if g.Held != 0 || g.DoubleRefunds != 0 || g.Charged != g.Refunded.Processed+g.Refunded.Discarded+g.Refunded.Cut+g.Refunded.Unretained {
		t.Errorf("event refunds not conserved: %+v", g)
	}
}

func TestAccountingBoundsSourceAndParserCoexistAcrossDrains(t *testing.T) {
	f := newAccountingFixture(t, 1<<20, 64, "", nil, nil)
	body := strings.Repeat("b", 256)
	f.feed(fragment.Sent, "POST /pending HTTP/1.1\r\nContent-Length: 512\r\n\r\n"+body)
	source := f.charges[0]
	for i := 0; i < 3; i++ {
		o := f.drain()
		held := processing.Connections(f.worker)
		if len(held) != 1 || held[0].Entries != 1 || held[0].Pending != 1 {
			t.Fatalf("wiring, not the property: half body not retained: %+v", held)
		}
		s := f.store.Stats()
		if s.Bytes != source || s.Parsing < processing.ReadingCharge+processing.MessageCharge+int64(len(body)) || s.Policy != 0 || held[0].Parsing != s.Parsing || held[0].Bytes != source {
			t.Errorf("coexisting source/parser ownership lost: stats=%+v held=%+v", s, held)
		}
		if o.ConnectionsCut != 0 || o.AllowanceCut != 0 {
			t.Errorf("roomy half body cut: %+v", o)
		}
	}
	if err := f.worker.Close(); err != nil {
		t.Fatal(err)
	}
	accountingZero(t, f)
}

func TestAccountingBoundsWorkersShareTheSessionAllowance(t *testing.T) {
	const n = 16
	f := newAccountingFixture(t, 32768, 64, "", nil, nil)
	_ = f.worker.Close()
	for i := 1; i <= n; i++ {
		f.identity.Connection = fragment.ConnectionID(i)
		id := f.identity
		f.evidence = fragment.Evidence{Identity: &id, Occupancy: 1, Origin: fragment.OriginBirth}
		f.feed(fragment.Sent, "POST /pending HTTP/1.1\r\nContent-Length: 8192\r\n\r\n"+strings.Repeat("b", 256))
	}
	initial := f.store.Stats()
	if initial.Queued != n || initial.Bytes+int64(n)*(processing.ReadingCharge+processing.MessageCharge+256) <= initial.LimitBytes {
		t.Fatal("wiring, not the property: fixture cannot fill one shared allowance")
	}
	var mutex sync.Mutex
	workers := map[int]bool{}
	taken := 0
	maxWork := int64(0)
	sawParsing := false
	opts := processing.Options{Plan: accountingPlan(t, ""), PolicyRevision: "accounting", Session: "accounting", Intake: f.store, Gate: f.gate, Output: f.output, Workers: 3, ConnectionInput: 64}
	opts = processing.ObserveTurns(opts, func(turn processing.Turn) {
		s := f.store.Stats()
		mutex.Lock()
		defer mutex.Unlock()
		if turn.Taken > 0 {
			workers[turn.Worker] = true
			taken += turn.Taken
		}
		maxWork = max(maxWork, accountingTotal(s))
		sawParsing = sawParsing || s.Parsing > 0
	})
	run, err := processing.Start(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = run.Close() }()
	run.Route()
	accountingWait(t, "all connections did not reach workers", func() bool { mutex.Lock(); defer mutex.Unlock(); return taken == n })
	mutex.Lock()
	count, peak, charged := len(workers), maxWork, sawParsing
	mutex.Unlock()
	if count != 3 {
		t.Fatalf("wiring, not the property: only %d of3 workers exercised", count)
	}
	s := f.store.Stats()
	o := run.Snapshot()
	if !charged || peak > 32768 || accountingTotal(s) > 32768 {
		t.Errorf("work allowance multiplied or uncharged: peak=%d stats=%+v", peak, s)
	}
	if o.AllowanceCut == 0 || o.ConnectionsCut != o.AllowanceCut || o.InputCut < o.AllowanceCut || s.ParsingRefused == 0 || s.PolicyRefused != 0 {
		t.Errorf("shared parsing pressure lost its cause: outcome=%+v stats=%+v", o, s)
	}
	if _, err = run.Finish(f.ctx, processing.Finalization{Withdrawn: true, Drained: true}); err != nil {
		t.Fatal(err)
	}
	accountingZero(t, f)
}

func TestAccountingBoundsCeilingCutIsNotAnAllowanceCut(t *testing.T) {
	f := newAccountingFixture(t, 1<<20, 2, "", nil, nil)
	for i := 0; i < 2; i++ {
		f.feed(fragment.Sent, accountingRequest(fmt.Sprintf("/pending-%d", i)))
	}
	o := f.drain()
	if f.taken != 2 {
		t.Fatal("wiring, not the property: two requests not read")
	}
	if o.ConnectionsCut != 1 || o.AllowanceCut != 0 || o.InputCut != 2 {
		t.Errorf("ceiling cut confused with allowance: %+v", o)
	}
	if s := f.store.Stats(); s.ParsingRefused != 0 || s.PolicyRefused != 0 {
		t.Errorf("ceiling invented reservation refusal: %+v", s)
	}
	_ = f.worker.Close()
	accountingZero(t, f)
}

// The peer's wire records follow the public protocol. A file releases its
// answer so no timing assumption decides when processing sees a replacement.
const accountingPeerSource = `package main
import("bufio";"encoding/json";"os";"strings";"time")
func main(){
 scan:=bufio.NewScanner(os.Stdin);scan.Buffer(make([]byte,4096),34<<20)
 for scan.Scan(){var m map[string]any;if json.Unmarshal(scan.Bytes(),&m)!=nil {os.Exit(2)}
 switch m["type"] {case "start":json.NewEncoder(os.Stdout).Encode(map[string]any{"type":"ready","protocol":"observer.extension/1"})
 case "exchange":
  if os.WriteFile(os.Args[1],append(append([]byte{},scan.Bytes()...),10),0600)!=nil {os.Exit(3)}
  for {if _,e:=os.Stat(os.Args[2]);e==nil {break};time.Sleep(time.Millisecond)}
  r:=map[string]any{"type":"result","id":m["id"],"outcome":"unchanged"}
  if os.Args[3]=="grow" {r["outcome"]="changed";r["changes"]=map[string]any{"request.line":map[string]any{"method":"GET","target":"/"+strings.Repeat("g",8192),"protocol":"HTTP/1.1"}}}
  if os.Args[3]=="replace" {r["outcome"]="changed";r["changes"]=map[string]any{"request.line":map[string]any{"method":"GET","target":"/changed?keep=KEEP-PUBLIC&secret=SECRET-REPLACEMENT","protocol":"HTTP/1.1"}}}
  json.NewEncoder(os.Stdout).Encode(r)
 case "shutdown":return}
 }
}`

func accountingPeer(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "peer.go")
	bin := filepath.Join(dir, "peer")
	if err := os.WriteFile(src, []byte(accountingPeerSource), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("wiring, not the property: peer build: %v %s", err, out)
	}
	return bin, filepath.Join(dir, "received"), filepath.Join(dir, "release")
}

type accountingSink struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	written atomic.Int64
	mutex   sync.Mutex
	lines   [][]byte
}

func (s *accountingSink) Write(_ context.Context, b []byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	s.mutex.Lock()
	s.lines = append(s.lines, append([]byte(nil), b...))
	s.mutex.Unlock()
	s.written.Add(1)
	return len(b), nil
}
func (*accountingSink) Reopen(context.Context) error { return nil }
func (*accountingSink) Close(context.Context) error  { return nil }

type accountingCheckingOutput struct {
	writer *processing.Writer
	store  *intake.Store
	before chan intake.Stats
	after  chan intake.Stats
	refuse bool
	lines  chan processing.Artifact
}

func (o *accountingCheckingOutput) WriteApproved(ctx context.Context, a processing.Approved) error {
	var line processing.Artifact
	if err := json.Unmarshal(a.Bytes(), &line); err != nil {
		return err
	}
	if line.Record != processing.ArtifactExchange {
		return o.writer.WriteApproved(ctx, a)
	}
	if o.lines != nil {
		o.lines <- line
	}
	o.before <- o.store.Stats()
	if o.refuse {
		o.after <- o.store.Stats()
		return sink.ErrQueueFull
	}
	err := o.writer.WriteApproved(ctx, a)
	o.after <- o.store.Stats()
	return err
}

func TestAccountingBoundsExtensionHandoffKeepsWorkerCopies(t *testing.T) {
	bin, audit, release := accountingPeer(t)
	for _, refuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sink_refuses_%t", refuse), func(t *testing.T) {
			// Each peer has its own barrier and audit, even though its executable is shared.
			audit, release := audit+fmt.Sprint(refuse), release+fmt.Sprint(refuse)
			accountingHandoff(t, bin, audit, release, "unchanged", refuse, false)
		})
	}
}
func TestAccountingBoundsReplacementGrowthCutsWithoutNewInput(t *testing.T) {
	bin, audit, release := accountingPeer(t)
	accountingHandoff(t, bin, audit, release, "grow", false, true)
}

func accountingHandoff(t *testing.T, bin, audit, release, mode string, refuse, grow bool) {
	heldSink := &accountingSink{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(heldSink.release) }) }
	defer unblock()
	writer, err := processing.OpenWriter(processing.WriterOptions{Directory: t.TempDir(), QueueBytes: 1 << 20, OpenSink: func(string) sink.Sink { return heldSink }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { unblock(); _ = writer.Close() }()
	checking := &accountingCheckingOutput{writer: writer, before: make(chan intake.Stats, 8), after: make(chan intake.Stats, 8), refuse: refuse, lines: make(chan processing.Artifact, 8)}
	f := newAccountingFixture(t, 1<<20, 64, "", nil, checking)
	_ = f.worker.Close()
	checking.store = f.store
	entries := []map[string]any{{"name": "peer", "command": []string{bin, audit, release, mode}, "fields": []string{"request.line"}, "timeout_ms": 30000}}
	if grow {
		if err := os.WriteFile(release+".second", []byte("go"), 0600); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, map[string]any{"name": "second", "command": []string{bin, audit + ".second", release + ".second", "unchanged"}, "fields": []string{"request.line"}, "timeout_ms": 30000})
	}
	ext, _ := json.Marshal(entries)
	ready := make(chan struct{}, 2)
	submits := make(chan processing.Submission, 8)
	beforeSubmit := make(chan intake.Stats, 8)
	options := processing.Options{Plan: accountingPlan(t, `"extensions":`+string(ext)), PolicyRevision: "accounting", Session: "accounting", Intake: f.store, Gate: f.gate, Output: checking, Derived: writer, ConnectionInput: 64, Supervision: func(e extension.Event) {
		if e.Kind == extension.Ready {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	}}
	options = processing.ObserveSubmits(options, func(s processing.Submission) { beforeSubmit <- f.store.Stats(); submits <- s })
	run, err := processing.Start(options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = run.Close() }()
	for range entries {
		select {
		case <-ready:
		case <-f.ctx.Done():
			t.Fatal("wiring, not the property: peer not ready")
		}
	}
	f.feed(fragment.Sent, accountingRequest("/handoff"))
	f.feed(fragment.Received, accountingResponse)
	f.retire(connection.HandleReleasedEnding)
	source := f.store.Stats().Bytes
	run.Route()
	var sub processing.Submission
	select {
	case sub = <-submits:
	case <-f.ctx.Done():
		t.Fatal("wiring, not the property: no submission")
	}
	before := <-beforeSubmit
	accountingWait(t, "peer did not receive encoded exchange", func() bool { _, err := os.Stat(audit); return err == nil })
	frame, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	if sub.ID != 1 || sub.Message != len(frame) || sub.Charged <= source || source == int64(sub.Message) {
		t.Fatalf("wiring, not the property: frame and retained input not distinct: submission=%+v source=%d frame=%d", sub, source, len(frame))
	}
	if sub.Bytes != sub.Charged || sub.Charged != accountingTotal(before) {
		t.Errorf("waiting bytes omit retained work: submission=%+v stats=%+v", sub, before)
	}
	waiting := f.store.Stats()
	// GET /handoff HTTP/1.1 + Host:x, HTTP/1.1 200 OK + Content-Length:2 + OK.
	copyCharge := 2*processing.MessageCharge + 2*processing.FieldCharge + int64(len("GET")+len("/handoff")+2*len("HTTP/1.1")+len("OK")+len("Host")+len("x")+len("Content-Length")+len("2")+len("OK"))
	if before.Bytes != source || before.Parsing <= 0 || before.Policy < copyCharge || waiting.Bytes != source || waiting.Parsing != before.Parsing || waiting.Policy != before.Policy {
		t.Errorf("Submit refunded retained representations: before=%+v waiting=%+v minimum_copy=%d", before, waiting, copyCharge)
	}
	if sub.Message > extension.FrameBytesToExtension || sub.Bytes > extension.WaitingBytes(1<<20, 1) {
		t.Errorf("accepted extension work exceeds its own bounds: %+v", sub)
	}
	if writer.Stats().Pending != 0 {
		t.Error("unanswered extension reached sink")
	}
	var ballast int64
	if grow {
		ballast = waiting.LimitBytes - accountingTotal(waiting) - 64
		if ballast <= 0 || !f.store.Reserve(intake.Policy, ballast) {
			t.Fatal("wiring, not the property: could not leave only64 bytes for growth")
		}
	}
	if err := os.WriteFile(release, []byte("go"), 0600); err != nil {
		t.Fatal(err)
	}
	if grow {
		accountingWait(t, "extension result never settled", func() bool {
			o := run.Snapshot()
			return len(o.Extensions) == 2 && o.Extensions[0].Considered == 1 && o.Extensions[0].Pending == 0 && o.Pending == 0
		})
		o := run.Snapshot()
		s := f.store.Stats()
		// Both transfers belong wholly to the released pair, which survives.
		if o.AllowanceCut != 1 || o.ConnectionsCut != 1 || o.InputCut != 0 || s.PolicyRefused != 1 || s.ParsingRefused != 0 {
			t.Errorf("growth without input not cut/counted by owner: outcome=%+v stats=%+v", o, s)
		}
		if s.Fragments != 2 || s.Connections != 1 || s.Bytes != 0 || s.Parsing != 0 || s.Policy != ballast || o.Pending != 0 {
			t.Errorf("growth retained work or consumed new input: %+v outcome=%+v", s, o)
		}
		if o.Extensions[0].FailedBy[extension.NoRoom] != 1 || o.Extensions[0].Changed != 0 || o.Extensions[1].Unchanged != 1 || o.Extensions[1].Pending != 0 {
			t.Errorf("refused replacement did not continue unchanged through the chain: %+v", o.Extensions)
		}
		select {
		case a := <-checking.lines:
			var rendered bytes.Buffer
			if err := processing.RenderArtifact(&rendered, a); err != nil {
				t.Fatal(err)
			}
			m := accountingRequestMessage(t, a)
			if m.Method != "GET" || m.Target != "/handoff" || m.Protocol != "HTTP/1.1" || strings.Contains(rendered.String(), strings.Repeat("g", 64)) {
				t.Errorf("no_room changed the surviving pair: %s", rendered.String())
			}
			first, last := <-checking.before, <-checking.after
			if first.Bytes != source || first.Parsing <= 0 || first.Policy < ballast+copyCharge || last.Parsing != first.Parsing || last.Policy != first.Policy {
				t.Errorf("refused replacement lost still-owned copies before output: before=%+v after=%+v", first, last)
			}
		default:
			t.Error("no_room dropped the released exchange")
		}
		second, err := os.ReadFile(audit + ".second")
		if err != nil || !bytes.Contains(second, []byte("/handoff")) || bytes.Contains(second, []byte(strings.Repeat("g", 64))) {
			t.Errorf("later extension did not receive the unchanged pair: %s, %v", second, err)
		}
		f.store.Return(intake.Policy, ballast)
	} else {
		var first, last intake.Stats
		select {
		case first = <-checking.before:
		case <-f.ctx.Done():
			t.Fatal("wiring, not the property: answer never reached output boundary")
		}
		last = <-checking.after
		if first.Parsing <= 0 || first.Policy < copyCharge || last.Parsing != first.Parsing || last.Policy != first.Policy {
			t.Errorf("output acceptance/refusal lost caller's still-owned copies: before=%+v after=%+v", first, last)
		}
		if !refuse {
			select {
			case <-heldSink.entered:
			case <-f.ctx.Done():
				t.Fatal("wiring, not the property: sink write not held")
			}
		}
		accountingWait(t, "extension work never settled", func() bool { return run.Snapshot().Pending == 0 })
		s := writer.Stats()
		if s.Pending == 0 || s.PendingBytes <= 0 || s.PendingBytes > s.LimitBytes || s.Written != 0 {
			t.Errorf("held sink queue not independently charged: %+v", s)
		}
		if refuse && run.Snapshot().OutputFailures != 1 {
			t.Errorf("refused exchange uncounted: %+v", run.Snapshot())
		}
	}
	unblock()
	if _, err = run.Finish(f.ctx, processing.Finalization{Withdrawn: true, Drained: true}); err != nil {
		t.Fatal(err)
	}
	if err = writer.Drain(f.ctx); err != nil {
		t.Fatal(err)
	}
	accountingZero(t, f)
	if s := writer.Stats(); s.Pending != 0 || s.PendingBytes != 0 {
		t.Errorf("sink settlement retains bytes: %+v", s)
	}
}

func TestAccountingBoundsSinkRefusalDoesNotBorrowWorkAllowance(t *testing.T) {
	s := &accountingSink{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(s.release) }) }
	defer unblock()
	writer, err := processing.OpenWriter(processing.WriterOptions{Directory: t.TempDir(), QueueBytes: 16384, OpenSink: func(string) sink.Sink { return s }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { unblock(); _ = writer.Close() }()
	f := newAccountingFixture(t, 1<<20, 64, "", nil, writer)
	var outcome processing.Outcome
	for i := 0; i < 12; i++ {
		f.feed(fragment.Sent, accountingRequest("/"+strings.Repeat("p", 1024)+fmt.Sprint(i)))
		f.feed(fragment.Received, accountingResponse)
		outcome = f.drain()
		if i == 0 {
			select {
			case <-s.entered:
			case <-f.ctx.Done():
				t.Fatal("wiring, not the property: first line never held at sink")
			}
		}
		if stats := writer.Stats(); stats.PendingBytes > stats.LimitBytes || stats.Written != 0 {
			t.Errorf("held queue exceeds its bound: %+v", stats)
		}
	}
	stats := writer.Stats()
	if stats.Pending == 0 {
		t.Fatal("wiring, not the property: queue never held approved work")
	}
	if stats.Refused == 0 || outcome.Delivery.Dropped != stats.Refused || stats.LimitBytes != 16384 {
		t.Errorf("sink did not refuse independently of roomy work domain: outcome=%+v sink=%+v", outcome, stats)
	}
	if a := f.store.Stats(); a.Bytes != 0 || a.Policy != 0 || a.Parsing > processing.ReadingCharge || a.ParsingRefused+a.PolicyRefused != 0 {
		t.Errorf("sink refusal leaked/refunded the wrong domain: %+v", a)
	}
	if outcome.ExchangeIDs != 12 || outcome.ConnectionsCut != 0 || outcome.AllowanceCut != 0 {
		t.Errorf("sink refusal became a work cut or lost IDs: %+v", outcome)
	}
	_ = f.worker.Close()
	accountingZero(t, f)
	unblock()
	if err = writer.Drain(f.ctx); err != nil {
		t.Fatal(err)
	}
	if stats = writer.Stats(); stats.PendingBytes != 0 || stats.Pending != 0 || stats.Written+stats.Refused != 12 {
		t.Errorf("sink settlement not conserved: %+v", stats)
	}
}

func TestAccountingBoundsExtensionUsesFrameCallAndCountLimitsSeparately(t *testing.T) {
	bin, audit, release := accountingPeer(t)
	for _, kind := range []string{"waiting", "frame", "in_flight"} {
		t.Run(kind, func(t *testing.T) {
			ready := make(chan struct{}, 1)
			allowance := int64(16)
			if kind == "in_flight" {
				allowance = extension.InFlight + 1
			}
			sup := extension.Start(extension.Config{Name: "peer", Command: []string{bin, audit + kind, release + kind, "unchanged"}, Session: "accounting", Revision: "accounting", TimeoutMS: 30000, WaitingBytes: allowance, Events: func(e extension.Event) {
				if e.Kind == extension.Ready {
					select {
					case ready <- struct{}{}:
					default:
					}
				}
			}})
			defer sup.Close()
			select {
			case <-ready:
			case <-time.After(8 * time.Second):
				t.Fatal("wiring, not the property: supervisor never ready")
			}
			message := func(id uint64) []byte { return []byte(fmt.Sprintf("{\"type\":\"exchange\",\"id\":\"%d\"}\n", id)) }
			submit := func(id uint64, n int64, b []byte) string {
				return sup.Submit(extension.Call{ID: id, Bytes: n, Message: b, Done: func(extension.Result) {}})
			}
			switch kind {
			case "waiting":
				if why := submit(1, 8, message(1)); why != "" {
					t.Fatalf("wiring, not the property: first call refused: %s", why)
				}
				if int64(len(message(1))) <= allowance {
					t.Fatal("wiring, not the property: frame must exceed waiting-byte bound")
				}
				if why := submit(2, 8, message(2)); why != "" {
					t.Errorf("message length was charged as Call.Bytes: %s", why)
				}
				if why := submit(3, 1, message(3)); why != extension.Busy {
					t.Errorf("retained-input limit did not refuse: %s", why)
				}
			case "frame":
				if why := submit(1, 1, message(1)); why != "" {
					t.Fatalf("wiring, not the property: control refused: %s", why)
				}
				if why := submit(2, 1, []byte(strings.Repeat("x", extension.FrameBytesToExtension+1))); why != extension.TooLarge {
					t.Errorf("frame limit borrowed from waiting bytes: %s", why)
				}
			case "in_flight":
				for id := uint64(1); id <= extension.InFlight; id++ {
					if why := submit(id, 1, message(id)); why != "" {
						t.Fatalf("in-flight bound refused call%d early: %s", id, why)
					}
				}
				if why := submit(extension.InFlight+1, 1, message(extension.InFlight+1)); why != extension.Busy {
					t.Errorf("in-flight count exceeded with byte room left: %s", why)
				}
			}
			retained, err := sup.Retained()
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, s := range retained {
				if strings.Contains(s.Store, "outstanding") {
					found = true
					if s.Held == 0 || s.Held > extension.InFlight {
						t.Errorf("outstanding storage not bounded: %+v", s)
					}
				}
			}
			if !found {
				t.Fatal("wiring, not the property: outstanding storage unreadable")
			}
		})
	}
}

// accountingRun uses the real supervisor and writer. Only captured input and
// the extension process at its protocol boundary are controlled here.
func accountingRun(t *testing.T, f *accountingFixture, bin, audit, release, mode, rules string, timeout int, output processing.Output, observe func(processing.Submission)) (*processing.Run, *processing.Writer) {
	t.Helper()
	_ = f.worker.Close()
	writer, err := processing.OpenWriter(processing.WriterOptions{Directory: t.TempDir(), QueueBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	if output == nil {
		output = f.output
	}
	fields := []string{"request.line", "request.headers", "request.body", "response.headers", "response.body"}
	entries := []map[string]any{{"name": "peer", "command": []string{bin, audit, release, mode}, "fields": fields, "timeout_ms": timeout}}
	if mode == "replace" {
		entries = append(entries, map[string]any{"name": "second", "command": []string{bin, audit + ".second", release, "unchanged"}, "fields": fields, "timeout_ms": timeout})
	}
	ext, _ := json.Marshal(entries)
	if rules != "" {
		rules += ","
	}
	ready := make(chan struct{}, len(entries))
	opts := processing.Options{Plan: accountingPlan(t, rules+`"extensions":`+string(ext)), PolicyRevision: "accounting", Session: "accounting", Intake: f.store, Gate: f.gate, Output: output, Derived: writer, ConnectionInput: 512, Supervision: func(e extension.Event) {
		if e.Kind == extension.Ready {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	}}
	if observe != nil {
		opts = processing.ObserveSubmits(opts, observe)
	}
	run, err := processing.Start(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.WriteFile(release, []byte("go"), 0600); _ = run.Close() })
	for range entries {
		select {
		case <-ready:
		case <-f.ctx.Done():
			t.Fatal("wiring, not the property: extension not ready")
		}
	}
	return run, writer
}

func accountingExchanges(t *testing.T, out *accountingOutput) []processing.Artifact {
	t.Helper()
	out.mutex.Lock()
	defer out.mutex.Unlock()
	var result []processing.Artifact
	for _, b := range out.lines {
		var a processing.Artifact
		if err := json.Unmarshal(b, &a); err != nil {
			t.Fatal(err)
		}
		if a.Record == processing.ArtifactExchange {
			result = append(result, a)
		}
	}
	return result
}

func accountingRequestMessage(t *testing.T, a processing.Artifact) *record.Message {
	t.Helper()
	if a.Reconstruction == nil || len(a.Reconstruction.Exchanges) != 1 || a.Reconstruction.Exchanges[0].Request.Message == nil {
		t.Fatal("wiring, not the property: output is not one reconstructed request")
	}
	return a.Reconstruction.Exchanges[0].Request.Message
}

func accountingAwaitProperty(t *testing.T, why string, ready func() bool) {
	t.Helper()
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); {
		if ready() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(why)
}

func TestAccountingBoundsBusyPrecedesAllowanceCut(t *testing.T) {
	bin, audit, release := accountingPeer(t)
	f := newAccountingFixture(t, 128<<10, 512, "", nil, nil)
	submits := make(chan processing.Submission, 16)
	atSubmit := make(chan intake.Stats, 16)
	run, _ := accountingRun(t, f, bin, audit, release, "unchanged", "", 30000, nil, func(s processing.Submission) { atSubmit <- f.store.Stats(); submits <- s })
	var waiting int64
	busy := false
	for n := 1; n <= 6; n++ {
		f.identity.Connection = fragment.ConnectionID(n)
		birth := f.identity
		f.evidence = fragment.Evidence{Identity: &birth, Occupancy: 1, Origin: fragment.OriginBirth}
		path := fmt.Sprintf("/load-%d", n)
		body := strings.Repeat("b", 19000)
		request := "POST " + path + " HTTP/1.1\r\nContent-Length: 19000\r\n\r\n" + body
		for off := 0; off < len(request); off += 4096 {
			f.feed(fragment.Sent, request[off:min(off+4096, len(request))])
		}
		f.feed(fragment.Received, accountingResponse)
		f.retire(connection.HandleReleasedEnding)
		run.Route()
		accountingAwaitProperty(t, "input did not reach an extension or a counted cut", func() bool {
			o := run.Snapshot()
			return o.ConnectionsCut > 0 || (len(o.Extensions) == 1 && o.Extensions[0].Considered >= uint64(n))
		})
		o := run.Snapshot()
		if o.ConnectionsCut != 0 || o.AllowanceCut != 0 {
			t.Fatalf("shared allowance cut before the slow extension refused busy: %+v stats=%+v", o, f.store.Stats())
		}
		var sub processing.Submission
		select {
		case sub = <-submits:
		case <-f.ctx.Done():
			t.Fatal("wiring, not the property: considered call lacked submission observation")
		}
		observed := <-atSubmit
		if accountingTotal(observed) > observed.LimitBytes {
			t.Errorf("shared work exceeds allowance: %+v", observed)
		}
		if waiting+sub.Charged > extension.WaitingBytes(128<<10, 1) {
			if accountingTotal(observed)*10 < observed.LimitBytes*9 {
				t.Fatalf("wiring, not the property: busy admission did not see a nearly full allowance: %+v", observed)
			}
			t.Logf("busy admission work=%d allowance=%d earlier_waiting=%d next_charge=%d", accountingTotal(observed), observed.LimitBytes, waiting, sub.Charged)
			accountingAwaitProperty(t, "full waiting charge did not refuse busy before another connection could consume capture capacity", func() bool { return run.Snapshot().Extensions[0].FailedBy[extension.Busy] > 0 })
		}
		o = run.Snapshot()
		if o.Extensions[0].FailedBy[extension.Busy] > 0 {
			busy = true
			accountingAwaitProperty(t, "busy exchange was not written unchanged", func() bool { return len(accountingExchanges(t, f.output)) > 0 })
			a := accountingExchanges(t, f.output)[0]
			var rendered bytes.Buffer
			if err := processing.RenderArtifact(&rendered, a); err != nil {
				t.Fatal(err)
			}
			m := accountingRequestMessage(t, a)
			kept, decodeErr := base64.StdEncoding.DecodeString(m.Body.Kept)
			if m.Method != "POST" || m.Target != path || m.Protocol != "HTTP/1.1" || decodeErr != nil || string(kept) != body {
				t.Errorf("busy changed the fixture's pair: %s", rendered.String())
			}
			accountingAwaitProperty(t, "busy work retained capture's free half", func() bool { return accountingTotal(f.store.Stats()) <= extension.WaitingBytes(128<<10, 1) })
			if o.ConnectionsCut != 0 || o.AllowanceCut != 0 {
				t.Errorf("busy came after a cut: %+v", o)
			}
			break
		}
		waiting += sub.Charged
		if sub.Bytes != sub.Charged {
			t.Errorf("waiting call counts only part of work: %+v", sub)
		}
		if waiting > extension.WaitingBytes(128<<10, 1) {
			t.Errorf("waiting connections consume capture's half: charged=%d limit=%d", waiting, extension.WaitingBytes(128<<10, 1))
		}
	}
	if !busy {
		t.Error("slow extension never counted busy")
	}
	if waiting == 0 {
		t.Fatal("wiring, not the property: no waiting connection")
	}
	if err := os.WriteFile(release, []byte("go"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := run.Finish(f.ctx, processing.Finalization{Withdrawn: true, Drained: true}); err != nil {
		t.Fatal(err)
	}
	accountingZero(t, f)
}

func TestAccountingBoundsDelayedExtensionKeepsSharedFragment(t *testing.T) {
	bin, audit, release := accountingPeer(t)
	f := newAccountingFixture(t, 1<<20, 64, "", nil, nil)
	run, _ := accountingRun(t, f, bin, audit, release, "unchanged", "", 30000, nil, nil)
	f.feed(fragment.Sent, accountingRequest("/first")+"GET /second HTTP/1.1\r\n")
	f.feed(fragment.Received, accountingResponse)
	run.Route()
	accountingAwaitProperty(t, "complete pair was held until retirement instead of entering the extension", func() bool { _, e := os.Stat(audit); return e == nil })
	if f.gate.Snapshot().Held != 2 || f.store.Stats().Bytes <= 0 || f.store.Stats().Parsing <= 0 || f.store.Stats().Policy <= 0 {
		t.Errorf("delayed extension prematurely refunded source or copies: gate=%+v stats=%+v", f.gate.Snapshot(), f.store.Stats())
	}
	if len(accountingExchanges(t, f.output)) != 0 {
		t.Error("unanswered extension reached output")
	}
	if err := os.WriteFile(release, []byte("go"), 0600); err != nil {
		t.Fatal(err)
	}
	accountingAwaitProperty(t, "first result never released the open pair", func() bool { return len(accountingExchanges(t, f.output)) == 1 })
	accountingAwaitProperty(t, "response fragment was not refunded after the first exchange's line", func() bool { refunds, _ := f.slots[1].refundRecord(); return refunds > 0 })
	sharedRefunds, sharedReturned := f.slots[0].refundRecord()
	responseRefunds, responseReturned := f.slots[1].refundRecord()
	if sharedRefunds != 0 || sharedReturned || responseRefunds != 1 || !responseReturned || f.gate.Snapshot().Held != 1 {
		t.Errorf("wrong fragment survived the first release: shared refunds=%d returned=%t, response refunds=%d returned=%t, held=%d", sharedRefunds, sharedReturned, responseRefunds, responseReturned, f.gate.Snapshot().Held)
	}
	f.feed(fragment.Sent, "Host: x\r\n\r\n")
	f.feed(fragment.Received, accountingResponse)
	run.Route()
	accountingAwaitProperty(t, "second result never released the shared fragment", func() bool { return len(accountingExchanges(t, f.output)) == 2 && f.gate.Snapshot().Held == 0 })
	for i, a := range accountingExchanges(t, f.output) {
		m := accountingRequestMessage(t, a)
		if m.Target != []string{"/first", "/second"}[i] {
			t.Errorf("shared fragment released wrong pair %d: %+v", i, m)
		}
	}
	f.retire(connection.HandleReleasedEnding)
	run.Route()
	if _, err := run.Finish(f.ctx, processing.Finalization{Withdrawn: true, Drained: true}); err != nil {
		t.Fatal(err)
	}
	accountingZero(t, f)
	for i, s := range f.slots {
		refunds, returned := s.refundRecord()
		if refunds != 1 || !returned {
			t.Errorf("slot %d refund count=%d returned=%t", i, refunds, returned)
		}
	}
}

func TestAccountingBoundsExtensionTimeoutReleasesOpenPair(t *testing.T) {
	bin, audit, release := accountingPeer(t)
	f := newAccountingFixture(t, 1<<20, 64, "", nil, nil)
	run, _ := accountingRun(t, f, bin, audit, release, "unchanged", "", 250, nil, nil)
	f.feed(fragment.Sent, accountingRequest("/timeout"))
	f.feed(fragment.Received, accountingResponse)
	run.Route()
	accountingAwaitProperty(t, "open pair never reached timeout accounting", func() bool {
		o := run.Snapshot()
		return len(o.Extensions) == 1 && o.Extensions[0].FailedBy[extension.Timeout] == 1
	})
	accountingAwaitProperty(t, "timed out open pair was not written/refunded", func() bool { return len(accountingExchanges(t, f.output)) == 1 && f.gate.Snapshot().Held == 0 })
	a := accountingExchanges(t, f.output)[0]
	var rendered bytes.Buffer
	if err := processing.RenderArtifact(&rendered, a); err != nil {
		t.Fatal(err)
	}
	m := accountingRequestMessage(t, a)
	if m.Method != "GET" || m.Target != "/timeout" || m.Protocol != "HTTP/1.1" {
		t.Errorf("timeout changed pair: %s", rendered.String())
	}
	f.retire(connection.HandleReleasedEnding)
	run.Route()
	if _, err := run.Finish(f.ctx, processing.Finalization{Withdrawn: true, Drained: true}); err != nil {
		t.Fatal(err)
	}
	accountingZero(t, f)
}

func TestAccountingBoundsAuthorizationAfterExtensionCompletion(t *testing.T) {
	bin, audit, release := accountingPeer(t)
	for _, open := range []bool{true, false} {
		t.Run(fmt.Sprintf("open_%t", open), func(t *testing.T) {
			for _, invalidateFirst := range []bool{true, false} {
				t.Run(fmt.Sprintf("invalidate_first_%t", invalidateFirst), func(t *testing.T) {
					audit, release := audit+fmt.Sprint(open, invalidateFirst), release+fmt.Sprint(open, invalidateFirst)
					s := &accountingSink{entered: make(chan struct{}), release: make(chan struct{})}
					var once sync.Once
					unblock := func() { once.Do(func() { close(s.release) }) }
					defer unblock()
					writer, err := processing.OpenWriter(processing.WriterOptions{Directory: t.TempDir(), QueueBytes: 1 << 20, OpenSink: func(string) sink.Sink { return s }})
					if err != nil {
						t.Fatal(err)
					}
					defer func() { unblock(); _ = writer.Close() }()
					var f *accountingFixture
					entered := make(chan struct{}, 8)
					invalidated := make(chan struct{})
					var releaseInvalidated sync.Once
					finishInvalidation := func() { releaseInvalidated.Do(func() { close(invalidated) }) }
					defer finishInvalidation()
					var authorizationCalls atomic.Int32
					f = newAccountingFixture(t, 1<<20, 64, "", func() {
						if authorizationCalls.Add(1) > 1 && !invalidateFirst {
							<-invalidated
						}
						if invalidateFirst {
							d := f.gate.Admit(probe.DeliveryTransfer, false)
							if d.Slot != nil {
								d.Slot.Refund(held.Unretained)
							}
						}
						entered <- struct{}{}
					}, writer)
					run, _ := accountingRun(t, f, bin, audit, release, "unchanged", "", 30000, writer, nil)
					f.feed(fragment.Sent, accountingRequest("/authorized"))
					f.feed(fragment.Received, accountingResponse)
					if !open {
						f.retire(connection.HandleReleasedEnding)
					}
					run.Route()
					accountingAwaitProperty(t, "open pair never reached extension before authorization", func() bool { _, e := os.Stat(audit); return e == nil })
					select {
					case <-entered:
						t.Fatal("unanswered extension was authorized")
					default:
					}
					if err := os.WriteFile(release, []byte("go"), 0600); err != nil {
						t.Fatal(err)
					}
					select {
					case <-entered:
					case <-f.ctx.Done():
						t.Fatal("wiring, not the property: completed extension never reached authorization")
					}
					if invalidateFirst {
						accountingAwaitProperty(t, "invalidation did not settle extension input", func() bool { return f.gate.Snapshot().Held == 0 })
						if st := writer.DeliveryStats(); st.Pending != 0 || st.Written != 0 {
							t.Errorf("line authorized after invalidation: %+v", st)
						}
					} else {
						select {
						case <-s.entered:
						case <-f.ctx.Done():
							t.Fatal("wiring, not the property: authorized line never entered held sink")
						}
						if st := writer.DeliveryStats(); st.Pending != 1 || st.Written != 0 {
							t.Fatalf("wiring, not the property: no held approved line: %+v", st)
						}
						d := f.gate.Admit(probe.DeliveryTransfer, false)
						if d.Slot != nil {
							d.Slot.Refund(held.Unretained)
						}
						finishInvalidation()
						unblock()
						if err := writer.Drain(f.ctx); err != nil {
							t.Fatal(err)
						}
						if st := writer.DeliveryStats(); st.Written != 1 || st.Pending != 0 || st.Failed != 0 || st.Dropped != 0 {
							t.Errorf("invalidation revoked an authorized line: %+v", st)
						}
						s.mutex.Lock()
						written := append([][]byte(nil), s.lines...)
						s.mutex.Unlock()
						if len(written) != 1 {
							t.Fatalf("wrong physical write count: %d", len(written))
						}
						var a processing.Artifact
						if err := json.Unmarshal(written[0], &a); err != nil {
							t.Fatal(err)
						}
						if a.Record != processing.ArtifactExchange || accountingRequestMessage(t, a).Target != "/authorized" {
							t.Errorf("authorized exchange replaced by another line: %s", written[0])
						}
					}
					if f.gate.Snapshot().Reason != probe.GateUnknownLength {
						t.Fatal("wiring, not the property: terminal invalidation absent")
					}
					unblock()
					if _, err := run.Finish(f.ctx, processing.Finalization{Withdrawn: true, Drained: true}); err != nil {
						t.Fatal(err)
					}
					accountingZero(t, f)
				})
			}
		})
	}
}

func TestAccountingBoundsFragmentedRemovalAfterReplacement(t *testing.T) {
	bin, audit, release := accountingPeer(t)
	for _, open := range []bool{true, false} {
		t.Run(fmt.Sprintf("open_%t", open), func(t *testing.T) {
			for _, refuse := range []bool{false, true} {
				t.Run(fmt.Sprintf("sink_refuses_%t", refuse), func(t *testing.T) {
					audit, release := audit+fmt.Sprint(open, refuse), release+fmt.Sprint(open, refuse)
					if err := os.WriteFile(release, []byte("go"), 0600); err != nil {
						t.Fatal(err)
					}
					f := newAccountingFixture(t, 1<<20, 512, "", nil, nil)
					f.output.refuse = refuse
					run, _ := accountingRun(t, f, bin, audit, release, "replace", `"remove":{"headers":["X-Secret"],"query":["secret"],"bodies":["request","response"]}`, 30000, nil, nil)
					for n := 0; n < 2; n++ {
						if !open {
							f.identity.Connection = fragment.ConnectionID(n + 1)
							birth := f.identity
							f.evidence = fragment.Evidence{Identity: &birth, Occupancy: 1, Origin: fragment.OriginBirth}
						}
						request := fmt.Sprintf("POST /pair-%d?keep=KEEP-PUBLIC&secret=SECRET-QUERY HTTP/1.1\r\nX-Keep: KEEP-PUBLIC\r\nX-Secret: SECRET-HEADER\r\nTransfer-Encoding: chunked\r\n\r\nf\r\nSECRET-REQ-BODY\r\n0\r\nX-Secret: SECRET-TRAILER\r\n\r\n", n)
						response := "HTTP/1.1 200 OK\r\nX-Secret: SECRET-RESPONSE\r\nContent-Length: 17\r\n\r\nSECRET-RESP-BODY!"
						for _, part := range []struct {
							dir  fragment.Direction
							wire string
						}{{fragment.Sent, request}, {fragment.Received, response}} {
							for off := 0; off < len(part.wire); off += 3 {
								f.feed(part.dir, part.wire[off:min(off+3, len(part.wire))])
							}
						}
						if !open {
							f.retire(connection.HandleReleasedEnding)
						}
						run.Route()
						accountingAwaitProperty(t, "fragmented open pair was held until retirement", func() bool { return len(accountingExchanges(t, f.output)) == n+1 })
						frame, err := os.ReadFile(audit)
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Contains(frame, []byte("KEEP-PUBLIC")) {
							t.Fatal("wiring, not the property: permitted content absent from extension projection")
						}
						for _, secret := range []string{"SECRET-QUERY", "SECRET-HEADER", "SECRET-REQ-BODY", "SECRET-TRAILER", "SECRET-RESPONSE", "SECRET-RESP-BODY!"} {
							if bytes.Contains(frame, []byte(secret)) || bytes.Contains(frame, []byte(base64.StdEncoding.EncodeToString([]byte(secret)))) {
								t.Errorf("removed sentinel reached extension: %s", frame)
							}
						}
						second, err := os.ReadFile(audit + ".second")
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Contains(second, []byte("/changed?keep=KEEP-PUBLIC")) || bytes.Contains(second, []byte("SECRET-")) {
							t.Errorf("replacement projection bypassed removal: %s", second)
						}
						a := accountingExchanges(t, f.output)[n]
						encoded, _ := json.Marshal(a)
						var rendered bytes.Buffer
						if err := processing.RenderArtifact(&rendered, a); err != nil {
							t.Fatal(err)
						}
						m := accountingRequestMessage(t, a)
						if m.Method != "GET" || m.Target != "/changed?keep=KEEP-PUBLIC" || m.Protocol != "HTTP/1.1" {
							t.Errorf("replacement not reprocessed with retained public query: %s", rendered.String())
						}
						if bytes.Contains(encoded, []byte("SECRET-")) || strings.Contains(rendered.String(), "SECRET-") {
							t.Errorf("removal fell back to raw after replacement/refusal: encoded=%s rendered=%s", encoded, rendered.String())
						}
						accountingAwaitProperty(t, "completed replacement retained source entries", func() bool { return f.gate.Snapshot().Held == 0 })
					}
					if open {
						f.retire(connection.HandleReleasedEnding)
						run.Route()
					}
					o, err := run.Finish(f.ctx, processing.Finalization{Withdrawn: true, Drained: true})
					if err != nil {
						t.Fatal(err)
					}
					if len(o.Extensions) != 2 || o.Extensions[0].Changed != 2 || o.Extensions[0].Pending != 0 || o.Extensions[1].Unchanged != 2 || o.Extensions[1].Pending != 0 {
						t.Errorf("consecutive replacements did not settle: %+v", o)
					}
					expectedRefusals := uint64(3)
					if !open {
						expectedRefusals = 4
					}
					if refuse && o.OutputFailures != expectedRefusals {
						t.Errorf("refused two exchanges and connection not counted: %+v", o)
					}
					accountingZero(t, f)
				})
			}
		})
	}
}
