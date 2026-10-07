package processing_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

// The child speaks only JSON. Its input reader keeps running while a result is
// held, so an overlapping exchange or an early done remains observable.
func TestExtensionReleasePeer(t *testing.T) {
	dir := os.Getenv("OBSERVER_RELEASE_PEER")
	if dir == "" {
		return
	}
	audit, err := os.OpenFile(filepath.Join(dir, "audit"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(2)
	}
	var mu sync.Mutex
	log := func(v any) {
		b, e := json.Marshal(v)
		if e != nil {
			os.Exit(3)
		}
		mu.Lock()
		_, e = audit.Write(append(b, '\n'))
		mu.Unlock()
		if e != nil {
			os.Exit(4)
		}
	}
	answer := func(m map[string]any) {
		id, _ := m["id"].(string)
		path := filepath.Join(dir, "answer-"+id)
		var b []byte
		var err error
		for {
			b, err = os.ReadFile(path)
			if err == nil {
				break
			}
			if _, autoErr := os.Stat(filepath.Join(dir, "answer-all")); autoErr == nil {
				b = []byte(`{"outcome":"unchanged"}`)
				break
			}
			if !errors.Is(err, os.ErrNotExist) {
				os.Exit(5)
			}
			time.Sleep(time.Millisecond)
		}
		var result map[string]any
		if json.Unmarshal(b, &result) != nil {
			os.Exit(6)
		}
		result["type"], result["id"] = "result", id
		log(map[string]any{"sent": result})
		mu.Lock()
		err = json.NewEncoder(os.Stdout).Encode(result)
		mu.Unlock()
		if err != nil {
			os.Exit(7)
		}
		if _, e := os.Stat(filepath.Join(dir, "duplicate-"+id)); e == nil {
			log(map[string]any{"sent": result})
			mu.Lock()
			err = json.NewEncoder(os.Stdout).Encode(result)
			mu.Unlock()
			if err != nil {
				os.Exit(8)
			}
		}
	}
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 32<<20)
	for scan.Scan() {
		var m map[string]any
		if json.Unmarshal(scan.Bytes(), &m) != nil {
			os.Exit(9)
		}
		log(m)
		switch m["type"] {
		case "start":
			if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "ready", "protocol": "observer.extension/1"}); err != nil {
				os.Exit(10)
			}
		case "exchange":
			go answer(m)
		case "shutdown":
			_ = audit.Close()
			os.Exit(0)
		}
	}
	os.Exit(0)
}

type releasePeer struct{ dir string }

func (p releasePeer) messages(t *testing.T) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(p.dir, "audit"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	// A concurrent append can leave an incomplete final line; only complete
	// lines are observations. A final read after shutdown checks the terminator.
	for _, line := range bytes.Split(b, []byte{'\n'})[:bytes.Count(b, []byte{'\n'})] {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}
func (p releasePeer) of(t *testing.T, kind string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, m := range p.messages(t) {
		if m["type"] == kind {
			out = append(out, m)
		}
	}
	return out
}
func releaseAwait(t *testing.T, why string, f func() bool) {
	t.Helper()
	end := time.Now().Add(5 * time.Second)
	for !f() {
		if time.Now().After(end) {
			t.Fatal(why)
		}
		time.Sleep(time.Millisecond)
	}
}
func (p releasePeer) exchange(t *testing.T, n int) map[string]any {
	t.Helper()
	releaseAwait(t, "released exchange did not reach the ready extension before retirement", func() bool { return len(p.of(t, "exchange")) > n })
	return p.of(t, "exchange")[n]
}
func (p releasePeer) answer(t *testing.T, m map[string]any, result string) {
	t.Helper()
	id, ok := m["id"].(string)
	if !ok {
		t.Fatalf("exchange has no id: %v", m)
	}
	temp := filepath.Join(p.dir, "answer.tmp")
	if err := os.WriteFile(temp, []byte(result), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temp, filepath.Join(p.dir, "answer-"+id)); err != nil {
		t.Fatal(err)
	}
}

type releaseOutput struct {
	mu   sync.Mutex
	got  []processing.Artifact
	drop int
}

func (o *releaseOutput) WriteApproved(_ context.Context, a processing.Approved) error {
	var artifact processing.Artifact
	if err := json.Unmarshal(a.Bytes(), &artifact); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if artifact.Record == "exchange" && artifact.Index != nil && *artifact.Index == o.drop {
		return errors.New("fixture sink refusal")
	}
	o.got = append(o.got, artifact)
	return nil
}
func (o *releaseOutput) exchanges() []processing.Artifact {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []processing.Artifact
	for _, a := range o.got {
		if a.Record == "exchange" {
			out = append(out, a)
		}
	}
	return out
}

type releaseFixture struct {
	t           *testing.T
	run         *processing.Run
	store       *intake.Store
	gate        *probe.DeliveryGate
	capture     *capture.Session
	out         *releaseOutput
	peers       []releasePeer
	events      chan extension.Event
	taken       atomic.Int64
	transferred int64
	stamp       uint64
	numbers     map[uint64][3]uint64
	ids         map[uint64]fragment.ConnectionID
	losses      map[uint64]*held.Loss
}

type releaseCaptureSink struct{ f *releaseFixture }

func (s releaseCaptureSink) Write(r fragment.Record) error {
	if err := r.Evidenced(); err != nil {
		return err
	}
	if r.Evidence.Identity == nil {
		return errors.New("wiring, not the property: capture supplied no evidence identity")
	}
	s.f.ids[r.Evidence.Identity.Address] = r.Connection
	s.f.losses[r.Evidence.Identity.Address] = r.Loss
	s.f.transferred++
	return s.f.store.Write(r)
}
func (s releaseCaptureSink) Connection(r connection.Record) error {
	s.f.transferred++
	return s.f.store.Connection(r)
}

func newReleaseFixture(t *testing.T, n, ceiling, timeout int, content bool, drop int) *releaseFixture {
	t.Helper()
	f := &releaseFixture{t: t, out: &releaseOutput{drop: drop}, events: make(chan extension.Event, 1000), numbers: map[uint64][3]uint64{}, ids: map[uint64]fragment.ConnectionID{}, losses: map[uint64]*held.Loss{}}
	var err error
	f.store, err = intake.New(8 << 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	var entries []any
	fields := []string{"request.headers", "response.body"}
	if !content {
		fields = []string{"connection"}
	}
	for i := 0; i < n; i++ {
		p := releasePeer{dir: t.TempDir()}
		f.peers = append(f.peers, p)
		entries = append(entries, map[string]any{"name": fmt.Sprintf("peer%d", i), "command": []string{"/usr/bin/env", "OBSERVER_RELEASE_PEER=" + p.dir, os.Args[0], "-test.run=^TestExtensionReleasePeer$"}, "fields": fields, "timeout_ms": timeout})
	}
	doc, err := json.Marshal(map[string]any{"version": "observer.config/1", "output": "/var/lib/observer", "watch": []any{map[string]any{"name": "api", "exe": "/usr/bin/php"}}, "extensions": entries, "write_content": content, "remove": map[string]any{"headers": []string{"authorization"}}})
	if err != nil {
		t.Fatal(err)
	}
	compiled, findings := config.Compile(doc, "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: config refused: %v", findings)
	}
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 64, IntakeExhausted: f.store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	f.gate = gate
	writer, err := processing.Open(t.TempDir(), 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	f.run, err = processing.Start(processing.Options{Plan: compiled.Plan, Session: "release-session", PolicyRevision: "release-policy", Intake: f.store, Gate: gate, Output: f.out, Derived: writer, ConnectionInput: ceiling, Supervision: func(e extension.Event) { f.events <- e }, Taken: func(_ int, _ fragment.Process, _ fragment.ConnectionID) { f.taken.Add(1) }})
	if err != nil {
		t.Fatalf("wiring, not the property: worker start: %v", err)
	}
	t.Cleanup(func() { _ = f.run.Close() })
	for range n {
		f.event(extension.Ready)
	}
	s := releaseCaptureSink{f}
	f.capture = capture.Recording(s, s)
	f.capture.Observing(probe.Capability{Backend: probe.BPF, Payload: true, Lifecycle: true})
	return f
}
func (f *releaseFixture) event(kind extension.EventKind) extension.Event {
	f.t.Helper()
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	for {
		select {
		case e := <-f.events:
			if e.Kind == kind {
				return e
			}
		case <-timer.C:
			f.t.Fatalf("wiring, not the property: no supervision event %s", kind)
		}
	}
}
func (f *releaseFixture) transfer(handle uint64, d fragment.Direction, body string) {
	f.t.Helper()
	f.stamp++
	numbers := f.numbers[handle]
	numbers[d]++
	f.numbers[handle] = numbers
	instance := admission.Instance{Namespace: admission.Namespace{Device: 3, Inode: 7}, PID: 71, Start: admission.Determinate(19), Generation: 1}
	// Probe attachment is not modelled: serial transfers obey the producer's
	// per-direction numbering and observed-birth invariants. Capture itself
	// supplies all evidence, identities, byte offsets and retirement records.
	f.capture.Transfer(probe.Transfer{Process: fragment.Process{PID: 71, StartTime: 19}, Instance: instance, Endpoint: handle, Stamp: f.stamp, Sequence: probe.Sequence{Occupancy: handle, Number: numbers[d], Born: true}, Direction: d, Length: uint32(len(body)), Measured: true, Payload: []byte(body), At: time.Now()})
	if f.ids[handle] == 0 {
		f.t.Fatal("wiring, not the property: capture produced no evidenced fragment")
	}
}
func (f *releaseFixture) pair(handle uint64, target string) {
	f.transfer(handle, fragment.Sent, "GET "+target+" HTTP/1.1\r\nHost: api\r\nAuthorization: removed-sentinel\r\n\r\n")
	f.transfer(handle, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(len(target))+"\r\n\r\n"+target)
	f.route()
}
func (f *releaseFixture) route() {
	f.t.Helper()
	f.run.Route()
	releaseAwait(f.t, "wiring, not the property: captured inputs did not reach the worker", func() bool { return f.taken.Load() == f.transferred })
}
func (f *releaseFixture) close(handle uint64) {
	f.stamp++
	n := f.numbers[handle]
	f.capture.Closed(probe.Connection{Process: fragment.Process{PID: 71, StartTime: 19}, Instance: admission.Instance{Namespace: admission.Namespace{Device: 3, Inode: 7}, PID: 71, Start: admission.Determinate(19), Generation: 1}, Endpoint: handle, Stamp: f.stamp, Sequence: probe.Sequence{Occupancy: handle, Born: true}, Final: probe.Final{Known: true, Sent: probe.Terminal{Last: n[fragment.Sent]}, Received: probe.Terminal{Last: n[fragment.Received]}}, At: time.Now()})
	f.route()
}
func (f *releaseFixture) finish() processing.Outcome {
	f.t.Helper()
	f.capture.Finish(time.Now())
	f.route()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	o, err := f.run.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil {
		f.t.Fatal(err)
	}
	for _, p := range f.peers {
		b, err := os.ReadFile(filepath.Join(p.dir, "audit"))
		if err != nil || len(b) == 0 || b[len(b)-1] != '\n' {
			f.t.Fatalf("wiring, not the property: peer audit incomplete: %v", err)
		}
	}
	return o
}
func (f *releaseFixture) identity(m map[string]any, handle uint64, index int) string {
	f.t.Helper()
	want := strconv.FormatUint(uint64(f.ids[handle]), 10)
	if m["connection_id"] != want || m["index"] != float64(index) {
		f.t.Errorf("exchange identity/index=%v/%v want %s/%d", m["connection_id"], m["index"], want, index)
	}
	if _, ok := m["ids"]; ok {
		f.t.Error("extension exchange carries a final id range")
	}
	if _, ok := m["connection"]; ok {
		f.t.Error("unselected connection projection was sent")
	}
	id, ok := m["id"].(string)
	if !ok {
		f.t.Fatalf("missing exchange id: %v", m)
	}
	value, err := strconv.ParseUint(id, 10, 64)
	if err != nil || value == 0 {
		f.t.Fatalf("invalid exchange id %q", id)
	}
	return id
}
func (f *releaseFixture) done(p releasePeer, handle uint64, count int) {
	f.t.Helper()
	key := strconv.FormatUint(uint64(f.ids[handle]), 10)
	found := 0
	pending := map[string]string{}
	byID := map[string]string{}
	ended := map[string]bool{}
	for _, m := range p.messages(f.t) {
		if sent, ok := m["sent"].(map[string]any); ok {
			if id, ok := sent["id"].(string); ok {
				delete(pending, byID[id])
			}
			continue
		}
		conn, _ := m["connection_id"].(string)
		switch m["type"] {
		case "start":
			pending = map[string]string{}
		case "exchange":
			if pending[conn] != "" || ended[conn] {
				f.t.Errorf("overlapping exchange or exchange after done: %v", m)
			}
			id, _ := m["id"].(string)
			pending[conn] = id
			byID[id] = conn
		case "connection_done":
			if pending[conn] != "" {
				f.t.Errorf("done preceded the last result: %v", m)
			}
			ended[conn] = true
		}
	}

	for _, m := range p.of(f.t, "connection_done") {
		if m["connection_id"] != key {
			continue
		}
		found++
		if m["count"] != strconv.Itoa(count) {
			f.t.Errorf("done count=%v want %d ids issued by fixture", m["count"], count)
		}
		if _, ok := m["ids"]; ok {
			f.t.Error("connection_done carries a final id range")
		}
	}
	if found != 1 {
		f.t.Errorf("connection %s got %d done messages, want exactly one", key, found)
	}
}
func (f *releaseFixture) noDone(p releasePeer) {
	f.t.Helper()
	if got := p.of(f.t, "connection_done"); len(got) != 0 {
		f.t.Errorf("connection_done before pending work settled: %v", got)
	}
}
func (f *releaseFixture) terminal(o processing.Outcome, count uint64) {
	f.t.Helper()
	if o.ExchangeIDs != count {
		f.t.Errorf("issued=%d want fixture count %d", o.ExchangeIDs, count)
	}
	for _, c := range o.Extensions {
		if c.Considered != count || c.Pending != 0 || c.Changed+c.Unchanged+c.Failed != count {
			f.t.Errorf("extension outcomes did not settle fixture population: %+v", c)
		}
	}
}

func TestExtensionReleaseBeforeCloseAndChainOrder(t *testing.T) {
	f := newReleaseFixture(t, 2, 100, 20000, true, -1)
	f.pair(11, "/first")
	first := f.peers[0].exchange(t, 0)
	id := f.identity(first, 11, 0)
	f.pair(11, "/second")
	f.peers[0].answer(t, first, `{"outcome":"unchanged"}`)
	secondPeer := f.peers[1].exchange(t, 0)
	if secondPeer["id"] != id {
		t.Error("chain changed the exchange id")
	}
	// A different connection traverses the first extension while the first
	// connection is held at the second, giving the worker a witnessed turn.
	f.pair(22, "/other")
	other := f.peers[0].exchange(t, 1)
	otherID := f.identity(other, 22, 0)
	if otherID == id {
		t.Error("two connections reused an exchange id")
	}
	if len(f.peers[0].of(t, "exchange")) != 2 {
		t.Error("second exchange started before the first settled at every extension")
	}
	f.peers[0].answer(t, other, `{"outcome":"unchanged"}`)
	otherSecond := f.peers[1].exchange(t, 1)
	f.peers[1].answer(t, otherSecond, `{"outcome":"unchanged"}`)
	f.peers[1].answer(t, secondPeer, `{"outcome":"unchanged"}`)
	next := f.peers[0].exchange(t, 2)
	nextID := f.identity(next, 11, 1)
	if nextID == id || nextID == otherID {
		t.Error("released exchange reused an id")
	}
	f.peers[0].answer(t, next, `{"outcome":"unchanged"}`)
	last := f.peers[1].exchange(t, 2)
	if last["id"] != nextID {
		t.Error("chain changed the next id")
	}
	f.close(11)
	f.close(22)
	f.peers[1].answer(t, last, `{"outcome":"unchanged"}`)
	o := f.finish()
	f.terminal(o, 3)
	for _, p := range f.peers {
		f.done(p, 11, 2)
		f.done(p, 22, 1)
	}
	want := map[string]struct {
		connection string
		index      int
	}{id: {strconv.FormatUint(uint64(f.ids[11]), 10), 0}, nextID: {strconv.FormatUint(uint64(f.ids[11]), 10), 1}, otherID: {strconv.FormatUint(uint64(f.ids[22]), 10), 0}}
	seen := map[string]bool{}
	for _, a := range f.out.exchanges() {
		w, ok := want[a.ExchangeID]
		if !ok || seen[a.ExchangeID] || a.Connection.ID != w.connection || a.Index == nil || *a.Index != w.index {
			t.Errorf("written line does not preserve wire identity: %+v", a)
		}
		seen[a.ExchangeID] = true
	}
	if len(seen) != 3 {
		t.Errorf("written exchange identities=%d want 3", len(seen))
	}
}

func TestExtensionReleaseExcludedTailAndDroppedCount(t *testing.T) {
	f := newReleaseFixture(t, 1, 100, 20000, true, 0)
	p := f.peers[0]
	f.pair(11, "/dropped")
	first := p.exchange(t, 0)
	f.identity(first, 11, 0)
	p.answer(t, first, `{"outcome":"unchanged"}`)
	f.pair(11, "/written")
	second := p.exchange(t, 1)
	f.identity(second, 11, 1)
	p.answer(t, second, `{"outcome":"unchanged"}`)
	f.transfer(11, fragment.Sent, "GET /tail HTTP/1.1\r\nHost: api\r\nAuthorization: removed-sentinel\r\n\r\n")
	f.route()
	if len(p.of(t, "exchange")) != 2 {
		t.Error("one-sided tail was sent before exclusion became decidable")
	}
	f.close(11)
	tail := p.exchange(t, 2)
	f.identity(tail, 11, 2)
	f.noDone(p)
	b, _ := json.Marshal(tail)
	if bytes.Contains(b, []byte("removed-sentinel")) {
		t.Error("excluded tail contains removed header")
	}
	output, ok := tail["output"].(map[string]any)
	if !ok || output["state"] != "excluded" || output["reason"] != "unpaired_exchange" {
		t.Errorf("tail was not declared excluded: %v", tail)
	}
	p.answer(t, tail, `{"outcome":"unchanged"}`)
	o := f.finish()
	f.terminal(o, 3)
	f.done(p, 11, 3)
	if o.OutputFailures != 1 {
		t.Errorf("sink refused one exchange, output failures=%d", o.OutputFailures)
	}
	if got := f.out.exchanges(); len(got) != 1 || got[0].Index == nil || *got[0].Index != 1 {
		t.Errorf("output did not contain exactly the eligible undropped exchange: %v", got)
	}
}

func TestExtensionReleaseCutThenLateResult(t *testing.T) {
	f := newReleaseFixture(t, 1, 4, 20000, true, -1)
	p := f.peers[0]
	f.pair(11, "/kept")
	first := p.exchange(t, 0)
	f.identity(first, 11, 0)
	for range 5 {
		f.transfer(11, fragment.Sent, "GET /waiting HTTP/1.1\r\nHost: api\r\n\r\n")
	}
	f.route()
	releaseAwait(t, "wiring, not the property: ceiling cut never occurred", func() bool { return f.run.Snapshot().ConnectionsCut == 1 })
	f.close(11)
	f.noDone(p)
	id := first["id"].(string)
	if err := os.WriteFile(filepath.Join(p.dir, "duplicate-"+id), nil, 0600); err != nil {
		t.Fatal(err)
	}
	p.answer(t, first, `{"outcome":"unchanged"}`)
	o := f.finish()
	f.terminal(o, 1)
	f.done(p, 11, 1)
	if len(p.of(t, "exchange")) != 1 || len(f.out.exchanges()) != 1 {
		t.Error("late result after cut lost or resurrected an exchange")
	}
}

func TestExtensionReleaseSessionEndSettlesPending(t *testing.T) {
	f := newReleaseFixture(t, 1, 100, 20000, true, -1)
	p := f.peers[0]
	f.pair(11, "/open")
	first := p.exchange(t, 0)
	f.identity(first, 11, 0)
	f.capture.Finish(time.Now())
	f.route()
	f.noDone(p)
	p.answer(t, first, `{"outcome":"unchanged"}`)
	o := f.finish()
	f.terminal(o, 1)
	f.done(p, 11, 1)
	done := p.of(t, "connection_done")
	if len(done) == 1 {
		ending, ok := done[0]["ending"].(map[string]any)
		if !ok || ending["how"] != "still_open" {
			t.Errorf("session end lost its retirement: %v", done)
		}
	}
}

func TestExtensionReleaseTimeoutRestartKeepsCount(t *testing.T) {
	f := newReleaseFixture(t, 1, 100, 500, true, -1)
	p := f.peers[0]
	f.pair(11, "/timeout")
	first := p.exchange(t, 0)
	firstID := f.identity(first, 11, 0)
	retired := f.event(extension.Retired)
	if retired.Cause != "timeout" {
		t.Fatalf("wiring, not the property: expected timeout generation, got %+v", retired)
	}
	ready := f.event(extension.Ready)
	if ready.Generation <= 1 {
		t.Fatal("wiring, not the property: no restart")
	}
	f.pair(11, "/after")
	next := p.exchange(t, 1)
	nextID := f.identity(next, 11, 1)
	if nextID == firstID {
		t.Error("restart reused id")
	}
	p.answer(t, next, `{"outcome":"unchanged"}`)
	f.close(11)
	o := f.finish()
	f.terminal(o, 2)
	f.done(p, 11, 2)
	if len(p.of(t, "exchange")) != 2 {
		t.Error("restart replayed an exchange")
	}
	if len(o.Extensions) != 1 || o.Extensions[0].FailedBy["timeout"] != 1 || o.Extensions[0].Unchanged != 1 {
		t.Errorf("restart lost terminal outcomes: %+v", o.Extensions)
	}
}

func TestExtensionReleaseReplacementWithoutRoomContinuesChain(t *testing.T) {
	f := newReleaseFixture(t, 2, 100, 20000, true, -1)
	f.pair(11, "/original")
	first := f.peers[0].exchange(t, 0)
	f.identity(first, 11, 0)
	// Once the first call is waiting, occupy all but one byte of the shared
	// allowance. The peer's answer is larger than that remaining room.
	s := f.store.Stats()
	reserved := s.LimitBytes - s.Bytes - s.Parsing - s.Policy - 1
	if reserved <= 0 || !f.store.Reserve(intake.Policy, reserved) {
		t.Fatal("wiring, not the property: could not occupy replacement room")
	}
	defer func() { f.store.Return(intake.Policy, reserved) }()
	replacement := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("replacement", 1024)))
	f.peers[0].answer(t, first, `{"outcome":"changed","changes":{"response.body":{"kept":"`+replacement+`"}}}`)
	next := f.peers[1].exchange(t, 0)
	b, _ := json.Marshal(next)
	if bytes.Contains(b, []byte(replacement)) {
		t.Error("replacement without room reached next extension")
	}
	f.peers[1].answer(t, next, `{"outcome":"unchanged"}`)
	releaseAwait(t, "no_room did not write unchanged released exchange", func() bool { return len(f.out.exchanges()) == 1 })
	f.store.Return(intake.Policy, reserved)
	reserved = 0
	f.close(11)
	o := f.finish()
	f.terminal(o, 1)
	for _, p := range f.peers {
		f.done(p, 11, 1)
	}
	if len(o.Extensions) != 2 || o.Extensions[0].FailedBy["no_room"] != 1 || o.Extensions[1].Unchanged != 1 || o.AllowanceCut != 1 {
		t.Errorf("no_room did not continue and settle the chain: %+v", o)
	}
	a := f.out.exchanges()[0]
	if a.Reconstruction == nil || len(a.Reconstruction.Exchanges) != 1 {
		t.Fatalf("written exchange has no reconstruction: %+v", a)
	}
	body := a.Reconstruction.Exchanges[0].Response.Message.Body.Kept
	if body != base64.StdEncoding.EncodeToString([]byte("/original")) {
		t.Errorf("no_room changed original body: %q", body)
	}
}

func TestExtensionReleaseRefusedWholeSendsNothing(t *testing.T) {
	f := newReleaseFixture(t, 1, 2, 20000, true, -1)
	p := f.peers[0]
	for range 3 {
		f.transfer(11, fragment.Sent, "GET /pending HTTP/1.1\r\nHost: api\r\n\r\n")
	}
	f.route()
	releaseAwait(t, "wiring, not the property: whole connection was not cut", func() bool { return f.run.Snapshot().ConnectionsCut == 1 })
	f.close(11)
	o := f.finish()
	f.terminal(o, 0)
	if len(p.of(t, "exchange")) != 0 || len(p.of(t, "connection_done")) != 0 {
		t.Error("connection refused whole reached extension")
	}
}

func TestExtensionReleaseMetadataOnlyDone(t *testing.T) {
	f := newReleaseFixture(t, 1, 100, 20000, false, -1)
	p := f.peers[0]
	f.pair(11, "/metadata")
	f.close(11)
	o := f.finish()
	f.terminal(o, 0)
	f.done(p, 11, 0)
	if len(p.of(t, "exchange")) != 0 {
		t.Error("write_content false sent an exchange")
	}
}

func TestExtensionReleaseCompressedTailPlateausWhileOpen(t *testing.T) {
	f := newReleaseFixture(t, 1, 4, 20000, true, -1)
	p := f.peers[0]
	var encoded bytes.Buffer
	z := gzip.NewWriter(&encoded)
	if _, err := z.Write([]byte("compressed response")); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	const exchanges = 96
	var warmMaximum int64
	for index := range exchanges {
		f.transfer(11, fragment.Sent, fmt.Sprintf("GET /tail/%03d HTTP/1.1\r\nHost: api\r\nAuthorization: removed-sentinel\r\n\r\n", index))
		if index == 0 {
			f.transfer(11, fragment.Received, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n%s", encoded.Len(), encoded.String()))
		} else {
			f.transfer(11, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntail")
		}
		f.route()
		m := p.exchange(t, index)
		f.identity(m, 11, index)
		out, ok := m["output"].(map[string]any)
		if !ok || out["state"] != "excluded" {
			t.Errorf("decidable excluded exchange %d was not marked excluded: %v", index, m)
		}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("removed-sentinel")) {
			t.Errorf("excluded exchange %d exposed a removed value", index)
		}
		p.answer(t, m, `{"outcome":"unchanged"}`)
		releaseAwait(t, "excluded exchange did not settle and release its copies", func() bool {
			o := f.run.Snapshot()
			s := f.store.Stats()
			return len(o.Extensions) == 1 && o.Extensions[0].Unchanged == uint64(index+1) &&
				o.Extensions[0].Pending == 0 && s.Bytes == 0 && s.Policy == 0
		})
		s := f.store.Stats()
		held := s.Bytes + s.Parsing + s.Policy
		if index < 3 {
			warmMaximum = max(warmMaximum, held)
		} else if held > warmMaximum {
			t.Errorf("excluded tail retained work grew at exchange %d: %d exceeds settled warmup maximum %d", index, held, warmMaximum)
		}
		if f.run.Snapshot().ConnectionsCut != 0 {
			t.Fatalf("ordinary compressed tail cut its open connection at exchange %d", index)
		}
		f.noDone(p)
	}
	if len(f.out.exchanges()) != 0 {
		t.Error("excluded tail was written as eligible exchanges")
	}
	f.close(11)
	o := f.finish()
	f.terminal(o, exchanges)
	f.done(p, 11, exchanges)
	if len(p.of(t, "exchange")) != exchanges {
		t.Errorf("excluded tail delivery count=%d want %d", len(p.of(t, "exchange")), exchanges)
	}
}

func TestExtensionReleaseCaptureLossSettlesWaitingExchanges(t *testing.T) {
	f := newReleaseFixture(t, 2, 100, 20000, true, -1)
	f.pair(11, "/first")
	first := f.peers[0].exchange(t, 0)
	f.identity(first, 11, 0)
	f.pair(11, "/second")
	f.pair(11, "/third")
	releaseAwait(t, "wiring, not the property: three fixture exchanges never took ids before loss", func() bool {
		return f.run.Snapshot().ExchangeIDs == 3
	})
	if len(f.peers[0].of(t, "exchange")) != 1 || len(f.peers[1].of(t, "exchange")) != 0 {
		t.Fatal("wiring, not the property: the first call did not hold the waiting exchange population")
	}
	var pressure []held.Slot
	for range 64 {
		d := f.gate.Admit(probe.DeliveryTransfer, true)
		if !d.Admitted || d.Slot == nil {
			t.Fatal("wiring, not the property: could not fill the delivery gate")
		}
		pressure = append(pressure, d.Slot)
	}
	t.Cleanup(func() {
		for _, slot := range pressure {
			slot.Refund(held.Unretained)
		}
	})
	d := f.gate.Admit(probe.DeliveryTransfer, true)
	if d.Admitted {
		t.Fatal("wiring, not the property: delivery pressure did not refuse a transfer")
	}
	f.stamp++
	numbers := f.numbers[11]
	numbers[fragment.Sent]++
	f.numbers[11] = numbers
	f.capture.Refused(probe.Transfer{Process: fragment.Process{PID: 71, StartTime: 19},
		Instance: admission.Instance{Namespace: admission.Namespace{Device: 3, Inode: 7}, PID: 71, Start: admission.Determinate(19), Generation: 1},
		Endpoint: 11, Stamp: f.stamp, Sequence: probe.Sequence{Occupancy: 11, Number: numbers[fragment.Sent], Born: true},
		Direction: fragment.Sent, Measured: true, Length: 1, Payload: []byte("x"), At: time.Now(), Slot: d.Slot})
	if f.gate.Snapshot().InputRefused != 1 || f.capture.Stats().GateRefused != 1 || f.losses[11].Reason() == "" {
		t.Fatal("wiring, not the property: capture loss did not reach the waiting connection's token")
	}
	for _, slot := range pressure {
		slot.Refund(held.Unretained)
	}
	pressure = nil
	// Keep accepting after the loss: an erroneously sent exchange must reach
	// the no-send assertion, rather than strand Finish on an unanswered call.
	for _, p := range f.peers {
		if err := os.WriteFile(filepath.Join(p.dir, "answer-all"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.close(11)
	f.peers[0].answer(t, first, `{"outcome":"unchanged"}`)
	o := f.finish()
	f.terminal(o, 3)
	for i, p := range f.peers {
		f.done(p, 11, 3)
		want := 0
		if i == 0 {
			want = 1
		}
		if got := len(p.of(t, "exchange")); got != want {
			t.Errorf("extension %d received %d exchanges, want %d sent before capture loss", i, got, want)
		}
	}
	if len(o.Extensions) != 2 {
		t.Fatalf("seal has %d extension accounts, want both configured extensions", len(o.Extensions))
	}
	for i, counts := range o.Extensions {
		if counts.FailedBy["unavailable"] != 0 {
			t.Errorf("capture loss was mislabelled unavailable: %+v", counts)
		}
		wantWithdrawn := uint64(2 + i)
		if counts.FailedBy["withdrawn"] != wantWithdrawn || counts.Failed != wantWithdrawn ||
			counts.Unchanged != 3-wantWithdrawn || counts.Changed != 0 {
			t.Errorf("extension %d did not count each exchange still waiting there as withdrawn: want %d, got %+v", i, wantWithdrawn, counts)
		}
	}
	if len(f.out.exchanges()) != 0 {
		t.Error("capture loss allowed a waiting exchange to be written")
	}
}
