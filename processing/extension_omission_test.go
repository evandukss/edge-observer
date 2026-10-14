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
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contentcoding"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/reconstruct"
)

// The child speaks only JSON. Its input reader keeps running while a result is
// held, so an overlapping exchange or an early done remains observable.
func TestExtensionOmissionPeer(t *testing.T) {
	dir := os.Getenv("OBSERVER_OMISSION_PEER")
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
			if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "ready", "protocol": "observer.extension/2"}); err != nil {
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

type omissionPeer struct{ dir string }

func (p omissionPeer) messages(t *testing.T) []map[string]any {
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
func (p omissionPeer) of(t *testing.T, kind string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, m := range p.messages(t) {
		if m["type"] == kind {
			out = append(out, m)
		}
	}
	return out
}
func omissionAwait(t *testing.T, why string, f func() bool) {
	t.Helper()
	end := time.Now().Add(5 * time.Second)
	for !f() {
		if time.Now().After(end) {
			t.Fatal(why)
		}
		time.Sleep(time.Millisecond)
	}
}
func (p omissionPeer) exchange(t *testing.T, n int) map[string]any {
	t.Helper()
	omissionAwait(t, "exchange did not reach the ready extension while the connection remained open", func() bool { return len(p.of(t, "exchange")) > n })
	return p.of(t, "exchange")[n]
}
func (p omissionPeer) answer(t *testing.T, m map[string]any, result string) {
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

type omissionOutput struct {
	mu   sync.Mutex
	got  []processing.Artifact
	drop int
}

func (o *omissionOutput) WriteApproved(_ context.Context, a processing.Approved) error {
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
func (o *omissionOutput) exchanges() []processing.Artifact {
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

type omissionFixture struct {
	t           *testing.T
	mu          sync.Mutex
	charges     []processing.DecodeCharge
	run         *processing.Run
	store       *intake.Store
	gate        *probe.DeliveryGate
	capture     *capture.Session
	out         *omissionOutput
	peers       []omissionPeer
	events      chan extension.Event
	taken       atomic.Int64
	transferred int64
	stamp       uint64
	numbers     map[uint64][3]uint64
	ids         map[uint64]fragment.ConnectionID
	losses      map[uint64]*held.Loss
}

type omissionCaptureSink struct{ f *omissionFixture }

func (s omissionCaptureSink) Write(r fragment.Record) error {
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
func (s omissionCaptureSink) Connection(r connection.Record) error {
	s.f.transferred++
	return s.f.store.Connection(r)
}

func newOmissionFixture(t *testing.T, n int, content bool, removal map[string]any, bound int) *omissionFixture {
	t.Helper()
	f := &omissionFixture{t: t, out: &omissionOutput{drop: -1}, events: make(chan extension.Event, 1000), numbers: map[uint64][3]uint64{}, ids: map[uint64]fragment.ConnectionID{}, losses: map[uint64]*held.Loss{}}
	var err error
	f.store, err = intake.New(8 << 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	var entries []any
	fields := []string{"request.line", "request.headers", "request.body", "response.line", "response.headers", "response.body", "connection"}
	if !content {
		fields = []string{"connection"}
	}
	for i := 0; i < n; i++ {
		p := omissionPeer{dir: t.TempDir()}
		f.peers = append(f.peers, p)
		entries = append(entries, map[string]any{"name": fmt.Sprintf("peer%d", i), "command": []string{"/usr/bin/env", "OBSERVER_OMISSION_PEER=" + p.dir, os.Args[0], "-test.run=^TestExtensionOmissionPeer$"}, "fields": fields, "timeout_ms": 20000})
	}
	doc, err := json.Marshal(map[string]any{"version": "observer.config/1", "output": "/var/lib/observer", "watch": []any{map[string]any{"name": "api", "exe": "/usr/bin/php"}}, "extensions": entries, "write_content": content, "remove": removal})
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
	options := processing.Options{Plan: compiled.Plan, Session: "omission-session", PolicyRevision: "omission-policy", Intake: f.store, Gate: gate, Output: f.out, Derived: writer, ConnectionInput: 100, Limits: reconstruct.Limits{HTTP: http1.Limits{MaxBodyBytes: bound}}, Supervision: func(e extension.Event) { f.events <- e }, Taken: func(_ int, _ fragment.Process, _ fragment.ConnectionID) { f.taken.Add(1) }}
	options = processing.ObserveDecodeCharges(options, func(c processing.DecodeCharge) { f.mu.Lock(); defer f.mu.Unlock(); f.charges = append(f.charges, c) })
	f.run, err = processing.Start(options)
	if err != nil {
		t.Fatalf("wiring, not the property: worker start: %v", err)
	}
	t.Cleanup(func() { _ = f.run.Close() })
	for range n {
		f.event(extension.Ready)
	}
	s := omissionCaptureSink{f}
	f.capture = capture.Recording(s, s)
	f.capture.Observing(probe.Capability{Backend: probe.BPF, Payload: true, Lifecycle: true})
	return f
}
func (f *omissionFixture) event(kind extension.EventKind) extension.Event {
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
func (f *omissionFixture) transfer(handle uint64, d fragment.Direction, body string) {
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
func (f *omissionFixture) route() {
	f.t.Helper()
	f.run.Route()
	omissionAwait(f.t, "wiring, not the property: captured inputs did not reach the worker", func() bool { return f.taken.Load() == f.transferred })
}
func (f *omissionFixture) close(handle uint64) {
	f.stamp++
	n := f.numbers[handle]
	f.capture.Closed(probe.Connection{Process: fragment.Process{PID: 71, StartTime: 19}, Instance: admission.Instance{Namespace: admission.Namespace{Device: 3, Inode: 7}, PID: 71, Start: admission.Determinate(19), Generation: 1}, Endpoint: handle, Stamp: f.stamp, Sequence: probe.Sequence{Occupancy: handle, Born: true}, Final: probe.Final{Known: true, Sent: probe.Terminal{Last: n[fragment.Sent]}, Received: probe.Terminal{Last: n[fragment.Received]}}, At: time.Now()})
	f.route()
}
func (f *omissionFixture) finish() processing.Outcome {
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
func (f *omissionFixture) identity(m map[string]any, handle uint64, index int) string {
	f.t.Helper()
	want := strconv.FormatUint(uint64(f.ids[handle]), 10)
	if m["connection_id"] != want || m["index"] != float64(index) {
		f.t.Errorf("exchange identity/index=%v/%v want %s/%d", m["connection_id"], m["index"], want, index)
	}
	if _, ok := m["ids"]; ok {
		f.t.Error("extension exchange carries a final id range")
	}
	if _, ok := m["connection"]; !ok {
		f.t.Error("selected connection projection was not sent")
	}
	id, ok := m["id"].(string)
	if !ok {
		f.t.Fatalf("missing exchange id: %v", m)
	}
	value, err := strconv.ParseUint(id, 10, 64)
	if err != nil || value == 0 {
		f.t.Fatalf("invalid exchange id %q", id)
	}
	if value != uint64(index+1) {
		f.t.Errorf("exchange id=%d want %d for this single-connection fixture", value, index+1)
	}
	return id
}
func (f *omissionFixture) done(p omissionPeer, handle uint64, count int) {
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
		if omissionUint(f.t, m["count"]) != uint64(count) {
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
func (f *omissionFixture) terminal(o processing.Outcome, count uint64) {
	f.t.Helper()
	if o.ExchangeIDs != count {
		f.t.Errorf("issued=%d want fixture count %d", o.ExchangeIDs, count)
	}
	if len(o.Extensions) != len(f.peers) {
		f.t.Errorf("extension population=%d want %d configured peers", len(o.Extensions), len(f.peers))
	}
	for _, c := range o.Extensions {
		if c.Considered != count || c.Pending != 0 || c.Changed+c.Unchanged+c.Failed != count {
			f.t.Errorf("extension outcomes did not settle fixture population: %+v", c)
		}
	}
}

func omissionObject(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected an object, got %#v", v)
	}
	return m
}

func omissionKeys(t *testing.T, m map[string]any, keys ...string) {
	t.Helper()
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	for k := range m {
		if !want[k] {
			t.Errorf("unexpected schema member %q in %#v", k, m)
		}
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Errorf("missing schema member %q in %#v", k, m)
		}
	}
}

func omissionMessage(t *testing.T, m map[string]any, side string) map[string]any {
	t.Helper()
	ex := omissionObject(t, m["exchange"])
	s := omissionObject(t, ex[side])
	if s["state"] != "present" {
		t.Fatalf("%s is not present: %#v", side, s)
	}
	return omissionObject(t, s["message"])
}

func omissionUint(t *testing.T, v any) uint64 {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("count is not a decimal string: %#v", v)
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != s {
		t.Fatalf("invalid whole decimal count %q: %v", s, err)
	}
	return n
}

func omissionGzip(t *testing.T, body []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := z.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func omissionWire(request bool, path, coding string, body []byte) string {
	line := "HTTP/1.1 200 OK\r\n"
	if request {
		line = "POST " + path + " HTTP/1.1\r\nHost: api\r\n"
	}
	if coding != "" {
		line += "Content-Encoding: " + coding + "\r\n"
	}
	return line + "Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + string(body)
}

func (f *omissionFixture) bodyPair(requestCoding string, request []byte, responseCoding string, response []byte) {
	f.transfer(11, fragment.Sent, omissionWire(true, "/body", requestCoding, request))
	f.transfer(11, fragment.Received, omissionWire(false, "", responseCoding, response))
	f.route()
}

func (f *omissionFixture) auto() {
	for _, p := range f.peers {
		if err := os.WriteFile(filepath.Join(p.dir, "answer-all"), nil, 0600); err != nil {
			f.t.Fatal(err)
		}
	}
}

// The control proves the real supervisor and every selected field are wired
// before any encoded input is offered. No output of the subject supplies the
// population: there is exactly one control per configured peer.
func (f *omissionFixture) control() {
	f.t.Helper()
	f.bodyPair("", []byte(`{"control_request":1}`), "", []byte(`{"control_response":2}`))
	for _, p := range f.peers {
		omissionAwait(f.t, "wiring, not the property: identity control did not reach the ready peer", func() bool { return len(p.of(f.t, "exchange")) == 1 })
		m := p.of(f.t, "exchange")[0]
		for _, side := range []string{"request", "response"} {
			s := omissionObject(f.t, omissionObject(f.t, m["exchange"])[side])
			msg, ok := s["message"].(map[string]any)
			if !ok || msg["body"] == nil || msg["headers"] == nil || msg["structure"] == nil {
				f.t.Fatalf("wiring, not the property: all-fields control missing %s projection: %v", side, s)
			}
		}
		if omissionMessage(f.t, m, "request")["target"] != "/body" {
			f.t.Fatal("wiring, not the property: control identity did not join")
		}
		p.answer(f.t, m, `{"outcome":"unchanged"}`)
	}
	omissionAwait(f.t, "wiring, not the property: control did not reach the sink", func() bool { return len(f.out.exchanges()) == 1 })
}

func omissionState(t *testing.T, m map[string]any, reason string) {
	t.Helper()
	out := omissionObject(t, m["output"])
	want := map[string]any{"state": "eligible"}
	if reason != "" {
		want = map[string]any{"state": "excluded", "reason": reason}
	}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("output classification=%v, want %v", out, want)
	}
}

func omissionAssert(t *testing.T, m map[string]any, side, reason string, wire []byte) {
	t.Helper()
	omissionKeys(t, m, "type", "id", "connection_id", "index", "output", "exchange", "connection")
	ex := omissionObject(t, m["exchange"])
	omissionKeys(t, ex, "index", "complete", "request", "response", "removed")
	omissionKeys(t, omissionObject(t, ex[side]), "state", "message")
	msg := omissionMessage(t, m, side)
	keys := []string{"kind", "complete", "framed", "defect", "protocol", "headers", "trailers", "framing", "body", "structure"}
	if side == "request" {
		keys = append(keys, "method", "target")
	} else {
		keys = append(keys, "status", "reason")
	}
	omissionKeys(t, msg, keys...)
	body := omissionObject(t, msg["body"])
	omissionKeys(t, body, "length", "kept", "holed", "elided", "encoding", "content")
	if body["kept"] != "" {
		t.Errorf("undecoded body bytes escaped in kept: %#v", body["kept"])
	}
	if omissionUint(t, body["length"]) != uint64(len(wire)) || body["holed"] != "0" || body["elided"] != "0" || body["encoding"] != "base64" {
		t.Errorf("omission lost captured extent or encoding: %v", body)
	}
	if !reflect.DeepEqual(body["content"], map[string]any{"state": "omitted", "reason": reason}) {
		t.Errorf("omission marker=%v, want the exchange reason %s", body["content"], reason)
	}
	if !reflect.DeepEqual(msg["structure"], map[string]any{"state": "omitted"}) {
		t.Errorf("undecoded structure/shape escaped: %#v", msg["structure"])
	}
	removed, ok := ex["removed"].([]any)
	if !ok {
		t.Fatalf("removed is not an array: %#v", ex["removed"])
	}
	for _, v := range removed {
		r := omissionObject(t, v)
		field, _ := r["field"].(string)
		if r["message"] == side && strings.HasPrefix(field, "message.body") {
			t.Errorf("policy evidence was derived from an omitted body: %v", r)
		}
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"OPAQUE_MEMBER_SENTINEL", base64.StdEncoding.EncodeToString(wire)} {
		if needle != "" && bytes.Contains(encoded, []byte(needle)) {
			t.Errorf("payload or field name escaped outside the omitted schema: %q", needle)
		}
	}
	omissionNoSentinel(t, m)
}

func omissionNoSentinel(t *testing.T, value any) {
	t.Helper()
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			omissionNoSentinel(t, key)
			omissionNoSentinel(t, child)
		}
	case []any:
		for _, child := range v {
			omissionNoSentinel(t, child)
		}
	case string:
		if strings.Contains(v, "OPAQUE_MEMBER_SENTINEL") {
			t.Error("undecoded field name reached the wire")
		}
		if decoded, err := base64.StdEncoding.DecodeString(v); err == nil && bytes.Contains(decoded, []byte("OPAQUE_MEMBER_SENTINEL")) {
			t.Error("undecoded field name reached the wire in base64")
		}
	}
}

func omissionRemoval(structure, header bool) map[string]any {
	r := map[string]any{"headers": []string{"authorization"}}
	if header {
		r["headers"] = []string{"authorization", "content-encoding"}
	}
	if structure {
		r["body_values"] = []string{"request", "response"}
	}
	return r
}

func (f *omissionFixture) refunds(requireDecode bool) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	type key struct {
		connection fragment.ConnectionID
		index      int
		request    bool
		charge     contentcoding.Charge
	}
	live := map[key]int{}
	reserved := 0
	for _, c := range f.charges {
		k := key{c.Connection, c.Index, c.Request, c.Charge}
		switch c.Event {
		case processing.ChargeReserved:
			live[k]++
			reserved++
		case processing.ChargeReturned:
			live[k]--
			if live[k] < 0 {
				f.t.Errorf("charge returned without ownership, or twice: %+v", c)
			}
		}
	}
	if requireDecode && reserved == 0 {
		f.t.Error("no decoder reservation observed for the encoded exchange")
	}
	for k, n := range live {
		if n != 0 {
			f.t.Errorf("decoder charge not returned exactly once: %+v outstanding=%d", k, n)
		}
	}
	s := f.store.Stats()
	if s.Bytes != 0 || s.Parsing != 0 || s.Policy != 0 || s.Leased != 0 || s.Queued != 0 {
		f.t.Errorf("finished connection retained charges: %+v", s)
	}
}

func TestUndecodedBodyOmissionSchema(t *testing.T) {
	opaque := []byte(`{"OPAQUE_MEMBER_SENTINEL":{"secret":"value"}}`)
	badChecksum := omissionGzip(t, opaque)
	badChecksum[len(badChecksum)-8] ^= 1
	omissionLateChecksumGuard(t, badChecksum, opaque)
	// A raw zstd block in each of four complete frames, with windows 1, 4,
	// 16 and 64 KiB. Each growth exceeds the preceding retained capacity.
	var costly []byte
	for _, exponent := range []byte{0, 2, 4, 6} {
		block := uint32(len(opaque))<<3 | 1
		costly = append(costly, 0x28, 0xb5, 0x2f, 0xfd, 0, exponent<<3, byte(block), byte(block>>8), byte(block>>16))
		costly = append(costly, opaque...)
	}
	for _, c := range []struct {
		name, coding, reason string
		body                 []byte
		bound                int
		header               bool
	}{
		{"unknown-coding-json", "opaque-test", "content_coding_unsupported", opaque, 1 << 20, false},
		{"gzip-json", "gzip", "content_decoding_failed", opaque, 1 << 20, false},
		{"removed-coding", "opaque-test", "content_coding_unsupported", opaque, 1 << 20, true},
		{"late-checksum", "gzip", "content_decoding_failed", badChecksum, 1 << 20, false},
		{"later-member", "gzip", "content_decoding_failed", append(omissionGzip(t, []byte(`{"first":1}`)), badChecksum...), 1 << 20, false},
		{"decoded-limit", "gzip", "content_decoded_too_large", omissionGzip(t, []byte(`{"OPAQUE_MEMBER_SENTINEL":"`+strings.Repeat("x", 2000)+`"}`)), 1024, false},
		{"history-limit", "zstd", "content_decoding_too_costly", costly, 1 << 20, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newOmissionFixture(t, 1, true, omissionRemoval(true, c.header), c.bound)
			f.control()
			f.auto()
			f.bodyPair("", []byte(`{"ordinary":1}`), c.coding, c.body)
			f.close(11)
			o := f.finish()
			messages := f.peers[0].of(t, "exchange")
			if len(messages) != 2 {
				t.Fatalf("got %d exchanges, want control and encoded pair", len(messages))
			}
			m := messages[1]
			f.identity(m, 11, 1)
			omissionState(t, m, c.reason)
			omissionAssert(t, m, "response", c.reason, c.body)
			if c.header {
				b, _ := json.Marshal(m)
				if bytes.Contains(b, []byte(c.coding)) {
					t.Error("removed Content-Encoding value was reintroduced")
				}
			}
			f.terminal(o, 2)
			counts := map[string]uint64{"content_coding_unsupported": o.Excluded.ContentCodingUnsupported, "content_decoding_failed": o.Excluded.ContentDecodingFailed, "content_decoded_too_large": o.Excluded.ContentDecodedTooLarge, "content_decoding_too_costly": o.Excluded.ContentDecodingTooCostly}
			if counts[c.reason] != 1 || o.Excluded.Total() != 1 {
				t.Errorf("exclusion count=%+v want exactly one %s", o.Excluded, c.reason)
			}
			f.done(f.peers[0], 11, 2)
			if len(f.out.exchanges()) != 1 {
				t.Error("an excluded exchange reached the sink")
			}
			f.refunds(c.reason != "content_coding_unsupported")
		})
	}
}

func omissionLateChecksumGuard(t *testing.T, encoded, plain []byte) {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("wiring, not the property: corrupt checksum fixture never reached decoding: %v", err)
	}
	got, err := io.ReadAll(r)
	if closeErr := r.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if !bytes.Equal(got, plain) || !errors.Is(err, gzip.ErrChecksum) {
		t.Fatalf("wiring, not the property: fixture did not yield full plaintext before checksum error: bytes=%q error=%v", got, err)
	}
}

func TestDecodedBodyProjectionAndRemovedCoding(t *testing.T) {
	for _, c := range []struct {
		name   string
		header bool
		member bool
	}{
		{"header-removed-false", false, true},
		{"header-removed-true", true, true},
		{"without-body-rule", false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			header := c.header
			removal := omissionRemoval(false, header)
			plain := []byte(`{"visible":7}`)
			if c.member {
				removal["json"] = map[string]any{"response": []string{"/secret"}}
				plain = []byte(`{"visible":7,"secret":"captured-secret"}`)
			}
			f := newOmissionFixture(t, 1, true, removal, 1<<20)
			f.control()
			wire := omissionGzip(t, plain)
			f.auto()
			f.bodyPair("", nil, "gzip", wire)
			f.close(11)
			o := f.finish()
			ms := f.peers[0].of(t, "exchange")
			if len(ms) != 2 {
				t.Fatalf("got %d exchanges, want 2", len(ms))
			}
			omissionState(t, ms[1], "")
			omissionDecoded(t, omissionMessage(t, ms[1], "response"), len(wire), len(plain), header, `{"visible":7}`)
			f.terminal(o, 2)
			f.done(f.peers[0], 11, 2)
			lines := f.out.exchanges()
			if len(lines) != 2 {
				t.Fatalf("sink got %d exchanges, want 2", len(lines))
			}
			omissionDecoded(t, omissionArtifactMessage(t, lines[1], "response"), len(wire), len(plain), header, `{"visible":7}`)
			f.refunds(true)
		})
	}
}

func omissionArtifactMessage(t *testing.T, a processing.Artifact, side string) map[string]any {
	t.Helper()
	if a.Reconstruction == nil || len(a.Reconstruction.Exchanges) != 1 {
		t.Fatalf("sink reconstruction is not one exchange: %+v", a)
	}
	b, err := json.Marshal(a.Reconstruction.Exchanges[0])
	if err != nil {
		t.Fatal(err)
	}
	var ex map[string]any
	if err := json.Unmarshal(b, &ex); err != nil {
		t.Fatal(err)
	}
	return omissionMessage(t, map[string]any{"exchange": ex}, side)
}

func omissionDecoded(t *testing.T, msg map[string]any, captured, decoded int, headerRemoved bool, wantJSON string) {
	t.Helper()
	body := omissionObject(t, msg["body"])
	want := map[string]any{"state": "decoded", "length": strconv.Itoa(decoded)}
	if !headerRemoved {
		want["codings"] = []any{"gzip"}
	}
	if !reflect.DeepEqual(body["content"], want) {
		t.Errorf("captured transformation metadata=%v want %v", body["content"], want)
	}
	if omissionUint(t, body["length"]) != uint64(captured) {
		t.Error("replacement/decoding changed captured extent")
	}
	kept, ok := body["kept"].(string)
	if !ok {
		t.Fatalf("kept is not base64 text: %v", body)
	}
	plain, err := base64.StdEncoding.DecodeString(kept)
	if err != nil {
		t.Fatal(err)
	}
	var gotJSON, expected any
	if err := json.Unmarshal(plain, &gotJSON); err != nil {
		t.Errorf("decoded content is not JSON: %q: %v", plain, err)
		return
	}
	if err := json.Unmarshal([]byte(wantJSON), &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotJSON, expected) {
		t.Errorf("sanitised decoded content=%s want %s", plain, wantJSON)
	}
	if headerRemoved {
		for _, v := range msg["headers"].([]any) {
			if strings.EqualFold(omissionObject(t, v)["name"].(string), "Content-Encoding") {
				t.Error("removed coding header reached the projection")
			}
		}
	}
	shape := omissionObject(t, msg["structure"])
	if shape["state"] != "derived" || shape["shape"] == nil {
		t.Errorf("decoded shape was not derived again: %v", shape)
	}
	if shape["shape"] != nil {
		fields, ok := omissionObject(t, shape["shape"])["fields"].([]any)
		wantFields := expected.(map[string]any)
		if !ok || len(fields) != len(wantFields) {
			t.Errorf("decoded shape fields=%v want names in %s", fields, wantJSON)
		}
		seen := map[string]bool{}
		for _, v := range fields {
			field := omissionObject(t, v)
			name, _ := field["name"].(string)
			if _, ok := wantFields[name]; !ok || seen[name] {
				t.Errorf("unexpected/duplicate decoded shape field %q", name)
			}
			seen[name] = true
		}
	}
	b, _ := json.Marshal(msg)
	if bytes.Contains(b, []byte("secret")) {
		t.Error("removed JSON member or its shape reached the projection")
	}
}

func TestDecodedSideSurvivesOtherSideExclusion(t *testing.T) {
	for _, decodedSide := range []string{"request", "response"} {
		t.Run(decodedSide, func(t *testing.T) {
			removal := omissionRemoval(false, true)
			removal["json"] = map[string]any{decodedSide: []string{"/secret"}}
			f := newOmissionFixture(t, 1, true, removal, 1<<20)
			f.control()
			plain := []byte(`{"visible":8,"secret":"captured-secret"}`)
			good := omissionGzip(t, plain)
			bad := []byte(`{"OPAQUE_MEMBER_SENTINEL":"not gzip"}`)
			request, response, omitted := good, bad, "response"
			if decodedSide == "response" {
				request, response, omitted = bad, good, "request"
			}
			f.bodyPair("gzip", request, "gzip", response)
			m := f.peers[0].exchange(t, 1)
			omissionState(t, m, "content_decoding_failed")
			omissionAssert(t, m, omitted, "content_decoding_failed", bad)
			omissionDecoded(t, omissionMessage(t, m, decodedSide), len(good), len(plain), true, `{"visible":8}`)
			f.peers[0].answer(t, m, `{"outcome":"changed","changes":{"`+decodedSide+`.body":{"kept":"e30="}}}`)
			f.close(11)
			o := f.finish()
			if len(o.Extensions) != 1 || o.Extensions[0].FailedBy["excluded"] != 1 || o.Extensions[0].Changed != 0 {
				t.Errorf("change accepted on an excluded exchange with a decoded side: %+v", o.Extensions)
			}
			if len(f.out.exchanges()) != 1 {
				t.Error("excluded decoded side reached the approved sink")
			}
			f.refunds(true)
		})
	}
}

func TestOmittedExchangeContinuesOrderedChainAndCountsOnce(t *testing.T) {
	f := newOmissionFixture(t, 2, true, omissionRemoval(true, false), 1<<20)
	f.control()
	opaque := []byte(`{"OPAQUE_MEMBER_SENTINEL":1}`)
	f.bodyPair("opaque-test", opaque, "opaque-test", opaque)
	first := f.peers[0].exchange(t, 1)
	f.identity(first, 11, 1)
	for _, side := range []string{"request", "response"} {
		omissionAssert(t, first, side, "content_coding_unsupported", opaque)
	}
	// Queue later traffic while the excluded call is outstanding. The peer
	// reader remains live and records any overlap, even while withholding a result.
	f.bodyPair("", []byte(`{"later_request":1}`), "", []byte(`{"later_response":2}`))
	f.bodyPair("", []byte(`{"last_request":3}`), "", []byte(`{"last_response":4}`))
	f.peers[0].answer(t, first, `{"outcome":"changed","changes":{"response.body":{"kept":"e30="}}}`)
	second := f.peers[1].exchange(t, 1)
	if second["id"] != first["id"] {
		t.Error("two extensions received different ids for one exchange")
	}
	omissionState(t, second, "content_coding_unsupported")
	for _, side := range []string{"request", "response"} {
		omissionAssert(t, second, side, "content_coding_unsupported", opaque)
	}
	f.peers[1].answer(t, second, `{"outcome":"unchanged"}`)
	for index := 2; index < 4; index++ {
		for _, p := range f.peers {
			m := p.exchange(t, index)
			f.identity(m, 11, index)
			omissionState(t, m, "")
			p.answer(t, m, `{"outcome":"unchanged"}`)
		}
	}
	omissionAwait(t, "later eligible exchanges did not reach the sink on the open connection", func() bool { return len(f.out.exchanges()) == 3 })
	for _, p := range f.peers {
		if len(p.of(t, "connection_done")) != 0 {
			t.Error("connection_done sent before the connection ended")
		}
	}
	f.close(11)
	o := f.finish()
	f.terminal(o, 4)
	for _, p := range f.peers {
		f.done(p, 11, 4)
	}
	for _, p := range f.peers {
		if len(p.of(t, "exchange")) != 4 {
			t.Error("extension exchange population differs from four offered pairs")
		}
	}
	if len(o.Extensions) != 2 {
		t.Fatalf("extension population=%d want 2", len(o.Extensions))
	}
	if o.Extensions[0].FailedBy["excluded"] != 1 || o.Extensions[0].Changed != 0 {
		t.Errorf("excluded replacement not rejected: %+v", o.Extensions[0])
	}
	if o.Excluded != (processing.Exclusions{ContentCodingUnsupported: 1}) {
		t.Errorf("exclusion multiplied by sides/extensions: %+v", o.Excluded)
	}
	lines := f.out.exchanges()
	for i, index := range []int{0, 2, 3} {
		if lines[i].Index == nil || *lines[i].Index != index {
			t.Errorf("sink order[%d]=%v, want %d", i, lines[i].Index, index)
		}
	}
	f.out.mu.Lock()
	connections := 0
	for _, a := range f.out.got {
		if a.Record != "connection" {
			continue
		}
		connections++
		want := processing.ExcludedExchanges{ContentCodingUnsupported: "1", ContentDecodingFailed: "0", ContentDecodedTooLarge: "0", ContentDecodingTooCostly: "0"}
		if a.ExcludedExchanges == nil || *a.ExcludedExchanges != want {
			t.Errorf("connection exclusion totals=%+v want %+v", a.ExcludedExchanges, want)
		}
	}
	f.out.mu.Unlock()
	if connections != 1 {
		t.Errorf("sink connection population=%d want 1", connections)
	}
	f.refunds(false)
}

func TestTerminalDefectStillOmitsEncodedBody(t *testing.T) {
	opaque := []byte(`{"OPAQUE_MEMBER_SENTINEL":1}`)
	// Both stops leave message boundaries readable. A valid Content-Encoding
	// on its own is never the terminal cause: malformed coding syntax or an
	// unsupported transfer coding stops this exchange and its following pair.
	for _, c := range []struct{ name, response, reason string }{
		{"malformed-coding-list", omissionWire(false, "", "(", opaque), "unsupported_message"},
		{"transfer-coding", fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nTransfer-Encoding: gzip, chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(opaque), opaque), "unsupported_message"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newOmissionFixture(t, 1, true, omissionRemoval(true, true), 1<<20)
			f.control()
			f.transfer(11, fragment.Sent, omissionWire(true, "/body", "gzip", opaque))
			f.transfer(11, fragment.Received, c.response)
			f.route()
			f.bodyPair("", []byte(`{"later_request":1}`), "", []byte(`{"later_response":2}`))
			f.auto()
			f.close(11)
			o := f.finish()
			ms := f.peers[0].of(t, "exchange")
			if len(ms) != 3 {
				t.Fatalf("terminal fixture delivered %d exchanges, want 3", len(ms))
			}
			for _, index := range []int{1, 2} {
				f.identity(ms[index], 11, index)
				omissionState(t, ms[index], c.reason)
			}
			for _, side := range []string{"request", "response"} {
				omissionAssert(t, ms[1], side, c.reason, opaque)
			}
			if o.Excluded.Total() != 0 {
				t.Errorf("terminal stop counted as isolated exclusion: %+v", o.Excluded)
			}
			if len(f.out.exchanges()) != 1 {
				t.Error("terminal defect allowed later exchanges into the sink")
			}
			f.done(f.peers[0], 11, 3)
			f.refunds(false)
		})
	}
}

func TestDecodedReplacementIsSanitisedWithoutAnotherDecode(t *testing.T) {
	removal := omissionRemoval(false, false)
	removal["json"] = map[string]any{"response": []string{"/secret"}}
	f := newOmissionFixture(t, 2, true, removal, 1<<20)
	f.control()
	plain := []byte(`{"visible":1,"secret":"captured-secret"}`)
	wire := omissionGzip(t, plain)
	f.bodyPair("", nil, "gzip", wire)
	m := f.peers[0].exchange(t, 1)
	omissionState(t, m, "")
	omissionDecoded(t, omissionMessage(t, m, "response"), len(wire), len(plain), false, `{"visible":1}`)
	replacement := base64.StdEncoding.EncodeToString([]byte(`{"replacement":22,"secret":"replacement-secret"}`))
	f.peers[0].answer(t, m, `{"outcome":"changed","changes":{"response.body":{"kept":"`+replacement+`"}}}`)
	next := f.peers[1].exchange(t, 1)
	omissionState(t, next, "")
	omissionDecoded(t, omissionMessage(t, next, "response"), len(wire), len(plain), false, `{"replacement":22}`)
	f.peers[1].answer(t, next, `{"outcome":"unchanged"}`)
	f.close(11)
	o := f.finish()
	if len(o.Extensions) != 2 || o.Extensions[0].Changed != 1 || o.Extensions[0].Failed != 0 {
		t.Errorf("eligible decoded replacement was not accepted: %+v", o.Extensions)
	}
	lines := f.out.exchanges()
	if len(lines) != 2 {
		t.Fatalf("sink received %d exchanges want 2", len(lines))
	}
	omissionDecoded(t, omissionArtifactMessage(t, lines[1], "response"), len(wire), len(plain), false, `{"replacement":22}`)
	f.mu.Lock()
	workspaces := 0
	for _, c := range f.charges {
		if c.Event == processing.ChargeReserved && c.Charge.Kind == contentcoding.WorkspaceCharge {
			workspaces++
		}
	}
	f.mu.Unlock()
	if workspaces != 1 {
		t.Errorf("captured body/replacement decoded %d times, want 1 workspace", workspaces)
	}
	f.refunds(true)
}

func TestDecodedRepresentationCannotBeReplaced(t *testing.T) {
	f := newOmissionFixture(t, 1, true, omissionRemoval(false, false), 1<<20)
	f.control()
	plain := []byte(`{"visible":1}`)
	wire := omissionGzip(t, plain)
	f.bodyPair("", nil, "gzip", wire)
	m := f.peers[0].exchange(t, 1)
	omissionState(t, m, "")
	f.peers[0].answer(t, m, `{"outcome":"changed","changes":{"response.body":{"kept":"e30=","content":{"state":"decoded","length":"0","codings":["br"]}}}}`)
	f.close(11)
	o := f.finish()
	if len(o.Extensions) != 1 || o.Extensions[0].FailedBy["read_only"] != 1 || o.Extensions[0].Changed != 0 {
		t.Errorf("representation metadata replacement not rejected as read_only: %+v", o.Extensions)
	}
	lines := f.out.exchanges()
	if len(lines) != 2 {
		t.Fatalf("sink exchange population=%d want 2", len(lines))
	}
	omissionDecoded(t, omissionArtifactMessage(t, lines[1], "response"), len(wire), len(plain), false, `{"visible":1}`)
}

func TestValueRemovedDecodedBodyRejectsReplacement(t *testing.T) {
	f := newOmissionFixture(t, 1, true, omissionRemoval(true, false), 1<<20)
	f.control()
	f.bodyPair("", nil, "gzip", omissionGzip(t, []byte(`{"visible":1}`)))
	m := f.peers[0].exchange(t, 1)
	omissionState(t, m, "")
	body := omissionObject(t, omissionMessage(t, m, "response")["body"])
	if body["kept"] != "" {
		t.Error("body values survived structure-only policy")
	}
	f.peers[0].answer(t, m, `{"outcome":"changed","changes":{"response.body":{"kept":"e30="}}}`)
	f.close(11)
	o := f.finish()
	if len(o.Extensions) != 1 || o.Extensions[0].FailedBy["removed_content"] != 1 || o.Extensions[0].Changed != 0 {
		t.Errorf("value-removed replacement not rejected: %+v", o.Extensions)
	}
	lines := f.out.exchanges()
	if len(lines) != 2 {
		t.Fatalf("sink exchange population=%d want 2", len(lines))
	}
	if omissionObject(t, omissionArtifactMessage(t, lines[1], "response")["body"])["kept"] != "" {
		t.Error("replacement restored removed values in sink")
	}
}

func TestMetadataOnlyConnectionIssuesNoContentIDs(t *testing.T) {
	f := newOmissionFixture(t, 2, false, omissionRemoval(false, false), 1<<20)
	// Answer even forbidden exchanges so their presence reaches the explicit
	// content and count assertions instead of blocking finalization.
	f.auto()
	f.bodyPair("", []byte(`{"ordinary":1}`), "opaque-test", []byte(`{"OPAQUE_MEMBER_SENTINEL":2}`))
	f.bodyPair("", []byte(`{"next":1}`), "", []byte(`{"ordinary":2}`))
	// Taken guards the fixed four capture transfers, independent of the
	// metadata-only subject's expected absence of exchange messages.
	if f.transferred != 4 || f.taken.Load() != 4 {
		t.Fatal("wiring, not the property: four transfers did not reach processing")
	}
	f.close(11)
	o := f.finish()
	f.terminal(o, 0)
	for _, p := range f.peers {
		if len(p.of(t, "exchange")) != 0 {
			t.Error("write_content=false sent content to an extension")
		}
		f.done(p, 11, 0)
		for _, m := range p.of(t, "connection_done") {
			omissionKeys(t, m, "type", "connection_id", "count", "ending", "connection")
		}
		b, _ := json.Marshal(p.messages(t))
		if bytes.Contains(b, []byte("OPAQUE_MEMBER_SENTINEL")) {
			t.Error("metadata-only lifecycle leaked body shape")
		}
	}
	if len(f.out.exchanges()) != 0 {
		t.Error("write_content=false wrote an exchange")
	}
	f.refunds(false)
}

func TestExcludedExchangeCleanupReturnsDecodedChargesOnce(t *testing.T) {
	for _, withdraw := range []bool{false, true} {
		t.Run(fmt.Sprintf("withdraw-%t", withdraw), func(t *testing.T) {
			f := newOmissionFixture(t, 2, true, omissionRemoval(true, false), 1<<20)
			f.control()
			f.bodyPair("gzip", omissionGzip(t, []byte(`{"retained":1}`)), "gzip", []byte(`{"OPAQUE_MEMBER_SENTINEL":2}`))
			m := f.peers[0].exchange(t, 1)
			omissionState(t, m, "content_decoding_failed")
			if withdraw {
				f.losses[11].Stop("fixture withdrawal")
				f.route()
			}
			f.auto()
			f.close(11)
			o := f.finish()
			f.terminal(o, 2)
			if o.Excluded != (processing.Exclusions{ContentDecodingFailed: 1}) {
				t.Errorf("isolated exclusion changed during cleanup: %+v", o.Excluded)
			}
			if withdraw && (len(o.Extensions) != 2 || o.Extensions[1].FailedBy["withdrawn"] != 1) {
				t.Errorf("second extension was not withdrawn: %+v", o.Extensions)
			}
			for _, p := range f.peers {
				f.done(p, 11, 2)
			}
			f.refunds(true)
			before := f.store.Stats()
			if err := f.run.Close(); err != nil {
				t.Fatal(err)
			}
			if after := f.store.Stats(); after != before {
				t.Errorf("Close returned charges again: before=%+v after=%+v", before, after)
			}
			f.refunds(true)
		})
	}
}
