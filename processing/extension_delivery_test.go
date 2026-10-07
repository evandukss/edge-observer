package processing_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	"github.com/evandukss/edge-observer/sink"
)

const extensionDeliverySecret = "REMOVAL_SENTINEL_6bc127"

// The subprocess speaks the real protocol over stdio. A separate fixture
// connection lets the parent inspect each received message and choose when
// and how to answer it; no observer state is read through that connection.
func TestExtensionDeliveryProcess(t *testing.T) {
	at := -1
	for i, arg := range os.Args {
		if arg == "--" {
			at = i
			break
		}
	}
	if at < 0 {
		return
	}
	if len(os.Args) != at+3 {
		os.Exit(41)
	}
	c, err := net.DialTimeout("tcp", os.Args[at+1], 5*time.Second)
	if err != nil {
		os.Exit(42)
	}
	control, answers := json.NewEncoder(c), json.NewDecoder(c)
	if err := control.Encode(map[string]string{"name": os.Args[at+2]}); err != nil {
		os.Exit(43)
	}
	wire := json.NewEncoder(os.Stdout)
	input := bufio.NewScanner(os.Stdin)
	input.Buffer(make([]byte, 4096), extension.FrameBytesToExtension)
	for input.Scan() {
		line := bytes.Clone(input.Bytes())
		var message map[string]json.RawMessage
		if err := json.Unmarshal(line, &message); err != nil {
			os.Exit(44)
		}
		if err := control.Encode(json.RawMessage(line)); err != nil {
			os.Exit(45)
		}
		var kind string
		if err := json.Unmarshal(message["type"], &kind); err != nil {
			os.Exit(46)
		}
		switch kind {
		case "start":
			if err := wire.Encode(map[string]string{"type": "ready", "protocol": extension.Protocol}); err != nil {
				os.Exit(47)
			}
		case "exchange":
			var answer json.RawMessage
			if err := answers.Decode(&answer); err != nil {
				os.Exit(48)
			}
			if err := wire.Encode(answer); err != nil {
				os.Exit(49)
			}
		case "shutdown":
			os.Exit(0)
		}
	}
	if input.Err() != nil {
		os.Exit(50)
	}
	os.Exit(0)
}

type extensionDeliveryPeer struct {
	name   string
	conn   net.Conn
	answer *json.Encoder
	lines  chan json.RawMessage
}

type extensionDeliveryOutput struct {
	mutex    sync.Mutex
	attempts [][]byte
	lines    [][]byte
	reject   int
}

func (o *extensionDeliveryOutput) WriteApproved(_ context.Context, a processing.Approved) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	line := a.Bytes()
	o.attempts = append(o.attempts, line)
	if len(o.attempts) == o.reject {
		return errors.New("fixture enqueue refusal")
	}
	o.lines = append(o.lines, line)
	return nil
}

func (o *extensionDeliveryOutput) snapshot() ([][]byte, [][]byte) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return append([][]byte(nil), o.lines...), append([][]byte(nil), o.attempts...)
}

type extensionDeliveryFixture struct {
	run    *processing.Run
	store  *intake.Store
	gate   *probe.DeliveryGate
	writer *processing.Writer
	dir    string
	peers  map[string]*extensionDeliveryPeer
	taken  atomic.Int64
}

func extensionDeliveryWait(t *testing.T, what string, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-deadline.C:
			t.Fatalf("%s: observation deadline expired", what)
		case <-tick.C:
		}
	}
}

func extensionDeliveryNew(t *testing.T, fields [][]string, output processing.Output, before func(), factory sink.Factory) *extensionDeliveryFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("wiring, not the property: fixture listener: %v", err)
	}
	connected := make(chan *extensionDeliveryPeer, len(fields))
	go func() {
		for range fields {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				decoder := json.NewDecoder(conn)
				var hello struct {
					Name string `json:"name"`
				}
				if decoder.Decode(&hello) != nil {
					_ = conn.Close()
					return
				}
				peer := &extensionDeliveryPeer{name: hello.Name, conn: conn, answer: json.NewEncoder(conn), lines: make(chan json.RawMessage, 32)}
				connected <- peer
				defer close(peer.lines)
				for {
					var line json.RawMessage
					if decoder.Decode(&line) != nil {
						return
					}
					peer.lines <- line
				}
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]map[string]any, len(fields))
	for i := range fields {
		name := fmt.Sprintf("reader%d", i)
		entries[i] = map[string]any{"name": name, "command": []string{self, "-test.run=^TestExtensionDeliveryProcess$", "--", listener.Addr().String(), name}, "fields": fields[i], "timeout_ms": 30000}
	}
	f := &extensionDeliveryFixture{dir: t.TempDir(), peers: map[string]*extensionDeliveryPeer{}}
	raw, err := json.Marshal(map[string]any{
		"version": "observer.config/1", "output": f.dir, "write_content": true,
		"watch":      []any{map[string]any{"name": "api", "exe": "/usr/bin/php"}},
		"remove":     map[string]any{"headers": []string{"authorization"}, "bodies": []string{"request"}},
		"extensions": entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	compiled, findings := config.Compile(raw, "")
	if len(findings) != 0 || compiled.Plan == nil {
		t.Fatalf("wiring, not the property: extension plan: %+v", findings)
	}
	f.store, err = intake.New(128 << 20)
	if err != nil {
		t.Fatal(err)
	}
	f.gate, err = probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 32768, BeforeAuthorize: before})
	if err != nil {
		t.Fatal(err)
	}
	f.writer, err = processing.OpenWriter(processing.WriterOptions{Directory: f.dir, OpenSink: factory})
	if err != nil {
		t.Fatal(err)
	}
	if output == nil {
		output = f.writer
	}
	ready := make(chan string, len(fields))
	f.run, err = processing.Start(processing.Options{Plan: compiled.Plan, PolicyRevision: "extension-delivery", Session: "extension-delivery", Intake: f.store, Gate: f.gate, Output: output, Derived: f.writer, ConnectionInput: 1024,
		Taken: func(int, fragment.Process, fragment.ConnectionID) { f.taken.Add(1) },
		Supervision: func(e extension.Event) {
			if e.Kind == extension.Ready {
				ready <- e.Extension
			}
		},
	})
	if err != nil {
		t.Fatalf("wiring, not the property: start worker: %v", err)
	}
	t.Cleanup(func() {
		_ = f.run.Close()
		for _, peer := range f.peers {
			_ = peer.conn.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = f.writer.Shutdown(ctx)
		_ = f.store.Close()
	})
	seen := map[string]bool{}
	extensionDeliveryWait(t, "wiring, not the property: every extension must answer ready", func() bool {
		for {
			select {
			case peer := <-connected:
				f.peers[peer.name] = peer
			case name := <-ready:
				seen[name] = true
			default:
				return len(seen) == len(fields) && len(f.peers) == len(fields)
			}
		}
	})
	return f
}

type extensionDeliveryCapture struct {
	fragments []fragment.Record
	finals    []connection.Record
	groups    [][]fragment.Record
}

func (c *extensionDeliveryCapture) Write(f fragment.Record) error {
	c.fragments = append(c.fragments, f)
	return nil
}
func (c *extensionDeliveryCapture) Connection(r connection.Record) error {
	c.finals = append(c.finals, r)
	return nil
}

func extensionDeliveryInput(t *testing.T, pairs int) extensionDeliveryCapture {
	t.Helper()
	var c extensionDeliveryCapture
	r := capture.Recording(&c, &c)
	p := fragment.Process{PID: 42, StartTime: 7}
	instance := admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42, Start: admission.Determinate(7), Generation: 1}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	numbers := [3]uint64{}
	stamp := uint64(0)
	ends := []int{}
	for i := range pairs {
		requestBody, responseBody := extensionDeliverySecret+fmt.Sprint(i), fmt.Sprintf("body-%d", i)
		request := fmt.Sprintf("POST /release-%d HTTP/1.1\r\nHost: fixture\r\nX-Allow: captured-%d\r\nAuthorization: %s\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\nX-Trail: request-%d\r\nAuthorization: %s\r\n\r\n", i, i, extensionDeliverySecret, len(requestBody), requestBody, i, extensionDeliverySecret)
		response := fmt.Sprintf("HTTP/1.1 200 OK\r\nX-Allow: response-%d\r\nAuthorization: %s\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\nX-Trail: response-%d\r\nAuthorization: %s\r\n\r\n", i, extensionDeliverySecret, len(responseBody), responseBody, i, extensionDeliverySecret)
		for side, wire := range []string{request, response} {
			d := fragment.Sent
			if side == 1 {
				d = fragment.Received
			}
			for len(wire) > 0 {
				n := min(7, len(wire))
				payload := []byte(wire[:n])
				wire = wire[n:]
				stamp++
				numbers[d]++
				r.Transfer(probe.Transfer{Process: p, Instance: instance, Endpoint: 77, Direction: d, Measured: true, Length: uint32(n), Payload: payload, Stamp: stamp, Sequence: probe.Sequence{Occupancy: 1, Number: numbers[d], Born: true}, At: at})
			}
		}
		ends = append(ends, len(c.fragments))
	}
	r.Closed(probe.Connection{Process: p, Instance: instance, Endpoint: 77, Stamp: stamp + 1, Sequence: probe.Sequence{Occupancy: 1, Born: true}, Final: probe.Final{Known: true, Sent: probe.Terminal{Last: numbers[fragment.Sent]}, Received: probe.Terminal{Last: numbers[fragment.Received]}}, At: at})
	if len(c.fragments) != int(stamp) || len(c.finals) != 1 || stamp == 0 {
		t.Fatal("wiring, not the property: measured fragmented capture population missing")
	}
	final := &c.finals[0]
	final.ID = 77
	for i := range final.Associations {
		final.Associations[i].Connection = 77
	}
	for i := range final.Placements {
		final.Placements[i].Connection = 77
	}
	e := fragment.Evidence{Identity: &fragment.Identity{Connection: 77, Process: p, Instance: instance, Address: 77, Generation: uint64(final.Handle.Generation), NetworkDevice: final.Network.Device, NetworkInode: final.Network.Inode, FirstSeen: final.FirstSeen}, Origin: fragment.OriginBirth, Occupancy: 1}
	for i := range c.fragments {
		f := &c.fragments[i]
		f.Connection = 77
		e.Through = f.Sequence
		d := &e.Sent
		if f.Direction == fragment.Received {
			d = &e.Received
		}
		*d = fragment.DirectionEvidence{Limit: f.End(), First: 1, Numbered: f.Produced, Resolved: f.Produced}
		f.Evidence = e
		if err := f.Evidenced(); err != nil {
			t.Fatalf("wiring, not the property: evidence: %v", err)
		}
		if err := final.Agrees(e); err != nil {
			t.Fatalf("wiring, not the property: capture/evidence disagreement: %v", err)
		}
	}
	if err := final.Validate(); err != nil {
		t.Fatalf("wiring, not the property: capture final: %v", err)
	}
	start := 0
	for _, end := range ends {
		c.groups = append(c.groups, c.fragments[start:end])
		start = end
	}
	return c
}

func (f *extensionDeliveryFixture) feed(t *testing.T, fragments []fragment.Record) {
	t.Helper()
	before := f.taken.Load()
	for _, part := range fragments {
		if err := f.store.Write(part); err != nil {
			t.Fatalf("wiring, not the property: intake: %v", err)
		}
	}
	f.run.Route()
	extensionDeliveryWait(t, "wiring, not the property: worker must take every fragment", func() bool { return f.taken.Load() == before+int64(len(fragments)) })
}

func extensionDeliveryClean(t *testing.T, raw []byte) {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("wiring, not the property: JSON: %v", err)
	}
	var visit func(any)
	visit = func(v any) {
		switch v := v.(type) {
		case string:
			if strings.Contains(v, extensionDeliverySecret) {
				t.Fatal("removed sentinel survived in delivered content")
			}
			if decoded, err := base64.StdEncoding.DecodeString(v); err == nil && bytes.Contains(decoded, []byte(extensionDeliverySecret)) {
				t.Fatal("removed sentinel survived in encoded content")
			}
		case []any:
			for _, child := range v {
				visit(child)
			}
		case map[string]any:
			for _, child := range v {
				visit(child)
			}
		}
	}
	visit(value)
}

func (f *extensionDeliveryFixture) exchange(t *testing.T, name string, index int) map[string]any {
	t.Helper()
	peer := f.peers[name]
	if peer == nil {
		t.Fatal("wiring, not the property: ready extension has no fixture connection")
	}
	var found map[string]any
	extensionDeliveryWait(t, "open pair did not reach ready extension "+name, func() bool {
		select {
		case raw, ok := <-peer.lines:
			if !ok {
				t.Fatal("wiring, not the property: extension fixture exited")
			}
			extensionDeliveryClean(t, raw)
			var message map[string]any
			if err := json.Unmarshal(raw, &message); err != nil {
				t.Fatal(err)
			}
			if message["type"] == "start" {
				return false
			}
			if message["type"] != "exchange" {
				t.Fatalf("open connection got %v before its next exchange", message["type"])
			}
			found = message
			return true
		default:
			return false
		}
	})
	if found["id"] != strconv.Itoa(index+1) || found["connection_id"] != "77" || found["index"] != float64(index) || found["ids"] != nil {
		t.Fatalf("released exchange identity/range: %+v", found)
	}
	return found
}

func extensionDeliveryMessage(t *testing.T, wire map[string]any, side string) map[string]any {
	t.Helper()
	x, ok := wire["exchange"].(map[string]any)
	if !ok {
		t.Fatal("wiring, not the property: exchange object absent")
	}
	s, ok := x[side].(map[string]any)
	if !ok {
		t.Fatal("wiring, not the property: projected side absent")
	}
	m, ok := s["message"].(map[string]any)
	if !ok {
		t.Fatal("wiring, not the property: projected message absent")
	}
	return m
}

func extensionDeliveryFields(t *testing.T, message map[string]any, index int, replacement bool) {
	t.Helper()
	for _, section := range []string{"headers", "trailers"} {
		fields, ok := message[section].([]any)
		if !ok {
			t.Fatalf("projected %s missing", section)
		}
		want := fmt.Sprintf("captured-%d", index)
		name := "x-allow"
		if section == "trailers" {
			name = "x-trail"
			want = fmt.Sprintf("request-%d", index)
		}
		if replacement {
			want = fmt.Sprintf("replacement-%d", index)
		}
		matched := 0
		for _, field := range fields {
			h := field.(map[string]any)
			if strings.EqualFold(h["name"].(string), "authorization") {
				t.Fatal("removed header name remains in fields")
			}
			if strings.EqualFold(h["name"].(string), name) && h["value"] == want {
				matched++
			}
		}
		if matched != 1 {
			t.Fatalf("%s preserved %d copies of %s=%q, want one", section, matched, name, want)
		}
	}
}

func extensionDeliveryBody(t *testing.T, message map[string]any, want string) {
	t.Helper()
	body, ok := message["body"].(map[string]any)
	if !ok {
		t.Fatal("selected body missing")
	}
	kept, _ := body["kept"].(string)
	decoded, err := base64.StdEncoding.DecodeString(kept)
	if err != nil || string(decoded) != want {
		t.Fatalf("kept body=%q err=%v, want %q", decoded, err, want)
	}
}

func extensionDeliveryResponseFields(t *testing.T, message map[string]any, index int) {
	t.Helper()
	for _, section := range []string{"headers", "trailers"} {
		fields, ok := message[section].([]any)
		if !ok {
			t.Fatalf("projected response %s missing", section)
		}
		name := "x-allow"
		if section == "trailers" {
			name = "x-trail"
		}
		found := 0
		for _, field := range fields {
			h := field.(map[string]any)
			if strings.EqualFold(h["name"].(string), "authorization") {
				t.Fatal("response retained a removed header or trailer")
			}
			if strings.EqualFold(h["name"].(string), name) && h["value"] == fmt.Sprintf("response-%d", index) {
				found++
			}
		}
		if found != 1 {
			t.Fatalf("response %s lost its permitted field: %+v", section, fields)
		}
	}
}

func (f *extensionDeliveryFixture) answer(t *testing.T, name string, index int, changes map[string]any) {
	t.Helper()
	answer := map[string]any{"type": "result", "id": strconv.Itoa(index + 1), "outcome": "unchanged"}
	if changes != nil {
		answer["outcome"] = "changed"
		answer["changes"] = changes
	}
	if err := f.peers[name].answer.Encode(answer); err != nil {
		t.Fatalf("wiring, not the property: fixture answer: %v", err)
	}
}

var extensionDeliveryAllFields = []string{"request.line", "request.headers", "request.body", "response.line", "response.headers", "response.body", "connection"}
var extensionDeliveryLimitedFields = []string{"request.headers", "response.body"}

func extensionDeliveryChanges(index int) map[string]any {
	fields := []any{map[string]any{"name": "X-Allow", "value": fmt.Sprintf("replacement-%d", index)}, map[string]any{"name": "Authorization", "value": extensionDeliverySecret}}
	trailers := []any{map[string]any{"name": "X-Trail", "value": fmt.Sprintf("replacement-%d", index)}, map[string]any{"name": "Authorization", "value": extensionDeliverySecret}}
	return map[string]any{"request.headers": map[string]any{"headers": fields, "trailers": trailers}, "response.body": map[string]any{"kept": base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("replacement-%d", index)))}}
}

func extensionDeliveryArtifact(t *testing.T, raw []byte, index int) processing.Artifact {
	t.Helper()
	extensionDeliveryClean(t, raw)
	var a processing.Artifact
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if a.Record != processing.ArtifactExchange || a.Connection.ID != "77" || !a.Connection.Provisional || a.Index == nil || *a.Index != index || a.ExchangeID != strconv.Itoa(index+1) || a.Reconstruction == nil || len(a.Reconstruction.Exchanges) != 1 {
		t.Fatalf("approved released pair has wrong identity or population: %+v", a)
	}
	if a.Reconstruction.Exchanges[0].Index != index {
		t.Fatalf("approved nested exchange index %d, want %d", a.Reconstruction.Exchanges[0].Index, index)
	}
	if a.Reconstruction.Exchanges[0].Request.Message.Target != fmt.Sprintf("/release-%d", index) {
		t.Fatal("approved request identity changed")
	}
	return a
}

func extensionDeliveryAwaitLines(t *testing.T, out *extensionDeliveryOutput, count int) [][]byte {
	t.Helper()
	var lines [][]byte
	extensionDeliveryWait(t, "completed extension chain did not enqueue its pair", func() bool { lines, _ = out.snapshot(); return len(lines) >= count })
	if len(lines) != count {
		t.Fatalf("got %d approved lines, want %d", len(lines), count)
	}
	return lines
}

func TestExtensionDeliveryPreservesProjectionAndReplacementAcrossReleases(t *testing.T) {
	out := &extensionDeliveryOutput{}
	f := extensionDeliveryNew(t, [][]string{extensionDeliveryAllFields, extensionDeliveryLimitedFields}, out, nil, nil)
	c := extensionDeliveryInput(t, 3)
	var prior [][]byte
	for i := range c.groups {
		f.feed(t, c.groups[i])
		first := f.exchange(t, "reader0", i)
		request := extensionDeliveryMessage(t, first, "request")
		extensionDeliveryFields(t, request, i, false)
		extensionDeliveryBody(t, request, "")
		response := extensionDeliveryMessage(t, first, "response")
		extensionDeliveryResponseFields(t, response, i)
		extensionDeliveryBody(t, response, fmt.Sprintf("body-%d", i))
		f.answer(t, "reader0", i, extensionDeliveryChanges(i))
		second := f.exchange(t, "reader1", i)
		request = extensionDeliveryMessage(t, second, "request")
		extensionDeliveryFields(t, request, i, true)
		if request["target"] != nil || request["body"] != nil || second["connection"] != nil {
			t.Fatal("extension received unselected fields")
		}
		extensionDeliveryBody(t, extensionDeliveryMessage(t, second, "response"), fmt.Sprintf("replacement-%d", i))
		f.answer(t, "reader1", i, nil)
		lines := extensionDeliveryAwaitLines(t, out, i+1)
		a := extensionDeliveryArtifact(t, lines[i], i)
		x := a.Reconstruction.Exchanges[0]
		body, err := base64.StdEncoding.DecodeString(x.Response.Message.Body.Kept)
		if err != nil || string(body) != fmt.Sprintf("replacement-%d", i) || x.Request.Message.Body.Kept != "" {
			t.Fatal("approved body lost the accepted replacement or restored removed input")
		}
		if x.Response.Message.Body.Length != strconv.Itoa(len(fmt.Sprintf("body-%d", i))) || x.Response.Message.Body.Holed != "0" || x.Response.Message.Body.Elided != "0" || !x.Complete {
			t.Fatal("replacement changed capture extent, loss or completeness")
		}
		for side, message := range map[string]any{"request": x.Request.Message, "response": x.Response.Message} {
			raw, err := json.Marshal(message)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			if side == "request" {
				extensionDeliveryFields(t, fields, i, true)
			} else {
				extensionDeliveryResponseFields(t, fields, i)
			}
		}
		if len(a.ExtensionOutcomes) != 2 || a.ExtensionOutcomes[0].Outcome != extension.Changed || a.ExtensionOutcomes[1].Outcome != extension.Unchanged || len(a.ReplacementExclusions) != 2 {
			t.Fatalf("replacement provenance lost: %+v", a)
		}
		sections := map[string]bool{}
		for _, removal := range a.ReplacementExclusions {
			if removal.Extension != "reader0" || removal.Exchange != i || removal.Message != "request" || removal.Field != "message.headers.authorization" || removal.Disposition != processing.DispositionRemoved || sections[removal.Section] {
				t.Fatalf("wrong replacement removal: %+v", removal)
			}
			sections[removal.Section] = true
		}
		if !sections["headers"] || !sections["trailers"] {
			t.Fatal("replacement removals did not preserve both sections")
		}
		for n, outcome := range a.ExtensionOutcomes {
			if outcome.Extension != fmt.Sprintf("reader%d", n) || outcome.Exchange != i {
				t.Fatalf("outcome attributed to another exchange or extension: %+v", outcome)
			}
		}
		for j, saved := range prior {
			if !bytes.Equal(saved, lines[j]) {
				t.Fatal("later release changed an earlier approved line")
			}
		}
		prior = append(prior, bytes.Clone(lines[i]))
		if i+1 < len(c.groups) {
			next := &c.groups[i+1][2]
			payload := bytes.Clone(next.Payload)
			if bytes.Equal(c.groups[i][2].Payload, payload) {
				t.Fatal("wiring, not the property: buffer reuse did not change captured bytes")
			}
			next.Payload = c.groups[i][2].Payload[:len(payload)]
			copy(next.Payload, payload)
		}
	}
}

func TestExtensionDeliveryUnchangedBodySurvivesCaptureBufferReuse(t *testing.T) {
	out := &extensionDeliveryOutput{}
	f := extensionDeliveryNew(t, [][]string{extensionDeliveryAllFields}, out, nil, nil)
	c := extensionDeliveryInput(t, 2)
	bodyFragment := func(group []fragment.Record, body string) (int, int) {
		var wire []byte
		for _, part := range group {
			if part.Direction == fragment.Received {
				wire = append(wire, part.Payload...)
			}
		}
		framed := []byte("\r\n6\r\n" + body + "\r\n")
		start := bytes.Index(wire, framed)
		if start < 0 || bytes.Count(wire, framed) != 1 {
			t.Fatal("wiring, not the property: captured response body not uniquely located")
		}
		last := start + len("\r\n6\r\n") + len(body) - 1
		offset := 0
		for i, part := range group {
			if part.Direction != fragment.Received {
				continue
			}
			if last >= offset && last < offset+len(part.Payload) {
				at := last - offset
				if part.Payload[at] != body[len(body)-1] {
					t.Fatal("wiring, not the property: reused fragment did not carry the body byte")
				}
				return i, at
			}
			offset += len(part.Payload)
		}
		t.Fatal("wiring, not the property: no fragment carried the response body byte")
		return 0, 0
	}
	oldIndex, oldAt := bodyFragment(c.groups[0], "body-0")
	nextIndex, nextAt := bodyFragment(c.groups[1], "body-1")
	old, next := &c.groups[0][oldIndex], &c.groups[1][nextIndex]
	if oldAt != nextAt || len(old.Payload) != len(next.Payload) || old.Payload[oldAt] != '0' || next.Payload[nextAt] != '1' {
		t.Fatal("wiring, not the property: reuse does not change the same captured body position")
	}
	f.feed(t, c.groups[0])
	first := f.exchange(t, "reader0", 0)
	extensionDeliveryBody(t, extensionDeliveryMessage(t, first, "response"), "body-0")
	projection, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	f.answer(t, "reader0", 0, nil)
	lines := extensionDeliveryAwaitLines(t, out, 1)
	prior := bytes.Clone(lines[0])
	approved := extensionDeliveryArtifact(t, prior, 0)
	if approved.Reconstruction.Exchanges[0].Response.Message.Body.Kept != base64.StdEncoding.EncodeToString([]byte("body-0")) || len(approved.ExtensionOutcomes) != 1 || approved.ExtensionOutcomes[0].Outcome != extension.Unchanged {
		t.Fatal("unreplaced captured body was not released unchanged")
	}
	before := bytes.Clone(old.Payload)
	payload := bytes.Clone(next.Payload)
	next.Payload = old.Payload[:len(payload)]
	copy(next.Payload, payload)
	if &next.Payload[0] != &old.Payload[0] || bytes.Equal(before, old.Payload) || before[oldAt] != '0' || old.Payload[oldAt] != '1' {
		t.Fatal("wiring, not the property: captured body buffer was not reused with changed bytes")
	}
	f.feed(t, c.groups[1])
	second := f.exchange(t, "reader0", 1)
	extensionDeliveryBody(t, extensionDeliveryMessage(t, second, "response"), "body-1")
	f.answer(t, "reader0", 1, nil)
	lines = extensionDeliveryAwaitLines(t, out, 2)
	if !bytes.Equal(prior, lines[0]) {
		t.Fatal("capture body buffer reuse changed a released approved line")
	}
	current, err := json.Marshal(first)
	if err != nil || !bytes.Equal(projection, current) {
		t.Fatal("capture body buffer reuse changed the earlier extension projection")
	}
	extensionDeliveryBody(t, extensionDeliveryMessage(t, first, "response"), "body-0")
	for i, line := range lines {
		a := extensionDeliveryArtifact(t, line, i)
		body, err := base64.StdEncoding.DecodeString(a.Reconstruction.Exchanges[0].Response.Message.Body.Kept)
		if err != nil || !bytes.Equal(body, []byte(fmt.Sprintf("body-%d", i))) {
			t.Fatal("capture body buffer reuse changed approved body bytes")
		}
	}
}

func TestExtensionDeliveryRejectsInvalidReplacementWithoutRawFallback(t *testing.T) {
	out := &extensionDeliveryOutput{}
	f := extensionDeliveryNew(t, [][]string{extensionDeliveryAllFields, extensionDeliveryAllFields}, out, nil, nil)
	c := extensionDeliveryInput(t, 2)
	for i := range c.groups {
		f.feed(t, c.groups[i])
		_ = f.exchange(t, "reader0", i)
		changes := extensionDeliveryChanges(i)
		changes["response.body"].(map[string]any)["length"] = "999"
		f.answer(t, "reader0", i, changes)
		second := f.exchange(t, "reader1", i)
		extensionDeliveryFields(t, extensionDeliveryMessage(t, second, "request"), i, false)
		extensionDeliveryBody(t, extensionDeliveryMessage(t, second, "request"), "")
		extensionDeliveryBody(t, extensionDeliveryMessage(t, second, "response"), fmt.Sprintf("body-%d", i))
		f.answer(t, "reader1", i, nil)
		a := extensionDeliveryArtifact(t, extensionDeliveryAwaitLines(t, out, i+1)[i], i)
		if len(a.ExtensionOutcomes) != 2 || a.ExtensionOutcomes[0].Outcome != extension.Failed || a.ExtensionOutcomes[0].Reason != extension.ReadOnly || a.ExtensionOutcomes[1].Outcome != extension.Unchanged || len(a.ReplacementExclusions) != 0 {
			t.Fatalf("invalid answer was applied or stopped the chain: %+v", a.ExtensionOutcomes)
		}
	}
}

func TestExtensionDeliverySinkRefusalKeepsLaterSanitizedPairs(t *testing.T) {
	out := &extensionDeliveryOutput{reject: 2}
	f := extensionDeliveryNew(t, [][]string{extensionDeliveryAllFields}, out, nil, nil)
	c := extensionDeliveryInput(t, 3)
	for i := range c.groups {
		f.feed(t, c.groups[i])
		_ = f.exchange(t, "reader0", i)
		f.answer(t, "reader0", i, nil)
		extensionDeliveryWait(t, "extension result did not reach enqueue attempt", func() bool { _, attempts := out.snapshot(); return len(attempts) >= i+1 })
	}
	lines, attempts := out.snapshot()
	if len(attempts) != 3 || len(lines) != 2 {
		t.Fatalf("sink refusal retried or suppressed later work: attempts %d, lines %d", len(attempts), len(lines))
	}
	for i, raw := range attempts {
		extensionDeliveryArtifact(t, raw, i)
	}
	extensionDeliveryArtifact(t, lines[0], 0)
	extensionDeliveryArtifact(t, lines[1], 2)
	extensionDeliveryWait(t, "sink refusal was not counted", func() bool { return f.run.Snapshot().OutputFailures == 1 })
}

type extensionDeliveryHeldSink struct {
	sink.Sink
	hold    *atomic.Bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *extensionDeliveryHeldSink) Write(ctx context.Context, line []byte) (int, error) {
	if s.hold.Load() {
		s.once.Do(func() { close(s.entered) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return s.Sink.Write(ctx, line)
}

func TestExtensionDeliveryTerminalInvalidationOrdersAfterCompletion(t *testing.T) {
	for _, first := range []bool{true, false} {
		t.Run(fmt.Sprintf("invalidation_first_%t", first), func(t *testing.T) {
			var armed atomic.Bool
			entered, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			var once sync.Once
			before := func() {
				if first && armed.Load() {
					once.Do(func() { close(entered) })
					<-release
				}
			}
			factory := func(path string) sink.Sink {
				base := sink.NewFile(path)
				if first || filepath.Base(path) != processing.ArtifactName {
					return base
				}
				return &extensionDeliveryHeldSink{Sink: base, hold: &armed, entered: entered, release: release}
			}
			f := extensionDeliveryNew(t, [][]string{extensionDeliveryAllFields}, nil, before, factory)
			t.Cleanup(unblock)
			c := extensionDeliveryInput(t, 2)
			f.feed(t, c.groups[0])
			_ = f.exchange(t, "reader0", 0)
			f.answer(t, "reader0", 0, nil)
			extensionDeliveryWait(t, "healthy extension control did not write", func() bool { return f.writer.DeliveryStats().Written == 1 })
			path := filepath.Join(f.dir, processing.ArtifactName)
			prior, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			extensionDeliveryArtifact(t, bytes.TrimSpace(prior), 0)
			armed.Store(true)
			f.feed(t, c.groups[1])
			_ = f.exchange(t, "reader0", 1)
			f.answer(t, "reader0", 1, nil)
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("wiring, not the property: completed extension did not reach the ordering barrier")
			}
			fault := f.gate.Admit(probe.DeliveryTransfer, false)
			if fault.State.Reason != probe.GateUnknownLength || fault.Slot == nil {
				t.Fatal("wiring, not the property: terminal invalidation not reached")
			}
			fault.Slot.Refund(held.Unretained)
			unblock()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			outcome, err := f.run.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true})
			if err != nil {
				t.Fatalf("finish: %v", err)
			}
			if err := f.writer.Drain(ctx); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
			want := 2
			if first {
				want = 1
			}
			if len(lines) != want || !bytes.HasPrefix(raw, prior) {
				t.Fatalf("ordered invalidation wrote %d lines, want %d, or changed the prior prefix", len(lines), want)
			}
			for i, line := range lines {
				extensionDeliveryArtifact(t, line, i)
			}
			if outcome.GateReason != probe.GateUnknownLength || outcome.Pending != 0 {
				t.Fatalf("terminal reason or retention lost: %+v", outcome)
			}
		})
	}
}
