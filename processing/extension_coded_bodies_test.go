package processing_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"os"
	"slices"
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
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/reconstruct"
)

// extCodedChain is a run whose extensions are TestExtensionDeliveryProcess: each
// forwards every message it is sent to the test, and answers each exchange as
// the test's answer function says, from a goroutine of the test's own, so a
// chain never waits on the test's main goroutine.
type extCodedChain struct {
	run    *processing.Run
	store  *intake.Store
	output *extensionDeliveryOutput
	peers  []*extCodedPeer
	taken  atomic.Int64

	mutex    sync.Mutex
	charges  []processing.DecodeCharge
	onCharge func(processing.DecodeCharge)
}

// extCodedPeer is what one extension was sent, in order, and the answers that
// could not be given.
type extCodedPeer struct {
	mutex    sync.Mutex
	raw      [][]byte
	messages []map[string]any
	faults   []string
}

// extCodedAnswer is the changes extension k answers an exchange message with,
// nil for unchanged.
type extCodedAnswer func(k int, message map[string]any) map[string]any

func extCodedChainNew(t *testing.T, extensions int, fields []string, rules map[string]any, answer extCodedAnswer) *extCodedChain {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("wiring, not the property: fixture listener: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	connected := make(chan *extensionDeliveryPeer, extensions)
	go func() {
		for range extensions {
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
				peer := &extensionDeliveryPeer{name: hello.Name, conn: conn, answer: json.NewEncoder(conn), lines: make(chan json.RawMessage, 64)}
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
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]map[string]any, extensions)
	for k := range entries {
		name := fmt.Sprintf("coded%d", k)
		entries[k] = map[string]any{"name": name, "command": []string{self, "-test.run=^TestExtensionDeliveryProcess$", "--", listener.Addr().String(), name},
			"fields": fields, "timeout_ms": 30000}
	}
	document := map[string]any{"version": "observer.config/1", "output": t.TempDir(), "write_content": true,
		"watch": []any{map[string]any{"name": "api", "exe": "/usr/bin/php"}}, "extensions": entries}
	for key, value := range rules {
		document[key] = value
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	compiled, findings := config.Compile(raw, "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: extension plan: %+v", findings)
	}
	f := &extCodedChain{output: &extensionDeliveryOutput{}}
	f.store, err = intake.New(64 << 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4096, IntakeExhausted: f.store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	derived, err := processing.Open(t.TempDir(), 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = derived.Close() })
	ready := make(chan string, extensions)
	options := processing.Options{Session: "coded-chain", PolicyRevision: "fixture", Plan: compiled.Plan, Intake: f.store, Gate: gate,
		Output: f.output, Derived: derived, ConnectionInput: 4096, Limits: reconstruct.Limits{HTTP: http1.Limits{MaxBodyBytes: 1 << 20}},
		Taken: func(int, fragment.Process, fragment.ConnectionID) { f.taken.Add(1) },
		Supervision: func(e extension.Event) {
			if e.Kind == extension.Ready {
				ready <- e.Extension
			}
		}}
	options = processing.ObserveDecodeCharges(options, func(e processing.DecodeCharge) {
		f.mutex.Lock()
		defer f.mutex.Unlock()
		f.charges = append(f.charges, e)
		if f.onCharge != nil {
			f.onCharge(e)
		}
	})
	f.run, err = processing.Start(options)
	if err != nil {
		t.Fatalf("wiring, not the property: start: %v", err)
	}
	t.Cleanup(func() { _ = f.run.Close() })
	byName := map[string]*extensionDeliveryPeer{}
	seen := map[string]bool{}
	extensionDeliveryWait(t, "wiring, not the property: every extension must answer ready", func() bool {
		for {
			select {
			case peer := <-connected:
				byName[peer.name] = peer
			case name := <-ready:
				seen[name] = true
			default:
				return len(seen) == extensions && len(byName) == extensions
			}
		}
	})
	for k := range extensions {
		wire := byName[fmt.Sprintf("coded%d", k)]
		t.Cleanup(func() { _ = wire.conn.Close() })
		peer := &extCodedPeer{}
		f.peers = append(f.peers, peer)
		go peer.serve(k, wire, answer)
	}
	return f
}

// serve records every message the extension was sent and answers each
// exchange.
func (p *extCodedPeer) serve(k int, wire *extensionDeliveryPeer, answer extCodedAnswer) {
	for raw := range wire.lines {
		var message map[string]any
		if err := json.Unmarshal(raw, &message); err != nil {
			p.fault("a message that is not JSON")
			continue
		}
		p.mutex.Lock()
		p.raw = append(p.raw, raw)
		p.messages = append(p.messages, message)
		p.mutex.Unlock()
		if message["type"] != "exchange" {
			continue
		}
		result := map[string]any{"type": "result", "id": message["id"], "outcome": "unchanged"}
		if answer != nil {
			if changes := answer(k, message); changes != nil {
				result["outcome"], result["changes"] = "changed", changes
			}
		}
		if err := wire.answer.Encode(result); err != nil {
			p.fault("an answer the fixture could not send")
		}
	}
}

func (p *extCodedPeer) fault(what string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.faults = append(p.faults, what)
}

// exchanges is every exchange message the extension was sent so far, with its
// raw line.
func (p *extCodedPeer) exchanges() ([]map[string]any, [][]byte) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	var messages []map[string]any
	var raw [][]byte
	for i, m := range p.messages {
		if m["type"] == "exchange" {
			messages = append(messages, m)
			raw = append(raw, p.raw[i])
		}
	}
	return messages, raw
}

// done is every connection_done message the extension was sent so far.
func (p *extCodedPeer) done() []map[string]any {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	var out []map[string]any
	for _, m := range p.messages {
		if m["type"] == "connection_done" {
			out = append(out, m)
		}
	}
	return out
}

// extCodedInput is one connection's capture: each message in one transfer, the
// fragments of pair i at 2i (request) and 2i+1 (response), and its retirement.
type extCodedInput struct {
	fragments []fragment.Record
	finals    []connection.Record
}

func (c *extCodedInput) Write(f fragment.Record) error {
	c.fragments = append(c.fragments, f)
	return nil
}

func (c *extCodedInput) Connection(r connection.Record) error {
	c.finals = append(c.finals, r)
	return nil
}

func extCodedConversation(t *testing.T, pairs [][2]string) extCodedInput {
	t.Helper()
	var c extCodedInput
	recorder := capture.Recording(&c, &c)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := fragment.Process{PID: 42, StartTime: 7}
	instance := admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42, Start: admission.Determinate(7), Generation: 1}
	for i, pair := range pairs {
		for side, wire := range pair {
			direction := fragment.Sent
			if side == 1 {
				direction = fragment.Received
			}
			recorder.Transfer(probe.Transfer{Process: p, Instance: instance, Endpoint: 9, Direction: direction, Measured: true, Length: uint32(len(wire)),
				Payload: []byte(wire), Stamp: uint64(2*i + side + 1), Sequence: probe.Sequence{Occupancy: 1, Number: uint64(i + 1), Born: true}, At: at})
		}
	}
	recorder.Closed(probe.Connection{Process: p, Instance: instance, Endpoint: 9, Stamp: uint64(2*len(pairs) + 1), Sequence: probe.Sequence{Occupancy: 1, Born: true},
		Final: probe.Final{Known: true, Sent: probe.Terminal{Last: uint64(len(pairs))}, Received: probe.Terminal{Last: uint64(len(pairs))}}, At: at})
	if len(c.fragments) != 2*len(pairs) || len(c.finals) != 1 {
		t.Fatalf("wiring, not the property: capture made %d fragments and %d retirements for %d pairs", len(c.fragments), len(c.finals), len(pairs))
	}
	r := c.finals[0]
	identity := &fragment.Identity{Connection: r.ID, Process: p, Instance: instance, Address: 9, Generation: uint64(r.Handle.Generation),
		NetworkDevice: r.Network.Device, NetworkInode: r.Network.Inode, FirstSeen: r.FirstSeen}
	evidence := fragment.Evidence{Identity: identity, Origin: fragment.OriginBirth, Occupancy: 1}
	for i := range c.fragments {
		f := &c.fragments[i]
		evidence.Through = f.Sequence
		d := &evidence.Sent
		if f.Direction == fragment.Received {
			d = &evidence.Received
		}
		*d = fragment.DirectionEvidence{Limit: f.End(), First: 1, Numbered: f.Produced, Resolved: f.Produced}
		f.Evidence = evidence
		if err := f.Evidenced(); err != nil {
			t.Fatalf("wiring, not the property: fragment %d: %v", i, err)
		}
		if err := r.Agrees(evidence); err != nil {
			t.Fatalf("wiring, not the property: retirement disagrees with fragment %d: %v", i, err)
		}
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("wiring, not the property: retirement: %v", err)
	}
	return c
}

// give hands fragments to the run and waits until its worker has taken them.
// The connection's retirement is not among them: what follows is observed
// while the connection is open.
func (f *extCodedChain) give(t *testing.T, fragments []fragment.Record) {
	t.Helper()
	before := f.taken.Load()
	for _, r := range fragments {
		if err := f.store.Write(r); err != nil {
			t.Fatalf("wiring, not the property: intake: %v", err)
		}
	}
	f.run.Route()
	extensionDeliveryWait(t, "wiring, not the property: the worker did not take the fragments", func() bool {
		return f.taken.Load() == before+int64(len(fragments))
	})
}

// finish hands over the retirement and finishes the run.
func (f *extCodedChain) finish(t *testing.T, r connection.Record) processing.Outcome {
	t.Helper()
	before := f.taken.Load()
	if err := f.store.Connection(r); err != nil {
		t.Fatal(err)
	}
	f.run.Route()
	extensionDeliveryWait(t, "wiring, not the property: the worker did not take the retirement", func() bool { return f.taken.Load() == before+1 })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := f.run.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	return out
}

// sent waits until extension k has been sent n exchanges and returns them.
func (f *extCodedChain) sent(t *testing.T, k, n int) ([]map[string]any, [][]byte) {
	t.Helper()
	var messages []map[string]any
	var raw [][]byte
	extensionDeliveryWait(t, fmt.Sprintf("extension %d was not sent %d exchanges", k, n), func() bool {
		messages, raw = f.peers[k].exchanges()
		return len(messages) >= n
	})
	if len(messages) != n {
		t.Fatalf("extension %d was sent %d exchanges, want %d", k, len(messages), n)
	}
	f.peers[k].mutex.Lock()
	faults := slices.Clone(f.peers[k].faults)
	f.peers[k].mutex.Unlock()
	if len(faults) != 0 {
		t.Fatalf("wiring, not the property: extension %d's fixture failed: %v", k, faults)
	}
	return messages, raw
}

// artifacts is every approved line written so far, read back.
func (f *extCodedChain) artifacts(t *testing.T) []processing.Artifact {
	t.Helper()
	lines, _ := f.output.snapshot()
	out := make([]processing.Artifact, 0, len(lines))
	for _, line := range lines {
		var a processing.Artifact
		if err := json.Unmarshal(line, &a); err != nil {
			t.Fatalf("approved line is not JSON: %v", err)
		}
		out = append(out, a)
	}
	return out
}

// exchangeLines is the approved exchange lines written so far, by index.
func (f *extCodedChain) exchangeLines(t *testing.T) map[int]processing.Artifact {
	t.Helper()
	out := map[int]processing.Artifact{}
	for _, a := range f.artifacts(t) {
		if a.Record == processing.ArtifactExchange && a.Index != nil {
			out[*a.Index] = a
		}
	}
	return out
}

// ledger checks every decoding charge granted was given back exactly once,
// and returns how many were granted.
func (f *extCodedChain) ledger(t *testing.T) int {
	t.Helper()
	f.mutex.Lock()
	defer f.mutex.Unlock()
	type key struct {
		index   int
		request bool
		charge  contentcoding.Charge
	}
	live := map[key]int{}
	granted := 0
	for _, e := range f.charges {
		k := key{e.Index, e.Request, e.Charge}
		switch e.Event {
		case processing.ChargeReserved:
			live[k]++
			granted++
		case processing.ChargeReturned:
			if live[k] == 0 {
				t.Errorf("a decoding charge given back that was not held: %+v", e)
			}
			live[k]--
		}
	}
	for k, n := range live {
		if n != 0 {
			t.Errorf("a decoding charge kept %d times: %+v", n, k)
		}
	}
	return granted
}

// waitFor reports whether ready came true within the fixture's deadline.
func (f *extCodedChain) waitFor(ready func() bool) bool {
	deadline := time.Now().Add(3 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

// reserving is how many decoding charges were asked of the allowance.
func (f *extCodedChain) reserving() int {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	n := 0
	for _, e := range f.charges {
		if e.Event == processing.ChargeReserving {
			n++
		}
	}
	return n
}

// drained checks the run holds nothing in the shared allowance.
func (f *extCodedChain) drained(t *testing.T) {
	t.Helper()
	if s := f.store.Stats(); s.Bytes != 0 || s.Parsing != 0 || s.Policy != 0 || s.Leased != 0 {
		t.Errorf("the run still holds charges: %+v", s)
	}
}

func extCodedGzip(t *testing.T, plain string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(plain)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func extCodedRequest(index int) string {
	return fmt.Sprintf("GET /item-%d HTTP/1.1\r\nHost: fixture\r\n\r\n", index)
}

func extCodedResponse(fields string, body []byte) string {
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n%sContent-Length: %d\r\n\r\n%s", fields, len(body), body)
}

func extCodedPlain(index int) [2]string {
	return [2]string{extCodedRequest(index), extCodedResponse("", []byte(fmt.Sprintf(`{"plain":%d}`, index)))}
}

// extCodedSide is one side's message of an exchange message, nil where it has
// none.
func extCodedSide(t *testing.T, message map[string]any, side string) map[string]any {
	t.Helper()
	x, ok := message["exchange"].(map[string]any)
	if !ok {
		t.Fatalf("wiring, not the property: an exchange message with no exchange: %v", message)
	}
	s, ok := x[side].(map[string]any)
	if !ok {
		t.Fatalf("wiring, not the property: an exchange message with no %s: %v", side, message)
	}
	m, _ := s["message"].(map[string]any)
	return m
}

// extCodedKept is a message's kept body bytes.
func extCodedKept(t *testing.T, m map[string]any) string {
	t.Helper()
	body, ok := m["body"].(map[string]any)
	if !ok {
		t.Fatalf("a selected body was not sent: %v", m)
	}
	kept, err := base64.StdEncoding.DecodeString(body["kept"].(string))
	if err != nil {
		t.Fatalf("kept is not base64: %v", err)
	}
	return string(kept)
}

// extCodedContent is a message's body's content record, nil where it has none.
func extCodedContent(m map[string]any) map[string]any {
	body, _ := m["body"].(map[string]any)
	content, _ := body["content"].(map[string]any)
	return content
}

// extCodedAbsent fails where a needle is anywhere in a raw line: in its text, or
// in a string of it read as base64.
func extCodedAbsent(t *testing.T, raw []byte, needles ...[]byte) {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("wiring, not the property: a line that is not JSON: %v", err)
	}
	var visit func(any)
	visit = func(v any) {
		switch v := v.(type) {
		case string:
			for _, needle := range needles {
				if strings.Contains(v, string(needle)) {
					t.Errorf("%q reached the line as text", needle)
				}
				if decoded, err := base64.StdEncoding.DecodeString(v); err == nil && bytes.Contains(decoded, needle) {
					t.Errorf("%q reached the line in base64", needle)
				}
			}
		case []any:
			for _, child := range v {
				visit(child)
			}
		case map[string]any:
			for key, child := range v {
				for _, needle := range needles {
					if strings.Contains(key, string(needle)) {
						t.Errorf("%q reached the line as a member name", needle)
					}
				}
				visit(child)
			}
		}
	}
	visit(value)
}

// extCodedOmitted checks the schema of a message whose body was omitted: the
// body's captured extent and loss, an empty kept, the omission marker naming
// reason, a structure with no shape, and nothing else.
func extCodedOmitted(t *testing.T, m map[string]any, reason, length string) {
	t.Helper()
	body, ok := m["body"].(map[string]any)
	if !ok {
		t.Fatalf("a selected body was not sent: %v", m)
	}
	if keys := slices.Sorted(maps.Keys(body)); !slices.Equal(keys, []string{"content", "elided", "encoding", "holed", "kept", "length"}) {
		t.Errorf("omitted body members %v", keys)
	}
	if body["kept"] != "" || body["length"] != length || body["holed"] != "0" || body["elided"] != "0" || body["encoding"] != "base64" {
		t.Errorf("omitted body %v, want an empty kept and the captured length %s", body, length)
	}
	content, _ := body["content"].(map[string]any)
	if len(content) != 2 || content["state"] != "omitted" || content["reason"] != reason {
		t.Errorf("omission marker %v, want state omitted and reason %s", body["content"], reason)
	}
	structure, _ := m["structure"].(map[string]any)
	if len(structure) != 1 || structure["state"] != "omitted" {
		t.Errorf("omitted body's structure %v, want only state omitted", m["structure"])
	}
	if _, ok := m["framing"].(string); !ok {
		t.Errorf("omitted body's framing was not sent: %v", m)
	}
}

func extCodedRemovedOf(t *testing.T, message map[string]any, side string) []any {
	t.Helper()
	x := message["exchange"].(map[string]any)
	var out []any
	for _, entry := range x["removed"].([]any) {
		if entry.(map[string]any)["message"] == side {
			out = append(out, entry)
		}
	}
	return out
}

// TestAnExtensionIsSentADecodedBodyBeforeClose: on an open connection, a gzip
// response between two plain exchanges reaches a ready extension decoded,
// with removal applied to the decoded content and a record of its decoding,
// and the exchange after it follows, all before the connection ends.
func TestAnExtensionIsSentADecodedBodyBeforeClose(t *testing.T) {
	const secret = "DECODED_SECRET_5e1d"
	plain := `{"id":1,"secret":"` + secret + `","list":[1,2]}`
	encoded := extCodedGzip(t, plain)
	pairs := [][2]string{extCodedPlain(0), {extCodedRequest(1), extCodedResponse("Content-Encoding: gzip\r\n", encoded)}, extCodedPlain(2)}
	c := extCodedConversation(t, pairs)
	f := extCodedChainNew(t, 1, []string{"response.headers", "response.body"}, map[string]any{"remove": map[string]any{"json": map[string]any{"response": []string{"/secret"}}}}, nil)
	f.give(t, c.fragments)
	messages, raw := f.sent(t, 0, 3)
	if f.store.Stats().Connections != 0 {
		t.Fatal("wiring, not the property: the retirement arrived before the open-connection assertions")
	}
	for i, m := range messages {
		if m["index"] != float64(i) || m["id"] != strconv.Itoa(i+1) {
			t.Errorf("exchange %d sent with index %v and id %v", i, m["index"], m["id"])
		}
		if output := m["output"].(map[string]any); output["state"] != "eligible" {
			t.Errorf("exchange %d sent %v, want eligible", i, output)
		}
	}
	response := extCodedSide(t, messages[1], "response")
	if kept := extCodedKept(t, response); kept != `{"id":1,"list":[1,2]}` {
		t.Errorf("decoded body sent as %q, want the decoded content with /secret removed", kept)
	}
	body, _ := response["body"].(map[string]any)
	if body["length"] != strconv.Itoa(len(encoded)) {
		t.Errorf("body length %v, want the captured extent %d", body["length"], len(encoded))
	}
	content, _ := body["content"].(map[string]any)
	codings, _ := content["codings"].([]any)
	if content["state"] != "decoded" || content["length"] != strconv.Itoa(len(plain)) || !slices.Equal(codings, []any{"gzip"}) {
		t.Errorf("decoding record %v, want decoded, %d bytes, gzip", body["content"], len(plain))
	}
	structure, _ := response["structure"].(map[string]any)
	shape, _ := structure["shape"].(map[string]any)
	if structure["state"] != "derived" || shape["kind"] != "object" || len(shape["fields"].([]any)) != 2 {
		t.Errorf("structure %v, want an object of two members derived from the decoded content", structure)
	}
	extCodedAbsent(t, raw[1], []byte(secret), encoded[:10])
	if removed := extCodedRemovedOf(t, messages[1], "response"); len(removed) != 1 {
		t.Errorf("removals %v, want the one /secret removal", removed)
	}
	if kept := extCodedKept(t, extCodedSide(t, messages[2], "response")); kept != `{"plain":2}` {
		t.Errorf("the exchange after the decoded one sent %q", kept)
	}
	var lines map[int]processing.Artifact
	extensionDeliveryWait(t, "the three exchanges were not written before close", func() bool {
		lines = f.exchangeLines(t)
		return len(lines) == 3
	})
	written := lines[1].Reconstruction.Exchanges[0].Response.Message
	if kept, _ := base64.StdEncoding.DecodeString(written.Body.Kept); string(kept) != `{"id":1,"list":[1,2]}` || written.Body.Content == nil || written.Body.Content.State != record.ContentDecoded {
		t.Errorf("written body %q content %+v, want the decoded content with its record", kept, written.Body.Content)
	}
	out := f.finish(t, c.finals[0])
	if out.Excluded.Total() != 0 || out.ExchangeIDs != 3 || out.Written != 4 {
		t.Errorf("outcome excluded %+v ids %d written %d, want none excluded, 3 ids, 4 lines", out.Excluded, out.ExchangeIDs, out.Written)
	}
	if granted := f.ledger(t); granted == 0 {
		t.Error("wiring, not the property: no decoding charge was granted, so nothing was decoded")
	}
	f.drained(t)
}

// TestAnExchangeWithAnUnsupportedCodingIsExcludedAloneOnTheChain: a response
// coded compress between two plain exchanges is excluded alone, sent to every
// extension at once with its reason, counted once however many extensions
// there are, and the exchange after it is written before close.
func TestAnExchangeWithAnUnsupportedCodingIsExcludedAloneOnTheChain(t *testing.T) {
	for _, last := range []bool{false, true} {
		t.Run(fmt.Sprintf("last=%t", last), func(t *testing.T) {
			extCodedExcludedAloneOnTheChain(t, last)
		})
	}
}

func extCodedExcludedAloneOnTheChain(t *testing.T, last bool) {
	pairs := [][2]string{extCodedPlain(0), {extCodedRequest(1), extCodedResponse("Content-Encoding: compress\r\n", []byte("\x1f\x9d\x90compressed"))}}
	if !last {
		pairs = append(pairs, extCodedPlain(2))
	}
	n := len(pairs)
	c := extCodedConversation(t, pairs)
	f := extCodedChainNew(t, 2, []string{"response.body"}, nil, nil)
	f.give(t, c.fragments)
	for k := range 2 {
		messages, _ := f.sent(t, k, n)
		for i, m := range messages {
			output := m["output"].(map[string]any)
			want := map[string]any{"state": "eligible"}
			if i == 1 {
				want = map[string]any{"state": "excluded", "reason": processing.ReasonContentCodingUnsupported}
			}
			if fmt.Sprint(output) != fmt.Sprint(want) || m["index"] != float64(i) {
				t.Errorf("extension %d exchange %d sent %v at index %v, want %v", k, i, output, m["index"], want)
			}
		}
	}
	var lines map[int]processing.Artifact
	extensionDeliveryWait(t, "the exchanges around the excluded one were not written before close", func() bool {
		lines = f.exchangeLines(t)
		return len(lines) == n-1
	})
	if _, ok := lines[1]; ok {
		t.Error("the excluded exchange was written")
	}
	if f.store.Stats().Connections != 0 {
		t.Fatal("wiring, not the property: the retirement arrived before the open-connection assertions")
	}
	out := f.finish(t, c.finals[0])
	if out.Excluded != (processing.Exclusions{ContentCodingUnsupported: 1}) || out.ExchangeIDs != uint64(n) {
		t.Errorf("excluded %+v with %d ids, want one content_coding_unsupported of %d", out.Excluded, out.ExchangeIDs, n)
	}
	for k, counts := range out.Extensions {
		if counts.Considered != uint64(n) || counts.Pending != 0 {
			t.Errorf("extension %d considered %d, pending %d", k, counts.Considered, counts.Pending)
		}
	}
	connections := 0
	for _, a := range f.artifacts(t) {
		if a.Record != processing.ArtifactConnection {
			continue
		}
		connections++
		if a.ExcludedExchanges == nil || a.ExcludedExchanges.ContentCodingUnsupported != "1" || a.ExcludedExchanges.ContentDecodingFailed != "0" ||
			a.ExcludedExchanges.ContentDecodedTooLarge != "0" || a.ExcludedExchanges.ContentDecodingTooCostly != "0" {
			t.Errorf("connection line counts %+v, want one content_coding_unsupported", a.ExcludedExchanges)
		}
		if a.ReconstructionTruncation != nil {
			t.Errorf("an exclusion alone left a truncated suffix: %+v", a.ReconstructionTruncation)
		}
	}
	if connections != 1 {
		t.Errorf("%d connection lines, want 1", connections)
	}
	for k, peer := range f.peers {
		done := peer.done()
		if len(done) != 1 || done[0]["count"] != strconv.Itoa(n) {
			t.Errorf("extension %d connection_done %v, want one counting %d", k, done, n)
		}
	}
	if n := f.reserving(); n != 0 {
		t.Errorf("%d decoding charges asked for an exchange decided by its header", n)
	}
	f.drained(t)
}

// TestAnUndecodedBodyAndAnythingDerivedFromItNeverReachAnExtension: a body
// that is not decoded is omitted from what an extension is sent, with the
// exclusion reason as its marker, whatever its bytes would parse as, whichever
// reason excluded it, and whether a rule removed its Content-Encoding.
func TestAnUndecodedBodyAndAnythingDerivedFromItNeverReachAnExtension(t *testing.T) {
	const field, value = "SENTINEL_FIELD_83c2", "SENTINEL_VALUE_83c2"
	opaque := []byte(`{"` + field + `":"` + value + `"}`)
	late := extCodedGzip(t, string(opaque))
	late[len(late)-8] ^= 0xff
	cases := []struct {
		name       string
		fields     string
		body       []byte
		reason     string
		rules      map[string]any
		headerless bool
	}{
		{"declared gzip, plain JSON", "Content-Encoding: gzip\r\n", opaque, processing.ReasonContentDecodingFailed, nil, false},
		{"gzip failing at its checksum", "Content-Encoding: gzip\r\n", late, processing.ReasonContentDecodingFailed, nil, false},
		{"unsupported coding", "Content-Encoding: compress\r\n", opaque, processing.ReasonContentCodingUnsupported, nil, false},
		{"two codings", "Content-Encoding: gzip\r\nContent-Encoding: gzip\r\n", opaque, processing.ReasonContentCodingUnsupported, nil, false},
		{"Content-Encoding removed", "Content-Encoding: gzip\r\n", opaque, processing.ReasonContentDecodingFailed,
			map[string]any{"remove": map[string]any{"headers": []string{"content-encoding"}}}, true},
		{"a removal naming the sentinel member", "Content-Encoding: gzip\r\n", opaque, processing.ReasonContentDecodingFailed,
			map[string]any{"remove": map[string]any{"json": map[string]any{"response": []string{"/" + field}}}}, false},
	}
	all := []string{"request.line", "request.headers", "request.body", "response.line", "response.headers", "response.body", "connection"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pairs := [][2]string{extCodedPlain(0), {extCodedRequest(1), extCodedResponse(tc.fields, tc.body)}, extCodedPlain(2)}
			c := extCodedConversation(t, pairs)
			f := extCodedChainNew(t, 1, all, tc.rules, nil)
			f.give(t, c.fragments)
			messages, raw := f.sent(t, 0, 3)
			output := messages[1]["output"].(map[string]any)
			if output["state"] != "excluded" {
				t.Fatalf("wiring, not the property: the fixture's exchange was sent %v, not excluded", output)
			}
			if output["reason"] != tc.reason {
				t.Errorf("the exchange was excluded as %v, want %s", output["reason"], tc.reason)
			}
			reason, _ := output["reason"].(string)
			extCodedOmitted(t, extCodedSide(t, messages[1], "response"), reason, strconv.Itoa(len(tc.body)))
			extCodedAbsent(t, raw[1], []byte(field), []byte(value), tc.body[:8])
			for _, entry := range extCodedRemovedOf(t, messages[1], "response") {
				if field, _ := entry.(map[string]any)["field"].(string); !strings.HasPrefix(field, "message.headers.") {
					t.Errorf("a removal from an omitted body was sent: %v", entry)
				}
			}
			if tc.headerless {
				for _, h := range extCodedSide(t, messages[1], "response")["headers"].([]any) {
					if strings.EqualFold(h.(map[string]any)["name"].(string), "content-encoding") {
						t.Error("a removed Content-Encoding header was sent")
					}
				}
				if bytes.Contains(raw[1], []byte("gzip")) {
					t.Error("the removed coding's name reached the extension")
				}
			}
			if kept := extCodedKept(t, extCodedSide(t, messages[2], "response")); kept != `{"plain":2}` {
				t.Errorf("the exchange after the omitted one sent %q", kept)
			}
			out := f.finish(t, c.finals[0])
			if out.Excluded.Total() != 1 {
				t.Errorf("excluded %+v, want one", out.Excluded)
			}
			f.ledger(t)
			f.drained(t)
		})
	}
}

// TestAMixedDefectWithAnEncodedBodyStopsAndOmitsIt: an exchange a stop
// excludes, one of whose messages carries an encoded body, stops its
// connection's output under the stop's reason, is never decoded, and its
// encoded body is omitted with that reason as its marker.
func TestAMixedDefectWithAnEncodedBodyStopsAndOmitsIt(t *testing.T) {
	const field = "SENTINEL_FIELD_d40a"
	encoded := extCodedGzip(t, `{"`+field+`":1}`)
	chunked := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(encoded), encoded)
	cases := []struct {
		name              string
		request, response string
	}{
		{"a stopped request beside an encoded response",
			"POST /item-1 HTTP/1.1\r\nHost: fixture\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
			extCodedResponse("Content-Encoding: gzip\r\n", encoded)},
		{"an encoded response that stops itself", extCodedRequest(1),
			"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: gzip, chunked\r\n\r\n" + chunked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pairs := [][2]string{extCodedPlain(0), {tc.request, tc.response}, extCodedPlain(2)}
			c := extCodedConversation(t, pairs)
			f := extCodedChainNew(t, 1, []string{"request.body", "response.headers", "response.body"}, nil, nil)
			f.give(t, c.fragments)
			out := f.finish(t, c.finals[0])
			messages, raw := f.sent(t, 0, 3)
			output := messages[1]["output"].(map[string]any)
			reason, _ := output["reason"].(string)
			if output["state"] != "excluded" || reason == "" || strings.HasPrefix(reason, "content_") {
				t.Fatalf("wiring, not the property: the stopped exchange was sent %v, not excluded under a stop", output)
			}
			if later := messages[2]["output"].(map[string]any); later["state"] != "excluded" {
				t.Errorf("the exchange after the stop was sent %v", later)
			}
			response := extCodedSide(t, messages[1], "response")
			body, _ := response["body"].(map[string]any)
			length, _ := body["length"].(string)
			extCodedOmitted(t, response, reason, length)
			extCodedAbsent(t, raw[1], []byte(field), encoded[:10])
			if lines := f.exchangeLines(t); len(lines) != 1 {
				t.Errorf("%d exchanges written, want only the one before the stop", len(lines))
			} else if _, ok := lines[0]; !ok {
				t.Error("the exchange before the stop was not written")
			}
			truncated := false
			for _, a := range f.artifacts(t) {
				if a.Record == processing.ArtifactConnection && a.ReconstructionTruncation != nil {
					for _, stop := range a.ReconstructionTruncation.Stops {
						truncated = truncated || stop.Reason == reason
					}
				}
			}
			if !truncated {
				t.Errorf("the connection line names no stop %s", reason)
			}
			if out.Excluded.Total() != 0 {
				t.Errorf("a stop counted as an exclusion alone: %+v", out.Excluded)
			}
			if n := f.reserving(); n != 0 {
				t.Errorf("%d decoding charges asked for a stopped exchange", n)
			}
			f.drained(t)
		})
	}
}

// TestAReplacedDecodedBodyIsContentAndNeverDecodedAgain: the first of two
// extensions replaces a decoded body; the replacement goes through the rules
// as content, the second extension and the output see it sanitised and not
// decoded again, and the record of the captured body's decoding stays.
func TestAReplacedDecodedBodyIsContentAndNeverDecodedAgain(t *testing.T) {
	const secret = "REPLACED_SECRET_a91f"
	plain := `{"secret":"captured","id":7}`
	pairs := [][2]string{{extCodedRequest(0), extCodedResponse("Content-Encoding: gzip\r\n", extCodedGzip(t, plain))}}
	c := extCodedConversation(t, pairs)
	replacement := `{"secret":"` + secret + `","kept":1}`
	answer := func(k int, message map[string]any) map[string]any {
		if k != 0 {
			return nil
		}
		return map[string]any{"response.body": map[string]any{"kept": base64.StdEncoding.EncodeToString([]byte(replacement))}}
	}
	f := extCodedChainNew(t, 2, []string{"response.headers", "response.body"}, map[string]any{"remove": map[string]any{"json": map[string]any{"response": []string{"/secret"}}}}, answer)
	f.give(t, c.fragments)
	_, firstRaw := f.sent(t, 0, 1)
	second, secondRaw := f.sent(t, 1, 1)
	if !bytes.Contains(firstRaw[0], []byte(`"decoded"`)) {
		t.Fatal("wiring, not the property: the first extension was not sent a decoded body")
	}
	response := extCodedSide(t, second[0], "response")
	if kept := extCodedKept(t, response); kept != `{"kept":1}` {
		t.Errorf("the second extension was sent %q, want the replacement with /secret removed", kept)
	}
	content := extCodedContent(response)
	codings, _ := content["codings"].([]any)
	if content["state"] != "decoded" || content["length"] != strconv.Itoa(len(plain)) || !slices.Equal(codings, []any{"gzip"}) {
		t.Errorf("the record of the decoding after a replacement is %v, want the captured body's", content)
	}
	extCodedAbsent(t, secondRaw[0], []byte(secret))
	var lines map[int]processing.Artifact
	extensionDeliveryWait(t, "the replaced exchange was not written", func() bool {
		lines = f.exchangeLines(t)
		return len(lines) == 1
	})
	a := lines[0]
	written := a.Reconstruction.Exchanges[0].Response.Message
	if kept, _ := base64.StdEncoding.DecodeString(written.Body.Kept); string(kept) != `{"kept":1}` {
		t.Errorf("written body %q, want the sanitised replacement", kept)
	}
	if written.Body.Content == nil || written.Body.Content.Length != strconv.Itoa(len(plain)) {
		t.Errorf("written decoding record %+v, want the captured body's", written.Body.Content)
	}
	if len(a.ExtensionOutcomes) != 2 || a.ExtensionOutcomes[0].Outcome != extension.Changed || a.ExtensionOutcomes[1].Outcome != extension.Unchanged {
		t.Errorf("extension outcomes %+v, want changed then unchanged", a.ExtensionOutcomes)
	}
	if len(a.ReplacementExclusions) != 1 || a.ReplacementExclusions[0].Extension != "coded0" {
		t.Errorf("replacement exclusions %+v, want the /secret removal attributed to coded0", a.ReplacementExclusions)
	}
	lines2, _ := f.output.snapshot()
	extCodedAbsent(t, lines2[0], []byte(secret))
	f.finish(t, c.finals[0])
	f.ledger(t)
	f.drained(t)
}

// TestTheDecodingRecordCannotBeReplaced: an answer whose body replacement
// names content fails as read_only, on a decoded body and on one sent as
// captured alike, and the body is written as the rules left it.
func TestTheDecodingRecordCannotBeReplaced(t *testing.T) {
	plain := `{"id":3}`
	for _, decoded := range []bool{false, true} {
		t.Run(fmt.Sprintf("decoded=%t", decoded), func(t *testing.T) {
			response := extCodedResponse("", []byte(plain))
			if decoded {
				response = extCodedResponse("Content-Encoding: gzip\r\n", extCodedGzip(t, plain))
			}
			c := extCodedConversation(t, [][2]string{{extCodedRequest(0), response}})
			answer := func(int, map[string]any) map[string]any {
				return map[string]any{"response.body": map[string]any{"kept": base64.StdEncoding.EncodeToString([]byte(`{"id":4}`)),
					"content": map[string]any{"state": "decoded", "length": "8"}}}
			}
			f := extCodedChainNew(t, 1, []string{"response.body"}, nil, answer)
			f.give(t, c.fragments)
			f.sent(t, 0, 1)
			var lines map[int]processing.Artifact
			extensionDeliveryWait(t, "the exchange was not written", func() bool {
				lines = f.exchangeLines(t)
				return len(lines) == 1
			})
			outcomes := lines[0].ExtensionOutcomes
			if len(outcomes) != 1 || outcomes[0].Outcome != extension.Failed || outcomes[0].Reason != extension.ReadOnly {
				t.Errorf("outcomes %+v, want one failed as read_only", outcomes)
			}
			written := lines[0].Reconstruction.Exchanges[0].Response.Message
			if kept, _ := base64.StdEncoding.DecodeString(written.Body.Kept); string(kept) != plain {
				t.Errorf("written body %q, want the content %q", kept, plain)
			}
			f.finish(t, c.finals[0])
			f.drained(t)
		})
	}
}

// TestAChangeToAnExchangeExcludedAloneFails: a replacement answered for an
// exchange excluded alone fails as excluded, and the exchange after it is
// written.
func TestAChangeToAnExchangeExcludedAloneFails(t *testing.T) {
	pairs := [][2]string{{extCodedRequest(0), extCodedResponse("Content-Encoding: gzip\r\n", []byte("not gzip"))}, extCodedPlain(1)}
	c := extCodedConversation(t, pairs)
	answer := func(int, map[string]any) map[string]any {
		return map[string]any{"response.body": map[string]any{"kept": base64.StdEncoding.EncodeToString([]byte(`{}`))}}
	}
	f := extCodedChainNew(t, 1, []string{"response.body"}, nil, answer)
	f.give(t, c.fragments)
	messages, _ := f.sent(t, 0, 2)
	output := messages[0]["output"].(map[string]any)
	if output["state"] != "excluded" {
		t.Fatalf("wiring, not the property: the fixture's exchange was sent %v, not excluded", output)
	}
	if output["reason"] != processing.ReasonContentDecodingFailed {
		t.Errorf("the exchange was excluded as %v, want it excluded alone as %s", output["reason"], processing.ReasonContentDecodingFailed)
	}
	extensionDeliveryWait(t, "the exchange after the excluded one was not written", func() bool { return len(f.exchangeLines(t)) == 1 })
	out := f.finish(t, c.finals[0])
	if failed := out.Extensions[0].FailedBy[extension.Excluded]; failed != 1 {
		t.Errorf("changes to the excluded exchange failed as excluded %d times, want 1: %+v", failed, out.Extensions[0].FailedBy)
	}
	if out.Excluded != (processing.Exclusions{ContentDecodingFailed: 1}) {
		t.Errorf("excluded %+v", out.Excluded)
	}
	f.drained(t)
}

// TestADecodedSideOfAnExcludedExchangeIsSentAsContent: of an exchange
// excluded alone, a side whose decoding completed is sent decoded, removal
// applied, and a side whose decoding did not complete is omitted; a side
// never decoded, because the other side's coding decided the exchange first,
// is omitted without any decoding.
func TestADecodedSideOfAnExcludedExchangeIsSentAsContent(t *testing.T) {
	const secret = "SIDE_SECRET_0b7e"
	plain := `{"id":5,"secret":"` + secret + `"}`
	encoded := extCodedGzip(t, plain)
	request := func(fields string, body []byte) string {
		return fmt.Sprintf("POST /item-1 HTTP/1.1\r\nHost: fixture\r\n%sContent-Length: %d\r\n\r\n%s", fields, len(body), body)
	}
	cases := []struct {
		name     string
		request  string
		reason   string
		decoded  bool
		reserves bool
	}{
		{"the request fails, the response decodes", request("Content-Encoding: gzip\r\n", []byte("not gzip")),
			processing.ReasonContentDecodingFailed, true, true},
		{"the request's coding decides, the response is never decoded", request("Content-Encoding: compress\r\n", []byte("compressed")),
			processing.ReasonContentCodingUnsupported, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pairs := [][2]string{extCodedPlain(0), {tc.request, extCodedResponse("Content-Encoding: gzip\r\n", encoded)}, extCodedPlain(2)}
			c := extCodedConversation(t, pairs)
			f := extCodedChainNew(t, 1, []string{"request.body", "response.body"},
				map[string]any{"remove": map[string]any{"json": map[string]any{"response": []string{"/secret"}}}}, nil)
			f.give(t, c.fragments)
			messages, raw := f.sent(t, 0, 3)
			output := messages[1]["output"].(map[string]any)
			if output["state"] != "excluded" {
				t.Fatalf("wiring, not the property: the fixture's exchange was sent %v, not excluded", output)
			}
			if output["reason"] != tc.reason {
				t.Errorf("the exchange was excluded as %v, want %s", output["reason"], tc.reason)
			}
			reason, _ := output["reason"].(string)
			requestSide := extCodedSide(t, messages[1], "request")
			requestBody, _ := requestSide["body"].(map[string]any)
			requestLength, _ := requestBody["length"].(string)
			extCodedOmitted(t, requestSide, reason, requestLength)
			response := extCodedSide(t, messages[1], "response")
			if !tc.decoded {
				extCodedOmitted(t, response, reason, strconv.Itoa(len(encoded)))
				extCodedAbsent(t, raw[1], []byte(secret), encoded[:10])
			} else {
				if kept := extCodedKept(t, response); kept != `{"id":5}` {
					t.Errorf("the decoded side was sent %q, want its content with /secret removed", kept)
				}
				content := extCodedContent(response)
				if content["state"] != "decoded" || content["length"] != strconv.Itoa(len(plain)) {
					t.Errorf("the decoded side's record %v", content)
				}
				extCodedAbsent(t, raw[1], []byte(secret), encoded[:10])
			}
			if reserving := f.reserving(); (reserving != 0) != tc.reserves {
				t.Errorf("%d decoding charges asked, want some: %t", reserving, tc.reserves)
			}
			extensionDeliveryWait(t, "the exchange after the excluded one was not written before close", func() bool { return len(f.exchangeLines(t)) == 2 })
			out := f.finish(t, c.finals[0])
			if out.Excluded.Total() != 1 {
				t.Errorf("excluded %+v, want one", out.Excluded)
			}
			f.ledger(t)
			f.drained(t)
		})
	}
}

// TestARefusedDecodingReservationCutsTheConnectionOnTheChain: a decoding whose
// charge the shared allowance refuses cuts the connection under the counted
// cut. The exchange takes no id, no extension is sent it, nothing is counted
// as excluded, the exchange before it stays written, and every charge comes
// back.
func TestARefusedDecodingReservationCutsTheConnectionOnTheChain(t *testing.T) {
	pairs := [][2]string{extCodedPlain(0), {extCodedRequest(1), extCodedResponse("Content-Encoding: gzip\r\n", extCodedGzip(t, `{"id":1}`))}, extCodedPlain(2)}
	c := extCodedConversation(t, pairs)
	f := extCodedChainNew(t, 1, []string{"response.body"}, nil, nil)
	f.give(t, c.fragments[:2])
	f.sent(t, 0, 1)
	// The allowance is filled at the decoding's first charge and given back at
	// its refusal, so nothing after the decoding finds it full: only the
	// decoding's own reservation is refused.
	var pressure int64
	filled, returned := false, false
	f.mutex.Lock()
	f.onCharge = func(e processing.DecodeCharge) {
		if e.Index != 1 {
			return
		}
		switch {
		case e.Event == processing.ChargeReserving && !filled:
			filled = true
			s := f.store.Stats()
			if pressure = s.LimitBytes - s.Bytes - s.Parsing - s.Policy; pressure <= 0 || !f.store.Reserve(intake.Policy, pressure) {
				pressure = 0
			}
		case e.Event == processing.ChargeRefused && pressure > 0 && !returned:
			f.store.Return(intake.Policy, pressure)
			returned = true
		}
	}
	f.mutex.Unlock()
	f.give(t, c.fragments[2:4])
	extensionDeliveryWait(t, "wiring, not the property: the exchange's decoding never asked the allowance for a charge", func() bool {
		f.mutex.Lock()
		defer f.mutex.Unlock()
		return filled
	})
	if !f.waitFor(func() bool {
		f.mutex.Lock()
		defer f.mutex.Unlock()
		return returned
	}) {
		t.Error("the decoding's reservation was not refused")
	}
	f.mutex.Lock()
	f.onCharge = nil
	held, gaveBack := pressure, returned
	f.mutex.Unlock()
	if held == 0 {
		t.Fatal("wiring, not the property: the fixture could not fill the allowance at the decoding's first charge")
	}
	if !gaveBack {
		f.store.Return(intake.Policy, held)
	}
	if !f.waitFor(func() bool { return f.run.Snapshot().ConnectionsCut == 1 }) {
		t.Error("the refused decoding did not cut its connection")
	}
	refused := 0
	f.mutex.Lock()
	for _, e := range f.charges {
		if e.Event == processing.ChargeRefused {
			refused++
		}
	}
	f.mutex.Unlock()
	if refused != 1 {
		t.Errorf("%d decoding charges refused, want 1", refused)
	}
	f.give(t, c.fragments[4:])
	out := f.finish(t, c.finals[0])
	if out.ConnectionsCut != 1 || out.AllowanceCut != 1 || out.Excluded.Total() != 0 || out.ExchangeIDs != 1 {
		t.Errorf("cut %d, by the allowance %d, excluded %+v, ids %d; want one counted cut, nothing excluded, one id",
			out.ConnectionsCut, out.AllowanceCut, out.Excluded, out.ExchangeIDs)
	}
	if messages, _ := f.peers[0].exchanges(); len(messages) != 1 {
		t.Errorf("the extension was sent %d exchanges, want only the one before the cut", len(messages))
	}
	if done := f.peers[0].done(); len(done) != 1 || done[0]["count"] != "1" {
		t.Errorf("connection_done %v, want one counting 1", done)
	}
	lines := f.exchangeLines(t)
	if _, ok := lines[0]; len(lines) != 1 || !ok {
		t.Errorf("%d exchanges written, want only the one before the cut", len(lines))
	}
	for _, a := range f.artifacts(t) {
		if a.Record != processing.ArtifactConnection {
			continue
		}
		if a.ReconstructionTruncation == nil {
			t.Error("the cut connection's line has no truncation")
			continue
		}
		for _, stop := range a.ReconstructionTruncation.Stops {
			if stop.Reason != processing.TruncationConnectionCut {
				t.Errorf("a stop %+v, want connection_cut", stop)
			}
		}
	}
	f.ledger(t)
	f.drained(t)
}
