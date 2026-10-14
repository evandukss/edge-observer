package processing_test

import (
	"bufio"
	"bytes"
	"context"
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

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/reconstruct"
)

// The peer is the same test binary in protocol-only mode. It records messages
// before answering and never transforms an exchange, eligible or excluded.
func TestEncodingProtocolPeer(t *testing.T) {
	path := os.Getenv("OBSERVER_ENCODING_AUDIT")
	if path == "" {
		return
	}
	audit, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		os.Exit(2)
	}
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 16<<20)
	for scan.Scan() {
		var m struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}
		if json.Unmarshal(scan.Bytes(), &m) != nil {
			os.Exit(3)
		}
		if _, err = audit.Write(append(append([]byte(nil), scan.Bytes()...), '\n')); err != nil {
			os.Exit(4)
		}
		switch m.Type {
		case "start":
			err = json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "ready", "protocol": "observer.extension/2"})
		case "exchange":
			err = json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "result", "id": m.ID, "outcome": "unchanged"})
		case "shutdown":
			_ = audit.Close()
			os.Exit(0)
		}
		if err != nil {
			os.Exit(5)
		}
	}
	if scan.Err() != nil {
		os.Exit(6)
	}
	_ = audit.Close()
	os.Exit(0)
}

type encodingAudit struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Index  int    `json:"index"`
	Count  string `json:"count"`
	Output struct {
		State  string `json:"state"`
		Reason string `json:"reason"`
	} `json:"output"`
}
type encodingConcurrentOutput struct {
	mu     sync.Mutex
	output encodingOutput
}

func (o *encodingConcurrentOutput) WriteApproved(ctx context.Context, a processing.Approved) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.output.WriteApproved(ctx, a)
}
func (o *encodingConcurrentOutput) snapshot() *encodingOutput {
	o.mu.Lock()
	defer o.mu.Unlock()
	return &encodingOutput{lines: append([][]byte(nil), o.output.lines...), artifacts: append([]processing.Artifact(nil), o.output.artifacts...)}
}

type encodingExtension struct {
	chargeMu sync.Mutex
	charges  []processing.DecodeCharge
	onCharge func(processing.DecodeCharge)
	run      *processing.Run
	store    *intake.Store
	output   *encodingConcurrentOutput
	audits   []string
	taken    atomic.Int64
	turns    chan struct{}
}

func encodingExtensionNew(t *testing.T, peers, inputBound int, extra map[string]any) *encodingExtension {
	t.Helper()
	return encodingExtensionWithin(t, peers, inputBound, encodingBodyBound, extra)
}

// encodingExtensionWithin is a run with ready extensions under the given
// pending-input and body bounds.
func encodingExtensionWithin(t *testing.T, peers, inputBound, bodyBound int, extra map[string]any) *encodingExtension {
	t.Helper()
	f := &encodingExtension{output: &encodingConcurrentOutput{}, turns: make(chan struct{}, 1024)}
	var entries []any
	for i := range peers {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		f.audits = append(f.audits, path)
		entries = append(entries, map[string]any{"name": fmt.Sprintf("observe%d", i), "command": []string{"/usr/bin/env", "OBSERVER_ENCODING_AUDIT=" + path, os.Args[0], "-test.run=^TestEncodingProtocolPeer$"}, "fields": []string{"request.headers", "response.headers", "request.body", "response.body"}, "timeout_ms": 10000})
	}
	document := map[string]any{"version": "observer.config/1", "output": "/var/lib/observer", "write_content": true, "watch": []any{map[string]any{"name": "api", "exe": "/usr/bin/php"}}, "extensions": entries}
	for key, value := range extra {
		document[key] = value
	}
	doc, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	compiled, findings := config.Compile(doc, "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: extension config: %+v", findings)
	}
	f.store, err = intake.New(64 << 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4096, IntakeExhausted: f.store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := processing.Open(t.TempDir(), 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	ready := make(chan struct{}, peers)
	options := processing.Options{Session: "encoding-continuation", PolicyRevision: "fixture", Plan: compiled.Plan, Intake: f.store, Gate: gate, Output: f.output, Derived: writer, ConnectionInput: inputBound, Limits: reconstruct.Limits{HTTP: http1.Limits{MaxBodyBytes: bodyBound}}, Taken: func(int, fragment.Process, fragment.ConnectionID) { f.taken.Add(1) }, Supervision: func(e extension.Event) {
		if e.Kind == extension.Ready {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	}}
	options = processing.ObserveTurns(options, func(processing.Turn) {
		select {
		case f.turns <- struct{}{}:
		default:
		}
	})
	options = processing.ObserveDecodeCharges(options, func(e processing.DecodeCharge) {
		f.chargeMu.Lock()
		defer f.chargeMu.Unlock()
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
	for range peers {
		select {
		case <-ready:
		case <-time.After(8 * time.Second):
			t.Fatal("wiring, not the property: extension never became ready")
		}
	}
	return f
}
func (f *encodingExtension) chargeSnapshot() []processing.DecodeCharge {
	f.chargeMu.Lock()
	defer f.chargeMu.Unlock()
	return append([]processing.DecodeCharge(nil), f.charges...)
}
func (f *encodingExtension) messages(t *testing.T, peer int) []encodingAudit {
	t.Helper()
	b, err := os.ReadFile(f.audits[peer])
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []encodingAudit
	// Only newline-terminated writes are complete while the peer is running.
	for _, line := range bytes.Split(b, []byte{'\n'})[:bytes.Count(b, []byte{'\n'})] {
		var m encodingAudit
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("wiring, not the property: invalid peer audit: %v", err)
		}
		out = append(out, m)
	}
	return out
}
func (f *encodingExtension) await(t *testing.T, why string, condition func() bool) bool {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for !condition() {
		select {
		case <-f.turns:
		case <-ticker.C:
		case <-deadline.C:
			t.Errorf("%s", why)
			return false
		}
	}
	return true
}
func (f *encodingExtension) give(t *testing.T, fragments []fragment.Record) {
	t.Helper()
	before := f.taken.Load()
	for _, r := range fragments {
		if err := f.store.Write(r); err != nil {
			t.Fatalf("wiring, not the property: extension intake: %v", err)
		}
	}
	f.run.Route()
	if !f.await(t, "wiring, not the property: supplied fragments did not reach the extension worker", func() bool { return f.taken.Load() == before+int64(len(fragments)) }) {
		t.FailNow()
	}
	if f.store.Stats().Connections != 0 {
		t.Fatal("wiring, not the property: retirement arrived before online extension assertions")
	}
}
func (f *encodingExtension) settle(t *testing.T, ids int) {
	t.Helper()
	f.await(t, fmt.Sprintf("before close: extension did not finish all %d issued exchanges", ids), func() bool {
		o := f.run.Snapshot()
		if len(o.Extensions) != len(f.audits) {
			return false
		}
		for _, e := range o.Extensions {
			if e.Considered != uint64(ids) || e.Pending != 0 {
				return false
			}
		}
		return true
	})
}

func (f *encodingExtension) checkOnline(t *testing.T, pairs []encodingPair) {
	t.Helper()
	f.settle(t, len(pairs))
	f.await(t, "before close: valid traffic after exclusions was not written", func() bool {
		return len(f.output.snapshot().artifacts) == len(pairs)-int(encodingExpected(pairs).Total())
	})
	helper := &encodingWorker{output: f.output.snapshot()}
	helper.checkOnline(t, pairs, f.run.Snapshot())
	for peer := range f.audits {
		exchanges := 0
		for _, m := range f.messages(t, peer) {
			if m.Type == "connection_done" {
				t.Error("extension got connection_done before close")
			}
			if m.Type != "exchange" {
				continue
			}
			index := exchanges
			exchanges++
			if index >= len(pairs) {
				t.Error("extension received more exchanges than supplied pairs")
				continue
			}
			id, err := strconv.ParseUint(m.ID, 10, 64)
			if err != nil || id != uint64(index+1) || m.Index != index {
				t.Errorf("extension %d id/index=%q/%d, want %d/%d", peer, m.ID, m.Index, index+1, index)
			}
			reason := pairs[index].reason
			state := "eligible"
			if reason != "" {
				state = "excluded"
			}
			if m.Output.State != state || m.Output.Reason != reason {
				t.Errorf("extension %d pair %d classification=%+v, want %s/%s", peer, index, m.Output, state, reason)
			}
		}
		if exchanges != len(pairs) {
			t.Errorf("before close: extension %d received %d of %d pairs", peer, exchanges, len(pairs))
		}
	}
}
func (f *encodingExtension) finish(t *testing.T, r connection.Record) processing.Outcome {
	t.Helper()
	before := f.taken.Load()
	if err := f.store.Connection(r); err != nil {
		t.Fatal(err)
	}
	f.run.Route()
	if !f.await(t, "wiring, not the property: extension worker did not take retirement", func() bool { return f.taken.Load() == before+1 }) {
		t.FailNow()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := f.run.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func (f *encodingExtension) checkDone(t *testing.T, ids int) {
	t.Helper()
	for peer := range f.audits {
		done := 0
		for _, m := range f.messages(t, peer) {
			if m.Type == "connection_done" {
				done++
				n, err := strconv.ParseUint(m.Count, 10, 64)
				if err != nil || n != uint64(ids) {
					t.Errorf("extension %d connection_done count=%q, want %d", peer, m.Count, ids)
				}
			}
		}
		if done != 1 {
			t.Errorf("extension %d connection_done population=%d, want 1", peer, done)
		}
	}
}
func encodingExtensionScenario(t *testing.T, pairs []encodingPair, peers int, extra map[string]any) {
	t.Helper()
	encodingExtensionScenarioWithin(t, pairs, peers, encodingBodyBound, extra)
}

// encodingExtensionScenarioWithin is encodingExtensionScenario under the given
// body bound.
func encodingExtensionScenarioWithin(t *testing.T, pairs []encodingPair, peers, bodyBound int, extra map[string]any) {
	t.Helper()
	c := encodingConversation(t, pairs)
	f := encodingExtensionWithin(t, peers, 4096, bodyBound, extra)
	f.give(t, c.fragments)
	f.checkOnline(t, pairs)
	out := f.finish(t, c.finals[0])
	if out.Excluded != encodingExpected(pairs) {
		t.Errorf("extension path counts=%+v, want %+v", out.Excluded, encodingExpected(pairs))
	}
	helper := &encodingWorker{output: f.output.snapshot(), finalOutcome: &out}
	helper.checkFinal(t, pairs, false)
	f.checkDone(t, len(pairs))
	headerOnly := true
	for _, pair := range pairs {
		if pair.reason != "" && pair.reason != processing.ReasonContentCodingUnsupported {
			headerOnly = false
		}
	}
	if headerOnly {
		encodingNoDecodeAdmission(t, f.chargeSnapshot())
	}
	stats := f.store.Stats()
	if stats.Bytes != 0 || stats.Parsing != 0 || stats.Policy != 0 || stats.Leased != 0 {
		t.Errorf("extension cleanup retained charges: %+v", stats)
	}
}
func TestExtensionEncodingContinuesPastExcludedPair(t *testing.T) {
	reasons := encodingReasons
	for _, peers := range []int{1, 2} {
		for i, requestReason := range append([]string{""}, reasons...) {
			for j, responseReason := range append([]string{""}, reasons...) {
				if i == 0 && j == 0 {
					continue
				}
				t.Run(fmt.Sprintf("peers-%d/%s/%s", peers, requestReason, responseReason), func(t *testing.T) {
					b := encodingPlain(1)
					if requestReason != "" {
						b = encodingBadWithin(t, 1, requestReason, "request", encodingCostlyBodyBound)
					}
					if responseReason != "" {
						b.response = encodingBadWithin(t, 1, responseReason, "response", encodingCostlyBodyBound).response
						if i == 0 || j < i {
							b.reason = responseReason
						}
					}
					// Consecutive exclusions consume distinct ids even with two extensions.
					next := b
					next.request = strings.Replace(b.request, "/item-1 ", "/item-2 ", 1)
					pairs := []encodingPair{encodingPlain(0), b, next, encodingPlain(3)}
					encodingExtensionScenarioWithin(t, pairs, peers, encodingCostlyBodyBound, nil)
				})
			}
		}
	}
}
func TestExtensionEncodingEmptyBodiesAndIdentityContinue(t *testing.T) {
	for _, side := range []string{"request", "response"} {
		for _, kind := range []string{"length-zero", "empty-chunked", "empty-chunked-trailers", "identity-list", "identity-fields", "head"} {
			if kind == "head" && side == "request" {
				continue
			}
			t.Run(side+"/"+kind, func(t *testing.T) {
				pairs := []encodingPair{encodingPlain(0), encodingPlain(1), encodingPlain(2)}
				request := side == "request"
				wire := encodingMessage(request, 1, "Content-Encoding: gzip\r\n", "")
				switch kind {
				case "empty-chunked", "empty-chunked-trailers":
					start := "HTTP/1.1 200 OK"
					if request {
						start = "POST /item-1 HTTP/1.1"
					}
					ending := "0\r\n\r\n"
					if kind == "empty-chunked-trailers" {
						ending = "0\r\nX-End: present\r\n\r\n"
					}
					wire = start + "\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" + ending
				case "identity-list":
					wire = encodingMessage(request, 1, "Content-Encoding: identity, identity\r\n", "identity content")
				case "identity-fields":
					wire = encodingMessage(request, 1, "Content-Encoding: identity\r\nContent-Encoding: identity\r\n", "identity content")
				case "head":
					pairs[1].request = "HEAD /item-1 HTTP/1.1\r\nHost: local\r\n\r\n"
					wire = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 912\r\n\r\n"
				}
				if request {
					pairs[1].request = wire
				} else {
					pairs[1].response = wire
				}
				encodingExtensionScenario(t, pairs, 1, nil)
			})
		}
	}
}
func TestExtensionEncodingRemovalDoesNotInventZeroBody(t *testing.T) {
	pairs := []encodingPair{encodingPlain(0), encodingBad(t, 1, processing.ReasonContentDecodingFailed, "both"), encodingPlain(2)}
	encodingExtensionScenario(t, pairs, 1, map[string]any{"remove": map[string]any{"bodies": []string{"request", "response"}}})
}

func TestExtensionEncodingTwoCodingsExcludedAloneWithoutDecoding(t *testing.T) {
	for _, side := range []string{"request", "response", "both"} {
		t.Run(side, func(t *testing.T) {
			encodingExtensionScenario(t, []encodingPair{encodingPlain(0), encodingStackedPair(t, 1, side), encodingPlain(2)}, 1, nil)
		})
	}
}

func TestExtensionEncodingNeverBypassesTerminalStops(t *testing.T) {
	for _, kind := range []string{"malformed", "malformed-coding", "ambiguous-empty", "protocol", "informational", "connect", "upgrade", "until-close", "transfer-coding", "elided", "hole"} {
		for _, side := range []string{"request", "response"} {
			if (kind == "informational" || kind == "until-close") && side == "request" || kind == "connect" && side == "response" {
				continue
			}
			for _, encodingSide := range []string{"none", "request", "response"} {
				for _, codingName := range []string{"compress", "gzip"} {
					if encodingSide == "none" && codingName == "gzip" {
						continue
					}
					t.Run(kind+"/"+side+"/"+encodingSide+"/"+codingName, func(t *testing.T) {
						pairs := []encodingPair{encodingPlain(0), encodingPlain(1), encodingPlain(2)}
						request := side == "request"
						coding := ""
						if encodingSide == side {
							coding = codingName
						}
						wire := encodingStoppedWire(kind, request, 1, coding)
						if request {
							pairs[1].request = wire
						} else {
							pairs[1].response = wire
						}
						if encodingSide != "none" && encodingSide != side {
							reason := processing.ReasonContentCodingUnsupported
							if codingName == "gzip" {
								reason = processing.ReasonContentDecodingFailed
							}
							other := encodingBad(t, 1, reason, encodingSide)
							if encodingSide == "request" {
								pairs[1].request = other.request
							} else {
								pairs[1].response = other.response
							}
						}
						if kind == "hole" {
							pairs[1].holeRequest = request
							pairs[1].holeResponse = !request
						}
						c := encodingConversation(t, pairs)
						f := encodingExtensionNew(t, 1, 4096, nil)
						f.give(t, c.fragments[:2])
						f.checkOnline(t, pairs[:1])
						f.give(t, c.fragments[2:])
						out := f.finish(t, c.finals[0])
						if out.Excluded.Total() != 0 {
							t.Errorf("terminal stop counted as isolated exclusion: %+v", out.Excluded)
						}
						output := f.output.snapshot()
						exchanges, connections := 0, 0
						for _, a := range output.artifacts {
							if a.Record == processing.ArtifactExchange {
								exchanges++
								if a.Index == nil || *a.Index != 0 {
									t.Errorf("extension content crossed %s terminal boundary: index=%v", kind, a.Index)
								}
								continue
							}
							connections++
							if a.ReconstructionTruncation == nil || len(a.ReconstructionTruncation.Stops) == 0 {
								t.Errorf("terminal %s lost suffix metadata", kind)
							}
							if a.ExcludedExchanges == nil || *a.ExcludedExchanges != (processing.ExcludedExchanges{ContentCodingUnsupported: "0", ContentDecodingFailed: "0", ContentDecodedTooLarge: "0", ContentDecodingTooCostly: "0"}) {
								t.Errorf("terminal %s isolated counts=%+v, want three zeros", kind, a.ExcludedExchanges)
							}
						}
						if exchanges != 1 || connections != 1 {
							t.Errorf("terminal output population exchanges=%d connections=%d, want 1/1", exchanges, connections)
						}
						encodingCheckTerminalProtocol(t, f, output, out)
						(&encodingWorker{output: output}).roundtrip(t)
						encodingNoDecodeAdmission(t, f.chargeSnapshot())
					})
				}
			}
		}
	}
}

func encodingCheckTerminalProtocol(t *testing.T, f *encodingExtension, output *encodingOutput, out processing.Outcome) {
	t.Helper()
	reasons := map[string]bool{}
	for _, a := range output.artifacts {
		if a.ReconstructionTruncation != nil {
			for _, stop := range a.ReconstructionTruncation.Stops {
				reasons[stop.Reason] = true
			}
		}
	}
	for peer := range f.audits {
		issued := 0
		for _, m := range f.messages(t, peer) {
			if m.Type != "exchange" {
				continue
			}
			id, err := strconv.ParseUint(m.ID, 10, 64)
			if err != nil || id != uint64(issued+1) || m.Index != issued {
				t.Errorf("terminal protocol id/index=%q/%d, want %d/%d", m.ID, m.Index, issued+1, issued)
			}
			if issued == 0 {
				if m.Output.State != "eligible" || m.Output.Reason != "" {
					t.Errorf("ordinary prefix classification=%+v", m.Output)
				}
			} else if m.Output.State != "excluded" || !reasons[m.Output.Reason] {
				t.Errorf("terminal tail classification=%+v, must remain excluded under a final suffix reason", m.Output)
			}
			issued++
		}
		if issued == 0 || uint64(issued) != out.ExchangeIDs {
			t.Errorf("protocol delivered %d of %d worker-issued ids", issued, out.ExchangeIDs)
		}
	}
	// A parser may stop before handing over the complete input population. The
	// done count must cover exactly the ids it did hand over, never guessed pairs.
	f.checkDone(t, int(out.ExchangeIDs))
}

func TestExtensionEncodingLaterCutKeepsAccountedBoundary(t *testing.T) {
	reasons := encodingReasons
	for i, first := range reasons {
		for j, second := range reasons {
			for _, continued := range []bool{false, true} {
				t.Run(first+"/"+second+fmt.Sprintf("/continued-%t", continued), func(t *testing.T) {
					b := encodingBadWithin(t, 1, first, "request", encodingCostlyBodyBound)
					b.response = encodingBadWithin(t, 1, second, "response", encodingCostlyBodyBound).response
					b.reason = reasons[min(i, j)]
					prefix := []encodingPair{encodingPlain(0), b}
					if continued {
						prefix = append(prefix, encodingPlain(2))
					}
					pairs := append([]encodingPair(nil), prefix...)
					const pending = 6
					for range pending {
						pairs = append(pairs, encodingPlain(len(pairs)))
					}
					c := encodingConversation(t, pairs)
					f := encodingExtensionWithin(t, 1, 4, encodingCostlyBodyBound, nil)
					for i := range prefix {
						f.give(t, c.fragments[2*i:2*i+2])
						f.settle(t, i+1)
					}
					f.checkOnline(t, prefix)
					for i := len(prefix); i < len(pairs); i++ {
						f.give(t, c.fragments[2*i:2*i+1])
					}
					if !f.await(t, "wiring, not the property: pending request fixture did not cut its connection", func() bool { return f.run.Snapshot().ConnectionsCut == 1 }) {
						t.FailNow()
					}
					for i := len(prefix); i < len(pairs); i++ {
						f.give(t, c.fragments[2*i+1:2*i+2])
					}
					out := f.finish(t, c.finals[0])
					if out.ConnectionsCut != 1 || out.AllowanceCut != 0 || out.InputCut != 2*pending {
						t.Errorf("extension cut counts connections/allowance/input=%d/%d/%d, want 1/0/%d", out.ConnectionsCut, out.AllowanceCut, out.InputCut, 2*pending)
					}
					if out.Excluded != encodingExpected(prefix) {
						t.Errorf("extension cut overwrote exclusions: %+v, want %+v", out.Excluded, encodingExpected(prefix))
					}
					output := f.output.snapshot()
					written := 0
					for _, a := range output.artifacts {
						if a.Record == processing.ArtifactExchange {
							written++
							if a.Index == nil || (*a.Index != 0 && (!continued || *a.Index != 2)) {
								t.Errorf("extension cut wrote suffix content at index %v", a.Index)
							}
							continue
						}
						tr := a.ReconstructionTruncation
						if tr == nil || len(tr.Stops) != 2 {
							t.Errorf("extension cut lacks two-direction suffix: %+v", tr)
							continue
						}
						for _, stop := range tr.Stops {
							want := 0
							for _, p := range prefix {
								switch stop.Direction {
								case "sent":
									want += len(p.request)
								case "received":
									want += len(p.response)
								default:
									t.Errorf("invalid direction %s", stop.Direction)
								}
							}
							got, err := strconv.ParseUint(stop.Offset, 10, 64)
							if err != nil || got != uint64(want) || stop.Reason != processing.TruncationConnectionCut {
								t.Errorf("extension cut suffix=%+v, want boundary %d and connection_cut", stop, want)
							}
						}
					}
					wantWritten := 1
					if continued {
						wantWritten++
					}
					if written != wantWritten {
						t.Errorf("extension cut changed released prefix: %d exchanges, want %d", written, wantWritten)
					}
					(&encodingWorker{output: output, finalOutcome: &out}).checkFinal(t, prefix, true)
					f.checkDone(t, len(prefix))
					stats := f.store.Stats()
					if stats.Bytes != 0 || stats.Parsing != 0 || stats.Policy != 0 || stats.Leased != 0 {
						t.Errorf("extension cut cleanup retained charges: %+v", stats)
					}
				})
			}
		}
	}
}

func TestExtensionEncodingConsumedHistoryStaysBounded(t *testing.T) {
	const count = 257
	pairs := make([]encodingPair, count)
	pairs[0] = encodingPlain(0)
	// The three cheap reasons: a body over the work budget is hundreds of
	// kilobytes, and 85 of them would measure the fixture, not the subject.
	reasons := encodingReasons[:3]
	for i := 1; i < count-1; i++ {
		pairs[i] = encodingBad(t, i, reasons[(i-1)%len(reasons)], "both")
	}
	pairs[count-1] = encodingPlain(count - 1)
	c := encodingConversation(t, pairs)
	f := encodingExtensionNew(t, 1, 4096, nil)
	for i := range pairs {
		f.give(t, c.fragments[2*i:2*i+2])
		f.settle(t, i+1)
		if !f.await(t, "consumed extension exchange retained payload charges", func() bool {
			s := f.store.Stats()
			return s.Bytes == 0 && s.Policy == 0 && s.Leased == 0 && s.Parsing <= processing.ReadingCharge
		}) {
			t.FailNow()
		}
	}
	f.checkOnline(t, pairs)
	out := f.finish(t, c.finals[0])
	if out.Excluded != encodingExpected(pairs) {
		t.Errorf("extension history counts=%+v, want %+v", out.Excluded, encodingExpected(pairs))
	}
	(&encodingWorker{output: f.output.snapshot(), finalOutcome: &out}).checkFinal(t, pairs, false)
	f.checkDone(t, len(pairs))
}

func TestExtensionEncodingLaterHolePreservesExclusionReason(t *testing.T) {
	for _, reason := range encodingReasons {
		for _, side := range []string{"request", "response"} {
			for _, continued := range []bool{false, true} {
				t.Run(reason+"/"+side+fmt.Sprintf("/continued-%t", continued), func(t *testing.T) {
					prefix := []encodingPair{encodingPlain(0), encodingBadWithin(t, 1, reason, "both", encodingCostlyBodyBound)}
					if continued {
						prefix = append(prefix, encodingPlain(2))
					}
					at := len(prefix)
					hole := encodingPlain(at)
					if side == "request" {
						hole.request = encodingMessage(true, at, "", "missing-body")
						hole.holeRequest = true
					} else {
						hole.response = encodingMessage(false, at, "", "missing-body")
						hole.holeResponse = true
					}
					pairs := append(append([]encodingPair(nil), prefix...), hole, encodingPlain(at+1))
					c := encodingConversation(t, pairs)
					f := encodingExtensionWithin(t, 1, 4096, encodingCostlyBodyBound, nil)
					f.give(t, c.fragments[:2*len(prefix)])
					f.checkOnline(t, prefix)
					f.give(t, c.fragments[2*len(prefix):])
					out := f.finish(t, c.finals[0])
					if out.Excluded != encodingExpected(prefix) {
						t.Errorf("extension later hole overwrote known reason: %+v, want %+v", out.Excluded, encodingExpected(prefix))
					}
					output := f.output.snapshot()
					encodingCheckSuffixBoundary(t, output, prefix)
					(&encodingWorker{output: output, finalOutcome: &out}).checkFinal(t, prefix, true)
				})
			}
		}
	}
}
