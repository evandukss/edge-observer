package processing_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

// extensionReceiptPeer builds the shared extension helper. It answers ready in
// the protocol version of the tree it is built from and, in record mode,
// appends every message it receives to its audit file, so what the observer
// handed it is read back rather than inferred.
func extensionReceiptPeer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "broken-extension")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/evandukss/edge-observer/internal/cmd/broken-extension").CombinedOutput(); err != nil {
		t.Fatalf("wiring, not the property: build extension peer: %v: %s", err, out)
	}
	return bin
}

type extensionReceiptSink struct{ w *processing.Writer }

func (s extensionReceiptSink) WriteApproved(ctx context.Context, a processing.Approved) error {
	return s.w.WriteApproved(ctx, a)
}

// extensionReceiptRun starts a run with one ready accepting extension selecting
// every field, feeds the capture on an open connection, retires it, and returns
// the exchange messages the extension recorded as received. removeSide names
// the side whose decoded JSON member "/secret" the policy removes.
func extensionReceiptRun(t *testing.T, bin, audit, removeSide string, c contentCapture) []map[string]any {
	t.Helper()
	configuration := map[string]any{
		"version": "observer.config/1", "output": "/var/lib/observer", "write_content": true,
		"watch":  []any{map[string]any{"name": "api", "exe": "/usr/bin/php"}},
		"remove": map[string]any{"json": map[string]any{removeSide: []string{"/secret"}}},
		"extensions": []any{map[string]any{
			"name":    "receipt",
			"command": []string{bin, "--mode", "record", "--record", audit},
			"fields": []string{config.FieldRequestLine, config.FieldRequestHeaders, config.FieldRequestBody,
				config.FieldResponseLine, config.FieldResponseHeaders, config.FieldResponseBody},
			"timeout_ms": 30000,
		}},
	}
	data, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	compiled, findings := config.Compile(data, "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: configuration: %+v", findings)
	}
	store, err := intake.New(1 << 28)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1 << 20, IntakeExhausted: store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := processing.Open(t.TempDir(), 1<<28)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	events := make(chan extension.Event, 1024)
	run, err := processing.Start(processing.Options{
		Plan: compiled.Plan, PolicyRevision: "fixture", Session: "extension-receipt",
		Intake: store, Gate: gate, Output: extensionReceiptSink{writer}, Derived: writer, Workers: 1,
		Supervision: func(e extension.Event) {
			select {
			case events <- e:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("wiring, not the property: start: %v", err)
	}
	t.Cleanup(func() { _ = run.Close() })
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	for ready := false; !ready; {
		select {
		case e := <-events:
			if e.Kind == extension.Ready {
				ready = true
			}
		case <-deadline.C:
			t.Fatal("wiring, not the property: extension never became ready")
		}
	}
	for _, f := range c.fragments {
		if err := store.Write(f); err != nil {
			t.Fatalf("wiring, not the property: intake: %v", err)
		}
	}
	run.Route()
	if err := store.Connection(c.finals[0]); err != nil {
		t.Fatal(err)
	}
	run.Route()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := run.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true}); err != nil {
		t.Fatalf("finish: %v", err)
	}
	b, err := os.ReadFile(audit)
	if err != nil {
		t.Fatalf("wiring, not the property: no extension audit: %v", err)
	}
	var got []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("wiring, not the property: extension audit incomplete: %v", err)
		}
		if m["type"] == "exchange" {
			got = append(got, m)
		}
	}
	return got
}

// extensionReceiptTarget is the request target of a received exchange, or "".
func extensionReceiptTarget(m map[string]any) string {
	ex, ok := m["exchange"].(map[string]any)
	if !ok {
		return ""
	}
	req, ok := ex["request"].(map[string]any)
	if !ok {
		return ""
	}
	msg, ok := req["message"].(map[string]any)
	if !ok {
		return ""
	}
	target, _ := msg["target"].(string)
	return target
}

// extensionReceiptFind is the received exchange whose request target is target.
func extensionReceiptFind(got []map[string]any, target string) map[string]any {
	for _, m := range got {
		if extensionReceiptTarget(m) == target {
			return m
		}
	}
	return nil
}

// extensionReceiptBody is the decoded body bytes the extension received on side
// of m, and whether that side carried a message with a body at all.
func extensionReceiptBody(t *testing.T, m map[string]any, side string) ([]byte, bool) {
	t.Helper()
	ex, ok := m["exchange"].(map[string]any)
	if !ok {
		return nil, false
	}
	s, ok := ex[side].(map[string]any)
	if !ok {
		return nil, false
	}
	msg, ok := s["message"].(map[string]any)
	if !ok {
		return nil, false
	}
	// The selected body is the record Body object (PROTOCOL.md: request.body is
	// length, kept in base64, holed, elided, encoding), not a bare string; its
	// bytes are kept in base64, as extension_delivery_test.go reads them.
	rec, ok := msg["body"].(map[string]any)
	if !ok {
		return nil, false
	}
	kept, ok := rec["kept"].(string)
	if !ok {
		return nil, false
	}
	body, err := base64.StdEncoding.DecodeString(kept)
	if err != nil {
		t.Fatalf("wiring, not the property: extension body.kept not base64: %v", err)
	}
	return body, true
}

// A ready accepting extension receives the DECODED content with the policy
// removal applied, not the encoded bytes (criterion 119 row 1). The expectation
// is derived from the fixture and the criterion, never from the implementation
// that delivers it.
//
// This is RED until the decode-to-extension chain lands: today the chain stops
// on a coded body, so the ready extension does not receive the coded exchange
// decoded. A plain control exchange BEFORE the coded one on the same keep-alive
// connection is delivered today, before the chain reaches the coded body, and is
// the wiring guard that separates that property red from a harness that never
// reached the extension.
func TestDecodedExchangeReachesExtension(t *testing.T) {
	bin := extensionReceiptPeer(t)
	plain := []byte(`{"secret":"removed-sentinel","keep":"retained-sentinel"}`)
	wantKept := []byte(`{"keep":"retained-sentinel"}`)
	wantControl := []byte(`{"control":"wired"}`)
	for _, side := range []string{"request", "response"} {
		t.Run(side, func(t *testing.T) {
			audit := filepath.Join(t.TempDir(), "received.jsonl")
			encoded := contentEncoded(t, "gzip", plain)
			// A plain control exchange BEFORE the coded one on the same keep-alive
			// connection. Today's behaviour delivers it, since the chain reaches it
			// before the coded body, so it establishes that this connection's
			// extension delivery is wired, independently of the property.
			controlReq := contentWire("POST /control HTTP/1.1", "", wantControl, false)
			controlResp := contentWire("HTTP/1.1 200 OK", "", wantControl, false)
			codedReq := contentWire("POST /coded HTTP/1.1", "gzip", encoded, false)
			codedResp := contentWire("HTTP/1.1 200 OK", "", []byte(`{"plain":true}`), false)
			if side == "response" {
				codedReq = []byte("GET /coded HTTP/1.1\r\nHost: fixture\r\n\r\n")
				codedResp = contentWire("HTTP/1.1 200 OK", "gzip", encoded, false)
			}
			requests := append(bytes.Clone(controlReq), codedReq...)
			responses := append(bytes.Clone(controlResp), codedResp...)
			got := extensionReceiptRun(t, bin, audit, side, contentCaptured(t, requests, responses, false))

			// Wiring guard: the pre-coded control exchange reached the extension
			// with its body. A failure here is wiring, not the property - the
			// extension never saw this connection's traffic.
			control := extensionReceiptFind(got, "/control")
			if control == nil {
				t.Fatal("wiring, not the property: the ready extension received no pre-coded control exchange")
			}
			if body, ok := extensionReceiptBody(t, control, side); !ok || !bytes.Equal(body, wantControl) {
				t.Fatalf("wiring, not the property: control %s body %q (present %t), want %q", side, body, ok, wantControl)
			}

			// The property: the coded exchange reaches the extension decoded,
			// with the removable member gone and no encoded byte.
			coded := extensionReceiptFind(got, "/coded")
			if coded == nil {
				t.Error("the ready extension did not receive the decoded coded exchange")
				return
			}
			body, ok := extensionReceiptBody(t, coded, side)
			if !ok {
				t.Errorf("the extension received the coded exchange with no %s body", side)
				return
			}
			if !bytes.Equal(body, wantKept) {
				t.Errorf("extension received %s body %q, want decoded removal-applied %q", side, body, wantKept)
			}
			if bytes.Contains(body, []byte("removed-sentinel")) {
				t.Errorf("removed member present in the extension's %s body: %q", side, body)
			}
			if bytes.Contains(body, encoded) {
				t.Errorf("encoded bytes reached the extension's %s body", side)
			}
		})
	}
}
