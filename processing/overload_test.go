package processing_test

import (
	"context"
	"encoding/json"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/held"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

func TestHeldEventOverloadCutsItsConnectionAndFreshInputContinues(t *testing.T) {
	out := &outputLog{}
	p := newPipeline(t, 4, 100, out)
	p.exchange(1, "/affected")
	p.exchange(2, "/unaffected")
	decision := p.gate.Admit(probe.DeliveryTransfer, true)
	if decision.Admitted || decision.State.Reason != probe.GateInputLimit {
		t.Fatalf("wiring: fifth event did not reach the bound: %+v", decision)
	}
	p.capture.Refused(probe.Transfer{Process: pipelineProcess, Instance: pipelineInstance, Endpoint: 1,
		Direction: fragment.Sent, Measured: true, Length: 1,
		Sequence: probe.Sequence{Occupancy: 1, Number: 2, Born: true}})
	p.numbers[1][fragment.Sent] = 2
	p.drain()
	p.transfer(1, fragment.Sent, "GET /still-cut HTTP/1.1\r\n\r\n")
	if seen := p.capture.Stats(); seen.Rejected != 1 {
		t.Fatalf("continued cut input was not counted refused: %+v", seen)
	}
	p.closed(1)
	p.closed(2)
	p.drain()
	p.exchange(3, "/fresh")
	p.closed(3)
	p.drain()
	joined := stringJoin(out.lines)
	if strings.Contains(joined, "/affected") || !strings.Contains(joined, "/unaffected") || !strings.Contains(joined, "/fresh") {
		t.Fatalf("overload affected the wrong output: %s", joined)
	}
	if state := p.gate.Snapshot(); state.Reason != "" || state.InputRefused != 1 || state.Held != 0 || state.DoubleRefunds != 0 {
		t.Fatalf("gate did not recover without leaking reservations: %+v", state)
	}
	if seen := p.capture.Stats(); seen.GateRefused != 1 || seen.Cut == 0 {
		t.Fatalf("uncounted cut: %+v", seen)
	}
}

func TestIntakeLossSurvivesAFullQueueAndFreshInputContinues(t *testing.T) {
	out := &outputLog{}
	p := newPipeline(t, 100, 100, out)
	store, err := intake.New(4096)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	w, err := processing.New(processing.Options{Session: "overload", Plan: rulesPlan(t, ""), PolicyRevision: "p",
		Intake: store, Gate: p.gate, Output: out, ConnectionInput: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	p.store, p.worker, p.capture = store, w, capture.Recording(store, store)
	p.transfer(1, fragment.Sent, "GET /affected HTTP/1.1\r\n\r\n")
	p.drain()
	p.transfer(1, fragment.Received, strings.Repeat("x", 4096))
	if store.Stats().FragmentsRefused != 1 {
		t.Fatalf("wiring: intake did not refuse oversized fragment: %+v", store.Stats())
	}
	// No payload or retirement is queued. The shared cut alone must release
	// the entry already leased by processing.
	o := p.drain()
	if store.Stats().Bytes != 0 || o.ConnectionsCut != 1 {
		t.Fatalf("full-queue cut did not release its batch: %+v %+v", store.Stats(), o)
	}
	p.closed(1)
	p.drain()
	p.exchange(2, "/fresh")
	p.closed(2)
	p.drain()
	joined := stringJoin(out.lines)
	if strings.Contains(joined, "/affected") || !strings.Contains(joined, "/fresh") {
		t.Fatalf("wrong recovered output: %s", joined)
	}
	if seen := p.capture.Stats(); seen.IntakeRefused != 1 || seen.Cut == 0 {
		t.Fatalf("uncounted intake loss: %+v", seen)
	}
	if state := p.gate.Snapshot(); state.Reason != "" || state.Held != 0 {
		t.Fatalf("intake stopped session or leaked slots: %+v", state)
	}
}

func TestAnObservedBirthRecoversAfterUnlocatedLoss(t *testing.T) {
	for _, born := range []bool{false, true} {
		out := &outputLog{}
		p := newPipeline(t, 100, 100, out)
		for _, part := range []struct {
			direction fragment.Direction
			text      string
		}{
			{fragment.Sent, "GET /after-loss HTTP/1.1\r\n\r\n"},
			{fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"},
		} {
			p.capture.Transfer(probe.Transfer{Process: pipelineProcess, Instance: pipelineInstance, Endpoint: 1,
				Direction: part.direction, Measured: true, Length: uint32(len(part.text)), Payload: []byte(part.text), At: p.at,
				Sequence: probe.Sequence{Occupancy: 1, Number: 1, Born: born, Unlocated: 1, BeginUnlocated: 1}})
		}
		p.capture.Closed(probe.Connection{Process: pipelineProcess, Instance: pipelineInstance, Endpoint: 1, At: p.at,
			Sequence: probe.Sequence{Occupancy: 1, Born: born, Unlocated: 1, BeginUnlocated: 1},
			Final:    probe.Final{Known: true, Sent: probe.Terminal{Last: 1}, Received: probe.Terminal{Last: 1}}})
		if _, err := p.worker.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
		written := strings.Contains(stringJoin(out.lines), "/after-loss")
		if written != born {
			t.Fatalf("born=%t: output eligibility was %t", born, written)
		}
	}
}

func stringJoin(lines [][]byte) string {
	var all strings.Builder
	for _, line := range lines {
		all.Write(line)
	}
	return all.String()
}

// Producer numbers and births, rather than HTTP-looking bytes, determine
// whether a loss boundary can be crossed.
func TestRecoveryDoesNotManufactureACompletePrefix(t *testing.T) {
	for _, scenario := range []string{"old hole", "unseen first loss", "lost close reused", "delayed old event", "delayed old close", "fresh birth", "prior occupancy"} {
		t.Run(scenario, func(t *testing.T) {
			out := &outputLog{}
			p := newPipeline(t, 100, 100, out)
			p.exchange(10, "/certified")
			p.closed(10)
			p.drain()
			send := func(occupancy, number, begin uint64, born bool, direction fragment.Direction, body string) {
				p.capture.Transfer(probe.Transfer{Process: pipelineProcess, Instance: pipelineInstance, Endpoint: 1,
					Direction: direction, Measured: true, Length: uint32(len(body)), Payload: []byte(body), At: p.at,
					Sequence: probe.Sequence{Occupancy: occupancy, Number: number, Born: born, Unlocated: 1, BeginUnlocated: begin}})
			}
			occupancy, number, begin, born := uint64(1), uint64(1), uint64(1), false
			want := false
			switch scenario {
			case "old hole":
				send(1, 1, 0, true, fragment.Sent, "GET /broken HTTP/1.1\r\nX-Missing: ")
				number, begin, born = 3, 0, true
			case "unseen first loss":
				number = 2
			case "lost close reused", "delayed old event", "delayed old close":
				send(1, 1, 0, true, fragment.Sent, "GET /old HTTP/1.1\r\nIncomplete: ")
				occupancy, born, want = 2, true, true
			case "fresh birth":
				born, want = true, true
			case "prior occupancy":
				begin, want = 0, true
			}
			send(occupancy, number, begin, born, fragment.Sent, "GET /candidate HTTP/1.1\r\n\r\n")
			if scenario == "delayed old event" {
				send(1, 2, 0, true, fragment.Sent, "GET /stale HTTP/1.1\r\n\r\n")
			}
			if scenario == "delayed old close" {
				p.capture.Closed(probe.Connection{Process: pipelineProcess, Instance: pipelineInstance, Endpoint: 1, At: p.at,
					Sequence: probe.Sequence{Occupancy: 1}, Final: probe.Final{Known: true, Sent: probe.Terminal{Last: 1}}})
			}
			send(occupancy, 1, begin, born, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
			p.capture.Closed(probe.Connection{Process: pipelineProcess, Instance: pipelineInstance, Endpoint: 1, At: p.at,
				Sequence: probe.Sequence{Occupancy: occupancy, Born: born, Unlocated: 1, BeginUnlocated: begin},
				Final:    probe.Final{Known: true, Sent: probe.Terminal{Last: number}, Received: probe.Terminal{Last: 1}}})
			p.drain()
			lines := stringJoin(out.lines)
			if !strings.Contains(lines, "/certified") || strings.Contains(lines, "/stale") || strings.Contains(lines, "/candidate") != want {
				t.Fatalf("wrong eligibility after %s: %s", scenario, lines)
			}
		})
	}
}

// lossTap observes the control token retained alongside real capture input.
type lossTap struct {
	store *intake.Store
	loss  *held.Loss
}

func (s *lossTap) Write(r fragment.Record) error { s.loss = r.Loss; return s.store.Write(r) }

func TestAConnectionCutOrdersAgainstHeldOutputAuthorization(t *testing.T) {
	arrived, resume := make(chan struct{}), make(chan struct{})
	var once, reached sync.Once
	defer once.Do(func() { close(resume) })
	out := &outputLog{}
	p := newPipeline(t, 100, 100, out)
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 100, BeforeAuthorize: func() { reached.Do(func() { close(arrived); <-resume }) }})
	if err != nil {
		t.Fatal(err)
	}
	w, err := processing.New(processing.Options{Session: "ordered", Plan: rulesPlan(t, ""), PolicyRevision: "p", Intake: p.store, Gate: gate, Output: out})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	p.gate, p.worker = gate, w
	tap := &lossTap{store: p.store}
	p.capture = capture.Recording(tap, p.store)
	p.exchange(1, "/cut")
	p.closed(1)
	done := make(chan error, 1)
	go func() { _, err := w.Drain(context.Background()); done <- err }()
	select {
	case <-arrived:
	case <-time.After(2 * time.Second):
		t.Fatal("wiring: output was not held")
	}
	cut := make(chan struct{})
	go func() { tap.loss.Stop("intake_exhausted"); close(cut) }()
	select {
	case <-cut:
	case <-time.After(2 * time.Second):
		once.Do(func() { close(resume) })
		<-done
		t.Fatal("cut blocked behind pending authorization")
	}
	once.Do(func() { close(resume) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(out.lines) != 0 {
		t.Fatalf("cut input escaped authorization: %s", stringJoin(out.lines))
	}
}

func TestAConnectionCutOrdersAgainstPendingExtensionSubmission(t *testing.T) {
	bin := independentPeer(t)
	dir := t.TempDir()
	audit := filepath.Join(dir, "received.jsonl")
	entries, err := json.Marshal([]any{map[string]any{"name": "worker", "command": []string{bin, "--mode", "unchanged", "--record", audit}, "fields": []string{"request.line"}, "timeout_ms": 1000}})
	if err != nil {
		t.Fatal(err)
	}
	out := &outputLog{}
	p := newPipeline(t, 100, 100, out)
	writer, err := processing.Open(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()
	arrived, resume, ready := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
	var once sync.Once
	defer once.Do(func() { close(resume) })
	run, err := processing.Start(processing.Options{Session: "ordered", PolicyRevision: "p", Plan: rulesPlan(t, `"extensions":`+string(entries)),
		Intake: p.store, Gate: p.gate, Output: out, Derived: writer, Workers: 1,
		BeforeParse: func(context.Context) error { close(arrived); <-resume; return nil },
		Supervision: func(e extension.Event) {
			if e.Kind == extension.Ready {
				ready <- struct{}{}
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = run.Close() }()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("wiring: extension not ready")
	}
	tap := &lossTap{store: p.store}
	p.capture = capture.Recording(tap, p.store)
	p.exchange(1, "/cut")
	p.closed(1)
	run.Route()
	select {
	case <-arrived:
	case <-time.After(2 * time.Second):
		t.Fatal("wiring: parse not held")
	}
	tap.loss.Stop("intake_exhausted")
	once.Do(func() { close(resume) })
	if _, err := run.Finish(context.Background(), processing.Finalization{Withdrawn: true, Drained: true}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), `"type":"exchange"`) || len(out.lines) != 0 {
		t.Fatalf("cut input reached extension or output: audit=%s output=%s", content, stringJoin(out.lines))
	}
}
