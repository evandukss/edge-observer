package processing_test

import (
	"context"
	"strings"
	"testing"

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
				Sequence: probe.Sequence{Occupancy: 1, Number: 1, Born: born, Unlocated: 1}})
		}
		p.capture.Closed(probe.Connection{Process: pipelineProcess, Instance: pipelineInstance, Endpoint: 1, At: p.at,
			Sequence: probe.Sequence{Occupancy: 1, Born: born, Unlocated: 1},
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
