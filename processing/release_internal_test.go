package processing

import (
	"testing"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/reconstruct"
)

// The gate is told what a line's own input establishes, not a constant: an
// exchange's inputs are settled only where both its messages end within what
// was read, and its lifecycle only where both are complete and framed.
func TestExchangeEvidenceSettlesOnlyWhatWasRead(t *testing.T) {
	message := func(end uint64, complete bool) *reconstruct.Message {
		return &reconstruct.Message{Message: http1.Message{End: end, Complete: complete, Framed: complete}}
	}
	b := &batch{}
	b.place[fragment.Sent].fed, b.place[fragment.Received].fed = 100, 50
	for _, c := range []struct {
		name               string
		exchange           reconstruct.Exchange
		role               reconstruct.Role
		inputs, lifecycles bool
	}{
		{"client, read through both ends", reconstruct.Exchange{Request: message(100, true), Response: message(50, true), Complete: true}, reconstruct.Client, true, true},
		{"client, response past what was read", reconstruct.Exchange{Request: message(100, true), Response: message(51, true), Complete: true}, reconstruct.Client, false, true},
		{"client, request past what was read", reconstruct.Exchange{Request: message(101, true), Response: message(50, true), Complete: true}, reconstruct.Client, false, true},
		{"server, directions swapped", reconstruct.Exchange{Request: message(50, true), Response: message(100, true), Complete: true}, reconstruct.Server, true, true},
		{"server, read as a client's would be", reconstruct.Exchange{Request: message(100, true), Response: message(50, true), Complete: true}, reconstruct.Server, false, true},
		{"unknown role", reconstruct.Exchange{Request: message(10, true), Response: message(10, true), Complete: true}, reconstruct.RoleUnknown, false, true},
		{"response missing", reconstruct.Exchange{Request: message(10, true)}, reconstruct.Client, false, false},
		{"response incomplete", reconstruct.Exchange{Request: message(10, true), Response: message(10, false), Complete: true}, reconstruct.Client, true, false},
		{"exchange incomplete", reconstruct.Exchange{Request: message(10, true), Response: message(10, true)}, reconstruct.Client, true, false},
	} {
		got := b.exchangeEvidence(c.exchange, c.role)
		if got.InputsSettled != c.inputs || got.LifecycleSettled != c.lifecycles {
			t.Errorf("%s: inputs %t lifecycle %t, want %t %t", c.name, got.InputsSettled, got.LifecycleSettled, c.inputs, c.lifecycles)
		}
	}
}

func TestRetirementEvidenceSettlesOnlyAnArrivedAndEndedConnection(t *testing.T) {
	if got := (&batch{}).retirementEvidence(); got.InputsSettled || got.LifecycleSettled {
		t.Fatalf("a connection with no retirement settles inputs %t lifecycle %t", got.InputsSettled, got.LifecycleSettled)
	}
	retirement := func(how connection.Ending) *connection.Record {
		return &connection.Record{How: how, Fragments: connection.Counted(2)}
	}
	for _, c := range []struct {
		name               string
		b                  batch
		inputs, lifecycles bool
	}{
		{"closed, every fragment arrived", batch{retirement: retirement(connection.SocketClosed), arrived: 2}, true, true},
		{"released, every fragment arrived", batch{retirement: retirement(connection.HandleReleasedEnding), arrived: 2}, true, true},
		{"closed, a fragment missing", batch{retirement: retirement(connection.SocketClosed), arrived: 1}, false, true},
		{"still open", batch{retirement: retirement(connection.StillOpen), arrived: 2}, true, false},
		{"still open, settled at the session's end", batch{retirement: retirement(connection.StillOpen), arrived: 2, final: true}, true, true},
		{"cut, a fragment missing", batch{retirement: retirement(connection.SocketClosed), arrived: 1, cut: true}, true, true},
	} {
		got := c.b.retirementEvidence()
		if got.InputsSettled != c.inputs || got.LifecycleSettled != c.lifecycles {
			t.Errorf("%s: inputs %t lifecycle %t, want %t %t", c.name, got.InputsSettled, got.LifecycleSettled, c.inputs, c.lifecycles)
		}
	}
}
