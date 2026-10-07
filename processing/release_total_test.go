package processing_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/reconstruct"
)

// The connection line states the connection's unplaced total, as version 3
// stated it on every exchange line: what reading the same fragments whole
// (reconstruct.Run) leaves unplaced.
func TestTheConnectionLineStatesItsUnplacedTotal(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
	for _, c := range []struct {
		name    string
		calls   []call
		nonzero bool
	}{
		{"every byte read", pairs("/one", "/two"), false},
		{"bytes after a malformed request", []call{wrote("GET /one HTTP/1.1\r\nHost: a\r\n\r\n"), read(response),
			wrote("NOT A REQUEST\r\n\r\n"), wrote("GET /after HTTP/1.1\r\nHost: a\r\n\r\n")}, true},
		{"neither side read", []call{wrote("opaque bytes"), read("more opaque bytes")}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newReleasing(t, releasingOptions{})
			conversation := converse(t, 1, c.calls...)
			whole := reconstruct.Run(conversation.fragments, reconstruct.DefaultLimits())
			if len(whole.Connections) != 1 || (whole.Connections[0].Unplaced != 0) != c.nonzero {
				t.Fatalf("wiring, not the property: reading the fixture whole leaves %+v unplaced", whole.Connections)
			}
			want := record.Count{State: record.Determined, Unit: record.Bytes,
				Value: strconv.FormatUint(whole.Connections[0].Unplaced, 10)}
			r.give(conversation.fragments...)
			r.retire(conversation.retirement)
			r.drain()
			lines := r.lines(processing.ArtifactConnection, 1)
			if len(lines) != 1 {
				t.Fatalf("wiring, not the property: %d connection lines", len(lines))
			}
			if got := lines[0].ReconstructionUnplaced; got == nil || *got != want {
				t.Fatalf("the connection line states unplaced %+v, want %+v", got, want)
			}
		})
	}
}

// A connection whose content was not read to its retirement states its total
// as undetermined, with why.
func TestAConnectionLineWithoutAReadingStatesWhy(t *testing.T) {
	t.Run("cut", func(t *testing.T) {
		r := newReleasing(t, releasingOptions{connectionInput: 2})
		request := func(target string) call { return wrote("GET " + target + " HTTP/1.1\r\nHost: a\r\n\r\n") }
		c := converse(t, 1, request("/1"), request("/2"), request("/3"))
		r.give(c.fragments...)
		r.retire(c.retirement)
		r.drain()
		lines := r.lines(processing.ArtifactConnection, 1)
		if r.outcome.ConnectionsCut != 1 || len(lines) != 1 {
			t.Fatalf("wiring, not the property: %d cut, %d connection lines", r.outcome.ConnectionsCut, len(lines))
		}
		want := record.Count{State: record.Undetermined, Unit: record.Bytes, Why: processing.TruncationConnectionCut}
		if got := lines[0].ReconstructionUnplaced; got == nil || *got != want {
			t.Fatalf("the cut connection's line states unplaced %+v, want %+v", got, want)
		}
	})
	t.Run("not read", func(t *testing.T) {
		store, err := intake.New(1 << 20)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 100, IntakeExhausted: store.Exhausted()})
		if err != nil {
			t.Fatal(err)
		}
		out := &outputLog{}
		w, err := processing.New(processing.Options{Session: "not-read", Plan: rulesPlan(t, `"write_content": false`),
			PolicyRevision: "not-read-policy", Intake: store, Gate: gate, Output: out})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = w.Close() })
		c := converse(t, 1, pair("/unread")...)
		for _, f := range c.fragments {
			if err := store.Write(f); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.Connection(c.retirement); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(out.artifacts) != 1 || out.artifacts[0].Record != processing.ArtifactConnection {
			t.Fatalf("wiring, not the property: a plan writing no content wrote %d lines", len(out.artifacts))
		}
		want := record.Count{State: record.Undetermined, Unit: record.Bytes, Why: "not_read"}
		if got := out.artifacts[0].ReconstructionUnplaced; got == nil || *got != want {
			t.Fatalf("a connection nothing reads states unplaced %+v, want %+v", got, want)
		}
	})
}
