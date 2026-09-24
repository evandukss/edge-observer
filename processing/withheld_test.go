package processing_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/processing"
)

// The old uint64 API asserted a known exchange count. Interpret that promise
// literally so these tests can expose its fabricated values before the API
// becomes Count. A scalar is NEVER adapted into an unknown result.
func withheldCount(t *testing.T, o processing.Outcome) connection.Count {
	t.Helper()
	raw, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var fields struct{ Withheld json.RawMessage }
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields.Withheld) == 0 {
		t.Fatal("worker outcome has no withheld count")
	}
	if fields.Withheld[0] == '{' {
		var count connection.Count
		if err := json.Unmarshal(fields.Withheld, &count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	var old int64
	if err := json.Unmarshal(fields.Withheld, &old); err != nil {
		t.Fatal(err)
	}
	return connection.Counted(old)
}

func expectWithheld(t *testing.T, o processing.Outcome, want connection.Count) {
	t.Helper()
	if got := withheldCount(t, o); got != want {
		t.Fatalf("withheld cardinality: got %+v, want %+v", got, want)
	}
}

func withheldControl(t *testing.T) (*processing.Worker, *intake.Store, *outputLog) {
	t.Helper()
	out := &outputLog{}
	w, store := worker(t, workerPlan(t, pipeline("exchanges")), out)
	enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
	o := drain(t, w)
	if o.Written != 1 || o.Batches != 1 || o.Pending != 0 || len(out.artifacts) != 1 || field(t, out.artifacts[0], "x-public") != "original" {
		t.Fatalf("decidable output control did not reach the worker: %+v", o)
	}
	expectWithheld(t, o, connection.Counted(0))
	t.Log("useful complete exchange written, withheld cardinality is exactly known zero")
	return w, store, out
}

const encodedResponse = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nOK"

func TestWithheldCountsWholeFramedExchangesExactly(t *testing.T) {
	w, store, _ := withheldControl(t)
	for index, amount := range []int{2, 1} {
		enqueue(t, store, batch(t, fragment.ConnectionID(index+2), strings.Repeat(goodRequest, amount), strings.Repeat(encodedResponse, amount)))
		o := drain(t, w)
		if o.Batches != uint64(index+2) || o.ProcessingFailures != uint64(index+1) || o.Written != 1 || o.Pending != 0 {
			t.Fatalf("framed unsupported exchanges did not reach refusal: %+v", o)
		}
		t.Logf("framed refusal reached: batch contains %d complete pairs", amount)
		expectWithheld(t, o, connection.Counted(int64(index+2)))
	}
	enqueue(t, store, batch(t, 4, goodRequest, goodResponse))
	o := drain(t, w)
	if o.Written != 2 {
		t.Fatal("a later decidable control was not written")
	}
	expectWithheld(t, o, connection.Counted(3))
}

func TestWithheldUnknownInputNeverBecomesAnExchangeCount(t *testing.T) {
	for _, name := range []string{"incomplete-tail", "unknown-role", "overlap", "late-entry", "unsettled-finalization"} {
		t.Run(name, func(t *testing.T) {
			w, store, _ := withheldControl(t)
			b := batch(t, 2, goodRequest, goodResponse)
			wantWrites, wantBatches, wantFailures := uint64(1), uint64(2), uint64(1)
			reason := "reconstruction_incomplete"
			switch name {
			case "incomplete-tail":
				b = batch(t, 2, goodRequest+"GET /tail HTTP/1.1\r\n", goodResponse)
				wantWrites = 2
			case "unknown-role":
				b = batch(t, 2, "opaque request", "opaque response")
			case "overlap":
				later := b.fragments[0]
				later.Sequence, later.Offset, later.Length, later.Payload = 3, 1, 1, []byte("x")
				b.fragments = append(b.fragments, later)
				b.records[0].Fragments = connection.Counted(3)
				reason = "invalid_input"
			case "late-entry":
				b = batch(t, 1, goodRequest, goodResponse)
				b.fragments, b.records = b.fragments[:1], nil
				wantBatches, wantFailures, reason = 1, 0, "late_batch_entry"
			case "unsettled-finalization":
				b.records[0].How, b.records[0].Ended = connection.StillOpen, time.Time{}
				wantBatches, wantFailures, reason = 1, 0, "unsettled_input"
			}
			enqueue(t, store, b)
			o := drain(t, w)
			if name == "unsettled-finalization" {
				if o.Pending != 1 || store.Stats().Leased != 3 || o.Written != 1 {
					t.Fatalf("unsettled input was not held: %+v", o)
				}
				expectWithheld(t, o, connection.Counted(0))
				var err error
				o, err = w.Finish(context.Background(), processing.Finalization{Withdrawn: true, Drained: false})
				if err != nil {
					t.Fatal(err)
				}
			}
			if o.Written != wantWrites || o.Batches != wantBatches || o.ProcessingFailures != wantFailures || o.Pending != 0 || store.Stats().Leased != 0 {
				t.Fatalf("%s did not reach its refusal state: %+v", name, o)
			}
			t.Logf("%s reached: written=%d batches=%d processing_failures=%d", name, o.Written, o.Batches, o.ProcessingFailures)
			expectWithheld(t, o, connection.Uncounted(reason))
			if name != "unsettled-finalization" {
				// Later exact refusals cannot turn an unknown cumulative total
				// back into a numeric answer or a nonzero guessed value.
				enqueue(t, store, batch(t, 3, strings.Repeat(goodRequest, 2), strings.Repeat(encodedResponse, 2)))
				o = drain(t, w)
				if o.Batches != wantBatches+1 || o.ProcessingFailures != wantFailures+1 || o.Written != wantWrites {
					t.Fatalf("later known refusal did not reach processing: %+v", o)
				}
				t.Logf("later framed refusal reached: two pairs after %s, batches=%d processing_failures=%d", name, o.Batches, o.ProcessingFailures)
				expectWithheld(t, o, connection.Uncounted(reason))
				t.Logf("absorption reached: later two exact refusals leave cumulative count unknown (%s)", reason)
			}
		})
	}
}
