package processing_test

import (
	"testing"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/processing"
)

func failurePlan(t *testing.T, action string, neighbors bool) *config.ProcessingPlan {
	t.Helper()
	remove := slot("remove", config.RemoveHeaders, `{"headers":["authorization"]}`)
	remove.OnFailure = action
	fanout := pipeline("fanout", remove)
	fanout.Sinks = []string{"account", "mirror"}
	pipelines := []config.Pipeline{fanout}
	if neighbors {
		metadata := pipeline("metadata")
		metadata.Input = "connection"
		pipelines = append(pipelines, pipeline("single"), metadata)
	}
	return workerPlan(t, pipelines...)
}

func failureControl(t *testing.T, plan *config.ProcessingPlan, want int) (*processing.Worker, *intake.Store) {
	t.Helper()
	out := &outputLog{}
	w, store := worker(t, plan, out)
	enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
	o := drain(t, w)
	if len(plan.Routes()) != want || len(out.artifacts) != want || o.Written != uint64(want) || o.Authorized != uint64(want) || o.Batches != 1 || o.Pending != 0 || o.ProcessingFailures != 0 || o.OutputFailures != 0 {
		t.Fatalf("compiled fan-out did not reach successful output: %+v, routes=%d artifacts=%d", o, len(plan.Routes()), len(out.artifacts))
	}
	seen := make(map[config.DurableRoute]int)
	for _, artifact := range out.artifacts {
		seen[artifact.Route]++
	}
	for _, route := range plan.Routes() {
		if seen[route] != 1 {
			t.Fatalf("compiled route did not write exactly once: %+v, writes=%d", route, seen[route])
		}
	}
	t.Logf("fan-out control reached: %d distinct compiled routes each wrote once, zero failures", want)
	return w, store
}

func refusalBatch(t *testing.T, id fragment.ConnectionID, kind string) capturedBatch {
	t.Helper()
	b := batch(t, id, goodRequest, goodResponse)
	switch kind {
	case "duplicate-sequence":
		b.fragments = append(b.fragments, b.fragments[0])
		b.records[0].Fragments = connection.Counted(3)
	case "overlap":
		later := b.fragments[0]
		later.Sequence, later.Offset, later.Length, later.Payload = 3, 1, 1, []byte("x")
		b.fragments = append(b.fragments, later)
		b.records[0].Fragments = connection.Counted(3)
	case "malformed-message":
		b = batch(t, id, "GET / HTTP/1.1\r\nBad : field\r\n\r\n", goodResponse)
	case "useful-prefix":
		b = batch(t, id, goodRequest+"GET /tail HTTP/1.1\r\n", goodResponse)
	default:
		t.Fatalf("unknown refusal fixture %q", kind)
	}
	return b
}

func TestProcessingFailureCountUsesDurableRoutes(t *testing.T) {
	for _, kind := range []string{"duplicate-sequence", "overlap", "malformed-message", "useful-prefix"} {
		t.Run(kind, func(t *testing.T) {
			w, store := failureControl(t, failurePlan(t, config.OnFailureDropAndAccount, true), 4)
			enqueue(t, store, refusalBatch(t, 2, kind))
			o := drain(t, w)
			wantWrites, wantFailures := uint64(4), uint64(4)
			if kind == "malformed-message" {
				// The connection route still succeeds; the two-sink pipeline
				// and its one-sink neighbor account for three affected routes.
				wantWrites, wantFailures = 5, 3
			}
			if kind == "useful-prefix" {
				// A route may write its useful prefix and also account for its
				// processing refusal; those dispositions are not exclusive.
				wantWrites, wantFailures = 8, 3
			}
			if o.Batches != 2 || o.Written != wantWrites || o.Authorized != wantWrites || o.OutputFailures != 0 || o.Pending != 0 || store.Stats().Leased != 0 || len(o.StoppedPipelines) != 0 {
				t.Fatalf("%s did not reach processing refusal: %+v", kind, o)
			}
			t.Logf("%s reached after fan-out control: batches=%d written=%d output_failures=%d", kind, o.Batches, o.Written, o.OutputFailures)
			if o.ProcessingFailures != wantFailures {
				t.Fatalf("affected durable routes: got %d processing failures, want %d", o.ProcessingFailures, wantFailures)
			}
			enqueue(t, store, batch(t, 3, goodRequest, goodResponse))
			o = drain(t, w)
			if o.Written != wantWrites+4 || o.ProcessingFailures != wantFailures || o.OutputFailures != 0 {
				t.Fatalf("later successful routes changed refusal count: %+v", o)
			}
			t.Log("later four-route output reached without adding a processing failure")
		})
	}
}

func TestProcessingFailureCountExcludesStoppedRoutes(t *testing.T) {
	w, store := failureControl(t, failurePlan(t, config.OnFailureStopPipeline, true), 4)
	enqueue(t, store, refusalBatch(t, 2, "malformed-message"))
	before := drain(t, w)
	if before.Batches != 2 || before.Written != 5 || len(before.StoppedPipelines) != 1 || before.StoppedPipelines[0] != "fanout" || before.OutputFailures != 0 {
		t.Fatalf("two-route pipeline was not stopped beside its successful metadata neighbor: %+v", before)
	}
	t.Log("stop control reached: two routes stopped, two neighboring routes remain active")
	enqueue(t, store, refusalBatch(t, 3, "duplicate-sequence"))
	o := drain(t, w)
	if o.Batches != 3 || o.Written != before.Written || o.Pending != 0 || store.Stats().Leased != 0 || len(o.StoppedPipelines) != 1 || o.OutputFailures != 0 {
		t.Fatalf("invalid batch did not reach refusal with stopped routes: %+v", o)
	}
	t.Log("invalid batch reached with exactly two active routes after the stop")
	if got := o.ProcessingFailures - before.ProcessingFailures; got != 2 {
		t.Fatalf("active affected routes: failure increment got %d, want 2", got)
	}
	if o.ProcessingFailures != 5 {
		t.Fatalf("cumulative affected routes: got %d, want 5", o.ProcessingFailures)
	}
	enqueue(t, store, batch(t, 4, goodRequest, goodResponse))
	o = drain(t, w)
	if o.Written != 7 || o.ProcessingFailures != 5 || o.OutputFailures != 0 {
		t.Fatalf("active neighbors did not resume without recounting stopped routes: %+v", o)
	}
	t.Log("two active neighbors wrote again; cumulative failures remain exactly five")
}

func TestProcessingFailureCountDoesNotRecountAllStoppedRoutes(t *testing.T) {
	w, store := failureControl(t, failurePlan(t, config.OnFailureStopPipeline, false), 2)
	enqueue(t, store, refusalBatch(t, 2, "malformed-message"))
	before := drain(t, w)
	if before.Batches != 2 || before.Written != 2 || len(before.StoppedPipelines) != 1 || before.StoppedPipelines[0] != "fanout" || before.OutputFailures != 0 {
		t.Fatalf("all-route stop control was not reached: %+v", before)
	}
	t.Log("all-route stop control reached: both formerly successful routes are stopped")
	enqueue(t, store, refusalBatch(t, 3, "duplicate-sequence"))
	o := drain(t, w)
	if o.Batches != 3 || o.Written != 2 || o.Pending != 0 || store.Stats().Leased != 0 || len(o.StoppedPipelines) != 1 || o.OutputFailures != 0 {
		t.Fatalf("invalid batch was not consumed after all routes stopped: %+v", o)
	}
	t.Log("invalid batch consumed with zero active routes")
	if got := o.ProcessingFailures - before.ProcessingFailures; got != 0 {
		t.Fatalf("already stopped routes were counted again: increment got %d, want 0", got)
	}
	if o.ProcessingFailures != 2 {
		t.Fatalf("original failed routes: got %d, want 2", o.ProcessingFailures)
	}
}
