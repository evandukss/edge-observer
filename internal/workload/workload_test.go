package workload_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/internal/workload"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

type output struct{ artifacts []processing.Artifact }

func (o *output) WriteApproved(_ context.Context, a processing.Approved) error {
	var artifact processing.Artifact
	if err := json.Unmarshal(a.Bytes(), &artifact); err != nil {
		return err
	}
	o.artifacts = append(o.artifacts, artifact)
	return nil
}

// processed runs w through one processing worker over a configuration with no
// rules, and returns what it wrote.
func processed(t *testing.T, w *workload.Workload) (*output, processing.Outcome) {
	t.Helper()
	raw, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatal(err)
	}
	compiled, findings := config.Compile(raw, "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: the example configuration was refused: %+v", findings)
	}
	store, err := intake.New(1 << 30)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1 << 20, IntakeExhausted: store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	out := &output{}
	worker, err := processing.New(processing.Options{Session: "workload", Plan: compiled.Plan, PolicyRevision: "workload", Intake: store, Gate: gate, Output: out})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := w.Write(store); err != nil || n != len(w.Entries) {
		t.Fatalf("wiring, not the property: %d of %d entries reached the intake: %v", n, len(w.Entries), err)
	}
	o, err := worker.Finish(context.Background(), processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil {
		t.Fatal(err)
	}
	return out, o
}

// written is the exchanges written per connection id.
func written(out *output) map[string]int {
	got := map[string]int{}
	for _, a := range out.artifacts {
		if a.Route.Pipeline == config.ExchangesPipeline && a.Reconstruction != nil {
			got[a.Connection.ID] += len(a.Reconstruction.Exchanges)
		}
	}
	return got
}

func TestTheSameShapeGeneratesTheSameEntries(t *testing.T) {
	shape := workload.Shape{Connections: 20, Exchanges: 3, HeaderBytes: 100, RequestBodyBytes: 50, ResponseBodyBytes: 300,
		JSONShare: 0.5, DefectShare: 0.3, Processes: 3, Concurrency: 4, ReorderShare: 0.2, Seed: 7}
	a, err := workload.Generate(shape)
	if err != nil {
		t.Fatal(err)
	}
	b, err := workload.Generate(shape)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Entries) == 0 {
		t.Fatal("wiring, not the property: nothing was generated")
	}
	if !reflect.DeepEqual(a, b) {
		t.Error("two workloads of one shape and seed differ")
	}
	shape.Seed = 8
	c, err := workload.Generate(shape)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(a.Entries, c.Entries) {
		t.Error("two seeds generated the same entries")
	}
}

// Capture numbers the connections, so they are 1 to Connections, and each has
// exactly one connection record.
func TestConnectionsAreNumberedByCapture(t *testing.T) {
	w, err := workload.Generate(workload.Shape{Connections: 50, Exchanges: 2, Processes: 4, Concurrency: 8, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	records := map[fragment.ConnectionID]int{}
	processes := map[fragment.Process]bool{}
	for _, e := range w.Entries {
		if e.Connection != nil {
			records[e.Connection.ID]++
			processes[e.Connection.Process] = true
		}
	}
	if len(w.Connections) != 50 || len(records) != 50 {
		t.Fatalf("%d connections planned and %d with records, want 50", len(w.Connections), len(records))
	}
	for i, c := range w.Connections {
		if c.ID != fragment.ConnectionID(i+1) || records[c.ID] != 1 {
			t.Errorf("connection %d has id %d and %d records, want id %d and one record", i, c.ID, records[c.ID], i+1)
		}
	}
	if len(processes) < 2 {
		t.Errorf("50 connections over 4 processes used %d", len(processes))
	}
}

// Without defects, processing writes every exchange of every connection; with a
// defect on every connection, it writes exactly the exchanges before the one
// the defect hit, whichever defect it is.
func TestProcessingWritesTheExchangesTheShapeDescribes(t *testing.T) {
	for _, defects := range []float64{0, 1} {
		t.Run("defect share "+strconv.FormatFloat(defects, 'f', -1, 64), func(t *testing.T) {
			w, err := workload.Generate(workload.Shape{Connections: 40, Exchanges: 4, HeaderBytes: 200, RequestBodyBytes: 100,
				ResponseBodyBytes: 9000, JSONShare: 0.5, DefectShare: defects, Processes: 2, Concurrency: 5, Seed: 3})
			if err != nil {
				t.Fatal(err)
			}
			out, o := processed(t, w)
			got := written(out)
			kinds := map[string]int{}
			for _, c := range w.Connections {
				want := 4
				if c.Defect != "" {
					want = c.DefectAt
					kinds[c.Defect]++
				}
				if got[strconv.FormatUint(uint64(c.ID), 10)] != want {
					t.Errorf("connection %d (defect %q at %d): %d exchanges written, want %d", c.ID, c.Defect, c.DefectAt, got[strconv.FormatUint(uint64(c.ID), 10)], want)
				}
			}
			if defects == 1 && len(kinds) != len(workload.Defects) {
				t.Errorf("40 defective connections carried %d kinds of defect, want all %d: %v", len(kinds), len(workload.Defects), kinds)
			}
			if o.Batches != 40 || o.Pending != 0 {
				t.Errorf("%d batches processed and %d pending, want 40 and 0", o.Batches, o.Pending)
			}
		})
	}
}

// JSONShare decides how many bodies are JSON, read back from what processing
// wrote.
func TestJSONShareDecidesTheBodies(t *testing.T) {
	for _, share := range []float64{0, 1} {
		w, err := workload.Generate(workload.Shape{Connections: 10, Exchanges: 3, RequestBodyBytes: 40, ResponseBodyBytes: 80, JSONShare: share, Seed: 5})
		if err != nil {
			t.Fatal(err)
		}
		out, _ := processed(t, w)
		bodies, labelled := 0, 0
		for _, a := range out.artifacts {
			if a.Reconstruction == nil {
				continue
			}
			for _, e := range a.Reconstruction.Exchanges {
				for _, m := range [][]string{fields(e.Request.Message.Headers), fields(e.Response.Message.Headers)} {
					bodies++
					for _, v := range m {
						if v == "application/json" {
							labelled++
						}
					}
				}
			}
		}
		if bodies != 60 {
			t.Fatalf("wiring, not the property: %d bodies written, want 60", bodies)
		}
		if want := int(share * 60); labelled != want {
			t.Errorf("JSON share %v: %d of 60 bodies labelled JSON, want %d", share, labelled, want)
		}
	}
}

func fields(headers []record.Field) []string {
	var out []string
	for _, h := range headers {
		if strings.EqualFold(h.Name, "content-type") {
			out = append(out, h.Value)
		}
	}
	return out
}

// Reordered connections deliver their record before their last fragment, and
// processing still writes them whole.
func TestReorderedRecordsPrecedeTheLastFragment(t *testing.T) {
	w, err := workload.Generate(workload.Shape{Connections: 30, Exchanges: 2, ResponseBodyBytes: 10, Concurrency: 3, ReorderShare: 1, Seed: 9})
	if err != nil {
		t.Fatal(err)
	}
	last, ending := map[fragment.ConnectionID]int{}, map[fragment.ConnectionID]int{}
	for n, e := range w.Entries {
		if e.Fragment != nil {
			last[e.Fragment.Connection] = n
		} else {
			ending[e.Connection.ID] = n
		}
	}
	for _, c := range w.Connections {
		if ending[c.ID] > last[c.ID] {
			t.Errorf("connection %d: record at %d, after its last fragment at %d", c.ID, ending[c.ID], last[c.ID])
		}
	}
	out, _ := processed(t, w)
	for id, n := range written(out) {
		if n != 2 {
			t.Errorf("connection %s: %d exchanges written, want 2", id, n)
		}
	}
	if len(written(out)) != 30 {
		t.Errorf("%d connections written, want 30", len(written(out)))
	}
}

// DefectKinds narrows the defects to the ones named, and naming none leaves
// the entries of a published shape unchanged.
func TestDefectKindsNarrowTheDefects(t *testing.T) {
	shape := workload.Shape{Connections: 40, Exchanges: 3, DefectShare: 1, Seed: 11}
	all, err := workload.Generate(shape)
	if err != nil {
		t.Fatal(err)
	}
	shape.DefectKinds = workload.Defects
	named, err := workload.Generate(shape)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(all.Entries, named.Entries) {
		t.Error("naming every defect changed the entries of the same shape")
	}
	shape.DefectKinds = []string{workload.DefectUnsupported}
	one, err := workload.Generate(shape)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range one.Connections {
		if c.Defect != workload.DefectUnsupported {
			t.Errorf("connection %d carries %q, want only %q", c.ID, c.Defect, workload.DefectUnsupported)
		}
	}
	shape.DefectKinds = []string{"other"}
	if _, err := workload.Generate(shape); err == nil {
		t.Error("a defect that does not exist was accepted")
	}
}
