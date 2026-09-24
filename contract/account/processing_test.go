package account

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/evandukss/edge-observer/probe"
)

// This tests projection of supplied session facts, not the worker that measures
// them. Deliberately different counts expose relabeling, and both known loss
// and an unavailable reading must survive publication unchanged.
func TestProcessingAggregatePreservesDistinctFactsAndCaptureLoss(t *testing.T) {
	reasons := probe.GateReasons()
	for _, gateReason := range reasons {
		if !gateReason.InvalidatesCapture() {
			continue
		}
		reason := string(gateReason)
		t.Run(reason, func(t *testing.T) {
			for _, known := range []bool{true, false} {
				source := filled(t, known)
				source.Processing = nil
				before, err := Project(source, NotSupplied())
				if err != nil {
					t.Fatal(err)
				}
				if known {
					if before.Capture.Loss.State != Carried || before.Capture.Loss.Dropped != "7" || before.Capture.Loss.Unmatched != "7" {
						t.Fatalf("known nonzero capture-loss control missing: %+v", before.Capture.Loss)
					}
				} else if before.Capture.Loss.State != Unavailable || before.Capture.Loss.Why != "7" {
					t.Fatalf("unavailable capture-loss control became zero: %+v", before.Capture.Loss)
				}
				facts := map[string]any{
					"gate_reason": reason, "processing_failures": 3, "output_failures": 2,
					"authorized": 11, "written": 5, "stopped_pipelines": []string{"privacy"},
				}
				encoded, err := json.Marshal(facts)
				if err != nil {
					t.Fatal(err)
				}
				// JSON supplies the ruled surface without depending on new Go
				// names merely to compile this red against the old representation.
				if err := json.Unmarshal(encoded, &source.Processing); err != nil {
					t.Fatal(err)
				}
				after, err := Project(source, NotSupplied())
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(before.Capture, after.Capture) || !reflect.DeepEqual(before.Seal, after.Seal) {
					t.Fatal("processing projection changed capture-loss or seal evidence")
				}
				t.Logf("capture-loss control reached: known=%t reason=%s", known, reason)
				encoded, err = json.Marshal(after.Processing)
				if err != nil {
					t.Fatal(err)
				}
				var got map[string]any
				if err := json.Unmarshal(encoded, &got); err != nil {
					t.Fatal(err)
				}
				want := map[string]any{
					"gate_reason": reason, "processing_failures": "3", "output_failures": "2",
					"authorized": "11", "written": "5", "stopped_pipelines": []any{"privacy"},
				}
				if got["state"] != string(Carried) || !reflect.DeepEqual(got["aggregate"], want) {
					t.Fatalf("ruled aggregate missing or dispositions conflated: %s", encoded)
				}
				if pipelines, ok := got["pipelines"].([]any); !ok || len(pipelines) != 0 {
					t.Fatal("session aggregate fabricated per-pipeline attribution")
				}
				// The operational account must carry only the same six facts;
				// no implementation snapshots survive under another name.
				encoded, err = json.Marshal(source.Processing)
				if err != nil {
					t.Fatal(err)
				}
				var operational map[string]any
				if err := json.Unmarshal(encoded, &operational); err != nil {
					t.Fatal(err)
				}
				if len(operational) != len(facts) {
					t.Fatalf("operational surface is not the ruled minimum: %s", encoded)
				}
				for key := range facts {
					if _, ok := operational[key]; !ok {
						t.Fatalf("operational disposition %s is missing: %s", key, encoded)
					}
				}
			}
		})
	}
}
