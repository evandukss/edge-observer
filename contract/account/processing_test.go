package account

import (
	"encoding/json"
	"reflect"
	"testing"

	observed "github.com/evandukss/edge-observer/account"
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
				// The filled account configures one extension, so its counts are
				// among the ruled facts.
				counts := observed.NoCounts(source.Extensions[0].Name)
				counts.Considered, counts.Changed = 13, 13
				facts := map[string]any{
					"gate_reason": reason, "processing_failures": 3, "output_failures": 2,
					"connections_cut": 17, "input_cut": 19,
					"authorized": 11, "written": 5, "delivery": map[string]any{"authorized": 11, "written": 5, "failed": 2, "dropped": 1, "pending": 3}, "exchange_ids": 13, "extensions": []observed.ExtensionCounts{counts},
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
					"connections_cut": "17", "input_cut": "19",
					"authorized": "11", "written": "5", "delivery": map[string]any{"authorized": "11", "written": "5", "failed": "2", "dropped": "1", "pending": "3", "discarded": "0", "bytes": "0", "pending_bytes": "0", "high_water_bytes": "0", "limit_bytes": "0"},
				}
				if got["state"] != string(Carried) || !reflect.DeepEqual(got["aggregate"], want) {
					t.Fatalf("ruled aggregate missing or dispositions conflated: %s", encoded)
				}
				extension, _ := got["extensions"].(map[string]any)[counts.Name].(map[string]any)
				if got["exchange_ids"] != "13" || extension["considered"] != "13" || extension["changed"] != "13" ||
					extension["unchanged"] != "0" {
					t.Fatalf("the ids issued or an extension's counts were not carried as counted: %s", encoded)
				}
				if pipelines, ok := got["pipelines"].([]any); !ok || len(pipelines) != 0 {
					t.Fatal("session aggregate fabricated per-pipeline attribution")
				}
				// The operational account must carry only the same eight facts;
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

func TestLogDestinationProjectionPreservesDistinctOutcomes(t *testing.T) {
	source := filled(t, true)
	source.LogDestinations = nil
	raw := []byte(`{"file":{"authorized":7,"written":3,"failed":1,"dropped":2,"pending":1,"discarded":2,"bytes":17,"pending_bytes":19,"high_water_bytes":23,"limit_bytes":29},"stdout":{"authorized":11,"written":0,"failed":11,"dropped":0,"pending":0,"discarded":0,"bytes":0,"pending_bytes":0,"high_water_bytes":31,"limit_bytes":29}}`)
	if err := json.Unmarshal(raw, &source.LogDestinations); err != nil {
		t.Fatal(err)
	}
	projected, err := Project(source, NotSupplied())
	if err != nil {
		t.Fatal(err)
	}
	file, ok := projected.LogDestinations["file"]
	if !ok || len(projected.LogDestinations) != 2 || file.Authorized != "7" || file.Written != "3" || file.Failed != "1" || file.Dropped != "2" || file.Pending != "1" || file.Discarded != "2" || file.Bytes != "17" || file.PendingBytes != "19" || file.HighWaterBytes != "23" || file.LimitBytes != "29" {
		t.Fatalf("file projection: %+v", projected.LogDestinations)
	}
	if out := projected.LogDestinations["stdout"]; out.Authorized != "11" || out.Written != "0" || out.Failed != "11" || out.HighWaterBytes != "31" {
		t.Fatalf("stdout projection: %+v", out)
	}
}
