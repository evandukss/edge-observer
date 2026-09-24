package policy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/policy"
)

func TestApprovedOutputAllowanceReachesProcessingPlan(t *testing.T) {
	document := processingDocument(t)
	observer := member(document, "observer")
	delete(observer, "spool_bound_mib")
	observer["approved_output_bound_mib"] = 13
	read, err := policy.CompileProcessing([]byte(encoded(t, document)), nil)
	if err != nil {
		t.Fatalf("approved output allowance refused: %v", err)
	}
	content, err := json.Marshal(read.Processing.Observer())
	if err != nil {
		t.Fatal(err)
	}
	var resolved map[string]any
	if err := json.Unmarshal(content, &resolved); err != nil {
		t.Fatal(err)
	}
	if resolved["approved_output_bound_mib"] != float64(13) {
		t.Fatalf("compiled output allowance not 13 MiB: %s", content)
	}
	if _, present := resolved["spool_bound_mib"]; present {
		t.Fatalf("compiled output still publishes retired spool setting: %s", content)
	}
}

func TestRetiredSpoolAllowanceCannotLookConfigured(t *testing.T) {
	document := processingDocument(t)
	observer := member(document, "observer")
	delete(observer, "spool_bound_mib")
	if read, err := policy.CompileProcessing([]byte(encoded(t, document)), nil); err != nil || read.Processing == nil {
		t.Fatalf("neighbour with output default did not compile: %v", err)
	}
	observer["spool_bound_mib"] = 13
	read, err := policy.CompileProcessing([]byte(encoded(t, document)), nil)
	if err == nil || read.Processing != nil || !strings.Contains(err.Error(), "spool_bound_mib") {
		t.Fatalf("retired key did not refuse by name: plan=%v error=%v", read.Processing, err)
	}
}
