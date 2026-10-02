package policy_test

import (
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/policy"
)

func TestOutputLimitIsUnknownKey(t *testing.T) {
	document := processingDocument(t)
	member(document, "limits")["output_mib"] = 13
	read, err := policy.CompileProcessing([]byte(encoded(t, document)), "")
	if err == nil || read.Processing != nil || !strings.Contains(err.Error(), "output_mib") || !strings.Contains(err.Error(), "unknown_key") {
		t.Fatalf("unknown output key: %v", err)
	}
}

func TestRetiredSpoolAllowanceCannotLookConfigured(t *testing.T) {
	document := processingDocument(t)
	limits := member(document, "limits")
	if read, err := policy.CompileProcessing([]byte(encoded(t, document)), ""); err != nil || read.Processing == nil {
		t.Fatalf("neighbour with output default did not compile: %v", err)
	}
	limits["spool_bound_mib"] = 13
	read, err := policy.CompileProcessing([]byte(encoded(t, document)), "")
	if err == nil || read.Processing != nil || !strings.Contains(err.Error(), "spool_bound_mib") {
		t.Fatalf("retired key did not refuse by name: plan=%v error=%v", read.Processing, err)
	}
}
