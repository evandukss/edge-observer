package main

import (
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/policy"
)

func TestReloadRequiresTheSameNonemptyCompiledProcessingRevision(t *testing.T) {
	current, err := policy.CompileProcessing([]byte(inForce), nil)
	if err != nil || current.Processing == nil {
		t.Fatalf("processing fixture refused: %v", err)
	}
	// A synthetic identity isolates additive's comparison from the compiler's
	// identity production, which policy's tests exercise separately.
	current.ProcessingRevision = "sha256:fixture-current"
	if _, why := additive(current, current); why != "" {
		t.Fatalf("unchanged compiled control refused: %s", why)
	}
	for _, tc := range []struct {
		name    string
		change  func(*policy.Policy)
		because string
	}{
		{"changed", func(p *policy.Policy) { p.ProcessingRevision = "sha256:fixture-next" }, "processing or retention"},
		{"absent identity", func(p *policy.Policy) { p.ProcessingRevision = "" }, "processing revision"},
		{"legacy plan", func(p *policy.Policy) { p.Processing = nil }, "compiled processing plan"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := current
			tc.change(&candidate)
			if _, why := additive(current, candidate); !strings.Contains(why, tc.because) {
				t.Fatalf("reload did not refuse %s by its deciding reason: %q", tc.name, why)
			}
		})
	}
}
