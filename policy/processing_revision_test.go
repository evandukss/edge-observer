package policy_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/policy"
)

func TestProcessingRevisionIsProducedAndStable(t *testing.T) {
	document := processingDocument(t)
	compile := func() policy.Policy {
		t.Helper()
		read, err := policy.CompileProcessing([]byte(encoded(t, document)), nil)
		if err != nil || read.Processing == nil {
			t.Fatalf("valid processing configuration refused: %v", err)
		}
		return read
	}
	first, second := compile(), compile()
	if first.ProcessingRevision == "" || first.ProcessingRevision != second.ProcessingRevision {
		t.Fatalf("compiler did not produce a stable processing identity: first=%q second=%q", first.ProcessingRevision, second.ProcessingRevision)
	}
	if !strings.HasPrefix(first.ProcessingRevision, "sha256:") {
		t.Fatalf("processing identity has no declared digest: %q", first.ProcessingRevision)
	}
}

func TestProcessingRevisionDistinguishesRetentionFromObservation(t *testing.T) {
	compile := func(document map[string]any) policy.Policy {
		t.Helper()
		read, err := policy.CompileProcessing([]byte(encoded(t, document)), nil)
		if err != nil || read.Processing == nil {
			t.Fatalf("valid processing configuration refused: %v", err)
		}
		return read
	}
	base := compile(processingDocument(t))
	if base.ProcessingRevision == "" {
		t.Fatal("compiler supplied no processing identity for the control")
	}
	observation := processingDocument(t)
	member(observation, "observation_scope")["targets"] = []any{target("different-observed-process", map[string]any{"exe": "/usr/bin/other"}, true, true)}
	member(observation, "observer")["approved_output_bound_mib"] = 19
	changedObservation := compile(observation)
	if changedObservation.Revision == base.Revision || changedObservation.ProcessingRevision != base.ProcessingRevision {
		t.Fatalf("observation/settings change did not remain separate: base=%+v changed=%+v", base, changedObservation)
	}
	retention := processingDocument(t)
	member(retention, "retention_and_export")["export_sinks"] = []any{"account"}
	changedRetention := compile(retention)
	if changedRetention.ProcessingRevision == base.ProcessingRevision {
		t.Fatal("retention declaration changed without changing processing identity")
	}
	// The configured sink stays local, so this declaration changes permission
	// without changing any present durable route. A route-only digest misses it.
	if !slices.Equal(changedRetention.Processing.Routes(), base.Processing.Routes()) {
		t.Fatal("retention fixture unexpectedly changed the existing routes")
	}
}
