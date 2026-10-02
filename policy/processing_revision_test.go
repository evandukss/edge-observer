package policy_test

import (
	"slices"
	"strings"
	"testing"
)

func TestProcessingRevisionIsProducedAndStable(t *testing.T) {
	document := processingDocument(t)
	first, second := compiled(t, document), compiled(t, document)
	if first.ProcessingRevision == "" || first.ProcessingRevision != second.ProcessingRevision {
		t.Fatalf("compiler did not produce a stable processing identity: first=%q second=%q", first.ProcessingRevision, second.ProcessingRevision)
	}
	if !strings.HasPrefix(first.ProcessingRevision, "sha256:") {
		t.Fatalf("processing identity has no declared digest: %q", first.ProcessingRevision)
	}
}

// What is watched and where the observer writes stay out of the processing
// revision, so reload can apply them; a rule change stays in it, so a restart
// applies it.
func TestProcessingRevisionDistinguishesRulesFromObservation(t *testing.T) {
	base := compiled(t, processingDocument(t))
	if base.ProcessingRevision == "" {
		t.Fatal("compiler supplied no processing identity for the control")
	}
	observation := processingDocument(t)
	observation["watch"] = []any{watching("different-observed-process", map[string]any{"exe": "/usr/bin/other"}, "all")}
	member(observation, "limits")["events"] = 19
	changedObservation := compiled(t, observation)
	if changedObservation.Revision == base.Revision || changedObservation.ProcessingRevision != base.ProcessingRevision {
		t.Fatalf("observation/settings change did not remain separate: base=%+v changed=%+v", base, changedObservation)
	}
	rules := processingDocument(t)
	member(rules, "remove")["query"] = []any{"token"}
	changedRules := compiled(t, rules)
	if changedRules.ProcessingRevision == base.ProcessingRevision {
		t.Fatal("a rule change did not change the processing identity")
	}
	// The rule adds an operation to the same route, so a route-only digest
	// misses it.
	if !slices.Equal(changedRules.Processing.Routes(), base.Processing.Routes()) {
		t.Fatal("the rule fixture unexpectedly changed the routes")
	}
}
