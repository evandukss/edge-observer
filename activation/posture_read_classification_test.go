//go:build linux && posturediagnostic

package activation

import "testing"

// This regression uses the diagnostic's real cgroup construction, but asserts
// the structured distinction between unavailable evidence and a failed check.
// It requires the same prepared, dedicated container as the diagnostic.
func TestPostureReadClassification(t *testing.T) {
	runPostureReadConstruction(t, true)
}
