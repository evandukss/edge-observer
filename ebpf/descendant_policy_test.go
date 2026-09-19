package ebpf

import (
	"testing"

	"github.com/evandukss/edge-observer/admission"
)

// This pins the policy answer without loading a program or placing a probe.
// A rejected follow request grants nothing; an accepted follow request beside
// a none request still covers future children. Placements decide neither case.
func TestDescendantCoverageUsesAcceptedPolicies(t *testing.T) {
	for _, tc := range []struct {
		name  string
		modes []admission.Mode
		want  bool
	}{
		{"no admitted instances", nil, false},
		{"none", []admission.Mode{admission.ModeNone}, false},
		{"existing", []admission.Mode{admission.ModeExisting}, false},
		{"follow", []admission.Mode{admission.ModeFollow}, true},
		{"none and existing", []admission.Mode{admission.ModeNone, admission.ModeExisting}, false},
		{"none then follow", []admission.Mode{admission.ModeNone, admission.ModeFollow}, true},
		{"follow then none", []admission.Mode{admission.ModeFollow, admission.ModeNone}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := Session{declined: []Declined{{Selection: admission.Selection{Mode: admission.ModeFollow}}}}
			for _, mode := range tc.modes {
				session.accepted = append(session.accepted, admission.Selection{Mode: mode})
			}
			if got := session.Coverage().Descendants; got != tc.want {
				t.Fatalf("accepted policies %v: descendant coverage = %t, want %t", tc.modes, got, tc.want)
			}
		})
	}
}
