//go:build attach

package attach_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/process"
)

// The account names an exclusion by its number alone and cites the
// configuration it ran under, so its exclusion N is the Nth exclusion of that
// configuration. A reload that reorders the exclusions while adding a target
// would make one number name two exclusions, and is refused. A reader keying
// the sealed account's exclusions by number finds each against the cited
// configuration's exclusion of that number: with no reload, after a reload
// that keeps their order, and after one that tried to reorder them.
func TestT19OneExclusionNumberNamesOneExclusionAcrossAReload(t *testing.T) {
	for _, one := range []struct {
		name            string
		reload, reorder bool
	}{
		{"no reload", false, false},
		{"a reload that keeps their order", true, false},
		{"a reload that reorders them", true, true},
	} {
		t.Run(one.name, func(t *testing.T) {
			binary := built(t)
			boot := thisBoot(t)
			a := rooted(t, serving(t), "A", t.TempDir())
			_, first := looping(t, serving(t), "X1", t.TempDir(), "loop")
			_, second := looping(t, serving(t), "X2", t.TempDir(), "loop")
			_, added := looping(t, serving(t), "U", t.TempDir(), "loop")
			exclusion := func(p process.Process) map[string]any {
				return map[string]any{"exe": p.Executable, "args": p.Arguments[1:]}
			}
			kept := []map[string]any{exactly(t19Target, a.root, boot, "follow")}
			inOrder := []map[string]any{exclusion(first), exclusion(second)}

			c := configuring(t, kept...)
			c.rewrite(t, kept, inOrder)
			observer := started(t, binary, c)
			cited := map[string][]int32{inspected(t, binary, c).Policy.Revision: {first.PID, second.PID}}

			if one.reload {
				offered, pids := inOrder, []int32{first.PID, second.PID}
				if one.reorder {
					offered, pids = []map[string]any{inOrder[1], inOrder[0]}, []int32{second.PID, first.PID}
				}
				c.rewrite(t, append(slices.Clone(kept), exactly(t19Inserted, added, boot, "none")), offered)
				candidate := previewed(t, binary, c).Policy.Revision
				if _, same := cited[candidate]; same {
					t.Fatalf("wiring, not the property: the candidate's revision %s is the start's, so no reload "+
						"below offers a different configuration", candidate)
				}
				cited[candidate] = pids
				answer, err := reloaded(t, binary, c)
				switch {
				case one.reorder && (err == nil || answer.Outcome != "refused" ||
					!strings.Contains(answer.Reason, "exclusion")):
					t.Errorf("a reload reordering the exclusions answered %+v with %v, want a refusal naming "+
						"the exclusions", answer, err)
				case !one.reorder && (err != nil || answer.Outcome != "activated"):
					t.Fatalf("wiring, not the property: a reload keeping the exclusions' order answered %+v with "+
						"%v, want activated", answer, err)
				}
			}
			sealed := ended(t, observer, c)

			order, known := cited[sealed.Policy.Revision]
			if !known {
				t.Fatalf("wiring, not the property: the account cites revision %s, which is neither configuration "+
					"this case wrote", sealed.Policy.Revision)
			}
			if len(sealed.Exclusions) != 2 {
				t.Fatalf("wiring, not the property: the account holds %d exclusions, want the 2 configured",
					len(sealed.Exclusions))
			}
			for _, excluded := range sealed.Exclusions {
				if len(excluded.Roots) != 1 {
					t.Fatalf("wiring, not the property: exclusion %d matched %d processes, want 1, so a number "+
						"cannot be checked against what it matched", excluded.Number, len(excluded.Roots))
				}
			}

			// The reader: the account's exclusions keyed by number, against the
			// cited configuration's exclusion of that number.
			for _, excluded := range sealed.Exclusions {
				if excluded.Number < 1 || excluded.Number > len(order) {
					t.Errorf("the account names exclusion %d, and the configuration it cites has %d",
						excluded.Number, len(order))
					continue
				}
				if want, got := order[excluded.Number-1], excluded.Roots[0].PID; got != want {
					t.Errorf("the account's exclusion %d matched pid %d, and exclusion %d of the configuration it "+
						"cites (revision %s) matches pid %d", excluded.Number, got, excluded.Number,
						sealed.Policy.Revision, want)
				}
			}
		})
	}
}
