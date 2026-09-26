//go:build attach

package attach_test

import (
	"slices"
	"testing"

	"github.com/evandukss/edge-observer/account"
)

// Within one session no two targets share a number, whatever a reload does to
// the order of the configuration. A reader that keys the sealed account's
// targets by number finds each process, and each admission, under the target
// that named it: after a reload that puts a new target first, and, as the
// control, in a session that held both targets from the start.
func TestT19NoTwoTargetsInOneSessionShareANumber(t *testing.T) {
	for _, reload := range []bool{false, true} {
		name := map[bool]string{false: "both from the start", true: "one added first by a reload"}[reload]
		t.Run(name, func(t *testing.T) {
			binary := built(t)
			boot := thisBoot(t)
			witness := t.TempDir()
			a := rooted(t, serving(t), "A", witness)
			_, inserted := looping(t, serving(t), "U", t.TempDir(), "loop")
			both := []map[string]any{exactly(t19Inserted, inserted, boot, "none"),
				exactly(t19Target, a.root, boot, "follow")}

			c := configuring(t, both...)
			if reload {
				c = configuring(t, both[1])
			}
			observer := started(t, binary, c)
			if reload {
				before := inspected(t, binary, c)
				c.rewrite(t, both, nil)
				candidate := previewed(t, binary, c)
				if named(before, t19Target).Number != 1 || named(candidate, t19Inserted).Number != 1 {
					t.Fatalf("wiring, not the property: the session numbers %q %d and the candidate on its own "+
						"numbers %q %d, want both 1, so the reload offers no number the session already holds",
						t19Target, named(before, t19Target).Number, t19Inserted, named(candidate, t19Inserted).Number)
				}
				answer, err := reloaded(t, binary, c)
				if err != nil || answer.Outcome != "activated" || !slices.Equal(answer.Added, []string{t19Inserted}) {
					t.Fatalf("wiring, not the property: the reload answered %+v with %v, want %q added and activated",
						answer, err, t19Inserted)
				}
			}
			for range 3 {
				a.exchange(t)
			}
			sealed := ended(t, observer, c)

			roots := map[int32]string{a.root.PID: t19Target, inserted.PID: t19Inserted}
			if len(sealed.Targets) != 2 {
				t.Fatalf("wiring, not the property: the sealed account holds %d targets, want the 2 configured",
					len(sealed.Targets))
			}
			for pid, want := range roots {
				if !slices.Contains(pidsIn(named(sealed, want).Roots), pid) {
					t.Fatalf("wiring, not the property: pid %d is not among %q's roots, so nothing below can find it",
						pid, want)
				}
			}
			if sealed.Admissions == nil || sealed.Admissions.Unavailable != "" {
				t.Fatalf("wiring, not the property: the sealed account carries no admissions (%+v)", sealed.Admissions)
			}
			rows := slices.Concat(sealed.Admissions.CoverageEnded, sealed.Admissions.GrantUnknown)
			for pid := range roots {
				if !slices.ContainsFunc(rows, func(one account.Admission) bool { return one.Instance.PID == pid }) {
					t.Fatalf("wiring, not the property: pid %d has no admission listed, so no admission below is "+
						"read for it", pid)
				}
			}

			// The reader: targets keyed by number, the way anything joining on the
			// number reads them.
			byNumber := make(map[int]account.Target, len(sealed.Targets))
			for _, one := range sealed.Targets {
				byNumber[one.Number] = one
			}
			for pid, want := range roots {
				got := byNumber[named(sealed, want).Number]
				if got.Name != want || !slices.Contains(pidsIn(got.Roots), pid) {
					t.Errorf("pid %d, named by %q, is target %d, and the target a reader finds under that number "+
						"is %q", pid, want, named(sealed, want).Number, got.Name)
				}
			}
			for _, one := range rows {
				if got := byNumber[named(sealed, one.Target).Number]; got.Name != one.Target {
					t.Errorf("the admission of pid %d is listed under %q, and the target a reader finds under that "+
						"target's number is %q", one.Instance.PID, one.Target, got.Name)
				}
			}
		})
	}
}
