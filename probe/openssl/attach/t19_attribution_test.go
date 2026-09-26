//go:build attach

package attach_test

import (
	"slices"
	"testing"

	"github.com/evandukss/edge-observer/account"
)

// t19Target is the one target of the case; nothing else in the session names a
// program, so every admission it lists belongs under this name.
const t19Target = "t19-parent"

// A child the fork hook admitted is credited in the sealed account to its
// parent's target, marked inherited, and counted in that target's share of the
// admissions. The parent, named by the target itself, is the control: the same
// target, not inherited. The child is forked after activation, so no
// resolution and no adoption walk can have found it; only the fork hook admits
// it, and its first appearance to userspace is its own transfer.
func TestT19AForkedChildIsCreditedToItsParentsTargetAsInherited(t *testing.T) {
	binary := built(t)
	port := serving(t)
	boot := thisBoot(t)
	witness := t.TempDir()

	a := rooted(t, port, "A", witness)
	c := configuring(t, exactly(t19Target, a.root, boot, "follow"))
	observer := started(t, binary, c)
	child := a.child(t, "fork", "C")

	roles := map[string]int32{"A": a.root.PID, "C": child.PID}
	before := map[string]int{"A": witnessed(witness, "A", a.root.PID), "C": witnessed(witness, "C", child.PID)}
	for range 3 {
		a.exchange(t)
	}
	waitWitnessed(t, witness, roles, before, 3)
	sealed := ended(t, observer, c)

	// Wiring: the child was admitted by the fork hook and its transfers reached
	// the session. Without these nothing below measures attribution.
	if by := observedBy(t, observer.directory(c)); by[child.PID] == 0 || by[a.root.PID] == 0 {
		t.Fatalf("wiring, not the property: the approved output holds %d entries for the child pid %d and %d for "+
			"the parent pid %d, so one of them was not admitted or transferred nothing, and no admission "+
			"below is the one this case is about", by[child.PID], child.PID, by[a.root.PID], a.root.PID)
	}
	if slices.Contains(pidsIn(named(sealed, t19Target).Descendants), child.PID) {
		t.Fatalf("wiring, not the property: the child pid %d is among the target's descendants at resolution, "+
			"so it was found by the process table and not admitted by the fork hook", child.PID)
	}
	if sealed.Admitted == nil || !sealed.Admitted.Known || sealed.Admitted.Descendants < 1 {
		t.Fatalf("wiring, not the property: the kernel reports no descendant admitted (%+v), so the fork hook "+
			"did not admit the child", sealed.Admitted)
	}
	if sealed.Admissions == nil || sealed.Admissions.Unavailable != "" {
		t.Fatalf("wiring, not the property: the sealed account carries no admissions (%+v)", sealed.Admissions)
	}
	parent, found := t19Listed(sealed.Admissions, a.root.PID)
	if !found {
		t.Fatalf("wiring, not the property: the parent pid %d is not listed among the admissions whose coverage "+
			"ended or whose grant was unknown, so the sealed account says nothing per admission here: %+v",
			a.root.PID, sealed.Admissions)
	}
	descendant, found := t19Listed(sealed.Admissions, child.PID)
	if !found {
		t.Fatalf("wiring, not the property: the child pid %d is not listed among the admissions whose coverage "+
			"ended or whose grant was unknown, so its attribution cannot be read: %+v", child.PID, sealed.Admissions)
	}

	// The control: the process the target named is under that target and not
	// inherited.
	if parent.Target != t19Target || parent.Inherited {
		t.Errorf("the parent pid %d is listed under %q with inherited %v, want %q and false",
			a.root.PID, parent.Target, parent.Inherited, t19Target)
	}

	// The property: the child is under its parent's target and inherited.
	if descendant.Target != t19Target || !descendant.Inherited {
		t.Errorf("the forked child pid %d is listed under %q with inherited %v, want %q and true",
			child.PID, descendant.Target, descendant.Inherited, t19Target)
	}

	// And the target's share counts both, with nothing under any other name.
	var names []string
	share := -1
	for _, one := range sealed.Admissions.ByTarget {
		names = append(names, one.Target)
		if one.Target == t19Target {
			share = one.Covered + one.Ended + one.Unknown
		}
	}
	if share != 2 || len(names) != 1 {
		t.Errorf("the admissions are shared among targets %q, with %d under %q; want the parent and the child, "+
			"2, under %q alone", names, share, t19Target, t19Target)
	}
}

// t19Listed is the one admission listed for pid, in either list; found is
// false where there is none or more than one.
func t19Listed(admissions *account.Admissions, pid int32) (account.Admission, bool) {
	var matched []account.Admission
	for _, one := range slices.Concat(admissions.CoverageEnded, admissions.GrantUnknown) {
		if one.Instance.PID == pid {
			matched = append(matched, one)
		}
	}
	if len(matched) != 1 {
		return account.Admission{}, false
	}
	return matched[0], true
}
