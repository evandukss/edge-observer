//go:build attach

package attach_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Each admission's pid namespace is labelled with what read it, in the
// operational account and in its projection. A child already running when the
// session started was listed by the policy's resolution, which read its
// namespace from /proc; a child forked after activation was admitted by the
// kernel, and its namespace is the one its events carry. Both are inherited,
// so inheritance cannot be what decides the label. The root, named by the
// target, is the control.
func TestT19EachAdmissionsNamespaceNamesWhatReadIt(t *testing.T) {
	binary := built(t)
	boot := thisBoot(t)
	witness := t.TempDir()
	a := rooted(t, serving(t), "A", witness)
	early := a.child(t, "fork", "B")
	c := configuring(t, exactly(t19Target, a.root, boot, "follow"))
	observer := started(t, binary, c)
	late := a.child(t, "fork", "C")

	roles := map[string]int32{"A": a.root.PID, "B": early.PID, "C": late.PID}
	before := make(map[string]int, len(roles))
	for role, pid := range roles {
		before[role] = witnessed(witness, role, pid)
	}
	for range 3 {
		a.exchange(t)
	}
	waitWitnessed(t, witness, roles, before, 3)
	sealed := ended(t, observer, c)

	by := observedBy(t, c.directory)
	for role, pid := range roles {
		if by[pid] == 0 {
			t.Fatalf("wiring, not the property: the approved output holds nothing for %s (pid %d), so it was not "+
				"admitted or transferred nothing", role, pid)
		}
	}
	listed := pidsIn(named(sealed, t19Target).Descendants)
	if !slices.Contains(listed, early.PID) || slices.Contains(listed, late.PID) {
		t.Fatalf("wiring, not the property: the resolution listed descendants %v, want B (pid %d) and not C "+
			"(pid %d), so the two children were not admitted the two ways this case compares", listed, early.PID, late.PID)
	}

	want := map[int32]struct {
		by        string
		inherited bool
	}{
		a.root.PID: {"resolution_proc_read", false},
		early.PID:  {"resolution_proc_read", true},
		late.PID:   {"admission_event", true},
	}
	operational := t19Rows(t, filepath.Join(observer.directory(c), "account.json"), "admissions")
	projected := t19Rows(t, filepath.Join(observer.directory(c), "contract-account.json"), "scope", "coverage")
	for pid := range want {
		if len(operational[pid]) != 1 || len(projected[pid]) != 1 {
			t.Fatalf("wiring, not the property: pid %d is listed %d times in the account and %d in its projection, "+
				"want once in each", pid, len(operational[pid]), len(projected[pid]))
		}
	}

	for pid, one := range want {
		row, projection := operational[pid][0], projected[pid][0]
		if row.Inherited != one.inherited || projection.Inherited != one.inherited {
			t.Errorf("pid %d reads inherited %v in the account and %v in its projection, want %v",
				pid, row.Inherited, projection.Inherited, one.inherited)
		}
		if row.NamespaceBy != one.by {
			t.Errorf("the account says pid %d's namespace was established by %q, want %q", pid, row.NamespaceBy, one.by)
		}
		if got := projection.Instance.PidNamespace.EstablishedBy; got != one.by {
			t.Errorf("the projection says pid %d's namespace was established by %q, want %q", pid, got, one.by)
		}
	}
}

// t19Row is the part of one listed admission these cases read, in either
// account: each spells only its own members, and the other's decode empty.
type t19Row struct {
	Instance struct {
		PID          int32 `json:"pid"`
		PidNamespace struct {
			EstablishedBy string `json:"established_by"`
		} `json:"pid_namespace"`
	} `json:"instance"`
	Inherited   bool   `json:"inherited"`
	NamespaceBy string `json:"namespace_by"`
}

// t19Rows is every admission listed in the file, whose coverage ended or whose
// grant was not read, by pid; path is the members leading to the two lists.
func t19Rows(t *testing.T, file string, path ...string) map[int32][]t19Row {
	t.Helper()
	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode %s: %v", file, err)
	}
	for _, member := range path[:len(path)-1] {
		var inner map[string]json.RawMessage
		if err := json.Unmarshal(document[member], &inner); err != nil {
			t.Fatalf("decode %s at %s: %v", file, member, err)
		}
		document = inner
	}
	var lists struct {
		Ended   []t19Row `json:"coverage_ended"`
		Unknown []t19Row `json:"grant_unknown"`
	}
	if err := json.Unmarshal(document[path[len(path)-1]], &lists); err != nil {
		t.Fatalf("decode the admissions of %s: %v", file, err)
	}
	found := make(map[int32][]t19Row)
	for _, one := range slices.Concat(lists.Ended, lists.Unknown) {
		found[one.Instance.PID] = append(found[one.Instance.PID], one)
	}
	return found
}
