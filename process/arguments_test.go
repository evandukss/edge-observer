package process_test

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/preflight"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// argumentTree is constructed procfs, with stat and argv captured from this
// live process and exe linked to its actual target. The test changes cmdline
// deliberately. Namespaces, sockets and execution are not modelled.
func argumentTree(t *testing.T) (string, process.Process) {
	t.Helper()
	root := t.TempDir()
	pid := int32(os.Getpid())
	directory := filepath.Join(root, strconv.Itoa(int(pid)))
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"stat", "cmdline"} {
		content, err := os.ReadFile(filepath.Join("/proc/self", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(directory, "exe")); err != nil {
		t.Fatal(err)
	}
	p, err := process.Identify(root, pid)
	if err != nil || p.StartTime == 0 || len(p.Arguments) == 0 {
		t.Fatalf("wiring: captured process unreadable: %+v, %v", p, err)
	}
	return root, p
}

func argumentFile(root string, p process.Process, name string) string {
	return filepath.Join(root, strconv.Itoa(int(p.PID)), name)
}

func emptyArguments(t *testing.T, root string, p process.Process) process.Process {
	t.Helper()
	if err := os.WriteFile(argumentFile(root, p, "cmdline"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := process.Identify(root, p.PID)
	if err != nil || got.Executable != p.Executable || len(got.Arguments) != 0 {
		t.Fatalf("wiring: expected readable exe and zero-byte cmdline: %+v, %v", got, err)
	}
	t.Log("wiring: exe readable, cmdline 0 bytes: 1 read")
	return got
}

func TestArgumentEvidenceSeparatesUnknownFromKnownEmpty(t *testing.T) {
	root, p := argumentTree(t)
	u := emptyArguments(t, root, p)
	if u.ArgumentEvidence != process.ArgumentsUndetermined || u.StartTime != p.StartTime {
		t.Fatalf("empty reading lost its uncertainty or birth: %+v", u)
	}
	rule := process.Rule{Executable: p.Executable}
	if got := rule.Decide(u); got != process.Indeterminate || rule.Matches(u) {
		t.Fatalf("executable-only rule decided empty reading: %v", got)
	}
	if err := os.WriteFile(argumentFile(root, p, "cmdline"), []byte(p.Executable+"\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	known, err := process.Identify(root, p.PID)
	if err != nil || known.ArgumentEvidence != process.ArgumentsKnown || !rule.Matches(known) {
		t.Fatalf("known argv[0] alone must match: %+v, %v", known, err)
	}
}

func TestArgumentUncertaintyBlocksInclusionAndExclusionAcrossSelection(t *testing.T) {
	root, p := argumentTree(t)
	u := emptyArguments(t, root, p)
	for _, tc := range []struct {
		name     string
		approval process.Approval
	}{
		{"executable-only", process.Approval{Rules: []process.Rule{{Executable: p.Executable}}}},
		{"arguments", process.Approval{Rules: []process.Rule{{Executable: p.Executable, Arguments: []string{"job"}}}}},
		{"exclusion", process.Approval{Rules: []process.Rule{{PID: &process.PIDGuard{PID: p.PID, Start: p.StartTime, Boot: "boot"}}},
			Exclusions: []process.Rule{{Executable: p.Executable, Arguments: []string{"secret"}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			table := process.TableOf(u)
			if tc.approval.Decide(u) != process.Indeterminate || tc.approval.Observes(u) || len(tc.approval.Select(table)) != 0 {
				t.Fatal("undetermined argument evidence granted selection")
			}
			if tc.approval.CheckArguments(table) == nil {
				t.Fatal("undetermined rule has no refusal")
			}
			if tc.name != "exclusion" && len(tc.approval.Matches(table)[0].Undetermined) != 1 {
				t.Fatal("match report collapsed unknown to no match")
			}
			resolution := tc.approval.Resolve(process.Host{Table: table, Boot: "boot"})
			if resolution.Err() == nil || len(resolution.Selections) != 0 {
				t.Fatal("resolution granted despite an undecidable rule")
			}
			if len(tc.approval.Denials(table)) != 0 {
				t.Fatal("an uncertain exclusion became a definite denial")
			}
			_, preflightErr := preflight.Take(preflight.Host{ProcFS: root}, tc.approval, probe.Catalog{})
			if preflightErr == nil || !strings.Contains(preflightErr.Error(), "arguments undetermined") {
				t.Fatalf("preflight did not refuse uncertainty: %v", preflightErr)
			}
			start := time.Now()
			_, err := tc.approval.SettleArguments(root, table)
			var refusal process.ArgumentsRefusal
			if !errors.As(err, &refusal) || refusal.PID != p.PID || !strings.Contains(err.Error(), "arguments undetermined") {
				t.Fatalf("deadline did not name this process: %v", err)
			}
			if elapsed := time.Since(start); elapsed < process.ArgumentReadBound || elapsed > time.Second {
				t.Fatalf("retry took %s, want bound %s plus scheduling allowance", elapsed, process.ArgumentReadBound)
			}
		})
	}
}

func TestArgumentRereadAcceptsSettledEvidence(t *testing.T) {
	root, p := argumentTree(t)
	u := emptyArguments(t, root, p)
	approval := process.Approval{Rules: []process.Rule{{Executable: p.Executable, Arguments: p.Arguments[1:]}}}
	if err := os.WriteFile(argumentFile(root, p, "cmdline"), []byte(strings.Join(p.Arguments, "\x00")+"\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	settled, err := approval.SettleArguments(root, process.TableOf(u))
	if err != nil || len(approval.Select(settled)) != 1 {
		t.Fatalf("settled process not selected: %v", err)
	}
	still, _ := (process.TableOf(u)).Lookup(p.PID)
	if still.ArgumentEvidence != process.ArgumentsUndetermined {
		t.Fatal("reread mutated original snapshot")
	}
}

func TestArgumentRereadRefusesChangedBirthOrExecutable(t *testing.T) {
	for _, changed := range []string{"birth", "executable"} {
		t.Run(changed, func(t *testing.T) {
			root, p := argumentTree(t)
			u := emptyArguments(t, root, p)
			if err := os.WriteFile(argumentFile(root, p, "cmdline"), []byte(strings.Join(p.Arguments, "\x00")+"\x00"), 0o600); err != nil {
				t.Fatal(err)
			}
			if changed == "birth" {
				u.StartTime++
			} else {
				u.Executable += "-previous"
			}
			approval := process.Approval{Rules: []process.Rule{{Executable: u.Executable, Arguments: p.Arguments[1:]}}}
			_, err := approval.SettleArguments(root, process.TableOf(u))
			if err == nil || !strings.Contains(err.Error(), "birth or executable changed") {
				t.Fatalf("replacement was silently judged as original: %v", err)
			}
		})
	}
}

func TestArgumentReadFailureKeepsTheProcessAndItsBirth(t *testing.T) {
	root, p := argumentTree(t)
	if err := os.Remove(argumentFile(root, p, "cmdline")); err != nil {
		t.Fatal(err)
	}
	got, err := process.Identify(root, p.PID)
	if err != nil || got.StartTime != p.StartTime || got.ArgumentEvidence != process.ArgumentsUndetermined {
		t.Fatalf("cmdline failure became disappearance: %+v, %v", got, err)
	}
	exec, err := process.ReadExec(root, p.PID)
	if err != nil || exec.StartTime != p.StartTime || exec.ArgumentEvidence != process.ArgumentsUndetermined {
		t.Fatalf("reload reading lost uncertainty: %+v, %v", exec, err)
	}
}

func TestAnUndeterminedExclusionBlocksInheritedSelection(t *testing.T) {
	root, p := argumentTree(t)
	child := emptyArguments(t, root, p)
	// A constructed family isolates ancestry; only the child's unknown argv is
	// read through procfs. No kernel admission is modelled by this table.
	parent := p
	parent.PID += 10
	parent.Executable = "/parent"
	parent.Arguments = []string{"/parent"}
	child.PPID = parent.PID
	grandchild := p
	grandchild.PID += 20
	grandchild.PPID = child.PID
	approval := process.Approval{Rules: []process.Rule{{Executable: parent.Executable}},
		Exclusions: []process.Rule{{Executable: child.Executable, Arguments: []string{"secret"}}}}
	if len(approval.Select(process.TableOf(parent))) != 1 {
		t.Fatal("wiring: known parent control did not select")
	}
	table := process.TableOf(parent, child, grandchild)
	if approval.CheckArguments(table) == nil || len(approval.Select(table)) != 0 {
		t.Fatal("an undecidable exclusion allowed inherited grants")
	}
	resolved := approval.Resolve(process.Host{Table: table})
	if resolved.Err() == nil || len(resolved.Selections) != 0 {
		t.Fatal("an undecidable exclusion allowed resolved grants")
	}
}

func TestArgumentEvidenceIsIndependentOfBirthEvidence(t *testing.T) {
	root, p := argumentTree(t)
	file := argumentFile(root, p, "stat")
	stat, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	// In the captured stat, set only starttime (field 22) to the reader's
	// undetermined-birth sentinel. This is constructed, not a live process.
	end := strings.LastIndexByte(string(stat), ')')
	fields := strings.Fields(string(stat[end+1:]))
	if end < 0 || len(fields) < 20 {
		t.Fatal("wiring: captured stat has no starttime field")
	}
	fields[19] = "0"
	if err := os.WriteFile(file, []byte(string(stat[:end+1])+" "+strings.Join(fields, " ")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := process.Identify(root, p.PID)
	if err != nil || got.Start().Determined || got.ArgumentEvidence != process.ArgumentsKnown {
		t.Fatalf("birth uncertainty changed argument evidence: %+v, %v", got, err)
	}
}
