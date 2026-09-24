//go:build attach

package attach_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
)

// intoCgroup makes a cgroup and moves the pid into it, so rule and allowlist
// cover one real cgroup on this host.
func intoCgroup(t *testing.T, name string, pid int32) {
	t.Helper()

	directory := filepath.Join(ebpf.DefaultCgroupMount, name)
	if err := os.Mkdir(directory, 0o755); err != nil && !os.IsExist(err) {
		t.Fatalf("make cgroup %s: %v", directory, err)
	}
	t.Cleanup(func() { _ = os.Remove(directory) })
	if err := os.WriteFile(filepath.Join(directory, "cgroup.procs"),
		[]byte(strconv.Itoa(int(pid))), 0o644); err != nil {
		t.Fatalf("move pid %d into %s: %v", pid, directory, err)
	}
}

// unifiedCgroup is where the kernel says this process sits on the version 2
// hierarchy, read from /proc because that is what a rule must match.
func unifiedCgroup(t *testing.T, pid int32) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(procfs, strconv.FormatInt(int64(pid), 10), "cgroup"))
	if err != nil {
		t.Fatalf("read the cgroup of pid %d: %v", pid, err)
	}
	for line := range strings.Lines(string(content)) {
		if path, found := strings.CutPrefix(strings.TrimSpace(line), "0::"); found {
			return path
		}
	}
	t.Fatalf("pid %d is on no unified hierarchy, so a cgroup rule has nothing to name:\n%s", pid, content)
	return ""
}

func pidsOf(processes []process.Process) map[int32]bool {
	found := make(map[int32]bool, len(processes))
	for _, p := range processes {
		found[p.PID] = true
	}
	return found
}

// A cgroup rule matched against this kernel's real processes. Two processes
// share one cgroup, as a gateway and a worker under one supervisor would. The
// rule approves both, because a cgroup names a service, and each stays a
// process of its own, so what crossed which is still attributable. A design
// taking the cgroup as the unit of attribution would pass the first half and
// lose the second silently.
func TestACgroupRuleSelectsRealProcessesAndKeepsThemApart(t *testing.T) {
	// Two servers, so the two clients' arguments differ; against one server their
	// command lines would be identical and the argument selector could not
	// separate them either.
	one := speaking(t, serving(t))
	two := speaking(t, serving(t))

	shared := "obs-shared-" + strconv.Itoa(os.Getpid())
	intoCgroup(t, shared, one.process.PID)
	intoCgroup(t, shared, two.process.PID)

	path := unifiedCgroup(t, one.process.PID)
	if other := unifiedCgroup(t, two.process.PID); other != path {
		t.Fatalf("the two processes are in %s and %s, so they do not share a cgroup and this "+
			"measures nothing", path, other)
	}

	rule := process.Rule{Cgroup: path}
	if err := rule.Validate(); err != nil {
		t.Fatalf("the cgroup this host gave these processes is not one a rule may name: %v", err)
	}
	approval := process.Approval{Rules: []process.Rule{rule}}

	table, err := process.Read(procfs)
	if err != nil {
		t.Fatalf("Read(%s): %v", procfs, err)
	}

	selected := pidsOf(approval.Select(table))
	if !selected[one.process.PID] || !selected[two.process.PID] {
		t.Fatalf("the cgroup rule for %s selected %v, and the two processes in it are %d and %d",
			path, selected, one.process.PID, two.process.PID)
	}

	// The control: a rule selecting every process on the host would also satisfy
	// the assertion above. This test's own process is outside that cgroup.
	if self := int32(os.Getpid()); selected[self] {
		t.Errorf("the cgroup rule also selected pid %d, which was never moved into %s", self, path)
	}

	matches := approval.Matches(table)
	if len(matches) != 1 || len(matches[0].Matched) < 2 {
		t.Errorf("rule 1 is reported as matching %d processes, and two are in its cgroup", len(matches[0].Matched))
	}

	// The other selector still separates them, which is the only thing that can
	// where two services share one cgroup.
	only := process.Approval{Rules: []process.Rule{{
		Executable: one.process.Executable,
		Arguments:  one.process.Arguments[1:],
	}}}
	alone := pidsOf(only.Select(table))
	if !alone[one.process.PID] {
		t.Errorf("an argument rule does not select the process it was written from")
	}
	if alone[two.process.PID] {
		t.Errorf("an argument rule for one process also selected the other, so the two are not separable")
	}
}

// On the wire: a cgroup rule selects both processes, both are observed, and
// every record names the process that transferred rather than the rule that
// selected it, because the identity travels with the event.
func TestBothProcessesUnderOneApprovedCgroupAreAttributedSeparately(t *testing.T) {
	port := serving(t)
	one := speaking(t, port)
	two := speaking(t, port)

	shared := "obs-attributed-" + strconv.Itoa(os.Getpid())
	intoCgroup(t, shared, one.process.PID)
	intoCgroup(t, shared, two.process.PID)

	approval := process.Approval{Rules: []process.Rule{{Cgroup: unifiedCgroup(t, one.process.PID)}}}
	table, err := process.Read(procfs)
	if err != nil {
		t.Fatalf("Read(%s): %v", procfs, err)
	}
	selected := approval.Select(table)
	if len(selected) < 2 {
		t.Fatalf("the cgroup rule selected %d processes, and the two in its cgroup are %d and %d",
			len(selected), one.process.PID, two.process.PID)
	}

	sink := &collected{}
	live, err := attach.NeweBPF(approval).Attach(requesting(selected...), capture.New(sink))
	if err != nil {
		t.Fatalf("attach to the %d processes the cgroup rule selected: %v", len(selected), err)
	}
	t.Cleanup(func() { _ = live.Close() })

	one.ask(t, "one")
	two.ask(t, "two")

	seen := make(map[int32]bool)
	for _, record := range records(t, sink, 4) {
		seen[record.Process.PID] = true
	}
	if !seen[one.process.PID] || !seen[two.process.PID] {
		t.Fatalf("records name %v, and the two processes in the approved cgroup are %d and %d",
			seen, one.process.PID, two.process.PID)
	}
	if len(seen) != 2 {
		t.Errorf("records name %d processes, want the two in the cgroup", len(seen))
	}
}
