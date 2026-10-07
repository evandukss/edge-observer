package process_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/process"
)

// These cases are written from process/arguments.go's published comments and
// the requirement that a process whose arguments are unreadable is never
// decided on them, not from the implementation.
//
// THE CONSTRUCTED PROCFS. A root built here holds, per process, the bytes the
// kernel gave for a real running child: stat, status and cgroup are copied
// from /proc/<pid>, exe is a symlink to the path the kernel's exe link names,
// and ns/pid is a symlink to that child's own nsfs link, so its device and
// inode are the kernel's. ONLY cmdline is constructed, as zero bytes: the
// reading the kernel gives while an exec has replaced the memory and not yet
// placed argv, and persistently after prctl(PR_SET_MM_ARG_END) sets the end of
// the arguments to their start. Nothing else under /proc/<pid> is modelled.

const independentProcfs = "/proc"

// independentInstall copies /bin/sleep to path, so each case's process is told
// apart by its executable.
func independentInstall(t *testing.T, path string) string {
	t.Helper()
	program, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatalf("wiring, not the property: read /bin/sleep: %v", err)
	}
	if err := os.WriteFile(path, program, 0o755); err != nil {
		t.Fatalf("wiring, not the property: write %s: %v", path, err)
	}
	return path
}

// independentChild is one real running copy of sleep and what the kernel
// reported for it once its arguments were placed.
type independentChild struct {
	pid                           int32
	path                          string
	args                          []string
	start                         uint64
	stat, status, cgroup, cmdline []byte
}

// independentSleeper copies /bin/sleep to a path of its own, runs it with the
// argument 600, and captures its /proc entry once the kernel names that path
// and those arguments.
func independentSleeper(t *testing.T, name string) independentChild {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := independentInstall(t, filepath.Join(directory, name))
	command := exec.Command(path, "600")
	if err := command.Start(); err != nil {
		t.Fatalf("wiring, not the property: start %s: %v", path, err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	c := independentChild{pid: int32(command.Process.Pid), path: path, args: command.Args}
	entry := filepath.Join(independentProcfs, strconv.Itoa(int(c.pid)))
	want := []byte(strings.Join(command.Args, "\x00") + "\x00")
	for range 200 {
		executable, _ := os.Readlink(filepath.Join(entry, "exe"))
		cmdline, _ := os.ReadFile(filepath.Join(entry, "cmdline"))
		if executable == path && bytes.Equal(cmdline, want) {
			c.cmdline = cmdline
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c.cmdline == nil {
		t.Fatalf("wiring, not the property: pid %d never read as %s running %q", c.pid, path, command.Args)
	}
	for file, into := range map[string]*[]byte{"stat": &c.stat, "status": &c.status, "cgroup": &c.cgroup} {
		content, err := os.ReadFile(filepath.Join(entry, file))
		if err != nil {
			t.Fatalf("wiring, not the property: capture %s/%s: %v", entry, file, err)
		}
		*into = content
	}
	stat := string(c.stat)
	fields := strings.Fields(stat[strings.LastIndexByte(stat, ')')+2:])
	if c.start, err = strconv.ParseUint(fields[19], 10, 64); err != nil {
		t.Fatalf("wiring, not the property: read the start time from %q: %v", stat, err)
	}
	return c
}

// independentConstruct writes c's entry under root with cmdline as given.
func independentConstruct(t *testing.T, root string, c independentChild, cmdline []byte) {
	t.Helper()
	entry := filepath.Join(root, strconv.Itoa(int(c.pid)))
	if err := os.MkdirAll(filepath.Join(entry, "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"stat": c.stat, "status": c.status, "cgroup": c.cgroup, "cmdline": cmdline} {
		if err := os.WriteFile(filepath.Join(entry, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(c.path, filepath.Join(entry, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(independentProcfs, strconv.Itoa(int(c.pid)), "ns", "pid"), filepath.Join(entry, "ns", "pid")); err != nil {
		t.Fatal(err)
	}
}

// independentReached reads root and returns the constructed undetermined
// process, failing as wiring where the reader did not reach it as built.
func independentReached(t *testing.T, root string, c independentChild) (process.Table, process.Process) {
	t.Helper()
	table, err := process.Read(root)
	if err != nil {
		t.Fatalf("wiring, not the property: the constructed root did not read: %v", err)
	}
	p, found := table.Lookup(c.pid)
	if !found || p.Executable != c.path || len(p.Arguments) != 0 || p.StartTime != c.start {
		t.Fatalf("wiring, not the property: the constructed pid %d read as found %v, executable %q, arguments %q, "+
			"start %d; want %s, no arguments and start %d", c.pid, found, p.Executable, p.Arguments, p.StartTime,
			c.path, c.start)
	}
	return table, p
}

func independentSelects(r process.Resolution, pid int32) bool {
	return slices.ContainsFunc(r.Selections, func(one admission.Selection) bool { return one.ObserverPID == pid })
}

// independentRefusesNaming requires err to carry an ArgumentsRefusal for c.
func independentRefusesNaming(t *testing.T, what string, err error, c independentChild) {
	t.Helper()
	var refusal process.ArgumentsRefusal
	switch {
	case err == nil:
		t.Errorf("%s did not refuse pid %d, whose arguments are undetermined", what, c.pid)
	case !errors.As(err, &refusal):
		t.Errorf("%s refused with %v, which names no process whose arguments are undetermined", what, err)
	case refusal.PID != c.pid || refusal.Executable != c.path:
		t.Errorf("%s refused pid %d (%s), want pid %d (%s)", what, refusal.PID, refusal.Executable, c.pid, c.path)
	}
}

func independentUndeterminedNames(r process.Resolution, c independentChild) bool {
	return slices.ContainsFunc(r.ArgumentsUndetermined, func(one process.ArgumentsRefusal) bool {
		return one.PID == c.pid && one.Executable == c.path
	})
}

// A reading with the executable readable and the command line empty is
// undetermined argument evidence, and one with the command line read is known.
func TestIndependentArgumentsAnEmptyCommandLineBesideAReadableExecutableIsUndetermined(t *testing.T) {
	target, control := independentSleeper(t, "undetermined"), independentSleeper(t, "known")
	root := t.TempDir()
	independentConstruct(t, root, target, nil)
	independentConstruct(t, root, control, control.cmdline)
	table, p := independentReached(t, root, target)
	known, found := table.Lookup(control.pid)
	if !found || !slices.Equal(known.Arguments, control.args) {
		t.Fatalf("wiring, not the property: the control pid %d read as found %v with arguments %q, want %q",
			control.pid, found, known.Arguments, control.args)
	}

	if p.ArgumentEvidence != process.ArgumentsUndetermined {
		t.Errorf("pid %d, executable readable and command line 0 bytes, reads with evidence %d, want "+
			"ArgumentsUndetermined (%d)", p.PID, p.ArgumentEvidence, process.ArgumentsUndetermined)
	}
	if known.ArgumentEvidence != process.ArgumentsKnown {
		t.Errorf("the control pid %d, command line read, has evidence %d, want ArgumentsKnown", known.PID, known.ArgumentEvidence)
	}
	identified, err := process.Identify(root, target.pid)
	if err != nil || identified.ArgumentEvidence != process.ArgumentsUndetermined {
		t.Errorf("Identify read pid %d with evidence %d (%v), want ArgumentsUndetermined", target.pid,
			identified.ArgumentEvidence, err)
	}
}

// An inclusion naming an executable and arguments is indeterminate on a
// process whose arguments are undetermined: never "no match", never a grant,
// and the resolution names the process.
func TestIndependentArgumentsAnInclusionOnUndeterminedArgumentsIsIndeterminateNeverNoMatch(t *testing.T) {
	target, control := independentSleeper(t, "undetermined"), independentSleeper(t, "known")
	root := t.TempDir()
	independentConstruct(t, root, target, nil)
	independentConstruct(t, root, control, control.cmdline)
	table, p := independentReached(t, root, target)
	known, _ := table.Lookup(control.pid)

	rule := process.Rule{Executable: target.path, Arguments: target.args[1:]}
	approval := process.Approval{Rules: []process.Rule{rule}}
	if got := (process.Rule{Executable: control.path, Arguments: control.args[1:]}).Decide(known); got != process.MatchFound {
		t.Fatalf("wiring, not the property: a rule naming the control's executable and arguments decides %d on it, "+
			"want MatchFound, so no decision below is evidence", got)
	}

	if got := rule.Decide(p); got != process.Indeterminate {
		t.Errorf("Rule.Decide on undetermined arguments = %d, want Indeterminate (%d)", got, process.Indeterminate)
	}
	if got := approval.Decide(p); got != process.Indeterminate {
		t.Errorf("Approval.Decide on undetermined arguments = %d, want Indeterminate", got)
	}
	if got := rule.Decide(known); got != process.NoMatch {
		t.Errorf("the rule on another executable decides %d, want NoMatch", got)
	}
	matches := approval.Matches(table)
	if len(matches) != 1 || slices.ContainsFunc(matches[0].Matched, func(m process.Process) bool { return m.PID == target.pid }) ||
		!slices.ContainsFunc(matches[0].Undetermined, func(m process.Process) bool { return m.PID == target.pid }) {
		t.Errorf("Matches reports %+v, want pid %d undetermined and not matched", matches, target.pid)
	}
	resolution := approval.Resolve(process.Host{Table: table})
	if independentSelects(resolution, target.pid) {
		t.Errorf("the resolution grants capture to pid %d on undetermined arguments", target.pid)
	}
	if !independentUndeterminedNames(resolution, target) {
		t.Errorf("the resolution does not name pid %d as undetermined: %+v", target.pid, resolution.ArgumentsUndetermined)
	}
	independentRefusesNaming(t, "Resolution.Err", resolution.Err(), target)
	independentRefusesNaming(t, "CheckArguments", approval.CheckArguments(table), target)
}

// An executable-only rule means no arguments after argv[0], so it consults
// the arguments too: on undetermined arguments it is indeterminate and grants
// nothing.
func TestIndependentArgumentsAnExecutableOnlyRuleOnUndeterminedArgumentsIsIndeterminate(t *testing.T) {
	target, control := independentSleeper(t, "undetermined"), independentSleeper(t, "known")
	root := t.TempDir()
	independentConstruct(t, root, target, nil)
	independentConstruct(t, root, control, control.cmdline)
	table, p := independentReached(t, root, target)
	known, _ := table.Lookup(control.pid)

	rule := process.Rule{Executable: target.path}
	approval := process.Approval{Rules: []process.Rule{rule}}
	if got := (process.Rule{Executable: control.path}).Decide(known); got != process.NoMatch {
		t.Fatalf("wiring, not the property: an executable-only rule on the control, which runs with an argument, "+
			"decides %d, want NoMatch", got)
	}

	if got := rule.Decide(p); got != process.Indeterminate {
		t.Errorf("an executable-only rule on undetermined arguments decides %d, want Indeterminate (%d)", got,
			process.Indeterminate)
	}
	resolution := approval.Resolve(process.Host{Table: table})
	if independentSelects(resolution, target.pid) {
		t.Errorf("an executable-only rule grants capture to pid %d on undetermined arguments", target.pid)
	}
	if !independentUndeterminedNames(resolution, target) {
		t.Errorf("the resolution does not name pid %d as undetermined: %+v", target.pid, resolution.ArgumentsUndetermined)
	}
	independentRefusesNaming(t, "Resolution.Err", resolution.Err(), target)
	independentRefusesNaming(t, "CheckArguments", approval.CheckArguments(table), target)
}

// An exclusion whose arguments cannot be decided grants nothing past it: a
// process an inclusion names is not captured while an exclusion may cover it.
func TestIndependentArgumentsAnUndeterminedExclusionGrantsNothing(t *testing.T) {
	target := independentSleeper(t, "undetermined")
	root := t.TempDir()
	independentConstruct(t, root, target, nil)
	table, _ := independentReached(t, root, target)
	// The boot is constructed: a pid rule's boot is compared with the host's
	// and nothing else reads it.
	const boot = "constructed-boot"
	host := process.Host{Table: table, Boot: boot}
	inclusion := process.Rule{PID: &process.PIDGuard{PID: target.pid, Start: target.start, Boot: boot}}

	if !independentSelects((process.Approval{Rules: []process.Rule{inclusion}}).Resolve(host), target.pid) {
		t.Fatalf("wiring, not the property: the pid rule does not select pid %d, so no exclusion below decides anything", target.pid)
	}
	elsewhere := process.Approval{Rules: []process.Rule{inclusion},
		Exclusions: []process.Rule{{Executable: "/nonexistent/other", Arguments: []string{"600"}}}}
	if r := elsewhere.Resolve(host); !independentSelects(r, target.pid) || len(r.ArgumentsUndetermined) != 0 || r.Err() != nil {
		t.Errorf("an exclusion naming another executable changed the outcome for pid %d: selected %v, undetermined %+v, "+
			"error %v", target.pid, independentSelects(r, target.pid), r.ArgumentsUndetermined, r.Err())
	}

	approval := process.Approval{Rules: []process.Rule{inclusion},
		Exclusions: []process.Rule{{Executable: target.path, Arguments: target.args[1:]}}}
	resolution := approval.Resolve(host)
	if independentSelects(resolution, target.pid) {
		t.Errorf("capture is granted to pid %d past an exclusion its undetermined arguments may match", target.pid)
	}
	if !independentUndeterminedNames(resolution, target) {
		t.Errorf("the resolution does not name pid %d as undetermined: %+v", target.pid, resolution.ArgumentsUndetermined)
	}
	independentRefusesNaming(t, "Resolution.Err", resolution.Err(), target)
	independentRefusesNaming(t, "CheckArguments", approval.CheckArguments(table), target)
}

// Arguments that stay unreadable are refused at the deadline, naming the
// process, within the bound; an approval that consults no arguments is not
// refused on them.
func TestIndependentArgumentsThatStayUnreadableAreRefusedAtTheDeadline(t *testing.T) {
	target := independentSleeper(t, "undetermined")
	root := t.TempDir()
	independentConstruct(t, root, target, nil)
	table, _ := independentReached(t, root, target)

	const boot = "constructed-boot"
	byPID := process.Approval{Rules: []process.Rule{{PID: &process.PIDGuard{PID: target.pid, Start: target.start, Boot: boot}}}}
	if _, err := byPID.SettleArguments(root, table); err != nil {
		t.Errorf("an approval naming no arguments was refused on them: %v", err)
	}

	approval := process.Approval{Rules: []process.Rule{{Executable: target.path, Arguments: target.args[1:]}}}
	began := time.Now()
	_, err := approval.SettleArguments(root, table)
	waited := time.Since(began)
	independentRefusesNaming(t, "SettleArguments", err, target)
	if waited > process.ArgumentReadBound+2*time.Second {
		t.Errorf("SettleArguments returned after %v, past its bound of %v", waited, process.ArgumentReadBound)
	}
}

// Arguments that become readable within the bound are reread, and the
// process is then decided on them.
func TestIndependentArgumentsAreRereadWithinTheBound(t *testing.T) {
	target := independentSleeper(t, "settling")
	root := t.TempDir()
	independentConstruct(t, root, target, nil)
	table, _ := independentReached(t, root, target)

	placed := make(chan error, 1)
	go func() {
		time.Sleep(10 * time.Millisecond)
		entry := filepath.Join(root, strconv.Itoa(int(target.pid)))
		staged := filepath.Join(entry, "cmdline.staged")
		if err := os.WriteFile(staged, target.cmdline, 0o644); err != nil {
			placed <- err
			return
		}
		placed <- os.Rename(staged, filepath.Join(entry, "cmdline"))
	}()
	rule := process.Rule{Executable: target.path, Arguments: target.args[1:]}
	approval := process.Approval{Rules: []process.Rule{rule}}
	settled, err := approval.SettleArguments(root, table)
	if placing := <-placed; placing != nil {
		t.Fatalf("wiring, not the property: the arguments were not placed: %v", placing)
	}
	if err != nil {
		t.Fatalf("arguments placed 10ms into a %v bound were refused: %v", process.ArgumentReadBound, err)
	}
	p, found := settled.Lookup(target.pid)
	if !found || p.ArgumentEvidence != process.ArgumentsKnown || !slices.Equal(p.Arguments, target.args) {
		t.Fatalf("after the reread pid %d is found %v with evidence %d and arguments %q, want known %q",
			target.pid, found, p.ArgumentEvidence, p.Arguments, target.args)
	}
	if got := rule.Decide(p); got != process.MatchFound {
		t.Errorf("the rule decides %d on the reread arguments, want MatchFound", got)
	}
	if !independentSelects(approval.Resolve(process.Host{Table: settled}), target.pid) {
		t.Errorf("pid %d is not selected after its arguments were reread", target.pid)
	}
}

// independentForceDescriptors holds n close-on-exec duplicates of /dev/null,
// numbered from 1000. A child closes each of them during exec, after its
// executable link names the new program and before argv is placed, so the
// window in which /proc/<pid>/cmdline reads 0 bytes widens from tens of
// microseconds to milliseconds. The exec'd program keeps none of them.
func independentForceDescriptors(t *testing.T, n int) {
	t.Helper()
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil || limit.Cur < uint64(n+2000) {
		t.Fatalf("wiring, not the property: the descriptor limit is %d (%v), and forcing the window needs %d",
			limit.Cur, err, n+2000)
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	duplicates := make([]int, 0, n)
	t.Cleanup(func() {
		for _, fd := range duplicates {
			_ = unix.Close(fd)
		}
		_ = null.Close()
	})
	for range n {
		fd, err := unix.FcntlInt(null.Fd(), unix.F_DUPFD_CLOEXEC, 1000)
		if err != nil {
			t.Fatalf("wiring, not the property: duplicate descriptor %d of %d: %v", len(duplicates)+1, n, err)
		}
		duplicates = append(duplicates, fd)
	}
}

// A process caught between exec and argv placement is decided on reread
// arguments or refused at the deadline. Scheduling can exhaust the bound for
// any start. Of 20 starts, at least one caught window must settle successfully:
// this is the minimum evidence of a working reread, not a success-rate claim.
// The window is forced with 200000 close-on-exec descriptors; no caught window
// is a wiring failure, distinct from catching windows but never settling one.
func TestIndependentArgumentsTheForcedExecWindowIsRereadAndDecided(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := independentInstall(t, filepath.Join(directory, "forced"))
	rule := process.Rule{Executable: path, Arguments: []string{"600"}}
	approval := process.Approval{Rules: []process.Rule{rule}}
	independentForceDescriptors(t, 200000)

	const starts = 20
	window, reread, refused := 0, 0, 0
	for i := range starts {
		command := exec.Command(path, "600")
		if err := command.Start(); err != nil {
			t.Fatalf("wiring, not the property: start %s: %v", path, err)
		}
		pid := int32(command.Process.Pid)
		first, err := process.Identify(independentProcfs, pid)
		caught := err == nil && first.Executable == path && len(first.Arguments) == 0
		if caught {
			window++
			if first.ArgumentEvidence != process.ArgumentsUndetermined {
				t.Errorf("start %d: empty arguments have evidence %d, want ArgumentsUndetermined", i, first.ArgumentEvidence)
			}
			if got := rule.Decide(first); got != process.Indeterminate {
				t.Errorf("start %d: argument rule decides %d on empty arguments, want Indeterminate", i, got)
			}
			empty := process.Rule{Executable: path}
			if got := empty.Decide(first); got != process.Indeterminate {
				t.Errorf("start %d: executable-only rule decides %d on empty arguments, want Indeterminate", i, got)
			}
			byPID := process.Rule{PID: &process.PIDGuard{PID: pid, Start: first.StartTime}}
			excluding := process.Approval{Rules: []process.Rule{byPID}, Exclusions: []process.Rule{empty}}
			if got := excluding.Decide(first); got != process.Indeterminate {
				t.Errorf("start %d: exclusion decides %d on empty arguments, want Indeterminate", i, got)
			}
		}
		began := time.Now()
		settled, settling := approval.SettleArguments(independentProcfs, process.TableOf(first))
		waited := time.Since(began)
		p, found := settled.Lookup(pid)
		decided := rule.Decide(p)
		_ = command.Process.Kill()
		_ = command.Wait()
		if err != nil {
			t.Fatalf("wiring, not the property: start %d: the first reading of pid %d failed: %v", i, pid, err)
		}
		if !found || p.Executable != path || p.StartTime != first.StartTime {
			t.Errorf("start %d: pid %d lost its identity on settling: found %v, executable %q, start %d; want %s, start %d",
				i, pid, found, p.Executable, p.StartTime, path, first.StartTime)
			continue
		}
		if settling != nil {
			var refusal process.ArgumentsRefusal
			if !errors.As(settling, &refusal) || refusal.PID != pid || refusal.Executable != path ||
				refusal.Detail != "the command line could not be established" || waited < process.ArgumentReadBound ||
				p.ArgumentEvidence != process.ArgumentsUndetermined || decided != process.Indeterminate {
				t.Errorf("start %d: pid %d refused after %v with evidence %d, decision %d, error %v; "+
					"want undetermined arguments refused at the deadline", i, pid, waited, p.ArgumentEvidence, decided, settling)
			} else {
				refused++
			}
			continue
		}
		if p.ArgumentEvidence != process.ArgumentsKnown || !slices.Equal(p.Arguments, command.Args) || decided != process.MatchFound {
			t.Errorf("start %d: pid %d first read with arguments %q settled to found %v, arguments %q, decision %d, "+
				"evidence %d; want known arguments %q and MatchFound", i, pid, first.Arguments, found, p.Arguments,
				decided, p.ArgumentEvidence, command.Args)
		} else if caught {
			reread++
		}
	}
	t.Logf("forced window: %d of %d first readings saw the executable readable and the command line 0 bytes", window, starts)
	t.Logf("settled after a forced window: %d; refused at the deadline: %d", reread, refused)
	if window == 0 {
		t.Fatalf("wiring, not the property: no first reading of %d saw the forced window, so no reread was measured", starts)
	}
	if reread == 0 {
		t.Errorf("none of %d forced windows settled to known arguments; want at least one successful reread", window)
	}
}
