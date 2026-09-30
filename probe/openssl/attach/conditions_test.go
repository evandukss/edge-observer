//go:build attach

package attach_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/processing"
)

// compiled is a fixture program built from testdata against the system's
// OpenSSL, calling SSL_read and SSL_write. The fixtures are C because Python's
// ssl module uses SSL_read_ex and SSL_write_ex, and a Python process has been
// seen making no observed exchange though the catalogue probes both; until
// that is explained, such a fixture measures nothing here.
func compiled(t *testing.T, source string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), strings.TrimSuffix(filepath.Base(source), ".c"))
	if out, err := exec.Command("cc", "-Wall", "-Werror", "-O0", "-o", binary, source,
		"-lssl", "-lcrypto").CombinedOutput(); err != nil {
		t.Fatalf("compile %s: %v\n%s", source, err, out)
	}
	return binary
}

// graph is the root of a constructed process graph (testdata/graph.c).
type graph struct {
	root    process.Process
	send    io.WriteCloser
	lines   *bufio.Scanner
	witness string
}

// rooted starts a graph's root against port. Stopping it writes the stop file
// first, so every process it created ends by itself rather than by a signal to
// a pid that may name somebody else by then.
func rooted(t *testing.T, port int, role, witness string) graph {
	t.Helper()
	command := exec.Command(compiled(t, "testdata/graph.c"), strconv.Itoa(port), role, witness)
	send, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start the graph's root: %v", err)
	}
	t.Cleanup(func() {
		stopGraph(witness)
		_ = send.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	lines := bufio.NewScanner(out)
	if !lines.Scan() || !strings.HasPrefix(lines.Text(), "ready ") {
		t.Fatalf("the graph's root did not come up: %q %v", lines.Text(), lines.Err())
	}
	return graph{root: loaded(t, int32(command.Process.Pid)), send: send, lines: lines, witness: witness}
}

func (g graph) say(t *testing.T, command string) string {
	t.Helper()
	if _, err := io.WriteString(g.send, command+"\n"); err != nil {
		t.Fatalf("tell the root %q: %v", command, err)
	}
	if !g.lines.Scan() {
		t.Fatalf("the root did not answer %q: %v", command, g.lines.Err())
	}
	return g.lines.Text()
}

// exchange has the root make one TLS exchange of its own.
func (g graph) exchange(t *testing.T) {
	t.Helper()
	if answer := g.say(t, "exchange"); answer != "done" {
		t.Fatalf("the root answered %q to an exchange", answer)
	}
}

// child has the root fork, or spawn by exec, a process exchanging on a loop.
func (g graph) child(t *testing.T, how, role string) process.Process {
	t.Helper()
	answer := g.say(t, how+" "+role)
	name, number, found := strings.Cut(answer, " ")
	pid, err := strconv.Atoi(number)
	if !found || name != role || err != nil {
		t.Fatalf("the root answered %q to %s %s", answer, how, role)
	}
	return loaded(t, int32(pid))
}

// looping starts a process outside any graph, exchanging on a loop or, in flood
// mode, without pausing. The command is returned so a test can end it.
func looping(t *testing.T, port int, role, witness, mode string) (*exec.Cmd, process.Process) {
	t.Helper()
	command := exec.Command(compiled(t, "testdata/graph.c"), strconv.Itoa(port), role, witness, mode)
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start %s: %v", role, err)
	}
	t.Cleanup(func() {
		stopGraph(witness)
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	return command, loaded(t, int32(command.Process.Pid))
}

func stopGraph(witness string) { _ = os.WriteFile(filepath.Join(witness, "stop"), nil, 0o600) }

// witnessed is how many exchanges pid completed as role, by its own record.
func witnessed(witness, role string, pid int32) int {
	content, err := os.ReadFile(filepath.Join(witness, fmt.Sprintf("%s-%d", role, pid)))
	if err != nil {
		return 0
	}
	return strings.Count(string(content), "200\n")
}

// waitWitnessed waits until every role has completed more exchanges, by its own
// record, than it had at before, so a process reported unobserved transmitted.
func waitWitnessed(t *testing.T, witness string, roles map[string]int32, before map[string]int, more int) {
	t.Helper()
	for range 500 {
		short := ""
		for role, pid := range roles {
			if witnessed(witness, role, pid) < before[role]+more {
				short = role
				break
			}
		}
		if short == "" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("wiring, not the property: not every process completed %d exchanges of its own, so an absence "+
		"below would measure an idle process rather than an unobserved one", more)
}

func thisBoot(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(procfs, "sys", "kernel", "random", "boot_id"))
	if err != nil {
		t.Fatalf("read this boot's id: %v", err)
	}
	return strings.TrimSpace(string(content))
}

// exactly is a target naming one instance: its pid, its start and this boot.
func exactly(name string, p process.Process, boot, mode string) map[string]any {
	return map[string]any{"name": name, "pid": map[string]any{"pid": p.PID, "start": p.StartTime, "boot": boot},
		"descendants": mode}
}

// observedBy counts what the session APPROVED, per holding process. It reads
// the approved artifact rather than the raw spool, which the observer stopped
// writing when capture moved to a volatile intake.
//
// The counts are not comparable with the spool's: that held one record per
// fragment and this holds one per approved route. Every caller asks only
// whether a process appears at all, so the magnitude is reported in failure
// text and asserted nowhere - keep it that way, because the two numbers answer
// different questions.
func observedBy(t *testing.T, directory string) map[int32]int {
	t.Helper()
	counts := make(map[int32]int)
	file, err := os.Open(filepath.Join(directory, processing.ArtifactName))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return counts
		}
		t.Fatalf("read the approved output: %v", err)
	}
	defer func() { _ = file.Close() }()
	lines := bufio.NewScanner(file)
	lines.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for lines.Scan() {
		var artifact processing.Artifact
		if err := json.Unmarshal(lines.Bytes(), &artifact); err != nil {
			// A line still being written.
			continue
		}
		counts[artifact.Connection.Process.PID]++
	}
	// Which KIND of empty this is. A caller that finds its pid absent cannot
	// otherwise tell "the artifact carries entries, none of them this one" -
	// its own question, answered no - from "the artifact carries nothing at
	// all", which is a different failure and not about the pid it asked for.
	pids := make([]int32, 0, len(counts))
	for pid := range counts {
		pids = append(pids, pid)
	}
	slices.Sort(pids)
	t.Logf("approved output holds %d entries across pids %v", len(pids), pids)
	return counts
}

func previewed(t *testing.T, binary string, c configured) account.Account {
	t.Helper()
	answer, err := exec.Command(binary, "dry-run", c.path).Output()
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	var planned account.Account
	if err := json.Unmarshal(answer, &planned); err != nil {
		t.Fatalf("decode the dry run: %v\n%s", err, answer)
	}
	return planned
}

func named(a account.Account, name string) account.Target {
	for _, one := range a.Targets {
		if one.Name == name {
			return one
		}
	}
	return account.Target{}
}

func pidsIn(instances []account.Instance) []int32 {
	pids := make([]int32, 0, len(instances))
	for _, one := range instances {
		pids = append(pids, one.PID)
	}
	return pids
}

// The three modes on one constructed graph. A target names only A, by its exact
// instance. B is forked before activation, C after, and all three record their
// own exchanges; U, outside the graph, transmits throughout. The expected set
// comes from the graph as declared, each role matched by its reported pid.
func TestTheThreeModesAnswerForOneGraphOfIndependentlyWitnessedProcesses(t *testing.T) {
	binary := built(t)
	port := serving(t)
	boot := thisBoot(t)
	for _, one := range []struct {
		mode string
		want map[string]bool
	}{
		{"none", map[string]bool{"A": true, "B": false, "C": false}},
		{"existing", map[string]bool{"A": true, "B": true, "C": false}},
		{"follow", map[string]bool{"A": true, "B": true, "C": true}},
	} {
		t.Run(one.mode, func(t *testing.T) {
			witness := t.TempDir()
			a := rooted(t, port, "A", witness)
			pids := map[string]int32{"A": a.root.PID, "B": a.child(t, "fork", "B").PID}
			_, control := looping(t, port, "U", witness, "loop")
			pids["U"] = control.PID

			c := configuring(t, exactly("graph", a.root, boot, one.mode))
			observer := started(t, binary, c)
			pids["C"] = a.child(t, "fork", "C").PID

			before := make(map[string]int, len(pids))
			for role, pid := range pids {
				before[role] = witnessed(witness, role, pid)
			}
			for range 3 {
				a.exchange(t)
			}
			waitWitnessed(t, witness, pids, before, 3)
			ended(t, observer, c)

			by := observedBy(t, observer.directory(c))
			for role, want := range one.want {
				if got := by[pids[role]] > 0; got != want {
					t.Errorf("under %s, %s (pid %d) observed %v with %d records, want %v", one.mode, role,
						pids[role], got, by[pids[role]], want)
				}
			}
			if by[pids["U"]] > 0 {
				t.Errorf("the control U outside the graph was observed: %d records", by[pids["U"]])
			}
		})
	}
}

// All four conditions on one target select the one process meeting every one,
// while a control meeting two (same executable and cgroup, other arguments and
// port) transmits beside it. The servers are testdata/forking_server.c in
// single mode, so the listener's process makes the TLS calls. openssl s_server
// is not used: its -www mode goes through an SSL BIO, calling inside the
// library rather than through the exported entry points.
func TestAllFourConditionsOnOneTargetSelectOnlyTheProcessMeetingEveryOne(t *testing.T) {
	binary := built(t)
	group := cgroupFor(t, fmt.Sprintf("attach-four-%d", os.Getpid()))
	server, port := forkingServer(t, "single")
	control, controlPort := forkingServer(t, "single")
	moveInto(t, group, server.PID)
	moveInto(t, group, control.PID)

	c := configuring(t, map[string]any{"name": "server", "exe": server.Executable, "args": server.Arguments[1:],
		"cgroup": unifiedCgroup(t, server.PID), "port": port, "descendants": "none"})
	observer := started(t, binary, c)
	// Selection first, then capture: never selected and selected but unseen are
	// different failures.
	if roots := pidsIn(named(inspected(t, binary, c), "server").Roots); !slices.Equal(roots, []int32{server.PID}) {
		t.Fatalf("the four conditions selected %v, want only the server %d", roots, server.PID)
	}
	witness := t.TempDir()
	_, toServer := looping(t, port, "T", witness, "loop")
	_, toControl := looping(t, controlPort, "K", witness, "loop")
	waitWitnessed(t, witness, map[string]int32{"T": toServer.PID, "K": toControl.PID}, nil, 3)
	ended(t, observer, c)

	by := observedBy(t, observer.directory(c))
	if by[server.PID] == 0 {
		t.Errorf("the process meeting all four conditions was not observed")
	}
	if by[control.PID] > 0 {
		t.Errorf("the control meeting two of the four was observed: %d records", by[control.PID])
	}
}

// An excluded process, a descendant of it whose argument list matches an
// include, and a control outside the subtree matching another. Only the
// control produces records, so observing nothing does not pass. The descendant
// is spawned by exec, so only the subtree denial covers it.
func TestAnExcludedProcessAndItsDescendantProduceNothingWhileAControlOutsideItDoes(t *testing.T) {
	binary := built(t)
	port := serving(t)
	witness := t.TempDir()
	excluded := rooted(t, port, "E", witness)
	descendant := excluded.child(t, "spawn", "D")
	_, control := looping(t, port, "S", witness, "loop")

	targets := []map[string]any{
		{"name": "descendant", "exe": descendant.Executable, "args": descendant.Arguments[1:], "descendants": "none"},
		{"name": "control", "exe": control.Executable, "args": control.Arguments[1:], "descendants": "none"},
	}
	c := configuring(t, targets...)
	c.rewrite(t, targets, []map[string]any{{"exe": excluded.root.Executable, "args": excluded.root.Arguments[1:]}})
	observer := started(t, binary, c)

	pids := map[string]int32{"E": excluded.root.PID, "D": descendant.PID, "S": control.PID}
	before := map[string]int{"E": witnessed(witness, "E", excluded.root.PID), "D": witnessed(witness, "D", descendant.PID),
		"S": witnessed(witness, "S", control.PID)}
	for range 3 {
		excluded.exchange(t)
	}
	waitWitnessed(t, witness, pids, before, 3)
	live := inspected(t, binary, c)
	ended(t, observer, c)

	by := observedBy(t, observer.directory(c))
	if by[control.PID] == 0 {
		t.Fatalf("the control outside the subtree was not observed, so nothing below is evidence of a denial")
	}
	for role, pid := range map[string]int32{"the excluded process": excluded.root.PID, "its descendant": descendant.PID} {
		if by[pid] > 0 {
			t.Errorf("%s (pid %d) produced %d records", role, pid, by[pid])
		}
	}
	if !slices.Contains(pidsIn(named(live, "descendant").Denied), descendant.PID) {
		t.Errorf("the account does not name pid %d as denied under its target: %+v", descendant.PID,
			named(live, "descendant"))
	}
}

// cgroupFor makes a cgroup under this container's hierarchy. Its removal is
// registered before anything moves in and moves out whatever remains, so
// nothing is left on the host whatever order the clean-ups run in.
//
// AT THE MOUNT ROOT, and a bounded cgroup cannot go anywhere else. The gate
// runner empties the root into gate-runner and enables the controllers THERE,
// on the root, because a cgroup holding processes may enable none in its own
// subtree - and gate-runner is where every process in this container then
// lives. So gate-runner can never carry controllers, nothing created beneath
// it has a memory.max to write, and a cgroup that needs a limit is a sibling
// of gate-runner rather than a child of it. Measured: creating the observer's
// envelope under gate-runner fails with permission denied on memory.max,
// which reads as a privilege problem and is the no-internal-process rule.
func cgroupFor(t *testing.T, name string) string {
	t.Helper()
	directory := filepath.Join(ebpf.DefaultCgroupMount, name)
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatalf("make cgroup %s: %v", directory, err)
	}
	t.Cleanup(func() {
		content, _ := os.ReadFile(filepath.Join(directory, "cgroup.procs"))
		home := ownCgroup(t)
		for _, pid := range strings.Fields(string(content)) {
			_ = os.WriteFile(filepath.Join(home, "cgroup.procs"), []byte(pid), 0o644)
		}
		_ = os.Remove(directory)
	})
	return directory
}

// ownCgroup is the cgroup this test process is in, which is where a process is
// returned to when the group holding it goes away.
//
// NOT the mount root. A cgroup with a controller enabled in its subtree_control
// may hold no processes of its own, so writing a pid to the root fails with
// "device or resource busy" the moment anything beneath it is capped - which is
// every run of this suite, because the observer needs a bounded envelope. The
// root accepts processes only while nothing is bounded, so a helper that
// returns them there models a system in which the resource controls are off.
func ownCgroup(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatalf("read this process's own cgroup: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join(ebpf.DefaultCgroupMount, path)
		}
	}
	t.Fatalf("no unified cgroup line in /proc/self/cgroup:\n%s", content)
	return ""
}

func moveInto(t *testing.T, directory string, pid int32) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, "cgroup.procs"), []byte(strconv.Itoa(int(pid))), 0o644); err != nil {
		t.Fatalf("move pid %d into %s: %v", pid, directory, err)
	}
}

// A cgroup target is a snapshot of the instances in one object. After
// activation a member leaves, an unrelated process enters, and a nested group
// appears with a process in it; the two members resolved at activation stay
// observed and the other two are not. Then the path is removed and made again,
// and it resolves to a different object holding only what is in it now. The
// observer stops only once each process has completed three exchanges after the
// churn, so one reported unobserved transmitted.
func TestACgroupTargetIsASnapshotAndTheObjectItResolvedToDecides(t *testing.T) {
	binary := built(t)
	port := serving(t)
	witness := t.TempDir()
	name := fmt.Sprintf("attach-churn-%d", os.Getpid())
	group := cgroupFor(t, name)
	_, leaver := looping(t, port, "leaver", witness, "loop")
	_, stayer := looping(t, port, "stayer", witness, "loop")
	moveInto(t, group, leaver.PID)
	moveInto(t, group, stayer.PID)

	c := configuring(t, map[string]any{"name": "service", "cgroup": "/" + name, "descendants": "none"})
	observer := started(t, binary, c)
	first := named(inspected(t, binary, c), "service")
	if roots := pidsIn(first.Roots); !slices.Contains(roots, leaver.PID) || !slices.Contains(roots, stayer.PID) {
		t.Fatalf("wiring, not the property: the target resolved to %v, want both members", roots)
	}
	if first.Cgroup == nil || first.Cgroup.Inode == 0 {
		t.Fatalf("the account records no object for the cgroup it resolved: %+v", first.Cgroup)
	}

	// Out of the target and into the cgroup this test is in, NOT the mount root:
	// the root holds no processes once anything beneath it is bounded, which is
	// every run of this suite. See ownCgroup.
	moveInto(t, ownCgroup(t), leaver.PID)
	_, entrant := looping(t, port, "entrant", witness, "loop")
	moveInto(t, group, entrant.PID)
	nested := cgroupFor(t, name+"/inner")
	_, nester := looping(t, port, "nester", witness, "loop")
	moveInto(t, nested, nester.PID)
	roles := map[string]int32{"leaver": leaver.PID, "stayer": stayer.PID, "entrant": entrant.PID, "nester": nester.PID}
	before := make(map[string]int, len(roles))
	for role, pid := range roles {
		before[role] = witnessed(witness, role, pid)
	}
	waitWitnessed(t, witness, roles, before, 3)
	ended(t, observer, c)

	by := observedBy(t, observer.directory(c))
	for role, one := range map[string]struct {
		pid  int32
		want bool
	}{
		"the member that left":                     {leaver.PID, true},
		"the member that stayed":                   {stayer.PID, true},
		"the process that entered after":           {entrant.PID, false},
		"the process in a nested group made after": {nester.PID, false},
	} {
		if got := by[one.pid] > 0; got != one.want {
			t.Errorf("%s (pid %d) observed %v with %d records, want %v", role, one.pid, got, by[one.pid], one.want)
		}
	}

	// The path made again: everything moved out, the object removed, a new one made
	// under the same path, a newcomer put in it.
	for _, pid := range []int32{stayer.PID, entrant.PID, nester.PID} {
		moveInto(t, ownCgroup(t), pid)
	}
	if err := os.Remove(nested); err != nil {
		t.Fatalf("remove %s: %v", nested, err)
	}
	if err := os.Remove(group); err != nil {
		t.Fatalf("remove %s: %v", group, err)
	}
	if err := os.Mkdir(group, 0o755); err != nil {
		t.Fatalf("make %s again: %v", group, err)
	}
	_, newcomer := looping(t, port, "newcomer", witness, "loop")
	moveInto(t, group, newcomer.PID)

	again := named(previewed(t, binary, c), "service")
	if again.Cgroup == nil || again.Cgroup.Inode == first.Cgroup.Inode {
		t.Errorf("the path made again resolves to object %+v, the same as the one removed (%d)", again.Cgroup,
			first.Cgroup.Inode)
	}
	if roots := pidsIn(again.Roots); !slices.Equal(roots, []int32{newcomer.PID}) {
		t.Errorf("the new object resolves to %v, want only what is in it now, pid %d", roots, newcomer.PID)
	}
}

// A dry run is not a promise. Between it and the start a child is born under a
// follow target and a process named by its exact instance ends. The start
// reconciles afresh: the child is there, and the ended instance is refused with
// its reason. A replaced instance is the resolver's own case
// (TestAPIDTargetSelectsOnlyTheInstanceItWasWrittenFor).
func TestADryRunIsNotAPromiseAndTheStartReconcilesAfresh(t *testing.T) {
	binary := built(t)
	port := serving(t)
	boot := thisBoot(t)
	witness := t.TempDir()
	root := rooted(t, port, "A", witness)
	born := root.child(t, "fork", "B")
	leaving, left := looping(t, port, "X", witness, "loop")

	c := configuring(t, exactly("graph", root.root, boot, "follow"), exactly("leaving", left, boot, "none"))
	preview := previewed(t, binary, c)
	if !slices.Contains(pidsIn(named(preview, "graph").Descendants), born.PID) ||
		!slices.Contains(pidsIn(named(preview, "leaving").Roots), left.PID) {
		t.Fatalf("wiring, not the property: the dry run did not preview the graph's child %d and the instance %d: %+v",
			born.PID, left.PID, preview.Targets)
	}

	late := root.child(t, "fork", "C")
	_ = leaving.Process.Kill()
	_ = leaving.Wait()

	observer := started(t, binary, c)
	live := inspected(t, binary, c)
	ended(t, observer, c)

	if slices.Contains(pidsIn(named(preview, "graph").Descendants), late.PID) {
		t.Fatalf("wiring, not the property: the dry run already named pid %d, so there is no delta to reconcile", late.PID)
	}
	if !slices.Contains(pidsIn(named(live, "graph").Descendants), late.PID) {
		t.Errorf("the child born after the dry run, pid %d, is not among the graph's descendants at the start: %v",
			late.PID, pidsIn(named(live, "graph").Descendants))
	}
	gone := named(live, "leaving")
	if len(gone.Roots) != 0 || !strings.Contains(gone.Unresolved, strconv.Itoa(int(left.PID))) {
		t.Errorf("the instance that ended after the dry run is reported %+v, want it refused with its reason", gone)
	}
}

// forkingServer starts testdata/forking_server.c, with its mode if given, and
// returns it and its port once ready.
func forkingServer(t *testing.T, mode ...string) (process.Process, int) {
	t.Helper()
	certificate, key := certificate(t)
	port := free(t)
	command := exec.Command(compiled(t, "testdata/forking_server.c"),
		append([]string{strconv.Itoa(port), certificate, key}, mode...)...)
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start the forking server: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || !strings.HasPrefix(line, "ready") {
		t.Fatalf("the forking server did not come up: %q %v", line, err)
	}
	return loaded(t, int32(command.Process.Pid)), port
}
