//go:build attach

package attach_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/privilege"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/processing"
)

// built is the observer compiled as it ships: without cgo, which lets it give
// up its capabilities on every thread.
func built(t *testing.T) string {
	t.Helper()

	binary := filepath.Join(t.TempDir(), "observer")
	command := exec.Command("go", "build", "-o", binary,
		"github.com/evandukss/edge-observer/cmd/observer")
	command.Env = append(os.Environ(), "CGO_ENABLED=0")

	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build the observer: %v\n%s", err, output)
	}
	return binary
}

// configured is one configuration file and where it points the observer.
type configured struct {
	path      string
	directory string
	log       string
}

func (c configured) sessions() string { return filepath.Join(c.directory, "sessions") }
func (c configured) pidFile() string  { return filepath.Join(c.directory, "observer.pid") }

// target is a configuration entry naming one process by what it reports now,
// following what it forks. An empty argument list is written out: an
// executable with none named means a process run with none.
func target(name string, p process.Process) map[string]any {
	arguments := []string{}
	if len(p.Arguments) > 1 {
		arguments = p.Arguments[1:]
	}
	return map[string]any{"name": name, "exe": p.Executable, "args": arguments, "descendants": "follow"}
}

// configuring writes a configuration holding these targets. The state is
// restated every second, so a case waiting on a state record waits seconds.
func configuring(t *testing.T, targets ...map[string]any) configured {
	t.Helper()
	root := t.TempDir()
	c := configured{
		path:      filepath.Join(root, "observer.json"),
		directory: filepath.Join(root, "state"),
		log:       filepath.Join(root, "state", "observer.log"),
	}
	c.rewrite(t, targets, nil)
	return c
}

// rewrite writes the configuration again with these targets and exclusions and
// the same output, log and limits, as an operator would before a reload. Each
// target becomes a watch entry (contract/config): its conditions as written
// and the mode word as the children answer that mode is.
func (c configured) rewrite(t *testing.T, targets, exclusions []map[string]any) {
	t.Helper()
	children := map[string]string{"none": config.ChildrenNone, "existing": config.ChildrenExisting,
		"follow": config.ChildrenAll}
	written := []any{}
	for _, one := range targets {
		entry := map[string]any{}
		for key, value := range one {
			if key != "descendants" {
				entry[key] = value
			}
		}
		word, _ := one["descendants"].(string)
		answer, known := children[word]
		if !known {
			t.Fatalf("wiring, not the observer: target %v names descendant mode %q", one["name"], word)
		}
		entry["children"] = answer
		written = append(written, entry)
	}
	excluded := []any{}
	for _, one := range exclusions {
		excluded = append(excluded, one)
	}
	document := map[string]any{
		"version":   config.FileVersion,
		"output":    c.directory,
		"log":       c.log,
		"limits":    map[string]any{"state_every_seconds": 1},
		"watch":     written,
		"ignore":    excluded,
		"libraries": []any{},
	}
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode the configuration: %v", err)
	}
	if err := os.WriteFile(c.path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", c.path, err)
	}
}

// reloaded asks the running session to reload and returns its answer.
func reloaded(t *testing.T, binary string, c configured) (reloadAnswer, error) {
	t.Helper()
	command := exec.Command(binary, "reload", c.path)
	output, err := command.Output()
	var answer reloadAnswer
	if decodeErr := json.Unmarshal(bytes.TrimSpace(output), &answer); decodeErr != nil {
		t.Fatalf("the reload answered something that is not a record: %v\n%s", decodeErr, output)
	}
	t.Logf("reload answered: %s", bytes.TrimSpace(output))
	return answer, err
}

type reloadAnswer struct {
	Outcome    string   `json:"outcome"`
	Generation int      `json:"generation"`
	Reason     string   `json:"reason"`
	Added      []string `json:"added"`
	Skipped    []string `json:"skipped"`
}

// inspected is the running session's live account.
func inspected(t *testing.T, binary string, c configured) account.Account {
	t.Helper()
	answer, err := exec.Command(binary, "inspect", c.path).Output()
	if err != nil {
		t.Fatalf("inspect the running session: %v", err)
	}
	var live account.Account
	if err := json.Unmarshal(answer, &live); err != nil {
		t.Fatalf("decode the live account: %v\n%s", err, answer)
	}
	return live
}

func observes(a account.Account, pid int32) bool {
	return slices.ContainsFunc(a.Processes, func(one attachment.Observed) bool { return one.PID == pid })
}

// logRecord is one line of the observer's log, as far as these cases read it.
type logRecord struct {
	Record   string `json:"record"`
	Version  int    `json:"version"`
	Session  string `json:"session"`
	Error    string `json:"error"`
	Coverage []struct {
		Name     string `json:"name"`
		Selected int    `json:"selected"`
		Attached int    `json:"attached"`
		Covered  *int   `json:"covered"`
	} `json:"coverage"`
	Changes []string `json:"changes"`
}

func recordOf(line []byte) (logRecord, bool) {
	var record logRecord
	if err := json.Unmarshal(line, &record); err != nil || record.Record == "" {
		return logRecord{}, false
	}
	return record, true
}

func (r logRecord) covered(name string) (int, bool) {
	for _, one := range r.Coverage {
		if one.Name == name && one.Covered != nil {
			return *one.Covered, true
		}
	}
	return 0, false
}

// runningWith is every process whose command line names this configuration.
func runningWith(t *testing.T, path string) []int32 {
	t.Helper()
	table, err := process.Read(procfs)
	if err != nil {
		t.Fatalf("read the process table: %v", err)
	}
	var found []int32
	for _, p := range table.All() {
		if slices.Contains(p.Arguments, path) {
			found = append(found, p.PID)
		}
	}
	return found
}

// A detached start that cannot activate exits non-zero with the reason and
// leaves no detached process behind.
func TestADetachedStartThatCannotActivateExitsNonZeroAndLeavesNoProcessBehind(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "not-running")
	c := configuring(t, map[string]any{"name": "not-running", "exe": absent, "descendants": "none"})

	command := exec.Command(built(t), "start", c.path, "--daemonize")
	intoEnvelope(t, command)
	output, err := command.CombinedOutput()
	if err == nil || command.ProcessState.ExitCode() == 0 {
		t.Fatalf("a detached start over a configuration that selects nothing exited zero:\n%s", output)
	}
	if !strings.Contains(string(output), "not-running") {
		t.Errorf("the parent does not carry the child's reason, which names the target:\n%s", output)
	}
	if left := runningWith(t, c.path); len(left) != 0 {
		t.Errorf("a detached start that failed left %v running", left)
	}
	if entries, err := os.ReadDir(c.sessions()); err == nil && len(entries) != 0 {
		t.Errorf("a detached start that failed left %d session directories", len(entries))
	}
}

// running is one observer in the foreground and the session it activated.
type running struct {
	command *exec.Cmd
	session string
	lines   *bufio.Scanner
	header  []string
}

func (r running) directory(c configured) string { return filepath.Join(c.sessions(), r.session) }

// started runs the observer and returns it once its log (mirrored on standard
// output in the foreground) carries its activation record, written after the
// probes are placed and the capabilities are gone.
// envelopeFor makes the bounded cgroup the observer is created into: a finite
// memory cap and swap denied, which is what activation reads back. The name is
// the test's, so a leftover directory names the test that left it.
//
// THIS IS SETUP AND IT IS EVIDENCE FOR NOTHING. Every test here stands up a
// bounded envelope because the observer refuses to activate without one, so a
// reader counting capped cgroups across this suite is counting a precondition
// rather than a result. A resource control is TESTED by a cap that is reached
// or a denial that refuses, deliberately, in a case written to do it - never by
// one that exists under every case because nothing runs otherwise.
func envelopeFor(t *testing.T) string {
	t.Helper()
	name := "observer-" + strings.NewReplacer("/", "-", " ", "-").Replace(t.Name())
	directory := cgroupFor(t, name)
	for setting, value := range map[string]string{"memory.max": "1073741824", "memory.swap.max": "0"} {
		if err := os.WriteFile(filepath.Join(directory, setting), []byte(value), 0o644); err != nil {
			t.Fatalf("set %s on the observer's envelope: %v. The gate runner enables the memory "+
				"controller before this suite; without that preparation this file does not exist "+
				"and the error is a permission one", setting, err)
		}
	}
	return directory
}

// intoEnvelope makes cmd start inside a bounded no-swap cgroup, which is what
// activation verifies before it will attach. Every route that launches the
// observer goes through here, DETACHED ONES INCLUDED: a detached start's child
// is the payload holder and it inherits the cgroup its parent was created
// into, so putting the parent in the envelope puts the holder there with no
// window in which the holder exists outside it.
func intoEnvelope(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	envelope := envelopeFor(t)
	held, err := os.Open(envelope)
	if err != nil {
		t.Fatalf("open the observer's envelope %s: %v", envelope, err)
	}
	t.Cleanup(func() { _ = held.Close() })
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(held.Fd())}
}

func started(t *testing.T, binary string, c configured) running {
	t.Helper()

	command := exec.Command(binary, "start", c.path)
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	command.Stderr = os.Stderr
	// The observer is CREATED into its envelope rather than moved there after
	// exec. A process created into a cgroup has no window in which it exists
	// and has not yet entered; a moved one does, and no reading afterwards can
	// say what it allocated during it. This is the launch precondition an
	// operator satisfies on a host, and the suite has to satisfy it too.
	intoEnvelope(t, command)
	if err := command.Start(); err != nil {
		t.Fatalf("start the observer: %v", err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	lines := bufio.NewScanner(out)
	lines.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var header []string
	for lines.Scan() {
		header = append(header, lines.Text())
		if record, ok := recordOf(lines.Bytes()); ok && record.Record == "activation-completed" && record.Version == 1 {
			return running{command: command, session: record.Session, lines: lines, header: header}
		}
	}
	t.Fatalf("the observer never activated: %v\n%s", lines.Err(), strings.Join(header, "\n"))
	return running{}
}

// ended stops the session and returns the account it sealed beside its spool.
func ended(t *testing.T, observer running, c configured) account.Account {
	t.Helper()

	if err := observer.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("stop the observer: %v", err)
	}
	for observer.lines.Scan() {
	}
	if err := observer.command.Wait(); err != nil {
		t.Fatalf("the observer exited with %v", err)
	}
	content, err := os.ReadFile(filepath.Join(observer.directory(c), "account.json"))
	if err != nil {
		t.Fatalf("read the sealed account: %v", err)
	}
	var sealed account.Account
	if err := json.Unmarshal(content, &sealed); err != nil {
		t.Fatalf("decode the sealed account: %v", err)
	}
	if sealed.Kind != account.Sealed || sealed.Session != observer.session {
		t.Fatalf("the account beside session %s is a %s account of session %s", observer.session, sealed.Kind, sealed.Session)
	}
	return sealed
}

func rendered(a account.Account) string {
	var out bytes.Buffer
	account.Render(&out, a, false)
	return out.String()
}

func names(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read %s: %v", directory, err)
	}
	found := make([]string, 0, len(entries))
	for _, entry := range entries {
		found = append(found, entry.Name())
	}
	slices.Sort(found)
	return found
}

// writable is every file the process has open for writing, by the path the
// kernel resolves each descriptor to.
func writable(t *testing.T, pid int) []string {
	t.Helper()

	directory := filepath.Join(procfs, strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read %s: %v", directory, err)
	}

	var open []string
	for _, entry := range entries {
		info, err := os.ReadFile(filepath.Join(procfs, strconv.Itoa(pid), "fdinfo", entry.Name()))
		if err != nil {
			continue
		}
		var flags uint64
		for line := range strings.Lines(string(info)) {
			if name, value, found := strings.Cut(strings.TrimSpace(line), ":"); found && name == "flags" {
				flags, _ = strconv.ParseUint(strings.TrimSpace(value), 8, 64)
			}
		}
		// O_WRONLY and O_RDWR are the low two bits of the reported flags.
		if flags&0o3 == 0 {
			continue
		}
		target, err := os.Readlink(filepath.Join(directory, entry.Name()))
		if err != nil {
			continue
		}
		open = append(open, target)
	}
	return open
}

func held(t *testing.T, pid int, field string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(procfs, strconv.Itoa(pid), "status"))
	if err != nil {
		t.Fatalf("read what pid %d holds: %v", pid, err)
	}
	for line := range strings.Lines(string(content)) {
		if name, value, found := strings.Cut(strings.TrimSpace(line), ":"); found && name == field {
			return strings.TrimSpace(value)
		}
	}
	t.Fatalf("the kernel reported no %s for pid %d", field, pid)
	return ""
}

// The observer as it ships, attached to an unmodified process: it holds no
// capability once the probes are placed, listens on nothing, and writes only
// its own files (spool, log, pid file).
func TestTheObserverHoldsNothingListensOnNothingAndWritesOnlyItsOwnFiles(t *testing.T) {
	binary := built(t)
	client := speaking(t, serving(t))
	c := configuring(t, target("under-test", client.process))

	observer := started(t, binary, c)
	pid := observer.command.Process.Pid

	if capabilities := held(t, pid, "CapEff"); strings.Trim(capabilities, "0") != "" {
		t.Errorf("the observer holds %s after attaching", capabilities)
	}
	if capabilities := held(t, pid, "CapPrm"); strings.Trim(capabilities, "0") != "" {
		t.Errorf("the observer is permitted %s after attaching", capabilities)
	}

	// The kernel's tables carry every socket in the namespace; the socket inodes
	// the process holds narrow them to it.
	sockets, err := privilege.Listening(filepath.Join(procfs, strconv.Itoa(pid)))
	if err != nil {
		t.Fatalf("read what the observer is listening on: %v", err)
	}
	if len(sockets) != 0 {
		t.Errorf("the observer is listening on %v, and it takes nothing in", sockets)
	}

	// Each writable file is named, so one more is a failure.
	//
	// The approved artifact is here because it is the session's durable output:
	// the worker writes authorized records to it while the session runs, so it
	// is open for writing for as long as the observer is. It is named exactly
	// rather than matched by a pattern, because a pattern over this directory
	// would admit whatever a later change put beside it, and nothing anywhere
	// reports a check that stopped refusing.
	// The two spool files are NOT here, and their absence is deliberate: the
	// write path was removed, so nothing opens either of them. A permission
	// that admits nothing today is a pre-authorised future write - it would
	// silently readmit the spool the moment anything reopened it, and this
	// enumeration exists precisely so that a new writable file is a failure.
	// Restoring the legacy read path does not restore them; only writing would.
	allowed := map[string]bool{
		filepath.Join(c.directory, processing.ArtifactName): true,
		c.log:       true,
		c.pidFile(): true,
	}
	for _, path := range writable(t, pid) {
		switch {
		case allowed[path]:
		case strings.HasPrefix(path, "pipe:"), strings.HasPrefix(path, "socket:"), strings.HasPrefix(path, "anon_inode:"):
			// The pipes this test gave it and the runtime's scheduling descriptors.
		case path == "/dev/null":
		default:
			t.Errorf("the observer has %s open for writing, and it writes only its approved output, its log and its pid file", path)
		}
	}
}

// A configuration whose targets select no process refuses to start, names the
// target, and leaves nothing behind (no session directory, no sealed account,
// no pid-file session), with a log record saying why.
func TestAConfigurationThatSelectsNoProcessRefusesTheStartAndLeavesNothingBehind(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "not-running")
	c := configuring(t, map[string]any{"name": "not-running", "exe": absent, "descendants": "none"})

	command := exec.Command(built(t), "start", c.path)
	output, err := command.CombinedOutput()
	if err == nil || command.ProcessState.ExitCode() == 0 {
		t.Fatalf("the observer started over a configuration that selects nothing:\n%s", output)
	}
	for _, want := range []string{"selected nothing", "not-running"} {
		if !strings.Contains(string(output), want) {
			t.Errorf("the refusal does not say %q:\n%s", want, output)
		}
	}

	if entries, err := os.ReadDir(c.sessions()); err == nil && len(entries) != 0 {
		t.Errorf("a start that failed left %d session directories behind", len(entries))
	}
	if held, err := os.ReadFile(c.pidFile()); err == nil && strings.TrimSpace(string(held)) != "" {
		t.Errorf("a start that failed left %q in the pid file", held)
	}
	logged, err := os.ReadFile(c.log)
	if err != nil {
		t.Fatalf("read the log: %v", err)
	}
	var failed, activated int
	for line := range strings.Lines(string(logged)) {
		record, ok := recordOf([]byte(line))
		switch {
		case !ok:
		case record.Record == "start-failed" && strings.Contains(record.Error, "selected nothing"):
			failed++
		case record.Record == "activation-completed":
			activated++
		}
	}
	if failed != 1 || activated != 0 {
		t.Errorf("the log carries %d start-failed and %d activation records, want one and none:\n%s", failed, activated, logged)
	}
}

// A second start while a session runs is refused, names the running session,
// and starts nothing.
func TestASecondStartIsRefusedWhileASessionRunsAndStartsNothing(t *testing.T) {
	binary := built(t)
	client := speaking(t, serving(t))
	c := configuring(t, target("under-test", client.process))
	first := started(t, binary, c)

	second := exec.Command(binary, "start", c.path)
	output, err := second.CombinedOutput()
	if err == nil {
		t.Fatalf("a second start for a configuration with a running session succeeded:\n%s", output)
	}
	if !strings.Contains(string(output), first.session) || !strings.Contains(string(output), "already running") {
		t.Errorf("the second start does not name the running session %s:\n%s", first.session, output)
	}
	if got := names(t, c.sessions()); !slices.Equal(got, []string{first.session}) {
		t.Errorf("the sessions directory holds %v, want only the running session", got)
	}

	answer, err := exec.Command(binary, "inspect", c.path).Output()
	if err != nil {
		t.Fatalf("inspect the running session after the refused start: %v", err)
	}
	var live account.Account
	if err := json.Unmarshal(answer, &live); err != nil || live.Session != first.session {
		t.Errorf("after the refused start the running session answers as %q (%v)", live.Session, err)
	}
}

// Attached with nothing crossing and never attached produce the same silence;
// the sealed account says which, with attachment and events side by side.
func TestAttachedAndIdleIsSaidRatherThanLeftAsSilence(t *testing.T) {
	binary := built(t)
	client := speaking(t, serving(t))
	c := configuring(t, target("under-test", client.process))

	summary := rendered(ended(t, started(t, binary, c), c))

	for _, want := range []string{"attached  ", "events     0 transfers", "attached, and no event arrived"} {
		if !strings.Contains(summary, want) {
			t.Errorf("the sealed account does not say %q:\n%s", want, summary)
		}
	}
	if strings.Contains(summary, string(attachment.NotAttached)) {
		t.Errorf("an attached run's account says it was not attached:\n%s", summary)
	}
}

// speakingThrough starts a TLS client loading libssl from a copy in its own
// directory, so its library is a file nothing has attached to.
func speakingThrough(t *testing.T, port int, library string) conversation {
	t.Helper()
	directory := t.TempDir()
	content, err := os.ReadFile(library)
	if err != nil {
		t.Fatalf("read %s: %v", library, err)
	}
	if err := os.WriteFile(filepath.Join(directory, filepath.Base(library)), content, 0o755); err != nil {
		t.Fatalf("copy %s: %v", library, err)
	}

	command := exec.Command("openssl", "s_client", "-quiet", "-no_ign_eof",
		"-connect", "127.0.0.1:"+strconv.Itoa(port))
	command.Env = append(os.Environ(), "LD_LIBRARY_PATH="+directory)
	send, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	receive, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start a TLS client: %v", err)
	}
	t.Cleanup(func() {
		_ = send.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	p := loaded(t, int32(command.Process.Pid))
	mappings, err := process.Mappings(procfs, p.PID)
	if err != nil || !slices.ContainsFunc(mappings, func(one process.Mapping) bool {
		return strings.HasPrefix(one.Path, directory) && one.Executable
	}) {
		t.Fatalf("wiring, not the property: pid %d does not run the copied library, so it is not a library "+
			"nothing has attached: %v %v", p.PID, mappings, err)
	}
	return conversation{process: p, send: send, receive: bufio.NewReader(receive)}
}

// libsslOf is the libssl file a process maps.
func libsslOf(t *testing.T, p process.Process) string {
	t.Helper()
	mappings, err := process.Mappings(procfs, p.PID)
	if err != nil {
		t.Fatalf("read pid %d's mappings: %v", p.PID, err)
	}
	for _, one := range mappings {
		if strings.Contains(one.Path, "libssl.so") && one.Executable {
			return one.Path
		}
	}
	t.Fatalf("pid %d maps no libssl", p.PID)
	return ""
}

// A reload that takes anything away, or needs a library nothing has attached,
// is refused: the policy in force stays at its generation, the reason is named,
// and nothing is admitted, including a valid addition bundled beside it.
func TestARefusedReloadLeavesThePolicyInForceAndSaysWhy(t *testing.T) {
	binary := built(t)
	kept := speaking(t, serving(t))
	added := speaking(t, serving(t))
	elsewhere := speakingThrough(t, serving(t), libsslOf(t, kept.process))
	c := configuring(t, target("kept", kept.process))
	started(t, binary, c)

	for _, one := range []struct {
		name       string
		targets    []map[string]any
		exclusions []map[string]any
		because    string
		unadmitted int32
	}{
		{"a removal beside an addition",
			[]map[string]any{target("added", added.process)}, nil,
			"removes target kept", added.process.PID},
		{"an exclusion beside an addition",
			[]map[string]any{target("kept", kept.process), target("added", added.process)},
			[]map[string]any{{"exe": "/usr/bin/nonexistent-exclusion"}},
			"adds an exclusion", added.process.PID},
		{"a library nothing has attached",
			[]map[string]any{target("kept", kept.process), target("elsewhere", elsewhere.process)}, nil,
			"needs a library nothing has attached yet", elsewhere.process.PID},
	} {
		t.Run(one.name, func(t *testing.T) {
			c.rewrite(t, one.targets, one.exclusions)
			answer, err := reloaded(t, binary, c)
			if err == nil || answer.Outcome != "refused" {
				t.Fatalf("the reload answered %+v with %v, want a refusal", answer, err)
			}
			if !strings.Contains(answer.Reason, one.because) {
				t.Errorf("the refusal says %q, want %q", answer.Reason, one.because)
			}
			if answer.Generation != 1 {
				t.Errorf("the refusal reports generation %d, want the one in force, 1", answer.Generation)
			}
			live := inspected(t, binary, c)
			if live.Policy.Generation != 1 {
				t.Errorf("after the refusal the session is at generation %d", live.Policy.Generation)
			}
			if observes(live, one.unadmitted) {
				t.Errorf("pid %d is observed after a reload that was refused", one.unadmitted)
			}
			if !observes(live, kept.process.PID) || live.Admissions == nil || live.Admissions.Covered < 1 {
				t.Errorf("the process the policy in force observes is no longer covered: %+v", live.Admissions)
			}
		})
	}
}

// The log says coverage ended when it ended. Two targets each cover one
// process; the first's process exits mid-run, and a later state record says the
// first target covers nothing while the second is covered, so neither a stale
// activation count nor a global zero passes.
func TestAStateRecordSaysCoverageEndedWhenATargetsLastProcessExits(t *testing.T) {
	binary := built(t)
	// Two servers, so each target selects exactly one client.
	first := speaking(t, serving(t))
	second := speaking(t, serving(t))
	c := configuring(t, target("first", first.process), target("second", second.process))
	observer := started(t, binary, c)

	next := func() logRecord {
		t.Helper()
		for observer.lines.Scan() {
			if record, ok := recordOf(observer.lines.Bytes()); ok && record.Record == "state" {
				return record
			}
		}
		t.Fatalf("the log ended without another state record: %v", observer.lines.Err())
		return logRecord{}
	}

	// The control, before anything ends: both targets are covered.
	var before logRecord
	for range 10 {
		before = next()
		one, known := before.covered("first")
		other, alsoKnown := before.covered("second")
		if known && alsoKnown && one >= 1 && other >= 1 {
			break
		}
	}
	if one, _ := before.covered("first"); one < 1 {
		t.Fatalf("wiring, not the property: the first target never read as covered, so its ending would measure nothing: %+v", before)
	}

	if err := syscall.Kill(int(first.process.PID), syscall.SIGKILL); err != nil {
		t.Fatalf("end the first target's only process: %v", err)
	}

	var after logRecord
	for range 15 {
		after = next()
		if covered, known := after.covered("first"); known && covered == 0 {
			break
		}
	}
	covered, known := after.covered("first")
	if !known || covered != 0 {
		t.Fatalf("the newest state record still reports the first target covered after its only process exited: %+v", after)
	}
	if still, known := after.covered("second"); !known || still < 1 {
		t.Errorf("the second target reads %d covered in the same record, so the zero is the whole run going dark: %+v", still, after)
	}
	var said bool
	for _, change := range after.Changes {
		said = said || (strings.Contains(change, "first") && strings.Contains(change, "coverage ended"))
	}
	if !said {
		t.Errorf("the record that shows the first target at zero does not say its coverage ended: %v", after.Changes)
	}
}
