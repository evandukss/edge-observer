//go:build attach

package attach_test

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/attachment"
	contract "github.com/evandukss/edge-observer/contract/account"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/internal/published"
	"github.com/evandukss/edge-observer/privilege"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/spool"
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
// the same observer section, as an operator would before a reload. Each target
// is put into the contract's shape (contract/config): the conditions become its
// match and the mode word the two answers the mode gives.
func (c configured) rewrite(t *testing.T, targets, exclusions []map[string]any) {
	t.Helper()
	answers := map[string][2]bool{"none": {false, false}, "existing": {true, false}, "follow": {true, true}}
	written := []any{}
	for _, one := range targets {
		match := map[string]any{}
		for key, value := range one {
			if key != "name" && key != "descendants" {
				match[key] = value
			}
		}
		word, _ := one["descendants"].(string)
		pair, known := answers[word]
		if !known {
			t.Fatalf("wiring, not the observer: target %v names descendant mode %q", one["name"], word)
		}
		written = append(written, map[string]any{"name": one["name"], "match": match, "descendants": map[string]any{
			"existing": pair[0], "future": pair[1], "boundary": "exec_ends_the_grant",
			"root_exit": "survivors_keep_their_grants", "replacement": "needs_restart",
		}})
	}
	excluded := []any{}
	for _, one := range exclusions {
		excluded = append(excluded, one)
	}
	document := map[string]any{
		"version":           "observer.config/draft",
		"observer":          map[string]any{"log": c.log, "directory": c.directory, "spool_bound_mib": 1, "state_every_seconds": 1},
		"observation_scope": map[string]any{"targets": written, "exclude": excluded, "libraries": []any{}},
		"traffic_scope": map[string]any{"rules": []any{map[string]any{
			"targets": []any{}, "direction": "any", "local_ports": []any{}, "remote_ports": []any{}}}},
		"retention_and_export": map[string]any{"retain_plaintext": true, "export_sinks": []any{}},
		"packs":                []any{},
		"sinks":                []any{map[string]any{"name": "account", "kind": "local_account"}},
		"pipelines": []any{
			map[string]any{"name": "exchanges", "input": "reconstruction", "slots": []any{}, "sinks": []any{"account"}, "queues": []any{}},
			map[string]any{"name": "connections", "input": "connection", "slots": []any{}, "sinks": []any{"account"}, "queues": []any{}},
		},
		"subscribers": []any{},
		"policy":      []any{},
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
	Admitted   int      `json:"admitted"`
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
	Follows *struct {
		Session string `json:"session"`
		Gap     string `json:"gap"`
	} `json:"follows"`
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

// sessionOf is the process and session the pid file names, written by a
// detached session before it records its activation.
func sessionOf(t *testing.T, c configured) (int, string) {
	t.Helper()
	for range 100 {
		content, err := os.ReadFile(c.pidFile())
		if fields := strings.Fields(string(content)); err == nil && len(fields) == 2 {
			pid, err := strconv.Atoi(fields[0])
			if err == nil {
				return pid, fields[1]
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the pid file %s names no running session", c.pidFile())
	return 0, ""
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

// activationOf is the activation record the log carries for session.
func activationOf(t *testing.T, c configured, session string) logRecord {
	t.Helper()
	logged, err := os.ReadFile(c.log)
	if err != nil {
		t.Fatalf("read the log: %v", err)
	}
	for line := range strings.Lines(string(logged)) {
		if record, ok := recordOf([]byte(line)); ok && record.Record == "activation-completed" && record.Session == session {
			return record
		}
	}
	t.Fatalf("the log carries no activation for session %s:\n%s", session, logged)
	return logRecord{}
}

// A detached start that cannot activate exits non-zero with the reason and
// leaves no detached process behind.
func TestADetachedStartThatCannotActivateExitsNonZeroAndLeavesNoProcessBehind(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "not-running")
	c := configuring(t, map[string]any{"name": "not-running", "exe": absent, "descendants": "none"})

	command := exec.Command(built(t), "start", c.path, "--daemonize")
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

// The parent exits zero only once the child has activated, and the child is the
// observer: it holds no capability and captures an exchange that crosses after
// the parent has gone.
func TestADetachedStartExitsZeroOnlyOnceActivatedAndItsChildGoesOnObserving(t *testing.T) {
	binary := built(t)
	client := speaking(t, serving(t))
	c := configuring(t, target("under-test", client.process))

	parent := exec.Command(binary, "start", c.path, "--daemonize")
	output, err := parent.CombinedOutput()
	if err != nil {
		t.Fatalf("the detached start failed: %v\n%s", err, output)
	}
	pid, session := sessionOf(t, c)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if pid == parent.Process.Pid {
		t.Fatalf("the pid file names the parent, %d, which has exited", pid)
	}
	if !strings.Contains(string(output), session) {
		t.Errorf("the parent does not name the session it started:\n%s", output)
	}
	// Activated before the parent returned: the record is already in the log.
	activationOf(t, c, session)

	if capabilities := held(t, pid, "CapEff"); strings.Trim(capabilities, "0") != "" {
		t.Errorf("the detached observer holds %s after activating", capabilities)
	}
	client.ask(t, "after-the-parent")
	waitForSpool(t, filepath.Join(c.sessions(), session), 2)

	if out, err := exec.Command(binary, "stop", c.path).CombinedOutput(); err != nil {
		t.Fatalf("stop the detached observer: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(c.sessions(), session, "account.json")); err != nil {
		t.Errorf("the detached session sealed no account: %v", err)
	}
}

// A restart seals one output session and begins another told apart from it,
// whose activation says which session it follows and how long nothing was
// observed between. A connection open across it stays observed.
func TestARestartIsANewOutputSessionWhoseActivationSaysHowLongNothingWasObserved(t *testing.T) {
	binary := built(t)
	client := speaking(t, serving(t))
	c := configuring(t, target("under-test", client.process))

	if out, err := exec.Command(binary, "start", c.path, "--daemonize").CombinedOutput(); err != nil {
		t.Fatalf("start detached: %v\n%s", err, out)
	}
	_, first := sessionOf(t, c)
	client.ask(t, "first")
	waitForSpool(t, filepath.Join(c.sessions(), first), 2)

	if out, err := exec.Command(binary, "restart", c.path).CombinedOutput(); err != nil {
		t.Fatalf("restart: %v\n%s", err, out)
	}
	pid, second := sessionOf(t, c)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if second == first {
		t.Fatalf("the restarted observer is still session %s", first)
	}
	if _, err := os.Stat(filepath.Join(c.sessions(), first, "account.json")); err != nil {
		t.Errorf("the first session did not seal before the second began: %v", err)
	}
	activation := activationOf(t, c, second)
	if activation.Follows == nil || activation.Follows.Session != first || activation.Follows.Gap == "" {
		t.Errorf("the second session's activation says it follows %+v, want session %s and the gap", activation.Follows, first)
	}

	client.ask(t, "second")
	waitForSpool(t, filepath.Join(c.sessions(), second), 1)
	if out, err := exec.Command(binary, "stop", c.path).CombinedOutput(); err != nil {
		t.Fatalf("stop: %v\n%s", err, out)
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
func started(t *testing.T, binary string, c configured) running {
	t.Helper()

	command := exec.Command(binary, "start", c.path)
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	command.Stderr = os.Stderr
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

// validatedBundle assembles a finished session's contract bundle from exactly
// what it sealed (contract account and spool) with the contract's Bundle, and
// requires the contract's validator to accept it. Assembly adds only the
// seal's member digests.
func validatedBundle(t *testing.T, directory, session string, spooled int) {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(directory, published.Name))
	if err != nil {
		t.Fatalf("read the sealed contract account: %v", err)
	}
	var sealed contract.Account
	if err := json.Unmarshal(content, &sealed); err != nil {
		t.Fatalf("decode the sealed contract account: %v", err)
	}
	if sealed.Moment != contract.Sealed || sealed.Session != session {
		t.Fatalf("the contract account beside session %s is a %s account of session %s", session, sealed.Moment, sealed.Session)
	}
	records, err := published.Records(os.DirFS(directory))
	if err != nil {
		t.Fatalf("read the session's spool into records: %v", err)
	}
	if len(records.Observations) < spooled || spooled == 0 {
		t.Fatalf("wiring, not the property: %d observations were read off a spool the run saw %d fragments in",
			len(records.Observations), spooled)
	}

	// No captured plaintext is in the contract account: no plaintext-carrying
	// member, no spool payload raw or base64. "payload" is not searched for: a
	// capability fact of that name says whether the build copies plaintext.
	t.Logf("the contract account is %d bytes, beside %d observations", len(content), len(records.Observations))
	for _, member := range []string{`"headers"`, `"body"`, `"start_line"`, `"data"`} {
		if bytes.Contains(content, []byte(member)) {
			t.Errorf("the contract account carries a %s member", member)
		}
	}
	checked := 0
	for _, one := range records.Observations {
		if len(one.Payload.Data) < 12 {
			continue
		}
		checked++
		raw, err := base64.StdEncoding.DecodeString(one.Payload.Data)
		if err != nil {
			t.Fatalf("an observation's payload is not base64: %v", err)
		}
		if bytes.Contains(content, []byte(one.Payload.Data)) || bytes.Contains(content, raw) {
			t.Errorf("the contract account carries a payload the spool holds")
		}
	}
	if checked == 0 {
		t.Fatalf("wiring, not the property: no observation carried a payload to look for")
	}
	files, err := contract.Bundle(sealed, records)
	if err != nil {
		t.Fatalf("bundle the sealed contract account: %v", err)
	}
	root := t.TempDir()
	for path, member := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, path), member, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result := contract.Validate(os.DirFS(root), contract.Options{})
	if result.Outcome != contract.Validated {
		t.Errorf("the contract's validator refuses the session's bundle: %s over %s, %+v",
			result.Outcome, result.Validated, result.Findings)
	}
	if result.Examined.Records < len(records.Observations) {
		t.Errorf("the validator examined %d records of a bundle holding %d observations",
			result.Examined.Records, len(records.Observations))
	}
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

func spooledRecords(t *testing.T, path string) []fragment.Record {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()

	var records []fragment.Record
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		var record fragment.Record
		if err := json.Unmarshal(lines.Bytes(), &record); err != nil {
			// A line still being written.
			continue
		}
		records = append(records, record)
	}
	return records
}

// waitForSpool waits until the session has written at least want records.
// settleWindow is how long the spool must hold still before a count from it is
// settled. settled() logs each wait, so a window that is too short shows as a
// count that still moves.
const settleWindow = 100 * time.Millisecond

// settled is the spool's records once it has stopped growing. waitForSpool
// returns what was there when it first held want, which is a lower bound: a
// late record of the same exchange can only add. Anything computing a number
// from the spool waits here instead.
func settled(t *testing.T, directory string, want int) []fragment.Record {
	t.Helper()
	records := waitForSpool(t, directory, want)
	started := time.Now()
	for range 200 {
		time.Sleep(settleWindow)
		next := spooledRecords(t, filepath.Join(directory, spool.Name))
		if len(next) == len(records) {
			t.Logf("the spool settled at %d records after %s", len(next), time.Since(started))
			return next
		}
		records = next
	}
	t.Fatalf("the spool never stopped growing: %d records after %s", len(records), time.Since(started))
	return nil
}

func waitForSpool(t *testing.T, directory string, want int) []fragment.Record {
	t.Helper()
	var records []fragment.Record
	for range 500 {
		if records = spooledRecords(t, filepath.Join(directory, spool.Name)); len(records) >= want {
			return records
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the observer wrote %d records, want %d, so what follows would measure nothing", len(records), want)
	return nil
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

	// Each writable file is named, so a fifth is a failure.
	allowed := map[string]bool{
		filepath.Join(observer.directory(c), spool.Name):            true,
		filepath.Join(observer.directory(c), spool.ConnectionsName): true,
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
			t.Errorf("the observer has %s open for writing, and it writes only its spool, its log and its pid file", path)
		}
	}
}

// What it captures reaches the spool, the configured log carries the
// activation standard output did, and stopping it seals the account and
// removes its probes.
func TestTheObserverSpoolsWhatCrossedTheProcessItWasGivenAndSealsItsAccountBesideIt(t *testing.T) {
	binary := built(t)
	client := speaking(t, serving(t))
	c := configuring(t, target("under-test", client.process))

	observer := started(t, binary, c)
	client.ask(t, "spooled")

	records := waitForSpool(t, observer.directory(c), 2)
	directions := make(map[fragment.Direction]int, 2)
	for _, record := range records {
		if record.Process.PID != client.process.PID {
			t.Errorf("a spooled record carries pid %d, and %d was approved", record.Process.PID, client.process.PID)
		}
		if err := record.Validate(); err != nil {
			t.Errorf("a spooled record is not usable: %v", err)
		}
		directions[record.Direction]++
	}
	if directions[fragment.Sent] == 0 || directions[fragment.Received] == 0 {
		t.Errorf("the spool carries %d sent and %d received", directions[fragment.Sent], directions[fragment.Received])
	}

	// The log is the configured file, and standard output only mirrors it.
	logged, err := os.ReadFile(c.log)
	if err != nil {
		t.Fatalf("read the configured log: %v", err)
	}
	var activation bool
	for line := range strings.Lines(string(logged)) {
		if record, ok := recordOf([]byte(line)); ok && record.Record == "activation-completed" && record.Session == observer.session {
			activation = true
		}
	}
	if !activation {
		t.Errorf("the configured log carries no activation for session %s:\n%s", observer.session, logged)
	}

	// What it keeps, and nothing beside it.
	if got, want := names(t, c.directory), []string{"observer.log", "observer.pid", "sessions"}; !slices.Equal(got, want) {
		t.Errorf("the observer's directory holds %v while it runs, want %v", got, want)
	}
	if got, want := names(t, observer.directory(c)), []string{spool.ConnectionsName, spool.Name}; !slices.Equal(got, want) {
		t.Errorf("the session's directory holds %v while it runs, want %v", got, want)
	}

	sealed := ended(t, observer, c)
	if sealed.Seal == nil || !sealed.Seal.Complete {
		t.Errorf("a run that finished its traffic did not seal completely: %+v %s", sealed.Seal, sealed.SealError)
	}
	// The contract account is another test's claim
	// (TestAFinishedSessionSealsAnAccountTheAccountContractsValidatorAccepts).
	if got, want := slices.DeleteFunc(names(t, observer.directory(c)), func(name string) bool {
		return name == published.Name
	}), []string{"account.json", spool.ConnectionsName, spool.Name}; !slices.Equal(got, want) {
		t.Errorf("the session's directory holds %v once it has ended, want %v", got, want)
	}
	if !slices.Contains(names(t, c.directory), "last-sealed.json") {
		t.Error("the observer's directory records no last sealed session, so the next one cannot say how long nothing was observed")
	}

	// The finished session's files, copied elsewhere and inspected with the
	// session gone, give back the account it sealed, byte for byte.
	elsewhere := t.TempDir()
	for _, name := range []string{"account.json", spool.ConnectionsName, spool.Name} {
		content, err := os.ReadFile(filepath.Join(observer.directory(c), name))
		if err != nil {
			t.Fatalf("read the finished session's %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(elsewhere, name), content, 0o600); err != nil {
			t.Fatalf("copy %s: %v", name, err)
		}
	}
	answer, err := exec.Command(binary, "inspect", elsewhere).Output()
	if err != nil {
		t.Fatalf("inspect the copied session: %v\n%s", err, answer)
	}
	if want, _ := os.ReadFile(filepath.Join(elsewhere, "account.json")); !bytes.Equal(answer, want) {
		t.Errorf("inspect of the copied session is not the account it sealed:\n%s", answer)
	}
	text, err := exec.Command(binary, "inspect", elsewhere, "--text").Output()
	if err != nil {
		t.Fatalf("inspect the copied session as text: %v", err)
	}
	if !strings.HasPrefix(string(text), "account    sealed, "+observer.session+", ") {
		t.Errorf("the text of the copied session is not session %s's sealed account:\n%s", observer.session, text)
	}
}

// A finished session also seals its account in the account contract, and a
// bundle assembled from what it sealed passes the contract's validator and
// holds none of the spool's plaintext.
func TestAFinishedSessionSealsAnAccountTheAccountContractsValidatorAccepts(t *testing.T) {
	binary := built(t)
	client := speaking(t, serving(t))
	c := configuring(t, target("under-test", client.process))

	observer := started(t, binary, c)
	client.ask(t, "contract")
	records := waitForSpool(t, observer.directory(c), 2)
	ended(t, observer, c)

	if got, want := names(t, observer.directory(c)), []string{"account.json", spool.ConnectionsName, published.Name, spool.Name}; !slices.Equal(got, want) {
		t.Errorf("the session's directory holds %v once it has ended, want %v", got, want)
	}
	validatedBundle(t, observer.directory(c), observer.session, len(records))
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

// inspect is the running session's account, served without stopping anything.
func TestInspectServesTheRunningSessionsAccountAsItStands(t *testing.T) {
	binary := built(t)
	client := speaking(t, serving(t))
	c := configuring(t, target("under-test", client.process))
	observer := started(t, binary, c)

	client.ask(t, "inspected")
	waitForSpool(t, observer.directory(c), 2)

	answer, err := exec.Command(binary, "inspect", c.path).Output()
	if err != nil {
		t.Fatalf("inspect the running session: %v", err)
	}
	var live account.Account
	if err := json.Unmarshal(answer, &live); err != nil {
		t.Fatalf("decode the live account: %v\n%s", err, answer)
	}
	if live.Kind != account.Live || live.Session != observer.session {
		t.Errorf("inspect answered a %s account of session %q, want the live account of %s", live.Kind, live.Session, observer.session)
	}
	if len(live.Processes) != 1 || live.Processes[0].Outcome != attachment.Attached ||
		live.Processes[0].Requested == 0 || live.Processes[0].Confirmed != live.Processes[0].Requested {
		t.Errorf("the live account says %+v about the one approved process", live.Processes)
	}
	if live.Seen == nil || live.Seen.Transfers == 0 {
		t.Errorf("the live account saw %+v after a request crossed the approved process", live.Seen)
	}
	if live.Admissions == nil || live.Admissions.Covered < 1 {
		t.Errorf("the live account covers %+v while the approved process runs", live.Admissions)
	}

	text, err := exec.Command(binary, "inspect", c.path, "--text").Output()
	if err != nil {
		t.Fatalf("inspect the running session as text: %v", err)
	}
	if !strings.Contains(string(text), "state      attached, and events arrived") {
		t.Errorf("the text account does not say events arrived:\n%s", text)
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

// The control: a run that saw traffic says so, so "no event arrived" is a
// measurement.
func TestARunThatSawTrafficDoesNotSayNoEventArrived(t *testing.T) {
	binary := built(t)
	client := speaking(t, serving(t))
	c := configuring(t, target("under-test", client.process))

	observer := started(t, binary, c)
	client.ask(t, "hello")
	waitForSpool(t, observer.directory(c), 1)
	summary := rendered(ended(t, observer, c))

	if strings.Contains(summary, "no event arrived") {
		t.Errorf("a run that captured traffic says no event arrived:\n%s", summary)
	}
	if !strings.Contains(summary, "events arrived") {
		t.Errorf("a run that captured traffic does not say events arrived:\n%s", summary)
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

// An additive reload puts a new target in force at the next generation and
// admits its process, while an already-observed connection continues with no
// gap and no duplicate; a reload adding nothing changes nothing.
func TestAnAdditiveReloadAdmitsTheNewProcessAndLeavesTheObservedOneAsItWas(t *testing.T) {
	binary := built(t)
	kept := speaking(t, serving(t))
	added := speaking(t, serving(t))
	c := configuring(t, target("kept", kept.process))
	observer := started(t, binary, c)

	kept.ask(t, "before")
	before := settled(t, observer.directory(c), 2)

	c.rewrite(t, []map[string]any{target("kept", kept.process), target("added", added.process)}, nil)
	answer, err := reloaded(t, binary, c)
	if err != nil || answer.Outcome != "activated" || answer.Generation != 2 || answer.Admitted != 1 {
		t.Fatalf("the additive reload answered %+v with %v, want generation 2 and one process admitted", answer, err)
	}

	kept.ask(t, "after")
	added.ask(t, "added")
	after := settled(t, observer.directory(c), len(before)+4)

	of := func(records []fragment.Record, pid int32) []fragment.Record {
		var found []fragment.Record
		for _, one := range records {
			if one.Process.PID == pid {
				found = append(found, one)
			}
		}
		return found
	}
	keptBefore, keptAfter := of(before, kept.process.PID), of(after, kept.process.PID)

	// Not a record count: an exchange here is three records (a 48-byte request,
	// and a 342-byte response read as 155 then 187), set by message sizes and
	// kernel reads, not by the reload. What must hold is that records before the
	// reload stand unchanged and each one after continues its direction at the
	// offset reached: a repeat shows as an offset behind, a loss as one ahead.
	describe := func(name string, records []fragment.Record) {
		carried := make(map[fragment.Direction]uint64, 2)
		for _, one := range records {
			carried[one.Direction] += uint64(one.Length)
			t.Logf("  %s: %s connection %d offset %d length %d", name, one.Direction, one.Connection,
				one.Offset, one.Length)
		}
		for direction, total := range carried {
			t.Logf("  %s: %s %d bytes", name, direction, total)
		}
	}
	if len(keptAfter) <= len(keptBefore) {
		describe("before", keptBefore)
		describe("after", keptAfter)
		t.Fatalf("the observed process held %d records before the reload and %d after one more exchange: "+
			"the exchange that crossed it is not there", len(keptBefore), len(keptAfter))
	}
	for i, one := range keptBefore {
		held := keptAfter[i]
		if held.Direction != one.Direction || held.Offset != one.Offset || held.Length != one.Length {
			describe("before", keptBefore)
			describe("after", keptAfter)
			t.Fatalf("record %d of the observed process was %s at offset %d for %d bytes and is now %s at %d "+
				"for %d: a reload rewrote what had already crossed", i, one.Direction, one.Offset, one.Length,
				held.Direction, held.Offset, held.Length)
		}
	}

	// The same connection, continuing where it left off, in both directions.
	next := make(map[fragment.Direction]uint64)
	for _, one := range keptBefore {
		if end := one.Offset + uint64(one.Length); end > next[one.Direction] {
			next[one.Direction] = end
		}
	}
	grew := make(map[fragment.Direction]int, 2)
	for _, one := range keptAfter[len(keptBefore):] {
		if one.Connection != keptBefore[0].Connection {
			t.Errorf("the observed process's exchange after the reload is on connection %d, and it was on %d",
				one.Connection, keptBefore[0].Connection)
		}
		if one.Offset != next[one.Direction] {
			was := "repeats what already crossed"
			if one.Offset > next[one.Direction] {
				was = "leaves a gap"
			}
			describe("before", keptBefore)
			describe("after", keptAfter)
			t.Errorf("the %s stream continues at offset %d after the reload, want %d: it %s", one.Direction,
				one.Offset, next[one.Direction], was)
		}
		next[one.Direction] = one.Offset + uint64(one.Length)
		grew[one.Direction]++
	}
	if grew[fragment.Sent] == 0 || grew[fragment.Received] == 0 {
		describe("after", keptAfter)
		t.Errorf("the exchange after the reload added %d sent and %d received records, want both directions",
			grew[fragment.Sent], grew[fragment.Received])
	}
	if len(of(after, added.process.PID)) < 2 {
		t.Errorf("the newly admitted process's exchange is not in the spool: %d records", len(of(after, added.process.PID)))
	}
	live := inspected(t, binary, c)
	if live.Policy.Generation != 2 || !observes(live, added.process.PID) {
		t.Errorf("the live account is at generation %d and observes the new process: %v", live.Policy.Generation,
			observes(live, added.process.PID))
	}

	// Nothing added: nothing changes, and nothing crossing is doubled.
	unchanged, err := reloaded(t, binary, c)
	if err != nil || unchanged.Outcome != "unchanged" || unchanged.Generation != 2 {
		t.Errorf("a reload adding nothing answered %+v with %v", unchanged, err)
	}
	// Both ends settled, and the same offset check rather than a count: a reload
	// adding nothing owes that the stream goes on as one stream.
	counted := len(settled(t, observer.directory(c), 1))
	kept.ask(t, "again")
	again := settled(t, observer.directory(c), counted+1)
	if len(again) <= counted {
		t.Errorf("one exchange after a reload that added nothing spooled %d records, want the exchange to be there",
			len(again)-counted)
	}
	reached := make(map[fragment.Direction]uint64, 2)
	for _, one := range again {
		if one.Process.PID != kept.process.PID {
			continue
		}
		if one.Offset != reached[one.Direction] {
			was := "repeats what already crossed"
			if one.Offset > reached[one.Direction] {
				was = "leaves a gap"
			}
			t.Errorf("after a reload that added nothing, the %s stream has a record at offset %d where it had "+
				"reached %d: it %s", one.Direction, one.Offset, reached[one.Direction], was)
		}
		reached[one.Direction] = one.Offset + uint64(one.Length)
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
