package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// The descendant answers a target states, one per admission mode.
const (
	fixedAnswers = `"boundary": "exec_ends_the_grant", "root_exit": "survivors_keep_their_grants", "replacement": "needs_restart"`
	follow       = `{"existing": true, "future": true, ` + fixedAnswers + `}`
	existing     = `{"existing": true, "future": false, ` + fixedAnswers + `}`
	none         = `{"existing": false, "future": false, ` + fixedAnswers + `}`

	gatewayTarget = `{"name": "gateway", "match": {"exe": "/usr/bin/php", "args": ["/srv/gateway/main.php"]}, "descendants": ` + follow + `}`
	workerTarget  = `{"name": "worker", "match": {"cgroup": "/system.slice/worker.service"}, "descendants": ` + existing + `}`
	batchTarget   = `{"name": "batch", "match": {"exe": "/usr/bin/batch"}, "descendants": ` + none + `}`
)

// inForce is the policy a running session holds; each case changes one thing.
const inForce = `{
  "version": "observer.config/draft",
  "observer": {"log": "/var/log/observer/observer.log", "directory": "/var/lib/observer"},
  "observation_scope": {
    "targets": [
      ` + gatewayTarget + `,
      ` + workerTarget + `
    ],
    "exclude": [{"exe": "/usr/bin/curl"}],
    "libraries": []
  },
  "traffic_scope": {"rules": [{"targets": [], "direction": "any", "local_ports": [], "remote_ports": []}]},
  "retention_and_export": {"retain_plaintext": true, "export_sinks": []},
  "packs": [],
  "sinks": [{"name": "account", "kind": "local_account"}],
  "pipelines": [
    {"name": "exchanges", "input": "reconstruction", "slots": [], "sinks": ["account"], "queues": []},
    {"name": "connections", "input": "connection", "slots": [], "sinks": ["account"], "queues": []}
  ],
  "subscribers": [],
  "policy": []
}`

func loaded(t *testing.T, content string) policy.Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "observer.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	read, err := policy.Load(path)
	if err != nil {
		t.Fatalf("load the policy: %v", err)
	}
	return read
}

func replaced(t *testing.T, old, new string) policy.Policy {
	t.Helper()
	if !strings.Contains(inForce, old) {
		t.Fatalf("the policy in force has no %q to replace", old)
	}
	return loaded(t, strings.Replace(inForce, old, new, 1))
}

// A reload adds: an identical candidate changes nothing; one adding a target
// names what it adds.
func TestAReloadThatOnlyAddsIsAdditiveAndNamesWhatItAdds(t *testing.T) {
	current := loaded(t, inForce)

	added, refused := additive(current, loaded(t, inForce))
	if refused != "" || len(added) != 0 {
		t.Errorf("an unchanged policy is refused %q or adds %v", refused, added)
	}

	added, refused = additive(current, replaced(t,
		`"exclude"`,
		`"exclude"`)) // the same file again, through the helper, as the control for the helper
	if refused != "" || len(added) != 0 {
		t.Errorf("the helper changed the policy: refused %q, added %v", refused, added)
	}

	added, refused = additive(current, replaced(t, workerTarget, workerTarget+`, `+batchTarget))
	if refused != "" {
		t.Fatalf("a candidate that only adds a target is refused: %s", refused)
	}
	if len(added) != 1 || added[0].Name != "batch" {
		t.Errorf("the candidate adds %v, want the one target batch", added)
	}
}

// Each of these takes something away or changes what the observer is, and is
// refused with the reason - including a target kept by name whose conditions
// or mode narrowed.
func TestAReloadThatTakesAnythingAwayIsRefusedWithItsReason(t *testing.T) {
	current := loaded(t, inForce)
	for name, one := range map[string]struct {
		old, new, because string
	}{
		"a target removed": {
			`,
      ` + workerTarget, ``,
			"removes target worker"},
		"a target's conditions narrowed": {
			`"args": ["/srv/gateway/main.php"]`, `"args": ["/srv/gateway/main.php", "--only"]`,
			"changes target gateway"},
		"a target's mode narrowed": {
			`"args": ["/srv/gateway/main.php"]}, "descendants": ` + follow, `"args": ["/srv/gateway/main.php"]}, "descendants": ` + none,
			"changes target gateway"},
		"an exclusion added": {
			`[{"exe": "/usr/bin/curl"}]`, `[{"exe": "/usr/bin/curl"}, {"exe": "/usr/bin/wget"}]`,
			"adds an exclusion"},
		"an exclusion removed": {
			`"exclude": [{"exe": "/usr/bin/curl"}]`, `"exclude": []`,
			"removes an exclusion"},
		"where it writes": {
			`/var/log/observer/observer.log`, `/var/log/observer/elsewhere.log`,
			"changes where the observer writes"},
		"which libraries it may place on": {
			`"libraries": []`,
			`"libraries": [{"build_id": "77b6", "symbols": {"SSL_read": 1}}]`,
			"changes which library builds"},
	} {
		t.Run(name, func(t *testing.T) {
			added, refused := additive(current, replaced(t, one.old, one.new))
			if !strings.Contains(refused, one.because) {
				t.Errorf("the candidate is refused %q, want a reason naming %q", refused, one.because)
			}
			if len(added) != 0 {
				t.Errorf("a refused candidate still names %v as added", added)
			}
		})
	}
}

// One forbidden change refuses the whole candidate, addition included.
func TestAnAdditionBundledWithARemovalIsRefusedWhole(t *testing.T) {
	added, refused := additive(loaded(t, inForce), replaced(t, workerTarget, batchTarget))
	if !strings.Contains(refused, "removes target worker") || len(added) != 0 {
		t.Errorf("a candidate adding batch and removing worker is refused %q with %v added, want the "+
			"whole candidate refused for the removal", refused, added)
	}
}

// What the command read crosses the control directory whole: the session
// cannot re-read it after dropping capabilities. The resolution is real, of the
// policy in force against a constructed table.
func TestAReloadRequestCrossesTheControlDirectoryWhole(t *testing.T) {
	gateway := process.Process{
		PID: 41, PPID: 1, StartTime: 9001, Executable: "/usr/bin/php",
		Arguments: []string{"php", "/srv/gateway/main.php"}, Cgroup: "/system.slice/gateway.service",
		Numbering: process.NumberingNested, Namespace: admission.Namespace{Device: 4, Inode: 4026531836},
		NamespacePID: 7, Threads: 3,
		Listening: []process.Listener{{Inode: 77, Port: 8443, Address: netip.MustParseAddr("10.0.0.2")}},
	}
	worker := process.Process{PID: 52, PPID: 1, StartTime: 9100, Executable: "/usr/bin/worker",
		Arguments: []string{"worker"}, Cgroup: "/system.slice/worker.service"}
	curl := process.Process{PID: 63, PPID: 41, StartTime: 9200, Executable: "/usr/bin/curl",
		Arguments: []string{"curl"}, Cgroup: "/system.slice/gateway.service"}
	resolution := loaded(t, inForce).Approval.Resolve(process.Host{Table: process.TableOf(gateway, worker, curl)})
	if len(resolution.Selections) < 2 || len(resolution.Denials) < 1 {
		t.Fatalf("wiring, not the property: the resolution holds %d selections and %d denials, want the gateway "+
			"and the worker selected and curl denied, so the encoding below is not measured over a full one",
			len(resolution.Selections), len(resolution.Denials))
	}

	request := reloadRequest{
		Revision:   "sha256:77b6",
		Resolution: resolution,
		Processes:  []process.Process{gateway, worker},
		Read: map[int32]probe.Reading{41: {
			Report: probe.Report{Process: gateway.Identity(), Supported: true, Adapter: "openssl",
				Support: []probe.Support{{Adapter: "openssl", Supported: true, Reason: "libssl.so.3 exports SSL_read",
					Runtime: "OpenSSL 3.0.13", Probes: []probe.Probe{{Symbol: "SSL_read",
						Path: "/proc/41/root/usr/lib/x86_64-linux-gnu/libssl.so.3", Offset: 4096}}}}},
			Library: probe.FileID{Device: 2049, Inode: 1311},
			Libc:    probe.FileID{Device: 2049, Inode: 1200},
			Network: probe.Netns{Device: 4, Inode: 4026531840},
			Exec:    process.Exec{StartTime: 9001, Comm: "php", Cmdline: "php\x00/srv/gateway/main.php\x00"},
		}},
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encode the request: %v", err)
	}
	var back reloadRequest
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatalf("decode the request: %v", err)
	}
	if !reflect.DeepEqual(request, back) {
		t.Errorf("the request did not survive its encoding:\nsent     %+v\nreceived %+v", request, back)
	}
}

// execing is a child running a shell until told to go on, then exec'ing
// another program: same pid, same start, different program. Its name is read
// from /proc directly, not through the reader under test.
func execing(t *testing.T) (int32, func()) {
	t.Helper()
	command := exec.Command("/bin/sh", "-c", "read line; exec /bin/sleep 600.5")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("a pipe to the child: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start the child: %v", err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	pid := int32(command.Process.Pid)
	comm := func() string {
		content, _ := os.ReadFile(filepath.Join(procfs, strconv.Itoa(int(pid)), "comm"))
		return strings.TrimSpace(string(content))
	}
	cmdline := func() string {
		content, _ := os.ReadFile(filepath.Join(procfs, strconv.Itoa(int(pid)), "cmdline"))
		return string(content)
	}
	// Wait for both: exec sets comm before the new cmdline exists, so waiting on
	// comm alone can return an empty cmdline. The cmdline is matched on its leading
	// path, since the shell's own line contains "sleep" too.
	waitFor := func(name, program string) {
		for range 200 {
			if comm() == name && strings.HasPrefix(cmdline(), program+"\x00") {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("pid %d is running %q with the command line %q, not %q running %s, after two seconds",
			pid, comm(), cmdline(), name, program)
	}
	waitFor("sh", "/bin/sh")
	return pid, func() {
		if _, err := stdin.Write([]byte("go\n")); err != nil {
			t.Fatalf("tell pid %d to exec: %v", pid, err)
		}
		waitFor("sleep", "/bin/sleep")
	}
}

// The session re-checks that a process still runs what the command read: the
// same start (a reused pid differs) and the same name and command line (an
// exec changes them).
func TestTheSessionTellsAProcessThatExecedOrWasReplacedFromTheOneTheCommandRead(t *testing.T) {
	pid, execs := execing(t)
	read, err := process.ReadExec(procfs, pid)
	if err != nil {
		t.Fatalf("read what pid %d runs: %v", pid, err)
	}
	if read.Comm != "sh" || !strings.HasPrefix(read.Cmdline, "/bin/sh\x00-c\x00") {
		t.Fatalf("wiring, not the property: pid %d reads as %+v, want the shell before it execs", pid, read)
	}
	p := process.Process{PID: pid, StartTime: read.StartTime}

	if why, same := unchanged(procfs, p, probe.Reading{Exec: read}); !same {
		t.Fatalf("control: a process that did nothing is reported changed: %s", why)
	}

	reused, earlier := p, read
	reused.StartTime++
	earlier.StartTime++
	if why, same := unchanged(procfs, reused, probe.Reading{Exec: earlier}); same || !strings.Contains(why, "started") {
		t.Errorf("a pid held by a process that started at another time is reported %q, unchanged %v, "+
			"want it named as a process that started at another time", why, same)
	}

	execs()
	why, same := unchanged(procfs, p, probe.Reading{Exec: read})
	if same {
		t.Fatalf("pid %d execed after the command read it and is reported unchanged", pid)
	}
	if !strings.Contains(why, "exec") {
		t.Errorf("the change is reported as %q, want it named as an exec", why)
	}
}

// admitting stands in for the attachment. during runs inside Admit, between
// the session's re-checks before and after its write.
type admitting struct {
	during    func()
	admitted  [][]admission.Selection
	retracted [][]admission.Selection
}

func (a *admitting) Close() error                 { return nil }
func (a *admitting) Capability() probe.Capability { return probe.Capability{} }

func (a *admitting) Admit(request probe.Request) (probe.Added, error) {
	a.admitted = append(a.admitted, request.Admit)
	if a.during != nil {
		a.during()
	}
	return probe.Added{Selections: request.Admit}, nil
}

func (a *admitting) Retract(granted []admission.Selection) {
	a.retracted = append(a.retracted, granted)
}

// reloading is a session with one target whose configuration now adds a
// second naming pid, plus the request the reload command would have written.
func reloading(t *testing.T, pid int32) (*daemon, *admitting, reloadRequest) {
	t.Helper()
	table, err := process.Read(procfs)
	if err != nil {
		t.Fatalf("read the processes: %v", err)
	}
	child, found := table.Lookup(pid)
	if !found {
		t.Fatalf("pid %d is not in the table", pid)
	}
	read, err := process.ReadExec(procfs, pid)
	if err != nil {
		t.Fatalf("read what pid %d runs: %v", pid, err)
	}

	directory := t.TempDir()
	document := func(targets ...string) string {
		observer, err := json.Marshal(map[string]any{"log": "stdout", "directory": directory})
		if err != nil {
			t.Fatalf("encode the configuration: %v", err)
		}
		written := strings.Replace(strings.Replace(inForce,
			`{"log": "/var/log/observer/observer.log", "directory": "/var/lib/observer"}`, string(observer), 1),
			gatewayTarget+`,
      `+workerTarget, strings.Join(targets, ", "), 1)
		if strings.Contains(written, "gateway") || !strings.Contains(written, directory) {
			t.Fatal("wiring, not the reload: the configuration still holds the policy in force")
		}
		return written
	}
	kept := `{"name": "kept", "match": {"exe": "/usr/bin/nonexistent-kept"}, "descendants": ` + none + `}`
	match, err := json.Marshal(map[string]any{"exe": child.Executable, "args": child.Arguments[1:]})
	if err != nil {
		t.Fatalf("encode the added target: %v", err)
	}
	added := `{"name": "added", "match": ` + string(match) + `, "descendants": ` + none + `}`
	current := loaded(t, document(kept))
	path := filepath.Join(t.TempDir(), "observer.json")
	if err := os.WriteFile(path, []byte(document(kept, added)), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	candidate, err := policy.Load(path)
	if err != nil {
		t.Fatalf("load the candidate: %v", err)
	}

	attached := &admitting{}
	d := &daemon{policy: current, session: "0123456789abcdef", path: path, attached: attached,
		plan: account.Account{Policy: account.Policy{Revision: current.Revision, Generation: 1}}}
	request := reloadRequest{
		Revision:   candidate.Revision,
		Resolution: candidate.Approval.Resolve(process.Host{Table: process.TableOf(child)}),
		Processes:  []process.Process{child},
		Read: map[int32]probe.Reading{pid: {
			Report: probe.Report{Process: child.Identity(), Supported: true, Adapter: "openssl",
				Support: []probe.Support{{Adapter: "openssl", Supported: true,
					Reason: "stands in for a library the session attached"}}},
			Exec: read,
		}},
	}
	if !slices.ContainsFunc(request.Resolution.Selections, func(one admission.Selection) bool {
		return one.ObserverPID == pid && one.Provenance.Target == "added"
	}) {
		t.Fatalf("wiring, not the property: the candidate's resolution does not select pid %d for target added: %+v",
			pid, request.Resolution.Targets)
	}
	return d, attached, request
}

// A reload writes a grant only for a process still running what the command
// read, re-checked before and after the write: an exec before is refused, one
// during is taken back, and every record says the window is narrowed, not
// closed.
func TestAReloadWritesAGrantOnlyForAProcessStillRunningWhatTheCommandRead(t *testing.T) {
	encode := func(t *testing.T, request reloadRequest) []byte {
		t.Helper()
		content, err := json.Marshal(request)
		if err != nil {
			t.Fatalf("encode the request: %v", err)
		}
		return content
	}
	names := func(lines []string, pid int32, word string) bool {
		return slices.ContainsFunc(lines, func(line string) bool {
			return strings.HasPrefix(line, "pid "+strconv.Itoa(int(pid))+":") && strings.Contains(line, word)
		})
	}
	bounded := func(t *testing.T, record reloadRecord) {
		t.Helper()
		if !strings.Contains(record.Bound, "open against exec") {
			t.Errorf("the record says of its window %q, want it named open against exec", record.Bound)
		}
	}

	t.Run("a process that did nothing is admitted and nothing is taken back", func(t *testing.T) {
		pid, _ := execing(t)
		d, attached, request := reloading(t, pid)
		record := d.reload(time.Now(), encode(t, request))
		if record.Outcome != "activated" || record.Admitted != 1 || len(attached.admitted) != 1 ||
			len(attached.retracted) != 0 {
			t.Errorf("the reload answered %+v, wrote %v and took back %v, want pid %d admitted once and "+
				"nothing taken back", record, attached.admitted, attached.retracted, pid)
		}
		bounded(t, record)
	})

	t.Run("an exec after the command read it is refused and nothing is written", func(t *testing.T) {
		pid, execs := execing(t)
		d, attached, request := reloading(t, pid)
		execs()
		record := d.reload(time.Now(), encode(t, request))
		if record.Admitted != 0 || len(attached.admitted) != 0 {
			t.Errorf("a process that execed after the command read it was written: %+v, wrote %v",
				record, attached.admitted)
		}
		if !names(record.Skipped, pid, "exec") {
			t.Errorf("the record skips %v, want pid %d named as having execed", record.Skipped, pid)
		}
		bounded(t, record)
	})

	t.Run("an exec while the grant is written is taken back", func(t *testing.T) {
		pid, execs := execing(t)
		d, attached, request := reloading(t, pid)
		attached.during = execs
		record := d.reload(time.Now(), encode(t, request))
		if len(attached.admitted) != 1 {
			t.Fatalf("wiring, not the property: the session wrote %d times, so there is no write to take back",
				len(attached.admitted))
		}
		if len(attached.retracted) != 1 || len(attached.retracted[0]) != 1 ||
			attached.retracted[0][0].ObserverPID != pid {
			t.Errorf("the session took back %v, want exactly pid %d's grant", attached.retracted, pid)
		}
		if record.Admitted != 0 || !names(record.Retracted, pid, "exec") {
			t.Errorf("the reload answered %+v, want nothing admitted and pid %d named as taken back", record, pid)
		}
		bounded(t, record)
	})

	t.Run("a configuration changed after the command read it is refused whole", func(t *testing.T) {
		pid, _ := execing(t)
		d, attached, request := reloading(t, pid)
		request.Revision = "sha256:" + strings.Repeat("0", 64)
		record := d.reload(time.Now(), encode(t, request))
		if record.Outcome != "refused" || !strings.Contains(record.Reason, "changed") || len(attached.admitted) != 0 {
			t.Errorf("a request read from another revision of the configuration answered %+v and wrote %v, "+
				"want it refused whole", record, attached.admitted)
		}
	})
}
