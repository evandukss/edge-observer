package preflight_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/preflight"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl"
	"github.com/evandukss/edge-observer/process"
)

func catalog(t *testing.T) probe.Catalog {
	t.Helper()

	built, err := probe.NewCatalog(openssl.New())
	if err != nil {
		t.Fatalf("NewCatalog: %v", err)
	}
	return built
}

// approved starts a process that uses OpenSSL, waits until it has loaded it,
// and returns an approval naming it. Its command line takes no password, so
// it is not rewritten after start.
func approved(t *testing.T) (process.Approval, int32) {
	t.Helper()

	command := exec.Command("openssl", "base64")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start openssl, which this test needs on the host: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	pid := int32(command.Process.Pid)
	var previous []string
	for range 200 {
		table, err := process.Read("/proc")
		if err != nil {
			t.Fatalf("Read(/proc): %v", err)
		}
		p, ok := table.Lookup(pid)
		if ok && filepath.Base(p.Executable) == "openssl" && len(p.Arguments) > 1 {
			mappings, err := process.Mappings("/proc", pid)
			if err == nil && len(openssl.Libraries(filepath.Join("/proc", strconv.Itoa(int(pid)), "root"), mappings)) > 0 {
				if slices.Equal(previous, p.Arguments) {
					rule := process.Rule{Executable: p.Executable, Arguments: p.Arguments[1:]}
					return process.Approval{Rules: []process.Rule{rule}}, pid
				}
				previous = p.Arguments
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid %d has not loaded openssl and its libraries after two seconds", pid)
	return process.Approval{}, 0
}

func take(t *testing.T, approval process.Approval) preflight.Report {
	t.Helper()

	report, err := preflight.Take(preflight.Running(), approval, catalog(t))
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	return report
}

func TestTheReportNamesTheKernelItWasTakenOn(t *testing.T) {
	approval, _ := approved(t)
	report := take(t, approval)

	if report.Kernel.Release == "" || strings.HasPrefix(report.Kernel.Release, "unknown") {
		t.Errorf("Kernel.Release = %q", report.Kernel.Release)
	}
	if !strings.Contains(report.Kernel.Version, "Linux") {
		t.Errorf("Kernel.Version = %q, which does not name a kernel", report.Kernel.Version)
	}
	if report.Binary.OS != "linux" || report.Binary.Arch == "" {
		t.Errorf("Binary = %+v", report.Binary)
	}
	if report.TakenAt.IsZero() {
		t.Error("the report says when it was taken nowhere")
	}
}

// Each kernel piece a probe needs is reported found or not found, by path.
func TestTheReportSaysWhereTheKernelExposesTracingAndWhetherItIsThere(t *testing.T) {
	approval, _ := approved(t)
	report := take(t, approval)

	if report.Tracing.BTF.Path == "" {
		t.Error("the report does not say where it looked for the kernel's type information")
	}
	if len(report.Tracing.UprobeEvents) < 2 {
		t.Errorf("%d places checked for the uprobe interface, want both", len(report.Tracing.UprobeEvents))
	}
	for _, file := range report.Tracing.UprobeEvents {
		if file.Path == "" {
			t.Error("a place checked for the uprobe interface is not named")
		}
		if !file.Present && file.Error == "" && file.Size != 0 {
			t.Errorf("%s is absent and has a size", file.Path)
		}
	}
	for _, knob := range []string{report.Tracing.PerfEventParanoid, report.Tracing.PtraceScope, report.Tracing.UnprivilegedBPFDisabled} {
		if knob == "" {
			t.Error("a kernel knob is reported as an empty string, which is neither its value nor a reason it is missing")
		}
	}
}

func TestTheReportSaysWhichCapabilitiesAttachmentNeedsAreHeld(t *testing.T) {
	approval, _ := approved(t)
	report := take(t, approval)

	privilege := report.Privilege
	if privilege.Effective == "" || privilege.Permitted == "" || privilege.Bounding == "" {
		t.Fatalf("Privilege = %+v, want the three masks", privilege)
	}

	held := append(append([]string{}, privilege.Holds...), privilege.Lacks...)
	seen := make(map[string]int, len(held))
	for _, name := range held {
		seen[name]++
	}
	for _, name := range []string{"CAP_BPF", "CAP_PERFMON", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE"} {
		if seen[name] != 1 {
			t.Errorf("%s appears %d times across held and lacked, want once", name, seen[name])
		}
	}
}

func TestAnApprovedProcessIsReportedWithWhatWouldObserveIt(t *testing.T) {
	approval, pid := approved(t)
	report := take(t, approval)

	if len(report.Approved) != 1 {
		t.Fatalf("%d rules reported, want 1", len(report.Approved))
	}
	rule := report.Approved[0]
	if rule.Arguments == 0 {
		t.Error("the rule is reported as naming no arguments")
	}

	var found bool
	for _, matched := range rule.Processes {
		if matched.PID != pid {
			continue
		}
		found = true
		if !matched.Named {
			t.Error("a process a rule matched is reported as a descendant of one")
		}
		if !matched.Support.Supported {
			t.Errorf("a process running OpenSSL is unsupported: %s", matched.Support.Reason())
		}
		if matched.Support.Adapter != "openssl" {
			t.Errorf("Adapter = %q", matched.Support.Adapter)
		}
		if len(matched.Libraries) == 0 {
			t.Error("no OpenSSL library is reported for a process running one")
		}
		if matched.StartTime == 0 {
			t.Error("StartTime = 0, so the process cannot be told from a later one reusing its pid")
		}
	}
	if !found {
		t.Fatalf("pid %d is absent from the report", pid)
	}
}

// The report leaves the host, and command lines hold secrets, so no process's
// arguments - including the rule's own - appear in it.
func TestTheReportCarriesNoProcessArguments(t *testing.T) {
	secret := "preflight-must-not-carry-this-9d31"

	// A shell holding a child keeps its command line as given.
	command := exec.Command("/bin/sh", "-c", "sleep 600", secret)
	if err := command.Start(); err != nil {
		t.Fatalf("start /bin/sh: %v", err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	pid := int32(command.Process.Pid)
	var rule process.Rule
	for range 200 {
		table, err := process.Read("/proc")
		if err != nil {
			t.Fatalf("Read(/proc): %v", err)
		}
		if p, ok := table.Lookup(pid); ok && len(p.Arguments) > 1 && slices.Contains(p.Arguments, secret) {
			rule = process.Rule{Executable: p.Executable, Arguments: p.Arguments[1:]}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rule.Executable == "" {
		t.Fatalf("pid %d does not report the arguments it was started with after two seconds", pid)
	}

	report := take(t, process.Approval{Rules: []process.Rule{rule}})

	// Guard: a report that matched nothing carries no arguments trivially.
	if len(report.Approved) != 1 || len(report.Approved[0].Processes) == 0 {
		t.Fatalf("pid %d was not reported, so there was nothing to leak", pid)
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal the report: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatal("the report carries an argument of an approved process")
	}
	if strings.Contains(string(encoded), "sleep 600") {
		t.Error("the report carries the command line of an approved process")
	}
}

func TestAnApprovalMatchingNothingReportsTheRuleWithNoProcesses(t *testing.T) {
	report := take(t, process.Approval{Rules: []process.Rule{{Executable: "/usr/bin/nothing-runs-this"}}})

	if len(report.Approved) != 1 {
		t.Fatalf("%d rules reported, want 1", len(report.Approved))
	}
	if got := len(report.Approved[0].Processes); got != 0 {
		t.Fatalf("%d processes reported for a rule nothing matched", got)
	}
	if report.Approved[0].Executable != "/usr/bin/nothing-runs-this" {
		t.Errorf("Executable = %q", report.Approved[0].Executable)
	}
}

// A missing path and an unreadable one are different answers.
func TestAPathThatIsNotThereIsReportedAbsentRatherThanUnreadable(t *testing.T) {
	elsewhere := t.TempDir()

	report, err := preflight.Take(preflight.Host{ProcFS: "/proc", SysFS: elsewhere, Debug: elsewhere}, process.Approval{}, catalog(t))
	if err != nil {
		t.Fatalf("Take: %v", err)
	}

	if report.Tracing.BTF.Present {
		t.Errorf("%s is reported present", report.Tracing.BTF.Path)
	}
	if report.Tracing.BTF.Error != "" {
		t.Errorf("a path that is simply not there is reported unreadable: %s", report.Tracing.BTF.Error)
	}
	if !strings.HasPrefix(report.Tracing.BTF.Path, elsewhere) {
		t.Errorf("BTF.Path = %q, want it under %s", report.Tracing.BTF.Path, elsewhere)
	}
}

// A tree that is not a procfs measured nothing, which must not read as a host
// with nothing approved running.
func TestTakeRefusesATreeThatIsNotAProcfs(t *testing.T) {
	empty := t.TempDir()
	if err := os.MkdirAll(filepath.Join(empty, "1"), 0o755); err != nil {
		t.Fatalf("make a process directory: %v", err)
	}

	if _, err := preflight.Take(preflight.Host{ProcFS: empty, SysFS: empty}, process.Approval{}, catalog(t)); err == nil {
		t.Fatal("Take accepted a tree that is not a procfs")
	}
}
