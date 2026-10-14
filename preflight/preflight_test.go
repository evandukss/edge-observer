package preflight_test

import (
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

// The readiness report leaves the host; selected process arguments must not.
func TestTheReportCarriesNoProcessArguments(t *testing.T) {
	secret := "preflight-must-not-carry-this-9d31"

	// A private shell copy lets the rule select only this fixture.
	shell := filepath.Join(t.TempDir(), "sh")
	program, err := os.ReadFile("/bin/sh")
	if err != nil {
		t.Fatalf("read /bin/sh: %v", err)
	}
	if err := os.WriteFile(shell, program, 0o755); err != nil {
		t.Fatalf("write %s: %v", shell, err)
	}
	command := exec.Command(shell, "-c", "sleep 600", secret)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatalf("start %s: %v", shell, err)
	}
	// Killing the group stops the shell's sleep too, which outlives the shell.
	t.Cleanup(func() {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
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

	// Until the shell's child execs sleep it runs the copy with the shell's
	// arguments, so the rule names it as well, and read across that exec it
	// refuses the report. The report is taken once the child runs sleep.
	forked := false
	for range 200 {
		table, err := process.Read("/proc")
		if err != nil {
			t.Fatalf("Read(/proc): %v", err)
		}
		forked = slices.ContainsFunc(table.All(), func(p process.Process) bool {
			return p.PPID == pid && p.Executable != rule.Executable
		})
		if forked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !forked {
		t.Fatalf("wiring, not the property: the child of pid %d is not running sleep after two seconds", pid)
	}

	table, err := process.Read("/proc")
	if err != nil {
		t.Fatal(err)
	}
	approval := process.Approval{Rules: []process.Rule{rule}}
	table, err = approval.SettleArguments("/proc", table)
	if err != nil {
		t.Fatal(err)
	}
	selected := approval.Select(table)
	if !slices.ContainsFunc(selected, func(p process.Process) bool {
		return p.PID == pid && slices.Contains(p.Arguments, secret)
	}) {
		t.Fatal("wiring, not privacy: selected process does not carry the argument sentinel")
	}
	report := preflight.Assess(preflight.Running(), selected, catalog(t))
	matches := 0
	for _, r := range report.Requirements {
		if r.Name == preflight.TLSLibrary && r.PID == pid {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("wiring, not privacy: pid %d has %d TLS judgments, want 1", pid, matches)
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

// Absence is a failed requirement; a failed read leaves the answer unknown.
func TestReadinessDistinguishesAbsentAndUnreadableBTF(t *testing.T) {
	for _, unreadable := range []bool{false, true} {
		t.Run(strconv.FormatBool(unreadable), func(t *testing.T) {
			c := meeting(t)
			p := c.live()
			if got := assess(c, p); got.Verdict != preflight.Ready {
				t.Fatalf("wiring: free control is not ready: %+v", got)
			}
			c.remove("sys/kernel/btf/vmlinux")
			wantStatus, wantVerdict := preflight.Missing, preflight.NotReady
			if unreadable {
				c.remove("sys/kernel/btf")
				c.write("sys/kernel/btf", "not a directory")
				wantStatus, wantVerdict = preflight.Indeterminate, preflight.Undetermined
			}
			_, err := os.Stat(filepath.Join(c.host.SysFS, "kernel/btf/vmlinux"))
			if err == nil || os.IsNotExist(err) == unreadable {
				t.Fatalf("wiring: requested BTF fault not reached: %v", err)
			}
			got := assess(c, p)
			only(t, got, preflight.KernelBTF, wantStatus)
			if got.Verdict != wantVerdict {
				t.Fatalf("BTF fault verdict = %s, want %s", got.Verdict, wantVerdict)
			}
		})
	}
}

func TestReadinessRefusesAnUnmeasuredHost(t *testing.T) {
	c := meeting(t)
	p := c.live()
	if got := assess(c, p); got.Verdict != preflight.Ready {
		t.Fatalf("wiring: free control is not ready: %+v", got)
	}
	c.host.ProcFS = t.TempDir()
	got := assess(c, p)
	if got.Verdict != preflight.Undetermined {
		t.Fatalf("unmeasured host verdict = %s, want undetermined", got.Verdict)
	}
	for _, name := range []string{preflight.KernelRelease, preflight.Capabilities, preflight.ProgramLoad, preflight.TLSLibrary} {
		if r := requirement(t, got, name); r.Status != preflight.Indeterminate {
			t.Errorf("%s = %s, want indeterminate", name, r.Status)
		}
	}
	if c.loads != 1 {
		t.Fatalf("unmeasured host attempted program load: total %d, want only the free control's 1", c.loads)
	}
}
