package ebpf

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/process"
)

// confirmReader names the pid a child of this test confirms, running as a user
// the pid does not belong to. It is set only for that child.
const confirmReader = "OBSERVER_CONFIRM_READER"

// A reload admits after capabilities are dropped, when another owner's
// executable is closed to the session. The confirm compares a start, readable
// by anyone: an unchanged process confirms, a different start is a reused
// number, and a gone process is reported gone, never as a changed identity.
// The first case needs a reader the executable is closed to; the attach
// suite's privileged container grants CAP_SYS_PTRACE, so it runs in a child
// started as another user.
func TestConfirmChecksTheStartAnyoneMayReadAndNamesAFailedReadForWhatItIs(t *testing.T) {
	if pid := os.Getenv(confirmReader); pid != "" {
		confirmedAsAnotherUser(t, pid)
		return
	}

	sleeper := exec.Command("/bin/sleep", "600.75")
	if err := sleeper.Start(); err != nil {
		t.Fatalf("start a process: %v", err)
	}
	t.Cleanup(func() {
		_ = sleeper.Process.Kill()
		_ = sleeper.Wait()
	})
	pid := int32(sleeper.Process.Pid)
	for attempt := 0; ; attempt++ {
		cmdline, err := os.ReadFile(filepath.Join(defaultProcFS, strconv.Itoa(int(pid)), "cmdline"))
		if err == nil && string(cmdline) == "/bin/sleep\x00600.75\x00" {
			break
		}
		if attempt == 200 {
			t.Fatalf("pid %d is not running sleep after two seconds", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
	read, err := process.ReadExec(defaultProcFS, pid)
	if err != nil {
		t.Fatalf("read the start of pid %d: %v", pid, err)
	}

	child := exec.Command(copiedForAnotherUser(t), "-test.run=^TestConfirmChecksTheStartAnyoneMayReadAndNamesAFailedReadForWhatItIs$",
		"-test.v", "-test.count=1")
	child.Env = append(os.Environ(), confirmReader+"="+strconv.Itoa(int(pid)))
	child.Dir = os.TempDir()
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	out, err := child.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS") {
		t.Errorf("confirming pid %d as another user: %v\n%s", pid, err, out)
	}

	s := &Session{}
	if reason, _ := s.confirm(approvedAs(pid, read.StartTime+1)); reason != IdentityChanged {
		t.Errorf("a pid held by a process of another start is refused as %q, want %q", reason, IdentityChanged)
	}
	_ = sleeper.Process.Kill()
	_ = sleeper.Wait()
	if reason, _ := s.confirm(approvedAs(pid, read.StartTime)); reason != GoneBeforeAdmission {
		t.Errorf("a process that has gone is refused as %q, want %q", reason, GoneBeforeAdmission)
	}
}

// confirmedAsAnotherUser is the child's half: the process's executable is closed
// to this reader, and the confirm still confirms it by its start.
func confirmedAsAnotherUser(t *testing.T, number string) {
	parsed, err := strconv.Atoi(number)
	if err != nil {
		t.Fatalf("the parent named %q as the pid to confirm", number)
	}
	pid := int32(parsed)
	directory := filepath.Join(defaultProcFS, number)
	if _, err := os.Readlink(filepath.Join(directory, "exe")); err == nil {
		t.Fatalf("precondition: pid %d's executable is readable to uid %d, so the confirm below is not measured "+
			"against the read the session is refused", pid, os.Getuid())
	}
	read, err := process.ReadExec(defaultProcFS, pid)
	if err != nil {
		t.Fatalf("read the start of pid %d as uid %d: %v", pid, os.Getuid(), err)
	}
	if reason, err := (&Session{}).confirm(approvedAs(pid, read.StartTime)); err != nil {
		t.Errorf("an unchanged process whose executable is closed to the reader is refused: %s: %v", reason, err)
	}
}

func approvedAs(pid int32, start uint64) admission.Selection {
	return admission.Selection{ObserverPID: pid, Instance: admission.Instance{PID: pid,
		Start: admission.Determinate(admission.BootTicks(start))}}
}

// copiedForAnotherUser is this test binary where another user can run it (the
// toolchain builds it in an owner-only directory).
func copiedForAnotherUser(t *testing.T) string {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatalf("find this test binary: %v", err)
	}
	directory, err := os.MkdirTemp("", "confirm-reader-")
	if err != nil {
		t.Fatalf("make a directory for the reader: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatalf("open %s to another user: %v", directory, err)
	}
	from, err := os.Open(source)
	if err != nil {
		t.Fatalf("open %s: %v", source, err)
	}
	defer func() { _ = from.Close() }()
	target := filepath.Join(directory, "ebpf.test")
	to, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatalf("create %s: %v", target, err)
	}
	if _, err := io.Copy(to, from); err != nil {
		_ = to.Close()
		t.Fatalf("copy the test binary: %v", err)
	}
	if err := to.Close(); err != nil {
		t.Fatalf("close %s: %v", target, err)
	}
	return target
}
