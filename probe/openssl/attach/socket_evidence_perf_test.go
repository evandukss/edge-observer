//go:build attach

package attach_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/privilege"
)

const socketEvidencePerfChild = "OBSERVER_SOCKET_EVIDENCE_PERF_CHILD"

// Mount changes and capability loss happen only in an isolated child, compiled
// without cgo so Drop has the shipped binary's all-thread semantics.
func TestSocketEvidenceWorksWithoutTracefsAfterCapabilityDrop(t *testing.T) {
	if os.Getenv(socketEvidencePerfChild) != "1" {
		binary := filepath.Join(t.TempDir(), "socket-evidence-perf.test")
		build := exec.Command("go", "test", "-c", "-tags", "attach", "-o", binary, ".")
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build capability-drop child: %v\n%s", err, out)
		}
		child := exec.Command(binary, "-test.run=^TestSocketEvidenceWorksWithoutTracefsAfterCapabilityDrop$", "-test.timeout=60s")
		child.Env = append(os.Environ(), socketEvidencePerfChild+"=1")
		child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
		if out, err := child.CombinedOutput(); err != nil {
			// The child is a whole test binary: its exit status says something in it
			// failed, never what. Its own output below says what failed.
			t.Fatalf("the capability-drop child exited: %v. Its exit status does not say WHICH of "+
				"its assertions failed, and the tracefs-absent property is only one of them - read "+
				"its own failures:\n%s", err, out)
		}
		return
	}
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	// Hide both tracefs locations with read-only empty filesystems, so creating a
	// tracefs event fails even as root.
	for _, path := range []string{"/sys/kernel/tracing", "/sys/kernel/debug"} {
		if err := syscall.Mount("none", path, "tmpfs", syscall.MS_RDONLY, "size=4096"); err != nil {
			t.Fatal(err)
		}
	}
	assertAbsent := func() {
		for _, path := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
			if _, err := os.Stat(filepath.Join(path, "uprobe_events")); !os.IsNotExist(err) {
				t.Fatalf("tracefs is accessible at %s: %v", path, err)
			}
		}
	}
	assertAbsent()
	a := socketEvidence(t)
	a.established(t)
	v6 := socketEvidenceOnNetwork(t, false, "tcp6")
	v6.established(t)
	if err := privilege.Drop(); err != nil {
		t.Fatal(err)
	}
	threads, err := os.ReadDir("/proc/self/task")
	if err != nil || len(threads) == 0 {
		t.Fatalf("read capability-drop witnesses: %v", err)
	}
	for _, thread := range threads {
		status, err := os.ReadFile(filepath.Join("/proc/self/task", thread.Name(), "status"))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(status), "\n") {
			for _, field := range []string{"CapEff:", "CapPrm:", "CapInh:"} {
				if strings.HasPrefix(line, field) && strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, field)), "0") != "" {
					t.Fatalf("thread %s retains %s", thread.Name(), line)
				}
			}
		}
	}
	for _, actor := range []*socketEvidenceActor{a, v6} {
		one, reply := actor.call(t, 7)
		actor.witness(t, 0, int(reply[3]))
		if capability := actor.live.Capability(); !capability.SocketEvidence || (actor == v6 && !capability.IPv6) {
			t.Errorf("perf attachment with no tracefs did not establish family coverage: %+v", capability)
		}
		if one.State != connection.Established || one.Basis != connection.ConfirmedInCall {
			t.Errorf("required send hooks did not correlate direct I/O after capability drop: %+v", one)
		}
		expectSocketPeer(t, one, actor.peers[0])
		if _, err := actor.peers[0].Write([]byte{'R'}); err != nil {
			t.Fatal(err)
		}
		received, _ := actor.call(t, 20)
		if received.State != connection.Established || received.Basis != connection.ConfirmedInCall {
			t.Errorf("required receive hooks did not correlate direct I/O after capability drop: %+v", received)
		}
		file, _ := actor.call(t, 4)
		if file.State != connection.Unknown || file.Reason != connection.OperationWasNotASocket {
			t.Errorf("required file classifier did not distinguish a file after capability drop: %+v", file)
		}
	}
	assertAbsent()
}
