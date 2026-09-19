//go:build attach

package ebpf_test

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/process"
)

// A process in its own pid namespace numbers its children there, and a number
// names different processes in different namespaces. So the allowlist is keyed
// by namespace and number, and bpf_get_ns_current_pid_tgid answers only for the
// task's own active namespace. This fixture runs in its own namespace,
// transfers, and forks a child that transfers under a number meaningless
// outside it.
const namespacedForker = `
import http.client, os, ssl, sys

port = int(sys.argv[1])

def ask(path):
    context = ssl._create_unverified_context()
    connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=10)
    connection.request("GET", path)
    connection.getresponse().read()
    connection.close()

print("ready", os.getpid(), flush=True)
sys.stdin.readline()
ask("/ns-parent")
child = os.fork()
if child == 0:
    ask("/ns-child")
    os._exit(0)
os.waitpid(child, 0)
print("child", child, flush=True)
print("done", flush=True)
# Held open until the test is finished with it: the exit hook removes a process
# from the allowlist as it goes, so a fixture that ran to the end would leave a
# map with nothing in it and the reading below would measure that instead.
sys.stdin.readline()
`

// namespacedProcess starts the fixture above in its own pid namespace and
// returns its pid here, its line reader, and the way to tell it to talk.
func namespacedProcess(t *testing.T, port int) (int32, *bufio.Reader, func()) {
	t.Helper()

	script := filepath.Join(t.TempDir(), "namespaced.py")
	if err := os.WriteFile(script, []byte(namespacedForker), 0o600); err != nil {
		t.Fatalf("write the namespaced fixture: %v", err)
	}

	command := exec.Command("python3", script, fmt.Sprint(port))
	// Its own namespace is the point; otherwise it is an ordinary process on this
	// host.
	command.SysProcAttr = &unix.SysProcAttr{Cloneflags: unix.CLONE_NEWPID}

	send, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start a process in a pid namespace of its own: %v", err)
	}
	t.Cleanup(func() {
		_ = send.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	said := bufio.NewReader(out)
	line, err := said.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "ready") {
		t.Fatalf("the namespaced fixture did not come up: %q %v", line, err)
	}
	return int32(command.Process.Pid), said, func() {
		if _, err := io.WriteString(send, "go\n"); err != nil {
			t.Fatalf("tell the namespaced fixture to talk: %v", err)
		}
	}
}

func TestAnInstanceInItsOwnPIDNamespaceIsAdmittedAndAttributedByThatNamespacesNumbers(t *testing.T) {
	_, port := serving(t)
	pid, said, talk := namespacedProcess(t, port)

	parent := loaded(t, pid)
	if parent.Numbering != process.NumberingNested {
		t.Fatalf("the fixture is %v, and this test measures a process that numbers its "+
			"children differently from the observer's own numbering", parent.Numbering)
	}
	if !parent.Namespace.Known() {
		t.Fatal("the fixture's pid namespace could not be read, so nothing here can be resolved in it")
	}
	if parent.NamespacePID == parent.PID {
		t.Fatalf("the fixture is numbered %d in its own namespace and %d here, so this run stages "+
			"nothing about two numberings", parent.NamespacePID, parent.PID)
	}

	requested := append([]ebpf.Point{forkPoint(t, parent)}, points(t, parent)...)
	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  requested,
		Admit:   authorise(parent),
	})
	if err != nil {
		t.Fatalf("attach to a process in a pid namespace of its own: %v", err)
	}
	defer func() { _ = session.Close() }()

	talk()
	child := int32(0)
	for {
		line, err := said.ReadString('\n')
		if err != nil {
			t.Fatalf("the namespaced fixture stopped before it finished: %v", err)
		}
		if number, found := strings.CutPrefix(strings.TrimSpace(line), "child "); found {
			parsed, err := strconv.ParseInt(number, 10, 32)
			if err != nil {
				t.Fatalf("the fixture named its child %q: %v", number, err)
			}
			child = int32(parsed)
		}
		if strings.HasPrefix(line, "done") {
			break
		}
	}
	if child <= 0 {
		t.Fatal("the fixture forked no child, so nothing was named in its own numbering")
	}

	captured := drain(session, 700*time.Millisecond)

	// The control: the approved process itself is observed.
	if !containsSubstring(captured.plaintext(fragment.Sent), "/ns-parent") {
		t.Fatal("the approved process's own plaintext did not appear, so this run measures " +
			"nothing about what it forks")
	}

	// The child transfers under a number of its parent's namespace, and is
	// admitted and attributed under that number, not under whatever holds it here.
	found := attribution(captured, "/ns-child")
	if found == nil {
		t.Fatalf("the child of an approved process in %s moved plaintext and none of it appeared",
			parent.Namespace)
	}
	if found.Namespace != parent.Namespace {
		t.Errorf("the child's plaintext is attributed to %s and its parent is in %s",
			found.Namespace, parent.Namespace)
	}
	if found.NamespacePID != child {
		t.Errorf("the child's plaintext is attributed to pid %d in %s, and the fixture numbered "+
			"its child %d there", found.NamespacePID, found.Namespace, child)
	}
	if !found.Generation.FromKernel() {
		t.Errorf("a child the fork hook admitted carries %s, which is not one the kernel stamped",
			found.Generation)
	}

	// The parent's own entry, read back from the allowlist.
	held, err := session.Admissions()
	if err != nil {
		t.Fatalf("read back what the session admitted: %v", err)
	}
	var admitted *admission.Selection
	for i := range held {
		if held[i].Instance.Namespace == parent.Namespace && held[i].Instance.PID == parent.NamespacePID {
			admitted = &held[i]
		}
	}
	if admitted == nil {
		t.Fatalf("the allowlist holds no entry for pid %d in %s, which is how the program names "+
			"the approved process", parent.NamespacePID, parent.Namespace)
	}
	if admitted.Kind != admission.ByTarget {
		t.Errorf("the approved process is admitted as %s", admitted.Kind)
	}
	if admitted.Propagation != admission.CanPropagate {
		t.Errorf("the approved process reports %s, and its child was named here", admitted.Propagation)
	}
	if admitted.Instance.Generation.FromKernel() {
		t.Errorf("a process a target named carries %s, which is the kernel's allocator",
			admitted.Instance.Generation)
	}
}

// attribution is the instance one captured transfer carrying want was
// attributed to, or nothing.
func attribution(captured captured, want string) *ebpf.Event {
	for i := range captured.events {
		event := &captured.events[i]
		if event.Kind == ebpf.Transfer && strings.Contains(string(event.Payload), want) {
			return event
		}
	}
	return nil
}

func TestAnInstanceInAPIDNamespaceNobodyEnumeratedIsRefusedAndTheReasonIsNamed(t *testing.T) {
	serverPID, serverPort := serving(t)
	server := loaded(t, serverPID)
	_, port := serving(t)
	pid, said, talk := namespacedProcess(t, port)
	namespaced := loaded(t, pid)

	if namespaced.Namespace == server.Namespace {
		t.Fatalf("the fixture and the control are both in %s, so this run enumerates the "+
			"fixture's namespace after all", server.Namespace)
	}

	// Only the control's namespace is enumerated, so the fixture matches nothing:
	// a live process running the same library is not observed, and this is stated.
	requested := append([]ebpf.Point{forkPoint(t, namespaced)}, points(t, namespaced)...)
	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  requested,
		Admit:   authorise(server),
	})
	if err != nil {
		t.Fatalf("attach with only the control's pid namespace enumerated: %v", err)
	}
	defer func() { _ = session.Close() }()

	talk()
	for {
		line, err := said.ReadString('\n')
		if err != nil {
			t.Fatalf("the namespaced fixture stopped before it finished: %v", err)
		}
		if strings.HasPrefix(line, "done") {
			break
		}
	}
	speaking(t, serverPort).ask(t, "/enumerated-control")

	captured := drain(session, 700*time.Millisecond)

	if !containsSubstring(captured.plaintext(fragment.Received), "/enumerated-control") {
		t.Fatal("the process in the enumerated namespace produced no plaintext, so a refusal " +
			"in the other one would prove nothing")
	}
	for _, text := range append(captured.plaintext(fragment.Sent), captured.plaintext(fragment.Received)...) {
		if strings.Contains(text, "/ns-parent") || strings.Contains(text, "/ns-child") {
			t.Errorf("plaintext from %s, which this session did not enumerate, appeared: %q",
				namespaced.Namespace, text)
		}
	}

	held, err := session.Admissions()
	if err != nil {
		t.Fatalf("read back what the session admitted: %v", err)
	}
	for _, one := range held {
		if one.Instance.Namespace == namespaced.Namespace {
			t.Errorf("the allowlist holds %s, in a namespace nothing here can resolve", one)
		}
	}
}

// A descendant entering its own pid namespace is beyond what the program can
// resolve, so it is not admitted, and the kernel cannot say which process it
// was (every unapproved process resolves in no enumerated namespace too). The
// reconciliation names it from the process table.
func TestADescendantInAPIDNamespaceNobodyEnumeratedIsNamedRatherThanAbsent(t *testing.T) {
	serverPID, _ := serving(t)
	server := loaded(t, serverPID)

	// The admitted instance is this test process; the children, made by one parent
	// in one run, differ only in the thing under test.
	self := settled(t, int32(os.Getpid()))
	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  points(t, server),
		Admit:   authorise(self),
	})
	if err != nil {
		t.Fatalf("attach with this process admitted: %v", err)
	}
	defer func() { _ = session.Close() }()

	beyond := settled(t, aChild(t, true))
	within := settled(t, aChild(t, false))

	if beyond.Namespace == self.Namespace {
		t.Fatalf("the child that was to enter a namespace of its own is in %s, the observer's "+
			"own, so this run stages nothing about an unenumerated one", beyond.Namespace)
	}
	if within.Namespace != self.Namespace {
		t.Fatalf("the control child is in %s and its parent is in %s, so the two children "+
			"differ in more than the namespace", within.Namespace, self.Namespace)
	}

	named, err := session.Reconcile()
	if err != nil {
		t.Fatalf("reconcile what the allowlist holds against the process table: %v", err)
	}

	var found *ebpf.Declined
	for i := range named {
		if named[i].Selection.ObserverPID == beyond.PID {
			found = &named[i]
		}
		if named[i].Selection.ObserverPID == within.PID {
			t.Errorf("pid %d, a child in the enumerated namespace %s, is named as %s",
				within.PID, within.Namespace, named[i].Reason)
		}
	}
	if found == nil {
		t.Fatalf("pid %d is a child of an admitted instance in %s, which this session did not "+
			"enumerate, and the reconciliation named %d instances, none of them it",
			beyond.PID, beyond.Namespace, len(named))
	}
	if found.Reason != ebpf.NamespaceUnenumerated {
		t.Errorf("pid %d in %s is named as %s", beyond.PID, beyond.Namespace, found.Reason)
	}
	if found.Selection.Kind != admission.ByDescent {
		t.Errorf("pid %d was named below pid %d and is recorded as %s",
			beyond.PID, self.PID, found.Selection.Kind)
	}
	parent := found.Selection.Provenance.Parent
	if parent.Namespace != self.Namespace || parent.PID != self.NamespacePID {
		t.Errorf("pid %d is recorded below %v and the instance it was found under is pid %d in %s",
			beyond.PID, parent, self.NamespacePID, self.Namespace)
	}
	// The parent is the admission it was found under, not the number, which may
	// name another process by the time somebody reads it.
	if parent.Generation == 0 {
		t.Errorf("pid %d is recorded below %v, which carries no admission generation", beyond.PID, parent)
	}

	// The account carries it too, for a caller reconciling on a timer.
	held := false
	for _, one := range session.Declined() {
		held = held || one.Selection.ObserverPID == beyond.PID
	}
	if !held {
		t.Errorf("pid %d was named by the reconciliation and is not in what the session declined",
			beyond.PID)
	}
}

// aChild starts a process below this one that outlives the reading, in its own
// pid namespace or this one's.
func aChild(t *testing.T, ownNamespace bool) int32 {
	t.Helper()
	command := exec.Command("sleep", "300")
	if ownNamespace {
		// clone(CLONE_NEWPID) puts the child in the new namespace; unshare would move
		// only this process's later children.
		command.SysProcAttr = &unix.SysProcAttr{Cloneflags: unix.CLONE_NEWPID}
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start a child (own pid namespace: %v): %v", ownNamespace, err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	return int32(command.Process.Pid)
}

// settled is the process at pid once its pid namespace can be read.
func settled(t *testing.T, pid int32) process.Process {
	t.Helper()
	for range 400 {
		table, err := process.Read(procfs)
		if err != nil {
			t.Fatalf("read processes: %v", err)
		}
		if p, ok := table.Lookup(pid); ok && p.Namespace.Known() {
			return p
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid %d never appeared with a pid namespace this run could read", pid)
	return process.Process{}
}
