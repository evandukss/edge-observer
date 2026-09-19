//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
)

func independentParentControl(t *testing.T, actor *armingProcess, session *ebpf.Session, received <-chan string) {
	t.Helper()
	if _, err := io.WriteString(actor.input, "P\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "parent 0\n")
	peerReceived(t, received, "/independent-parent")
	if attribution(drain(session, 100*time.Millisecond), "/independent-parent") == nil {
		t.Fatal("approved parent control was not captured")
	}
}

func TestAlreadyExitedChildHasNoGrantBeforeAnyReconciliation(t *testing.T) {
	port, received := independentPeer(t)
	actor := independentActor(t, immediateForkSource(), port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: append(points(t, parent), independentForkPoint(t, parent)), Admit: authorise(parent)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	independentParentControl(t, actor, session, received)
	if _, err := io.WriteString(actor.input, "F\n"); err != nil {
		t.Fatal(err)
	}
	line, err := actor.output.ReadString('\n')
	var child int32
	if _, scanErr := fmt.Sscanf(line, "child %d", &child); err != nil || scanErr != nil || child <= 0 {
		t.Fatalf("child identity: %q: %v, %v", line, err, scanErr)
	}
	actorLine(t, actor, "before-parent-return 0\n")
	actorLine(t, actor, fmt.Sprintf("parent-returned %d\n", child))
	peerReceived(t, received, "/independent-immediate-child")
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", child)); !os.IsNotExist(err) {
		t.Fatalf("child not reaped before admission completed: %v", err)
	}
	present, err := ebpf.IndependentKernelGrantPresent(session, admission.Instance{Namespace: parent.Namespace, PID: child})
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Error("already-reaped child still has a kernel grant before an observer query can reconcile it")
	}

}

const independentNewNamespaceMain = `
#include <sched.h>
int main(int argc, char **argv) {
 if(argc!=2) return 10;
 port=atoi(argv[1]); context=SSL_CTX_new(TLS_client_method());
 if(!context) return 11;
 SSL_CTX_set_verify(context,SSL_VERIFY_NONE,NULL);
 printf("ready\n"); fflush(stdout);
 pid_t child=0; char command[8]; int gate[2];
 while(fgets(command,sizeof(command),stdin)) {
  if(command[0]=='P') printf("parent %d\n",transfer("/independent-parent"));
  else if(command[0]=='N') {
   if(pipe(gate) || unshare(CLONE_NEWPID)) return 30;
   child=fork(); if(child<0) return 31;
   if(child==0) { char start; if(read(gate[0],&start,1)!=1) _exit(33); int result=transfer("/independent-new-namespace"); printf("namespace-transfer %d\n",result); fflush(stdout); if(result) _exit(result); if(read(gate[0],&start,1)<0) _exit(34); _exit(0); }
   printf("namespace-child %d\n",child);
  } else if(command[0]=='G') {
   printf("resumed\n"); fflush(stdout);
   if(write(gate[1],"G",1)!=1) return 32;
  }
  fflush(stdout);
 }
 return 0;
}
`

func TestUnenumeratedNamespaceIsNamedSeparatelyFromAnExitedChild(t *testing.T) {
	port, received := independentPeer(t)
	actor := independentActor(t, "#define _GNU_SOURCE\n"+independentTransferSource+independentNewNamespaceMain, port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: append(points(t, parent), independentForkPoint(t, parent)), Admit: authorise(parent)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	independentParentControl(t, actor, session, received)
	childPID, err := actor.child('N', "namespace-child")
	if err != nil {
		t.Fatal(err)
	}
	waitActorState(t, childPID, "S")
	child := loaded(t, childPID)
	if child.Namespace == parent.Namespace || child.NamespacePID != 1 {
		t.Fatalf("child did not enter a new active pid namespace: %+v", child)
	}
	if _, err := io.WriteString(actor.input, "G\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "resumed\n")
	actorLine(t, actor, "namespace-transfer 0\n")
	peerReceived(t, received, "/independent-new-namespace")
	if got := attribution(drain(session, 100*time.Millisecond), "/independent-new-namespace"); got != nil {
		t.Errorf("never-enumerated namespace was read: %+v", got)
	}
	present, err := ebpf.IndependentKernelGrantPresent(session, child.Instance())
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Error("never-enumerated child namespace received a kernel grant")
	}
	refused, err := session.Refusals()
	if err != nil {
		t.Fatal(err)
	}
	// The counter is the child one: a child created in an unenumerated namespace
	// is refused in the program (ChildNamespaceUnenumerated), whereas
	// NamespaceUnenumerated is an instance's own namespace, refused in userspace,
	// and would read zero in Counted. Nothing reaches Named: the child was never
	// admitted. The Named arm stays for a per-instance record, should one exist.
	named := refused.Counted[ebpf.ChildNamespaceUnenumerated] > 0
	for _, one := range refused.Named {
		if one.Selection.Instance.Namespace == child.Namespace && one.Reason == ebpf.NamespaceUnenumerated {
			named = true
		}
	}
	if !named {
		t.Errorf("live child in an unenumerated namespace has no specific dynamic refusal reason: %+v", refused)
	}
}

func exerciseIndependentExitBeforeAdmission(t *testing.T) {
	port, received := independentPeer(t)
	source := strings.Replace(heldFamilySource(), "if (child != 0) return child;", "if (child != 0) { int status; if(waitpid(child,&status,WUNTRACED)!=child || !WIFSTOPPED(status)) exit(30); return child; }", 1)
	source = strings.Replace(source, "if (command[0] == 'P') {", `if (command[0] == 'T') {
  transient_child=held_child(0); printf("transient %d\n",transient_child);
 } else if (command[0] == 'X') {
  kill(transient_child,SIGCONT); int status;
  if(waitpid(transient_child,&status,0)!=transient_child) return 31;
  printf("transient-exited %d\n",status);
 } else if (command[0] == 'P') {`, 1)
	actor := independentActor(t, source, port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	runtime.LockOSThread()
	listener, err := installArmingListener()
	if err != nil {
		t.Fatal(err)
	}
	coordinated := coordinateArming(listener, actor)
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: append(points(t, parent), independentForkPoint(t, parent)), Admit: authorise(parent)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	var children armingChildren
	select {
	case children = <-coordinated.children:
	default:
		t.Fatal("adoption never opened the independently controlled child-creation window")
	}
	select {
	case <-coordinated.exited:
	default:
		t.Fatal("child did not exit between the adoption reading and its allowlist write")
	}
	select {
	case err := <-coordinated.errors:
		t.Fatal(err)
	default:
	}
	independentParentControl(t, actor, session, received)
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", children.transient)); !os.IsNotExist(err) {
		t.Fatalf("transient child not reaped: %v", err)
	}
	present, err := ebpf.IndependentKernelGrantPresent(session, admission.Instance{Namespace: parent.Namespace, PID: children.transient})
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Error("child reaped between adoption's reading and write retained a kernel grant")
	}
	refused, err := session.Refusals()
	if err != nil {
		t.Fatal(err)
	}
	named := false
	for _, one := range refused.Named {
		if one.Selection.Instance.Namespace == parent.Namespace && one.Selection.Instance.PID == children.transient && one.Reason == ebpf.GoneBeforeAdmission {
			named = true
		}
	}
	if !named {
		t.Errorf("child gone before admission was not named with its own refusal reason: %+v", refused)
	}
	if err := actor.finish('G', "live"); err != nil {
		t.Fatal(err)
	}
	peerReceived(t, received, "/independent-held-child")
	if attribution(drain(session, 100*time.Millisecond), "/independent-held-child") == nil {
		t.Fatal("the live child staged beside the exiting child was not captured")
	}
}

func TestChildGoneBetweenAdoptionReadAndWriteIsNamed(t *testing.T) {
	const environment = "OBSERVER_INDEPENDENT_EXIT_HELPER"
	if os.Getenv(environment) == "1" {
		exerciseIndependentExitBeforeAdmission(t)
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestChildGoneBetweenAdoptionReadAndWriteIsNamed$", "-test.v", "-test.timeout=45s")
	command.Env = append(os.Environ(), environment+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("exit-before-admission property failed in its syscall-isolated process: %v\n%s", err, output)
	}
}
