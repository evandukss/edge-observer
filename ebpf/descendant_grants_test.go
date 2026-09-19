//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
)

func TestExistingDescendantsRequireTheChosenMode(t *testing.T) {
	for _, mode := range []admission.Mode{admission.ModeNone, admission.ModeExisting, admission.ModeFollow} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			parentPID, parentPort, childPID, childPort := servingFamily(t)
			parent := loaded(t, parentPID)
			selected := admit(parent)
			selected.Mode = mode
			session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, parent), Admit: []admission.Selection{selected}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = session.Close() }()
			familyRequest(t, parentPort, "/mode-root-control")
			familyRequest(t, childPort, "/mode-existing-child")
			got := drain(session, 100*time.Millisecond)
			control := attribution(got, "/mode-root-control")
			if control == nil || control.PID != parentPID {
				t.Fatal("selected root control was not captured with its own identity")
			}
			child := attribution(got, "/mode-existing-child")
			if mode == admission.ModeNone {
				if child != nil {
					t.Errorf("roots-only policy read an existing child's peer-confirmed transfer: %+v", child)
				}
			} else if child == nil || child.PID != childPID || child.Generation == control.Generation {
				t.Errorf("%s did not capture the existing child with a distinct instance: %+v", mode, child)
			}
		})
	}
}

func TestExecEndsTheGrantAndFailedExecPreservesIt(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(fmt.Sprintf("success=%t", success), func(t *testing.T) {
			source := immediateForkSource()
			target := `"/no-such-independent-test-image"`
			if success {
				target = "argv[0]"
			}
			source = strings.Replace(source, "if (command[0] == 'P') {", `if (command[0] == 'X') {
			execl(`+target+`, argv[0], argv[1], NULL);
			printf("exec-failed\n");
		} else if (command[0] == 'P') {`, 1)
			port, received := independentPeer(t)
			actor := independentActor(t, source, port)
			parent := loaded(t, int32(actor.command.Process.Pid))
			session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, parent), Admit: authorise(parent)})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = session.Close() }()
			transfer := func() captured {
				if _, err := io.WriteString(actor.input, "P\n"); err != nil {
					t.Fatal(err)
				}
				actorLine(t, actor, "parent 0\n")
				peerReceived(t, received, "/independent-parent")
				return drain(session, 100*time.Millisecond)
			}
			control := attribution(transfer(), "/independent-parent")
			if control == nil {
				t.Fatal("pre-exec control was not captured")
			}
			if _, err := io.WriteString(actor.input, "X\n"); err != nil {
				t.Fatal(err)
			}
			if success {
				actorLine(t, actor, "ready\n")
			} else {
				actorLine(t, actor, "exec-failed\n")
			}
			got := attribution(transfer(), "/independent-parent")
			if success && got != nil {
				t.Errorf("successful exec read the new image before restart activated approval: %+v", got)
			}
			if !success && (got == nil || got.Generation != control.Generation) {
				t.Errorf("failed exec lost or replaced the continuing execution's grant: %+v", got)
			}
			if success {
				if err := session.Close(); err != nil {
					t.Fatal(err)
				}
				current := loaded(t, parent.PID)
				session, err = ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, current), Admit: authorise(current)})
				if err != nil {
					t.Fatal(err)
				}
				if resumed := attribution(transfer(), "/independent-parent"); resumed == nil || resumed.NamespacePID != current.NamespacePID {
					t.Errorf("restart did not activate the explicitly selected post-exec image: %+v", resumed)
				}
			}
		})
	}
}

// The policy still requires the grant to survive; the reported limit is
// acceptable only when the continuing execution is named.
func TestLeaderExitNamesTheStillRunningExecutionItStoppedObserving(t *testing.T) {
	source := immediateForkSource()
	prefix, _, _ := strings.Cut(source, "int main(int argc")
	source = prefix + `
static void *worker(void *unused) {
	char command[8];
	if (!fgets(command, sizeof(command), stdin)) return NULL;
	printf("worker %d\n", transfer("/independent-surviving-thread")); fflush(stdout);
	while (fgets(command, sizeof(command), stdin)) {}
	return NULL;
}
int main(int argc, char **argv) {
	if (argc != 2) return 10;
	port = atoi(argv[1]);
	context = SSL_CTX_new(TLS_client_method());
	if (!context) return 11;
	SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
	printf("ready\n"); fflush(stdout);
	char command[8];
	if (!fgets(command, sizeof(command), stdin)) return 12;
	printf("parent %d\n", transfer("/independent-parent")); fflush(stdout);
	if (!fgets(command, sizeof(command), stdin)) return 13;
	pthread_t thread;
	if (pthread_create(&thread, NULL, worker, NULL) != 0) return 14;
	pthread_exit(NULL);
}
`
	port, received := independentPeer(t)
	actor := independentActor(t, source, port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, parent), Admit: authorise(parent)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	if _, err := io.WriteString(actor.input, "P\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "parent 0\n")
	peerReceived(t, received, "/independent-parent")
	control := attribution(drain(session, 100*time.Millisecond), "/independent-parent")
	if control == nil {
		t.Fatal("leader's approved control was not captured")
	}
	admitted := independentAdmittedIdentity(t, session, parent)
	if control.Generation != admitted.Generation {
		t.Fatalf("pre-exit transfer generation %d differs from admitted generation %d", control.Generation, admitted.Generation)
	}
	if _, err := io.WriteString(actor.input, "L\n"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", parent.PID))
		if err != nil {
			t.Fatal(err)
		}
		_, suffix, found := strings.Cut(string(stat), ") ")
		if found && strings.HasPrefix(suffix, "Z ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("group leader did not exit; surviving-thread state was not established")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := io.WriteString(actor.input, "G\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "worker 0\n")
	peerReceived(t, received, "/independent-surviving-thread")
	got := drain(session, 100*time.Millisecond)
	count := 0
	for _, event := range got.events {
		if event.Kind == ebpf.Transfer && event.Direction == fragment.Sent && strings.Contains(string(event.Payload), "/independent-surviving-thread") {
			count++
			if event.PID != parent.PID || event.Generation != control.Generation {
				t.Errorf("surviving worker changed execution identity: %+v", event)
			}
		}
	}
	if count != 0 {
		t.Errorf("reported-limit state captured %d surviving-thread transfers, want 0; revisit the placed limit if the policy repair has landed", count)
	}
	independentWithdrawal(t, session, admitted, ebpf.GrantEndedWhileRunning)
}
