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
	"github.com/evandukss/edge-observer/process"
)

func heldFamilySource() string {
	return independentTransferSource + `
static pid_t held_child(int moves) {
    pid_t child = fork();
    if (child != 0) return child;
    raise(SIGSTOP);
    _exit(moves ? transfer("/independent-held-child") : 0);
}
int main(int argc, char **argv) {
    if (argc != 2) return 10;
    port = atoi(argv[1]);
    context = SSL_CTX_new(TLS_client_method());
    if (!context) return 11;
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
    printf("ready\n"); fflush(stdout);
    char command[8];
    while (fgets(command, sizeof(command), stdin)) {
        if (command[0] == 'P') {
            printf("parent %d\n", transfer("/independent-parent"));
        } else if (command[0] == 'L') {
            live_child = held_child(1);
            printf("live %d\n", live_child);
        } else if (command[0] == 'G') {
            kill(live_child, SIGCONT);
            int status = 0;
            waitpid(live_child, &status, 0);
            printf("live-exited %d\n", status);
        }
        fflush(stdout);
    }
    return 0;
}
`
}

func waitActorState(t *testing.T, pid int32, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			t.Fatal(err)
		}
		at := strings.LastIndex(string(stat), ") ")
		if at >= 0 && strings.HasPrefix(string(stat)[at+2:], want+" ") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d did not reach state %s", pid, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestFutureDescendantsRequireFollow(t *testing.T) {
	for _, mode := range []admission.Mode{admission.ModeNone, admission.ModeExisting, admission.ModeFollow} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			port, received := independentPeer(t)
			actor := independentActor(t, heldFamilySource(), port)
			parent := loaded(t, int32(actor.command.Process.Pid))
			selected := admit(parent)
			selected.Mode = mode
			session, err := ebpf.Attach(ebpf.Options{
				Program: bpf.Full(), Points: append(points(t, parent), independentForkPoint(t, parent)), Admit: []admission.Selection{selected},
			})
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
				t.Fatal("approved root control was not captured")
			}
			child, err := actor.child('L', "live")
			if err != nil {
				t.Fatal(err)
			}
			waitActorState(t, child, "T")
			if err := actor.finish('G', "live"); err != nil {
				t.Fatal(err)
			}
			peerReceived(t, received, "/independent-held-child")
			got := attribution(drain(session, 100*time.Millisecond), "/independent-held-child")
			if mode != admission.ModeFollow && got != nil {
				t.Errorf("%s read a child born after activation: %+v", mode, got)
			}
			if mode == admission.ModeFollow && (got == nil || got.NamespacePID != child || got.Generation == control.Generation) {
				t.Errorf("follow did not capture its future child with a distinct instance: %+v", got)
			}
		})
	}
}

func TestCgroupMovementDoesNotChangeActivatedGrants(t *testing.T) {
	approvedPID, approvedPort := serving(t)
	unapprovedPID, unapprovedPort := serving(t)
	approved := loaded(t, approvedPID)
	first := fmt.Sprintf("obs-independent-first-%d", os.Getpid())
	second := fmt.Sprintf("obs-independent-second-%d", os.Getpid())
	moveToCgroup(t, first, approvedPID)
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, approved), Admit: authorise(approved)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	familyRequest(t, approvedPort, "/cgroup-before-movement")
	control := attribution(drain(session, 100*time.Millisecond), "/cgroup-before-movement")
	if control == nil {
		t.Fatal("approved control was not captured before cgroup movement")
	}
	moveToCgroup(t, second, approvedPID)
	moveToCgroup(t, first, unapprovedPID)
	familyRequest(t, approvedPort, "/cgroup-approved-moved-out")
	familyRequest(t, unapprovedPort, "/cgroup-unapproved-moved-in")
	got := drain(session, 100*time.Millisecond)
	continuing := attribution(got, "/cgroup-approved-moved-out")
	if continuing == nil || continuing.Generation != control.Generation {
		t.Errorf("moving out revoked or changed the activated grant: %+v", continuing)
	}
	if outside := attribution(got, "/cgroup-unapproved-moved-in"); outside != nil {
		t.Errorf("moving in admitted a non-descendant without selection: %+v", outside)
	}
}

func TestOverlappingTargetsKeepProvenanceAcrossSeparateRestarts(t *testing.T) {
	port, received := independentPeer(t)
	actor := independentActor(t, immediateForkSource(), port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	moveToCgroup(t, fmt.Sprintf("independent-overlap-%d", parent.PID), parent.PID)
	parent = loaded(t, parent.PID)
	root := process.Rule{Executable: parent.Executable, Arguments: []string{fmt.Sprint(port)}}
	family := process.Rule{Cgroup: parent.Cgroup}
	for _, rules := range [][]process.Rule{{root, family}, {root}, {family}} {
		t.Run(fmt.Sprintf("targets=%d/first=%s", len(rules), rules[0].String()), func(t *testing.T) {
			table, err := process.Read(procfs)
			if err != nil {
				t.Fatal(err)
			}
			selected := (process.Approval{Rules: rules}).Selections(table)
			if len(selected) != 1 || selected[0].ObserverPID != parent.PID {
				t.Fatalf("real approval producer did not resolve exactly the controlled process: %+v", selected)
			}
			// Closing the previous session and attaching a fresh one is the
			// restart boundary; no additive reload is used to revoke a grant.
			session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, parent), Admit: selected})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = session.Close() }()
			if _, err := io.WriteString(actor.input, "P\n"); err != nil {
				t.Fatal(err)
			}
			actorLine(t, actor, "parent 0\n")
			peerReceived(t, received, "/independent-parent")
			got := drain(session, 100*time.Millisecond)
			count := 0
			for _, event := range got.events {
				if event.Kind == ebpf.Transfer && event.Direction == fragment.Sent && strings.Contains(string(event.Payload), "/independent-parent") {
					count++
					if event.PID != parent.PID || event.Namespace != parent.Namespace || event.Generation == 0 {
						t.Errorf("overlapping target transfer lost its instance: %+v", event)
					}
				}
			}
			if count != 1 {
				t.Fatalf("%d remaining targets emitted one peer-confirmed transfer %d times", len(rules), count)
			}
			held, err := session.Admissions()
			if err != nil {
				t.Fatal(err)
			}
			provenance := map[int]bool{}
			for _, one := range held {
				if one.Instance.Namespace == parent.Namespace && one.Instance.PID == parent.NamespacePID {
					for _, reason := range one.NamedBy() {
						provenance[reason.Number] = true
					}
				}
			}
			for number := 1; number <= len(rules); number++ {
				if !provenance[number] {
					t.Errorf("active target %d disappeared from the instance's admission provenance", number)
				}
			}
		})
	}
}
