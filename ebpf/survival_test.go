//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
)

func survivingFamilySource() string {
	source := heldFamilySource()
	// A stopped child in the actor's private process group receives SIGHUP
	// when the exiting root orphans that group. Keep the actor alive through
	// that real signal so the test reaches the surviving-execution state.
	source = strings.Replace(source, "raise(SIGSTOP);", "signal(SIGHUP, SIG_IGN); raise(SIGSTOP);", 1)
	source = strings.Replace(source, `_exit(moves ? transfer("/independent-held-child") : 0);`, `if (!moves) _exit(0);
	printf("survivor %d\n", transfer("/independent-survivor")); fflush(stdout);
	char command[8];
	if (!fgets(command, sizeof(command), stdin)) _exit(30);
	int ready[2];
	if (pipe(ready) != 0) _exit(31);
	pid_t grandchild = fork();
	if (grandchild < 0) _exit(32);
	if (grandchild == 0) {
		close(ready[1]);
		char byte;
		if (read(ready[0], &byte, 1) != 1) _exit(33);
		_exit(transfer("/independent-grandchild"));
	}
	close(ready[0]);
	if (write(ready[1], "G", 1) != 1) _exit(34);
	close(ready[1]);
	int status;
	if (waitpid(grandchild, &status, 0) != grandchild) _exit(35);
	printf("grandchild %d %d\n", grandchild, status); fflush(stdout);
	while (fgets(command, sizeof(command), stdin)) {}
	_exit(0);`, 1)
	return strings.Replace(source, "if (command[0] == 'P') {", `if (command[0] == 'O') {
			printf("root-exiting\n"); fflush(stdout); return 0;
		} else if (command[0] == 'P') {`, 1)
}

func TestRootExitPreservesSurvivorsButDoesNotSelectAReplacement(t *testing.T) {
	for _, mode := range []admission.Mode{admission.ModeExisting, admission.ModeFollow} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			port, received := independentPeer(t)
			actor := independentActor(t, survivingFamilySource(), port)
			parent := loaded(t, int32(actor.command.Process.Pid))
			child, err := actor.child('L', "live")
			if err != nil {
				t.Fatal(err)
			}
			waitActorState(t, child, "T")
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
			if attribution(drain(session, 100*time.Millisecond), "/independent-parent") == nil {
				t.Fatal("approved root control was not captured")
			}
			held, err := session.Admissions()
			if err != nil {
				t.Fatal(err)
			}
			var generation admission.Generation
			for _, one := range held {
				if one.Instance.Namespace == parent.Namespace && one.Instance.PID == child {
					generation = one.Instance.Generation
				}
			}
			if generation == 0 {
				t.Fatal("pre-existing child had no grant before the root exited")
			}
			if _, err := io.WriteString(actor.input, "O\n"); err != nil {
				t.Fatal(err)
			}
			actorLine(t, actor, "root-exiting\n")
			// Wait for the kernel to reap the leader without closing the shared
			// stdout pipe that its surviving child still owns.
			if _, err := actor.command.Process.Wait(); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Kill(int(child), syscall.SIGCONT); err != nil {
				t.Fatal(err)
			}
			actorLine(t, actor, "survivor 0\n")
			peerReceived(t, received, "/independent-survivor")
			got := attribution(drain(session, 100*time.Millisecond), "/independent-survivor")
			if got == nil || got.NamespacePID != child || got.Generation != generation {
				t.Errorf("root exit revoked or replaced the survivor's own grant: %+v", got)
			}
			if _, err := io.WriteString(actor.input, "C\n"); err != nil {
				t.Fatal(err)
			}
			line, err := actor.output.ReadString('\n')
			var grandchild int32
			var status int
			if _, scanErr := fmt.Sscanf(line, "grandchild %d %d", &grandchild, &status); err != nil || scanErr != nil || grandchild <= 0 || status != 0 {
				t.Fatalf("grandchild did not complete: %q: %v, %v", line, err, scanErr)
			}
			peerReceived(t, received, "/independent-grandchild")
			born := attribution(drain(session, 100*time.Millisecond), "/independent-grandchild")
			if mode == admission.ModeFollow && (born == nil || born.NamespacePID != grandchild || born.Generation == generation) {
				t.Errorf("surviving follow grant did not admit its own child: %+v", born)
			}
			if mode == admission.ModeExisting && born != nil {
				t.Errorf("existing-only survivor admitted a new child after root exit: %+v", born)
			}
			replacement := independentActor(t, immediateForkSource(), port)
			if _, err := io.WriteString(replacement.input, "P\n"); err != nil {
				t.Fatal(err)
			}
			actorLine(t, replacement, "parent 0\n")
			peerReceived(t, received, "/independent-parent")
			if replacementEvent := attribution(drain(session, 100*time.Millisecond), "/independent-parent"); replacementEvent != nil {
				t.Errorf("replacement under an unselected supervisor was admitted without restart: %+v", replacementEvent)
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			current := loaded(t, int32(replacement.command.Process.Pid))
			session, err = ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, current), Admit: authorise(current)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(replacement.input, "P\n"); err != nil {
				t.Fatal(err)
			}
			actorLine(t, replacement, "parent 0\n")
			peerReceived(t, received, "/independent-parent")
			if resumed := attribution(drain(session, 100*time.Millisecond), "/independent-parent"); resumed == nil || resumed.NamespacePID != current.NamespacePID {
				t.Errorf("restart did not activate the explicitly selected replacement: %+v", resumed)
			}
		})
	}
}
