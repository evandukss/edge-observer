//go:build attach

package ebpf_test

import (
	"io"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
)

func TestAnUnapprovedReturnCannotCountAnApprovedCallsTombstoneAsUnmatched(t *testing.T) {
	port, received := independentPeer(t)
	actor := independentActor(t, immediateForkSource(), port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, parent), Admit: authorise(parent)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	independentParentControl(t, actor, session, received)
	present, live, generation, function, err := ebpf.IndependentThreadCall(session, parent.PID, parent.PID)
	if err != nil || !present || live || function != 1 {
		t.Fatalf("completed approved read left no intact tombstone control: present=%t live=%t generation=%d function=%d err=%v", present, live, generation, function, err)
	}
	before, err := session.Unmatched()
	if err != nil {
		t.Fatal(err)
	}
	withdrawal, err := session.StopProducing()
	if err != nil || !withdrawal.Complete || withdrawal.Instances != 1 {
		t.Fatalf("authority withdrawal was not established: %+v, %v", withdrawal, err)
	}
	if held, err := ebpf.IndependentKernelGrantPresent(session, parent.Instance()); err != nil || held {
		t.Fatalf("withdrawn thread still holds a grant: %t, %v", held, err)
	}
	present, live, _, function, err = ebpf.IndependentThreadCall(session, parent.PID, parent.PID)
	if err != nil || !present || live || function != 1 {
		t.Fatalf("withdrawal did not preserve the tombstone required for this state: present=%t live=%t function=%d err=%v", present, live, function, err)
	}
	if _, err := io.WriteString(actor.input, "P\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "parent 0\n")
	peerReceived(t, received, "/independent-parent")
	if got := attribution(drain(session, 100*time.Millisecond), "/independent-parent"); got != nil {
		t.Fatalf("withdrawn actor's transfer was captured: %+v", got)
	}
	after, err := session.Unmatched()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("an unapproved return counted the old approved call's tombstone as unmatched: %d -> %d", before, after)
	}
}
