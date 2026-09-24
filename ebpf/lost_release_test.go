//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/spool"
)

type independentLostReleaseSink struct {
	*independentBindingSink
	removed chan probe.Connection
	omitted bool
}

func (s *independentLostReleaseSink) Closed(one probe.Connection) {
	if !s.omitted {
		s.omitted = true
		s.removed <- one
		return
	}
	s.independentBindingSink.Closed(one)
}

// Lose an ACTUAL decoded ending at the delivery boundary. No observation,
// production stamp or kernel loss count is fabricated. The ring-reservation
// tests separately exercise the path that loses observations in the kernel.
func TestALostReleaseCannotSpliceTheNextOccupantOfTheSameHandle(t *testing.T) {
	port, written := independentGreetingPeer(t)
	actor := independentActor(t, independentHandleReuseSource, port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	disk, err := spool.Open(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = disk.Close() })
	base := &independentBindingSink{recording: capture.Recording(disk, disk), transfers: make(chan probe.Transfer, 8)}
	sink := &independentLostReleaseSink{independentBindingSink: base, removed: make(chan probe.Connection, 1)}
	live, err := attach.NeweBPF(process.Approval{}).Attach(probe.Request{Processes: []process.Process{parent}, Admit: authorise(parent)}, sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Close() })
	command := func(letter string) {
		t.Helper()
		if _, err := io.WriteString(actor.input, letter+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	command("C")
	line, err := actor.output.ReadString('\n')
	var original uint64
	var first int32
	if _, scanErr := fmt.Sscanf(line, "control %d %d", &original, &first); err != nil || scanErr != nil || original == 0 || first < 0 {
		t.Fatalf("control identity: %q: %v, %v", line, err, scanErr)
	}
	peerReceived(t, written, "peer-control-socket")
	control := independentBindingTransfer(t, base, "peer-control-socket")
	if control.Endpoint != original || control.Bound != probe.BoundTo || control.Descriptor != first || control.Stamp == 0 {
		t.Fatalf("socket read did not establish the stamped live-handle control: %+v", control)
	}
	command("F")
	actorLine(t, actor, "freed\n")
	var ending probe.Connection
	select {
	case ending = <-sink.removed:
	case <-time.After(3 * time.Second):
		t.Fatal("no real release reached the boundary where the test removes it")
	}
	if ending.Stamp != control.Stamp+1 || !ending.Instance.Same(control.Instance) {
		t.Fatalf("removed ending was not the next real observation for the approved execution: control=%+v ending=%+v", control, ending)
	}
	command("N")
	line, err = actor.output.ReadString('\n')
	var reused uint64
	var second, pending int
	if _, scanErr := fmt.Sscanf(line, "buffered %d %d %d", &reused, &second, &pending); err != nil || scanErr != nil || reused != original || second < 0 || second == int(first) || pending != len("peer-reused-socket") {
		t.Fatalf("same handle's new occupancy and buffered peer bytes were not established: %q: %v, %v", line, err, scanErr)
	}
	peerReceived(t, written, "peer-reused-socket")
	command("R")
	actorLine(t, actor, fmt.Sprintf("read-without-socket-io %d\n", pending))
	after := independentBindingTransfer(t, base, "peer-reused-socket")
	if after.Endpoint != original || after.Stamp != ending.Stamp+1 || !after.Instance.Same(control.Instance) {
		t.Fatalf("successor did not bracket exactly the omitted release at the same handle: %+v", after)
	}
	command("F")
	actorLine(t, actor, "freed\n")
	waitIndependentLifecycleConnections(t, disk, 2)
	records := independentLifecycleConnections(t, disk.ConnectionsPath())
	if len(records) != 2 || records[0].ID == records[1].ID {
		t.Fatalf("missing release spliced two occupancies of one address: %+v", records)
	}
	association, ok := records[1].Association(fragment.Received)
	if !ok || association.State != connection.Unknown || association.Reason != connection.ObservationLost || association.Joinable() {
		t.Errorf("successor claimed a binding across the missing lifetime evidence: %+v", association)
	}
	if stats := base.recording.Stats(); stats.Lost != 1 || stats.Interrupted != 1 {
		t.Errorf("the actual omitted ending disappeared from the capture account: %+v", stats)
	}
}
