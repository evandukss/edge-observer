//go:build attach

package ebpf_test

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/spool"
)

// Only the observer's delivery is held. The actor and peer continue without
// tracing or a stop signal while events wait behind this sink boundary.
type independentHeldSink struct {
	capture *capture.Session
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *independentHeldSink) unblock() { s.once.Do(func() { close(s.release) }) }
func (s *independentHeldSink) Transfer(transfer probe.Transfer) {
	if s.armed.CompareAndSwap(true, false) {
		close(s.entered)
		<-s.release
	}
	s.capture.Transfer(transfer)
}
func (s *independentHeldSink) Closed(ending probe.Connection) { s.capture.Closed(ending) }

func independentConnections(t *testing.T, path string) []connection.Record {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(file)
	var records []connection.Record
	for {
		var record connection.Record
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			return records
		}
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
}

func waitIndependentConnections(t *testing.T, disk *spool.Spool, want int64) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for disk.Stats().Connections < want {
		select {
		case <-deadline.C:
			t.Fatalf("only %d connections persisted, wanted %d", disk.Stats().Connections, want)
		case <-tick.C:
		}
	}
}

func TestExitedChildIsIdentifiedAfterItsGrantAndProcEntryAreGone(t *testing.T) {
	port, received := independentPeer(t)
	actor := independentActor(t, heldFamilySource(), port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	disk, err := spool.Open(t.TempDir(), 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = disk.Close() })
	recording := capture.Recording(disk, disk)
	sink := &independentHeldSink{capture: recording, entered: make(chan struct{}), release: make(chan struct{})}
	backend := attach.NeweBPF(process.Approval{})
	live, err := backend.Attach(probe.Request{Processes: []process.Process{parent}, Admit: authorise(parent)}, sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Close() })
	t.Cleanup(sink.unblock)
	producer, ok := live.(connection.Producer)
	if !ok {
		t.Fatal("real attachment exposes no production finalisation boundary")
	}
	if _, err := io.WriteString(actor.input, "P\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "parent 0\n")
	peerReceived(t, received, "/independent-parent")
	waitIndependentConnections(t, disk, 1)
	control := independentConnections(t, disk.ConnectionsPath())
	if len(control) != 1 || control[0].Instance.PID != parent.NamespacePID || control[0].Instance.Generation == 0 || !control[0].Instance.Start.Determined {
		t.Fatalf("live root did not establish a persisted instance control: %+v", control)
	}
	childPID, err := actor.child('L', "live")
	if err != nil {
		t.Fatal(err)
	}
	waitActorState(t, childPID, "T")
	child := loaded(t, childPID)
	sink.armed.Store(true)
	if _, err := io.WriteString(actor.input, "P\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "parent 0\n")
	peerReceived(t, received, "/independent-parent")
	select {
	case <-sink.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("delivery never reached the independently held boundary")
	}
	if err := actor.finish('G', "live"); err != nil {
		t.Fatal(err)
	}
	peerReceived(t, received, "/independent-held-child")
	if _, err := process.Identify(procfs, childPID); err == nil {
		t.Fatal("child was still readable when its event was waiting for delivery")
	}
	withdrawal, err := producer.StopProducing()
	if err != nil || !withdrawal.Complete || withdrawal.Instances != 1 {
		t.Fatalf("exited child's grant was not gone before delayed delivery; expected only the root to be withdrawn: %+v, %v", withdrawal, err)
	}
	// No child identity has reached the sink, and no live map or /proc entry
	// can now supply it. The production adapter must use the queued event.
	if got := len(independentConnections(t, disk.ConnectionsPath())); got != 1 {
		t.Fatalf("delivery escaped the hold: %d persisted connections before release", got)
	}
	sink.unblock()
	waitIndependentConnections(t, disk, 3)
	records := independentConnections(t, disk.ConnectionsPath())
	var found []connection.Record
	for _, record := range records {
		if record.Instance.Namespace == child.Namespace && record.Instance.PID == child.NamespacePID {
			found = append(found, record)
		}
	}
	if len(found) != 1 {
		t.Fatalf("exited child's transfer did not retain its own persisted instance: %+v", records)
	}
	record := found[0]
	if record.Instance.Generation == 0 || record.Instance.Generation == control[0].Instance.Generation {
		t.Errorf("child inherited or lost its parent's generation: %+v", record.Instance)
	}
	if record.Instance.Start.Determined || record.Instance.Executable != "" {
		t.Errorf("already-exited child received invented live-process evidence: %+v", record.Instance)
	}
	if record.Handle.Instance != record.Instance.Key() {
		t.Errorf("persisted handle and instance disagree: %+v", record)
	}
	if err := record.Validate(); err != nil {
		t.Errorf("real delivered connection is unusable: %v", err)
	}
}

func TestSealAccountsForAnEventAlreadyDecodedButNotPersisted(t *testing.T) {
	port, received := independentPeer(t)
	actor := independentActor(t, immediateForkSource(), port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	disk, err := spool.Open(t.TempDir(), 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = disk.Close() })
	recording := capture.Recording(disk, disk)
	sink := &independentHeldSink{capture: recording, entered: make(chan struct{}), release: make(chan struct{})}
	live, err := attach.NeweBPF(process.Approval{}).Attach(probe.Request{Processes: []process.Process{parent}, Admit: authorise(parent)}, sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Close() })
	t.Cleanup(sink.unblock)
	producer, ok := live.(connection.Producer)
	if !ok {
		t.Fatal("real attachment exposes no production finalisation boundary")
	}
	transfer := func() {
		if _, err := io.WriteString(actor.input, "P\n"); err != nil {
			t.Fatal(err)
		}
		actorLine(t, actor, "parent 0\n")
		peerReceived(t, received, "/independent-parent")
	}
	transfer()
	waitIndependentConnections(t, disk, 1)
	control := independentConnections(t, disk.ConnectionsPath())
	if len(control) != 1 || !control[0].Fragments.Known || control[0].Fragments.Value < 2 {
		t.Fatalf("complete persisted exchange control is absent: %+v", control)
	}
	sink.armed.Store(true)
	transfer()
	select {
	case <-sink.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the decoded transfer never reached the held sink")
	}
	if disk.Stats().Connections != 1 {
		t.Fatal("the held transfer was already persisted before sealing")
	}
	sealer := connection.Sealer{Producer: producer, Within: 200 * time.Millisecond}
	seal, err := sealer.Stop()
	if err != nil {
		t.Fatal(err)
	}
	if !seal.Withdrawal.Complete {
		t.Fatalf("authority was not withdrawn: %+v", seal.Withdrawal)
	}
	if seal.Complete || seal.Drain.Complete || (seal.Drain.Outstanding.Known && seal.Drain.Outstanding.Value == 0) {
		t.Errorf("decoded transfer held before persistence vanished from finalisation: %+v", seal)
	}
	sink.unblock()
	waitIndependentConnections(t, disk, 2)
}
