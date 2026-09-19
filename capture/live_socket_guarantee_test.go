package capture_test

import (
	"testing"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

func TestLiveViewPreservesAmbiguityAndBindingOwnership(t *testing.T) {
	s := capture.Recording(&collected{}, nil)
	s.Transfer(bound(worker, 0x31, fragment.Sent, 4, 7, 3))
	ambiguous := transfer(worker, 0x31, fragment.Sent, 4)
	ambiguous.Descriptor = 7
	ambiguous.Bound = probe.BoundAmbiguously
	s.Transfer(ambiguous)
	live := s.Live(at)
	if len(live) != 1 {
		t.Fatalf("%d live records, want 1", len(live))
	}
	one, ok := live[0].Association(fragment.Sent)
	if !ok || one.State != connection.Ambiguous || one.Descriptor.Known {
		t.Errorf("live association resolved or lost ambiguity: %+v", one)
	}
	if len(one.Contended) < 2 {
		t.Errorf("live ambiguity names %d candidates", len(one.Contended))
	}
}

func TestLiveViewExposesContinuityBasisDebt(t *testing.T) {
	s := capture.Recording(&collected{}, nil)
	s.Transfer(bound(worker, 0x32, fragment.Sent, 4, 8, 4))
	buffered := transfer(worker, 0x32, fragment.Sent, 2)
	buffered.Bound = probe.NotBound
	buffered.Outcome = probe.NoKernelIO
	s.Transfer(buffered)
	live := s.Live(at)
	if len(live) != 1 {
		t.Fatalf("%d live records, want 1", len(live))
	}
	one, _ := live[0].Association(fragment.Sent)
	if one.State != connection.Established || one.Descriptor != connection.Held(8) {
		t.Fatalf("buffered call lost the still-valid binding: %+v", one)
	}
	if one.Basis != connection.Continuity {
		t.Errorf("live continuity has basis %s, want continuity", one.Basis)
	}
}

func TestShortTransfersConserveOnlyReportedBytes(t *testing.T) {
	s := capture.Recording(&collected{}, nil)
	first := bound(worker, 0x33, fragment.Sent, 3, 9, 5)
	second := bound(worker, 0x33, fragment.Sent, 2, 9, 5)
	s.Transfer(first)
	s.Transfer(second)
	live := s.Live(at)
	if len(live) != 1 {
		t.Fatalf("%d live records, want one call stream", len(live))
	}
	if got := live[0].Fragments.Value; got != 2 {
		t.Errorf("short/split transfers produced %d fragments, want the two reported completions", got)
	}
	finished := finished(s)
	if len(finished) != 1 || finished[0].Fragments.Value != 2 {
		t.Errorf("sealed stream inferred bytes beyond reports: %+v", finished)
	}
}

func TestReverseFileThenSocketEvidenceDoesNotOverwriteEitherOutcome(t *testing.T) {
	s := capture.Recording(&collected{}, nil)
	file := transfer(worker, 0x34, fragment.Sent, 2)
	file.Bound = probe.NotBound
	file.Outcome = probe.FileIO
	s.Transfer(file)
	socket := bound(worker, 0x34, fragment.Sent, 3, 11, 6)
	socket.Outcome = probe.SocketIO
	s.Transfer(socket)
	live := s.Live(at)
	if len(live) != 1 {
		t.Fatalf("%d live records, want one reverse-order call", len(live))
	}
	one, ok := live[0].Association(fragment.Sent)
	if !ok || one.State != connection.Established || one.Descriptor != connection.Held(11) || one.Binding != 6 {
		t.Errorf("reverse file/socket ordering lost the later socket evidence: %+v", one)
	}
}

func TestSameDescriptorAcrossExecutionsKeepsBindingsSeparate(t *testing.T) {
	s := capture.Recording(&collected{}, nil)
	left := bound(worker, 0x35, fragment.Sent, 4, 12, 7)
	right := bound(gateway, 0x35, fragment.Sent, 4, 13, 8)
	s.Transfer(left)
	s.Transfer(right)
	live := s.Live(at)
	if len(live) != 2 {
		t.Fatalf("same descriptor across two executions collapsed to %d live records", len(live))
	}
	seen := map[connection.Generation]bool{}
	for _, record := range live {
		one, ok := record.Association(fragment.Sent)
		if !ok || one.State != connection.Established {
			t.Fatalf("execution lost its established binding: %+v", one)
		}
		seen[one.Binding] = true
	}
	if len(seen) != 2 {
		t.Errorf("two executions sharing fd 5 were assigned one occupancy binding: %v", seen)
	}
}
