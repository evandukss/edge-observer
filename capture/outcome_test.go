package capture_test

import (
	"testing"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

// outcome is an unbound transfer saying what its own kernel I/O came to.
func outcome(direction fragment.Direction, came probe.SocketOutcome) probe.Transfer {
	one := transfer(worker, 0x18, direction, 10)
	one.Bound = probe.NotBound
	one.Outcome = came
	return one
}

// reasons is what one unbound transfer's association says.
func reason(t *testing.T, came probe.SocketOutcome) connection.Reason {
	t.Helper()
	s := capture.Recording(&collected{}, nil)
	s.Transfer(outcome(fragment.Sent, came))

	records := finished(s)
	if len(records) != 1 {
		t.Fatalf("%d connection records, want 1", len(records))
	}
	one, found := records[0].Association(fragment.Sent)
	if !found {
		t.Fatal("the connection carries no association for the direction that transferred")
	}
	if one.State != connection.Unknown {
		t.Fatalf("the association is %s, want unknown", one.State)
	}
	if err := one.Validate(); err != nil {
		t.Errorf("the association is not usable: %v", err)
	}
	return one.Reason
}

// Three outcomes, three reasons: an ordinary-file write inside a TLS call is
// determinate, unreadable evidence is an absence, and only a call with no
// kernel I/O may use an earlier binding.
func TestWhatACallsOwnIOCameToIsWhatItsMissingBindingSays(t *testing.T) {
	for _, one := range []struct {
		came probe.SocketOutcome
		want connection.Reason
	}{
		{probe.FileIO, connection.OperationWasNotASocket},
		{probe.EvidenceUnreadable, connection.EvidenceUnreadable},
		{probe.OperationUnresolved, connection.OperationUnresolved},
		{probe.RouteUnsupported, connection.RouteUnsupported},
		{probe.FrameBroken, connection.OperationFrameBroken},
	} {
		if got := reason(t, one.came); got != one.want {
			t.Errorf("a transfer whose I/O was %q reports %q, want %q", one.came, got, one.want)
		}
	}
}

// A backend silent about a call's I/O leaves the stream's reason standing;
// the zero value is not an outcome.
func TestABackendThatSaysNothingLeavesTheStreamsOwnReason(t *testing.T) {
	if got := reason(t, probe.NoKernelIO); got != connection.NoBindingObserved {
		t.Errorf("a transfer whose backend answered nothing reports %q, want the stream's own reason", got)
	}
}

// SocketIO is deliberately unmapped: socket I/O without a binding is explained
// upstream.
func TestSocketIOWithNoBindingIsNotExplainedByItsOutcome(t *testing.T) {
	if got := reason(t, probe.SocketIO); got != connection.NoBindingObserved {
		t.Errorf("a transfer whose I/O was on a socket and which bound nothing reports %q, and its "+
			"outcome does not explain that", got)
	}
}

// What a connection says while open, which conditions about mid-call state
// must read. Records reports only what has stopped changing.
func TestAConnectionStillOpenSaysWhatItHasEstablishedSoFar(t *testing.T) {
	s := capture.Recording(&collected{}, nil)
	s.Transfer(outcome(fragment.Sent, probe.FileIO))

	if held := s.Records(); len(held) != 0 {
		t.Fatalf("%d sealed records for a connection nothing has closed", len(held))
	}

	live := s.Live(at)
	if len(live) != 1 {
		t.Fatalf("%d live records, want the one connection this session is following", len(live))
	}
	one, found := live[0].Association(fragment.Sent)
	if !found {
		t.Fatal("the live record carries no association for the direction that transferred")
	}
	if one.Reason != connection.OperationWasNotASocket {
		t.Errorf("the live association reports %q, want what the call's own I/O came to", one.Reason)
	}
	if live[0].How != connection.StillOpen && live[0].How != connection.EndingUnestablished {
		t.Errorf("a connection nothing has closed is reported as %s", live[0].How)
	}
}

// Reading the live view takes nothing away.
func TestReadingTheLiveViewRetiresNothing(t *testing.T) {
	s := capture.Recording(&collected{}, nil)
	s.Transfer(outcome(fragment.Sent, probe.FileIO))

	before := s.Open()
	if len(s.Live(at)) != 1 || s.Open() != before {
		t.Fatalf("reading the live view left %d connections open, want %d", s.Open(), before)
	}

	records := finished(s)
	if len(records) != 1 {
		t.Errorf("%d records after the seal, want the connection the live view reported", len(records))
	}
}
