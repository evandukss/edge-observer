package capture_test

import (
	"testing"
	"time"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

// Drive the producer with an unbound transfer and read the association
// reason. EvidenceUnreadable is structural; the other outcomes stay distinct
// and none inherits a cached binding.
func TestSocketOutcomesReachAssociationReasons(t *testing.T) {
	for _, tc := range []struct {
		outcome probe.SocketOutcome
		want    connection.Reason
	}{
		{probe.FileIO, connection.OperationWasNotASocket},
		{probe.OperationUnresolved, connection.OperationUnresolved},
		{probe.RouteUnsupported, connection.RouteUnsupported},
		{probe.FrameBroken, connection.OperationFrameBroken},
		{probe.EvidenceUnreadable, connection.EvidenceUnreadable},
	} {
		s := capture.Recording(&collected{}, nil)
		one := transfer(worker, 0x126, fragment.Sent, 1)
		one.Bound = probe.NotBound
		one.Outcome = tc.outcome
		s.Transfer(one)
		live := s.Live(time.Now())
		if len(live) != 1 {
			t.Fatalf("outcome %q produced %d live records", tc.outcome, len(live))
		}
		association, ok := live[0].Association(fragment.Sent)
		if !ok {
			t.Fatalf("outcome %q produced no sent association", tc.outcome)
		}
		if association.Reason != tc.want || association.State != connection.Unknown {
			t.Errorf("outcome %q produced state %s/reason %q, want unknown/%q", tc.outcome, association.State, association.Reason, tc.want)
		}
		if tc.outcome.CarriesBinding() {
			t.Errorf("outcome %q is incorrectly eligible to inherit a binding", tc.outcome)
		}
	}
}
