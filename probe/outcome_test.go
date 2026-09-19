package probe_test

import (
	"testing"

	"github.com/evandukss/edge-observer/probe"
)

// One outcome may carry an earlier binding forward and six may not; a new
// outcome must be decided here, not defaulted.
func TestOnlyACallThatPerformedNoKernelIOCarriesAnEarlierBinding(t *testing.T) {
	if !probe.NoKernelIO.CarriesBinding() {
		t.Error("a call that performed no kernel I/O cannot use the handle's still-valid binding, " +
			"so a buffered read reports unknown and a connection breaks into fragments")
	}

	for _, outcome := range []probe.SocketOutcome{
		probe.SocketIO,
		probe.FileIO,
		probe.OperationUnresolved,
		probe.RouteUnsupported,
		probe.EvidenceUnreadable,
		probe.FrameBroken,
	} {
		if outcome.CarriesBinding() {
			t.Errorf("%q carries an earlier call's binding forward, and this call did I/O whose "+
				"socket it cannot name", outcome)
		}
	}
}

// No two outcomes print the same sentence.
func TestEveryOutcomeSaysSomethingOfItsOwn(t *testing.T) {
	said := make(map[string]probe.SocketOutcome)
	for outcome := probe.NoKernelIO; outcome <= probe.FrameBroken; outcome++ {
		text := outcome.String()
		if first, seen := said[text]; seen {
			t.Errorf("outcomes %d and %d both print %q", first, outcome, text)
		}
		said[text] = outcome
	}
}
