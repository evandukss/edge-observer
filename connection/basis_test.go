package connection_test

import (
	"errors"
	"testing"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
)

// unbound is an association with everything but the two fields under test.
func unbound(state connection.State, reason connection.Reason) connection.Association {
	return connection.Association{
		Connection: 1,
		Direction:  fragment.Sent,
		State:      state,
		Reason:     reason,
		Join:       connection.DoesNotJoin,
		JoinReason: connection.NoBindingToJoin,
	}
}

// The six kernel-evidence reasons are all Unknown reasons; a record giving one
// for any other state is refused.
func TestTheKernelEvidenceReasonsBelongToUnknownAndToNothingElse(t *testing.T) {
	added := []connection.Reason{
		connection.OperationWasNotASocket,
		connection.EvidenceUnreadable,
		connection.OperationUnresolved,
		connection.RouteUnsupported,
		connection.OperationFrameBroken,
		connection.SocketEvidenceUnavailable,
	}

	for _, reason := range added {
		if err := unbound(connection.Unknown, reason).Validate(); err != nil {
			t.Errorf("an unknown binding giving the reason %q is refused: %v", reason, err)
		}
		for _, state := range []connection.State{
			connection.Established, connection.Ambiguous, connection.Invalidated,
		} {
			one := unbound(state, reason)
			if state == connection.Established {
				one.Join, one.JoinReason = connection.DoesNotJoin, connection.NoEndpointProducer
			}
			if err := one.Validate(); !errors.Is(err, connection.ErrInvalid) {
				t.Errorf("a %s binding giving the reason %q is accepted, and that reason "+
					"belongs to an unknown one", state, reason)
			}
		}
	}
}

// No two reasons print the same sentence.
func TestEveryReasonPrintsSomethingOfItsOwn(t *testing.T) {
	said := make(map[string]connection.Reason)
	for reason := connection.ReasonUnset; reason <= connection.HandleLifetimeUnobservable; reason++ {
		text := reason.String()
		if text == "no reason" && reason != connection.ReasonUnset {
			t.Errorf("reason %d prints nothing of its own", reason)
			continue
		}
		if first, seen := said[text]; seen {
			t.Errorf("reasons %d and %d both print %q", first, reason, text)
		}
		said[text] = reason
	}
}

// A basis belongs to an established binding only.
func TestABasisOnAnythingButAnEstablishedBindingIsRefused(t *testing.T) {
	for _, basis := range []connection.Basis{connection.ConfirmedInCall, connection.Continuity} {
		one := unbound(connection.Unknown, connection.NoBindingObserved)
		one.Basis = basis
		if err := one.Validate(); !errors.Is(err, connection.ErrInvalid) {
			t.Errorf("an unknown binding claiming the basis %q is accepted", basis)
		}
	}
}

// The two bases print as different sentences.
func TestTheTwoBasesSayDifferentThings(t *testing.T) {
	if connection.ConfirmedInCall.String() == connection.Continuity.String() {
		t.Error("a confirmation and a continuity assertion print the same sentence")
	}
	if connection.BasisUnset.String() != "unset" {
		t.Errorf("an unfilled basis prints %q", connection.BasisUnset)
	}
}
