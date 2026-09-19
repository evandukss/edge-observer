package connection_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
)

var (
	at     = time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)
	inside = admission.Namespace{Device: 4, Inode: 4026531836}
)

func execution() admission.Instance {
	return admission.Instance{
		Namespace:  inside,
		PID:        1731,
		Start:      admission.Determinate(90210),
		Generation: 1,
		Executable: "/usr/bin/service",
	}
}

func handle(address uint64, generation connection.Generation) connection.Handle {
	return connection.Handle{Instance: execution().Key(), Address: address, Generation: generation}
}

// held is a fully filled record: both directions established, every offset
// placeable. Each case mutates one field of it.
func held() connection.Record {
	record := connection.Record{
		ID:        7,
		Handle:    handle(0x18, 1),
		Instance:  execution(),
		FirstSeen: at,
		How:       connection.StillOpen,
		Fragments: connection.Counted(4),
	}
	for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
		record.Associations = append(record.Associations, connection.Association{
			Connection: record.ID,
			Direction:  direction,
			State:      connection.Established,
			Join:       connection.Joins,
			Binding:    3,
			Source:     connection.InCallSyscall,
			Valid:      connection.Since(at),
			Descriptor: connection.Held(7),
			Endpoints: connection.Endpoints{
				Local:  connection.At(netip.MustParseAddr("172.25.0.4"), 37707),
				Remote: connection.At(netip.MustParseAddr("172.25.0.8"), 8443),
				Netns:  connection.Netns{Device: 4, Inode: 4026532567},
			},
		})
		record.Placements = append(record.Placements, connection.Placement{
			Connection: record.ID,
			Direction:  direction,
			Positions:  connection.PositionsEstablished,
			Lost:       connection.Counted(0),
		})
	}
	return record
}

func TestTheControlRecordIsValidAndJoinableInBothDirections(t *testing.T) {
	record := held()
	if err := record.Validate(); err != nil {
		t.Fatalf("the control record is refused: %v", err)
	}
	for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
		if !record.Joinable(direction) {
			t.Errorf("%s is not joinable, so no refusal below proves anything", direction)
		}
		if !record.Placeable(direction) {
			t.Errorf("%s is not placeable, so no invalidation below proves anything", direction)
		}
	}
}

// Descriptor zero is real; zero must not mean "not established".
func TestADescriptorOfZeroIsAValidDescriptorAndNotTheUnknownSentinel(t *testing.T) {
	record := held()
	record.Associations[0].Descriptor = connection.Held(0)

	if err := record.Validate(); err != nil {
		t.Fatalf("a binding on descriptor 0 is refused: %v", err)
	}
	if !record.Joinable(fragment.Sent) {
		t.Error("a binding on descriptor 0 is not joinable")
	}
	if unheld := connection.Unheld(); unheld.Known {
		t.Error("the unknown descriptor reports itself known")
	}
	if connection.Held(0) == connection.Unheld() {
		t.Error("descriptor 0 and no descriptor are the same value")
	}
}

// Port zero is a port, and an unread address is not an address of zeroes.
func TestAnEndpointNobodyReadIsNotAnEndpointOfZeroes(t *testing.T) {
	unread := connection.Nowhere()
	if unread.Known {
		t.Fatal("an address nothing established reports itself known")
	}
	zero := connection.At(netip.IPv4Unspecified(), 0)
	if !zero.Known {
		t.Fatal("0.0.0.0:0 reports itself unknown, so a real unspecified endpoint cannot be recorded")
	}
	if zero == unread {
		t.Fatal("an endpoint of zeroes and an endpoint nobody read are the same value")
	}

	// An incomplete tuple does not join, stated on the join axis; the binding
	// stays established.
	record := held()
	record.Associations[0].Endpoints.Local = unread
	record.Associations[0].Join = connection.DoesNotJoin
	record.Associations[0].JoinReason = connection.EndpointUnreadable
	if record.Joinable(fragment.Sent) {
		t.Error("a connection whose local address nothing established is joinable")
	}
	if got, _ := record.Association(fragment.Sent); got.State != connection.Established {
		t.Errorf("its binding became %s when its endpoints did not read", got.State)
	}
	if err := record.Validate(); err != nil {
		t.Errorf("an established binding with an incomplete tuple is refused: %v", err)
	}

	// Claiming the join anyway is refused.
	record.Associations[0].Join = connection.Joins
	record.Associations[0].JoinReason = connection.JoinReasonUnset
	if err := record.Validate(); err == nil {
		t.Error("an association claims to join on a tuple missing an end")
	}
}

// The axes move independently: a binding that is not established cannot claim
// the join, whatever its endpoints read.
func TestAnAssociationWithNoEstablishedBindingCannotClaimTheJoin(t *testing.T) {
	for _, state := range []connection.State{connection.Unknown, connection.Ambiguous, connection.Invalidated} {
		record := held()
		record.Associations[0].State = state
		switch state {
		case connection.Unknown:
			record.Associations[0].Reason = connection.NoBindingObserved
			record.Associations[0].Descriptor = connection.Unheld()
		case connection.Ambiguous:
			record.Associations[0].Reason = connection.SeveralDescriptors
			record.Associations[0].Contended = []connection.Descriptor{connection.Held(7), connection.Held(9)}
			record.Associations[0].Descriptor = connection.Unheld()
		default:
			record.Associations[0].Reason = connection.DescriptorReplaced
		}
		if err := record.Validate(); err == nil {
			t.Errorf("a %s association keeps a claim to join", state)
		}

		// With the join answered on its own axis it is valid; the other direction was
		// never affected.
		record.Associations[0].Join = connection.DoesNotJoin
		record.Associations[0].JoinReason = connection.NoBindingToJoin
		if err := record.Validate(); err != nil {
			t.Errorf("a %s association that does not claim the join is refused: %v", state, err)
		}
		if record.Joinable(fragment.Sent) {
			t.Errorf("a %s association is joinable", state)
		}
		if !record.Joinable(fragment.Received) {
			t.Errorf("the other direction stopped joining when %s did", state)
		}
	}
}

// Every non-Established state names one of its own reasons; another state's
// reason is refused.
func TestAStateCarriesOnlyAReasonThatBelongsToIt(t *testing.T) {
	cases := []struct {
		name   string
		state  connection.State
		reason connection.Reason
		valid  bool
	}{
		{"unknown with no binding observed", connection.Unknown, connection.NoBindingObserved, true},
		{"unknown with a refused insertion", connection.Unknown, connection.InsertionRefused, true},
		{"unknown with a lost observation", connection.Unknown, connection.ObservationLost, true},
		{"unknown with an unsupported transport", connection.Unknown, connection.TransportUnsupported, true},
		{"unknown with no reason at all", connection.Unknown, connection.ReasonUnset, false},
		{"unknown wearing an invalidation reason", connection.Unknown, connection.DescriptorReplaced, false},
		{"ambiguous with its own reason", connection.Ambiguous, connection.SeveralDescriptors, true},
		{"ambiguous wearing an unknown reason", connection.Ambiguous, connection.NoBindingObserved, false},
		{"invalidated by a replaced descriptor", connection.Invalidated, connection.DescriptorReplaced, true},
		{"invalidated by a replaced transport", connection.Invalidated, connection.TransportReplaced, true},
		{"invalidated by lifetime evidence running out", connection.Invalidated, connection.LifetimeEvidenceEnded, true},
		{"invalidated by the handle being released", connection.Invalidated, connection.HandleReleased, true},
		{"invalidated with no reason at all", connection.Invalidated, connection.ReasonUnset, false},
		{"established with a reason", connection.Established, connection.NoBindingObserved, false},
	}

	for _, one := range cases {
		t.Run(one.name, func(t *testing.T) {
			association := connection.Association{
				Connection: 7,
				Direction:  fragment.Sent,
				State:      one.state,
				Reason:     one.reason,
				Join:       connection.DoesNotJoin,
				JoinReason: connection.NoBindingToJoin,
			}
			if one.state == connection.Ambiguous {
				association.Contended = []connection.Descriptor{connection.Held(7), connection.Held(9)}
			}
			if one.state == connection.Established {
				association.Binding = 3
				association.Source = connection.InCallSyscall
				association.Descriptor = connection.Held(7)
				association.Valid = connection.Since(at)
				association.JoinReason = connection.NoEndpointProducer
			}
			err := association.Validate()
			if one.valid && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !one.valid && err == nil {
				t.Fatal("accepted")
			}
			if err != nil && !errors.Is(err, connection.ErrInvalid) {
				t.Fatalf("the refusal does not wrap ErrInvalid: %v", err)
			}
		})
	}
}

// An unfilled association must not read as established.
func TestAnAssociationWithNoStateIsRefused(t *testing.T) {
	association := connection.Association{
		Connection: 7, Direction: fragment.Sent,
		Join: connection.DoesNotJoin, JoinReason: connection.NoBindingToJoin,
	}
	if err := association.Validate(); err == nil {
		t.Fatal("an association carrying no state is accepted")
	}
	if association.Joinable() {
		t.Fatal("an association carrying no state is joinable")
	}
}

// An ambiguous association must name more than one descriptor.
func TestAnAmbiguousAssociationNamesEveryDescriptorItsWindowHeld(t *testing.T) {
	one := connection.Association{
		Connection: 7,
		Direction:  fragment.Sent,
		State:      connection.Ambiguous,
		Reason:     connection.SeveralDescriptors,
		Join:       connection.DoesNotJoin,
		JoinReason: connection.NoBindingToJoin,
		Contended:  []connection.Descriptor{connection.Held(7)},
	}
	if err := one.Validate(); err == nil {
		t.Fatal("an ambiguous association naming one descriptor is accepted")
	}
	one.Contended = append(one.Contended, connection.Held(9))
	if err := one.Validate(); err != nil {
		t.Fatalf("an ambiguous association naming two descriptors is refused: %v", err)
	}
	if one.Joinable() {
		t.Fatal("an ambiguous association is joinable")
	}
}

// A direction with no association is not joinable.
func TestADirectionWithNoAssociationIsNotJoinable(t *testing.T) {
	record := held()
	record.Associations = record.Associations[:1]
	if record.Joinable(fragment.Received) {
		t.Fatal("a direction nothing was recorded for is joinable")
	}
	if err := record.Validate(); err != nil {
		t.Errorf("a record with one direction recorded is refused: %v", err)
	}
}

// An unknown association keeps its id and fragments: it costs an exact join
// and nothing else.
func TestAConnectionWithAnUnknownAssociationKeepsItsIdentityAndItsBytes(t *testing.T) {
	record := held()
	for i := range record.Associations {
		record.Associations[i] = connection.Association{
			Connection: record.ID,
			Direction:  record.Associations[i].Direction,
			State:      connection.Unknown,
			Reason:     connection.TransportUnsupported,
			Join:       connection.DoesNotJoin,
			JoinReason: connection.NoBindingToJoin,
		}
	}
	if err := record.Validate(); err != nil {
		t.Fatalf("a connection with no established binding is refused: %v", err)
	}
	if record.ID != held().ID || record.Handle != held().Handle {
		t.Fatal("the connection lost its identity with its binding")
	}
	if got := record.Fragments; !got.Known || got.Value != 4 {
		t.Fatalf("Fragments = %s, want 4", got)
	}
	for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
		if !record.Placeable(direction) {
			t.Errorf("%s stopped being placeable when its association became unknown", direction)
		}
	}
}

// A handle address alone is not an identity; execution and occupancy are part
// of the key.
func TestAHandleIsIdentifiedByItsExecutionAndItsOccupancyAndNotByItsAddress(t *testing.T) {
	first := handle(0x18, 1)
	if first == handle(0x18, 2) {
		t.Error("two occupancies of one address are one handle")
	}
	elsewhere := first
	elsewhere.Instance.PID = 1732
	if first == elsewhere {
		t.Error("one address in two executions is one handle")
	}

	for _, one := range []struct {
		name   string
		handle connection.Handle
	}{
		{"no pid namespace", connection.Handle{Instance: admission.Key{PID: 1731, Generation: 1}, Address: 0x18, Generation: 1}},
		{"no admission generation", connection.Handle{Instance: admission.Key{Namespace: inside, PID: 1731}, Address: 0x18, Generation: 1}},
		{"no handle generation", connection.Handle{Instance: execution().Key(), Address: 0x18}},
	} {
		if err := one.handle.Validate(); err == nil {
			t.Errorf("a handle with %s is accepted", one.name)
		}
	}
	if err := first.Validate(); err != nil {
		t.Errorf("the whole handle is refused: %v", err)
	}
}

// A record must say how it ended: a connection the run outlived is truncated,
// one that closed is not.
func TestARecordSaysHowItEndedAndAStillOpenOneSaysThat(t *testing.T) {
	record := held()
	record.How = connection.EndingUnset
	if err := record.Validate(); err == nil {
		t.Fatal("a record saying nothing about how it ended is accepted")
	}

	record.How = connection.SocketClosed
	if err := record.Validate(); err == nil {
		t.Fatal("a record that ended and names no time for it is accepted")
	}
	record.Ended = at.Add(time.Second)
	if err := record.Validate(); err != nil {
		t.Fatalf("a closed record with a time is refused: %v", err)
	}
}

// One connection cannot hold two facts about one direction.
func TestARecordHoldsOneAssociationAndOnePlacementPerDirection(t *testing.T) {
	record := held()
	record.Associations = append(record.Associations, record.Associations[0])
	if err := record.Validate(); err == nil {
		t.Fatal("a record with two associations for one direction is accepted")
	}

	record = held()
	record.Placements = append(record.Placements, record.Placements[0])
	if err := record.Validate(); err == nil {
		t.Fatal("a record with two placements for one direction is accepted")
	}

	record = held()
	record.Associations[0].Connection = 9
	if err := record.Validate(); err == nil {
		t.Fatal("a record carrying another connection's association is accepted")
	}
}
