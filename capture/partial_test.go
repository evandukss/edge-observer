package capture_test

import (
	"testing"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

// placing is what an attachment that placed every probe can do.
func placing() probe.Capability {
	return probe.Capability{
		Backend: probe.BPF, Program: "full", Payload: true, Filtered: true,
		Descendants: true, Lifecycle: true, Binding: true,
	}
}

// observing is a recording session told what its attachment can do.
func observing(capability probe.Capability) *capture.Session {
	s := capture.Recording(&collected{}, nil)
	s.Observing(capability)
	return s
}

// The control: an attachment that placed everything reports an established
// binding on a connection whose end it could see.
func TestASessionWhoseAttachmentPlacedEverythingReportsWhatItObserved(t *testing.T) {
	s := observing(placing())

	s.Transfer(bound(worker, 0x18, fragment.Sent, 10, 7, 3))
	records := finished(s)

	one, _ := records[0].Association(fragment.Sent)
	if one.State != connection.Established {
		t.Errorf("the binding is %s because %s, and every probe was placed", one.State, one.Reason)
	}
	if records[0].How != connection.StillOpen {
		t.Errorf("the connection ended %q, and the run was sealed while it was open", records[0].How)
	}
}

// No binding probe placed: every association on that process is unknown, with
// a reason saying a probe is absent, distinct from the other unknown reasons.
func TestAnAssociationWithNoBindingSourcePlacedSaysThatIsWhy(t *testing.T) {
	unbound := placing()
	unbound.Binding = false
	s := observing(unbound)

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	records := finished(s)
	one, _ := records[0].Association(fragment.Sent)

	if one.State != connection.Unknown {
		t.Fatalf("the binding is %s, want unknown", one.State)
	}
	if one.Reason != connection.BindingUnobservable {
		t.Errorf("it is unknown because %q, which is not that no binding source was placed", one.Reason)
	}
	if one.Reason == connection.NoBindingObserved {
		t.Error("a session that could not have observed a binding reports a call through which " +
			"none was seen, and those are different facts about different things")
	}
	if one.Join != connection.DoesNotJoin || one.JoinReason != connection.NoBindingToJoin {
		t.Errorf("joinability is %s because %s", one.Join, one.JoinReason)
	}
	if err := one.Validate(); err != nil {
		t.Errorf("the association is not usable: %v", err)
	}
}

// Those connections stay in the population, so dropping the unresolvable
// cannot improve a fidelity figure.
func TestConnectionsWithNoBindingSourceKeepTheirRecordsAndTheirFragments(t *testing.T) {
	unbound := placing()
	unbound.Binding = false
	sink := &collected{}
	s := capture.Recording(sink, nil)
	s.Observing(unbound)

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	s.Transfer(transfer(gateway, 0x20, fragment.Sent, 10))
	records := finished(s)

	if len(records) != 2 {
		t.Fatalf("%d connection records, want 2", len(records))
	}
	if len(sink.records) != 2 {
		t.Fatalf("%d fragments, want 2", len(sink.records))
	}
	for _, record := range records {
		one, found := record.Association(fragment.Sent)
		if !found {
			t.Fatalf("connection %d carries no association at all, which reads as a direction "+
				"nothing was observed for", record.ID)
		}
		if one.Joinable() {
			t.Errorf("connection %d joins with no binding source placed", record.ID)
		}
		placement, found := record.Placement(fragment.Sent)
		if !found || !placement.Whole() {
			t.Errorf("connection %d lost its byte positions to an unresolved association", record.ID)
		}
	}
}

// A binding observed despite the capability saying none could be: the
// observation wins.
func TestAnObservedBindingIsReportedWhateverTheCapabilitySaid(t *testing.T) {
	unbound := placing()
	unbound.Binding = false
	s := observing(unbound)

	s.Transfer(bound(worker, 0x18, fragment.Sent, 10, 7, 3))
	records := finished(s)
	one, _ := records[0].Association(fragment.Sent)

	if one.State == connection.Unknown {
		t.Errorf("a binding this run observed is reported as unknown because %s", one.Reason)
	}
}

// No release probe placed: a handle's lifetime is unproven, so an established
// association is invalidated (bytes kept), with no claim about when a reuse
// happened.
func TestAConnectionWhoseEndCouldNotBeObservedCarriesAnUnprovenLifetime(t *testing.T) {
	blind := placing()
	blind.Lifecycle = false
	s := observing(blind)

	s.Transfer(bound(worker, 0x18, fragment.Sent, 10, 7, 3))
	records := finished(s)

	if records[0].How != connection.EndingUnestablished {
		t.Errorf("the connection ended %q, and no probe could have observed an ending", records[0].How)
	}
	if records[0].How == connection.StillOpen {
		t.Error("a connection whose end nothing could observe is reported as one the run outlived, " +
			"which says the run stopped first")
	}

	one, _ := records[0].Association(fragment.Sent)
	if one.State != connection.Invalidated {
		t.Fatalf("the association is %s, want invalidated", one.State)
	}
	if one.Reason != connection.HandleLifetimeUnobservable {
		t.Errorf("it is invalidated because %q, which is not that the handle's release could not "+
			"be observed", one.Reason)
	}
	if err := one.Validate(); err != nil {
		t.Errorf("the association is not usable: %v", err)
	}
	if err := records[0].Validate(); err != nil {
		t.Errorf("the record is not usable: %v", err)
	}
}

// The bytes are kept: an unproven lifetime is not corruption.
func TestAnUnprovenLifetimeKeepsTheBytesAndTheirPositions(t *testing.T) {
	blind := placing()
	blind.Lifecycle = false
	sink := &collected{}
	s := capture.Recording(sink, nil)
	s.Observing(blind)

	s.Transfer(bound(worker, 0x18, fragment.Sent, 10, 7, 3))
	s.Transfer(bound(worker, 0x18, fragment.Sent, 25, 7, 3))
	records := finished(s)

	if len(sink.records) != 2 {
		t.Fatalf("%d fragments, want 2", len(sink.records))
	}
	if sink.at(1).Offset != 10 {
		t.Errorf("the second fragment is at offset %d, want 10", sink.at(1).Offset)
	}
	placement, found := records[0].Placement(fragment.Sent)
	if !found || !placement.Whole() {
		t.Errorf("an unproven lifetime cost this direction its byte positions: %+v", placement)
	}
}

// A session told nothing about its attachment reports what it observed and
// makes neither claim.
func TestASessionToldNothingAboutItsAttachmentMakesNeitherClaim(t *testing.T) {
	s := capture.Recording(&collected{}, nil)

	s.Transfer(transfer(worker, 0x18, fragment.Sent, 10))
	records := finished(s)
	one, _ := records[0].Association(fragment.Sent)

	if one.Reason != connection.NoBindingObserved {
		t.Errorf("the binding is unknown because %q, and nothing said what could be observed",
			one.Reason)
	}
	if records[0].How != connection.StillOpen {
		t.Errorf("the connection ended %q, and nothing said what could be observed", records[0].How)
	}
}
