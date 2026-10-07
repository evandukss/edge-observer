package intake_test

import (
	"errors"
	"testing"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
)

// fits writes one fragment of payload and reports whether the store took it,
// failing on any refusal but the limit.
func fits(t *testing.T, s *intake.Store, payload string) bool {
	t.Helper()
	err := s.Write(fragment.Record{Payload: []byte(payload)})
	if err != nil && !errors.Is(err, intake.ErrLimit) {
		t.Fatalf("Write refused for another reason than the limit: %v", err)
	}
	return err == nil
}

// A work charge is held in the one allowance beside the entries, so an
// insertion that fits beside the entries alone is refused while the work holds
// the rest, and fits again once the work gives it back.
func TestAWorkChargeTakesRoomFromTheEntries(t *testing.T) {
	payload := "0123456789"
	entry := fragmentBytes(payload)
	s := open(t, 4*entry)
	if !s.Reserve(intake.Parsing, entry) || !s.Reserve(intake.Policy, 2*entry) {
		t.Fatalf("wiring, not the property: reservations of %d and %d in an empty allowance of %d were refused",
			entry, 2*entry, 4*entry)
	}
	if got := s.Stats(); got.Parsing != entry || got.Policy != 2*entry {
		t.Fatalf("charges held: Parsing %d, Policy %d, want %d and %d: %+v", got.Parsing, got.Policy, entry,
			2*entry, got)
	}
	if !fits(t, s, payload) {
		t.Fatalf("an entry of %d did not fit in the %d the work charges left", entry, entry)
	}
	if fits(t, s, payload) {
		t.Fatalf("a second entry fitted beside work charges of %d and one entry, in an allowance of %d: %+v",
			3*entry, 4*entry, s.Stats())
	}
	if got := s.Stats(); got.FragmentsRefused != 1 || !got.Exhausted {
		t.Fatalf("the refused insertion is counted as any intake refusal: %+v", got)
	}
	s.Return(intake.Policy, 2*entry)
	if got := s.Stats(); got.Policy != 0 || got.Parsing != entry {
		t.Fatalf("Policy given back: Policy %d, Parsing %d, want 0 and %d", got.Policy, got.Parsing, entry)
	}
	if !fits(t, s, payload) {
		t.Fatalf("an entry did not fit once the policy charge was given back: %+v", s.Stats())
	}
}

// A reservation that does not fit beside the entries and the other owner's
// charge is refused, charges nothing, and is counted against its own owner
// only. It is not an insertion refused, so the intake's exhaustion signal
// stays open.
func TestARefusedReservationChargesNothingAndIsCountedAgainstItsOwner(t *testing.T) {
	payload := "0123456789"
	entry := fragmentBytes(payload)
	s := open(t, 3*entry)
	if !fits(t, s, payload) || !s.Reserve(intake.Policy, entry) {
		t.Fatalf("wiring, not the property: an entry and a policy charge of %d did not fit in %d", entry, 3*entry)
	}
	if s.Reserve(intake.Parsing, entry+1) {
		t.Fatalf("a parsing reservation of %d fitted where %d was left: %+v", entry+1, entry, s.Stats())
	}
	got := s.Stats()
	if got.Parsing != 0 || got.Policy != entry || got.Bytes != entry {
		t.Fatalf("a refused reservation changed what is held: %+v", got)
	}
	if got.ParsingRefused != 1 || got.PolicyRefused != 0 {
		t.Fatalf("refusals counted: Parsing %d, Policy %d, want 1 and 0", got.ParsingRefused, got.PolicyRefused)
	}
	select {
	case <-s.Exhausted():
		t.Fatal("a refused work reservation closed the insertion exhaustion signal")
	default:
	}
	if !s.Reserve(intake.Parsing, entry) {
		t.Fatalf("a reservation of exactly what was left, %d, was refused: %+v", entry, s.Stats())
	}
	if s.Reserve(intake.Policy, 1) {
		t.Fatal("a reservation fitted in a full allowance")
	}
	if got := s.Stats(); got.ParsingRefused != 1 || got.PolicyRefused != 1 || got.Parsing+got.Policy+got.Bytes != 3*entry {
		t.Fatalf("a full allowance: %+v", got)
	}
}

// Giving back one owner's charge, or one entry, gives back nothing of
// another: a source and its copy are each charged.
func TestGivingBackOneChargeLeavesTheOthers(t *testing.T) {
	payload := "0123456789"
	entry := fragmentBytes(payload)
	s := open(t, 10*entry)
	if !fits(t, s, payload) || !s.Reserve(intake.Parsing, 2*entry) || !s.Reserve(intake.Policy, 3*entry) {
		t.Fatalf("wiring, not the property: the three charges did not fit: %+v", s.Stats())
	}
	e := s.Take()
	if e == nil {
		t.Fatal("wiring, not the property: the entry written was not queued")
	}
	e.Release()
	if got := s.Stats(); got.Bytes != 0 || got.Parsing != 2*entry || got.Policy != 3*entry {
		t.Fatalf("releasing the entry: %+v", got)
	}
	s.Return(intake.Parsing, 2*entry)
	if got := s.Stats(); got.Parsing != 0 || got.Policy != 3*entry {
		t.Fatalf("returning the parsing charge: %+v", got)
	}
	s.Return(intake.Policy, entry)
	if got := s.Stats(); got.Policy != 2*entry {
		t.Fatalf("returning part of the policy charge: %+v", got)
	}
}

// The input rules: an owner other than Parsing or Policy, a negative charge,
// and a nil or zero store are refused and not counted; zero is granted and
// charges nothing; a return outside the rules does nothing; a closed store
// refuses input and still holds and grants work.
func TestReservationInputRules(t *testing.T) {
	s := open(t, 1000)
	for _, one := range []struct {
		owner intake.Owner
		n     int64
	}{{0, 1}, {intake.Policy + 1, 1}, {intake.Parsing, -1}, {intake.Policy, -1}} {
		if s.Reserve(one.owner, one.n) {
			t.Errorf("Reserve(%d, %d) was granted", one.owner, one.n)
		}
	}
	for _, store := range []*intake.Store{nil, new(intake.Store)} {
		if store.Reserve(intake.Parsing, 1) {
			t.Error("an uninitialized store granted a reservation")
		}
		store.Return(intake.Parsing, 1)
	}
	if !s.Reserve(intake.Parsing, 0) || !s.Reserve(intake.Policy, 0) {
		t.Error("a zero reservation was refused")
	}
	if got := s.Stats(); got.Parsing != 0 || got.Policy != 0 || got.ParsingRefused != 0 || got.PolicyRefused != 0 {
		t.Fatalf("invalid or zero reservations changed the store: %+v", got)
	}
	if !s.Reserve(intake.Parsing, 100) {
		t.Fatal("wiring, not the property: a reservation of 100 in 1000 was refused")
	}
	s.Return(0, 50)
	s.Return(intake.Parsing, -50)
	s.Return(intake.Parsing, 0)
	if got := s.Stats(); got.Parsing != 100 {
		t.Fatalf("returns outside the rules changed the charge: %+v", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(fragment.Record{Payload: []byte("x")}); !errors.Is(err, intake.ErrClosed) {
		t.Fatalf("a closed store took input: %v", err)
	}
	if !s.Reserve(intake.Policy, 900) || s.Reserve(intake.Policy, 1) {
		t.Fatalf("a closed store's allowance: %+v", s.Stats())
	}
	if got := s.Stats(); got.Parsing != 100 || got.Policy != 900 || got.PolicyRefused != 1 {
		t.Fatalf("a closed store keeps its work charges: %+v", got)
	}
}
