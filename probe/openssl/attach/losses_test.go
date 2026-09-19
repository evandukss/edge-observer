package attach

import (
	"testing"

	"github.com/evandukss/edge-observer/probe"
)

// counting is a set member that reports only what it lost. It stands in for
// the attachment: the subject is how the set aggregates its members.
type counting struct{ lost probe.Losses }

func (c counting) Close() error                  { return nil }
func (c counting) Capability() probe.Capability  { return probe.Capability{Backend: probe.BPF} }
func (c counting) Losses() (probe.Losses, error) { return c.lost, nil }

// saw is a member that met unmatched returns, with its occasion.
func saw(unmatched, first, last int64, handle uint64, pid, tid int32) counting {
	return counting{lost: probe.Losses{
		Unmatched: unmatched,
		When:      probe.Occasion{First: first, Last: last, Handle: handle, PID: pid, TID: tid},
	}}
}

// silent is a member that met none, which is the zero occasion.
func silent() counting { return counting{} }

// of builds a set over the given members, in order.
func of(members ...probe.Attachment) *set {
	s := newSet()
	for i, one := range members {
		s.place(one, int32(100+i))
	}
	return s
}

// A set reports the occasion of what its members lost, including when only
// some lost anything; a count with no occasion cannot be placed against
// anything afterwards. A silent member's zero is the trap: a minimum over
// First takes it and the set again reports no occasion.
func TestASetCarriesTheOccasionOfTheOneMemberThatSawUnmatchedReturns(t *testing.T) {
	held := of(silent(), saw(5, 1200, 9900, 0x5f, 41, 42))

	total, err := held.Losses()
	if err != nil {
		t.Fatalf("a set of two counting members cannot say what it lost: %v", err)
	}

	// First: a set that aggregated nothing would satisfy every assertion below.
	if total.Unmatched != 5 {
		t.Fatalf("the set summed %d unmatched returns and its members reported 5, so this "+
			"measures nothing about the occasion", total.Unmatched)
	}

	if !total.When.Seen() {
		t.Fatalf("five unmatched returns and no occasion: %+v", total.When)
	}
	if total.When.First != 1200 || total.When.Last != 9900 {
		t.Errorf("the set reports the interval %d to %d and the member that saw them reported "+
			"1200 to 9900", total.When.First, total.When.Last)
	}
	if total.When.Handle != 0x5f || total.When.PID != 41 || total.When.TID != 42 {
		t.Errorf("the set names handle %#x of pid %d thread %d, and the member that saw the "+
			"first occasion named 0x5f, 41, 42", total.When.Handle, total.When.PID, total.When.TID)
	}
}

// Two members that both saw them at different times: the interval spans both,
// and the identity is the first occasion's. The members are placed latest
// first, so taking the first or last member met reports the wrong identity.
func TestASetSpansBothMembersAndNamesTheFirstOccasion(t *testing.T) {
	held := of(saw(2, 9000, 9500, 0xbb, 71, 72), saw(3, 1200, 4000, 0xaa, 41, 42))

	total, err := held.Losses()
	if err != nil {
		t.Fatalf("a set of two counting members cannot say what it lost: %v", err)
	}

	if total.Unmatched != 5 {
		t.Fatalf("the set summed %d unmatched returns and its members reported 2 and 3",
			total.Unmatched)
	}

	if total.When.First != 1200 {
		t.Errorf("the set's first occasion is %d and the earlier member's was 1200", total.When.First)
	}
	if total.When.Last != 9500 {
		t.Errorf("the set's last occasion is %d and the later member's was 9500", total.When.Last)
	}
	if total.When.Handle != 0xaa || total.When.PID != 41 || total.When.TID != 42 {
		t.Errorf("the set names handle %#x of pid %d thread %d, and the FIRST occasion was the "+
			"other member's 0xaa, 41, 42", total.When.Handle, total.When.PID, total.When.TID)
	}
}

// No member saw any, so there is no occasion; zero is an absence, not a time.
func TestASetThatLostNothingReportsNoOccasion(t *testing.T) {
	held := of(silent(), silent())

	total, err := held.Losses()
	if err != nil {
		t.Fatalf("a set of two counting members cannot say what it lost: %v", err)
	}
	if total.Unmatched != 0 {
		t.Fatalf("two silent members summed to %d unmatched returns", total.Unmatched)
	}
	if total.When.Seen() {
		t.Errorf("no member saw an unmatched return and the set reports the occasion %+v", total.When)
	}
	if total.When != (probe.Occasion{}) {
		t.Errorf("the set invented %+v where no member had one", total.When)
	}
}
