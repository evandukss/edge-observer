package attach

import (
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/probe"
)

// t23Under is a set member whose threads said this at attach.
func t23Under(under probe.UnderWay) counting { return counting{lost: probe.Losses{UnderWay: under}} }

// A set sums what its members' threads said, names the first thread any member
// named, and one member that could not read a thread makes the whole not known.
func TestASetSumsTheCallsUnderWayAndOneUnreadMemberMakesThemNotKnown(t *testing.T) {
	first := &probe.Blocked{PID: 41, TID: 42, FD: 5, Call: "read"}
	known := of(t23Under(probe.UnderWay{Known: true, Undetermined: 1}),
		t23Under(probe.UnderWay{Known: true, Threads: 2, Undetermined: 3, First: first}))
	total, err := known.Losses()
	if err != nil {
		t.Fatalf("a set of two counting members cannot say what it lost: %v", err)
	}
	if !total.UnderWay.Known || total.UnderWay.Threads != 2 || total.UnderWay.Undetermined != 4 {
		t.Errorf("the set reads %+v, want known, 2 under way and 4 undetermined", total.UnderWay)
	}
	if total.UnderWay.First != first {
		t.Errorf("the set names %+v, want the second member's thread, the only one named", total.UnderWay.First)
	}

	unread := of(t23Under(probe.UnderWay{Known: true, Threads: 1, First: first}),
		t23Under(probe.UnderWay{Why: "thread 9 of pid 8: permission denied"}))
	total, err = unread.Losses()
	if err != nil {
		t.Fatalf("a set of two counting members cannot say what it lost: %v", err)
	}
	if total.UnderWay.Known || !strings.Contains(total.UnderWay.Why, "thread 9 of pid 8") {
		t.Errorf("a set with a member that could not read a thread reads %+v, want not known with its reason",
			total.UnderWay)
	}
	if total.UnderWay.Threads != 1 {
		t.Errorf("the set dropped the count the readable member made: %+v", total.UnderWay)
	}
}
