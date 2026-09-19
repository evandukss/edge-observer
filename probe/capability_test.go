package probe_test

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/probe"
)

// full is a placement that reached the plaintext program with every probe held.
func full() probe.Capability {
	return probe.Capability{
		Backend: probe.BPF, Program: "full", Payload: true, Filtered: true,
		Descendants: true, Lifecycle: true, Binding: true, MinimumKernel: "5.15",
	}
}

// degraded is a member copying no plaintext, filtering in userspace, and
// following no forks.
func degraded() probe.Capability {
	return probe.Capability{Backend: probe.TraceFS, Lifecycle: true}
}

// One placement folds to itself.
func TestOneMemberFoldsToItself(t *testing.T) {
	if got := probe.Weakest(full()); !reflect.DeepEqual(got, full()) {
		t.Errorf("one member folded to %+v, want %+v", got, full())
	}
}

// A set answers with the weakest of its members on every axis, so a process
// nothing can read plaintext from never sits in an attachment claiming
// plaintext.
func TestASetAnswersWithTheWeakestOfItsMembersOnEveryAxis(t *testing.T) {
	folded := probe.Weakest(full(), degraded())

	if folded.Backend != probe.Mixed {
		t.Errorf("backend %s, want mixed", folded.Backend)
	}
	if folded.Payload {
		t.Error("a set holding a member that copies no plaintext says it copies plaintext")
	}
	if folded.Filtered {
		t.Error("a set holding a member that filters in userspace says an unapproved process is refused in the kernel")
	}
	if folded.Descendants {
		t.Error("a set holding a member that follows nothing a process forks says it follows them")
	}
	if folded.Program != "" {
		t.Errorf("a set whose members loaded different programs names %q", folded.Program)
	}
	if !folded.Lifecycle {
		t.Error("both members observe a connection ending and the set says it does not")
	}
}

// Member order decides nothing.
func TestFoldingIsTheSameWhicheverMemberIsFirst(t *testing.T) {
	forwards := probe.Weakest(full(), degraded())
	backwards := probe.Weakest(degraded(), full())

	if forwards.Payload != backwards.Payload || forwards.Filtered != backwards.Filtered ||
		forwards.Descendants != backwards.Descendants || forwards.Binding != backwards.Binding ||
		forwards.Lifecycle != backwards.Lifecycle || forwards.Backend != backwards.Backend {
		t.Errorf("the fold depends on the order: %+v against %+v", forwards, backwards)
	}
}

// What one member cannot observe, the set cannot; names are carried, not
// counted.
func TestTheSetNamesEveryEntryPointAnyMemberDoesNotObserve(t *testing.T) {
	one, two := full(), full()
	one.Unobserved = []string{"SSL_read"}
	two.Unobserved = []string{"SSL_write", "SSL_read"}

	folded := probe.Weakest(one, two)
	for _, symbol := range []string{"SSL_read", "SSL_write"} {
		if !slices.Contains(folded.Unobserved, symbol) {
			t.Errorf("%s is unobserved by a member and the set names %v", symbol, folded.Unobserved)
		}
	}
	if len(folded.Unobserved) != 2 {
		t.Errorf("one symbol is unobserved by both members and the set names it %d times: %v",
			len(folded.Unobserved), folded.Unobserved)
	}
}

// A set with no members can do nothing, and says so.
func TestASetWithNoMembersCanDoNothing(t *testing.T) {
	folded := probe.Weakest()
	if folded.Payload || folded.Filtered || folded.Descendants || folded.Lifecycle || folded.Binding {
		t.Errorf("a set with no placement at all reports %+v", folded)
	}
}

// A kernel floor belongs to whichever member has one.
func TestTheSetCarriesTheKernelFloorOfWhicheverMemberHasOne(t *testing.T) {
	if got := probe.Weakest(degraded(), full()).MinimumKernel; got != "5.15" {
		t.Errorf("the set's kernel floor is %q, want 5.15", got)
	}
}

// The zero request must refuse an attachment copying no plaintext: forgetting
// a setting must not produce a silent observer.
func TestTheZeroRequestIsUnmetByAnAttachmentThatCopiesNoPlaintext(t *testing.T) {
	err := (probe.Request{}).Unmet(degraded())
	if !errors.Is(err, probe.ErrDegraded) {
		t.Fatalf("a request built with nothing set met an attachment that copies no plaintext: %v", err)
	}
}

// The control: the check does not refuse everything.
func TestTheZeroRequestIsMetByAnAttachmentThatCopiesPlaintext(t *testing.T) {
	if err := (probe.Request{}).Unmet(full()); err != nil {
		t.Errorf("a request built with nothing set was refused an attachment that copies plaintext: %v", err)
	}
}

// Before placement: a build with no plaintext program cannot satisfy a
// request.
func TestARequestRequiringPlaintextIsUnmetByABuildThatCopiesNone(t *testing.T) {
	err := probe.Request{}.Unmet(
		probe.Capability{Backend: probe.BPF, Program: "meta"})
	if !errors.Is(err, probe.ErrDegraded) {
		t.Fatalf("a build with no plaintext program met a request that requires it: %v", err)
	}
	if !strings.Contains(err.Error(), "meta") {
		t.Errorf("the refusal does not name the program that was loaded: %v", err)
	}
}

// After placement: the program is loaded and the kernel holds no plaintext
// probe, which looks like a silent host.
func TestARequestRequiringPlaintextIsUnmetWhenNoPlaintextFunctionWasHeld(t *testing.T) {
	placed := full()
	placed.Payload = false
	placed.Unobserved = []string{"SSL_read", "SSL_write"}

	err := probe.Request{}.Unmet(placed)
	if !errors.Is(err, probe.ErrDegraded) {
		t.Fatalf("an attachment holding no plaintext-moving function met a request that requires "+
			"one: %v", err)
	}
	for _, symbol := range placed.Unobserved {
		if !strings.Contains(err.Error(), symbol) {
			t.Errorf("the refusal does not name %s: %v", symbol, err)
		}
	}
}

// A partial placement meets the request: its watched functions still copy
// plaintext.
func TestAPartialPlacementMeetsARequestRequiringPlaintext(t *testing.T) {
	placed := full()
	placed.Unobserved = []string{"SSL_read_early_data"}

	if err := (probe.Request{}).Unmet(placed); err != nil {
		t.Errorf("an attachment holding all but one entry point was refused: %v", err)
	}
}
