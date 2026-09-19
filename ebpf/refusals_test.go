package ebpf

import (
	"errors"
	"testing"

	"github.com/evandukss/edge-observer/admission"
	obpf "github.com/evandukss/edge-observer/bpf"
)

// Which counter each refusal reason is read from, asserted by name: a reason
// wired to the wrong counter reads a valid number under the wrong meaning, and
// Refusals errors only when a counter cannot be read. The pairs follow the
// program's own words, so a rewiring must change both.
func TestEveryRefusalReasonIsReadFromTheCounterItMeans(t *testing.T) {
	meant := map[RefusalReason]string{
		TransferRefusedAtReturn: "OBS_STAT_REFUSED",
		CallNotRecorded:         "OBS_STAT_CALL_UNRECORDED",
		ReadNotFiled:            "OBS_STAT_READ_UNRECORDED",
		DescendantNotWritten:    "OBS_STAT_DESCENDANT_UNRECORDED",
		DenialNotWritten:        "OBS_STAT_DENIAL_UNRECORDED",
		NeverAdmitted:           "OBS_STAT_DEFERRED_DISCARDED",
		NotTheApprovedOccupant:  "OBS_STAT_UNAUTHENTICATED",
		ChildUnnameable:         "OBS_STAT_CHILD_UNNAMEABLE",

		ChildNamespaceUnenumerated: "OBS_STAT_CHILD_NS_UNENUMERATED",

		SocketDescriptorInvalid:   "OBS_STAT_SOCKET_FD_INVALID",
		SocketWorkOutsideACall:    "OBS_STAT_SOCKET_OUTSIDE_CALL",
		SocketTaskUnlocatable:     "OBS_STAT_SOCKET_UNLOCATABLE",
		SocketLifetimeUnknown:     "OBS_STAT_SOCKET_NO_LIFETIME",
		DescriptorSeenInsideACall: "OBS_STAT_SOCKET_RECORDED",
	}

	if len(refusalCounters) != len(meant) {
		t.Fatalf("%d reasons are read from a counter and %d are named here; a reason added without "+
			"a line here is one nothing checks the meaning of", len(refusalCounters), len(meant))
	}

	for reason, index := range refusalCounters {
		name, named := meant[reason]
		if !named {
			t.Errorf("reason %v is read from index %d and nothing here says which counter it means",
				reason, index)
			continue
		}
		want, defined := obpf.Stats[name]
		if !defined {
			t.Errorf("reason %v is meant to read %s and the registry names no such counter", reason, name)
			continue
		}
		if index != want {
			t.Errorf("reason %v reads index %d and %s is index %d, so its number is filed under "+
				"another counter's meaning", reason, index, name, want)
		}
	}
}

// Every index a reason reads is one the registry names; no bare literals.
func TestNoRefusalReasonReadsAnIndexTheRegistryDoesNotName(t *testing.T) {
	named := make(map[uint32]string, len(obpf.Stats))
	for name, index := range obpf.Stats {
		named[index] = name
	}
	for reason, index := range refusalCounters {
		if _, found := named[index]; !found {
			t.Errorf("reason %v reads index %d, which the registry names no counter for", reason, index)
		}
	}
}

// encode's birth field decides whether an approved process is observed at all,
// and a selection with no start identity has nothing to put there.
func TestAGrantCarriesTheStartIdentityOfTheProcessItWasWrittenFor(t *testing.T) {
	value, err := encode(admission.Selection{
		Instance: admission.Instance{
			Namespace:  admission.Namespace{Device: 3, Inode: 4026531836},
			PID:        4321,
			Generation: 7,
			Start:      admission.Determinate(admission.BootTicks(37574)),
		},
		Kind:        admission.ByTarget,
		Mode:        admission.ModeFollow,
		Propagation: admission.CanPropagate,
		Provenance:  admission.Provenance{Target: "a target", Number: 1, Rule: 1},
	}, 3)
	if err != nil {
		t.Fatalf("encode a selection with a start identity: %v", err)
	}
	if value.Birth != 37574 {
		t.Errorf("the grant carries birth %d and the process was approved as the one that started at "+
			"tick 37574, so the program would authenticate every read against the wrong process",
			value.Birth)
	}
}

func TestASelectionWithNoStartIdentityIsNotWrittenAsAGrant(t *testing.T) {
	value, err := encode(admission.Selection{
		Instance: admission.Instance{
			Namespace:  admission.Namespace{Device: 3, Inode: 4026531836},
			PID:        4321,
			Generation: 7,
			Start:      admission.Indeterminate(),
		},
		Kind:        admission.ByTarget,
		Mode:        admission.ModeFollow,
		Propagation: admission.CanPropagate,
		Provenance:  admission.Provenance{Target: "a target", Number: 1, Rule: 1},
	}, 3)
	if err == nil {
		t.Fatalf("a selection whose start could not be read encoded as a grant carrying birth %d, "+
			"which is a grant the program can authenticate nothing against", value.Birth)
	}
	if !errors.Is(err, errNoBirth) {
		t.Errorf("a selection with no start identity was refused as %v, and a caller branching on "+
			"the reason would report it as something other than a start that could not be read", err)
	}
}
