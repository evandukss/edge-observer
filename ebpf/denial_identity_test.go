//go:build attach

package ebpf_test

import (
	"testing"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
)

// The old birth is constructed in the kernel map. Fork, denial propagation,
// reload admission and the positive traffic controls all run on live actors.
func TestStaleKernelDenialNeitherPropagatesNorBlocksAdmission(t *testing.T) {
	port, received := trafficPeer(t)
	controlActor := trafficActor(t, immediateForkSource(), port)
	control := loaded(t, int32(controlActor.command.Process.Pid))
	family := trafficActor(t, heldFamilySource(), port)
	root := loaded(t, int32(family.command.Process.Pid))
	s, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(),
		Points: append(points(t, root), trafficForkPoint(t, root)),
		Admit:  []admission.Selection{admit(control)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	trafficParentControl(t, controlActor, s, received)
	old := root.Instance()
	if !old.Start.Determined || old.Start.Ticks < 2 {
		t.Fatalf("unusable actor birth: %+v", old)
	}
	old.Start.Ticks--
	if err := ebpf.PlantStaleDenial(s, old); err != nil {
		t.Fatal(err)
	}
	denials, err := s.Denials()
	if err != nil || len(denials) != 1 || denials[0].Instance.Start != old.Start {
		t.Fatalf("wiring: stale denial not installed: %+v %v", denials, err)
	}
	childPID, err := family.child('L', "live")
	if err != nil {
		t.Fatal(err)
	}
	waitActorState(t, childPID, "T")
	child := loaded(t, childPID)
	denials, err = s.Denials()
	if err != nil {
		t.Fatal(err)
	}
	for _, one := range denials {
		if one.Instance.PID == child.NamespacePID && one.Instance.Namespace == child.Namespace {
			t.Errorf("stale creator denial propagated to live child: %+v", one)
		}
	}
	if err := family.finish('G', "live"); err != nil {
		t.Fatal(err)
	}
	peerReceived(t, received, "/independent-held-child")
	selected := admit(root)
	selected.Mode = admission.ModeNone
	selected.Provenance = admission.Provenance{Target: "current birth", Number: 2}
	granted, skipped, err := s.Admit([]admission.Selection{selected})
	if err != nil || len(granted) != 1 || len(skipped) != 0 {
		t.Fatalf("qualified actor blocked by stale kernel denial: grants=%v skips=%v err=%v", granted, skipped, err)
	}
	if granted[0].Instance.Start != root.Start() || granted[0].Provenance.Target != "current birth" {
		t.Fatalf("admission borrowed stale identity: %+v", granted)
	}
	trafficParentControl(t, family, s, received)
	trafficParentControl(t, controlActor, s, received)
}
