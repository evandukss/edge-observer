//go:build attach

package attach_test

import (
	"os"
	"testing"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
)

// unobservable is this test binary, which maps no OpenSSL library: a process an
// adapter can be asked for and can place nothing on.
func unobservable(t *testing.T) process.Process {
	t.Helper()

	table, err := process.Read(procfs)
	if err != nil {
		t.Fatalf("Read(%s): %v", procfs, err)
	}
	self, found := table.Lookup(int32(os.Getpid()))
	if !found {
		t.Fatalf("pid %d is absent from its own process table", os.Getpid())
	}
	return self
}

// One requested process is refused outright and the others place: the
// attachment is kept, answers for the placed one with its capability, and for
// the refused one with the reason. Refusing everything would lose observable
// traffic; answering the refused one with an empty capability would claim it
// is watched.
func TestAMemberRefusedOutrightLeavesTheOthersPlacedAndIsAnsweredForByName(t *testing.T) {
	port := serving(t)
	talking := speaking(t, port)
	refused := unobservable(t)

	adapter := attach.NeweBPF(process.Approval{})
	live, err := adapter.Attach(requesting(talking.process, refused), capture.New(&collected{}))
	if err != nil {
		t.Fatalf("one unobservable member cost the whole attachment: %v", err)
	}
	defer func() { _ = live.Close() }()

	// The refusal does not weaken the placement: a refused process has no
	// placement to fold in, and the account states it as uncovered.
	whole := live.Capability()
	if whole.Backend != probe.BPF || !whole.Payload {
		t.Errorf("the set reports %+v, and the member that placed reached the plaintext program", whole)
	}
	if len(whole.Unobserved) != 0 {
		t.Errorf("every probe of the member that placed was held and the set names %v as unobserved",
			whole.Unobserved)
	}

	covering, can := live.(probe.Covering)
	if !can {
		t.Fatal("the attachment cannot say what it can do for one process, so no account of a " +
			"partly covered family can be built from it")
	}

	placed, err := covering.Capable(talking.process.PID)
	if err != nil {
		t.Fatalf("the member that placed is not answered for: %v", err)
	}
	if !placed.Payload || placed.Backend != probe.BPF {
		t.Errorf("the member that placed reports %+v", placed)
	}

	if _, err := covering.Capable(refused.PID); err == nil {
		t.Error("a member nothing was placed for is answered with a capability rather than a reason")
	}
	if _, err := live.(probe.Attested).Placements(refused.PID); err == nil {
		t.Error("a member nothing was placed for is answered with an empty list of placements")
	}
}

// The same request from a caller requiring plaintext is not refused: the
// placement made copies plaintext, and the refused process's absence is
// reported through the account.
func TestARequestRequiringPlaintextSurvivesAMemberRefusedOutright(t *testing.T) {
	port := serving(t)
	talking := speaking(t, port)

	adapter := attach.NeweBPF(process.Approval{})
	live, err := adapter.Attach(
		requesting(talking.process, unobservable(t)), capture.New(&collected{}))
	if err != nil {
		t.Fatalf("a request requiring plaintext was refused over a member nothing could be "+
			"placed on: %v", err)
	}
	defer func() { _ = live.Close() }()

	if !live.Capability().Payload {
		t.Error("the attachment a plaintext-requiring caller was given copies no plaintext")
	}
}
