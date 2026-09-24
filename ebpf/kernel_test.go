package ebpf_test

import (
	"strconv"
	"strings"
	"testing"

	obpf "github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/probe"
)

// The floor is what the object forces: this reads the shipped full program,
// counts the instruction that decides it, and refuses a floor below the kernel
// that accepts it. (A floor from a feature table, ring buffer and namespace
// helper, would name a kernel the object cannot load on.)
func TestThePublishedFloorIsNotBelowWhatTheShippedObjectForces(t *testing.T) {
	fetches, err := obpf.AtomicFetches(obpf.Full().Object)
	if err != nil {
		t.Fatalf("read the full object: %v", err)
	}
	if fetches == 0 {
		t.Skip("the object holds no atomic add-and-fetch, so nothing here forces a floor")
	}

	if older(ebpf.MinimumKernel, obpf.AtomicFetchFloor) {
		t.Errorf("the object holds %d atomic add-and-fetch instructions, which the verifier "+
			"refuses below %s, and the published floor is %s",
			fetches, obpf.AtomicFetchFloor, ebpf.MinimumKernel)
	}
}

// older reports whether left names an earlier kernel than right, as dotted
// numbers.
func older(left, right string) bool {
	leftParts, rightParts := strings.Split(left, "."), strings.Split(right, ".")
	for i := 0; i < len(leftParts) && i < len(rightParts); i++ {
		l, lerr := strconv.Atoi(leftParts[i])
		r, rerr := strconv.Atoi(rightParts[i])
		if lerr != nil || rerr != nil {
			return false
		}
		if l != r {
			return l < r
		}
	}
	return len(leftParts) < len(rightParts)
}

// Every member of the group is placeable and says what its absence costs; a
// member with no claim would allow a silent partial placement.
func TestEveryKernelMemberNamesTheClaimItsAbsenceWithdraws(t *testing.T) {
	symbols := make(map[string]bool)
	programs := make(map[string]bool)

	for _, point := range ebpf.KernelPoints() {
		switch {
		case point.Symbol == "":
			t.Errorf("a member of the group names no kernel symbol")
		case point.Program == "":
			t.Errorf("%s names no program", point.Symbol)
		case point.Kind != ebpf.KernelKprobe && point.Kind != ebpf.KernelRawTracepoint:
			t.Errorf("%s says nothing about how it attaches", point.Symbol)
		case point.Claim == "":
			t.Errorf("%s names no claim, so its absence would withdraw nothing", point.Symbol)
		}
		if symbols[point.Symbol] {
			t.Errorf("%s appears twice", point.Symbol)
		}
		if programs[point.Program] {
			t.Errorf("%s is placed on more than one member", point.Program)
		}
		symbols[point.Symbol], programs[point.Program] = true, true
	}
}

// The IPv6 half is claimed separately, so a missing inet6 symbol does not take
// IPv4 down with it.
func TestTheIPv6MembersAreTheOnlyOnesCarryingTheIPv6Claim(t *testing.T) {
	sixes := ebpf.KernelPointsFor(probe.IPv6Claim)
	if len(sixes) != 2 {
		t.Fatalf("the IPv6 claim rests on %d members, want the two inet6 entry points", len(sixes))
	}
	for _, point := range sixes {
		if !strings.HasPrefix(point.Symbol, "inet6_") {
			t.Errorf("%s carries the IPv6 claim and is not an inet6 entry point", point.Symbol)
		}
	}

	group := ebpf.KernelPointsFor(probe.SocketEvidenceClaim)
	for _, point := range group {
		if strings.HasPrefix(point.Symbol, "inet6_") {
			t.Errorf("%s is an inet6 entry point and carries the whole group's claim, so a host "+
				"without it would report no socket evidence at all", point.Symbol)
		}
	}
	if len(group)+len(sixes) != len(ebpf.KernelPoints()) {
		t.Errorf("%d members carry neither claim",
			len(ebpf.KernelPoints())-len(group)-len(sixes))
	}
}

// Narrow only takes away: a build that cannot establish a socket from the
// kernel does not gain the claim by placing every probe.
func TestNarrowCannotGrantTheSocketClaimAFullBuildDoesNotHave(t *testing.T) {
	built := probe.Capability{Backend: probe.BPF}
	held := ebpf.Coverage{SocketEvidence: true, IPv6: true}

	narrowed := held.Narrow(built)
	if narrowed.SocketEvidence {
		t.Error("a build with no socket evidence acquired the claim from a session that has it")
	}
	if narrowed.IPv6 {
		t.Error("a build with no IPv6 coverage acquired the claim from a session that has it")
	}
}

// A withheld claim carries the member that withdrew it, through Narrow into
// what the run publishes, so a missing symbol is told from a refused
// attachment.
func TestAWithheldClaimReachesTheCapabilityWithItsMemberNamed(t *testing.T) {
	held := ebpf.Coverage{
		Withheld: []probe.Withheld{{
			Claim:  probe.IPv6Claim,
			Member: "inet6_recvmsg",
			Reason: "no such kernel symbol",
		}},
	}

	narrowed := held.Narrow(probe.Capability{Backend: probe.BPF, IPv6: true})
	if len(narrowed.Withheld) != 1 {
		t.Fatalf("the capability carries %d withheld claims, want the one the session withheld",
			len(narrowed.Withheld))
	}
	if narrowed.Withheld[0].Member != "inet6_recvmsg" {
		t.Errorf("the withheld claim names the member %q", narrowed.Withheld[0].Member)
	}
}
