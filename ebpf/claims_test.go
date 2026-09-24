package ebpf_test

import (
	"testing"

	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/probe"
)

// holding answers for a set of members by name and refuses the rest: a host's
// state without a host.
func holding(names ...string) func(ebpf.KernelPoint) (bool, string) {
	held := make(map[string]bool, len(names))
	for _, name := range names {
		held[name] = true
	}
	return func(member ebpf.KernelPoint) (bool, string) {
		if held[member.Symbol] {
			return true, ""
		}
		return false, "no such kernel symbol"
	}
}

func every() []ebpf.KernelPoint { return ebpf.KernelPoints() }

func symbols(points []ebpf.KernelPoint) []string {
	names := make([]string, 0, len(points))
	for _, one := range points {
		names = append(names, one.Symbol)
	}
	return names
}

// without is the group less one member: a host where one required member is
// unavailable.
func without(symbol string) []ebpf.KernelPoint {
	var kept []ebpf.KernelPoint
	for _, one := range every() {
		if one.Symbol != symbol {
			kept = append(kept, one)
		}
	}
	return kept
}

// The control: a session holding every member claims both.
func TestASessionHoldingEveryMemberClaimsBoth(t *testing.T) {
	claimed := ebpf.ClaimsOver(every(), holding(symbols(every())...))
	if !claimed.SocketEvidence {
		t.Error("a session holding every member does not claim the socket evidence")
	}
	if !claimed.IPv6 {
		t.Error("a session holding every member does not claim IPv6")
	}
	if len(claimed.Withheld) != 0 {
		t.Errorf("a session holding every member withholds %v", claimed.Withheld)
	}
}

// A required member is unavailable, and the session must not claim full
// coverage. Asserted one member at a time, since the classifier and the two
// tracepoints each carry the group alone.
func TestOneMissingRequiredMemberWithdrawsTheWholeClaimByName(t *testing.T) {
	for _, member := range ebpf.KernelPointsFor(probe.SocketEvidenceClaim) {
		claimed := ebpf.ClaimsOver(every(), holding(symbols(without(member.Symbol))...))

		if claimed.SocketEvidence {
			t.Errorf("%s is unavailable and the session still claims the socket evidence", member.Symbol)
		}
		if claimed.IPv6 {
			t.Errorf("%s is unavailable and the session still claims IPv6, which rests on the group",
				member.Symbol)
		}
		if !named(claimed.Withheld, member.Symbol) {
			t.Errorf("%s is unavailable and no withheld claim names it: %v", member.Symbol, claimed.Withheld)
		}
	}
}

// The IPv6 half withdraws alone: a narrower capture, not a broken attachment.
func TestAMissingIPv6MemberWithdrawsOnlyTheIPv6Claim(t *testing.T) {
	for _, member := range ebpf.KernelPointsFor(probe.IPv6Claim) {
		claimed := ebpf.ClaimsOver(every(), holding(symbols(without(member.Symbol))...))

		if !claimed.SocketEvidence {
			t.Errorf("%s is unavailable and the socket evidence claim went with it", member.Symbol)
		}
		if claimed.IPv6 {
			t.Errorf("%s is unavailable and the session still claims IPv6", member.Symbol)
		}
		if !named(claimed.Withheld, member.Symbol) {
			t.Errorf("%s is unavailable and no withheld claim names it: %v", member.Symbol, claimed.Withheld)
		}
	}
}

// A member never asked for costs its claim as one the kernel refused does, and
// says which happened; otherwise a short set would claim coverage on fewer
// members.
func TestAMemberNobodyAskedForIsWithheldWithItsOwnReason(t *testing.T) {
	short := without("rw_verify_area")
	claimed := ebpf.ClaimsOver(short, holding(symbols(short)...))

	if claimed.SocketEvidence {
		t.Error("a session asked for six of seven members claims the whole group")
	}
	reason := reasonFor(claimed.Withheld, "rw_verify_area")
	if reason == "" {
		t.Fatalf("no withheld claim names rw_verify_area: %v", claimed.Withheld)
	}
	if reason == "no such kernel symbol" {
		t.Error("a member nobody asked for is reported as one the kernel refused, and an operator " +
			"reading that would look at their host for a member this session never asked for")
	}
}

// An empty group claims nothing.
func TestAnEmptyGroupClaimsNothing(t *testing.T) {
	claimed := ebpf.ClaimsOver(nil, holding(symbols(every())...))
	if claimed.SocketEvidence || claimed.IPv6 {
		t.Errorf("a session asked to place nothing claims %+v", claimed)
	}
	if len(claimed.Withheld) != len(every()) {
		t.Errorf("a session asked to place nothing withholds %d claims, want one per member",
			len(claimed.Withheld))
	}
}

func named(withheld []probe.Withheld, symbol string) bool {
	for _, one := range withheld {
		if one.Member == symbol {
			return true
		}
	}
	return false
}

func reasonFor(withheld []probe.Withheld, symbol string) string {
	for _, one := range withheld {
		if one.Member == symbol {
			return one.Reason
		}
	}
	return ""
}
