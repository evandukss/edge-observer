package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/evandukss/edge-observer/probe"
)

// The kernel side of the socket evidence, which establishes the socket a
// call's own I/O crossed.
//
// A descriptor number is what the process passed; the socket is what the
// kernel acquired for the operation. They diverge when the number is replaced,
// and a descriptor that arrived without a syscall (inherited across a fork,
// dup'd, passed over a unix socket, taken with pidfd_getfd, shared through a
// common file table, or open before attach) is in no table of descriptors this
// run watched being created, so that lookup misses silently.
//
// The four protocol-layer entry points hold the socket the operation uses. The
// IPv4 and IPv6 forms are distinct functions, so both are placed and IPv6
// carries its own claim; the generic layer above them misses fast paths.
// rw_verify_area makes a non-socket a positive answer, so "no network hook
// fired" is not taken as a file. The two raw syscall tracepoints carry the
// descriptor operand and the result, covering direct syscalls too.
//
// They attach through the performance-event kprobe interface, which needs no
// tracefs mount. A required member the kernel will not take withdraws its
// claim by name; no weaker resolution is selected. They are placed before
// privilege.Drop, after which nothing can attach (package privilege).

// KernelKind is how a member is attached: a kprobe on a kernel function by name
// through the performance-event interface, or a raw tracepoint by name through
// bpf(2).
type KernelKind uint8

const (
	// KernelKprobe is an entry kprobe on a kernel function.
	KernelKprobe KernelKind = iota + 1
	// KernelRawTracepoint is a raw tracepoint attached by name.
	KernelRawTracepoint
)

// KernelPoint is one member of the socket evidence group. Claim is what its
// absence costs: the four IPv4 members and two tracepoints carry the group, and
// the two IPv6 members only IPv6. Without rw_verify_area there is no group.
type KernelPoint struct {
	// Symbol is the kernel function for a kprobe, or the tracepoint name for a
	// raw tracepoint.
	Symbol string

	// Program is the BPF program that goes on it.
	Program string

	Kind  KernelKind
	Claim probe.Claim
}

// The programs of the group, by the name each carries in the object.
const (
	progInetSendmsg  = "obs_inet_sendmsg"
	progInetRecvmsg  = "obs_inet_recvmsg"
	progInet6Sendmsg = "obs_inet6_sendmsg"
	progInet6Recvmsg = "obs_inet6_recvmsg"
	progVerifyArea   = "obs_rw_verify_area"
	progSyscallEnter = "obs_sys_enter"
	progSyscallExit  = "obs_sys_exit"
)

// KernelPoints is every member of the group in a fixed order: the tracepoints,
// the classifier, then the protocol entry points by family.
func KernelPoints() []KernelPoint {
	return []KernelPoint{
		{Symbol: "sys_enter", Program: progSyscallEnter, Kind: KernelRawTracepoint, Claim: probe.SocketEvidenceClaim},
		{Symbol: "sys_exit", Program: progSyscallExit, Kind: KernelRawTracepoint, Claim: probe.SocketEvidenceClaim},
		{Symbol: "rw_verify_area", Program: progVerifyArea, Kind: KernelKprobe, Claim: probe.SocketEvidenceClaim},
		{Symbol: "inet_sendmsg", Program: progInetSendmsg, Kind: KernelKprobe, Claim: probe.SocketEvidenceClaim},
		{Symbol: "inet_recvmsg", Program: progInetRecvmsg, Kind: KernelKprobe, Claim: probe.SocketEvidenceClaim},
		{Symbol: "inet6_sendmsg", Program: progInet6Sendmsg, Kind: KernelKprobe, Claim: probe.IPv6Claim},
		{Symbol: "inet6_recvmsg", Program: progInet6Recvmsg, Kind: KernelKprobe, Claim: probe.IPv6Claim},
	}
}

// KernelPointsFor is the members carrying one claim.
func KernelPointsFor(claim probe.Claim) []KernelPoint {
	var members []KernelPoint
	for _, point := range KernelPoints() {
		if point.Claim == claim {
			members = append(members, point)
		}
	}
	return members
}

// Claimed is what a set of placements amounts to: which claims are made, and
// which are withheld with the member that cost each. A pure function, so the
// arithmetic can be tested without a kernel.
type Claimed struct {
	SocketEvidence bool
	IPv6           bool
	Withheld       []probe.Withheld
}

// ClaimsOver is what a session claims, given the group it was asked to place
// and what it holds. A member not asked for and a member refused both withdraw
// their claim, with different reasons. IPv6 also rests on the group: IPv6
// coverage without the tracepoints and classifier covers nothing.
func ClaimsOver(asked []KernelPoint, held func(KernelPoint) (bool, string)) Claimed {
	inSet := make(map[string]bool, len(asked))
	for _, one := range asked {
		inSet[one.Symbol] = true
	}

	var claimed Claimed
	holds := make(map[probe.Claim]int, 2)
	needs := make(map[probe.Claim]int, 2)

	for _, member := range KernelPoints() {
		needs[member.Claim]++
		if !inSet[member.Symbol] {
			claimed.Withheld = append(claimed.Withheld, probe.Withheld{
				Claim:  member.Claim,
				Member: member.Symbol,
				Reason: "this session was not asked to place it",
			})
			continue
		}
		placed, why := held(member)
		if !placed {
			claimed.Withheld = append(claimed.Withheld, probe.Withheld{
				Claim: member.Claim, Member: member.Symbol, Reason: why,
			})
			continue
		}
		holds[member.Claim]++
	}

	// A claim is made when every member it rests on was placed, counted over the
	// whole group, so a short ask withholds rather than claims.
	whole := func(claim probe.Claim) bool { return holds[claim] == needs[claim] }
	claimed.SocketEvidence = whole(probe.SocketEvidenceClaim)
	claimed.IPv6 = claimed.SocketEvidence && whole(probe.IPv6Claim)
	return claimed
}

// placeKernel attaches the socket evidence group and records which claims this
// session makes. A member that cannot be placed withdraws its claim by name,
// and an incomplete claim rolls back its placed members rather than
// half-enabling. The TLS capture already placed stands, as a narrower capture.
// Only the performance-event interface is used, never a tracefs mount. It runs
// before privilege.Drop, the last moment anything can attach.
func (s *Session) placeKernel() error {
	put := make(map[probe.Claim][]link.Link, 2)

	claimed := ClaimsOver(s.asked, func(member KernelPoint) (bool, string) {
		program := s.collection.Programs[member.Program]
		if program == nil {
			return false, "this build carries no " + member.Program
		}
		attached, err := attachKernel(member, program)
		if err != nil {
			return false, err.Error()
		}
		put[member.Claim] = append(put[member.Claim], attached)
		return true, ""
	})

	// A claim that did not come through takes its members' links with it; losing
	// the group takes IPv6 too.
	if !claimed.SocketEvidence {
		s.rollback(put[probe.SocketEvidenceClaim])
	}
	if !claimed.IPv6 {
		s.rollback(put[probe.IPv6Claim])
	}
	if claimed.SocketEvidence {
		s.links = append(s.links, put[probe.SocketEvidenceClaim]...)
	}
	if claimed.IPv6 {
		s.links = append(s.links, put[probe.IPv6Claim]...)
	}

	s.evidence, s.sixes, s.withheld = claimed.SocketEvidence, claimed.IPv6, claimed.Withheld
	return nil
}

// rollback detaches what a withdrawn claim had placed. A failed close is not
// reported: a member left attached only writes into maps nothing reads.
func (s *Session) rollback(links []link.Link) {
	for _, one := range links {
		_ = one.Close()
	}
}

// attachKernel places one member through the interface its kind names.
func attachKernel(member KernelPoint, program *ebpf.Program) (link.Link, error) {
	switch member.Kind {
	case KernelRawTracepoint:
		return link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    member.Symbol,
			Program: program,
		})
	case KernelKprobe:
		return link.Kprobe(member.Symbol, program, nil)
	default:
		return nil, fmt.Errorf("no attachment is known for %s", member.Symbol)
	}
}

// Withheld is every claim this session does not make, with the member whose
// absence withdrew it, read off what was asked for and what was placed.
func (s *Session) Withheld() []probe.Withheld { return s.withheld }
