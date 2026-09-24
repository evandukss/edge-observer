package ebpf

import (
	"slices"

	obpf "github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/probe"
)

// Placed is one point this session asked the kernel for, with whether the
// kernel holds every probe it needed. A point whose entry probe went on and
// whose return did not is not confirmed: the entry alone records calls that
// never complete.
type Placed struct {
	Point     Point
	Confirmed bool
}

// Coverage is what a session's placements amount to: which things its program
// can do are observed, and which catalogued entry points the kernel holds no
// probe on. What the build could do says nothing about entry points that did
// not place, where bytes are simply absent.
type Coverage struct {
	// Payload is whether any plaintext-moving function is observed; Unobserved
	// names the ones that are not.
	Payload bool

	// Descendants is whether what approved processes create will be observed. It
	// is a policy answer: a child is admitted at the kernel's fork event, armed
	// before any point is placed and fatal to the attachment if it fails, so only
	// the approvals' modes decide it. Session.Coverage fills it; CoverageOf does
	// not.
	Descendants bool

	// Lifecycle is whether a connection ending is observed.
	Lifecycle bool

	// Binding is whether this session holds a point that can record a descriptor
	// against a call. Of fourteen socket entry points only the send, receive, read
	// and write families do; socket, accept, connect, close and dup2 maintain the
	// occupancy table (package bpf, BindingPrograms). It is not the precondition
	// for trusting an unknown association: with Binding and without
	// SocketEvidence a session names the number a call passed and cannot say which
	// socket it was.
	Binding bool

	// SocketEvidence is whether this session holds every required member of the
	// kernel evidence group (kernel.go). Binding without it establishes nothing
	// for a descriptor that arrived without a syscall, and reports every
	// association unknown while looking healthy.
	SocketEvidence bool

	// IPv6 is whether the group's IPv6 members are held; without them the capture
	// is narrower, not broken.
	IPv6 bool

	// Withheld is every claim this session does not make, with the member whose
	// absence withdrew it and the kernel's words, so a missing symbol can be told
	// from a refused attachment.
	Withheld []probe.Withheld

	// Unobserved is every catalogued entry point the kernel holds no probe on, in
	// asked order. Fork and socket points are not catalogued functions; their
	// absence shows in the booleans above.
	Unobserved []string
}

// CoverageOf reduces what the kernel answered to what this session observes.
func CoverageOf(answered []Placed) Coverage {
	var coverage Coverage
	for _, one := range answered {
		if !one.Confirmed {
			if catalogued(one.Point) {
				coverage.Unobserved = append(coverage.Unobserved, one.Point.Symbol)
			}
			continue
		}
		switch {
		// The fork pair is absent here: it decides the window a call inside a fork is
		// held through, not whether a descendant is observed.
		case one.Point.Entry == progFreeEntry:
			coverage.Lifecycle = true
		case bindingProgram(one.Point):
			coverage.Binding = true
		case socketProgram(one.Point):
			// A socket point maintaining the occupancy table: neither catalogued nor a
			// binding source.
		case catalogued(one.Point):
			coverage.Payload = true
		}
	}
	return coverage
}

// Narrow is what the build can do, reduced to what this session holds. It only
// takes away.
func (c Coverage) Narrow(built probe.Capability) probe.Capability {
	built.Payload = built.Payload && c.Payload
	built.Descendants = built.Descendants && c.Descendants
	built.Lifecycle = built.Lifecycle && c.Lifecycle
	built.Binding = built.Binding && c.Binding
	built.SocketEvidence = built.SocketEvidence && c.SocketEvidence
	built.IPv6 = built.IPv6 && c.IPv6
	built.Unobserved = slices.Clone(c.Unobserved)
	built.Withheld = slices.Clone(c.Withheld)
	return built
}

// Coverage is what this session observes, read off what the kernel says it
// holds.
func (s *Session) Coverage() Coverage {
	answered := make([]Placed, 0, len(s.placed))
	for _, put := range s.placed {
		answered = append(answered, Placed{Point: put.point, Confirmed: s.answer(put).Confirmed})
	}
	coverage := CoverageOf(answered)

	// The socket evidence was established by placeKernel, and is reported here
	// rather than derived a second time.
	coverage.SocketEvidence = s.evidence
	coverage.IPv6 = s.sixes
	coverage.Withheld = s.withheld

	// Descendants are admitted at the kernel's fork event, which every session
	// has, so the policy decides and is answered here.
	for _, one := range s.accepted {
		if one.Mode.Answers().Future {
			coverage.Descendants = true
			break
		}
	}
	return coverage
}

// catalogued reports whether a point is one of the observed runtime's own entry
// points, as opposed to the C library points a session places beside them.
func catalogued(point Point) bool {
	return !socketProgram(point) &&
		point.Entry != ForkEntryProgram && point.Return != ForkReturnProgram
}

// bindingProgram reports whether a point carries a program that records a
// descriptor against the call in flight, which is what establishes a binding.
func bindingProgram(point Point) bool { return obpf.BindingPrograms[point.Entry] }

// socketProgram reports whether a point carries any socket program, which keeps
// it out of the catalogued entry points.
func socketProgram(point Point) bool {
	for _, program := range SocketPrograms {
		if point.Entry == program {
			return true
		}
	}
	for _, program := range SocketReturnPrograms {
		if point.Return == program {
			return true
		}
	}
	return false
}
