// Package connection is what the observer publishes about a captured
// connection: which one it is, what it was bound to, for how long that binding
// held, and where its bytes stop being placeable. It carries what a fragment
// leaves out - descriptor, endpoints, namespace, open and close times, and the
// evidence for each - joined by ConnectionID.
//
// Three records, because they fail differently:
//
//	Record       one connection: its identity, its lifetime, and what it is
//	             joined to
//	Association  one direction's binding to a socket, its state, the reason
//	             for that state, and the interval it held
//	Placement    where a direction's bytes stop being placeable, which is what
//	             a lost observation costs
//
// An unknown association is not byte corruption: it prevents only an exact
// join with an outside record. An established one can still have lost an
// event, after which positions are not established.
//
// Nothing is invented: descriptor zero and port zero are valid, so every field
// that can be absent says whether it is present, and every state but
// Established says which reason it holds.
package connection

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/fragment"
)

// ErrInvalid is what every Validate failure here wraps.
var ErrInvalid = errors.New("invalid connection record")

// Generation separates one occupancy of a reusable name from the next: a
// handle generation for a library handle address, a binding generation for a
// descriptor number. It is a counter, not a time; zero is none.
type Generation uint64

// Known reports whether this names a generation.
func (g Generation) Known() bool { return g != 0 }

func (g Generation) String() string {
	if !g.Known() {
		return "no generation"
	}
	return fmt.Sprintf("generation %d", uint64(g))
}

// Netns is a network namespace, named by the device and inode of the nsfs
// entry behind /proc/<pid>/ns/net. Addresses mean something only inside one:
// two containers can each hold 10.0.0.2:8443.
type Netns struct {
	Device uint64
	Inode  uint64
}

// Known reports whether this names a namespace. The zero value, from an unread
// /proc/<pid>/ns/net, does not.
func (n Netns) Known() bool { return n.Device != 0 || n.Inode != 0 }

func (n Netns) String() string {
	if !n.Known() {
		return "a network namespace nothing here names"
	}
	return fmt.Sprintf("network namespace %d:%d", n.Device, n.Inode)
}

// Descriptor is a file descriptor as evidence. Known is required because
// descriptor zero is ordinary, so zero cannot mean "not established".
type Descriptor struct {
	Number int32
	Known  bool
}

// Socket is the socket a call's I/O crossed, by the kernel's inode for it (as
// ss, /proc/net and /proc/<pid>/fd report). Published because a descriptor
// number cannot be compared with anything outside this observer: one slot holds
// different sockets over time.
//
// Inodes are reused once a socket is freed, so it is meaningful only with the
// Binding generation beside it. Unnamed (zero) is an absence: a socket with no
// file has no inode.
type Socket struct {
	Inode uint64
	Known bool
}

// Named is a socket whose own inode this run read.
func Named(inode uint64) Socket {
	if inode == 0 {
		return Socket{}
	}
	return Socket{Inode: inode, Known: true}
}

// Unnamed is a socket this run could not name. It is the zero value.
func Unnamed() Socket { return Socket{} }

func (s Socket) String() string {
	if !s.Known {
		return "a socket nothing here named"
	}
	return fmt.Sprintf("socket:[%d]", s.Inode)
}

// Held is a descriptor that was established.
func Held(number int32) Descriptor { return Descriptor{Number: number, Known: true} }

// Unheld is a descriptor nothing established. It is the zero value, so an
// unfilled field reads as unknown, not descriptor zero.
func Unheld() Descriptor { return Descriptor{} }

func (d Descriptor) String() string {
	if !d.Known {
		return "a descriptor nothing here established"
	}
	return fmt.Sprintf("descriptor %d", d.Number)
}

// Address is one end of a connection. Port zero and the unspecified address
// are valid, so presence is carried beside the values.
type Address struct {
	IP    netip.Addr
	Port  uint16
	Known bool
}

// At is an address that was established.
func At(ip netip.Addr, port uint16) Address { return Address{IP: ip, Port: port, Known: true} }

// Nowhere is an address nothing established.
func Nowhere() Address { return Address{} }

func (a Address) String() string {
	if !a.Known {
		return "an address nothing here established"
	}
	return netip.AddrPortFrom(a.IP, a.Port).String()
}

// Endpoints is both ends as far as each was established; either may be unknown
// alone. Netns is the namespace of these addresses - the socket's own, which
// can differ from its holder's (a socket inherited across a namespace change or
// passed in). The process's namespace is recorded separately (Record.Network).
type Endpoints struct {
	Local  Address
	Remote Address
	Netns  Netns
}

// Complete reports whether both ends and their namespace were established:
// what an exact join needs.
func (e Endpoints) Complete() bool { return e.Local.Known && e.Remote.Known && e.Netns.Known() }

func (e Endpoints) String() string {
	return fmt.Sprintf("%s to %s in %s", e.Local, e.Remote, e.Netns)
}

// State is what is established about a binding. Four states, no "probably":
// Established may be joined on; the other three are distinct defects - nothing
// seen, too much seen, or seen and no longer true.
type State uint8

const (
	// StateUnset is the zero value; a record carrying it is refused.
	StateUnset State = iota

	// Established is a binding this run observed and has evidence for over a
	// stated interval.
	Established

	// Unknown is no valid binding, with a required reason saying which.
	Unknown

	// Ambiguous is a call whose window held socket work on more than one
	// descriptor: something was seen, and which one is missing. Never resolved to
	// the first.
	Ambiguous

	// Invalidated is a binding that was established and has stopped being
	// trustworthy: the descriptor was replaced under it, the transport beneath
	// the handle changed, or the lifetime evidence it rested on ran out.
	Invalidated
)

func (s State) String() string {
	switch s {
	case Established:
		return "established"
	case Unknown:
		return "unknown"
	case Ambiguous:
		return "ambiguous"
	case Invalidated:
		return "invalidated"
	default:
		return "unset"
	}
}

// Reason says which of the named states this is; every state but Established
// requires one. Every reason is about the binding; whether its endpoints can be
// joined is a separate axis (Joinability), because a binding without endpoints
// is not an absent binding. Reasons are distinct because a reader acts
// differently on each: coverage, the ring buffer, the host.
type Reason uint8

const (
	// ReasonUnset is the zero value: the only valid reason for Established.
	ReasonUnset Reason = iota

	// The reasons an association is Unknown. BindingUnobservable and
	// SocketEvidenceUnavailable are about this run's own probes; the rest are
	// about the observed process or the host.
	// same has lost it.

	// NoBindingObserved is a call with no kernel I/O of its own and no earlier
	// binding to carry forward: a read served from the library's buffer, or setup
	// before this run attached. The narrowest unknown, not a bucket: every other
	// reason below is a call that did perform I/O.
	NoBindingObserved
	// InsertionRefused is a binding the kernel side established and could not
	// record because its map was full.
	InsertionRefused
	// ObservationLost is binding evidence submitted and never delivered: the ring
	// buffer's loss reaching the association. A hole, not a quiet call.
	ObservationLost
	// TransportUnsupported is a handle whose transport this build does not follow:
	// a BIO answering no descriptor, or a non-socket transport.
	TransportUnsupported
	// BindingUnobservable is a run that placed no probe able to observe a binding.
	// Its output is identical to NoBindingObserved on every connection; this says
	// the observer was not watching, rather than that the process did nothing.
	BindingUnobservable
	// OperationWasNotASocket is a call whose own I/O the kernel classified as an
	// ordinary file: a determinate answer, not an absence.
	OperationWasNotASocket
	// EvidenceUnreadable is an operation whose acquired object could not be read.
	// It must never inherit an earlier cached binding.
	EvidenceUnreadable
	// OperationUnresolved is a supported syscall inside the call that reached no
	// classification or confirmation.
	OperationUnresolved
	// RouteUnsupported is I/O through a route this build does not follow:
	// unix-domain, sendpage, splice, asynchronous submission, or work on another
	// thread. A coverage limit, distinct from TransportUnsupported.
	RouteUnsupported
	// OperationFrameBroken is an operation frame nested, overwritten or completed
	// with no entry. It cannot donate a cached success.
	OperationFrameBroken
	// SocketEvidenceUnavailable is a run whose kernel evidence group is not
	// placed. It is to SocketEvidence what BindingUnobservable is to Binding.
	SocketEvidenceUnavailable

	// The reason an association is Ambiguous.

	// SeveralDescriptors is a call window with socket work on more than one
	// descriptor; which carried the bytes is undecidable.
	SeveralDescriptors

	// The reasons an association is Invalidated.

	// DescriptorReplaced is the socket beneath a bound descriptor changing with no
	// TLS library call (dup2 onto it, for example).
	DescriptorReplaced
	// TransportReplaced is a fresh BIO installed on a live handle.
	TransportReplaced
	// LifetimeEvidenceEnded is a binding whose descriptor lifetime evidence ran
	// out: the socket closed, or the run lost track of it.
	LifetimeEvidenceEnded
	// HandleReleased is the library handle released or recycled. SSL_free is
	// reference counted and SSL_clear recycles in place, so this invalidates the
	// binding without proving the connection ended.
	HandleReleased
	// HandleLifetimeUnobservable is a run with no probe on handle release. A
	// binding was established but nothing bounds how long it held, since the
	// address may be reused unseen: bytes are kept, the association invalidated,
	// and no claim is made about when a reuse happened.
	HandleLifetimeUnobservable
)

func (r Reason) String() string {
	switch r {
	case NoBindingObserved:
		return "no binding was observed"
	case InsertionRefused:
		return "the binding could not be recorded"
	case ObservationLost:
		return "the observation of the binding was lost"
	case TransportUnsupported:
		return "the transport answers no descriptor"
	case BindingUnobservable:
		return "no probe that could observe a binding was placed"
	case OperationWasNotASocket:
		return "the call's own I/O was an ordinary file"
	case EvidenceUnreadable:
		return "the socket the operation acquired could not be read"
	case OperationUnresolved:
		return "the call's own I/O reached no socket evidence"
	case RouteUnsupported:
		return "the call's I/O took a route this build does not follow"
	case OperationFrameBroken:
		return "the operation frame this call's evidence would have hung on was broken"
	case SocketEvidenceUnavailable:
		return "no kernel evidence of the socket a call's I/O crossed was placed"
	case SeveralDescriptors:
		return "the call's window held socket work on more than one descriptor"
	case DescriptorReplaced:
		return "the descriptor was replaced under the binding"
	case TransportReplaced:
		return "the handle's transport was replaced"
	case LifetimeEvidenceEnded:
		return "the descriptor lifetime evidence ran out"
	case HandleReleased:
		return "the handle was released or recycled"
	case HandleLifetimeUnobservable:
		return "no probe that could observe the handle's release was placed"
	default:
		return "no reason"
	}
}

// holds reports whether this reason may accompany that state.
func (r Reason) holds(state State) bool {
	switch state {
	case Established:
		return r == ReasonUnset
	case Unknown:
		return r == NoBindingObserved || r == InsertionRefused || r == ObservationLost ||
			r == TransportUnsupported || r == BindingUnobservable ||
			r == OperationWasNotASocket || r == EvidenceUnreadable ||
			r == OperationUnresolved || r == RouteUnsupported ||
			r == OperationFrameBroken || r == SocketEvidenceUnavailable
	case Ambiguous:
		return r == SeveralDescriptors
	case Invalidated:
		return r == DescriptorReplaced || r == TransportReplaced ||
			r == LifetimeEvidenceEnded || r == HandleReleased || r == HandleLifetimeUnobservable
	default:
		return false
	}
}

// Joinability is the second axis: is the endpoint tuple complete enough to
// join an outside record of the same connection. Stored rather than derived
// from the state, so consumers never infer it.
type Joinability uint8

const (
	// JoinabilityUnset is the zero value; an association carrying it is refused.
	JoinabilityUnset Joinability = iota
	// Joins is an association whose endpoint tuple and namespace are complete.
	Joins
	// DoesNotJoin is one whose tuple is not, with a JoinReason saying why.
	DoesNotJoin
)

func (j Joinability) String() string {
	switch j {
	case Joins:
		return "joinable"
	case DoesNotJoin:
		return "not joinable"
	default:
		return "unset"
	}
}

// JoinReason says why an association cannot be joined. Every reason is about
// the endpoints, not the binding.
type JoinReason uint8

const (
	// JoinReasonUnset is the zero value: the only valid reason for Joins.
	JoinReasonUnset JoinReason = iota
	// NoBindingToJoin is an association with no valid binding, so no socket to
	// take endpoints from.
	NoBindingToJoin
	// EndpointUnreadable is a binding whose addresses a producer tried and failed
	// to read. It claims a producer ran.
	EndpointUnreadable
	// NoEndpointProducer is a build that establishes no endpoints for any
	// connection: a fact about the build.
	NoEndpointProducer

	// NamespaceUnestablished is a binding whose addresses were read and whose
	// network namespace was not. The reads fail independently, and an address
	// without its namespace is not joinable.
	NamespaceUnestablished
)

func (j JoinReason) String() string {
	switch j {
	case NoBindingToJoin:
		return "there is no binding to take endpoints from"
	case EndpointUnreadable:
		return "the endpoints could not be read"
	case NoEndpointProducer:
		return "this build establishes no endpoints"
	case NamespaceUnestablished:
		return "the addresses were read and the namespace they are in was not"
	default:
		return "no reason"
	}
}

// Source is where a binding's evidence came from; the sources differ in reach.
type Source uint8

const (
	// SourceUnset is the zero value and names nothing.
	SourceUnset Source = iota

	// SetterArgument is the descriptor passed to the library's setter (SSL_set_fd
	// and family): direct, no window, no inference.
	SetterArgument

	// InCallSyscall is a socket syscall on the calling thread between an SSL
	// call's entry and return. It need not come from the TLS library (a custom BIO
	// makes it), so it reaches paths where the setter never runs.
	InCallSyscall

	// SocketLifetime is the descriptor's lifetime record from socket-creating and
	// -destroying syscalls. It carries a binding across calls with no syscall of
	// their own, and runs out when a descriptor is replaced.
	SocketLifetime
)

func (s Source) String() string {
	switch s {
	case SetterArgument:
		return "the library's own setter argument"
	case InCallSyscall:
		return "a socket syscall inside the call on the same thread"
	case SocketLifetime:
		return "the descriptor's own lifetime record"
	default:
		return "no evidence source"
	}
}

// Interval is when a fact held: [From, Until), Open meaning it had not stopped
// when the run was sealed. Required on an established association; an
// invalidation truncates it.
type Interval struct {
	From  time.Time
	Until time.Time
	Open  bool
}

// Since is an interval that has not ended.
func Since(from time.Time) Interval { return Interval{From: from, Open: true} }

// Between is an interval that has ended.
func Between(from, until time.Time) Interval { return Interval{From: from, Until: until} }

// Holds reports whether the interval covers an instant. An open interval
// covers everything from its start.
func (i Interval) Holds(at time.Time) bool {
	if at.Before(i.From) {
		return false
	}
	return i.Open || at.Before(i.Until)
}

func (i Interval) String() string {
	if i.Open {
		return fmt.Sprintf("from %s, still open", i.From.UTC().Format(time.RFC3339Nano))
	}
	return fmt.Sprintf("from %s to %s",
		i.From.UTC().Format(time.RFC3339Nano), i.Until.UTC().Format(time.RFC3339Nano))
}

// Validate refuses an interval with no start or ending before it begins.
func (i Interval) Validate() error {
	switch {
	case i.From.IsZero():
		return fmt.Errorf("%w: an interval with no start claims a binding for all time", ErrInvalid)
	case !i.Open && i.Until.IsZero():
		return fmt.Errorf("%w: a closed interval names when it ended", ErrInvalid)
	case !i.Open && i.Until.Before(i.From):
		return fmt.Errorf("%w: an interval that ends at %s began at %s",
			ErrInvalid, i.Until.UTC().Format(time.RFC3339Nano), i.From.UTC().Format(time.RFC3339Nano))
	}
	return nil
}

// Wire is what the socket syscall behind a binding reported: ciphertext, not
// the fragment's plaintext Length (they differ by record framing). Accepted is
// kernel acceptance, not peer receipt.
type Wire struct {
	Accepted int64
	Known    bool
}

// Accepted is a wire count that was observed.
func Accepted(bytes int64) Wire { return Wire{Accepted: bytes, Known: true} }

func (w Wire) String() string {
	if !w.Known {
		return "no wire count"
	}
	return fmt.Sprintf("%d bytes the kernel accepted", w.Accepted)
}

// Handle is one occupancy of a TLS library handle: the identity a connection
// is keyed by, every component required. An address alone is reused by the
// allocator; an instance holds many handles. Instance is admission's Key, so
// the binding belongs to the admitted execution, never to a thread.
type Handle struct {
	Instance   admission.Key
	Address    uint64
	Generation Generation
}

// Validate refuses a handle that identifies nothing.
func (h Handle) Validate() error {
	switch {
	case !h.Instance.Namespace.Known():
		return fmt.Errorf("%w: a handle in no pid namespace belongs to no execution", ErrInvalid)
	case h.Instance.PID <= 0:
		return fmt.Errorf("%w: %d names no process", ErrInvalid, h.Instance.PID)
	case !Generation(h.Instance.Generation).Known():
		return fmt.Errorf("%w: pid %d carries no admission generation, so nothing separates it "+
			"from the next process to hold that number", ErrInvalid, h.Instance.PID)
	case !h.Generation.Known():
		return fmt.Errorf("%w: handle %#x carries no handle generation, so nothing separates this "+
			"occupancy of the address from the next", ErrInvalid, h.Address)
	}
	return nil
}

func (h Handle) String() string {
	return fmt.Sprintf("handle %#x of pid %d in %s, %s",
		h.Address, h.Instance.PID, h.Instance.Namespace, h.Generation)
}

// Association is one direction's binding to a socket and how far it may be
// trusted. Per direction, because the two directions are established by
// different evidence and can disagree (a server may call SSL_set_fd for one
// and never for the other).
type Association struct {
	Connection fragment.ConnectionID `json:"connection"`
	Direction  fragment.Direction    `json:"direction"`

	State  State  `json:"state"`
	Reason Reason `json:"reason"`

	// Binding is the descriptor occupancy generation this rests on. A replacement
	// moves it, showing the socket changed while the number did not.
	Binding Generation `json:"binding"`

	Source Source `json:"source"`

	// Valid is the interval this association held over; a transfer outside it is
	// not covered, whatever the state says.
	Valid Interval `json:"valid"`

	Descriptor Descriptor `json:"descriptor"`

	// Socket is the socket that descriptor named for this call's I/O, by kernel
	// identity: comparable outside this observer, and meaningful only with Binding.
	Socket Socket `json:"socket"`

	Endpoints Endpoints `json:"endpoints"`

	// Join and JoinReason are the second axis: whether the endpoint tuple can be
	// joined with an outside record, and why not. Stored, not derived.
	Join       Joinability `json:"join"`
	JoinReason JoinReason  `json:"join_reason,omitempty"`

	// Wire is what the syscall behind the binding reported: ciphertext, not
	// the fragment's Length.
	Wire Wire `json:"wire"`

	// Contended is the descriptors an Ambiguous window held, kept and never
	// resolved to the first.
	Contended []Descriptor `json:"contended,omitempty"`

	// Basis is what an Established association rests on: this call's own I/O, or
	// an earlier call's restated. Refused for other states and not required for
	// Established (see Basis).
	Basis Basis `json:"basis"`
}

// Basis is what an Established association rests on. It is not a fifth State:
// the binding is established either way, and what differs is whether this
// call's own I/O confirmed it.
//
// Only the kernel backend produces it, so Validate refuses a basis on other
// states but does not require one on Established: unset means the backend did
// not answer, not that nothing confirmed the binding.
type Basis uint8

const (
	// BasisUnset is the zero value: the only valid basis for a non-Established
	// state.
	BasisUnset Basis = iota

	// ConfirmedInCall is a binding this call's own I/O established.
	ConfirmedInCall

	// Continuity is a call with no I/O of its own (a read served from the
	// library's buffer) whose handle still holds a binding on the current
	// occupancy. An assertion that nothing changed, never what a call that did I/O
	// with an unknown socket falls through to.
	Continuity
)

func (b Basis) String() string {
	switch b {
	case ConfirmedInCall:
		return "established by this call's own I/O"
	case Continuity:
		return "continued from the handle's earlier binding, this call performing none of its own"
	default:
		return "unset"
	}
}

// Joinable reports whether this association may join the connection to an
// outside record. Use it rather than "not Unknown", which admits Ambiguous and
// Invalidated.
func (a Association) Joinable() bool { return a.Join == Joins }

// Validate reports what would make this association unusable to a consumer.
func (a Association) Validate() error {
	switch {
	case a.Direction != fragment.Sent && a.Direction != fragment.Received:
		return fmt.Errorf("%w: direction %d is neither sent nor received", ErrInvalid, a.Direction)
	case a.State == StateUnset:
		return fmt.Errorf("%w: connection %d %s carries no association state, and an association "+
			"nobody filled in is not an established one", ErrInvalid, a.Connection, a.Direction)
	case !a.Reason.holds(a.State):
		return fmt.Errorf("%w: connection %d %s is %s and gives the reason %q, which does not belong "+
			"to that state", ErrInvalid, a.Connection, a.Direction, a.State, a.Reason)
	case a.State != Established && a.Basis != BasisUnset:
		return fmt.Errorf("%w: connection %d %s is %s and claims the basis %q, which only an "+
			"established binding has", ErrInvalid, a.Connection, a.Direction, a.State, a.Basis)
	}

	switch {
	case a.Join == JoinabilityUnset:
		return fmt.Errorf("%w: connection %d %s says nothing about whether it can be joined, and "+
			"silence there reads as joinable", ErrInvalid, a.Connection, a.Direction)
	case a.Join == Joins && a.JoinReason != JoinReasonUnset:
		return fmt.Errorf("%w: connection %d %s is joinable and gives the reason %q",
			ErrInvalid, a.Connection, a.Direction, a.JoinReason)
	case a.Join == DoesNotJoin && a.JoinReason == JoinReasonUnset:
		return fmt.Errorf("%w: connection %d %s cannot be joined and says nothing about why",
			ErrInvalid, a.Connection, a.Direction)
	case a.Join == Joins && a.State != Established:
		return fmt.Errorf("%w: connection %d %s is %s and claims to be joinable, and there is no "+
			"socket to take its endpoints from", ErrInvalid, a.Connection, a.Direction, a.State)
	case a.Join == Joins && !a.Endpoints.Complete():
		return fmt.Errorf("%w: connection %d %s claims to be joinable on %s, and a join needs both "+
			"ends and the namespace they are in", ErrInvalid, a.Connection, a.Direction, a.Endpoints)
	case a.Join == DoesNotJoin && a.JoinReason == NoBindingToJoin && a.State == Established:
		return fmt.Errorf("%w: connection %d %s has an established binding and says it cannot be "+
			"joined for want of one", ErrInvalid, a.Connection, a.Direction)
	}

	if a.State == Ambiguous && len(a.Contended) < 2 {
		return fmt.Errorf("%w: connection %d %s is ambiguous and names %d descriptors; ambiguity is "+
			"more than one", ErrInvalid, a.Connection, a.Direction, len(a.Contended))
	}

	if a.State != Established {
		// Non-established associations keep their evidence, but never a descriptor
		// presented as established.
		if a.State == Unknown && a.Descriptor.Known {
			return fmt.Errorf("%w: connection %d %s is unknown because %s and still names %s",
				ErrInvalid, a.Connection, a.Direction, a.Reason, a.Descriptor)
		}
		return nil
	}

	switch {
	case a.Source == SourceUnset:
		return fmt.Errorf("%w: connection %d %s is established and names no evidence source",
			ErrInvalid, a.Connection, a.Direction)
	case !a.Descriptor.Known:
		return fmt.Errorf("%w: connection %d %s is established and names no descriptor",
			ErrInvalid, a.Connection, a.Direction)
	case !a.Binding.Known():
		return fmt.Errorf("%w: connection %d %s is established on %s with no binding generation, so "+
			"nothing separates this occupancy of the number from the next",
			ErrInvalid, a.Connection, a.Direction, a.Descriptor)
	}
	return a.Valid.Validate()
}

func (a Association) String() string {
	if a.State == Established {
		// The basis is printed too: confirmed and continued are different facts, and
		// a comparison failing on it must show it.
		return fmt.Sprintf("connection %d %s: established on %s as %s, %s, by %s, %s, %s, generation %s, %s",
			a.Connection, a.Direction, a.Descriptor, a.Socket, a.Endpoints, a.Source, a.Valid,
			a.Join, a.Binding, a.Basis)
	}
	return fmt.Sprintf("connection %d %s: %s, %s", a.Connection, a.Direction, a.State, a.Reason)
}
