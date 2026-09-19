// Package ebpf attaches the observer's BPF programs to functions in a
// process's own libraries and reads what they report.
//
// A program here can read the caller's buffer, which gives the observer the
// ability to read another process's memory. Which embedded program it loads
// decides whether it does: the full program reads plaintext, the
// metadata-only one reads none, and the observer loads the full one (package
// bpf).
//
// The allowlist is in the kernel, ahead of every read: a uprobe fires for every
// process running the library, so an unapproved process is refused inside the
// program. It names process instances (a pid namespace, the thread group id in
// it, and the admission generation), which are what an operator approves and
// what a fragment is attributed to. Anything coarser makes enforcement wider
// than approval: a cgroup holds everything a supervisor started, and a bare
// number names different processes across namespaces and over time.
package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/evandukss/edge-observer/admission"
	obpf "github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// ErrUnavailable is what attaching fails with when this host cannot load or
// attach a BPF program at all (no BPF, or no privilege). It is separate from a
// program that would not attach.
var ErrUnavailable = errors.New("this host cannot load or attach a BPF program")

// Kind is what an event reports happened.
type Kind uint8

const (
	// Transfer is a call that moved plaintext.
	Transfer Kind = 1
	// Closed is a connection ending.
	Closed Kind = 2
)

// Point is one place to attach: a symbol at a file offset in a file on disk,
// and which loaded programs go on it.
type Point struct {
	Symbol string
	Path   string
	Offset uint64

	// Entry and Return name the BPF programs as the object calls them. Either may
	// be empty: a connection ending needs only the call, and a fork only the
	// return (the child's pid is in the return register).
	Entry  string
	Return string
}

// Options is what a session attaches with.
type Options struct {
	// Program is the embedded program to load: full or metadata-only.
	Program obpf.Program

	// Points are the places to attach it.
	Points []Point

	// Admit is the allowlist: the process instances to observe, each carrying why
	// it is admitted. Empty admits nothing. A selection rather than a pid, so a
	// grant can be withdrawn without withdrawing another's (package admission).
	Admit []admission.Selection

	// Deny is what an exclusion denies: those instances and their subtrees. A
	// denial takes the key an admission would, so an instance named by both is
	// denied.
	Deny []admission.Denial

	// Kernel is the socket evidence group to place; nil means all of it, which
	// every production caller passes. A shorter set is how a missing member can be
	// exercised without a host that lacks the symbol. A member absent from this set
	// is withheld by name, exactly as one the kernel refuses; no weaker resolution
	// is selected quietly.
	Kernel []KernelPoint
}

// MinimumKernel is the oldest kernel this package will attach on, published
// rather than discovered as a failure about a map type.
//
// It is forced by the atomic allocators, not by the ring buffer (5.8) or
// bpf_get_ns_current_pid_tgid (5.7). Three allocators (the attempts counter,
// the admission stamp and the socket occupancy generation) use their
// fetch-and-add result, which compiles to BPF_ATOMIC with BPF_FETCH, refused
// before 5.12 with "BPF_XADD uses reserved fields"; the full object holds 35
// such instructions and the metadata-only one 28. They cannot drop the fetch:
// an allocator exists to return a unique number. The published floor is 5.15,
// the oldest kernel tested, above the 5.12 the object forces.
//
// A version is not the gate; the load is. Vendor kernels backport, and the
// programs read kernel structures through CO-RE, so a host must publish its own
// BTF (a build option, not a version); without it the load is refused rather
// than run degraded (bpf/ssl.bpf.h, HOST-REQUIREMENTS.md).
const MinimumKernel = "5.15"

// RefusalReason names why something was not observed. It is a value rather
// than prose because a caller acts on the difference: an unenumerated namespace
// is a host this session cannot see into; an instance gone before its entry was
// written finished its work.
type RefusalReason string

const (
	// NamespaceUnenumerated is an instance whose pid namespace this session did not
	// pass to the program, so an entry for it would never be found.
	NamespaceUnenumerated RefusalReason = "its pid namespace is not one this session enumerated"

	// StartIndeterminate is an instance whose start identity could not be read, so
	// nothing separates it from the next holder of its number. Not a start of zero.
	StartIndeterminate RefusalReason = "its start identity could not be read"

	// IdentityChanged is a number the kernel handed to another process between the
	// approval's reading and this attachment.
	IdentityChanged RefusalReason = "the number now names a different process from the one approved"

	// GoneBeforeAdmission is a descendant found in the process table and written
	// into the allowlist that was no longer itself when the table was read again.
	// Its entry is withdrawn.
	GoneBeforeAdmission RefusalReason = "it was gone, or no longer itself, before its entry was written"

	// PolicyIncomplete is a selection this session could not act on: no
	// descendant mode, or a mode it does not know.
	PolicyIncomplete RefusalReason = "it carries no descendant mode this session can act on"

	// ExcludedBySubtree is an instance an exclusion denies; a target naming it does
	// not override that.
	ExcludedBySubtree RefusalReason = "an exclusion denies it, and a target naming it does not override that"

	// DenialNotWritten is a child of a denied instance that the allowlist
	// would not take, so the subtree's denial did not reach it.
	DenialNotWritten RefusalReason = "the allowlist would not take a child of a denied instance"

	// InstanceGone is an allowlist entry for a number no process holds: a
	// descendant that exited between the table reading and the write, after the
	// exit hook had fired (adopt, sweep).
	InstanceGone RefusalReason = "the allowlist holds it and no process holds that number"

	// NeverAdmitted is a call held through a fork window whose task was still not
	// admitted at its return. Nothing was read; on a busy host this is ordinary.
	NeverAdmitted RefusalReason = "a call held through a fork window belonged to a task that was never admitted"

	// DescendantNotWritten is a child of an admitted instance the allowlist would
	// not take, counted because the program cannot say which child.
	DescendantNotWritten RefusalReason = "the allowlist would not take a child of an admitted instance"

	// CallNotRecorded is a call the in-flight table would not take on its way in.
	CallNotRecorded RefusalReason = "the in-flight table would not take a call on its way in"

	// TransferRefusedAtReturn is an in-flight call that reached its return with
	// its admission gone. The payload was not read; the bytes are absent.
	TransferRefusedAtReturn RefusalReason = "an in-flight call reached its return with its admission gone"

	// ReadNotFiled is a user-memory read that could not be filed against its
	// admission, so Reads refuses to answer.
	ReadNotFiled RefusalReason = "a user-memory read could not be filed against its admission"

	// NamedTwice is a second selection naming an already-admitted instance. One
	// instance holds one grant, so every target naming it belongs on that
	// selection's AlsoNamedBy; a second selection would replace the first grant
	// and its reasons silently.
	NamedTwice RefusalReason = "a second selection names an instance this session has already admitted"

	// NotTheApprovedOccupant is a task holding an admitted instance's number whose
	// birth is not the grant's: the number was reused, or the entry was written for
	// somebody else. Nothing is read. It is its own reason, not a lost
	// observation: the run refused to observe an unapproved process.
	NotTheApprovedOccupant RefusalReason = "the task holding the number is not the process the grant was written for"

	// ChildUnnameable is a child the fork event could not name: a kernel read
	// failed or returned an unusable number. Nothing is read for it and the
	// creator's grant is untouched; it is a condition of the host.
	ChildUnnameable RefusalReason = "a child could not be named at the fork event, so it was not admitted"

	// ChildNamespaceUnenumerated is a child created in a pid namespace this session
	// did not enumerate (a clone asking for its own namespace), so no lookup would
	// find its entry. Nothing failed: the operator's enumeration is short.
	ChildNamespaceUnenumerated RefusalReason = "a child was created in a pid namespace this session did not enumerate"

	// The five ways out of the socket observation, which decide whether a call's
	// window ever holds a descriptor. They are unmet preconditions rather than
	// refused writes; without them a run whose probes fired and left at a
	// precondition looks like one whose probes never fired.

	// SocketDescriptorInvalid is socket work whose descriptor is not one. It is
	// counted above the in-flight lookup, so it covers all of the process's C
	// library traffic.
	SocketDescriptorInvalid RefusalReason = "socket work carried a descriptor that is not one"

	// SocketWorkOutsideACall is socket work on a thread with no TLS call in flight,
	// most of what a process does, and not a loss. It cannot tell a thread with no
	// call from one doing socket work for a call on another thread.
	SocketWorkOutsideACall RefusalReason = "socket work happened on a thread with no TLS call in flight"

	// SocketTaskUnlocatable is socket work inside a call whose task is in a pid
	// namespace this session did not enumerate.
	SocketTaskUnlocatable RefusalReason = "a descriptor seen inside a call belongs to a task whose pid namespace this session did not enumerate"

	// SocketLifetimeUnknown is a descriptor seen inside a call through an entry
	// point that could be operating on a file, with no recorded occupancy, so it
	// is not taken as network I/O. The occupancy table is filled by socket, accept,
	// connect and dup2, and holds pre-existing descriptors only if seeded.
	SocketLifetimeUnknown RefusalReason = "a descriptor seen inside a call has no occupancy this run recorded"

	// DescriptorSeenInsideACall is not a refusal: it counts the success, without
	// which four failure counters at zero cannot be told from four that cannot
	// move.
	DescriptorSeenInsideACall RefusalReason = "a descriptor was recorded against the call in flight on its thread, which is a binding source doing its work rather than a refusal"
)

// Declined is one admission the kernel was never given, and why. It is carried
// back rather than failing the attachment, because the rest of the set is
// still observed (package attachment).
type Declined struct {
	Selection admission.Selection

	// Reason is what a caller branches on; Err carries the same fact with what the
	// host said, for a reader.
	Reason RefusalReason
	Err    error
}

// Refusals is everything this session did not observe, and why. Named ones
// happened while deciding what to admit, so the instance is known; counted ones
// happened in the kernel during the run, where the instance is not
// recoverable. A counted reason at zero is present: it was looked for. One
// counted entry is a success (DescriptorSeenInsideACall).
type Refusals struct {
	Named   []Declined
	Counted map[RefusalReason]int64
}

// Event is one firing, decoded from the ring buffer.
type Event struct {
	Kind Kind
	SSL  uint64

	// Stamp is this event's place in production order, taken before its
	// reservation. Stamps are consecutive, so a missing number is an event
	// produced and lost, which says which streams were live across the loss. Zero
	// means the program could not reach its allocator.
	Stamp uint64

	// Descriptor is the socket this call's bytes crossed, Bound what is
	// established about it, and Binding the generation of its occupancy. Bound is
	// what a consumer reads: descriptor zero is a real descriptor.
	Descriptor int32
	Binding    uint64
	Bound      probe.Bound

	// Socket is the inode of the socket this call's I/O crossed. Zero is a socket
	// with no file of its own.
	Socket uint64

	// Endpoints is the socket's addresses as the program published them.
	Endpoints probe.Ends

	// Outcome is what this call's own kernel I/O came to: why there is no binding,
	// where Bound says there is none. Only a call with no kernel I/O may carry an
	// earlier binding forward.
	Outcome probe.SocketOutcome

	// Namespace, NamespacePID and Generation are the instance the program admitted
	// and attributed this firing to. PID and TID are the observer's own numbering
	// for the task, for reading /proc.
	Namespace    admission.Namespace
	NamespacePID int32
	Generation   admission.Generation

	PID       int32
	TID       int32
	Direction fragment.Direction
	Length    uint32

	// Payload is what the program copied from the caller's buffer: the first
	// len(Payload) bytes the call moved. It is shorter than Length where the call
	// moved more than one event carries, and empty where the program reads no
	// payload or the kernel refused the read; never bytes that were not copied.
	Payload []byte

	Early bool

	// Measured is whether Length is a real count; false for every out-parameter
	// call the metadata-only program handles.
	Measured bool

	At time.Time
}

// Session is a loaded program, its links, and the events they report.
type Session struct {
	collection *ebpf.Collection
	links      []link.Link
	reader     *ringbuf.Reader

	// monotonicBase is the wall-clock instant the program's clock reads zero at,
	// established once per session from one reading of each clock, so kernel
	// stamps (CLOCK_MONOTONIC) can be compared with wall-clock lifetimes. It is not
	// exact: it carries the gap between the two readings and any wall-clock step
	// since, and must not be differenced against another host's times.
	monotonicBase time.Time

	// placed is one entry per point this session asked the kernel for, so what the
	// kernel says about each can be read back.
	placed []placed

	// asked is the socket evidence group this session was told to place, and
	// withheld every claim it does not make, with the member that cost it: never
	// asked and refused by the kernel withhold the same claim and are different
	// facts.
	asked    []KernelPoint
	withheld []probe.Withheld

	// evidence and sixes are the two claims, held apart from Coverage's booleans
	// so Coverage reports what this session established.
	evidence bool
	sixes    bool

	// accepted is what went into the allowlist and declined what did not;
	// descendants are adopted only for the first.
	accepted []admission.Selection
	declined []Declined

	// generations is this session's userspace allocator, counting up from one,
	// below the kernel's range (package admission, KernelGenerations).
	generations admission.Generation

	// enumerated is every pid namespace passed to the program, in its slots.
	enumerated []admission.Namespace

	// excluded is what the caller denied and denied what went into the map for
	// it, so nothing admitted later can take those keys.
	excluded []admission.Denial
	denied   map[instanceKey]bool

	// namedBy is every target that named an instance; the allowlist holds one.
	namedBy map[instanceKey][]admission.Provenance

	// inventory is every instance this session recorded a grant for, in first
	// recorded order, and index its position. Both the delivery goroutine and the
	// caller write it, through recorded.
	inventory []admission.Selection
	index     map[instanceKey]int
	held      sync.Mutex

	// beyond is every descendant of an admitted instance found in an unenumerated
	// pid namespace, with its start identity, so each is named once.
	beyond map[instanceKey]admission.Start

	// seen is the start identity first read for each allowlist entry, which later
	// readings are compared against.
	seen map[instanceKey]admission.Start

	events chan Event
	done   chan struct{}

	// idle carries one signal each time a ring-buffer read finds nothing, which
	// is how Drain learns the buffer is empty without a second reader.
	idle chan struct{}

	// stopped is closed by the reading goroutine when it returns.
	stopped chan struct{}

	// delivered is how many events this session decoded and handed on, and
	// abandoned how many it decoded and did not (the one held when told to stop),
	// so a stream that lost its last fragment does not look complete.
	delivered atomic.Int64
	abandoned atomic.Int64

	// undecodable is events shorter than the program's header, counted so a moved
	// ABI does not look like a quiet host.
	undecodable atomic.Int64

	// failure is why the ring reader stopped, where it was not the session
	// closing, so the account can say it could not find out what was lost.
	failed  atomic.Bool
	failure atomic.Pointer[string]
}

// readerFailure is why the ring reader stopped, or empty where it stopped
// because the session was closing.
func (s *Session) readerFailure() string {
	if !s.failed.Load() {
		return ""
	}
	if why := s.failure.Load(); why != nil {
		return *why
	}
	return "the ring reader stopped and gave no reason"
}

// Undecodable is how many events arrived that could not be decoded: the two
// sides of the ABI no longer agree.
func (s *Session) Undecodable() int64 { return s.undecodable.Load() }

// instanceKey and admissionValue are the two halves of the allowlist as the
// program declares them (bpf/ssl.bpf.h), fixed width with explicit padding. A
// unit test compares them with the compiled object's map definition.
type instanceKey struct {
	NamespaceDevice uint64
	NamespaceInode  uint64
	PID             uint32
	Reserved        uint32
}

type admissionValue struct {
	Generation       uint64
	Birth            uint64
	ParentGeneration uint64
	ParentNSDevice   uint64
	ParentNSInode    uint64
	ParentPID        uint32
	Target           uint32
	Rule             uint32
	Threads          uint32
	Kind             uint8
	Mode             uint8
	Propagate        uint8
	LeaderGone       uint8
	Reserved         [4]uint8
}

// namespaceValue is one entry of the enumerated pid namespaces.
type namespaceValue struct {
	Device uint64
	Inode  uint64
}

// maxNamespaces is the bound the program's array was written with
// (OBS_NAMESPACES in bpf/ssl.bpf.h); authorise reads the real one off the
// loaded map.
const maxNamespaces = 8

func keyOf(instance admission.Instance) instanceKey {
	return instanceKey{
		NamespaceDevice: instance.Namespace.Device,
		NamespaceInode:  instance.Namespace.Inode,
		PID:             uint32(instance.PID),
	}
}

// placed is one point as asked for, with the kernel's links or its reason for
// none.
type placed struct {
	point Point
	entry link.Link
	back  link.Link

	// refusal is the kernel's own error, verbatim.
	refusal string
}

const chunk = 4096

// rawHeader is the fixed part of struct event before its data array: seven
// eight-byte fields, six four-byte and six one-byte fields (86 bytes), then
// the socket's endpoints appended after them (a flag, a padding byte, the
// network namespace, two 16-byte addresses, two ports, four padding bytes),
// then the socket's start: 144. The padding is explicit so no offset depends
// on the compiler, and package bpf's layout guard pins every offset against
// the source (bpf/ssl.bpf.h).
const rawHeader = 144

// Attach loads the program, places the points, fills the allowlist and begins
// reading. Nothing is captured before this and nothing after Close.
func Attach(options Options) (*Session, error) {
	if len(options.Points) == 0 {
		return nil, errors.New("no points to attach to")
	}

	collection, err := load(options.Program)
	if err != nil {
		return nil, err
	}

	session := &Session{
		monotonicBase: pairClocks(),
		collection:    collection,
		events:        make(chan Event, 4096),
		done:          make(chan struct{}),
		idle:          make(chan struct{}, 1),
		stopped:       make(chan struct{}),
	}

	session.excluded = options.Deny

	if err := session.authorise(options.Admit); err != nil {
		_ = session.Close()
		return nil, err
	}

	// Every function is unmeasurable before any probe is placed, and cleared only
	// once its return probe is confirmed: an entry probe is live the moment it is
	// placed.
	if err := session.blindToEveryFunction(); err != nil {
		_ = session.Close()
		return nil, err
	}
	if err := session.place(options.Points); err != nil {
		_ = session.Close()
		return nil, err
	}
	session.asked = options.Kernel
	if session.asked == nil {
		session.asked = KernelPoints()
	}
	if err := session.placeKernel(); err != nil {
		_ = session.Close()
		return nil, err
	}
	if err := session.measurable(); err != nil {
		_ = session.Close()
		return nil, err
	}

	// After the probes are placed, so a reading covers the window between filling
	// the allowlist and placing the fork probe (adopt).
	if err := session.adopt(); err != nil {
		_ = session.Close()
		return nil, err
	}

	// And the sockets those processes already hold (seedSockets).
	if err := session.seedSockets(); err != nil {
		_ = session.Close()
		return nil, err
	}

	reader, err := ringbuf.NewReader(collection.Maps["events"])
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("%w: open the ring buffer: %v", ErrUnavailable, err)
	}
	session.reader = reader

	go session.read()
	return session, nil
}

// Loads loads the program into this kernel and closes it, placing and admitting
// nothing. It is Attach's own first step, so a kernel it clears is one Attach
// clears, and a refusal carries Attach's reason.
func Loads(program obpf.Program) error {
	collection, err := load(program)
	if err != nil {
		return err
	}
	collection.Close()
	return nil
}

// load is the program as this kernel took it, before any probe is placed.
func load(program obpf.Program) (*ebpf.Collection, error) {
	// Userspace reads a grant's birth from /proc and the program from the kernel;
	// they agree only while this reader's time namespace shifts nothing
	// (process.StartTimesAreOffset). Otherwise every grant would name a number the
	// program never recognises, so it is refused here once, by name.
	offset, err := process.StartTimesAreOffset(defaultProcFS)
	if err != nil {
		return nil, fmt.Errorf("%w: establish whether this session's start times are the kernel's: %v",
			ErrUnavailable, err)
	}
	if offset != 0 {
		return nil, fmt.Errorf("%w: this session is in a time namespace whose boot time is offset by "+
			"%s, so the start times it reads out of /proc are not the ones the kernel establishes, "+
			"and no grant it writes could be authenticated", ErrUnavailable, offset)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(newReader(program.Object))
	if err != nil {
		return nil, fmt.Errorf("%w: read the program: %v", ErrUnavailable, err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("%w: load the program: %v", ErrUnavailable, err)
	}
	return collection, nil
}

// defaultProcFS is where the kernel publishes what an authorisation is checked
// against.
const defaultProcFS = "/proc"

// How an instance came to be in the allowlist, what its target permits it to
// pass on, and whether this host can act on that (bpf/ssl.bpf.h): three facts.
const (
	byTarget  uint8 = 1
	byDescent uint8 = 2
	denied    uint8 = 3

	modeNone     uint8 = 1
	modeExisting uint8 = 2
	modeFollow   uint8 = 3

	propagateNo  uint8 = 1
	propagateYes uint8 = 2
)

func encodeMode(mode admission.Mode) (uint8, error) {
	switch mode {
	case admission.ModeNone:
		return modeNone, nil
	case admission.ModeExisting:
		return modeExisting, nil
	case admission.ModeFollow:
		return modeFollow, nil
	default:
		return 0, fmt.Errorf("%w: descendant mode %q", admission.ErrInvalid, mode)
	}
}

func decodeMode(mode uint8) admission.Mode {
	switch mode {
	case modeNone:
		return admission.ModeNone
	case modeExisting:
		return admission.ModeExisting
	case modeFollow:
		return admission.ModeFollow
	default:
		return admission.ModeUnset
	}
}

func decodeKind(kind uint8) admission.Kind {
	switch kind {
	case byTarget:
		return admission.ByTarget
	case byDescent:
		return admission.ByDescent
	default:
		return admission.KindUnknown
	}
}

func decodePropagation(propagate uint8) admission.Propagation {
	switch propagate {
	case propagateYes:
		return admission.CanPropagate
	case propagateNo:
		return admission.CannotPropagate
	default:
		return admission.PropagationUnknown
	}
}

// ForkReturnProgram and ForkEntryProgram are the pair on the observed process's
// own fork; a caller builds that point, knowing each process's C library
// (ForkPoint). Neither admits anything (the kernel's fork event does,
// forkTracepoint): the entry opens and the return closes the window in which
// an unadmitted task's call is held.
const (
	ForkReturnProgram = "obs_fork_return"
	ForkEntryProgram  = "obs_fork_entry"
)

// The three raw tracepoints keeping the allowlist current: fork establishes
// what was created, exec ends a grant, exit removes a process. Raw, because a
// formatted tracepoint needs its id from tracefs, which most hosts do not
// mount.
const (
	forkTracepoint = "sched_process_fork"
	forkProgram    = "obs_fork"

	exitTracepoint = "sched_process_exit"
	exitProgram    = "obs_exit"

	execTracepoint = "sched_process_exec"
	execProgram    = "obs_exec"
)

// authorise puts the named processes in the allowlist, before any probe is
// placed, because the fork probe admits a child on its parent's entry. An
// entry this will not take is skipped and the rest are written: entries are
// independent, and an approved process exiting between reading and attaching
// is ordinary and must not cost the others their observation (place does the
// same). Accepting nothing is an error: it would capture nothing and report
// success.
func (s *Session) authorise(who []admission.Selection) error {
	allowed := s.collection.Maps["allowed_processes"]
	if allowed == nil {
		return fmt.Errorf("%w: the program has no allowlist map", ErrUnavailable)
	}

	if err := s.enumerate(who); err != nil {
		return err
	}
	if err := s.seed(); err != nil {
		return err
	}
	if err := s.deny(allowed); err != nil {
		return err
	}

	for _, one := range who {
		if s.denied[keyOf(one.Instance)] {
			// A denial is already under this key; writing the admission would overwrite
			// it.
			s.refuse(one, ExcludedBySubtree, fmt.Errorf(
				"%w: pid %d in %s is denied by an exclusion, and a target naming it does not "+
					"override that", ErrNotAuthorised, one.Instance.PID, one.Instance.Namespace))
			continue
		}
		if !s.resolvable(one.Instance.Namespace) {
			// A namespace the program was not given cannot be resolved, so the entry would
			// never be found: refused by name.
			s.refuse(one, NamespaceUnenumerated, fmt.Errorf(
				"%w: pid %d is in %s, which this session did not enumerate, so the program "+
					"cannot resolve a pid inside it", ErrNotAuthorised, one.Instance.PID,
				one.Instance.Namespace))
			continue
		}
		if held, already := s.namedBy[keyOf(one.Instance)]; already {
			// A grant is already under this key, with its own generation and reasons.
			// Refused rather than overwritten, so no reason is silently lost.
			s.refuse(one, NamedTwice, fmt.Errorf(
				"%w: pid %d in %s is already admitted under target %q, and one instance holds "+
					"one grant - both targets belong on the one selection",
				ErrNotAuthorised, one.Instance.PID, one.Instance.Namespace, held[0].Target))
			continue
		}
		if reason, err := s.confirm(one); err != nil {
			s.refuse(one, reason, err)
			continue
		}

		s.generations++
		granted := one
		granted.Instance.Generation = s.generations
		granted.Propagation = admission.CanPropagate

		value, err := encode(granted, s.threadsOf(granted.ObserverPID))
		if err != nil {
			reason := PolicyIncomplete
			if errors.Is(err, errNoBirth) {
				reason = StartIndeterminate
			}
			s.refuse(one, reason, err)
			continue
		}
		if err := allowed.Update(keyOf(granted.Instance), value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("%w: admit pid %d: %v", ErrUnavailable, granted.Instance.PID, err)
		}
		s.accepted = append(s.accepted, granted)
		s.recorded(granted)
		if s.namedBy == nil {
			s.namedBy = make(map[instanceKey][]admission.Provenance)
		}
		s.namedBy[keyOf(granted.Instance)] = granted.NamedBy()
	}

	if len(s.accepted) == 0 {
		reasons := make([]error, 0, len(s.declined))
		for _, one := range s.declined {
			reasons = append(reasons, one.Err)
		}
		return fmt.Errorf("%w: none of the %d processes offered: %w",
			ErrNotAuthorised, len(who), errors.Join(reasons...))
	}
	return s.follow()
}

// threadsOf is how many threads a process has now, read when the entry is
// written.
func (s *Session) threadsOf(pid int32) int32 {
	p, err := process.Identify(defaultProcFS, pid)
	if err != nil {
		return 0
	}
	return p.Threads
}

// liveThreads is the count the program counts down from. No reading counts as
// one: the grant then ends at the leader's exit, observing less rather than
// more. Too high leaves an entry Reconcile withdraws.
func liveThreads(threads int32) uint32 {
	if threads < 1 {
		return 1
	}
	return uint32(threads)
}

// deny writes the exclusions before anything is admitted, so an instance named
// by both finds the denial in its key. A denied entry carries no mode: the
// instance has no grant and what it forks is denied.
func (s *Session) deny(allowed *ebpf.Map) error {
	s.denied = make(map[instanceKey]bool, len(s.excluded))
	for _, one := range s.excluded {
		if !s.resolvable(one.Instance.Namespace) {
			s.refuseDenial(one, NamespaceUnenumerated, fmt.Errorf(
				"%w: pid %d is in %s, which this session did not enumerate, so the program "+
					"cannot resolve a pid inside it to deny it", ErrNotAuthorised,
				one.Instance.PID, one.Instance.Namespace))
			continue
		}
		s.generations++
		value := admissionValue{
			Generation: uint64(s.generations),
			Target:     uint32(one.Provenance.Number),
			Rule:       uint32(one.Provenance.Rule),
			Threads:    liveThreads(s.threadsOf(one.ObserverPID)),
			Kind:       denied,
			Propagate:  propagateYes,

			ParentGeneration: uint64(one.Provenance.Parent.Generation),
			ParentNSDevice:   one.Provenance.Parent.Namespace.Device,
			ParentNSInode:    one.Provenance.Parent.Namespace.Inode,
			ParentPID:        uint32(one.Provenance.Parent.PID),
		}
		key := keyOf(one.Instance)
		if err := allowed.Update(key, value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("%w: deny pid %d: %v", ErrUnavailable, one.Instance.PID, err)
		}
		s.denied[key] = true
	}
	return nil
}

// refuseDenial records an exclusion this session could not put in force, which
// differs from one that denied nothing.
func (s *Session) refuseDenial(one admission.Denial, reason RefusalReason, err error) {
	s.declined = append(s.declined, Declined{
		Selection: admission.Selection{Instance: one.Instance, Provenance: one.Provenance,
			ObserverPID: one.ObserverPID},
		Reason: reason,
		Err:    err,
	})
}

// errNoBirth is a selection with no start identity to bind a grant to, a
// sentinel so callers report this reason and not an unusable mode.
var errNoBirth = errors.New("it carries no start identity to bind a grant to")

// encode is one selection as the program holds it. threads is the instance's
// thread count when read, which the program counts down (struct admission,
// bpf/ssl.bpf.h). The birth is the thread group's start in the clock ticks
// /proc reports (admission.BootTicks), the same number the program
// establishes at a fork and authenticates against (obs_birth).
func encode(one admission.Selection, threads int32) (admissionValue, error) {
	if !one.Instance.Start.Determined {
		return admissionValue{}, fmt.Errorf("admit pid %d: %w", one.Instance.PID, errNoBirth)
	}
	mode, err := encodeMode(one.Mode)
	if err != nil {
		return admissionValue{}, fmt.Errorf("admit pid %d: %w", one.Instance.PID, err)
	}
	kind := byTarget
	if one.Kind == admission.ByDescent {
		kind = byDescent
	}
	propagate := propagateNo
	if one.Propagation == admission.CanPropagate {
		propagate = propagateYes
	}
	return admissionValue{
		Generation:       uint64(one.Instance.Generation),
		Birth:            uint64(one.Instance.Start.Ticks),
		ParentGeneration: uint64(one.Provenance.Parent.Generation),
		ParentNSDevice:   one.Provenance.Parent.Namespace.Device,
		ParentNSInode:    one.Provenance.Parent.Namespace.Inode,
		ParentPID:        uint32(one.Provenance.Parent.PID),
		Target:           uint32(one.Provenance.Number),
		Rule:             uint32(one.Provenance.Rule),
		Threads:          liveThreads(threads),
		Kind:             kind,
		Mode:             mode,
		Propagate:        propagate,
	}, nil
}

// enumerate passes the pid namespaces of everything being admitted to the
// program, which can resolve a pid only in those. A namespace beyond the
// array's size is left out and every instance in it is declined by name.
func (s *Session) enumerate(who []admission.Selection) error {
	slots := s.collection.Maps["namespaces"]
	if slots == nil {
		return fmt.Errorf("%w: the program has no namespaces map, so it can resolve no pid at all",
			ErrUnavailable)
	}
	if int(slots.MaxEntries()) < maxNamespaces {
		return fmt.Errorf("%w: the program holds %d pid namespaces and this expects %d",
			ErrUnavailable, slots.MaxEntries(), maxNamespaces)
	}

	seen := make(map[admission.Namespace]bool, len(who)+len(s.excluded))
	namespaces := make([]admission.Namespace, 0, len(who)+len(s.excluded))
	for _, one := range s.excluded {
		namespaces = append(namespaces, one.Instance.Namespace)
	}
	for _, one := range who {
		namespaces = append(namespaces, one.Instance.Namespace)
	}
	for _, namespace := range namespaces {
		if !namespace.Known() || seen[namespace] {
			continue
		}
		if len(s.enumerated) == maxNamespaces {
			break
		}
		seen[namespace] = true
		s.enumerated = append(s.enumerated, namespace)
	}

	for index, namespace := range s.enumerated {
		entry := namespaceValue{Device: namespace.Device, Inode: namespace.Inode}
		if err := slots.Update(uint32(index), entry, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("%w: pass %s to the program: %v", ErrUnavailable, namespace, err)
		}
	}
	return nil
}

func (s *Session) resolvable(namespace admission.Namespace) bool {
	return slices.Contains(s.enumerated, namespace)
}

// seed puts the kernel's admission-generation allocator at the start of its own
// range (package admission, KernelGenerations).
func (s *Session) seed() error {
	counter := s.collection.Maps["generations"]
	if counter == nil {
		return fmt.Errorf("%w: the program has no generation counter, so a descendant it admits "+
			"would carry nothing that separates it from the next holder of its number",
			ErrUnavailable)
	}
	if err := counter.Update(uint32(0), uint64(admission.KernelGenerations), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("%w: seed the generation counter: %v", ErrUnavailable, err)
	}
	return nil
}

// Declined is what this session would not authorise, and why.
func (s *Session) Declined() []Declined { return s.declined }

// refusalCounters is which counter each refusal reason is read from, by named
// constant: a moved index still reads a valid number, filed under the wrong
// reason.
var refusalCounters = map[RefusalReason]uint32{
	TransferRefusedAtReturn: obpf.StatRefused,
	CallNotRecorded:         obpf.StatCallUnrecorded,
	ReadNotFiled:            obpf.StatReadUnrecorded,
	DescendantNotWritten:    obpf.StatDescendantUnrecorded,
	DenialNotWritten:        obpf.StatDenialUnrecorded,
	NeverAdmitted:           obpf.StatDeferredDiscarded,
	NotTheApprovedOccupant:  obpf.StatUnauthenticated,
	ChildUnnameable:         obpf.StatChildUnnameable,

	ChildNamespaceUnenumerated: obpf.StatChildNSUnenumerated,

	SocketDescriptorInvalid:   obpf.StatSocketFDInvalid,
	SocketWorkOutsideACall:    obpf.StatSocketOutsideCall,
	SocketTaskUnlocatable:     obpf.StatSocketUnlocatable,
	SocketLifetimeUnknown:     obpf.StatSocketNoLifetime,
	DescriptorSeenInsideACall: obpf.StatSocketRecorded,
}

// Refusals is everything this session did not observe: what it declined while
// deciding and what the program counted while running. An unreadable counter
// fails the whole call rather than leaving a partial map.
func (s *Session) Refusals() (Refusals, error) {
	counted := make(map[RefusalReason]int64, 4)
	for reason, index := range refusalCounters {
		value, err := s.stat(index)
		if err != nil {
			return Refusals{}, err
		}
		counted[reason] = value
	}
	return Refusals{Named: s.declined, Counted: counted}, nil
}

// adopt puts the descendants an accepted process already had into the
// allowlist, after the probes are placed. It walks what authorise accepted,
// never what it was offered: a refused entry may name a reused pid, whose new
// occupant's children must not be admitted.
//
// Order: the named processes go into the map, the fork probe is placed, then
// this reads the process table. A child forked before the probe is in the
// table and found here; one forked after is the probe's.
//
// Writing an entry cannot double anything: the allowlist is keyed by instance
// and the fork probe emits no event, so a child found by both is admitted once
// (each write carries its own generation, and a stale saved call is refused
// against the one in force). A process exiting between the reading and the
// write leaves an entry the exit hook can no longer remove; the final sweep
// handles that.
func (s *Session) adopt() error {
	allowed := s.collection.Maps["allowed_processes"]
	if allowed == nil {
		return fmt.Errorf("%w: the program has no allowlist map", ErrUnavailable)
	}

	table, err := process.Read(defaultProcFS)
	if err != nil {
		return fmt.Errorf("%w: read the process table: %v", ErrUnavailable, err)
	}

	who := s.accepted
	named := make(map[instanceKey]bool, len(who))
	for _, one := range who {
		named[keyOf(one.Instance)] = true
	}

	var adopted []admission.Selection
	for _, one := range who {
		// Descendants already running are covered by existing and follow, not by
		// none. Only this walk finds them; the fork hook sees later creations only.
		if !one.Mode.Answers().Existing {
			continue
		}
		for _, below := range table.Descendants(one.ObserverPID) {
			child := below.Instance()
			if !s.resolvable(child.Namespace) {
				// The program resolves a pid only in a namespace it was given, so an entry
				// under any other would never be found: left out and named.
				s.refuse(admission.Selection{
					Instance:    child,
					Kind:        admission.ByDescent,
					Provenance:  admission.Provenance{Target: one.Provenance.Target, Number: one.Provenance.Number, Parent: one.Instance.Key()},
					Mode:        one.Mode,
					ObserverPID: below.PID,
				}, NamespaceUnenumerated, fmt.Errorf(
					"%w: pid %d below pid %d is in %s, which this session did not enumerate",
					ErrNotAuthorised, below.PID, one.ObserverPID, child.Namespace))
				continue
			}
			if named[keyOf(child)] || s.denied[keyOf(child)] {
				continue
			}
			if !child.Start.Determined {
				// A descendant whose start could not be read has no birth to bind, so its
				// grant could never authenticate: refused by name, while the rest of the
				// family is still adopted.
				s.refuse(admission.Selection{
					Instance:    child,
					Kind:        admission.ByDescent,
					Provenance:  admission.Provenance{Target: one.Provenance.Target, Number: one.Provenance.Number, Parent: one.Instance.Key()},
					Mode:        one.Mode,
					ObserverPID: below.PID,
				}, StartIndeterminate, fmt.Errorf(
					"%w: pid %d below pid %d has a start identity that could not be read, so it "+
						"names no particular process", ErrNotAuthorised, below.PID, one.ObserverPID))
				continue
			}

			s.generations++
			child.Generation = s.generations
			inherited := admission.Selection{
				Instance:    child,
				Kind:        admission.ByDescent,
				Provenance:  admission.Provenance{Target: one.Provenance.Target, Number: one.Provenance.Number, Rule: one.Provenance.Rule, Parent: one.Instance.Key()},
				Mode:        one.Mode,
				Propagation: admission.CanPropagate,
				ObserverPID: below.PID,
			}
			value, err := encode(inherited, below.Threads)
			if err != nil {
				return fmt.Errorf("%w: admit pid %d below pid %d: %v",
					ErrUnavailable, below.PID, one.ObserverPID, err)
			}
			if err := allowed.Update(keyOf(child), value, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("%w: admit pid %d below pid %d: %v",
					ErrUnavailable, below.PID, one.ObserverPID, err)
			}
			named[keyOf(child)] = true
			s.recorded(inherited)
			adopted = append(adopted, inherited)
		}
	}
	return s.sweep(allowed, adopted)
}

// socketKey and socketLife are the descriptor table as the program declares it
// (bpf/ssl.bpf.h), with explicit layout on both sides.
type socketKey struct {
	NamespaceDevice uint64
	NamespaceInode  uint64
	PID             uint32
	FD              int32
}

type socketLife struct {
	Generation uint64

	// Opened is when the program saw the socket created, on the monotonic clock. A
	// seeded entry leaves it zero: this run did not see those sockets open.
	Opened uint64
}

// seedSockets records the sockets an admitted process already holds, before
// any of its calls are observed. It feeds withdrawal, not resolution: a call's
// socket comes from the object the kernel acquired, so a process admitted
// after its sockets existed resolves from its first call regardless. Unseeded,
// a process cannot have a continuity assertion withdrawn when a number is
// reused. A descriptor opened between this reading and probe placement is
// missed; attaching before traffic starts bounds that.
func (s *Session) seedSockets() error {
	sockets := s.collection.Maps["sockets"]
	generations := s.collection.Maps["bindings"]
	if sockets == nil || generations == nil {
		return fmt.Errorf("%w: the program has no socket table, so nothing here can record the "+
			"descriptors an admitted process already holds", ErrUnavailable)
	}

	var next uint64
	for _, one := range s.accepted {
		if one.ObserverPID <= 0 {
			continue
		}
		held, err := process.Sockets(defaultProcFS, one.ObserverPID)
		if err != nil {
			// A process whose descriptors could not be read is not one with none; its
			// sockets are learned from the probes instead.
			continue
		}
		for _, descriptor := range held {
			next++
			key := socketKey{
				NamespaceDevice: one.Instance.Namespace.Device,
				NamespaceInode:  one.Instance.Namespace.Inode,
				PID:             uint32(one.Instance.PID),
				FD:              descriptor,
			}
			if err := sockets.Update(key, socketLife{Generation: next}, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("%w: record descriptor %d of pid %d: %v",
					ErrUnavailable, descriptor, one.ObserverPID, err)
			}
		}
	}

	// The program's allocator starts above everything seeded here, so the two
	// never hand out one generation.
	return generations.Update(uint32(0), next, ebpf.UpdateAny)
}

// sweep removes what adopt wrote for a process that is no longer the process
// it was written for. It reads the table again after the writes: an instance
// absent now exited before its entry was written (removed here) or after (the
// exit hook, armed before adopt began, removed it). It compares the instance,
// not the number: a pid reused between the two readings is present in both.
// An entry whose identity cannot be established is withdrawn.
func (s *Session) sweep(allowed *ebpf.Map, adopted []admission.Selection) error {
	if len(adopted) == 0 {
		return nil
	}

	table, err := process.Read(defaultProcFS)
	if err != nil {
		return fmt.Errorf("%w: re-read the process table: %v", ErrUnavailable, err)
	}
	for _, one := range adopted {
		still, alive := table.Lookup(one.ObserverPID)
		if alive && confirms(still, one.Instance) {
			continue
		}
		if err := allowed.Delete(keyOf(one.Instance)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("%w: withdraw pid %d, which is not the process it was admitted as: %v",
				ErrUnavailable, one.ObserverPID, err)
		}
		// Withdrawn and said so: a descendant that finished between the readings is
		// not the same absence as one never eligible.
		s.refuse(one, GoneBeforeAdmission, fmt.Errorf(
			"%w: pid %d was found below an admitted process and was gone, or no longer itself, "+
				"when the table was read again", ErrNotAuthorised, one.ObserverPID))
	}
	return nil
}

// confirms reports whether a second reading of /proc found the same instance
// the entry was written for: namespace, number and start identity (not the
// generation, which no reading produces). An indeterminate start confirms
// nothing.
func confirms(still process.Process, admitted admission.Instance) bool {
	return still.Namespace == admitted.Namespace &&
		still.NamespacePID == admitted.PID &&
		still.Start().Determined &&
		still.Start() == admitted.Start
}

// confirm checks that the pid is still the approved process: the kernel reuses
// numbers, so a reading taken a moment ago can name an exited process. An
// indeterminate start identity is refused too, as a different refusal.
func (s *Session) confirm(one admission.Selection) (RefusalReason, error) {
	if !one.Instance.Start.Determined {
		return StartIndeterminate, fmt.Errorf("%w: pid %d was approved with a start identity that "+
			"could not be read, so it names no particular process", ErrNotAuthorised, one.Instance.PID)
	}
	if one.ObserverPID <= 0 {
		return StartIndeterminate, fmt.Errorf("%w: pid %d in %s has no number in this observer's own "+
			"namespace, so nothing here can check that it is still the process that was approved",
			ErrNotAuthorised, one.Instance.PID, one.Instance.Namespace)
	}
	// The start is read from /proc/<pid>/stat, which anyone may read, not through
	// the whole process: this confirms a reload after capabilities are dropped,
	// when another owner's executable is closed to the session.
	read, err := process.ReadExec(defaultProcFS, one.ObserverPID)
	switch {
	case os.IsNotExist(err):
		return GoneBeforeAdmission, fmt.Errorf("%w: pid %d has gone", ErrNotAuthorised, one.ObserverPID)
	case err != nil:
		return StartIndeterminate, fmt.Errorf("%w: the start of pid %d could not be read: %v",
			ErrNotAuthorised, one.ObserverPID, err)
	}
	if start := (process.Process{StartTime: read.StartTime}).Start(); start != one.Instance.Start {
		return IdentityChanged, fmt.Errorf("%w: pid %d %s and was approved as the process that %s, "+
			"so the number has been handed to something else",
			ErrNotAuthorised, one.ObserverPID, start, one.Instance.Start)
	}
	return "", nil
}

// refuse records one instance this session will not observe, with the reason a
// caller branches on and the message a reader is shown.
func (s *Session) refuse(one admission.Selection, reason RefusalReason, err error) {
	s.declined = append(s.declined, Declined{Selection: one, Reason: reason, Err: err})
}

// follow arms the three hooks keeping the allowlist current: fork, exec and
// exit, as raw tracepoints attached by name through bpf(2) (no tracefs). It
// runs after the named processes are in the allowlist, since the fork hook
// admits a child on its creator's entry (authorise).
func (s *Session) follow() error {
	for _, hook := range []struct{ tracepoint, program string }{
		{forkTracepoint, forkProgram},
		{exitTracepoint, exitProgram},
		{execTracepoint, execProgram},
	} {
		handler := s.collection.Programs[hook.program]
		if handler == nil {
			return fmt.Errorf("%w: the program has no %s", ErrUnavailable, hook.program)
		}
		attached, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    hook.tracepoint,
			Program: handler,
		})
		if err != nil {
			return fmt.Errorf("%w: follow %s: %v", ErrUnavailable, hook.tracepoint, err)
		}
		s.links = append(s.links, attached)
	}
	return nil
}

// place attaches every point's entry and return programs. A point the kernel
// refuses keeps its refusal, verbatim, and the rest are still placed, so a
// short attachment observes what attached and can report the rest. Placing
// nothing is an error: a session with no probes looks like a quiet host.
func (s *Session) place(points []Point) error {
	var refused []string

	for _, point := range points {
		put := placed{point: point}
		if err := s.put(&put); err != nil {
			put.refusal = err.Error()
			refused = append(refused, point.Symbol+": "+err.Error())
		}
		s.placed = append(s.placed, put)
	}

	if len(refused) == len(points) {
		return fmt.Errorf("%w: %s", ErrRefused, strings.Join(refused, "; "))
	}
	return nil
}

// blindToEveryFunction marks every function code unmeasurable, the state a
// session starts in, so nothing records a call it cannot complete.
func (s *Session) blindToEveryFunction() error {
	unmeasurable := s.collection.Maps["unmeasurable"]
	if unmeasurable == nil {
		return fmt.Errorf("%w: the program has no per-function measurability table", ErrUnavailable)
	}
	for code := uint32(0); code < obpf.FuncCodeBound; code++ {
		if err := unmeasurable.Update(code, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("%w: mark function %d unmeasurable: %v", ErrUnavailable, code, err)
		}
	}
	return nil
}

// measurable clears the functions whose return probe the kernel confirms (not
// the placement calls' answer, see Confirmed). A function left marked has its
// calls counted and not recorded.
func (s *Session) measurable() error {
	unmeasurable := s.collection.Maps["unmeasurable"]
	if unmeasurable == nil {
		return fmt.Errorf("%w: the program has no per-function measurability table", ErrUnavailable)
	}
	for _, put := range s.placed {
		code, known := obpf.EntryPrograms[put.point.Entry]
		if !known || !s.answer(put).Confirmed {
			continue
		}
		if err := unmeasurable.Update(code, uint8(0), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("%w: mark function %d measurable: %v", ErrUnavailable, code, err)
		}
	}
	return nil
}

// ErrRefused is what attaching fails with when the kernel refused every probe:
// a host that can attach, and would not place these (unlike ErrUnavailable).
var ErrRefused = errors.New("the kernel placed none of the probes it was asked for")

// ErrNotAuthorised is what attaching fails with when a process to authorise is
// not the approved process. It says nothing about the host, and a caller must
// not read it as a reason to try a lesser backend.
var ErrNotAuthorised = errors.New("a process to authorise is not the process that was approved")

// put places one point's entry and return probes.
func (s *Session) put(target *placed) error {
	point := target.point

	if point.Entry == "" && point.Return == "" {
		return errors.New("this point names no program to place")
	}

	executable, err := link.OpenExecutable(point.Path)
	if err != nil {
		return fmt.Errorf("open %s: %w", point.Path, err)
	}
	options := &link.UprobeOptions{Address: point.Offset}

	if point.Entry != "" {
		entry := s.collection.Programs[point.Entry]
		if entry == nil {
			return fmt.Errorf("the program has no %s", point.Entry)
		}
		front, err := executable.Uprobe(point.Symbol, entry, options)
		if err != nil {
			return fmt.Errorf("place %s on %s: %w", point.Symbol, point.Path, err)
		}
		s.links = append(s.links, front)
		target.entry = front
	}

	if point.Return == "" {
		return nil
	}
	back := s.collection.Programs[point.Return]
	if back == nil {
		return fmt.Errorf("the program has no %s", point.Return)
	}
	placedReturn, err := executable.Uretprobe(point.Symbol, back, options)
	if err != nil {
		return fmt.Errorf("place the return of %s on %s: %w", point.Symbol, point.Path, err)
	}
	s.links = append(s.links, placedReturn)
	target.back = placedReturn
	return nil
}

// Confirmed is what the kernel says about the probes this session asked for,
// one entry per point, read back through each link's info. Where the kernel
// carries the uprobe's file and offset (not every kernel does), the offset is
// compared with the one asked for, and a point is confirmed only when every
// probe it needed is; Through says which kind of answer it was.
func (s *Session) Confirmed() []probe.Placement {
	confirmed := make([]probe.Placement, 0, len(s.placed))
	for _, put := range s.placed {
		confirmed = append(confirmed, s.answer(put))
	}
	return confirmed
}

// answer is what the kernel says about one point, decided here only so
// Coverage cannot answer the same question on other terms.
func (s *Session) answer(put placed) probe.Placement {
	entry := probe.Placement{Symbol: put.point.Symbol, Path: put.point.Path, Offset: put.point.Offset}
	if put.refusal != "" {
		entry.Refusal = put.refusal
		return entry
	}

	asked := put.entry
	if asked == nil {
		asked = put.back
	}
	through, err := ask(asked, put.point)
	if err == nil && put.entry != nil && put.back != nil {
		_, err = ask(put.back, put.point)
	}
	if err != nil {
		entry.Refusal = err.Error()
		return entry
	}
	entry.Confirmed, entry.Through = true, through
	return entry
}

// ask puts one link to the kernel and returns what it said. The kernel's
// uprobe offset field is 32 bits; library entry points are far below that.
func ask(placed link.Link, point Point) (string, error) {
	info, err := placed.Info()
	if err != nil {
		return "", fmt.Errorf("the kernel would not say what this link holds: %v", err)
	}
	if perf := info.PerfEvent(); perf != nil {
		if uprobe := perf.Uprobe(); uprobe != nil {
			if uint64(uprobe.Offset) != point.Offset {
				return "", fmt.Errorf("the kernel holds this probe at offset %#x, and it was asked for at %#x",
					uprobe.Offset, point.Offset)
			}
			return fmt.Sprintf("the kernel names %s at %#x", uprobe.File, uprobe.Offset), nil
		}
	}
	return fmt.Sprintf("bpf link %d on program %d, which is as much as this kernel says about a probe",
		info.ID, info.Program), nil
}

// Events is what the probes reported. It is closed when the session is.
func (s *Session) Events() <-chan Event { return s.events }

// Admissions is what the kernel holds, read back from the allowlist: it
// includes fork-hook descendants never offered here and omits instances the
// exit hook removed. Start identity and executable come from /proc where the
// instance is reachable, and are indeterminate (not zero) where it is gone.
func (s *Session) Admissions() ([]admission.Selection, error) {
	allowed := s.collection.Maps["allowed_processes"]
	if allowed == nil {
		return nil, fmt.Errorf("%w: the program has no allowlist map", ErrUnavailable)
	}
	// Withdraw what has ceased first, so an entry for a gone process is not
	// reported as coverage (Reconcile).
	if _, err := s.Reconcile(); err != nil {
		return nil, err
	}

	// One reading of the table, so an instance in a namespace this observer does
	// not share is found by the numbering on its status line.
	located := make(map[instanceKey]process.Process)
	if table, err := process.Read(defaultProcFS); err == nil {
		for _, p := range table.All() {
			located[keyOf(p.Instance())] = p
		}
	}

	var (
		key       instanceKey
		value     admissionValue
		selection []admission.Selection
	)
	entries := allowed.Iterate()
	for entries.Next(&key, &value) {
		if value.Kind == denied {
			continue
		}
		one := admission.Selection{
			Instance: admission.Instance{
				Namespace:  admission.Namespace{Device: key.NamespaceDevice, Inode: key.NamespaceInode},
				PID:        int32(key.PID),
				Generation: admission.Generation(value.Generation),
			},
			Kind: decodeKind(value.Kind),
			Provenance: admission.Provenance{
				Number: int(value.Target),
				Rule:   int(value.Rule),
				Parent: admission.Key{
					Namespace:  admission.Namespace{Device: value.ParentNSDevice, Inode: value.ParentNSInode},
					PID:        int32(value.ParentPID),
					Generation: admission.Generation(value.ParentGeneration),
				},
			},
			Mode:        decodeMode(value.Mode),
			Propagation: decodePropagation(value.Propagate),
		}
		if p, found := located[key]; found {
			one.Instance.Start = p.Start()
			one.Instance.Executable = p.Executable
			one.ObserverPID = p.PID
		}
		// The allowlist holds one grant, so one target, per instance; every other
		// target that named it is kept here, so both reasons are reported.
		if also := s.namedBy[key]; len(also) > 1 {
			one.Provenance = also[0]
			one.AlsoNamedBy = also[1:]
		}
		s.recorded(one)
		selection = append(selection, one)
	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("%w: read the allowlist back: %v", ErrUnavailable, err)
	}
	return selection, nil
}

// Entry is one row of the kernel's allowlist, decoded. Instance.Start is the
// birth the grant carries (clock ticks since boot), against which the program
// authenticates the number's occupant. It is indeterminate on a denial, which
// denies a subtree and is not authenticated.
type Entry struct {
	Instance    admission.Instance
	Kind        admission.Kind
	Mode        admission.Mode
	Propagation admission.Propagation
	Parent      admission.Key

	// Denied is an entry that is an exclusion rather than a grant; Kind has no
	// spelling for one.
	Denied bool

	// Threads is how many of the group the program still counts, and LeaderGone
	// whether the leader has exited with workers remaining; together they decide
	// when the grant ends.
	Threads    uint32
	LeaderGone bool
}

// Held is the allowlist exactly as the kernel holds it, grants and denials
// alike, with no reconciliation, no /proc reading and nothing withdrawn.
// Admissions reconciles first, so asking it whether an entry was left behind
// asks the cleanup whether the cleanup ran; a check that no entry survives
// asserts on this.
func (s *Session) Held() ([]Entry, error) {
	allowed := s.collection.Maps["allowed_processes"]
	if allowed == nil {
		return nil, fmt.Errorf("%w: the program has no allowlist map", ErrUnavailable)
	}

	var (
		key   instanceKey
		value admissionValue
		held  []Entry
	)
	entries := allowed.Iterate()
	for entries.Next(&key, &value) {
		one := Entry{
			Instance: admission.Instance{
				Namespace:  admission.Namespace{Device: key.NamespaceDevice, Inode: key.NamespaceInode},
				PID:        int32(key.PID),
				Generation: admission.Generation(value.Generation),
				Start:      birth(value.Birth),
			},
			Kind:        decodeKind(value.Kind),
			Mode:        decodeMode(value.Mode),
			Propagation: decodePropagation(value.Propagate),
			Parent: admission.Key{
				Namespace:  admission.Namespace{Device: value.ParentNSDevice, Inode: value.ParentNSInode},
				PID:        int32(value.ParentPID),
				Generation: admission.Generation(value.ParentGeneration),
			},
			Denied:     value.Kind == denied,
			Threads:    value.Threads,
			LeaderGone: value.LeaderGone != 0,
		}
		held = append(held, one)
	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("%w: read the allowlist back: %v", ErrUnavailable, err)
	}
	return held, nil
}

// birth is the start identity a grant carries. Zero means the entry
// authenticates nothing, not a start at boot.
func birth(ticks uint64) admission.Start {
	if ticks == 0 {
		return admission.Indeterminate()
	}
	return admission.Determinate(admission.BootTicks(ticks))
}

// Denials is what the kernel holds as denied, read back from the allowlist: the
// fork hook extends an exclusion as its subtree grows, so this says what is
// denied now, not what was offered.
func (s *Session) Denials() ([]admission.Denial, error) {
	allowed := s.collection.Maps["allowed_processes"]
	if allowed == nil {
		return nil, fmt.Errorf("%w: the program has no allowlist map", ErrUnavailable)
	}

	located := make(map[instanceKey]process.Process)
	if table, err := process.Read(defaultProcFS); err == nil {
		for _, p := range table.All() {
			located[keyOf(p.Instance())] = p
		}
	}

	var (
		key     instanceKey
		value   admissionValue
		refused []admission.Denial
	)
	entries := allowed.Iterate()
	for entries.Next(&key, &value) {
		if value.Kind != denied {
			continue
		}
		one := admission.Denial{
			Instance: admission.Instance{
				Namespace:  admission.Namespace{Device: key.NamespaceDevice, Inode: key.NamespaceInode},
				PID:        int32(key.PID),
				Generation: admission.Generation(value.Generation),
			},
			Provenance: admission.Provenance{
				Number: int(value.Target),
				Rule:   int(value.Rule),
				Parent: admission.Key{
					Namespace:  admission.Namespace{Device: value.ParentNSDevice, Inode: value.ParentNSInode},
					PID:        int32(value.ParentPID),
					Generation: admission.Generation(value.ParentGeneration),
				},
			},
		}
		if p, found := located[key]; found {
			one.Instance.Start = p.Start()
			one.Instance.Executable = p.Executable
			one.ObserverPID = p.PID
		}
		refused = append(refused, one)
	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("%w: read the denials back: %v", ErrUnavailable, err)
	}
	return refused, nil
}

// recorded puts an instance into the inventory once, keeping the first record:
// an authorised selection carries its target and mode, which a later event
// cannot.
func (s *Session) recorded(one admission.Selection) {
	s.held.Lock()
	defer s.held.Unlock()
	if s.index == nil {
		s.index = make(map[instanceKey]int)
	}
	key := keyOf(one.Instance)
	if _, already := s.index[key]; already {
		return
	}
	s.index[key] = len(s.inventory)
	s.inventory = append(s.inventory, one)
}

// Inventory is every instance this session recorded a grant for: what authorise
// admitted, what adopt wrote, what a reading of the allowlist found (where a
// fork-hook descendant enters), and every instance an event was attributed to.
// It is session state and cannot fail, so an instance absent here was recorded
// by nothing. Not covered: a fork-hook descendant that transferred nothing and
// whose entry was removed before any reading of the allowlist.
func (s *Session) Inventory() []admission.Selection {
	s.held.Lock()
	defer s.held.Unlock()
	return slices.Clone(s.inventory)
}

// Ended is what became of a recorded instance whose grant the kernel no longer
// holds, decided on positive evidence; without it the answer is the third.
type Ended string

const (
	// ExecutionEnded: the observer's number for it holds no process, or holds a
	// different instance. Its grant went with it.
	ExecutionEnded Ended = "its execution ended and its grant went with it"

	// GrantEndedWhileRunning is the reported limit: the same instance (namespace,
	// number, start identity) is running and its grant is gone, so what it
	// transfers is not observed.
	GrantEndedWhileRunning Ended = "it is still running and its grant is gone, so it is no longer observed"

	// ExecutionIndeterminate: neither established, because no observer-side number
	// was recorded or its start identity could not be read.
	ExecutionIndeterminate Ended = "whether it is still running could not be established"
)

// Withdrawal is one recorded instance whose grant the kernel no longer holds,
// and what became of it.
type Withdrawal struct {
	Selection admission.Selection
	State     Ended

	// Evidence is what the state was decided on.
	Evidence string

	// Reading is the observation the state was decided on, kept whole: the
	// witnessed task has exited by the time anybody reads this, so it must travel
	// with the record.
	Reading process.Execution
}

// Withdrawn is every inventory instance whose grant the kernel no longer
// holds, with what became of each. An unreadable allowlist is an error, never a
// shorter list. Any other failure belongs to its one instance, which is left
// unestablished while the others keep their answers.
func (s *Session) Withdrawn() ([]Withdrawal, error) {
	allowed := s.collection.Maps["allowed_processes"]
	if allowed == nil {
		return nil, fmt.Errorf("%w: the program has no allowlist map", ErrUnavailable)
	}
	holds := make(map[instanceKey]bool)
	var (
		key   instanceKey
		value admissionValue
	)
	entries := allowed.Iterate()
	for entries.Next(&key, &value) {
		holds[key] = true
	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("%w: read the allowlist back: %v", ErrUnavailable, err)
	}
	var gone []Withdrawal
	for _, one := range s.Inventory() {
		if holds[keyOf(one.Instance)] {
			continue
		}
		gone = append(gone, WhatBecameOf(one, s.inspect(one)))
	}
	return gone, nil
}

// inspect reads whether one recorded instance is still running, from its
// execution alone: the process table omits a process whose executable is
// unreadable, such as a group whose leader exited while workers transfer.
func (s *Session) inspect(one admission.Selection) process.Execution {
	return process.Inspect(defaultProcFS, one.ObserverPID, s.expected(one))
}

// expected is the identity recorded for one instance, compared against /proc.
// The birth comes from the admission record first (never deleted) and from
// Reconcile's baseline second (deleted with its entry); a fork-hook descendant
// has no birth in its record. With neither, the identity is unestablished.
func (s *Session) expected(one admission.Selection) process.Group {
	start := one.Instance.Start
	if !start.Determined {
		start = s.seenOf(keyOf(one.Instance))
	}
	return process.Group{
		Namespace:    one.Instance.Namespace,
		NamespacePID: one.Instance.PID,
		Start:        start,
	}
}

// seenOf, see and forget are the only way into s.seen, and each holds s.held:
// Reconcile writes the map and expected, reachable through Grants, reads it.
func (s *Session) seenOf(key instanceKey) admission.Start {
	s.held.Lock()
	defer s.held.Unlock()
	return s.seen[key]
}

func (s *Session) see(key instanceKey, start admission.Start) {
	s.held.Lock()
	defer s.held.Unlock()
	if s.seen == nil {
		s.seen = make(map[instanceKey]admission.Start)
	}
	s.seen[key] = start
}

func (s *Session) forget(key instanceKey) {
	s.held.Lock()
	defer s.held.Unlock()
	delete(s.seen, key)
}

// WhatBecameOf decides which of the three states one recorded instance is in,
// from a reading of its execution passed in, so the decision can be tested
// against observations nobody staged.
func WhatBecameOf(one admission.Selection, reading process.Execution) Withdrawal {
	became := func(state Ended, evidence string) Withdrawal {
		return Withdrawal{Selection: one, State: state, Evidence: evidence, Reading: reading}
	}
	if one.ObserverPID == 0 {
		return became(ExecutionIndeterminate,
			"no number in the observer's own pid namespace was ever recorded for it, "+
				"so nothing here can be looked up")
	}

	switch reading.Liveness {
	case process.LivenessRunning:
		return became(GrantEndedWhileRunning,
			fmt.Sprintf("pid %d is still running and the allowlist holds no grant for it: %s",
				one.ObserverPID, reading.Evidence()))
	case process.LivenessTerminated, process.LivenessGone, process.LivenessReplaced:
		return became(ExecutionEnded,
			fmt.Sprintf("pid %d %s: %s", one.ObserverPID, reading.Liveness, reading.Evidence()))
	default:
		return became(ExecutionIndeterminate,
			fmt.Sprintf("pid %d: %s", one.ObserverPID, reading.Evidence()))
	}
}

// Reconcile withdraws every allowlist entry that no longer names the instance
// it was written for, and says what it withdrew. An entry can outlive its
// process: a descendant found in the process table can exit before its entry
// is written, and exits this session did not see leave entries too. Such an
// entry confers no authority (the program authenticates every read against its
// birth, obs_grant), so this is cleanup and accounting.
//
// The first reading records the start identity at each key; later readings
// compare against it. An entry with no live process, a different start
// identity, or an unreadable one is withdrawn. Entries for dead processes stand
// until the next run of this.
//
// Two kinds of refusal come back, told apart by Reason: withdrawn entries, and
// descendants of surviving entries in pid namespaces this session did not
// enumerate (beyondEnumeration).
//
// Admissions calls it, and only this package's tests call Admissions; the
// observer command reaches neither. Withdrawing deletes the entry's baseline in
// s.seen, so a fork-hook descendant (whose record has no birth) reads as
// established before and indeterminate after.
func (s *Session) Reconcile() ([]Declined, error) {
	allowed := s.collection.Maps["allowed_processes"]
	if allowed == nil {
		return nil, fmt.Errorf("%w: the program has no allowlist map", ErrUnavailable)
	}
	table, err := process.Read(defaultProcFS)
	if err != nil {
		return nil, fmt.Errorf("%w: read the process table: %v", ErrUnavailable, err)
	}
	living := make(map[instanceKey]process.Process, len(table.All()))
	for _, p := range table.All() {
		living[keyOf(p.Instance())] = p
	}
	var (
		key       instanceKey
		value     admissionValue
		withdrawn []Declined
		inForce   []admission.Selection
	)
	entries := allowed.Iterate()
	for entries.Next(&key, &value) {
		one := admission.Selection{
			Instance: admission.Instance{
				Namespace:  admission.Namespace{Device: key.NamespaceDevice, Inode: key.NamespaceInode},
				PID:        int32(key.PID),
				Generation: admission.Generation(value.Generation),
			},
			Kind:       decodeKind(value.Kind),
			Provenance: admission.Provenance{Number: int(value.Target), Rule: int(value.Rule)},
			Mode:       decodeMode(value.Mode),
		}

		live, alive := living[key]
		baseline := s.seenOf(key)
		switch {
		case !alive:
			withdrawn = append(withdrawn, Declined{Selection: one, Reason: InstanceGone, Err: fmt.Errorf(
				"%w: pid %d in %s is in the allowlist and no process holds that number",
				ErrNotAuthorised, one.Instance.PID, one.Instance.Namespace)})
		case !live.Start().Determined:
			withdrawn = append(withdrawn, Declined{Selection: one, Reason: StartIndeterminate, Err: fmt.Errorf(
				"%w: pid %d in %s is in the allowlist and its start identity could not be read",
				ErrNotAuthorised, one.Instance.PID, one.Instance.Namespace)})
		case baseline.Determined && baseline != live.Start():
			withdrawn = append(withdrawn, Declined{Selection: one, Reason: IdentityChanged, Err: fmt.Errorf(
				"%w: pid %d in %s was admitted when it %s and now %s",
				ErrNotAuthorised, one.Instance.PID, one.Instance.Namespace, baseline, live.Start())})
		default:
			s.see(key, live.Start())
			if value.Kind != denied {
				one.ObserverPID = live.PID
				inForce = append(inForce, one)
			}
			continue
		}
	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("%w: read the allowlist back: %v", ErrUnavailable, err)
	}

	for _, one := range withdrawn {
		gone := keyOf(one.Selection.Instance)
		if err := allowed.Delete(gone); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("%w: withdraw pid %d: %v",
				ErrUnavailable, one.Selection.Instance.PID, err)
		}
		s.forget(gone)
	}
	beyond := s.beyondEnumeration(table, inForce)
	s.declined = append(s.declined, withdrawn...)
	s.declined = append(s.declined, beyond...)
	return append(withdrawn, beyond...), nil
}

// beyondEnumeration names the descendants of still-admitted instances that the
// program could not have admitted, because their pid namespace was not passed
// to it. No kernel counter can do this: every unapproved process on the host
// resolves in no enumerated namespace, so it would count the host's traffic.
// The set is a floor: exited children cannot be named, and one whose namespace
// cannot be read is left out. Only modes covering descendants created after
// resolution are walked; under the others the policy already accounts for the
// absence.
func (s *Session) beyondEnumeration(table process.Table, inForce []admission.Selection) []Declined {
	if s.beyond == nil {
		s.beyond = make(map[instanceKey]admission.Start)
	}

	var named []Declined
	for _, one := range inForce {
		if !one.Mode.Answers().Future || one.ObserverPID == 0 {
			continue
		}
		for _, below := range table.Descendants(one.ObserverPID) {
			child := below.Instance()
			if !child.Namespace.Known() || s.resolvable(child.Namespace) {
				continue
			}
			// Named once per instance, not per reconciliation; a number reused by another
			// process in that namespace is a different instance and is named again.
			key := keyOf(child)
			if start, already := s.beyond[key]; already && start == below.Start() {
				continue
			}
			s.beyond[key] = below.Start()
			named = append(named, Declined{
				Selection: admission.Selection{
					Instance: child,
					Kind:     admission.ByDescent,
					Provenance: admission.Provenance{
						Target: one.Provenance.Target,
						Number: one.Provenance.Number,
						Rule:   one.Provenance.Rule,
						Parent: one.Instance.Key(),
					},
					Mode:        one.Mode,
					ObserverPID: below.PID,
				},
				Reason: NamespaceUnenumerated,
				Err: fmt.Errorf("%w: pid %d below pid %d is in %s, which this session did not enumerate",
					ErrNotAuthorised, below.PID, one.ObserverPID, child.Namespace),
			})
		}
	}
	return named
}

// ErrNoPayloadReads is what Reads answers for a program that reads no user
// memory, rather than a zero indistinguishable from the full program taking
// none.
var ErrNoPayloadReads = errors.New("this program reads no user memory, so it counts no reads of it")

// ErrReadsIncomplete is what Reads answers when a user-memory read could not
// be filed against an admission: an absent generation then no longer means
// that admission took no read.
var ErrReadsIncomplete = errors.New("a user-memory read could not be filed against its admission, " +
	"so a generation missing from this map is not evidence that no read was taken under it")

// Reads is how many user-memory reads the program took, by admission
// generation. It is counted at the read, so a read whose output is discarded
// still counts. A generation with no entry took no read, while the error is
// nil. The map holds 65536 generations with no eviction, since the evidence
// must outlive its admission; once full, new first reads are counted as
// unfiled and this refuses to answer.
func (s *Session) Reads() (map[admission.Generation]uint64, error) {
	counters := s.collection.Maps["reads"]
	if counters == nil {
		return nil, ErrNoPayloadReads
	}

	var (
		generation uint64
		taken      uint64
	)
	found := make(map[admission.Generation]uint64)
	entries := counters.Iterate()
	for entries.Next(&generation, &taken) {
		found[admission.Generation(generation)] = taken
	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("%w: read the user-memory read counters: %v", ErrUnavailable, err)
	}

	unfiled, err := s.stat(obpf.StatReadUnrecorded)
	if err != nil {
		return found, err
	}
	if unfiled > 0 {
		return found, fmt.Errorf("%w: %d of them", ErrReadsIncomplete, unfiled)
	}
	return found, nil
}

// Dropped is how many ring-buffer reservations the kernel refused because the
// buffer was full. A dropped event never arrives, so its stream closes over the
// gap and every later byte sits at an offset nothing says is wrong.
func (s *Session) Dropped() (int64, error) { return s.stat(obpf.StatReserveFailed) }

// Unmatched is how many returns fired with nothing recorded on the way in, so
// the call's count was never read. It may cover a call already inside the
// function when the probes were placed; whether that return fires varies
// between runs on some kernels, so neither zero nor one is evidence about such
// a call. Attaching before the traffic starts bounds the loss. Returns of entry
// points reached inside a probed call are not counted (struct call's live
// flag, bpf/ssl.bpf.h).
func (s *Session) Unmatched() (int64, error) { return s.stat(obpf.StatUnmatched) }

// Unmeasurable is how many calls entered a function this session holds no
// return probe for: never recorded, because recording would take the thread's
// in-flight slot for ever. It is separate from Unmatched (a return whose entry
// was never seen) and Executing (an entry whose return has not arrived): those
// bytes crossed and their count is unavailable (the unmeasurable map).
func (s *Session) Unmeasurable() (int64, error) { return s.stat(obpf.StatUnmeasurableCall) }

// Descendants is how many processes the allowlist gained because an approved
// process created them, counted by the program rather than by a walk.
func (s *Session) Descendants() (int64, error) { return s.stat(obpf.StatDescendants) }

// DescendantsUnrecorded is how many children of an admitted instance the
// allowlist would not take, so they are not observed. Without it such a child
// looks like one never forked.
func (s *Session) DescendantsUnrecorded() (int64, error) {
	return s.stat(obpf.StatDescendantUnrecorded)
}

// Unrecorded is how many calls the in-flight table would not take on the way
// in. A refused insertion produces an unmatched return, so folding the two
// would report a full table as calls entered before the probes were placed.
func (s *Session) Unrecorded() (int64, error) { return s.stat(obpf.StatCallUnrecorded) }

// Refused is how many in-flight calls reached their return with their
// admission gone (exec, exit, withdrawal, or the key passed to another
// thread). Their payload was not read, and their bytes are absent from their
// stream.
func (s *Session) Refused() (int64, error) { return s.stat(obpf.StatRefused) }

// Consumed is the places this program took out of the production order and
// delivered nothing for. Only two counters do that: a refused reservation (the
// stamp precedes it) and the two refusal sites at the read boundary. Every
// other counted refusal returns before stamping and takes no place, so a
// consumer may not sum the counters it sees (obs_emit, bpf/ssl.bpf.h).
func (s *Session) Consumed() (probe.Consumed, error) {
	failed, err := s.stat(obpf.StatReserveFailed)
	if err != nil {
		return probe.Consumed{}, err
	}
	refused, err := s.stat(obpf.StatRefused)
	if err != nil {
		return probe.Consumed{}, err
	}
	return probe.Consumed{ReserveFailed: failed, Refused: refused}, nil
}

// callValue is the in-flight table's value as the program declares it (struct
// call, bpf/ssl.bpf.h), with explicit padding: reading a wrong byte here would
// report operations in flight that are not.
type callValue struct {
	SSL        uint64
	Buffer     uint64
	Capacity   uint64
	Count      uint64
	Generation uint64
	Sequence   uint64
	Function   uint32
	FD         int32
	FDs        uint8
	// The seven alignment bytes before the socket fields, named so every later
	// field reads from the right place.
	Aligning  [7]uint8
	Socket    uint64
	SocketIno uint64
	SocketGen uint64
	SocketOcc uint64

	// The socket's endpoints, in the program's order, which needs no padding.
	NetIno uint64
	Opened uint64
	Local  [16]byte
	Peer   [16]byte
	LPort  uint16
	DPort  uint16

	SocketFD  int32
	Sockets   uint8
	Ends      uint8
	Outcome   uint8
	IO        uint8
	Direction uint8
	Counting  uint8
	Early     uint8
	// Deferred sits between Early and Live in the program's struct; unnamed, Live
	// would read Deferred at the same total size.
	Deferred    uint8
	Live        uint8
	Reserved    [4]uint8
	LivePadding [3]uint8
}

// Executing is how many calls are still inside the observed library: live
// entries in the in-flight table. It differs from an event reserved and not yet
// persisted: an executing call's bytes may not have crossed at all. It also
// measures what nothing else can: a return that never arrives leaves its entry
// live with nothing counted, so after traffic ends this should be near zero.
// Completed calls leave entries with Live clear, so the flag is counted, not
// the entries.
func (s *Session) Executing() (int64, error) {
	inflight := s.collection.Maps["inflight"]
	if inflight == nil {
		return 0, fmt.Errorf("%w: the program has no in-flight table, so nothing here says what "+
			"was still executing when the run was sealed", ErrUnavailable)
	}

	var (
		thread uint64
		call   callValue
		live   int64
	)
	entries := inflight.Iterate()
	for entries.Next(&thread, &call) {
		if call.Live != 0 {
			live++
		}
	}
	if err := entries.Err(); err != nil {
		return 0, fmt.Errorf("%w: read the in-flight table: %v", ErrUnavailable, err)
	}
	return live, nil
}

// DenialsUnrecorded is how many children of a denied instance the allowlist
// would not take.
func (s *Session) DenialsUnrecorded() (int64, error) { return s.stat(obpf.StatDenialUnrecorded) }

// DiscardedDeferred is how many calls held through a fork window were
// discarded because their task was never admitted. Nothing captured is short
// by them, so it is not a refusal.
func (s *Session) DiscardedDeferred() (int64, error) { return s.stat(obpf.StatDeferredDiscarded) }

// SocketsUnrecorded is how many descriptor lifetimes the socket table would not
// take. Each such refusal turns a possible binding into one reported as never
// observed, so a run with full tables looks like one watching a process whose
// socket calls it cannot see; these counters tell the two apart.
func (s *Session) SocketsUnrecorded() (int64, error) { return s.stat(obpf.StatSocketUnrecorded) }

// BindingsUnrecorded is the handle bindings the binding table would not take.
func (s *Session) BindingsUnrecorded() (int64, error) { return s.stat(obpf.StatBindingUnrecorded) }

// StaleBindingsDropped is how many handle bindings a gone occupant of a number
// left behind and a later task at that number retired by freeing the same
// handle address. Nothing was lost; a climbing count says pid reuse reaches
// this capture (obs_free_entry, bpf/ssl.bpf.h).
func (s *Session) StaleBindingsDropped() (int64, error) {
	return s.stat(obpf.StatStaleBindingDropped)
}

// Attempts is how many events the program tried to place in the ring buffer,
// from its own allocator: granted reservations are attempts minus refusals, so
// the run's inventory is an identity (package connection, Counters).
func (s *Session) Attempts() (int64, error) {
	attempts := s.collection.Maps["attempts"]
	if attempts == nil {
		return 0, fmt.Errorf("%w: the program has no event-order allocator, so nothing here says "+
			"how many events it tried to place", ErrUnavailable)
	}
	var value uint64
	if err := attempts.Lookup(uint32(0), &value); err != nil {
		return 0, fmt.Errorf("%w: read the event-order allocator: %v", ErrUnavailable, err)
	}
	return int64(value), nil
}

// stat reads one of the program's counters. An unreadable counter is an error,
// never zero, which would read as a capture that lost nothing.
func (s *Session) stat(index uint32) (int64, error) {
	stats := s.collection.Maps["stats"]
	if stats == nil {
		return 0, fmt.Errorf("%w: the program has no counters map, so nothing here says what "+
			"this capture lost", ErrUnavailable)
	}
	var value uint64
	if err := stats.Lookup(index, &value); err != nil {
		return 0, fmt.Errorf("%w: read counter %d: %v", ErrUnavailable, index, err)
	}
	return int64(value), nil
}

// StopReading ends delivery: the reader returns and the event channel closes.
// Close also frees the maps and their counters, so a run reads its numbers
// between the two.
func (s *Session) StopReading() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	<-s.stopped
}

// Close removes every probe and stops reading.
func (s *Session) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	if s.reader != nil {
		_ = s.reader.Close()
	} else {
		// Nothing ever read, so nothing will close this; a session that failed before
		// its reader existed must still close.
		select {
		case <-s.stopped:
		default:
			close(s.stopped)
		}
	}
	for _, l := range s.links {
		_ = l.Close()
	}
	if s.collection != nil {
		s.collection.Close()
	}
	return nil
}

func (s *Session) read() {
	defer close(s.stopped)
	defer close(s.events)
	for {
		// A deadline on every read, so the loop can conclude the buffer is empty (a
		// read that found nothing for quiet), which Drain needs.
		s.reader.SetDeadline(time.Now().Add(quiet))
		record, err := s.reader.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			s.idled()
			select {
			case <-s.done:
				return
			default:
			}
			continue
		}
		if err != nil {
			// A reader stopped by closing has lost nothing; one stopped otherwise lost
			// whatever the buffer held. They are told apart here, since afterwards they
			// look identical.
			select {
			case <-s.done:
			default:
				why := err.Error()
				s.failure.Store(&why)
				s.failed.Store(true)
			}
			return
		}
		event, ok := s.decode(record.RawSample)
		if !ok {
			s.undecodable.Add(1)
			continue
		}
		// An instance admitted by the fork hook that transferred and had gone before
		// any reading of the allowlist is recorded here only (Inventory).
		s.recorded(admission.Selection{
			Instance: admission.Instance{
				Namespace:  event.Namespace,
				PID:        event.NamespacePID,
				Generation: event.Generation,
			},
			Kind:        admission.KindUnknown,
			ObserverPID: event.PID,
		})
		select {
		case s.events <- event:
			s.delivered.Add(1)
		case <-s.done:
			// Decoded and going nowhere: counted, since its stream is short by exactly
			// this.
			s.abandoned.Add(1)
			return
		}
	}
}

// idled says the ring buffer held nothing for a whole read. The send is not
// blocking, so a session nobody is draining costs nothing to signal.
func (s *Session) idled() {
	select {
	case s.idle <- struct{}{}:
	default:
	}
}

// endpointsOf reads the socket's addresses out of one event, at offsets the
// layout guard in package bpf pins. Known comes from the program's flag, never
// the bytes: an all-zero address is the unspecified address.
func (s *Session) endpointsOf(sample []byte) probe.Ends {
	order := binary.LittleEndian
	ends := probe.Ends{
		Netns:     order.Uint64(sample[88:96]),
		LocalPort: order.Uint16(sample[128:130]),
		PeerPort:  order.Uint16(sample[130:132]),
		Known:     sample[86] != 0,
		// This backend reads the endpoints at every acquisition, so a producer ran.
		Attempted: true,
	}
	copy(ends.Local[:], sample[96:112])
	copy(ends.Peer[:], sample[112:128])

	// The socket's start, moved from the program's clock to the wall so it can be
	// ordered against other lifetimes. Zero stays zero: no start was seen.
	if raw := order.Uint64(sample[136:144]); raw != 0 && !s.monotonicBase.IsZero() {
		ends.OpenedAt = s.monotonicBase.Add(time.Duration(raw))
	}
	return ends
}

// pairClocks reads the program's clock and the wall clock once and returns the
// wall instant of the first's zero, bounded by the gap between the readings;
// taken at Attach so that gap is paid once.
func pairClocks() time.Time {
	var ts unix.Timespec
	wall := time.Now()
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// No pairing rather than a wrong one: an unplaceable open time is left unset.
		return time.Time{}
	}
	return wall.Add(-time.Duration(ts.Nano()))
}

// decode reads one raw event (struct event, bpf/ssl.bpf.h). The object has no
// BTF for it, since a ring buffer declares no types, so the offsets are proved
// by the attach suite comparing a delivered event's instance with the
// allowlist's.
func (s *Session) decode(sample []byte) (Event, bool) {
	if len(sample) < rawHeader {
		return Event{}, false
	}
	order := binary.LittleEndian
	kept := order.Uint32(sample[72:76])

	event := Event{
		Kind:  Kind(sample[83]),
		Stamp: order.Uint64(sample[0:8]),
		SSL:   order.Uint64(sample[16:24]),
		Namespace: admission.Namespace{
			Device: order.Uint64(sample[32:40]),
			Inode:  order.Uint64(sample[40:48]),
		},
		Generation:   admission.Generation(order.Uint64(sample[24:32])),
		PID:          int32(order.Uint32(sample[56:60])),
		TID:          int32(order.Uint32(sample[60:64])),
		NamespacePID: int32(order.Uint32(sample[64:68])),
		Length:       order.Uint32(sample[68:72]),
		Descriptor:   int32(order.Uint32(sample[76:80])),
		Binding:      order.Uint64(sample[8:16]),
		Socket:       order.Uint64(sample[48:56]),
		Bound:        probe.Bound(sample[84]),
		Outcome:      probe.SocketOutcome(sample[85]),
		Early:        sample[81] != 0,
		Measured:     sample[82] != 0,
		Endpoints:    s.endpointsOf(sample),
		At:           time.Now(),
	}
	switch sample[80] {
	case 1:
		event.Direction = fragment.Sent
	case 2:
		event.Direction = fragment.Received
	}

	if kept > chunk {
		kept = chunk
	}
	if int(rawHeader+kept) <= len(sample) && kept > 0 {
		event.Payload = append([]byte(nil), sample[rawHeader:rawHeader+kept]...)
	}
	return event, true
}
