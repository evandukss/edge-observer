// Package probe is the contract a TLS implementation is observed through, and
// the catalog of implementations that have one. Supporting a new runtime means
// writing an Adapter, touching nothing in capture, correlation or
// reconstruction.
//
// A runtime with no adapter reports itself unsupported and never degrades into
// inferring plaintext from socket traffic: wrong inferred plaintext is
// indistinguishable from right.
package probe

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/process"
)

// Transfer is one plaintext transfer an adapter observed: what one call into a
// TLS library moved, on one connection, in one direction. Stream position is
// capture's to decide.
type Transfer struct {
	Process fragment.Process

	// Instance is the admitted execution this transfer belongs to (pid namespace,
	// pid, generation, and start and executable as evidence). A connection's
	// identity is built on it, since handles are unique only within a process and
	// addresses recur across forks. Zero where the backend cannot supply one, and
	// visible as such.
	Instance admission.Instance

	// Network is the observed execution's network namespace, which scopes an
	// address. It is read while probes are placed, since /proc/<pid>/ns/net is
	// refused after the capability drop.
	Network Netns

	// Descriptor is the socket this transfer's bytes crossed, Binding the
	// generation of that descriptor's occupancy, and Bound what is established
	// about the pair; the first two mean nothing without Bound. A closed-and-reused
	// or dup2-replaced descriptor is a different socket under the same number.
	Descriptor int32
	Binding    uint64
	Bound      Bound

	// Socket is the inode of the socket the kernel acquired for this call's I/O,
	// as ss and /proc/net report it: the only part of a binding comparable outside
	// this observer. Zero is a socket with no file of its own.
	Socket uint64

	// Ends is that socket's addresses, read at the same hook and moment.
	Ends Ends

	// Outcome is what happened to this call's own kernel I/O: why there is no
	// binding. An ordinary-file write, unreadable evidence and no I/O at all are
	// different facts, and only the last may use the handle's earlier binding.
	Outcome SocketOutcome

	// Stamp is this observation's place in the backend's production order: the
	// only thing that locates a loss. Stamps are consecutive, so a missing number
	// is an observation produced and not delivered, which says which streams were
	// live across the gap. Zero means the backend does not stamp: ordering
	// evidence absent, not a lossless run.
	Stamp uint64

	// Endpoint is the adapter's opaque handle for the connection: unique within a
	// process while open, reusable afterwards (hence Closed).
	Endpoint uint64

	Direction fragment.Direction

	// Length is what the call returned: bytes transferred, not buffer size.
	Length uint32

	// Payload is what the probe copied from the caller's buffer: the first
	// len(Payload) bytes moved, and nothing else. Shorter than Length when the
	// call moved more than one event carries; empty where no plaintext is copied
	// or the kernel refused the read. Never filler.
	Payload []byte

	// Early is whether these bytes arrived as TLS 1.3 early data: same stream and
	// offsets, but replayable and not forward-secret.
	Early bool

	// Measured is whether Length is the count the call reported. False where the
	// count is written through a pointer and unreadable from registers: a transfer
	// nobody could measure is not a transfer of nothing.
	Measured bool

	At time.Time
}

// Connection is one connection ending, letting an endpoint be reused without
// its successor continuing the old stream.
type Connection struct {
	Process fragment.Process

	// Instance is the admitted execution, as on a Transfer, so one execution's
	// ending cannot end another's connection at the same handle address.
	Instance admission.Instance

	// Network is the namespace the execution is in, as it is on a Transfer.
	Network Netns

	// Stamp is this ending's production-order place: an ending can be lost too.
	Stamp uint64

	Endpoint uint64
	At       time.Time
}

// Sink is where an attached adapter puts what it sees. Both methods run on the
// adapter's event reader, so they must return quickly and never block on
// anything an observed process could stall.
type Sink interface {
	Transfer(Transfer)
	Closed(Connection)
}

// Probe is one place an adapter attaches: a symbol at a file offset. Entry and
// return probes share it: the buffer is known on entry, the count on return.
type Probe struct {
	Symbol string `json:"symbol"`
	Path   string `json:"path"`
	Offset uint64 `json:"offset"`
}

// Support is one adapter's answer about one process.
type Support struct {
	Adapter   string `json:"adapter"`
	Supported bool   `json:"supported"`

	// Reason is always filled, whichever way the answer went.
	Reason string `json:"reason"`

	// Runtime names what the adapter found; empty when nothing.
	Runtime string `json:"runtime,omitempty"`

	// Error is set when the adapter could not find out, which is not no.
	Error string `json:"error,omitempty"`

	Probes []Probe `json:"probes,omitempty"`

	// Unknown is what the runtime's plaintext family exports that the catalogue
	// does not name: bytes crossing it would be silently absent.
	Unknown []string `json:"unknown,omitempty"`

	// Missing is what the catalogue expects of this version and the library did
	// not export: a short resolution, not an old library.
	Missing []string `json:"missing,omitempty"`
}

// Inspector answers whether a runtime can be observed and where its entry
// points are, without attaching. The catalogue is built from these, so a
// program needing only the answer reaches no attach machinery.
type Inspector interface {
	// Name identifies the adapter; unique among registered adapters.
	Name() string

	// Inspect answers whether this adapter can observe the process, without
	// attaching to it or reading anything the process holds.
	Inspect(process.Process) Support
}

// Request is what a caller asks an adapter to attach to, and what it demands.
type Request struct {
	// Processes is the whole approved set. Probes are placed on files and fire for
	// every process running one, so asking per process would place (and report)
	// everything twice. Which process an event came from is decided per event.
	Processes []process.Process

	// Admit is why each process may be observed: instance, target, inherited
	// parent and descendant mode - one entry per process, matched by ObserverPID.
	// A process with no entry is refused: the mismatch means the lists came from
	// different readings.
	Admit []admission.Selection

	// Read is each process's own files, by ObserverPID, where read by someone
	// else (the reload command, for a session that dropped the privilege). Nil
	// means the adapter reads them.
	Read map[int32]Reading

	// Deny is what an exclusion denies: those instances and their subtrees, given
	// with Admit so the adapter enforces the denial where admissions are decided.
	Deny []admission.Denial
}

// Unmet is why a capability does not satisfy this request, nil where it does.
// Every request requires plaintext copying, which is not a setting: a request
// that cannot have plaintext is refused with ErrDegraded, since an observer
// copying nothing looks like one on a quiet host.
//
// It is asked twice with one function: of the build before placement, and of
// what the kernel confirmed after, which alone catches a program holding no
// probe on any plaintext function. A partial placement is not unmet: the
// functions it lacks are named.
func (r Request) Unmet(capability Capability) error {
	if capability.Payload {
		return nil
	}
	if len(capability.Unobserved) == 0 {
		return fmt.Errorf("%w: this attachment loads the %s program",
			ErrDegraded, capability.Program)
	}
	return fmt.Errorf("%w: the probes placed hold no plaintext-moving function: %s",
		ErrDegraded, strings.Join(capability.Unobserved, ", "))
}

// Backend is how an attachment reached the kernel, read off the attachment
// rather than the request.
type Backend string

const (
	// BPF is a loaded BPF program on the entry points: the only backend able to
	// copy the caller's buffer, depending on the program loaded.
	BPF Backend = "bpf"

	// TraceFS is the tracefs uprobe interface: registers only, so it can report a
	// transfer and its size but never its bytes.
	TraceFS Backend = "tracefs"

	// Mixed is an attachment whose placements reached different backends, named
	// rather than folded into either neighbour.
	Mixed Backend = "mixed"
)

// Capability is what an attachment can actually do, as opposed to what was
// asked: an attachment that fell back to a backend copying no plaintext must
// not look like a correct one on a silent host.
type Capability struct {
	Backend Backend `json:"backend"`

	// Program names the BPF program loaded; empty for a backend that loads none.
	Program string `json:"program,omitempty"`

	// Payload is whether this attachment copies the observed plaintext; false
	// means every record has a length and no bytes.
	Payload bool `json:"payload"`

	// Filtered is whether an unapproved process is refused before anything about
	// it reaches this program. A BPF program holds the allowlist in the kernel; a
	// tracefs uprobe carries metadata to userspace, where the filter runs.
	Filtered bool `json:"filtered"`

	// Descendants is whether this attachment can observe what an approved process
	// forks, where a forking server transfers. Stated, since absence looks like
	// silence.
	Descendants bool `json:"descendants"`

	// Lifecycle is whether this attachment observes a connection ending. Without
	// it a reused handle address continues the previous connection's stream,
	// invisibly.
	Lifecycle bool `json:"lifecycle"`

	// Binding is whether this attachment can record a descriptor against a call
	// (the number passed, not the socket used). Which socket was crossed is
	// SocketEvidence: with Binding and no SocketEvidence, descriptors are recorded
	// and nothing is established.
	Binding bool `json:"binding"`

	// Unobserved is every catalogued entry point asked for that the kernel holds
	// no probe on, by name, since a reader acts on which function is unwatched.
	Unobserved []string `json:"unobserved,omitempty"`

	// SocketEvidence is whether this attachment establishes the socket from the
	// object the kernel acquired for a call's own I/O, rather than from a table of
	// descriptors it watched being created. A separate axis from Binding.
	SocketEvidence bool `json:"socket_evidence"`

	// IPv6 is whether the socket evidence covers IPv6 as well as IPv4. The
	// families have distinct entry points, so a missing IPv6 symbol withdraws only
	// that claim.
	IPv6 bool `json:"ipv6"`

	// Withheld is every claim this attachment does not make, with the member whose
	// absence withdrew it, so an operator can tell a missing symbol from a policy.
	Withheld []Withheld `json:"withheld,omitempty"`

	// MinimumKernel is the oldest kernel this attachment's mechanism works on;
	// empty for a backend with no floor.
	MinimumKernel string `json:"minimum_kernel,omitempty"`
}

// Claim is one thing an attachment says it observes, named so it can be
// withdrawn by name, in words an operator can act on.
type Claim string

const (
	// SocketEvidenceClaim is the whole socket-evidence group: without every
	// required member, a call's I/O cannot be tied to its socket, and the claim is
	// withdrawn rather than weakened.
	SocketEvidenceClaim Claim = "the socket a call's own I/O crossed"

	// IPv6Claim is the IPv6 half, claimed separately (distinct entry points). Its
	// absence narrows the capture; it never breaks it.
	IPv6Claim Claim = "IPv6 socket coverage"
)

// Withheld is one claim not made, and why: Member is the kernel function or
// tracepoint, Reason the kernel's words where any.
type Withheld struct {
	Claim  Claim  `json:"claim"`
	Member string `json:"member"`
	Reason string `json:"reason,omitempty"`
}

// Weakest is what a set of placements can report together: the weakest of
// them on every axis, decided here so no new axis is forgotten. No placements
// can do nothing (the zero value).
func Weakest(capabilities ...Capability) Capability {
	if len(capabilities) == 0 {
		return Capability{}
	}

	folded := capabilities[0]
	folded.Unobserved = slices.Clone(capabilities[0].Unobserved)
	folded.Withheld = slices.Clone(capabilities[0].Withheld)
	for _, next := range capabilities[1:] {
		folded.Payload = folded.Payload && next.Payload
		folded.Filtered = folded.Filtered && next.Filtered
		folded.Descendants = folded.Descendants && next.Descendants
		folded.Lifecycle = folded.Lifecycle && next.Lifecycle
		folded.Binding = folded.Binding && next.Binding
		folded.SocketEvidence = folded.SocketEvidence && next.SocketEvidence
		folded.IPv6 = folded.IPv6 && next.IPv6
		for _, withheld := range next.Withheld {
			if !slices.Contains(folded.Withheld, withheld) {
				folded.Withheld = append(folded.Withheld, withheld)
			}
		}
		if folded.Backend != next.Backend {
			folded.Backend = Mixed
		}
		if folded.Program != next.Program {
			folded.Program = ""
		}
		// A member's floor is the set's. Only one backend here has a floor.
		if folded.MinimumKernel == "" {
			folded.MinimumKernel = next.MinimumKernel
		}
		for _, symbol := range next.Unobserved {
			if !slices.Contains(folded.Unobserved, symbol) {
				folded.Unobserved = append(folded.Unobserved, symbol)
			}
		}
	}
	return folded
}

// ErrDegraded refuses a request when the host cannot copy plaintext: the
// plaintext program will not load, or no placement holds a plaintext function.
var ErrDegraded = errors.New("no attachment on this host can copy the observed plaintext, and this run requires it")

// Adapter is an Inspector that can also attach.
type Adapter interface {
	Inspector

	// Attach begins observation of the requested set; Close ends it.
	Attach(Request, Sink) (Attachment, error)
}

// Attachment is a live attachment covering a set of approved processes.
type Attachment interface {
	// Close removes every probe this attachment placed. It is safe to call
	// more than once.
	Close() error

	// Capability is what this attachment can report, read off what it attached
	// with.
	Capability() Capability
}

// Placement is one catalogued function as the observer asked the kernel to
// probe it, and as the kernel answered: a probe is never reported placed
// merely because placing it did not fail.
type Placement struct {
	Symbol string `json:"symbol"`
	Path   string `json:"path"`
	Offset uint64 `json:"offset"`

	// Confirmed is what the kernel says, read back after placement.
	Confirmed bool `json:"confirmed"`

	// Through names what answered: kernels confirm different amounts by version.
	Through string `json:"through,omitempty"`

	// Refusal is the kernel's own error, verbatim, from placement or read-back.
	Refusal string `json:"refusal,omitempty"`
}

// Attested is an attachment that can say what the kernel holds for it. One
// that cannot ask is honest by not implementing it.
type Attested interface {
	Attachment

	// Placements is one entry per catalogued function asked for on behalf of the
	// named process, with the kernel's answer, or why nothing was asked. Processes
	// sharing a library share placements. An uncovered process gets a reason, not
	// an empty list.
	Placements(pid int32) ([]Placement, error)
}

// Covering is an attachment that can say what it can do for one covered
// process. Capability folds a set to its weakest; an account of one process
// needs that process's own.
type Covering interface {
	Attachment

	// Capable is what this attachment can report about the named process, or why
	// it covers no such process (an error, never a zero capability).
	Capable(pid int32) (Capability, error)
}

// Catalog is the registry of adapters. It is fixed once built, so support is
// decided where it is constructed.
type Catalog struct {
	adapters []Inspector
}

// NewCatalog builds a catalog in the order the adapters are given, which is the
// order they are asked in.
func NewCatalog(adapters ...Inspector) (Catalog, error) {
	named := make(map[string]bool, len(adapters))
	for i, adapter := range adapters {
		if adapter == nil {
			return Catalog{}, fmt.Errorf("adapter %d is missing", i+1)
		}
		name := adapter.Name()
		if name == "" {
			return Catalog{}, fmt.Errorf("adapter %d has no name", i+1)
		}
		if named[name] {
			// Two adapters under one name would make reports unreadable.
			return Catalog{}, fmt.Errorf("two adapters are named %q", name)
		}
		named[name] = true
	}
	return Catalog{adapters: adapters}, nil
}

// Adapters is what this catalog holds, in the order it asks them.
func (c Catalog) Adapters() []Inspector { return c.adapters }

// Report is what the catalog concluded about one process, with every adapter's
// answer behind it.
type Report struct {
	Process   fragment.Process `json:"process"`
	Supported bool             `json:"supported"`

	// Adapter is the adapter that will observe this process, and is empty when
	// none will.
	Adapter string `json:"adapter,omitempty"`

	// Support holds every adapter's answer, including the ones that said no.
	Support []Support `json:"support"`
}

// ErrUnsupported is what an unsupported process is refused with, wherever a
// caller needs an error rather than a report.
var ErrUnsupported = errors.New("no adapter supports this process")

// Inspect asks every adapter about the process and takes the first that says
// yes. Every answer is kept, whichever way it went.
func (c Catalog) Inspect(p process.Process) Report {
	report := Report{Process: p.Identity(), Support: make([]Support, 0, len(c.adapters))}
	for _, adapter := range c.adapters {
		support := adapter.Inspect(p)
		support.Adapter = adapter.Name()
		report.Support = append(report.Support, support)

		if support.Supported && !report.Supported {
			report.Supported = true
			report.Adapter = adapter.Name()
		}
	}
	return report
}

// Reason is one line saying what the report concluded and why, for an operator
// looking at a process that is not observed.
func (r Report) Reason() string {
	if r.Supported {
		for _, support := range r.Support {
			if support.Adapter == r.Adapter {
				return r.Adapter + ": " + support.Reason
			}
		}
	}
	if len(r.Support) == 0 {
		return "unsupported: the catalog holds no adapter"
	}

	reasons := make([]string, 0, len(r.Support))
	for _, support := range r.Support {
		reasons = append(reasons, support.Adapter+": "+support.Reason)
	}
	return "unsupported: " + strings.Join(reasons, "; ")
}

// Ends is a socket's own endpoints as the kernel had them at the hook that
// acquired it, in the program's raw shape. Addresses are 16 bytes (v4 as
// v4-mapped); ports are in host order.
//
// Netns is the socket's own network namespace, not the process's; they can
// differ for an inherited or passed socket. Known says the addresses were
// read: unreadable addresses are never reported as zeros.
type Ends struct {
	Local [16]byte
	Peer  [16]byte
	Netns uint64

	// OpenedAt is when the observer saw this socket created, crossed from the
	// program's monotonic clock to wall time. Zero is a socket that predates the
	// probes.
	OpenedAt  time.Time
	LocalPort uint16
	PeerPort  uint16
	Known     bool

	// Attempted says an endpoint producer ran for this transfer, separating a
	// failed read from a build with no producer.
	Attempted bool
}

// Netns is a network namespace, as its nsfs device and inode (not a pid
// namespace).
type Netns struct {
	Device uint64
	Inode  uint64
}

// FileID names one file by the device and inode holding it, which is what a
// probe placed on a library is placed on.
type FileID struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

// Reading is what one process's own files said when read with privileges a
// running session has dropped (maps, root and namespace links are ptrace
// checked), so the reload command reads them for the session.
type Reading struct {
	Report  Report       `json:"report"`
	Library FileID       `json:"library"`
	Libc    FileID       `json:"libc"`
	Network Netns        `json:"network"`
	Exec    process.Exec `json:"exec"`
}

// Known reports whether this names a namespace. The zero value, from an unread
// /proc/<pid>/ns/net, is never the observer's own.
func (n Netns) Known() bool { return n.Device != 0 || n.Inode != 0 }

// Bound is what an adapter established about which socket a transfer crossed:
// the answer, with the descriptor as evidence. Descriptor zero is real.
type Bound uint8

const (
	// NotBound is no valid binding; Descriptor means nothing.
	NotBound Bound = 0
	// BoundTo is one descriptor, seen inside this call or inherited from the
	// handle's still-valid binding.
	BoundTo Bound = 1
	// BoundAmbiguously is a call window with socket work on several descriptors:
	// something was seen, not which.
	BoundAmbiguously Bound = 2
	// BoundInvalidated is a binding that was established and stopped being true.
	BoundInvalidated Bound = 3
)

// SocketOutcome is what happened to a call's own kernel I/O. An ordinary-file
// write is determinate, an unresolved operation an absence, and only a call
// with no I/O may carry an earlier binding. Ordered worst-last; a call reports
// the worst of its operations.
type SocketOutcome uint8

const (
	// NoKernelIO is a call with no kernel I/O of its own (served from or buffered
	// in the library): the only outcome that may carry an earlier binding.
	NoKernelIO SocketOutcome = iota
	// SocketIO is socket I/O, established from the object the kernel acquired.
	SocketIO
	// FileIO is I/O the kernel classified as an ordinary file: determinate.
	FileIO
	// OperationUnresolved is a supported syscall that reached no evidence.
	OperationUnresolved
	// RouteUnsupported is I/O through a route this build does not follow (an
	// unclaimed socket family, sendfile, splice, async submission): a stated
	// coverage limit.
	RouteUnsupported
	// EvidenceUnreadable is an acquired object this run could not read.
	EvidenceUnreadable
	// FrameBroken is an operation frame overwritten or completed with no entry.
	FrameBroken
)

func (o SocketOutcome) String() string {
	switch o {
	case SocketIO:
		return "the call's I/O was on a socket"
	case FileIO:
		return "the call's I/O was an ordinary file"
	case OperationUnresolved:
		return "the call's I/O reached no socket evidence"
	case RouteUnsupported:
		return "the call's I/O took a route this build does not follow"
	case EvidenceUnreadable:
		return "the socket the call's I/O acquired could not be read"
	case FrameBroken:
		return "the operation frame this call's evidence would have hung on was broken"
	default:
		return "the call made no kernel I/O of its own"
	}
}

// CarriesBinding reports whether an outcome may carry an earlier binding
// forward: only NoKernelIO, so no I/O with an unknown socket inherits a cached
// success.
func (o SocketOutcome) CarriesBinding() bool { return o == NoKernelIO }

func (b Bound) String() string {
	switch b {
	case BoundTo:
		return "bound"
	case BoundAmbiguously:
		return "ambiguously bound"
	case BoundInvalidated:
		return "invalidated"
	default:
		return "not bound"
	}
}

// Losses is what a capture discarded before reconstruction: events that
// crossed a watched point and were not delivered. A lost event advances no
// offset, so without this a holed stream parses like a whole one.
type Losses struct {
	// Dropped is events refused by the full ring buffer: absent with no gap to
	// mark them.
	Dropped int64 `json:"dropped"`

	// Unmatched is returns whose entry was never recorded, so the length is
	// unknown. It may include calls in flight when probes were placed, which
	// fire inconsistently, so zero does not prove a run began outside a call.
	Unmatched int64 `json:"unmatched"`

	// Descendants is processes admitted because an approved process forked them:
	// not a loss, but evidence the admission mechanism worked.
	Descendants int64 `json:"descendants"`

	// When is the occasion of the unmatched returns, zero where none: without it
	// the count cannot be correlated with anything.
	When Occasion `json:"when"`
}

// Occasion is when a counted thing was seen: on the monotonic clock, in
// nanoseconds since this boot (not across suspend, not comparable across
// boots), at the host clocksource's resolution. The first and last occasions
// bound the interval; Handle, PID and TID are the first one's.
type Occasion struct {
	// First and Last are nanoseconds since this boot. First zero means nothing was
	// seen.
	First int64 `json:"first"`
	Last  int64 `json:"last"`

	// Handle, PID and TID name the first occasion only.
	Handle uint64 `json:"handle"`
	PID    int32  `json:"pid"`
	TID    int32  `json:"tid"`
}

// Seen reports whether there was an occasion at all.
func (o Occasion) Seen() bool { return o.First != 0 }

// Withdrawal is one process with a recorded grant it no longer holds: what
// became of it and the evidence. The execution ended (the hook worked), the
// grant ended while the process runs (a coverage limit, silent in the
// capture), or neither was established.
type Withdrawal struct {
	// PID is the observer's number for it; zero where none was recorded.
	PID int32 `json:"pid"`

	// Instance names the process: pid namespace, number inside it, admission.
	Instance string `json:"instance"`

	// State and Evidence are what became of it and what that rests on.
	State    string `json:"state"`
	Evidence string `json:"evidence"`

	// Limit marks the coverage limit: still running, no longer observed.
	Limit bool `json:"limit"`
}

// Accounting is an attachment that can say which recorded processes no longer
// hold a grant. A backend that cannot is honest by not implementing it; a
// caller then reports that it cannot say, never "nothing withdrawn".
type Accounting interface {
	Attachment

	// Withdrawals is every recorded process whose grant is gone, or why that
	// could not be answered (never an empty list).
	Withdrawals() ([]Withdrawal, error)
}

// GrantState is what the kernel's allowlist says about one recorded admission.
type GrantState string

const (
	GrantHeld    GrantState = "held"
	GrantAbsent  GrantState = "absent"
	GrantUnknown GrantState = "unknown"
)

// Grant is one recorded admission and the state of its grant.
type Grant struct {
	Selection admission.Selection
	State     GrantState
	Read      time.Time
	Evidence  process.Interval
	Why       string
}

// Granting is an attachment that can say, for every admission it recorded,
// whether the kernel still holds its grant.
type Granting interface {
	Attachment
	Grants() ([]Grant, error)
}

// Added is what an attachment admitted after it attached, and what it did not
// take because the session had already recorded that instance.
type Added struct {
	Selections []admission.Selection
	Skipped    []Skip
}

// Skip is one instance an attachment did not admit, and why.
type Skip struct {
	Selection admission.Selection
	Why       string
}

// Admitting is an attachment that can add grants after attaching: a reload,
// for processes needing no new probe. Without it a reload says a restart
// applies the candidate.
type Admitting interface {
	Attachment
	Admit(request Request) (Added, error)

	// Retract takes back grants Admit wrote, for a program found not to be the
	// one resolved.
	Retract(granted []admission.Selection)
}

// Consumed is how many production-order places an attachment took and
// delivered nothing for. ReserveFailed is an event produced and lost; Refused
// is a transfer refused deliberately so its gap invalidates. Watching only the
// first would suppress an intended invalidation.
type Consumed struct {
	ReserveFailed int64
	Refused       int64
}

// Consuming is an attachment that can say what it took out of the production
// order; which refusal paths take a number is the backend's knowledge alone.
// Without it the consumer confirms every gap.
type Consuming interface {
	Attachment

	Consumed() (Consumed, error)
}

// Counting is an attachment that can say what its capture lost. One that
// cannot is honest by not implementing it; a caller then says it cannot say,
// never "nothing lost".
type Counting interface {
	Attachment

	// Losses is what this attachment discarded, or why the numbers are
	// unreadable (an error, never zero).
	Losses() (Losses, error)
}

// Refusing is an attachment that can say what its capture refused, by reason,
// for absences with several possible causes (a transfer with no binding may
// be an unseen socket call, a descriptor with no lifetime, or socket work on
// another thread).
type Refusing interface {
	Attachment

	// Refusals is how many times each reason fired, by the reason's own words. A
	// zero entry was looked for and did not happen; an unreadable counter is an
	// error. A success counted beside the refusals is their control.
	Refusals() (map[string]int64, error)
}
