// Package record is the Go form of the observer's published record contracts -
// the OBSERVATION, the CONNECTION, and the MESSAGE and EXCHANGE carried in a
// RECONSTRUCTION with the REASSEMBLY that reports what it refused - at the draft
// version named by Version. The contract itself is record.md beside this file;
// these types encode it, and where the two disagree the document is the one to
// correct first.
//
// Every value that can be absent says whether it is present, every instant says
// which clock it was read from and how, and every 64-bit identity or instant is
// carried as a decimal string so that a reader whose numbers are doubles cannot
// round it silently.
package record

// Version names the draft contract these types encode. No machine-readable
// schema is published; the tool's Go validators enforce the contract.
const Version = "observer.record/1-draft"

// The record kinds, carried on every record so a line read alone says what it
// is.
const (
	KindObservation    = "observation"
	KindConnection     = "connection"
	KindReconstruction = "reconstruction"
	KindReassembly     = "reassembly"
)

// State says whether a value was established. It is on every field whose source
// uses a zero or a flag to mean "could not find out".
type State string

const (
	// Determined is a value that was read or computed, and Value holds it.
	Determined State = "determined"
	// Undetermined is a value this run could not establish. It is not zero and
	// Value is empty.
	Undetermined State = "undetermined"
	// NotCarried is a field the contract names and this version's producer does
	// not supply at all - a field reserved for evidence that exists in the
	// kernel and does not reach the record yet. It is never a reading of any
	// particular event.
	NotCarried State = "not_carried"
)

// Domain is which clock an instant or a birth is counted on. The three are not
// comparable with each other: boottime advances across a suspend and monotonic
// does not, and wall time can be stepped.
type Domain string

const (
	Wall      Domain = "wall"
	Monotonic Domain = "monotonic"
	Boottime  Domain = "boottime"
)

// Unit is what one step of a value is worth.
type Unit string

const (
	Nanoseconds Unit = "nanoseconds"
	// ClockTicks is the unit /proc/<pid>/stat field 22 reports in. Its length
	// is the host's clock tick, which no record carries, so a birth is compared
	// only with another birth read the same way and is never converted.
	ClockTicks Unit = "clock_ticks"
	Bytes      Unit = "bytes"
	Events     Unit = "events"
	Fragments  Unit = "fragments"
	// Calls is calls into an observed library, each counted once whether or
	// not its bytes reached a record.
	Calls Unit = "calls"
	// Instances is admitted executions or processes.
	Instances Unit = "instances"
	// Places is places in a session's production order: each is an event
	// produced or a call refused at the read boundary.
	Places Unit = "places"
	// DescriptorLifetimes is occupancies of a descriptor by a socket.
	DescriptorLifetimes Unit = "descriptor_lifetimes"
	// Bindings is bindings of a library handle to a descriptor occupancy.
	Bindings Unit = "bindings"
)

// Reading is how a determined instant was obtained.
type Reading string

const (
	// ObserverWallRead is the observer reading its own wall clock in userspace:
	// at decode for a transfer, at detection for an ending or a gap. It is after
	// the moment it dates by a lag nothing measures.
	ObserverWallRead Reading = "observer_wall_read"
	// CrossedFromMonotonic is a kernel CLOCK_MONOTONIC stamp moved onto the
	// wall clock by one pairing of the two clocks taken per session. It is not
	// interchangeable with a direct wall reading at millisecond granularity.
	CrossedFromMonotonic Reading = "crossed_from_monotonic"
	// KernelStamp is a kernel clock read at the event itself, on its own
	// domain, not crossed to any other.
	KernelStamp Reading = "kernel_stamp"
)

// Instant is one point in time with its clock, its unit and how it was read.
type Instant struct {
	State   State   `json:"state"`
	Domain  Domain  `json:"domain"`
	Unit    Unit    `json:"unit"`
	Reading Reading `json:"reading,omitempty"`
	// Value is a decimal count of Unit since the domain's origin: the Unix
	// epoch for wall, this boot for monotonic and boottime.
	Value string `json:"value,omitempty"`
}

// Birth is a process start IDENTITY, not a timestamp. It separates one
// occupant of a pid from the next and is compared only against another birth
// read the same way.
type Birth struct {
	State  State  `json:"state"`
	Domain Domain `json:"domain"`
	Unit   Unit   `json:"unit"`
	Value  string `json:"value,omitempty"`
}

// Count is a quantity that may not be knowable.
type Count struct {
	State State  `json:"state"`
	Unit  Unit   `json:"unit"`
	Value string `json:"value,omitempty"`
	Why   string `json:"why,omitempty"`
}

// Namespace is a kernel namespace named by its nsfs device and inode, with
// what established it.
type Namespace struct {
	State         State  `json:"state"`
	Device        string `json:"device,omitempty"`
	Inode         string `json:"inode,omitempty"`
	EstablishedBy string `json:"established_by,omitempty"`
}

// What established a namespace. They are different evidence about different
// objects and a reader must not substitute one for the other.
const (
	// ByAdmissionEvent is the pid namespace the kernel reported on the event
	// that admitted the instance.
	ByAdmissionEvent = "admission_event"
	// ByProcessRead is the network namespace read from /proc/<pid>/ns/net of
	// the holding process while probes were placed. It is the process's, not
	// any socket's.
	ByProcessRead = "process_proc_read"
	// ByResolutionRead is the pid namespace read from /proc/<pid>/ns/pid of a
	// process when the observer resolved its policy. It is the process's, as it
	// was at that read.
	ByResolutionRead = "resolution_proc_read"
	// BySocketEvidence is the network namespace of the socket itself, taken
	// from kernel socket evidence on the call.
	BySocketEvidence = "socket_evidence"
)

// InstanceKey is the identity of one admitted execution.
type InstanceKey struct {
	PidNamespace Namespace `json:"pid_namespace"`
	PID          int32     `json:"pid"`
	Generation   string    `json:"generation"`
	// Allocator is which counter stamped Generation: "target" for an instance
	// a selection named, "descent" for one the kernel admitted as a child. It
	// is read off the generation's range and carries no other evidence.
	Allocator string `json:"allocator"`
}

// Instance is an admitted execution with the evidence read about it.
type Instance struct {
	Key        InstanceKey `json:"key"`
	Birth      Birth       `json:"birth"`
	Executable Text        `json:"executable"`
}

// Text is a string that may not have been read.
type Text struct {
	State State  `json:"state"`
	Value string `json:"value,omitempty"`
}

// Process is the observed process in the OBSERVER's own pid numbering, which is
// what a fragment is attributed by and what joins an observation to its
// connection.
type Process struct {
	PID   int32 `json:"pid"`
	Birth Birth `json:"birth"`
}

// Observation is one plaintext fragment as one library call transferred it.
type Observation struct {
	Record     string  `json:"record"`
	Version    string  `json:"version"`
	Process    Process `json:"process"`
	Connection string  `json:"connection"`
	Direction  string  `json:"direction"`
	Sequence   string  `json:"sequence"`
	Offset     string  `json:"offset"`
	// Length is what the call transferred; Payload.Kept is what capture kept.
	Length  uint32  `json:"length"`
	Payload Payload `json:"payload"`
	// Seen is when the observer read the event, not when it happened.
	Seen Instant `json:"seen"`
	// Produced is when the kernel produced the event. Reserved: not carried by
	// this version's producer.
	Produced Instant `json:"produced"`
}

// Payload is the bytes capture kept.
type Payload struct {
	Encoding  string `json:"encoding"`
	Data      string `json:"data"`
	Kept      uint32 `json:"kept"`
	Truncated bool   `json:"truncated"`
}

// Connection is one occupancy of a TLS library handle by one admitted
// execution.
type Connection struct {
	Record  string `json:"record"`
	Version string `json:"version"`
	ID      string `json:"id"`

	Handle   Handle   `json:"handle"`
	Instance Instance `json:"instance"`
	Process  Process  `json:"process"`

	// ProcessNetwork is the holding process's network namespace, never the
	// socket's.
	ProcessNetwork Namespace `json:"process_network"`

	FirstSeen Instant `json:"first_seen"`
	Opened    Instant `json:"opened"`
	Ending    Ending  `json:"ending"`

	Associations []Association `json:"associations"`
	Placements   []Placement   `json:"placements"`

	Fragments       Count   `json:"fragments"`
	Early           []Range `json:"early"`
	EarlyUnmeasured Count   `json:"early_unmeasured"`
}

// Handle is the connection's identity.
type Handle struct {
	Instance   InstanceKey `json:"instance"`
	Address    string      `json:"address"`
	Generation string      `json:"generation"`
}

// Ending is how a connection stopped and when.
//
// At is when the ending itself was observed. An unobserved ending has no such
// instant: At is undetermined and Detected carries when the observer detected
// the loss that retired the record, which is not when the connection ended and
// is named so it cannot be read as that.
type Ending struct {
	How      string   `json:"how"`
	At       Instant  `json:"at"`
	Detected *Instant `json:"detected,omitempty"`
}

// Association is one direction's binding to a socket.
type Association struct {
	Direction string     `json:"direction"`
	State     string     `json:"state"`
	Reason    string     `json:"reason,omitempty"`
	Basis     string     `json:"basis,omitempty"`
	Source    string     `json:"source,omitempty"`
	Binding   Generation `json:"binding"`
	Valid     Interval   `json:"valid"`

	Descriptor Descriptor   `json:"descriptor"`
	Contended  []Descriptor `json:"contended"`
	Socket     Socket       `json:"socket"`
	Endpoints  Endpoints    `json:"endpoints"`

	Join       string `json:"join"`
	JoinReason string `json:"join_reason,omitempty"`

	// Wire is ciphertext bytes the kernel accepted, not the fragment's length.
	Wire Count `json:"wire"`
}

// Generation separates one occupancy of a reused name from the next.
type Generation struct {
	State State  `json:"state"`
	Value string `json:"value,omitempty"`
}

// Interval is [From, Until) and Open as the observer wrote them. What Open
// establishes is not established: every association in the captured runs
// carries it, including those of records that ended (record.md).
type Interval struct {
	From  Instant `json:"from"`
	Until Instant `json:"until"`
	Open  bool    `json:"open"`
}

// Descriptor is a file descriptor number that may not have been established.
type Descriptor struct {
	State  State  `json:"state"`
	Number *int32 `json:"number,omitempty"`
}

// Socket is the kernel's own inode for the socket, and the key that groups
// every connection record holding it.
type Socket struct {
	State State  `json:"state"`
	Inode string `json:"inode,omitempty"`
}

// Endpoints is both ends and the network namespace the addresses are in.
type Endpoints struct {
	Local     Address   `json:"local"`
	Remote    Address   `json:"remote"`
	Namespace Namespace `json:"namespace"`
}

// Address is an IP and port that may not have been established.
type Address struct {
	State   State   `json:"state"`
	Address string  `json:"address,omitempty"`
	Port    *uint16 `json:"port,omitempty"`
}

// Placement is where one direction's bytes stop being placeable.
type Placement struct {
	Direction string `json:"direction"`
	Positions string `json:"positions"`
	// From is meaningful only for unknown_from.
	From    string `json:"from,omitempty"`
	Because string `json:"because,omitempty"`
	Lost    Count  `json:"lost"`
}

// Range is a run of stream offsets.
type Range struct {
	Direction string `json:"direction"`
	Offset    string `json:"offset"`
	Length    uint32 `json:"length"`
}
