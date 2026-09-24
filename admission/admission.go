// Package admission defines what the observer publishes about a process it
// admitted:
//
//	instance   a pid namespace, a pid inside it, a start identity, an admission
//	           generation and the executable that was running
//	selection  which target admitted the instance, through which rule, from
//	           which parent, and what the descendant mode answers
//
// The instance is the attribution unit (which process produced a fragment);
// the selection is the authorisation unit (why it may be observed). They are
// reported separately so a right family with a wrong member cannot hide.
//
// Four counters here are not one clock: BootTicks (/proc/<pid>/stat field 22),
// Generation (stamped at admission), a record's event time, and process
// accounting's epoch seconds (not read).
//
// An unread start identity is indeterminate, never zero: zero would claim the
// process started at boot.
package admission

import (
	"errors"
	"fmt"
	"strings"
)

// Namespace is a pid namespace, named by the device and inode of the nsfs entry
// behind /proc/<pid>/ns/pid. A pid means something only inside one namespace.
type Namespace struct {
	Device uint64
	Inode  uint64
}

// Known reports whether this names a namespace. The zero value, from an unread
// /proc/<pid>/ns/pid, does not.
func (n Namespace) Known() bool { return n.Device != 0 || n.Inode != 0 }

func (n Namespace) String() string {
	if !n.Known() {
		return "a pid namespace nothing here names"
	}
	return fmt.Sprintf("pid namespace %d:%d", n.Device, n.Inode)
}

// BootTicks is clock ticks since boot, the unit of /proc/<pid>/stat start
// times.
type BootTicks uint64

// Start is a process's start identity, which separates successive occupants
// of a pid within a boot. Determined says whether it was read; an unread one
// is none, not zero.
type Start struct {
	Ticks      BootTicks
	Determined bool
}

// Determinate is a start identity that was read.
func Determinate(ticks BootTicks) Start { return Start{Ticks: ticks, Determined: true} }

// Indeterminate is an unread start identity. It is the zero value, so an
// unfilled field reads as unknown.
func Indeterminate() Start { return Start{} }

func (s Start) String() string {
	if !s.Determined {
		return "a start identity that could not be read"
	}
	return fmt.Sprintf("started at tick %d", s.Ticks)
}

// Generation is the admission generation: a counter, not a time, stamped when
// an instance enters the allowlist and fresh on every readmission, so an
// instance is separated from the next occupant of its pid when admitted.
//
// Userspace counts up from one; the kernel counts up from KernelGenerations.
// The disjoint ranges stop a stale saved call meeting a live grant with the
// same number.
type Generation uint64

// KernelGenerations is where the kernel's allocator starts. Userspace writes
// it into the counter at attach and never again.
const KernelGenerations Generation = 1 << 63

// FromKernel reports which allocator stamped this generation.
func (g Generation) FromKernel() bool { return g >= KernelGenerations }

func (g Generation) String() string {
	if g == 0 {
		return "no admission generation"
	}
	if g.FromKernel() {
		return fmt.Sprintf("kernel admission generation %d", uint64(g-KernelGenerations)+1)
	}
	return fmt.Sprintf("admission generation %d", uint64(g))
}

// Instance is one runtime process instance: what a captured fragment is
// attributed to. PID is the number inside Namespace, the process's own
// numbering; Selection carries the observer's.
type Instance struct {
	Namespace  Namespace
	PID        int32
	Start      Start
	Generation Generation

	// Executable is where /proc/<pid>/exe pointed (the interpreter, for a
	// script), or empty where unreadable.
	Executable string
}

// Key is an instance's identity: namespace, pid and generation. Start and
// executable are evidence, and may be indeterminate for a well-identified
// instance.
type Key struct {
	Namespace  Namespace
	PID        int32
	Generation Generation
}

// Key is this instance's identity.
func (i Instance) Key() Key {
	return Key{Namespace: i.Namespace, PID: i.PID, Generation: i.Generation}
}

// Same reports whether two records name one instance, by identity rather than
// evidence.
func (i Instance) Same(other Instance) bool { return i.Key() == other.Key() }

// ErrInvalid is what every Validate failure here wraps.
var ErrInvalid = errors.New("invalid admission record")

// Validate reports what would make this instance unusable as an identity.
func (i Instance) Validate() error {
	switch {
	case !i.Namespace.Known():
		return fmt.Errorf("%w: pid %d names no pid namespace, so the number belongs to nothing",
			ErrInvalid, i.PID)
	case i.PID <= 0:
		return fmt.Errorf("%w: %d names no process in %s", ErrInvalid, i.PID, i.Namespace)
	case i.Generation == 0:
		return fmt.Errorf("%w: pid %d in %s carries no admission generation, so nothing separates "+
			"it from the next process to hold that number", ErrInvalid, i.PID, i.Namespace)
	}
	return nil
}

func (i Instance) String() string {
	at := i.Executable
	if at == "" {
		at = "an executable that could not be read"
	}
	return fmt.Sprintf("pid %d in %s, %s, %s, running %s",
		i.PID, i.Namespace, i.Start, i.Generation, at)
}

// Kind is how an instance came to be admitted. Whether it may admit what it
// forks is separate: a Mode (permission) and a Propagation (ability).
type Kind uint8

const (
	// KindUnknown is the zero value and names no admission.
	KindUnknown Kind = iota
	// ByTarget is an instance a configured target named.
	ByTarget
	// ByDescent is an instance an admitted process created.
	ByDescent
)

func (k Kind) String() string {
	switch k {
	case ByTarget:
		return "named by a target"
	case ByDescent:
		return "created by an admitted process"
	default:
		return "admitted by nothing this names"
	}
}

// Mode is the descendant permission a target carries. It is required: there
// is no default.
type Mode uint8

const (
	// ModeUnset is the zero value, not a mode; an entry carrying it is refused.
	ModeUnset Mode = iota
	// ModeNone admits the matched instances only.
	ModeNone
	// ModeExisting admits those, plus descendants running when the policy was
	// resolved.
	ModeExisting
	// ModeFollow admits those, plus descendants created afterwards.
	ModeFollow
)

func (m Mode) String() string {
	switch m {
	case ModeNone:
		return "none"
	case ModeExisting:
		return "existing"
	case ModeFollow:
		return "follow"
	default:
		return "unset"
	}
}

// ParseMode reads the mode word of a policy entry. A missing mode is refused.
func ParseMode(text string) (Mode, error) {
	switch strings.TrimSpace(text) {
	case "none":
		return ModeNone, nil
	case "existing":
		return ModeExisting, nil
	case "follow":
		return ModeFollow, nil
	case "":
		return ModeUnset, fmt.Errorf("%w: an entry names its descendant mode, and this one names none: "+
			"one of none, existing or follow", ErrInvalid)
	default:
		return ModeUnset, fmt.Errorf("%w: %q is not a descendant mode: one of none, existing or follow",
			ErrInvalid, text)
	}
}

// Boundary is which scope change ends a grant.
type Boundary uint8

const (
	// BoundaryUnset is the zero value and answers nothing.
	BoundaryUnset Boundary = iota

	// ExecEndsTheGrant, in every mode: only an admitted execution's own successful
	// exec ends its grant. Reparenting and cgroup moves do not (the cgroup
	// selector is a snapshot), and an unenumerated pid namespace is never entered.
	ExecEndsTheGrant
)

func (b Boundary) String() string {
	switch b {
	case ExecEndsTheGrant:
		return "a successful exec ends the grant; reparenting and a cgroup move do not, " +
			"and an unenumerated pid namespace is never entered"
	default:
		return "no boundary answer"
	}
}

// RootExit is what happens to the family when the selected root goes.
type RootExit uint8

const (
	// RootExitUnset is the zero value and answers nothing.
	RootExitUnset RootExit = iota

	// SurvivorsKeepTheirGrants, in every mode: the root's exit ends only the
	// root's grant. A surviving execution keeps its own, and under follow keeps
	// admitting what it forks; otherwise follow would become narrower than
	// existing when the root exits.
	SurvivorsKeepTheirGrants
)

func (r RootExit) String() string {
	switch r {
	case SurvivorsKeepTheirGrants:
		return "the root's own grant ends and nothing else's"
	default:
		return "no root-exit answer"
	}
}

// Replacement is whether a restarted root needs fresh approval.
type Replacement uint8

const (
	// ReplacementUnset is the zero value and answers nothing.
	ReplacementUnset Replacement = iota

	// ReplacementNeedsRestart, in every mode: a new root is covered after a
	// restart re-resolves the policy; reload never selects one. A replacement
	// started by an unselected supervisor can open and close a connection before
	// that, and nothing recovers it.
	ReplacementNeedsRestart
)

func (r Replacement) String() string {
	switch r {
	case ReplacementNeedsRestart:
		return "a replacement root is covered only after a restart re-resolves the policy"
	default:
		return "no replacement answer"
	}
}

// Answers is the five behaviours a descendant policy owes: existing and future
// descendants, which scope change ends a grant, what the root's exit does, and
// whether a replacement root needs approval.
type Answers struct {
	Existing    bool
	Future      bool
	Boundary    Boundary
	RootExit    RootExit
	Replacement Replacement
}

// Answers is what this mode answers. Three answers are the same for every
// mode, so a broader mode never becomes narrower when a root exits.
func (m Mode) Answers() Answers {
	answers := Answers{
		Boundary:    ExecEndsTheGrant,
		RootExit:    SurvivorsKeepTheirGrants,
		Replacement: ReplacementNeedsRestart,
	}
	switch m {
	case ModeExisting:
		answers.Existing = true
	case ModeFollow:
		answers.Existing, answers.Future = true, true
	}
	return answers
}

// Propagation is whether this instance's forks can be named here: an ability,
// not a permission. It depends on whether the instance's pid namespace was
// enumerated, a fact about the host rather than the configuration.
type Propagation uint8

const (
	// PropagationUnknown is the zero value: nothing established either way.
	PropagationUnknown Propagation = iota
	// CanPropagate: the kernel side can resolve this instance's numbering, so a
	// child can be named when it is created.
	CanPropagate
	// CannotPropagate: it cannot, so nothing this instance forks is admitted.
	CannotPropagate
)

func (p Propagation) String() string {
	switch p {
	case CanPropagate:
		return "its own fork can be named here"
	case CannotPropagate:
		return "nothing it forks can be named here"
	default:
		return "whether its fork can be named here was not established"
	}
}

// Provenance is why an instance is admitted: target, rule and inherited
// parent. It travels with the grant, so a process two targets matched can lose
// one reason without losing the other.
type Provenance struct {
	// Target is the entry's configured name; Number its position from one.
	Target string
	Number int

	// Rule is which condition matched, counting from one; zero where the target
	// has one condition.
	Rule int

	// Parent is the instance the grant was inherited from; zero for one a target
	// named directly.
	Parent Key
}

// Inherited reports whether the grant came from a parent.
func (p Provenance) Inherited() bool { return p.Parent != Key{} }

func (p Provenance) String() string {
	name := p.Target
	if name == "" {
		name = fmt.Sprintf("target %d", p.Number)
	}
	if p.Inherited() {
		return fmt.Sprintf("%s, inherited from pid %d in %s", name, p.Parent.PID, p.Parent.Namespace)
	}
	return name
}

// Denial is one instance an exclusion denies, with its subtree. It carries no
// mode: an exclusion always denies the subtree, and a direct include never
// overrides it.
//
// A denial survives an exec and a reparenting (same execution, same subtree)
// but not a reused pid, which is a different process.
type Denial struct {
	Instance Instance

	// Provenance names the exclusion and, for a denial inherited from an
	// ancestor, the instance it came from.
	Provenance Provenance

	// ObserverPID is the observer's own number for it, or zero where unknown.
	ObserverPID int32
}

// Validate reports what would make this denial unusable.
func (d Denial) Validate() error {
	if err := d.Instance.Validate(); err != nil {
		return err
	}
	if d.Provenance.Number <= 0 && !d.Provenance.Inherited() {
		return fmt.Errorf("%w: pid %d is denied by nothing this names", ErrInvalid, d.Instance.PID)
	}
	return nil
}

func (d Denial) String() string {
	return fmt.Sprintf("%s: denied by %s", d.Instance, d.Provenance)
}

// Selection is one grant: an instance, how it was admitted, from where, and
// what the mode answers. The kernel side holds all of it but the two fields
// userspace fills in.
type Selection struct {
	Instance Instance
	Kind     Kind

	// Provenance is the target the grant is filed under; AlsoNamedBy is every
	// other target that named the same instance. The allowlist holds one grant per
	// instance, so removing one target removes a reason, not the grant.
	Provenance  Provenance
	AlsoNamedBy []Provenance

	Mode Mode

	// Propagation is the ability, beside the Mode's permission.
	Propagation Propagation

	// ObserverPID is the observer's own number for this instance, for reading
	// /proc. Zero where unknown, which is not pid zero.
	ObserverPID int32
}

// Answers is what this selection's mode answers to the five behaviours.
func (s Selection) Answers() Answers { return s.Mode.Answers() }

// Validate reports what would make this selection unusable.
func (s Selection) Validate() error {
	if err := s.Instance.Validate(); err != nil {
		return err
	}
	switch {
	case s.Kind != ByTarget && s.Kind != ByDescent:
		return fmt.Errorf("%w: %s names no admission for pid %d", ErrInvalid, s.Kind, s.Instance.PID)
	case s.Mode == ModeUnset:
		return fmt.Errorf("%w: pid %d carries no descendant mode, and there is no default",
			ErrInvalid, s.Instance.PID)
	case s.Kind == ByDescent && !s.Provenance.Inherited():
		return fmt.Errorf("%w: pid %d was admitted by descent and names no parent",
			ErrInvalid, s.Instance.PID)
	case s.Kind == ByTarget && s.Provenance.Number <= 0:
		return fmt.Errorf("%w: pid %d was admitted by a target and names no target",
			ErrInvalid, s.Instance.PID)
	}
	return nil
}

// NamedBy is every target that named this instance, the filing one first.
func (s Selection) NamedBy() []Provenance {
	return append([]Provenance{s.Provenance}, s.AlsoNamedBy...)
}

func (s Selection) String() string {
	named := s.Provenance.String()
	for _, also := range s.AlsoNamedBy {
		named += " and " + also.String()
	}
	return fmt.Sprintf("%s: %s, %s, descendants %s, %s",
		s.Instance, s.Kind, named, s.Mode, s.Propagation)
}
