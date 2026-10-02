// Package account is what the observer says about a session: the policy it
// resolved, what that selected, what was attached, what came through, what was
// lost, whose coverage ended and how the session ended.
//
// One type serves three moments: a dry run (Planned), a running session
// (Live) and an ended one (Sealed).
//
// It carries no process's arguments, because command lines hold secrets and
// the account may leave the host. Render's local view is the one place a
// target's conditions appear, and it says so.
package account

import (
	"fmt"
	"github.com/evandukss/edge-observer/sink"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/spool"
)

// Version is the account's shape. A reader refuses a version it does not know.
const Version = 1

// Kind is which of the three moments an account describes.
type Kind string

const (
	// Planned is a policy resolved and not attached: what would be observed.
	Planned Kind = "planned"
	// Live is a running session as it stands at the moment it was asked.
	Live Kind = "live"
	// Sealed is a session that has ended, written once beside its spool.
	Sealed Kind = "sealed"
)

// Policy is the configuration's content revision and the generation a session
// activated. Generation zero is a dry run.
type Policy struct {
	Revision   string `json:"revision"`
	Generation int    `json:"generation"`
}

// Floor is the oldest kernel the artifact publishes, and whether that is
// proved. It describes the artifact, not the run.
type Floor struct {
	Published      string `json:"published"`
	Proved         bool   `json:"proved"`
	Established    string `json:"established"`
	WouldEstablish string `json:"would_establish"`
}

// Instance is one process as an account names it. Never its arguments.
type Instance struct {
	PID          int32   `json:"pid"`
	Namespace    string  `json:"namespace"`
	NamespacePID int32   `json:"namespace_pid"`
	Start        *uint64 `json:"start"`
	Executable   string  `json:"executable"`
}

// Answers is what a target's mode answers to the five descendant behaviours.
type Answers struct {
	Existing    bool   `json:"existing"`
	Future      bool   `json:"future"`
	Boundary    string `json:"boundary"`
	RootExit    string `json:"root_exit"`
	Replacement string `json:"replacement"`
}

// Listener is one listening socket a port target resolved to, and its holders.
type Listener struct {
	Address string  `json:"address"`
	Owners  []int32 `json:"owners"`
}

// Cgroup is the object a cgroup target's path named when it was resolved.
type Cgroup struct {
	Path  string `json:"path"`
	Inode uint64 `json:"inode,omitempty"`
	Why   string `json:"why,omitempty"`
}

// Unsupported is a selected process no adapter can observe: eligible and
// uncovered, which is not absent.
type Unsupported struct {
	Instance Instance `json:"instance"`
	Reason   string   `json:"reason"`
}

// Target is one target of the policy and what it resolved to.
type Target struct {
	Number      int           `json:"number"`
	Name        string        `json:"name"`
	Mode        string        `json:"mode"`
	Answers     Answers       `json:"answers"`
	Roots       []Instance    `json:"roots"`
	Descendants []Instance    `json:"descendants"`
	Denied      []Instance    `json:"denied"`
	Unsupported []Unsupported `json:"unsupported"`
	Unresolved  string        `json:"unresolved,omitempty"`
	Cgroup      *Cgroup       `json:"cgroup,omitempty"`
	Listeners   []Listener    `json:"listeners,omitempty"`

	// conditions is the target's conditions, arguments included, for the local
	// view only; never encoded.
	conditions string
}

// Exclusion is one exclusion and what it denied.
type Exclusion struct {
	Number int        `json:"number"`
	Roots  []Instance `json:"roots"`
	Denied []Instance `json:"denied"`
}

// Loss is what capture discarded on the kernel side, or why that is unknown,
// and what the threads said about calls under way when the probes were placed.
type Loss struct {
	Known     bool           `json:"known"`
	Why       string         `json:"why,omitempty"`
	Dropped   int64          `json:"dropped"`
	Unmatched int64          `json:"unmatched"`
	UnderWay  probe.UnderWay `json:"under_way"`
	When      probe.Occasion `json:"when"`
}

// Admitted is the processes the kernel admitted as descendants while the
// session ran. Not a loss, and kept apart from Loss.
type Admitted struct {
	Known       bool   `json:"known"`
	Why         string `json:"why,omitempty"`
	Descendants int64  `json:"descendants"`
}

// Interval is when a reading opened and closed.
type Interval struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Admission is one recorded admission whose coverage ended, or whose grant could
// not be read.
type Admission struct {
	Instance  Instance `json:"instance"`
	Target    string   `json:"target"`
	Inherited bool     `json:"inherited"`

	// NamespaceBy is what read the instance's pid namespace, in the record
	// contract's words (namespaceBy).
	NamespaceBy string `json:"namespace_by"`

	// NoLaterThan is the reading that found the grant gone: the latest its
	// coverage can have ended.
	NoLaterThan *time.Time `json:"no_later_than,omitempty"`

	// Read is when the execution was read afterwards.
	Read *Interval `json:"read,omitempty"`

	// Why is why a grant could not be read.
	Why string `json:"why,omitempty"`
}

// coverageRule states in the account how admissions are placed below.
const coverageRule = "an admission whose grant the kernel still holds is covered and is counted rather " +
	"than listed; one whose execution is established as ended is counted under its target as ended and " +
	"no longer listed, its identity written once to the operational log when that was established; one " +
	"whose grant the kernel no longer holds while its execution may still run has had its coverage end, " +
	"and is listed with the latest moment that can have happened; one whose grant could not be read is " +
	"listed as unknown"

// TargetCoverage is one target's share of the admissions, so one target going
// dark is told apart from the whole run going dark.
type TargetCoverage struct {
	Target  string `json:"target"`
	Covered int    `json:"covered"`
	Ended   int    `json:"ended"`
	Unknown int    `json:"unknown"`
}

// Admissions is coverage over every admission the session recorded.
type Admissions struct {
	Rule          string           `json:"rule"`
	Covered       int              `json:"covered"`
	ByTarget      []TargetCoverage `json:"by_target"`
	CoverageEnded []Admission      `json:"coverage_ended"`
	GrantUnknown  []Admission      `json:"grant_unknown"`

	// Unavailable is why the backend could not answer, which is not an empty
	// population.
	Unavailable string `json:"unavailable,omitempty"`
}

// Refused is what the program refused while it ran, by reason, or why that is
// unknown.
type Refused struct {
	Known   bool             `json:"known"`
	Why     string           `json:"why,omitempty"`
	Reasons map[string]int64 `json:"reasons"`
}

// Account is what the observer says about one session.
type Account struct {
	LogDestinations map[string]sink.Stats `json:"log_destinations,omitempty"`
	LogDelivery     *sink.Stats           `json:"log_delivery,omitempty"`
	Version         int                   `json:"version"`
	Kind            Kind                  `json:"kind"`
	Session         string                `json:"session,omitempty"`
	At              time.Time             `json:"at"`
	Policy          Policy                `json:"policy"`

	// Build is what this build can do; Floor the kernel it publishes.
	Build probe.Capability `json:"build"`
	Floor Floor            `json:"floor"`

	Targets    []Target    `json:"targets"`
	Exclusions []Exclusion `json:"exclusions"`

	// Limits is what this policy's coverage does not reach, so an empty capture
	// is not read as a quiet host.
	Limits []string `json:"limits"`

	// Extensions is every configured extension, in the order it runs.
	Extensions []Extension `json:"extensions"`

	// Everything below exists only once something has attached.
	//
	// Processes is every attached process whose execution has not been
	// established as ended, and ProcessesEnded how many were dropped from it
	// because it was: each is written once to the operational log when it is.
	Processes      []attachment.Observed `json:"processes,omitempty"`
	ProcessesEnded int                   `json:"processes_ended"`
	Capability     *probe.Capability     `json:"capability,omitempty"`
	Capturing      string                `json:"capturing,omitempty"`
	Seen           *capture.Stats        `json:"seen,omitempty"`
	Loss           *Loss                 `json:"loss,omitempty"`
	Admitted       *Admitted             `json:"admitted,omitempty"`
	Admissions     *Admissions           `json:"admissions,omitempty"`
	Refused        *Refused              `json:"refused,omitempty"`
	Spool          *spool.Stats          `json:"spool,omitempty"`
	Processing     *Processing           `json:"processing,omitempty"`

	// Seal is how a sealed session ended; SealError why it could not be finalised.
	Seal      *connection.Seal `json:"seal,omitempty"`
	SealError string           `json:"seal_error,omitempty"`
}

// Run is what a session has seen at one moment. Ran replaces all of it, so no
// field describes an earlier moment.
type Run struct {
	Seen        capture.Stats
	Losses      probe.Losses
	LossesErr   error
	Refusals    map[string]int64
	RefusalsErr error
	Grants      []probe.Grant
	GrantsErr   error
	Ended       []probe.EndedCount
	Spool       *spool.Stats
	Processing  *Processing
}

// ExtensionEffects labels what an extension changes and emits: its own
// declaration, which the observer checks for shape and attribution and never
// for truth.
const ExtensionEffects = "extension_declared_not_observer_enforced"

// Extension is one configured extension as the account lists it. Its command
// is not listed: arguments can hold secrets, and the account may leave the
// host.
type Extension struct {
	Name      string   `json:"name"`
	Fields    []string `json:"fields"`
	TimeoutMS int64    `json:"timeout_ms"`
	Effects   string   `json:"effects"`
}

// ExtensionsOf lists configured extensions, each labelled.
func ExtensionsOf(configured []config.Extension) []Extension {
	list := make([]Extension, 0, len(configured))
	for _, one := range configured {
		list = append(list, Extension{Name: one.Name, Fields: slices.Clone(one.Fields), TimeoutMS: one.TimeoutMS,
			Effects: ExtensionEffects})
	}
	return list
}

// The fixed vocabularies an extension's counts are kept by, from the extension
// protocol (contract/extension/PROTOCOL.md).
var (
	ExtensionFailureReasons = []string{"timeout", "crash", "protocol", "oversized_frame", "unknown_id", "flood",
		"malformed", "not_given", "read_only", "removed_content", "excluded", "declined", "unavailable", "busy",
		"too_large"}
	ExtensionRetirementCauses = []string{"start_failed", "startup_timeout", "timeout", "crash", "protocol",
		"oversized_frame", "unknown_id", "flood"}
	DerivedRefusalReasons = []string{"malformed", "unknown_source", "rate", "queue_full", "stopped",
		"write_failed"}
)

// NoCounts is the counts of an extension nothing has been done with: every
// count zero and every vocabulary member present.
func NoCounts(name string) ExtensionCounts {
	zero := func(vocabulary []string) map[string]uint64 {
		counts := make(map[string]uint64, len(vocabulary))
		for _, key := range vocabulary {
			counts[key] = 0
		}
		return counts
	}
	return ExtensionCounts{Name: name, FailedBy: zero(ExtensionFailureReasons),
		RetiredBy: zero(ExtensionRetirementCauses), DerivedRefusedBy: zero(DerivedRefusalReasons)}
}

// ExtensionCounts is the observer's own count of what it did with one
// extension (contract/account/ACCOUNT.md, processing). Considered is Changed +
// Unchanged + Failed + Pending; the maps hold every member of the protocol's
// vocabularies.
type ExtensionCounts struct {
	Delivery         sink.Stats        `json:"delivery"`
	Name             string            `json:"name"`
	Considered       uint64            `json:"considered"`
	Changed          uint64            `json:"changed"`
	Unchanged        uint64            `json:"unchanged"`
	Failed           uint64            `json:"failed"`
	Pending          uint64            `json:"pending"`
	FailedBy         map[string]uint64 `json:"failed_by"`
	RetiredBy        map[string]uint64 `json:"retired_by"`
	Restarts         uint64            `json:"restarts"`
	StateResets      uint64            `json:"state_resets"`
	Late             uint64            `json:"late"`
	Duplicate        uint64            `json:"duplicate"`
	DerivedWritten   uint64            `json:"derived_written"`
	DerivedBytes     uint64            `json:"derived_bytes"`
	DerivedRefused   uint64            `json:"derived_refused"`
	DerivedRefusedBy map[string]uint64 `json:"derived_refused_by"`
	StderrDropped    uint64            `json:"stderr_dropped"`
}

// Processing carries session aggregates, never per-pipeline attribution.
// Authorized and Written count route records: permission is not completion or
// durable flush. ProcessingFailures counts affected durable routes for each
// batch's processing refusals: all routes for a batch refusal, or the affected
// pipeline's routes once for a pipeline refusal. These are not unique-route,
// batch or exchange counts; a route may write a useful prefix and also count a
// refused suffix. OutputFailures counts failed approved writes; neither is
// policy suppression or capture loss.
// Internal artifact-serialization defects use the terminal error/seal reason,
// not either counter.
// ConnectionsCut counts connections cut because they held as much input as one
// connection may while waiting to be processed, and InputCut the input
// entries (one per captured transfer) discarded for them, what each held when
// it was cut and what arrived for it afterwards. A cut is neither a processing
// failure nor a capture loss.
// GateReason is the current capture-wide invalidation reason, independently of
// whether a candidate reached authorization. Counts are the last returned
// worker outcome; the gate is read later.
// Its presence identifies a session that does not create a raw spool.
type Processing struct {
	Delivery           sink.Stats       `json:"delivery"`
	GateReason         probe.GateReason `json:"gate_reason"`
	ProcessingFailures uint64           `json:"processing_failures"`
	OutputFailures     uint64           `json:"output_failures"`
	ConnectionsCut     uint64           `json:"connections_cut"`
	InputCut           uint64           `json:"input_cut"`
	Authorized         uint64           `json:"authorized"`
	Written            uint64           `json:"written"`
	// ExchangeIDs is the number of exchange ids the session issued, and
	// Extensions one entry per configured extension, in the order it runs.
	ExchangeIDs uint64            `json:"exchange_ids"`
	Extensions  []ExtensionCounts `json:"extensions"`
}

// Plan is the account of a policy resolved and not attached. inspect, where
// given, reports selected processes as unsupported; nil leaves that unasked.
func Plan(at time.Time, policy Policy, resolution process.Resolution, build probe.Capability,
	inspect func(process.Process) probe.Report) Account {
	a := Account{
		Version: Version, Kind: Planned, At: at, Policy: policy, Build: build, Floor: floor(),
		Targets: []Target{}, Exclusions: []Exclusion{}, Limits: []string{}, Extensions: []Extension{},
	}
	for _, one := range resolution.Targets {
		target := Target{
			Number: one.Number, Name: one.Name, Mode: one.Mode.String(), Answers: answersOf(one.Mode),
			Roots: instancesOf(one.Roots), Descendants: instancesOf(one.Descendants), Denied: instancesOf(one.Denied),
			Unsupported: []Unsupported{}, Unresolved: one.Unresolved, conditions: one.Conditions,
		}
		if one.Cgroup != nil {
			target.Cgroup = &Cgroup{Path: one.Cgroup.Path, Inode: one.Cgroup.Inode, Why: one.Cgroup.Why}
		}
		for _, socket := range one.Listeners {
			target.Listeners = append(target.Listeners, Listener{Address: socket.String(), Owners: socket.Owners})
		}
		if inspect != nil {
			for _, p := range slices.Concat(one.Roots, one.Descendants) {
				if report := inspect(p); !report.Supported {
					target.Unsupported = append(target.Unsupported, Unsupported{Instance: instanceOf(p), Reason: report.Reason()})
				}
			}
		}
		a.Limits = append(a.Limits, limitsOf(one)...)
		a.Targets = append(a.Targets, target)
	}
	for _, one := range resolution.Exclusions {
		a.Exclusions = append(a.Exclusions, Exclusion{Number: one.Number, Roots: instancesOf(one.Roots),
			Denied: instancesOf(one.Denied)})
	}
	return a
}

// Attached adds the session, what the kernel confirms per process, and what
// the attachment can do.
func (a *Account) Attached(kind Kind, session string, processes []attachment.Observed, capability probe.Capability) {
	a.Kind, a.Session, a.Processes = kind, session, processes
	a.Capability = &capability
	a.Capturing = Describe(capability)
}

// Ran is what the session has seen at one moment.
func (a *Account) Ran(at time.Time, run Run) {
	a.At = at
	seen := run.Seen
	a.Seen = &seen

	if run.LossesErr != nil {
		a.Loss = &Loss{Why: run.LossesErr.Error()}
		a.Admitted = &Admitted{Why: run.LossesErr.Error()}
	} else {
		a.Loss = &Loss{Known: true, Dropped: run.Losses.Dropped, Unmatched: run.Losses.Unmatched,
			UnderWay: run.Losses.UnderWay, When: run.Losses.When}
		a.Admitted = &Admitted{Known: true, Descendants: run.Losses.Descendants}
	}

	if run.RefusalsErr != nil {
		a.Refused = &Refused{Why: run.RefusalsErr.Error(), Reasons: map[string]int64{}}
	} else {
		reasons := maps.Clone(run.Refusals)
		if reasons == nil {
			reasons = map[string]int64{}
		}
		a.Refused = &Refused{Known: true, Reasons: reasons}
	}

	switch {
	case run.GrantsErr != nil:
		a.Admissions = &Admissions{Rule: coverageRule, ByTarget: []TargetCoverage{}, CoverageEnded: []Admission{},
			GrantUnknown: []Admission{}, Unavailable: run.GrantsErr.Error()}
	case run.Grants != nil:
		a.Admissions = admissionsOf(run.Grants, run.Ended)
	default:
		a.Admissions = nil
	}
	a.Spool = run.Spool
	a.Processing = nil
	if run.Processing != nil {
		copy := *run.Processing
		a.Processing = &copy
	}
}

// Closed is how the session ended. An error means it could not be finalised,
// which differs from a seal whose steps failed.
func (a *Account) Closed(seal connection.Seal, err error) {
	a.Kind = Sealed
	if err != nil {
		a.Seal, a.SealError = nil, err.Error()
		return
	}
	a.Seal, a.SealError = &seal, ""
}

func floor() Floor {
	return Floor{
		Published: ebpf.MinimumKernel, Proved: ebpf.FloorProved,
		Established: ebpf.FloorEstablished, WouldEstablish: ebpf.FloorWouldEstablish,
	}
}

func answersOf(mode admission.Mode) Answers {
	answers := mode.Answers()
	return Answers{
		Existing: answers.Existing, Future: answers.Future, Boundary: answers.Boundary.String(),
		RootExit: answers.RootExit.String(), Replacement: answers.Replacement.String(),
	}
}

func instanceOf(p process.Process) Instance {
	one := Instance{PID: p.PID, Namespace: namespaceText(p.Namespace), NamespacePID: p.NamespacePID,
		Executable: p.Executable}
	if start := p.Start(); start.Determined {
		ticks := uint64(start.Ticks)
		one.Start = &ticks
	}
	return one
}

func instancesOf(processes []process.Process) []Instance {
	found := make([]Instance, 0, len(processes))
	for _, p := range processes {
		found = append(found, instanceOf(p))
	}
	return found
}

func namespaceText(namespace admission.Namespace) string {
	if !namespace.Known() {
		return ""
	}
	return fmt.Sprintf("%d:%d", namespace.Device, namespace.Inode)
}

// limitsOf is what a target's coverage does not reach.
func limitsOf(one process.Resolved) []string {
	var limits []string
	label := fmt.Sprintf("target %d (%s)", one.Number, one.Name)
	if one.Listeners != nil || strings.Contains(one.Conditions, "port ") {
		limits = append(limits, label+": a port finds the processes holding a listener on it; an "+
			"outbound-only process holds none and cannot be found this way, and a process it finds is "+
			"observed on all of its connections rather than on that port alone")
	}
	if one.Cgroup != nil {
		limits = append(limits, label+": the cgroup is a snapshot taken when the policy was resolved; a "+
			"process that moves in afterwards is not selected until a restart resolves it again")
	}
	if one.Mode.Answers().Future {
		limits = append(limits, label+": what it forks is observed, and a child that then execs is not "+
			"until a restart resolves the policy again")
	}
	return limits
}

func admissionsOf(grants []probe.Grant, ended []probe.EndedCount) *Admissions {
	admissions := &Admissions{Rule: coverageRule, ByTarget: []TargetCoverage{}, CoverageEnded: []Admission{},
		GrantUnknown: []Admission{}}
	at := make(map[string]int)
	for _, one := range ended {
		target := targetOf(admission.Provenance{Target: one.Target, Number: one.Number})
		index, seen := at[target]
		if !seen {
			index = len(admissions.ByTarget)
			at[target] = index
			admissions.ByTarget = append(admissions.ByTarget, TargetCoverage{Target: target})
		}
		admissions.ByTarget[index].Ended += one.Count
	}
	for _, grant := range grants {
		one := Admission{
			Instance:    instanceOfSelection(grant.Selection),
			Target:      targetOf(grant.Selection.Provenance),
			Inherited:   grant.Selection.Provenance.Inherited(),
			NamespaceBy: namespaceBy(grant.Selection),
		}
		index, seen := at[one.Target]
		if !seen {
			index = len(admissions.ByTarget)
			at[one.Target] = index
			admissions.ByTarget = append(admissions.ByTarget, TargetCoverage{Target: one.Target})
		}
		switch grant.State {
		case probe.GrantHeld:
			admissions.ByTarget[index].Covered++
		case probe.GrantAbsent:
			admissions.ByTarget[index].Ended++
		default:
			admissions.ByTarget[index].Unknown++
		}
		switch grant.State {
		case probe.GrantHeld:
			admissions.Covered++
		case probe.GrantAbsent:
			read := grant.Read
			one.NoLaterThan = &read
			if !grant.Evidence.From.IsZero() {
				one.Read = &Interval{From: grant.Evidence.From, To: grant.Evidence.To}
			}
			admissions.CoverageEnded = append(admissions.CoverageEnded, one)
		default:
			one.Why = grant.Why
			admissions.GrantUnknown = append(admissions.GrantUnknown, one)
		}
	}
	return admissions
}

// namespaceBy is what read an admission's pid namespace. The kernel admitted an
// instance whose generation it allocated, at a fork, and the namespace is the
// one its events carry; the walk of running descendants at attach read an
// adopted one's from /proc; the policy's resolution read the rest's. Whether
// the instance was inherited cannot decide it: all but the first are
// descendants.
func namespaceBy(selection admission.Selection) string {
	switch {
	case selection.Instance.Generation.FromKernel():
		return record.ByAdmissionEvent
	case selection.Adopted:
		return record.ByAttachRead
	default:
		return record.ByResolutionRead
	}
}

// EndedAdmission is one admission established as ended, as the operational log
// records it: the only record of its identity once the account counts it.
func EndedAdmission(one probe.Ended) Admission {
	return Admission{
		Instance:    instanceOfSelection(one.Selection),
		Target:      targetOf(one.Selection.Provenance),
		Inherited:   one.Selection.Provenance.Inherited(),
		NamespaceBy: namespaceBy(one.Selection),
		Why:         one.Evidence,
	}
}

func instanceOfSelection(selection admission.Selection) Instance {
	one := Instance{
		PID: selection.ObserverPID, Namespace: namespaceText(selection.Instance.Namespace),
		NamespacePID: selection.Instance.PID, Executable: selection.Instance.Executable,
	}
	if selection.Instance.Start.Determined {
		ticks := uint64(selection.Instance.Start.Ticks)
		one.Start = &ticks
	}
	return one
}

func targetOf(provenance admission.Provenance) string {
	if provenance.Target != "" {
		return provenance.Target
	}
	return fmt.Sprintf("target %d", provenance.Number)
}

// Describe is one line saying what an attachment can report. It separates an
// attachment that copies no plaintext from a host where none crossed.
func Describe(capability probe.Capability) string {
	what := "metadata only, no plaintext is copied"
	if capability.Payload {
		what = "plaintext"
	}
	through := string(capability.Backend)
	if capability.Program != "" {
		through += ", the " + capability.Program + " program"
	}
	if capability.MinimumKernel != "" {
		through += ", kernel " + capability.MinimumKernel + " or newer"
	}
	if capability.Backend == probe.BPF {
		// The loader relocates against the host's BTF, a build option rather than a
		// version, so the requirement is stated beside the version.
		through += ", publishing its own BTF"
	}
	line := fmt.Sprintf("%s (%s)", what, through)

	// Narrower facts, stated only where they apply: an empty capture must not
	// read as a quiet host.
	if !capability.Filtered {
		line += "; an unapproved process's probe events reach userspace before the process filter runs"
	}
	if !capability.Descendants {
		line += "; nothing an approved process forks is observed"
	}
	if !capability.Lifecycle {
		line += "; no connection ending is observed, so a reused library handle continues the " +
			"previous connection's stream"
	}
	// Hangs off SocketEvidence, not Binding: an association needs the socket the
	// kernel acquired, which Binding does not provide.
	if !capability.SocketEvidence {
		line += "; which socket a transfer crossed is not established, so every association is unknown"
	}
	if len(capability.Unprobed) > 0 {
		line += "; capture is not live, no probe held for " + strings.Join(capability.Unprobed, ", ") +
			", so the whole attachment sequences nothing and certifies no exchange"
	}
	if len(capability.Unobserved) > 0 {
		line += "; the kernel holds no probe on " + strings.Join(capability.Unobserved, ", ")
	}
	return line
}

// Render writes the account for a terminal. local adds each target's
// conditions, arguments included, and says so.
func Render(to io.Writer, a Account, local bool) {
	say := func(format string, arguments ...any) { _, _ = fmt.Fprintf(to, format+"\n", arguments...) }

	session := a.Session
	if session == "" {
		session = "no session"
	}
	say("account    %s, %s, version %d, at %s", a.Kind, session, a.Version, a.At.UTC().Format(time.RFC3339Nano))
	if local {
		say("local      this is the local view: it carries each target's conditions, arguments " +
			"included, and is not for anything that leaves this host")
	}
	say("policy     revision %s, generation %d", a.Policy.Revision, a.Policy.Generation)
	if a.Floor.Proved {
		say("floor      kernel %s or newer is published, and loading there is proved", a.Floor.Published)
	} else {
		say("floor      kernel %s or newer is published, and loading there is UNPROVED - a claim about the "+
			"artifact and not about this run. Established: %s. What would establish it: %s",
			a.Floor.Published, a.Floor.Established, a.Floor.WouldEstablish)
	}

	for _, target := range a.Targets {
		if target.Unresolved != "" {
			say("target %-3d %s, descendants %s: UNRESOLVED: %s", target.Number, target.Name, target.Mode, target.Unresolved)
		} else {
			say("target %-3d %s, descendants %s: %d roots, %d existing descendants, %d denied",
				target.Number, target.Name, target.Mode, len(target.Roots), len(target.Descendants), len(target.Denied))
		}
		if local {
			say("           conditions: %s", target.conditions)
		}
		for _, root := range target.Roots {
			say("           root pid %d, %s", root.PID, root.Executable)
		}
		for _, one := range target.Unsupported {
			say("           pid %d is selected and UNSUPPORTED, eligible and uncovered: %s", one.Instance.PID, one.Reason)
		}
	}
	for _, exclusion := range a.Exclusions {
		say("ignore     %d: %d matched, %d denied with their subtrees", exclusion.Number, len(exclusion.Roots), len(exclusion.Denied))
	}
	for _, limit := range a.Limits {
		say("limit      %s", limit)
	}
	for _, one := range a.Extensions {
		say("extension  %s: %s; timeout %d ms; extension-declared, not observer-enforced", one.Name,
			strings.Join(one.Fields, ", "), one.TimeoutMS)
	}

	if a.Capability == nil {
		return
	}
	say("capturing  %s", a.Capturing)
	seen := capture.Stats{}
	if a.Seen != nil {
		seen = *a.Seen
	}
	(attachment.Account{Processes: a.Processes}).State(to, seen.Transfers, seen.Records, seen.Connections)
	say("seen       %d transfers, %d unmeasured, %d empty", seen.Transfers, seen.Unmeasured, seen.Empty)
	say("placed     %d records over %d connections, %d of them ended", seen.Records, seen.Connections, seen.Closed)
	say("early      %d transfers arrived before a handshake finished", seen.Early)

	// Ordering is reported apart from loss: what a connection's own sequence
	// says it lost, and what that cost its positions.
	say("ordering   %d transfers missing from their connections' sequences, %d directions whose "+
		"positions stopped being established, %d connections retired with their endings never "+
		"delivered, %d transfers with no sequence, %d losses the producer could place in no "+
		"connection",
		seen.Lost, seen.Cut, seen.Retired, seen.Unsequenced, seen.Unlocated)

	say("overload   %d transfers refused by the admission gate, %d fragments refused by volatile intake", seen.GateRefused, seen.IntakeRefused)

	// Losses only. A dropped event leaves no mark in the stream it would have
	// joined.
	switch {
	case a.Loss == nil:
	case !a.Loss.Known:
		say("lost       NOT KNOWN: %s", a.Loss.Why)
	default:
		say("lost       %d events the kernel could not buffer, %d returns with no entry recorded%s",
			a.Loss.Dropped, a.Loss.Unmatched, occasion(a.Loss.When))
		say("under way  %s", underWay(a.Loss.UnderWay))
	}
	// Not a loss: whether descendant admission did anything.
	switch {
	case a.Admitted == nil:
	case !a.Admitted.Known:
		say("admitted   NOT KNOWN: %s", a.Admitted.Why)
	default:
		say("admitted   %d processes as descendants of an approved process", a.Admitted.Descendants)
	}

	switch {
	case a.Admissions == nil:
	case a.Admissions.Unavailable != "":
		say("coverage   NOT KNOWN: %s", a.Admissions.Unavailable)
	default:
		say("coverage   %d admissions covered, %d whose coverage has ended, %d whose grant could not be read",
			a.Admissions.Covered, len(a.Admissions.CoverageEnded), len(a.Admissions.GrantUnknown))
		for _, one := range a.Admissions.CoverageEnded {
			say("  coverage ended for pid %d (%s), no later than %s", one.Instance.PID, one.Target,
				one.NoLaterThan.UTC().Format(time.RFC3339Nano))
		}
		for _, one := range a.Admissions.GrantUnknown {
			say("  grant not read for pid %d (%s): %s", one.Instance.PID, one.Target, one.Why)
		}
	}

	if a.Refused != nil {
		if !a.Refused.Known {
			say("refused    NOT KNOWN: %s", a.Refused.Why)
		} else {
			say("refused    %d reasons counted", len(a.Refused.Reasons))
			for _, reason := range slices.Sorted(maps.Keys(a.Refused.Reasons)) {
				say("  %-10d %s", a.Refused.Reasons[reason], reason)
			}
		}
	}

	switch {
	case a.SealError != "":
		say("sealed     NOT SEALED: %s", a.SealError)
	case a.Seal == nil:
	case a.Seal.Complete:
		say("sealed     %d admissions withdrawn, %s drained, %s outstanding, %s interrupted in flight, "+
			"%s calls still executing%s", a.Seal.Withdrawal.Instances, a.Seal.Drain.Delivered,
			a.Seal.Drain.Outstanding, a.Seal.Interrupted, a.Seal.Counters.StillExecuting, besideSeal(a.Lost()))
	default:
		for _, why := range a.Seal.Because {
			say("sealed     INCOMPLETE: %s", why)
		}
	}
	if a.Seal != nil {
		for _, identity := range a.Seal.Counters.Identities() {
			say("conserved  %s", identity)
		}
		complete, known := a.Seal.Counters.Complete()
		switch {
		case !known:
			say("recorded   NOT KNOWN: %s, %s", a.Seal.Counters.SocketsUnrecorded, a.Seal.Counters.BindingsUnrecorded)
		case complete:
			say("recorded   every descriptor lifetime, handle binding and denial this run saw")
		default:
			say("recorded   SHORT: %s descriptor lifetimes, %s handle bindings and %s denials could not be "+
				"recorded, so anything missing is this observer's shortfall rather than the process's",
				a.Seal.Counters.SocketsUnrecorded, a.Seal.Counters.BindingsUnrecorded, a.Seal.Counters.DenialsUnrecorded)
		}
		say("deferred   %s calls discarded for want of an admission", a.Seal.Counters.DeferredDiscarded)
	}

	if a.Spool != nil {
		say("spooled    %d records, %d dropped at the bound, %d refused, %d of %d bytes",
			a.Spool.Written, a.Spool.Dropped, a.Spool.Refused, a.Spool.Bytes, a.Spool.Limit)
		say("joined     %d connection records, %d dropped at the bound, %d refused",
			a.Spool.Connections, a.Spool.ConnectionsDropped, a.Spool.ConnectionsRefused)
	}
	if d := a.LogDelivery; d != nil {
		say("log        %d authorized, %d written, %d failed, %d dropped, %d pending; %d discarded at shutdown", d.Authorized, d.Written, d.Failed, d.Dropped, d.Pending, d.Discarded)
	}
	if p := a.Processing; p != nil {
		say("processed  %d route processing failures, %d output failures", p.ProcessingFailures, p.OutputFailures)
		say("approved   %d route records authorized, %d written", p.Authorized, p.Written)
		say("delivery   %d failed, %d dropped, %d pending; %d discarded at shutdown", p.Delivery.Failed, p.Delivery.Dropped, p.Delivery.Pending, p.Delivery.Discarded)
		if p.GateReason != "" {
			say("release    refused: %s", p.GateReason)
		}
		if len(p.Extensions) > 0 {
			say("ids        %d exchange ids issued", p.ExchangeIDs)
		}
		for _, one := range p.Extensions {
			say("extension  %s: %d considered, %d changed, %d unchanged, %d failed, %d pending; %d restarts, "+
				"%d state resets; %d derived lines written, %d refused", one.Name, one.Considered, one.Changed,
				one.Unchanged, one.Failed, one.Pending, one.Restarts, one.StateResets, one.DerivedWritten,
				one.DerivedRefused)
		}
	}
}

// underWay is the line for calls under way when the probes were placed: the
// threads blocked in socket I/O throughout, the first of them, and those that
// ran meanwhile, which are NOT KNOWN rather than none.
func underWay(u probe.UnderWay) string {
	line := fmt.Sprintf("%d threads were inside socket I/O throughout probe placement", u.Threads)
	if u.First != nil {
		line += fmt.Sprintf(", the first pid %d thread %d in %s on descriptor %d, so a TLS call any of them "+
			"was inside began before the probes and what it moved is absent", u.First.PID, u.First.TID,
			u.First.Call, u.First.FD)
	}
	if u.Undetermined != 0 {
		line += fmt.Sprintf("; %d threads ran while the probes were placed, so whether each lost a call is NOT KNOWN",
			u.Undetermined)
	}
	if !u.Known {
		line += "; NOT KNOWN for the rest: " + underWayWhy(u)
	}
	return line
}

// underWayWhy is why a reading is not known. An account written before the
// reading existed carries none, and says so rather than nothing.
func underWayWhy(u probe.UnderWay) string {
	if u.Why == "" {
		return "this account does not carry a reading of the threads"
	}
	return u.Why
}

// Lost is every loss the account carries that is not nothing - a count above
// zero or a reading not known - as one clause, or empty where there is none: the
// kernel's losses, the calls under way when the probes were placed, and the
// records the volatile intake refused. A seal that completed says its steps
// succeeded and nothing about what capture lost, so wherever a session is said
// to have sealed this is printed on the same line (Render, and the stop
// command). An event the delivery gate refused is not a loss and is not here.
func (a Account) Lost() string {
	var lost []string
	switch {
	case a.Loss == nil:
	case !a.Loss.Known:
		lost = append(lost, "what capture lost is NOT KNOWN: "+a.Loss.Why)
	default:
		if a.Loss.Dropped != 0 {
			lost = append(lost, fmt.Sprintf("%d events the kernel could not buffer", a.Loss.Dropped))
		}
		if a.Loss.Unmatched != 0 {
			lost = append(lost, fmt.Sprintf("%d returns with no entry recorded", a.Loss.Unmatched))
		}
		u := a.Loss.UnderWay
		if u.Threads != 0 {
			lost = append(lost, fmt.Sprintf("%d threads under way when the probes were placed", u.Threads))
		}
		if u.Undetermined != 0 {
			lost = append(lost, fmt.Sprintf("%d threads NOT KNOWN, having run while the probes were placed",
				u.Undetermined))
		}
		if !u.Known {
			lost = append(lost, "whether a call was under way when the probes were placed is NOT KNOWN: "+
				underWayWhy(u))
		}
	}
	if a.Seen != nil {
		if a.Seen.Rejected != 0 {
			lost = append(lost, fmt.Sprintf("%d records the volatile intake refused", a.Seen.Rejected))
		}
		if a.Seen.ConnectionsUnrecorded != 0 {
			lost = append(lost, fmt.Sprintf("%d connection records the volatile intake refused",
				a.Seen.ConnectionsUnrecorded))
		}
	}
	return strings.Join(lost, ", ")
}

// besideSeal is Lost as it follows a seal line.
func besideSeal(lost string) string {
	if lost == "" {
		return ""
	}
	return "; LOST " + lost
}

// occasion is when the unmatched returns were seen, on which clock, and the
// first one's handle and thread.
func occasion(when probe.Occasion) string {
	if !when.Seen() {
		return ""
	}
	return fmt.Sprintf(", first seen %d and last %d nanoseconds after this boot on the monotonic clock, "+
		"the first on handle %#x of pid %d thread %d", when.First, when.Last, when.Handle, when.PID, when.TID)
}
