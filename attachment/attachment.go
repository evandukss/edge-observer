// Package attachment is what a run says it attached to, and why it did not
// attach to the rest.
//
// The account is built from what was asked for and what the kernel answered
// (a bpf link carries the file and offset it was placed at), and never reports
// the first as the second. It is printed on every run: a host where nothing
// attached and one where nothing has happened yet look the same otherwise.
package attachment

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// Outcome is what a run concluded about one approved process.
type Outcome string

const (
	// Attached is every probe the kernel was asked for, confirmed by it.
	Attached Outcome = "attached"

	// Partial is fewer confirmed than asked for, with the rest named.
	Partial Outcome = "partially attached"

	// NotAttached is none confirmed; in capitals so it cannot pass as a quiet host.
	NotAttached Outcome = "NOT ATTACHED"

	// Unconfirmed is an attachment nothing could ask the kernel about. Not knowing
	// is not nothing, so it is never folded into a neighbour. No adapter in this
	// build produces it.
	Unconfirmed Outcome = "attached, and unconfirmed"
)

// Attempt is one approved process and everything one run learned about
// attaching to it. Describe decides what it amounts to.
type Attempt struct {
	Process process.Process

	// Alive is whether the process was still there when attachment was tried.
	Alive bool

	// Support is what the catalogue's adapters said about the process: library,
	// resolved entry points, uncatalogued exports and expected ones missing.
	Support probe.Report

	// Err is what attaching returned; where the kernel refused every probe, it
	// carries each refusal verbatim.
	Err error

	// Placements is what the kernel says about each probe that was asked for.
	Placements []probe.Placement

	// Attested is whether the attachment could be asked what the kernel holds
	// at all.
	Attested bool

	// Admitted is why this process is observed. The mode is stated because what
	// it does not cover is invisible in a capture: an image a descendant execs into
	// is covered only from the next policy resolution.
	Admitted admission.Selection

	// Catalogued is every function the catalogue attaches to for this runtime,
	// what Unattempted is measured against: the only check that sees a function
	// nothing tried to place.
	Catalogued []string

	// Capability is what the attachment covering this process can do, as the
	// kernel confirms it. Per process, because one attachment covers several that
	// need not be equal. Describe reads it only where something attached.
	Capability probe.Capability
}

// Observed is the account of one approved process.
type Observed struct {
	PID       int32
	StartTime uint64
	Runtime   string

	// Requested is how many probes the kernel was asked for; Confirmed how many it
	// holds.
	Requested int
	Confirmed int

	Placements []probe.Placement

	// Unattempted is what the catalogue attaches to and this run did not request.
	// Bytes crossing such an entry point are simply absent, and nothing downstream
	// reveals it.
	Unattempted []string

	// Uncatalogued is what the library's plaintext family exports that the
	// catalogue does not name; Absent is what the catalogue expects and it lacks.
	Uncatalogued []string
	Absent       []string

	Outcome Outcome

	// Reason says which link of the chain produced a non-Attached outcome.
	Reason string

	// Namespace is the process's pid namespace. A child is numbered in it (unless
	// cloned into a new one), so naming children needs it enumerated; otherwise a
	// forking server's traffic looks like none.
	Namespace admission.Namespace

	// Mode is the descendant mode in force for this process.
	Mode admission.Mode

	// Capability is what the covering attachment can do; its absences are stated
	// in the report.
	Capability probe.Capability
}

// Describe decides what one attempt amounts to. The chain: process gone, no
// TLS library, nothing recognised, uncatalogued exports, kernel refused, fewer
// taken than asked. "Reason unknown" is stated when none fits, never a default.
func Describe(attempt Attempt) Observed {
	observed := Observed{
		PID:          attempt.Process.PID,
		StartTime:    attempt.Process.StartTime,
		Namespace:    attempt.Process.Namespace,
		Mode:         attempt.Admitted.Mode,
		Runtime:      runtime(attempt.Support),
		Requested:    len(attempt.Placements),
		Placements:   attempt.Placements,
		Uncatalogued: uncatalogued(attempt.Support),
		Absent:       absent(attempt.Support),
		Unattempted:  unattempted(attempt),
		Capability:   attempt.Capability,
	}
	for _, placement := range attempt.Placements {
		if placement.Confirmed {
			observed.Confirmed++
		}
	}

	switch {
	case !attempt.Alive:
		observed.Outcome, observed.Reason = NotAttached,
			fmt.Sprintf("the process matched a rule and is gone: there is no %d in the process table", attempt.Process.PID)

	case !attempt.Support.Supported:
		observed.Outcome, observed.Reason = NotAttached, attempt.Support.Reason()

	case attempt.Err != nil:
		observed.Outcome, observed.Reason = NotAttached, attempt.Err.Error()

	case !attempt.Attested:
		observed.Outcome, observed.Reason = Unconfirmed,
			"this adapter cannot ask the kernel what it holds, so nothing here is confirmed and nothing here is denied"

	case observed.Requested == 0:
		observed.Outcome, observed.Reason = NotAttached,
			"the kernel was asked for no probe at all, so nothing could ever fire"

	case observed.Confirmed == 0:
		observed.Outcome, observed.Reason = NotAttached, refusals(attempt.Placements)

	case observed.Confirmed < observed.Requested:
		observed.Outcome, observed.Reason = Partial, refusals(attempt.Placements)

	default:
		observed.Outcome = Attached
	}
	return observed
}

// refusals names each probe the kernel does not confirm, in the kernel's own
// words, or says it gave none.
func refusals(placements []probe.Placement) string {
	var named []string
	for _, placement := range placements {
		if placement.Confirmed {
			continue
		}
		if placement.Refusal == "" {
			named = append(named, placement.Symbol+": not attached, reason unknown")
			continue
		}
		named = append(named, placement.Symbol+": "+placement.Refusal)
	}
	if len(named) == 0 {
		return "not attached, reason unknown"
	}
	return strings.Join(named, "; ")
}

// unattempted is what the catalogue attaches to and nothing asked the kernel
// for, less what the library lacks (which is Absent).
func unattempted(attempt Attempt) []string {
	asked := make(map[string]bool, len(attempt.Placements))
	for _, placement := range attempt.Placements {
		asked[placement.Symbol] = true
	}
	explained := make(map[string]bool)
	for _, support := range attempt.Support.Support {
		for _, symbol := range support.Missing {
			explained[symbol] = true
		}
	}

	var missed []string
	for _, symbol := range attempt.Catalogued {
		if !asked[symbol] && !explained[symbol] {
			missed = append(missed, symbol)
		}
	}
	return missed
}

func runtime(report probe.Report) string {
	for _, support := range report.Support {
		if support.Adapter == report.Adapter && support.Runtime != "" {
			return support.Runtime
		}
	}
	return ""
}

func uncatalogued(report probe.Report) []string {
	var found []string
	for _, support := range report.Support {
		found = append(found, support.Unknown...)
	}
	return found
}

func absent(report probe.Report) []string {
	var found []string
	for _, support := range report.Support {
		found = append(found, support.Missing...)
	}
	return found
}

// Coverage is what a rule's processes amount to together, so a family
// observed in part is never reported as covered.
type Coverage string

const (
	// Covered is every process the rule named, fully attached.
	Covered Coverage = "covered"

	// CoveredInPart is part of the family observed: a member refused, or one
	// holding fewer probes than asked.
	CoveredInPart Coverage = "covered in part"

	// Uncovered is none of it observed, in capitals and apart from CoveredInPart.
	Uncovered Coverage = "UNCOVERED"
)

// Matched is one rule of the approval and the processes it named.
type Matched struct {
	Number int
	Names  string
	PIDs   []int32

	// Coverage is what those processes amount to; Uncovered is each not fully
	// attached. Reasons stay on each process's own line.
	Coverage  Coverage
	Uncovered []int32
}

// Account is what one run says about the whole approval.
type Account struct {
	Rules     []Matched
	Processes []Observed
}

// Of builds the account of an approval against a table.
func Of(matches []process.Match, observed []Observed) Account {
	outcomes := make(map[int32]Outcome, len(observed))
	for _, one := range observed {
		outcomes[one.PID] = one.Outcome
	}

	account := Account{Processes: observed}
	for _, match := range matches {
		named := Matched{Number: match.Number, Names: match.Rule.String()}
		whole := 0
		attached := 0
		for _, p := range match.Matched {
			named.PIDs = append(named.PIDs, p.PID)
			switch outcomes[p.PID] {
			case Attached:
				whole++
				attached++
			case Partial, Unconfirmed:
				attached++
				named.Uncovered = append(named.Uncovered, p.PID)
			default:
				named.Uncovered = append(named.Uncovered, p.PID)
			}
		}
		named.Coverage = coverage(len(match.Matched), whole, attached)
		account.Rules = append(account.Rules, named)
	}
	return account
}

// coverage decides what a rule's members amount to. A rule that named nothing
// is Uncovered, never a vacuous Covered.
func coverage(members, whole, attached int) Coverage {
	switch {
	case members == 0 || attached == 0:
		return Uncovered
	case whole == members:
		return Covered
	default:
		return CoveredInPart
	}
}

// Barren is the rules that named no process: configured, believed to approve
// something, and invisible downstream.
func (a Account) Barren() []Matched {
	var barren []Matched
	for _, rule := range a.Rules {
		if len(rule.PIDs) == 0 {
			barren = append(barren, rule)
		}
	}
	return barren
}

// Err is why this run should not proceed. An approval where no rule matched
// anything is refused; one rule matching nothing beside others that matched is
// reported and not refused.
func (a Account) Err() error {
	barren := a.Barren()
	if len(a.Rules) == 0 || len(barren) < len(a.Rules) {
		return nil
	}

	named := make([]string, 0, len(barren))
	for _, rule := range barren {
		named = append(named, fmt.Sprintf("rule %d (%s)", rule.Number, rule.Names))
	}
	return fmt.Errorf("no process on this host matches the approval: %s matched nothing",
		strings.Join(named, ", "))
}

// Confirmed is how many approved processes are fully attached, and how many
// probes the kernel confirms across all of them.
func (a Account) Confirmed() (processes, probes, asked int) {
	for _, observed := range a.Processes {
		if observed.Outcome == Attached {
			processes++
		}
		probes += observed.Confirmed
		asked += observed.Requested
	}
	return processes, probes, asked
}

// ErrNothingAttached is why a run gives up when no approved process could be
// attached to.
var ErrNothingAttached = errors.New("no approved process could be attached to")

// Report writes the account, in the shape a person reads down a terminal.
func (a Account) Report(to io.Writer) {
	_, _ = fmt.Fprintf(to, "approval   %d rules, %d processes selected\n", len(a.Rules), len(a.Processes))
	for _, rule := range a.Rules {
		if len(rule.PIDs) == 0 {
			_, _ = fmt.Fprintf(to, "  rule %-3d %s: MATCHED NOTHING\n", rule.Number, rule.Names)
			continue
		}
		_, _ = fmt.Fprintf(to, "  rule %-3d %s: %s, %s\n",
			rule.Number, rule.Names, pids(rule.PIDs), rule.Coverage)
		if len(rule.Uncovered) > 0 {
			_, _ = fmt.Fprintf(to, "           %s of this family %s not fully attached, and the "+
				"reason is on each line below\n", pids(rule.Uncovered), were(len(rule.Uncovered)))
		}
	}

	// A barren rule is repeated at the left margin beside the attachment outcomes,
	// where it is read.
	for _, rule := range a.Barren() {
		_, _ = fmt.Fprintf(to, "unmatched  rule %d (%s) matched no process on this host\n",
			rule.Number, rule.Names)
	}

	for _, observed := range a.Processes {
		_, _ = fmt.Fprintf(to, "pid %-7d %s: asked the kernel for %d probes and it confirms %d\n",
			observed.PID, observed.Outcome, observed.Requested, observed.Confirmed)
		if observed.Runtime != "" {
			_, _ = fmt.Fprintf(to, "           through %s\n", observed.Runtime)
		}
		if observed.Reason != "" {
			_, _ = fmt.Fprintf(to, "           %s\n", observed.Reason)
		}
		for _, line := range observed.notes() {
			_, _ = fmt.Fprintf(to, "           %s\n", line)
		}
	}
}

// notes is what a report says beside the outcome: entry points never
// requested, uncatalogued exports, and expected exports missing.
func (o Observed) notes() []string {
	var lines []string
	if len(o.Unattempted) > 0 {
		lines = append(lines, "the catalogue attaches to "+strings.Join(o.Unattempted, ", ")+
			" and this run asked the kernel for none of them")
	}
	if len(o.Uncatalogued) > 0 {
		lines = append(lines, "the library exports "+strings.Join(o.Uncatalogued, ", ")+
			", which the catalogue does not name, so nothing is attached there")
	}
	if len(o.Absent) > 0 {
		lines = append(lines, "the catalogue expects "+strings.Join(o.Absent, ", ")+
			" of a library of this version and this one does not export them")
	}
	// What this attachment cannot do, stated only where it cannot, from the
	// capability the kernel confirmed. Each absence otherwise reads as a quiet
	// process.
	if o.attached() && o.Capability.Backend == "" {
		// A capability with no backend is one nothing supplied; say so rather than
		// state limits nobody measured.
		lines = append(lines, "nothing here says what this attachment can do for this process, "+
			"so what it does not watch is not stated")
	}
	if o.attached() && o.Capability.Backend != "" {
		if !o.Capability.Descendants {
			lines = append(lines, descendants(o.Mode))
		}
		if !o.Capability.Lifecycle {
			lines = append(lines, "no connection ending is observed: a library handle the allocator "+
				"hands out again continues the stream of the connection that held it before")
		}
		if !o.Capability.Binding {
			lines = append(lines, "which socket a transfer crossed is not established: no binding "+
				"source is held, so every association this run reports is unknown for that reason")
		}
		if len(o.Capability.Unobserved) > 0 {
			lines = append(lines, "the kernel holds no probe on "+
				strings.Join(o.Capability.Unobserved, ", ")+
				", so what crosses them is absent from this capture")
		}
	}

	if o.Mode == admission.ModeFollow {
		// Follow covers what this process forks, not what a child then execs into:
		// that image is covered from the next policy resolution, at a restart. Covering
		// it at the exec would need an exec-time resolver in the kernel path.
		lines = append(lines, "descendants follow: what it forks is observed, and a child that "+
			"then execs is not until the policy is resolved again, which happens at a restart")
	}
	if !o.Namespace.Known() {
		lines = append(lines, "nothing it forks is observed: its own pid namespace could not be "+
			"read, so a child numbered in it cannot be resolved to a process here")
	}
	return lines
}

// descendants is what missing descendant coverage costs this process, by the
// mode its target carries. Descendants are admitted at the kernel's fork event,
// armed before any point is placed, so what remains is whether the approval
// asks for them; each mode loses something different.
func descendants(mode admission.Mode) string {
	switch mode {
	case admission.ModeFollow:
		return "what this process forks FROM NOW ON is unobserved, while the descendants already " +
			"running when the policy was resolved are admitted and observed"
	case admission.ModeExisting:
		return "this target admits no descendant created afterwards, so nothing it would have " +
			"covered is lost"
	case admission.ModeNone:
		return "this target admits no descendant at all, so nothing it would have covered is lost"
	default:
		return "this target carries no descendant mode, so what an unobserved descendant costs " +
			"is not established"
	}
}

// attached reports whether anything was placed for this process; without that,
// its limits are beside the point.
func (o Observed) attached() bool {
	return o.Outcome == Attached || o.Outcome == Partial || o.Outcome == Unconfirmed
}

// State is what the kernel confirms is attached beside what has come through
// it: either alone cannot tell a quiet host from a run watching nothing.
func (a Account) State(to io.Writer, transfers, records, connections int64) {
	processes, probes, asked := a.Confirmed()

	for _, rule := range a.Barren() {
		_, _ = fmt.Fprintf(to, "unmatched  rule %d (%s) matched no process on this host\n",
			rule.Number, rule.Names)
	}
	_, _ = fmt.Fprintf(to, "attached   %d of %d approved processes fully, %d of %d probes confirmed by the kernel\n",
		processes, len(a.Processes), probes, asked)
	_, _ = fmt.Fprintf(to, "events     %d transfers, %d records over %d connections\n",
		transfers, records, connections)

	switch {
	case probes == 0:
		_, _ = fmt.Fprintln(to, "state      NOT ATTACHED, and no event arrived, which is what that means")
	case transfers == 0:
		_, _ = fmt.Fprintln(to, "state      attached, and no event arrived: the probes are in the kernel and nothing has crossed them")
	default:
		_, _ = fmt.Fprintln(to, "state      attached, and events arrived")
	}
}

// were agrees the verb with a count.
func were(count int) string {
	if count == 1 {
		return "is"
	}
	return "are"
}

func pids(of []int32) string {
	named := make([]string, len(of))
	for i, pid := range of {
		named[i] = fmt.Sprintf("pid %d", pid)
	}
	return strings.Join(named, ", ")
}
