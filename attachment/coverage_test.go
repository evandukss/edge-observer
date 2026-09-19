package attachment_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// errUnplaceable is an adapter's answer when nothing could be placed.
var errUnplaceable = errors.New("the kernel placed none of the probes it was asked for")

// named is a pid namespace this run read and can enumerate.
func named() admission.Namespace {
	return admission.Namespace{Device: 4, Inode: 4026531836}
}

// whole is what an attachment that placed everything can do.
func whole() probe.Capability {
	return probe.Capability{
		Backend: probe.BPF, Program: "full", Payload: true, Filtered: true,
		Descendants: true, Lifecycle: true, Binding: true,
	}
}

// member is one process of a family, attached as the placements say.
func member(pid int32, capability probe.Capability, placements ...probe.Placement) attachment.Observed {
	one := attempt()
	one.Process = process.Process{
		PID: pid, StartTime: 900, Numbering: process.NumberingShared, Namespace: named(),
	}
	one.Placements = placements
	one.Capability = capability
	return attachment.Describe(one)
}

func family(matched ...process.Process) []process.Match {
	return rules(matched)
}

func coverageOf(t *testing.T, account attachment.Account) attachment.Coverage {
	t.Helper()
	if len(account.Rules) != 1 {
		t.Fatalf("%d rules, want 1", len(account.Rules))
	}
	return account.Rules[0].Coverage
}

// The control: a family whose members all attached is covered.
func TestAFamilyWhoseMembersAreAllAttachedIsCovered(t *testing.T) {
	one := member(41, whole(), placed("SSL_read", true, ""), placed("SSL_write", true, ""))
	two := member(42, whole(), placed("SSL_read", true, ""), placed("SSL_write", true, ""))

	account := attachment.Of(family(
		process.Process{PID: 41}, process.Process{PID: 42}), []attachment.Observed{one, two})

	if got := coverageOf(t, account); got != attachment.Covered {
		t.Errorf("a family whose members are all attached is %q", got)
	}
}

// One member refused outright: covered in part, and the refused instance
// named.
func TestAFamilyWithOneRefusedMemberIsCoveredInPartAndNamesIt(t *testing.T) {
	placedOne := member(41, whole(), placed("SSL_read", true, ""), placed("SSL_write", true, ""))

	refused := attempt()
	refused.Process = process.Process{
		PID: 42, StartTime: 901, Numbering: process.NumberingShared, Namespace: named(),
	}
	refused.Placements = nil
	refused.Err = errUnplaceable
	uncovered := attachment.Describe(refused)

	account := attachment.Of(family(
		process.Process{PID: 41}, process.Process{PID: 42}), []attachment.Observed{placedOne, uncovered})

	if got := coverageOf(t, account); got != attachment.CoveredInPart {
		t.Errorf("a family with one refused member is %q", got)
	}
	if got := account.Rules[0].Uncovered; len(got) != 1 || got[0] != 42 {
		t.Errorf("the family names %v as uncovered, want pid 42 alone", got)
	}

	var report strings.Builder
	account.Report(&report)
	if !strings.Contains(report.String(), string(attachment.CoveredInPart)) {
		t.Errorf("the report does not say the family is covered in part:\n%s", report.String())
	}
	if !strings.Contains(report.String(), errUnplaceable.Error()) {
		t.Errorf("the report does not say why pid 42 is uncovered:\n%s", report.String())
	}
}

// One member holding fewer probes than asked: covered in part too.
func TestAFamilyWhoseMemberIsPartlyAttachedIsCoveredInPart(t *testing.T) {
	short := whole()
	short.Unobserved = []string{"SSL_read"}

	one := member(41, whole(), placed("SSL_read", true, ""), placed("SSL_write", true, ""))
	two := member(42, short, placed("SSL_read", false, "the kernel would not take it"),
		placed("SSL_write", true, ""))

	account := attachment.Of(family(
		process.Process{PID: 41}, process.Process{PID: 42}), []attachment.Observed{one, two})

	if got := coverageOf(t, account); got != attachment.CoveredInPart {
		t.Errorf("a family with a partly attached member is %q", got)
	}
	if got := account.Rules[0].Uncovered; len(got) != 1 || got[0] != 42 {
		t.Errorf("the family names %v as uncovered, want pid 42 alone", got)
	}
}

// No member attached: UNCOVERED, a third answer, not "in part".
func TestAFamilyNoneOfWhoseMembersAttachedIsUncovered(t *testing.T) {
	refused := attempt()
	refused.Process = process.Process{
		PID: 42, StartTime: 901, Numbering: process.NumberingShared, Namespace: named(),
	}
	refused.Placements = nil
	refused.Err = errUnplaceable

	account := attachment.Of(family(process.Process{PID: 42}),
		[]attachment.Observed{attachment.Describe(refused)})

	if got := coverageOf(t, account); got != attachment.Uncovered {
		t.Errorf("a family with no attached member at all is %q", got)
	}
}

// An unheld fork point costs what the mode says. The fork point alone names a
// child at creation; descendants running at resolution are found by walking
// the process table. So follow loses what is forked from now on, and the other
// modes lose nothing.
func TestAnUnheldForkPointCostsWhatTheModeSaysItCosts(t *testing.T) {
	unfollowed := whole()
	unfollowed.Descendants = false

	said := func(mode admission.Mode) string {
		one := attempt()
		one.Process = process.Process{
			PID: 41, StartTime: 900, Numbering: process.NumberingShared, Namespace: named(),
		}
		one.Admitted.Mode = mode
		one.Capability = unfollowed

		var out strings.Builder
		attachment.Of(family(one.Process), []attachment.Observed{attachment.Describe(one)}).Report(&out)
		return out.String()
	}

	following := said(admission.ModeFollow)
	if !strings.Contains(following, "FROM NOW ON") {
		t.Errorf("a target that follows forks is not told what an unheld fork point costs it:\n%s", following)
	}
	if !strings.Contains(following, "already running") {
		t.Errorf("the report does not say that the descendants already running are still "+
			"observed, so it reads as a family nothing covers:\n%s", following)
	}

	// Modes admitting no later descendant lose nothing to an unheld fork point.
	for _, mode := range []admission.Mode{admission.ModeNone, admission.ModeExisting} {
		out := said(mode)
		if !strings.Contains(out, "nothing it would have covered is lost") {
			t.Errorf("descendants: %s loses nothing to an unheld fork point and the report does "+
				"not say so:\n%s", mode, out)
		}
		if strings.Contains(out, "FROM NOW ON") {
			t.Errorf("descendants: %s is told it lost what it forks from now on:\n%s", mode, out)
		}
	}
}

// The control: a held fork point costs nothing under any mode.
func TestAHeldForkPointCostsNothingUnderAnyMode(t *testing.T) {
	for _, mode := range []admission.Mode{admission.ModeNone, admission.ModeExisting, admission.ModeFollow} {
		one := attempt()
		one.Process = process.Process{
			PID: 41, StartTime: 900, Numbering: process.NumberingShared, Namespace: named(),
		}
		one.Admitted.Mode = mode
		one.Capability = whole()

		var out strings.Builder
		attachment.Of(family(one.Process), []attachment.Observed{attachment.Describe(one)}).Report(&out)
		if strings.Contains(out.String(), "fork point is held") {
			t.Errorf("descendants: %s holds its fork point and the report reads as one that does "+
				"not:\n%s", mode, out.String())
		}
	}
}

// No connection ending observed: a reused handle continues the previous
// connection's stream, and only the report can say so.
func TestAProcessWhoseConnectionEndingsAreNotObservedSaysSo(t *testing.T) {
	blind := whole()
	blind.Lifecycle = false

	one := member(41, blind, placed("SSL_read", true, ""), placed("SSL_write", true, ""))
	account := attachment.Of(family(process.Process{PID: 41}), []attachment.Observed{one})

	var report strings.Builder
	account.Report(&report)
	if !strings.Contains(report.String(), "ending") {
		t.Errorf("the report says nothing about connection endings:\n%s", report.String())
	}
}

// No socket entry point held: every association is unknown, and the report
// says why.
func TestAProcessWithNoBindingSourceSaysSoBesideItsAttachment(t *testing.T) {
	unbound := whole()
	unbound.Binding = false

	one := member(41, unbound, placed("SSL_read", true, ""), placed("SSL_write", true, ""))
	account := attachment.Of(family(process.Process{PID: 41}), []attachment.Observed{one})

	var report strings.Builder
	account.Report(&report)
	if !strings.Contains(report.String(), "socket") {
		t.Errorf("the report says nothing about which socket a transfer crossed:\n%s", report.String())
	}
}

// The control: an attachment that can do everything carries none of these
// notes.
func TestAProcessWhoseAttachmentCanDoEverythingCarriesNoneOfThoseNotes(t *testing.T) {
	one := member(41, whole(), placed("SSL_read", true, ""), placed("SSL_write", true, ""))
	account := attachment.Of(family(process.Process{PID: 41}), []attachment.Observed{one})

	var report strings.Builder
	account.Report(&report)
	for _, absent := range []string{"forks", "ending", "socket"} {
		if strings.Contains(report.String(), absent) {
			t.Errorf("a fully capable attachment reports %q as a limit:\n%s", absent, report.String())
		}
	}
}

// An adapter that said nothing about its capability is reported as that, not
// as able to do nothing; the two share a zero value.
func TestAnAttachmentThatSaidNothingAboutItselfIsNotReportedAsAbleToDoNothing(t *testing.T) {
	silent := member(41, probe.Capability{},
		placed("SSL_read", true, ""), placed("SSL_write", true, ""))
	account := attachment.Of(family(process.Process{PID: 41}), []attachment.Observed{silent})

	var report strings.Builder
	account.Report(&report)
	said := report.String()
	for _, absent := range []string{"forks", "ending", "socket"} {
		if strings.Contains(said, absent) {
			t.Errorf("a capability nobody supplied is reported as a limit on %q:\n%s", absent, said)
		}
	}
	if !strings.Contains(said, "nothing here says what this attachment can do") {
		t.Errorf("the report is silent about a capability nobody supplied:\n%s", said)
	}
}
