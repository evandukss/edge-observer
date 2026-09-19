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

// supported is what the catalogue says about a process it can observe.
func supported() probe.Report {
	return probe.Report{
		Supported: true,
		Adapter:   "openssl",
		Support: []probe.Support{{
			Adapter:   "openssl",
			Supported: true,
			Runtime:   "libssl.so.3 (OpenSSL 3.3.2)",
			Reason:    "/lib/libssl.so.3 exports SSL_read, SSL_write",
		}},
	}
}

func placed(symbol string, confirmed bool, refusal string) probe.Placement {
	return probe.Placement{
		Symbol: symbol, Path: "/lib/libssl.so.3", Offset: 0x3dc50,
		Confirmed: confirmed, Refusal: refusal,
	}
}

// attempt is a successful attachment that each case spoils one way. Without
// this control, a chain reporting everything NOT ATTACHED would pass them all.
func attempt() attachment.Attempt {
	return attachment.Attempt{
		Process:    process.Process{PID: 41, StartTime: 900, Numbering: process.NumberingShared},
		Alive:      true,
		Support:    supported(),
		Attested:   true,
		Catalogued: []string{"SSL_read", "SSL_write"},
		Placements: []probe.Placement{
			placed("SSL_read", true, ""),
			placed("SSL_write", true, ""),
		},
		Capability: whole(),
	}
}

func TestAnAttachmentTheKernelConfirmsWholeIsAttached(t *testing.T) {
	observed := attachment.Describe(attempt())

	if observed.Outcome != attachment.Attached {
		t.Fatalf("outcome %q with reason %q, want %q", observed.Outcome, observed.Reason, attachment.Attached)
	}
	if observed.Requested != 2 || observed.Confirmed != 2 {
		t.Errorf("asked %d and confirmed %d, want 2 and 2", observed.Requested, observed.Confirmed)
	}
	if observed.Reason != "" {
		t.Errorf("an attachment the kernel confirms whole carries a reason: %q", observed.Reason)
	}
}

// Fewer confirmed than asked for is its own state, naming which functions the
// kernel did not take and why; it is neither working nor broken.
func TestFewerConfirmedThanAskedForIsPartialAndNamesWhichAndWhy(t *testing.T) {
	spoiled := attempt()
	spoiled.Placements[1] = placed("SSL_write", false, "no such device")

	observed := attachment.Describe(spoiled)

	if observed.Outcome != attachment.Partial {
		t.Fatalf("outcome %q, want %q", observed.Outcome, attachment.Partial)
	}
	if observed.Confirmed != 1 {
		t.Errorf("confirmed %d, want 1", observed.Confirmed)
	}
	for _, want := range []string{"SSL_write", "no such device"} {
		if !strings.Contains(observed.Reason, want) {
			t.Errorf("the reason does not name %q: %q", want, observed.Reason)
		}
	}
	if strings.Contains(observed.Reason, "SSL_read") {
		t.Errorf("the reason names a function the kernel did confirm: %q", observed.Reason)
	}
}

func TestNoneConfirmedIsNotAttachedAndCarriesTheKernelsOwnWords(t *testing.T) {
	spoiled := attempt()
	spoiled.Placements = []probe.Placement{
		placed("SSL_read", false, "invalid argument"),
		placed("SSL_write", false, "invalid argument"),
	}

	observed := attachment.Describe(spoiled)

	if observed.Outcome != attachment.NotAttached {
		t.Fatalf("outcome %q, want %q", observed.Outcome, attachment.NotAttached)
	}
	if !strings.Contains(observed.Reason, "invalid argument") {
		t.Errorf("the reason does not carry the kernel's own words: %q", observed.Reason)
	}
}

// Reason unknown is stated when no link fits, never an unfilled default.
func TestAProbeTheKernelRefusedWithoutSayingWhyIsNamedAsUnknown(t *testing.T) {
	spoiled := attempt()
	spoiled.Placements = []probe.Placement{placed("SSL_read", false, "")}

	observed := attachment.Describe(spoiled)

	if observed.Outcome != attachment.NotAttached {
		t.Fatalf("outcome %q, want %q", observed.Outcome, attachment.NotAttached)
	}
	if !strings.Contains(observed.Reason, "SSL_read") || !strings.Contains(observed.Reason, "reason unknown") {
		t.Errorf("the reason neither names the function nor admits it is unknown: %q", observed.Reason)
	}
}

// Each link of the chain is established without any traffic.
func TestTheChainNamesTheReasonWhereverOneCanBeEstablished(t *testing.T) {
	gone := attempt()
	gone.Alive = false

	unsupported := attempt()
	unsupported.Support = probe.Report{Support: []probe.Support{{
		Adapter: "openssl",
		Reason:  "no libssl.so is mapped with code, so this process either does not use OpenSSL or carries its own TLS inside itself",
	}}}

	refused := attempt()
	refused.Err = errors.New("SSL_read: place SSL_read on /lib/libssl.so.3: no such device")

	nothingAsked := attempt()
	nothingAsked.Placements = nil

	cases := map[string]struct {
		attempt attachment.Attempt
		names   string
	}{
		"a process that matched a rule and is gone": {gone, "is gone"},
		"a process with no TLS library mapped":      {unsupported, "no libssl.so is mapped with code"},
		"a kernel that refused the attachment":      {refused, "no such device"},
		"an attachment that asked for no probe":     {nothingAsked, "no probe at all"},
	}

	for name, one := range cases {
		t.Run(name, func(t *testing.T) {
			observed := attachment.Describe(one.attempt)
			if observed.Outcome != attachment.NotAttached {
				t.Fatalf("outcome %q, want %q", observed.Outcome, attachment.NotAttached)
			}
			if !strings.Contains(observed.Reason, one.names) {
				t.Errorf("the reason does not say %q: %q", one.names, observed.Reason)
			}
		})
	}
}

// An adapter that cannot ask the kernel is neither confirmed nor denied.
func TestAnAttachmentNothingCouldAskTheKernelAboutIsItsOwnState(t *testing.T) {
	unattested := attempt()
	unattested.Attested = false
	unattested.Placements = nil

	observed := attachment.Describe(unattested)

	if observed.Outcome != attachment.Unconfirmed {
		t.Fatalf("outcome %q, want %q", observed.Outcome, attachment.Unconfirmed)
	}
	if observed.Outcome == attachment.Attached || observed.Outcome == attachment.NotAttached {
		t.Error("an unconfirmed attachment was reported as one of the answers nobody made")
	}
}

// A catalogued function nothing asked the kernel for is named: no count of
// what was asked for can see it.
func TestACataloguedFunctionNothingAskedTheKernelForIsNamed(t *testing.T) {
	missed := attempt()
	missed.Catalogued = []string{"SSL_read", "SSL_write", "SSL_free"}

	observed := attachment.Describe(missed)

	if observed.Outcome != attachment.Attached {
		t.Fatalf("outcome %q: an entry point nobody asked about does not make the attachment short", observed.Outcome)
	}
	if len(observed.Unattempted) != 1 || observed.Unattempted[0] != "SSL_free" {
		t.Fatalf("unattempted = %v, want SSL_free alone", observed.Unattempted)
	}
}

// A function the library does not export is Absent, not unattempted, or the
// check would fire on every old library.
func TestAFunctionTheLibraryDoesNotExportIsNotReportedAsUnattempted(t *testing.T) {
	old := attempt()
	old.Catalogued = []string{"SSL_read", "SSL_write", "SSL_write_ex2"}
	old.Support.Support[0].Missing = []string{"SSL_write_ex2"}

	observed := attachment.Describe(old)

	if len(observed.Unattempted) != 0 {
		t.Errorf("unattempted = %v, and the catalogue already explains that library", observed.Unattempted)
	}
	if len(observed.Absent) != 1 || observed.Absent[0] != "SSL_write_ex2" {
		t.Errorf("absent = %v, want SSL_write_ex2", observed.Absent)
	}
}

func rules(matched ...[]process.Process) []process.Match {
	built := make([]process.Match, len(matched))
	for i, processes := range matched {
		built[i] = process.Match{
			Number:  i + 1,
			Rule:    process.Rule{Executable: "/usr/bin/interpreter", Arguments: []string{"/srv/main"}},
			Matched: processes,
		}
	}
	return built
}

// An approval that matched nothing is refused, naming each rule.
func TestAnApprovalThatMatchedNothingIsRefusedAndNamesTheRules(t *testing.T) {
	account := attachment.Of(rules(nil, nil), nil)

	err := account.Err()
	if err == nil {
		t.Fatal("an approval that matched no process at all was not refused")
	}
	for _, want := range []string{"rule 1", "rule 2", "/srv/main"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

// A rule matching nothing beside rules that matched is named, not refused.
func TestARuleThatMatchedNothingBesideOneThatDidIsNamedAndNotRefused(t *testing.T) {
	account := attachment.Of(rules([]process.Process{{PID: 41}}, nil), nil)

	if err := account.Err(); err != nil {
		t.Fatalf("a run with one rule matching was refused: %v", err)
	}
	barren := account.Barren()
	if len(barren) != 1 || barren[0].Number != 2 {
		t.Fatalf("barren = %v, want rule 2 alone", barren)
	}

	var out strings.Builder
	account.Report(&out)
	if !strings.Contains(out.String(), "MATCHED NOTHING") {
		t.Errorf("the report does not say the rule matched nothing:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "rule 1") || !strings.Contains(out.String(), "pid 41") {
		t.Errorf("the report does not say what rule 1 matched:\n%s", out.String())
	}
}

// Attached-and-idle and never-attached are silent alike, so both lines are
// always printed and the state line says which.
func TestAttachedAndIdleIsDistinctFromNotAttached(t *testing.T) {
	attachedAndIdle := attachment.Of(rules([]process.Process{{PID: 41}}),
		[]attachment.Observed{attachment.Describe(attempt())})

	neverAttached := attempt()
	neverAttached.Placements = []probe.Placement{placed("SSL_read", false, "invalid argument")}
	nothing := attachment.Of(rules([]process.Process{{PID: 41}}),
		[]attachment.Observed{attachment.Describe(neverAttached)})

	var idle, absent strings.Builder
	attachedAndIdle.State(&idle, 0, 0, 0)
	nothing.State(&absent, 0, 0, 0)

	if idle.String() == absent.String() {
		t.Fatalf("an attached and idle run and a run that never attached print the same thing:\n%s", idle.String())
	}
	if !strings.Contains(idle.String(), "attached, and no event arrived") {
		t.Errorf("an attached and idle run does not say so:\n%s", idle.String())
	}
	if !strings.Contains(absent.String(), "NOT ATTACHED") {
		t.Errorf("a run that never attached does not say so:\n%s", absent.String())
	}

	// Both carry the attachment and the events.
	for _, out := range []string{idle.String(), absent.String()} {
		if !strings.Contains(out, "probes confirmed by the kernel") || !strings.Contains(out, "transfers") {
			t.Errorf("the state does not show the attachment and the events side by side:\n%s", out)
		}
	}
}

func TestAttachedWithEventsIsDistinctFromAttachedAndIdle(t *testing.T) {
	account := attachment.Of(rules([]process.Process{{PID: 41}}),
		[]attachment.Observed{attachment.Describe(attempt())})

	var busy strings.Builder
	account.State(&busy, 12, 12, 2)

	if strings.Contains(busy.String(), "no event arrived") {
		t.Errorf("a run that saw twelve transfers says no event arrived:\n%s", busy.String())
	}
	if !strings.Contains(busy.String(), "12 transfers") {
		t.Errorf("the state does not carry the counters:\n%s", busy.String())
	}
}

// A barren rule is repeated at the left margin, like an attachment that
// failed.
func TestABarrenRuleIsSaidAtTheLeftMarginLikeAnAttachmentThatFailed(t *testing.T) {
	account := attachment.Of(rules([]process.Process{{PID: 41}}, nil),
		[]attachment.Observed{attachment.Describe(attempt())})

	var report, state strings.Builder
	account.Report(&report)
	account.State(&state, 0, 0, 0)

	for name, out := range map[string]string{"the report": report.String(), "the summary": state.String()} {
		var margin bool
		for line := range strings.Lines(out) {
			if strings.HasPrefix(line, "unmatched ") && strings.Contains(line, "rule 2") {
				margin = true
			}
		}
		if !margin {
			t.Errorf("%s does not name the barren rule at the left margin:\n%s", name, out)
		}
	}
}

// The control: a run whose rules all matched says nothing about unmatched
// rules.
func TestARunWhoseRulesAllMatchedSaysNothingAboutUnmatchedRules(t *testing.T) {
	account := attachment.Of(rules([]process.Process{{PID: 41}}),
		[]attachment.Observed{attachment.Describe(attempt())})

	var report, state strings.Builder
	account.Report(&report)
	account.State(&state, 0, 0, 0)

	if strings.Contains(report.String()+state.String(), "unmatched") {
		t.Errorf("a run whose every rule matched reports an unmatched rule:\n%s%s", report.String(), state.String())
	}
}

// Under follow, an exec'd image is covered only from the next policy
// resolution, and the report says so.
func TestAModeThatFollowsForksSaysWhatItDoesNotCover(t *testing.T) {
	following := attempt()
	following.Admitted.Mode = admission.ModeFollow

	roots := attempt()
	roots.Admitted.Mode = admission.ModeNone

	report := func(a attachment.Attempt) string {
		var out strings.Builder
		attachment.Of(rules([]process.Process{a.Process}),
			[]attachment.Observed{attachment.Describe(a)}).Report(&out)
		return out.String()
	}

	said := report(following)
	if !strings.Contains(said, "execs") || !strings.Contains(said, "restart") {
		t.Errorf("a run following forks does not say that a child which execs is uncovered "+
			"until the policy is resolved again:\n%s", said)
	}

	// The control: a mode covering no descendants says nothing about execs.
	if strings.Contains(report(roots), "execs") {
		t.Errorf("a run admitting no descendant reports what a descendant that execs would "+
			"cost:\n%s", report(roots))
	}
}

// A fork returns the child's pid in the forking process's own namespace, so
// an unreadable namespace means nothing it forks is observed - most of a
// per-connection forking server's traffic. The report says so.
func TestAProcessWhosePIDNamespaceCouldNotBeReadSaysSoBesideItsAttachment(t *testing.T) {
	unread := attempt()
	unread.Process.Namespace = admission.Namespace{}

	named := attempt()
	named.Process.Namespace = admission.Namespace{Device: 4, Inode: 4026531836}

	report := func(a attachment.Attempt) string {
		var out strings.Builder
		attachment.Of(rules([]process.Process{a.Process}),
			[]attachment.Observed{attachment.Describe(a)}).Report(&out)
		return out.String()
	}

	said := report(unread)
	if !strings.Contains(said, "forks") || !strings.Contains(said, "pid namespace could not be") {
		t.Errorf("the report does not say that what this process forks is unobserved:\n%s", said)
	}

	// The control: a process in its own, enumerated pid namespace is observed,
	// forks included.
	if strings.Contains(report(named), "forks") {
		t.Errorf("a process whose pid namespace was read is reported as one whose children "+
			"cannot be named:\n%s", report(named))
	}
}
