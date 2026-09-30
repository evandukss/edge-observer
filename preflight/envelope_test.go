package preflight_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/preflight"
	"github.com/evandukss/edge-observer/process"
)

// The envelope as start's check judges it on a host meeting every condition, in
// start's order. The names are start's own, which this package does not import.
func metEnvelope(selected []process.Process) []preflight.EnvelopeJudgment {
	return []preflight.EnvelopeJudgment{
		{Check: "payload_membership", Met: true, Detail: "pid 7 in /observer"},
		{Check: "execution_memory", Met: true, Detail: "/observer is a memory domain with memory.max 268435456"},
		{Check: "anonymous_swap", Met: true, Detail: "memory.swap.max and memory.swap.current are both zero"},
		{Check: "core_dumps", Met: true, Detail: "payload process dumpability is zero"},
		{Check: "participant_outside_envelope", Met: true, Detail: "1 participant outside payload envelope /observer"},
	}
}

// replacing is metEnvelope with the named condition's judgment replaced.
func replacing(check string, with ...preflight.EnvelopeJudgment) func([]process.Process) []preflight.EnvelopeJudgment {
	return func(selected []process.Process) []preflight.EnvelopeJudgment {
		var judged []preflight.EnvelopeJudgment
		for _, one := range metEnvelope(selected) {
			if one.Check == check {
				judged = append(judged, with...)
				continue
			}
			judged = append(judged, one)
		}
		return judged
	}
}

func envelopeStatuses(readiness preflight.Readiness) []string {
	var got []string
	for _, r := range readiness.Envelope {
		got = append(got, r.Check+"="+string(r.Status))
	}
	return got
}

func TestAHostWhoseEnvelopeHoldsIsReadyAndSaysSo(t *testing.T) {
	c := meeting(t)
	readiness := assess(c, c.live())

	if readiness.Verdict != preflight.Ready {
		t.Fatalf("Verdict = %q, want READY: %+v %+v", readiness.Verdict, readiness.Requirements, readiness.Envelope)
	}
	want := []string{"payload_membership=met", "execution_memory=met", "anonymous_swap=met", "core_dumps=met",
		"participant_outside_envelope=met"}
	if got := envelopeStatuses(readiness); !slices.Equal(got, want) {
		t.Errorf("envelope = %v, want %v", got, want)
	}
	for _, r := range readiness.Envelope {
		if r.Name != preflight.ExecutionEnvelope || r.Declared == "" || r.Found == "" {
			t.Errorf("an envelope requirement without its name, declaration or evidence: %+v", r)
		}
	}
}

// The envelope is judged beside the host's requirements, never among them.
func TestTheEnvelopeLeavesTheHostsRequirementsAsTheyAre(t *testing.T) {
	c := meeting(t)
	p := c.live()
	with := assess(c, p)
	c.host.Envelope = replacing("execution_memory", preflight.EnvelopeJudgment{Check: "execution_memory", Detail: "no cap"})
	without := assess(c, p)

	for _, readiness := range []preflight.Readiness{with, without} {
		var names []string
		for _, r := range readiness.Requirements {
			names = append(names, r.Name)
		}
		if want := append(slices.Clone(hostRequirements), preflight.TLSLibrary); !slices.Equal(names, want) {
			t.Errorf("requirements = %v, want %v", names, want)
		}
	}
}

func TestAParticipantInsideTheEnvelopeWithholdsReadyAndIsNamed(t *testing.T) {
	c := meeting(t)
	detail := `participant pid 43319 start 12462608 cgroup "/docker/a" is not an identified process outside payload envelope "/docker/a"`
	c.host.Envelope = replacing("participant_outside_envelope",
		preflight.EnvelopeJudgment{Check: "participant_outside_envelope", PID: 43319, Detail: detail})

	readiness := assess(c, c.live())

	if readiness.Verdict != preflight.NotReady {
		t.Errorf("Verdict = %q, want NOT READY", readiness.Verdict)
	}
	var missing []preflight.Requirement
	for _, r := range readiness.Envelope {
		if r.Status != preflight.Met {
			missing = append(missing, r)
		}
	}
	if len(missing) != 1 || missing[0].Status != preflight.Missing || missing[0].Check != "participant_outside_envelope" ||
		missing[0].PID != 43319 || !strings.Contains(missing[0].Found, detail) {
		t.Errorf("not met: %+v, want only participant_outside_envelope for pid 43319, missing, carrying start's words", missing)
	}
}

func TestEveryUnmetConditionIsNamed(t *testing.T) {
	c := meeting(t)
	c.host.Envelope = func(selected []process.Process) []preflight.EnvelopeJudgment {
		judged := metEnvelope(selected)
		judged[1] = preflight.EnvelopeJudgment{Check: "execution_memory", Detail: "memory.max is max"}
		judged[2] = preflight.EnvelopeJudgment{Check: "anonymous_swap", Detail: "memory.swap.max is max"}
		return judged
	}

	readiness := assess(c, c.live())

	want := []string{"payload_membership=met", "execution_memory=missing", "anonymous_swap=missing", "core_dumps=met",
		"participant_outside_envelope=met"}
	if got := envelopeStatuses(readiness); !slices.Equal(got, want) {
		t.Errorf("envelope = %v, want %v", got, want)
	}
	if readiness.Verdict != preflight.NotReady {
		t.Errorf("Verdict = %q, want NOT READY", readiness.Verdict)
	}
}

func TestAnEnvelopeConditionThatCouldNotBeReadIsIndeterminate(t *testing.T) {
	c := meeting(t)
	c.host.Envelope = func([]process.Process) []preflight.EnvelopeJudgment {
		return []preflight.EnvelopeJudgment{{Check: "execution_memory", Unreadable: true, Detail: "memory.max: permission denied"}}
	}

	readiness := assess(c, c.live())

	if got := envelopeStatuses(readiness); !slices.Equal(got, []string{"execution_memory=indeterminate"}) {
		t.Errorf("envelope = %v, want only execution_memory indeterminate", got)
	}
	if readiness.Verdict != preflight.Undetermined {
		t.Errorf("Verdict = %q, want INDETERMINATE", readiness.Verdict)
	}
}

// A host whose envelope nobody judged is not cleared, whatever else it meets.
func TestAnEnvelopeNobodyJudgedWithholdsReady(t *testing.T) {
	for _, envelope := range map[string]func([]process.Process) []preflight.EnvelopeJudgment{
		"nil":            nil,
		"judged_nothing": func([]process.Process) []preflight.EnvelopeJudgment { return nil },
	} {
		c := meeting(t)
		c.host.Envelope = envelope

		readiness := assess(c, c.live())

		if readiness.Verdict != preflight.Undetermined {
			t.Errorf("Verdict = %q, want INDETERMINATE", readiness.Verdict)
		}
		if len(readiness.Envelope) != 1 || readiness.Envelope[0].Status != preflight.Indeterminate ||
			readiness.Envelope[0].Found == "" {
			t.Errorf("envelope = %+v, want one indeterminate requirement saying why", readiness.Envelope)
		}
	}
}

func TestTheEnvelopeIsJudgedForExactlyTheSelectedProcesses(t *testing.T) {
	c := meeting(t)
	var asked []process.Process
	c.host.Envelope = func(selected []process.Process) []preflight.EnvelopeJudgment {
		asked = slices.Clone(selected)
		return metEnvelope(selected)
	}
	selected := []process.Process{c.live(), {PID: 404}}

	assess(c, selected...)

	if len(asked) != 2 || asked[0].PID != selected[0].PID || asked[1].PID != 404 {
		t.Errorf("the envelope was judged for %+v, want exactly %+v", asked, selected)
	}
}
