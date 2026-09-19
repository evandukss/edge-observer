package admission_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/admission"
)

func instance() admission.Instance {
	return admission.Instance{
		Namespace:  admission.Namespace{Device: 4, Inode: 4026531836},
		PID:        812,
		Start:      admission.Determinate(9911),
		Generation: 3,
		Executable: "/usr/bin/php",
	}
}

func TestAStartNobodyCouldReadIsNotAStartOfZero(t *testing.T) {
	unread := admission.Indeterminate()
	if unread.Determined {
		t.Fatal("an unread start identity reports itself as read")
	}
	// Started at tick zero and unreadable are different answers.
	atBoot := admission.Determinate(0)
	if unread == atBoot {
		t.Error("an unread start identity and a start of zero are the same value, so a start " +
			"nobody could read is indistinguishable from a process that started at boot")
	}
	if !strings.Contains(unread.String(), "could not be read") {
		t.Errorf("an unread start describes itself as %q, which does not say it was not read",
			unread.String())
	}
}

func TestTheTwoGenerationAllocatorsCannotHandOutOneNumber(t *testing.T) {
	// A userspace generation must never be one the kernel can stamp.
	if !admission.KernelGenerations.FromKernel() {
		t.Error("the kernel's first generation does not report itself as the kernel's")
	}
	if (admission.KernelGenerations - 1).FromKernel() {
		t.Error("the last userspace generation reports itself as the kernel's, so the two " +
			"allocators share a number")
	}
	if admission.Generation(1).FromKernel() {
		t.Error("the first userspace generation reports itself as the kernel's")
	}
}

func TestAnInstanceWithNoNamespaceOrNoGenerationIsRefused(t *testing.T) {
	cases := map[string]func(admission.Instance) admission.Instance{
		"no namespace":  func(i admission.Instance) admission.Instance { i.Namespace = admission.Namespace{}; return i },
		"no pid":        func(i admission.Instance) admission.Instance { i.PID = 0; return i },
		"no generation": func(i admission.Instance) admission.Instance { i.Generation = 0; return i },
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			if err := damage(instance()).Validate(); !errors.Is(err, admission.ErrInvalid) {
				t.Errorf("an instance with %s validated: %v", name, err)
			}
		})
	}
	if err := instance().Validate(); err != nil {
		t.Errorf("a whole instance was refused: %v", err)
	}
}

func TestOneInstanceIsIdentifiedByItsKeyAndNotByEvidenceAboutIt(t *testing.T) {
	read := instance()
	unread := instance()
	unread.Start = admission.Indeterminate()
	unread.Executable = ""
	if !read.Same(unread) {
		t.Error("two records of one instance are different instances because one's start " +
			"identity could not be read, which would split that process's byte stream in two")
	}

	// The generation separates successive occupants of a pid, so it is identity.
	readmitted := instance()
	readmitted.Generation = 4
	if read.Same(readmitted) {
		t.Error("a readmission of the same number is the same instance, so a stale saved call " +
			"would be used for it")
	}

	elsewhere := instance()
	elsewhere.Namespace = admission.Namespace{Device: 4, Inode: 4026532500}
	if read.Same(elsewhere) {
		t.Error("the same number in two pid namespaces is one instance, which is the defect " +
			"the namespace is in the key to prevent")
	}
}

func TestAnEntryWithNoDescendantModeIsRefusedRatherThanGivenOne(t *testing.T) {
	if _, err := admission.ParseMode(""); !errors.Is(err, admission.ErrInvalid) {
		t.Error("an entry naming no descendant mode was accepted, so it got a mode nobody chose")
	}
	if _, err := admission.ParseMode("all"); !errors.Is(err, admission.ErrInvalid) {
		t.Error("an unknown descendant mode was accepted")
	}
	for text, want := range map[string]admission.Mode{
		"none":     admission.ModeNone,
		"existing": admission.ModeExisting,
		"follow":   admission.ModeFollow,
	} {
		got, err := admission.ParseMode(text)
		if err != nil || got != want {
			t.Errorf("%q parsed to %v, %v", text, got, err)
		}
		if got.String() != text {
			t.Errorf("%q round-trips to %q", text, got.String())
		}
	}
}

func TestEachModeAnswersAllFiveAndTheLifetimeRuleIsTheSameInAllThree(t *testing.T) {
	descendants := map[admission.Mode][2]bool{
		admission.ModeNone:     {false, false},
		admission.ModeExisting: {true, false},
		admission.ModeFollow:   {true, true},
	}
	for mode, want := range descendants {
		answers := mode.Answers()
		if answers.Existing != want[0] || answers.Future != want[1] {
			t.Errorf("%s answers existing=%v future=%v, want %v", mode, answers.Existing, answers.Future, want)
		}
		// One lifetime rule for all modes, so follow never narrows below existing.
		if answers.RootExit != admission.SurvivorsKeepTheirGrants {
			t.Errorf("%s does not leave a surviving descendant's grant alone when the root exits", mode)
		}
		if answers.Boundary != admission.ExecEndsTheGrant {
			t.Errorf("%s answers the boundary question with %v", mode, answers.Boundary)
		}
		if answers.Replacement != admission.ReplacementNeedsRestart {
			t.Errorf("%s answers the replacement question with %v", mode, answers.Replacement)
		}
	}

	// An entry with no mode answers nothing.
	unset := admission.ModeUnset.Answers()
	if unset.Existing || unset.Future {
		t.Error("an entry with no mode admits descendants")
	}
}

func TestAGrantByDescentNamesItsParentAndAGrantByTargetNamesItsTarget(t *testing.T) {
	byTarget := admission.Selection{
		Instance:   instance(),
		Kind:       admission.ByTarget,
		Provenance: admission.Provenance{Target: "api-server", Number: 1},
		Mode:       admission.ModeFollow,
	}
	if err := byTarget.Validate(); err != nil {
		t.Fatalf("a whole target selection was refused: %v", err)
	}
	if byTarget.Provenance.Inherited() {
		t.Error("a target match reports itself as inherited from a parent")
	}

	orphan := byTarget
	orphan.Kind = admission.ByDescent
	if err := orphan.Validate(); !errors.Is(err, admission.ErrInvalid) {
		t.Error("a grant by descent with no parent was accepted, so removing the parent's grant " +
			"could not find this one")
	}

	unnamed := byTarget
	unnamed.Provenance = admission.Provenance{}
	if err := unnamed.Validate(); !errors.Is(err, admission.ErrInvalid) {
		t.Error("a grant by target naming no target was accepted, so withdrawing that target " +
			"would leave it behind")
	}

	modeless := byTarget
	modeless.Mode = admission.ModeUnset
	if err := modeless.Validate(); !errors.Is(err, admission.ErrInvalid) {
		t.Error("a selection with no descendant mode was accepted")
	}
}

func TestPermissionAndAbilityAreReportedSeparately(t *testing.T) {
	// Follow is the configured permission; whether the observer can act on it is
	// a fact about the host, and the two must not be conflated.
	namespaced := admission.Selection{
		Instance:    instance(),
		Kind:        admission.ByTarget,
		Provenance:  admission.Provenance{Target: "worker", Number: 2},
		Mode:        admission.ModeFollow,
		Propagation: admission.CannotPropagate,
	}
	if err := namespaced.Validate(); err != nil {
		t.Fatalf("an instance that cannot propagate was refused: %v", err)
	}
	if !namespaced.Answers().Future {
		t.Error("an instance whose fork cannot be named here reports that the configuration " +
			"asked for no future descendants")
	}
	if !strings.Contains(namespaced.Propagation.String(), "forks can be named") {
		t.Errorf("the ability reads as %q", namespaced.Propagation.String())
	}
}
