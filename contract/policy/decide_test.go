package policy_test

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/policy"
)

// caseCount is how many worked cases testdata/cases holds. It is asserted
// before any case is read, so a glob that matched nothing cannot pass.
const caseCount = 20

type workedCase struct {
	Purpose                  string   `json:"purpose"`
	WithoutEnforcementPoints []string `json:"without_enforcement_points"`
	WithoutSinkFacts         []string `json:"without_sink_facts"`
	Documents                []struct {
		Source   policy.Source   `json:"source"`
		Document json.RawMessage `json:"document"`
	} `json:"documents"`
	Expected struct {
		DecodeRefused bool                 `json:"decode_refused"`
		Findings      []expectedFinding    `json:"findings"`
		Activations   []expectedActivation `json:"activations"`
	} `json:"expected"`
}

type expectedFinding struct {
	Declaration      string             `json:"declaration"`
	Disposition      policy.Disposition `json:"disposition"`
	Reason           policy.Reason      `json:"reason"`
	EnforcementPoint string             `json:"enforcement_point"`
	SinkFacts        *policy.Sink       `json:"sink_facts"`
	Pipelines        []string           `json:"pipelines"`
	Limitation       string             `json:"limitation"`
}

type expectedActivation struct {
	Pipeline    string   `json:"pipeline"`
	Activates   bool     `json:"activates"`
	RefusedBy   []string `json:"refused_by"`
	Limitations []string `json:"limitations"`
}

// strict decodes the way the notation is defined: a member the vocabulary does
// not define is an error, not an ignored key.
func strict(t *testing.T, content []byte, into any) error {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	return decoder.Decode(into)
}

func inventory(t *testing.T) policy.Inventory {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", "inventory.json"))
	if err != nil {
		t.Fatalf("read the inventory: %v", err)
	}
	var read policy.Inventory
	if err := strict(t, content, &read); err != nil {
		t.Fatalf("decode the inventory: %v", err)
	}
	if len(read.Pipelines) != 2 || len(read.EnforcementPoints) != 8 {
		t.Fatalf("wiring, not the vocabulary: the inventory holds %d pipelines and %d enforcement points "+
			"where 2 and 8 are written, so no case below measures what it says", len(read.Pipelines), len(read.EnforcementPoints))
	}
	return read
}

func cases(t *testing.T) map[string]workedCase {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "cases", "*.json"))
	if err != nil {
		t.Fatalf("glob the cases: %v", err)
	}
	if len(paths) != caseCount {
		t.Fatalf("wiring, not the vocabulary: %d case files where %d are written", len(paths), caseCount)
	}
	read := map[string]workedCase{}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var one workedCase
		if err := strict(t, content, &one); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		if len(one.Documents) == 0 {
			t.Fatalf("wiring, not the vocabulary: %s declares no document", path)
		}
		read[strings.TrimSuffix(filepath.Base(path), ".json")] = one
	}
	return read
}

// loaded decodes a case's documents, reporting whether any was refused as a
// document the notation does not define.
func loaded(t *testing.T, one workedCase) ([]policy.Loaded, bool) {
	t.Helper()
	var documents []policy.Loaded
	for _, raw := range one.Documents {
		var document policy.Document
		if err := strict(t, raw.Document, &document); err != nil {
			return nil, true
		}
		documents = append(documents, policy.Loaded{Source: raw.Source, Document: document})
	}
	return documents, false
}

func withoutSinks(base map[string]policy.Sink, names []string) map[string]policy.Sink {
	kept := map[string]policy.Sink{}
	for name, facts := range base {
		if !slices.Contains(names, name) {
			kept[name] = facts
		}
	}
	return kept
}

func without(base policy.Inventory, points []string) policy.Inventory {
	kept := map[string]policy.Limits{}
	for name, limits := range base.EnforcementPoints {
		if !slices.Contains(points, name) {
			kept[name] = limits
		}
	}
	base.EnforcementPoints = kept
	return base
}

func TestEveryWorkedCaseDecidesAsWritten(t *testing.T) {
	base := inventory(t)
	for name, one := range cases(t) {
		t.Run(name, func(t *testing.T) {
			for _, point := range one.WithoutEnforcementPoints {
				if _, present := base.EnforcementPoints[point]; !present {
					t.Fatalf("wiring, not the vocabulary: the case removes %s, which the inventory never had", point)
				}
			}
			documents, refused := loaded(t, one)
			if one.Expected.DecodeRefused {
				if !refused {
					t.Fatalf("a document with a member the vocabulary does not define decoded")
				}
				return
			}
			if refused {
				t.Fatalf("wiring, not the vocabulary: a document the case expects to be decided did not decode")
			}

			runtime := without(base, one.WithoutEnforcementPoints)
			for _, sink := range one.WithoutSinkFacts {
				if _, present := runtime.Sinks[sink]; !present {
					t.Fatalf("wiring, not the vocabulary: the case removes the facts of %s, which the inventory never had", sink)
				}
			}
			runtime.Sinks = withoutSinks(runtime.Sinks, one.WithoutSinkFacts)
			result := policy.Decide(documents, runtime)
			assertFindings(t, one.Expected.Findings, result.Findings)
			assertActivations(t, one.Expected.Activations, result.Activations)
		})
	}
}

func assertFindings(t *testing.T, expected []expectedFinding, actual []policy.Finding) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Errorf("%d findings where %d are expected: %+v", len(actual), len(expected), actual)
	}
	for index, want := range expected {
		if index >= len(actual) {
			t.Errorf("no finding for %s", want.Declaration)
			continue
		}
		got := actual[index]
		if got.Declaration != want.Declaration || got.Disposition != want.Disposition || got.Reason != want.Reason {
			t.Errorf("finding %d is %s %s %s, expected %s %s %s", index,
				got.Declaration, got.Disposition, got.Reason, want.Declaration, want.Disposition, want.Reason)
		}
		if !slices.Equal(got.Pipelines, want.Pipelines) {
			t.Errorf("%s reaches %v, expected %v", want.Declaration, got.Pipelines, want.Pipelines)
		}
		if got.Limitation != want.Limitation {
			t.Errorf("%s carries the limitation %q, expected %q", want.Declaration, got.Limitation, want.Limitation)
		}
		if want.Disposition != policy.Accept {
			if got.Scope != nil {
				t.Errorf("%s is not an acceptance and names a scope: %+v", want.Declaration, *got.Scope)
			}
			continue
		}
		if got.Scope == nil {
			t.Errorf("%s is accepted without naming its scope", want.Declaration)
			continue
		}
		if got.Scope.EnforcementPoint != want.EnforcementPoint || got.Scope.Covers == "" || got.Scope.DoesNotCover == "" {
			t.Errorf("%s names the scope %+v, expected enforcement point %s with both halves stated",
				want.Declaration, *got.Scope, want.EnforcementPoint)
		}
		if want.SinkFacts != nil && (got.Scope.Sink == nil || *got.Scope.Sink != *want.SinkFacts) {
			t.Errorf("%s names the sink facts %+v, expected %+v", want.Declaration, got.Scope.Sink, *want.SinkFacts)
		}
	}
}

func assertActivations(t *testing.T, expected []expectedActivation, actual []policy.Activation) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("%d activations where %d are expected: %+v", len(actual), len(expected), actual)
	}
	for index, want := range expected {
		got := actual[index]
		if got.Pipeline != want.Pipeline || got.Activates != want.Activates ||
			!slices.Equal(got.RefusedBy, want.RefusedBy) || !slices.Equal(got.Limitations, want.Limitations) {
			t.Errorf("activation %d is %+v, expected %+v", index, got, want)
		}
	}
}

// The set of cases is the claim that the vocabulary is covered, so it is held to
// covering every disposition and every reason: a reason no case reaches is one
// nothing shows the procedure can give.
func TestTheWorkedCasesReachEveryDispositionAndReason(t *testing.T) {
	dispositions := map[policy.Disposition]bool{}
	reasons := map[policy.Reason]bool{}
	for _, one := range cases(t) {
		for _, finding := range one.Expected.Findings {
			dispositions[finding.Disposition] = true
			reasons[finding.Reason] = true
		}
	}
	for _, disposition := range []policy.Disposition{policy.Accept, policy.RefuseActivation, policy.AllowTrusted, policy.RefuseAssurance} {
		if !dispositions[disposition] {
			t.Errorf("no worked case reaches the disposition %s", disposition)
		}
	}
	for _, reason := range policy.Reasons {
		if !reasons[reason] {
			t.Errorf("no worked case reaches the reason %s", reason)
		}
	}
	if len(reasons) != len(policy.Reasons) {
		t.Errorf("the cases name %d reasons and the vocabulary has %d", len(reasons), len(policy.Reasons))
	}
}

// An operator's approval of trusted behaviour must not swallow a mandatory
// requirement the operator never withdrew. The second configuration is the first
// with exactly one requirement added, so the requirement is the only thing that
// can explain a different result.
func TestAnApprovalNeverDowngradesAMandatoryRequirement(t *testing.T) {
	runtime := without(inventory(t), []string{"sink_admission"})
	approved := cases(t)["allow-trusted-approved"]
	documents, refused := loaded(t, approved)
	if refused {
		t.Fatal("wiring, not the vocabulary: the approved case did not decode")
	}

	alone := policy.Decide(documents, runtime)
	if len(alone.Activations) != 2 || !alone.Activations[0].Activates || len(alone.Activations[0].Limitations) != 1 {
		t.Fatalf("wiring, not the property: without the requirement the approved claim does not activate "+
			"capture with its limitation, so nothing below measures a downgrade: %+v", alone.Activations)
	}

	intact := slices.Clone(documents)
	intact[1].Document.Requirements = append(intact[1].Document.Requirements, policy.Requirement{
		ID:            "r-structure",
		Target:        policy.Target{Kind: "sink", Name: "local-account"},
		Operation:     "require_output_structure",
		Parameters:    map[string]any{"structure": "exchange-record"},
		FailureAction: policy.DropAndAccount,
	})
	both := policy.Decide(intact, runtime)

	var requirement, claim *policy.Finding
	for index := range both.Findings {
		switch both.Findings[index].Declaration {
		case "r-structure":
			requirement = &both.Findings[index]
		case "c-redacts":
			claim = &both.Findings[index]
		}
	}
	if requirement == nil || requirement.Disposition != policy.RefuseAssurance || requirement.Reason != policy.NoEnforcementPoint {
		t.Errorf("the mandatory requirement with no enforcement point is %+v, expected refuse_assurance no_enforcement_point", requirement)
	}
	if claim == nil || claim.Disposition != policy.AllowTrusted {
		t.Errorf("the approved claim is %+v; approving it is still allowed, it just cannot activate anything", claim)
	}
	for _, activation := range both.Activations {
		if activation.Activates {
			t.Errorf("%s activates with a mandatory requirement standing that the runtime cannot enforce", activation.Pipeline)
		}
	}
}

// A processor name that is both a slot and a component could mean either, and
// an ordering that silently picked one would enforce something nobody declared.
func TestAProcessorNamingBothASlotAndAComponentIsRefused(t *testing.T) {
	runtime := inventory(t)
	runtime.Components = maps.Clone(runtime.Components)
	runtime.Components["capture.classify"] = policy.Component{Execution: policy.External, InputFields: []string{"message.body"}}
	capture := runtime.Pipelines["capture"]
	capture.Components = append(slices.Clone(capture.Components), "capture.classify")
	runtime.Pipelines = maps.Clone(runtime.Pipelines)
	runtime.Pipelines["capture"] = capture

	decide := func(processor string) policy.Finding {
		result := policy.Decide([]policy.Loaded{{Source: policy.Operator, Document: policy.Document{
			Vocabulary: policy.Vocabulary,
			Requirements: []policy.Requirement{{
				ID: "r-order", Target: policy.Target{Kind: "sink", Name: "local-account"}, Operation: "order_before",
				Parameters: map[string]any{"processor": processor}, FailureAction: policy.StopPipeline,
			}},
		}}}, runtime)
		return result.Findings[0]
	}
	if control := decide("capture.redact"); control.Disposition != policy.Accept {
		t.Fatalf("wiring, not the property: an ordering on an unambiguous slot is %s %s", control.Disposition, control.Reason)
	}
	got := decide("capture.classify")
	if got.Declaration != "r-order" || got.Disposition != policy.RefuseActivation || got.Reason != policy.IncompatibleInterface ||
		!slices.Equal(got.Pipelines, []string{"capture"}) || got.Scope != nil {
		t.Fatalf("a processor naming both a slot and a component is %+v, expected r-order refuse_activation "+
			"incompatible_interface over [capture] with no scope", got)
	}
}

// VOCABULARY.md is the specification and Operations is it executed. The tables
// and the procedure are read out of the document and held against the code, so
// the two cannot say different things about a name.
func TestTheSpecificationAndTheVocabularyAgree(t *testing.T) {
	content, err := os.ReadFile("VOCABULARY.md")
	if err != nil {
		t.Fatalf("read the specification: %v", err)
	}
	quoted := regexp.MustCompile("`([a-z_]+)`")
	names := func(cell string) []string {
		var found []string
		for _, match := range quoted.FindAllStringSubmatch(cell, -1) {
			found = append(found, match[1])
		}
		slices.Sort(found)
		return slices.Compact(found)
	}

	// A row belongs to the table whose header it sits under, and a line that is
	// not a row ends the table.
	operations := map[string][]string{}
	scopes := map[string][]string{}
	table := ""
	for _, line := range strings.Split(string(content), "\n") {
		switch {
		case strings.HasPrefix(line, "| operation | target kinds |"):
			table = "operations"
			continue
		case strings.HasPrefix(line, "| operation | covers |"):
			table = "scopes"
			continue
		case !strings.HasPrefix(line, "|"):
			table = ""
			continue
		}
		cells := strings.Split(line, "|")
		if !strings.HasPrefix(strings.TrimSpace(cells[1]), "`") {
			continue
		}
		name := strings.Trim(strings.TrimSpace(cells[1]), "`")
		switch {
		case table == "operations" && len(cells) == 7:
			operations[name] = cells[2:6]
		case table == "scopes" && len(cells) == 5:
			scopes[name] = []string{strings.TrimSpace(cells[2]), strings.TrimSpace(cells[3])}
		}
	}
	if len(operations) != len(policy.Operations) || len(scopes) != len(policy.Operations) {
		t.Fatalf("the specification tables hold %d operations and %d scopes, and the vocabulary %d",
			len(operations), len(scopes), len(policy.Operations))
	}

	for _, operation := range policy.Operations {
		row, present := operations[operation.Name]
		if !present {
			t.Errorf("%s is not in the specification's operation table", operation.Name)
			continue
		}
		var kinds, points []string
		for kind, point := range operation.EnforcementPoints {
			kinds = append(kinds, kind)
			points = append(points, point)
		}
		for _, check := range []struct {
			what       string
			cell, code []string
		}{
			{"target kinds", names(row[0]), kinds},
			{"enforcement points", names(row[2]), points},
			{"failure actions", names(row[3]), operation.FailureActions},
		} {
			slices.Sort(check.code)
			if !slices.Equal(check.cell, slices.Compact(check.code)) {
				t.Errorf("%s: the specification names the %s %v and the vocabulary %v", operation.Name, check.what, check.cell, check.code)
			}
		}
		var parameters []string
		for _, parameter := range operation.Parameters {
			parameters = append(parameters, parameter.Name)
		}
		slices.Sort(parameters)
		cell := names(row[1])
		for _, parameter := range parameters {
			if !slices.Contains(cell, parameter) {
				t.Errorf("%s: the specification does not name the parameter %s", operation.Name, parameter)
			}
		}

		scope := scopes[operation.Name]
		if scope == nil || scope[0] != operation.Covers || scope[1] != operation.DoesNotCover {
			t.Errorf("%s: the specification's scope %q does not match the vocabulary's %q and %q",
				operation.Name, scope, operation.Covers, operation.DoesNotCover)
		}
	}

	given := regexp.MustCompile(`(?m)(?:else (?:refuse_activation|refuse_assurance)|accept|allow_trusted) ([a-z_]+)`)
	stated := map[string]bool{}
	for _, match := range given.FindAllStringSubmatch(string(content), -1) {
		stated[match[1]] = true
	}
	for _, reason := range policy.Reasons {
		if !stated[string(reason)] {
			t.Errorf("the procedure never gives the reason %s", reason)
		}
	}
	for reason := range stated {
		if !slices.Contains(policy.Reasons, policy.Reason(reason)) {
			t.Errorf("the procedure gives the reason %s, which the vocabulary does not have", reason)
		}
	}
}
