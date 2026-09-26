package processing_test

import (
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	cp "github.com/evandukss/edge-observer/contract/policy"
)

// t20Refused asserts that a configuration is refused for one reason only.
func t20Refused(t *testing.T, reason config.Reason, requirements []cp.Requirement, pipelines ...config.Pipeline) []config.Finding {
	t.Helper()
	plan, findings := t20Compile(t, requirements, pipelines...)
	if plan != nil || len(findings) == 0 {
		t.Fatalf("PROPERTY: the configuration was accepted: %+v", plan)
	}
	for _, f := range findings {
		if f.Reason != reason || f.Subject == "" || f.Detail == "" {
			t.Fatalf("PROPERTY: %s was not the deciding rule: %+v", reason, findings)
		}
	}
	return findings
}

// t20Writes asserts that a configuration compiles, activates and writes one
// exchange from which the protected value is absent.
func t20Writes(t *testing.T, requirements []cp.Requirement, request, response string, pipelines ...config.Pipeline) {
	t.Helper()
	plan, findings := t20Compile(t, requirements, pipelines...)
	if plan == nil {
		t.Fatalf("wiring, not the property: the neighbour was refused: %+v", findings)
	}
	out := &outputLog{}
	w, store := worker(t, plan, out)
	enqueue(t, store, batch(t, 1, request, response))
	o := drain(t, w)
	if o.Written != uint64(len(plan.Routes())) || o.ProcessingFailures != 0 || o.Written == 0 {
		t.Fatalf("PROPERTY: the neighbour did not write every route: %+v", o)
	}
	for _, line := range out.lines {
		if !strings.Contains(string(line), t20Keep) {
			t.Fatalf("wiring, not the property: the permitted header did not reach %s", line)
		}
	}
	for _, a := range out.artifacts {
		for _, side := range []string{"request", "response"} {
			if strings.Contains(t20Body(t, a, side), t20Card) {
				t.Fatalf("PROPERTY: the neighbour kept the protected value in the %s body", side)
			}
		}
		if strings.Contains(a.Reconstruction.Exchanges[0].Request.Message.Target, t20Card) {
			t.Fatal("PROPERTY: the neighbour kept the protected value in the target")
		}
	}
}

func TestT20RefusalsBesideWorkingNeighbours(t *testing.T) {
	json := t20Post("/pay", "application/json", `{"card":{"number":"`+t20Card+`"},"other":"`+t20Other+`"}`)
	jsonResponse := t20Response("application/json", `{"card":{"number":"`+t20Card+`"}}`)
	both := `{"messages":["request","response"],`

	t.Run("route-missing-the-removal", func(t *testing.T) {
		requirement := []cp.Requirement{t20Requirement(config.JSONFieldPrefix + "/card/number")}
		findings := t20Refused(t, config.ExclusionNotEnforced, requirement,
			pipeline("exchanges", t20Slot("r", config.RemoveJSONFields, both+`"pointers":["/card/cvc"]}`)))
		if !strings.Contains(findings[0].Detail, "exclude") || !strings.Contains(findings[0].Subject, "exchanges") {
			t.Fatalf("PROPERTY: the refusal does not name the requirement and route: %+v", findings)
		}
		t20Writes(t, requirement, json, jsonResponse, pipeline("exchanges", t20Slot("r", config.RemoveJSONFields, both+`"pointers":["/card"]}`)))
	})
	t.Run("one-message-left-uncovered", func(t *testing.T) {
		requirement := []cp.Requirement{t20Requirement(config.JSONFieldPrefix + "/card/number")}
		findings := t20Refused(t, config.ExclusionNotEnforced, requirement,
			pipeline("exchanges", t20Slot("r", config.RemoveJSONFields, `{"messages":["request"],"pointers":["/card/number"]}`)))
		if !strings.Contains(findings[0].Detail, "response") {
			t.Fatalf("PROPERTY: the refusal does not name the uncovered message: %+v", findings)
		}
		t20Writes(t, requirement, json, jsonResponse, pipeline("exchanges",
			t20Slot("r", config.RemoveJSONFields, `{"messages":["request"],"pointers":["/card/number"]}`),
			t20Slot("s", config.RemoveBody, `{"messages":["response"]}`)))
	})
	t.Run("reduce-against-message-body", func(t *testing.T) {
		requirement := []cp.Requirement{t20Requirement(config.BodyField)}
		t20Refused(t, config.ExclusionNotEnforced, requirement,
			pipeline("exchanges", t20Slot("r", config.ReduceBodyToStructure, both[:len(both)-1]+`}`)))
		t20Writes(t, requirement, json, jsonResponse, pipeline("exchanges", t20Slot("r", config.RemoveBody, both[:len(both)-1]+`}`)))
	})
	t.Run("reduce-satisfies-body-values", func(t *testing.T) {
		t20Writes(t, []cp.Requirement{t20Requirement(config.BodyValuesField)}, json, jsonResponse,
			pipeline("exchanges", t20Slot("r", config.ReduceBodyToStructure, both[:len(both)-1]+`}`)))
	})
	t.Run("json-and-form-rules-on-one-route", func(t *testing.T) {
		jsonRule := t20Slot("json", config.RemoveJSONFields, `{"messages":["request"],"pointers":["/card"]}`)
		formRule := t20Slot("form", config.RemoveFormFields, `{"names":["card"]}`)
		findings := t20Refused(t, config.BodyGrammarConflict, nil, pipeline("exchanges", jsonRule, formRule))
		if findings[0].Subject != "pipeline:exchanges" {
			t.Fatalf("PROPERTY: the refusal does not name the pipeline: %+v", findings)
		}
		t20Refused(t, config.BodyGrammarConflict, nil, pipeline("exchanges", formRule, t20Slot("json", config.ReplaceJSONValues, `{"messages":["request"],"pointers":["/card"],"value":""}`)))
		t20Writes(t, nil, json, goodResponse, pipeline("json", jsonRule), pipeline("form", formRule))
	})
	t.Run("replace-against-a-removal", func(t *testing.T) {
		requirement := []cp.Requirement{t20Requirement(config.JSONFieldPrefix + "/card")}
		t20Refused(t, config.ExclusionNotEnforced, requirement,
			pipeline("exchanges", t20Slot("r", config.ReplaceJSONValues, both+`"pointers":["/card"],"value":"x"}`)))
		t20Writes(t, requirement, json, jsonResponse, pipeline("exchanges", t20Slot("r", config.RemoveJSONFields, both+`"pointers":["/card"]}`)))
	})
	t.Run("query-parameter-and-whole-query", func(t *testing.T) {
		requirement := []cp.Requirement{t20Requirement(config.QueryFieldPrefix + "card")}
		request := t20Get("/pay?card=" + t20Card)
		t20Refused(t, config.ExclusionNotEnforced, requirement,
			pipeline("exchanges", t20Slot("r", config.RemoveQueryParameters, `{"names":["cvc"]}`)))
		t20Writes(t, requirement, request, goodResponse, pipeline("exchanges", t20Slot("r", config.RemoveQueryParameters, `{"names":["card"]}`)))
		t20Writes(t, requirement, request, goodResponse, pipeline("exchanges", t20Slot("r", config.RemoveQuery, `{}`)))
	})
	t.Run("form-field-by-component", func(t *testing.T) {
		requirement := []cp.Requirement{t20Requirement(config.FormFieldPrefix + "card")}
		request := t20Post("/pay", "application/x-www-form-urlencoded", "card="+t20Card)
		t20Refused(t, config.ExclusionNotEnforced, requirement,
			pipeline("exchanges", t20Slot("r", config.RemoveBody, `{"messages":["response"]}`)))
		t20Writes(t, requirement, request, goodResponse, pipeline("exchanges", t20Slot("r", config.RemoveBody, `{"messages":["request"]}`)))
	})
	t.Run("failure-action-of-a-body-slot", func(t *testing.T) {
		requirement := []cp.Requirement{t20Requirement(config.BodyField)}
		stop := t20Slot("r", config.RemoveBody, both[:len(both)-1]+`}`)
		stop.OnFailure = config.OnFailureStopPipeline
		t20Refused(t, config.ExclusionFailureActionMismatch, requirement, pipeline("exchanges", stop))
		t20Writes(t, requirement, json, jsonResponse, pipeline("exchanges", t20Slot("r", config.RemoveBody, both[:len(both)-1]+`}`)))
	})
}
