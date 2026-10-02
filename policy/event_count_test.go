package policy_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

func eventCountViews(t *testing.T, read policy.Policy, want float64) {
	t.Helper()
	for _, view := range []struct {
		name  string
		value any
		key   string
	}{
		{"compiled plan", read.Processing.Observer(), "admitted_event_limit"},
		{"activation settings", read.Settings, "AdmittedEventLimit"},
	} {
		content, err := json.Marshal(view.value)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(content, &fields); err != nil {
			t.Fatal(err)
		}
		if got := fields[view.key]; got != want {
			t.Errorf("%s event count = %v, want %v; view=%s", view.name, got, want, content)
		}
	}
}

func TestAdmittedEventCountReachesActivationAndPlan(t *testing.T) {
	document := processingDocument(t)
	limits := member(document, "limits")
	limits["events"] = 7
	read, err := policy.CompileProcessing([]byte(encoded(t, document)), "")
	if err != nil || read.Processing == nil {
		t.Fatalf("positive event count refused: plan=%v error=%v", read.Processing, err)
	}
	eventCountViews(t, read, 7)

}

func TestAdmittedEventCountDefaults(t *testing.T) {
	document := processingDocument(t)
	delete(member(document, "limits"), "events")
	read, err := policy.CompileProcessing([]byte(encoded(t, document)), "")
	if err != nil {
		t.Fatal(err)
	}
	eventCountViews(t, read, 16384)
}

func TestNonpositiveAdmittedEventCountRefusesAtItsOwnSetting(t *testing.T) {
	for _, count := range []int{0, -1} {
		document := processingDocument(t)
		limits := member(document, "limits")
		delete(limits, "events")
		if read, err := policy.CompileProcessing([]byte(encoded(t, document)), ""); err != nil || read.Processing == nil {
			t.Fatalf("default neighbour refused: plan=%v error=%v", read.Processing, err)
		}
		limits["events"] = count
		read, err := policy.CompileProcessing([]byte(encoded(t, document)), "")
		var refused *policy.Refused
		if !errors.As(err, &refused) || read.Processing != nil {
			t.Fatalf("nonpositive event count %d not refused: plan=%v error=%v", count, read.Processing, err)
		}
		if len(refused.Findings) != 1 || refused.Findings[0].Subject != "limits.events" || refused.Findings[0].Reason != config.InvalidValue {
			t.Fatalf("nonpositive event count %d did not reach its own setting check: %+v", count, refused.Findings)
		}
	}
}
