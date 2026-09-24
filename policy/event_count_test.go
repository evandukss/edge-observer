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
	observer := member(document, "observer")
	observer["admitted_event_limit"] = 7
	observer["approved_output_bound_mib"] = 13
	read, err := policy.CompileProcessing([]byte(encoded(t, document)), nil)
	if err != nil || read.Processing == nil {
		t.Fatalf("positive event count refused: plan=%v error=%v", read.Processing, err)
	}
	eventCountViews(t, read, 7)
	if read.Settings.ApprovedOutputBoundMiB != 13 {
		t.Fatalf("event count changed the separate approved output allowance: %+v", read.Settings)
	}
}

func TestAdmittedEventCountDefaultsWithoutOutputCoupling(t *testing.T) {
	for _, outputMiB := range []int{1, 97} {
		document := processingDocument(t)
		observer := member(document, "observer")
		delete(observer, "admitted_event_limit")
		observer["approved_output_bound_mib"] = outputMiB
		read, err := policy.CompileProcessing([]byte(encoded(t, document)), nil)
		if err != nil || read.Processing == nil {
			t.Fatalf("default event count refused: plan=%v error=%v", read.Processing, err)
		}
		eventCountViews(t, read, 16384)
	}
}

func TestNonpositiveAdmittedEventCountRefusesAtItsOwnSetting(t *testing.T) {
	for _, count := range []int{0, -1} {
		document := processingDocument(t)
		observer := member(document, "observer")
		delete(observer, "admitted_event_limit")
		if read, err := policy.CompileProcessing([]byte(encoded(t, document)), nil); err != nil || read.Processing == nil {
			t.Fatalf("default neighbour refused: plan=%v error=%v", read.Processing, err)
		}
		observer["admitted_event_limit"] = count
		read, err := policy.CompileProcessing([]byte(encoded(t, document)), nil)
		var refused *policy.Refused
		if !errors.As(err, &refused) || read.Processing != nil {
			t.Fatalf("nonpositive event count %d not refused: plan=%v error=%v", count, read.Processing, err)
		}
		if len(refused.Findings) != 1 || refused.Findings[0].Subject != "observer.admitted_event_limit" || refused.Findings[0].Reason != config.Malformed {
			t.Fatalf("nonpositive event count %d did not reach its own setting check: %+v", count, refused.Findings)
		}
	}
}
