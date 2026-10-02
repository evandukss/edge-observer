package account

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	observed "github.com/evandukss/edge-observer/account"
)

// withProcessing is the example account with processing carried, holding the
// ids issued and one extension's entry changed by change.
func withProcessing(t *testing.T, change func(entry map[string]any)) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(up, "examples", "bundle", "account.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	counts := func(vocabulary []string) map[string]any {
		out := map[string]any{}
		for _, key := range vocabulary {
			out[key] = "0"
		}
		return out
	}
	entry := map[string]any{
		"effects": observed.ExtensionEffects, "fields": []string{"request.line", "response.line"}, "timeout_ms": "250",
		"considered": "3", "changed": "0", "unchanged": "3", "failed": "0", "pending": "0",
		"failed_by": counts(observed.ExtensionFailureReasons), "retired_by": counts(observed.ExtensionRetirementCauses),
		"restarts": "0", "state_resets": "0", "late": "0", "duplicate": "0",
		"derived_written": "1", "derived_bytes": "120", "derived_refused": "0",
		"derived_refused_by": counts(observed.DerivedRefusalReasons), "stderr_dropped": "0",
	}
	change(entry)
	document["processing"] = map[string]any{"state": "carried", "pipelines": []any{}, "exchange_ids": "3",
		"extensions": map[string]any{"inventory": entry}}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// An extension's entry is read whole: its label, its fields in the protocol's
// order, and every member of each vocabulary, each present once. Each refusal
// is one change from an entry that reads.
func TestAnExtensionsEntryIsReadAgainstTheProtocolsVocabulary(t *testing.T) {
	if _, findings, _ := readAccount("account.json", withProcessing(t, func(map[string]any) {})); len(findings) != 0 {
		t.Fatalf("wiring, not the property: the entry that should read is refused: %+v", findings)
	}
	at := "processing.extensions.inventory"
	for _, one := range []struct {
		name   string
		change func(entry map[string]any)
		at     string
		reason Reason
	}{
		{"another label", func(e map[string]any) { e["effects"] = "observer_enforced" }, at + ".effects", ValueNotInContract},
		{"a field out of order", func(e map[string]any) { e["fields"] = []string{"response.line", "request.line"} },
			at + ".fields[1]", ValueNotInContract},
		{"a field that is not one", func(e map[string]any) { e["fields"] = []string{"request.method"} },
			at + ".fields[0]", ValueNotInContract},
		{"a failure reason missing", func(e map[string]any) { delete(e["failed_by"].(map[string]any), "timeout") },
			at + ".failed_by.timeout", RequiredMemberAbsent},
		{"a failure reason the protocol does not have", func(e map[string]any) {
			e["failed_by"].(map[string]any)["slow"] = "1"
		}, at + ".failed_by.slow", ValueNotInContract},
		{"a retirement cause missing", func(e map[string]any) { delete(e["retired_by"].(map[string]any), "flood") },
			at + ".retired_by.flood", RequiredMemberAbsent},
		{"start_failed missing", func(e map[string]any) { delete(e["retired_by"].(map[string]any), "start_failed") },
			at + ".retired_by.start_failed", RequiredMemberAbsent},
		{"a derived refusal missing", func(e map[string]any) {
			delete(e["derived_refused_by"].(map[string]any), "budget")
		}, at + ".derived_refused_by.budget", RequiredMemberAbsent},
		{"a count that is not decimal", func(e map[string]any) { e["considered"] = "three" }, at + ".considered",
			ValueNotInContract},
		{"a count absent", func(e map[string]any) { delete(e, "pending") }, at + ".pending", RequiredMemberAbsent},
	} {
		t.Run(one.name, func(t *testing.T) {
			_, findings, _ := readAccount("account.json", withProcessing(t, one.change))
			if !slices.ContainsFunc(findings, func(f Finding) bool { return f.At == one.at && f.Reason == one.reason }) {
				t.Errorf("refused with %+v, want %s at %s", findings, one.reason, one.at)
			}
		})
	}

	// An extension named outside the configuration's rule.
	content := withProcessing(t, func(map[string]any) {})
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	processing := document["processing"].(map[string]any)
	processing["extensions"] = map[string]any{"Inventory": processing["extensions"].(map[string]any)["inventory"]}
	content, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	_, findings, _ := readAccount("account.json", content)
	if !slices.ContainsFunc(findings, func(f Finding) bool {
		return f.At == "processing.extensions.Inventory" && f.Reason == ValueNotInContract
	}) {
		t.Errorf("an extension named Inventory was refused with %+v, want %s", findings, ValueNotInContract)
	}
}

// A configured extension the processing block holds no counts for, and counts
// for one nobody configured, are refused rather than filled in.
func TestAnExtensionsCountsAreNeverFilledIn(t *testing.T) {
	configured := []observed.Extension{{Name: "inventory", Fields: []string{"request.line"}, TimeoutMS: 250,
		Effects: observed.ExtensionEffects}}
	if _, err := extensionsOf(configured, []observed.ExtensionCounts{observed.NoCounts("inventory")}); err != nil {
		t.Fatalf("wiring, not the property: matching counts were refused: %v", err)
	}
	if _, err := extensionsOf(configured, nil); err == nil {
		t.Error("a configured extension with no counts was projected")
	}
	if _, err := extensionsOf(nil, []observed.ExtensionCounts{observed.NoCounts("inventory")}); err == nil {
		t.Error("counts for an extension nobody configured were projected")
	}
}
