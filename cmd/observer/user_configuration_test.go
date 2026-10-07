package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

// written is the contract's no-rules example with these members written in
// at the top level as given, in place of any the example has, and written
// where the program reads it.
func written(t *testing.T, members string) string {
	t.Helper()
	content, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatal(err)
	}
	var base, replaced map[string]json.RawMessage
	if err := json.Unmarshal(content, &base); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte("{"+members+"}"), &replaced); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	for key := range replaced {
		delete(base, key)
	}
	encoded, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if members != "" {
		text = strings.TrimSuffix(text, "}") + ", " + members + "}"
	}
	path := filepath.Join(t.TempDir(), "observer.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A misspelled key, one in another case, and one written twice are each
// refused by the program naming the key; the corrected file activates.
func TestAMisspelledKeyIsRefusedByNameAndTheCorrectedFileActivates(t *testing.T) {
	corrected := `"remove": {"headers": ["authorization"]}`
	var out bytes.Buffer
	if err := run([]string{"dry-run", written(t, corrected)}, &out); err != nil {
		t.Fatalf("wiring, not the property: the corrected file is refused: %v", err)
	}
	var planned account.Account
	if err := json.Unmarshal(out.Bytes(), &planned); err != nil || planned.Policy.Revision == "" {
		t.Fatalf("the corrected file printed no plan: %v\n%s", err, out.Bytes())
	}
	for _, one := range []struct {
		name, members, key string
		reason             config.Reason
	}{
		{"misspelled at the top", `"remvoe": {"headers": ["authorization"]}`, "remvoe", config.UnknownKey},
		{"misspelled inside remove", `"remove": {"remvoe": ["authorization"]}`, "remove.remvoe", config.UnknownKey},
		{"in another case", `"Remove": {"headers": ["authorization"]}`, "Remove", config.UnknownKey},
		{"written twice", `"remove": {"headers": [], "headers": ["authorization"]}`, "remove.headers", config.DuplicateKey},
	} {
		t.Run(one.name, func(t *testing.T) {
			var out bytes.Buffer
			err := run([]string{"dry-run", written(t, one.members)}, &out)
			var refused *policy.Refused
			if !errors.As(err, &refused) {
				t.Fatalf("answered %v, want the reader's refusal", err)
			}
			if !slices.ContainsFunc(refused.Findings, func(f config.Finding) bool {
				return f.Document == "configuration" && f.Subject == one.key && f.Reason == one.reason
			}) || !strings.Contains(err.Error(), one.key) {
				t.Errorf("refused as %v, want %s naming %s", err, one.reason, one.key)
			}
			if out.Len() != 0 {
				t.Errorf("a refused file printed a plan:\n%s", out.Bytes())
			}
		})
	}
}

// Reload adds a watch entry and applies nothing else: a mask value changed in
// the configuration is a processing change, which a restart applies.
func TestAReloadAddsAWatchEntryAndRefusesAChangedMask(t *testing.T) {
	mask := func(value string) string { return `"mask": {"headers": {"x-api-key": "` + value + `"}}` }
	current, err := loadProcessing(written(t, mask("withheld")))
	if err != nil {
		t.Fatalf("the configuration in force was refused: %v", err)
	}
	grown, err := loadProcessing(written(t, mask("withheld")+
		`, "watch": [{"name": "api-server", "exe": "/usr/local/bin/api-server", "args": ["--listen", "8443"], "children": "all"},
		{"name": "worker", "exe": "/usr/bin/worker"}]`))
	if err != nil {
		t.Fatalf("the grown configuration was refused: %v", err)
	}
	if added, why := additive(current, grown); why != "" || len(added) != 1 || added[0].Name != "worker" {
		t.Fatalf("a watch entry added answered %v %q, want the entry added", added, why)
	}
	changed, err := loadProcessing(written(t, mask("masked")))
	if err != nil {
		t.Fatalf("the changed configuration was refused outright: %v", err)
	}
	if added, why := additive(current, changed); !strings.Contains(why, "changes processing -") || len(added) != 0 {
		t.Errorf("a changed mask value answered %v %q, want a processing change a restart applies", added, why)
	}
}

// Each children answer is the mode the account states for its target.
func TestTheAccountStatesEachTargetsChildrenAnswer(t *testing.T) {
	var out bytes.Buffer
	path := written(t, `"watch": [{"name": "all", "exe": "/usr/bin/a", "children": "all"},
		{"name": "existing", "exe": "/usr/bin/b", "children": "existing"},
		{"name": "none", "exe": "/usr/bin/c", "children": "none"}]`)
	if err := run([]string{"dry-run", path}, &out); err != nil {
		t.Fatalf("the dry run refused: %v", err)
	}
	var planned account.Account
	if err := json.Unmarshal(out.Bytes(), &planned); err != nil {
		t.Fatalf("the dry run printed no account: %v", err)
	}
	want := map[string]admission.Mode{"all": admission.ModeFollow, "existing": admission.ModeExisting,
		"none": admission.ModeNone}
	if len(planned.Targets) != len(want) {
		t.Fatalf("wiring, not the property: the account states %d targets, want %d", len(planned.Targets), len(want))
	}
	for _, target := range planned.Targets {
		mode := want[target.Name]
		answers := mode.Answers()
		if target.Mode != mode.String() || target.Answers.Existing != answers.Existing ||
			target.Answers.Future != answers.Future {
			t.Errorf("target %s is stated as mode %q with %+v, want %q", target.Name, target.Mode, target.Answers, mode.String())
		}
	}
}

// A session sealed before this observer carries processing.stopped_pipelines,
// which the account no longer has. Inspect still reads it, as JSON and as text.
func TestASessionSealedByAnEarlierObserverStillInspects(t *testing.T) {
	f := processingController(t)
	f.liveControl(t)
	f.halt(t)
	if err := f.finish(&logger{}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.d.directory, sealedName)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var sealed map[string]any
	if err := json.Unmarshal(content, &sealed); err != nil {
		t.Fatal(err)
	}
	processing, ok := sealed["processing"].(map[string]any)
	if !ok {
		t.Fatalf("wiring, not the property: the sealed account carries no processing block: %s", content)
	}
	processing["stopped_pipelines"] = []string{config.ExchangesPipeline}
	earlier, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, earlier, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"inspect", f.d.directory}, &out); err != nil {
		t.Fatalf("PROPERTY: an account sealed by an earlier observer is not read: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("stopped_pipelines")) {
		t.Fatalf("wiring, not the property: inspect printed another account than the earlier one:\n%s", out.Bytes())
	}
	out.Reset()
	if err := run([]string{"inspect", f.d.directory, "--text"}, &out); err != nil {
		t.Fatalf("PROPERTY: an account sealed by an earlier observer is not rendered: %v", err)
	}
}
