package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	protected "github.com/evandukss/edge-observer/activation"
	"github.com/evandukss/edge-observer/contract/config"
)

// declared is the listing every surface must carry for the extension
// withExtension configures.
var declared = account.Extension{Name: "inventory", Fields: []string{config.FieldRequestLine}, TimeoutMS: 250,
	Effects: account.ExtensionEffects}

// declaredLine is how the text forms say it.
const declaredLine = "inventory: request.line; timeout 250 ms; extension-declared, not observer-enforced"

func listsDeclared(t *testing.T, where string, listed []account.Extension) {
	t.Helper()
	if len(listed) != 1 || listed[0].Name != declared.Name || !slices.Equal(listed[0].Fields, declared.Fields) ||
		listed[0].TimeoutMS != declared.TimeoutMS || listed[0].Effects != declared.Effects {
		t.Errorf("%s lists %+v, want %+v", where, listed, declared)
	}
}

// The dry run, preflight and the activation record each list a configured
// extension labelled extension-declared and not observer-enforced; without
// one, each lists none.
func TestEverySurfaceBeforeDataListsTheExtensionAsDeclared(t *testing.T) {
	path := withExtension(t, nil)
	without := withExtension(t, map[string]any{"extensions": []any{}})

	var planned account.Account
	for _, one := range []struct {
		path string
		want int
	}{{path, 1}, {without, 0}} {
		var out bytes.Buffer
		if err := run([]string{"dry-run", one.path}, &out); err != nil {
			t.Fatalf("wiring, not the property: the dry run refused: %v", err)
		}
		var read account.Account
		if err := json.Unmarshal(out.Bytes(), &read); err != nil || read.Policy.Revision == "" {
			t.Fatalf("wiring, not the property: the dry run printed no account: %v\n%s", err, out.Bytes())
		}
		if len(read.Extensions) != one.want {
			t.Fatalf("the dry run lists %d extensions, want %d", len(read.Extensions), one.want)
		}
		if one.want == 1 {
			listsDeclared(t, "the dry run", read.Extensions)
			planned = read
		}
	}
	var text bytes.Buffer
	if err := run([]string{"dry-run", path, "--text"}, &text); err != nil {
		t.Fatalf("wiring, not the property: the dry run refused: %v", err)
	}
	if !strings.Contains(text.String(), "extension  "+declaredLine+"\n") {
		t.Errorf("the dry run's text does not say %q:\n%s", declaredLine, text.String())
	}

	// Preflight answers NOT READY or INDETERMINATE here, where nothing it
	// selects can be observed; it prints its answer first either way.
	var out bytes.Buffer
	_ = run([]string{"preflight", path}, &out)
	var readiness struct {
		Verdict    string              `json:"verdict"`
		Extensions []account.Extension `json:"extensions"`
	}
	if err := json.Unmarshal(out.Bytes(), &readiness); err != nil || readiness.Verdict == "" {
		t.Fatalf("wiring, not the property: preflight printed no readiness: %v\n%s", err, out.Bytes())
	}
	listsDeclared(t, "preflight", readiness.Extensions)
	text.Reset()
	_ = run([]string{"preflight", path, "--text"}, &text)
	if !strings.Contains(text.String(), "EXTENSION      "+declaredLine+"\n") {
		t.Errorf("preflight's text does not say %q:\n%s", declaredLine, text.String())
	}

	// The activation record, from the account start plans.
	content, err := json.Marshal(activated("0123456789abcdef", 4242, time.Now(), planned, protected.Posture{}))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Record     string              `json:"record"`
		Extensions []account.Extension `json:"extensions"`
	}
	if err := json.Unmarshal(content, &record); err != nil || record.Record != "activation-completed" {
		t.Fatalf("wiring, not the property: no activation record: %v\n%s", err, content)
	}
	listsDeclared(t, "the activation record", record.Extensions)
}
