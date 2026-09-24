package policy_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

func processingDocument(t *testing.T) map[string]any {
	t.Helper()
	c := example(t)
	c["pipelines"] = []any{map[string]any{"name": "exchanges", "input": "reconstruction", "sinks": []any{"account"}, "slots": []any{
		map[string]any{"name": "remove", "implementation": config.RemoveHeaders, "configuration": map[string]any{"headers": []any{"authorization"}}, "on_failure": config.OnFailureDropAndAccount},
	}}}
	return c
}
func TestProcessingActivationConfiguration(t *testing.T) {
	c := processingDocument(t)
	read, err := policy.CompileProcessing([]byte(encoded(t, c)), nil)
	if err != nil {
		t.Fatalf("valid processing neighbour refused: %v", err)
	}
	if read.Processing == nil || len(read.Processing.Pipelines()) != 1 || len(read.Approval.Rules) != 1 || read.Approval.Rules[0].Executable != "/usr/bin/php" || read.Settings.ApprovedOutputBoundMiB != 64 {
		t.Fatalf("activation configuration incomplete: %+v", read)
	}
	c["pipelines"].([]any)[0].(map[string]any)["slots"].([]any)[0].(map[string]any)["configuration"] = map[string]any{"headers": []any{"authorization"}, "regex": true}
	read, err = policy.CompileProcessing([]byte(encoded(t, c)), nil)
	var refused *policy.Refused
	if !errors.As(err, &refused) || read.Processing != nil || len(refused.Findings) != 1 || refused.Findings[0].Reason != config.InvalidBuiltinArguments {
		t.Fatalf("processing rule did not decide before activation: read=%+v err=%v", read, err)
	}
}
func TestProcessingActivationPreservesObservationValidation(t *testing.T) {
	for _, tc := range []struct {
		name           string
		valid, invalid map[string]any
		detail         string
	}{
		{"cgroup", map[string]any{"cgroup": "/service"}, map[string]any{"cgroup": "/"}, "root cgroup"},
		{"executable", map[string]any{"exe": "/usr/bin/php"}, map[string]any{"exe": "php"}, "absolute path"},
		{"pid", map[string]any{"pid": map[string]any{"pid": 23, "start": 1, "boot": "boot"}}, map[string]any{"pid": map[string]any{"pid": 23, "start": 0, "boot": "boot"}}, "no start time"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := processingDocument(t)
			scope := member(c, "observation_scope")
			scope["targets"] = []any{target("server", tc.valid, true, true)}
			read, err := policy.CompileProcessing([]byte(encoded(t, c)), nil)
			if err != nil || read.Processing == nil {
				t.Fatalf("valid observation neighbour refused: %v", err)
			}
			scope["targets"] = []any{target("server", tc.invalid, true, true)}
			read, err = policy.CompileProcessing([]byte(encoded(t, c)), nil)
			if err == nil || read.Processing != nil || !strings.Contains(err.Error(), tc.detail) {
				t.Fatalf("observation fault not reached: read=%+v err=%v", read, err)
			}
		})
	}
}
func TestProcessingRevisionIncludesSelectedPack(t *testing.T) {
	c := processingDocument(t)
	c["packs"] = []any{"profile"}
	p := config.Manifest{Version: config.ManifestVersion, Name: "profile", PackVersion: "1", Replacements: []config.Replacement{{Pipeline: "exchanges", Slot: "remove", Implementation: config.RemoveHeaders, Configuration: json.RawMessage(`{"headers":["authorization"]}`)}}}
	encode := func() []config.Supplied {
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return []config.Supplied{{Name: "profile", Content: raw}}
	}
	first, err := policy.CompileProcessing([]byte(encoded(t, c)), encode())
	if err != nil {
		t.Fatal(err)
	}
	p.Replacements[0].Configuration = json.RawMessage(`{"headers":["cookie"]}`)
	second, err := policy.CompileProcessing([]byte(encoded(t, c)), encode())
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision == second.Revision || first.Revision == "" || second.Revision == "" {
		t.Fatalf("selected pack change invisible in policy revision: %q %q", first.Revision, second.Revision)
	}
}
