package policy_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

// processingDocument is the example with one removal rule.
func processingDocument(t *testing.T) map[string]any {
	t.Helper()
	c := example(t)
	c["remove"] = map[string]any{"headers": []any{"authorization"}}
	return c
}

func exchanges(t *testing.T, read policy.Policy) config.EffectivePipeline {
	t.Helper()
	pipelines := read.Processing.Pipelines()
	at := slices.IndexFunc(pipelines, func(p config.EffectivePipeline) bool { return p.Name == config.ExchangesPipeline })
	if at < 0 {
		t.Fatalf("no %s pipeline in %+v", config.ExchangesPipeline, pipelines)
	}
	return pipelines[at]
}

func TestProcessingActivationConfiguration(t *testing.T) {
	c := processingDocument(t)
	read, err := policy.CompileProcessing([]byte(encoded(t, c)), nil)
	if err != nil {
		t.Fatalf("valid processing neighbour refused: %v", err)
	}
	if read.Processing == nil || len(exchanges(t, read).Slots) != 1 || len(read.Approval.Rules) != 1 ||
		read.Approval.Rules[0].Executable != "/usr/bin/php" || read.Settings.ApprovedOutputBoundMiB != 64 {
		t.Fatalf("activation configuration incomplete: %+v", read)
	}
	c["remove"] = map[string]any{"headers": []any{"authorization", "bad name"}}
	read, err = policy.CompileProcessing([]byte(encoded(t, c)), nil)
	var refused *policy.Refused
	if !errors.As(err, &refused) || read.Processing != nil || len(refused.Findings) != 1 ||
		refused.Findings[0].Reason != config.InvalidValue || refused.Findings[0].Subject != "remove.headers[1]" {
		t.Fatalf("the rule did not decide before activation: read=%+v err=%v", read, err)
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
			c["watch"] = []any{watching("server", tc.valid, "all")}
			read, err := policy.CompileProcessing([]byte(encoded(t, c)), nil)
			if err != nil || read.Processing == nil {
				t.Fatalf("valid observation neighbour refused: %v", err)
			}
			c["watch"] = []any{watching("server", tc.invalid, "all")}
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
	pack := func(header string) []config.Supplied {
		return []config.Supplied{{Name: "profile", Content: []byte(`{"version": "observer.pack/1", "name": "profile", ` +
			`"remove": {"headers": ["` + header + `"]}}`)}}
	}
	first, err := policy.CompileProcessing([]byte(encoded(t, c)), pack("authorization"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := policy.CompileProcessing([]byte(encoded(t, c)), pack("cookie"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision == second.Revision || first.Revision == "" || second.Revision == "" {
		t.Fatalf("selected pack change invisible in policy revision: %q %q", first.Revision, second.Revision)
	}
}
