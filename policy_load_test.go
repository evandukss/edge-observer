package observer_test

// These tests take their population from contract/config/CONFIG.md's
// configuration and structural-rule lists, never from the implementation.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/policy"
)

func independentExample(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("contract/config/examples/no-extension.config.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func independentDocument(t *testing.T) map[string]any {
	t.Helper()
	var d map[string]any
	if err := json.Unmarshal(independentExample(t), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func independentBytes(t *testing.T, d map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Paths are JSON-pointer-like test addresses, not paths supplied by Load.
func independentParent(t *testing.T, d map[string]any, path string) (map[string]any, string) {
	t.Helper()
	parts := strings.Split(path, "/")
	var current any = d
	for _, part := range parts[:len(parts)-1] {
		switch node := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = node[part]
			if !ok {
				t.Fatalf("fixture path %q has no member %q", path, part)
			}
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(node) {
				t.Fatalf("fixture path %q has invalid index %q", path, part)
			}
			current = node[i]
		default:
			t.Fatalf("fixture path %q traverses %T", path, current)
		}
	}
	parent, ok := current.(map[string]any)
	if !ok {
		t.Fatalf("fixture path %q ends in %T", path, current)
	}
	return parent, parts[len(parts)-1]
}

func independentSet(t *testing.T, d map[string]any, path string, value any) {
	t.Helper()
	p, key := independentParent(t, d, path)
	p[key] = value
}

func independentLoad(t *testing.T, b []byte) (policy.Policy, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "operator.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return policy.Load(path)
}

func independentAcceptedFixture(t *testing.T, b []byte) {
	t.Helper()
	r := config.Check(config.Input{Configuration: b, Available: policy.Inventory()})
	if r.Outcome != config.Accepted {
		t.Fatalf("fixture did not reach program-refusal stage: %+v", r)
	}
}

func TestConfigPositiveControl(t *testing.T) {
	b := independentExample(t)
	independentAcceptedFixture(t, b)
	if _, err := independentLoad(t, b); err != nil {
		t.Fatalf("contract no-extension example must be accepted: %v", err)
	}
}

func independentRefused(t *testing.T, err error, outcome config.Outcome, reason config.Reason) []config.Finding {
	t.Helper()
	var refused *policy.Refused
	if !errors.As(err, &refused) {
		t.Fatalf("want *policy.Refused (%s/%s), got %T: %v", outcome, reason, err, err)
	}
	if refused.Outcome != outcome {
		t.Errorf("refusal outcome = %q, want %q", refused.Outcome, outcome)
	}
	var unsupported *policy.Unimplemented
	var unanswerable *policy.Unanswerable
	if errors.As(err, &unsupported) || errors.As(err, &unanswerable) {
		t.Errorf("contract refusal must precede program/admission refusal: %v", err)
	}
	found := false
	for _, f := range refused.Findings {
		if f.Reason == reason {
			found = true
			if f.Document != "configuration" || f.Detail == "" {
				t.Errorf("finding lost its document/detail: %+v", f)
			}
		}
	}
	if !found {
		t.Errorf("refusal findings omit %q: %+v", reason, refused.Findings)
	}
	return refused.Findings
}

func TestConfigCaseSensitiveMembers(t *testing.T) {
	// Explicit population from CONFIG.md, optional and defaulted members
	// included; not derived from Go tags or the implementation's list.
	paths := []string{
		"version", "observer", "observation_scope", "traffic_scope", "retention_and_export",
		"packs", "sinks", "pipelines", "subscribers", "policy",
		"observer/log", "observer/directory", "observer/spool_bound_mib", "observer/state_every_seconds",
		"observation_scope/targets", "observation_scope/exclude", "observation_scope/libraries",
		"observation_scope/targets/0/name", "observation_scope/targets/0/match", "observation_scope/targets/0/descendants",
		"observation_scope/targets/0/match/exe", "observation_scope/targets/0/match/args",
		"observation_scope/targets/0/descendants/existing", "observation_scope/targets/0/descendants/future",
		"observation_scope/targets/0/descendants/boundary", "observation_scope/targets/0/descendants/root_exit",
		"observation_scope/targets/0/descendants/replacement",
		"traffic_scope/rules", "traffic_scope/rules/0/targets", "traffic_scope/rules/0/direction",
		"traffic_scope/rules/0/local_ports", "traffic_scope/rules/0/remote_ports",
		"retention_and_export/retain_plaintext", "retention_and_export/export_sinks",
		"sinks/0/name", "sinks/0/kind", "pipelines/0/name", "pipelines/0/input",
		"pipelines/0/slots", "pipelines/0/sinks", "pipelines/0/queues", "pipelines/0/queues/0/name",
		"observation_scope/targets/0/match/cgroup", "observation_scope/targets/0/match/port",
		"observation_scope/targets/0/match/interface", "observation_scope/targets/0/match/pid",
		"observation_scope/targets/0/match/pid/pid", "observation_scope/targets/0/match/pid/start",
		"observation_scope/targets/0/match/pid/boot", "observation_scope/exclude/0/exe",
		"observation_scope/libraries/0/build_id", "observation_scope/libraries/0/symbols",
		"pipelines/0/slots/0/name", "pipelines/0/slots/0/implementation",
		"pipelines/0/slots/0/on_failure", "pipelines/0/slots/0/configuration",
		"subscribers/0/name", "subscribers/0/stream", "subscribers/0/implementation",
		"policy/0/vocabulary", "policy/0/requirements", "policy/0/claims", "policy/0/approvals",
	}
	for _, path := range paths {
		for _, spelling := range []string{"upper", "initial-upper"} {
			t.Run(path+"/"+spelling, func(t *testing.T) {
				d := independentDocument(t)
				independentSet(t, d, "observation_scope/targets/0/match/cgroup", "/service")
				independentSet(t, d, "observation_scope/targets/0/match/port", 443)
				independentSet(t, d, "observation_scope/targets/0/match/interface", "eth0")
				independentSet(t, d, "observation_scope/targets/0/match/pid", map[string]any{"pid": 42, "start": 17, "boot": "test-boot"})
				independentSet(t, d, "observation_scope/exclude", []any{map[string]any{"exe": "/bin/curl"}})
				independentSet(t, d, "observation_scope/libraries", []any{map[string]any{"build_id": "abc123", "symbols": map[string]any{"SSL_read": 123}}})
				independentSet(t, d, "pipelines/0/slots", []any{map[string]any{"name": "redact", "implementation": "redactor", "on_failure": "drop_and_account", "configuration": map[string]any{}}})
				d["subscribers"] = []any{map[string]any{"name": "notes", "stream": "exchanges", "implementation": "annotator"}}
				d["policy"] = []any{independentPolicyDocument()}
				before := config.Check(config.Input{Configuration: independentBytes(t, d), Available: policy.Inventory()})
				if before.Outcome == config.StructurallyRefused {
					t.Fatalf("canonical fixture was already malformed: %+v", before)
				}
				p, key := independentParent(t, d, path)
				value, present := p[key]
				if !present {
					t.Fatalf("fixture lacks documented member %q", path)
				}
				alias := strings.ToUpper(key)
				if spelling == "initial-upper" {
					alias = strings.ToUpper(key[:1]) + key[1:]
				}
				delete(p, key)
				p[alias] = value
				_, err := independentLoad(t, independentBytes(t, d))
				independentRefused(t, err, config.StructurallyRefused, config.Malformed)
			})
		}
	}
}

func TestConfigCaseAliasesBesideCanonicalMembers(t *testing.T) {
	// A missing-required-member check cannot catch these: the canonical member
	// stays present, and some aliases change its value.
	cases := []struct{ canonical, alias string }{
		{`"version":"observer.config/draft"`, `"VERSION":"observer.config/draft"`},
		{`"spool_bound_mib":64`, `"SPOOL_BOUND_MIB":1`},
		{`"state_every_seconds":30`, `"State_every_seconds":90`},
		{`"existing":true`, `"EXISTING":false`},
		{`"retain_plaintext":true`, `"RETAIN_PLAINTEXT":false`},
		{`"policy":[]`, `"POLICY":[{"vocabulary":"observer.policy/draft","requirements":[],"claims":[],"approvals":[]}]`},
	}
	for i, c := range cases {
		for _, aliasFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("member-%d/alias-first-%t", i, aliasFirst), func(t *testing.T) {
				b := independentBytes(t, independentDocument(t))
				independentAcceptedFixture(t, b)
				if n := strings.Count(string(b), c.canonical); n != 1 {
					t.Fatalf("fixture has %d occurrences of %s, want 1", n, c.canonical)
				}
				pair := c.canonical + "," + c.alias
				if aliasFirst {
					pair = c.alias + "," + c.canonical
				}
				b = []byte(strings.Replace(string(b), c.canonical, pair, 1))
				_, err := independentLoad(t, b)
				independentRefused(t, err, config.StructurallyRefused, config.Malformed)
			})
		}
	}
}

func TestConfigUnimplementedRendererOnly(t *testing.T) {
	// Renderer only: the message when produced, not whether Load produces it;
	// the Load cases establish reachability. Population: CONFIG.md's sections.
	wants := []independentSectionWant{
		{"pipelines[0].slots", processing}, {"packs", processingAndPlugins},
		{"subscribers", processing}, {"policy", processing},
		{"retention_and_export.retain_plaintext", processing}, {"pipelines", processing},
		{"sinks[1].kind", nil}, {"retention_and_export.export_sinks", nil},
		{"traffic_scope.rules[0]", processing},
	}
	for _, want := range wants {
		t.Run(want.path, func(t *testing.T) {
			detail := "unsupported selection"
			if len(want.needs) == 0 {
				// Caller-supplied, not evidence that Load supplies it.
				detail = "arrives as a contribution of outputs and sinks"
			}
			u := &policy.Unimplemented{Sections: []policy.Section{{Path: want.path, Needs: want.needs, Detail: detail}}}
			independentSectionMessage(t, u.Error(), want)
		})
	}
}

type independentSectionWant struct {
	path  string
	needs []policy.Capability
}

var (
	processing           = []policy.Capability{policy.Processing}
	processingAndPlugins = []policy.Capability{policy.Processing, policy.Plugins}
)

func independentUnimplemented(t *testing.T, b []byte, want []independentSectionWant) {
	t.Helper()
	reference := config.Check(config.Input{Configuration: b, Available: policy.Inventory()})
	if reference.Outcome == config.StructurallyRefused {
		t.Fatalf("fixture is malformed, so cannot reach Unimplemented: %+v", reference)
	}
	_, err := independentLoad(t, b)
	var got *policy.Unimplemented
	if !errors.As(err, &got) {
		t.Fatalf("want *policy.Unimplemented, got %T: %v", err, err)
	}
	if len(got.Sections) != len(want) {
		t.Errorf("refusal names %d sections, want %d: %+v", len(got.Sections), len(want), got.Sections)
	}
	for _, expected := range want {
		matches := 0
		for _, section := range got.Sections {
			if section.Path != expected.path {
				continue
			}
			matches++
			needs := append([]policy.Capability(nil), section.Needs...)
			sort.Slice(needs, func(i, j int) bool { return needs[i] < needs[j] })
			if !reflect.DeepEqual(needs, expected.needs) {
				t.Errorf("%s needs = %v, want %v", expected.path, needs, expected.needs)
			}
			if section.Detail == "" {
				t.Errorf("%s has no refusal detail", expected.path)
			}
			// Each section's own rendering is checked, so another section's
			// capabilities cannot conceal that this one omitted them.
			message := (&policy.Unimplemented{Sections: []policy.Section{section}}).Error()
			independentSectionMessage(t, message, expected)
			start := strings.Index(message, section.Path)
			if start < 0 || !strings.Contains(err.Error(), message[start:]) {
				t.Errorf("Load error omits section %s's rendered reason/schedule: %v", section.Path, err)
			}
		}
		if matches != 1 {
			t.Errorf("section %s occurred %d times, want exactly once: %+v", expected.path, matches, got.Sections)
		}
	}
}

func independentSectionMessage(t *testing.T, message string, want independentSectionWant) {
	t.Helper()
	if !strings.Contains(message, want.path) {
		t.Errorf("message omits %s: %s", want.path, message)
	}
	if len(want.needs) == 0 {
		for _, word := range []string{"no configuration enables it", "contribut", "output", "sink"} {
			if !strings.Contains(strings.ToLower(message), word) {
				t.Errorf("unscheduled %s message omits %q: %s", want.path, word, message)
			}
		}
		return
	}
	needsRE := regexp.MustCompile(`\bit needs (.+)$`)
	separatorRE := regexp.MustCompile(`, | and `)
	var needs []policy.Capability
	for _, match := range needsRE.FindAllStringSubmatch(message, -1) {
		for _, name := range separatorRE.Split(match[1], -1) {
			needs = append(needs, policy.Capability(name))
		}
	}
	sort.Slice(needs, func(i, j int) bool { return needs[i] < needs[j] })
	if !reflect.DeepEqual(needs, want.needs) {
		t.Errorf("%s message needs = %q, want %q: %s", want.path, needs, want.needs, message)
	}
}

func independentPolicyDocument() map[string]any {
	return map[string]any{"vocabulary": "observer.policy/draft", "requirements": []any{}, "claims": []any{}, "approvals": []any{}}
}

func TestConfigUnimplementedSections(t *testing.T) {
	cases := []struct {
		name, path string
		value      any
		want       independentSectionWant
	}{
		// Each section is named in CONFIG.md, not discovered from the subject.
		// Unimplemented precedes composition, which makes these reachable.
		{"packs", "packs", []any{"not-installed"}, independentSectionWant{"packs", processingAndPlugins}},
		{"slots", "pipelines/0/slots", []any{map[string]any{"name": "redact", "implementation": "redactor", "on_failure": "drop_and_account"}}, independentSectionWant{"pipelines[0].slots", processing}},
		{"subscribers", "subscribers", []any{map[string]any{"name": "notes", "stream": "exchanges", "implementation": "annotator"}}, independentSectionWant{"subscribers", processing}},
		{"sink-kind", "sinks", []any{map[string]any{"name": "account", "kind": "local_account"}, map[string]any{"name": "remote", "kind": "remote_archive"}}, independentSectionWant{"sinks[1].kind", nil}},
		{"retention", "retention_and_export/retain_plaintext", false, independentSectionWant{"retention_and_export.retain_plaintext", processing}},
		{"policy", "policy", []any{independentPolicyDocument()}, independentSectionWant{"policy", processing}},
		{"export", "retention_and_export/export_sinks", []any{"account"}, independentSectionWant{"retention_and_export.export_sinks", nil}},
		{"named-target", "traffic_scope/rules/0/targets", []any{"api-server"}, independentSectionWant{"traffic_scope.rules[0]", processing}},
		{"inbound", "traffic_scope/rules/0/direction", "inbound", independentSectionWant{"traffic_scope.rules[0]", processing}},
		{"outbound", "traffic_scope/rules/0/direction", "outbound", independentSectionWant{"traffic_scope.rules[0]", processing}},
		{"local-port", "traffic_scope/rules/0/local_ports", []any{443}, independentSectionWant{"traffic_scope.rules[0]", processing}},
		{"remote-port", "traffic_scope/rules/0/remote_ports", []any{8443}, independentSectionWant{"traffic_scope.rules[0]", processing}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := independentDocument(t)
			independentSet(t, d, c.path, c.value)
			independentUnimplemented(t, independentBytes(t, d), []independentSectionWant{c.want})
		})
	}
	for _, removed := range []int{0, 1} {
		t.Run(fmt.Sprintf("missing-route-%d", removed), func(t *testing.T) {
			d := independentDocument(t)
			pipelines := d["pipelines"].([]any)
			d["pipelines"] = []any{pipelines[1-removed]}
			independentUnimplemented(t, independentBytes(t, d), []independentSectionWant{{"pipelines", processing}})
		})
	}
}

func TestConfigAllUnimplementedSectionsAreNamed(t *testing.T) {
	d := independentDocument(t)
	d["policy"] = []any{independentPolicyDocument()}
	independentSet(t, d, "retention_and_export/export_sinks", []any{"account"})
	independentSet(t, d, "traffic_scope/rules", []any{
		map[string]any{"targets": []any{}, "direction": "outbound", "local_ports": []any{}, "remote_ports": []any{}},
		map[string]any{"targets": []any{}, "direction": "any", "local_ports": []any{}, "remote_ports": []any{443}},
	})
	d["pipelines"] = []any{d["pipelines"].([]any)[0]}
	d["packs"] = []any{"not-installed"}
	d["subscribers"] = []any{map[string]any{"name": "notes", "stream": "exchanges", "implementation": "annotator"}}
	independentSet(t, d, "pipelines/0/slots", []any{map[string]any{"name": "redact", "implementation": "redactor", "on_failure": "drop_and_account"}})
	independentSet(t, d, "retention_and_export/retain_plaintext", false)
	d["sinks"] = append(d["sinks"].([]any), map[string]any{"name": "remote", "kind": "remote_archive"})
	independentUnimplemented(t, independentBytes(t, d), []independentSectionWant{
		{"policy", processing}, {"retention_and_export.export_sinks", nil},
		{"traffic_scope.rules[0]", processing}, {"traffic_scope.rules[1]", processing},
		{"pipelines", processing},
		{"packs", processingAndPlugins}, {"subscribers", processing},
		{"pipelines[0].slots", processing}, {"retention_and_export.retain_plaintext", processing},
		{"sinks[1].kind", nil},
	})
}

func TestConfigUnimplementedPrecedesComposition(t *testing.T) {
	// Both competing conditions hold on these bytes, so the order is what the
	// outcome shows.
	d := independentDocument(t)
	d["packs"] = []any{"not-installed"}
	b := independentBytes(t, d)
	reference := config.Check(config.Input{Configuration: b, Available: policy.Inventory()})
	if reference.Outcome != config.CompositionRefused {
		t.Fatalf("precedence fixture did not reach competing composition refusal: %+v", reference)
	}
	found := false
	for _, finding := range reference.Composition {
		if finding.Reason == config.UnknownPack {
			found = true
		}
	}
	if !found {
		t.Fatalf("precedence fixture was refused for a different reason: %+v", reference.Composition)
	}
	independentUnimplemented(t, b, []independentSectionWant{{"packs", processingAndPlugins}})
}

func TestConfigContractRefusalPrecedesProgramRefusal(t *testing.T) {
	// Structural refusal precedes Unimplemented, which precedes composition.
	// These composition cases use only implemented sections.
	cases := []struct {
		name, path string
		value      any
		outcome    config.Outcome
		reason     config.Reason
	}{
		{"boundary", "observation_scope/targets/0/descendants/boundary", "survive_exec", config.CompositionRefused, config.DescendantAnswerNotSupported},
		{"root-exit", "observation_scope/targets/0/descendants/root_exit", "revoke_survivors", config.CompositionRefused, config.DescendantAnswerNotSupported},
		{"replacement", "observation_scope/targets/0/descendants/replacement", "hot_reload", config.CompositionRefused, config.DescendantAnswerNotSupported},
		{"unknown-version", "version", "observer.config/not-this-draft", config.StructurallyRefused, config.UnknownVersion},
		{"malformed", "observer/spool_bound_mib", 0, config.StructurallyRefused, config.Malformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := independentDocument(t)
			if c.outcome == config.StructurallyRefused {
				// Structural refusal must win over a reachable Unimplemented.
				d["policy"] = []any{independentPolicyDocument()}
			} else {
				// Composition must win over the otherwise unanswerable pair.
				independentSet(t, d, "observation_scope/targets/0/descendants/existing", false)
			}
			independentSet(t, d, c.path, c.value)
			b := independentBytes(t, d)
			reference := config.Check(config.Input{Configuration: b, Available: policy.Inventory()})
			if reference.Outcome != c.outcome {
				t.Fatalf("fixture contract outcome = %s, want %s: %+v", reference.Outcome, c.outcome, reference)
			}
			_, err := independentLoad(t, b)
			got := independentRefused(t, err, c.outcome, c.reason)
			findings := reference.Composition
			if c.outcome == config.StructurallyRefused {
				findings = reference.Structural
			}
			if !reflect.DeepEqual(got, findings) {
				t.Errorf("Load changed contract findings: got %+v, want %+v", got, findings)
			}
		})
	}
}

func TestConfigUnanswerableDescendantPair(t *testing.T) {
	d := independentDocument(t)
	independentSet(t, d, "observation_scope/targets/0/descendants/existing", false)
	independentSet(t, d, "observation_scope/targets/0/descendants/future", true)
	b := independentBytes(t, d)
	independentAcceptedFixture(t, b)
	_, err := independentLoad(t, b)
	var got *policy.Unanswerable
	if !errors.As(err, &got) {
		t.Fatalf("false/true must be *policy.Unanswerable, got %T: %v", err, err)
	}
	if got.Target != "api-server" || got.Existing || !got.Future {
		t.Errorf("unanswerable changed the target or pair: %+v", got)
	}
	for _, fragment := range []string{"api-server", "existing false", "future true"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Errorf("unanswerable error omits %q: %v", fragment, err)
		}
	}
}
