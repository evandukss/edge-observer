package processing_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/processing"
)

// Reader compatibility covers four wire forms, including a legacy artifact
// re-encoded through the public type. This does not replace the independent
// condition-2 engagement over capture, exclusion and undecidable suffixes.
func TestApprovedReaderDistinguishesAllFourExclusionWireForms(t *testing.T) {
	empty, _ := readableArtifact(t)
	var out outputLog
	w, store := worker(t, rulesPlan(t, `"remove": {"headers": ["authorization"]}`), &out)
	enqueue(t, store, batch(t, 1, "GET /public HTTP/1.1\r\nAuthorization: source-value\r\nX-Public: useful\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\npublic-body"))
	counted(t, drain(t, w), &out, 1, 1)
	_, lines := out.routed(config.ExchangesPipeline)
	var members map[string]json.RawMessage
	if err := json.Unmarshal(empty, &members); err != nil {
		t.Fatal(err)
	}
	members["version"] = json.RawMessage(`"observer.approved/1"`)
	delete(members, "policy_exclusions")
	absent, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	var legacy processing.Artifact
	if err := json.Unmarshal(absent, &legacy); err != nil {
		t.Fatal(err)
	}
	null, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	const unavailable = "policy exclusions  unavailable:"
	const none = "policy exclusions  none excluded in retained messages;"
	const excluded = "policy excluded  exchange=0 message=\"request\" field=\"message.headers.authorization\" section=\"headers\" disposition=\"removed\""
	for _, tc := range []struct {
		name string
		line []byte
		wire string
		want []processing.PolicyExclusion
		text string
	}{
		{"populated", lines[0], `[{"exchange":0,"message":"request","field":"message.headers.authorization","section":"headers","disposition":"removed"}]`, []processing.PolicyExclusion{{Exchange: 0, Message: "request", Field: "message.headers.authorization", Section: "headers", Disposition: "removed"}}, excluded},
		{"literal-empty-array", empty, "[]", []processing.PolicyExclusion{}, none},
		{"absent-legacy-key", append(absent, '\n'), "", nil, unavailable},
		{"literal-null-after-public-round-trip", append(null, '\n'), "null", nil, unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Establish the actual input form independently of the reader.
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(tc.line, &raw); err != nil {
				t.Fatal(err)
			}
			wire, present := raw["policy_exclusions"]
			if present != (tc.wire != "") || string(wire) != tc.wire {
				t.Fatalf("wire form not reached: present=%t wire=%s want=%q", present, wire, tc.wire)
			}
			requireUsefulRead(t, empty)
			var rendered bytes.Buffer
			visits := 0
			err := processing.ReadArtifacts(artifactFS(tc.line), func(a processing.Artifact) error {
				visits++
				// DeepEqual distinguishes nil from a non-nil empty slice.
				if !reflect.DeepEqual(a.PolicyExclusions, tc.want) {
					t.Fatalf("reader changed evidence: got %#v want %#v", a.PolicyExclusions, tc.want)
				}
				return processing.RenderArtifact(&rendered, a)
			})
			if err != nil || visits != 1 {
				t.Fatalf("reader/renderer did not accept wire form: visits=%d err=%v", visits, err)
			}
			for _, state := range []string{unavailable, none, excluded} {
				if strings.Contains(rendered.String(), state) != (state == tc.text) {
					t.Fatalf("wrong exclusion disposition for %s: want %q\n%s", tc.name, tc.text, &rendered)
				}
			}
			for _, value := range []string{"useful", "public-body", "fixture-policy"} {
				if !strings.Contains(rendered.String(), value) {
					t.Fatalf("evidence case omitted useful value/provenance %q", value)
				}
			}
			t.Logf("wire %s reached reader and renderer; nil=%t entries=%d; useful control passed", tc.name, tc.want == nil, len(tc.want))
		})
	}
}
