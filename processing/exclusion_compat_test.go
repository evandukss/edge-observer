package processing_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/processing"
)

// Supplementary representation check added after the five producer reds were
// captured. It is not red-first evidence or the independent public-reader test.
func TestPolicyExclusionEvidencePreservesAvailability(t *testing.T) {
	out := &outputLog{}
	w, store := worker(t, rulesPlan(t, `"remove": {"headers": ["authorization"]}`), out)
	enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
	enqueue(t, store, batch(t, 2, "GET / HTTP/1.1\r\nX-Public: original\r\nAuthorization: excluded-source\r\n\r\n", goodResponse))
	o := drain(t, w)
	if o.ProcessingFailures != 0 || o.OutputFailures != 0 {
		t.Fatalf("availability controls did not reach both outputs: %+v", o)
	}
	counted(t, o, out, 2, 2)
	exchanges, lines := out.routed(config.ExchangesPipeline)
	for _, a := range exchanges {
		if field(t, a, "x-public") != "original" {
			t.Fatal("availability control lost permitted output")
		}
	}
	t.Log("useful new artifacts reached with selected field absent and removed")

	// Derive an older representation by removing only the new member from a
	// valid artifact. This checks compatibility, not an old producer execution.
	var legacy map[string]json.RawMessage
	if err := json.Unmarshal(lines[0], &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "policy_exclusions")
	oldLine, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		line []byte
		want []processing.PolicyExclusion
		wire string
	}{
		{"populated", lines[1], []processing.PolicyExclusion{{Exchange: 0, Message: "request", Field: "message.headers.authorization", Section: "headers", Disposition: "removed"}}, `[{"exchange":0,"message":"request","field":"message.headers.authorization","section":"headers","disposition":"removed"}]`},
		{"new-empty", lines[0], []processing.PolicyExclusion{}, "[]"},
		{"old-absent", oldLine, nil, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertWire := func(line []byte, want string) map[string]json.RawMessage {
				t.Helper()
				var members map[string]json.RawMessage
				if err := json.Unmarshal(line, &members); err != nil {
					t.Fatal(err)
				}
				raw, present := members["policy_exclusions"]
				if present != (want != "") || string(raw) != want {
					t.Fatalf("serialized evidence: present=%t member=%s, want %q (empty string means absent)", present, raw, want)
				}
				return members
			}
			members := assertWire(test.line, test.wire)
			encoded, err := json.Marshal(members)
			if err != nil {
				t.Fatal(err)
			}
			assertWire(encoded, test.wire)
			t.Logf("%s reached after serialization and wire readback: member=%q (empty string means absent)", test.name, test.wire)
			var artifact processing.Artifact
			if err := json.Unmarshal(test.line, &artifact); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(artifact.PolicyExclusions, test.want) {
				t.Fatalf("decoded evidence: got %#v want %#v", artifact.PolicyExclusions, test.want)
			}
			roundTrip, err := json.Marshal(artifact)
			if err != nil {
				t.Fatal(err)
			}
			wantWire := test.wire
			if test.name == "old-absent" {
				// The public type re-encodes unavailable evidence as null. This
				// preserves availability, not literal absence of the member.
				wantWire = "null"
			}
			assertWire(roundTrip, wantWire)
			evidence, available := policyExclusions(t, roundTrip)
			if available != (test.want != nil) || len(evidence) != len(test.want) {
				t.Fatalf("round trip changed availability: available=%t entries=%d", available, len(evidence))
			}
			t.Logf("%s preserved through public Artifact decode and encode: available=%t entries=%d", test.name, available, len(evidence))
		})
	}
}
