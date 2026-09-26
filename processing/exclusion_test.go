package processing_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
)

// Read the proposed wire member without referring to new production names, so
// the current producer can reach the actual-removal control before the red.
type exclusionWire struct {
	Exchange    int    `json:"exchange"`
	Message     string `json:"message"`
	Field       string `json:"field"`
	Section     string `json:"section"`
	Disposition string `json:"disposition"`
}

func policyExclusions(t *testing.T, line []byte) ([]exclusionWire, bool) {
	t.Helper()
	var wire struct {
		Exclusions json.RawMessage `json:"policy_exclusions"`
	}
	if err := json.Unmarshal(line, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Exclusions) == 0 || bytes.Equal(wire.Exclusions, []byte("null")) {
		return nil, false
	}
	var exclusions []exclusionWire
	decoder := json.NewDecoder(bytes.NewReader(wire.Exclusions))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&exclusions); err != nil {
		t.Fatalf("policy exclusions are not name/location evidence only: %v", err)
	}
	return exclusions, true
}

func requirePolicyExclusions(t *testing.T, line []byte, want []exclusionWire) {
	t.Helper()
	got, carried := policyExclusions(t, line)
	if !carried {
		t.Fatal("actual RemoveHeaders output carries no named policy-exclusion evidence")
	}
	if len(got) != len(want) {
		t.Fatalf("named policy exclusions: got %+v, want %+v", got, want)
	}
	seen := make(map[exclusionWire]int)
	for _, e := range got {
		seen[e]++
	}
	for _, e := range want {
		if seen[e] != 1 {
			t.Fatalf("named policy exclusion missing or repeated: %+v, occurrences=%d", e, seen[e])
		}
	}
}

func namedField(fields []record.Field, name string) (string, bool) {
	for _, f := range fields {
		if strings.EqualFold(f.Name, name) {
			return f.Value, true
		}
	}
	return "", false
}

func TestRemoveHeadersRecordsNamedPolicyExclusions(t *testing.T) {
	for _, location := range []struct{ message, section string }{
		{"request", "headers"}, {"response", "headers"},
		{"request", "trailers"}, {"response", "trailers"},
	} {
		t.Run(location.message+"-"+location.section, func(t *testing.T) {
			remove := slot("remove", config.RemoveHeaders, `{"headers":["authorization","x-secret","x-never"]}`)
			again := remove
			again.Name = "remove-again"
			out := &outputLog{}
			w, store := worker(t, workerPlan(t, pipeline("removed", remove, again)), out)
			enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
			if o := drain(t, w); o.Written != 1 || o.ProcessingFailures != 0 || o.OutputFailures != 0 || field(t, out.artifacts[0], "x-public") != "original" {
				t.Fatalf("useful never-present control did not reach output: %+v", o)
			}
			if exclusions, _ := policyExclusions(t, out.lines[0]); len(exclusions) != 0 {
				t.Fatal("configured-but-absent fields acquired removal evidence")
			}
			t.Log("useful control reached with no selected source field present")

			fields := "AUTHORIZATION: remove-first\r\nx-secret: remove-second\r\nAuthorization: remove-repeat\r\n"
			request, response := goodRequest, goodResponse
			switch {
			case location.message == "request" && location.section == "headers":
				request = "GET / HTTP/1.1\r\nX-Public: original\r\n" + fields + "\r\n"
			case location.message == "response" && location.section == "headers":
				response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n" + fields + "\r\nOK"
			case location.message == "request":
				request = "POST / HTTP/1.1\r\nX-Public: original\r\nTransfer-Encoding: chunked\r\nTrailer: Authorization, X-Secret\r\n\r\n0\r\n" + fields + "\r\n"
			default:
				response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Authorization, X-Secret\r\n\r\n2\r\nOK\r\n0\r\n" + fields + "\r\n"
			}
			enqueue(t, store, batch(t, 2, request, response))
			o := drain(t, w)
			if o.Written != 2 || o.Batches != 2 || o.ProcessingFailures != 0 || o.OutputFailures != 0 || field(t, out.artifacts[1], "x-public") != "original" {
				t.Fatalf("field-removal batch did not reach useful output: %+v", o)
			}
			e := out.artifacts[1].Reconstruction.Exchanges[0]
			message := e.Request.Message
			if location.message == "response" {
				message = e.Response.Message
			}
			for _, source := range [][]record.Field{message.Headers, message.Trailers} {
				for _, name := range []string{"authorization", "x-secret"} {
					if _, present := namedField(source, name); present {
						t.Fatalf("RemoveHeaders did not remove %s", name)
					}
				}
			}
			for _, value := range []string{"remove-first", "remove-second", "remove-repeat"} {
				if bytes.Contains(out.lines[1], []byte(value)) {
					t.Fatal("removed value remained in the approved line")
				}
			}
			t.Logf("RemoveHeaders reached %s/%s: useful output remains; both names and all three original values removed", location.message, location.section)
			requirePolicyExclusions(t, out.lines[1], []exclusionWire{
				{Exchange: 0, Message: location.message, Field: "message.headers.authorization", Section: location.section, Disposition: "removed"},
				{Exchange: 0, Message: location.message, Field: "message.headers.x-secret", Section: location.section, Disposition: "removed"},
			})
			// This explicit-empty assertion is intentionally after the new
			// evidence assertion: the old producer reaches removal before red.
			requirePolicyExclusions(t, out.lines[0], nil)
			t.Log("named evidence and explicit empty control both reached; repeated removals and absent names add nothing")
		})
	}
}

func TestPolicyExclusionsFollowRetainedPipelineMessages(t *testing.T) {
	remove := slot("remove", config.RemoveHeaders, `{"headers":["authorization","x-secret","x-suffix"]}`)
	replace := slot("replace", config.ReplaceHeaderValues, `{"headers":["authorization","x-secret"],"value":"changed"}`)
	truncate := slot("truncate", config.TruncateHeaderValues, `{"headers":["authorization","x-secret"],"length":3}`)
	metadata := config.Pipeline{Name: "metadata", Input: "connection", Sinks: []string{"account"}}
	out := &outputLog{}
	w, store := worker(t, workerPlan(t, pipeline("removed", remove), pipeline("replaced", replace), pipeline("truncated", truncate), metadata), out)
	request := "GET /first HTTP/1.1\r\nX-Public: original\r\nAuthorization: first-source\r\n\r\n" + goodRequest + "GET /suffix HTTP/1.1\r\nX-Suffix: withheld-marker-value"
	response := goodResponse + "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Secret: second-source\r\n\r\nOK"
	enqueue(t, store, batch(t, 1, request, response))
	o := drain(t, w)
	if o.Written != 4 || o.ProcessingFailures != 3 || o.OutputFailures != 0 || len(out.artifacts) != 4 {
		t.Fatalf("independent pipeline prefix controls did not reach output: %+v", o)
	}
	for i, expected := range []string{"", "changed", "fir"} {
		a := out.artifacts[i]
		if a.Reconstruction == nil || len(a.Reconstruction.Exchanges) != 2 || a.ReconstructionTruncation == nil {
			t.Fatalf("pipeline %s did not retain two exchanges and report the suffix", a.Route.Pipeline)
		}
		first := a.Reconstruction.Exchanges[0].Request.Message
		if value, present := namedField(first.Headers, "x-public"); !present || value != "original" {
			t.Fatal("retained prefix lost its permitted field")
		}
		value, present := namedField(first.Headers, "authorization")
		if (i == 0 && present) || (i != 0 && (!present || value != expected)) {
			t.Fatalf("pipeline %s did not reach its configured operation", a.Route.Pipeline)
		}
		if bytes.Contains(out.lines[i], []byte("withheld-marker-value")) || bytes.Contains(out.lines[i], []byte("x-suffix")) {
			t.Fatal("undecidable suffix entered the retained artifact")
		}
	}
	if out.artifacts[3].Reconstruction != nil || out.artifacts[3].ReconstructionTruncation != nil {
		t.Fatal("metadata control received a reconstruction")
	}
	t.Log("three independent operations reached two retained exchanges beside metadata; incomplete suffix withheld")
	requirePolicyExclusions(t, out.lines[0], []exclusionWire{
		{Exchange: 0, Message: "request", Field: "message.headers.authorization", Section: "headers", Disposition: "removed"},
		{Exchange: 1, Message: "response", Field: "message.headers.x-secret", Section: "headers", Disposition: "removed"},
	})
	for _, index := range []int{1, 2, 3} {
		requirePolicyExclusions(t, out.lines[index], nil)
	}
	t.Log("exclusion identity follows exchange and message; replacement, truncation and metadata have explicit empty evidence")
}
