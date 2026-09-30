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
			out := &outputLog{}
			w, store := worker(t, rulesPlan(t, `"remove": {"headers": ["authorization", "x-secret", "x-never"]}`), out)
			enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
			o := drain(t, w)
			counted(t, o, out, 1, 1)
			exchanges, lines := out.routed(config.ExchangesPipeline)
			if o.ProcessingFailures != 0 || o.OutputFailures != 0 || field(t, exchanges[0], "x-public") != "original" {
				t.Fatalf("useful never-present control did not reach output: %+v", o)
			}
			if exclusions, _ := policyExclusions(t, lines[0]); len(exclusions) != 0 {
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
			o = drain(t, w)
			counted(t, o, out, 2, 2)
			exchanges, lines = out.routed(config.ExchangesPipeline)
			if o.Batches != 2 || o.ProcessingFailures != 0 || o.OutputFailures != 0 || field(t, exchanges[1], "x-public") != "original" {
				t.Fatalf("field-removal batch did not reach useful output: %+v", o)
			}
			e := exchanges[1].Reconstruction.Exchanges[0]
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
				if bytes.Contains(lines[1], []byte(value)) {
					t.Fatal("removed value remained in the approved line")
				}
			}
			t.Logf("RemoveHeaders reached %s/%s: useful output remains; both names and all three original values removed", location.message, location.section)
			requirePolicyExclusions(t, lines[1], []exclusionWire{
				{Exchange: 0, Message: location.message, Field: "message.headers.authorization", Section: location.section, Disposition: "removed"},
				{Exchange: 0, Message: location.message, Field: "message.headers.x-secret", Section: location.section, Disposition: "removed"},
			})
			// This explicit-empty assertion is intentionally after the new
			// evidence assertion: the old producer reaches removal before red.
			requirePolicyExclusions(t, lines[0], nil)
			t.Log("named evidence and explicit empty control both reached; absent names add nothing")
		})
	}
}
