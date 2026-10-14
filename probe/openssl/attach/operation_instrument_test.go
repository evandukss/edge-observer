//go:build attach

package attach_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/processing"
)

// operationProtected and operationPermitted name markers so that none is a substring of
// another and each says which kind it is where it turns up.
func operationProtected(name string) string { return "OPERPROT_" + name + "_END" }
func operationPermitted(name string) string { return "OPERKEEP_" + name + "_END" }

// The instrument every absence in these tests rests on. A marker planted in
// each form it searches is found, inside surrounding bytes and at every base64
// alignment, and a source without it, or with it one byte off, is not.
func TestTheInstrumentFindsAMarkerInEveryFormItSearches(t *testing.T) {
	marker := operationProtected("INSTRUMENT")
	near := strings.Replace(marker, "INSTRUMENT", "INSTRUMENS", 1)
	escaped, err := json.Marshal(map[string]string{"k": "x" + marker + "y"})
	if err != nil {
		t.Fatal(err)
	}
	unicode := strings.ReplaceAll(string(escaped), "OPER", `\u004f\u0050\u0045\u0052`)
	planted := map[string]string{
		"raw":         "before " + marker + " after",
		"hex":         "0a" + hex.EncodeToString([]byte(marker)) + "0b",
		"HEX":         "0A" + strings.ToUpper(hex.EncodeToString([]byte(marker))) + "0B",
		"JSON escape": unicode,
	}
	for pad := range 3 {
		for alphabet, encoding := range map[string]*base64.Encoding{"standard": base64.StdEncoding, "url": base64.URLEncoding} {
			blob := encoding.EncodeToString([]byte(strings.Repeat("p", pad) + marker + strings.Repeat("s", 5-pad)))
			planted[fmt.Sprintf("%s base64 at offset %d in JSON", alphabet, pad)] = "{\"kept\":\"" + blob + "\"}"
			planted[fmt.Sprintf("%s base64 at offset %d in text", alphabet, pad)] = "line " + blob + " end"
		}
	}
	for form, content := range planted {
		o := operationOutput{sources: map[string][]byte{form: []byte(content)}}
		if len(o.found(marker)) == 0 {
			t.Errorf("the instrument does not find a marker planted as %s: %q", form, content)
		}
		if where := o.found(near); len(where) != 0 {
			t.Errorf("the instrument finds a marker one byte off in %s: %v", form, where)
		}
	}
	empty := operationOutput{sources: map[string][]byte{"nothing": []byte("no marker here"), "empty": nil}}
	if where := empty.found(marker); len(where) != 0 {
		t.Errorf("the instrument finds a marker in sources that do not hold it: %v", where)
	}
}

// A header exclusion through the whole run, beside a body, a query and a
// response that must persist: the header is removed and recorded as a version
// 2 entry, and nothing else changes.
func TestAHeaderExclusionRemovesTheHeaderAndRecordsItAsAVersion2Entry(t *testing.T) {
	body := `{"note":"` + operationPermitted("HDR_BODY") + `"}`
	cases := []operationCase{{
		name: "header",
		pieces: []string{operationRequest("POST", "/oper/header?keep="+operationPermitted("HDR_QUERY"), []operationHeader{
			{"Authorization", operationProtected("HDR_AUTH")}, {"X-Oper-Keep", operationPermitted("HDR_HEADER")},
			{"Content-Type", "application/json"}}, body)},
		response:  operationResponse{Body: []byte(operationPermitted("HDR_RESPONSE"))},
		protected: []string{operationProtected("HDR_AUTH")},
		permitted: []string{operationPermitted("HDR_BODY"), operationPermitted("HDR_QUERY"), operationPermitted("HDR_HEADER"), operationPermitted("HDR_RESPONSE")},
		check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
			request := x.Request.Message
			for _, h := range request.Headers {
				if strings.EqualFold(h.Name, "authorization") {
					t.Errorf("the excluded header was written: %+v", h)
				}
			}
			operationHasHeader(t, request, "X-Oper-Keep", operationPermitted("HDR_HEADER"))
			if request.Target != "/oper/header?keep="+operationPermitted("HDR_QUERY") {
				t.Errorf("the target changed to %q", request.Target)
			}
			operationKept(t, request, body)
			if request.Structure.State != record.StructureDerived {
				t.Errorf("the kept JSON body has structure %+v", request.Structure)
			}
			operationKept(t, x.Response.Message, operationPermitted("HDR_RESPONSE"))
			operationEvidence(t, a, x, operationEntry{"request", config.HeaderFieldPrefix + "authorization", "headers", processing.DispositionRemoved})
		},
	}}
	setup := operationSetup{
		rules: map[string]any{"remove": map[string]any{"headers": []string{"authorization"}}},
	}
	operationAssert(t, operationRun(t, setup, cases), []string{config.ExchangesPipeline}, cases)
}
