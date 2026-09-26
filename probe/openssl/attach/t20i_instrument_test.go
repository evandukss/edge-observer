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
	cp "github.com/evandukss/edge-observer/contract/policy"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/processing"
)

// t20iProtected and t20iPermitted name markers so that none is a substring of
// another and each says which kind it is where it turns up.
func t20iProtected(name string) string { return "T20IPROT_" + name + "_END" }
func t20iPermitted(name string) string { return "T20IKEEP_" + name + "_END" }

// The instrument every absence in these tests rests on. A marker planted in
// each form it searches is found, inside surrounding bytes and at every base64
// alignment, and a source without it, or with it one byte off, is not.
func TestT20iTheInstrumentFindsAMarkerInEveryFormItSearches(t *testing.T) {
	marker := t20iProtected("INSTRUMENT")
	near := strings.Replace(marker, "INSTRUMENT", "INSTRUMENS", 1)
	escaped, err := json.Marshal(map[string]string{"k": "x" + marker + "y"})
	if err != nil {
		t.Fatal(err)
	}
	unicode := strings.ReplaceAll(string(escaped), "T20I", `\u0054\u0032\u0030\u0049`)
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
		o := t20iOutput{sources: map[string][]byte{form: []byte(content)}}
		if len(o.found(marker)) == 0 {
			t.Errorf("the instrument does not find a marker planted as %s: %q", form, content)
		}
		if where := o.found(near); len(where) != 0 {
			t.Errorf("the instrument finds a marker one byte off in %s: %v", form, where)
		}
	}
	empty := t20iOutput{sources: map[string][]byte{"nothing": []byte("no marker here"), "empty": nil}}
	if where := empty.found(marker); len(where) != 0 {
		t.Errorf("the instrument finds a marker in sources that do not hold it: %v", where)
	}
}

// A header exclusion through the whole run, beside a body, a query and a
// response that must persist: the header is removed and recorded as a version
// 2 entry, and nothing else changes.
func TestT20iAHeaderExclusionRemovesTheHeaderAndRecordsItAsAVersion2Entry(t *testing.T) {
	body := `{"note":"` + t20iPermitted("HDR_BODY") + `"}`
	cases := []t20iCase{{
		name: "header",
		pieces: []string{t20iRequest("POST", "/t20i/header?keep="+t20iPermitted("HDR_QUERY"), []t20iHeader{
			{"Authorization", t20iProtected("HDR_AUTH")}, {"X-T20i-Keep", t20iPermitted("HDR_HEADER")},
			{"Content-Type", "application/json"}}, body)},
		response:  t20iResponse{Body: []byte(t20iPermitted("HDR_RESPONSE"))},
		protected: []string{t20iProtected("HDR_AUTH")},
		permitted: []string{t20iPermitted("HDR_BODY"), t20iPermitted("HDR_QUERY"), t20iPermitted("HDR_HEADER"), t20iPermitted("HDR_RESPONSE")},
		check: func(t *testing.T, _ string, a processing.Artifact, x record.Exchange) {
			request := x.Request.Message
			for _, h := range request.Headers {
				if strings.EqualFold(h.Name, "authorization") {
					t.Errorf("the excluded header was written: %+v", h)
				}
			}
			t20iHasHeader(t, request, "X-T20i-Keep", t20iPermitted("HDR_HEADER"))
			if request.Target != "/t20i/header?keep="+t20iPermitted("HDR_QUERY") {
				t.Errorf("the target changed to %q", request.Target)
			}
			t20iKept(t, request, body)
			if request.Structure.State != record.StructureDerived {
				t.Errorf("the kept JSON body has structure %+v", request.Structure)
			}
			t20iKept(t, x.Response.Message, t20iPermitted("HDR_RESPONSE"))
			t20iEvidence(t, a, x, t20iEntry{"request", config.HeaderFieldPrefix + "authorization", "headers", processing.DispositionRemoved})
		},
	}}
	setup := t20iSetup{
		pipelines:    []map[string]any{t20iPipeline("t20i", []string{"account"}, t20iSlot("auth", config.RemoveHeaders, map[string]any{"headers": []string{"authorization"}}))},
		requirements: []cp.Requirement{t20iRequirement("t20i-auth", config.HeaderFieldPrefix+"authorization")},
	}
	t20iAssert(t, t20iRun(t, setup, cases), []string{"t20i"}, cases)
}
