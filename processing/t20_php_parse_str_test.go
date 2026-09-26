package processing

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// phpCapture is testdata/php-parse-str.json: which top-level names PHP's own
// parse_str files each wire name of a generated corpus under, captured in the
// laboratory participant's image. research1 re-captures it and fails on any
// difference, so this test is held to the PHP the laboratory runs.
type phpCapture struct {
	Parser    string `json:"parser"`
	Version   string `json:"php_version"`
	Separator string `json:"arg_separator_input"`
	Value     string `json:"value"`
	Count     int    `json:"count"`
	Entries   []struct {
		Wire   string   `json:"wire"`
		Keys   []string `json:"keys"`
		Values []string `json:"values"`
	} `json:"entries"`
}

// Every byte PHP files under a name a rule can configure is removed by a rule
// naming that name, the value's ; included, while a neighbouring parameter
// stays. This is what makes the field operations sound for that PHP; for any
// other parser they are claimed only to remove more.
func TestT20ParameterMatchingCoversPHPParseStr(t *testing.T) {
	raw, err := os.ReadFile("testdata/php-parse-str.json")
	if err != nil {
		t.Fatalf("wiring, not the property: the capture is not readable: %v", err)
	}
	var capture phpCapture
	if err := json.Unmarshal(raw, &capture); err != nil {
		t.Fatalf("wiring, not the property: the capture is not one JSON document: %v", err)
	}
	if capture.Parser != "parse_str" || capture.Version == "" || capture.Separator != "&" || capture.Value != "T20A;T20B" || capture.Count != len(capture.Entries) || capture.Count < 3925 {
		t.Fatalf("wiring, not the property: the capture does not describe a whole corpus: parser=%q version=%q separator=%q value=%q count=%d entries=%d",
			capture.Parser, capture.Version, capture.Separator, capture.Value, capture.Count, len(capture.Entries))
	}

	const neighbour = "keep=T20K"
	var configurable, unconfigurable, unfiled, rewritten int
	for _, entry := range capture.Entries {
		wire, err := hex.DecodeString(entry.Wire)
		if err != nil {
			t.Fatalf("wiring, not the property: entry wire %q is not hex", entry.Wire)
		}
		if len(entry.Keys) == 0 {
			unfiled++
			continue
		}
		for _, hexKey := range entry.Keys {
			key, err := hex.DecodeString(hexKey)
			if err != nil {
				t.Fatalf("wiring, not the property: entry key %q is not hex", hexKey)
			}
			if config.ValidParameterName(string(key)) != nil {
				// No rule can name this key, so there is nothing to hold.
				unconfigurable++
				continue
			}
			configurable++
			if string(key) != phpDecode(string(wire)) {
				rewritten++
			}
			query := neighbour + "&" + string(wire) + "=" + capture.Value
			kept, matched := removeParameters(query, []string{string(key)})
			survivors := []string{"T20A", "T20B"}
			for _, hexValue := range entry.Values {
				if filed, err := hex.DecodeString(hexValue); err == nil && len(filed) > 0 {
					survivors = append(survivors, string(filed))
				}
			}
			for _, filed := range survivors {
				if !slices.Contains(matched, string(key)) || strings.Contains(kept, filed) {
					t.Errorf("PROPERTY: PHP %s files %q under %q, and a rule naming %q keeps %q of it: %q", capture.Version, wire, key, key, filed, kept)
					break
				}
			}
			if !strings.Contains(kept, neighbour) {
				t.Errorf("PROPERTY: a rule naming %q removed its neighbour too: %q", key, kept)
			}
		}
	}
	t.Logf("PHP %s: %d entries; %d keys a rule can name, %d of them not the decoded name; %d keys no rule can name; %d entries PHP files under nothing",
		capture.Version, len(capture.Entries), configurable, rewritten, unconfigurable, unfiled)
	// The corpus reaches PHP's rewriting: without names PHP changes, the
	// readings beyond the decoded name would be tested by nothing. The floors
	// are the counts of the PHP 8.5.4 capture.
	if configurable < 1301 || rewritten < 682 {
		t.Fatalf("wiring, not the property: only %d configurable keys, %d rewritten by PHP", configurable, rewritten)
	}
}
