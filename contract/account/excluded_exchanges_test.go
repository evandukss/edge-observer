package account

import (
	"encoding/json"
	"strings"
	"testing"

	observed "github.com/evandukss/edge-observer/account"
)

// excludedFindings is what the contract's shape finds under the aggregate's
// excluded exchanges in a published account, and how many blocks it read.
func excludedFindings(t *testing.T, published map[string]any) ([]Finding, int) {
	t.Helper()
	content, err := json.Marshal(published)
	if err != nil {
		t.Fatal(err)
	}
	_, findings, blocks := readAccount("account", content)
	var out []Finding
	for _, finding := range findings {
		if strings.HasPrefix(finding.At, "processing.aggregate.excluded_exchanges") {
			out = append(out, finding)
		}
	}
	return out, blocks
}

// The exchanges a session excluded alone are carried by reason, each as the
// decimal string of its count; an account whose observer did not count them
// carries no member, never a zero; and the contract's shape refuses a count
// that is not a decimal string and a reason left out.
func TestTheExchangesExcludedAloneAreCarriedAsCounted(t *testing.T) {
	source := filled(t, true)
	source.Processing.ExcludedExchanges = &observed.ExcludedExchanges{ContentCodingUnsupported: 3,
		ContentDecodingFailed: 5, ContentDecodedTooLarge: 0, ContentDecodingTooCostly: 11}
	projected, err := Project(source, NotSupplied())
	if err != nil {
		t.Fatalf("project the account: %v", err)
	}
	if projected.Processing.Aggregate == nil {
		t.Fatal("wiring, not the property: the projection carries no processing aggregate, so nothing in it is read")
	}
	want := ExcludedExchanges{ContentCodingUnsupported: "3", ContentDecodingFailed: "5", ContentDecodedTooLarge: "0",
		ContentDecodingTooCostly: "11"}
	if got := projected.Processing.Aggregate.ExcludedExchanges; got == nil || *got != want {
		t.Fatalf("the excluded exchanges are carried as %+v, want %+v", got, want)
	}

	content, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	var published map[string]any
	if err := json.Unmarshal(content, &published); err != nil {
		t.Fatal(err)
	}
	findings, blocks := excludedFindings(t, published)
	if blocks == 0 {
		t.Fatal("wiring, not the property: the shape read no blocks, so its silence measures nothing")
	}
	if len(findings) != 0 {
		t.Fatalf("the contract refuses the counts it was given: %+v", findings)
	}
	counts := published["processing"].(map[string]any)["aggregate"].(map[string]any)["excluded_exchanges"].(map[string]any)
	for name, change := range map[string]func(){
		"a count that is not decimal": func() { counts["content_decoding_failed"] = "five" },
		"a count with a leading zero": func() { counts["content_decoding_failed"] = "05" },
		"a reason left out":           func() { delete(counts, "content_decoded_too_large") },
	} {
		saved := map[string]any{}
		for key, value := range counts {
			saved[key] = value
		}
		change()
		if found, _ := excludedFindings(t, published); len(found) == 0 {
			t.Errorf("%s was read without a finding", name)
		}
		for key := range counts {
			delete(counts, key)
		}
		for key, value := range saved {
			counts[key] = value
		}
	}

	source.Processing.ExcludedExchanges = nil
	uncounted, err := Project(source, NotSupplied())
	if err != nil {
		t.Fatalf("project the account: %v", err)
	}
	if uncounted.Processing.Aggregate == nil || uncounted.Processing.Aggregate.ExcludedExchanges != nil {
		t.Fatalf("an account that did not count exclusions carries %+v", uncounted.Processing.Aggregate)
	}
	content, err = json.Marshal(uncounted)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "excluded_exchanges") {
		t.Fatal("an account that did not count exclusions publishes the member")
	}
}

// The decodings whose decoder library failed are carried as the decimal
// string of their count, apart from the exchanges excluded alone; an account
// whose observer did not count them carries no member, never a zero; and the
// contract's shape refuses a count that is not a decimal string.
func TestTheDecoderFaultsAreCarriedAsCounted(t *testing.T) {
	source := filled(t, true)
	faults := uint64(2)
	source.Processing.DecoderFaults = &faults
	projected, err := Project(source, NotSupplied())
	if err != nil {
		t.Fatalf("project the account: %v", err)
	}
	if projected.Processing.Aggregate == nil {
		t.Fatal("wiring, not the property: the projection carries no processing aggregate, so nothing in it is read")
	}
	if got := projected.Processing.Aggregate.DecoderFaults; got != "2" {
		t.Fatalf("the decoder faults are carried as %q, want \"2\"", got)
	}
	content, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	var published map[string]any
	if err := json.Unmarshal(content, &published); err != nil {
		t.Fatal(err)
	}
	aggregate := published["processing"].(map[string]any)["aggregate"].(map[string]any)
	findings := func() []Finding {
		content, err := json.Marshal(published)
		if err != nil {
			t.Fatal(err)
		}
		_, all, blocks := readAccount("account", content)
		if blocks == 0 {
			t.Fatal("wiring, not the property: the shape read no blocks, so its silence measures nothing")
		}
		var out []Finding
		for _, finding := range all {
			if strings.HasPrefix(finding.At, "processing.aggregate.decoder_faults") {
				out = append(out, finding)
			}
		}
		return out
	}
	if found := findings(); len(found) != 0 {
		t.Fatalf("the contract refuses the count it was given: %+v", found)
	}
	aggregate["decoder_faults"] = "two"
	if found := findings(); len(found) == 0 {
		t.Error("a decoder fault count that is not decimal was read without a finding")
	}

	source.Processing.DecoderFaults = nil
	uncounted, err := Project(source, NotSupplied())
	if err != nil {
		t.Fatalf("project the account: %v", err)
	}
	content, err = json.Marshal(uncounted)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "decoder_faults") {
		t.Fatal("an account that did not count decoder faults publishes the member")
	}
}
