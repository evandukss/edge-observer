package main

import (
	"testing"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/processing"
)

// The account carries a run's exchanges excluded alone, each reason under its
// own name, and its contained decoder faults apart from them.
func TestTheAccountCarriesARunsExclusionsAndDecoderFaults(t *testing.T) {
	outcome := processing.Outcome{DecoderFaults: 5, Excluded: processing.Exclusions{ContentCodingUnsupported: 1,
		ContentDecodingFailed: 2, ContentDecodedTooLarge: 3, ContentDecodingTooCostly: 4}}
	excluded, faults := exclusionsOf(outcome)
	want := account.ExcludedExchanges{ContentCodingUnsupported: 1, ContentDecodingFailed: 2, ContentDecodedTooLarge: 3,
		ContentDecodingTooCostly: 4}
	if excluded == nil || *excluded != want {
		t.Fatalf("the account carries %+v excluded, want %+v", excluded, want)
	}
	if faults == nil || *faults != 5 {
		t.Fatalf("the account carries decoder faults %v, want 5", faults)
	}
	outcome.DecoderFaults = 6
	if *faults != 5 {
		t.Fatal("the account's decoder faults change with the outcome they were read from")
	}
}
