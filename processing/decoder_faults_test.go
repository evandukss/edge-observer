package processing_test

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/evandukss/edge-observer/contentcoding"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/processing"
)

// A decoding whose decoder library failed and was contained excludes its
// exchange alone as a failed decoding, counted once, and is counted once more
// as a decoder fault; the exchanges around it are written, and traffic goes
// on. A failed decoding that was not a fault excludes the same way and counts
// no fault. The fault's value cannot reach this layer at all: the decoder
// reports it as Result.Fault, a boolean.
func TestAContainedDecoderFaultIsCountedBesideItsFailedDecoding(t *testing.T) {
	const marker = "decoder-fault-marker"
	for _, tc := range []struct {
		name   string
		fault  bool
		faults uint64
	}{{"fault", true, 1}, {"failed-decoding-control", false, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			decoded := 0
			r := newReleasing(t, releasingOptions{decoder: func(list contentcoding.List, encoded []byte,
				options contentcoding.Options) contentcoding.Result {
				decoded++
				if bytes.Equal(encoded, []byte(marker)) {
					return contentcoding.Result{Outcome: contentcoding.DecodingFailed, Stage: 1, Fault: tc.fault}
				}
				return contentcoding.Decode(list, encoded, options)
			}})
			c := converse(t, 1, append(append(pair("/a"), codedGet("/b"), read(codedResponse("gzip", marker))),
				pair("/c")...)...)
			r.give(c.fragments...)
			r.drain()
			if decoded != 1 {
				t.Fatalf("wiring, not the property: the decoder was asked %d times, want once for /b's response", decoded)
			}
			released := r.released()
			if len(released) != 3 || released[1].Outcome != processing.ReleaseExcluded {
				t.Fatalf("the releases are %+v, want /b excluded at index 1", released)
			}
			r.writtenAt(1, map[string]int{"/a": 0, "/c": 2})
			if r.outcome.Excluded != (processing.Exclusions{ContentDecodingFailed: 1}) || r.outcome.DecoderFaults != tc.faults {
				t.Fatalf("the outcome counts %+v excluded and %d decoder faults, want one failed decoding and %d faults",
					r.outcome.Excluded, r.outcome.DecoderFaults, tc.faults)
			}
			next := converse(t, 2, pair("/after")...)
			r.give(next.fragments...)
			r.drain()
			if after := r.lines(processing.ArtifactExchange, 2); len(after) != 1 || target(t, after[0]) != "/after" {
				t.Fatalf("traffic after the fault wrote %d exchange lines on the next connection, want /after", len(after))
			}
			r.retire(c.retirement)
			r.drain()
			if got := excludedCounts(t, r.lines(processing.ArtifactConnection, 1)[0]); got.ContentDecodingFailed != "1" {
				t.Fatalf("the connection line counts %+v", got)
			}
			if r.outcome.DecoderFaults != tc.faults {
				t.Fatalf("after retirement the outcome counts %d decoder faults, want %d", r.outcome.DecoderFaults, tc.faults)
			}
		})
	}
}

// A decoding that would take more work than its budget excludes its exchange
// alone as content_decoding_too_costly, counted once, in the outcome and on
// the connection line, and the exchanges around it are written.
func TestADecodingTooCostlyIsExcludedAloneAndCounted(t *testing.T) {
	const marker = "too-costly-marker"
	decoded := 0
	r := newReleasing(t, releasingOptions{decoder: func(list contentcoding.List, encoded []byte,
		options contentcoding.Options) contentcoding.Result {
		decoded++
		if bytes.Equal(encoded, []byte(marker)) {
			return contentcoding.Result{Outcome: contentcoding.DecodingTooCostly, Stage: 1}
		}
		return contentcoding.Decode(list, encoded, options)
	}})
	c := converse(t, 1, append(append(pair("/a"), codedGet("/b"), read(codedResponse("br", marker))), pair("/c")...)...)
	r.give(c.fragments...)
	r.drain()
	if decoded != 1 {
		t.Fatalf("wiring, not the property: the decoder was asked %d times, want once for /b's response", decoded)
	}
	r.writtenAt(1, map[string]int{"/a": 0, "/c": 2})
	if r.outcome.Excluded != (processing.Exclusions{ContentDecodingTooCostly: 1}) || r.outcome.DecoderFaults != 0 {
		t.Fatalf("the outcome counts %+v excluded and %d decoder faults, want one too costly and none",
			r.outcome.Excluded, r.outcome.DecoderFaults)
	}
	r.retire(c.retirement)
	r.drain()
	if got := excludedCounts(t, r.lines(processing.ArtifactConnection, 1)[0]); got != (processing.ExcludedExchanges{
		ContentCodingUnsupported: "0", ContentDecodingFailed: "0", ContentDecodedTooLarge: "0",
		ContentDecodingTooCostly: "1"}) {
		t.Fatalf("the connection line counts %+v", got)
	}
}

// Decoder faults on connections that different workers own add up in the run's
// outcome, as the exchanges they excluded do.
func TestDecoderFaultsFromSeveralWorkersAddUp(t *testing.T) {
	const connections, marker = 8, "decoder-fault-marker"
	var mutex sync.Mutex
	owners := map[fragment.ConnectionID]int{}
	run, store := startRun(t, rulesPlan(t, ""), runOptions{workers: 4, output: &lines{},
		taken: func(worker int, _ fragment.Process, id fragment.ConnectionID) {
			mutex.Lock()
			owners[id] = worker
			mutex.Unlock()
		},
		decoder: func(list contentcoding.List, encoded []byte, options contentcoding.Options) contentcoding.Result {
			if bytes.Equal(encoded, []byte(marker)) {
				return contentcoding.Result{Outcome: contentcoding.DecodingFailed, Stage: 1, Fault: true}
			}
			return contentcoding.Decode(list, encoded, options)
		}})
	for id := 1; id <= connections; id++ {
		c := converse(t, fragment.ConnectionID(id), codedGet("/b"), read(codedResponse("gzip", marker)))
		for _, f := range c.fragments {
			if err := store.Write(f); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.Connection(c.retirement); err != nil {
			t.Fatal(err)
		}
	}
	run.Route()
	o, err := run.Finish(context.Background(), settled)
	if err != nil {
		t.Fatal(err)
	}
	workers := map[int]bool{}
	mutex.Lock()
	for _, worker := range owners {
		workers[worker] = true
	}
	owned := len(owners)
	mutex.Unlock()
	if owned != connections || len(workers) < 2 {
		t.Fatalf("wiring, not the property: %d connections were taken, by %d workers, so the faults were not split "+
			"between workers", owned, len(workers))
	}
	if o.DecoderFaults != connections || o.Excluded != (processing.Exclusions{ContentDecodingFailed: connections}) {
		t.Fatalf("the run counts %d decoder faults and %+v excluded over %d workers, want %d of each", o.DecoderFaults,
			o.Excluded, len(workers), connections)
	}
}
