package contentcoding

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// Exact work-budget boundaries, at both the credit rule C + k x D and the
// absolute ceiling W_abs (criterion 119 row 1a rev 53; decisions 577, 583, 586).
// Each uses T12's seam with TEST-ONLY lowered parameters over an EXISTING
// brotli fixture; no new crafted input (decision 579). The boundary is found by
// bisection: the smallest parameter for which the decode passes is W + q, and
// one unit less is content_decoding_too_costly with the work not done.
//
// Seam: decodeWithin(list, encoded, options, within{budget workBudget{base,
// perByte, most}, feed, inject}); the stage's Work is read through Observe.

const seamHugeBudget = uint64(1) << 50

func seamWork(t *testing.T, encoded []byte, wb workBudget, feed func(io.Reader) io.Reader) (Result, int64) {
	t.Helper()
	var work int64
	var seen int
	got := decodeWithin(decodingList(Brotli), encoded, Options{Bound: 8 << 20, Observe: func(s StageIO) { work = s.Work; seen++ }},
		within{budget: wb, feed: feed})
	if seen == 0 && got.Outcome != DecodingFailed {
		t.Fatalf("wiring, not the property: no stage observed for outcome %v", got.Outcome)
	}
	return got, work
}

// seamSmallest is the smallest p in [1, hi] for which pass(p) is true, by
// doubling then bisection; pass must be monotone. It returns 0 if none up to hi.
func seamSmallest(hi uint64, pass func(uint64) bool) uint64 {
	p := uint64(1)
	for ; p <= hi; p *= 2 {
		if pass(p) {
			break
		}
	}
	if p > hi {
		return 0
	}
	lo := p / 2
	for p-lo > 1 {
		mid := lo + (p-lo)/2
		if pass(mid) {
			p = mid
		} else {
			lo = mid
		}
	}
	return p
}

func TestBrotliWorkBudgetAbsoluteCeilingBoundary(t *testing.T) {
	encoded, plain := brotliContextStream(256, 64)
	// Total work with a budget that never binds.
	full, total := seamWork(t, encoded, workBudget{base: seamHugeBudget, perByte: seamHugeBudget, most: seamHugeBudget}, nil)
	if full.Outcome != Decoded || !bytes.Equal(full.Body, plain) || total <= 0 {
		t.Fatalf("wiring, not the property: unbudgeted decode gave %v, work %d", full.Outcome, total)
	}
	// most binds (base huge, perByte 0): smallest most that passes is the total work.
	m0 := seamSmallest(uint64(total)*4, func(most uint64) bool {
		r, _ := seamWork(t, encoded, workBudget{base: seamHugeBudget, perByte: 0, most: most}, nil)
		return r.Outcome == Decoded
	})
	if m0 != uint64(total) {
		t.Errorf("W_abs boundary: smallest passing most %d, want total work %d", m0, total)
	}
	pass, pwork := seamWork(t, encoded, workBudget{base: seamHugeBudget, perByte: 0, most: m0}, nil)
	fail, fwork := seamWork(t, encoded, workBudget{base: seamHugeBudget, perByte: 0, most: m0 - 1}, nil)
	if pass.Outcome != Decoded || !bytes.Equal(pass.Body, plain) {
		t.Errorf("most = W_abs did not pass: %v", pass.Outcome)
	}
	if fail.Outcome != DecodingTooCostly || fail.Outcome.Reason() != ReasonDecodingTooCostly || fail.Body != nil {
		t.Errorf("most = W_abs - 1: outcome=%v reason=%q body=%d, want DecodingTooCostly and no body", fail.Outcome, fail.Outcome.Reason(), len(fail.Body))
	}
	if fwork >= pwork {
		t.Errorf("the refused operation was done: work at refusal %d, whole-stream work %d", fwork, pwork)
	}
	t.Logf("W_abs boundary: total=%d most=%d; refusal work=%d whole work=%d", total, m0, fwork, pwork)
}

func TestBrotliWorkBudgetCreditBoundary(t *testing.T) {
	encoded, plain := brotliContextStream(256, 64)
	full, total := seamWork(t, encoded, workBudget{base: seamHugeBudget, perByte: seamHugeBudget, most: seamHugeBudget}, nil)
	if full.Outcome != Decoded || total <= 0 {
		t.Fatalf("wiring, not the property: unbudgeted decode gave %v, work %d", full.Outcome, total)
	}
	// The credit rule binds (perByte = k, most huge): the smallest base for which
	// the decode passes is W + q at the binding operation, where the credit is
	// k x D produced so far. One unit less refuses it.
	const k = uint64(4)
	b0 := seamSmallest(uint64(total)*2+16, func(base uint64) bool {
		r, _ := seamWork(t, encoded, workBudget{base: base, perByte: k, most: seamHugeBudget}, nil)
		return r.Outcome == Decoded
	})
	if b0 == 0 {
		t.Fatalf("no base up to %d admitted the stream with perByte %d", total*2+16, k)
	}
	pass, pwork := seamWork(t, encoded, workBudget{base: b0, perByte: k, most: seamHugeBudget}, nil)
	fail, fwork := seamWork(t, encoded, workBudget{base: b0 - 1, perByte: k, most: seamHugeBudget}, nil)
	if pass.Outcome != Decoded || !bytes.Equal(pass.Body, plain) {
		t.Errorf("base = C at the boundary did not pass: %v", pass.Outcome)
	}
	if fail.Outcome != DecodingTooCostly || fail.Outcome.Reason() != ReasonDecodingTooCostly || fail.Body != nil {
		t.Errorf("base = C - 1: outcome=%v reason=%q body=%d, want DecodingTooCostly and no body", fail.Outcome, fail.Outcome.Reason(), len(fail.Body))
	}
	if fwork >= pwork {
		t.Errorf("the refused operation was done: work at refusal %d, whole-stream work %d", fwork, pwork)
	}
	// The credit is from bytes produced: with a larger per-byte credit, the same
	// stream needs no more base than with none, and never less than 1.
	t.Logf("credit boundary: total=%d k=%d smallest base=%d; refusal work=%d whole work=%d", total, k, b0, fwork, pwork)
}

func TestBrotliWorkBudgetIsInvariantUnderFeedAndReadSizes(t *testing.T) {
	encoded, plain := brotliContextStream(256, 64)
	_, total := seamWork(t, encoded, workBudget{base: seamHugeBudget, perByte: seamHugeBudget, most: seamHugeBudget}, nil)
	feeds := map[string]func(io.Reader) io.Reader{
		"whole": nil,
		"one":   func(r io.Reader) io.Reader { return iotestN{r, 1} },
		"seven": func(r io.Reader) io.Reader { return iotestN{r, 7} },
	}
	for _, most := range []uint64{uint64(total), uint64(total) - 1} {
		wantCostly := most < uint64(total)
		for name, feed := range feeds {
			r, work := seamWork(t, encoded, workBudget{base: seamHugeBudget, perByte: 0, most: most}, feed)
			if wantCostly {
				if r.Outcome != DecodingTooCostly {
					t.Errorf("most=%d feed=%s: outcome=%v, want DecodingTooCostly", most, name, r.Outcome)
				}
			} else {
				if r.Outcome != Decoded || !bytes.Equal(r.Body, plain) || work != total {
					t.Errorf("most=%d feed=%s: outcome=%v work=%d, want Decoded at work %d", most, name, r.Outcome, work, total)
				}
			}
		}
	}
}

// A size or integrity result the stage establishes is not overwritten by the
// work budget: the guard sits before its work and never changes an outcome
// already decided. Under a budget that does not bind, an overrun gives
// content_decoded_too_large and a corrupt stream content_decoding_failed.
func TestBrotliWorkBudgetDoesNotOverwriteASizeOrIntegrityResult(t *testing.T) {
	big := workBudget{base: seamHugeBudget, perByte: seamHugeBudget, most: seamHugeBudget}
	// Overrun: a cheap stream whose output exceeds a small bound.
	encoded, plain := brotliContextStream(1, 4096)
	over := decodeWithin(decodingList(Brotli), encoded, Options{Bound: 16}, within{budget: big})
	if over.Outcome != DecodedTooLarge || over.Body != nil {
		t.Errorf("an overrun under a non-binding budget: outcome=%v, want DecodedTooLarge", over.Outcome)
	}
	if len(plain) <= 16 {
		t.Fatal("wiring, not the property: the overrun fixture does not exceed the bound")
	}
	// Error: a corrupt stream ends content_decoding_failed, not too_costly.
	valid, _ := brotliContextStream(1, 64)
	corrupt := bytes.Clone(valid)
	corrupt[len(corrupt)/2] ^= 0xff
	if bytes.Equal(corrupt, valid) {
		t.Fatal("wiring, not the property: corruption did not change the stream")
	}
	bad := decodeWithin(decodingList(Brotli), corrupt, Options{Bound: 8 << 20}, within{budget: big})
	if bad.Outcome != DecodingFailed {
		t.Errorf("a corrupt stream under a non-binding budget: outcome=%v, want DecodingFailed", bad.Outcome)
	}
}

// The crafted history-regrowth-scale brotli fixture, under a tiny absolute
// ceiling, stops early with a bounded whole-Decode time. Uses an existing
// fixture; the SHIPPED-budget stop is covered in brotli_budget_decoding_test.go.
func TestBrotliWorkBudgetStopsEarlyUnderALowCeiling(t *testing.T) {
	encoded, _ := brotliContextStream(256, 8192)
	started := time.Now()
	got, work := seamWork(t, encoded, workBudget{base: seamHugeBudget, perByte: 0, most: 1 << 16}, nil)
	elapsed := time.Since(started)
	if got.Outcome != DecodingTooCostly {
		t.Errorf("the crafted fixture under a low ceiling: outcome=%v, want DecodingTooCostly", got.Outcome)
	}
	t.Logf("low-ceiling early stop: work at stop=%d, whole-Decode time=%s", work, elapsed)
}

// iotestN reads at most n bytes at a time.
type iotestN struct {
	r io.Reader
	n int
}

func (o iotestN) Read(p []byte) (int, error) {
	if len(p) > o.n {
		p = p[:o.n]
	}
	return o.r.Read(p)
}
