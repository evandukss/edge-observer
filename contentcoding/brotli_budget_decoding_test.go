package contentcoding

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"
	"time"

	original "github.com/andybalholm/brotli"
)

// The brotli work budget on the SHIPPED constants (BrotliWorkBase,
// BrotliWorkPerByte, brotliWorkCeiling). These two tests measure what the
// exact-boundary seam cases in brotli_budget_seam_decoding_test.go do not: the
// real crafted fixture stopped under the shipped budget, and that every
// non-adversarial calibration stream decodes under it. The exact C + k x D and
// W_abs boundaries, by lowered test-only parameters, are the seam cases; the
// earlier search-based boundary test is removed as redundant with them.

// budgetOutcome is what one Decode of a brotli stream came to.
type budgetOutcome struct {
	result  Result
	stage   StageIO
	elapsed time.Duration
	alloc   uint64
}

// budgetDecode decodes a brotli stream under bound through a ledger and checks
// what every outcome owes: one observed stage, nothing retained unless Decoded,
// and every charge returned. It is for streams whose brotli header is admitted,
// so a stage is always observed.
func budgetDecode(t *testing.T, encoded []byte, bound int) budgetOutcome {
	t.Helper()
	list := decodingList(Brotli)
	ledger := &decodingLedger{t: t, list: list, bound: bound}
	var out budgetOutcome
	observed := 0
	options := Options{Bound: bound, Reserver: ledger, Observe: func(s StageIO) { out.stage = s; observed++ }}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	started := time.Now()
	out.result = Decode(list, encoded, options)
	out.elapsed = time.Since(started)
	runtime.ReadMemStats(&after)
	out.alloc = after.TotalAlloc - before.TotalAlloc
	if out.result.Outcome == 0 {
		t.Fatal("wiring, not the property: Decode returned no outcome")
	}
	if observed != 1 {
		t.Fatalf("wiring, not the property: %d stages observed, want 1", observed)
	}
	if out.result.Outcome == Decoded {
		if out.result.Charge > 0 {
			ledger.Release(Charge{Kind: OutputCharge, Stage: 1, Bytes: out.result.Charge})
		}
	} else if out.result.Body != nil || out.result.Charge != 0 {
		t.Errorf("a stage that ended %v retained body=%d charge=%d", out.result.Outcome, len(out.result.Body), out.result.Charge)
	}
	if ledger.total() != 0 {
		t.Errorf("decode left %d bytes charged", ledger.total())
	}
	if out.stage.Work < 0 {
		t.Errorf("negative work %d", out.stage.Work)
	}
	return out
}

// The crafted stream, 65536 metablocks of 256 block types, 5,300,226 bytes that
// decode to 65,536, is stopped early by the SHIPPED budget. Its work at the
// stop and its capped whole-Decode time are recorded; a cheap stream of the
// same shape with one block type decodes.
func TestBrotliWorkBudgetStopsTheCraftedStream(t *testing.T) {
	const bound = 8 << 20
	encoded, plain := brotliContextStream(256, 65536)
	brotliCheckAuthored(t, "context-256-65536", encoded)
	if !bytes.Equal(decodingReference(t, "br", encoded), plain) {
		t.Fatal("wiring, not the property: the crafted stream does not decode with the original decoder")
	}
	got := budgetDecode(t, encoded, bound)
	if got.result.Outcome != DecodingTooCostly || got.result.Stage != 1 || got.result.Outcome.Reason() != ReasonDecodingTooCostly {
		t.Fatalf("the crafted stream ended %v, stage %d, reason %q, want DecodingTooCostly",
			got.result.Outcome, got.result.Stage, got.result.Outcome.Reason())
	}
	if got.result.Body != nil {
		t.Error("the refused crafted stream retained a partial body")
	}
	if got.stage.Returned >= int64(len(plain)) || got.stage.Read >= got.stage.Input {
		t.Errorf("the stream was not stopped early: returned %d of %d, read %d of %d", got.stage.Returned, len(plain), got.stage.Read, got.stage.Input)
	}
	// W at the stop and the capped whole-Decode time are RECORDS (criterion row 1a).
	t.Logf("crafted stream stop: work=%d (C=%d k=%d W_abs=%d), returned=%d of %d, read=%d of %d, whole Decode=%s, alloc=%d",
		got.stage.Work, int64(BrotliWorkBase), int64(BrotliWorkPerByte), int64(brotliWorkCeiling),
		got.stage.Returned, len(plain), got.stage.Read, got.stage.Input, got.elapsed, got.alloc)

	t.Run("cheap-ordinary-decodes", func(t *testing.T) {
		enc, pl := brotliContextStream(1, 64)
		g := budgetDecode(t, enc, bound)
		if g.result.Outcome != Decoded || !bytes.Equal(g.result.Body, pl) {
			t.Fatalf("a cheap one-block-type stream ended %v at work %d, want Decoded", g.result.Outcome, g.stage.Work)
		}
		t.Logf("cheap control: work=%d for %d bytes, whole Decode=%s", g.stage.Work, len(pl), g.elapsed)
	})
}

// brotliDeclaredWindow is the window a stream's first byte declares (RFC 7932
// section 9.1), in bytes.
func brotliDeclaredWindow(first byte) int {
	var wbits int
	switch {
	case first&1 == 0:
		wbits = 16
	case first>>1&7 != 0:
		wbits = 17 + int(first>>1&7)
	case first>>4&7 == 0:
		wbits = 17
	default:
		wbits = 8 + int(first>>4&7)
	}
	return 1<<wbits - 16
}

// budgetCorpus is the calibration corpus's contents: compressible,
// incompressible and structured, small and large.
func budgetCorpus() []struct {
	name  string
	plain []byte
} {
	const small, large = 512, 16 << 10
	phrase := []byte("the quick brown fox jumps over the lazy dog; ")
	compressible := func(n int) []byte { return bytes.Repeat(phrase, n/len(phrase)+1)[:n] }
	incompressible := func(n int) []byte {
		out := make([]byte, n)
		seed := uint32(0x9e3779b9)
		for i := range out {
			seed ^= seed << 13
			seed ^= seed >> 17
			seed ^= seed << 5
			out[i] = byte(seed)
		}
		return out
	}
	structured := func(n int) []byte {
		var b bytes.Buffer
		for i := 0; b.Len() < n; i++ {
			fmt.Fprintf(&b, "{\"id\":%d,\"name\":\"item-%d\",\"tags\":[\"a\",\"b\"],\"value\":%d.%02d}\n", i, i, i*7, i%100)
		}
		return b.Bytes()[:n]
	}
	return []struct {
		name  string
		plain []byte
	}{
		{"compressible-small", compressible(small)}, {"compressible-large", compressible(large)},
		{"incompressible-small", incompressible(small)}, {"incompressible-large", incompressible(large)},
		{"structured-small", structured(small)}, {"structured-large", structured(large)},
	}
}

// budgetEncode encodes plain with the original encoder at quality and window,
// flushed every flush bytes, or not at all when flush is 0.
func budgetEncode(t *testing.T, quality, window, flush int, plain []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := original.NewWriterOptions(&b, original.WriterOptions{Quality: quality, LGWin: window})
	step := len(plain)
	if flush > 0 {
		step = flush
	}
	for start := 0; start < len(plain); start += step {
		if _, err := w.Write(plain[start:min(start+step, len(plain))]); err != nil {
			t.Fatal(err)
		}
		if flush > 0 {
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// Every non-adversarial calibration stream decodes under the SHIPPED budget at
// the real body bound, MaxBodyBytes: qualities 0 to 11, windows 10 to 24,
// unflushed and flushed every 16, 64, 256 and 4096 bytes, over the six
// contents. A stream whose declared window is larger than the bound is a
// content_decoded_too_large window refusal, counted apart from any budget
// refusal (criterion row 1a rev 53). No non-adversarial stream is refused for
// its work.
func TestBrotliCalibrationCorpusDecodes(t *testing.T) {
	const bound = 8 << 20
	corpus := budgetCorpus()
	flushes := []int{0, 16, 64, 256, 4096}
	count, decoded, windowRefusals := 0, 0, 0
	tooCostly := 0
	for quality := 0; quality <= 11; quality++ {
		for window := 10; window <= 24; window++ {
			for _, flush := range flushes {
				for _, content := range corpus {
					encoded := budgetEncode(t, quality, window, flush, content.plain)
					count++
					got := Decode(decodingList(Brotli), encoded, Options{Bound: bound})
					if brotliDeclaredWindow(encoded[0]) > bound {
						if got.Outcome != DecodedTooLarge {
							t.Errorf("q%d w%d flush%d %s: declared window over the bound ended %v, want DecodedTooLarge", quality, window, flush, content.name, got.Outcome)
						} else {
							windowRefusals++
						}
						continue
					}
					switch got.Outcome {
					case Decoded:
						if !bytes.Equal(got.Body, content.plain) {
							t.Errorf("q%d w%d flush%d %s: decoded bytes differ", quality, window, flush, content.name)
						}
						decoded++
					case DecodingTooCostly:
						tooCostly++
						if tooCostly <= 20 {
							t.Errorf("q%d w%d flush%d %s (%d encoded bytes): a non-adversarial stream was refused for its work", quality, window, flush, content.name, len(encoded))
						}
					default:
						t.Errorf("q%d w%d flush%d %s: unexpected outcome %v", quality, window, flush, content.name, got.Outcome)
					}
				}
			}
		}
	}
	if want := 12 * 15 * len(flushes) * len(corpus); count != want {
		t.Fatalf("wiring, not the property: %d streams, want %d", count, want)
	}
	t.Logf("corpus: %d streams, %d decoded, %d window refusals (content_decoded_too_large), %d work refusals", count, decoded, windowRefusals, tooCostly)
}
