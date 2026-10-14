package contentcoding

import (
	"bytes"
	"io"
	"math"
	"slices"
	"testing"

	"github.com/andybalholm/brotli"
	ours "github.com/evandukss/edge-observer/internal/brotli"
)

// flushedBrotliOf encodes p in a window of WBITS 10, which every bound admits,
// flushing every so many bytes.
func flushedBrotliOf(p []byte, every int) []byte {
	var b bytes.Buffer
	w := brotli.NewWriterOptions(&b, brotli.WriterOptions{Quality: 5, LGWin: 10})
	for i := 0; i < len(p); i += every {
		if _, err := w.Write(p[i:min(i+every, len(p))]); err != nil {
			panic(err)
		}
		if err := w.Flush(); err != nil {
			panic(err)
		}
	}
	written(w, nil)
	return b.Bytes()
}

// counted is the work internal/brotli counts reading encoded to its end with
// no budget.
func counted(t *testing.T, encoded []byte) uint64 {
	t.Helper()
	r := ours.NewReader(bytes.NewReader(encoded))
	if _, err := io.ReadAll(r); err != nil || r.Work() == 0 {
		t.Fatalf("wiring, not the property: the stream ended with %v after %d units", err, r.Work())
	}
	return r.Work()
}

// decodeUnder runs one br Decode within budget, with a ledger it checks
// afterwards, and returns the stage's I/O beside the result.
func decodeUnder(t *testing.T, encoded []byte, bound int, budget workBudget) (Result, StageIO, *ledger) {
	t.Helper()
	led := newLedger(t)
	var stages []StageIO
	r := decodeWithin(list(t, "br"), encoded, Options{Bound: bound, Reserver: led, Observe: func(s StageIO) { stages = append(stages, s) }}, within{budget: budget})
	led.settled(r, 1)
	if len(stages) != 1 {
		t.Fatalf("wiring, not the property: %d stages observed", len(stages))
	}
	return r, stages[0], led
}

func TestAStageReportsTheWorkItCounted(t *testing.T) {
	body := text(64<<10, 3)
	encoded := flushedBrotliOf(body, 256)
	r, stages, _ := observed(t, list(t, "br"), encoded, 1<<20)
	expect(t, r, Decoded, body)
	if want := counted(t, encoded); stages[0].Work != int64(want) {
		t.Fatalf("the stage reported %d units, the decoder counts %d", stages[0].Work, want)
	}
	for _, c := range []Coding{Gzip, Deflate, Zstd} {
		r, stages, _ := observed(t, list(t, c.String()), encode(c, body), 1<<20)
		expect(t, r, Decoded, body)
		if stages[0].Work != 0 {
			t.Fatalf("%s reported %d units of work", c, stages[0].Work)
		}
	}
}

func TestAStageOverItsBudgetIsTooCostly(t *testing.T) {
	const most = math.MaxUint64
	body := text(64<<10, 4)
	encoded := flushedBrotliOf(body, 256)
	total := counted(t, encoded)
	for _, c := range []struct {
		name   string
		budget workBudget
		want   Outcome
	}{
		{"the base, exactly", workBudget{total, 0, most}, Decoded},
		{"the base, one unit short", workBudget{total - 1, 0, most}, DecodingTooCostly},
		{"the ceiling, exactly", workBudget{most, most, total}, Decoded},
		{"the ceiling one unit short, beside unlimited credit", workBudget{most, most, total - 1}, DecodingTooCostly},
		{"nothing at all", workBudget{0, 0, 0}, DecodingTooCostly},
	} {
		r, stage, led := decodeUnder(t, encoded, 1<<20, c.budget)
		expect(t, r, c.want, body)
		if c.want == Decoded {
			if stage.Work != int64(total) {
				t.Fatalf("%s: %d units, the decoder counts %d", c.name, stage.Work, total)
			}
			continue
		}
		if r.Outcome.Reason() != ReasonDecodingTooCostly || stage.Work >= int64(total) {
			t.Fatalf("%s: reason %q after %d units of %d", c.name, r.Outcome.Reason(), stage.Work, total)
		}
		// What the refusal gave back: the output buffers it had reserved,
		// each released once (the ledger fails the test on a second release).
		if c.budget.base > 0 && (stage.Returned == 0 || !slices.ContainsFunc(led.asked, func(c Charge) bool { return c.Kind == OutputCharge })) {
			t.Fatalf("wiring, not the property: %s refused with %d bytes returned and no output reserved", c.name, stage.Returned)
		}
	}
}

func TestTheFirstDecisiveResultWins(t *testing.T) {
	body := text(64<<10, 5)
	encoded := flushedBrotliOf(body, 256)
	total := counted(t, encoded)
	// The output passes bound + 1 bytes long before the last unit of work.
	r, stage, _ := decodeUnder(t, encoded, 4096, workBudget{total - 1, 0, math.MaxUint64})
	if r.Outcome != DecodedTooLarge || stage.Returned != 4097 {
		t.Fatalf("a refusal after the output stop: outcome %d after %d bytes, want %d after 4097", r.Outcome, stage.Returned, DecodedTooLarge)
	}
	// The first unit of work comes before the first byte.
	r, stage, _ = decodeUnder(t, encoded, 4096, workBudget{0, 0, math.MaxUint64})
	if r.Outcome != DecodingTooCostly || stage.Returned != 0 {
		t.Fatalf("a refusal before the output stop: outcome %d after %d bytes, want %d after none", r.Outcome, stage.Returned, DecodingTooCostly)
	}
}
