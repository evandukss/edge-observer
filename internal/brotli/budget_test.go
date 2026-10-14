package brotli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"testing"

	upstream "github.com/andybalholm/brotli"
)

// flushedEncode encodes p flushing every so many bytes, so that the stream
// carries a metablock, with its prefix codes and maps, for each piece.
func flushedEncode(p []byte, quality, lgwin, every int) []byte {
	var b bytes.Buffer
	w := upstream.NewWriterOptions(&b, upstream.WriterOptions{Quality: quality, LGWin: lgwin})
	for i := 0; i < len(p); i += every {
		if _, err := w.Write(p[i:min(i+every, len(p))]); err != nil {
			panic(err)
		}
		if err := w.Flush(); err != nil {
			panic(err)
		}
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// budgetStreams are encoder output with a metablock for every 64 bytes, and
// with few metablocks.
func budgetStreams() map[string][]byte {
	streams := map[string][]byte{}
	for _, q := range []int{1, 5, 11} {
		streams[fmt.Sprintf("q%d flushed every 64", q)] = flushedEncode(mixed(20000, int64(q)), q, 16, 64)
		streams[fmt.Sprintf("q%d unflushed", q)] = encode(mixed(70000, int64(q)), q, 18)
	}
	return streams
}

// budgetShapes are the sizes input is fed and output read in: whole, and in
// pieces that stop the decoder inside every state it can resume.
var budgetShapes = [][2]int{{1 << 20, 1 << 20}, {1, 7}, {13, 1}, {300, 4096}}

// decodeUnder decodes encoded with a fresh Reader under budget, fed and read in
// shape, and returns what it read, how it ended and the work it counted. A nil
// budget leaves the Reader without one.
func decodeUnder(encoded []byte, budget *[3]uint64, shape [2]int, seed int64) (result, uint64) {
	r := NewReader(&feeder{b: encoded, rng: rand.New(rand.NewSource(seed)), most: shape[0]})
	if budget != nil {
		r.SetBudget(budget[0], budget[1], budget[2])
	}
	got := drain(r, rand.New(rand.NewSource(seed+1)), shape[1], nil)
	return got, r.Work()
}

func TestWorkIsChargedOnceWhateverTheReads(t *testing.T) {
	for name, encoded := range budgetStreams() {
		want := drain(upstream.NewReader(bytes.NewReader(encoded)), rand.New(rand.NewSource(1)), 1<<20, nil)
		var whole uint64
		for i, shape := range budgetShapes {
			got, work := decodeUnder(encoded, nil, shape, int64(i))
			if got.err != "" || !bytes.Equal(got.out, want.out) {
				t.Fatalf("wiring, not the property: %s %v returned %d bytes and %q, the module %d bytes", name, shape, len(got.out), got.err, len(want.out))
			}
			if work == 0 {
				t.Fatalf("wiring, not the property: %s counted no work, so nothing below measured a charge", name)
			}
			if i == 0 {
				whole = work
			} else if work != whole {
				t.Fatalf("%s: %d units read in pieces of %v, %d read whole", name, work, shape, whole)
			}
		}
	}
}

func TestTheBudgetAdmitsExactlyTheWorkCounted(t *testing.T) {
	const most = math.MaxUint64
	for name, encoded := range budgetStreams() {
		want, total := decodeUnder(encoded, nil, budgetShapes[0], 0)
		if want.err != "" || total == 0 || len(want.out) == 0 {
			t.Fatalf("wiring, not the property: %s decoded %d bytes with %q and counted %d", name, len(want.out), want.err, total)
		}
		for _, c := range []struct {
			name    string
			budget  [3]uint64
			refused bool
		}{
			{"the base alone, exactly", [3]uint64{total, 0, most}, false},
			{"the base alone, one unit short", [3]uint64{total - 1, 0, most}, true},
			{"the ceiling exactly, beside unlimited credit", [3]uint64{most, most, total}, false},
			{"the ceiling one unit short, beside unlimited credit", [3]uint64{most, most, total - 1}, true},
			{"no base, so no work before the first byte", [3]uint64{0, most, most}, true},
			{"every limit at its largest", [3]uint64{most, most, most}, false},
		} {
			var refusedAt uint64
			for i, shape := range budgetShapes {
				got, work := decodeUnder(encoded, &c.budget, shape, int64(i))
				if !c.refused {
					if got.err != "" || !bytes.Equal(got.out, want.out) || work != total {
						t.Fatalf("%s, %s, %v: %d bytes, %q, %d units; want all %d bytes and %d units", name, c.name, shape, len(got.out), got.err, work, len(want.out), total)
					}
					continue
				}
				if got.err != ErrTooCostly.Error() || !bytes.HasPrefix(want.out, got.out) || work >= total {
					t.Fatalf("%s, %s, %v: %d bytes, %q, %d units; want a prefix, %q and fewer than %d units", name, c.name, shape, len(got.out), got.err, work, ErrTooCostly, total)
				}
				if c.budget[0] == 0 && (work != 0 || len(got.out) != 0) {
					t.Fatalf("%s, %s, %v: %d units and %d bytes before the first byte was earned", name, c.name, shape, work, len(got.out))
				}
				if i == 0 {
					refusedAt = work
				} else if work != refusedAt {
					t.Fatalf("%s, %s: refused at %d units read in pieces of %v, at %d read whole", name, c.name, work, shape, refusedAt)
				}
			}
		}
	}
}

// A Reader reused through Reset counts what each stream does after the Reset:
// the budget is gone and the count starts again. Its first metablock also
// clears the tree storage the stream before it left, so it can count more than
// a new Reader would for the same stream, and the same each time for the same
// predecessor.
func TestResetClearsTheBudgetAndTheCount(t *testing.T) {
	encoded := budgetStreams()["q5 flushed every 64"]
	_, total := decodeUnder(encoded, nil, budgetShapes[0], 0)
	r := NewReader(bytes.NewReader(encoded))
	r.SetBudget(total/2, 0, math.MaxUint64)
	if _, err := io.ReadAll(r); !errors.Is(err, ErrTooCostly) || r.Work() == 0 {
		t.Fatalf("wiring, not the property: under half its work the stream ended with %v after %d units", err, r.Work())
	}
	var counts []uint64
	for range 3 {
		if err := r.Reset(bytes.NewReader(encoded)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(r); err != nil {
			t.Fatalf("after Reset the stream ended with %v after %d units: the budget outlived the Reset", err, r.Work())
		}
		counts = append(counts, r.Work())
	}
	// The first decode after Reset follows a refused one, the next two follow
	// a whole decode of the same stream, so those two leave the same storage.
	if counts[1] != counts[2] || counts[1] < total || counts[1] >= 2*total {
		t.Fatalf("counts after Reset %v, a new Reader's %d: the count did not start again at each Reset", counts, total)
	}
}

// A Reset after a clean end goes through decoderStateInit alone, where one
// after an error rebuilds the whole Reader, so each path has to clear the
// budget itself.
func TestResetAfterACleanEndClearsTheBudget(t *testing.T) {
	encoded := budgetStreams()["q5 flushed every 64"]
	_, total := decodeUnder(encoded, nil, budgetShapes[0], 0)
	// A reused Reader counts more than a new one for the same stream, so a
	// budget of exactly the new one's count, had it outlived the Reset,
	// would refuse the second decode.
	reused := NewReader(bytes.NewReader(encoded))
	if _, err := io.ReadAll(reused); err != nil {
		t.Fatal(err)
	}
	if err := reused.Reset(bytes.NewReader(encoded)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reused); err != nil || reused.Work() <= total {
		t.Fatalf("wiring, not the property: a reused Reader counted %d against a new one's %d (%v), so a stale budget of %d would refuse nothing", reused.Work(), total, err, total)
	}

	r := NewReader(bytes.NewReader(encoded))
	r.SetBudget(total, 0, math.MaxUint64)
	if _, err := io.ReadAll(r); err != nil || r.Work() != total {
		t.Fatalf("wiring, not the property: at a budget of exactly its work the stream ended with %v after %d units of %d", err, r.Work(), total)
	}
	if err := r.Reset(bytes.NewReader(encoded)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("after a Reset that followed a clean end, the stream ended with %v after %d units: the budget outlived the Reset", err, r.Work())
	}
}
