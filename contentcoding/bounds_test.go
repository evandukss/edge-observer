package contentcoding

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// frameWindow reads the window a zstd frame that is not single-segment
// declares in its window descriptor (RFC 8878 section 3.1.1.1.2).
func frameWindow(t *testing.T, frame []byte) uint64 {
	t.Helper()
	if len(frame) < 6 || frame[4]&(1<<5) != 0 {
		t.Fatal("wiring, not the property: not a frame with a window descriptor")
	}
	base := uint64(1) << (10 + frame[5]>>3)
	return base + base/8*uint64(frame[5]&7)
}

// withWindow is a frame with its window descriptor replaced by one declaring
// 2^(10+exponent) * (1 + mantissa/8). The encoder shrinks the window it
// declares to a small body's size, and a larger declared window decodes the
// same blocks.
func withWindow(frame []byte, exponent, mantissa byte) []byte {
	frame = bytes.Clone(frame)
	if frame[4]&(1<<5) != 0 {
		panic("a single-segment frame has no window descriptor")
	}
	frame[5] = exponent<<3 | mantissa
	return frame
}

// allocatedBy is what the runtime counts as allocated while f runs. Nothing
// else in this package's tests runs at the same time.
func allocatedBy(f func()) int64 {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return int64(after.TotalAlloc - before.TotalAlloc)
}

// observed decodes with a ledger and records each stage's I/O.
func observed(t *testing.T, l List, encoded []byte, bound int) (Result, []StageIO, int64) {
	t.Helper()
	led := newLedger(t)
	var stages []StageIO
	options := Options{Bound: bound, Reserver: led, Observe: func(s StageIO) { stages = append(stages, s) }}
	stages = make([]StageIO, 0, MaxCodings)
	var r Result
	total := allocatedBy(func() { r = Decode(l, encoded, options) })
	led.settled(r, l.Len())
	for _, s := range stages {
		if s.Read > s.Input || s.Returned > int64(bound)+1 {
			t.Errorf("stage %d read %d of %d and returned %d under a bound of %d", s.Stage, s.Read, s.Input, s.Returned, bound)
		}
	}
	return r, stages, total
}

func TestAnOutputAtTheBoundPassesAndOneByteMoreDoesNot(t *testing.T) {
	body := text(5000, 20)
	for _, c := range []struct {
		coding  Coding
		encoded []byte
	}{
		{Gzip, gzipOf(body)},
		{Deflate, zlibOf(body)},
		{Deflate, rawOf(body)},
		{Brotli, brotliOf(body, 10)},
		{Zstd, zstdOf(body, 1<<10)},
	} {
		t.Run(c.coding.String(), func(t *testing.T) {
			l := list(t, c.coding.String())
			r, stages, _ := observed(t, l, c.encoded, len(body))
			expect(t, r, Decoded, body)
			if stages[0].Read != int64(len(c.encoded)) {
				t.Fatalf("read %d of %d", stages[0].Read, len(c.encoded))
			}
			r, stages, _ = observed(t, l, c.encoded, len(body)-1)
			expect(t, r, DecodedTooLarge, nil)
			if stages[0].Returned != int64(len(body)) {
				t.Fatalf("returned %d before stopping at a bound of %d", stages[0].Returned, len(body)-1)
			}
		})
	}
}

// lengthBound is what one Decode of the coding allocates at most over an
// encoded body of the length given: StageAllocation at that length and the
// decode's overhead, tighter than Cumulative, which takes the worst length.
func lengthBound(c Coding, bound, length int) int64 {
	return DecodeOverhead + StageAllocation(c, bound, length).Total()
}

// bombs are 32 MiB of zeros in each coding under a 64 KiB bound. A decode of
// them all allocates more than the length bound in every coding, and more
// than A(coding, B) in gzip and deflate, whose bound does not grow with the
// input.
func TestBombsStopWithinTheBound(t *testing.T) {
	plain := make([]byte, 32<<20)
	const bound = 64 << 10
	for _, c := range []struct {
		coding  Coding
		encoded []byte
	}{
		{Gzip, gzipOf(plain)},
		{Deflate, zlibOf(plain)},
		{Brotli, brotliOf(plain, 16)},
		{Zstd, zstdOf(plain, bound)},
	} {
		t.Run(c.coding.String(), func(t *testing.T) {
			l := list(t, c.coding.String())
			limit := lengthBound(c.coding, bound, len(c.encoded))
			if limit >= int64(len(plain)) {
				t.Fatalf("wiring, not the property: the fixture cannot separate, a decode of all %d bytes is within the length bound %d", len(plain), limit)
			}
			if (c.coding == Gzip || c.coding == Deflate) && Cumulative(c.coding, bound) >= int64(len(plain)) {
				t.Fatalf("wiring, not the property: a decode of all %d bytes is within A(coding, B), %d", len(plain), Cumulative(c.coding, bound))
			}
			r, stages, total := observed(t, l, c.encoded, bound)
			if total > limit {
				t.Errorf("allocated %d, over the length bound %d", total, limit)
			}
			if total > Cumulative(c.coding, bound) {
				t.Errorf("allocated %d, over A(coding, B) %d", total, Cumulative(c.coding, bound))
			}
			expect(t, r, DecodedTooLarge, nil)
			if r.Stage != 1 || stages[0].Returned != int64(bound)+1 {
				t.Fatalf("stage %d returned %v", r.Stage, stages)
			}
		})
	}
}

func TestALargeWindowWithASmallOutputIsTooLarge(t *testing.T) {
	body := text(1000, 22)
	const bound = 64 << 10
	br := brotliOf(body, 24)
	r, led := decodeChecked(t, list(t, "br"), br, bound)
	expect(t, r, DecodedTooLarge, nil)
	if len(led.asked) != 0 {
		t.Fatalf("the header check reserved %v", led.asked)
	}
	// The same window is admitted under a bound that covers it.
	r, _ = decodeChecked(t, list(t, "br"), br, 1<<24)
	expect(t, r, Decoded, body)

	zs := withWindow(zstdOf(body, 1<<10), 13, 0)
	if window := frameWindow(t, zs); window <= bound {
		t.Fatalf("wiring, not the property: the frame declares a window of %d", window)
	}
	r, _ = decodeChecked(t, list(t, "zstd"), zs, bound)
	expect(t, r, DecodedTooLarge, nil)
	r, _ = decodeChecked(t, list(t, "zstd"), zs, 8<<20)
	expect(t, r, Decoded, body)

	// A single-segment frame declares its content size as its window.
	e, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	single := e.EncodeAll(text(bound+1000, 23), nil)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if single[4]&(1<<5) == 0 {
		t.Fatal("wiring, not the property: the frame is not single-segment")
	}
	r, stages, _ := observed(t, list(t, "zstd"), single, bound)
	expect(t, r, DecodedTooLarge, nil)
	if stages[0].Returned != 0 {
		t.Fatalf("the frame header did not decide it: the decoder returned %d bytes", stages[0].Returned)
	}
}

func TestABlockLargerThanItsWindowIsCorruptNotTooLarge(t *testing.T) {
	// One frame, window 1 KiB, holding a single raw block of 2 KiB.
	frame := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x00}
	header := uint32(1 | 2048<<3)
	frame = append(frame, byte(header), byte(header>>8), byte(header>>16))
	frame = append(frame, make([]byte, 2048)...)
	r, _ := decodeChecked(t, list(t, "zstd"), frame, 8<<20)
	expect(t, r, DecodingFailed, nil)
}

func TestTheBoundDecidesBeforeALaterError(t *testing.T) {
	const bound = 64 << 10
	zeros := make([]byte, 1<<20)
	gz := gzipOf(zeros)
	gz[len(gz)-8] ^= 1
	r, _ := decodeChecked(t, list(t, "gzip"), gz, bound)
	expect(t, r, DecodedTooLarge, nil)
	r, _ = decodeChecked(t, list(t, "gzip"), gz, 2<<20)
	expect(t, r, DecodingFailed, nil)

	zs := zstdOf(zeros, bound)
	zs[len(zs)-1] ^= 1
	r, _ = decodeChecked(t, list(t, "zstd"), zs, bound)
	expect(t, r, DecodedTooLarge, nil)
}

func TestAllocationIsWithinTheCumulativeBound(t *testing.T) {
	body := text(300<<10, 25)
	members := append(append(gzipOf(body[:1000]), gzipOf(body[1000:2000])...), gzipOf(body[2000:])...)
	for _, c := range []struct {
		name, header string
		encoded      []byte
		bound        int
	}{
		{"gzip", "gzip", gzipOf(body), 8 << 20},
		{"members", "gzip", members, 8 << 20},
		{"deflate", "deflate", rawOf(body), 1 << 20},
		{"br", "br", brotliOf(body, 22), 8 << 20},
		{"zstd", "zstd", zstdOf(body, 1<<20), 8 << 20},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := list(t, c.header)
			r, _, total := observed(t, l, c.encoded, c.bound)
			expect(t, r, Decoded, body)
			if limit := lengthBound(l.At(0), c.bound, len(c.encoded)); total > limit {
				t.Fatalf("allocated %d, over the length bound %d", total, limit)
			}
			if limit := Cumulative(l.At(0), c.bound); total > limit {
				t.Fatalf("allocated %d, over A(coding, B) %d", total, limit)
			}
		})
	}
}

func TestARefusedWorkspaceAllocatesNothing(t *testing.T) {
	body := text(20000, 26)
	for _, c := range []Coding{Gzip, Deflate, Brotli, Zstd} {
		t.Run(c.String(), func(t *testing.T) {
			led := newLedger(t)
			led.refuse = func(ch Charge) bool { return ch.Kind == WorkspaceCharge }
			encoded := encode(c, body)
			l := list(t, c.String())
			var r Result
			total := allocatedBy(func() { r = Decode(l, encoded, Options{Bound: 8 << 20, Reserver: led}) })
			led.settled(r, 1)
			expect(t, r, Refused, nil)
			if r.Stage != 1 || len(led.asked) != 1 {
				t.Fatalf("stage %d after %v", r.Stage, led.asked)
			}
			if total > AdmissionAllocation {
				t.Fatalf("allocated %d before the workspace was refused, over %d", total, AdmissionAllocation)
			}
		})
	}
}

func TestARefusalReturnsEveryCharge(t *testing.T) {
	body := text(400<<10, 27)
	encoded := zstdOf(body, 1<<18)
	l := list(t, "zstd")
	full := newLedger(t)
	Decode(l, encoded, Options{Bound: 8 << 20, Reserver: full})
	if len(full.asked) < 6 {
		t.Fatalf("wiring, not the property: only %d reservations to refuse", len(full.asked))
	}
	for i := range full.asked {
		t.Run(fmt.Sprint(i, full.asked[i]), func(t *testing.T) {
			led := newLedger(t)
			n := 0
			led.refuse = func(Charge) bool { n++; return n == i+1 }
			r := Decode(l, encoded, Options{Bound: 8 << 20, Reserver: led})
			expect(t, r, Refused, nil)
			led.settled(r, l.Len())
			if r.Stage != full.asked[i].Stage {
				t.Fatalf("refused at stage %d, reported stage %d", full.asked[i].Stage, r.Stage)
			}
		})
	}
}

func TestOutputGrowthReservesTheNewBufferBeforeReleasingTheOld(t *testing.T) {
	body := text(1<<20, 28)
	l := list(t, "br")
	encoded := brotliOf(body, 20)
	const bound = 2 << 20
	n := int64(bound) + 1
	r, led := decodeChecked(t, l, encoded, bound)
	expect(t, r, Decoded, body)
	buffers := map[int][]int64{}
	held := map[int]int64{}
	// let go is a stage whose last buffer was released: only the end of the
	// decode does that, so nothing is reserved for it after.
	letGo := map[int]bool{}
	grew := 0
	for _, e := range led.events {
		if e.Kind != OutputCharge {
			continue
		}
		live := buffers[e.Stage]
		if e.reserved {
			if letGo[e.Stage] {
				t.Fatalf("stage %d released its only buffer, then reserved %d: a growth released the old buffer before reserving the new", e.Stage, e.Bytes)
			}
			if len(live) > 1 || e.Bytes > n || (len(live) == 1 && e.Bytes > 2*live[0]) {
				t.Fatalf("stage %d reserved %d holding %v", e.Stage, e.Bytes, live)
			}
			buffers[e.Stage] = append(live, e.Bytes)
			held[e.Stage] += e.Bytes
			grew++
		} else {
			if len(live) == 0 || live[0] != e.Bytes {
				t.Fatalf("stage %d released %d holding %v", e.Stage, e.Bytes, live)
			}
			buffers[e.Stage] = live[1:]
			held[e.Stage] -= e.Bytes
			letGo[e.Stage] = len(live) == 1
		}
		if held[e.Stage] > n+(n+1)/2 {
			t.Fatalf("stage %d held %d in output buffers", e.Stage, held[e.Stage])
		}
	}
	if grew < 4 {
		t.Fatalf("wiring, not the property: only %d output buffers", grew)
	}
	if len(buffers[1]) != 1 || buffers[1][0] != r.Charge {
		t.Fatalf("left %v, passing %d", buffers, r.Charge)
	}
	for _, c := range led.asked {
		if c.Kind != WorkspaceCharge {
			continue
		}
		if want := Workspace(Brotli, encoded, bound); c.Bytes != want {
			t.Fatalf("stage %d reserved %d for its workspace, planned %d", c.Stage, c.Bytes, want)
		}
	}
}

// emptyFrame is a zstd frame with the window descriptor given and one empty
// raw block: 9 bytes, all of them header.
func emptyFrame(descriptor byte) []byte {
	return []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, descriptor, 0x01, 0x00, 0x00}
}

func TestTheZstdWorkspaceFollowsTheFramesInOrder(t *testing.T) {
	const kib, mib = 1 << 10, 1 << 20
	// descriptor(e, m) is a window of 2^(10+e) * (1 + m/8).
	descriptor := func(e, m byte) byte { return e<<3 | m }
	history := func(window int64) int64 {
		if window < 2*mib-1 {
			return allocated(2 * window)
		}
		return allocated(window + (2*mib-1)/2)
	}
	fixed := zstdFixed + 2*zstdBlockBuffers + stageOverhead
	for _, c := range []struct {
		name    string
		frames  [][]byte
		bound   int
		held    int64
		planned int
		outcome Outcome
	}{
		{"one frame", [][]byte{emptyFrame(descriptor(0, 0))}, mib, history(kib), 9, Decoded},
		{"a larger window holds both", [][]byte{emptyFrame(descriptor(0, 0)), emptyFrame(descriptor(6, 0))}, mib,
			history(kib) + history(64*kib), 18, Decoded},
		{"a smaller window releases nothing", [][]byte{emptyFrame(descriptor(6, 0)), emptyFrame(descriptor(4, 0)), emptyFrame(descriptor(6, 0))}, mib,
			history(64 * kib), 27, Decoded},
		{"each growth counted with what it replaces", [][]byte{emptyFrame(descriptor(2, 0)), emptyFrame(descriptor(6, 0)), emptyFrame(descriptor(8, 0))}, mib,
			history(64*kib) + history(256*kib), 27, Decoded},
		// 1.875 MiB takes 3.75 MiB of history and 2 MiB only 3 MiB: the
		// history is not monotone at the threshold.
		{"below the threshold first", [][]byte{emptyFrame(descriptor(10, 7)), emptyFrame(descriptor(11, 0))}, 4 * mib,
			history(1875 * mib / 1000), 18, Decoded},
		{"above the threshold first", [][]byte{emptyFrame(descriptor(11, 0)), emptyFrame(descriptor(10, 7))}, 4 * mib,
			history(2*mib) + history(1875*mib/1000), 18, Decoded},
		{"a later frame over the bound is not planned", [][]byte{emptyFrame(descriptor(0, 0)), emptyFrame(descriptor(12, 0))}, mib,
			history(kib), 15, DecodedTooLarge},
		{"a truncated frame's header is planned", [][]byte{emptyFrame(descriptor(0, 0)), emptyFrame(descriptor(6, 0))[:7]}, mib,
			history(kib) + history(64*kib), 16, DecodingFailed},
	} {
		t.Run(c.name, func(t *testing.T) {
			var stream []byte
			for _, f := range c.frames {
				stream = append(stream, f...)
			}
			if got := Workspace(Zstd, stream, c.bound); got != fixed+c.held {
				t.Fatalf("Workspace %d, want %d", got, fixed+c.held)
			}
			r, stages, _ := observed(t, list(t, "zstd"), stream, c.bound)
			expect(t, r, c.outcome, nil)
			if stages[0].Workspace != fixed+c.held || stages[0].Planned != int64(c.planned) {
				t.Fatalf("observed %+v", stages[0])
			}
		})
	}
}

func TestTheWorkspaceIsPlannedFromTheStream(t *testing.T) {
	body := text(1000, 29)
	const bound = 8 << 20
	for _, lgwin := range []int{10, 16, 22} {
		encoded := brotliOf(body, lgwin)
		r, stages, _ := observed(t, list(t, "br"), encoded, bound)
		expect(t, r, Decoded, body)
		want := brotliFixed + 2*brotliTrees + brotliMaps + allocated(int64(1)<<lgwin+42) + allocated(int64(1)<<(lgwin-1)+42) + stageOverhead
		if stages[0].Workspace != want || stages[0].Planned != 1 {
			t.Fatalf("lgwin %d: observed %+v, want a workspace of %d", lgwin, stages[0], want)
		}
		if want > WorkspaceCeiling(Brotli, bound) {
			t.Fatalf("lgwin %d: %d over the ceiling %d", lgwin, want, WorkspaceCeiling(Brotli, bound))
		}
	}
	for _, encoded := range [][]byte{gzipOf(body), gzipOf(text(1<<20, 30))} {
		_, stages, _ := observed(t, list(t, "gzip"), encoded, bound)
		if stages[0].Workspace != WorkspaceCeiling(Gzip, bound) || stages[0].Planned != 0 {
			t.Fatalf("gzip observed %+v", stages[0])
		}
	}
}
