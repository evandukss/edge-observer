package contentcoding

import (
	"bytes"
	"testing"
)

// windowed is an empty frame declaring a window of 2^(10+exponent).
func windowed(exponent byte) []byte { return emptyFrame(exponent << 3) }

// skippable is a skippable frame carrying payload bytes.
func skippable(payload int) []byte {
	return append([]byte{0x50, 0x2a, 0x4d, 0x18, byte(payload), 0, 0, 0}, make([]byte, payload)...)
}

func joined(frames ...[]byte) []byte { return bytes.Join(frames, nil) }

func TestAFourthHistoryIsNeverRead(t *testing.T) {
	const bound = 1 << 20
	three := joined(windowed(0), windowed(2), windowed(4))
	for _, c := range []struct {
		name    string
		stream  []byte
		prefix  []byte
		outcome Outcome
	}{
		{"the first history and two growths decode", three, three, Decoded},
		{"a third growth is too costly, and its frame is not read", joined(three, windowed(6)), three, DecodingTooCostly},
		{"nor any frame after it", joined(three, windowed(6), windowed(1), windowed(8)), three, DecodingTooCostly},
		{"an equal or smaller window is no growth",
			joined(windowed(6), windowed(4), windowed(6), windowed(2), windowed(8), windowed(10)), nil, Decoded},
		{"a skippable frame is no growth",
			joined(windowed(0), skippable(3), windowed(2), skippable(0), windowed(4), skippable(5)), nil, Decoded},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, stages, _ := observed(t, list(t, "zstd"), c.stream, bound)
			expect(t, r, c.outcome, nil)
			read := len(c.stream)
			if c.prefix != nil {
				read = len(c.prefix)
			}
			if stages[0].Read != int64(read) {
				t.Fatalf("the decoder read %d bytes of %d, want %d", stages[0].Read, len(c.stream), read)
			}
			if c.prefix != nil && stages[0].Workspace != Workspace(Zstd, c.prefix, bound) {
				t.Fatalf("workspace %d, the frames before the cut take %d", stages[0].Workspace, Workspace(Zstd, c.prefix, bound))
			}
		})
	}
}

func TestAnEarlierResultKeepsItsReason(t *testing.T) {
	failing := zstdOf(text(4096, 1), 1<<12)
	failing[len(failing)-1] ^= 0xff // the content checksum
	stopping := zstdOf(text(100<<10, 2), 1<<12)
	for _, f := range [][]byte{failing, stopping} {
		if w := frameWindow(t, f); w > 4<<10 {
			t.Fatalf("wiring, not the property: the encoder declared a window of %d", w)
		}
	}
	// Each is the first history; two growths follow, and the frame after them
	// would be a third.
	growths := joined(windowed(4), windowed(5), windowed(6))
	for _, c := range []struct {
		name    string
		stream  []byte
		bound   int
		outcome Outcome
	}{
		{"a failure before the cut", joined(failing, growths), 1 << 20, DecodingFailed},
		{"the output stop before the cut", joined(stopping, growths), 64 << 10, DecodedTooLarge},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, _, cut := zstdPlanned(c.stream, zstdWindow(c.bound)); cut < 0 {
				t.Fatal("wiring, not the property: the stream has no third growth")
			}
			r, _, _ := observed(t, list(t, "zstd"), c.stream, c.bound)
			expect(t, r, c.outcome, nil)
		})
	}
}

// The history is the one buffer that grows with the declared window, so two
// streams of the same frames, one declaring large rising windows and one a
// small window throughout, allocate the same except for their histories. The
// limited stream may then allocate what the control does, less the control's
// one history, plus the three histories the limit allows, and the slack: the
// block buffers a window below a block sizes to the window (three of 64 KiB in
// the control, a block in the other) and size classes, 512 KiB in all. A
// fourth history, through any path, is at least 2 MiB more here.
func TestTheHistoryIsMadeAtMostThreeTimes(t *testing.T) {
	const kib, mib, bound = 1 << 10, 1 << 20, 8 << 20
	content := text(64*kib, 12)
	base := zstdOf(content, 64*kib)
	if w := frameWindow(t, base); w > 64*kib {
		t.Fatalf("wiring, not the property: the encoder declared a window of %d", w)
	}
	control := joined(withWindow(base, 6, 0), withWindow(base, 6, 0), withWindow(base, 6, 0))
	prefix := joined(withWindow(base, 10, 0), withWindow(base, 11, 0), withWindow(base, 12, 0))
	limited := joined(prefix, withWindow(base, 13, 0), withWindow(base, 13, 0))

	var r Result
	controlled := allocatedBy(func() { r = Decode(list(t, "zstd"), control, Options{Bound: bound}) })
	if r.Outcome != Decoded || !bytes.Equal(r.Body, bytes.Repeat(content, 3)) {
		t.Fatalf("wiring, not the property: the control decoded as %d with %d bytes", r.Outcome, len(r.Body))
	}
	used := allocatedBy(func() { r = Decode(list(t, "zstd"), limited, Options{Bound: bound}) })
	if r.Outcome != DecodingTooCostly {
		t.Fatalf("wiring, not the property: the limited stream decoded as %d", r.Outcome)
	}

	three := allocated(zstdHistory(mib)) + allocated(zstdHistory(2*mib)) + allocated(zstdHistory(4*mib))
	allowed := controlled - allocated(zstdHistory(64*kib)) + three + 512*kib
	stated := StageAllocation(Zstd, bound, len(limited)).Total() + decodeOverhead
	t.Logf("allocated %d; control %d; three histories %d; allowed %d; A at this length %d", used, controlled, three, allowed, stated)
	if used > allowed || used > stated {
		t.Fatalf("allocated %d, above the control's %d less its history plus three histories (%d) or A (%d)", used, controlled, allowed, stated)
	}
}
