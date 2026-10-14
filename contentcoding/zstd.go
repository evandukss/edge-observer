package contentcoding

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/klauspost/compress/zstd"
)

// zstdSmallestWindow is the smallest window the decoder can be limited to,
// zstd.MinWindowSize. A bound below it still admits it.
const zstdSmallestWindow = 1 << 10

// zstdWindow is the largest window, and the largest declared frame content,
// a stage admits under bound.
func zstdWindow(bound int) uint64 {
	return uint64(max(clampBound(bound), zstdSmallestWindow))
}

// zstdStage undoes zstd with a decoder made for this stage alone: one block at
// a time on this goroutine, reading feed, which is in or reads it, its window
// and its declared frame size limited to zstdWindow, and closed when the
// stage ends unless its library faulted. Where the frames would make the
// decoder's history a fourth time, in is cut before that frame, so the
// decoder cannot read any byte of it, and a clean end of what comes before is
// DecodingTooCostly.
func zstdStage(in *input, feed io.Reader, out *output, bound int, lib *library) Outcome {
	if len(in.b) == 0 {
		return DecodingFailed
	}
	window := zstdWindow(bound)
	_, _, cut := zstdPlanned(in.b, window)
	if cut >= 0 {
		in.b = in.b[:cut]
	}
	var decoder *zstd.Decoder
	var err error
	if !lib.call(operationMake, func() {
		decoder, err = zstd.NewReader(feed,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxWindow(window),
			zstd.WithDecoderMaxMemory(window),
			zstd.WithDecodeBuffersBelow(0),
		)
	}) || err != nil {
		return DecodingFailed
	}
	outcome, err := out.fill(guarded{lib, decoder})
	lib.close(decoder.Close)
	switch outcome {
	case Decoded:
	case DecodingFailed:
		if (errors.Is(err, zstd.ErrWindowSizeExceeded) || errors.Is(err, zstd.ErrDecoderSizeExceeded)) &&
			zstdDeclaresMore(in.b, in.pos, window) {
			return DecodedTooLarge
		}
		return DecodingFailed
	default:
		return outcome
	}
	if zstdFramesEnd(in.b) != len(in.b) {
		return DecodingFailed
	}
	if cut >= 0 {
		return DecodingTooCostly
	}
	return Decoded
}

// zstdDeclaresMore reports whether the frame holding the last byte the
// decoder read, b[read-1], declares in its header a window larger than limit,
// or, as a single-segment frame, content larger than it. The decoder returns
// the same errors for a block too large for a window the header admitted,
// which is a corrupt stream rather than a declared size.
func zstdDeclaresMore(b []byte, read int, limit uint64) bool {
	if read <= 0 || read > len(b) {
		return false
	}
	start := 0
	for {
		n := zstdFrameLength(b[start:])
		if n <= 0 || start+n > read-1 {
			break
		}
		start += n
	}
	window, ok := zstdDeclaredWindow(b[start:])
	return ok && window > limit
}

// zstdFramesEnd walks the frames at the start of b by their headers alone
// (RFC 8878 section 3.1) and returns the offset where the last complete frame
// ends. The decoder has already accepted every frame up to the end of its
// stream; the walk finds what it accepted without consuming, since it reads
// a lone byte after the last frame as the end of the stream.
func zstdFramesEnd(b []byte) int {
	end := 0
	for {
		n := zstdFrameLength(b[end:])
		if n <= 0 {
			return end
		}
		end += n
	}
}

// zstdFrameLength is the length of the frame b starts with, or 0 when b does
// not start with a complete one.
func zstdFrameLength(b []byte) int {
	if len(b) < 4 {
		return 0
	}
	magic := binary.LittleEndian.Uint32(b)
	if magic&0xfffffff0 == 0x184d2a50 {
		if len(b) < 8 {
			return 0
		}
		size := uint64(binary.LittleEndian.Uint32(b[4:]))
		if size > uint64(len(b)-8) {
			return 0
		}
		return 8 + int(size)
	}
	if magic != zstdMagic || len(b) < 5 {
		return 0
	}
	descriptor := b[4]
	header := 5 + [4]int{0, 1, 2, 4}[descriptor&3] + [4]int{0, 2, 4, 8}[descriptor>>6]
	if descriptor&(1<<5) == 0 || descriptor>>6 == 0 {
		header++
	}
	if len(b) < header {
		return 0
	}
	end, _ := zstdFrameEnd(b, header, descriptor&(1<<2) != 0)
	return end
}
