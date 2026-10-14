package contentcoding

import (
	"errors"
	"io"

	"github.com/evandukss/edge-observer/internal/brotli"
)

// brotliSmallestWindow is the window of WBITS 10, the smallest a brotli stream
// can declare. A bound below it still admits it, as zstd's smallest window is
// admitted, so that a small bound does not refuse every brotli body.
const brotliSmallestWindow = 1<<10 - 16

// brotliHeader decides, from the stream header alone, what refuses a brotli
// stage before its decoder exists: an empty input, the large-window marker,
// and a window larger than the bound admits. Zero lets the stage run.
func brotliHeader(in []byte, bound int) Outcome {
	if len(in) == 0 {
		return DecodingFailed
	}
	bits, large := brotliWindowBits(in[0])
	if large {
		return DecodingFailed
	}
	if 1<<bits-16 > max(bound, brotliSmallestWindow) {
		return DecodedTooLarge
	}
	return 0
}

// brotliStage undoes br within the work budget, and returns the work it
// counted. The decoder reads feed, which is in or reads it. It returns an
// error for any byte after the stream, which it reads in the call that ends
// the stream or the next one; the remaining check covers a stream that ends
// exactly at a read boundary. The Reader holds nothing to close.
func brotliStage(in *input, feed io.Reader, out *output, budget workBudget, lib *library) (Outcome, int64) {
	var r *brotli.Reader
	if !lib.call(operationMake, func() {
		r = brotli.NewReader(feed)
		r.SetBudget(budget.base, budget.perByte, budget.most)
	}) {
		return DecodingFailed, 0
	}
	outcome, err := out.fill(guarded{lib, r})
	work := int64(r.Work())
	switch {
	case outcome == DecodingFailed && errors.Is(err, brotli.ErrTooCostly):
		return DecodingTooCostly, work
	case outcome != Decoded:
		return outcome, work
	case in.remaining() != 0:
		return DecodingFailed, work
	}
	return Decoded, work
}
