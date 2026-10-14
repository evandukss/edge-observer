package contentcoding

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// Decoder panic containment (criterion 119 row 1a rev 53; decisions 583, 586).
// A benign panic inside a guarded library operation is contained as a decoder
// fault: the stage ends content_decoding_failed with Result.Fault set, no
// partial output, every charge refunded once, and later traffic continues. A
// panic value carrying a protected sentinel never reaches the result, and a
// panic in one of the caller's own callbacks, outside the library boundary, is
// not swallowed.
//
// These bind to T12's unexported seam in package contentcoding:
//   decodeWithin(list, encoded, options, within) Result
//   within{budget workBudget; feed func(io.Reader) io.Reader; inject func(Coding, operation)}
//   workBudget{base, perByte, most uint64}
//   operationMake, operationReset, operationRead, operationClose
// inject runs at the start of each guarded operation; feed wraps the stage's
// input. Reach: make all four codings; reset gzip from its second member; read
// all four; close gzip, deflate and zstd (brotli has no close).

// panicSentinel is a value a contained panic carries; its text must never reach
// the result of a contained decode.
const panicSentinelText = "credential-like-protected-sentinel-9f3a"

type panicSentinel struct{ secret string }

func (panicSentinel) Error() string { return panicSentinelText }

// containmentBudget never refuses, so only the injected panic decides the
// outcome.
func containmentBudget() workBudget {
	return workBudget{base: 1 << 40, perByte: 1 << 20, most: 1 << 40}
}

func containmentStreams(t *testing.T) map[Coding][]byte {
	t.Helper()
	// Larger than the output buffer's first capacity (4096), so gzip and deflate
	// read across more than one call and a read after output is reachable.
	plain := bytes.Repeat([]byte("decoder-containment/"), 512)
	return map[Coding][]byte{
		Gzip:    decodingEncode(t, "gzip", plain),
		Deflate: decodingEncode(t, "deflate", plain),
		Brotli:  decodingEncode(t, "br", plain),
		Zstd:    decodingEncode(t, "zstd", plain),
	}
}

func TestDecoderContainsAGuardedLibraryPanic(t *testing.T) {
	const bound = 1 << 20
	streams := containmentStreams(t)
	// Two gzip members, so a reset from the second member is reachable.
	twoGzip := append(bytes.Clone(streams[Gzip]), streams[Gzip]...)

	type target struct {
		name   string
		coding Coding
		op     operation
		stream []byte
		at     int // the 1-based call of (coding, op) to panic on
	}
	targets := []target{
		{"gzip-make", Gzip, operationMake, streams[Gzip], 1},
		{"deflate-make", Deflate, operationMake, streams[Deflate], 1},
		{"br-make", Brotli, operationMake, streams[Brotli], 1},
		{"zstd-make", Zstd, operationMake, streams[Zstd], 1},
		{"gzip-reset-second-member", Gzip, operationReset, twoGzip, 1},
		{"gzip-read-after-output", Gzip, operationRead, streams[Gzip], 2},
		{"deflate-read-after-output", Deflate, operationRead, streams[Deflate], 2},
		{"br-read-after-output", Brotli, operationRead, streams[Brotli], 2},
		{"zstd-read-after-output", Zstd, operationRead, streams[Zstd], 2},
		{"gzip-close", Gzip, operationClose, streams[Gzip], 1},
		{"deflate-close", Deflate, operationClose, streams[Deflate], 1},
		{"zstd-close", Zstd, operationClose, streams[Zstd], 1},
	}
	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			list := decodingList(tc.coding)
			ledger := &decodingLedger{t: t, list: list, bound: bound}
			calls := 0
			w := within{
				budget: containmentBudget(),
				inject: func(c Coding, op operation) {
					if c == tc.coding && op == tc.op {
						calls++
						if calls == tc.at {
							panic(panicSentinel{secret: panicSentinelText})
						}
					}
				},
			}
			got := decodeWithin(list, tc.stream, Options{Bound: bound, Reserver: ledger}, w)
			if calls < tc.at {
				t.Fatalf("wiring, not the property: %s was reached %d times, never %d", tc.name, calls, tc.at)
			}
			if got.Outcome != DecodingFailed || got.Outcome.Reason() != ReasonDecodingFailed {
				t.Errorf("contained panic: outcome=%v reason=%q, want DecodingFailed/%s", got.Outcome, got.Outcome.Reason(), ReasonDecodingFailed)
			}
			if !got.Fault {
				t.Error("a contained library panic did not set Result.Fault")
			}
			if got.Body != nil || got.Charge != 0 {
				t.Errorf("contained panic retained output: body=%d charge=%d", len(got.Body), got.Charge)
			}
			if ledger.total() != 0 {
				t.Errorf("contained panic leaked charges: %d held", ledger.total())
			}
			// The sentinel text reaches nothing observable in the result.
			if got.Outcome.Reason() == panicSentinelText || strings.Contains(string(got.Body), panicSentinelText) {
				t.Error("the panic sentinel reached the result")
			}
			// Later traffic continues: a clean decode after the fault succeeds.
			plainAfter := []byte("after-the-fault")
			clean := decodingEncode(t, codingName(tc.coding), plainAfter)
			after := decodeWithin(decodingList(tc.coding), clean, Options{Bound: bound}, within{budget: containmentBudget()})
			if after.Outcome != Decoded || !bytes.Equal(after.Body, plainAfter) {
				t.Errorf("later traffic did not continue after a contained fault: outcome=%v", after.Outcome)
			}
		})
	}
}

// codingName is the fixture-encoder name for a coding.
func codingName(c Coding) string {
	switch c {
	case Gzip:
		return "gzip"
	case Deflate:
		return "deflate"
	case Brotli:
		return "br"
	case Zstd:
		return "zstd"
	}
	return "identity"
}

// A panic in one of the caller's own callbacks is outside the library boundary
// and is not swallowed: it propagates out of the decode.
func TestDecoderDoesNotSwallowACallerCallbackPanic(t *testing.T) {
	const bound = 1 << 20
	stream := decodingEncode(t, "gzip", bytes.Repeat([]byte("x"), 256))
	defer func() {
		if r := recover(); r == nil {
			t.Error("a panic in the Observe callback was swallowed by the decoder")
		}
	}()
	decodeWithin(decodingList(Gzip), stream, Options{Bound: bound, Observe: func(StageIO) { panic("caller observe panic") }},
		within{budget: containmentBudget()})
}

// feed wrapping does not change the contained-fault outcome: an input split into
// one-byte reads still contains a panic the same way.
func TestContainedPanicIsInvariantUnderFeed(t *testing.T) {
	const bound = 1 << 20
	stream := decodingEncode(t, "zstd", bytes.Repeat([]byte("y"), 300))
	oneByte := func(r io.Reader) io.Reader { return iotest1{r} }
	for _, feed := range []func(io.Reader) io.Reader{nil, oneByte} {
		ledger := &decodingLedger{t: t, list: decodingList(Zstd), bound: bound}
		calls := 0
		got := decodeWithin(decodingList(Zstd), stream, Options{Bound: bound, Reserver: ledger}, within{
			budget: containmentBudget(),
			feed:   feed,
			inject: func(c Coding, op operation) {
				if c == Zstd && op == operationRead {
					calls++
					if calls == 1 {
						panic(panicSentinel{secret: panicSentinelText})
					}
				}
			},
		})
		if got.Outcome != DecodingFailed || !got.Fault || got.Body != nil || ledger.total() != 0 {
			t.Errorf("feed=%v: contained panic differed: outcome=%v fault=%v body=%d held=%d", feed != nil, got.Outcome, got.Fault, len(got.Body), ledger.total())
		}
	}
}

// iotest1 reads one byte at a time.
type iotest1 struct{ r io.Reader }

func (o iotest1) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}
