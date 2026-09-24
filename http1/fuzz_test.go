package http1_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/stream"
)

// pieces cuts data into fragments of at most size bytes, as a run of library
// calls would.
func pieces(data []byte, size int) stream.Stream {
	if size <= 0 {
		size = len(data) + 1
	}

	var records []fragment.Record
	for start := 0; start < len(data); start += size {
		end := min(start+size, len(data))
		records = append(records, fragment.Record{
			Process:    fragment.Process{PID: 1731, StartTime: 90210},
			Connection: 7,
			Direction:  fragment.Received,
			Sequence:   uint64(start),
			Offset:     uint64(start),
			Length:     uint32(end - start),
			Payload:    data[start:end],
			At:         time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC),
		})
	}

	result := stream.Assemble(records)
	if len(result.Streams) == 0 {
		return stream.Stream{}
	}
	return result.Streams[0]
}

func seeds(f *testing.F) {
	f.Helper()

	f.Add([]byte(postRequest))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=1\r\nhello\r\n0\r\nT: 1\r\n\r\n"))
	f.Add([]byte("POST /one HTTP/1.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /x HTTP/1.1\r\n\r\n"))
	f.Add([]byte("POST /one HTTP/1.1\r\nContent-Length : 0\r\n\r\n"))
	f.Add([]byte("\r\n\r\n\r\n"))
	f.Add([]byte(""))
}

// FuzzParseIsBoundedAndAccountsForEveryOffset: nothing the parser holds grows
// past the caller's bounds, and every offset is inside a message or counted as
// unplaced.
func FuzzParseIsBoundedAndAccountsForEveryOffset(f *testing.F) {
	seeds(f)

	limits := http1.Limits{
		MaxStartLine: 64, MaxHeaderLine: 64, MaxHeaders: 8, MaxHeaderBytes: 256,
		MaxBodyBytes: 128, MaxMessages: 4, MaxChunks: 8, MaxTrailers: 2,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		for _, kind := range []http1.Kind{http1.Request, http1.Response} {
			s := pieces(data, 0)
			parsed := http1.Parse(s, kind, limits)

			if len(parsed.Messages) > limits.MaxMessages {
				t.Fatalf("%s: parsed %d messages, bound %d", kind, len(parsed.Messages), limits.MaxMessages)
			}

			next := s.Start
			for i, m := range parsed.Messages {
				if m.Offset != next {
					t.Fatalf("%s: message %d begins at %d, want %d", kind, i, m.Offset, next)
				}
				if m.End < m.Offset {
					t.Fatalf("%s: message %d ends at %d, before it began at %d", kind, i, m.End, m.Offset)
				}
				if len(m.Headers) > limits.MaxHeaders {
					t.Fatalf("%s: message %d kept %d headers, bound %d", kind, i, len(m.Headers), limits.MaxHeaders)
				}
				if len(m.Trailers) > limits.MaxTrailers {
					t.Fatalf("%s: message %d kept %d trailers, bound %d", kind, i, len(m.Trailers), limits.MaxTrailers)
				}
				if len(m.Body) > limits.MaxBodyBytes {
					t.Fatalf("%s: message %d kept %d body bytes, bound %d", kind, i, len(m.Body), limits.MaxBodyBytes)
				}
				// A complete message must know where it ends.
				if m.Complete && !m.Framed {
					t.Fatalf("%s: message %d is complete and unframed", kind, i)
				}
				if m.Complete && m.Defect != http1.DefectNone {
					t.Fatalf("%s: message %d is complete and reports %s", kind, i, m.Defect)
				}
				next = m.End
			}
			if next+parsed.Unplaced != s.End {
				t.Fatalf("%s: messages reach %d and %d are unplaced, want the extent %d",
					kind, next, parsed.Unplaced, s.End)
			}
		}
	})
}

// FuzzParseDoesNotDependOnWhereTheFragmentsFall: a fragment boundary is one
// library call and carries no meaning, so one byte stream split differently
// must parse identically.
func FuzzParseDoesNotDependOnWhereTheFragmentsFall(f *testing.F) {
	seeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		// One record per byte at the smallest size: keep inputs small so the
		// fuzzer measures the parser, not this harness.
		if len(data) > 2048 {
			return
		}
		for _, kind := range []http1.Kind{http1.Request, http1.Response} {
			whole := describe(http1.Parse(pieces(data, 0), kind, http1.DefaultLimits()))
			for _, size := range []int{1, 2, 3, 5, 17, 1024} {
				split := describe(http1.Parse(pieces(data, size), kind, http1.DefaultLimits()))
				if split != whole {
					t.Fatalf("%s: fragments of %d bytes read differently:\n%s\nagainst\n%s", kind, size, split, whole)
				}
			}
		}
	})
}

// describe renders everything a parse decided, so two parses compare by
// conclusion.
func describe(parsed http1.Parsed) string {
	var b strings.Builder
	for _, m := range parsed.Messages {
		fmt.Fprintf(&b, "%s %q framing=%s complete=%v framed=%v defect=%s body=%q length=%d holed=%d elided=%d span=%d..%d\n",
			m.Kind, m.StartLine(), m.Framing, m.Complete, m.Framed, m.Defect,
			m.Body, m.BodyLength, m.BodyHoled, m.BodyElided, m.Offset, m.End)
		for _, h := range m.Headers {
			fmt.Fprintf(&b, "  header %q: %q\n", h.Name, h.Value)
		}
		for _, h := range m.Trailers {
			fmt.Fprintf(&b, "  trailer %q: %q\n", h.Name, h.Value)
		}
	}
	fmt.Fprintf(&b, "unplaced=%d\n", parsed.Unplaced)
	return b.String()
}
