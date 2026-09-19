package stream_test

import (
	"testing"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/stream"
)

// plan turns the fuzzer's second argument into where the calls fell, which
// were truncated, and the delivery order.
type plan struct{ state uint32 }

func (p *plan) next(bound int) int {
	// A linear congruential step, reproducible from the fuzzer's input.
	p.state = p.state*1664525 + 1013904223
	if bound <= 0 {
		return 0
	}
	return int(p.state>>16) % bound
}

// capture cuts data into fragments as SSL_write calls would, truncating some
// and delivering them in its own order.
func capture(data []byte, seed uint32) []fragment.Record {
	p := plan{state: seed}

	var records []fragment.Record
	var offset uint64
	for i := 0; len(data) > 0; i++ {
		size := p.next(len(data)) + 1
		piece := data[:size]
		data = data[size:]

		record := fragment.Record{
			Process:    fragment.Process{PID: 1731, StartTime: 90210},
			Connection: fragment.ConnectionID(p.next(3)),
			Direction:  []fragment.Direction{fragment.Sent, fragment.Received}[p.next(2)],
			Sequence:   uint64(i),
			Offset:     offset,
			Length:     uint32(len(piece)),
			Payload:    piece,
			At:         at,
		}
		// One fragment in eight is truncated: a hole inside a record.
		if p.next(8) == 0 {
			record.Payload = piece[:p.next(len(piece)+1)]
		}
		offset = record.End()
		records = append(records, record)
	}

	for i := len(records) - 1; i > 0; i-- {
		j := p.next(i + 1)
		records[i], records[j] = records[j], records[i]
	}
	return records
}

// FuzzAssembleTilesEveryStreamItProduces: a stream's parts cover its whole
// extent once each, with bytes or a named hole.
func FuzzAssembleTilesEveryStreamItProduces(f *testing.F) {
	f.Add([]byte("POST /db/v2/row HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi"), uint32(1))
	f.Add([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n"), uint32(7))
	f.Add([]byte{}, uint32(0))
	f.Add([]byte{0, 0, 0, 0}, uint32(0xffffffff))

	f.Fuzz(func(t *testing.T, data []byte, seed uint32) {
		records := capture(data, seed)
		result := stream.Assemble(records)

		var kept uint64
		for _, s := range result.Streams {
			next := s.Start
			for i, p := range s.Parts {
				if p.Offset != next {
					t.Fatalf("%v part %d begins at %d, want %d", s.Key, i, p.Offset, next)
				}
				if p.Length == 0 {
					t.Fatalf("%v part %d is empty", s.Key, i)
				}
				switch p.Gap {
				case stream.GapNone:
					if uint64(len(p.Bytes)) != p.Length {
						t.Fatalf("%v part %d carries %d bytes over %d offsets", s.Key, i, len(p.Bytes), p.Length)
					}
				default:
					if p.Bytes != nil {
						t.Fatalf("%v part %d is a %s gap carrying bytes", s.Key, i, p.Gap)
					}
				}
				next = p.Offset + p.Length
			}
			if next != s.End {
				t.Fatalf("%v parts end at %d, want %d", s.Key, next, s.End)
			}
			if s.Bytes()+s.Gaps() != s.End-s.Start {
				t.Fatalf("%v holds %d bytes and %d gap offsets over an extent of %d",
					s.Key, s.Bytes(), s.Gaps(), s.End-s.Start)
			}
			kept += s.Bytes()
		}

		// Nothing is invented: at most what went in comes out.
		var given uint64
		for _, record := range records {
			given += uint64(len(record.Payload))
		}
		if kept > given {
			t.Fatalf("assembly produced %d bytes from %d", kept, given)
		}
	})
}

// FuzzAssembleIsDeterministicAndIdempotent: delivery order and duplicate
// delivery change nothing.
func FuzzAssembleIsDeterministicAndIdempotent(f *testing.F) {
	f.Add([]byte("POST /db/v2/row HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi"), uint32(1))
	f.Add([]byte("HTTP/1.1 204 No Content\r\n\r\n"), uint32(99))

	f.Fuzz(func(t *testing.T, data []byte, seed uint32) {
		records := capture(data, seed)

		once := render(stream.Assemble(records))
		if again := render(stream.Assemble(records)); again != once {
			t.Fatalf("two assemblies of one set of records differ")
		}

		replayed := append(append([]fragment.Record{}, records...), records...)
		if twice := render(stream.Assemble(replayed)); twice != once {
			t.Fatalf("replaying every record changed the streams:\n%s\nagainst\n%s", twice, once)
		}
	})
}

func render(result stream.Result) string {
	var out []byte
	for _, s := range result.Streams {
		out = append(out, s.Key.String()...)
		out = append(out, '\n')
		for _, p := range s.Parts {
			if p.Gap == stream.GapNone {
				out = append(out, '=')
				out = append(out, p.Bytes...)
			} else {
				out = append(out, '#')
				out = append(out, p.Gap.String()...)
				out = append(out, itoa(p.Length)...)
			}
			out = append(out, '\n')
		}
	}
	return string(out)
}
