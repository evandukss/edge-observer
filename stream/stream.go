// Package stream reassembles one direction of one connection from its
// fragments and says where the bytes it lacks would have been.
//
// A fragment boundary is one TLS library call and says nothing about message
// boundaries; records of one fragment.Stream reassemble by Offset. There are
// two kinds of hole - offsets no record covered, and a record's tail capture
// did not keep - and both are recorded as gaps, never closed up: joining the
// two sides of a hole invents a stream.
//
// Assembled parts alias the records' payloads, so the records must outlive the
// Stream and not be modified.
package stream

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/evandukss/edge-observer/fragment"
)

// GapReason says why a run of offsets carries no bytes.
type GapReason uint8

const (
	// GapNone is a part that carries its bytes.
	GapNone GapReason = iota
	// GapMissing is a run of offsets no record covered.
	GapMissing
	// GapTruncated is the tail of one record the call transferred and capture did
	// not keep.
	GapTruncated
)

func (g GapReason) String() string {
	switch g {
	case GapNone:
		return "none"
	case GapMissing:
		return "missing"
	case GapTruncated:
		return "truncated"
	default:
		return fmt.Sprintf("gap(%d)", uint8(g))
	}
}

// Part is one run of consecutive offsets, bytes or hole. A Stream's parts
// cover its extent with no overlap or space, so walking them visits every
// offset once.
type Part struct {
	Offset uint64
	Length uint64
	// Gap is GapNone for a part carrying bytes, else the kind of hole.
	Gap GapReason
	// Bytes is exactly Length bytes when Gap is GapNone, nil otherwise, aliasing
	// the record's payload.
	Bytes []byte
}

// Conflict is a run of offsets two records covered with different bytes: a
// capture defect, recorded rather than resolved. The Stream carries the first
// record's bytes.
type Conflict struct {
	Offset uint64
	Length uint64
}

// Stream is one direction of one connection reassembled.
type Stream struct {
	Key   fragment.Stream
	Parts []Part
	// Start is the first offset accounted for and End one past the last. Start
	// need not be zero: capture may attach mid-connection.
	Start uint64
	End   uint64
	// Conflicts is empty for every stream capture produced correctly.
	Conflicts []Conflict
}

// Bytes reports how many of the stream's offsets carry bytes. Bytes plus Gaps
// is End minus Start.
func (s Stream) Bytes() uint64 {
	var n uint64
	for _, p := range s.Parts {
		if p.Gap == GapNone {
			n += p.Length
		}
	}
	return n
}

// Gaps is the number of offsets in the stream that carry no bytes.
func (s Stream) Gaps() uint64 {
	return s.End - s.Start - s.Bytes()
}

// Discard is a record Assemble refused, by its input index. Its offsets come
// out as a gap, keeping later offsets true.
type Discard struct {
	Index int
	Err   error
}

// Duplicate is a record whose offsets were all already placed. Reassembly
// needs nothing from it, so it is reported: otherwise a fragment emitted twice
// would reconstruct identically to one emitted once. A retransmit at the same
// offsets lands here too.
type Duplicate struct {
	// Index is the record's position in the input.
	Index int
	// Offset and Length are the range it covered, all already placed.
	Offset uint64
	Length uint64
	// Agrees is whether its bytes matched what was there. False is also a Conflict
	// on the stream.
	Agrees bool
}

// Result is every stream the records reassemble into, the records not usable,
// and those not needed.
type Result struct {
	Streams    []Stream
	Discards   []Discard
	Duplicates []Duplicate
}

// Assemble buckets records by their Stream and reassembles each, in a fixed
// order (process, connection, direction).
func Assemble(records []fragment.Record) Result {
	var result Result

	type placed struct {
		record fragment.Record
		index  int
	}
	buckets := make(map[fragment.Stream][]placed)

	for i, record := range records {
		if err := record.Validate(); err != nil {
			result.Discards = append(result.Discards, Discard{Index: i, Err: err})
			continue
		}
		key := record.Stream()
		buckets[key] = append(buckets[key], placed{record: record, index: i})
	}

	keys := make([]fragment.Stream, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return less(keys[i], keys[j]) })

	for _, key := range keys {
		held := buckets[key]
		// Offset orders a stream; Sequence, then input index, break ties, so the sort
		// is total.
		sort.SliceStable(held, func(i, j int) bool {
			switch {
			case held[i].record.Offset != held[j].record.Offset:
				return held[i].record.Offset < held[j].record.Offset
			case held[i].record.Sequence != held[j].record.Sequence:
				return held[i].record.Sequence < held[j].record.Sequence
			default:
				return held[i].index < held[j].index
			}
		})

		ordered := make([]fragment.Record, len(held))
		indexes := make([]int, len(held))
		for i, p := range held {
			ordered[i] = p.record
			indexes[i] = p.index
		}
		assembled, duplicates := oneWithDuplicates(key, ordered, indexes)
		result.Streams = append(result.Streams, assembled)
		result.Duplicates = append(result.Duplicates, duplicates...)
	}

	return result
}

func less(a, b fragment.Stream) bool {
	switch {
	case a.Process.PID != b.Process.PID:
		return a.Process.PID < b.Process.PID
	case a.Process.StartTime != b.Process.StartTime:
		return a.Process.StartTime < b.Process.StartTime
	case a.Connection != b.Connection:
		return a.Connection < b.Connection
	default:
		return a.Direction < b.Direction
	}
}

// oneWithDuplicates reassembles one stream's offset-ordered records and says
// which covered nothing new. indexes names each record's input position.
func oneWithDuplicates(key fragment.Stream, records []fragment.Record, indexes []int) (Stream, []Duplicate) {
	var duplicates []Duplicate
	assembled := Stream{Key: key}
	if len(records) == 0 {
		return assembled, nil
	}

	assembled.Start = records[0].Offset
	next := assembled.Start

	for i, record := range records {
		kept := uint64(len(record.Payload))
		end := record.End()
		agrees := true

		// Bytes shared with what is placed: the placed ones stay, so the stream does
		// not depend on arrival order.
		if record.Offset < next && kept > 0 {
			overlap := min(next, record.Offset+kept) - record.Offset
			if overlap > 0 && !assembled.agreesAt(record.Offset, record.Payload[:overlap]) {
				agrees = false
				assembled.Conflicts = append(assembled.Conflicts, Conflict{
					Offset: record.Offset,
					Length: overlap,
				})
			}
		}

		if end <= next {
			// Wholly placed already: recorded as a duplicate, not skipped.
			at := -1
			if indexes != nil {
				at = indexes[i]
			}
			duplicates = append(duplicates, Duplicate{
				Index:  at,
				Offset: record.Offset,
				Length: uint64(record.Length),
				Agrees: agrees,
			})
			continue
		}

		if record.Offset > next {
			assembled.append(Part{Offset: next, Length: record.Offset - next, Gap: GapMissing})
			next = record.Offset
		}

		if record.Offset+kept > next {
			skip := next - record.Offset
			assembled.append(Part{
				Offset: next,
				Length: kept - skip,
				Bytes:  record.Payload[skip:kept],
			})
			next = record.Offset + kept
		}

		if end > next {
			// The untransferred-and-unkept bytes are at the record's end.
			assembled.append(Part{Offset: next, Length: end - next, Gap: GapTruncated})
			next = end
		}
	}

	assembled.End = next
	return assembled, duplicates
}

// append adds a part, joining it to the previous one of the same kind.
func (s *Stream) append(p Part) {
	if p.Length == 0 {
		return
	}
	// Only gaps join; payloads stay separate parts rather than being copied.
	if n := len(s.Parts); n > 0 && p.Gap != GapNone {
		if last := &s.Parts[n-1]; last.Gap == p.Gap && last.Offset+last.Length == p.Offset {
			last.Length += p.Length
			return
		}
	}
	s.Parts = append(s.Parts, p)
}

// agreesAt reports whether the stream already carries want at offset. Offsets
// in a gap agree.
func (s Stream) agreesAt(offset uint64, want []byte) bool {
	for _, p := range s.Parts {
		if len(want) == 0 {
			return true
		}
		if offset >= p.Offset+p.Length || offset < p.Offset {
			continue
		}
		within := offset - p.Offset
		n := min(uint64(len(want)), p.Length-within)
		if p.Gap == GapNone && !bytes.Equal(p.Bytes[within:within+n], want[:n]) {
			return false
		}
		want = want[n:]
		offset += n
	}
	return true
}
