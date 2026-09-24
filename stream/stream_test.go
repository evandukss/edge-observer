package stream_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/stream"
)

var at = time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)

var process = fragment.Process{PID: 1731, StartTime: 90210}

// record is a fragment carrying every byte the call transferred.
func record(direction fragment.Direction, sequence, offset uint64, payload string) fragment.Record {
	return fragment.Record{
		Process:    process,
		Connection: 7,
		Direction:  direction,
		Sequence:   sequence,
		Offset:     offset,
		Length:     uint32(len(payload)),
		Payload:    []byte(payload),
		At:         at,
	}
}

// truncated is a fragment whose call transferred length bytes, of which
// capture kept payload.
func truncated(direction fragment.Direction, sequence, offset uint64, payload string, length uint32) fragment.Record {
	r := record(direction, sequence, offset, payload)
	r.Length = length
	return r
}

// text is every byte of a stream in order, with a gap rendered as its reason
// in braces, so assertions see holes as well as bytes.
func text(s stream.Stream) string {
	var b strings.Builder
	for _, p := range s.Parts {
		if p.Gap == stream.GapNone {
			b.Write(p.Bytes)
			continue
		}
		b.WriteString("{" + p.Gap.String() + ":")
		b.WriteString(itoa(p.Length))
		b.WriteString("}")
	}
	return b.String()
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func single(t *testing.T, records ...fragment.Record) stream.Stream {
	t.Helper()
	result := stream.Assemble(records)
	if len(result.Discards) != 0 {
		t.Fatalf("Assemble discarded %d of %d records: %v", len(result.Discards), len(records), result.Discards)
	}
	if len(result.Streams) != 1 {
		t.Fatalf("Assemble produced %d streams, want 1", len(result.Streams))
	}
	return result.Streams[0]
}

func TestConsecutiveFragmentsBecomeOneUninterruptedStream(t *testing.T) {
	s := single(t,
		record(fragment.Sent, 1, 0, "POST /db"),
		record(fragment.Sent, 2, 8, "/v2/row "),
		record(fragment.Sent, 3, 16, "HTTP/1.1"),
	)

	if got, want := text(s), "POST /db/v2/row HTTP/1.1"; got != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
	if s.Gaps() != 0 {
		t.Fatalf("Gaps() = %d, want 0", s.Gaps())
	}
}

// Offset, not arrival order, orders the stream.
func TestOffsetOrdersTheStreamAndArrivalOrderDoesNot(t *testing.T) {
	forwards := single(t,
		record(fragment.Sent, 1, 0, "one"),
		record(fragment.Sent, 2, 3, "two"),
		record(fragment.Sent, 3, 6, "six"),
	)
	shuffled := single(t,
		record(fragment.Sent, 3, 6, "six"),
		record(fragment.Sent, 1, 0, "one"),
		record(fragment.Sent, 2, 3, "two"),
	)

	if text(forwards) != text(shuffled) {
		t.Fatalf("arrival order changed the stream: %q against %q", text(forwards), text(shuffled))
	}
	if got, want := text(forwards), "onetwosix"; got != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
}

func TestTheTwoDirectionsOfOneConnectionAssembleSeparately(t *testing.T) {
	result := stream.Assemble([]fragment.Record{
		record(fragment.Sent, 1, 0, "request"),
		record(fragment.Received, 2, 0, "response"),
	})

	if len(result.Streams) != 2 {
		t.Fatalf("Assemble produced %d streams, want 2", len(result.Streams))
	}
	for _, s := range result.Streams {
		want := map[fragment.Direction]string{fragment.Sent: "request", fragment.Received: "response"}[s.Key.Direction]
		if got := text(s); got != want {
			t.Errorf("%v = %q, want %q", s.Key, got, want)
		}
	}
}

// Uncaptured bytes are a hole; the fragments either side did not touch.
func TestBytesNoFragmentCoveredAreAHoleAndNotAJoin(t *testing.T) {
	s := single(t,
		record(fragment.Sent, 1, 0, "before"),
		record(fragment.Sent, 2, 106, "after"),
	)

	if got, want := text(s), "before{missing:100}after"; got != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
	if got, want := s.Gaps(), uint64(100); got != want {
		t.Fatalf("Gaps() = %d, want %d", got, want)
	}
}

// A truncated fragment's missing bytes are at its end, and the next fragment
// sits where the process put it.
func TestATruncatedFragmentLeavesItsHoleAtItsEnd(t *testing.T) {
	s := single(t,
		truncated(fragment.Sent, 1, 0, "head", 10),
		record(fragment.Sent, 2, 10, "tail"),
	)

	if got, want := text(s), "head{truncated:6}tail"; got != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
}

// A fragment with nothing kept is a hole the width of the call.
func TestAFragmentWhollyLostIsAHoleTheWidthOfTheCall(t *testing.T) {
	s := single(t,
		record(fragment.Sent, 1, 0, "head"),
		truncated(fragment.Sent, 2, 4, "", 32),
		record(fragment.Sent, 3, 36, "tail"),
	)

	if got, want := text(s), "head{truncated:32}tail"; got != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
	if got, want := s.End, uint64(40); got != want {
		t.Fatalf("End = %d, want %d", got, want)
	}
}

// Delivering the same fragment twice changes nothing.
func TestTheSameFragmentDeliveredTwiceChangesNothing(t *testing.T) {
	once := single(t,
		record(fragment.Sent, 1, 0, "one"),
		record(fragment.Sent, 2, 3, "two"),
	)
	twice := single(t,
		record(fragment.Sent, 1, 0, "one"),
		record(fragment.Sent, 2, 3, "two"),
		record(fragment.Sent, 1, 0, "one"),
		record(fragment.Sent, 2, 3, "two"),
	)

	if text(once) != text(twice) {
		t.Fatalf("a replayed fragment changed the stream: %q against %q", text(once), text(twice))
	}
	if len(twice.Conflicts) != 0 {
		t.Fatalf("a replayed fragment reported %d conflicts", len(twice.Conflicts))
	}
}

// Two records claiming one offset with different bytes: the stream keeps one
// and reports the conflict.
func TestTwoFragmentsThatDisagreeAboutOneOffsetAreRecordedAsAConflict(t *testing.T) {
	s := single(t,
		record(fragment.Sent, 1, 0, "approved"),
		record(fragment.Sent, 2, 0, "declined"),
	)

	if len(s.Conflicts) != 1 {
		t.Fatalf("Conflicts = %v, want one", s.Conflicts)
	}
	if got, want := s.Conflicts[0].Length, uint64(8); got != want {
		t.Fatalf("conflict length = %d, want %d", got, want)
	}
	// The earlier fragment is kept, so reordering cannot change what is read.
	if got, want := text(s), "approved"; got != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
}

// A record that should not exist contributes no bytes; its offsets become a
// hole.
func TestARecordValidateRefusesIsDiscardedAndLeavesItsOffsetsAHole(t *testing.T) {
	spoiled := record(fragment.Sent, 2, 4, "lost")
	spoiled.At = time.Time{}

	result := stream.Assemble([]fragment.Record{
		record(fragment.Sent, 1, 0, "head"),
		spoiled,
		record(fragment.Sent, 3, 8, "tail"),
	})

	if len(result.Discards) != 1 {
		t.Fatalf("Discards = %v, want one", result.Discards)
	}
	if got, want := result.Discards[0].Index, 1; got != want {
		t.Fatalf("discarded index %d, want %d", got, want)
	}
	if !errors.Is(result.Discards[0].Err, fragment.ErrInvalid) {
		t.Fatalf("discard error %v is not a %v", result.Discards[0].Err, fragment.ErrInvalid)
	}
	if got, want := text(result.Streams[0]), "head{missing:4}tail"; got != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
}

// A stream need not begin at zero: capture may attach mid-connection, and
// earlier bytes are not a hole.
func TestAStreamThatBeginsPartWayThroughHasNoHoleInFrontOfIt(t *testing.T) {
	s := single(t, record(fragment.Sent, 1, 4096, "tail"))

	if got, want := s.Start, uint64(4096); got != want {
		t.Fatalf("Start = %d, want %d", got, want)
	}
	if s.Gaps() != 0 {
		t.Fatalf("Gaps() = %d, want 0", s.Gaps())
	}
	if got, want := text(s), "tail"; got != want {
		t.Fatalf("stream = %q, want %q", got, want)
	}
}

func TestStreamsComeBackInAFixedOrderWhateverOrderTheRecordsArriveIn(t *testing.T) {
	second := record(fragment.Received, 1, 0, "b")
	second.Connection = 9
	third := record(fragment.Sent, 1, 0, "c")
	third.Process.PID = 2000

	forwards := stream.Assemble([]fragment.Record{record(fragment.Sent, 1, 0, "a"), second, third})
	backwards := stream.Assemble([]fragment.Record{third, second, record(fragment.Sent, 1, 0, "a")})

	if len(forwards.Streams) != 3 {
		t.Fatalf("Assemble produced %d streams, want 3", len(forwards.Streams))
	}
	for i := range forwards.Streams {
		if forwards.Streams[i].Key != backwards.Streams[i].Key {
			t.Fatalf("stream %d differs by input order: %v against %v", i, forwards.Streams[i].Key, backwards.Streams[i].Key)
		}
	}
}

func TestBytesAndGapsAccountForEveryOffsetOfTheStream(t *testing.T) {
	s := single(t,
		record(fragment.Sent, 1, 0, "head"),
		truncated(fragment.Sent, 2, 4, "k", 5),
		record(fragment.Sent, 3, 20, "tail"),
	)

	if got, want := s.Bytes()+s.Gaps(), s.End-s.Start; got != want {
		t.Fatalf("bytes %d plus gaps %d = %d, want the extent %d", s.Bytes(), s.Gaps(), got, want)
	}
}

func TestPartsCoverTheStreamWithNoOverlapAndNoSpace(t *testing.T) {
	s := single(t,
		record(fragment.Sent, 1, 0, "head"),
		truncated(fragment.Sent, 2, 4, "k", 5),
		record(fragment.Sent, 3, 20, "tail"),
	)

	next := s.Start
	for i, p := range s.Parts {
		if p.Offset != next {
			t.Fatalf("part %d begins at %d, want %d", i, p.Offset, next)
		}
		if p.Length == 0 {
			t.Fatalf("part %d is empty", i)
		}
		if p.Gap == stream.GapNone && uint64(len(p.Bytes)) != p.Length {
			t.Fatalf("part %d carries %d bytes over %d offsets", i, len(p.Bytes), p.Length)
		}
		if p.Gap != stream.GapNone && p.Bytes != nil {
			t.Fatalf("part %d is a %s gap and carries bytes", i, p.Gap)
		}
		next = p.Offset + p.Length
	}
	if next != s.End {
		t.Fatalf("the parts end at %d, want %d", next, s.End)
	}
}
