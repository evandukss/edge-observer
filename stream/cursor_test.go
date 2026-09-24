package stream_test

import (
	"errors"
	"testing"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/stream"
)

// A message split across many library calls is the ordinary case.
func TestALineSplitAcrossFragmentsIsReadWhole(t *testing.T) {
	c := stream.NewCursor(single(t,
		record(fragment.Sent, 1, 0, "POST /db/v2"),
		record(fragment.Sent, 2, 11, "/row HTTP/1.1\r"),
		record(fragment.Sent, 3, 25, "\nHost: backends\r\n"),
	))

	first, err := c.ReadLine(1024)
	if err != nil {
		t.Fatalf("ReadLine() = %v", err)
	}
	if got, want := string(first), "POST /db/v2/row HTTP/1.1"; got != want {
		t.Fatalf("first line = %q, want %q", got, want)
	}

	second, err := c.ReadLine(1024)
	if err != nil {
		t.Fatalf("ReadLine() = %v", err)
	}
	if got, want := string(second), "Host: backends"; got != want {
		t.Fatalf("second line = %q, want %q", got, want)
	}
}

// Only CRLF ends a line; a bare LF is a smuggling vector.
func TestABareLineFeedDoesNotEndALine(t *testing.T) {
	c := stream.NewCursor(single(t, record(fragment.Sent, 1, 0, "GET / HTTP/1.1\nHost: x\r\n")))

	line, err := c.ReadLine(1024)
	if err != nil {
		t.Fatalf("ReadLine() = %v", err)
	}
	if got, want := string(line), "GET / HTTP/1.1\nHost: x"; got != want {
		t.Fatalf("line = %q, want %q", got, want)
	}
}

func TestACarriageReturnThatIsNotFollowedByALineFeedStaysInTheLine(t *testing.T) {
	c := stream.NewCursor(single(t, record(fragment.Sent, 1, 0, "a\rb\r\n")))

	line, err := c.ReadLine(1024)
	if err != nil {
		t.Fatalf("ReadLine() = %v", err)
	}
	if got, want := string(line), "a\rb"; got != want {
		t.Fatalf("line = %q, want %q", got, want)
	}
}

func TestALineThatReachesItsBoundIsRefusedRatherThanReturnedShort(t *testing.T) {
	c := stream.NewCursor(single(t, record(fragment.Sent, 1, 0, "0123456789\r\n")))

	if _, err := c.ReadLine(4); !errors.Is(err, stream.ErrTooLong) {
		t.Fatalf("ReadLine(4) = %v, want %v", err, stream.ErrTooLong)
	}
}

func TestALineThatRunsIntoAHoleIsRefused(t *testing.T) {
	c := stream.NewCursor(single(t,
		record(fragment.Sent, 1, 0, "Host: acq"),
		record(fragment.Sent, 2, 20, "uirer\r\n"),
	))

	if _, err := c.ReadLine(1024); !errors.Is(err, stream.ErrGap) {
		t.Fatalf("ReadLine() = %v, want %v", err, stream.ErrGap)
	}
}

func TestALineThatRunsOffTheEndOfTheStreamIsRefused(t *testing.T) {
	c := stream.NewCursor(single(t, record(fragment.Sent, 1, 0, "GET / HTTP/1.1")))

	if _, err := c.ReadLine(1024); !errors.Is(err, stream.ErrShort) {
		t.Fatalf("ReadLine() = %v, want %v", err, stream.ErrShort)
	}
}

func TestReadNJoinsFragmentsAndRefusesToCrossAHole(t *testing.T) {
	whole := stream.NewCursor(single(t,
		record(fragment.Sent, 1, 0, "{\"a\":"),
		record(fragment.Sent, 2, 5, "1}"),
	))
	got, err := whole.ReadN(7)
	if err != nil {
		t.Fatalf("ReadN(7) = %v", err)
	}
	if want := "{\"a\":1}"; string(got) != want {
		t.Fatalf("ReadN(7) = %q, want %q", got, want)
	}

	holed := stream.NewCursor(single(t,
		record(fragment.Sent, 1, 0, "{\"a\":"),
		record(fragment.Sent, 2, 9, "1}"),
	))
	if _, err := holed.ReadN(11); !errors.Is(err, stream.ErrGap) {
		t.Fatalf("ReadN over a hole = %v, want %v", err, stream.ErrGap)
	}
}

func TestReadNBeyondTheEndOfTheStreamIsRefusedAndReadsNothing(t *testing.T) {
	c := stream.NewCursor(single(t, record(fragment.Sent, 1, 0, "short")))

	if _, err := c.ReadN(64); !errors.Is(err, stream.ErrShort) {
		t.Fatalf("ReadN(64) = %v, want %v", err, stream.ErrShort)
	}
	if got, want := c.Offset(), uint64(0); got != want {
		t.Fatalf("a refused read moved the cursor to %d, want %d", got, want)
	}
}

// A hole inside a body of known length leaves an incomplete body, not an
// unknown end.
func TestTakeReadsAcrossAHoleAndReportsHowWideItWas(t *testing.T) {
	c := stream.NewCursor(single(t,
		record(fragment.Sent, 1, 0, "head"),
		record(fragment.Sent, 2, 10, "tail"),
	))

	data, holed, err := c.Take(14, 1024)
	if err != nil {
		t.Fatalf("Take() = %v", err)
	}
	if got, want := string(data), "headtail"; got != want {
		t.Fatalf("Take kept %q, want %q", got, want)
	}
	if got, want := holed, uint64(6); got != want {
		t.Fatalf("Take reported %d holed offsets, want %d", got, want)
	}
	if got, want := c.Offset(), uint64(14); got != want {
		t.Fatalf("Take left the cursor at %d, want %d", got, want)
	}
}

// The bound limits what Take keeps, not how far it advances.
func TestTakeStepsOverEveryOffsetWhileKeepingOnlyWhatItWasAllowed(t *testing.T) {
	c := stream.NewCursor(single(t, record(fragment.Sent, 1, 0, "0123456789")))

	data, _, err := c.Take(10, 4)
	if err != nil {
		t.Fatalf("Take() = %v", err)
	}
	if got, want := string(data), "0123"; got != want {
		t.Fatalf("Take kept %q, want %q", got, want)
	}
	if !c.AtEnd() {
		t.Fatalf("Take left the cursor at %d, want the end at %d", c.Offset(), uint64(10))
	}
}

func TestAtGapNamesTheHoleTheCursorIsSittingIn(t *testing.T) {
	c := stream.NewCursor(single(t,
		truncated(fragment.Sent, 1, 0, "he", 4),
		record(fragment.Sent, 2, 4, "tail"),
	))

	if _, err := c.ReadN(2); err != nil {
		t.Fatalf("ReadN(2) = %v", err)
	}
	reason, in := c.AtGap()
	if !in {
		t.Fatal("the cursor reports no hole where the fragment was truncated")
	}
	if reason != stream.GapTruncated {
		t.Fatalf("AtGap() = %s, want %s", reason, stream.GapTruncated)
	}
}

func TestPeekDoesNotMoveTheCursorAndStopsAtAHole(t *testing.T) {
	c := stream.NewCursor(single(t,
		record(fragment.Sent, 1, 0, "HTTP"),
		record(fragment.Sent, 2, 8, "/1.1"),
	))

	if got, want := string(c.Peek(8)), "HTTP"; got != want {
		t.Fatalf("Peek(8) = %q, want %q", got, want)
	}
	if got, want := c.Offset(), uint64(0); got != want {
		t.Fatalf("Peek moved the cursor to %d, want %d", got, want)
	}
}
