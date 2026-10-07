package http1_test

import (
	"errors"
	"testing"

	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/stream"
)

// grant is a Reserver that grants everything and keeps the account, so a case
// can read what was reserved and released.
type grant struct {
	reserved, released http1.Charge
	asked              int
}

func (g *grant) Reserve(c http1.Charge) bool {
	g.asked++
	g.reserved = g.reserved.Add(c)
	return true
}

func (g *grant) Release(c http1.Charge) { g.released = g.released.Add(c) }

func bytesAt(offset uint64, text string) stream.Part {
	return stream.Part{Offset: offset, Length: uint64(len(text)), Bytes: []byte(text)}
}

func holeAt(offset, length uint64) stream.Part {
	return stream.Part{Offset: offset, Length: length, Gap: stream.GapMissing}
}

func newParser(t *testing.T, kind http1.Kind, reserver http1.Reserver) *http1.Parser {
	t.Helper()
	p, err := http1.NewParser(kind, http1.DefaultLimits(), reserver)
	if err != nil {
		t.Fatalf("NewParser(%s): %v", kind, err)
	}
	return p
}

func TestAParserIsForRequestsOrResponsesAndNeedsAReserver(t *testing.T) {
	if _, err := http1.NewParser(http1.UnknownKind, http1.DefaultLimits(), &grant{}); !errors.Is(err, http1.ErrKind) {
		t.Errorf("NewParser(unknown) = %v, want %v", err, http1.ErrKind)
	}
	if _, err := http1.NewParser(http1.Request, http1.DefaultLimits(), nil); !errors.Is(err, http1.ErrReserver) {
		t.Errorf("NewParser with no reserver = %v, want %v", err, http1.ErrReserver)
	}
	for _, kind := range []http1.Kind{http1.Request, http1.Response} {
		if _, err := http1.NewParser(kind, http1.DefaultLimits(), &grant{}); err != nil {
			t.Errorf("NewParser(%s) = %v, the control", kind, err)
		}
	}
}

// The first part may begin anywhere, as capture can attach part way through a
// connection; every later one begins where the parser stands.
func TestAPartThatDoesNotBeginWhereTheParserStandsIsRefusedAndChangesNothing(t *testing.T) {
	p := newParser(t, http1.Request, &grant{})
	if _, started := p.Next(); started {
		t.Fatal("Next reports a position before any part was fed")
	}

	progress, err := p.Feed(bytesAt(1000, "GET /o"))
	if err != nil {
		t.Fatalf("the first part, at 1000: %v", err)
	}
	if progress.Result != http1.NeedInput || progress.Consumed != 6 {
		t.Fatalf("wiring, not the property: half a start line returned %s having consumed %d of 6", progress.Result, progress.Consumed)
	}
	if next, started := p.Next(); !started || next != 1006 {
		t.Fatalf("Next = %d, %t after six offsets from 1000, want 1006, true", next, started)
	}

	before := http1.Snapshot(p)
	for name, part := range map[string]stream.Part{
		"behind":     bytesAt(1005, "ne HTTP/1.1\r\n"),
		"ahead":      bytesAt(1007, "e HTTP/1.1\r\n"),
		"a hole off": holeAt(1010, 4),
		"from zero":  bytesAt(0, "ne HTTP/1.1\r\n"),
	} {
		if _, err := p.Feed(part); !errors.Is(err, http1.ErrOffset) {
			t.Errorf("%s: Feed = %v, want %v", name, err, http1.ErrOffset)
		}
		if after := http1.Snapshot(p); after != before {
			t.Errorf("%s: a refused part changed the parser:\n  before %s\n  after  %s", name, before, after)
		}
	}

	if _, err := p.Feed(bytesAt(1006, "ne HTTP/1.1\r\n")); err != nil {
		t.Errorf("the part that begins where the parser stands, the control: %v", err)
	}
}

func TestAPartThatBreaksItsOwnRulesIsRefusedAndChangesNothing(t *testing.T) {
	p := newParser(t, http1.Response, &grant{})
	before := http1.Snapshot(p)

	for name, part := range map[string]stream.Part{
		"empty":              {Offset: 0, Length: 0},
		"short of its bytes": {Offset: 0, Length: 4, Bytes: []byte("HT")},
		"a hole with bytes":  {Offset: 0, Length: 2, Gap: stream.GapTruncated, Bytes: []byte("HT")},
	} {
		if _, err := p.Feed(part); !errors.Is(err, stream.ErrInvalidPart) {
			t.Errorf("%s: Feed = %v, want %v", name, err, stream.ErrInvalidPart)
		}
		if after := http1.Snapshot(p); after != before {
			t.Errorf("%s: a refused part changed the parser:\n  before %s\n  after  %s", name, before, after)
		}
	}
}

func TestNothingIsFedAfterEnd(t *testing.T) {
	p := newParser(t, http1.Request, &grant{})
	if _, err := p.Feed(bytesAt(0, "GET")); err != nil {
		t.Fatalf("the control, before End: %v", err)
	}
	if got := p.End(); got.Result != http1.End {
		t.Fatalf("End returned %s", got.Result)
	}
	if _, err := p.Feed(bytesAt(3, " /one HTTP/1.1\r\n\r\n")); !errors.Is(err, http1.ErrEnded) {
		t.Errorf("Feed after End = %v, want %v", err, http1.ErrEnded)
	}
	if again := p.End(); again.Result != http1.End || again.Message != nil || again.Consumed != 0 {
		t.Errorf("a second End = %s with message %v, want End and nothing", again.Result, again.Message)
	}
}

// Only a response waiting on the request it answers takes an answer.
func TestAnAnswerNoResponseIsWaitingForIsRefused(t *testing.T) {
	request := newParser(t, http1.Request, &grant{})
	if _, err := request.Answer("GET"); !errors.Is(err, http1.ErrAnswer) {
		t.Errorf("Answer on a request parser = %v, want %v", err, http1.ErrAnswer)
	}

	response := newParser(t, http1.Response, &grant{})
	if _, err := response.Answer("GET"); !errors.Is(err, http1.ErrAnswer) {
		t.Errorf("Answer before any response = %v, want %v", err, http1.ErrAnswer)
	}
	if _, err := response.Feed(bytesAt(0, "HTTP/1.1 200 OK\r\nContent-Le")); err != nil {
		t.Fatalf("half a field section: %v", err)
	}
	before := http1.Snapshot(response)
	if _, err := response.Answer("GET"); !errors.Is(err, http1.ErrAnswer) {
		t.Errorf("Answer inside a field section = %v, want %v", err, http1.ErrAnswer)
	}
	if after := http1.Snapshot(response); after != before {
		t.Errorf("a refused answer changed the parser:\n  before %s\n  after  %s", before, after)
	}
}
