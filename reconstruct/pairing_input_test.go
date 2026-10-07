package reconstruct_test

import (
	"errors"
	"testing"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/reconstruct"
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

func newPairing(t *testing.T, reserver http1.Reserver) *reconstruct.Pairing {
	t.Helper()
	p, err := reconstruct.NewPairing(reconstruct.DefaultLimits(), reserver)
	if err != nil {
		t.Fatalf("NewPairing: %v", err)
	}
	return p
}

func TestAPairingNeedsAReserver(t *testing.T) {
	if _, err := reconstruct.NewPairing(reconstruct.DefaultLimits(), nil); !errors.Is(err, http1.ErrReserver) {
		t.Errorf("NewPairing with no reserver = %v, want %v", err, http1.ErrReserver)
	}
}

// Each direction keeps its own position: the first part of each may begin
// anywhere, and every later one where that direction stands.
func TestEachDirectionOfAPairingKeepsItsOwnPosition(t *testing.T) {
	p := newPairing(t, &grant{})

	if _, err := p.Feed(fragment.Received, bytesAt(0, "GET")); err != nil {
		t.Fatalf("the first received part: %v", err)
	}
	if _, err := p.Feed(fragment.Sent, bytesAt(500, "HTTP")); err != nil {
		t.Fatalf("the first sent part, at its own offset: %v", err)
	}
	received, receivedStarted := p.Next(fragment.Received)
	sent, sentStarted := p.Next(fragment.Sent)
	if !receivedStarted || received != 3 || !sentStarted || sent != 504 {
		t.Fatalf("Next = received %d %t, sent %d %t; want 3 true, 504 true", received, receivedStarted, sent, sentStarted)
	}

	before := reconstruct.Snapshot(p)
	for name, refused := range map[string]struct {
		direction fragment.Direction
		part      stream.Part
	}{
		"received at the sent position": {fragment.Received, bytesAt(504, " /")},
		"sent at the received position": {fragment.Sent, bytesAt(3, "/1.1")},
		"received behind":               {fragment.Received, bytesAt(2, "T /")},
	} {
		if _, err := p.Feed(refused.direction, refused.part); !errors.Is(err, http1.ErrOffset) {
			t.Errorf("%s: Feed = %v, want %v", name, err, http1.ErrOffset)
		}
		if after := reconstruct.Snapshot(p); after != before {
			t.Errorf("%s: a refused part changed the pairing:\n  before %s\n  after  %s", name, before, after)
		}
	}

	if _, err := p.Feed(fragment.Received, bytesAt(3, " /one HTTP/1.1\r\n\r\n")); err != nil {
		t.Errorf("the received part that begins where received stands, the control: %v", err)
	}
}

func TestAPartForNeitherDirectionOrBreakingItsRulesIsRefused(t *testing.T) {
	p := newPairing(t, &grant{})
	before := reconstruct.Snapshot(p)

	if _, err := p.Feed(fragment.Unknown, bytesAt(0, "GET")); !errors.Is(err, reconstruct.ErrDirection) {
		t.Errorf("a part with no direction: Feed = %v, want %v", err, reconstruct.ErrDirection)
	}
	if _, err := p.Feed(fragment.Received, stream.Part{Offset: 0, Length: 3}); !errors.Is(err, stream.ErrInvalidPart) {
		t.Errorf("a part with no bytes and no hole: Feed = %v, want %v", err, stream.ErrInvalidPart)
	}
	if after := reconstruct.Snapshot(p); after != before {
		t.Errorf("a refused part changed the pairing:\n  before %s\n  after  %s", before, after)
	}
}

func TestNothingIsFedToAPairingAfterEnd(t *testing.T) {
	p := newPairing(t, &grant{})
	if _, err := p.Feed(fragment.Received, bytesAt(0, "GET")); err != nil {
		t.Fatalf("the control, before End: %v", err)
	}
	if got := p.End(); got.Result != http1.End {
		t.Fatalf("End returned %s", got.Result)
	}
	if _, err := p.Feed(fragment.Received, bytesAt(3, " /")); !errors.Is(err, http1.ErrEnded) {
		t.Errorf("Feed after End = %v, want %v", err, http1.ErrEnded)
	}
	if again := p.End(); again.Result != http1.End || len(again.Exchanges) != 0 {
		t.Errorf("a second End = %s with %d exchanges, want End and nothing", again.Result, len(again.Exchanges))
	}
}
