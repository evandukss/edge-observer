package processing

import "testing"

// Between the decoding outcomes the two messages established, the exchange
// takes the higher reason - a failed decoding over one too large over one too
// costly - whichever message established it, and no reason where neither did.
func TestTheExchangeTakesTheHigherOfItsMessagesReasons(t *testing.T) {
	order := []string{ReasonContentDecodingFailed, ReasonContentDecodedTooLarge, ReasonContentDecodingTooCostly}
	if got := ranked([2]string{}); got != "" {
		t.Fatalf("no outcome on either message ranks as %q, want none", got)
	}
	for higher, one := range order {
		for _, other := range append(append([]string{}, order[higher:]...), "") {
			for _, reasons := range [][2]string{{one, other}, {other, one}} {
				if got := ranked(reasons); got != one {
					t.Errorf("request %q and response %q rank as %q, want %q", reasons[0], reasons[1], got, one)
				}
			}
		}
	}
}
