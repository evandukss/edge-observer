//go:build attach

package attach_test

import (
	"strings"
	"testing"
)

// Exit-criterion row 12: on ONE connection the application keeps open, a
// complete framed exchange followed by an undecidable suffix produces useful
// output that the public command reads correctly from a copy - the permitted
// value present, the protected value and the suffix withheld, capture-end kept
// distinct from transport close, and no reinterpretation under a changed local
// policy. Row 3's second unexercised state - an undecided prefix not flushed at
// shutdown - is exercised here too, since the observer is stopped while the
// connection is still open and the suffix undecided.
func TestT17AConnectionKeptOpenProducesUsefulOutputThroughThePublicCommand(t *testing.T) {
	// The suffix is a request whose end never arrives: a client stopped after
	// its start line and one header has written a prefix the observer cannot
	// decide, on a connection nobody has closed.
	s := t17DriveCompleteThenSuffix(t, "GET /?asked="+t17Suffix+" HTTP/1.1\r\nX-Tail: rec")

	t17AssertRetainedComplete(t, s)

	// Capture-end is not a transport close: the connection was still open when
	// the observer sealed it.
	if s.retained.ending != "still_open" {
		t.Errorf("the sealed connection ended %q, want still_open: capture-end must stay distinct from a transport close", s.retained.ending)
	}

	// The undecidable suffix was withheld, witnessed as an incomplete message
	// on the sent direction rather than silently dropped.
	if reason, ok := t17TruncationReason(s.retained.truncation, "sent"); !ok || reason != "incomplete_message" {
		t.Fatalf("the undecidable suffix was not withheld as incomplete: reason=%q present=%v truncation=%+v",
			reason, ok, s.retained.truncation)
	}

	// The suffix marker reached the observer (t17DriveCompleteThenSuffix waited
	// for it) and still must appear nowhere in durable output.
	t17Absent(t, "kept-open durable", t17DurableBytes(t, s.dir), t17Suffix)

	// The copy reads correctly through the public command alone, under a changed
	// local policy, with the suffix still absent.
	t17PublicInspection(t, s, t17Suffix)
}

// Exit-criterion row 12's close-delimited control: a response whose end is
// signalled only by the transport closing must NOT be treated as complete
// merely because capture stopped. This observer withholds every close-delimited
// response by construction - a fragment carries no close, so a closed
// connection and missing bytes look alike - so the decidable control beside it
// is a length-framed response on the same open connection, which DOES complete
// and is retained. Without that pairing, a system that completed nothing would
// pass. Prior grading recorded this requirement as NOT ESTABLISHED.
func TestT17ACloseDelimitedResponseIsNotCompletedByCaptureStopping(t *testing.T) {
	binary := built(t)
	port := t17CloseServer(t)
	client := speaking(t, port)
	c := configuring(t, target("under-test", client.process))
	observer := started(t, binary, c)

	// Control: a length-framed response completes and is retained.
	t17SendRaw(t, client, "GET /?asked=framed HTTP/1.1\r\nHost: localhost\r\n\r\n")
	t17ReadResponse(t, client)
	seen := t17SeenAtLeast(t, binary, c, 2)

	// Fault: a close-delimited response on the SAME open connection. Its end is
	// signalled only by a transport close, which never comes; capture stopping
	// must not stand in for it.
	t17SendRaw(t, client, "GET /?asked=close HTTP/1.1\r\nHost: localhost\r\n\r\n")
	t17ReadUntilMarker(t, client, t17CloseBody)
	t17SeenAtLeast(t, binary, c, seen+1)

	sealed := ended(t, observer, c)
	dir := observer.directory(c)

	framed := t17ReadRetained(t, dir, sealed, client.process.PID, "framed")
	if len(framed.exchanges) != 1 {
		t.Fatalf("the length-framed control was not retained as exactly one exchange: %d", len(framed.exchanges))
	}
	if framed.ending != "still_open" {
		t.Errorf("the connection ended %q, want still_open: capture stopped while it was open", framed.ending)
	}
	durable := t17DurableBytes(t, dir)
	if !strings.Contains(string(durable), t17Base64(t17FramedBody)) {
		t.Fatal("the length-framed control's body did not reach durable output, so the run completes nothing and proves nothing")
	}
	t17Absent(t, "close-delimited durable", durable, t17CloseBody)
}
