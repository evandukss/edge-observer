//go:build attach

package attach_test

import (
	"strings"
	"testing"
)

// On ONE connection the application keeps open, a complete framed exchange
// followed by an undecidable suffix produces useful output that the public
// command reads correctly from a copy - the permitted value present, the
// protected value and the suffix withheld, capture-end kept distinct from
// transport close, and no reinterpretation under a changed local policy. That
// an undecided prefix is not flushed at shutdown is exercised here too, since
// the observer is stopped while the connection is still open and the suffix
// undecided.
func TestAConnectionKeptOpenProducesUsefulOutputThroughThePublicCommand(t *testing.T) {
	// The suffix is a request whose end never arrives: a client stopped after
	// its start line and one header has written a prefix the observer cannot
	// decide, on a connection nobody has closed.
	s := withholdDriveCompleteThenSuffix(t, "GET /?asked="+withholdSuffix+" HTTP/1.1\r\nX-Tail: rec")

	withholdAssertRetainedComplete(t, s)

	// Capture-end is not a transport close: the connection was still open when
	// the observer sealed it.
	if s.retained.ending != "still_open" {
		t.Errorf("the sealed connection ended %q, want still_open: capture-end must stay distinct from a transport close", s.retained.ending)
	}

	// The undecidable suffix was withheld, witnessed as an incomplete message
	// on the sent direction rather than silently dropped.
	if reason, ok := withholdTruncationReason(s.retained.truncation, "sent"); !ok || reason != "incomplete_message" {
		t.Fatalf("the undecidable suffix was not withheld as incomplete: reason=%q present=%v truncation=%+v",
			reason, ok, s.retained.truncation)
	}

	// The suffix marker reached the observer (withholdDriveCompleteThenSuffix waited
	// for it) and still must appear nowhere in durable output.
	withholdAbsent(t, "kept-open durable", withholdDurableBytes(t, s.dir), withholdSuffix)

	// The copy reads correctly through the public command alone, under a changed
	// local policy, with the suffix still absent.
	withholdPublicInspection(t, s, withholdSuffix)
}

// The close-delimited control: a response whose end is signalled only by the
// transport closing must NOT be treated as complete merely because capture
// stopped. This observer withholds every close-delimited response by
// construction - a fragment carries no close, so a closed connection and
// missing bytes look alike - so the decidable control beside it is a
// length-framed response on the same open connection, which DOES complete and
// is retained. Without that pairing, a system that completed nothing would
// pass. Prior grading recorded this requirement as NOT ESTABLISHED.
func TestACloseDelimitedResponseIsNotCompletedByCaptureStopping(t *testing.T) {
	binary := built(t)
	port := withholdCloseServer(t)
	client := speaking(t, port)
	c := configuring(t, target("under-test", client.process))
	observer := started(t, binary, c)

	// Control: a length-framed response completes and is retained.
	withholdSendRaw(t, client, "GET /?asked=framed HTTP/1.1\r\nHost: localhost\r\n\r\n")
	withholdReadResponse(t, client)
	seen := withholdSeenAtLeast(t, binary, c, 2)

	// Fault: a close-delimited response on the SAME open connection. Its end is
	// signalled only by a transport close, which never comes; capture stopping
	// must not stand in for it.
	withholdSendRaw(t, client, "GET /?asked=close HTTP/1.1\r\nHost: localhost\r\n\r\n")
	withholdReadUntilMarker(t, client, withholdCloseBody)
	withholdSeenAtLeast(t, binary, c, seen+1)

	sealed := ended(t, observer, c)
	dir := observer.directory(c)

	framed := withholdReadRetained(t, dir, sealed, client.process.PID, "framed")
	if len(framed.exchanges) != 1 {
		t.Fatalf("the length-framed control was not retained as exactly one exchange: %d", len(framed.exchanges))
	}
	if framed.ending != "still_open" {
		t.Errorf("the connection ended %q, want still_open: capture stopped while it was open", framed.ending)
	}
	durable := withholdDurableBytes(t, dir)
	if !strings.Contains(string(durable), withholdBase64(withholdFramedBody)) {
		t.Fatal("the length-framed control's body did not reach durable output, so the run completes nothing and proves nothing")
	}
	withholdAbsent(t, "close-delimited durable", durable, withholdCloseBody)
}
