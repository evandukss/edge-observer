//go:build attach

package attach_test

import (
	"strings"
	"testing"
)

// Exit-criterion row 3, state 1: input a strict endpoint would reject is not
// written raw because parsing failed. A complete exchange (the decidable
// control that must persist) is followed on the same open connection by a
// request whose start line carries no version - malformed - carrying a marker.
// The marker reaches nothing durable, and the malformed message is witnessed as
// the reason the retained prefix stops.
func TestT17MalformedInputIsNotWrittenRawBecauseParsingFailed(t *testing.T) {
	s := t17DriveCompleteThenSuffix(t, "GET /?asked="+t17Malformed+"\r\n\r\n")

	t17AssertRetainedComplete(t, s)

	if reason, ok := t17TruncationReason(s.retained.truncation, "sent"); !ok || reason != "malformed_message" {
		t.Fatalf("the malformed suffix was not witnessed as the malformed reason it stopped on: reason=%q present=%v truncation=%+v",
			reason, ok, s.retained.truncation)
	}
	t17Absent(t, "malformed durable", t17DurableBytes(t, s.dir), t17Malformed)
}

// Exit-criterion row 3, state 2: an undecided prefix is not flushed at shutdown.
// The observer is stopped while the connection is still open and the suffix
// undecidable; the suffix must be withheld, witnessed as an incomplete message,
// with capture-end kept distinct from a transport close.
func TestT17AnUndecidedPrefixIsNotFlushedAtShutdown(t *testing.T) {
	s := t17DriveCompleteThenSuffix(t, "GET /?asked="+t17Suffix+" HTTP/1.1\r\nX-Tail: rec")

	t17AssertRetainedComplete(t, s)

	if reason, ok := t17TruncationReason(s.retained.truncation, "sent"); !ok || reason != "incomplete_message" {
		t.Fatalf("the undecided prefix was not withheld as incomplete at shutdown: reason=%q present=%v truncation=%+v",
			reason, ok, s.retained.truncation)
	}
	if s.retained.ending != "still_open" {
		t.Errorf("shutdown sealed the connection as %q, want still_open", s.retained.ending)
	}
	t17Absent(t, "undecided durable", t17DurableBytes(t, s.dir), t17Suffix)
}

// Exit-criterion row 3, state 3: a header split across two TLS writes does not
// leak. The client writes the header name and then, only after the observer has
// seen that first write, the value - so the two cross the boundary as separate
// fragments. The observer must join them before the transform, or the protected
// value survives. The permitted header on the same request is the decidable
// control that must persist.
func TestT17AHeaderSplitAcrossTwoWritesDoesNotLeak(t *testing.T) {
	binary := built(t)
	port := serving(t)
	client := speaking(t, port)
	c := configuring(t, target("under-test", client.process))
	t17RemoveAuthorization(t, c)
	observer := started(t, binary, c)

	t17SendRaw(t, client, "GET /?asked=split HTTP/1.1\r\nHost: localhost\r\nX-Public: "+t17Permitted+"\r\nAuthorization: Bearer ")
	// The observer saw the first write. The count rising again after the second
	// write, with no response in between, proves the value crossed as its own
	// fragment: the split is real, not coalesced by the client.
	first := t17SeenAtLeast(t, binary, c, 1)
	t17SendRaw(t, client, t17Split+"\r\n\r\n")
	t17SeenAtLeast(t, binary, c, first+1)
	t17ReadResponse(t, client)

	sealed := ended(t, observer, c)
	dir := observer.directory(c)
	retained := t17ReadRetained(t, dir, sealed, client.process.PID, "split")

	if len(retained.exchanges) != 1 {
		t.Fatalf("the split request was not reconstructed as exactly one exchange: %d", len(retained.exchanges))
	}
	req := retained.exchanges[0].Request.Message
	if v, ok := t17HeaderValue(req, "x-public"); !ok || v != t17Permitted {
		t.Fatalf("the split request did not reconstruct its permitted header: value=%q present=%v", v, ok)
	}
	if v, ok := t17HeaderValue(req, "authorization"); ok {
		t.Fatalf("the protected header, split across two writes, survived with value %q", v)
	}
	durable := t17DurableBytes(t, dir)
	t17Absent(t, "split durable", durable, t17Split)
	if !strings.Contains(string(durable), t17Permitted) {
		t.Fatal("the permitted marker did not reach durable output")
	}
}
