package http1_test

import (
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/stream"
)

var at = time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)

// fragments turns text into one stream, split at every occurrence of the split
// marker, so a case states where the library calls fell. "|12|" is a hole of
// twelve offsets transferred and not kept.
func fragments(t *testing.T, direction fragment.Direction, pieces ...string) stream.Stream {
	t.Helper()

	var records []fragment.Record
	var offset uint64
	for i, piece := range pieces {
		record := fragment.Record{
			Process:    fragment.Process{PID: 1731, StartTime: 90210},
			Connection: 7,
			Direction:  direction,
			Sequence:   uint64(i),
			Offset:     offset,
			Length:     uint32(len(piece)),
			Payload:    []byte(piece),
			At:         at,
		}
		if hole, ok := strings.CutPrefix(piece, "hole:"); ok {
			n := atoi(t, hole)
			record.Length = uint32(n)
			record.Payload = nil
		}
		records = append(records, record)
		offset += uint64(record.Length)
	}

	result := stream.Assemble(records)
	if len(result.Discards) != 0 {
		t.Fatalf("the case's own fragments were discarded: %v", result.Discards)
	}
	if len(result.Streams) != 1 {
		t.Fatalf("the case's own fragments made %d streams, want 1", len(result.Streams))
	}
	return result.Streams[0]
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("hole width %q is not a number", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func parseRequests(t *testing.T, pieces ...string) http1.Parsed {
	t.Helper()
	return http1.Parse(fragments(t, fragment.Received, pieces...), http1.Request, http1.DefaultLimits())
}

func parseResponses(t *testing.T, pieces ...string) http1.Parsed {
	t.Helper()
	return http1.Parse(fragments(t, fragment.Sent, pieces...), http1.Response, http1.DefaultLimits())
}

func only(t *testing.T, parsed http1.Parsed) http1.Message {
	t.Helper()
	if len(parsed.Messages) != 1 {
		t.Fatalf("parsed %d messages, want 1: %v", len(parsed.Messages), parsed.Messages)
	}
	return parsed.Messages[0]
}

const postRequest = "POST /api/v2/items HTTP/1.1\r\n" +
	"Host: backend:8443\r\n" +
	"Accept: */*\r\n" +
	"Content-Type: application/json\r\n" +
	"Content-Length: 26\r\n" +
	"\r\n" +
	`{"ref":"entry-4001-read"}` + "\n"

func TestARequestIsReadFromItsStartLineHeadersAndBody(t *testing.T) {
	m := only(t, parseRequests(t, postRequest))

	if m.Kind != http1.Request {
		t.Fatalf("Kind = %s, want %s", m.Kind, http1.Request)
	}
	if got, want := m.StartLine(), "POST /api/v2/items HTTP/1.1"; got != want {
		t.Errorf("StartLine() = %q, want %q", got, want)
	}
	if got, want := len(m.Headers), 4; got != want {
		t.Errorf("read %d headers, want %d: %v", got, want, m.Headers)
	}
	if got, ok := m.Lookup("content-type"); !ok || got != "application/json" {
		t.Errorf("Lookup(content-type) = %q, %v", got, ok)
	}
	if got, want := string(m.Body), `{"ref":"entry-4001-read"}`+"\n"; got != want {
		t.Errorf("Body = %q, want %q", got, want)
	}
	if m.Framing != http1.FramingContentLength {
		t.Errorf("Framing = %s, want %s", m.Framing, http1.FramingContentLength)
	}
	if !m.Complete || !m.Framed {
		t.Errorf("Complete = %v, Framed = %v, want both true (%s: %s)", m.Complete, m.Framed, m.Defect, m.Detail)
	}
}

func TestAResponseIsReadFromItsStatusLine(t *testing.T) {
	m := only(t, parseResponses(t,
		"HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\n\r\n"))

	if m.Kind != http1.Response {
		t.Fatalf("Kind = %s, want %s", m.Kind, http1.Response)
	}
	if got, want := m.Status, 409; got != want {
		t.Errorf("Status = %d, want %d", got, want)
	}
	if got, want := m.Reason, "Conflict"; got != want {
		t.Errorf("Reason = %q, want %q", got, want)
	}
	if !m.Complete {
		t.Errorf("Complete = false (%s: %s)", m.Defect, m.Detail)
	}
}

func TestAStatusLineWithNoReasonPhraseIsRead(t *testing.T) {
	for _, line := range []string{"HTTP/1.1 200\r\n", "HTTP/1.1 200 \r\n"} {
		m := only(t, parseResponses(t, line+"Content-Length: 0\r\n\r\n"))
		if m.Status != 200 || !m.Complete {
			t.Errorf("%q gave status %d complete %v (%s: %s)", line, m.Status, m.Complete, m.Defect, m.Detail)
		}
	}
}

// Fragment boundaries fall anywhere; where they fall must not change what is
// read.
func TestWhereTheFragmentBoundariesFallDoesNotChangeWhatIsRead(t *testing.T) {
	whole := only(t, parseRequests(t, postRequest))

	for _, size := range []int{1, 2, 3, 7, 13, 64} {
		var pieces []string
		for i := 0; i < len(postRequest); i += size {
			pieces = append(pieces, postRequest[i:min(i+size, len(postRequest))])
		}

		split := only(t, parseRequests(t, pieces...))
		if split.StartLine() != whole.StartLine() || string(split.Body) != string(whole.Body) ||
			len(split.Headers) != len(whole.Headers) || split.Complete != whole.Complete {
			t.Errorf("split into %d-byte fragments read %q with %d headers, want %q with %d",
				size, split.StartLine(), len(split.Headers), whole.StartLine(), len(whole.Headers))
		}
	}
}

func TestSeveralMessagesOnOneConnectionAreSeparated(t *testing.T) {
	parsed := parseRequests(t,
		"POST /one HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
		"POST /two HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
		"GET /three HTTP/1.1\r\n\r\n")

	if got, want := len(parsed.Messages), 3; got != want {
		t.Fatalf("parsed %d messages, want %d", got, want)
	}
	for i, want := range []string{"/one", "/two", "/three"} {
		if got := parsed.Messages[i].Target; got != want {
			t.Errorf("message %d target = %q, want %q", i, got, want)
		}
		if !parsed.Messages[i].Complete {
			t.Errorf("message %d is incomplete (%s: %s)", i, parsed.Messages[i].Defect, parsed.Messages[i].Detail)
		}
	}
	if got, want := string(parsed.Messages[0].Body), "abc"; got != want {
		t.Errorf("first body = %q, want %q", got, want)
	}
	if parsed.Unplaced != 0 {
		t.Errorf("Unplaced = %d, want 0", parsed.Unplaced)
	}
}

func TestAChunkedBodyIsRejoinedWithItsTrailers(t *testing.T) {
	m := only(t, parseResponses(t,
		"HTTP/1.1 200 OK\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n"+
			"5\r\nhello\r\n"+
			"6;name=value\r\n world\r\n"+
			"0\r\n"+
			"Checksum: 1\r\n"+
			"\r\n"))

	if m.Framing != http1.FramingChunked {
		t.Fatalf("Framing = %s, want %s (%s: %s)", m.Framing, http1.FramingChunked, m.Defect, m.Detail)
	}
	if got, want := string(m.Body), "hello world"; got != want {
		t.Errorf("Body = %q, want %q", got, want)
	}
	if got, want := len(m.Trailers), 1; got != want {
		t.Fatalf("read %d trailers, want %d", got, want)
	}
	if got, want := m.Trailers[0].Name, "Checksum"; got != want {
		t.Errorf("trailer = %q, want %q", got, want)
	}
	if !m.Complete || !m.Framed {
		t.Errorf("Complete = %v, Framed = %v (%s: %s)", m.Complete, m.Framed, m.Defect, m.Detail)
	}
}

func TestAMessageAfterAChunkedOneIsFound(t *testing.T) {
	parsed := parseResponses(t,
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
		"HTTP/1.1 204 No Content\r\n\r\n")

	if got, want := len(parsed.Messages), 2; got != want {
		t.Fatalf("parsed %d messages, want %d", got, want)
	}
	if got, want := parsed.Messages[1].Status, 204; got != want {
		t.Errorf("second status = %d, want %d", got, want)
	}
}

// Both framings declared is the smuggling shape: the endpoints disagree on
// where the next message begins, so the parser picks neither and stops.
func TestContentLengthAndTransferEncodingTogetherStopTheParseRatherThanChooseOne(t *testing.T) {
	parsed := parseRequests(t,
		"POST /one HTTP/1.1\r\n"+
			"Content-Length: 6\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n"+
			"0\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n")

	m := only(t, parsed)
	if m.Framing != http1.FramingAmbiguous {
		t.Errorf("Framing = %s, want %s", m.Framing, http1.FramingAmbiguous)
	}
	if m.Defect != http1.DefectAmbiguousFraming {
		t.Errorf("Defect = %s, want %s", m.Defect, http1.DefectAmbiguousFraming)
	}
	if m.Complete || m.Framed {
		t.Errorf("Complete = %v, Framed = %v, want both false", m.Complete, m.Framed)
	}
	if parsed.Unplaced == 0 {
		t.Error("Unplaced = 0; the bytes after the refused message are unaccounted for")
	}
}

func TestTwoContentLengthValuesThatDisagreeAreMalformed(t *testing.T) {
	m := only(t, parseRequests(t,
		"POST /one HTTP/1.1\r\nContent-Length: 6\r\nContent-Length: 7\r\n\r\nabcdef"))

	if m.Defect != http1.DefectMalformed {
		t.Errorf("Defect = %s, want %s", m.Defect, http1.DefectMalformed)
	}
	if m.Framed {
		t.Error("Framed = true; the end of a message with two lengths is not known")
	}
}

func TestTwoContentLengthValuesThatAgreeAreOneLength(t *testing.T) {
	m := only(t, parseRequests(t,
		"POST /one HTTP/1.1\r\nContent-Length: 6\r\nContent-Length: 6\r\n\r\nabcdef"))

	if !m.Complete {
		t.Fatalf("Complete = false (%s: %s)", m.Defect, m.Detail)
	}
	if got, want := string(m.Body), "abcdef"; got != want {
		t.Errorf("Body = %q, want %q", got, want)
	}
}

func TestHeadersThatNoStrictEndpointAcceptsAreMalformed(t *testing.T) {
	cases := map[string]string{
		"a space between the field name and the colon": "POST /one HTTP/1.1\r\nContent-Length : 0\r\n\r\n",
		"a field name that is not a token":             "POST /one HTTP/1.1\r\nContent\tLength: 0\r\n\r\n",
		"a line continued by leading whitespace":       "POST /one HTTP/1.1\r\nHost: acq\r\n uirer\r\nContent-Length: 0\r\n\r\n",
		"a header line with no colon at all":           "POST /one HTTP/1.1\r\nContent-Length\r\n\r\n",
		"a null byte in a field value":                 "POST /one HTTP/1.1\r\nHost: a\x00b\r\nContent-Length: 0\r\n\r\n",
		"an empty line before the start line":          "\r\nPOST /one HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
		"a content length that is not a number":        "POST /one HTTP/1.1\r\nContent-Length: 0x10\r\n\r\n",
		"a signed content length":                      "POST /one HTTP/1.1\r\nContent-Length: +10\r\n\r\n",
		"a start line with an extra space":             "POST  /one HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
		"a start line naming no protocol":              "POST /one\r\nContent-Length: 0\r\n\r\n",
		"a status line whose code is not three digits": "HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n",
	}

	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			kind := http1.Request
			if strings.HasPrefix(text, "HTTP/") {
				kind = http1.Response
			}
			m := only(t, http1.Parse(fragments(t, fragment.Received, text), kind, http1.DefaultLimits()))
			if m.Defect != http1.DefectMalformed {
				t.Fatalf("Defect = %s, want %s", m.Defect, http1.DefectMalformed)
			}
			if m.Complete || m.Framed {
				t.Fatalf("Complete = %v, Framed = %v, want both false", m.Complete, m.Framed)
			}
		})
	}
}

func TestFieldValuesAreTrimmedOfTheirSurroundingWhitespace(t *testing.T) {
	m := only(t, parseRequests(t, "POST /one HTTP/1.1\r\nHost: \t backend \t\r\nContent-Length: 0\r\n\r\n"))

	if got, ok := m.Lookup("host"); !ok || got != "backend" {
		t.Fatalf("Lookup(host) = %q, %v, want %q", got, ok, "backend")
	}
}

func TestRepeatedHeadersAreKeptInTheOrderTheyWereSent(t *testing.T) {
	m := only(t, parseRequests(t,
		"POST /one HTTP/1.1\r\nSet-Cookie: a\r\nSet-Cookie: b\r\nContent-Length: 0\r\n\r\n"))

	var values []string
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, "set-cookie") {
			values = append(values, h.Value)
		}
	}
	if got, want := strings.Join(values, ","), "a,b"; got != want {
		t.Fatalf("Set-Cookie values = %q, want %q", got, want)
	}
}

// A cut-off exchange must never be reported as a plausible complete one.
func TestAStreamThatEndsInsideABodyIsIncompleteRatherThanShort(t *testing.T) {
	m := only(t, parseRequests(t, "POST /one HTTP/1.1\r\nContent-Length: 26\r\n\r\n", `{"ref":"entry-`))

	if m.Complete {
		t.Fatal("a request whose body was cut off reports complete")
	}
	if m.Defect != http1.DefectStreamEnded {
		t.Errorf("Defect = %s, want %s", m.Defect, http1.DefectStreamEnded)
	}
	if m.Framed {
		t.Error("Framed = true; the end of a body that never arrived is not in the stream")
	}
	if got, want := string(m.Body), `{"ref":"entry-`; got != want {
		t.Errorf("Body = %q, want %q; what did arrive is kept", got, want)
	}
}

func TestAStreamThatEndsInsideTheHeadersIsIncomplete(t *testing.T) {
	m := only(t, parseRequests(t, "POST /one HTTP/1.1\r\nContent-Len"))

	if m.Complete || m.Framed {
		t.Fatalf("Complete = %v, Framed = %v, want both false", m.Complete, m.Framed)
	}
	if m.Defect != http1.DefectStreamEnded {
		t.Errorf("Defect = %s, want %s", m.Defect, http1.DefectStreamEnded)
	}
	if got, want := m.Method, "POST"; got != want {
		t.Errorf("Method = %q, want %q; what was read before the end is kept", got, want)
	}
}

// A hole inside a body loses the body's bytes, not the structure: the declared
// length still locates the next message.
func TestAHoleInsideABodyLeavesTheMessageFramedAndTheBodyIncomplete(t *testing.T) {
	parsed := parseRequests(t,
		"POST /one HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc", "hole:4", "hij",
		"POST /two HTTP/1.1\r\nContent-Length: 0\r\n\r\n")

	if got, want := len(parsed.Messages), 2; got != want {
		t.Fatalf("parsed %d messages, want %d: the second is behind the hole", got, want)
	}
	first := parsed.Messages[0]
	if first.Complete {
		t.Error("a body with a hole in it reports complete")
	}
	if first.Defect != http1.DefectHole {
		t.Errorf("Defect = %s, want %s", first.Defect, http1.DefectHole)
	}
	if !first.Framed {
		t.Error("Framed = false; a declared length says where the message ends whatever is missing inside it")
	}
	if got, want := first.BodyHoled, uint64(4); got != want {
		t.Errorf("BodyHoled = %d, want %d", got, want)
	}
	if got, want := string(first.Body), "abchij"; got != want {
		t.Errorf("Body = %q, want %q", got, want)
	}
	if got, want := parsed.Messages[1].Target, "/two"; got != want {
		t.Errorf("second target = %q, want %q", got, want)
	}
}

// A hole in the structure leaves the next boundary unknown, so the parse stops
// and reports what it never placed.
func TestAHoleInsideTheHeadersStopsTheParseAndTheRestIsUnplaced(t *testing.T) {
	parsed := parseRequests(t,
		"POST /one HTTP/1.1\r\nContent-Len", "hole:8", "gth: 0\r\n\r\n",
		"POST /two HTTP/1.1\r\nContent-Length: 0\r\n\r\n")

	m := only(t, parsed)
	if m.Defect != http1.DefectHole {
		t.Errorf("Defect = %s, want %s", m.Defect, http1.DefectHole)
	}
	if m.Framed {
		t.Error("Framed = true across a hole in the headers")
	}
	if parsed.Unplaced == 0 {
		t.Error("Unplaced = 0; everything behind the hole is unaccounted for")
	}
}

func TestAResponseThatCanOnlyBeFramedByTheConnectionClosingIsNotComplete(t *testing.T) {
	m := only(t, parseResponses(t, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody"))

	if m.Framing != http1.FramingUntilClose {
		t.Fatalf("Framing = %s, want %s", m.Framing, http1.FramingUntilClose)
	}
	if m.Complete {
		t.Error("a body framed by a close reports complete; a fragment carries no close")
	}
	if got, want := string(m.Body), "body"; got != want {
		t.Errorf("Body = %q, want %q", got, want)
	}
}

func TestAResponseThatCarriesNoBodyByItsStatusIsCompleteWithoutOne(t *testing.T) {
	for _, status := range []int{204, 304} {
		parsed := parseResponses(t,
			"HTTP/1.1 "+itoa(status)+" No\r\nContent-Length: 12\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

		if got, want := len(parsed.Messages), 2; got != want {
			t.Fatalf("status %d: parsed %d messages, want %d", status, got, want)
		}
		if m := parsed.Messages[0]; !m.Complete || len(m.Body) != 0 || m.Framing != http1.FramingNone {
			t.Errorf("status %d: Complete = %v, body %d bytes, framing %s", status, m.Complete, len(m.Body), m.Framing)
		}
	}
}

// A response to HEAD declares a length and carries no body; framing by that
// length would swallow the next response.
func TestAResponseToHeadCarriesNoBodyAndTheResponseAfterItIsFound(t *testing.T) {
	s := fragments(t, fragment.Sent,
		"HTTP/1.1 200 OK\r\nContent-Length: 34\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")

	parsed := http1.ParseResponses(s, http1.DefaultLimits(), []bool{true, false})
	if got, want := len(parsed.Messages), 2; got != want {
		t.Fatalf("parsed %d messages, want %d", got, want)
	}
	if m := parsed.Messages[0]; !m.Complete || len(m.Body) != 0 {
		t.Errorf("the HEAD response: Complete = %v, body %d bytes (%s: %s)", m.Complete, len(m.Body), m.Defect, m.Detail)
	}
	if got, want := string(parsed.Messages[1].Body), "hi"; got != want {
		t.Errorf("second body = %q, want %q", got, want)
	}
}

func TestARequestWithNoDeclaredFramingHasNoBody(t *testing.T) {
	parsed := parseRequests(t, "GET /one HTTP/1.1\r\nHost: acq\r\n\r\n", "GET /two HTTP/1.1\r\n\r\n")

	if got, want := len(parsed.Messages), 2; got != want {
		t.Fatalf("parsed %d messages, want %d", got, want)
	}
	if m := parsed.Messages[0]; m.Framing != http1.FramingNone || !m.Complete || len(m.Body) != 0 {
		t.Errorf("Framing = %s, Complete = %v, body %d bytes", m.Framing, m.Complete, len(m.Body))
	}
}

func TestChunkedFramingRefusesWhatNoDecoderWouldAccept(t *testing.T) {
	cases := map[string]string{
		"a chunk size that is not hexadecimal": "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nab\r\n0\r\n\r\n",
		"a chunk size with no size at all":     "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\nab\r\n0\r\n\r\n",
		"a chunk not followed by its CRLF":     "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabXX0\r\n\r\n",
		"a coding applied after chunked":       "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n",
		"a chunked request that never ends":    "POST /one HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n",
	}

	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			kind := http1.Request
			if strings.HasPrefix(text, "HTTP/") {
				kind = http1.Response
			}
			m := only(t, http1.Parse(fragments(t, fragment.Received, text), kind, http1.DefaultLimits()))
			if m.Complete || m.Framed {
				t.Fatalf("Complete = %v, Framed = %v, want both false (%s: %s)", m.Complete, m.Framed, m.Defect, m.Detail)
			}
		})
	}
}

// An undecodable transfer coding is not malformed, and its end cannot be
// found either.
func TestATransferEncodingThatIsNotChunkedIsFramedByTheCloseInAResponse(t *testing.T) {
	m := only(t, parseResponses(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nrubbish"))

	if m.Framing != http1.FramingUntilClose {
		t.Fatalf("Framing = %s, want %s", m.Framing, http1.FramingUntilClose)
	}
	if m.Complete {
		t.Error("Complete = true for a body framed by a close")
	}
}

func TestATransferEncodingThatIsNotChunkedIsMalformedInARequest(t *testing.T) {
	m := only(t, parseRequests(t, "POST /one HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\nrubbish"))

	if m.Defect != http1.DefectMalformed {
		t.Fatalf("Defect = %s, want %s", m.Defect, http1.DefectMalformed)
	}
}

func TestABodyLargerThanTheBoundIsSteppedOverAndWhatWasDroppedIsCounted(t *testing.T) {
	limits := http1.DefaultLimits()
	limits.MaxBodyBytes = 8

	s := fragments(t, fragment.Received,
		"POST /one HTTP/1.1\r\nContent-Length: 40\r\n\r\n"+strings.Repeat("x", 40),
		"POST /two HTTP/1.1\r\nContent-Length: 0\r\n\r\n")

	parsed := http1.Parse(s, http1.Request, limits)
	if got, want := len(parsed.Messages), 2; got != want {
		t.Fatalf("parsed %d messages, want %d", got, want)
	}
	first := parsed.Messages[0]
	if got, want := len(first.Body), 8; got != want {
		t.Errorf("kept %d body bytes, want %d", got, want)
	}
	if got, want := first.BodyElided, uint64(32); got != want {
		t.Errorf("BodyElided = %d, want %d", got, want)
	}
	if !first.Complete {
		t.Errorf("Complete = false; every byte was there and the bound is what dropped them (%s: %s)", first.Defect, first.Detail)
	}
}

func TestTheNumberOfMessagesReadFromOneStreamIsBounded(t *testing.T) {
	limits := http1.DefaultLimits()
	limits.MaxMessages = 3

	pieces := make([]string, 10)
	for i := range pieces {
		pieces[i] = "GET /one HTTP/1.1\r\n\r\n"
	}

	parsed := http1.Parse(fragments(t, fragment.Received, pieces...), http1.Request, limits)
	if got, want := len(parsed.Messages), 3; got != want {
		t.Fatalf("parsed %d messages, want the bound %d", got, want)
	}
	if parsed.Unplaced == 0 {
		t.Error("Unplaced = 0; the messages past the bound are unaccounted for")
	}
}

func TestTheNumberAndSizeOfHeadersReadFromOneMessageAreBounded(t *testing.T) {
	limits := http1.DefaultLimits()
	limits.MaxHeaders = 4

	text := "POST /one HTTP/1.1\r\n"
	for i := 0; i < 40; i++ {
		text += "X-Pad: 1\r\n"
	}
	text += "\r\n"

	m := only(t, http1.Parse(fragments(t, fragment.Received, text), http1.Request, limits))
	if m.Defect != http1.DefectLimit {
		t.Fatalf("Defect = %s, want %s", m.Defect, http1.DefectLimit)
	}
	if len(m.Headers) > 4 {
		t.Fatalf("kept %d headers, want at most the bound 4", len(m.Headers))
	}
}

func TestAStartLineLongerThanItsBoundIsRefused(t *testing.T) {
	limits := http1.DefaultLimits()
	limits.MaxStartLine = 32

	m := only(t, http1.Parse(
		fragments(t, fragment.Received, "GET /"+strings.Repeat("a", 200)+" HTTP/1.1\r\n\r\n"),
		http1.Request, limits))

	if m.Defect != http1.DefectLimit {
		t.Fatalf("Defect = %s, want %s", m.Defect, http1.DefectLimit)
	}
}

func TestAnEmptyStreamParsesToNoMessages(t *testing.T) {
	parsed := http1.Parse(stream.Stream{}, http1.Request, http1.DefaultLimits())

	if len(parsed.Messages) != 0 {
		t.Fatalf("parsed %d messages from nothing", len(parsed.Messages))
	}
	if parsed.Unplaced != 0 {
		t.Fatalf("Unplaced = %d, want 0", parsed.Unplaced)
	}
}

func itoa(n int) string {
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
