package http1_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/stream"
)

// render is every field of a message a reader could act on, with nil and empty
// rendered alike, so two readings compare as text.
func render(m http1.Message) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %q %q %q %d %q", m.Kind, m.Method, m.Target, m.Protocol, m.Status, m.Reason)
	for _, h := range m.Headers {
		fmt.Fprintf(&b, " [%q: %q]", h.Name, h.Value)
	}
	fmt.Fprintf(&b, " | %s body %q length %d holed %d elided %d |", m.Framing, m.Body, m.BodyLength, m.BodyHoled, m.BodyElided)
	for _, h := range m.Trailers {
		fmt.Fprintf(&b, " [%q: %q]", h.Name, h.Value)
	}
	fmt.Fprintf(&b, " | complete %t framed %t %s %q | %d-%d", m.Complete, m.Framed, m.Defect, m.Detail, m.Offset, m.End)
	return b.String()
}

func renderAll(messages []http1.Message) string {
	lines := make([]string, len(messages))
	for i, m := range messages {
		lines[i] = render(m)
	}
	return strings.Join(lines, "\n")
}

// cut splits a stream's parts at each of the offsets given, bytes and holes
// alike, so a case can put a part boundary anywhere.
func cut(s stream.Stream, at ...uint64) []stream.Part {
	var out []stream.Part
	for _, part := range s.Parts {
		for _, offset := range at {
			if offset <= part.Offset || offset >= part.Offset+part.Length {
				continue
			}
			head, tail := divide(part, offset-part.Offset)
			out = append(out, head)
			part = tail
		}
		out = append(out, part)
	}
	return out
}

// sized splits a stream's parts into parts of at most size offsets.
func sized(s stream.Stream, size uint64) []stream.Part {
	var out []stream.Part
	for _, part := range s.Parts {
		for part.Length > size {
			head, tail := divide(part, size)
			out = append(out, head)
			part = tail
		}
		out = append(out, part)
	}
	return out
}

func divide(part stream.Part, n uint64) (stream.Part, stream.Part) {
	head, tail := part, part
	head.Length, tail.Offset, tail.Length = n, part.Offset+n, part.Length-n
	if part.Gap == stream.GapNone {
		head.Bytes, tail.Bytes = part.Bytes[:n], part.Bytes[n:]
	}
	return head, tail
}

func rest(part stream.Part, consumed uint64) stream.Part {
	_, tail := divide(part, consumed)
	return tail
}

// reading is what a caller sees reading one direction through a Parser.
type reading struct {
	messages []http1.Message
	// stop is the result that stopped the direction, NeedInput where none did.
	stop http1.Result
	// charges is what was handed over with the messages.
	charges http1.Charge
	// refusals is how many reservations were refused and fed again.
	refusals int
}

// read feeds parts through p as a caller would: the rest of a part is fed
// again until it is used up, the i'th response head is answered with
// methods[i] (empty past the end), and a refusal is fed again once the
// reserver has been told to grant. Then End.
func read(t *testing.T, p *http1.Parser, parts []stream.Part, methods []string, reserver *refuser) reading {
	t.Helper()
	var r reading
	responses := 0
	take := func(progress http1.Progress) {
		switch {
		case progress.Result == http1.Framed:
			r.messages = append(r.messages, *progress.Message)
			r.charges = r.charges.Add(progress.Charge)
		case progress.Result.Stopped() && progress.Message != nil:
			r.messages = append(r.messages, *progress.Message)
			r.charges = r.charges.Add(progress.Charge)
			r.stop = progress.Result
		}
	}
	for _, part := range parts {
		for steps := 0; part.Length > 0; steps++ {
			if steps > 1<<20 {
				t.Fatalf("Feed at %d made no progress in %d calls", part.Offset, steps)
			}
			progress, err := p.Feed(part)
			if err != nil {
				t.Fatalf("Feed at %d: %v", part.Offset, err)
			}
			if progress.Consumed > part.Length {
				t.Fatalf("Feed at %d consumed %d of a %d-offset part", part.Offset, progress.Consumed, part.Length)
			}
			switch progress.Result {
			case http1.Refused:
				if reserver == nil {
					t.Fatalf("Feed at %d was refused by a reserver that grants everything", part.Offset)
				}
				reserver.refused(t, p)
				r.refusals++
			case http1.NeedRequest:
				t.Fatalf("Feed at %d: a response waits on an answer it was given", part.Offset)
			case http1.Head:
				if progress.Message == nil {
					t.Fatalf("Head at %d with no message", part.Offset)
				}
				if progress.Message.Kind == http1.Response {
					method := ""
					if responses < len(methods) {
						method = methods[responses]
					}
					responses++
					answered, err := p.Answer(method)
					if err != nil {
						t.Fatalf("Answer(%q) at %d: %v", method, part.Offset, err)
					}
					take(answered)
				}
			default:
				take(progress)
			}
			part = rest(part, progress.Consumed)
		}
	}
	end := p.End()
	if end.Message != nil {
		r.messages = append(r.messages, *end.Message)
		r.charges = r.charges.Add(end.Charge)
	}
	return r
}

// refuser grants every reservation but the n'th, which it refuses once, and
// records what the parser kept at that moment. Zero n refuses nothing.
type refuser struct {
	grant
	n int
	// snapshot and retained are the parser's state when it asked the refused
	// reservation.
	snapshot string
	retained http1.Charge
	asking   *http1.Parser
	checked  bool
}

func (r *refuser) Reserve(c http1.Charge) bool {
	if r.asked+1 == r.n {
		r.asked++
		r.snapshot, r.retained = http1.Snapshot(r.asking), r.asking.Retained()
		return false
	}
	return r.grant.Reserve(c)
}

// refused checks that a refusal left the parser as it was when it asked.
func (r *refuser) refused(t *testing.T, p *http1.Parser) {
	t.Helper()
	if r.asked < r.n || r.checked {
		t.Fatalf("Refused with no reservation refused (asked %d, refusing the %d'th)", r.asked, r.n)
	}
	r.checked = true
	if got := http1.Snapshot(p); got != r.snapshot {
		t.Errorf("refusing reservation %d changed what the parser keeps:\n  when it asked %s\n  after         %s", r.n, r.snapshot, got)
	}
	if got := p.Retained(); got != r.retained {
		t.Errorf("refusing reservation %d changed what the parser retains: %+v when it asked, %+v after", r.n, r.retained, got)
	}
}

func parserFor(t *testing.T, kind http1.Kind, limits http1.Limits, reserver *refuser) *http1.Parser {
	t.Helper()
	p, err := http1.NewParser(kind, limits, reserver)
	if err != nil {
		t.Fatalf("NewParser(%s): %v", kind, err)
	}
	reserver.asking = p
	return p
}

// A case is one direction's stream, how Parse reads it, and the methods its
// responses answer.
type parserCase struct {
	kind    http1.Kind
	pieces  []string
	methods []string
	limits  http1.Limits
}

func (c parserCase) stream(t *testing.T) stream.Stream {
	t.Helper()
	direction := fragment.Received
	if c.kind == http1.Response {
		direction = fragment.Sent
	}
	return fragments(t, direction, c.pieces...)
}

// parsed is how Parse reads the case's stream whole.
func (c parserCase) parsed(t *testing.T) http1.Parsed {
	t.Helper()
	s := c.stream(t)
	if c.kind == http1.Request {
		return http1.Parse(s, http1.Request, c.limits)
	}
	bodiless := make([]bool, len(c.methods))
	for i, method := range c.methods {
		bodiless[i] = strings.EqualFold(method, "HEAD")
	}
	return http1.ParseResponses(s, c.limits, bodiless)
}

const chunkedRequest = "POST /three HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" +
	"4;name=value\r\nWiki\r\n5\r\npedia\r\n0\r\nTrailer-One: x\r\nTrailer-Two: y\r\n\r\n"

// Streams Parse reads to their end, a defect, a hole or a bound, each a
// syntax boundary or a stop a part boundary can fall beside.
func framedCases() map[string]parserCase {
	small := http1.Limits{MaxStartLine: 32, MaxHeaderLine: 28, MaxHeaders: 2, MaxHeaderBytes: 40, MaxBodyBytes: 4, MaxChunks: 3, MaxTrailers: 1}
	return map[string]parserCase{
		"pipelined requests of every framing": {kind: http1.Request, pieces: []string{
			postRequest + "GET /two HTTP/1.1\r\nHost: a\r\n\r\n" + chunkedRequest + "GET /four HTTP/1.1\r\nContent-Length: 0\r\n\r\n"}},
		"responses to GET, HEAD and conditional requests": {kind: http1.Response, methods: []string{"GET", "HEAD", "GET", "POST", "GET"}, pieces: []string{
			"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" +
				"HTTP/1.1 200 OK\r\nContent-Length: 34\r\n\r\n" +
				"HTTP/1.1 204 No Content\r\n\r\n" +
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nT: v\r\n\r\n" +
				"HTTP/1.1 304 Not Modified\r\nContent-Length: 12\r\n\r\n"}},
		"a field line no strict endpoint accepts": {kind: http1.Request, pieces: []string{
			"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\nBad Header\r\n\r\nGET /c HTTP/1.1\r\n\r\n"}},
		"a bare line feed":             {kind: http1.Request, pieces: []string{"GET /a HTTP/1.1\nHost: x\r\n\r\n"}},
		"a carriage return in a value": {kind: http1.Request, pieces: []string{"GET /a HTTP/1.1\r\nX-A: b\rc\r\n\r\n"}},
		"two framings at once": {kind: http1.Request, pieces: []string{
			"POST /a HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc"}},
		"a chunk not followed by CRLF": {kind: http1.Response, methods: []string{"GET"}, pieces: []string{
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabXX0\r\n\r\n"}},
		"the stream ends inside a chunk": {kind: http1.Request, pieces: []string{
			"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n5\r\nab"}},
		"the stream ends between a chunk and its CRLF": {kind: http1.Request, pieces: []string{
			"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r"}},
		"the stream ends inside a declared body": {kind: http1.Request, pieces: []string{
			"POST /a HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc"}},
		"the stream ends inside the fields": {kind: http1.Request, pieces: []string{
			"GET /a HTTP/1.1\r\nHost: a\r\nAcc"}},
		"the stream ends on a carriage return": {kind: http1.Request, pieces: []string{
			"GET /a HTTP/1.1\r\nHost: a\r"}},
		"a hole inside a declared body, and the message after it": {kind: http1.Request, pieces: []string{
			"POST /a HTTP/1.1\r\nContent-Length: 10\r\n\r\nab", "hole:5", "cde", "GET /b HTTP/1.1\r\n\r\n"}},
		"a hole inside the fields": {kind: http1.Request, pieces: []string{
			"GET /a HTTP/1.1\r\nHo", "hole:4", "st: a\r\n\r\nGET /b HTTP/1.1\r\n\r\n"}},
		"a hole inside chunk data": {kind: http1.Response, methods: []string{"GET", "GET"}, pieces: []string{
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nab", "hole:2", "cd\r\n0\r\n\r\nHTTP/1.1 204 No\r\n\r\n"}},
		"a hole inside a chunk size": {kind: http1.Response, methods: []string{"GET"}, pieces: []string{
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1", "hole:1", "\r\nab\r\n0\r\n\r\n"}},
		"a hole where a chunk's CRLF belongs": {kind: http1.Response, methods: []string{"GET"}, pieces: []string{
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r", "hole:1", "0\r\n\r\n"}},
		"a hole before the first byte": {kind: http1.Request, pieces: []string{"hole:3", "GET /a HTTP/1.1\r\n\r\n"}},
		"bounds reached on every line and the body": {kind: http1.Request, limits: small, pieces: []string{
			"POST /a HTTP/1.1\r\nContent-Length: 9\r\n\r\nabcdefghi" + "GET /b HTTP/1.1\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n"}},
		"a start line past its bound": {kind: http1.Request, limits: small, pieces: []string{
			"GET /a-target-longer-than-the-bound HTTP/1.1\r\n\r\n"}},
		"field bytes past their bound": {kind: http1.Request, limits: small, pieces: []string{
			"GET /a HTTP/1.1\r\nA: 12345678901234567\r\nB: 12345678901234567890\r\n\r\n"}},
		"more chunks than the bound": {kind: http1.Response, limits: small, methods: []string{"GET"}, pieces: []string{
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n1\r\nb\r\n1\r\nc\r\n0\r\n\r\n"}},
		"more trailers than the bound": {kind: http1.Response, limits: small, methods: []string{"GET"}, pieces: []string{
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nA: 1\r\nB: 2\r\n\r\n"}},
		"a chunked body larger than the bound": {kind: http1.Response, limits: small, methods: []string{"GET", "GET"}, pieces: []string{
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\nHTTP/1.1 204 No\r\n\r\n"}},
		"a response with no request known": {kind: http1.Response, pieces: []string{
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"}},
	}
}

func checkSplits(t *testing.T, c parserCase, want string, splits map[string][]stream.Part) {
	t.Helper()
	for name, parts := range splits {
		r := read(t, parserFor(t, c.kind, c.limits, &refuser{}), parts, c.methods, nil)
		if got := renderAll(r.messages); got != want {
			t.Errorf("%s: read\n%s\nwant\n%s", name, got, want)
		}
	}
}

// Every part boundary, wherever it falls - inside a start line, a field line,
// a chunk size, chunk data, a trailer or a body, or between messages - gives
// the messages the stream gives whole, and those are the messages Parse reads.
func TestWhereverAPartEndsTheMessagesAreThoseOfTheWholeStream(t *testing.T) {
	for name, c := range framedCases() {
		t.Run(name, func(t *testing.T) {
			s := c.stream(t)
			whole := c.parsed(t)
			if len(whole.Messages) == 0 {
				t.Fatalf("wiring, not the property: Parse read no message from the case's own stream, so nothing below compares anything")
			}
			want := renderAll(whole.Messages)

			splits := map[string][]stream.Part{
				"as assembled":        s.Parts,
				"one offset a part":   sized(s, 1),
				"three offsets apart": sized(s, 3),
			}
			for offset := s.Start + 1; offset < s.End; offset++ {
				splits[fmt.Sprintf("split at %d", offset)] = cut(s, offset)
			}
			checkSplits(t, c, want, splits)
		})
	}
}

// A body only the connection closing would end is where a reader of an open
// connection stops: Answer hands the response over unframed, with its head and
// none of its body, and nothing after it is read. Parse, which has the whole
// stream, still reads the rest as that body.
func TestABodyOnlyACloseWouldEndStopsTheDirectionAtItsHead(t *testing.T) {
	head := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
	s := fragments(t, fragment.Sent, "HTTP/1.1 204 No\r\n\r\n"+head+"body bytes, then HTTP/1.1 200 OK\r\n\r\n")

	whole := http1.ParseResponses(s, http1.DefaultLimits(), nil)
	if len(whole.Messages) != 2 || whole.Messages[1].Framing != http1.FramingUntilClose {
		t.Fatalf("wiring, not the property: Parse read %d messages, want a 204 and then one framed by the close", len(whole.Messages))
	}

	for name, parts := range map[string][]stream.Part{"whole": s.Parts, "one offset a part": sized(s, 1)} {
		t.Run(name, func(t *testing.T) {
			p := parserFor(t, http1.Response, http1.Limits{}, &refuser{})
			r := read(t, p, parts, []string{"GET", "GET"}, nil)
			if len(r.messages) == 0 {
				t.Fatalf("wiring, not the property: no message was handed over, so the stop below measured nothing")
			}
			if got, want := len(r.messages), 2; got != want {
				t.Fatalf("handed over %d messages, want the 204 and the response framed by the close:\n%s", got, renderAll(r.messages))
			}
			if r.stop != http1.Unsupported {
				t.Errorf("the direction stopped with %s, want %s", r.stop, http1.Unsupported)
			}
			m := r.messages[1]
			if m.Framed || m.Complete || m.Framing != http1.FramingUntilClose || len(m.Body) != 0 || m.BodyLength != 0 {
				t.Errorf("the response framed by the close: framed %t complete %t framing %s, body %d of %d bytes; want unframed with no body read",
					m.Framed, m.Complete, m.Framing, len(m.Body), m.BodyLength)
			}
			if got, want := m.End, uint64(len("HTTP/1.1 204 No\r\n\r\n")+len(head)); got != want {
				t.Errorf("End = %d, want %d, where its fields end", got, want)
			}
			if got, want := p.Unplaced(), s.End-m.End; got != want {
				t.Errorf("Unplaced = %d, want %d: every offset after the head", got, want)
			}
		})
	}
}

// What the parser examines grows with the input it is given, never with what
// it already holds: each byte is looked at once however finely the message
// arrives.
func TestEachByteIsExaminedOnceHoweverFinelyAMessageArrives(t *testing.T) {
	longValue := strings.Repeat("v", 8000)
	body := strings.Repeat("0123456789", 10000)
	var chunks strings.Builder
	for i := 0; i < 2000; i++ {
		chunks.WriteString("5\r\nchunk\r\n")
	}

	cases := map[string]struct {
		kind  http1.Kind
		text  string
		size  uint64
		count int
	}{
		"a long field line, a byte at a time": {http1.Request, "GET /a HTTP/1.1\r\nX-Long: " + longValue + "\r\n\r\n", 1, 1},
		"a long start line, a byte at a time": {http1.Request, "GET /" + strings.Repeat("t", 8000) + " HTTP/1.1\r\n\r\n", 1, 1},
		"a long declared body, seven at a time": {http1.Request,
			"POST /a HTTP/1.1\r\nContent-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body, 7, 1},
		"two thousand chunks, three at a time": {http1.Response,
			"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks.String() + "0\r\n\r\n", 3, 1},
	}
	limits := http1.Limits{MaxStartLine: 16 << 10, MaxHeaderLine: 16 << 10, MaxBodyBytes: 1 << 20}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := fragments(t, fragment.Received, c.text)
			parts := sized(s, c.size)
			p := parserFor(t, c.kind, limits, &refuser{})

			var total, fed uint64
			var messages []http1.Message
			for _, part := range parts {
				for part.Length > 0 {
					before := http1.Examined(p)
					progress, err := p.Feed(part)
					if err != nil {
						t.Fatalf("Feed at %d: %v", part.Offset, err)
					}
					if spent := http1.Examined(p) - before; spent > part.Length {
						t.Fatalf("Feed at %d examined %d bytes of a %d-byte part: it went back over what it already held", part.Offset, spent, part.Length)
					}
					fed += progress.Consumed
					switch progress.Result {
					case http1.Head:
						if c.kind == http1.Response {
							answered, err := p.Answer("GET")
							if err != nil {
								t.Fatalf("Answer: %v", err)
							}
							if answered.Message != nil {
								messages = append(messages, *answered.Message)
							}
						}
					case http1.Framed:
						messages = append(messages, *progress.Message)
					case http1.NeedInput:
					default:
						t.Fatalf("Feed at %d returned %s", part.Offset, progress.Result)
					}
					part = rest(part, progress.Consumed)
				}
			}
			total = http1.Examined(p)

			if len(messages) != c.count || !messages[0].Complete {
				t.Fatalf("wiring, not the property: %d messages framed, want %d complete, so the work counted below read nothing", len(messages), c.count)
			}
			if fed != s.End-s.Start {
				t.Fatalf("wiring, not the property: %d of %d offsets consumed", fed, s.End-s.Start)
			}
			if total != fed {
				t.Errorf("examined %d bytes reading %d: each byte once is %d", total, fed, fed)
			}
		})
	}
}

// A refused reservation leaves the parser exactly as it was when it asked,
// retaining none of what it asked for; feeding the rest again once the
// reserver grants reads what was never refused. Every reservation a stream
// makes is refused in turn.
func TestARefusedReservationLeavesTheParserAsItWas(t *testing.T) {
	for name, c := range framedCases() {
		t.Run(name, func(t *testing.T) {
			s := c.stream(t)
			parts := sized(s, 5)

			counting := &refuser{}
			never := read(t, parserFor(t, c.kind, c.limits, counting), parts, c.methods, nil)
			asks := counting.asked
			if asks == 0 || len(never.messages) == 0 {
				t.Fatalf("wiring, not the property: reading the stream asked %d reservations and handed over %d messages, so no refusal can be exercised", asks, len(never.messages))
			}
			want := renderAll(never.messages)
			if counting.reserved.Add(negate(counting.released)) != never.charges {
				t.Errorf("granted %+v less released %+v is not the %+v handed over, with nothing retained after End",
					counting.reserved, counting.released, never.charges)
			}

			for n := 1; n <= asks; n++ {
				reserver := &refuser{n: n}
				p := parserFor(t, c.kind, c.limits, reserver)
				r := read(t, p, parts, c.methods, reserver)
				if r.refusals != 1 {
					t.Errorf("refusing reservation %d: %d refusals reached the caller, want 1", n, r.refusals)
					continue
				}
				if got := renderAll(r.messages); got != want {
					t.Errorf("refusing reservation %d, then granting: read\n%s\nwant\n%s", n, got, want)
				}
				if left := p.Retained(); !left.IsZero() {
					t.Errorf("refusing reservation %d: %+v still retained after End", n, left)
				}
				if reserver.reserved.Add(negate(reserver.released)) != r.charges {
					t.Errorf("refusing reservation %d: granted %+v less released %+v is not the %+v handed over",
						n, reserver.reserved, reserver.released, r.charges)
				}
			}
		})
	}
}

func negate(c http1.Charge) http1.Charge { return http1.Charge{Bytes: -c.Bytes, Messages: -c.Messages} }
