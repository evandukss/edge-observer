package reconstruct_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/reconstruct"
	"github.com/evandukss/edge-observer/stream"
)

// side renders every field of one message of an exchange a reader could act
// on, with nil and empty rendered alike.
func side(m *reconstruct.Message) string {
	if m == nil {
		return "none"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %q", m.Kind, m.StartLine())
	for _, h := range m.Headers {
		fmt.Fprintf(&b, " [%q: %q]", h.Name, h.Value)
	}
	fmt.Fprintf(&b, " | %s body %q length %d holed %d elided %d |", m.Framing, m.Body, m.BodyLength, m.BodyHoled, m.BodyElided)
	for _, h := range m.Trailers {
		fmt.Fprintf(&b, " [%q: %q]", h.Name, h.Value)
	}
	fmt.Fprintf(&b, " | complete %t framed %t %s %q | %d-%d", m.Complete, m.Framed, m.Defect, m.Detail, m.Offset, m.End)
	if m.Shape != nil {
		fmt.Fprintf(&b, " | shape %s", strings.ReplaceAll(m.Shape.String(), "\n", "; "))
	}
	if m.ShapeRefused != "" {
		fmt.Fprintf(&b, " | no shape: %s", m.ShapeRefused)
	}
	return b.String()
}

func renderExchanges(exchanges []reconstruct.Exchange) string {
	var b strings.Builder
	for i, e := range exchanges {
		fmt.Fprintf(&b, "exchange %d complete %t\n  %s\n  %s\n", i, e.Complete, side(e.Request), side(e.Response))
	}
	return b.String()
}

func divide(part stream.Part, n uint64) (stream.Part, stream.Part) {
	head, tail := part, part
	head.Length, tail.Offset, tail.Length = n, part.Offset+n, part.Length-n
	if part.Gap == stream.GapNone {
		head.Bytes, tail.Bytes = part.Bytes[:n], part.Bytes[n:]
	}
	return head, tail
}

// cutAt splits parts at each offset given.
func cutAt(parts []stream.Part, at ...uint64) []stream.Part {
	var out []stream.Part
	for _, part := range parts {
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

// sizedParts splits parts into parts of at most size offsets.
func sizedParts(parts []stream.Part, size uint64) []stream.Part {
	var out []stream.Part
	for _, part := range parts {
		for part.Length > size {
			head, tail := divide(part, size)
			out = append(out, head)
			part = tail
		}
		out = append(out, part)
	}
	return out
}

// event is one part of one direction, in the order a caller feeds it.
type event struct {
	direction fragment.Direction
	part      stream.Part
}

func of(direction fragment.Direction, parts []stream.Part) []event {
	out := make([]event, len(parts))
	for i, part := range parts {
		out[i] = event{direction, part}
	}
	return out
}

// interleave alternates the two directions' parts, one of each in turn.
func interleave(first, second []event) []event {
	var out []event
	for i := 0; i < max(len(first), len(second)); i++ {
		if i < len(first) {
			out = append(out, first[i])
		}
		if i < len(second) {
			out = append(out, second[i])
		}
	}
	return out
}

// connection is one connection's two directions as text, "hole:N" for a hole
// of N offsets, with the records Run reads and the parts a caller feeds.
type connection struct {
	records  []fragment.Record
	sent     []stream.Part
	received []stream.Part
}

func connectionOf(t *testing.T, sent, received []string) connection {
	t.Helper()
	var c connection
	sequence := uint64(0)
	for _, direction := range []struct {
		which  fragment.Direction
		pieces []string
	}{{fragment.Received, received}, {fragment.Sent, sent}} {
		offset := uint64(0)
		for _, piece := range direction.pieces {
			record := fragment.Record{
				Process:    fragment.Process{PID: 1731, StartTime: 90210},
				Connection: 7,
				Direction:  direction.which,
				Sequence:   sequence,
				Offset:     offset,
				Length:     uint32(len(piece)),
				Payload:    []byte(piece),
				At:         at,
			}
			if hole, ok := strings.CutPrefix(piece, "hole:"); ok {
				var n int
				if _, err := fmt.Sscanf(hole, "%d", &n); err != nil {
					t.Fatalf("hole width %q: %v", hole, err)
				}
				record.Length, record.Payload = uint32(n), nil
			}
			c.records = append(c.records, record)
			offset += uint64(record.Length)
			sequence++
		}
	}
	assembled := stream.Assemble(c.records)
	if len(assembled.Discards) != 0 {
		t.Fatalf("the case's own records were discarded: %v", assembled.Discards)
	}
	for _, s := range assembled.Streams {
		switch s.Key.Direction {
		case fragment.Sent:
			c.sent = s.Parts
		case fragment.Received:
			c.received = s.Parts
		}
	}
	return c
}

// pairingRun is what a caller sees feeding a pairing.
type pairingRun struct {
	// before are the exchanges handed over by Feed, atEnd those End handed over.
	before, atEnd []reconstruct.Exchange
	// result is the last Feed's result, end End's.
	result, end http1.Result
	charges     http1.Charge
	refusals    int
	fed         uint64
}

func (r pairingRun) exchanges() []reconstruct.Exchange {
	return append(append([]reconstruct.Exchange{}, r.before...), r.atEnd...)
}

// feed feeds events through p as a caller would, feeding the rest of a refused
// part again once the reserver grants, and then calls End.
func feed(t *testing.T, p *reconstruct.Pairing, events []event, reserver *pairingRefuser) pairingRun {
	t.Helper()
	var r pairingRun
	for _, e := range events {
		part := e.part
		for steps := 0; part.Length > 0; steps++ {
			if steps > 1<<20 {
				t.Fatalf("Feed %s at %d made no progress in %d calls", e.direction, part.Offset, steps)
			}
			step, err := p.Feed(e.direction, part)
			if err != nil {
				t.Fatalf("Feed %s at %d: %v", e.direction, part.Offset, err)
			}
			if step.Consumed > part.Length {
				t.Fatalf("Feed %s at %d consumed %d of a %d-offset part", e.direction, part.Offset, step.Consumed, part.Length)
			}
			if step.Result == http1.Refused {
				if reserver == nil {
					t.Fatalf("Feed %s at %d was refused by a reserver that grants everything", e.direction, part.Offset)
				}
				reserver.refused(t, p)
				r.refusals++
			} else if step.Consumed != part.Length {
				t.Fatalf("Feed %s at %d returned %s having consumed %d of %d", e.direction, part.Offset, step.Result, step.Consumed, part.Length)
			}
			for _, x := range step.Exchanges {
				r.charges = r.charges.Add(x.Charge)
			}
			r.before = append(r.before, step.Exchanges...)
			r.result = step.Result
			r.fed += step.Consumed
			_, part = divide(part, step.Consumed)
		}
	}
	for steps := 0; ; steps++ {
		end := p.End()
		for _, x := range end.Exchanges {
			r.charges = r.charges.Add(x.Charge)
		}
		r.atEnd = append(r.atEnd, end.Exchanges...)
		r.end = end.Result
		if end.Result != http1.Refused {
			break
		}
		if reserver == nil || steps > 0 {
			t.Fatalf("End was refused (%d times)", steps+1)
		}
		reserver.refused(t, p)
		r.refusals++
	}
	return r
}

// pairingRefuser grants every reservation but the n'th, which it refuses
// once, and records what the pairing kept at that moment. Zero n refuses
// nothing.
type pairingRefuser struct {
	grant
	n        int
	snapshot string
	retained http1.Charge
	asking   *reconstruct.Pairing
	checked  bool
}

func (r *pairingRefuser) Reserve(c http1.Charge) bool {
	if r.asked+1 == r.n {
		r.asked++
		r.snapshot, r.retained = reconstruct.Snapshot(r.asking), r.asking.Retained()
		return false
	}
	return r.grant.Reserve(c)
}

func (r *pairingRefuser) refused(t *testing.T, p *reconstruct.Pairing) {
	t.Helper()
	if r.asked < r.n || r.checked {
		t.Fatalf("Refused with no reservation refused (asked %d, refusing the %d'th)", r.asked, r.n)
	}
	r.checked = true
	if got := reconstruct.Snapshot(p); got != r.snapshot {
		t.Errorf("refusing reservation %d changed what the pairing keeps:\n  when it asked %s\n  after         %s", r.n, r.snapshot, got)
	}
	if got := p.Retained(); got != r.retained {
		t.Errorf("refusing reservation %d changed what the pairing retains: %+v when it asked, %+v after", r.n, r.retained, got)
	}
}

func pairingFor(t *testing.T, reserver *pairingRefuser) *reconstruct.Pairing {
	t.Helper()
	p, err := reconstruct.NewPairing(reconstruct.DefaultLimits(), reserver)
	if err != nil {
		t.Fatalf("NewPairing: %v", err)
	}
	reserver.asking = p
	return p
}

// Requests of every framing, a HEAD among them, and the responses answering
// each, every response naming the request it answers.
var (
	pipelinedRequests = []string{
		"GET /one HTTP/1.1\r\nHost: backend\r\n\r\n" +
			"HEAD /two HTTP/1.1\r\nHost: backend\r\n\r\n" +
			"GET /three HTTP/1.1\r\n\r\n" +
			"POST /four HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"ref\":\"r-4\"}\r\n" +
			"POST /five HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n6;x=y\r\n{\"n\":5\r\n1\r\n}\r\n0\r\nChecksum: abc\r\n\r\n",
	}
	thirdResponse      = "HTTP/1.1 204 Empty!\r\nAnswer: 3\r\n\r\n"
	pipelinedResponses = []string{
		"HTTP/1.1 200 OK\r\nAnswer: 1\r\nContent-Length: 8\r\n\r\n{\"n\":1}\n" +
			// Declares exactly the length of the response after it, which a reader
			// framing a HEAD response by its length would swallow.
			fmt.Sprintf("HTTP/1.1 200 OK\r\nAnswer: 2\r\nContent-Length: %d\r\n\r\n", len(thirdResponse)) +
			thirdResponse +
			"HTTP/1.1 201 Created\r\nAnswer: 4\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"n\"\r\n3\r\n:4}\r\n0\r\nT: 1\r\n\r\n" +
			"HTTP/1.1 200 OK\r\nAnswer: 5\r\nContent-Length: 0\r\n\r\n",
	}
)

// answers checks each exchange pairs the i'th request with the response
// naming it, which is the property a count of exchanges cannot show.
func answers(t *testing.T, exchanges []reconstruct.Exchange, targets ...string) {
	t.Helper()
	if len(exchanges) != len(targets) {
		t.Fatalf("%d exchanges, want %d:\n%s", len(exchanges), len(targets), renderExchanges(exchanges))
	}
	for i, e := range exchanges {
		if e.Request == nil || e.Response == nil {
			t.Errorf("exchange %d: request %v, response %v", i, e.Request != nil, e.Response != nil)
			continue
		}
		answer, _ := e.Response.Lookup("Answer")
		if e.Request.Target != targets[i] || answer != fmt.Sprint(i+1) {
			t.Errorf("exchange %d pairs %s with the response answering request %s", i, e.Request.Target, answer)
		}
		if !e.Complete {
			t.Errorf("exchange %d (%s) is incomplete", i, e.Request.Target)
		}
	}
}

var pipelinedTargets = []string{"/one", "/two", "/three", "/four", "/five"}

// Every part boundary in either direction, and the directions arriving in
// either order or interleaved, give the exchanges Run reads off the whole
// connection.
func TestWhereverAPartEndsAndHoweverTheDirectionsInterleaveTheExchangesAreRuns(t *testing.T) {
	for _, role := range []string{"server", "client"} {
		t.Run(role, func(t *testing.T) {
			sent, received := pipelinedResponses, pipelinedRequests
			requestSide, responseSide := fragment.Received, fragment.Sent
			if role == "client" {
				sent, received = pipelinedRequests, pipelinedResponses
				requestSide, responseSide = fragment.Sent, fragment.Received
			}
			c := connectionOf(t, sent, received)
			whole := reconstruct.Run(c.records, reconstruct.DefaultLimits())
			if len(whole.Connections) != 1 || len(whole.Connections[0].Exchanges) != len(pipelinedTargets) {
				t.Fatalf("wiring, not the property: Run read %d connections from the case's own records, want one of %d exchanges", len(whole.Connections), len(pipelinedTargets))
			}
			want := renderExchanges(whole.Connections[0].Exchanges)
			answers(t, whole.Connections[0].Exchanges, pipelinedTargets...)

			parts := map[fragment.Direction][]stream.Part{fragment.Sent: c.sent, fragment.Received: c.received}
			requests, responses := parts[requestSide], parts[responseSide]
			schedules := map[string][]event{}
			add := func(name string, requests, responses []stream.Part) {
				schedules[name+", requests first"] = append(of(requestSide, requests), of(responseSide, responses)...)
				schedules[name+", responses first"] = append(of(responseSide, responses), of(requestSide, requests)...)
				schedules[name+", interleaved"] = interleave(of(requestSide, requests), of(responseSide, responses))
			}
			add("whole", requests, responses)
			add("a byte a part", sizedParts(requests, 1), sizedParts(responses, 1))
			end := requests[len(requests)-1]
			for offset := uint64(1); offset < end.Offset+end.Length; offset++ {
				add(fmt.Sprintf("requests split at %d", offset), cutAt(requests, offset), sizedParts(responses, 7))
			}
			end = responses[len(responses)-1]
			for offset := uint64(1); offset < end.Offset+end.Length; offset++ {
				add(fmt.Sprintf("responses split at %d", offset), sizedParts(requests, 7), cutAt(responses, offset))
			}

			for name, schedule := range schedules {
				p := pairingFor(t, &pairingRefuser{})
				r := feed(t, p, schedule, nil)
				if got := renderExchanges(r.exchanges()); got != want {
					t.Errorf("%s: handed over\n%s\nwant\n%s", name, got, want)
					continue
				}
				if role, decided := p.Role(); !decided || role != whole.Connections[0].Role {
					t.Errorf("%s: Role = %s, %t; want %s, true", name, role, decided, whole.Connections[0].Role)
				}
				if len(r.atEnd) != 0 {
					t.Errorf("%s: %d exchanges waited for End though both their messages were framed", name, len(r.atEnd))
				}
			}
		})
	}
}

// Several pairs arriving in one part each way pair in order, and a response to
// HEAD among pipelined requests carries no body, so the response its declared
// length would cover is still the next one.
func TestPairsCoalescedIntoOnePartAndHeadAmongPipelinedRequestsPairInOrder(t *testing.T) {
	c := connectionOf(t, pipelinedResponses, pipelinedRequests)
	if len(c.received) != 1 || len(c.sent) != 1 {
		t.Fatalf("wiring, not the property: the case's requests are %d parts and responses %d, want one each", len(c.received), len(c.sent))
	}
	for name, schedule := range map[string][]event{
		"requests first":  append(of(fragment.Received, c.received), of(fragment.Sent, c.sent)...),
		"responses first": append(of(fragment.Sent, c.sent), of(fragment.Received, c.received)...),
	} {
		t.Run(name, func(t *testing.T) {
			r := feed(t, pairingFor(t, &pairingRefuser{}), schedule, nil)
			if len(r.before) == 0 {
				t.Fatalf("wiring, not the property: nothing was handed over, so no pairing was measured")
			}
			answers(t, r.before, pipelinedTargets...)
			if head := r.before[1].Response; head != nil && (len(head.Body) != 0 || head.BodyLength != 0) {
				t.Errorf("the response to HEAD carries %d body bytes, want none", head.BodyLength)
			}
		})
	}
}

// A response arriving before the request it answers is held and then paired
// with that request; a response that is only late is never handed over as
// unpaired while the connection is open.
func TestAResponseBeforeItsRequestIsHeldAndALateOneIsNeverDeclaredUnpaired(t *testing.T) {
	c := connectionOf(t, pipelinedResponses, pipelinedRequests)

	t.Run("responses before their requests", func(t *testing.T) {
		p := pairingFor(t, &pairingRefuser{})
		var handed []reconstruct.Exchange
		for _, part := range sizedParts(c.sent, 9) {
			step, err := p.Feed(fragment.Sent, part)
			if err != nil || step.Consumed != part.Length {
				t.Fatalf("Feed sent at %d: %v, consumed %d of %d", part.Offset, err, step.Consumed, part.Length)
			}
			handed = append(handed, step.Exchanges...)
		}
		last := c.sent[len(c.sent)-1]
		if next, started := p.Next(fragment.Sent); !started || next != last.Offset+last.Length {
			t.Fatalf("wiring, not the property: the responses fed reached %d of %d", next, last.Offset+last.Length)
		}
		if len(handed) != 0 {
			t.Fatalf("%d exchanges handed over before any request:\n%s", len(handed), renderExchanges(handed))
		}
		if held := p.Retained(); held.Bytes == 0 || held.Messages == 0 {
			t.Errorf("responses waiting on their requests retain %+v: held input is reserved like anything else retained", held)
		}
		for _, part := range sizedParts(c.received, 9) {
			step, err := p.Feed(fragment.Received, part)
			if err != nil || step.Consumed != part.Length {
				t.Fatalf("Feed received at %d: %v, consumed %d of %d", part.Offset, err, step.Consumed, part.Length)
			}
			handed = append(handed, step.Exchanges...)
		}
		answers(t, handed, pipelinedTargets...)
		if end := p.End(); len(end.Exchanges) != 0 {
			t.Errorf("End handed over %d more exchanges", len(end.Exchanges))
		}
		if left := p.Retained(); !left.IsZero() {
			t.Errorf("%+v still retained after End", left)
		}
	})

	t.Run("responses arrive late, one at a time", func(t *testing.T) {
		p := pairingFor(t, &pairingRefuser{})
		var handed []reconstruct.Exchange
		feedOne := func(direction fragment.Direction, part stream.Part) {
			t.Helper()
			step, err := p.Feed(direction, part)
			if err != nil || step.Consumed != part.Length {
				t.Fatalf("Feed %s at %d: %v, consumed %d of %d", direction, part.Offset, err, step.Consumed, part.Length)
			}
			for _, x := range step.Exchanges {
				if x.Request == nil || x.Response == nil {
					t.Errorf("an exchange missing its %s was handed over while the connection is open", map[bool]string{true: "request", false: "response"}[x.Request == nil])
				}
			}
			handed = append(handed, step.Exchanges...)
		}
		for _, part := range c.received {
			feedOne(fragment.Received, part)
		}
		if len(handed) != 0 {
			t.Fatalf("%d exchanges handed over before any response", len(handed))
		}
		responses := c.sent[0].Bytes
		var offset uint64
		for i, length := range responseLengths(t, string(responses)) {
			feedOne(fragment.Sent, stream.Part{Offset: offset, Length: uint64(length), Bytes: responses[offset : offset+uint64(length)]})
			offset += uint64(length)
			if len(handed) != i+1 {
				t.Fatalf("after response %d: %d exchanges handed over, want %d", i+1, len(handed), i+1)
			}
		}
		answers(t, handed, pipelinedTargets...)
		if end := p.End(); len(end.Exchanges) != 0 {
			t.Errorf("End handed over %d more exchanges", len(end.Exchanges))
		}
	})
}

// responseLengths is the length of each response in a run of them, read by
// Parse, which knows which is the response to HEAD.
func responseLengths(t *testing.T, text string) []int {
	t.Helper()
	s := connectionOf(t, []string{text}, nil)
	parsed := http1.ParseResponses(stream.Stream{Parts: s.sent, Start: 0, End: uint64(len(text))}, http1.DefaultLimits(), []bool{false, true})
	var out []int
	for _, m := range parsed.Messages {
		out = append(out, int(m.End-m.Offset))
	}
	if len(out) != len(pipelinedTargets) {
		t.Fatalf("wiring, not the property: Parse found %d responses in the case's own text, want %d", len(out), len(pipelinedTargets))
	}
	return out
}

// An exchange leaves once both its messages are framed, in the call that
// framed the second, even when that message ended exactly where its part did
// and the connection then goes quiet: a response with no body is framed by the
// answer alone, and waits for no further input.
func TestTheLastCompletePairLeavesWhileTheConnectionIdles(t *testing.T) {
	cases := map[string]struct{ request, response string }{
		"a declared body":    {"GET /one HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"},
		"a chunked body":     {"GET /one HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n"},
		"no body":            {"GET /one HTTP/1.1\r\n\r\n", "HTTP/1.1 204 No Content\r\n\r\n"},
		"an empty body":      {"GET /one HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"},
		"a response to HEAD": {"HEAD /one HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n"},
		"a request body":     {"POST /one HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi", "HTTP/1.1 204 No Content\r\n\r\n"},
	}
	for name, c := range cases {
		for _, order := range []string{"request first", "response first"} {
			t.Run(name+", "+order, func(t *testing.T) {
				conn := connectionOf(t, []string{c.response}, []string{c.request})
				first, second := event{fragment.Received, conn.received[0]}, event{fragment.Sent, conn.sent[0]}
				if order == "response first" {
					first, second = second, first
				}
				p := pairingFor(t, &pairingRefuser{})
				step, err := p.Feed(first.direction, first.part)
				if err != nil || step.Consumed != first.part.Length {
					t.Fatalf("wiring, not the property: the first part: %v, consumed %d of %d", err, step.Consumed, first.part.Length)
				}
				if len(step.Exchanges) != 0 {
					t.Fatalf("an exchange was handed over with one direction fed")
				}
				step, err = p.Feed(second.direction, second.part)
				if err != nil || step.Consumed != second.part.Length {
					t.Fatalf("wiring, not the property: the second part: %v, consumed %d of %d", err, step.Consumed, second.part.Length)
				}
				if len(step.Exchanges) != 1 || !step.Exchanges[0].Complete {
					t.Fatalf("the call that framed the second message handed over %d exchanges, want the complete pair", len(step.Exchanges))
				}
				if step.Result != http1.NeedInput {
					t.Errorf("Result = %s, want %s: the connection is still open", step.Result, http1.NeedInput)
				}
			})
		}
	}
}

// What the pairing examines grows with the input it is given, whichever
// direction arrives first: held input is read once when it can be, never again.
// The only bytes looked at twice are the few each direction begins with, read
// to decide which side the process was on.
func TestNewInputCostsThePairingWorkInProportionToItself(t *testing.T) {
	c := connectionOf(t, pipelinedResponses, pipelinedRequests)
	total := c.sent[0].Length + c.received[0].Length
	for name, schedule := range map[string][]event{
		"a byte a part, responses first": append(of(fragment.Sent, sizedParts(c.sent, 1)), of(fragment.Received, sizedParts(c.received, 1))...),
		"a byte a part, interleaved":     interleave(of(fragment.Received, sizedParts(c.received, 1)), of(fragment.Sent, sizedParts(c.sent, 1))),
		"a byte a part, requests first":  append(of(fragment.Received, sizedParts(c.received, 1)), of(fragment.Sent, sizedParts(c.sent, 1))...),
	} {
		t.Run(name, func(t *testing.T) {
			p := pairingFor(t, &pairingRefuser{})
			r := feed(t, p, schedule, nil)
			if len(r.exchanges()) != len(pipelinedTargets) || r.fed != total {
				t.Fatalf("wiring, not the property: %d exchanges from %d of %d offsets, so the work counted below read nothing", len(r.exchanges()), r.fed, total)
			}
			examined := reconstruct.Examined(p)
			if examined < total || examined > total+2*32 {
				t.Errorf("examined %d bytes reading %d: each byte once, and at most 32 more per direction to decide the side", examined, total)
			}
		})
	}
}

// A refused reservation leaves the pairing exactly as it was when it asked;
// feeding the rest again once the reserver grants hands over what was never
// refused. Every reservation the connection makes is refused in turn.
func TestARefusedReservationLeavesThePairingAsItWas(t *testing.T) {
	c := connectionOf(t, pipelinedResponses, pipelinedRequests)
	for name, schedule := range map[string][]event{
		"interleaved":     interleave(of(fragment.Received, sizedParts(c.received, 11)), of(fragment.Sent, sizedParts(c.sent, 11))),
		"responses first": append(of(fragment.Sent, sizedParts(c.sent, 11)), of(fragment.Received, sizedParts(c.received, 11))...),
	} {
		t.Run(name, func(t *testing.T) {
			counting := &pairingRefuser{}
			never := feed(t, pairingFor(t, counting), schedule, nil)
			asks := counting.asked
			if asks == 0 || len(never.exchanges()) == 0 {
				t.Fatalf("wiring, not the property: the connection asked %d reservations and handed over %d exchanges, so no refusal can be exercised", asks, len(never.exchanges()))
			}
			want := renderExchanges(never.exchanges())
			if counting.reserved.Add(negate(counting.released)) != never.charges {
				t.Errorf("granted %+v less released %+v is not the %+v handed over, with nothing retained after End", counting.reserved, counting.released, never.charges)
			}
			for n := 1; n <= asks; n++ {
				reserver := &pairingRefuser{n: n}
				p := pairingFor(t, reserver)
				r := feed(t, p, schedule, reserver)
				if r.refusals != 1 {
					t.Errorf("refusing reservation %d: %d refusals reached the caller, want 1", n, r.refusals)
					continue
				}
				if got := renderExchanges(r.exchanges()); got != want {
					t.Errorf("refusing reservation %d, then granting: handed over\n%s\nwant\n%s", n, got, want)
				}
				if left := p.Retained(); !left.IsZero() {
					t.Errorf("refusing reservation %d: %+v still retained after End", n, left)
				}
				if reserver.reserved.Add(negate(reserver.released)) != r.charges {
					t.Errorf("refusing reservation %d: granted %+v less released %+v is not the %+v handed over", n, reserver.reserved, reserver.released, r.charges)
				}
			}
		})
	}
}

func negate(c http1.Charge) http1.Charge { return http1.Charge{Bytes: -c.Bytes, Messages: -c.Messages} }
