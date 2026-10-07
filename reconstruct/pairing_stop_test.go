package reconstruct_test

import (
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/reconstruct"
	"github.com/evandukss/edge-observer/stream"
)

// schedules feeds a connection whole, a byte a part, and with either
// direction first, so a stop is shown not to depend on how input arrived.
func schedules(c connection) map[string][]event {
	return map[string][]event{
		"whole, requests first":          append(of(fragment.Received, c.received), of(fragment.Sent, c.sent)...),
		"whole, responses first":         append(of(fragment.Sent, c.sent), of(fragment.Received, c.received)...),
		"a byte a part, interleaved":     interleave(of(fragment.Received, sizedParts(c.received, 1)), of(fragment.Sent, sizedParts(c.sent, 1))),
		"a byte a part, responses first": append(of(fragment.Sent, sizedParts(c.sent, 1)), of(fragment.Received, sizedParts(c.received, 1))...),
	}
}

// answerThree is how the response naming the third request renders, which a
// response read past the stop would carry.
const answerThree = `"Answer": "3"`

// settled checks that every charge the pairing reserved left it exactly once,
// handed over with an exchange or released, and that nothing is retained.
func settled(t *testing.T, g *pairingRefuser, p *reconstruct.Pairing, r pairingRun) {
	t.Helper()
	if left := p.Retained(); !left.IsZero() {
		t.Errorf("%+v still retained after End", left)
	}
	if g.reserved.Add(negate(g.released)) != r.charges {
		t.Errorf("granted %+v less released %+v is not the %+v handed over", g.reserved, g.released, r.charges)
	}
}

// mentions reports whether any message handed over carries text, which no
// message read past a stop could avoid.
func mentions(exchanges []reconstruct.Exchange, text string) bool {
	return strings.Contains(renderExchanges(exchanges), text)
}

// An informational response, a CONNECT request and a message carrying Upgrade
// end what can be paired: the exchanges before them are handed over, the one
// they are in is handed over last with Unsupported, and nothing after it is
// read, so no later response is shifted onto a later request.
func TestAnInformationalResponseConnectAndUpgradeAreWherePairingStops(t *testing.T) {
	before := "GET /before HTTP/1.1\r\n\r\n"
	answered := "HTTP/1.1 200 OK\r\nAnswer: 1\r\nContent-Length: 0\r\n\r\n"
	cases := map[string]struct {
		requests, responses string
		target, after       string
	}{
		"an informational response": {
			requests:  before + "POST /up HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello" + "GET /after HTTP/1.1\r\n\r\n",
			responses: answered + "HTTP/1.1 100 Continue\r\n\r\n" + "HTTP/1.1 200 OK\r\nAnswer: 2\r\nContent-Length: 0\r\n\r\n" + "HTTP/1.1 200 OK\r\nAnswer: 3\r\nContent-Length: 0\r\n\r\n",
			target:    "/up", after: "/after",
		},
		"a CONNECT request": {
			requests:  before + "CONNECT backend:443 HTTP/1.1\r\nHost: backend:443\r\n\r\n" + "GET /tunnelled HTTP/1.1\r\n\r\n",
			responses: answered + "HTTP/1.1 200 Connection Established\r\n\r\n" + "HTTP/1.1 200 OK\r\nAnswer: 3\r\nContent-Length: 0\r\n\r\n",
			target:    "backend:443", after: "/tunnelled",
		},
		"a switch to another protocol": {
			requests:  before + "GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" + "GET /after HTTP/1.1\r\n\r\n",
			responses: answered + "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" + "HTTP/1.1 200 OK\r\nAnswer: 3\r\nContent-Length: 0\r\n\r\n",
			target:    "/chat", after: "/after",
		},
		"an upgrade asked for and declined": {
			requests:  before + "GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" + "GET /after HTTP/1.1\r\n\r\n",
			responses: answered + "HTTP/1.1 200 OK\r\nAnswer: 2\r\nContent-Length: 0\r\n\r\n" + "HTTP/1.1 200 OK\r\nAnswer: 3\r\nContent-Length: 0\r\n\r\n",
			target:    "/chat", after: "/after",
		},
	}
	for name, c := range cases {
		conn := connectionOf(t, []string{c.responses}, []string{c.requests})
		for order, schedule := range schedules(conn) {
			t.Run(name+", "+order, func(t *testing.T) {
				g := &pairingRefuser{}
				p := pairingFor(t, g)
				r := feed(t, p, schedule, nil)
				settled(t, g, p, r)
				exchanges := r.exchanges()
				if len(exchanges) == 0 || exchanges[0].Request == nil || exchanges[0].Request.Target != "/before" {
					t.Fatalf("wiring, not the property: the exchange before the stop was not handed over, so nothing below measured a stop:\n%s", renderExchanges(exchanges))
				}
				answers(t, exchanges[:1], "/before")
				if len(exchanges) != 2 {
					t.Fatalf("%d exchanges, want the one before the stop and the one it is in:\n%s", len(exchanges), renderExchanges(exchanges))
				}
				if got := exchanges[1].Request; got == nil || got.Target != c.target {
					t.Errorf("the last exchange's request is %s, want %s", side(got), c.target)
				}
				if mentions(exchanges, c.after) || mentions(exchanges, answerThree) {
					t.Errorf("a message after the stop was handed over:\n%s", renderExchanges(exchanges))
				}
				if r.result != http1.Unsupported {
					t.Errorf("the last Feed returned %s, want %s", r.result, http1.Unsupported)
				}
				if len(r.atEnd) != 0 {
					t.Errorf("End handed over %d exchanges after the stop", len(r.atEnd))
				}
				if p.Unplaced(fragment.Received) == 0 || p.Unplaced(fragment.Sent) == 0 {
					t.Errorf("Unplaced = %d received, %d sent; what follows the stop in each direction was never read", p.Unplaced(fragment.Received), p.Unplaced(fragment.Sent))
				}
			})
		}
	}
}

// A body only the connection closing would end is never framed, so its
// exchange is never complete, not at End either; it is the last exchange.
func TestABodyOnlyACloseWouldEndIsNeverCertified(t *testing.T) {
	requests := "GET /one HTTP/1.1\r\n\r\nGET /two HTTP/1.1\r\n\r\nGET /three HTTP/1.1\r\n\r\n"
	responses := "HTTP/1.1 200 OK\r\nAnswer: 1\r\nContent-Length: 2\r\n\r\nhi" +
		"HTTP/1.1 200 OK\r\nAnswer: 2\r\n\r\nstreamed until the close HTTP/1.1 200 OK\r\nAnswer: 3\r\nContent-Length: 0\r\n\r\n"
	conn := connectionOf(t, []string{responses}, []string{requests})
	for order, schedule := range schedules(conn) {
		t.Run(order, func(t *testing.T) {
			g := &pairingRefuser{}
			p := pairingFor(t, g)
			r := feed(t, p, schedule, nil)
			settled(t, g, p, r)
			exchanges := r.exchanges()
			if len(exchanges) == 0 {
				t.Fatalf("wiring, not the property: nothing was handed over")
			}
			answers(t, exchanges[:1], "/one")
			if len(exchanges) != 2 {
				t.Fatalf("%d exchanges, want two, the second the last:\n%s", len(exchanges), renderExchanges(exchanges))
			}
			last := exchanges[1]
			if last.Complete || last.Response == nil || last.Response.Framed || last.Response.Complete || last.Response.Framing != http1.FramingUntilClose {
				t.Errorf("the exchange whose body only a close would end:\n%s", renderExchanges(exchanges[1:]))
			}
			if mentions(exchanges, "/three") || mentions(exchanges, answerThree) {
				t.Errorf("a message after the response framed by the close was handed over")
			}
			if r.result != http1.Unsupported {
				t.Errorf("the last Feed returned %s, want %s", r.result, http1.Unsupported)
			}
		})
	}
}

// A hole where a request should begin ends what can be paired there: the
// request it took is handed over as the hole left it, and no plausible start
// line after the hole is read as a request.
func TestNothingIsReadForwardOfAHoleForAPlausibleStartLine(t *testing.T) {
	conn := connectionOf(t,
		[]string{"HTTP/1.1 200 OK\r\nAnswer: 1\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nAnswer: 2\r\nContent-Length: 0\r\n\r\n"},
		[]string{"GET /one HTTP/1.1\r\n\r\n", "hole:9", "GET /plausible HTTP/1.1\r\n\r\n"})
	whole := reconstruct.Run(conn.records, reconstruct.DefaultLimits())
	if len(whole.Connections) != 1 || len(whole.Connections[0].Exchanges) != 2 {
		t.Fatalf("wiring, not the property: Run read %d connections from the case's own records", len(whole.Connections))
	}
	want := renderExchanges(whole.Connections[0].Exchanges)

	for order, schedule := range schedules(conn) {
		t.Run(order, func(t *testing.T) {
			g := &pairingRefuser{}
			p := pairingFor(t, g)
			r := feed(t, p, schedule, nil)
			settled(t, g, p, r)
			exchanges := r.exchanges()
			if len(exchanges) == 0 {
				t.Fatalf("wiring, not the property: nothing was handed over")
			}
			if mentions(exchanges, "/plausible") {
				t.Fatalf("a start line after the hole was read as a request:\n%s", renderExchanges(exchanges))
			}
			if got := renderExchanges(exchanges); got != want {
				t.Errorf("handed over\n%s\nwant what Run reads\n%s", got, want)
			}
			if r.result != http1.Cut {
				t.Errorf("the last Feed returned %s, want %s", r.result, http1.Cut)
			}
			if got, want := p.Unplaced(fragment.Received), uint64(9+len("GET /plausible HTTP/1.1\r\n\r\n")); got != want {
				t.Errorf("Unplaced received = %d, want %d: the hole and everything after it", got, want)
			}
		})
	}
}

// A connection whose directions do not begin as Run would read them is not
// read, and a direction that begins as neither waits for the other to say how
// it is read; either way the pairing agrees with Run.
func TestTheSideIsDecidedAsRunDecidesIt(t *testing.T) {
	cases := map[string]struct {
		sent, received []string
		role           reconstruct.Role
		exchanges      int
	}{
		"both directions begin as requests": {
			sent: []string{"GET /a HTTP/1.1\r\n\r\n"}, received: []string{"GET /b HTTP/1.1\r\n\r\n"}, role: reconstruct.RoleUnknown},
		"both directions begin as responses": {
			sent: []string{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"}, received: []string{"HTTP/1.1 204 No\r\n\r\n"}, role: reconstruct.RoleUnknown},
		"a request answered by something else": {
			sent: []string{"\x16\x03\x01 not HTTP"}, received: []string{"GET /b HTTP/1.1\r\n\r\n"}, role: reconstruct.RoleUnknown},
		"something else answered as HTTP": {
			sent: []string{"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"}, received: []string{"\x00\x01 not a request\r\n\r\n"}, role: reconstruct.Server, exchanges: 1},
		"a client": {
			sent: []string{"GET /a HTTP/1.1\r\n\r\n"}, received: []string{"HTTP/1.1 204 No\r\n\r\n"}, role: reconstruct.Client, exchanges: 1},
	}
	for name, c := range cases {
		conn := connectionOf(t, c.sent, c.received)
		whole := reconstruct.Run(conn.records, reconstruct.DefaultLimits())
		if len(whole.Connections) != 1 || whole.Connections[0].Role != c.role || len(whole.Connections[0].Exchanges) != c.exchanges {
			t.Fatalf("%s: wiring, not the property: Run reads the case's own records as %+v", name, whole.Connections)
		}
		want := renderExchanges(whole.Connections[0].Exchanges)
		for order, schedule := range schedules(conn) {
			t.Run(name+", "+order, func(t *testing.T) {
				g := &pairingRefuser{}
				p := pairingFor(t, g)
				r := feed(t, p, schedule, nil)
				settled(t, g, p, r)
				if role, decided := p.Role(); !decided || role != c.role {
					t.Errorf("Role = %s, %t; want %s, true", role, decided, c.role)
				}
				if got := renderExchanges(r.exchanges()); got != want {
					t.Errorf("handed over\n%s\nwant what Run reads\n%s", got, want)
				}
				if c.role == reconstruct.RoleUnknown {
					sent, received := totalLength(conn.sent), totalLength(conn.received)
					if p.Unplaced(fragment.Sent) != sent || p.Unplaced(fragment.Received) != received {
						t.Errorf("Unplaced = %d sent, %d received; a connection not read leaves all %d and %d unplaced",
							p.Unplaced(fragment.Sent), p.Unplaced(fragment.Received), sent, received)
					}
				}
			})
		}
	}
}

func totalLength(parts []stream.Part) uint64 {
	var n uint64
	for _, part := range parts {
		n += part.Length
	}
	return n
}
