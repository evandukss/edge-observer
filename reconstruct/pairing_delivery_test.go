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

type pairingDeliveryReserve struct{}

func (pairingDeliveryReserve) Reserve(http1.Charge) bool { return true }
func (pairingDeliveryReserve) Release(http1.Charge)      {}

func pairingDeliveryNew(t *testing.T) *reconstruct.Pairing {
	t.Helper()
	p, err := reconstruct.NewPairing(reconstruct.Limits{}, pairingDeliveryReserve{})
	if err != nil || p == nil {
		t.Fatalf("wiring, not the property: pairing construction: %v", err)
	}
	return p
}

func pairingDeliveryFeed(t *testing.T, p *reconstruct.Pairing, d fragment.Direction, text string) reconstruct.Step {
	t.Helper()
	offset, _ := p.Next(d)
	part := stream.Part{Offset: offset, Length: uint64(len(text)), Bytes: []byte(text)}
	if err := part.Validate(); err != nil {
		t.Fatalf("wiring, not the property: input part: %v", err)
	}
	step, err := p.Feed(d, part)
	if err != nil {
		t.Fatalf("wiring, not the property: valid input did not reach pairing: %v", err)
	}
	if step.Consumed != part.Length {
		t.Fatalf("accepting reserver: consumed %d of %d", step.Consumed, part.Length)
	}
	return step
}

func pairingDeliveryAssert(t *testing.T, got []reconstruct.Exchange, methods, targets, bodies []string) {
	t.Helper()
	if len(got) != len(targets) {
		t.Fatalf("handed over %d pairs, want fixture's %d", len(got), len(targets))
	}
	for i, ex := range got {
		if ex.Request == nil || ex.Response == nil {
			t.Fatalf("pair %d missing a side: %+v", i, ex)
		}
		if ex.Request.Method != methods[i] || ex.Request.Target != targets[i] || string(ex.Response.Body) != bodies[i] {
			t.Errorf("pair %d = %s %s -> %q, want %s %s -> %q", i, ex.Request.Method, ex.Request.Target, ex.Response.Body, methods[i], targets[i], bodies[i])
		}
		if !ex.Complete || !ex.Request.Framed || !ex.Response.Framed {
			t.Errorf("pair %d is not complete and framed", i)
		}
	}
}

func TestPairingDeliveryEverySyntaxSplit(t *testing.T) {
	request := "POST /alpha HTTP/1.1\r\nHost: fixture\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-End: yes\r\n\r\n"
	response := "HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nxyz\r\n0\r\nX-End: done\r\n\r\n"
	for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
		wire, other, opposite := request, response, fragment.Received
		if direction == fragment.Received {
			wire, other, opposite = response, request, fragment.Sent
		}
		for split := 1; split < len(wire); split++ {
			t.Run(fmt.Sprintf("%s/%d", direction, split), func(t *testing.T) {
				p := pairingDeliveryNew(t)
				var got []reconstruct.Exchange
				got = append(got, pairingDeliveryFeed(t, p, opposite, other).Exchanges...)
				got = append(got, pairingDeliveryFeed(t, p, direction, wire[:split]).Exchanges...)
				if len(got) != 0 {
					t.Fatal("an unfinished message was handed over")
				}
				got = append(got, pairingDeliveryFeed(t, p, direction, wire[split:]).Exchanges...)
				pairingDeliveryAssert(t, got, []string{"POST"}, []string{"/alpha"}, []string{"xyz"})
				if string(got[0].Request.Body) != "abc" || len(got[0].Request.Trailers) != 1 || len(got[0].Response.Trailers) != 1 {
					t.Fatal("fragmentation lost a request body or trailer")
				}
				if end := p.End(); len(end.Exchanges) != 0 {
					t.Fatal("retirement duplicated an early pair")
				}
			})
		}
	}
}

func TestPairingDeliveryHeadAndPipelineInEitherArrivalOrder(t *testing.T) {
	requests := "HEAD /head HTTP/1.1\r\n\r\nGET /second HTTP/1.1\r\n\r\nGET /third HTTP/1.1\r\n\r\n"
	responses := "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nBHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nC"
	for _, responseFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(responseFirst), func(t *testing.T) {
			p := pairingDeliveryNew(t)
			d1, d2, first, second := fragment.Sent, fragment.Received, requests, responses
			if responseFirst {
				d1, d2, first, second = d2, d1, second, first
			}
			if step := pairingDeliveryFeed(t, p, d1, first); len(step.Exchanges) != 0 {
				t.Fatal("one direction alone was declared unpaired before end")
			}
			got := pairingDeliveryFeed(t, p, d2, second).Exchanges
			pairingDeliveryAssert(t, got, []string{"HEAD", "GET", "GET"}, []string{"/head", "/second", "/third"}, []string{"", "B", "C"})
			request := "GET /after-release HTTP/1.1\r\n\r\n"
			response := "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nD"
			first, second = request, response
			if responseFirst {
				first, second = response, request
			}
			if step := pairingDeliveryFeed(t, p, d1, first); len(step.Exchanges) != 0 {
				t.Fatal("a later message was paired before its other side arrived")
			}
			after := pairingDeliveryFeed(t, p, d2, second).Exchanges
			pairingDeliveryAssert(t, after, []string{"GET"}, []string{"/after-release"}, []string{"D"})
		})
	}
}

func TestPairingDeliveryDelayedResponseCrossesReleases(t *testing.T) {
	p := pairingDeliveryNew(t)
	if s := pairingDeliveryFeed(t, p, fragment.Sent, "GET /one HTTP/1.1\r\n\r\nGET /two HTTP/1.1\r\n\r\n"); len(s.Exchanges) != 0 {
		t.Fatal("requests awaiting responses were declared unpaired")
	}
	first := pairingDeliveryFeed(t, p, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nAHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
	pairingDeliveryAssert(t, first.Exchanges, []string{"GET"}, []string{"/one"}, []string{"A"})
	if s := pairingDeliveryFeed(t, p, fragment.Sent, "GET /three HTTP/1.1\r\n\r\n"); len(s.Exchanges) != 0 {
		t.Fatal("a delayed response was treated as absent")
	}
	last := pairingDeliveryFeed(t, p, fragment.Received, "BHTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nC")
	pairingDeliveryAssert(t, last.Exchanges, []string{"GET", "GET"}, []string{"/two", "/three"}, []string{"B", "C"})
	if string(first.Exchanges[0].Response.Body) != "A" {
		t.Fatal("later input changed a handed-over response")
	}
}

func TestPairingDeliveryStopsNeverShiftLaterResponses(t *testing.T) {
	for _, tc := range []struct{ name, request, response string }{
		{"informational", "GET /stop HTTP/1.1\r\n\r\n", "HTTP/1.1 100 Continue\r\n\r\n"},
		{"connect", "CONNECT fixture:443 HTTP/1.1\r\n\r\n", "HTTP/1.1 200 Connected\r\nContent-Length: 0\r\n\r\n"},
		{"upgrade", "GET /stop HTTP/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"},
		{"close-delimited", "GET /stop HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nbody"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := pairingDeliveryNew(t)
			pairingDeliveryFeed(t, p, fragment.Sent, "GET /before HTTP/1.1\r\n\r\n")
			before := pairingDeliveryFeed(t, p, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA")
			pairingDeliveryAssert(t, before.Exchanges, []string{"GET"}, []string{"/before"}, []string{"A"})
			x := pairingDeliveryFeed(t, p, fragment.Sent, tc.request+"GET /must-not-pair HTTP/1.1\r\n\r\n")
			y := pairingDeliveryFeed(t, p, fragment.Received, tc.response+"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nZ")
			all := append(x.Exchanges, y.Exchanges...)
			all = append(all, p.End().Exchanges...)
			if len(all) != 1 || all[0].Request == nil || all[0].Request.Target == "/must-not-pair" {
				t.Fatalf("stop shifted or lost its exchange: %+v", all)
			}
			if y.Result != http1.Unsupported {
				t.Errorf("stopping boundary returned %s", y.Result)
			}
			if tc.name == "close-delimited" && all[0].Response != nil && all[0].Response.Framed {
				t.Fatal("close-delimited response certified at retirement")
			}
		})
	}
}

func TestPairingDeliveryWorkTracksNewInput(t *testing.T) {
	p := pairingDeliveryNew(t)
	pairingDeliveryFeed(t, p, fragment.Sent, "POST /growing HTTP/1.1\r\nContent-Length: 4096\r\n\r\n")
	pairingDeliveryFeed(t, p, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	start := reconstruct.Examined(p)
	var got []reconstruct.Exchange
	for range 256 {
		got = append(got, pairingDeliveryFeed(t, p, fragment.Sent, strings.Repeat("x", 16)).Exchanges...)
	}
	pairingDeliveryAssert(t, got, []string{"POST"}, []string{"/growing"}, []string{""})
	work := reconstruct.Examined(p) - start
	if work == 0 || work > 4*4096 {
		t.Fatalf("4096 new body bytes cost %d examined bytes; want positive linear work <= %d", work, 4*4096)
	}
}
