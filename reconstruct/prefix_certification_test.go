package reconstruct_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/reconstruct"
	"github.com/evandukss/edge-observer/stream"
)

// These are downstream boundary checks with known wire bytes. They do not
// certify capture input or substitute for the release gate's decision.
type certificationPairReserver struct {
	granted  http1.Charge
	released http1.Charge
}

func (r *certificationPairReserver) Reserve(c http1.Charge) bool {
	r.granted = r.granted.Add(c)
	return true
}

func (r *certificationPairReserver) Release(c http1.Charge) {
	r.released = r.released.Add(c)
}

func certificationPair(t *testing.T) (*reconstruct.Pairing, *certificationPairReserver) {
	t.Helper()
	r := &certificationPairReserver{}
	p, err := reconstruct.NewPairing(reconstruct.Limits{}, r)
	if err != nil {
		t.Fatalf("wiring, not the property: pairing construction: %v", err)
	}
	return p, r
}

func certificationPairFeed(t *testing.T, p *reconstruct.Pairing, direction fragment.Direction, payload []byte) reconstruct.Step {
	t.Helper()
	next, _ := p.Next(direction)
	part := stream.Part{Offset: next, Length: uint64(len(payload)), Bytes: payload}
	if err := part.Validate(); err != nil {
		t.Fatalf("wiring, not the property: invalid fixture input: %v", err)
	}
	step, err := p.Feed(direction, part)
	if err != nil {
		t.Fatalf("valid contiguous fixture input refused: %v", err)
	}
	if step.Consumed != part.Length {
		t.Fatalf("unlimited reserver did not admit the whole part: %+v", step)
	}
	at, started := p.Next(direction)
	if !started || at != part.Offset+part.Length {
		t.Fatalf("wiring, not the property: input did not reach its stated boundary: next=%d started=%t", at, started)
	}
	return step
}

func certificationPairSnapshot(t *testing.T, exchanges []reconstruct.Exchange) []byte {
	t.Helper()
	b, err := json.Marshal(exchanges)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPairPrefixResponseBeforeHeadRequestKeepsWireOrder(t *testing.T) {
	p, reserver := certificationPair(t)
	responseHead := "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"
	responseGet := "HTTP/1.1 201 Created\r\nContent-Length: 3\r\n\r\nxyz"
	input := []byte(responseHead + responseGet)
	before := certificationPairFeed(t, p, fragment.Received, input)
	t.Logf("PRECONDITIONS response_bytes_accepted=%d request_bytes_accepted=0", len(input))
	if len(before.Exchanges) != 0 {
		t.Fatal("response delay was declared permanently unpaired before its requests arrived")
	}
	if p.Retained().Bytes == 0 || reserver.granted.Bytes == 0 {
		t.Error("response-before-request bytes were neither held nor reserved")
	}
	// The caller reuses its input after Feed. Held input must be copied.
	for i := range input {
		input[i] = '?'
	}
	requests := "HEAD /a HTTP/1.1\r\nHost: local\r\n\r\nGET /b HTTP/1.1\r\nHost: local\r\n\r\n"
	ready := certificationPairFeed(t, p, fragment.Sent, []byte(requests))
	if len(ready.Exchanges) != 2 {
		t.Fatalf("idle complete pipeline did not hand over its two pairs without End: %+v", ready)
	}
	for i, want := range []struct {
		method, target, body string
		status               int
	}{{"HEAD", "/a", "", 200}, {"GET", "/b", "xyz", 201}} {
		x := ready.Exchanges[i]
		if x.Request == nil || x.Response == nil {
			t.Fatalf("wire pair %d lacks its request or response: %+v", i, x)
		}
		if !x.Complete || x.Request.Method != want.method || x.Request.Target != want.target || x.Response.Status != want.status || string(x.Response.Body) != want.body {
			t.Errorf("wire pair %d changed its method, response or payload: %+v", i, x)
		}
	}
	if ready.Exchanges[0].Response.End != uint64(len(responseHead)) || ready.Exchanges[1].Response.Offset != uint64(len(responseHead)) {
		t.Error("HEAD response consumed bytes of the following response")
	}
	frozen := certificationPairSnapshot(t, ready.Exchanges)
	certificationPairFeed(t, p, fragment.Sent, []byte("GET /later HTTP/1.1\r\nHost: local\r\n\r\n"))
	certificationPairFeed(t, p, fragment.Received, []byte("HTTP/1.1 204 No Content\r\n\r\n"))
	if !bytes.Equal(frozen, certificationPairSnapshot(t, ready.Exchanges)) {
		t.Error("later pipeline activity changed an already handed-over pair")
	}
}

func TestPairPrefixByteSplitsDoNotRequireRetirement(t *testing.T) {
	p, _ := certificationPair(t)
	request := "GET /split HTTP/1.1\r\nHost: local\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"
	for i := range request {
		step := certificationPairFeed(t, p, fragment.Sent, []byte(request[i:i+1]))
		if len(step.Exchanges) != 0 {
			t.Fatal("request-only prefix became an exchange before the response direction began")
		}
	}
	var ready []reconstruct.Exchange
	for i := range response {
		step := certificationPairFeed(t, p, fragment.Received, []byte(response[i:i+1]))
		if i != len(response)-1 && len(step.Exchanges) != 0 {
			t.Fatal("response escaped before its fixed-length body was complete")
		}
		ready = append(ready, step.Exchanges...)
	}
	t.Logf("PRECONDITIONS one_byte_parts=%d end_calls=0", len(request)+len(response))
	if len(ready) != 1 || ready[0].Request == nil || ready[0].Response == nil || !ready[0].Complete || string(ready[0].Response.Body) != "body" {
		t.Fatalf("last complete pair was stranded at an idle open boundary: %+v", ready)
	}
}

func TestPairPrefixStructuralHoleNeverResynchronizes(t *testing.T) {
	p, _ := certificationPair(t)
	prefix := "GET /broken HTTP/1.1\r\nHos"
	certificationPairFeed(t, p, fragment.Sent, []byte(prefix))
	hole := stream.Part{Offset: uint64(len(prefix)), Length: 3, Gap: stream.GapMissing}
	if err := hole.Validate(); err != nil {
		t.Fatalf("wiring, not the property: hole invalid: %v", err)
	}
	cut, err := p.Feed(fragment.Sent, hole)
	if err != nil || cut.Consumed != hole.Length {
		t.Fatalf("wiring, not the property: structural hole did not enter pairing: %+v %v", cut, err)
	}
	fake := "\r\n\r\nGET /plausible HTTP/1.1\r\nHost: local\r\n\r\n"
	after := certificationPairFeed(t, p, fragment.Sent, []byte(fake))
	response := certificationPairFeed(t, p, fragment.Received, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	all := append(append(cut.Exchanges, after.Exchanges...), response.Exchanges...)
	t.Log("PRECONDITIONS structural_holes=1 plausible_messages_after_hole=1 opposite_direction_messages=1")
	if len(all) != 1 || response.Result != http1.Cut {
		t.Errorf("structural hole did not remain the final exchange boundary: exchanges=%d result=%s", len(all), response.Result)
	}
	for _, x := range all {
		if x.Complete || (x.Request != nil && x.Request.Target == "/plausible") {
			t.Errorf("pairing scanned beyond a structural hole: %+v", x)
		}
	}
	if p.Unplaced(fragment.Sent) < uint64(len(fake)) {
		t.Error("bytes after the structural hole were read as another message")
	}
}

func TestPairPrefixEndCannotFrameCloseDelimitedBody(t *testing.T) {
	p, _ := certificationPair(t)
	certificationPairFeed(t, p, fragment.Sent, []byte("GET /close HTTP/1.1\r\nHost: local\r\n\r\n"))
	before := certificationPairFeed(t, p, fragment.Received, []byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody"))
	frozen := certificationPairSnapshot(t, before.Exchanges)
	ended := p.End()
	t.Log("PRECONDITIONS close_delimited_response_bytes_accepted=1 end_calls=1")
	if before.Result != http1.Unsupported || len(before.Exchanges) != 1 {
		t.Errorf("close-delimited framing was not stopped while still open: %+v", before)
	}
	for _, x := range append(before.Exchanges, ended.Exchanges...) {
		if x.Complete || (x.Response != nil && x.Response.Framed) {
			t.Error("End promoted a close-delimited body to established framing")
		}
	}
	if !bytes.Equal(frozen, certificationPairSnapshot(t, before.Exchanges)) {
		t.Error("End rewrote an already handed-over unsupported exchange")
	}
}
