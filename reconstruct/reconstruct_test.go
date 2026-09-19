package reconstruct_test

import (
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/reconstruct"
)

var at = time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)

// exchange is one connection's two directions, cut into fragments of at most
// size bytes.
func exchange(id fragment.ConnectionID, size int, sent, received string) []fragment.Record {
	var records []fragment.Record
	sequence := uint64(0)

	for _, side := range []struct {
		direction fragment.Direction
		text      string
	}{{fragment.Received, received}, {fragment.Sent, sent}} {
		if size <= 0 {
			size = len(side.text) + 1
		}
		for start := 0; start < len(side.text); start += size {
			end := min(start+size, len(side.text))
			records = append(records, fragment.Record{
				Process:    fragment.Process{PID: 1731, StartTime: 90210},
				Connection: id,
				Direction:  side.direction,
				Sequence:   sequence,
				Offset:     uint64(start),
				Length:     uint32(end - start),
				Payload:    []byte(side.text[start:end]),
				At:         at,
			})
			sequence++
		}
	}
	return records
}

func run(t *testing.T, records []fragment.Record) reconstruct.Reconstruction {
	t.Helper()
	result := reconstruct.Run(records, reconstruct.DefaultLimits())
	if len(result.Discards) != 0 {
		t.Fatalf("the case's own records were discarded: %v", result.Discards)
	}
	return result
}

const (
	request = "POST /db/v2/row HTTP/1.1\r\n" +
		"Host: backend:8443\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 44\r\n" +
		"\r\n" +
		`{"ref":"entry-4001","qty":"1995","ok":true}` + "\n"

	response = "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 40\r\n" +
		"\r\n" +
		`{"id":"00","note":"ACCEPTED","n":1.5}` + "\n\n\n"
)

// Fragments in, structure out.
func TestAWholeExchangeIsReconstructedFromItsFragments(t *testing.T) {
	got := run(t, exchange(1, 7, response, request)).String()

	want := strings.TrimLeft(`
process 1731/90210 connection 1 server
  exchange 1
    request POST /db/v2/row HTTP/1.1
      fields Host, Content-Type, Content-Length
      body content-length 44 bytes
        object
          ref: short string
          qty: decimal string
          ok: boolean
    response HTTP/1.1 200 OK
      fields Content-Type, Content-Length
      body content-length 40 bytes
        object
          id: decimal string
          note: short string
          n: fraction
`, "\n")

	if got != want {
		t.Fatalf("reconstruction:\n%s\nwant:\n%s", got, want)
	}
}

// The process's side is read off what it wrote and read; a fragment does not
// say.
func TestTheObservedProcessesSideOfTheConnectionIsReadOffWhatItWroteAndRead(t *testing.T) {
	server := run(t, exchange(1, 0, response, request))
	client := run(t, exchange(1, 0, request, response))

	if got, want := server.Connections[0].Role, reconstruct.Server; got != want {
		t.Errorf("a process that read a request and wrote a response is %s, want %s", got, want)
	}
	if got, want := client.Connections[0].Role, reconstruct.Client; got != want {
		t.Errorf("a process that wrote a request and read a response is %s, want %s", got, want)
	}

	for _, result := range []reconstruct.Reconstruction{server, client} {
		if got, want := len(result.Connections[0].Exchanges), 1; got != want {
			t.Fatalf("%s: %d exchanges, want %d", result.Connections[0].Role, got, want)
		}
		if !result.Connections[0].Exchanges[0].Complete {
			t.Errorf("%s: the exchange is incomplete", result.Connections[0].Role)
		}
	}
}

// A direction with no message says nothing; the other direction decides.
func TestASideIsStillReadWhenOnlyOneDirectionCarriedAnything(t *testing.T) {
	if got, want := run(t, exchange(1, 0, "", request)).Connections[0].Role, reconstruct.Server; got != want {
		t.Errorf("a process that only read a request is %s, want %s", got, want)
	}
	if got, want := run(t, exchange(1, 0, request, "")).Connections[0].Role, reconstruct.Client; got != want {
		t.Errorf("a process that only wrote a request is %s, want %s", got, want)
	}
}

// Where neither direction is HTTP, nothing is invented: not an empty server.
func TestATrafficItCannotReadIsReportedAsUnknownRatherThanEmpty(t *testing.T) {
	result := run(t, exchange(1, 0, "\x00\x01\x02\x03", "\x04\x05\x06\x07"))

	connection := result.Connections[0]
	if got, want := connection.Role, reconstruct.RoleUnknown; got != want {
		t.Fatalf("Role = %s, want %s", got, want)
	}
	if len(connection.Exchanges) != 0 {
		t.Errorf("%d exchanges were read from traffic that is not HTTP", len(connection.Exchanges))
	}
	if connection.Unplaced == 0 {
		t.Error("Unplaced = 0; the bytes that could not be read are unaccounted for")
	}
	if !strings.Contains(result.String(), "unknown") {
		t.Errorf("the rendering does not say the side is unknown:\n%s", result.String())
	}
}

// A cut-off run produces an exchange marked incomplete, never a plausible
// whole one.
func TestAStreamThatEndsMidMessageProducesAnIncompleteExchange(t *testing.T) {
	result := run(t, exchange(1, 0, response[:20], request))

	got := result.Connections[0].Exchanges[0]
	if got.Complete {
		t.Fatal("an exchange whose response was cut off reports complete")
	}
	if got.Request == nil || !got.Request.Complete {
		t.Error("the request that did arrive whole is not reported as whole")
	}
	if got.Response == nil {
		t.Fatal("the response that arrived in part is absent rather than incomplete")
	}
	if got.Response.Complete {
		t.Error("a response cut off after 20 bytes reports complete")
	}
	if !strings.Contains(result.String(), "incomplete") {
		t.Errorf("the rendering does not say the exchange is incomplete:\n%s", result.String())
	}
}

// An unanswered request is a request and an absence, not an empty response.
func TestARequestNothingAnsweredIsPairedWithNoResponseAtAll(t *testing.T) {
	result := run(t, exchange(1, 0, "", request))

	got := result.Connections[0].Exchanges[0]
	if got.Request == nil || !got.Request.Complete {
		t.Fatal("the request is not reported as whole")
	}
	if got.Response != nil {
		t.Fatalf("an unanswered request was paired with a response: %q", got.Response.StartLine())
	}
	if got.Complete {
		t.Error("an unanswered exchange reports complete")
	}
	if !strings.Contains(result.String(), "response none") {
		t.Errorf("the rendering does not say there was no response:\n%s", result.String())
	}
}

func TestSeveralExchangesOnOneConnectionArePairedInOrder(t *testing.T) {
	requests := strings.ReplaceAll(request, "/db/v2/row", "/one") + strings.ReplaceAll(request, "/db/v2/row", "/two")
	responses := response + strings.Replace(response, "200 OK", "409 Conflict", 1)

	connection := run(t, exchange(1, 11, responses, requests)).Connections[0]
	if got, want := len(connection.Exchanges), 2; got != want {
		t.Fatalf("%d exchanges, want %d", got, want)
	}
	if got, want := connection.Exchanges[0].Request.Target, "/one"; got != want {
		t.Errorf("first request = %q, want %q", got, want)
	}
	if got, want := connection.Exchanges[1].Response.Status, 409; got != want {
		t.Errorf("second response = %d, want %d", got, want)
	}
}

func TestTwoConnectionsOfOneProcessAreReportedSeparately(t *testing.T) {
	records := append(exchange(1, 0, response, request), exchange(2, 0, response, request)...)

	result := run(t, records)
	if got, want := len(result.Connections), 2; got != want {
		t.Fatalf("%d connections, want %d", got, want)
	}
	if result.Connections[0].ID == result.Connections[1].ID {
		t.Fatalf("both connections are %d", result.Connections[0].ID)
	}
}

func TestABodyThatIsNotJSONIsReportedWithoutAShapeAndWithAReason(t *testing.T) {
	plain := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"

	got := run(t, exchange(1, 0, plain, request)).Connections[0].Exchanges[0].Response
	if got.Shape != nil {
		t.Fatalf("a body that is not JSON came back with the shape %s", got.Shape.Kind)
	}
	if got.ShapeRefused == "" {
		t.Fatal("ShapeRefused is empty; a body with no shape says why")
	}
	if !got.Complete {
		t.Error("a whole response with a body that is not JSON is not a message defect")
	}
}

func TestAMessageWithNoBodyCarriesNoShapeAndNoComplaint(t *testing.T) {
	empty := "HTTP/1.1 204 No Content\r\n\r\n"

	got := run(t, exchange(1, 0, empty, request)).Connections[0].Exchanges[0].Response
	if got.Shape != nil || got.ShapeRefused != "" {
		t.Fatalf("a message with no body reports shape %v and %q", got.Shape, got.ShapeRefused)
	}
}

// Fragment boundaries carry no meaning: the reconstruction is the same however
// the calls fell.
func TestWhereTheFragmentBoundariesFallDoesNotChangeTheReconstruction(t *testing.T) {
	whole := run(t, exchange(1, 0, response, request)).String()

	for _, size := range []int{1, 2, 5, 23, 4096} {
		if got := run(t, exchange(1, size, response, request)).String(); got != whole {
			t.Errorf("fragments of %d bytes reconstructed differently:\n%s\nagainst\n%s", size, got, whole)
		}
	}
}

func TestNothingIsReconstructedFromNoRecords(t *testing.T) {
	result := reconstruct.Run(nil, reconstruct.DefaultLimits())

	if len(result.Connections) != 0 {
		t.Fatalf("%d connections from no records", len(result.Connections))
	}
	if got := result.String(); got != "" {
		t.Fatalf("String() = %q from no records", got)
	}
}

// Two identical exchanges on one keep-alive connection are two exchanges.
// Identical bytes are where keying on content and keying on position differ:
// a duplicate is a fact about position (offsets already placed), and a second
// identical exchange sits at later offsets and is traffic.
func TestTwoIdenticalExchangesInSuccessionAreTwoExchangesAndNeitherIsARepeat(t *testing.T) {
	result := run(t, exchange(1, 0, response+response, request+request))

	held := result.Connections[0]
	if got, want := len(held.Exchanges), 2; got != want {
		t.Fatalf("%d exchanges, want %d: the same bytes twice is traffic twice", got, want)
	}
	// The fixture measures something only if the two are identical.
	first, second := held.Exchanges[0], held.Exchanges[1]
	if first.Request.Target != second.Request.Target || first.Response.Status != second.Response.Status {
		t.Fatalf("the two exchanges differ, so nothing below measures multiplicity over identical "+
			"bytes: %q %d against %q %d",
			first.Request.Target, first.Response.Status, second.Request.Target, second.Response.Status)
	}
	if !first.Complete || !second.Complete {
		t.Errorf("an identical pair left an incomplete exchange: %v and %v", first.Complete, second.Complete)
	}
	if len(result.Duplicates) != 0 {
		t.Errorf("the second of two identical exchanges is reported as a record no stream needed: %+v",
			result.Duplicates)
	}
	if len(result.Discards) != 0 {
		t.Errorf("an identical pair had a record refused: %+v", result.Discards)
	}
}

// One capture of that pair delivered twice is one duplicate, and the
// connection still holds both exchanges: the control for the test above.
func TestOneCaptureOfAnIdenticalPairDeliveredTwiceIsADuplicateAndNotAThirdExchange(t *testing.T) {
	records := exchange(1, 0, response+response, request+request)
	// The same record again, at offsets it already covered.
	repeated := append(append([]fragment.Record{}, records...), records[0])

	result := run(t, repeated)

	held := result.Connections[0]
	if got, want := len(held.Exchanges), 2; got != want {
		t.Fatalf("%d exchanges beside a duplicated capture, want %d", got, want)
	}
	if got, want := len(result.Duplicates), 1; got != want {
		t.Fatalf("%d duplicates, want %d: a record covering placed offsets is one", got, want)
	}
	if !result.Duplicates[0].Agrees {
		t.Error("a record repeating bytes already placed is reported as contradicting them")
	}
}

// With identical exchanges and one response missing, the survivor pairs with
// the first request. Only order can decide this.
func TestWhenIdenticalExchangesLoseAResponseTheSurvivorAnswersTheFirstRequest(t *testing.T) {
	result := run(t, exchange(1, 0, response, request+request))

	held := result.Connections[0]
	if got, want := len(held.Exchanges), 2; got != want {
		t.Fatalf("%d exchanges, want %d: an unanswered request is still an exchange", got, want)
	}
	first, second := held.Exchanges[0], held.Exchanges[1]
	if first.Response == nil {
		t.Error("the surviving response did not answer the first request")
	}
	if second.Response != nil {
		t.Errorf("the second request was answered by a response the capture never carried: %q",
			second.Response.StartLine())
	}
	if !first.Complete || second.Complete {
		t.Errorf("completeness does not follow the pairing: first %v, second %v", first.Complete, second.Complete)
	}
}
