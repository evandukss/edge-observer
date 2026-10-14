package processing_test

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contentcoding"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/reconstruct"
)

// codedSentinel is a member value only a removed member carries.
const codedSentinel = "coded-sentinel-7f3a"

func gzipOf(t *testing.T, plain string) string {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(plain)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// codedResponse is a response whose body is in the codings named.
func codedResponse(codings, body string) string {
	return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: " + codings +
		"\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

func codedGet(target string) call { return wrote("GET " + target + " HTTP/1.1\r\nHost: a\r\n\r\n") }

// released is every exchange the worker's turns issued an id to, in order.
func (r *releasing) released() []processing.Released {
	var out []processing.Released
	for _, one := range r.turns {
		out = append(out, one.Released...)
	}
	return out
}

// writtenAt fails unless connection 1's exchange lines are exactly want's
// targets, each at its index, with the id issued at that index counting from
// firstID.
func (r *releasing) writtenAt(firstID int, want map[string]int) {
	r.t.Helper()
	lines := r.lines(processing.ArtifactExchange, 1)
	if len(lines) != len(want) {
		r.t.Fatalf("%d exchange lines, want %d (%v)", len(lines), len(want), want)
	}
	for _, a := range lines {
		index, ok := want[target(r.t, a)]
		if !ok || *a.Index != index || a.ExchangeID != strconv.Itoa(firstID+index) {
			r.t.Fatalf("exchange line %s has index %d id %s, want index %d id %d", target(r.t, a), *a.Index, a.ExchangeID,
				index, firstID+index)
		}
	}
}

func excludedCounts(t *testing.T, a processing.Artifact) processing.ExcludedExchanges {
	t.Helper()
	if a.Version != processing.ArtifactVersion5 || a.ExcludedExchanges == nil {
		t.Fatalf("the connection line is %s with excluded exchanges %+v, want version 5 counts", a.Version, a.ExcludedExchanges)
	}
	return *a.ExcludedExchanges
}

// An encoded body on an open keep-alive connection is written as its content,
// with the configuration's removal applied to the decoded content, and the
// exchanges around it are written in order, all before the connection closes.
func TestADecodedBodyIsWrittenAsItsContentWhileItsConnectionIsOpen(t *testing.T) {
	type observed struct {
		charge  processing.DecodeCharge
		written int
	}
	var charges []observed
	var r *releasing
	r = newReleasing(t, releasingOptions{rules: `"remove": {"json": {"response": ["/secret"]}}`,
		decodeCharges: func(c processing.DecodeCharge) { charges = append(charges, observed{c, len(r.out.lines)}) }})
	plain := `{"kept":"visible","secret":"` + codedSentinel + `"}`
	encoded := gzipOf(t, plain)
	c := converse(t, 1, append(append(pair("/a"), codedGet("/b"), read(codedResponse("gzip", encoded))), pair("/c")...)...)
	r.give(c.fragments...)
	r.drain()
	if !bytes.Contains(c.fragments[3].Payload, []byte(encoded)) {
		t.Fatal("wiring, not the property: the encoded body is not what capture holds")
	}
	r.writtenAt(1, map[string]int{"/a": 0, "/b": 1, "/c": 2})
	if len(r.lines(processing.ArtifactConnection, 1)) != 0 {
		t.Fatal("wiring, not the property: the connection retired before the assertions on an open connection")
	}
	b := r.lines(processing.ArtifactExchange, 1)[1]
	response := b.Reconstruction.Exchanges[0].Response.Message
	kept, err := base64.StdEncoding.DecodeString(response.Body.Kept)
	if err != nil {
		t.Fatal(err)
	}
	var content map[string]string
	if err := json.Unmarshal(kept, &content); err != nil || content["kept"] != "visible" || len(content) != 1 {
		t.Fatalf("the written body is %q, want the decoded content with the removed member gone", kept)
	}
	if response.Body.Content == nil || response.Body.Content.State != record.ContentDecoded ||
		response.Body.Content.Length != strconv.Itoa(len(plain)) || !slices.Equal(response.Body.Content.Codings, []string{"gzip"}) {
		t.Fatalf("the decoding is recorded as %+v, want decoded, %d bytes, gzip", response.Body.Content, len(plain))
	}
	if response.Body.Length != strconv.Itoa(len(encoded)) {
		t.Fatalf("the body's length is %s, want the captured %d", response.Body.Length, len(encoded))
	}
	shape := response.Structure.Shape
	if response.Structure.State != record.StructureDerived || shape == nil || shape.Kind != "object" ||
		len(shape.Fields) != 1 || shape.Fields[0].Name != "kept" {
		t.Fatalf("the structure is %+v, want the decoded content's object with the member kept", response.Structure)
	}
	if len(b.PolicyExclusions) != 1 || b.PolicyExclusions[0].Field != "message.body.json/secret" {
		t.Fatalf("the removal is recorded as %+v", b.PolicyExclusions)
	}
	for n, line := range r.out.lines {
		if bytes.Contains(line, []byte(codedSentinel)) || bytes.Contains(line, []byte(base64.StdEncoding.EncodeToString([]byte(encoded)))) {
			t.Fatalf("line %d carries the removed member or the encoded body: %s", n, line)
		}
	}
	if _, err := r.readBack(); err != nil {
		t.Fatalf("the shipped reader refuses what was written: %v", err)
	}
	// Every charge the decoding of /b's response asked for is granted and given
	// back exactly once, the decoded content's after /b's line is written.
	held := map[contentcoding.Charge]int{}
	returnedAfterLine := 0
	for _, one := range charges {
		c := one.charge
		if c.Connection != 1 || c.Index != 1 || c.Request {
			t.Fatalf("a decoding charge for another message: %+v", c)
		}
		switch c.Event {
		case processing.ChargeReserved:
			held[c.Charge]++
		case processing.ChargeReturned:
			held[c.Charge]--
			if c.Charge.Kind == contentcoding.OutputCharge && one.written >= 2 {
				returnedAfterLine++
			}
		case processing.ChargeRefused:
			t.Fatalf("a decoding charge was refused: %+v", c)
		}
	}
	if len(held) == 0 || returnedAfterLine != 1 {
		t.Fatalf("wiring, not the property: %d distinct charges observed, %d output returned after /b's line, so "+
			"nothing below measured the decoded content's charge", len(held), returnedAfterLine)
	}
	for charge, balance := range held {
		if balance != 0 {
			t.Errorf("the charge %+v was reserved and returned with a balance of %d, want 0", charge, balance)
		}
	}
	r.retire(c.retirement)
	r.drain()
	if got := excludedCounts(t, r.lines(processing.ArtifactConnection, 1)[0]); got != (processing.ExcludedExchanges{
		ContentCodingUnsupported: "0", ContentDecodingFailed: "0", ContentDecodedTooLarge: "0",
		ContentDecodingTooCostly: "0"}) {
		t.Fatalf("the connection line counts %+v excluded", got)
	}
	if stats := r.store.Stats(); stats.Parsing != 0 || stats.Policy != 0 {
		t.Fatalf("after retirement the allowance still holds parsing %d and policy %d", stats.Parsing, stats.Policy)
	}
}

// A decoded body's structure is read from its decoded bytes, whether the body
// is kept or reduced to its structure; the structure the encoded bytes would
// give is never used.
func TestADecodedBodysStructureIsReadFromItsContent(t *testing.T) {
	plain := `{"kept":"visible","count":3}`
	for _, tc := range []struct {
		name, rules, state string
		kept               bool
	}{
		{"kept", "", record.StructureDerived, true},
		{"reduced-to-structure", `"remove": {"body_values": ["response"]}`, record.StructureDerived, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReleasing(t, releasingOptions{rules: tc.rules})
			c := converse(t, 1, codedGet("/b"), read(codedResponse("gzip", gzipOf(t, plain))))
			r.give(c.fragments...)
			r.drain()
			r.writtenAt(1, map[string]int{"/b": 0})
			response := r.lines(processing.ArtifactExchange, 1)[0].Reconstruction.Exchanges[0].Response.Message
			if response.Body.Content == nil {
				t.Fatal("wiring, not the property: the body was not decoded, so its structure says nothing about decoding")
			}
			kept, _ := base64.StdEncoding.DecodeString(response.Body.Kept)
			if (string(kept) == plain) != tc.kept {
				t.Fatalf("the written body is %q", kept)
			}
			shape := response.Structure.Shape
			var names []string
			if shape != nil {
				for _, f := range shape.Fields {
					names = append(names, f.Name)
				}
			}
			slices.Sort(names)
			if response.Structure.State != tc.state || shape == nil || shape.Kind != "object" ||
				!slices.Equal(names, []string{"count", "kept"}) {
				t.Fatalf("the structure is %+v, want the decoded content's object of two members", response.Structure)
			}
		})
	}
}

// With the Content-Encoding header removed by policy, the body is still
// decoded, and the line names no coding: only that it was decoded.
func TestARemovedCodingHeaderLeavesTheDecodingUnnamed(t *testing.T) {
	r := newReleasing(t, releasingOptions{rules: `"remove": {"headers": ["content-encoding"]}`})
	plain := `{"kept":"visible"}`
	c := converse(t, 1, codedGet("/b"), read(codedResponse("gzip", gzipOf(t, plain))))
	r.give(c.fragments...)
	r.drain()
	r.writtenAt(1, map[string]int{"/b": 0})
	response := r.lines(processing.ArtifactExchange, 1)[0].Reconstruction.Exchanges[0].Response.Message
	for _, h := range response.Headers {
		if strings.EqualFold(h.Name, "content-encoding") {
			t.Fatal("wiring, not the property: the policy did not remove the header")
		}
	}
	if kept, _ := base64.StdEncoding.DecodeString(response.Body.Kept); string(kept) != plain {
		t.Fatalf("the written body is %q, want %q", kept, plain)
	}
	if response.Body.Content == nil || response.Body.Content.State != record.ContentDecoded || response.Body.Content.Codings != nil {
		t.Fatalf("the decoding is recorded as %+v, want decoded with no coding named", response.Body.Content)
	}
	if _, err := r.readBack(); err != nil {
		t.Fatalf("the shipped reader refuses what was written: %v", err)
	}
}

// A coding outside the four excludes its exchange alone: it keeps its id and
// index, it is counted once, and the exchange after it is written before the
// connection closes.
func TestAnUnsupportedCodingExcludesItsExchangeAlone(t *testing.T) {
	r := newReleasing(t, releasingOptions{})
	c := converse(t, 1, append(append(pair("/a"), codedGet("/b"), read(codedResponse("compress", "xyz"))), pair("/c")...)...)
	r.give(c.fragments...)
	r.drain()
	released := r.released()
	if len(released) != 3 {
		t.Fatalf("wiring, not the property: the reading handed over %d of the 3 exchanges", len(released))
	}
	for n, want := range []processing.ReleaseOutcome{processing.ReleaseEnqueued, processing.ReleaseExcluded, processing.ReleaseEnqueued} {
		if released[n].Index != n || released[n].ID != uint64(n+1) || released[n].Outcome != want {
			t.Fatalf("exchange %d was released as %+v, want index %d id %d %s", n, released[n], n, n+1, want)
		}
	}
	r.writtenAt(1, map[string]int{"/a": 0, "/c": 2})
	if len(r.lines(processing.ArtifactConnection, 1)) != 0 {
		t.Fatal("wiring, not the property: the connection retired before /c was asserted written while open")
	}
	r.retire(c.retirement)
	r.drain()
	line := r.lines(processing.ArtifactConnection, 1)
	if len(line) != 1 || line[0].ReconstructionTruncation != nil {
		t.Fatalf("the connection line is %+v, want one with no truncation", line)
	}
	if got := excludedCounts(t, line[0]); got != (processing.ExcludedExchanges{ContentCodingUnsupported: "1",
		ContentDecodingFailed: "0", ContentDecodedTooLarge: "0", ContentDecodingTooCostly: "0"}) {
		t.Fatalf("the connection line counts %+v", got)
	}
	o := r.outcome
	if o.Excluded != (processing.Exclusions{ContentCodingUnsupported: 1}) || o.Withheld != connection.Counted(0) ||
		o.ProcessingFailures != 0 || o.ExchangeIDs != 3 {
		t.Fatalf("the outcome counts excluded %+v, withheld %+v, %d processing failures, %d ids", o.Excluded, o.Withheld,
			o.ProcessingFailures, o.ExchangeIDs)
	}
	if _, err := r.readBack(); err != nil {
		t.Fatalf("the shipped reader refuses what was written: %v", err)
	}
}

// A connection cut after an exchange excluded alone starts its suffix after
// that exchange, and keeps its count.
func TestACutAfterAnExclusionStartsItsSuffixAfterIt(t *testing.T) {
	r := newReleasing(t, releasingOptions{connectionInput: 4})
	c := converse(t, 1, append(append(pair("/a"), codedGet("/b"), read(codedResponse("compress", "xyz"))),
		codedGet("/3"), codedGet("/4"), codedGet("/5"), codedGet("/6"))...)
	r.give(c.fragments...)
	r.drain()
	if r.outcome.ConnectionsCut != 1 {
		t.Fatalf("wiring, not the property: four pending requests on a connection bounded at four were not cut: %+v", r.outcome)
	}
	r.retire(c.retirement)
	r.drain()
	r.writtenAt(1, map[string]int{"/a": 0})
	line := r.lines(processing.ArtifactConnection, 1)
	if len(line) != 1 {
		t.Fatalf("%d connection lines, want 1", len(line))
	}
	after := map[string]uint64{"sent": c.fragments[2].End(), "received": c.fragments[3].End()}
	truncation := line[0].ReconstructionTruncation
	if truncation == nil || len(truncation.Stops) != 2 {
		t.Fatalf("the cut connection's truncation is %+v, want a stop in each direction", truncation)
	}
	for _, stop := range truncation.Stops {
		if stop.Reason != processing.TruncationConnectionCut || stop.Offset != strconv.FormatUint(after[stop.Direction], 10) {
			t.Fatalf("the %s stop is %+v, want connection_cut at %d, after the excluded exchange", stop.Direction, stop,
				after[stop.Direction])
		}
	}
	if got := excludedCounts(t, line[0]); got.ContentCodingUnsupported != "1" {
		t.Fatalf("after the cut the connection line counts %+v", got)
	}
	if r.outcome.Excluded != (processing.Exclusions{ContentCodingUnsupported: 1}) {
		t.Fatalf("after the cut the outcome counts %+v", r.outcome.Excluded)
	}
	if _, err := r.readBack(); err != nil {
		t.Fatalf("the shipped reader refuses what was written: %v", err)
	}
}

// A message whose framing establishes no content bytes encodes nothing,
// whatever its Content-Encoding says: it is written as it is, it is counted
// nowhere, and the next message's bytes stay the next message's.
func TestABodilessMessageDeclaringACodingIsWrittenAsItIs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		request  string
		response string
	}{
		{"head", "HEAD /b HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 40\r\n\r\n"},
		{"content-length-0", "GET /b HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n"},
		{"empty-chunked", "GET /b HTTP/1.1\r\nHost: a\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"},
		{"unsupported-on-head", "HEAD /b HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Encoding: compress\r\nContent-Length: 40\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReleasing(t, releasingOptions{})
			c := converse(t, 1, append([]call{wrote(tc.request), read(tc.response)}, pair("/c")...)...)
			r.give(c.fragments...)
			r.drain()
			r.writtenAt(1, map[string]int{"/b": 0, "/c": 1})
			for _, a := range r.lines(processing.ArtifactExchange, 1) {
				if m := a.Reconstruction.Exchanges[0].Response.Message; m.Body.Content != nil {
					t.Fatalf("%s carries a decoding record %+v", target(t, a), m.Body.Content)
				}
			}
			c2 := r.lines(processing.ArtifactExchange, 1)[1].Reconstruction.Exchanges[0].Response.Message
			if kept, _ := base64.StdEncoding.DecodeString(c2.Body.Kept); string(kept) != "/c" {
				t.Fatalf("the next response's body is %q, want its own", kept)
			}
			r.retire(c.retirement)
			r.drain()
			if r.outcome.Excluded != (processing.Exclusions{}) || r.outcome.Withheld != connection.Counted(0) {
				t.Fatalf("a bodiless message was counted: excluded %+v, withheld %+v", r.outcome.Excluded, r.outcome.Withheld)
			}
		})
	}
}

// A coded message beside a stop still stops: the stop is the exchange's
// reason, nothing after it is written, and nothing is counted as excluded
// alone.
func TestACodedBodyBesideAStopStillStops(t *testing.T) {
	encoded := ""
	for _, tc := range []struct {
		name  string
		calls func() []call
	}{
		{"malformed-coding", func() []call {
			return []call{codedGet("/b"), read(codedResponse("gzip, @", encoded))}
		}},
		{"upgrade-request", func() []call {
			return []call{wrote("GET /b HTTP/1.1\r\nHost: a\r\nUpgrade: h2c\r\n\r\n"), read(codedResponse("gzip", encoded))}
		}},
		{"upgrade-response", func() []call {
			return []call{codedGet("/b"), read("HTTP/1.1 200 OK\r\nUpgrade: h2c\r\nContent-Encoding: gzip\r\nContent-Length: " +
				strconv.Itoa(len(encoded)) + "\r\n\r\n" + encoded)}
		}},
		{"transfer-coding", func() []call {
			return []call{codedGet("/b"), read("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: gzip, chunked\r\n\r\n" +
				strconv.FormatInt(int64(len(encoded)), 16) + "\r\n" + encoded + "\r\n0\r\n\r\n")}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded = gzipOf(t, `{"kept":"visible"}`)
			r := newReleasing(t, releasingOptions{})
			c := converse(t, 1, append(append(pair("/a"), tc.calls()...), pair("/c")...)...)
			r.give(c.fragments...)
			r.drain()
			if len(r.released()) < 2 {
				t.Fatalf("wiring, not the property: the reading handed over %d exchanges, so /b never reached release",
					len(r.released()))
			}
			r.writtenAt(1, map[string]int{"/a": 0})
			r.retire(c.retirement)
			r.drain()
			line := r.lines(processing.ArtifactConnection, 1)
			if len(line) != 1 || line[0].ReconstructionTruncation == nil {
				t.Fatalf("the connection line is %+v, want one with a truncated suffix", line)
			}
			if got := excludedCounts(t, line[0]); got.ContentCodingUnsupported != "0" || got.ContentDecodingFailed != "0" ||
				got.ContentDecodedTooLarge != "0" || r.outcome.Excluded != (processing.Exclusions{}) {
				t.Fatalf("a stop was counted as excluded alone: line %+v, outcome %+v", got, r.outcome.Excluded)
			}
			for _, stop := range line[0].ReconstructionTruncation.Stops {
				offset, _ := strconv.ParseUint(stop.Offset, 10, 64)
				if want := c.fragments[1].End(); stop.Direction == "received" && offset != want {
					t.Fatalf("the received stop starts at %d, want %d after /a", offset, want)
				}
			}
		})
	}
}

// Between the outcomes both messages established, the exchange takes one
// reason - unsupported over a failed decoding over a decoding too large - and
// is counted once under it.
func TestAnExchangeIsCountedOnceUnderItsRankedReason(t *testing.T) {
	const bound = 512
	limits := reconstruct.Limits{HTTP: http1.Limits{MaxBodyBytes: bound}}
	post := func(codings, body string) call {
		return wrote("POST /b HTTP/1.1\r\nHost: a\r\nContent-Encoding: " + codings + "\r\nContent-Length: " +
			strconv.Itoa(len(body)) + "\r\n\r\n" + body)
	}
	for _, tc := range []struct {
		name               string
		request, response  func(t *testing.T) (string, string)
		unsupported, fails uint64
		large              uint64
	}{
		{"failed-request-large-response", func(t *testing.T) (string, string) { return "gzip", "zz" },
			func(t *testing.T) (string, string) { return "gzip", gzipOf(t, strings.Repeat("a", 8*bound)) }, 0, 1, 0},
		{"large-request-failed-response", func(t *testing.T) (string, string) { return "gzip", gzipOf(t, strings.Repeat("a", 8*bound)) },
			func(t *testing.T) (string, string) { return "gzip", "zz" }, 0, 1, 0},
		{"unsupported-request-failed-response", func(t *testing.T) (string, string) { return "compress", "zz" },
			func(t *testing.T) (string, string) { return "gzip", "zz" }, 1, 0, 0},
		{"large-on-both", func(t *testing.T) (string, string) { return "gzip", gzipOf(t, strings.Repeat("a", 8*bound)) },
			func(t *testing.T) (string, string) { return "gzip", gzipOf(t, strings.Repeat("b", 8*bound)) }, 0, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReleasing(t, releasingOptions{limits: limits})
			requestCodings, requestBody := tc.request(t)
			responseCodings, responseBody := tc.response(t)
			if len(requestBody) > bound || len(responseBody) > bound {
				t.Fatalf("wiring, not the property: a captured body of %d or %d bytes is over the %d-byte bound, so it "+
					"would stop rather than decode", len(requestBody), len(responseBody), bound)
			}
			c := converse(t, 1, append([]call{post(requestCodings, requestBody), read(codedResponse(responseCodings, responseBody))},
				pair("/c")...)...)
			r.give(c.fragments...)
			r.drain()
			r.writtenAt(1, map[string]int{"/c": 1})
			want := processing.Exclusions{ContentCodingUnsupported: tc.unsupported, ContentDecodingFailed: tc.fails,
				ContentDecodedTooLarge: tc.large}
			if r.outcome.Excluded != want {
				t.Fatalf("counted %+v, want %+v", r.outcome.Excluded, want)
			}
		})
	}
}

// A decoding the shared allowance cannot hold cuts its connection by the
// existing counted cut: nothing of the exchange or after it is written, it is
// never counted as excluded, and everything is given back once. The allowance
// is filled just before the decoding's first charge is asked, with no intake
// event between.
func TestARefusedDecodingCutsItsConnection(t *testing.T) {
	var r *releasing
	var filled int64
	var refused int
	r = newReleasing(t, releasingOptions{decodeCharges: func(c processing.DecodeCharge) {
		switch {
		case c.Event == processing.ChargeReserving && filled == 0:
			stats := r.store.Stats()
			filled = stats.LimitBytes - stats.Bytes - stats.Parsing - stats.Policy
			if filled <= 0 || !r.store.Reserve(intake.Parsing, filled) {
				t.Fatalf("wiring, not the property: the allowance's %d bytes left could not be taken", filled)
			}
		case c.Event == processing.ChargeRefused:
			refused++
		}
	}})
	c := converse(t, 1, append(append(pair("/a"), codedGet("/b"), read(codedResponse("gzip", gzipOf(t, `{"kept":"visible"}`)))),
		pair("/c")...)...)
	r.give(c.fragments...)
	r.drain()
	if filled == 0 || refused != 1 {
		t.Fatalf("wiring, not the property: %d bytes taken and %d charges refused, so no decoding was refused", filled,
			refused)
	}
	if r.outcome.ConnectionsCut != 1 || r.outcome.AllowanceCut != 1 {
		t.Fatalf("the refused decoding cut %d connections, %d by the allowance, want 1 and 1", r.outcome.ConnectionsCut,
			r.outcome.AllowanceCut)
	}
	r.writtenAt(1, map[string]int{"/a": 0})
	r.store.Return(intake.Parsing, filled)
	r.retire(c.retirement)
	r.drain()
	line := r.lines(processing.ArtifactConnection, 1)
	if len(line) != 1 || line[0].ReconstructionTruncation == nil {
		t.Fatalf("the connection line is %+v, want one truncated by the cut", line)
	}
	for _, stop := range line[0].ReconstructionTruncation.Stops {
		if stop.Reason != processing.TruncationConnectionCut {
			t.Fatalf("the stop is %+v, want connection_cut", stop)
		}
	}
	if r.outcome.Excluded != (processing.Exclusions{}) {
		t.Fatalf("a refused decoding was counted as excluded: %+v", r.outcome.Excluded)
	}
	if stats := r.store.Stats(); stats.Parsing != 0 || stats.Policy != 0 {
		t.Fatalf("after retirement the allowance holds parsing %d and policy %d", stats.Parsing, stats.Policy)
	}
}

// versionFiveLines is one connection's exchange line, its response recast as
// decoded gzip content, and its connection line, as the worker writes them.
func versionFiveLines(t *testing.T) (processing.Artifact, processing.Artifact) {
	t.Helper()
	r := newReleasing(t, releasingOptions{})
	c := converse(t, 1, pair("/a")...)
	r.give(c.fragments...)
	r.retire(c.retirement)
	r.drain()
	exchanges, connections := r.lines(processing.ArtifactExchange, 1), r.lines(processing.ArtifactConnection, 1)
	if len(exchanges) != 1 || len(connections) != 1 || exchanges[0].Version != processing.ArtifactVersion5 {
		t.Fatalf("wiring, not the property: the worker wrote %d exchange and %d connection lines of version %v",
			len(exchanges), len(connections), exchanges)
	}
	exchange := exchanges[0]
	reconstruction := *exchange.Reconstruction
	e := reconstruction.Exchanges[0]
	m := *e.Response.Message
	m.Headers = append(slices.Clone(m.Headers), record.Field{Name: "Content-Encoding", Value: "gzip"})
	m.Body.Content = &record.Content{State: record.ContentDecoded, Length: "2", Codings: []string{"gzip"}}
	e.Response.Message = &m
	reconstruction.Exchanges = []record.Exchange{e}
	exchange.Reconstruction = &reconstruction
	return exchange, connections[0]
}

// withResponse is a with its response message changed by change, on copies.
func withResponse(a processing.Artifact, change func(*record.Message)) processing.Artifact {
	reconstruction := *a.Reconstruction
	e := reconstruction.Exchanges[0]
	m := *e.Response.Message
	m.Headers = slices.Clone(m.Headers)
	if m.Body.Content != nil {
		content := *m.Body.Content
		content.Codings = slices.Clone(content.Codings)
		m.Body.Content = &content
	}
	change(&m)
	e.Response.Message = &m
	reconstruction.Exchanges = []record.Exchange{e}
	a.Reconstruction = &reconstruction
	return a
}

func TestVersionFiveLinesAreReadUnderTheirOwnRules(t *testing.T) {
	exchange, connection := versionFiveLines(t)
	if err := readLines(t, exchange, connection); err != nil {
		t.Fatalf("wiring, not the property: the reader refuses the well-formed version 5 pair, so no refusal below "+
			"is about the member it names: %v", err)
	}
	refused := map[string]processing.Artifact{}
	for name, counts := range map[string]*processing.ExcludedExchanges{
		"counts absent": nil,
		"a count empty": {ContentCodingUnsupported: "", ContentDecodingFailed: "0", ContentDecodedTooLarge: "0",
			ContentDecodingTooCostly: "0"},
		"a count not decimal": {ContentCodingUnsupported: "0", ContentDecodingFailed: "-1", ContentDecodedTooLarge: "0",
			ContentDecodingTooCostly: "0"},
		"a leading zero": {ContentCodingUnsupported: "0", ContentDecodingFailed: "0", ContentDecodedTooLarge: "01",
			ContentDecodingTooCostly: "0"},
		"the fourth reason left out": {ContentCodingUnsupported: "0", ContentDecodingFailed: "0",
			ContentDecodedTooLarge: "0"},
	} {
		bad := connection
		bad.ExcludedExchanges = counts
		refused["connection line, "+name] = bad
	}
	onExchange := exchange
	onExchange.ExcludedExchanges = connection.ExcludedExchanges
	refused["counts on an exchange line"] = onExchange
	onFour := connection
	onFour.Version = processing.ArtifactVersion4
	refused["counts on a version 4 connection line"] = onFour
	contentOnFour := exchange
	contentOnFour.Version = processing.ArtifactVersion4
	refused["decoded content on a version 4 line"] = contentOnFour
	for name, change := range map[string]func(*record.Message){
		"another state":            func(m *record.Message) { m.Body.Content.State = "encoded" },
		"a length not decimal":     func(m *record.Message) { m.Body.Content.Length = "two" },
		"a length with a zero":     func(m *record.Message) { m.Body.Content.Length = "02" },
		"no captured body":         func(m *record.Message) { m.Body.Length = "0" },
		"a hole":                   func(m *record.Message) { m.Body.Holed = "1" },
		"an elision":               func(m *record.Message) { m.Body.Elided = "1" },
		"an unknown coding":        func(m *record.Message) { m.Body.Content.Codings = []string{"compress"} },
		"two codings":              func(m *record.Message) { m.Body.Content.Codings = []string{"gzip", "br"} },
		"four codings":             func(m *record.Message) { m.Body.Content.Codings = []string{"gzip", "gzip", "gzip", "gzip"} },
		"a coding the header lost": func(m *record.Message) { m.Body.Content.Codings = []string{"br"} },
		"codings with no header": func(m *record.Message) {
			m.Headers = slices.DeleteFunc(m.Headers, func(f record.Field) bool { return f.Name == "Content-Encoding" })
		},
	} {
		refused["decoded content, "+name] = withResponse(exchange, change)
	}
	// Where an extension's change of the headers is written, the headers are
	// not checked against the codings, so the one-coding limit is all that
	// refuses two.
	twoReplaced := withResponse(exchange, func(m *record.Message) { m.Body.Content.Codings = []string{"gzip", "br"} })
	twoReplaced.ExtensionOutcomes = []processing.ExtensionOutcome{{Exchange: *twoReplaced.Index, Extension: "marker",
		Outcome: extension.Changed, Changed: []string{"response.headers"}, Overwritten: []string{}}}
	refused["decoded content, two codings beside a replaced header"] = twoReplaced
	for name, bad := range refused {
		if err := readLines(t, bad); err == nil {
			t.Errorf("%s was read", name)
		}
	}
	for name, good := range map[string]processing.Artifact{
		"counts of exchanges": func() processing.Artifact {
			a := connection
			a.ExcludedExchanges = &processing.ExcludedExchanges{ContentCodingUnsupported: "3", ContentDecodingFailed: "10",
				ContentDecodedTooLarge: "0", ContentDecodingTooCostly: "7"}
			return a
		}(),
		"no coding named": withResponse(exchange, func(m *record.Message) {
			m.Body.Content.Codings = nil
			m.Headers = slices.DeleteFunc(m.Headers, func(f record.Field) bool { return f.Name == "Content-Encoding" })
		}),
		"x-gzip read as gzip": withResponse(exchange, func(m *record.Message) {
			m.Headers[len(m.Headers)-1].Value = "x-gzip, identity"
		}),
		"codings beside a replaced header": func() processing.Artifact {
			a := withResponse(exchange, func(m *record.Message) {
				m.Headers = slices.DeleteFunc(m.Headers, func(f record.Field) bool { return f.Name == "Content-Encoding" })
			})
			a.ExtensionOutcomes = []processing.ExtensionOutcome{{Exchange: *a.Index, Extension: "marker",
				Outcome: extension.Changed, Changed: []string{"response.headers"}, Overwritten: []string{}}}
			return a
		}(),
	} {
		if err := readLines(t, good); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	empty, err := json.Marshal(withResponse(exchange, func(*record.Message) {}))
	if err != nil {
		t.Fatal(err)
	}
	empty = bytes.Replace(empty, []byte(`"codings":["gzip"]`), []byte(`"codings":[]`), 1)
	if !bytes.Contains(empty, []byte(`"codings":[]`)) {
		t.Fatal("wiring, not the property: the line carries no codings to empty")
	}
	err = processing.ReadArtifacts(fstest.MapFS{processing.ArtifactName: {Data: append(empty, '\n')}},
		func(processing.Artifact) error { return nil })
	if err == nil {
		t.Error("decoded content naming an empty list of codings was read")
	}
}

// Many exchanges excluded alone on one open connection keep what the worker
// holds for it bounded: the exchanges are counted, and nothing else grows.
func TestManyExclusionsKeepAConnectionsBookkeepingBounded(t *testing.T) {
	const excluded = 200
	r := newReleasing(t, releasingOptions{})
	var calls []call
	for n := range excluded {
		calls = append(calls, codedGet("/x"+strconv.Itoa(n)), read(codedResponse("compress", "xyz")))
	}
	c := converse(t, 1, append(calls, pair("/last")...)...)
	maxEntries := 0
	for n := 0; n < len(c.fragments); n += 2 {
		r.give(c.fragments[n : n+2]...)
		r.drain()
		for _, held := range processing.Connections(r.worker) {
			maxEntries = max(maxEntries, held.Entries)
		}
	}
	held := processing.Connections(r.worker)
	if len(held) != 1 || held[0].Exchanges != excluded+1 {
		t.Fatalf("wiring, not the property: the worker holds %+v, want one connection that handed over %d exchanges",
			held, excluded+1)
	}
	if held[0].Excluded != (processing.Exclusions{ContentCodingUnsupported: excluded}) || held[0].Chain != 0 {
		t.Fatalf("the connection counts %+v excluded with %d on its chain", held[0].Excluded, held[0].Chain)
	}
	if maxEntries > 2 {
		t.Fatalf("the connection held up to %d entries across %d exclusions, want no more than one pair's 2", maxEntries,
			excluded)
	}
	r.writtenAt(1, map[string]int{"/last": excluded})
}
