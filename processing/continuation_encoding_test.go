package processing_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contentcoding"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/reconstruct"
)

type encodingPair struct {
	request, response         string
	reason                    string
	holeRequest, holeResponse bool
}
type encodingCapture struct {
	fragments []fragment.Record
	finals    []connection.Record
}

func (c *encodingCapture) Write(r fragment.Record) error {
	c.fragments = append(c.fragments, r)
	return nil
}
func (c *encodingCapture) Connection(r connection.Record) error {
	c.finals = append(c.finals, r)
	return nil
}

// Capture produces the numbered library-event records. The fixture's prefix
// certificate is derived from those loss-free transfers, before retirement is
// delivered to processing. No kernel or network behaviour is modelled.
func encodingConversation(t *testing.T, pairs []encodingPair) encodingCapture {
	t.Helper()
	var c encodingCapture
	recorder := capture.Recording(&c, &c)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := fragment.Process{PID: 42, StartTime: 7}
	instance := admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42, Start: admission.Determinate(7), Generation: 1}
	for i, pair := range pairs {
		for side, wire := range []string{pair.request, pair.response} {
			direction := fragment.Sent
			if side == 1 {
				direction = fragment.Received
			}
			payload := []byte(wire)
			if side == 0 && pair.holeRequest || side == 1 && pair.holeResponse {
				payload = payload[:len(payload)-len("missing-body")]
			}
			recorder.Transfer(probe.Transfer{Process: p, Instance: instance, Endpoint: 7, Direction: direction, Measured: true, Length: uint32(len(wire)), Payload: payload, Stamp: uint64(2*i + side + 1), Sequence: probe.Sequence{Occupancy: 1, Number: uint64(i + 1), Born: true}, At: at})
		}
	}
	recorder.Closed(probe.Connection{Process: p, Instance: instance, Endpoint: 7, Stamp: uint64(2*len(pairs) + 1), Sequence: probe.Sequence{Occupancy: 1, Born: true}, Final: probe.Final{Known: true, Sent: probe.Terminal{Last: uint64(len(pairs))}, Received: probe.Terminal{Last: uint64(len(pairs))}}, At: at})
	if len(c.fragments) != 2*len(pairs) || len(c.finals) != 1 {
		t.Fatalf("wiring, not the property: capture emitted %d fragments and %d retirements for %d pairs", len(c.fragments), len(c.finals), len(pairs))
	}
	r := c.finals[0]
	identity := &fragment.Identity{Connection: r.ID, Process: p, Instance: instance, Address: 7, Generation: uint64(r.Handle.Generation), NetworkDevice: r.Network.Device, NetworkInode: r.Network.Inode, FirstSeen: r.FirstSeen}
	evidence := fragment.Evidence{Identity: identity, Origin: fragment.OriginBirth, Occupancy: 1}
	for i := range c.fragments {
		f := &c.fragments[i]
		evidence.Through = f.Sequence
		d := &evidence.Sent
		if f.Direction == fragment.Received {
			d = &evidence.Received
		}
		*d = fragment.DirectionEvidence{Limit: f.End(), First: 1, Numbered: f.Produced, Resolved: f.Produced}
		f.Evidence = evidence
		if err := f.Validate(); err != nil {
			t.Fatalf("wiring, not the property: fragment %d: %v", i, err)
		}
		if err := f.Evidenced(); err != nil {
			t.Fatalf("wiring, not the property: prefix %d: %v", i, err)
		}
		if err := r.Agrees(evidence); err != nil {
			t.Fatalf("wiring, not the property: retirement/prefix %d: %v", i, err)
		}
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("wiring, not the property: retirement: %v", err)
	}
	return c
}

func encodingMessage(request bool, index int, fields, body string) string {
	start := "HTTP/1.1 200 OK"
	if request {
		start = fmt.Sprintf("POST /item-%d HTTP/1.1", index)
	}
	return fmt.Sprintf("%s\r\nContent-Length: %d\r\n%s\r\n%s", start, len(body), fields, body)
}
func encodingPlain(index int) encodingPair {
	return encodingPair{request: encodingMessage(true, index, "", "request"), response: encodingMessage(false, index, "", "response")}
}

// encodingBodyBound is the per-message body bound the fixtures run under,
// unless a case carries a body over the work budget.
const encodingBodyBound = 4096

// encodingCostlyBodyBound is the body bound of the cases that carry a brotli
// stream over the work budget. At the published budget such a stream is larger
// than 4096 bytes, and a body over the bound is elided into a stop before any
// decoding, so those cases run under a bound the stream fits.
const encodingCostlyBodyBound = 1 << 20

// encodingReasons is every exclusion reason, in the order the contract ranks
// them between the outcomes two messages established.
var encodingReasons = []string{processing.ReasonContentCodingUnsupported, processing.ReasonContentDecodingFailed, processing.ReasonContentDecodedTooLarge, processing.ReasonContentDecodingTooCostly}

func encodingGzip(t *testing.T, body string) string {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}
func encodingBad(t *testing.T, index int, reason, side string) encodingPair {
	t.Helper()
	return encodingBadWithin(t, index, reason, side, encodingBodyBound)
}

// encodingBadWithin is encodingBad under the body bound the worker runs with:
// the too-large body decodes to one byte over it, and the too-costly body is
// a brotli stream over the work budget that fits under it.
func encodingBadWithin(t *testing.T, index int, reason, side string, bound int) encodingPair {
	t.Helper()
	p := encodingPlain(index)
	fields, body := "Content-Encoding: compress\r\n", "opaque"
	switch reason {
	case processing.ReasonContentDecodingFailed:
		fields, body = "Content-Encoding: gzip\r\n", encodingGzip(t, "corrupt checksum")
		body = body[:len(body)-1]
	case processing.ReasonContentDecodedTooLarge:
		fields, body = "Content-Encoding: gzip\r\n", encodingGzip(t, strings.Repeat("x", bound+1))
	case processing.ReasonContentDecodingTooCostly:
		fields, body = "Content-Encoding: br\r\n", encodingCostly(t, bound)
	}
	if side != "response" {
		p.request = encodingMessage(true, index, fields, body)
	}
	if side != "request" {
		p.response = encodingMessage(false, index, fields, body)
	}
	p.reason = reason
	return p
}

// encodingStacked is an otherwise valid two-coding body, br applied first and
// gzip over it: a stream a stacked decode could undo, which the one-coding
// rule refuses from the header alone.
func encodingStacked(t *testing.T, body string) string {
	t.Helper()
	var b bytes.Buffer
	w := brotli.NewWriter(&b)
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return encodingGzip(t, b.String())
}

// encodingStackedPair is an exchange whose side carries a two-coding body
// under "br, gzip", excluded as content_coding_unsupported.
func encodingStackedPair(t *testing.T, index int, side string) encodingPair {
	t.Helper()
	p := encodingPlain(index)
	fields, body := "Content-Encoding: br, gzip\r\n", encodingStacked(t, "stacked content")
	if side != "response" {
		p.request = encodingMessage(true, index, fields, body)
	}
	if side != "request" {
		p.response = encodingMessage(false, index, fields, body)
	}
	p.reason = processing.ReasonContentCodingUnsupported
	return p
}

// encodingBits writes bits least significant first, as brotli reads them.
type encodingBits struct {
	out []byte
	pos int
}

func (b *encodingBits) put(value uint64, n int) {
	for i := 0; i < n; i++ {
		if b.pos%8 == 0 {
			b.out = append(b.out, 0)
		}
		b.out[len(b.out)-1] |= byte((value>>uint(i))&1) << uint(b.pos%8)
		b.pos++
	}
}

// simple is a simple prefix code with one symbol of the given width.
func (b *encodingBits) simple(symbol uint64, width int) {
	b.put(1, 2)
	b.put(0, 2)
	b.put(symbol, width)
}

// types declares one block type, or 256 with a one-symbol block-type code and
// block lengths of one.
func (b *encodingBits) types(count int) {
	if count == 1 {
		b.put(0, 1)
		return
	}
	b.put(1, 1)
	b.put(7, 3)
	b.put(127, 7)
	b.simple(0, 9)
	b.simple(0, 5)
	b.put(0, 2)
}

// encodingCostlyBrotli is a brotli stream of count compressed metablocks, each
// producing one "a" while declaring 256 literal and 256 distance block types
// with all-zero context maps, then the last, empty metablock. Its work grows
// with count while its output is count bytes, which is what the work budget
// exists to refuse.
func encodingCostlyBrotli(count int) []byte {
	var b encodingBits
	b.put(1, 1)
	b.put(0, 3)
	b.put(2, 3) // WBITS 10
	for i := 0; i < count; i++ {
		b.put(0, 1)
		b.put(0, 2)
		b.put(0, 16)
		b.put(0, 1) // a non-last compressed metablock of length 1
		b.types(256)
		b.types(1)
		b.types(256)
		b.put(0, 6) // distance postfix and direct distance bits
		for t := 0; t < 256; t++ {
			b.put(0, 2) // the literal context mode of each literal block type
		}
		b.put(0, 1)
		b.put(0, 1) // one literal tree and one distance tree: all-zero context maps
		b.simple('a', 8)
		b.simple(8, 10)
		b.simple(0, 6) // the sole command inserts one literal
	}
	b.put(1, 1)
	b.put(1, 1) // the last, empty metablock
	return b.out
}

// encodingCostly is a brotli stream over the work budget that fits under bound
// encoded and decodes, by a decoder without a budget, to fewer than bound
// bytes. Two guards: the upstream reader decodes it whole, so the only thing
// the observer's decoder can hold against it is its cost; and the observer's
// decoder does find it too costly, so a case built on it measures the fourth
// reason and nothing else.
func encodingCostly(t *testing.T, bound int) string {
	t.Helper()
	count := bound / 128
	stream := encodingCostlyBrotli(count)
	if len(stream) > bound {
		t.Fatalf("wiring, not the property: the costly fixture is %d bytes, over the body bound %d", len(stream), bound)
	}
	plain, err := io.ReadAll(brotli.NewReader(bytes.NewReader(stream)))
	if err != nil || len(plain) != count || strings.Trim(string(plain), "a") != "" {
		t.Fatalf("wiring, not the property: the costly fixture is not a valid brotli stream of %d bytes: %d bytes, %v", count, len(plain), err)
	}
	list, verdict := contentcoding.ParseList([]string{"br"})
	if verdict != contentcoding.Supported {
		t.Fatalf("wiring, not the property: br is not a supported coding: %v", verdict)
	}
	result := contentcoding.Decode(list, stream, contentcoding.Options{Bound: bound})
	if result.Outcome != contentcoding.DecodingTooCostly {
		t.Fatalf("wiring, not the property: the decoder did not find the costly fixture too costly (outcome %v): pending the work counter, or the fixture needs more work per byte", result.Outcome)
	}
	return string(stream)
}

type encodingOutput struct {
	lines     [][]byte
	artifacts []processing.Artifact
}

func (o *encodingOutput) WriteApproved(_ context.Context, a processing.Approved) error {
	var artifact processing.Artifact
	line := a.Bytes()
	if err := json.Unmarshal(line, &artifact); err != nil {
		return err
	}
	o.lines = append(o.lines, append([]byte(nil), line...))
	o.artifacts = append(o.artifacts, artifact)
	return nil
}

type encodingWorker struct {
	charges      []processing.DecodeCharge
	onCharge     func(processing.DecodeCharge)
	finalOutcome *processing.Outcome
	worker       *processing.Worker
	store        *intake.Store
	output       *encodingOutput
	taken        int
}

func encodingNew(t *testing.T, extra string) *encodingWorker {
	t.Helper()
	return encodingBounded(t, extra, 4096)
}
func encodingBounded(t *testing.T, extra string, inputBound int) *encodingWorker {
	t.Helper()
	return encodingWorkerWithin(t, extra, inputBound, encodingBodyBound)
}

// encodingWorkerWithin is a worker under the given pending-input and body
// bounds.
func encodingWorkerWithin(t *testing.T, extra string, inputBound, bodyBound int) *encodingWorker {
	t.Helper()
	compiled, findings := config.Compile([]byte(`{"version":"observer.config/1","output":"/var/lib/observer","write_content":true,"watch":[{"name":"api","exe":"/usr/bin/php"}]`+extra+`}`), "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: config: %+v", findings)
	}
	f := &encodingWorker{output: &encodingOutput{}}
	var err error
	f.store, err = intake.New(64 << 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1 << 20, IntakeExhausted: f.store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	options := processing.Options{Session: "encoding-continuation", PolicyRevision: "fixture", Plan: compiled.Plan, Intake: f.store, Gate: gate, Output: f.output, ConnectionInput: inputBound, Limits: reconstruct.Limits{HTTP: http1.Limits{MaxBodyBytes: bodyBound}}, Taken: func(int, fragment.Process, fragment.ConnectionID) { f.taken++ }}
	options = processing.ObserveDecodeCharges(options, func(e processing.DecodeCharge) {
		f.charges = append(f.charges, e)
		if f.onCharge != nil {
			f.onCharge(e)
		}
	})
	f.worker, err = processing.New(options)
	if err != nil {
		t.Fatalf("wiring, not the property: worker: %v", err)
	}
	t.Cleanup(func() { _ = f.worker.Close() })
	return f
}
func (f *encodingWorker) feed(t *testing.T, fragments []fragment.Record) processing.Outcome {
	t.Helper()
	before := f.taken
	for _, r := range fragments {
		if err := f.store.Write(r); err != nil {
			t.Fatalf("wiring, not the property: intake: %v", err)
		}
	}
	out, err := f.worker.Drain(context.Background())
	if f.taken-before != len(fragments) {
		t.Fatalf("wiring, not the property: worker took %d of %d supplied fragments", f.taken-before, len(fragments))
	}
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if f.store.Stats().Connections != 0 {
		t.Fatal("wiring, not the property: retirement reached processing before online assertions")
	}
	return out
}
func (f *encodingWorker) retire(t *testing.T, r connection.Record) processing.Outcome {
	t.Helper()
	before := f.taken
	if err := f.store.Connection(r); err != nil {
		t.Fatalf("wiring, not the property: retirement intake: %v", err)
	}
	out, err := f.worker.Drain(context.Background())
	if f.taken != before+1 {
		t.Fatalf("wiring, not the property: retirement not consumed, taken %d -> %d", before, f.taken)
	}
	if err != nil {
		t.Fatal(err)
	}
	f.finalOutcome = &out
	return out
}
func (f *encodingWorker) roundtrip(t *testing.T) {
	t.Helper()
	data := bytes.Join(f.output.lines, nil)
	count := 0
	err := processing.ReadArtifactFiles(fstest.MapFS{"approved.jsonl": &fstest.MapFile{Data: data}}, []string{"approved.jsonl"}, "encoding-continuation", func(a processing.Artifact) error { count++; return nil })
	if err != nil {
		t.Errorf("shipped reader refused written lines: %v", err)
	}
	if count != len(f.output.lines) {
		t.Errorf("reader returned %d of %d written lines", count, len(f.output.lines))
	}
}
func encodingExpected(pairs []encodingPair) processing.Exclusions {
	var e processing.Exclusions
	for _, p := range pairs {
		switch p.reason {
		case processing.ReasonContentCodingUnsupported:
			e.ContentCodingUnsupported++
		case processing.ReasonContentDecodingFailed:
			e.ContentDecodingFailed++
		case processing.ReasonContentDecodedTooLarge:
			e.ContentDecodedTooLarge++
		case processing.ReasonContentDecodingTooCostly:
			e.ContentDecodingTooCostly++
		}
	}
	return e
}
func (f *encodingWorker) checkOnline(t *testing.T, pairs []encodingPair, out processing.Outcome) {
	t.Helper()
	var expected []int
	for i, p := range pairs {
		if p.reason == "" {
			expected = append(expected, i)
		}
	}
	var exchanges []processing.Artifact
	for _, a := range f.output.artifacts {
		if a.Record == processing.ArtifactExchange {
			exchanges = append(exchanges, a)
		} else {
			t.Error("connection retired before close")
		}
	}
	if len(exchanges) != len(expected) {
		t.Errorf("before close: wrote %d exchanges, want indexes %v", len(exchanges), expected)
	}
	for n, a := range exchanges {
		if n >= len(expected) {
			break
		}
		index := expected[n]
		id, err := strconv.ParseUint(a.ExchangeID, 10, 64)
		if err != nil || id != uint64(index+1) || a.Index == nil || *a.Index != index {
			t.Errorf("exchange %d: id/index %q/%v, want %d/%d", n, a.ExchangeID, a.Index, index+1, index)
		}
		if a.Reconstruction == nil || len(a.Reconstruction.Exchanges) != 1 {
			t.Errorf("exchange %d lacks paired content", n)
			continue
		}
		x := a.Reconstruction.Exchanges[0]
		if x.Request.Message == nil || x.Request.Message.Target != fmt.Sprintf("/item-%d", index) {
			t.Errorf("exchange %d contains the wrong request", n)
		}
		for side, m := range []*record.Message{x.Request.Message, x.Response.Message} {
			if m == nil {
				t.Errorf("exchange %d missing side %d", index, side)
				continue
			}
			if m.Body.Content != nil {
				t.Errorf("written identity or zero-body fixture acquired decoding metadata at exchange %d side %d", index, side)
			}
			start := 0
			for _, p := range pairs[:index] {
				if side == 0 {
					start += len(p.request)
				} else {
					start += len(p.response)
				}
			}
			wire := pairs[index].request
			direction := "sent"
			if side == 1 {
				wire = pairs[index].response
				direction = "received"
			}
			offset, offsetErr := strconv.ParseUint(m.Stream.Offset, 10, 64)
			end, endErr := strconv.ParseUint(m.Stream.End, 10, 64)
			if offsetErr != nil || endErr != nil || offset != uint64(start) || end != uint64(start+len(wire)) || m.Stream.Direction != direction {
				t.Errorf("exchange %d side %d wire extent=%+v, want %s %d-%d", index, side, m.Stream, direction, start, start+len(wire))
			}
			if strings.Contains(wire, "Content-Length:") && !strings.HasPrefix(pairs[index].request, "HEAD ") && m.Structure.State != "removed" {
				_, body, _ := strings.Cut(wire, "\r\n\r\n")
				kept, err := base64.StdEncoding.DecodeString(m.Body.Kept)
				if err != nil || string(kept) != body {
					t.Errorf("exchange %d side %d content changed or next-message bytes consumed: %q, want %q", index, side, kept, body)
				}
			}
		}
	}
	if out.Excluded != encodingExpected(pairs) {
		t.Errorf("exclusions before close: %+v, want %+v", out.Excluded, encodingExpected(pairs))
	}
	if out.Withheld != connection.Counted(0) || out.ProcessingFailures != 0 || out.OutputFailures != 0 {
		t.Errorf("isolated exclusions changed legacy counts: withheld=%+v processing=%d output=%d", out.Withheld, out.ProcessingFailures, out.OutputFailures)
	}
}
func (f *encodingWorker) checkFinal(t *testing.T, pairs []encodingPair, cut bool) {
	t.Helper()
	if f.finalOutcome == nil {
		t.Fatal("wiring, not the property: final outcome not supplied")
	}
	if !cut {
		o := *f.finalOutcome
		if o.Withheld != connection.Counted(0) || o.ProcessingFailures != 0 || o.OutputFailures != 0 {
			t.Errorf("retirement counted isolated exclusions as legacy failure: %+v", o)
		}
	}
	connections := 0
	want := encodingExpected(pairs)
	for _, a := range f.output.artifacts {
		if a.Record != processing.ArtifactConnection {
			continue
		}
		connections++
		if a.Version != processing.ArtifactVersion5 {
			t.Errorf("connection version=%s, want %s", a.Version, processing.ArtifactVersion5)
		}
		if a.ExcludedExchanges == nil {
			t.Error("connection lacks isolated-exclusion totals")
			continue
		}
		for _, c := range []struct {
			got  string
			want uint64
		}{{a.ExcludedExchanges.ContentCodingUnsupported, want.ContentCodingUnsupported}, {a.ExcludedExchanges.ContentDecodingFailed, want.ContentDecodingFailed}, {a.ExcludedExchanges.ContentDecodedTooLarge, want.ContentDecodedTooLarge}, {a.ExcludedExchanges.ContentDecodingTooCostly, want.ContentDecodingTooCostly}} {
			n, err := strconv.ParseUint(c.got, 10, 64)
			if err != nil || n != c.want {
				t.Errorf("connection exclusion count %q, want %d", c.got, c.want)
			}
		}
		if !cut && a.ReconstructionTruncation != nil {
			t.Errorf("ordinary retirement has a terminal suffix: %+v", a.ReconstructionTruncation)
		}
	}
	if connections != 1 {
		t.Errorf("connection lines=%d, want 1", connections)
	}
	f.roundtrip(t)
}

func TestEncodingExclusionsContinueBeforeClose(t *testing.T) {
	for _, reason := range encodingReasons {
		for _, side := range []string{"request", "response", "both"} {
			t.Run(reason+"/"+side, func(t *testing.T) {
				pairs := []encodingPair{encodingPlain(0), encodingBadWithin(t, 1, reason, side, encodingCostlyBodyBound), encodingBadWithin(t, 2, reason, side, encodingCostlyBodyBound), encodingPlain(3)}
				c := encodingConversation(t, pairs)
				f := encodingWorkerWithin(t, "", 4096, encodingCostlyBodyBound)
				var out processing.Outcome
				for i := range pairs {
					out = f.feed(t, c.fragments[2*i:2*i+2])
				}
				f.checkOnline(t, pairs, out)
				out = f.retire(t, c.finals[0])
				if out.Excluded != encodingExpected(pairs) {
					t.Errorf("retirement changed counts: %+v", out.Excluded)
				}
				f.checkFinal(t, pairs, false)
			})
		}
	}
}

func TestEncodingZeroBodiesAndIdentityLeaveNextPairIntact(t *testing.T) {
	for _, side := range []string{"request", "response"} {
		for _, kind := range []string{"length-zero", "empty-chunked", "empty-chunked-trailers", "identity-list", "identity-fields", "head"} {
			if kind == "head" && side == "request" {
				continue
			}
			t.Run(side+"/"+kind, func(t *testing.T) {
				pairs := []encodingPair{encodingPlain(0), encodingPlain(1), encodingPlain(2)}
				request := side == "request"
				wire := encodingMessage(request, 1, "Content-Encoding: gzip\r\n", "")
				switch kind {
				case "empty-chunked", "empty-chunked-trailers":
					start := "HTTP/1.1 200 OK"
					if request {
						start = "POST /item-1 HTTP/1.1"
					}
					ending := "0\r\n\r\n"
					if kind == "empty-chunked-trailers" {
						ending = "0\r\nX-End: present\r\n\r\n"
					}
					wire = start + "\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" + ending
				case "identity-list":
					wire = encodingMessage(request, 1, "Content-Encoding: identity, identity\r\n", "identity content")
				case "identity-fields":
					wire = encodingMessage(request, 1, "Content-Encoding: identity\r\nContent-Encoding: identity\r\n", "identity content")
				case "head":
					pairs[1].request = "HEAD /item-1 HTTP/1.1\r\nHost: local\r\n\r\n"
					wire = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 912\r\n\r\n"
				}
				if request {
					pairs[1].request = wire
				} else {
					pairs[1].response = wire
				}
				c := encodingConversation(t, pairs)
				f := encodingNew(t, "")
				out := f.feed(t, c.fragments)
				f.checkOnline(t, pairs, out)
				for _, a := range f.output.artifacts {
					if a.Reconstruction != nil {
						for _, x := range a.Reconstruction.Exchanges {
							for _, s := range []bool{true, false} {
								m := x.Request.Message
								if !s {
									m = x.Response.Message
								}
								if m != nil && m.Body.Content != nil {
									t.Error("identity or zero body acquired decoding metadata")
								}
							}
						}
					}
				}
				encodingNoDecodeAdmission(t, f.charges)
				f.retire(t, c.finals[0])
				f.checkFinal(t, pairs, false)
			})
		}
	}
}

func TestEncodingMixedReasonsCountOnce(t *testing.T) {
	reasons := encodingReasons
	for i, requestReason := range reasons {
		for j, responseReason := range reasons {
			if i == j {
				continue
			}
			t.Run(requestReason+"/"+responseReason, func(t *testing.T) {
				b := encodingBadWithin(t, 1, requestReason, "request", encodingCostlyBodyBound)
				b.response = encodingBadWithin(t, 1, responseReason, "response", encodingCostlyBodyBound).response
				b.reason = reasons[min(i, j)]
				pairs := []encodingPair{encodingPlain(0), b, encodingPlain(2)}
				c := encodingConversation(t, pairs)
				f := encodingWorkerWithin(t, "", 4096, encodingCostlyBodyBound)
				out := f.feed(t, c.fragments)
				f.checkOnline(t, pairs, out)
				f.retire(t, c.finals[0])
				f.checkFinal(t, pairs, false)
			})
		}
	}
}

func TestEncodingRemovalDoesNotTurnCapturedContentIntoZeroBody(t *testing.T) {
	pairs := []encodingPair{encodingPlain(0), encodingBad(t, 1, processing.ReasonContentDecodingFailed, "both"), encodingPlain(2)}
	c := encodingConversation(t, pairs)
	f := encodingNew(t, `,"remove":{"bodies":["request","response"]}`)
	out := f.feed(t, c.fragments)
	f.checkOnline(t, pairs, out)
	f.retire(t, c.finals[0])
	f.checkFinal(t, pairs, false)
}

func TestEncodingConsumedHistoryStaysBounded(t *testing.T) {
	const count = 257
	pairs := make([]encodingPair, count)
	pairs[0] = encodingPlain(0)
	// The three cheap reasons: a body over the work budget is hundreds of
	// kilobytes, and 85 of them would measure the fixture, not the subject.
	reasons := encodingReasons[:3]
	for i := 1; i < count-1; i++ {
		pairs[i] = encodingBad(t, i, reasons[(i-1)%len(reasons)], "both")
	}
	pairs[count-1] = encodingPlain(count - 1)
	c := encodingConversation(t, pairs)
	f := encodingNew(t, "")
	var out processing.Outcome
	for i := range pairs {
		out = f.feed(t, c.fragments[2*i:2*i+2])
		held := processing.Connections(f.worker)
		if len(held) != 1 {
			t.Fatalf("wiring, not the property: expected one held connection, got %d", len(held))
		}
		h := held[0]
		if h.Exchanges != i+1 || h.Excluded != encodingExpected(pairs[:i+1]) {
			t.Errorf("consumed history at %d: exchanges=%d exclusions=%+v", i, h.Exchanges, h.Excluded)
		}
		if h.Entries != 0 || h.Pending != 0 || h.Bytes != 0 || h.Chain != 0 || h.Parsing > processing.ReadingCharge {
			t.Errorf("consumed history grew at %d: %+v", i, h)
		}
		stats := f.store.Stats()
		if stats.Bytes != 0 || stats.Leased != 0 || stats.Policy != 0 || stats.Parsing > processing.ReadingCharge {
			t.Errorf("after consumed pair %d retained bytes/leases/policy/parsing=%d/%d/%d/%d (fixed reading=%d)", i, stats.Bytes, stats.Leased, stats.Policy, stats.Parsing, processing.ReadingCharge)
		}
		// The expected stores and bounds come from the one live connection and
		// zero outstanding calls, not from whichever stores the subject reports.
		stores, err := f.worker.Retained()
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"processing.batches", "processing.order", "processing.entries", "processing.fragments", "processing.waiting_exchanges", "processing.waiting_exchanges_capacity", "processing.waiting_bodies"} {
			found := false
			limit := 0
			if name == "processing.batches" || name == "processing.order" {
				limit = 1
			}
			for _, s := range stores {
				if s.Store == name {
					found = true
					if s.Held > limit {
						t.Errorf("after pair %d %s retains %d, bound %d", i, name, s.Held, limit)
					}
				}
			}
			if !found {
				t.Fatalf("wiring, not the property: missing retained store %s", name)
			}
		}
	}
	f.checkOnline(t, pairs, out)
	f.retire(t, c.finals[0])
	f.checkFinal(t, pairs, false)
	stats := f.store.Stats()
	if stats.Bytes != 0 || stats.Parsing != 0 || stats.Policy != 0 || stats.Leased != 0 {
		t.Errorf("retirement leaked charges: %+v", stats)
	}
}

func encodingStoppedWire(kind string, request bool, index int, coding string) string {
	start := "HTTP/1.1 200 OK"
	if request {
		start = fmt.Sprintf("POST /item-%d HTTP/1.1", index)
	}
	fields := ""
	if coding != "" {
		fields = "Content-Encoding: " + coding + "\r\n"
	}
	switch kind {
	case "malformed":
		return start + "\r\nBroken Header\r\n" + fields + "Content-Length: 1\r\n\r\nx"
	case "malformed-coding":
		return encodingMessage(request, index, fields+"Content-Encoding: gzip;invalid\r\n", "")
	case "ambiguous-empty":
		return start + "\r\n" + fields + "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
	case "protocol":
		return strings.Replace(encodingMessage(request, index, fields, "x"), "HTTP/1.1", "HTTP/2.0", 1)
	case "informational":
		return "HTTP/1.1 103 Early Hints\r\n" + fields + "\r\n"
	case "connect":
		return "CONNECT local:443 HTTP/1.1\r\nHost: local\r\n" + fields + "\r\n"
	case "upgrade":
		return encodingMessage(request, index, fields+"Upgrade: websocket\r\nConnection: Upgrade\r\n", "x")
	case "until-close":
		return start + "\r\n" + fields + "\r\nx"
	case "transfer-coding":
		return start + "\r\n" + fields + "Transfer-Encoding: compress\r\n\r\nx"
	case "elided":
		return encodingMessage(request, index, fields, strings.Repeat("x", 4097))
	case "hole":
		return encodingMessage(request, index, fields, "missing-body")
	}
	panic(kind)
}

func TestEncodingNeverBypassesTerminalStops(t *testing.T) {
	for _, kind := range []string{"malformed", "malformed-coding", "ambiguous-empty", "protocol", "informational", "connect", "upgrade", "until-close", "transfer-coding", "elided", "hole"} {
		for _, side := range []string{"request", "response"} {
			if (kind == "informational" || kind == "until-close") && side == "request" || kind == "connect" && side == "response" {
				continue
			}
			for _, encodingSide := range []string{"none", "request", "response"} {
				for _, codingName := range []string{"compress", "gzip"} {
					if encodingSide == "none" && codingName == "gzip" {
						continue
					}
					t.Run(kind+"/"+side+"/coding-"+encodingSide+"-"+codingName, func(t *testing.T) {
						pairs := []encodingPair{encodingPlain(0), encodingPlain(1), encodingPlain(2)}
						request := side == "request"
						coding := ""
						if encodingSide == side {
							coding = codingName
						}
						wire := encodingStoppedWire(kind, request, 1, coding)
						if request {
							pairs[1].request = wire
						} else {
							pairs[1].response = wire
						}
						if encodingSide != "none" && encodingSide != side {
							reason := processing.ReasonContentCodingUnsupported
							if codingName == "gzip" {
								reason = processing.ReasonContentDecodingFailed
							}
							other := encodingBad(t, 1, reason, encodingSide)
							if encodingSide == "request" {
								pairs[1].request = other.request
							} else {
								pairs[1].response = other.response
							}
						}
						if kind == "hole" {
							pairs[1].holeRequest = request
							pairs[1].holeResponse = !request
						}
						c := encodingConversation(t, pairs)
						if kind == "hole" {
							at := 2
							if !request {
								at = 3
							}
							if err := c.fragments[at].Validate(); err != nil {
								t.Fatalf("wiring, not the property: hole fixture invalid: %v", err)
							}
							if !c.fragments[at].Truncated() {
								t.Fatal("wiring, not the property: hole fixture has no missing bytes")
							}
						}
						f := encodingNew(t, "")
						// The ordinary prefix proves the same live connection can release.
						prefix := f.feed(t, c.fragments[:2])
						f.checkOnline(t, pairs[:1], prefix)
						out := f.feed(t, c.fragments[2:])
						for _, a := range f.output.artifacts {
							if a.Record == processing.ArtifactExchange && (a.Index == nil || *a.Index != 0) {
								t.Errorf("content crossed %s terminal boundary before close: index=%v", kind, a.Index)
							}
						}
						out = f.retire(t, c.finals[0])
						encodingNoDecodeAdmission(t, f.charges)
						if out.Excluded.Total() != 0 {
							t.Errorf("terminal stop was counted as isolated exclusion: %+v", out.Excluded)
						}
						connections := 0
						for _, a := range f.output.artifacts {
							if a.Record == processing.ArtifactExchange {
								if a.Index == nil || *a.Index != 0 {
									t.Errorf("content resynchronised beyond %s: index=%v", kind, a.Index)
								}
								continue
							}
							connections++
							if a.ReconstructionTruncation == nil || len(a.ReconstructionTruncation.Stops) == 0 {
								t.Errorf("terminal %s lost its suffix metadata", kind)
							}
							if a.ExcludedExchanges != nil && *a.ExcludedExchanges != (processing.ExcludedExchanges{ContentCodingUnsupported: "0", ContentDecodingFailed: "0", ContentDecodedTooLarge: "0", ContentDecodingTooCostly: "0"}) {
								t.Errorf("terminal %s acquired isolated totals: %+v", kind, a.ExcludedExchanges)
							}
						}
						if connections != 1 {
							t.Errorf("terminal %s produced %d final connection lines", kind, connections)
						}
						f.roundtrip(t)
					})
				}
			}
		}
	}
}

func TestEncodingLaterCutStartsAfterAccountedPair(t *testing.T) {
	reasons := encodingReasons
	for i, first := range reasons {
		for j, second := range reasons {
			for _, continued := range []bool{false, true} {
				t.Run(first+"/"+second+fmt.Sprintf("/continued-%t", continued), func(t *testing.T) {
					b := encodingBadWithin(t, 1, first, "request", encodingCostlyBodyBound)
					b.response = encodingBadWithin(t, 1, second, "response", encodingCostlyBodyBound).response
					// The ranking is the contract's order, independent of the implementation.
					b.reason = reasons[min(i, j)]
					prefix := []encodingPair{encodingPlain(0), b}
					if continued {
						prefix = append(prefix, encodingPlain(2))
					}
					pairs := append([]encodingPair(nil), prefix...)
					const pending = 6
					for range pending {
						pairs = append(pairs, encodingPlain(len(pairs)))
					}
					c := encodingConversation(t, pairs)
					f := encodingWorkerWithin(t, "", 4, encodingCostlyBodyBound)
					var out processing.Outcome
					for i := range prefix {
						out = f.feed(t, c.fragments[2*i:2*i+2])
					}
					f.checkOnline(t, prefix, out)
					// Withhold responses to fill the connection's pending-input allowance.
					// The remaining captures arrive only after that cut has occurred.
					for i := len(prefix); i < len(pairs); i++ {
						out = f.feed(t, c.fragments[2*i:2*i+1])
					}
					if out.ConnectionsCut != 1 || out.AllowanceCut != 0 {
						t.Fatalf("wiring, not the property: pending requests did not make the intended connection-input cut: %+v", out)
					}
					for i := len(prefix); i < len(pairs); i++ {
						out = f.feed(t, c.fragments[2*i+1:2*i+2])
					}
					if out.InputCut != 2*pending {
						t.Errorf("cut discarded %d entries, want %d", out.InputCut, 2*pending)
					}
					out = f.retire(t, c.finals[0])
					if out.Excluded != encodingExpected(prefix) {
						t.Errorf("later cut overwrote known reasons: %+v, want %+v", out.Excluded, encodingExpected(prefix))
					}
					wantWritten := 1
					if continued {
						wantWritten++
					}
					written := 0
					for _, a := range f.output.artifacts {
						if a.Record == processing.ArtifactExchange {
							written++
							if a.Index == nil || (*a.Index != 0 && (!continued || *a.Index != 2)) {
								t.Errorf("cut released unaccounted suffix: index=%v", a.Index)
							}
							continue
						}
						tr := a.ReconstructionTruncation
						if tr == nil || len(tr.Stops) != 2 {
							t.Errorf("cut has no two-direction suffix: %+v", tr)
							continue
						}
						for _, stop := range tr.Stops {
							expected := uint64(0)
							for _, p := range prefix {
								switch stop.Direction {
								case "sent":
									expected += uint64(len(p.request))
								case "received":
									expected += uint64(len(p.response))
								default:
									t.Errorf("unknown stop direction %q", stop.Direction)
								}
							}
							got, err := strconv.ParseUint(stop.Offset, 10, 64)
							if err != nil || got != expected || stop.Reason != processing.TruncationConnectionCut {
								t.Errorf("cut suffix=%+v, want accounted boundary %d and connection_cut", stop, expected)
							}
						}
					}
					if written != wantWritten {
						t.Errorf("released prefix changed after cut: %d exchanges, want %d", written, wantWritten)
					}
					f.checkFinal(t, prefix, true)
					stats := f.store.Stats()
					if stats.Bytes != 0 || stats.Parsing != 0 || stats.Policy != 0 || stats.Leased != 0 {
						t.Errorf("cut cleanup left charges: %+v", stats)
					}
				})
			}
		}
	}
}

func TestEncodingHeaderChecksPrecedeBodyAndRemoval(t *testing.T) {
	for _, side := range []string{"request", "response", "both"} {
		for _, fields := range []string{"Content-Encoding: gzip, compress\r\n", "Content-Encoding: compress\r\nContent-Encoding: gzip\r\n", "Content-Encoding: gzip, gzip\r\n"} {
			for _, remove := range []bool{false, true} {
				t.Run(side+"/"+strings.ReplaceAll(strings.TrimSpace(fields), "\r\n", ";")+fmt.Sprintf("/remove-%t", remove), func(t *testing.T) {
					b := encodingPlain(1)
					if side != "response" {
						b.request = encodingMessage(true, 1, fields, "not a gzip stream")
					}
					if side != "request" {
						b.response = encodingMessage(false, 1, fields, "not a gzip stream")
					}
					b.reason = processing.ReasonContentCodingUnsupported
					pairs := []encodingPair{encodingPlain(0), b, encodingPlain(2)}
					extra := ""
					if remove {
						extra = `,"remove":{"headers":["content-encoding"],"bodies":["request","response"]}`
					}
					c := encodingConversation(t, pairs)
					f := encodingNew(t, extra)
					out := f.feed(t, c.fragments)
					f.checkOnline(t, pairs, out)
					encodingNoDecodeAdmission(t, f.charges)
					f.retire(t, c.finals[0])
					f.checkFinal(t, pairs, false)
				})
			}
		}
	}
}

func TestEncodingTwoCodingsExcludedAloneWithoutDecoding(t *testing.T) {
	for _, side := range []string{"request", "response", "both"} {
		t.Run(side, func(t *testing.T) {
			pairs := []encodingPair{encodingPlain(0), encodingStackedPair(t, 1, side), encodingPlain(2)}
			c := encodingConversation(t, pairs)
			f := encodingNew(t, "")
			out := f.feed(t, c.fragments)
			f.checkOnline(t, pairs, out)
			encodingNoDecodeAdmission(t, f.charges)
			f.retire(t, c.finals[0])
			f.checkFinal(t, pairs, false)
		})
	}
}

func TestEncodingBoundedOutcomeDoesNotSeekLaterChecksumFailure(t *testing.T) {
	for _, side := range []string{"request", "response", "both"} {
		t.Run(side, func(t *testing.T) {
			body := []byte(encodingGzip(t, strings.Repeat("x", 4097)))
			body[len(body)-8] ^= 0xff
			b := encodingPlain(1)
			if side != "response" {
				b.request = encodingMessage(true, 1, "Content-Encoding: gzip\r\n", string(body))
			}
			if side != "request" {
				b.response = encodingMessage(false, 1, "Content-Encoding: gzip\r\n", string(body))
			}
			b.reason = processing.ReasonContentDecodedTooLarge
			pairs := []encodingPair{encodingPlain(0), b, encodingPlain(2)}
			c := encodingConversation(t, pairs)
			f := encodingNew(t, "")
			out := f.feed(t, c.fragments)
			f.checkOnline(t, pairs, out)
			f.retire(t, c.finals[0])
			f.checkFinal(t, pairs, false)
		})
	}
}

func encodingCheckSuffixBoundary(t *testing.T, output *encodingOutput, prefix []encodingPair) {
	t.Helper()
	for _, a := range output.artifacts {
		if a.Record == processing.ArtifactExchange {
			if a.Index == nil || *a.Index >= len(prefix) {
				t.Errorf("content crossed later capture-hole boundary: index=%v", a.Index)
			}
			continue
		}
		tr := a.ReconstructionTruncation
		if tr == nil || len(tr.Stops) == 0 {
			t.Error("later capture hole has no suffix metadata")
			continue
		}
		for _, stop := range tr.Stops {
			want := 0
			for _, p := range prefix {
				switch stop.Direction {
				case "sent":
					want += len(p.request)
				case "received":
					want += len(p.response)
				default:
					t.Errorf("invalid suffix direction %q", stop.Direction)
				}
			}
			got, err := strconv.ParseUint(stop.Offset, 10, 64)
			if err != nil || got != uint64(want) {
				t.Errorf("later hole suffix starts at %q, want after accounted prefix %d", stop.Offset, want)
			}
		}
	}
}
func TestEncodingLaterHolePreservesExclusionReason(t *testing.T) {
	for _, reason := range encodingReasons {
		for _, side := range []string{"request", "response"} {
			// The hole follows the excluded pair directly, or a written pair
			// after it: only the first tells whether the exclusion itself moved
			// the accounted boundary.
			for _, continued := range []bool{false, true} {
				t.Run(reason+"/"+side+fmt.Sprintf("/continued-%t", continued), func(t *testing.T) {
					prefix := []encodingPair{encodingPlain(0), encodingBadWithin(t, 1, reason, "both", encodingCostlyBodyBound)}
					if continued {
						prefix = append(prefix, encodingPlain(2))
					}
					at := len(prefix)
					hole := encodingPlain(at)
					if side == "request" {
						hole.request = encodingMessage(true, at, "", "missing-body")
						hole.holeRequest = true
					} else {
						hole.response = encodingMessage(false, at, "", "missing-body")
						hole.holeResponse = true
					}
					pairs := append(append([]encodingPair(nil), prefix...), hole, encodingPlain(at+1))
					c := encodingConversation(t, pairs)
					f := encodingWorkerWithin(t, "", 4096, encodingCostlyBodyBound)
					out := f.feed(t, c.fragments[:2*len(prefix)])
					f.checkOnline(t, prefix, out)
					f.feed(t, c.fragments[2*len(prefix):])
					out = f.retire(t, c.finals[0])
					if out.Excluded != encodingExpected(prefix) {
						t.Errorf("later hole overwrote known reason: %+v, want %+v", out.Excluded, encodingExpected(prefix))
					}
					encodingCheckSuffixBoundary(t, f.output, prefix)
					f.checkFinal(t, prefix, true)
				})
			}
		}
	}
}
