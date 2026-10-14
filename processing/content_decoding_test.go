package processing_test

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
	"github.com/klauspost/compress/zstd"
)

// Every byte and stream offset expected below comes from these wire fixtures.
// The retirement is captured to validate identity, but is withheld from the
// worker until all open-connection assertions have been made.
type contentCapture struct {
	fragments []fragment.Record
	finals    []connection.Record
}

func (c *contentCapture) Write(f fragment.Record) error {
	c.fragments = append(c.fragments, f)
	return nil
}
func (c *contentCapture) Connection(r connection.Record) error {
	c.finals = append(c.finals, r)
	return nil
}
func contentCaptured(t *testing.T, requests, responses []byte, fragmented bool) contentCapture {
	t.Helper()
	var c contentCapture
	recorder := capture.Recording(&c, &c)
	p := fragment.Process{PID: 42, StartTime: 7}
	instance := admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42, Start: admission.Determinate(7), Generation: 1}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var stamp uint64
	var totals [2]uint64
	for side, wire := range [][]byte{requests, responses} {
		direction := fragment.Sent
		if side == 1 {
			direction = fragment.Received
		}
		step := len(wire)
		if fragmented {
			step = 17
		}
		for off := 0; off < len(wire); off += step {
			part := wire[off:min(off+step, len(wire))]
			stamp++
			totals[side]++
			recorder.Transfer(probe.Transfer{Process: p, Instance: instance, Endpoint: 71, Direction: direction, Measured: true, Length: uint32(len(part)), Payload: part, Stamp: stamp, Sequence: probe.Sequence{Occupancy: 1, Number: totals[side], Born: true}, At: at})
		}
	}
	recorder.Closed(probe.Connection{Process: p, Instance: instance, Endpoint: 71, Stamp: stamp + 1, Sequence: probe.Sequence{Occupancy: 1, Born: true}, Final: probe.Final{Known: true, Sent: probe.Terminal{Last: totals[0]}, Received: probe.Terminal{Last: totals[1]}}, At: at})
	if len(c.finals) != 1 || len(c.fragments) != int(totals[0]+totals[1]) {
		t.Fatalf("wiring, not the property: capture produced %d fragments and %d retirements", len(c.fragments), len(c.finals))
	}
	r := &c.finals[0]
	identity := &fragment.Identity{Connection: r.ID, Process: p, Instance: instance, Address: 71, Generation: uint64(r.Handle.Generation), NetworkDevice: r.Network.Device, NetworkInode: r.Network.Inode, FirstSeen: r.FirstSeen}
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
		if err := f.Evidenced(); err != nil {
			t.Fatalf("wiring, not the property: uncertified fragment: %v", err)
		}
		if err := r.Agrees(evidence); err != nil {
			t.Fatalf("wiring, not the property: prefix identity disagrees: %v", err)
		}
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("wiring, not the property: retirement: %v", err)
	}
	return c
}

func contentEncoded(t *testing.T, coding string, plain []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	var w io.WriteCloser
	var err error
	switch coding {
	case "gzip", "x-gzip":
		w = gzip.NewWriter(&b)
	case "deflate":
		w = zlib.NewWriter(&b)
	case "raw":
		w, err = flate.NewWriter(&b, flate.DefaultCompression)
	case "br":
		w = brotli.NewWriterOptions(&b, brotli.WriterOptions{Quality: 5, LGWin: 10})
	case "zstd":
		w, err = zstd.NewWriter(&b, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1024), zstd.WithSingleSegment(false), zstd.WithEncoderCRC(true))
	default:
		t.Fatalf("fixture coding %q", coding)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	encoded := bytes.Clone(b.Bytes())
	var r io.Reader
	var closeReader func() error
	switch coding {
	case "gzip", "x-gzip":
		v, e := gzip.NewReader(bytes.NewReader(encoded))
		err = e
		if e == nil {
			r = v
			closeReader = v.Close
		}
	case "deflate":
		v, e := zlib.NewReader(bytes.NewReader(encoded))
		err = e
		if e == nil {
			r = v
			closeReader = v.Close
		}
	case "raw":
		v := flate.NewReader(bytes.NewReader(encoded))
		r = v
		closeReader = v.Close
	case "br":
		r = brotli.NewReader(bytes.NewReader(encoded))
	case "zstd":
		v, e := zstd.NewReader(bytes.NewReader(encoded), zstd.WithDecoderConcurrency(1))
		err = e
		if e == nil {
			r = v
			closeReader = func() error { v.Close(); return nil }
		}
	}
	if err != nil {
		t.Fatalf("wiring, not the property: reference decoder: %v", err)
	}
	decoded, err := io.ReadAll(r)
	if closeReader != nil {
		_ = closeReader()
	}
	if err != nil || !bytes.Equal(decoded, plain) || bytes.Equal(encoded, plain) {
		t.Fatalf("wiring, not the property: encoded fixture is not a distinct valid stream: %v", err)
	}
	return encoded
}

func contentWire(start, codings string, encoded []byte, chunked bool) []byte {
	headers := start + "\r\nHost: fixture\r\nContent-Type: application/json\r\nX-Keep: visible-header\r\n"
	if codings != "" {
		headers += "Content-Encoding: " + codings + "\r\n"
	}
	if !chunked {
		return append([]byte(headers+fmt.Sprintf("Content-Length: %d\r\n\r\n", len(encoded))), encoded...)
	}
	var b bytes.Buffer
	b.WriteString(headers + "Transfer-Encoding: chunked\r\nTrailer: X-Tail\r\n\r\n")
	for off := 0; off < len(encoded); off += 11 {
		part := encoded[off:min(off+11, len(encoded))]
		fmt.Fprintf(&b, "%x\r\n", len(part))
		b.Write(part)
		b.WriteString("\r\n")
	}
	b.WriteString("0\r\nX-Tail: visible-trailer\r\n\r\n")
	return b.Bytes()
}

type contentOutput struct{ lines [][]byte }

func (o *contentOutput) WriteApproved(_ context.Context, a processing.Approved) error {
	o.lines = append(o.lines, a.Bytes())
	return nil
}

type contentWorker struct {
	worker  *processing.Worker
	store   *intake.Store
	output  *contentOutput
	taken   int
	charges []contentChargeSample
}

func contentNew(t *testing.T, rules map[string]any) *contentWorker {
	t.Helper()
	configuration := map[string]any{"version": "observer.config/1", "output": "/var/lib/observer", "write_content": true, "watch": []any{map[string]any{"name": "api", "exe": "/usr/bin/php"}}}
	for k, v := range rules {
		configuration[k] = v
	}
	data, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	compiled, findings := config.Compile(data, "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: configuration: %+v", findings)
	}
	s := &contentWorker{output: &contentOutput{}}
	s.store, err = intake.New(1 << 28)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1 << 20, IntakeExhausted: s.store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	options := processing.Options{Session: "content-decoding", PolicyRevision: "fixture", Plan: compiled.Plan, Intake: s.store, Gate: gate, Output: s.output, ConnectionInput: 4096, Taken: func(int, fragment.Process, fragment.ConnectionID) { s.taken++ }}
	s.worker, err = processing.New(processing.ObserveDecodeCharges(options, func(event processing.DecodeCharge) {
		s.charges = append(s.charges, contentChargeSample{event: event, stats: s.store.Stats()})
	}))
	if err != nil {
		t.Fatalf("wiring, not the property: worker: %v", err)
	}
	t.Cleanup(func() { _ = s.worker.Close() })
	return s
}
func (s *contentWorker) drain(t *testing.T, entries int) processing.Outcome {
	t.Helper()
	before := s.taken
	o, err := s.worker.Drain(context.Background())
	if err != nil || s.taken-before != entries {
		t.Fatalf("wiring, not the property: drain took %d/%d entries, error %v", s.taken-before, entries, err)
	}
	return o
}
func (s *contentWorker) give(t *testing.T, c contentCapture) processing.Outcome {
	t.Helper()
	for _, f := range c.fragments {
		if err := s.store.Write(f); err != nil {
			t.Fatalf("wiring, not the property: intake: %v", err)
		}
	}
	o := s.drain(t, len(c.fragments))
	if s.store.Stats().Connections != 0 {
		t.Fatal("wiring, not the property: retirement was fed before open assertions")
	}
	return o
}
func contentRead(t *testing.T, lines [][]byte) []processing.Artifact {
	t.Helper()
	var artifacts []processing.Artifact
	var b bytes.Buffer
	for _, line := range lines {
		b.Write(line)
		if !bytes.HasSuffix(line, []byte("\n")) {
			b.WriteByte('\n')
		}
	}
	err := processing.ReadArtifactFiles(fstest.MapFS{"content.jsonl": &fstest.MapFile{Data: b.Bytes()}}, []string{"content.jsonl"}, "content-decoding", func(a processing.Artifact) error { artifacts = append(artifacts, a); return nil })
	if err != nil {
		t.Fatalf("shipped reader refused decoded output: %v", err)
	}
	return artifacts
}
func contentPairs(t *testing.T, s *contentWorker) []processing.Artifact {
	t.Helper()
	if len(s.output.lines) != 2 {
		t.Fatalf("wiring, not the property: complete coded pair and following plain pair did not both reach output before close: %d lines", len(s.output.lines))
	}
	a := contentRead(t, s.output.lines)
	for i := range a {
		if a[i].Record != processing.ArtifactExchange || a[i].Index == nil || *a[i].Index != i || a[i].Reconstruction == nil || len(a[i].Reconstruction.Exchanges) != 1 {
			t.Fatalf("pair identity/index %d: %+v", i, a[i])
		}
		x := a[i].Reconstruction.Exchanges[0]
		if x.Request.Message == nil || x.Response.Message == nil || !x.Complete {
			t.Fatalf("wiring, not the property: pair %d incomplete", i)
		}
		target := "/coded"
		if i == 1 {
			target = "/later"
		}
		if x.Request.Message.Target != target || !a[i].Connection.Provisional || a[i].ExchangeID == "" {
			t.Errorf("pair %d lost identity or open state: %+v", i, a[i])
		}
	}
	if a[0].ExchangeID == a[1].ExchangeID {
		t.Error("pair ids duplicated")
	}
	return a
}
func contentBody(t *testing.T, m *record.Message) []byte {
	t.Helper()
	if m.Body.Encoding != "base64" {
		t.Fatalf("body encoding %q", m.Body.Encoding)
	}
	body, err := base64.StdEncoding.DecodeString(m.Body.Kept)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func contentMessage(t *testing.T, m *record.Message, encoded, plain, wire []byte, codings []string, chunked bool) {
	t.Helper()
	if m.Body.Content == nil {
		t.Fatal("decoded body has no representation metadata")
	}
	if m.Body.Content.State != "decoded" || m.Body.Content.Length != strconv.Itoa(len(plain)) || !reflect.DeepEqual(m.Body.Content.Codings, codings) {
		t.Errorf("decoded metadata %+v, want length %d codings %v", m.Body.Content, len(plain), codings)
	}
	if m.Body.Length != strconv.Itoa(len(encoded)) || m.Body.Holed != "0" || m.Body.Elided != "0" {
		t.Errorf("captured body facts changed: %+v", m.Body)
	}
	framing := "content_length"
	if chunked {
		framing = "chunked"
	}
	if m.Framing != framing || m.Stream.Offset != "0" || m.Stream.End != strconv.Itoa(len(wire)) {
		t.Errorf("captured framing/offsets changed: %s %+v", m.Framing, m.Stream)
	}
	if chunked && !reflect.DeepEqual(m.Trailers, []record.Field{{Name: "X-Tail", Value: "visible-trailer"}}) {
		t.Errorf("captured trailers changed: %+v", m.Trailers)
	}
}
func contentRetire(t *testing.T, s *contentWorker, c contentCapture) {
	t.Helper()
	s.drain(t, 0)
	if len(s.output.lines) != 2 {
		t.Error("idle drain duplicated an exchange")
	}
	if err := s.store.Connection(c.finals[0]); err != nil {
		t.Fatal(err)
	}
	o := s.drain(t, 1)
	if o.ProcessingFailures != 0 || o.ConnectionsCut != 0 || o.Excluded.Total() != 0 {
		t.Errorf("healthy decoded fixture failed or excluded: %+v", o)
	}
	if len(s.output.lines) != 3 {
		t.Errorf("retirement wrote %d total lines, want 3", len(s.output.lines))
	}
	stats := s.store.Stats()
	if stats.Bytes != 0 || stats.Parsing != 0 || stats.Policy != 0 {
		t.Errorf("charges not returned exactly to zero: %+v", stats)
	}
	contentRead(t, s.output.lines)
}

func TestDecodedBodiesReachOpenOutput(t *testing.T) {
	plain := []byte(`{"keep":"visible-body","nested":{"number":7},"items":[true,null]}`)
	for _, coding := range []string{"gzip", "x-gzip", "deflate", "raw", "br", "zstd", "identity-fields"} {
		for _, side := range []string{"request", "response"} {
			for _, chunked := range []bool{false, true} {
				for _, fragmented := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/chunked-%t/fragmented-%t", coding, side, chunked, fragmented), func(t *testing.T) {
						names := []string{coding}
						if coding == "identity-fields" {
							names = []string{"gzip"}
						}
						encoded := plain
						for _, name := range names {
							encoded = contentEncoded(t, name, encoded)
						}
						header := coding
						if coding == "identity-fields" {
							header = "identity\r\nContent-Encoding: identity, gzip\r\nContent-Encoding: IDENTITY"
						}
						canonical := append([]string(nil), names...)
						if coding == "raw" {
							header = "deflate"
							canonical = []string{"deflate"}
						}
						if coding == "x-gzip" {
							canonical = []string{"gzip"}
						}
						request := []byte("GET /coded HTTP/1.1\r\nHost: fixture\r\n\r\n")
						response := contentWire("HTTP/1.1 200 OK", "", []byte(`{"plain":true}`), false)
						wire := contentWire("POST /coded HTTP/1.1", header, encoded, chunked)
						if side == "response" {
							wire = contentWire("HTTP/1.1 200 OK", header, encoded, chunked)
							response = wire
						} else {
							request = wire
						}
						requests := append(bytes.Clone(request), []byte("GET /later HTTP/1.1\r\nHost: fixture\r\n\r\n")...)
						responses := append(bytes.Clone(response), []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nNEXT")...)
						c := contentCaptured(t, requests, responses, fragmented)
						s := contentNew(t, nil)
						s.give(t, c)
						a := contentPairs(t, s)
						if a[0].Version != processing.ArtifactVersion5 {
							t.Errorf("decoded output version %q, want version 5", a[0].Version)
						}
						x := a[0].Reconstruction.Exchanges[0]
						m := x.Request.Message
						if side == "response" {
							m = x.Response.Message
						}
						contentMessage(t, m, encoded, plain, wire, canonical, chunked)
						if !bytes.Equal(contentBody(t, m), plain) {
							t.Errorf("written body is not decoded plaintext: %q", contentBody(t, m))
						}
						if m.Structure.State != record.StructureDerived || m.Structure.Shape == nil || m.Structure.Shape.Kind != "object" {
							t.Errorf("shape was not derived again from plaintext: %+v", m.Structure)
						}
						if !bytes.Equal(contentBody(t, a[1].Reconstruction.Exchanges[0].Response.Message), []byte("NEXT")) {
							t.Error("later exchange body changed")
						}
						for _, line := range s.output.lines {
							if bytes.Contains(line, []byte(base64.StdEncoding.EncodeToString(encoded))) {
								t.Error("encoded body reached output")
							}
						}
						contentRetire(t, s, c)
					})
				}
			}
		}
	}
}

func TestDecodedBodiesPassThroughRemovalAndStructure(t *testing.T) {
	plain := []byte(`{"secret":"removed-sentinel","keep":"retained-sentinel","nested":{"number":7}}`)
	for _, mode := range []string{"member", "structure", "header"} {
		for _, side := range []string{"request", "response"} {
			t.Run(mode+"/"+side, func(t *testing.T) {
				rules := map[string]any{}
				switch mode {
				case "member":
					rules["remove"] = map[string]any{"json": map[string]any{side: []string{"/secret"}}}
				case "structure":
					rules["remove"] = map[string]any{"body_values": []string{side}}
				case "header":
					rules["remove"] = map[string]any{"headers": []string{"Content-Encoding"}}
				}
				encoded := contentEncoded(t, "gzip", plain)
				request := []byte("GET /coded HTTP/1.1\r\nHost: fixture\r\n\r\n")
				response := contentWire("HTTP/1.1 200 OK", "", []byte(`{"plain":true}`), false)
				wire := contentWire("POST /coded HTTP/1.1", "gzip", encoded, true)
				if side == "response" {
					wire = contentWire("HTTP/1.1 200 OK", "gzip", encoded, true)
					response = wire
				} else {
					request = wire
				}
				c := contentCaptured(t, append(bytes.Clone(request), []byte("GET /later HTTP/1.1\r\nHost: fixture\r\n\r\n")...), append(bytes.Clone(response), []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nNEXT")...), true)
				s := contentNew(t, rules)
				s.give(t, c)
				a := contentPairs(t, s)
				if a[0].Version != processing.ArtifactVersion5 {
					t.Errorf("decoded output version %q, want version 5", a[0].Version)
				}
				m := a[0].Reconstruction.Exchanges[0].Request.Message
				if side == "response" {
					m = a[0].Reconstruction.Exchanges[0].Response.Message
				}
				codings := []string{"gzip"}
				if mode == "header" {
					codings = nil
				}
				contentMessage(t, m, encoded, plain, wire, codings, true)
				kept := contentBody(t, m)
				switch mode {
				case "member":
					want := []byte(`{"keep":"retained-sentinel","nested":{"number":7}}`)
					if !bytes.Equal(kept, want) {
						t.Errorf("member removal did not act on decoded bytes: %q", kept)
					}
					var rendered bytes.Buffer
					if err := processing.RenderArtifact(&rendered, a[0]); err != nil {
						t.Fatal(err)
					}
					if strings.Contains(rendered.String(), "removed-sentinel") || !strings.Contains(rendered.String(), "retained-sentinel") {
						t.Errorf("rendered removal/positive control failed: %s", rendered.String())
					}
				case "structure":
					want := &record.Shape{Kind: "object", Fields: []record.ShapeField{{Name: "secret", Shape: record.Shape{Kind: "short_string"}}, {Name: "keep", Shape: record.Shape{Kind: "short_string"}}, {Name: "nested", Shape: record.Shape{Kind: "object", Fields: []record.ShapeField{{Name: "number", Shape: record.Shape{Kind: "integer"}}}}}}}
					if len(kept) != 0 || m.Structure.State != record.StructureDerived || !reflect.DeepEqual(m.Structure.Shape, want) {
						t.Errorf("decoded structure reduction: kept=%q structure=%+v, want %+v", kept, m.Structure, want)
					}
					if bytes.Contains(s.output.lines[0], []byte("removed-sentinel")) || bytes.Contains(s.output.lines[0], []byte("retained-sentinel")) {
						t.Error("structure-only output retained values")
					}
				case "header":
					if !bytes.Equal(kept, plain) {
						t.Error("removing coding header stopped decoding")
					}
					for _, h := range m.Headers {
						if strings.EqualFold(h.Name, "Content-Encoding") {
							t.Error("removed coding header survived")
						}
					}
					if bytes.Contains(s.output.lines[0], []byte(`"codings"`)) {
						t.Error("coding metadata reintroduced removed header")
					}
				}
				if bytes.Contains(s.output.lines[0], []byte(base64.StdEncoding.EncodeToString(encoded))) {
					t.Error("encoded body reached policy output")
				}
				contentRetire(t, s, c)
			})
		}
	}
}

// This ordinary-body control qualifies the capture, prefix certification,
// coalescing, fragmentation and accepting sink without needing a decoder.
func TestPlainBodyControlsForDecodedPaths(t *testing.T) {
	plain := []byte(`{"control":"plain-body"}`)
	for _, chunked := range []bool{false, true} {
		for _, fragmented := range []bool{false, true} {
			t.Run(fmt.Sprintf("chunked-%t/fragmented-%t", chunked, fragmented), func(t *testing.T) {
				request := contentWire("POST /coded HTTP/1.1", "", plain, chunked)
				response := contentWire("HTTP/1.1 200 OK", "", plain, chunked)
				c := contentCaptured(t, append(bytes.Clone(request), []byte("GET /later HTTP/1.1\r\nHost: fixture\r\n\r\n")...), append(bytes.Clone(response), []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nNEXT")...), fragmented)
				s := contentNew(t, nil)
				s.give(t, c)
				a := contentPairs(t, s)
				x := a[0].Reconstruction.Exchanges[0]
				for _, m := range []*record.Message{x.Request.Message, x.Response.Message} {
					if !bytes.Equal(contentBody(t, m), plain) || m.Body.Content != nil {
						t.Errorf("wiring, not the property: ordinary-body control changed: %+v", m.Body)
					}
				}
				contentRetire(t, s, c)
			})
		}
	}
}

// A coding limit rejects the entire pair before workspace admission. The next
// exchange must retain index 1, and must be visible while the connection is open.
func TestDecodedBodiesRejectMultipleCodings(t *testing.T) {
	plain := []byte(`{"keep":"visible-body"}`)
	for _, tc := range []struct {
		name   string
		header string
		inner  string
	}{
		{"distinct", "br, gzip", "br"},
		{"duplicates", "gzip\r\nContent-Encoding: gzip", "gzip"},
		{"aliases", "gzip\r\nContent-Encoding: x-gzip", "gzip"},
	} {
		for _, side := range []string{"request", "response", "both"} {
			t.Run(tc.name+"/"+side, func(t *testing.T) {
				encoded := contentEncoded(t, "gzip", contentEncoded(t, tc.inner, plain))
				request := []byte("GET /coded HTTP/1.1\r\nHost: fixture\r\n\r\n")
				response := contentWire("HTTP/1.1 200 OK", "", plain, false)
				if side != "response" {
					request = contentWire("POST /coded HTTP/1.1", tc.header, encoded, true)
				}
				if side != "request" {
					response = contentWire("HTTP/1.1 200 OK", tc.header, encoded, true)
				}
				c := contentCaptured(t, append(request, []byte("GET /later HTTP/1.1\r\nHost: fixture\r\n\r\n")...), append(response, []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nNEXT")...), true)
				s := contentNew(t, nil)
				o := s.give(t, c)
				if o.Excluded != (processing.Exclusions{ContentCodingUnsupported: 1}) || o.Withheld != connection.Counted(0) || o.ProcessingFailures != 0 || o.ConnectionsCut != 0 {
					t.Errorf("coding limit was not counted once as an isolated exclusion: %+v", o)
				}
				if len(s.charges) != 0 {
					t.Errorf("unsupported coding list attempted decode admission: %+v", s.charges)
				}
				if len(s.output.lines) != 1 {
					t.Fatalf("open output has %d lines, want only the later exchange", len(s.output.lines))
				}
				a := contentRead(t, s.output.lines)[0]
				if a.Index == nil || *a.Index != 1 || a.Reconstruction == nil || len(a.Reconstruction.Exchanges) != 1 || !a.Connection.Provisional {
					t.Fatalf("later exchange lost its open identity: %+v", a)
				}
				x := a.Reconstruction.Exchanges[0]
				if !x.Complete || x.Request.Message == nil || x.Request.Message.Target != "/later" || x.Response.Message == nil || !bytes.Equal(contentBody(t, x.Response.Message), []byte("NEXT")) {
					t.Fatal("later exchange did not continue intact")
				}
				if err := s.store.Connection(c.finals[0]); err != nil {
					t.Fatal(err)
				}
				s.drain(t, 1)
				if len(s.output.lines) != 2 {
					t.Fatalf("retirement wrote %d lines", len(s.output.lines))
				}
				end := contentRead(t, s.output.lines)[1]
				want := processing.ExcludedExchanges{ContentCodingUnsupported: "1", ContentDecodingFailed: "0", ContentDecodedTooLarge: "0", ContentDecodingTooCostly: "0"}
				if end.Record != processing.ArtifactConnection || end.ExcludedExchanges == nil || *end.ExcludedExchanges != want || end.ReconstructionTruncation != nil {
					t.Errorf("connection exclusion record: %+v", end)
				}
				stats := s.store.Stats()
				if stats.Bytes != 0 || stats.Parsing != 0 || stats.Policy != 0 || len(s.charges) != 0 {
					t.Errorf("rejected coding retained ownership: %+v charges=%+v", stats, s.charges)
				}
			})
		}
	}
}
