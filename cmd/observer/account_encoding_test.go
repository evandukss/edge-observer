package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contentcoding"
	published "github.com/evandukss/edge-observer/contract/account"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/reconstruct"
)

type accountEncodingPair struct {
	request, response         string
	reason                    string
	holeRequest, holeResponse bool
}
type accountEncodingCapture struct {
	recorder  *capture.Session
	fragments []fragment.Record
	finals    []connection.Record
}

func (c *accountEncodingCapture) Write(r fragment.Record) error {
	c.fragments = append(c.fragments, r)
	return nil
}
func (c *accountEncodingCapture) Connection(r connection.Record) error {
	c.finals = append(c.finals, r)
	return nil
}

// Capture produces the numbered library-event records. The fixture's prefix
// certificate is derived from those loss-free transfers, before retirement is
// delivered to processing. No kernel or network behaviour is modelled.
func accountEncodingConversation(t *testing.T, pairs []accountEncodingPair, endpoint uint64, sessions ...*accountEncodingCapture) accountEncodingCapture {
	t.Helper()
	source := &accountEncodingCapture{}
	if len(sessions) != 0 {
		source = sessions[0]
	}
	if source.recorder == nil {
		source.recorder = capture.Recording(source, source)
	}
	recorder := source.recorder
	startFragments, startFinals := len(source.fragments), len(source.finals)
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
			recorder.Transfer(probe.Transfer{Process: p, Instance: instance, Endpoint: endpoint, Direction: direction, Measured: true, Length: uint32(len(wire)), Payload: payload, Stamp: endpoint<<32 | uint64(2*i+side+1), Sequence: probe.Sequence{Occupancy: 1, Number: uint64(i + 1), Born: true}, At: at})
		}
	}
	recorder.Closed(probe.Connection{Process: p, Instance: instance, Endpoint: endpoint, Stamp: endpoint<<32 | uint64(2*len(pairs)+1), Sequence: probe.Sequence{Occupancy: 1, Born: true}, Final: probe.Final{Known: true, Sent: probe.Terminal{Last: uint64(len(pairs))}, Received: probe.Terminal{Last: uint64(len(pairs))}}, At: at})
	c := accountEncodingCapture{fragments: source.fragments[startFragments:], finals: source.finals[startFinals:]}
	if len(c.fragments) != 2*len(pairs) || len(c.finals) != 1 {
		t.Fatalf("wiring, not the property: capture emitted %d fragments and %d retirements for %d pairs", len(c.fragments), len(c.finals), len(pairs))
	}
	r := c.finals[0]
	identity := &fragment.Identity{Connection: r.ID, Process: p, Instance: instance, Address: endpoint, Generation: uint64(r.Handle.Generation), NetworkDevice: r.Network.Device, NetworkInode: r.Network.Inode, FirstSeen: r.FirstSeen}
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

func accountEncodingMessage(request bool, index int, fields, body string) string {
	start := "HTTP/1.1 200 OK"
	if request {
		start = fmt.Sprintf("POST /item-%d HTTP/1.1", index)
	}
	return fmt.Sprintf("%s\r\nContent-Length: %d\r\n%s\r\n%s", start, len(body), fields, body)
}
func accountEncodingPlain(index int) accountEncodingPair {
	return accountEncodingPair{request: accountEncodingMessage(true, index, "", "request"), response: accountEncodingMessage(false, index, "", "response")}
}

// accountEncodingBodyBound is the per-message body bound the account fixtures
// run under. A brotli stream over the work budget is larger than 4096 bytes at
// the published budget, and a body over the bound is elided into a stop before
// any decoding, so the bound is one such a stream fits.
const accountEncodingBodyBound = 1 << 20

// accountEncodingReasons is every exclusion reason, in the contract's rank
// order.
var accountEncodingReasons = []string{processing.ReasonContentCodingUnsupported, processing.ReasonContentDecodingFailed, processing.ReasonContentDecodedTooLarge, processing.ReasonContentDecodingTooCostly}

func accountEncodingGzip(t *testing.T, body string) string {
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
func accountEncodingBad(t *testing.T, index int, reason, side string) accountEncodingPair {
	t.Helper()
	p := accountEncodingPlain(index)
	fields, body := "Content-Encoding: compress\r\n", "opaque"
	switch reason {
	case processing.ReasonContentDecodingFailed:
		fields, body = "Content-Encoding: gzip\r\n", accountEncodingGzip(t, "corrupt checksum")
		body = body[:len(body)-1]
	case processing.ReasonContentDecodedTooLarge:
		fields, body = "Content-Encoding: gzip\r\n", accountEncodingGzip(t, strings.Repeat("x", accountEncodingBodyBound+1))
	case processing.ReasonContentDecodingTooCostly:
		fields, body = "Content-Encoding: br\r\n", accountEncodingCostly(t, accountEncodingBodyBound)
	}
	if side != "response" {
		p.request = accountEncodingMessage(true, index, fields, body)
	}
	if side != "request" {
		p.response = accountEncodingMessage(false, index, fields, body)
	}
	p.reason = reason
	return p
}

// accountEncodingBits writes bits least significant first, as brotli reads them.
type accountEncodingBits struct {
	out []byte
	pos int
}

func (b *accountEncodingBits) put(value uint64, n int) {
	for i := 0; i < n; i++ {
		if b.pos%8 == 0 {
			b.out = append(b.out, 0)
		}
		b.out[len(b.out)-1] |= byte((value>>uint(i))&1) << uint(b.pos%8)
		b.pos++
	}
}

// simple is a simple prefix code with one symbol of the given width.
func (b *accountEncodingBits) simple(symbol uint64, width int) {
	b.put(1, 2)
	b.put(0, 2)
	b.put(symbol, width)
}

// types declares one block type, or 256 with a one-symbol block-type code and
// block lengths of one.
func (b *accountEncodingBits) types(count int) {
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

// accountEncodingCostlyBrotli is a brotli stream of count compressed metablocks, each
// producing one "a" while declaring 256 literal and 256 distance block types
// with all-zero context maps, then the last, empty metablock. Its work grows
// with count while its output is count bytes, which is what the work budget
// exists to refuse.
func accountEncodingCostlyBrotli(count int) []byte {
	var b accountEncodingBits
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

// accountEncodingCostly is a brotli stream over the work budget that fits under bound
// encoded and decodes, by a decoder without a budget, to fewer than bound
// bytes. Two guards: the upstream reader decodes it whole, so the only thing
// the observer's decoder can hold against it is its cost; and the observer's
// decoder does find it too costly, so a case built on it measures the fourth
// reason and nothing else.
func accountEncodingCostly(t *testing.T, bound int) string {
	t.Helper()
	count := bound / 128
	stream := accountEncodingCostlyBrotli(count)
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

// A ready peer records every exchange it is asked about, including exclusions.
func TestAccountEncodingProtocolPeer(t *testing.T) {
	path := os.Getenv("OBSERVER_ACCOUNT_ENCODING_AUDIT")
	if path == "" {
		return
	}
	audit, err := os.Create(path)
	if err != nil {
		os.Exit(2)
	}
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 16<<20)
	for scan.Scan() {
		var m struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}
		if json.Unmarshal(scan.Bytes(), &m) != nil {
			os.Exit(3)
		}
		if _, err = audit.Write(append(append([]byte(nil), scan.Bytes()...), '\n')); err != nil {
			os.Exit(4)
		}
		switch m.Type {
		case "start":
			err = json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "ready", "protocol": "observer.extension/2"})
		case "exchange":
			err = json.NewEncoder(os.Stdout).Encode(map[string]any{"type": "result", "id": m.ID, "outcome": "unchanged"})
		case "shutdown":
			_ = audit.Close()
			os.Exit(0)
		}
		if err != nil {
			os.Exit(5)
		}
	}
	if scan.Err() != nil {
		os.Exit(6)
	}
	_ = audit.Close()
	os.Exit(0)
}

type accountEncodingHarness struct {
	d      *daemon
	store  *intake.Store
	writer *processing.Writer
	run    *processing.Run
	taken  atomic.Int64
	output string
	audits []string
	peers  int
}

func accountEncodingStart(t *testing.T, peers, inputBound int) *accountEncodingHarness {
	t.Helper()
	f := &accountEncodingHarness{output: t.TempDir(), peers: peers}
	extensions := []any{}
	for i := 0; i < peers; i++ {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		f.audits = append(f.audits, path)
		extensions = append(extensions, map[string]any{"name": fmt.Sprintf("observe%d", i), "command": []string{"/usr/bin/env", "OBSERVER_ACCOUNT_ENCODING_AUDIT=" + path, os.Args[0], "-test.run=^TestAccountEncodingProtocolPeer$"}, "fields": []string{"request.headers", "response.headers"}, "timeout_ms": 10000})
	}
	doc, err := json.Marshal(map[string]any{"version": "observer.config/1", "output": "/var/lib/observer", "write_content": true, "watch": []any{map[string]any{"name": "api", "exe": "/usr/bin/php"}}, "extensions": extensions})
	if err != nil {
		t.Fatal(err)
	}
	compiled, findings := config.Compile(doc, "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: account config: %+v", findings)
	}
	f.store, err = intake.New(64 << 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4096, IntakeExhausted: f.store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	f.writer, err = processing.Open(f.output, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.writer.Close() })
	ready := make(chan struct{}, peers)
	f.run, err = processing.Start(processing.Options{Session: "encoding-account", PolicyRevision: "fixture", Plan: compiled.Plan, Intake: f.store, Gate: gate, Output: f.writer, Derived: f.writer, ConnectionInput: inputBound, Limits: reconstruct.Limits{HTTP: http1.Limits{MaxBodyBytes: accountEncodingBodyBound}}, Taken: func(int, fragment.Process, fragment.ConnectionID) { f.taken.Add(1) }, Supervision: func(e extension.Event) {
		if e.Kind == extension.Ready {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	}})
	if err != nil {
		t.Fatalf("wiring, not the property: start account run: %v", err)
	}
	t.Cleanup(func() { _ = f.run.Close() })
	f.d = &daemon{output: f.writer, gate: gate, policy: policy.Policy{Processing: compiled.Plan}, processing: &processingRun{run: f.run}}
	for range peers {
		select {
		case <-ready:
		case <-time.After(8 * time.Second):
			t.Fatal("wiring, not the property: account extension never ready")
		}
	}
	return f
}
func accountEncodingAwait(t *testing.T, why string, condition func() bool) bool {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !condition() {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Error(why)
			return false
		}
	}
	return true
}
func (f *accountEncodingHarness) give(t *testing.T, rs []fragment.Record) {
	t.Helper()
	before := f.taken.Load()
	for _, r := range rs {
		if err := f.store.Write(r); err != nil {
			t.Fatalf("wiring, not the property: account intake: %v", err)
		}
	}
	f.run.Route()
	if !accountEncodingAwait(t, "wiring, not the property: account worker did not take supplied fragments", func() bool { return f.taken.Load() == before+int64(len(rs)) }) {
		t.FailNow()
	}
}

// settle waits until every extension has answered the ids issued so far. A
// chained exchange keeps its messages retained against the connection's input
// bound until its extensions are through, so the next pair is given only once
// the previous one is released; otherwise the bound cuts the connection before
// the prefix is accounted, and nothing below measures the property.
func (f *accountEncodingHarness) settle(t *testing.T, ids int) {
	t.Helper()
	if !accountEncodingAwait(t, fmt.Sprintf("wiring, not the property: extension did not answer prefix pair %d", ids-1), func() bool {
		o := f.run.Snapshot()
		if len(o.Extensions) != f.peers {
			return false
		}
		for _, e := range o.Extensions {
			if e.Considered != uint64(ids) || e.Pending != 0 {
				return false
			}
		}
		return true
	}) {
		t.FailNow()
	}
}
func (f *accountEncodingHarness) finish(t *testing.T, rs []connection.Record) processing.Outcome {
	t.Helper()
	before := f.taken.Load()
	for _, r := range rs {
		if err := f.store.Connection(r); err != nil {
			t.Fatal(err)
		}
	}
	f.run.Route()
	if !accountEncodingAwait(t, "wiring, not the property: account worker did not take retirements", func() bool { return f.taken.Load() == before+int64(len(rs)) }) {
		t.FailNow()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := f.run.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out
}
func accountEncodingCount(t *testing.T, label, value string, want uint64) {
	t.Helper()
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n != want || value != strconv.FormatUint(want, 10) {
		t.Errorf("%s=%q, want whole decimal %d", label, value, want)
	}
}
func (f *accountEncodingHarness) check(t *testing.T, want account.ExcludedExchanges, ids, cut, inputCut uint64, connections, written int) {
	t.Helper()
	state := f.d.processingSnapshot()
	if state == nil {
		t.Fatal("wiring, not the property: live daemon has no processing snapshot")
	}
	if state.ExcludedExchanges == nil {
		t.Error("live processing account omits counted exclusion totals")
	} else if *state.ExcludedExchanges != want {
		t.Errorf("operational exclusions=%+v, want %+v", *state.ExcludedExchanges, want)
	}
	if state.ProcessingFailures != 0 || state.OutputFailures != 0 || state.ConnectionsCut != cut || state.InputCut != inputCut || state.ExchangeIDs != ids {
		t.Errorf("exclusions changed legacy counters or ids: %+v", state)
	}
	if state.Written != uint64(written+connections) || state.Authorized != state.Written {
		t.Errorf("account delivery authorized/written=%d/%d, want %d", state.Authorized, state.Written, written+connections)
	}
	for _, e := range state.Extensions {
		if e.Considered != ids || e.Unchanged != ids || e.Failed != 0 || e.Pending != 0 {
			t.Errorf("ready extension accounting differs from fixture: %+v", e)
		}
	}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	source := account.Plan(at, account.Policy{Revision: "fixture", Generation: 1}, process.Resolution{}, probe.Capability{}, nil)
	source.Attached(account.Live, "encoding-account", nil, probe.Capability{})
	source.Extensions = account.ExtensionsOf(f.d.policy.Processing.Extensions())
	source.Ran(at, account.Run{Processing: state})
	// Read back the operational JSON before invoking the published projection.
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var operational account.Account
	if err := json.Unmarshal(data, &operational); err != nil {
		t.Fatal(err)
	}
	projected, err := published.Project(operational, published.NotSupplied())
	if err != nil {
		t.Fatalf("wiring, not the property: published account projection: %v", err)
	}
	data, err = json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip published.Account
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatal(err)
	}
	aggregate := roundtrip.Processing.Aggregate
	if aggregate == nil {
		t.Fatal("wiring, not the property: published projection has no processing aggregate")
	}
	counts := aggregate.ExcludedExchanges
	if counts == nil {
		t.Error("published account omits counted exclusion totals")
	} else {
		accountEncodingCount(t, "unsupported", counts.ContentCodingUnsupported, want.ContentCodingUnsupported)
		accountEncodingCount(t, "failed", counts.ContentDecodingFailed, want.ContentDecodingFailed)
		accountEncodingCount(t, "large", counts.ContentDecodedTooLarge, want.ContentDecodedTooLarge)
		accountEncodingCount(t, "costly", counts.ContentDecodingTooCostly, want.ContentDecodingTooCostly)
	}
	accountEncodingCount(t, "published exchange ids", roundtrip.Processing.ExchangeIDs, ids)
	accountEncodingCount(t, "published processing failures", aggregate.ProcessingFailures, 0)
	accountEncodingCount(t, "published connections cut", aggregate.ConnectionsCut, cut)
	accountEncodingCount(t, "published input cut", aggregate.InputCut, inputCut)
	var totals account.ExcludedExchanges
	seenConnections, seenWritten := 0, 0
	err = processing.ReadArtifactFiles(os.DirFS(f.output), []string{processing.ArtifactName}, "encoding-account", func(a processing.Artifact) error {
		if a.Record == processing.ArtifactExchange {
			seenWritten++
		}
		if a.Record == processing.ArtifactConnection {
			seenConnections++
			if a.ExcludedExchanges == nil {
				t.Error("connection omits counted exclusion totals")
				return nil
			}
			for _, field := range []struct {
				s    string
				dest *uint64
			}{{a.ExcludedExchanges.ContentCodingUnsupported, &totals.ContentCodingUnsupported}, {a.ExcludedExchanges.ContentDecodingFailed, &totals.ContentDecodingFailed}, {a.ExcludedExchanges.ContentDecodedTooLarge, &totals.ContentDecodedTooLarge}, {a.ExcludedExchanges.ContentDecodingTooCostly, &totals.ContentDecodingTooCostly}} {
				n, err := strconv.ParseUint(field.s, 10, 64)
				if err != nil {
					t.Errorf("connection count is not whole decimal: %q", field.s)
				} else {
					*field.dest += n
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Errorf("shipped line reader: %v", err)
	}
	if seenConnections != connections || seenWritten != written {
		t.Errorf("read connections/exchanges=%d/%d, want %d/%d", seenConnections, seenWritten, connections, written)
	}
	if totals != want {
		t.Errorf("sum of connection counters=%+v, want account totals %+v", totals, want)
	}
	if state.ExcludedExchanges != nil && totals != *state.ExcludedExchanges {
		t.Errorf("line/account totals disagree: %+v/%+v", totals, *state.ExcludedExchanges)
	}
}

func TestAccountEncodingCountsEachExcludedExchangeOnce(t *testing.T) {
	for _, peers := range []int{0, 1, 2} {
		for _, zero := range []bool{true, false} {
			t.Run(fmt.Sprintf("peers-%d/zero-%t", peers, zero), func(t *testing.T) {
				f := accountEncodingStart(t, peers, 4096)
				var finals []connection.Record
				var session accountEncodingCapture
				seenConnections := map[fragment.ConnectionID]bool{}
				want := account.ExcludedExchanges{}
				var ids uint64
				written := 0
				for connectionIndex, reason := range accountEncodingReasons {
					pairs := []accountEncodingPair{accountEncodingPlain(0)}
					if !zero {
						for i := 0; i <= connectionIndex; i++ {
							pairs = append(pairs, accountEncodingBad(t, len(pairs), reason, []string{"request", "response", "both"}[i%3]))
						}
					}
					pairs = append(pairs, accountEncodingPlain(len(pairs)))
					c := accountEncodingConversation(t, pairs, uint64(7+connectionIndex), &session)
					if seenConnections[c.finals[0].ID] {
						t.Fatal("wiring, not the property: multi-connection fixture reused a session connection id")
					}
					seenConnections[c.finals[0].ID] = true
					finals = append(finals, c.finals...)
					f.give(t, c.fragments)
					ids += uint64(len(pairs))
					written += 2
					accountEncodingAwait(t, "before close: account fixture did not continue after isolated exclusions", func() bool { return f.writer.DeliveryStats().Written == uint64(written) })
				}
				if !zero {
					want = account.ExcludedExchanges{ContentCodingUnsupported: 1, ContentDecodingFailed: 2, ContentDecodedTooLarge: 3, ContentDecodingTooCostly: 4}
				}
				out := f.finish(t, finals)
				if out.Withheld != connection.Counted(0) {
					t.Errorf("isolated exclusions changed withheld: %+v", out.Withheld)
				}
				f.check(t, want, ids, 0, 0, len(finals), written)
			})
		}
	}
}

func TestAccountEncodingKeepsCountsBeforeLaterCut(t *testing.T) {
	for _, peers := range []int{0, 1, 2} {
		for _, reason := range accountEncodingReasons {
			for _, middleWritten := range []bool{false, true} {
				t.Run(fmt.Sprintf("peers-%d/%s/middle-%t", peers, reason, middleWritten), func(t *testing.T) {
					f := accountEncodingStart(t, peers, 4)
					pairs := []accountEncodingPair{accountEncodingPlain(0), accountEncodingBad(t, 1, reason, "both")}
					if middleWritten {
						pairs = append(pairs, accountEncodingPlain(2))
					}
					prefix := len(pairs)
					written := prefix - 1
					for i := 0; i < 6; i++ {
						pairs = append(pairs, accountEncodingPlain(len(pairs)))
					}
					c := accountEncodingConversation(t, pairs, 7)
					for i := 0; i < prefix; i++ {
						f.give(t, c.fragments[2*i:2*i+2])
						accountEncodingAwait(t, "before cut: paired prefix did not receive its id", func() bool { return f.run.Snapshot().ExchangeIDs == uint64(i+1) })
						f.settle(t, i+1)
					}
					accountEncodingAwait(t, "before cut: valid prefix was not written", func() bool { return f.writer.DeliveryStats().Written == uint64(written) })
					for i := prefix; i < len(pairs); i++ {
						f.give(t, c.fragments[2*i:2*i+1])
					}
					if !accountEncodingAwait(t, "wiring, not the property: account fixture did not reach input-bound cut", func() bool { return f.run.Snapshot().ConnectionsCut == 1 }) {
						t.FailNow()
					}
					for i := prefix; i < len(pairs); i++ {
						f.give(t, c.fragments[2*i+1:2*i+2])
					}
					out := f.finish(t, c.finals)
					if out.AllowanceCut != 0 {
						t.Errorf("input-bound cut became allowance cut: %+v", out)
					}
					want := account.ExcludedExchanges{}
					switch reason {
					case processing.ReasonContentCodingUnsupported:
						want.ContentCodingUnsupported = 1
					case processing.ReasonContentDecodingFailed:
						want.ContentDecodingFailed = 1
					case processing.ReasonContentDecodedTooLarge:
						want.ContentDecodedTooLarge = 1
					case processing.ReasonContentDecodingTooCostly:
						want.ContentDecodingTooCostly = 1
					}
					f.check(t, want, uint64(prefix), 1, 12, 1, written)
				})
			}
		}
	}
}

func TestAccountEncodingUncountedIsNotCountedZero(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		counts *account.ExcludedExchanges
	}{
		{"uncounted", nil},
		{"counted-zero", &account.ExcludedExchanges{}},
		{"whole-integers", &account.ExcludedExchanges{ContentCodingUnsupported: 9007199254740993, ContentDecodingFailed: 18446744073709551615, ContentDecodedTooLarge: 103, ContentDecodingTooCostly: 7}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := account.Plan(at, account.Policy{Revision: "fixture", Generation: 1}, process.Resolution{}, probe.Capability{}, nil)
			source.Attached(account.Live, "encoding-account", nil, probe.Capability{})
			source.Ran(at, account.Run{Processing: &account.Processing{ExcludedExchanges: tc.counts}})
			raw, err := json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			var operational account.Account
			if err := json.Unmarshal(raw, &operational); err != nil {
				t.Fatal(err)
			}
			if operational.Processing == nil {
				t.Fatal("wiring, not the property: processing disappeared before projection")
			}
			projected, err := published.Project(operational, published.NotSupplied())
			if err != nil {
				t.Fatalf("wiring, not the property: project countedness: %v", err)
			}
			raw, err = json.Marshal(projected)
			if err != nil {
				t.Fatal(err)
			}
			var back published.Account
			if err := json.Unmarshal(raw, &back); err != nil {
				t.Fatal(err)
			}
			if back.Processing.Aggregate == nil {
				t.Fatal("wiring, not the property: processing aggregate disappeared")
			}
			got := back.Processing.Aggregate.ExcludedExchanges
			if tc.counts == nil {
				if operational.Processing.ExcludedExchanges != nil || got != nil {
					t.Error("uncounted exclusions were invented as counted zero")
				}
				if bytes.Contains(raw, []byte(`"excluded_exchanges"`)) {
					t.Error("published uncounted account has excluded_exchanges member")
				}
				return
			}
			if operational.Processing.ExcludedExchanges == nil || *operational.Processing.ExcludedExchanges != *tc.counts {
				t.Errorf("operational count round trip=%+v, want %+v", operational.Processing.ExcludedExchanges, tc.counts)
			}
			if got == nil {
				t.Fatal("counted exclusions disappeared from projection")
			}
			accountEncodingCount(t, "unsupported", got.ContentCodingUnsupported, tc.counts.ContentCodingUnsupported)
			accountEncodingCount(t, "failed", got.ContentDecodingFailed, tc.counts.ContentDecodingFailed)
			accountEncodingCount(t, "large", got.ContentDecodedTooLarge, tc.counts.ContentDecodedTooLarge)
			accountEncodingCount(t, "costly", got.ContentDecodingTooCostly, tc.counts.ContentDecodingTooCostly)
		})
	}
}
