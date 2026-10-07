package processing_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"testing"
	"testing/fstest"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

type openDeliveryCapture struct {
	fragments []fragment.Record
	finals    []connection.Record
}

func (c *openDeliveryCapture) Write(f fragment.Record) error {
	c.fragments = append(c.fragments, f)
	return nil
}
func (c *openDeliveryCapture) Connection(r connection.Record) error {
	c.finals = append(c.finals, r)
	return nil
}

// Capture supplies the records and retirement invariants. Prefix evidence is
// constructed from the numbered, loss-free transfers, without using retirement
// to advance its byte limits. The fixture models library events, not a network.
func openDeliveryFixture(t *testing.T, id fragment.ConnectionID, pairs int) openDeliveryCapture {
	t.Helper()
	return openDeliveryFixtureWithResponses(t, id, pairs, pairs)
}

func openDeliveryFixtureWithResponses(t *testing.T, id fragment.ConnectionID, requests, responses int) openDeliveryCapture {
	t.Helper()
	var c openDeliveryCapture
	recorder := capture.Recording(&c, &c)
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := fragment.Process{PID: 42, StartTime: 7}
	instance := admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42, Start: admission.Determinate(7), Generation: 1}
	for i := range requests {
		for j, text := range []string{fmt.Sprintf("GET /item-%d HTTP/1.1\r\nHost: fixture\r\n\r\n", i), fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Item: %d\r\n\r\n%c", i, 'a'+i%26)} {
			if j == 1 && i >= responses {
				continue
			}
			d := fragment.Sent
			if j == 1 {
				d = fragment.Received
			}
			recorder.Transfer(probe.Transfer{Process: p, Instance: instance, Endpoint: uint64(id), Direction: d, Measured: true, Length: uint32(len(text)), Payload: []byte(text), Stamp: uint64(2*i + j + 1), Sequence: probe.Sequence{Occupancy: 1, Number: uint64(i + 1), Born: true}, At: at})
		}
	}
	if requests == responses {
		recorder.Closed(probe.Connection{Process: p, Instance: instance, Endpoint: uint64(id), Stamp: uint64(requests + responses + 1), Sequence: probe.Sequence{Occupancy: 1, Born: true}, Final: probe.Final{Known: true, Sent: probe.Terminal{Last: uint64(requests)}, Received: probe.Terminal{Last: uint64(responses)}}, At: at})
	} else {
		recorder.Finish(at)
	}
	if len(c.fragments) != requests+responses || len(c.finals) != 1 {
		t.Fatalf("wiring, not the property: capture delivered %d fragments and %d retirements", len(c.fragments), len(c.finals))
	}
	r := &c.finals[0]
	r.ID = id
	for i := range r.Associations {
		r.Associations[i].Connection = id
	}
	for i := range r.Placements {
		r.Placements[i].Connection = id
	}
	identity := &fragment.Identity{Connection: id, Process: p, Instance: instance, Address: uint64(id), Generation: uint64(r.Handle.Generation), NetworkDevice: r.Network.Device, NetworkInode: r.Network.Inode, FirstSeen: r.FirstSeen}
	e := fragment.Evidence{Identity: identity, Origin: fragment.OriginBirth, Occupancy: 1}
	for i := range c.fragments {
		f := &c.fragments[i]
		f.Connection = id
		e.Through = f.Sequence
		d := &e.Sent
		if f.Direction == fragment.Received {
			d = &e.Received
		}
		*d = fragment.DirectionEvidence{Limit: f.End(), First: 1, Numbered: f.Produced, Resolved: f.Produced}
		f.Evidence = e
		if err := f.Evidenced(); err != nil {
			t.Fatalf("wiring, not the property: prefix %d: %v", i, err)
		}
		if err := r.Agrees(e); err != nil {
			t.Fatalf("wiring, not the property: retirement contradicts prefix %d: %v", i, err)
		}
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("wiring, not the property: retirement invalid: %v", err)
	}
	return c
}

type openDeliveryOutput struct {
	lines [][]byte
	fail  bool
}

func (o *openDeliveryOutput) WriteApproved(_ context.Context, a processing.Approved) error {
	if o.fail {
		return errors.New("fixture sink refusal")
	}
	o.lines = append(o.lines, a.Bytes())
	return nil
}

type openDeliveryWorker struct {
	worker *processing.Worker
	store  *intake.Store
	gate   *probe.DeliveryGate
	turns  []processing.Turn
	taken  int
}

func openDeliveryNew(t *testing.T, output processing.Output) *openDeliveryWorker {
	t.Helper()
	s := &openDeliveryWorker{}
	compiled, findings := config.Compile([]byte(`{"version":"observer.config/1","output":"/var/lib/observer","write_content":true,"watch":[{"name":"api","exe":"/usr/bin/php"}]}`), "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: configuration: %+v", findings)
	}
	var err error
	s.store, err = intake.New(1 << 28)
	if err != nil {
		t.Fatalf("wiring, not the property: intake: %v", err)
	}
	t.Cleanup(func() { _ = s.store.Close() })
	s.gate, err = probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1 << 20, IntakeExhausted: s.store.Exhausted()})
	if err != nil {
		t.Fatalf("wiring, not the property: gate: %v", err)
	}
	options := processing.Options{Session: "open-delivery", PolicyRevision: "fixture", Plan: compiled.Plan, Intake: s.store, Gate: s.gate, Output: output, ConnectionInput: 4096,
		Taken: func(int, fragment.Process, fragment.ConnectionID) { s.taken++ }}
	s.worker, err = processing.New(processing.ObserveTurns(options, func(turn processing.Turn) { s.turns = append(s.turns, turn) }))
	if err != nil {
		t.Fatalf("wiring, not the property: worker: %v", err)
	}
	t.Cleanup(func() { _ = s.worker.Close() })
	return s
}

func (s *openDeliveryWorker) feed(t *testing.T, fragments []fragment.Record) {
	t.Helper()
	for _, f := range fragments {
		if err := s.store.Write(f); err != nil {
			t.Fatalf("wiring, not the property: intake refused fragment: %v", err)
		}
	}
}

func (s *openDeliveryWorker) drain(t *testing.T, entries int) processing.Outcome {
	t.Helper()
	before := s.taken
	o, err := s.worker.Drain(context.Background())
	if s.taken-before != entries {
		t.Fatalf("wiring, not the property: worker took %d of %d fixture entries", s.taken-before, entries)
	}
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	return o
}

func openDeliveryRead(t *testing.T, lines [][]byte) []processing.Artifact {
	t.Helper()
	var artifacts []processing.Artifact
	var data []byte
	for _, line := range lines {
		data = append(data, line...)
		if !bytes.HasSuffix(line, []byte("\n")) {
			data = append(data, '\n')
		}
	}
	err := processing.ReadArtifactFiles(fstest.MapFS{"lines.jsonl": &fstest.MapFile{Data: data}}, []string{"lines.jsonl"}, "open-delivery", func(a processing.Artifact) error {
		artifacts = append(artifacts, a)
		return nil
	})
	if err != nil {
		t.Fatalf("shipped reader refused output: %v", err)
	}
	return artifacts
}

func openDeliveryPair(t *testing.T, a processing.Artifact, id fragment.ConnectionID, index int) {
	t.Helper()
	if a.Connection.ID != strconv.FormatUint(uint64(id), 10) || a.Index == nil || *a.Index != index || a.Reconstruction == nil || len(a.Reconstruction.Exchanges) != 1 {
		t.Fatalf("wrong connection or pair index: %+v", a)
	}
	x := a.Reconstruction.Exchanges[0]
	if x.Request.Message == nil || x.Response.Message == nil || x.Request.Message.Target != fmt.Sprintf("/item-%d", index) {
		t.Fatalf("pair identity lost at %d: %+v", index, x)
	}
	responseIndex := ""
	for _, h := range x.Response.Message.Headers {
		if h.Name == "X-Item" || h.Name == "x-item" {
			responseIndex = h.Value
		}
	}
	if responseIndex != strconv.Itoa(index) {
		t.Errorf("response at index %d belongs to %q", index, responseIndex)
	}
	if a.Version != processing.ArtifactVersion4 || !a.Connection.Provisional {
		t.Errorf("early pair has version %q provisional %t", a.Version, a.Connection.Provisional)
	}
	for _, present := range a.Connection.Lifecycle() {
		if present {
			t.Error("early pair presents lifecycle or totals as final")
		}
	}
	if a.Reconstruction.Unplaced.State != "undetermined" || a.Reconstruction.Unplaced.Why != "provisional" {
		t.Errorf("early line presents a connection-wide total: %+v", a.Reconstruction.Unplaced)
	}
	if a.ReconstructionUnplaced != nil {
		t.Errorf("exchange line carries a retirement total: %+v", a.ReconstructionUnplaced)
	}
}

func TestOpenDeliveryWritesLastPairBeforeRetirement(t *testing.T) {
	dir := t.TempDir()
	w, err := processing.OpenWriter(processing.WriterOptions{Directory: dir})
	if err != nil {
		t.Fatalf("wiring, not the property: writer: %v", err)
	}
	t.Cleanup(func() { _ = w.Shutdown(context.Background()) })
	s := openDeliveryNew(t, w)
	c := openDeliveryFixture(t, 7, 3)
	for i := range 3 {
		s.feed(t, c.fragments[2*i:2*i+2])
		s.drain(t, 2)
		if err := w.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
		var got []processing.Artifact
		err := processing.ReadArtifacts(os.DirFS(dir), func(a processing.Artifact) error { got = append(got, a); return nil })
		if err != nil || len(got) != i+1 {
			t.Fatalf("open connection wrote %d of %d complete pairs: %v", len(got), i+1, err)
		}
		openDeliveryPair(t, got[i], 7, i)
	}
	// Drain with no new input models indefinite idle without an elapsed-time oracle.
	s.drain(t, 0)
	if err := s.store.Connection(c.finals[0]); err != nil {
		t.Fatalf("wiring, not the property: retirement refused: %v", err)
	}
	s.drain(t, 1)
	if err := w.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got []processing.Artifact
	if err := processing.ReadArtifacts(os.DirFS(dir), func(a processing.Artifact) error { got = append(got, a); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[3].Record != "connection" || got[3].Connection.Provisional {
		t.Fatalf("retirement must add exactly one final connection line: %+v", got)
	}
	total := got[3].ReconstructionUnplaced
	if total == nil || total.State != "determined" || total.Unit != "bytes" || total.Value != "0" || total.Why != "" {
		t.Errorf("healthy retirement must state zero unplaced bytes: %+v", total)
	}
	ids := map[string]bool{}
	for i := range 3 {
		openDeliveryPair(t, got[i], 7, i)
		if got[i].ExchangeID == "" || ids[got[i].ExchangeID] {
			t.Errorf("exchange id missing or duplicated: %q", got[i].ExchangeID)
		}
		ids[got[i].ExchangeID] = true
	}
}

func TestOpenDeliveryRunsPairsWhileIntakeHasBacklog(t *testing.T) {
	out := &openDeliveryOutput{}
	s := openDeliveryNew(t, out)
	c := openDeliveryFixture(t, 9, processing.TurnEntries)
	s.feed(t, c.fragments)
	s.drain(t, len(c.fragments))
	if len(s.turns) == 0 {
		t.Fatal("wiring, not the property: scheduler observer was never called")
	}
	first := s.turns[0]
	if first.Taken > processing.TurnEntries {
		t.Fatalf("one turn took %d entries, bound %d", first.Taken, processing.TurnEntries)
	}
	if !first.Backlog || len(first.Released) == 0 {
		t.Fatalf("complete pair waited until intake emptied: first turn %+v", first)
	}
	if first.Released[0].Connection != 9 || first.Released[0].Index != 0 || first.Released[0].Outcome != processing.ReleaseEnqueued {
		t.Fatalf("first runnable pair not released in its completing turn: %+v", first.Released)
	}
	taken, released := 0, 0
	for _, turn := range s.turns {
		taken += turn.Taken
		if turn.Taken > processing.TurnEntries || len(turn.Released) != taken/2-released {
			t.Fatalf("turn %d took %d entries and released %d pairs; fixture requires %d ready pairs", turn.Number, turn.Taken, len(turn.Released), taken/2-released)
		}
		released += len(turn.Released)
	}
	got := openDeliveryRead(t, out.lines)
	if len(got) != processing.TurnEntries {
		t.Fatalf("released %d of fixture's %d pairs", len(got), processing.TurnEntries)
	}
	for i, a := range got {
		openDeliveryPair(t, a, 9, i)
	}
}

func TestOpenDeliverySinkDropKeepsIndexesAndSessionIDs(t *testing.T) {
	out := &openDeliveryOutput{}
	s := openDeliveryNew(t, out)
	c := openDeliveryFixture(t, 11, 3)
	for i := range 3 {
		out.fail = i == 1
		s.feed(t, c.fragments[2*i:2*i+2])
		s.drain(t, 2)
	}
	other := openDeliveryFixture(t, 12, 1)
	s.feed(t, other.fragments)
	o := s.drain(t, 2)
	if o.OutputFailures != 1 {
		t.Errorf("sink refusal counted %d times, want 1", o.OutputFailures)
	}
	var released []processing.Released
	for _, turn := range s.turns {
		released = append(released, turn.Released...)
	}
	if len(released) != 4 {
		t.Fatalf("issued %d ids, want four including drop", len(released))
	}
	for i, r := range released {
		if r.ID != uint64(i+1) {
			t.Errorf("session id %d = %d", i, r.ID)
		}
		wantIndex := i
		if i == 3 {
			wantIndex = 0
		}
		wantOutcome := processing.ReleaseEnqueued
		if i == 1 {
			wantOutcome = processing.ReleaseDropped
		}
		if r.Index != wantIndex || r.Outcome != wantOutcome {
			t.Errorf("release %d = %+v, want index %d outcome %s", i, r, wantIndex, wantOutcome)
		}
	}
	got := openDeliveryRead(t, out.lines)
	if len(got) != 3 {
		t.Fatalf("healthy later work did not continue: %d lines", len(got))
	}
	openDeliveryPair(t, got[0], 11, 0)
	openDeliveryPair(t, got[1], 11, 2)
	openDeliveryPair(t, got[2], 12, 0)
}

func TestOpenDeliveryLineSurvivesInputBufferReuse(t *testing.T) {
	out := &openDeliveryOutput{}
	s := openDeliveryNew(t, out)
	c := openDeliveryFixture(t, 17, 2)
	s.feed(t, c.fragments[:2])
	s.drain(t, 2)
	if len(out.lines) != 1 {
		t.Fatalf("complete first pair not released: %d lines", len(out.lines))
	}
	saved := bytes.Clone(out.lines[0])
	for i := range 2 {
		for j := range c.fragments[i].Payload {
			c.fragments[i].Payload[j] = '!'
		}
	}
	s.feed(t, c.fragments[2:])
	s.drain(t, 2)
	if !bytes.Equal(saved, out.lines[0]) {
		t.Fatal("released bytes changed when captured buffers were reused")
	}
	got := openDeliveryRead(t, out.lines)
	if len(got) != 2 {
		t.Fatalf("second pair missing or first duplicated: %d", len(got))
	}
	openDeliveryPair(t, got[0], 17, 0)
	openDeliveryPair(t, got[1], 17, 1)
}

func TestOpenDeliveryReaderRejectsContradictoryForms(t *testing.T) {
	out := &openDeliveryOutput{}
	s := openDeliveryNew(t, out)
	c := openDeliveryFixture(t, 19, 1)
	s.feed(t, c.fragments)
	s.drain(t, 2)
	if err := s.store.Connection(c.finals[0]); err != nil {
		t.Fatalf("wiring, not the property: retirement refused: %v", err)
	}
	s.drain(t, 1)
	if len(out.lines) != 2 {
		t.Fatalf("fixture's exchange and final line missing: %d", len(out.lines))
	}
	artifacts := openDeliveryRead(t, out.lines)
	if artifacts[0].Version != processing.ArtifactVersion4 || artifacts[1].Version != processing.ArtifactVersion4 {
		t.Fatalf("producer emitted %s and %s, need version 4 before testing its forms", artifacts[0].Version, artifacts[1].Version)
	}
	for _, tc := range []struct {
		name   string
		line   int
		change func(map[string]any)
	}{
		{"exchange-not-provisional", 0, func(c map[string]any) { delete(c, "provisional") }},
		{"exchange-empty-final-list", 0, func(c map[string]any) { c["associations"] = []any{} }},
		{"final-provisional", 1, func(c map[string]any) { c["provisional"] = true }},
		{"final-missing-total", 1, func(c map[string]any) { delete(c, "fragments") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(out.lines[tc.line], &value); err != nil {
				t.Fatalf("wiring, not the property: output JSON: %v", err)
			}
			conn, ok := value["connection"].(map[string]any)
			if !ok {
				t.Fatal("wiring, not the property: no connection object to corrupt")
			}
			tc.change(conn)
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			err = processing.ReadArtifactFiles(fstest.MapFS{"bad.jsonl": &fstest.MapFile{Data: append(data, '\n')}}, []string{"bad.jsonl"}, "", func(processing.Artifact) error { return nil })
			if err == nil {
				t.Fatal("shipped reader accepted a contradictory connection form")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		line   int
		total  any
		omit   bool
		legacy bool
		valid  bool
	}{
		{name: "exchange-total", total: map[string]any{"state": "determined", "unit": "bytes", "value": "0"}},
		{name: "final-missing-unplaced", line: 1, omit: true},
		{name: "final-null-unplaced", line: 1},
		{name: "final-no-value", line: 1, total: map[string]any{"state": "determined", "unit": "bytes"}},
		{name: "final-nondecimal", line: 1, total: map[string]any{"state": "determined", "unit": "bytes", "value": "many"}},
		{name: "final-wrong-unit", line: 1, total: map[string]any{"state": "determined", "unit": "events", "value": "0"}},
		{name: "final-determined-with-reason", line: 1, total: map[string]any{"state": "determined", "unit": "bytes", "value": "0", "why": "connection_cut"}},
		{name: "final-unknown-without-reason", line: 1, total: map[string]any{"state": "undetermined", "unit": "bytes"}},
		{name: "final-unknown-with-value", line: 1, total: map[string]any{"state": "undetermined", "unit": "bytes", "value": "0", "why": "connection_cut"}},
		{name: "final-not-carried", line: 1, total: map[string]any{"state": "not_carried", "unit": "bytes", "why": "not_read"}},
		{name: "legacy-total", line: 1, legacy: true, total: map[string]any{"state": "determined", "unit": "bytes", "value": "0"}},
		{name: "final-determined", line: 1, valid: true, total: map[string]any{"state": "determined", "unit": "bytes", "value": "17"}},
		{name: "final-unknown", line: 1, valid: true, total: map[string]any{"state": "undetermined", "unit": "bytes", "why": "connection_cut"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(out.lines[tc.line], &value); err != nil {
				t.Fatalf("wiring, not the property: output JSON: %v", err)
			}
			value["reconstruction_unplaced"] = tc.total
			if tc.omit {
				delete(value, "reconstruction_unplaced")
			}
			if tc.legacy {
				value["version"] = processing.ArtifactVersion3
			}
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			err = processing.ReadArtifactFiles(fstest.MapFS{"total.jsonl": &fstest.MapFile{Data: append(data, '\n')}}, []string{"total.jsonl"}, "", func(processing.Artifact) error { return nil })
			if (err == nil) != tc.valid {
				t.Fatalf("reader error %v, want accepted %t", err, tc.valid)
			}
		})
	}
}

func TestOpenDeliveryRecoverableLossKeepsOtherConnectionsRunning(t *testing.T) {
	for _, mode := range []string{"capture-cut", "unsupported-response"} {
		t.Run(mode, func(t *testing.T) {
			out := &openDeliveryOutput{}
			s := openDeliveryNew(t, out)
			c := openDeliveryFixture(t, 23, 2)
			s.feed(t, c.fragments[:2])
			s.drain(t, 2)
			if len(out.lines) != 1 {
				t.Fatalf("complete prefix was not released: %d lines", len(out.lines))
			}
			saved := bytes.Clone(out.lines[0])
			if mode == "capture-cut" {
				if c.fragments[2].Loss == nil {
					t.Fatal("wiring, not the property: capture did not supply the connection loss token")
				}
				c.fragments[2].Loss.Stop("input_limit")
			} else {
				c.fragments[3].Payload = bytes.Replace(c.fragments[3].Payload, []byte("200 OK"), []byte("100 OK"), 1)
				if !bytes.HasPrefix(c.fragments[3].Payload, []byte("HTTP/1.1 100 OK\r\n")) {
					t.Fatal("wiring, not the property: informational response was not installed")
				}
			}
			s.feed(t, c.fragments[2:])
			s.drain(t, 2)
			if err := s.store.Connection(c.finals[0]); err != nil {
				t.Fatalf("wiring, not the property: retirement refused: %v", err)
			}
			s.drain(t, 1)
			other := openDeliveryFixture(t, 24, 1)
			s.feed(t, other.fragments)
			o := s.drain(t, 2)
			if s.gate.Snapshot().Reason != "" || o.GateReason != "" {
				t.Errorf("recoverable loss invalidated the session: %+v", o)
			}
			if (o.Withheld.Known && o.Withheld.Value == 0) || (!o.Withheld.Known && o.Withheld.Why == "") {
				t.Errorf("recoverable loss left no counted or indeterminate outcome: %+v", o.Withheld)
			}
			if !bytes.Equal(saved, out.lines[0]) {
				t.Error("loss contradicted an earlier released line")
			}
			got := openDeliveryRead(t, out.lines)
			found, finals, prefix := 0, 0, 0
			for _, a := range got {
				if a.Record == processing.ArtifactConnection {
					finals++
					continue
				}
				if a.Connection.ID == "24" {
					openDeliveryPair(t, a, 24, 0)
					found++
				} else {
					openDeliveryPair(t, a, 23, 0)
					prefix++
				}
			}
			if found != 1 || finals > 1 || prefix != 1 {
				t.Errorf("unaffected pair delivered %d times, prefix %d times, failed connection finalized %d times", found, prefix, finals)
			}
		})
	}
}

func TestOpenDeliveryTerminalInvalidationForbidsLaterAuthorization(t *testing.T) {
	out := &openDeliveryOutput{}
	s := openDeliveryNew(t, out)
	c := openDeliveryFixture(t, 29, 2)
	s.feed(t, c.fragments[:2])
	s.drain(t, 2)
	if len(out.lines) != 1 {
		t.Fatalf("complete prefix was not released: %d lines", len(out.lines))
	}
	fault := s.gate.Admit(probe.DeliveryTransfer, false)
	if fault.State.Reason != probe.GateUnknownLength || fault.Slot == nil {
		t.Fatal("wiring, not the property: terminal invalidation was not reached")
	}
	fault.Slot.Refund(held.Unretained)
	s.feed(t, c.fragments[2:])
	_, _ = s.worker.Drain(context.Background())
	if len(out.lines) != 1 {
		t.Fatal("new authorization followed terminal invalidation")
	}
	o, _ := s.worker.Finish(context.Background(), processing.Finalization{Withdrawn: true, Drained: true})
	if o.GateReason != probe.GateUnknownLength || s.gate.Snapshot().Reason != probe.GateUnknownLength {
		t.Errorf("terminal stop lost its reason: %+v", o)
	}
	if o.Pending != 0 || s.store.Stats().Leased != 0 || len(out.lines) != 1 {
		t.Errorf("terminal settlement retained work or wrote new lines: %+v, intake %+v, lines %d", o, s.store.Stats(), len(out.lines))
	}
}

func TestOpenDeliveryFinishWithoutSettlementKeepsEvidenceRelease(t *testing.T) {
	for _, final := range []processing.Finalization{{}, {Withdrawn: true}, {Drained: true}} {
		t.Run(fmt.Sprintf("withdrawn_%t_drained_%t", final.Withdrawn, final.Drained), func(t *testing.T) {
			out := &openDeliveryOutput{}
			s := openDeliveryNew(t, out)
			c := openDeliveryFixtureWithResponses(t, 30, 2, 1)
			// The final queue contains one complete pair and the next request.
			// A still-open record cannot supply the missing settlement facts.
			s.feed(t, c.fragments)
			if c.finals[0].How != connection.StillOpen {
				t.Fatal("wiring, not the property: capture did not leave the connection open")
			}
			if err := s.store.Connection(c.finals[0]); err != nil {
				t.Fatalf("wiring, not the property: still-open record refused: %v", err)
			}
			if s.taken != 0 || s.store.Stats().Fragments != 3 || len(out.lines) != 0 {
				t.Fatal("wiring, not the property: final queue was not left for Finish")
			}
			if _, err := s.worker.Finish(context.Background(), final); err != nil {
				t.Fatalf("finish without settlement: %v", err)
			}
			if len(out.lines) != 1 {
				t.Fatalf("final queue released %d lines, want only its evidence-backed pair", len(out.lines))
			}
			got := openDeliveryRead(t, out.lines)
			if got[0].Record != processing.ArtifactExchange {
				t.Fatalf("missing settlement facts produced a retirement: %s", got[0].Record)
			}
			openDeliveryPair(t, got[0], 30, 0)
			if s.store.Stats().Leased != 0 || s.store.Stats().Bytes != 0 {
				t.Fatalf("Finish retained the final queue: %+v", s.store.Stats())
			}
		})
	}
}

func TestOpenDeliveryFinalSinkRefusalIsCountedOnce(t *testing.T) {
	out := &openDeliveryOutput{}
	s := openDeliveryNew(t, out)
	c := openDeliveryFixture(t, 31, 1)
	s.feed(t, c.fragments)
	s.drain(t, 2)
	if len(out.lines) != 1 {
		t.Fatalf("open connection produced %d lines, want its single exchange", len(out.lines))
	}
	openDeliveryPair(t, openDeliveryRead(t, out.lines)[0], 31, 0)
	out.fail = true
	if err := s.store.Connection(c.finals[0]); err != nil {
		t.Fatalf("wiring, not the property: retirement refused: %v", err)
	}
	o := s.drain(t, 1)
	if o.OutputFailures != 1 || o.Pending != 0 || len(out.lines) != 1 {
		t.Fatalf("final sink refusal uncounted or retirement duplicated exchange: %+v, lines %d", o, len(out.lines))
	}
	out.fail = false
	o = s.drain(t, 0)
	if o.OutputFailures != 1 || len(out.lines) != 1 {
		t.Fatal("settled final refusal was retried or counted twice")
	}
}
