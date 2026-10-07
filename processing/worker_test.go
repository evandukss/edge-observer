package processing_test

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

type outputFunc func(context.Context, processing.Approved) error

func (f outputFunc) WriteApproved(ctx context.Context, a processing.Approved) error { return f(ctx, a) }

type outputLog struct {
	artifacts []processing.Artifact
	lines     [][]byte
}

func (o *outputLog) WriteApproved(_ context.Context, a processing.Approved) error {
	line := a.Bytes()
	var r processing.Artifact
	if err := json.Unmarshal(line, &r); err != nil {
		return err
	}
	o.artifacts = append(o.artifacts, r)
	o.lines = append(o.lines, line)
	return nil
}

func worker(t *testing.T, plan *config.ProcessingPlan, output processing.Output) (*processing.Worker, *intake.Store) {
	t.Helper()
	return workerSession(t, plan, output, "fixture-session")
}
func workerSession(t *testing.T, plan *config.ProcessingPlan, output processing.Output, session string) (*processing.Worker, *intake.Store) {
	t.Helper()
	store, err := intake.New(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1000, IntakeExhausted: store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	w, err := processing.New(processing.Options{Session: session, Plan: plan, PolicyRevision: "fixture-policy", Intake: store, Gate: gate, Output: output})
	if err != nil || w == nil {
		t.Fatalf("worker construction: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, store
}

type capturedBatch struct {
	fragments []fragment.Record
	records   []connection.Record
}

func (b *capturedBatch) Write(r fragment.Record) error {
	b.fragments = append(b.fragments, r)
	return nil
}
func (b *capturedBatch) Connection(r connection.Record) error {
	b.records = append(b.records, r)
	return nil
}

// Capture supplies sequences, placements and final counts from synthetic
// library events. This is not a live network fixture.
func batch(t *testing.T, id fragment.ConnectionID, request, response string) capturedBatch {
	t.Helper()
	var b capturedBatch
	s := capture.Recording(&b, &b)
	at := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	i := admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42, Start: admission.Determinate(7), Generation: 1}
	p := fragment.Process{PID: 42, StartTime: 7}
	for n, text := range []string{request, response} {
		direction := fragment.Sent
		if n == 1 {
			direction = fragment.Received
		}
		s.Transfer(probe.Transfer{Process: p, Instance: i, Endpoint: 7, Direction: direction, Measured: true, Length: uint32(len(text)), Payload: []byte(text), Stamp: uint64(n + 1),
			Sequence: probe.Sequence{Occupancy: 1, Number: 1, Born: true}, At: at})
	}
	s.Closed(probe.Connection{Process: p, Instance: i, Endpoint: 7, Stamp: 3, Sequence: probe.Sequence{Occupancy: 1, Born: true},
		Final: probe.Final{Known: true, Sent: probe.Terminal{Last: 1}, Received: probe.Terminal{Last: 1}}, At: at})
	if len(b.fragments) != 2 || len(b.records) != 1 {
		t.Fatal("fixture did not reach both capture callbacks")
	}
	for n := range b.fragments {
		b.fragments[n].Connection = id
		identity := *b.fragments[n].Evidence.Identity
		identity.Connection = id
		b.fragments[n].Evidence.Identity = &identity
		if err := b.fragments[n].Validate(); err != nil {
			t.Fatal(err)
		}
	}
	r := &b.records[0]
	r.ID = id
	for n := range r.Associations {
		r.Associations[n].Connection = id
	}
	for n := range r.Placements {
		r.Placements[n].Connection = id
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := record.FromConnection(*r); err != nil {
		t.Fatalf("fixture is not publishable: %v", err)
	}
	return b
}

func enqueue(t *testing.T, s *intake.Store, b capturedBatch) {
	t.Helper()
	for _, f := range b.fragments {
		if err := s.Write(f); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range b.records {
		if err := s.Connection(r); err != nil {
			t.Fatal(err)
		}
	}
}

func drain(t *testing.T, w *processing.Worker) processing.Outcome {
	t.Helper()
	o, err := w.Drain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func field(t *testing.T, a processing.Artifact, name string) string {
	t.Helper()
	if a.Reconstruction == nil || len(a.Reconstruction.Exchanges) != 1 {
		t.Fatal("one processed exchange required")
	}
	m := a.Reconstruction.Exchanges[0].Request.Message
	if m == nil {
		t.Fatal("request absent")
	}
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	t.Fatalf("permitted field %s absent", name)
	return ""
}

const goodRequest = "GET / HTTP/1.1\r\nX-Public: original\r\n\r\n"
const goodResponse = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"

func TestWorkerConnectionRouteContainsOnlyMetadata(t *testing.T) {
	out := &outputLog{}
	w, store := worker(t, rulesPlan(t, ""), out)
	enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
	drain(t, w)
	if len(out.artifacts) != 2 {
		t.Fatalf("both route controls required, got %d", len(out.artifacts))
	}
	if field(t, out.artifacts[0], "x-public") != "original" {
		t.Fatal("reconstruction control lost permitted value")
	}
	if out.artifacts[1].Route.Pipeline != config.ConnectionsPipeline || out.artifacts[1].Reconstruction != nil {
		t.Fatal("metadata exception carried reconstruction")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(out.lines[1], &members); err != nil {
		t.Fatal(err)
	}
	if _, carried := members["reconstruction"]; carried || strings.Contains(string(out.lines[1]), "original") {
		t.Fatal("metadata route carries payload fields")
	}
}

func TestWorkerWaitsForOutstandingFragmentAfterRetirement(t *testing.T) {
	out := &outputLog{}
	w, store := worker(t, rulesPlan(t, ""), out)
	b := batch(t, 1, goodRequest, goodResponse)
	if err := store.Connection(b.records[0]); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(b.fragments[0]); err != nil {
		t.Fatal(err)
	}
	o := drain(t, w)
	if o.Pending != 1 || len(out.artifacts) != 0 || store.Stats().Leased != 2 {
		t.Fatalf("retirement is not callback completeness: %+v %+v", o, store.Stats())
	}
	if err := store.Write(b.fragments[1]); err != nil {
		t.Fatal(err)
	}
	o = drain(t, w)
	if o.Pending != 0 {
		t.Fatalf("late callback did not settle positive control: %+v", o)
	}
	counted(t, o, out, 1, 1)
}

func TestWorkerFinalizationKeepsDecidablePrefixAndWithholdsTail(t *testing.T) {
	out := &outputLog{}
	w, store := worker(t, rulesPlan(t, ""), out)
	b := batch(t, 1, goodRequest+"GET /later HTTP/1.1\r\nAuthorization: unfinished", goodResponse)
	b.records[0].How, b.records[0].Ended = connection.StillOpen, time.Time{}
	enqueue(t, store, b)
	if o := drain(t, w); o.Pending != 1 || len(retirementsOf(out)) != 0 {
		t.Fatalf("live batch prematurely emitted: %+v", o)
	}
	o, err := w.Finish(context.Background(), processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil || o.Pending != 0 {
		t.Fatalf("prefix and tail: %+v %v", o, err)
	}
	counted(t, o, out, 1, 1)
	exchanges, lines := out.routed(config.ExchangesPipeline)
	if field(t, exchanges[0], "x-public") != "original" {
		t.Fatal("decidable prefix lost")
	}
	expectWithheld(t, o, connection.Uncounted("reconstruction_incomplete"))
	if strings.Contains(string(lines[0]), "unfinished") || strings.Contains(string(lines[0]), "/later") {
		t.Fatal("undecidable tail persisted")
	}
	retirements := retirementsOf(out)
	if len(retirements) != 1 || retirements[0].Connection.Ending.How != "still_open" {
		t.Fatalf("capture end became close: %+v", retirements)
	}
}

// retirementsOf is the connection lines written, in order.
func retirementsOf(out *outputLog) []processing.Artifact {
	retirements, _ := out.routed(config.ConnectionsPipeline)
	return retirements
}

// A processing failure drops the output it concerns, is counted, and the
// pipeline goes on with the next batch.
func TestWorkerProcessingFailureDropsAndAccounts(t *testing.T) {
	out := &outputLog{}
	w, store := worker(t, rulesPlan(t, `"remove": {"headers": ["authorization"]}`), out)
	enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
	counted(t, drain(t, w), out, 1, 1)
	enqueue(t, store, batch(t, 2, "GET / HTTP/1.1\r\nBad : field\r\n\r\n", goodResponse))
	o := drain(t, w)
	if o.ProcessingFailures != 1 {
		t.Fatalf("parse fault was not classified: %+v", o)
	}
	counted(t, o, out, 1, 2)
	enqueue(t, store, batch(t, 3, goodRequest, goodResponse))
	counted(t, drain(t, w), out, 2, 3)
}

// Decode the wire amendment independently of the producer's new Go types so
// its absence is a behavioral red on the published implementation.
type truncationWire struct {
	State  string `json:"state"`
	Suffix string `json:"suffix"`
	Stops  []struct {
		Direction      string `json:"direction"`
		Offset         string `json:"offset"`
		Reason         string `json:"reason"`
		EvidenceOffset string `json:"evidence_offset"`
	} `json:"stops"`
}

func truncationOf(t *testing.T, line []byte) *truncationWire {
	t.Helper()
	var wire struct {
		Truncation *truncationWire `json:"reconstruction_truncation"`
	}
	if err := json.Unmarshal(line, &wire); err != nil {
		t.Fatal(err)
	}
	return wire.Truncation
}

func TestWorkerReportsIndeterminateSuffixAfterUsefulPrefix(t *testing.T) {
	partial := "GET /withheld HTTP/1.1\r\nX-Secret: hidden"
	for _, name := range []string{"gap-at-boundary", "gap-inside-message", "short-payload", "unterminated-message", "placement-at-boundary", "producer-number-skipped"} {
		t.Run(name, func(t *testing.T) {
			out := &outputLog{}
			plan := rulesPlan(t, "")
			w, store := worker(t, plan, out)
			enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
			if o := drain(t, w); o.Written != 2 || len(out.lines) != 2 {
				t.Fatalf("clean control did not emit both routes: %+v", o)
			}
			if field(t, out.artifacts[0], "x-public") != "original" || truncationOf(t, out.lines[0]) != nil {
				t.Fatal("clean control is not a useful untruncated exchange")
			}
			if count := out.artifacts[0].Reconstruction.Unplaced; count != (record.Count{State: record.Undetermined, Unit: record.Bytes, Why: record.WhyProvisional}) {
				t.Fatalf("clean control's exchange line states its connection's unplaced total: %+v", count)
			}
			if count := out.artifacts[1].ReconstructionUnplaced; out.artifacts[1].Record != processing.ArtifactConnection || count == nil ||
				count.State != record.Determined || count.Value != "0" {
				t.Fatalf("clean control lost known zero: %+v", count)
			}

			request := goodRequest
			if name == "gap-inside-message" || name == "unterminated-message" {
				request += partial
			}
			b := batch(t, 2, request, goodResponse)
			reason := "capture_hole"
			evidence := len(request)
			switch name {
			case "gap-at-boundary", "gap-inside-message":
				later := b.fragments[0]
				later.Sequence, later.Offset = 3, uint64(len(request)+5)
				later.Evidence = fragment.Evidence{}
				later.Payload = []byte("GET /after-hole HTTP/1.1\r\nX-Secret: hidden\r\n\r\n")
				later.Length = uint32(len(later.Payload))
				if later.Offset <= b.fragments[0].End() {
					t.Fatal("constructed hole was not reached")
				}
				b.fragments = append(b.fragments, later)
				b.records[0].Fragments = connection.Counted(3)
			case "producer-number-skipped":
				// Contiguous by offset, which is what capture writes when it advances by what
				// arrived; only the producer number shows transfer two never did.
				later := b.fragments[0]
				later.Sequence, later.Offset, later.Produced = 3, uint64(len(request)), 3
				later.Evidence = fragment.Evidence{}
				later.Payload = []byte("GET /after-hole HTTP/1.1\r\nX-Secret: hidden\r\n\r\n")
				later.Length = uint32(len(later.Payload))
				if later.Offset != b.fragments[0].End() || b.fragments[0].Produced != 1 {
					t.Fatal("wiring, not the property: the constructed fragments are not contiguous by offset " +
						"with a producer number skipped between them")
				}
				b.fragments = append(b.fragments, later)
				b.records[0].Fragments = connection.Counted(3)
			case "short-payload":
				b.fragments[0].Length += 5
				if !b.fragments[0].Truncated() {
					t.Fatal("payload shortening was not reached")
				}
				// Capture advances a direction by what the call transferred, so
				// every evidence taken from this fragment on reaches its new end.
				for n := range b.fragments {
					b.fragments[n].Evidence.Sent.Limit += 5
				}
			case "unterminated-message":
				reason = "incomplete_message"
			case "placement-at-boundary":
				reason = "positions_unknown"
				found := false
				for n := range b.records[0].Placements {
					p := &b.records[0].Placements[n]
					if p.Direction == fragment.Sent {
						p.Positions, p.From, p.Because = connection.PositionsUnknownFrom, uint64(len(request)), connection.ObservationLost
						found = !p.Placeable(uint64(len(request)))
					}
				}
				if !found {
					t.Fatal("unknown placement boundary was not reached")
				}
			}
			for _, f := range b.fragments {
				if err := f.Validate(); err != nil {
					t.Fatal(err)
				}
			}
			if err := b.records[0].Validate(); err != nil {
				t.Fatal(err)
			}
			if _, err := record.FromConnection(b.records[0]); err != nil {
				t.Fatal(err)
			}
			enqueue(t, store, b)
			o := drain(t, w)
			if o.Written != 4 || len(out.lines) != 4 || field(t, out.artifacts[2], "x-public") != "original" {
				t.Fatalf("decidable prefix beside the fault was lost: %+v", o)
			}
			if strings.Contains(string(out.lines[2]), "hidden") || strings.Contains(string(out.lines[2]), "after-hole") || strings.Contains(string(out.lines[2]), "/withheld") {
				t.Fatal("withheld source entered the artifact")
			}
			truncated := truncationOf(t, out.lines[3])
			if truncated == nil {
				t.Fatal("useful prefix has no truncation marker; indeterminate suffix reads as absent")
			}
			if truncated.State != "truncated" || truncated.Suffix != "indeterminate" || len(truncated.Stops) != 1 {
				t.Fatalf("truncation meaning: %+v", truncated)
			}
			stop := truncated.Stops[0]
			if stop.Direction != "sent" || stop.Offset != strconv.Itoa(len(goodRequest)) || stop.Reason != reason || stop.EvidenceOffset != strconv.Itoa(evidence) {
				t.Fatalf("stop location/reason: %+v, evidence want %d", stop, evidence)
			}

			expectWithheld(t, o, connection.Uncounted("reconstruction_incomplete"))
			if truncationOf(t, out.lines[2]) != nil || out.artifacts[3].Reconstruction != nil {
				t.Fatal("metadata route received reconstruction state")
			}
			if out.artifacts[3].Record != processing.ArtifactConnection || out.artifacts[3].Connection.Ending.How != "handle_released" {
				t.Fatal("reconstruction truncation changed lifecycle ending")
			}
		})
	}
}
