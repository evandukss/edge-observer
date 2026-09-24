package processing_test

import (
	"context"
	"encoding/json"
	"errors"
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

func workerPlan(t *testing.T, pipelines ...config.Pipeline) *config.ProcessingPlan {
	t.Helper()
	raw, err := config.Examples.ReadFile("examples/no-extension.config.json")
	if err != nil {
		t.Fatal(err)
	}
	var c config.Configuration
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.Pipelines = pipelines
	for n := range c.Pipelines {
		if c.Pipelines[n].Slots == nil {
			c.Pipelines[n].Slots = []config.Slot{}
		}
	}
	c.Policy, c.Packs, c.Subscribers = nil, nil, nil
	c.Sinks = nil
	seenSinks := make(map[string]bool)
	for _, p := range pipelines {
		for _, name := range p.Sinks {
			if !seenSinks[name] {
				c.Sinks = append(c.Sinks, config.Sink{Name: name, Kind: "local_account"})
				seenSinks[name] = true
			}
		}
	}
	raw, err = json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	plan, findings := config.CompileProcessing(raw, nil)
	if plan == nil || len(findings) != 0 {
		t.Fatalf("fixture compiler refused: %+v", findings)
	}
	return plan
}

func pipeline(name string, slots ...config.Slot) config.Pipeline {
	return config.Pipeline{Name: name, Input: "reconstruction", Slots: slots, Sinks: []string{"account"}}
}

func slot(name, implementation, args string) config.Slot {
	return config.Slot{Name: name, Implementation: implementation, Configuration: json.RawMessage(args), OnFailure: config.OnFailureDropAndAccount}
}

func worker(t *testing.T, plan *config.ProcessingPlan, output processing.Output) (*processing.Worker, *intake.Store) {
	t.Helper()
	store, err := intake.New(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1000, StorageExhausted: store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	w, err := processing.New(processing.Options{Plan: plan, PolicyRevision: "fixture-policy", Intake: store, Gate: gate, Output: output})
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
		s.Transfer(probe.Transfer{Process: p, Instance: i, Endpoint: 7, Direction: direction, Measured: true, Length: uint32(len(text)), Payload: []byte(text), Stamp: uint64(n + 1), At: at})
	}
	s.Closed(probe.Connection{Process: p, Instance: i, Endpoint: 7, Stamp: 3, At: at})
	if len(b.fragments) != 2 || len(b.records) != 1 {
		t.Fatal("fixture did not reach both capture callbacks")
	}
	for n := range b.fragments {
		b.fragments[n].Connection = id
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

func TestWorkerExecutesCompiledOrderOnIndependentCopies(t *testing.T) {
	replace := slot("replace", config.ReplaceHeaderValues, `{"headers":["x-public"],"value":"abcdef"}`)
	truncate := slot("truncate", config.TruncateHeaderValues, `{"headers":["x-public"],"length":3}`)
	plan := workerPlan(t, pipeline("unchanged"), pipeline("short", replace, truncate), pipeline("long", truncate, replace))
	out := &outputLog{}
	w, store := worker(t, plan, out)
	enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
	got := drain(t, w)
	if got.Written != 3 || len(out.artifacts) != 3 {
		t.Fatalf("three compiled routes must emit: %+v", got)
	}
	for n, want := range []string{"original", "abc", "abcdef"} {
		if value := field(t, out.artifacts[n], "x-public"); value != want {
			t.Errorf("route %d value %q want %q", n, value, want)
		}
		if out.artifacts[n].PolicyRevision != "fixture-policy" || out.artifacts[n].Version != processing.ArtifactVersion {
			t.Error("artifact provenance missing")
		}
	}
	if st := store.Stats(); st.Bytes != 0 || st.Leased != 0 {
		t.Fatalf("completed batch retains intake: %+v", st)
	}
}

func TestWorkerConnectionRouteContainsOnlyMetadata(t *testing.T) {
	metadata := config.Pipeline{Name: "metadata", Input: "connection", Sinks: []string{"account"}}
	out := &outputLog{}
	w, store := worker(t, workerPlan(t, pipeline("exchanges"), metadata), out)
	enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
	drain(t, w)
	if len(out.artifacts) != 2 {
		t.Fatalf("both route controls required, got %d", len(out.artifacts))
	}
	if field(t, out.artifacts[0], "x-public") != "original" {
		t.Fatal("reconstruction control lost permitted value")
	}
	if out.artifacts[1].Route.Pipeline != "metadata" || out.artifacts[1].Reconstruction != nil {
		t.Fatal("metadata exception carried reconstruction")
	}
	if strings.Contains(string(out.lines[1]), "original") || strings.Contains(string(out.lines[1]), "reconstruction") {
		t.Fatal("metadata route carries payload fields")
	}
}

func TestWorkerWaitsForOutstandingFragmentAfterRetirement(t *testing.T) {
	out := &outputLog{}
	w, store := worker(t, workerPlan(t, pipeline("exchanges")), out)
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
	if o.Pending != 0 || o.Written != 1 || len(out.artifacts) != 1 {
		t.Fatalf("late callback did not settle positive control: %+v", o)
	}
}

func TestWorkerFinalizationKeepsDecidablePrefixAndWithholdsTail(t *testing.T) {
	out := &outputLog{}
	w, store := worker(t, workerPlan(t, pipeline("exchanges")), out)
	b := batch(t, 1, goodRequest+"GET /later HTTP/1.1\r\nAuthorization: unfinished", goodResponse)
	b.records[0].How, b.records[0].Ended = connection.StillOpen, time.Time{}
	enqueue(t, store, b)
	if o := drain(t, w); o.Written != 0 || o.Pending != 1 {
		t.Fatalf("live batch prematurely emitted: %+v", o)
	}
	o, err := w.Finish(context.Background(), processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil || o.Written != 1 || o.Pending != 0 {
		t.Fatalf("prefix and tail: %+v %v", o, err)
	}
	if len(out.artifacts) != 1 || field(t, out.artifacts[0], "x-public") != "original" {
		t.Fatal("decidable prefix lost")
	}
	expectWithheld(t, o, connection.Uncounted("reconstruction_incomplete"))
	if strings.Contains(string(out.lines[0]), "unfinished") || strings.Contains(string(out.lines[0]), "/later") {
		t.Fatal("undecidable tail persisted")
	}
	if out.artifacts[0].Connection.Ending.How != "still_open" {
		t.Fatalf("capture end became close: %+v", out.artifacts[0].Connection.Ending)
	}
}

func TestWorkerProcessingFailureHonorsResolvedAction(t *testing.T) {
	for _, action := range []string{config.OnFailureDropAndAccount, config.OnFailureStopPipeline} {
		t.Run(action, func(t *testing.T) {
			s := slot("remove", config.RemoveHeaders, `{"headers":["authorization"]}`)
			s.OnFailure = action
			out := &outputLog{}
			w, store := worker(t, workerPlan(t, pipeline("exchanges", s)), out)
			enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
			if o := drain(t, w); o.Written != 1 {
				t.Fatalf("independent decidable control: %+v", o)
			}
			enqueue(t, store, batch(t, 2, "GET / HTTP/1.1\r\nBad : field\r\n\r\n", goodResponse))
			o := drain(t, w)
			if o.ProcessingFailures != 1 || o.Written != 1 {
				t.Fatalf("parse fault was not classified: %+v", o)
			}
			enqueue(t, store, batch(t, 3, goodRequest, goodResponse))
			o = drain(t, w)
			want := uint64(2)
			if action == config.OnFailureStopPipeline {
				want = 1
				if len(o.StoppedPipelines) != 1 {
					t.Fatal("stop action not recorded")
				}
			}
			if o.Written != want {
				t.Fatalf("action %s: %+v", action, o)
			}
		})
	}
}

func TestWorkerOutputFailureIsNotDeliveryAndIsTerminal(t *testing.T) {
	var out outputLog
	calls := 0
	failure := errors.New("constructed output failure")
	output := outputFunc(func(ctx context.Context, a processing.Approved) error {
		calls++
		if calls == 2 {
			return failure
		}
		return out.WriteApproved(ctx, a)
	})
	w, store := worker(t, workerPlan(t, pipeline("exchanges")), output)
	enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
	if o := drain(t, w); o.Written != 1 {
		t.Fatalf("write control: %+v", o)
	}
	enqueue(t, store, batch(t, 2, goodRequest, goodResponse))
	o, err := w.Drain(context.Background())
	if err == nil || o.OutputFailures != 1 || o.Written != 1 || calls != 2 {
		t.Fatalf("fault boundary: %+v %v calls=%d", o, err, calls)
	}
	enqueue(t, store, batch(t, 3, goodRequest, goodResponse))
	_, _ = w.Drain(context.Background())
	if calls != 2 || len(out.artifacts) != 1 {
		t.Fatal("output retried or falsely counted delivered")
	}
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
	for _, name := range []string{"gap-at-boundary", "gap-inside-message", "short-payload", "unterminated-message", "placement-at-boundary"} {
		t.Run(name, func(t *testing.T) {
			out := &outputLog{}
			plan := workerPlan(t, pipeline("exchanges"), config.Pipeline{Name: "metadata", Input: "connection", Sinks: []string{"account"}})
			w, store := worker(t, plan, out)
			enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
			if o := drain(t, w); o.Written != 2 || len(out.lines) != 2 {
				t.Fatalf("clean control did not emit both routes: %+v", o)
			}
			if field(t, out.artifacts[0], "x-public") != "original" || truncationOf(t, out.lines[0]) != nil {
				t.Fatal("clean control is not a useful untruncated exchange")
			}
			if count := out.artifacts[0].Reconstruction.Unplaced; count.State != record.Determined || count.Value != "0" {
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
				later.Payload = []byte("GET /after-hole HTTP/1.1\r\nX-Secret: hidden\r\n\r\n")
				later.Length = uint32(len(later.Payload))
				if later.Offset <= b.fragments[0].End() {
					t.Fatal("constructed hole was not reached")
				}
				b.fragments = append(b.fragments, later)
				b.records[0].Fragments = connection.Counted(3)
			case "short-payload":
				b.fragments[0].Length += 5
				if !b.fragments[0].Truncated() {
					t.Fatal("payload shortening was not reached")
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
			truncated := truncationOf(t, out.lines[2])
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
			if count := out.artifacts[2].Reconstruction.Unplaced; count.State != record.Undetermined || count.Value != "" || count.Why == "" {
				t.Fatalf("indeterminate suffix became a measured absence: %+v", count)
			}
			expectWithheld(t, o, connection.Uncounted("reconstruction_incomplete"))
			if truncationOf(t, out.lines[3]) != nil || out.artifacts[3].Reconstruction != nil {
				t.Fatal("metadata route received reconstruction state")
			}
			if out.artifacts[2].Connection.Ending.How != "handle_released" {
				t.Fatal("reconstruction truncation changed lifecycle ending")
			}
		})
	}
}
