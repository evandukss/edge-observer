package attach

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

const p3t9ProtectedMarker = "P3T9_PROTECTED_MARKER"

func p3t9ProtectedPlan(t *testing.T) *config.ProcessingPlan {
	t.Helper()
	raw, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["remove"] = map[string]any{"headers": []string{"authorization"}}
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	compiled, findings := config.Compile(raw, "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("published protected-plan control does not compile: %+v", findings)
	}
	plan := compiled.Plan
	routes := map[string]int{}
	for _, route := range plan.Routes() {
		routes[route.Pipeline]++
	}
	if len(routes) != 2 || routes[config.ExchangesPipeline] != 1 || routes[config.ConnectionsPipeline] != 1 || len(plan.Exclusions()) != 1 {
		t.Fatalf("compiled protected route/exclusion not witnessed: routes by pipeline %v, exclusions %d", routes, len(plan.Exclusions()))
	}
	return plan
}

// Inspect only Worker-produced Approved bytes, then delegate to the concrete
// Writer. This neither executes policy nor fabricates release permission.
type p3t9ApprovedBoundary struct {
	writer *processing.Writer
	mutex  sync.Mutex
	// handed counts the records handed to this output by route.pipeline. The
	// worker authorizes each record immediately before handing it here, so it
	// is also the authorized count per route.
	handed map[string]int
}

func p3t9ContainsProtected(v any) bool {
	switch v := v.(type) {
	case string:
		if strings.Contains(v, p3t9ProtectedMarker) {
			return true
		}
		decoded, err := base64.StdEncoding.DecodeString(v)
		return err == nil && bytes.Contains(decoded, []byte(p3t9ProtectedMarker))
	case []any:
		for _, x := range v {
			if p3t9ContainsProtected(x) {
				return true
			}
		}
	case map[string]any:
		for k, x := range v {
			if p3t9ContainsProtected(k) || p3t9ContainsProtected(x) {
				return true
			}
		}
	}
	return false
}

func (b *p3t9ApprovedBoundary) WriteApproved(ctx context.Context, a processing.Approved) error {
	var route struct {
		Route struct {
			Pipeline string `json:"pipeline"`
		} `json:"route"`
	}
	_ = json.Unmarshal(a.Bytes(), &route)
	b.mutex.Lock()
	if b.handed == nil {
		b.handed = map[string]int{}
	}
	b.handed[route.Route.Pipeline]++
	b.mutex.Unlock()
	var v any
	if err := json.Unmarshal(a.Bytes(), &v); err != nil {
		return fmt.Errorf("approved boundary did not receive a JSON artifact: %w", err)
	}
	if p3t9ContainsProtected(v) {
		return fmt.Errorf("protected marker reached approved write boundary")
	}
	return b.writer.WriteApproved(ctx, a)
}

// t20iHanded is how many records of this route were handed to the output.
func (b *p3t9ApprovedBoundary) t20iHanded(pipeline string) int {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.handed[pipeline]
}

type p3t9ProtectedCapture struct {
	t              *testing.T
	dir            string
	store          *intake.Store
	gate           *probe.DeliveryGate
	capture        *capture.Session
	attachment     *ebpfAttachment
	worker         *processing.Worker
	boundary       *p3t9ApprovedBoundary
	callbackErrors <-chan error
	stamp          uint64
	sealed         bool
	production     protectedSequenceSource
}

type protectedSequenceSource struct {
	next     uint64
	byHandle map[uint64]probe.Settlement
}

func (s *protectedSequenceSource) Settled(h probe.Handle) (probe.Settlement, error) {
	return s.byHandle[h.Endpoint], nil
}

func (*protectedSequenceSource) Unlocated() (uint64, error) { return 0, nil }

func p3t9Protected(t *testing.T, maxEvents uint64, hook func()) *p3t9ProtectedCapture {
	t.Helper()
	return p3t9ProtectedWithIntakeLimit(t, maxEvents, 1<<20, hook)
}

// Observe the actual callback result without replacing the intake, retaining
// source payload, changing the error, or deciding release permission.
type p3t9IntakeCallbacks struct {
	store  *intake.Store
	errors chan error
}

func (s *p3t9IntakeCallbacks) Write(r fragment.Record) error {
	err := s.store.Write(r)
	if err != nil {
		select {
		case s.errors <- err:
		default:
		}
	}
	return err
}

func (s *p3t9IntakeCallbacks) Connection(r connection.Record) error {
	err := s.store.Connection(r)
	if err != nil {
		select {
		case s.errors <- err:
		default:
		}
	}
	return err
}

func p3t9ProtectedWithIntakeLimit(t *testing.T, maxEvents uint64, intakeBytes int64, hook func(), connectionBound ...int) *p3t9ProtectedCapture {
	t.Helper()
	plan := p3t9ProtectedPlan(t)
	s, err := intake.New(intakeBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: maxEvents, IntakeExhausted: s.Exhausted(), BeforeAuthorize: hook})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	w, err := processing.Open(dir, 1<<20)
	if err != nil {
		t.Fatalf("real approved writer unavailable; protected property NOT reached: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	b := &p3t9ApprovedBoundary{writer: w}
	bound := 0
	if len(connectionBound) != 0 {
		bound = connectionBound[0]
	}
	worker, err := processing.New(processing.Options{ConnectionInput: bound, Plan: plan, PolicyRevision: "p3t9-policy", Session: "p3t9-session", Intake: s, Gate: g, Output: b})
	if err != nil {
		t.Fatalf("real worker unavailable; protected property NOT reached: %v", err)
	}
	t.Cleanup(func() { _ = worker.Close() })
	callbacks := &p3t9IntakeCallbacks{store: s, errors: make(chan error, 8)}
	c := capture.Recording(callbacks, callbacks)
	a := &ebpfAttachment{gate: g, sink: c, procfs: t.TempDir(), known: make(map[int32]identity)}
	f := &p3t9ProtectedCapture{t: t, dir: dir, store: s, gate: g, capture: c, attachment: a, worker: worker, boundary: b, callbackErrors: callbacks.errors}
	f.production.byHandle = make(map[uint64]probe.Settlement)
	c.Settling(&f.production)
	return f
}

// The only source here is controlled decoded delivery. Sealing prevents any
// later delivery and every call is synchronous, establishing this test source's
// withdrawn/drained facts. It is NOT a kernel attachment or T5 activation.
func (f *p3t9ProtectedCapture) send(handle uint64, direction fragment.Direction, payload string, measured bool, closed bool) {
	f.t.Helper()
	if f.sealed {
		f.t.Fatal("fixture attempted delivery after source withdrawal")
	}
	f.stamp++
	e := p3t9Event(f.stamp, payload)
	e.SSL, e.Direction, e.Measured = handle, direction, measured
	state := f.production.byHandle[handle]
	if state.Occupancy == 0 && measured && len(payload) > 0 && !closed {
		f.production.next++
		state = probe.Settlement{Occupancy: f.production.next, Final: probe.Final{Known: true}}
	}
	e.Sequence = probe.Sequence{Occupancy: state.Occupancy, Born: state.Occupancy != 0}
	if measured && len(payload) > 0 && !closed {
		terminal := &state.Final.Sent
		if direction == fragment.Received {
			terminal = &state.Final.Received
		}
		terminal.Last++
		e.Sequence.Number = terminal.Last
		f.production.byHandle[handle] = state
	}
	if closed {
		e.Kind, e.Measured, e.Length, e.Payload = ebpf.Closed, false, 0, nil
		e.Final = state.Final
		delete(f.production.byHandle, handle)
	}
	if !measured && !closed {
		e.Length, e.Payload = 0, nil
	}
	f.attachment.deliverEvent(e)
}

func (f *p3t9ProtectedCapture) exchange(handle uint64, target string, closed bool) {
	f.send(handle, fragment.Sent, "GET "+target+" HTTP/1.1\r\nHost: test\r\nX-public: benign\r\nAuthorization: "+p3t9ProtectedMarker+"\r\n\r\n", true, false)
	f.send(handle, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-public: response\r\n\r\nOK", true, false)
	if closed {
		f.send(handle, fragment.Sent, "", false, true)
	}
}

func (f *p3t9ProtectedCapture) drain() processing.Outcome {
	f.t.Helper()
	o, err := f.worker.Drain(context.Background())
	if err != nil {
		f.t.Fatalf("real worker Drain failed: %v, outcome %+v", err, o)
	}
	return o
}

func (f *p3t9ProtectedCapture) finish() processing.Outcome {
	f.t.Helper()
	f.sealed = true
	f.capture.Finish(time.Unix(101, 0))
	o, err := f.worker.Finish(context.Background(), processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil {
		f.t.Fatalf("real worker Finish failed: %v, outcome %+v", err, o)
	}
	if o.Pending != 0 || f.store.Stats().Bytes != 0 {
		f.t.Fatalf("Finish retained pending payload: outcome %+v storage %+v", o, f.store.Stats())
	}
	return o
}

// delivered waits until the approved writer has finished with every line
// handed to it: delivery is asynchronous to the worker's handing.
func (f *p3t9ProtectedCapture) delivered() {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.boundary.writer.Drain(ctx); err != nil {
		f.t.Fatalf("the approved writer did not finish the lines handed to it: %v", err)
	}
}

func (f *p3t9ProtectedCapture) artifacts(want int) ([]processing.Artifact, []byte) {
	f.t.Helper()
	f.delivered()
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		f.t.Fatal(err)
	}
	// The stable approved file is opened by its sink, which may not have
	// created it where nothing was ever written.
	if len(entries) == 0 && want == 0 && f.boundary.t20iHanded(config.ExchangesPipeline) == 0 {
		return nil, nil
	}
	if len(entries) != 1 || entries[0].Name() != processing.ArtifactName {
		f.t.Fatalf("unexpected durable path population: %v", entries)
	}
	raw, err := os.ReadFile(filepath.Join(f.dir, processing.ArtifactName))
	if err != nil {
		f.t.Fatal(err)
	}
	var artifacts []processing.Artifact
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var anyValue any
		if err := json.Unmarshal(line, &anyValue); err != nil {
			f.t.Fatal(err)
		}
		if p3t9ContainsProtected(anyValue) {
			f.t.Fatal("protected plaintext present in decoded durable artifact")
		}
		var a processing.Artifact
		if err := json.Unmarshal(line, &a); err != nil {
			f.t.Fatal(err)
		}
		switch a.Route.Pipeline {
		case config.ExchangesPipeline:
			if a.Version != processing.ArtifactVersion || a.PolicyRevision != "p3t9-policy" || a.Route.Sink != "account" || a.Reconstruction == nil {
				f.t.Fatalf("approved artifact lacks published provenance: %+v", a)
			}
			artifacts = append(artifacts, a)
		case config.ConnectionsPipeline:
			if a.Version != processing.ArtifactVersion || a.PolicyRevision != "p3t9-policy" || a.Route.Sink != "account" {
				f.t.Fatalf("approved connection record lacks published provenance: %+v", a)
			}
		default:
			f.t.Fatalf("approved record on a route that is neither exchanges nor connections: %+v", a.Route)
		}
	}
	if len(artifacts) != want || f.boundary.t20iHanded(config.ExchangesPipeline) != want {
		f.t.Fatalf("approved exchanges records: persisted=%d handed to the output=%d want=%d", len(artifacts), f.boundary.t20iHanded(config.ExchangesPipeline), want)
	}
	return artifacts, raw
}

// t20iPersisted is how many records of this route the approved output holds.
func (f *p3t9ProtectedCapture) t20iPersisted(pipeline string) int {
	f.t.Helper()
	f.delivered()
	raw, err := os.ReadFile(filepath.Join(f.dir, processing.ArtifactName))
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		f.t.Fatal(err)
	}
	count := 0
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var route struct {
			Route struct {
				Pipeline string `json:"pipeline"`
			} `json:"route"`
		}
		if err := json.Unmarshal(line, &route); err != nil {
			f.t.Fatal(err)
		}
		if route.Route.Pipeline == pipeline {
			count++
		}
	}
	return count
}

func p3t9Useful(t *testing.T, a processing.Artifact, target, ending string) {
	t.Helper()
	if a.Connection.Ending.How != ending || len(a.Reconstruction.Exchanges) != 1 {
		t.Fatalf("wrong batch/exchange population: %+v", a)
	}
	x := a.Reconstruction.Exchanges[0]
	if !x.Complete || x.Request.Message == nil || x.Response.Message == nil {
		t.Fatal("approved result is not a complete paired exchange")
	}
	request, response := x.Request.Message, x.Response.Message
	if request.Target != target || response.Status == nil || *response.Status != 200 {
		t.Fatal("approved result lost useful request/response values")
	}
	public := false
	for _, h := range request.Headers {
		if strings.EqualFold(h.Name, "authorization") {
			t.Fatal("excluded header survived processing")
		}
		if strings.EqualFold(h.Name, "x-public") && h.Value == "benign" {
			public = true
		}
	}
	if !public {
		t.Fatal("permitted header value did not survive processing")
	}
	body, err := base64.StdEncoding.DecodeString(response.Body.Kept)
	if err != nil || string(body) != "OK" {
		t.Fatalf("published approved body is not useful base64 payload: %q, %v", response.Body.Kept, err)
	}
}

func TestP3T9ProtectedWitnessAndMeasuredOutput(t *testing.T) {
	for _, measured := range []bool{true, false} {
		name := "unknown_length"
		if measured {
			name = "fully_measured"
		}
		t.Run(name, func(t *testing.T) {
			f := p3t9Protected(t, 32, nil)
			f.send(9, fragment.Sent, "GET /witness HTTP/1.1\r\nHost: test\r\nX-public: ", true, false)
			if f.capture.Stats().Records != 1 || f.store.Stats().Fragments != 1 {
				t.Fatal("witness prefix did not reach real intake")
			}
			if o := f.drain(); o.Pending != 1 || f.t20iPersisted(config.ExchangesPipeline) != 0 {
				t.Fatalf("live prefix not held by real worker: exchanges records persisted %d, %+v", f.t20iPersisted(config.ExchangesPipeline), o)
			}
			f.artifacts(0)
			f.send(9, fragment.Sent, "benign\r\nAuthorization: ", measured, false)
			f.send(9, fragment.Sent, p3t9ProtectedMarker+"\r\n\r\n", true, false)
			f.send(9, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", true, false)
			f.send(9, fragment.Sent, "", false, true)
			if measured {
				p3t9Reason(t, f.gate, 5, "")
				if f.capture.Stats().Closed != 1 {
					t.Fatal("ordinary Measured=false close below N failed")
				}
				if o := f.drain(); f.t20iPersisted(config.ExchangesPipeline) != 1 || f.boundary.t20iHanded(config.ExchangesPipeline) != 1 || o.ProcessingFailures != 0 {
					t.Fatalf("measured closed control did not produce useful output: exchanges records persisted %d, authorized %d, %+v",
						f.t20iPersisted(config.ExchangesPipeline), f.boundary.t20iHanded(config.ExchangesPipeline), o)
				}
				a, _ := f.artifacts(1)
				p3t9Useful(t, a[0], "/witness", "handle_released")
			} else {
				p3t9Reason(t, f.gate, 2, probe.GateUnknownLength)
				if f.capture.Stats().Records != 1 || f.capture.Stats().Closed != 0 {
					t.Fatal("unknown transfer failed to refuse the suffix before capture")
				}
				t.Log("unknown_length_reached_with_real_worker_pending_prefix")
			}
			o := f.finish()
			want := 0
			if measured {
				want = 1
			} else if o.GateReason != probe.GateUnknownLength || f.boundary.t20iHanded(config.ExchangesPipeline) != 0 || f.t20iPersisted(config.ExchangesPipeline) != 0 {
				t.Fatalf("Finish released invalidated witness: exchanges records authorized %d, persisted %d, %+v",
					f.boundary.t20iHanded(config.ExchangesPipeline), f.t20iPersisted(config.ExchangesPipeline), o)
			}
			f.artifacts(want)
		})
	}
}

func TestP3T9ProtectedDrainedLimitAndPendingFinish(t *testing.T) {
	for _, count := range []int{3, 4, 5} {
		t.Run([]string{"N_minus_1", "N", "N_plus_1"}[count-3], func(t *testing.T) {
			// Isolate the shared reservation bound from the independent
			// per-connection cut. All admitted fragments remain with the worker.
			f := p3t9ProtectedWithIntakeLimit(t, 4, 1<<20, nil, 8)
			parts := []string{"GET /limit HTTP/1.1\r\nHost: test\r\n", "X-public: benign\r\n", "Authorization: " + p3t9ProtectedMarker + "\r\n\r\n"}
			if count == 3 {
				parts = []string{parts[0] + parts[1], parts[2]}
			}
			for _, part := range parts {
				f.send(9, fragment.Sent, part, true, false)
			}
			f.send(9, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", true, false)
			if o := f.drain(); o.Pending != 1 || o.ConnectionsCut != 0 || f.t20iPersisted(config.ExchangesPipeline) != 0 {
				t.Fatalf("complete-but-live batch was not pending without a cut: %+v", o)
			}
			if f.gate.Snapshot().Held != uint64(min(count, 4)) {
				t.Fatalf("wiring, not the property: worker did not retain the input reservations: %+v", f.gate.Snapshot())
			}
			f.artifacts(0)
			if count == 5 {
				f.send(99, fragment.Sent, "tail", true, false)
			}
			reason, charged := probe.GateReason(""), uint64(count)
			if count == 5 {
				reason, charged = probe.GateInputLimit, 4
			}
			p3t9Reason(t, f.gate, charged, reason)
			if f.capture.Stats().Records != int64(min(count, 4)) || f.capture.Stats().Closed != 0 {
				t.Fatal("limit fixture changed the complete live exchange population")
			}
			if count == 5 {
				t.Log("input_limit_reached_with_real_worker_pending_complete_exchange")
			}
			o := f.finish()
			if o.GateReason != reason {
				t.Fatalf("wrong final gate reason: %+v", o)
			}
			if count == 5 {
				if f.boundary.t20iHanded(config.ExchangesPipeline) != 0 || f.t20iPersisted(config.ExchangesPipeline) != 0 {
					t.Fatalf("refused tail became approved at Finish: exchanges records authorized %d, persisted %d, %+v",
						f.boundary.t20iHanded(config.ExchangesPipeline), f.t20iPersisted(config.ExchangesPipeline), o)
				}
				f.artifacts(0)
			} else {
				if f.boundary.t20iHanded(config.ExchangesPipeline) != 1 || f.t20iPersisted(config.ExchangesPipeline) != 1 {
					t.Fatalf("below/at-limit pending control did not finalize: exchanges records authorized %d, persisted %d, %+v",
						f.boundary.t20iHanded(config.ExchangesPipeline), f.t20iPersisted(config.ExchangesPipeline), o)
				}
				a, _ := f.artifacts(1)
				p3t9Useful(t, a[0], "/limit", "still_open")
			}
		})
	}
}

func TestP3T9ProtectedWorkerHeldAuthorizationKeepsPriorResult(t *testing.T) {
	for _, fault := range []probe.GateReason{probe.GateUnknownLength, probe.GateInputLimit, probe.GateIntakeExhausted} {
		t.Run(string(fault), func(t *testing.T) {
			for _, inject := range []bool{false, true} {
				name := "successful_neighbor"
				if inject {
					name = "reached_fault"
				}
				t.Run(name, func(t *testing.T) {
					entered, release := make(chan struct{}), make(chan struct{})
					var hold atomic.Bool
					var once sync.Once
					unblock := func() { once.Do(func() { close(release) }) }
					limit, intakeBytes := uint64(32), int64(1<<20)
					if fault == probe.GateInputLimit {
						limit = 4
						if inject {
							limit = 3
						}
					}
					if fault == probe.GateIntakeExhausted {
						intakeBytes = 16384
						if inject {
							intakeBytes = 8192
						}
					}
					// Each batch now authorizes two records, its exchanges record and
					// its connection record; the hold is the candidate batch's first.
					f := p3t9ProtectedWithIntakeLimit(t, limit, intakeBytes, func() {
						if hold.CompareAndSwap(true, false) {
							close(entered)
							<-release
						}
					}, 8)
					// Release before worker.Close even if a test assertion fails.
					t.Cleanup(unblock)
					f.exchange(9, "/prior", true)
					if o := f.drain(); f.t20iPersisted(config.ExchangesPipeline) != 1 || f.boundary.t20iHanded(config.ExchangesPipeline) != 1 {
						t.Fatalf("independently closed prior batch was not approved: exchanges records persisted %d, authorized %d, %+v",
							f.t20iPersisted(config.ExchangesPipeline), f.boundary.t20iHanded(config.ExchangesPipeline), o)
					}
					prior, priorBytes := f.artifacts(1)
					p3t9Useful(t, prior[0], "/prior", "handle_released")
					f.exchange(10, "/candidate", true)
					if f.capture.Stats().Closed != 2 {
						t.Fatal("second real closed batch missing")
					}
					before := f.store.Stats()
					if before.Exhausted || before.Fragments != 4 || before.Connections != 2 || before.FragmentsRefused != 0 || before.ConnectionsRefused != 0 {
						t.Fatalf("declared two-batch population did not reach intake: %+v", before)
					}
					hold.Store(true)
					type result struct {
						outcome processing.Outcome
						err     error
					}
					done := make(chan result, 1)
					go func() { o, err := f.worker.Drain(context.Background()); done <- result{o, err} }()
					select {
					case <-entered:
					case <-time.After(3 * time.Second):
						t.Fatal("real worker did not reach held authorization")
					}
					leased := f.store.Stats().Leased
					if leased == 0 {
						t.Fatal("worker reached authorization without charged batch leases")
					}
					f.artifacts(1)
					if fault == probe.GateInputLimit && f.gate.Snapshot().Held != 3 {
						t.Fatalf("candidate did not retain three slots: %+v", f.gate.Snapshot())
					}
					// One fixed delivery population per fault/neighbor pair. The
					// storage pair uses real maximum-sized fragments, not a signal
					// manufactured by the test or a loop bounded by subject counts.
					delivered := make(chan struct{})
					go func() {
						defer close(delivered)
						if fault == probe.GateIntakeExhausted {
							for i := 0; i < 2; i++ {
								f.send(99, fragment.Sent, strings.Repeat("S", 4096), true, false)
							}
						} else if fault == probe.GateInputLimit {
							f.send(99, fragment.Sent, "pending", true, false)
						} else {
							f.send(99, fragment.Sent, "", !inject || fault != probe.GateUnknownLength, false)
						}
					}()
					select {
					case <-delivered:
					case <-time.After(3 * time.Second):
						t.Fatal("held worker blocked independent capture delivery")
					}
					wantReason := probe.GateReason("")
					if inject {
						wantReason = fault
					}
					charged := uint64(7)
					if inject && fault == probe.GateInputLimit {
						charged = 6
					}
					if fault == probe.GateIntakeExhausted {
						charged = 8
						after := f.store.Stats()
						if after.Leased != leased {
							t.Fatalf("storage callback discarded held worker leases: before %d after %+v", leased, after)
						}
						if inject {
							select {
							case err := <-f.callbackErrors:
								if !errors.Is(err, intake.ErrLimit) {
									t.Fatalf("wrong real callback refusal: %v", err)
								}
							default:
								t.Fatal("actual intake ErrLimit NOT reached")
							}
							select {
							case <-f.store.Exhausted():
							default:
								t.Fatal("actual intake refusal did not signal exhaustion")
							}
							if !after.Exhausted || after.FragmentsRefused != 1 || after.Fragments != 5 || after.ConnectionsRefused != 0 || f.capture.Stats().Rejected != 1 {
								t.Fatalf("fixed storage population did not reach exactly the second-fragment refusal: %+v capture %+v", after, f.capture.Stats())
							}
							t.Log("intake_exhausted_reached: actual ErrLimit, store-owned signal, one rejected fragment, real closed batch still leased at authorization, prior artifact already useful")
						} else {
							select {
							case err := <-f.callbackErrors:
								t.Fatalf("nonexhausted neighbor had callback refusal: %v", err)
							default:
							}
							select {
							case <-f.store.Exhausted():
								t.Fatal("nonexhausted neighbor signaled exhaustion")
							default:
							}
							if after.Exhausted || after.FragmentsRefused != 0 || after.Fragments != 6 || f.capture.Stats().Rejected != 0 {
								t.Fatalf("same-input storage neighbor did not accept both fragments: %+v", after)
							}
						}
						// NO gate call here: Snapshot or controller consumption could
						// hide a worker that fails to observe storage at Authorize.
					} else {
						p3t9Reason(t, f.gate, charged, wantReason)
						if inject {
							t.Logf("%s_reached_while_real_closed_batch_held_before_authorization", fault)
						}
					}
					unblock()
					select {
					case r := <-done:
						if r.err != nil {
							t.Fatalf("held worker failed: %v %+v", r.err, r.outcome)
						}
					case <-time.After(3 * time.Second):
						t.Fatal("real worker failed to resume after barrier")
					}
					hold.Store(false)
					// Observe the authorization effect before Snapshot/Finish can
					// consume a missed storage signal or change the output history.
					select {
					case <-f.gate.Withdrawal():
						if !inject {
							t.Fatal("successful neighbor requested withdrawal")
						}
					default:
						if inject {
							t.Fatal("worker resumed after invalidation without withdrawal request")
						}
					}
					want := 2
					if inject {
						want = 1
					}
					f.artifacts(want)
					p3t9Reason(t, f.gate, charged, wantReason)
					o := f.finish()
					if f.t20iPersisted(config.ExchangesPipeline) != want || f.boundary.t20iHanded(config.ExchangesPipeline) != want || o.GateReason != wantReason {
						t.Fatalf("candidate authorization/output crossed invalidation: exchanges records persisted %d, authorized %d, want %d, %+v",
							f.t20iPersisted(config.ExchangesPipeline), f.boundary.t20iHanded(config.ExchangesPipeline), want, o)
					}
					a, afterBytes := f.artifacts(want)
					if !bytes.HasPrefix(afterBytes, priorBytes) || (inject && !bytes.Equal(afterBytes, priorBytes)) {
						t.Fatal("later fault recalled or altered the earlier approved result")
					}
					p3t9Useful(t, a[0], "/prior", "handle_released")
					if !inject {
						if a[0].Connection.ID == a[1].Connection.ID {
							t.Fatal("prior and candidate were not independent batches")
						}
						p3t9Useful(t, a[1], "/candidate", "handle_released")
					}
				})
			}
		})
	}
}
