package processing_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

// Synthetic snapshots isolate the consumer's obligation from capture's
// implementation. Every value comes from the fixture's operation transcript.
// The separate capture-to-worker case checks the actual carriage boundary.
type certificationReleaseStream struct {
	identity *fragment.Identity
	evidence fragment.Evidence
}

func certificationReleaseOrigin(id uint64) *certificationReleaseStream {
	identity := &fragment.Identity{
		Connection: fragment.ConnectionID(id), Process: fragment.Process{PID: 1901, StartTime: 83},
		Instance: admission.Instance{Namespace: admission.Namespace{Device: 4, Inode: 9}, PID: 1901, Start: admission.Determinate(83), Generation: 1, Executable: "/usr/bin/service"},
		Address:  0x80 + id, Generation: id, FirstSeen: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	return &certificationReleaseStream{identity: identity, evidence: fragment.Evidence{Identity: identity, Occupancy: id, Origin: fragment.OriginBirth}}
}

func (s *certificationReleaseStream) next(direction fragment.Direction, payload string) fragment.Record {
	s.evidence.Through++
	d := &s.evidence.Sent
	if direction == fragment.Received {
		d = &s.evidence.Received
	}
	offset := d.Limit
	d.Limit += uint64(len(payload))
	d.Numbered++
	d.Resolved = d.Numbered
	if d.First == 0 {
		d.First = d.Numbered
	}
	return fragment.Record{Process: s.identity.Process, Connection: s.identity.Connection, Direction: direction,
		Sequence: s.evidence.Through, Offset: offset, Length: uint32(len(payload)), Produced: d.Numbered,
		Payload: []byte(payload), At: s.identity.FirstSeen, Evidence: s.evidence}
}

func certificationReleaseRequest(target string) string {
	return "POST " + target + " HTTP/1.1\r\nHost: local\r\nContent-Length: 4\r\n\r\nABCD"
}
func certificationReleaseResponse(body string) string {
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
}

type certificationReleaseOutput struct {
	approved  []processing.Approved
	frozen    [][]byte
	artifacts []processing.Artifact
}

func (o *certificationReleaseOutput) WriteApproved(_ context.Context, a processing.Approved) error {
	line := a.Bytes()
	var artifact processing.Artifact
	if err := json.Unmarshal(line, &artifact); err != nil {
		return err
	}
	o.approved = append(o.approved, a)
	o.frozen = append(o.frozen, append([]byte(nil), line...))
	o.artifacts = append(o.artifacts, artifact)
	return nil
}
func (o *certificationReleaseOutput) exchanges() []processing.Artifact {
	var out []processing.Artifact
	for _, a := range o.artifacts {
		if a.Record == processing.ArtifactExchange {
			out = append(out, a)
		}
	}
	return out
}
func (o *certificationReleaseOutput) unchanged(t *testing.T) {
	t.Helper()
	for i, a := range o.approved {
		if !bytes.Equal(a.Bytes(), o.frozen[i]) {
			t.Errorf("approved line %d changed after later input", i)
		}
	}
}

type certificationReleaseFixture struct {
	worker *processing.Worker
	store  *intake.Store
	gate   *probe.DeliveryGate
	output *certificationReleaseOutput
	turns  []processing.Turn
}

func certificationReleaseNew(t *testing.T) *certificationReleaseFixture {
	t.Helper()
	compiled, findings := config.Compile([]byte(`{"version":"observer.config/1","output":"/var/lib/observer","watch":[{"name":"api","exe":"/usr/bin/service"}]}`), "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: configuration refused: %+v", findings)
	}
	store, err := intake.New(4 << 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4096, IntakeExhausted: store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	f := &certificationReleaseFixture{store: store, gate: gate, output: &certificationReleaseOutput{}}
	options := processing.Options{Plan: compiled.Plan, PolicyRevision: "certification-policy", Session: "certification-session", Intake: store, Gate: gate, Output: f.output}
	options = processing.ObserveTurns(options, func(turn processing.Turn) { f.turns = append(f.turns, turn) })
	f.worker, err = processing.New(options)
	if err != nil {
		t.Fatalf("wiring, not the property: worker construction: %v", err)
	}
	t.Cleanup(func() { _ = f.worker.Close() })
	return f
}
func (f *certificationReleaseFixture) put(t *testing.T, records ...fragment.Record) {
	t.Helper()
	for _, r := range records {
		if err := r.Validate(); err != nil {
			t.Fatalf("wiring, not the property: invalid synthetic record: %v", err)
		}
		if r.Evidence.Taken() {
			if err := r.Evidenced(); err != nil {
				t.Fatalf("wiring, not the property: synthetic snapshot does not bind: %v", err)
			}
		}
		if err := f.store.Write(r); err != nil {
			t.Fatalf("wiring, not the property: fixture intake refused: %v", err)
		}
	}
}
func (f *certificationReleaseFixture) drain(t *testing.T, count int) {
	t.Helper()
	start := len(f.turns)
	if _, err := f.worker.Drain(context.Background()); err != nil {
		t.Fatalf("worker drain: %v", err)
	}
	taken := 0
	for _, turn := range f.turns[start:] {
		taken += turn.Taken
	}
	if taken != count {
		t.Fatalf("wiring, not the property: worker took %d of %d fixture entries", taken, count)
	}
	t.Logf("PRECONDITIONS taken=%d retirement_records=%d", taken, f.store.Stats().Connections)
}
func certificationReleasePair(t *testing.T, a processing.Artifact, id uint64, index int, target, response string) {
	t.Helper()
	if a.Connection.ID != strconv.FormatUint(id, 10) || a.Index == nil || *a.Index != index || a.ExchangeID == "" {
		t.Errorf("release identity/index missing: %+v", a)
	}
	if a.Version != processing.ArtifactVersion4 || !a.Connection.Provisional {
		t.Errorf("online exchange carries final or legacy metadata: %+v", a.Connection)
	}
	for _, present := range a.Connection.Lifecycle() {
		if present {
			t.Error("online exchange states a lifecycle or connection total")
		}
	}
	if a.Reconstruction == nil || len(a.Reconstruction.Exchanges) != 1 {
		t.Fatal("released line lacks its one exchange")
	}
	if a.Reconstruction.Unplaced != (record.Count{State: record.Undetermined, Unit: record.Bytes, Why: record.WhyProvisional}) {
		t.Errorf("online exchange states an unplaced total: %+v", a.Reconstruction.Unplaced)
	}
	x := a.Reconstruction.Exchanges[0]
	if x.Request.Message == nil || x.Response.Message == nil {
		t.Fatal("released line lacks a paired message")
	}
	if !x.Complete || x.Request.Message.Target != target || x.Response.Message.Body.Kept != base64.StdEncoding.EncodeToString([]byte(response)) {
		t.Errorf("release differs from known wire pair: %+v", x)
	}
}

func TestReleaseCertifiedOpenPairAdvancesBeforeRetirement(t *testing.T) {
	f := certificationReleaseNew(t)
	s := certificationReleaseOrigin(1)
	firstRequest := s.next(fragment.Sent, certificationReleaseRequest("/first"))
	firstResponse := s.next(fragment.Received, certificationReleaseResponse("FIRST"))
	f.put(t, firstRequest, firstResponse)
	f.drain(t, 2)
	lines := f.output.exchanges()
	if len(lines) != 1 {
		t.Fatalf("certified idle open pair not released in its input turn: lines=%d", len(lines))
	}
	certificationReleasePair(t, lines[0], 1, 0, "/first", "FIRST")
	firstFrozen := append([]byte(nil), f.output.frozen[0]...)
	f.put(t, s.next(fragment.Sent, certificationReleaseRequest("/second")), s.next(fragment.Received, certificationReleaseResponse("SECOND")))
	f.drain(t, 2)
	lines = f.output.exchanges()
	if len(lines) != 2 {
		t.Fatalf("second certified prefix did not advance: lines=%d", len(lines))
	}
	certificationReleasePair(t, lines[1], 1, 1, "/second", "SECOND")
	if lines[0].ExchangeID == lines[1].ExchangeID {
		t.Error("successive exchanges reused an id")
	}
	if !bytes.Equal(firstFrozen, f.output.approved[0].Bytes()) {
		t.Error("later prefix changed first released bytes")
	}
	f.output.unchanged(t)
}

func TestReleaseRequiresContiguousReceiptAndEstablishedBytes(t *testing.T) {
	for _, name := range []string{"no snapshot", "unknown origin", "cut before request", "missing fragment", "missing producer number", "nonzero first offset", "truncated body"} {
		t.Run(name, func(t *testing.T) {
			f := certificationReleaseNew(t)
			bad := certificationReleaseOrigin(1)
			rq := bad.next(fragment.Sent, certificationReleaseRequest("/unsafe"))
			rs := bad.next(fragment.Received, certificationReleaseResponse("UNSAFE"))
			switch name {
			case "no snapshot":
				rq.Evidence = fragment.Evidence{}
				rs.Evidence = fragment.Evidence{}
			case "unknown origin":
				for _, r := range []*fragment.Record{&rq, &rs} {
					r.Evidence.Origin = fragment.OriginUnestablished
					r.Evidence.Sent.Cut = true
					r.Evidence.Received.Cut = true
				}
			case "cut before request":
				rq.Evidence.Sent.Cut = true
				rs.Evidence.Sent.Cut = true
			case "missing fragment":
				rq.Sequence++
				rq.Evidence.Through++
				rs.Sequence++
				rs.Evidence.Through++
			case "missing producer number":
				rq.Produced = 2
				for _, r := range []*fragment.Record{&rq, &rs} {
					r.Evidence.Sent.Numbered = 2
					r.Evidence.Sent.Resolved = 2
				}
			case "nonzero first offset":
				rq.Offset = 1
				rq.Evidence.Sent.Limit++
				rs.Evidence.Sent.Limit++
			case "truncated body":
				rq.Payload = rq.Payload[:len(rq.Payload)-2]
			}
			good := certificationReleaseOrigin(2)
			f.put(t, rq, rs, good.next(fragment.Sent, certificationReleaseRequest("/control")), good.next(fragment.Received, certificationReleaseResponse("CONTROL")))
			f.drain(t, 4)
			lines := f.output.exchanges()
			if len(lines) != 1 {
				t.Errorf("one healthy control and no unsafe pair required: lines=%d", len(lines))
			}
			for _, a := range lines {
				certificationReleasePair(t, a, 2, 0, "/control", "CONTROL")
			}
		})
	}
}

func TestReleaseMissingReceiptCanBecomeEligibleOnlyWhenReceived(t *testing.T) {
	f := certificationReleaseNew(t)
	s := certificationReleaseOrigin(1)
	rq := s.next(fragment.Sent, certificationReleaseRequest("/delayed"))
	rs := s.next(fragment.Received, certificationReleaseResponse("DELAYED"))
	f.put(t, rs)
	f.drain(t, 1)
	if len(f.output.exchanges()) != 0 {
		t.Fatal("later snapshot authorized absent earlier fragment")
	}
	f.put(t, rq)
	f.drain(t, 1)
	lines := f.output.exchanges()
	if len(lines) != 1 {
		t.Fatalf("complete contiguous receipt did not unblock open pair: %d", len(lines))
	}
	certificationReleasePair(t, lines[0], 1, 0, "/delayed", "DELAYED")
}

func TestReleaseLaterGapAndCallbackCannotRewriteEarlierPrefix(t *testing.T) {
	f := certificationReleaseNew(t)
	s := certificationReleaseOrigin(1)
	f.put(t, s.next(fragment.Sent, certificationReleaseRequest("/before")), s.next(fragment.Received, certificationReleaseResponse("BEFORE")))
	f.drain(t, 2)
	lines := f.output.exchanges()
	if len(lines) != 1 {
		t.Fatalf("initial known prefix not released before adversary: %d", len(lines))
	}
	certificationReleasePair(t, lines[0], 1, 0, "/before", "BEFORE")
	boundary := s.evidence.Sent.Limit
	late := s.next(fragment.Sent, certificationReleaseRequest("/late"))
	after := s.next(fragment.Sent, certificationReleaseRequest("/after-gap"))
	// Capture cannot advance over an absent operation's unknown length.
	after.Offset = boundary
	after.Evidence.Sent.Limit = boundary + uint64(after.Length)
	after.Evidence.Sent.Cut = true
	after.Evidence.Sent.From = boundary
	after.Evidence.Sent.Resolved = 1
	after.Evidence.Sent.Lost = 1
	s.evidence = after.Evidence
	response := s.next(fragment.Received, certificationReleaseResponse("AFTER"))
	f.put(t, after, response)
	f.drain(t, 2)
	f.put(t, late)
	f.drain(t, 1)
	if len(f.output.exchanges()) != 1 {
		t.Error("late callback resumed parsing across the first unresolved byte")
	}
	f.output.unchanged(t)
}

func TestReleaseTerminalInvalidationPreservesOnlyEarlierAuthorization(t *testing.T) {
	f := certificationReleaseNew(t)
	s := certificationReleaseOrigin(1)
	f.put(t, s.next(fragment.Sent, certificationReleaseRequest("/authorized")), s.next(fragment.Received, certificationReleaseResponse("AUTHORIZED")))
	f.drain(t, 2)
	if len(f.output.exchanges()) != 1 {
		t.Fatal("initial positive control did not reach authorization")
	}
	decision := f.gate.Admit(probe.DeliveryKind(255), true)
	if decision.Admitted || decision.State.Reason == "" {
		t.Fatal("wiring, not the property: unknown event did not invalidate the gate")
	}
	if decision.Slot != nil {
		decision.Slot.Refund(held.Unretained)
	}
	f.put(t, s.next(fragment.Sent, certificationReleaseRequest("/forbidden")), s.next(fragment.Received, certificationReleaseResponse("FORBIDDEN")))
	f.drain(t, 2)
	if len(f.output.exchanges()) != 1 {
		t.Error("terminal invalidation allowed another release")
	}
	f.output.unchanged(t)
}

type certificationReleaseCapture struct{ fragments []fragment.Record }

func (c *certificationReleaseCapture) Write(r fragment.Record) error {
	c.fragments = append(c.fragments, r)
	return nil
}
func TestReleaseCaptureEvidenceReachesOpenWorker(t *testing.T) {
	f := certificationReleaseNew(t)
	origin := certificationReleaseOrigin(1)
	c := &certificationReleaseCapture{}
	s := capture.Recording(c, nil)
	for i, payload := range []string{certificationReleaseRequest("/captured"), certificationReleaseResponse("CAPTURED")} {
		direction := fragment.Sent
		if i == 1 {
			direction = fragment.Received
		}
		s.Transfer(probe.Transfer{Process: origin.identity.Process, Instance: origin.identity.Instance, Endpoint: origin.identity.Address, Direction: direction, Measured: true, Length: uint32(len(payload)), Payload: []byte(payload), At: origin.identity.FirstSeen, Sequence: probe.Sequence{Occupancy: 1, Number: 1, Born: true}})
	}
	if len(c.fragments) != 2 {
		t.Fatal("wiring, not the property: capture did not receive both known messages")
	}
	for _, r := range c.fragments {
		if err := r.Evidenced(); err != nil {
			t.Errorf("capture did not carry release evidence: %v", err)
		}
	}
	f.put(t, c.fragments...)
	f.drain(t, 2)
	lines := f.output.exchanges()
	if len(lines) != 1 {
		t.Fatalf("capture-to-worker open pair not released: %d", len(lines))
	}
	certificationReleasePair(t, lines[0], uint64(c.fragments[0].Connection), 0, "/captured", "CAPTURED")
}

func TestReleaseCutKeepsOnlyTheEarlierCompletePair(t *testing.T) {
	f := certificationReleaseNew(t)
	s := certificationReleaseOrigin(1)
	rq1 := s.next(fragment.Sent, certificationReleaseRequest("/prefix"))
	rs1 := s.next(fragment.Received, certificationReleaseResponse("PREFIX"))
	boundary := s.evidence.Sent.Limit
	s.evidence.Sent.Numbered++
	rq2 := s.next(fragment.Sent, certificationReleaseRequest("/suffix"))
	rq2.Evidence.Sent.Cut = true
	rq2.Evidence.Sent.From = boundary
	rq2.Evidence.Sent.Resolved = 1
	rq2.Evidence.Sent.Lost = 1
	s.evidence = rq2.Evidence
	rs2 := s.next(fragment.Received, certificationReleaseResponse("SUFFIX"))
	f.put(t, rq1, rs1, rq2, rs2)
	f.drain(t, 4)
	lines := f.output.exchanges()
	if len(lines) != 1 {
		t.Fatalf("first cut must preserve exactly its earlier complete pair: %d", len(lines))
	}
	certificationReleasePair(t, lines[0], 1, 0, "/prefix", "PREFIX")
}

func TestReleaseZeroByteBridgeResolvesWithoutMovingOffsets(t *testing.T) {
	f := certificationReleaseNew(t)
	s := certificationReleaseOrigin(1)
	request := certificationReleaseRequest("/zero")
	first := s.next(fragment.Sent, request[:11])
	// Producer number two resolved with zero bytes; the next fragment carries it.
	s.evidence.Sent.Numbered++
	s.evidence.Sent.Resolved++
	last := s.next(fragment.Sent, request[11:])
	last.Empties = 1
	response := s.next(fragment.Received, certificationReleaseResponse("ZERO"))
	if first.Produced != 1 || last.Produced != 3 || last.Offset != 11 || last.Empties != 1 {
		t.Fatal("wiring, not the property: numbered zero-byte bridge absent")
	}
	f.put(t, first, last, response)
	f.drain(t, 3)
	lines := f.output.exchanges()
	if len(lines) != 1 {
		t.Fatalf("resolved zero-byte operation blocked or duplicated a pair: %d", len(lines))
	}
	certificationReleasePair(t, lines[0], 1, 0, "/zero", "ZERO")
}

func TestReleaseSeparateOccupanciesNeverPairAcrossReusedAddress(t *testing.T) {
	f := certificationReleaseNew(t)
	old := certificationReleaseOrigin(1)
	fresh := certificationReleaseOrigin(2)
	fresh.identity.Address = old.identity.Address
	oldRequest := old.next(fragment.Sent, certificationReleaseRequest("/old"))
	newResponse := fresh.next(fragment.Received, certificationReleaseResponse("NEW"))
	f.put(t, oldRequest, newResponse)
	f.drain(t, 2)
	if len(f.output.exchanges()) != 0 {
		t.Fatal("same address joined a retired occupancy's request with a fresh response")
	}
	newRequest := fresh.next(fragment.Sent, certificationReleaseRequest("/new"))
	f.put(t, newRequest)
	f.drain(t, 1)
	lines := f.output.exchanges()
	if len(lines) != 1 {
		t.Fatalf("fresh occupancy did not release its own pair: %d", len(lines))
	}
	certificationReleasePair(t, lines[0], 2, 0, "/new", "NEW")
}

func TestReleaseFinishWithoutFinalFactsUsesOnlyCertifiedPrefix(t *testing.T) {
	for _, final := range []processing.Finalization{{}, {Withdrawn: true}, {Drained: true}} {
		t.Run(fmt.Sprintf("withdrawn=%t drained=%t", final.Withdrawn, final.Drained), func(t *testing.T) {
			f := certificationReleaseNew(t)
			known := certificationReleaseOrigin(1)
			unknown := certificationReleaseOrigin(2)
			closeDelimited := certificationReleaseOrigin(3)
			unknownRequest := unknown.next(fragment.Sent, certificationReleaseRequest("/unqualified"))
			unknownResponse := unknown.next(fragment.Received, certificationReleaseResponse("UNQUALIFIED"))
			unknownRequest.Evidence = fragment.Evidence{}
			unknownResponse.Evidence = fragment.Evidence{}
			f.put(t,
				known.next(fragment.Sent, certificationReleaseRequest("/certified")),
				known.next(fragment.Received, certificationReleaseResponse("CERTIFIED")),
				unknownRequest, unknownResponse,
				closeDelimited.next(fragment.Sent, certificationReleaseRequest("/close-delimited")),
				closeDelimited.next(fragment.Received, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nUNFRAMED"))
			if len(f.turns) != 0 || len(f.output.artifacts) != 0 {
				t.Fatal("wiring, not the property: a drain ran before the final-queue decision")
			}
			if _, err := f.worker.Finish(context.Background(), final); err != nil {
				t.Fatalf("finish without finalization facts: %v", err)
			}
			taken := 0
			for _, turn := range f.turns {
				taken += turn.Taken
			}
			if taken != 6 || f.store.Stats().Connections != 0 {
				t.Fatalf("wiring, not the property: final queue taken=%d, retirement records=%d", taken, f.store.Stats().Connections)
			}
			t.Log("PRECONDITIONS queued_pairs=3 prior_drains=0 retirement_records=0 complete_finalization=false")
			lines := f.output.exchanges()
			if len(lines) != 1 {
				t.Fatalf("Finish must release exactly the independently certified pair: lines=%d", len(lines))
			}
			certificationReleasePair(t, lines[0], 1, 0, "/certified", "CERTIFIED")
			for _, artifact := range f.output.artifacts {
				if artifact.Record == processing.ArtifactConnection {
					t.Error("Finish without both facts invented a settled connection")
				}
			}
		})
	}
}
