package capture_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

// The sink saves each snapshot when it arrives, before the test releases the
// next event. Its copy includes the pointed-to identity, so a later mutation
// cannot silently rewrite the oracle's earlier observation.
type certificationEvidenceSink struct {
	records  []fragment.Record
	frozen   []fragment.Evidence
	endings  []connection.Record
	attempts int
	refuse   int
}

func (s *certificationEvidenceSink) Write(r fragment.Record) error {
	s.attempts++
	if s.attempts == s.refuse {
		return errors.New("fixture refuses this fragment")
	}
	s.records = append(s.records, r)
	e := r.Evidence
	if e.Identity != nil {
		identity := *e.Identity
		e.Identity = &identity
	}
	s.frozen = append(s.frozen, e)
	return nil
}
func (s *certificationEvidenceSink) Connection(r connection.Record) error {
	s.endings = append(s.endings, r)
	return nil
}
func certificationEvidenceTransfer(direction fragment.Direction, number uint64, payload string) probe.Transfer {
	return probe.Transfer{
		Process:  fragment.Process{PID: 1731, StartTime: 90210},
		Instance: admission.Instance{Namespace: admission.Namespace{Device: 4, Inode: 4026531836}, PID: 1731, Start: admission.Determinate(90210), Generation: 1, Executable: "/usr/bin/service"},
		Endpoint: 0x18, Direction: direction, Length: uint32(len(payload)), Measured: true, Payload: []byte(payload),
		At:       time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Sequence: probe.Sequence{Occupancy: 7, Number: number, Born: true},
	}
}
func certificationEvidenceRecord(t *testing.T, s *certificationEvidenceSink, index int, payload string) fragment.Record {
	t.Helper()
	if len(s.records) <= index || string(s.records[index].Payload) != payload {
		t.Fatalf("wiring, not the property: accepted records=%d, want record %d payload %q", len(s.records), index, payload)
	}
	t.Logf("PRECONDITIONS accepted_fragment=%d payload_bytes=%d retirement_records=%d", index+1, len(payload), len(s.endings))
	r := s.records[index]
	if err := r.Evidenced(); err != nil {
		t.Errorf("required capture snapshot absent or inconsistent: %v", err)
	}
	return r
}
func certificationEvidenceFrozen(t *testing.T, s *certificationEvidenceSink) {
	t.Helper()
	for i, r := range s.records {
		if !reflect.DeepEqual(r.Evidence, s.frozen[i]) {
			t.Errorf("fragment %d snapshot changed after receipt: then=%+v now=%+v", i+1, s.frozen[i], r.Evidence)
		}
	}
}
func certificationEvidenceCut(t *testing.T, d fragment.DirectionEvidence, from, resolved, numbered uint64) {
	t.Helper()
	if !d.Cut || d.From != from || d.Resolved != resolved || d.Numbered != numbered {
		t.Errorf("cut or numbering changed: got %+v want cut=%d resolved=%d numbered=%d", d, from, resolved, numbered)
	}
}

func TestEvidenceOpenConnectionAdvancesByDirection(t *testing.T) {
	sink := &certificationEvidenceSink{}
	s := capture.Recording(sink, sink)
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 1, "alpha"))
	first := certificationEvidenceRecord(t, sink, 0, "alpha")
	if first.Evidence.Sent.Limit != 5 || first.Evidence.Sent.Resolved != 1 || first.Evidence.Received.Limit != 0 || !first.Evidence.Usable(1) {
		t.Errorf("first online snapshot=%+v", first.Evidence)
	}
	s.Transfer(certificationEvidenceTransfer(fragment.Received, 1, "reply"))
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 2, "beta"))
	last := certificationEvidenceRecord(t, sink, 2, "beta")
	if len(sink.endings) != 0 {
		t.Fatal("wiring, not the property: fixture retired the open connection")
	}
	if last.Offset != 5 || last.Evidence.Through != 3 || last.Evidence.Sent.Limit != 9 || last.Evidence.Received.Limit != 5 || last.Evidence.Sent.Resolved != 2 || last.Evidence.Received.Resolved != 1 {
		t.Errorf("independent direction progress=%+v record=%+v", last.Evidence, last)
	}
	if last.Evidence.Identity != first.Evidence.Identity {
		t.Error("connection identity was not shared across its snapshots")
	}
	certificationEvidenceFrozen(t, sink)
}

func TestEvidenceGapAndLateArrivalCannotHealReleasedPrefix(t *testing.T) {
	sink := &certificationEvidenceSink{}
	s := capture.Recording(sink, sink)
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 1, "known-prefix"))
	first := certificationEvidenceRecord(t, sink, 0, "known-prefix")
	boundary := uint64(len("known-prefix"))
	if first.Evidence.Established(fragment.Sent) != boundary {
		t.Errorf("initial prefix not established: %+v", first.Evidence)
	}
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 3, "after-hole"))
	gap := certificationEvidenceRecord(t, sink, 1, "after-hole")
	certificationEvidenceCut(t, gap.Evidence.Sent, boundary, 1, 3)
	if gap.Evidence.Sent.Lost != 1 {
		t.Errorf("missing call count=%d", gap.Evidence.Sent.Lost)
	}
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 2, "late-hole"))
	late := certificationEvidenceRecord(t, sink, 2, "late-hole")
	certificationEvidenceCut(t, late.Evidence.Sent, boundary, 1, 3)
	s.Transfer(certificationEvidenceTransfer(fragment.Received, 1, "healthy-other-direction"))
	other := certificationEvidenceRecord(t, sink, 3, "healthy-other-direction")
	if other.Evidence.Received.Cut || other.Evidence.Received.Resolved != 1 {
		t.Errorf("sent gap contaminated received: %+v", other.Evidence)
	}
	certificationEvidenceFrozen(t, sink)
}

func TestEvidenceMissingFirstTransferCutsOnlyItsDirection(t *testing.T) {
	sink := &certificationEvidenceSink{}
	s := capture.Recording(sink, sink)
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 2, "second"))
	r := certificationEvidenceRecord(t, sink, 0, "second")
	certificationEvidenceCut(t, r.Evidence.Sent, 0, 0, 2)
	if r.Evidence.Sent.First != 2 || r.Evidence.Sent.Lost != 1 || r.Evidence.Origin != fragment.OriginBirth {
		t.Errorf("first missing transfer evidence=%+v", r.Evidence)
	}
	s.Transfer(certificationEvidenceTransfer(fragment.Received, 1, "first"))
	other := certificationEvidenceRecord(t, sink, 1, "first")
	if other.Evidence.Received.Cut || other.Evidence.Received.Resolved != 1 {
		t.Errorf("independent received evidence=%+v", other.Evidence)
	}
	certificationEvidenceFrozen(t, sink)
}

func TestEvidenceZeroByteResolutionTravelsAcrossDirections(t *testing.T) {
	sink := &certificationEvidenceSink{}
	s := capture.Recording(sink, sink)
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 1, "a"))
	certificationEvidenceRecord(t, sink, 0, "a")
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 2, ""))
	s.Transfer(certificationEvidenceTransfer(fragment.Received, 1, "b"))
	if len(sink.records) != 2 || s.Stats().Empty != 1 {
		t.Fatal("wiring, not the property: zero-byte transfer emitted a fragment or was not consumed")
	}
	r := certificationEvidenceRecord(t, sink, 1, "b")
	if r.Evidence.Sent.Cut || r.Evidence.Sent.Resolved != 2 || r.Evidence.Sent.Empties != 1 || r.Evidence.Sent.Limit != 1 {
		t.Errorf("pending empty resolution=%+v", r.Evidence.Sent)
	}
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 3, "c"))
	next := certificationEvidenceRecord(t, sink, 2, "c")
	if next.Empties != 1 || next.Offset != 1 || next.Evidence.Sent.Empties != 0 || next.Evidence.Sent.Resolved != 3 || next.Evidence.Sent.Cut {
		t.Errorf("empty resolution was lost or counted twice: %+v", next)
	}
	certificationEvidenceFrozen(t, sink)
}

func TestEvidenceOriginQualification(t *testing.T) {
	for _, tc := range []struct {
		name      string
		occupancy uint64
		born      bool
		unlocated uint64
		want      fragment.Origin
	}{
		{"observed birth", 7, true, 0, fragment.OriginBirth},
		{"first recorded", 7, false, 0, fragment.OriginFirstRecorded},
		{"unlocated before existing handle", 7, false, 1, fragment.OriginUnestablished},
		{"no occupancy", 0, false, 0, fragment.OriginUnestablished},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &certificationEvidenceSink{}
			s := capture.Recording(sink, sink)
			event := certificationEvidenceTransfer(fragment.Sent, 1, "origin")
			event.Sequence.Occupancy = tc.occupancy
			event.Sequence.Born = tc.born
			event.Sequence.BeginUnlocated = tc.unlocated
			event.Sequence.Unlocated = tc.unlocated
			if tc.occupancy == 0 {
				event.Sequence.Number = 0
			}
			s.Transfer(event)
			r := certificationEvidenceRecord(t, sink, 0, "origin")
			if r.Evidence.Origin != tc.want || r.Evidence.Occupancy != tc.occupancy {
				t.Errorf("origin=%+v want=%s", r.Evidence, tc.want)
			}
			for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
				d := r.Evidence.Of(direction)
				if tc.want == fragment.OriginUnestablished {
					if !d.Cut || d.From != 0 {
						t.Errorf("unqualified origin established positions: %+v", d)
					}
				} else if d.Cut {
					t.Errorf("qualified positive control cut: %+v", d)
				}
			}
		})
	}
}

func TestEvidenceSinkRefusalCannotAuthorizeUnreceivedFragments(t *testing.T) {
	sink := &certificationEvidenceSink{refuse: 2}
	s := capture.Recording(sink, sink)
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 1, "held"))
	first := certificationEvidenceRecord(t, sink, 0, "held")
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 2, "refused"))
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 3, "later"))
	if sink.attempts != 3 || len(sink.records) != 2 || sink.records[1].Sequence != 3 {
		t.Fatal("wiring, not the property: one sink refusal did not leave the intended receipt gap")
	}
	last := certificationEvidenceRecord(t, sink, 1, "later")
	// Count contiguous receipt from actual fragment sequences, never from Through.
	held := uint64(0)
	for _, r := range sink.records {
		if r.Sequence == held+1 {
			held++
		} else {
			break
		}
	}
	if held != 1 || !first.Evidence.Usable(held) || last.Evidence.Usable(held) {
		t.Errorf("unreceived input authorized: contiguous=%d later=%+v", held, last.Evidence)
	}
	if !last.Evidence.Sent.Cut || last.Evidence.Sent.From != 4 {
		t.Errorf("sink refusal did not cut at refused fragment: %+v", last.Evidence.Sent)
	}
	certificationEvidenceFrozen(t, sink)
}

func TestEvidenceTransferredLengthKeepsTruncationVisible(t *testing.T) {
	sink := &certificationEvidenceSink{}
	s := capture.Recording(sink, sink)
	event := certificationEvidenceTransfer(fragment.Sent, 1, "abc")
	event.Length = 7
	s.Transfer(event)
	first := certificationEvidenceRecord(t, sink, 0, "abc")
	if !first.Truncated() {
		t.Fatal("wiring, not the property: fixture did not truncate retained bytes")
	}
	if first.Evidence.Sent.Limit != 7 {
		t.Errorf("snapshot compressed missing bytes: %+v", first.Evidence.Sent)
	}
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 2, "hij"))
	last := certificationEvidenceRecord(t, sink, 1, "hij")
	if last.Offset != 7 || last.Evidence.Sent.Limit != 10 {
		t.Errorf("later payload moved into truncated bytes: %+v", last)
	}
	certificationEvidenceFrozen(t, sink)
}

func TestEvidenceOverlapCutsBytesWithoutInventingMissingNumbers(t *testing.T) {
	sink := &certificationEvidenceSink{}
	s := capture.Recording(sink, sink)
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 1, "before"))
	certificationEvidenceRecord(t, sink, 0, "before")
	event := certificationEvidenceTransfer(fragment.Sent, 2, "overlap")
	event.Sequence.Overlapped = true
	s.Transfer(event)
	r := certificationEvidenceRecord(t, sink, 1, "overlap")
	certificationEvidenceCut(t, r.Evidence.Sent, 6, 2, 2)
	if r.Evidence.Sent.Lost != 0 {
		t.Errorf("overlap invented missing calls: %+v", r.Evidence.Sent)
	}
	certificationEvidenceFrozen(t, sink)
}

func TestEvidenceRetirementCannotWithdrawHeldPrefix(t *testing.T) {
	for _, closed := range []bool{false, true} {
		name := "open unsettled"
		if closed {
			name = "closed missing tail"
		}
		t.Run(name, func(t *testing.T) {
			sink := &certificationEvidenceSink{}
			s := capture.Recording(sink, sink)
			event := certificationEvidenceTransfer(fragment.Sent, 1, "held-prefix")
			s.Transfer(event)
			first := certificationEvidenceRecord(t, sink, 0, "held-prefix")
			if closed {
				s.Closed(probe.Connection{Process: event.Process, Instance: event.Instance, Endpoint: event.Endpoint, At: event.At.Add(time.Second), Sequence: probe.Sequence{Occupancy: 7}, Final: probe.Final{Known: true, Sent: probe.Terminal{Last: 2}}})
			} else {
				s.Finish(event.At.Add(time.Second))
			}
			if len(sink.endings) != 1 {
				t.Fatal("wiring, not the property: final record absent")
			}
			final := sink.endings[0]
			if err := final.Agrees(first.Evidence); err != nil {
				t.Errorf("retirement withdrew previously held evidence: %v", err)
			}
			placement, ok := final.Placement(fragment.Sent)
			if !ok {
				t.Fatal("retirement lacks sent placement")
			}
			if closed && (!placement.Lost.Known || placement.Lost.Value != 1) {
				t.Errorf("closed missing tail not counted: %+v", placement)
			}
			if !closed && placement.Lost.Known && placement.Lost.Value != 0 {
				t.Errorf("open unsettled tail invented counted losses: %+v", placement)
			}
			certificationEvidenceFrozen(t, sink)
		})
	}
}

func TestEvidenceUnmeasuredTransferNeverResolvesItsNumber(t *testing.T) {
	sink := &certificationEvidenceSink{}
	s := capture.Recording(sink, sink)
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 1, "before"))
	certificationEvidenceRecord(t, sink, 0, "before")
	event := certificationEvidenceTransfer(fragment.Sent, 2, "")
	event.Measured = false
	s.Transfer(event)
	s.Transfer(certificationEvidenceTransfer(fragment.Received, 1, "witness"))
	if len(sink.records) != 2 || s.Stats().Unmeasured != 1 {
		t.Fatal("wiring, not the property: unmeasured call did not reach capture")
	}
	witness := certificationEvidenceRecord(t, sink, 1, "witness")
	certificationEvidenceCut(t, witness.Evidence.Sent, 6, 1, 2)
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 3, "later"))
	last := certificationEvidenceRecord(t, sink, 2, "later")
	certificationEvidenceCut(t, last.Evidence.Sent, 6, 1, 3)
	certificationEvidenceFrozen(t, sink)
}

func TestEvidenceDeliveryRefusalPreservesEarlierSnapshot(t *testing.T) {
	sink := &certificationEvidenceSink{}
	s := capture.Recording(sink, sink)
	event := certificationEvidenceTransfer(fragment.Sent, 1, "before")
	s.Transfer(event)
	first := certificationEvidenceRecord(t, sink, 0, "before")
	s.Refused(certificationEvidenceTransfer(fragment.Sent, 2, "refused"))
	s.Transfer(certificationEvidenceTransfer(fragment.Received, 1, "withheld"))
	s.Transfer(certificationEvidenceTransfer(fragment.Sent, 3, "later"))
	if len(sink.records) != 1 || s.Stats().GateRefused != 1 || s.Stats().Rejected != 2 {
		t.Fatal("wiring, not the property: delivery refusal did not stop subsequent fragments")
	}
	s.Finish(event.At.Add(time.Second))
	if len(sink.endings) != 1 {
		t.Fatal("wiring, not the property: refused connection did not retire")
	}
	if err := sink.endings[0].Agrees(first.Evidence); err != nil {
		t.Errorf("delivery refusal withdrew held evidence: %v", err)
	}
	certificationEvidenceFrozen(t, sink)
}

func TestEvidenceReusedAddressRejectsOldOccupancy(t *testing.T) {
	sink := &certificationEvidenceSink{}
	s := capture.Recording(sink, sink)
	old := certificationEvidenceTransfer(fragment.Sent, 1, "old-prefix")
	s.Transfer(old)
	first := certificationEvidenceRecord(t, sink, 0, "old-prefix")
	fresh := certificationEvidenceTransfer(fragment.Sent, 1, "new-prefix")
	fresh.Sequence.Occupancy = 8
	s.Transfer(fresh)
	next := certificationEvidenceRecord(t, sink, 1, "new-prefix")
	if first.Connection == next.Connection || len(sink.endings) != 1 {
		t.Fatal("wiring, not the property: address reuse did not create and retire distinct connections")
	}
	late := certificationEvidenceTransfer(fragment.Sent, 2, "late-old")
	s.Transfer(late)
	if len(sink.records) != 2 || s.Stats().Rejected != 1 {
		t.Fatal("wiring, not the property: late old occupancy was not rejected")
	}
	fresh.Sequence.Number = 2
	fresh.Payload = []byte("new-second")
	fresh.Length = uint32(len(fresh.Payload))
	s.Transfer(fresh)
	last := certificationEvidenceRecord(t, sink, 2, "new-second")
	if next.Evidence.Occupancy != 8 || last.Connection != next.Connection || last.Evidence.Sent.Cut || last.Evidence.Sent.Resolved != 2 || last.Offset != uint64(len("new-prefix")) {
		t.Errorf("old event contaminated new occupancy: %+v", last)
	}
	if err := sink.endings[0].Agrees(first.Evidence); err != nil {
		t.Errorf("reuse retirement contradicts held old evidence: %v", err)
	}
	certificationEvidenceFrozen(t, sink)
}

// The final read is a fixture input, not an oracle derived from capture's
// totals. It distinguishes a failed reservation from an event still pending
// after the boundary, even when both consumed a producer number.
type certificationEvidenceSettler struct {
	handle probe.Handle
	answer probe.Settlement
	calls  int
}

func (s *certificationEvidenceSettler) Settled(handle probe.Handle) (probe.Settlement, error) {
	s.calls++
	if handle != s.handle {
		return probe.Settlement{}, errors.New("fixture received another handle")
	}
	return s.answer, nil
}

func (*certificationEvidenceSettler) Unlocated() (uint64, error) { return 0, nil }

func TestEvidenceOpenTailCountsOnlyReservationLoss(t *testing.T) {
	for _, tc := range []struct {
		name     string
		last     uint64
		dropped  uint64
		inflight bool
		wantLost int64
	}{
		{"submitted but undelivered", 2, 0, false, 0},
		{"one failed reservation", 2, 1, false, 1},
		{"drop before undelivered submission", 3, 1, false, 1},
		{"entry still in flight", 2, 0, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &certificationEvidenceSink{}
			event := certificationEvidenceTransfer(fragment.Sent, 1, "held")
			settler := &certificationEvidenceSettler{
				handle: probe.Handle{Instance: event.Instance.Key(), Endpoint: event.Endpoint},
				answer: probe.Settlement{Occupancy: 7, Final: probe.Final{Known: true, Sent: probe.Terminal{Last: tc.last, Dropped: tc.dropped, InFlight: tc.inflight}}},
			}
			s := capture.Recording(sink, sink, capture.Settles(settler))
			s.Transfer(event)
			first := certificationEvidenceRecord(t, sink, 0, "held")
			s.Finish(event.At.Add(time.Second))
			if settler.calls != 1 || len(sink.endings) != 1 {
				t.Fatal("wiring, not the property: terminal fixture was not consumed exactly once")
			}
			t.Logf("PRECONDITIONS final_reads=1 last=%d reservation_drops=%d inflight=%t", tc.last, tc.dropped, tc.inflight)
			if s.Stats().Lost != tc.wantLost {
				t.Errorf("open tail conflated reservations with pending events: lost=%d want=%d", s.Stats().Lost, tc.wantLost)
			}
			if err := sink.endings[0].Agrees(first.Evidence); err != nil {
				t.Errorf("terminal evidence withdrew held prefix: %v", err)
			}
			certificationEvidenceFrozen(t, sink)
		})
	}
}

func TestEvidenceEarlierNumberGapCannotHideTailReservationLoss(t *testing.T) {
	for _, below := range []uint64{0, 1} {
		t.Run(map[uint64]string{0: "earlier gap was not a reservation", 1: "earlier gap was a reservation"}[below], func(t *testing.T) {
			sink := &certificationEvidenceSink{}
			event := certificationEvidenceTransfer(fragment.Sent, 1, "prefix")
			settler := &certificationEvidenceSettler{
				handle: probe.Handle{Instance: event.Instance.Key(), Endpoint: event.Endpoint},
				answer: probe.Settlement{Occupancy: 7, Final: probe.Final{Known: true, Sent: probe.Terminal{Last: 5, Dropped: below + 1}}},
			}
			s := capture.Recording(sink, sink, capture.Settles(settler))
			s.Transfer(event)
			first := certificationEvidenceRecord(t, sink, 0, "prefix")
			later := certificationEvidenceTransfer(fragment.Sent, 3, "after-gap")
			later.Sequence.Dropped = below
			s.Transfer(later)
			gap := certificationEvidenceRecord(t, sink, 1, "after-gap")
			certificationEvidenceCut(t, gap.Evidence.Sent, 6, 1, 3)
			s.Finish(event.At.Add(time.Second))
			if settler.calls != 1 || len(sink.endings) != 1 {
				t.Fatal("wiring, not the property: final reservation accounting was not queried")
			}
			if s.Stats().Lost != 2 {
				t.Errorf("one earlier gap plus one tail reservation must count twice: lost=%d below=%d", s.Stats().Lost, below)
			}
			for _, held := range []fragment.Evidence{first.Evidence, gap.Evidence} {
				if err := sink.endings[0].Agrees(held); err != nil {
					t.Errorf("tail accounting contradicted held snapshot: %v", err)
				}
			}
			certificationEvidenceFrozen(t, sink)
		})
	}
}

func TestEvidenceLaterUnlocatedLossCannotRewriteEarlierOrigin(t *testing.T) {
	sink := &certificationEvidenceSink{}
	s := capture.Recording(sink, sink)
	old := certificationEvidenceTransfer(fragment.Sent, 1, "earlier")
	old.Sequence.Born = false
	s.Transfer(old)
	first := certificationEvidenceRecord(t, sink, 0, "earlier")
	fresh := certificationEvidenceTransfer(fragment.Sent, 1, "later-origin")
	fresh.Endpoint++
	fresh.Sequence.Occupancy = 8
	fresh.Sequence.Born = false
	fresh.Sequence.Unlocated = 1
	fresh.Sequence.BeginUnlocated = 1
	s.Transfer(fresh)
	unqualified := certificationEvidenceRecord(t, sink, 1, "later-origin")
	if first.Connection == unqualified.Connection || s.Stats().Unlocated != 1 {
		t.Fatal("wiring, not the property: two occupancies did not straddle the unlocated loss")
	}
	old.Sequence.Number = 2
	old.Sequence.Unlocated = 1
	old.Payload = []byte("still-earlier")
	old.Length = uint32(len(old.Payload))
	s.Transfer(old)
	last := certificationEvidenceRecord(t, sink, 2, "still-earlier")
	if first.Evidence.Origin != fragment.OriginFirstRecorded || last.Evidence.Origin != fragment.OriginFirstRecorded || last.Evidence.Sent.Cut || last.Evidence.Sent.Resolved != 2 {
		t.Errorf("later unlocated loss rewrote earlier origin: first=%+v last=%+v", first.Evidence, last.Evidence)
	}
	if unqualified.Evidence.Origin != fragment.OriginUnestablished || !unqualified.Evidence.Sent.Cut || unqualified.Evidence.Sent.From != 0 || !unqualified.Evidence.Received.Cut || unqualified.Evidence.Received.From != 0 {
		t.Errorf("later origin escaped its own unlocated loss: %+v", unqualified.Evidence)
	}
	certificationEvidenceFrozen(t, sink)
}

// A callback already holding a record may remain blocked while a later event
// is placed. The earlier snapshot must describe only its own receipt boundary.
type certificationEvidenceBlockedSink struct {
	entered chan fragment.Record
	release chan struct{}
}

func (s *certificationEvidenceBlockedSink) Write(r fragment.Record) error {
	s.entered <- r
	if r.Sequence == 1 {
		<-s.release
	}
	return nil
}

func TestEvidenceBlockedCallbackCannotObserveFutureState(t *testing.T) {
	sink := &certificationEvidenceBlockedSink{entered: make(chan fragment.Record, 2), release: make(chan struct{})}
	defer close(sink.release)
	s := capture.Recording(sink, nil)
	firstDone := make(chan struct{})
	go func() {
		s.Transfer(certificationEvidenceTransfer(fragment.Sent, 1, "before"))
		close(firstDone)
	}()
	receive := func() fragment.Record {
		t.Helper()
		select {
		case r := <-sink.entered:
			return r
		case <-time.After(3 * time.Second):
			t.Fatal("wiring, not the property: callback did not receive its fragment")
			return fragment.Record{}
		}
	}
	first := receive()
	if string(first.Payload) != "before" || first.Sequence != 1 {
		t.Fatal("wiring, not the property: blocked callback lacks the known first record")
	}
	frozen := first.Evidence
	if frozen.Identity != nil {
		identity := *frozen.Identity
		frozen.Identity = &identity
	}
	secondDone := make(chan struct{})
	go func() {
		s.Transfer(certificationEvidenceTransfer(fragment.Sent, 2, "after"))
		close(secondDone)
	}()
	second := receive()
	select {
	case <-secondDone:
	case <-time.After(3 * time.Second):
		t.Fatal("wiring, not the property: second callback did not finish")
	}
	select {
	case <-firstDone:
		t.Fatal("wiring, not the property: first callback was not held")
	default:
	}
	if string(second.Payload) != "after" || second.Sequence != 2 {
		t.Fatal("wiring, not the property: later known record absent")
	}
	t.Log("PRECONDITIONS blocked_callbacks=1 later_callbacks_completed=1 held_fragments=2")
	for _, r := range []fragment.Record{first, second} {
		if err := r.Evidenced(); err != nil {
			t.Errorf("callback lacks valid receipt evidence: %v", err)
		}
	}
	if !reflect.DeepEqual(first.Evidence, frozen) || first.Evidence.Sent.Limit != 6 || first.Evidence.Sent.Resolved != 1 || first.Evidence.Through != 1 {
		t.Errorf("later placement changed blocked callback's evidence: frozen=%+v now=%+v", frozen, first.Evidence)
	}
	if second.Evidence.Sent.Limit != 11 || second.Evidence.Sent.Resolved != 2 || second.Evidence.Through != 2 {
		t.Errorf("later snapshot did not describe its own boundary: %+v", second.Evidence)
	}
}
