package capture_test

import (
	"errors"
	"testing"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

// witnessed is a fragment sink that, as each record arrives, reads back what
// the session holds for the record's connection at that moment. A write it is
// told to refuse is still seen, so a case can read the evidence of a fragment
// that never arrived anywhere.
type witnessed struct {
	session *capture.Session
	refuse  int

	writes  int
	records []fragment.Record
	live    []connection.Record
	found   []bool
	refused []fragment.Record
}

func (w *witnessed) Write(record fragment.Record) error {
	w.writes++
	if w.writes == w.refuse {
		w.refused = append(w.refused, record)
		return errors.New("refused")
	}
	var held connection.Record
	found := false
	for _, one := range w.session.Live(at) {
		if one.ID == record.Connection {
			held, found = one, true
		}
	}
	w.records = append(w.records, record)
	w.live = append(w.live, held)
	w.found = append(w.found, found)
	return nil
}

// witnessing is a producer-fronted session whose sink reads the session back
// at every write; refuse names the write, from one, the sink refuses.
func witnessing(refuse int) (*producer, *witnessed) {
	sink := &witnessed{refuse: refuse}
	p := produced(sink, nil)
	sink.session = p.Session
	return p, sink
}

// sameIdentity reports how an evidence's identity differs from the record
// capture held for the connection, or nothing where it does not.
func sameIdentity(t *testing.T, label string, identity *fragment.Identity, held connection.Record) {
	t.Helper()
	switch {
	case identity == nil:
		t.Errorf("%s: the evidence names no connection", label)
	case identity.Connection != held.ID || identity.Process != held.Process:
		t.Errorf("%s: the evidence names connection %d of pid %d, capture holds connection %d of pid %d",
			label, identity.Connection, identity.Process.PID, held.ID, held.Process.PID)
	case identity.Instance != held.Instance:
		t.Errorf("%s: the evidence names execution %+v, capture holds %+v", label, identity.Instance, held.Instance)
	case identity.Address != held.Handle.Address || identity.Generation != uint64(held.Handle.Generation):
		t.Errorf("%s: the evidence names handle %#x generation %d, capture holds %s",
			label, identity.Address, identity.Generation, held.Handle)
	case identity.NetworkDevice != held.Network.Device || identity.NetworkInode != held.Network.Inode:
		t.Errorf("%s: the evidence names network %d:%d, capture holds %+v",
			label, identity.NetworkDevice, identity.NetworkInode, held.Network)
	case !identity.FirstSeen.Equal(held.FirstSeen) || !identity.Opened.Equal(held.Opened):
		t.Errorf("%s: the evidence was first seen %s and opened %s, capture holds %s and %s",
			label, identity.FirstSeen, identity.Opened, held.FirstSeen, held.Opened)
	}
}

// samePlacement reports how one direction's evidence differs from the placement
// capture held for it at the same moment.
func samePlacement(t *testing.T, label string, direction fragment.Direction, evidence fragment.DirectionEvidence,
	held connection.Record) {
	t.Helper()
	placement, carried := held.Placement(direction)
	if !carried {
		if evidence.Cut || evidence.Limit != 0 {
			t.Errorf("%s %s: capture holds no placement, and the evidence reaches %d, cut %t",
				label, direction, evidence.Limit, evidence.Cut)
		}
		return
	}
	want := fragment.DirectionEvidence{Limit: evidence.Limit}
	switch placement.Positions {
	case connection.PositionsUnknownFrom:
		want.Cut, want.From = true, placement.From
	case connection.PositionsUnknownThroughout:
		want.Cut = true
	}
	// A count capture's record cannot state is compared as uncounted: the record
	// drops the part that was counted, and the evidence keeps it.
	got := fragment.DirectionEvidence{Limit: evidence.Limit, Cut: evidence.Cut, From: evidence.From,
		Lost: evidence.Lost, LostUncounted: evidence.LostUncounted}
	if placement.Lost.Known {
		want.Lost = uint64(placement.Lost.Value)
	} else {
		want.LostUncounted, got.Lost = true, 0
	}
	if got != want {
		t.Errorf("%s %s: the evidence says cut %t from %d, lost %d (uncounted %t); capture holds %s, lost %s",
			label, direction, got.Cut, got.From, got.Lost, got.LostUncounted, placement, placement.Lost)
	}
}

// An open connection's fragments each carry what capture held for the
// connection as it placed them: the identity and placement capture's own record
// shows at that moment, the fragment count through it, and each direction's
// limit and producer numbers, including a transfer that moved no bytes and a
// number that never arrived.
func TestEachFragmentOfAnOpenConnectionCarriesWhatCaptureHeldAsItPlacedIt(t *testing.T) {
	p, sink := witnessing(0)

	const occupancy = 7
	steps := []struct {
		direction fragment.Direction
		length    uint32
		number    uint64
	}{
		{fragment.Sent, 10, 1},
		{fragment.Received, 4, 1},
		{fragment.Received, 0, 2}, // a read that moved nothing: numbered, no fragment
		{fragment.Sent, 7, 2},
		{fragment.Received, 5, 3},
		{fragment.Sent, 3, 4}, // number three was produced and never delivered
		{fragment.Received, 6, 4},
	}
	for _, step := range steps {
		p.Transfer(numberedAs(worker, 0x18, step.direction, step.length, occupancy, step.number))
	}

	// What each direction's evidence must say at each fragment, from the steps
	// above: limit, cut, from, lost, first, numbered, resolved, empties.
	type want struct{ sent, received fragment.DirectionEvidence }
	wants := []want{
		{sent: fragment.DirectionEvidence{Limit: 10, First: 1, Numbered: 1, Resolved: 1}},
		{sent: fragment.DirectionEvidence{Limit: 10, First: 1, Numbered: 1, Resolved: 1},
			received: fragment.DirectionEvidence{Limit: 4, First: 1, Numbered: 1, Resolved: 1}},
		{sent: fragment.DirectionEvidence{Limit: 17, First: 1, Numbered: 2, Resolved: 2},
			received: fragment.DirectionEvidence{Limit: 4, First: 1, Numbered: 2, Resolved: 2, Empties: 1}},
		{sent: fragment.DirectionEvidence{Limit: 17, First: 1, Numbered: 2, Resolved: 2},
			received: fragment.DirectionEvidence{Limit: 9, First: 1, Numbered: 3, Resolved: 3}},
		{sent: fragment.DirectionEvidence{Limit: 20, Cut: true, From: 17, Lost: 1, First: 1, Numbered: 4, Resolved: 2},
			received: fragment.DirectionEvidence{Limit: 9, First: 1, Numbered: 3, Resolved: 3}},
		{sent: fragment.DirectionEvidence{Limit: 20, Cut: true, From: 17, Lost: 1, First: 1, Numbered: 4, Resolved: 2},
			received: fragment.DirectionEvidence{Limit: 15, First: 1, Numbered: 4, Resolved: 4}},
	}

	if len(sink.records) != len(wants) || p.Stats().Lost != 1 {
		t.Fatalf("wiring, not the property: %d fragments placed and %d transfers lost, want %d and 1, so "+
			"the fixture did not reach capture as built", len(sink.records), p.Stats().Lost, len(wants))
	}
	for i, found := range sink.found {
		if !found {
			t.Fatalf("wiring, not the property: capture held no record for fragment %d's connection when it "+
				"was written, so nothing below compares against anything", i+1)
		}
	}

	for i, record := range sink.records {
		label := "fragment " + record.Stream().String()
		evidence := record.Evidence
		if !evidence.Taken() {
			t.Errorf("fragment %d (%s) carries no evidence", record.Sequence, label)
			continue
		}
		if err := record.Evidenced(); err != nil {
			t.Errorf("fragment %d: %v", record.Sequence, err)
		}
		held := sink.live[i]
		if evidence.Through != record.Sequence || !held.Fragments.Known ||
			uint64(held.Fragments.Value) != evidence.Through {
			t.Errorf("fragment %d: evidence through %d, capture had placed %s fragments",
				record.Sequence, evidence.Through, held.Fragments)
		}
		if evidence.Origin != fragment.OriginBirth || evidence.Occupancy != occupancy {
			t.Errorf("fragment %d: origin %s in occupancy %d, want the handle's birth in occupancy %d",
				record.Sequence, evidence.Origin, evidence.Occupancy, occupancy)
		}
		sameIdentity(t, label, evidence.Identity, held)
		for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
			samePlacement(t, label, direction, evidence.Of(direction), held)
		}
		if evidence.Sent != wants[i].sent {
			t.Errorf("fragment %d: sent evidence %+v, want %+v", record.Sequence, evidence.Sent, wants[i].sent)
		}
		if evidence.Received != wants[i].received {
			t.Errorf("fragment %d: received evidence %+v, want %+v",
				record.Sequence, evidence.Received, wants[i].received)
		}
	}
	// Every evidence of one connection shares one identity.
	for _, record := range sink.records[1:] {
		if record.Evidence.Identity != sink.records[0].Evidence.Identity {
			t.Errorf("fragment %d carries an identity of its own rather than the connection's", record.Sequence)
		}
	}
}

// What the producer's number one is, and the first number capture saw, are two
// facts. An observed birth, the first call recorded on an existing handle, an
// occupancy begun after a loss nobody placed, and a transfer with no occupancy
// at all each name a different origin; a first observation past one leaves the
// origin as it was and establishes nothing.
func TestEvidenceSeparatesTheOriginFromTheFirstObservation(t *testing.T) {
	cases := []struct {
		name      string
		sequence  probe.Sequence
		origin    fragment.Origin
		occupancy uint64
		sent      fragment.DirectionEvidence
		received  fragment.DirectionEvidence
	}{
		{"an observed birth", probe.Sequence{Occupancy: 7, Number: 1, Born: true},
			fragment.OriginBirth, 7,
			fragment.DirectionEvidence{Limit: 5, First: 1, Numbered: 1, Resolved: 1},
			fragment.DirectionEvidence{}},
		{"the first call recorded on an existing handle", probe.Sequence{Occupancy: 7, Number: 1},
			fragment.OriginFirstRecorded, 7,
			fragment.DirectionEvidence{Limit: 5, First: 1, Numbered: 1, Resolved: 1},
			fragment.DirectionEvidence{}},
		{"an occupancy begun after a loss nobody placed",
			probe.Sequence{Occupancy: 7, Number: 1, Unlocated: 2, BeginUnlocated: 2},
			fragment.OriginUnestablished, 7,
			fragment.DirectionEvidence{Limit: 5, Cut: true, LostUncounted: true, First: 1, Numbered: 1, Resolved: 1},
			fragment.DirectionEvidence{Cut: true, LostUncounted: true}},
		{"a transfer the producer kept no occupancy for", probe.Sequence{},
			fragment.OriginUnestablished, 0,
			fragment.DirectionEvidence{Limit: 5, Cut: true, LostUncounted: true},
			fragment.DirectionEvidence{Cut: true, LostUncounted: true}},
		{"a birth whose first two transfers never arrived", probe.Sequence{Occupancy: 7, Number: 3, Born: true},
			fragment.OriginBirth, 7,
			fragment.DirectionEvidence{Limit: 5, Cut: true, Lost: 2, First: 3, Numbered: 3},
			fragment.DirectionEvidence{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sink := &collected{}
			s := recording(sink)
			one := transfer(worker, 0x18, fragment.Sent, 5)
			one.Sequence = c.sequence
			s.Transfer(one)

			if len(sink.records) != 1 {
				t.Fatalf("wiring, not the property: %d fragments placed from one transfer", len(sink.records))
			}
			evidence := sink.records[0].Evidence
			if !evidence.Taken() {
				t.Fatalf("the fragment carries no evidence")
			}
			if err := sink.records[0].Evidenced(); err != nil {
				t.Errorf("%v", err)
			}
			if evidence.Origin != c.origin || evidence.Occupancy != c.occupancy {
				t.Errorf("origin %s in occupancy %d, want %s in occupancy %d",
					evidence.Origin, evidence.Occupancy, c.origin, c.occupancy)
			}
			if evidence.Sent != c.sent {
				t.Errorf("sent evidence %+v, want %+v", evidence.Sent, c.sent)
			}
			if evidence.Received != c.received {
				t.Errorf("received evidence %+v, want %+v", evidence.Received, c.received)
			}
		})
	}
}

// A later evidence never establishes what an earlier loss cut. Each case loses
// something before a fragment, sends more of both directions after it, and reads
// every evidence from the loss on: the cut direction stays cut where the loss
// began, whatever arrives afterwards. The direction that lost nothing is the
// control, and goes on advancing.
func TestALaterEvidenceNeverEstablishesWhatAnEarlierLossCut(t *testing.T) {
	cases := []struct {
		name string
		// run feeds the session; it returns the Sequence of the first fragment
		// after the loss.
		run func(p *producer) uint64
		// refuse is the write the sink refuses, from one; zero refuses none.
		refuse int
		// cut is where the sent direction's positions stop, and resolved the run of
		// sent numbers that arrived in order before the loss ended it.
		cut, resolved uint64
	}{
		{"a number that never arrived", func(p *producer) uint64 {
			p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
			p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 2))
			p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 4))
			return 3
		}, 0, 20, 2},
		{"a number arriving behind a later one", func(p *producer) uint64 {
			p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
			p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 3))
			p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 2))
			return 2
		}, 0, 10, 1},
		{"a transfer whose length nothing measured", func(p *producer) uint64 {
			p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
			unmeasured := numberedAs(worker, 0x18, fragment.Sent, 0, 7, 2)
			unmeasured.Measured = false
			p.Transfer(unmeasured)
			p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 3))
			return 2
		}, 0, 10, 1},
		{"a fragment the sink refused", func(p *producer) uint64 {
			p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
			p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 2))
			p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 3))
			return 3
		}, 2, 10, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, sink := witnessing(c.refuse)
			after := c.run(p)
			// After the loss: both directions go on, with a read that moves nothing.
			p.Transfer(numberedAs(worker, 0x18, fragment.Received, 5, 7, 1))
			p.Transfer(numberedAs(worker, 0x18, fragment.Received, 0, 7, 2))
			p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 5))
			p.Transfer(numberedAs(worker, 0x18, fragment.Received, 5, 7, 3))

			later := 0
			for _, record := range sink.records {
				if record.Sequence < after {
					continue
				}
				later++
				evidence := record.Evidence
				if !evidence.Taken() {
					t.Errorf("fragment %d carries no evidence", record.Sequence)
					continue
				}
				if sent := evidence.Of(fragment.Sent); !sent.Cut || sent.From != c.cut {
					t.Errorf("fragment %d: the sent direction is cut %t from %d, want cut from %d where the "+
						"loss began", record.Sequence, sent.Cut, sent.From, c.cut)
				}
				if got := evidence.Established(fragment.Sent); got != c.cut {
					t.Errorf("fragment %d: the evidence vouches for sent offsets below %d, past the loss at %d",
						record.Sequence, got, c.cut)
				}
				if sent := evidence.Of(fragment.Sent); sent.Resolved != c.resolved {
					t.Errorf("fragment %d: the sent numbers resolve through %d, want %d: nothing after the "+
						"loss resumes the run", record.Sequence, sent.Resolved, c.resolved)
				}
				if received := evidence.Of(fragment.Received); received.Cut {
					t.Errorf("fragment %d: the received direction lost nothing and is cut from %d",
						record.Sequence, received.From)
				}
			}
			if later < 3 {
				t.Fatalf("wiring, not the property: %d fragments placed from the loss on, so nothing after it "+
					"was read", later)
			}
			if last := sink.records[len(sink.records)-1].Evidence; last.Established(fragment.Received) != 10 {
				t.Errorf("the control: the received direction's last evidence vouches below %d, want 10",
					last.Established(fragment.Received))
			}
		})
	}
}

// A fragment that never arrived leaves every later evidence unusable to the
// consumer that missed it, and the last evidence it can use vouches for nothing
// past the missing fragment. The refused fragment's own evidence claimed its
// bytes, which is why receipt is checked by the consumer rather than read from
// any evidence.
func TestEvidenceAfterAFragmentTheConsumerNeverReceivedVouchesForNothingPastIt(t *testing.T) {
	p, sink := witnessing(3)
	p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
	p.Transfer(numberedAs(worker, 0x18, fragment.Received, 5, 7, 1))
	p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 2)) // refused at the sink
	p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 3))
	p.Transfer(numberedAs(worker, 0x18, fragment.Received, 5, 7, 2))

	if len(sink.refused) != 1 || len(sink.records) != 4 {
		t.Fatalf("wiring, not the property: %d refused and %d delivered, want 1 and 4",
			len(sink.refused), len(sink.records))
	}
	// What the consumer holds without a gap, counted from the fragments.
	var held uint64
	for _, record := range sink.records {
		if record.Sequence != held+1 {
			break
		}
		held = record.Sequence
	}
	if held != 2 {
		t.Fatalf("wiring, not the property: the consumer holds fragments 1 through %d without a gap, want 2",
			held)
	}

	refused := sink.refused[0].Evidence
	if !refused.Taken() || refused.Established(fragment.Sent) != 20 {
		t.Errorf("the refused fragment's evidence vouches for sent offsets below %d, want 20: the claim the "+
			"receipt rule exists to refuse", refused.Established(fragment.Sent))
	}
	if refused.Usable(held) {
		t.Errorf("the refused fragment's evidence is usable to a consumer holding 1 through %d", held)
	}
	for _, record := range sink.records {
		usable := record.Evidence.Usable(held)
		switch {
		case record.Sequence <= held && !usable:
			t.Errorf("fragment %d's evidence is not usable to a consumer holding 1 through %d",
				record.Sequence, held)
		case record.Sequence > held && usable:
			t.Errorf("fragment %d's evidence is usable to a consumer that never received fragment %d",
				record.Sequence, held+1)
		}
		if record.Sequence <= held && record.Evidence.Established(fragment.Sent) > 10 {
			t.Errorf("fragment %d's evidence vouches for sent offsets below %d, past the missing fragment at 10",
				record.Sequence, record.Evidence.Established(fragment.Sent))
		}
		if record.Sequence > held && record.Evidence.Established(fragment.Sent) > 10 {
			t.Errorf("fragment %d's evidence re-establishes sent offsets below %d after the refusal at 10",
				record.Sequence, record.Evidence.Established(fragment.Sent))
		}
	}
}

// Evidence for one occupancy of a handle never stands for another: a reused
// handle is a new connection, and its evidence attached to the old connection's
// fragment is refused.
func TestEvidenceOfAReusedHandleNeverStandsForTheOccupancyBeforeIt(t *testing.T) {
	sink := &collected{}
	s := recording(sink)
	s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
	s.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 9, 1))

	if len(sink.records) != 2 || sink.records[0].Connection == sink.records[1].Connection {
		t.Fatalf("wiring, not the property: %d fragments, want two on two connections", len(sink.records))
	}
	before, after := sink.records[0], sink.records[1]
	if !before.Evidence.Taken() || !after.Evidence.Taken() {
		t.Fatalf("a fragment carries no evidence: before %t, after %t",
			before.Evidence.Taken(), after.Evidence.Taken())
	}
	if after.Evidence.Identity.Connection != after.Connection || after.Evidence.Occupancy != 9 {
		t.Errorf("the reused handle's evidence names connection %d in occupancy %d, want %d in 9",
			after.Evidence.Identity.Connection, after.Evidence.Occupancy, after.Connection)
	}
	grafted := before
	grafted.Evidence = after.Evidence
	grafted.Evidence.Through = before.Sequence
	if err := grafted.Validate(); !errors.Is(err, fragment.ErrInvalid) {
		t.Errorf("the old connection's fragment carrying the new occupancy's evidence is accepted: %v", err)
	}
}

// The retirement record, the later word, agrees with the last evidence the
// consumer held, and with every one before it: it keeps the identity and every
// cut, and never cuts below what an evidence established, however the
// connection ended.
func TestTheRetirementRecordAgreesWithTheEvidenceBeforeIt(t *testing.T) {
	traffic := func(p *producer) {
		p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
		p.Transfer(numberedAs(worker, 0x18, fragment.Received, 5, 7, 1))
		p.Transfer(numberedAs(worker, 0x18, fragment.Received, 0, 7, 2))
		p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 7, 7, 2))
		p.Transfer(numberedAs(worker, 0x18, fragment.Received, 5, 7, 3))
	}
	born := probe.Sequence{Occupancy: 7, Born: true}
	cases := []struct {
		name string
		end  func(p *producer)
		how  connection.Ending
	}{
		{"closed with every transfer delivered", func(p *producer) {
			p.Closed(ending(worker, 0x18))
		}, connection.HandleReleasedEnding},
		{"closed with its last transfers lost", func(p *producer) {
			c := ending(worker, 0x18)
			c.Sequence = born
			c.Final = probe.Final{Known: true, Sent: probe.Terminal{Last: 4}, Received: probe.Terminal{Last: 3}}
			p.Closed(c)
		}, connection.HandleReleasedEnding},
		{"settled while open at session end", func(p *producer) {
			p.Finish(at)
		}, connection.StillOpen},
		{"retired when the producer began another occupancy", func(p *producer) {
			p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 4, 9, 1))
		}, connection.EndingUnobserved},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, sink := witnessing(0)
			traffic(p)
			c.end(p)

			var retired *connection.Record
			for _, one := range p.Records() {
				if one.ID == 1 {
					retired = &one
				}
			}
			delivered := 0
			for _, record := range sink.records {
				if record.Connection == 1 {
					delivered++
				}
			}
			if retired == nil || delivered != 4 || retired.How != c.how {
				t.Fatalf("wiring, not the property: %d fragments of the connection delivered and its "+
					"retirement %v, want 4 and one ending %s", delivered, retired, c.how)
			}
			last := sink.records[delivered-1].Evidence
			if !last.Taken() {
				t.Fatalf("the last fragment carries no evidence")
			}
			if retired.Fragments.Value != int64(last.Through) {
				t.Errorf("the retirement counts %s fragments and the last evidence describes %d",
					retired.Fragments, last.Through)
			}
			for _, record := range sink.records[:delivered] {
				if err := retired.Agrees(record.Evidence); err != nil {
					t.Errorf("against fragment %d's evidence: %v", record.Sequence, err)
				}
			}
		})
	}
}

// A retirement that cut a direction at a fragment its sink refused agrees with
// the evidence the consumer last held and contradicts the refused fragment's
// own, which claimed bytes nobody received.
func TestTheRetirementContradictsTheEvidenceOfAFragmentThatNeverArrived(t *testing.T) {
	p, sink := witnessing(3)
	p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 1))
	p.Transfer(numberedAs(worker, 0x18, fragment.Received, 5, 7, 1))
	p.Transfer(numberedAs(worker, 0x18, fragment.Sent, 10, 7, 2)) // refused at the sink
	p.Closed(ending(worker, 0x18))

	records := p.Records()
	if len(sink.refused) != 1 || len(sink.records) != 2 || len(records) != 1 {
		t.Fatalf("wiring, not the property: %d refused, %d delivered, %d retirements, want 1, 2 and 1",
			len(sink.refused), len(sink.records), len(records))
	}
	retired := records[0]
	if err := retired.Agrees(sink.records[1].Evidence); err != nil {
		t.Errorf("against the last evidence the consumer held: %v", err)
	}
	if err := retired.Agrees(sink.refused[0].Evidence); !errors.Is(err, connection.ErrInvalid) {
		t.Errorf("the retirement agrees with the refused fragment's evidence, which established sent offsets "+
			"the retirement cut: %v", err)
	}
}
