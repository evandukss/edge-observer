package fragment_test

import (
	"errors"
	"testing"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/fragment"
)

// evidenced is valid() carrying the evidence capture would take at it: the
// sent direction placed through this fragment's end with every number resolved,
// and the received direction holding one read that moved nothing after its last
// fragment. Each case changes one thing.
func evidenced() fragment.Record {
	record := valid()
	record.Produced = 3
	record.Evidence = fragment.Evidence{
		Identity: &fragment.Identity{
			Connection: record.Connection,
			Process:    record.Process,
			Instance: admission.Instance{
				Namespace:  admission.Namespace{Device: 4, Inode: 4026531836},
				PID:        1731,
				Start:      admission.Determinate(90210),
				Generation: 1,
			},
			Address:    0x18,
			Generation: 18,
			FirstSeen:  at,
		},
		Occupancy: 7,
		Origin:    fragment.OriginBirth,
		Through:   record.Sequence,
		Sent:      fragment.DirectionEvidence{Limit: record.End(), First: 1, Numbered: 3, Resolved: 3},
		Received:  fragment.DirectionEvidence{Limit: 20, First: 1, Numbered: 2, Resolved: 2, Empties: 1},
	}
	return record
}

func TestTheControlEvidenceIsValidAndBoundToItsRecord(t *testing.T) {
	record := evidenced()
	if err := record.Evidence.Validate(); err != nil {
		t.Fatalf("the control evidence: %v", err)
	}
	if err := record.Validate(); err != nil {
		t.Fatalf("the control record: %v", err)
	}
	if err := record.Evidenced(); err != nil {
		t.Fatalf("the control binding: %v", err)
	}
}

// Every rule an evidence keeps on its own refuses the evidence that breaks it,
// and each says why a consumer would be misled.
func TestEvidenceThatContradictsItselfIsRefused(t *testing.T) {
	cases := []struct {
		name   string
		change func(*fragment.Evidence)
	}{
		{"no evidence taken", func(e *fragment.Evidence) { *e = fragment.Evidence{} }},
		{"no identity", func(e *fragment.Evidence) { e.Identity = nil }},
		{"connection zero", func(e *fragment.Evidence) { e.Identity.Connection = 0 }},
		{"no process", func(e *fragment.Evidence) { e.Identity.Process.PID = 0 }},
		{"no origin", func(e *fragment.Evidence) { e.Origin = fragment.OriginUnset }},
		{"an origin past the named ones", func(e *fragment.Evidence) { e.Origin = fragment.OriginUnestablished + 1 }},
		{"no occupancy and an established origin", func(e *fragment.Evidence) { e.Occupancy = 0 }},
		{"an unestablished origin and an uncut direction", func(e *fragment.Evidence) {
			e.Origin = fragment.OriginUnestablished
			e.Received.Cut = true
		}},
		{"an unestablished origin and a cut past zero", func(e *fragment.Evidence) {
			e.Origin = fragment.OriginUnestablished
			e.Sent.Cut, e.Sent.From = true, 4
			e.Received.Cut = true
		}},
		{"an offset of a cut that was not made", func(e *fragment.Evidence) { e.Sent.From = 4 }},
		{"a cut past the bytes reached", func(e *fragment.Evidence) {
			e.Sent.Cut, e.Sent.From = true, e.Sent.Limit+1
		}},
		{"transfers lost and no cut", func(e *fragment.Evidence) { e.Sent.Lost = 1 }},
		{"an uncounted loss and no cut", func(e *fragment.Evidence) { e.Sent.LostUncounted = true }},
		{"a first number past the highest", func(e *fragment.Evidence) { e.Sent.First = 4 }},
		{"numbers seen and no first", func(e *fragment.Evidence) { e.Sent.First = 0 }},
		{"resolved past the highest number", func(e *fragment.Evidence) {
			e.Sent.Cut, e.Sent.Resolved = true, 4
		}},
		{"resolved from a first number past one", func(e *fragment.Evidence) {
			e.Sent.Cut, e.Sent.First = true, 2
		}},
		{"more empty transfers than numbers", func(e *fragment.Evidence) { e.Received.Empties = 3 }},
		{"an uncut direction with numbers unresolved", func(e *fragment.Evidence) { e.Sent.Resolved = 2 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			record := evidenced()
			identity := *record.Evidence.Identity
			record.Evidence.Identity = &identity
			c.change(&record.Evidence)
			if err := record.Evidence.Validate(); !errors.Is(err, fragment.ErrInvalid) {
				t.Errorf("accepted: %v", err)
			}
		})
	}
}

// A record carrying evidence carries its own: the evidence names its
// connection and process and was taken through it. Evidence is optional, and a
// record without it is what it was before evidence existed.
func TestARecordRefusesEvidenceThatIsNotItsOwn(t *testing.T) {
	without := evidenced()
	without.Evidence = fragment.Evidence{}
	if err := without.Validate(); err != nil {
		t.Errorf("a record with no evidence is refused: %v", err)
	}

	cases := []struct {
		name   string
		change func(*fragment.Record)
	}{
		{"another connection", func(r *fragment.Record) { r.Connection++ }},
		{"another process", func(r *fragment.Record) { r.Process.StartTime++ }},
		{"taken through another fragment", func(r *fragment.Record) { r.Evidence.Through++ }},
		{"evidence that contradicts itself", func(r *fragment.Record) { r.Evidence.Sent.Lost = 1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			record := evidenced()
			c.change(&record)
			if err := record.Validate(); !errors.Is(err, fragment.ErrInvalid) {
				t.Errorf("accepted: %v", err)
			}
		})
	}
}

// A consumer shortens a record to the bytes it keeps, and the shortened record
// still validates; the whole binding is read on receipt, before that, and a
// shortened record no longer meets it.
func TestTheWholeBindingIsReadOnReceiptAndSurvivesNoTrimming(t *testing.T) {
	trimmed := evidenced()
	trimmed.Length -= 4
	trimmed.Payload = trimmed.Payload[:trimmed.Length]
	if err := trimmed.Validate(); err != nil {
		t.Errorf("a record shortened to the bytes kept is refused: %v", err)
	}
	if err := trimmed.Evidenced(); !errors.Is(err, fragment.ErrInvalid) {
		t.Errorf("a shortened record meets the binding of the record capture placed: %v", err)
	}

	unnumbered := evidenced()
	unnumbered.Produced = 0
	unnumbered.Evidence.Sent = fragment.DirectionEvidence{Limit: unnumbered.End(), Cut: true, From: unnumbered.Offset,
		LostUncounted: true}
	if err := unnumbered.Evidenced(); err != nil {
		t.Errorf("a fragment no producer numbered, its direction cut at it, is refused: %v", err)
	}

	cases := []struct {
		name   string
		change func(*fragment.Record)
	}{
		{"no evidence", func(r *fragment.Record) { r.Evidence = fragment.Evidence{} }},
		{"a limit short of the fragment's end", func(r *fragment.Record) { r.Evidence.Sent.Limit-- }},
		{"a limit past the fragment's end", func(r *fragment.Record) { r.Evidence.Sent.Limit++ }},
		{"empty transfers after a fragment it was taken at", func(r *fragment.Record) {
			r.Evidence.Sent.Empties = 1
		}},
		{"an unnumbered fragment its evidence vouches for", func(r *fragment.Record) { r.Produced = 0 }},
		{"an unnumbered fragment cut only past it", func(r *fragment.Record) {
			r.Produced = 0
			r.Evidence.Sent.Cut, r.Evidence.Sent.From, r.Evidence.Sent.Resolved = true, r.Offset+1, 2
		}},
		{"a producer number past the evidence's highest", func(r *fragment.Record) { r.Produced = 4 }},
		{"an uncut evidence resolved short of the fragment", func(r *fragment.Record) {
			r.Produced = 2
		}},
		{"a record that is not valid", func(r *fragment.Record) { r.Evidence.Through++ }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			record := evidenced()
			identity := *record.Evidence.Identity
			record.Evidence.Identity = &identity
			c.change(&record)
			if err := record.Evidenced(); !errors.Is(err, fragment.ErrInvalid) {
				t.Errorf("accepted: %v", err)
			}
		})
	}
}

// What an evidence vouches for in a direction stops at its limit, or at its cut
// where there is one, and evidence not taken vouches for nothing.
func TestEvidenceVouchesForADirectionOnlyBelowItsLimitAndItsCut(t *testing.T) {
	record := evidenced()
	evidence := record.Evidence
	if got := evidence.Established(fragment.Sent); got != record.End() {
		t.Errorf("an uncut direction vouches below %d, want its limit %d", got, record.End())
	}
	evidence.Received = fragment.DirectionEvidence{Limit: 20, Cut: true, From: 12, Lost: 1, First: 1, Numbered: 3,
		Resolved: 1}
	if got := evidence.Established(fragment.Received); got != 12 {
		t.Errorf("a direction cut at 12 vouches below %d", got)
	}
	evidence.Received.From = 0
	if got := evidence.Established(fragment.Received); got != 0 {
		t.Errorf("a direction cut at its first byte vouches below %d", got)
	}
	if got := evidence.Established(fragment.Unknown); got != 0 {
		t.Errorf("a direction that is neither sent nor received vouches below %d", got)
	}
	if got := (fragment.Evidence{Sent: fragment.DirectionEvidence{Limit: 20}}).Established(fragment.Sent); got != 0 {
		t.Errorf("evidence not taken vouches for sent offsets below %d", got)
	}
}

// The falsifying state of the receipt rule: a fragment lost before fragment N,
// and evidence arriving with N that claims every offset placed. A consumer
// relies only on evidence through the last fragment it holds without a gap, so
// N's evidence authorises nothing, and what it can rely on stops before the
// hole.
func TestALaterEvidenceNeverAuthorisesInputTheConsumerIsMissing(t *testing.T) {
	const missing = 3
	var records []fragment.Record
	for sequence := uint64(1); sequence <= 6; sequence++ {
		record := evidenced()
		identity := *record.Evidence.Identity
		record.Evidence.Identity = &identity
		record.Sequence = sequence
		record.Offset = (sequence - 1) * uint64(record.Length)
		record.Produced = sequence
		record.Evidence.Through = sequence
		record.Evidence.Sent = fragment.DirectionEvidence{Limit: record.End(), First: 1, Numbered: sequence,
			Resolved: sequence}
		record.Evidence.Received = fragment.DirectionEvidence{}
		if err := record.Evidenced(); err != nil {
			t.Fatalf("wiring, not the property: fragment %d of the fixture is not one capture could place: %v",
				sequence, err)
		}
		if sequence != missing {
			records = append(records, record)
		}
	}
	var held uint64
	for _, record := range records {
		if record.Sequence != held+1 {
			break
		}
		held = record.Sequence
	}
	if held != missing-1 || len(records) != 5 {
		t.Fatalf("wiring, not the property: the consumer holds 1 through %d of %d fragments, want 1 through %d",
			held, len(records), missing-1)
	}

	last := records[len(records)-1].Evidence
	if last.Established(fragment.Sent) != records[len(records)-1].End() {
		t.Fatalf("wiring, not the property: the last evidence does not claim every sent offset placed")
	}
	for _, record := range records {
		usable := record.Evidence.Usable(held)
		if record.Sequence < missing && !usable {
			t.Errorf("fragment %d's evidence is unusable to a consumer holding 1 through %d", record.Sequence, held)
		}
		if record.Sequence > missing && usable {
			t.Errorf("fragment %d's evidence is usable to a consumer missing fragment %d", record.Sequence, missing)
		}
	}
	if (fragment.Evidence{}).Usable(held) {
		t.Errorf("evidence not taken is usable")
	}
}
