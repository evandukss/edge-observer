package intake_test

import (
	"errors"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
)

// Red-first against e1663af's published, behavior-free interface. No parser,
// worker, admission gate, or filesystem writer is supplied by this fixture.
func p3t9Store(t *testing.T, limit int64) *intake.Store {
	t.Helper()
	s, err := intake.New(limit)
	if err != nil || s == nil {
		t.Fatalf("positive-limit constructor unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return s
}

func p3t9Signal(t *testing.T, s *intake.Store, exhausted bool) {
	t.Helper()
	select {
	case <-s.Exhausted():
		if !exhausted {
			t.Fatal("successful neighbor signaled exhaustion")
		}
	default:
		if exhausted {
			t.Fatal("storage refusal returned without exhaustion signal")
		}
	}
}

func TestP3T9IntakeOwnsOpaqueRecordsAndChargesLengths(t *testing.T) {
	s := p3t9Store(t, 1<<20)
	// Intentionally not structurally valid: storage must not decide whether
	// this fragment or retirement is complete or parseable.
	payload := make([]byte, 4, 4096)
	copy(payload, "data")
	f := fragment.Record{Payload: payload, At: time.Unix(100, 0).In(time.FixedZone("caller", 3600))}
	r := connection.Record{ID: 9, Placements: make([]connection.Placement, 1, 100), Early: make([]connection.Early, 1, 100)}
	r.Placements[0] = connection.Placement{From: 17, Lost: connection.Uncounted("unknown")}
	r.Early[0] = connection.Early{Offset: 11, Length: 3}
	if err := s.Write(f); err != nil {
		t.Fatalf("opaque fragment refused: %v", err)
	}
	if err := s.Connection(r); err != nil {
		t.Fatalf("opaque retirement refused: %v", err)
	}
	before := s.Stats()
	payload[0] = 'X'
	r.Placements[0].From, r.Early[0].Offset = 999, 999
	first, second := s.Take(), s.Take()
	if first == nil || first.Fragment == nil || first.Connection != nil || second == nil || second.Connection == nil || second.Fragment != nil {
		t.Fatal("callback FIFO/type ownership lost")
	}
	defer first.Release()
	defer second.Release()
	if string(first.Fragment.Payload) != "data" || first.Fragment.At.Location() != time.UTC || !first.Fragment.At.Equal(f.At) {
		t.Fatalf("fragment aliases caller or retains timezone: %+v", first.Fragment)
	}
	if second.Connection.Placements[0].From != 17 || second.Connection.Early[0].Offset != 11 {
		t.Fatal("retirement retained caller slice backing")
	}
	if now := s.Stats(); now.Bytes != before.Bytes || now.Queued != 0 || now.Leased != 2 || now.Fragments != 1 || now.Connections != 1 {
		t.Fatalf("Take refunded or lost storage: %+v", now)
	}
	if s.Take() != nil {
		t.Fatal("empty Take did not return nil")
	}
	p3t9Signal(t, s, false)

	// Compare identical lengths with different caller capacities, then exact
	// variable-length deltas. This avoids choosing the private fixed entry
	// overhead while independently pinning what payload/nested storage costs.
	a, b := p3t9Store(t, 1<<20), p3t9Store(t, 1<<20)
	if err := a.Write(fragment.Record{Payload: make([]byte, 4)}); err != nil {
		t.Fatal(err)
	}
	if err := b.Write(fragment.Record{Payload: make([]byte, 4, 4096)}); err != nil {
		t.Fatal(err)
	}
	if a.Stats().Bytes != b.Stats().Bytes || a.Stats().Bytes <= 4 {
		t.Fatal("spare capacity charged or fixed record cost absent")
	}
	c := p3t9Store(t, 1<<20)
	if err := c.Write(fragment.Record{Payload: make([]byte, 5)}); err != nil {
		t.Fatal(err)
	}
	if c.Stats().Bytes-a.Stats().Bytes != 1 {
		t.Fatal("one additional payload byte did not cost one byte")
	}
	d, e := p3t9Store(t, 1<<20), p3t9Store(t, 1<<20)
	if err := d.Connection(connection.Record{}); err != nil {
		t.Fatal(err)
	}
	if err := e.Connection(connection.Record{Early: make([]connection.Early, 1, 100)}); err != nil {
		t.Fatal(err)
	}
	if e.Stats().Bytes-d.Stats().Bytes != int64(unsafe.Sizeof(connection.Early{})) {
		t.Fatal("nested retirement storage was not charged by length")
	}
}

func TestP3T9IntakeSharedLimitRefusesWholeRecordAndStaysExhausted(t *testing.T) {
	f := fragment.Record{Payload: []byte("pending")}
	r := connection.Record{ID: 9, Early: []connection.Early{{Length: 7}}}
	// Fixed cost is architecture-dependent and the contract does not publish
	// a size function. Establish actual charges, independently tested above,
	// then pin the adjacent accepted/refused shared-bound cases.
	measure := p3t9Store(t, 1<<20)
	if err := measure.Write(f); err != nil {
		t.Fatal(err)
	}
	fBytes := measure.Stats().Bytes
	if err := measure.Connection(r); err != nil {
		t.Fatal(err)
	}
	total := measure.Stats().Bytes
	if fBytes <= 0 || total <= fBytes {
		t.Fatal("both record kinds were not charged")
	}
	for _, connectionFirst := range []bool{false, true} {
		for _, exact := range []bool{true, false} {
			name := "fragment_first"
			if connectionFirst {
				name = "connection_first"
			}
			if exact {
				name += "/exact_fit"
			} else {
				name += "/one_byte_short"
			}
			t.Run(name, func(t *testing.T) {
				limit := total
				if !exact {
					limit--
				}
				s := p3t9Store(t, limit)
				insertFirst, insertSecond := func() error { return s.Write(f) }, func() error { return s.Connection(r) }
				if connectionFirst {
					insertFirst, insertSecond = insertSecond, insertFirst
				}
				if err := insertFirst(); err != nil {
					t.Fatalf("first record refused: %v", err)
				}
				lease := s.Take()
				if lease == nil {
					t.Fatal("first callback yielded no pending entry")
				}
				defer lease.Release()
				before := s.Stats()
				err := insertSecond()
				if exact {
					if err != nil {
						t.Fatalf("exact-fit neighbor refused: %v", err)
					}
					p3t9Signal(t, s, false)
					next := s.Take()
					if next == nil {
						t.Fatal("accepted second record missing")
					}
					defer next.Release()
					if s.Stats().Bytes != total || s.Stats().Leased != 2 {
						t.Fatalf("shared charge lost: %+v", s.Stats())
					}
					next.Release()
					lease.Release()
					if s.Stats().Bytes != 0 {
						t.Fatal("release retained charged storage")
					}
					if err := insertFirst(); err != nil {
						t.Fatalf("non-exhausted released capacity not reusable: %v", err)
					}
				} else {
					if !errors.Is(err, intake.ErrLimit) {
						t.Fatalf("named limit fault not reached: %v", err)
					}
					p3t9Signal(t, s, true)
					after := s.Stats()
					if after.Bytes != before.Bytes || after.Queued != 0 || after.Leased != 1 || !after.Exhausted || after.Fragments != before.Fragments || after.Connections != before.Connections || after.Bytes > limit {
						t.Fatalf("refusal evicted, partially stored, or refunded pending data: before %+v after %+v", before, after)
					}
					if connectionFirst && after.FragmentsRefused != 1 || !connectionFirst && after.ConnectionsRefused != 1 {
						t.Fatalf("refused callback miscounted: %+v", after)
					}
					if connectionFirst {
						if !reflect.DeepEqual(*lease.Connection, r) {
							t.Fatal("refusal changed leased retirement")
						}
					} else if string(lease.Fragment.Payload) != "pending" {
						t.Fatal("refusal changed leased payload")
					}
					if s.Take() != nil {
						t.Fatal("whole-record refusal queued an entry")
					}
					lease.Release()
					if s.Stats().Bytes != 0 {
						t.Fatal("release failed after exhaustion")
					}
					if err := insertFirst(); !errors.Is(err, intake.ErrLimit) {
						t.Fatalf("release reopened exhausted store: %v", err)
					}
				}
			})
		}
	}
}

func TestP3T9IntakeCloseKeepsLeaseChargedUntilRelease(t *testing.T) {
	s := p3t9Store(t, 1<<20)
	if err := s.Write(fragment.Record{Payload: []byte("leased")}); err != nil {
		t.Fatal(err)
	}
	leaseBytes := s.Stats().Bytes
	lease := s.Take()
	if lease == nil {
		t.Fatal("lease missing")
	}
	defer lease.Release()
	if err := s.Connection(connection.Record{ID: 9}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s.Take() != nil {
		t.Fatal("Close left queued retirement available")
	}
	if s.Stats().Bytes != leaseBytes || s.Stats().Leased != 1 || s.Stats().Queued != 0 || !s.Stats().Closed || string(lease.Fragment.Payload) != "leased" {
		t.Fatalf("Close invalidated or refunded worker-owned data: %+v", s.Stats())
	}
	if err := s.Write(fragment.Record{}); !errors.Is(err, intake.ErrClosed) {
		t.Fatalf("closed store accepted fragment: %v", err)
	}
	if err := s.Connection(connection.Record{}); !errors.Is(err, intake.ErrClosed) {
		t.Fatalf("closed store accepted retirement: %v", err)
	}
	lease.Release()
	lease.Release()
	if s.Stats().Bytes != 0 || s.Stats().Leased != 0 || s.Stats().Fragments != 1 || s.Stats().Connections != 1 {
		t.Fatalf("release was not idempotent/cumulative: %+v", s.Stats())
	}
	control := p3t9Store(t, 1<<20)
	if err := control.Write(fragment.Record{}); err != nil {
		t.Fatalf("open opaque fragment control refused: %v", err)
	}
	if err := control.Connection(connection.Record{}); err != nil {
		t.Fatalf("open opaque retirement control refused: %v", err)
	}
}
