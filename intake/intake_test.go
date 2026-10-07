package intake_test

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
)

func open(t *testing.T, limit int64) *intake.Store {
	t.Helper()
	s, err := intake.New(limit)
	if err != nil || s == nil {
		t.Fatalf("New(%d): store=%v error=%v", limit, s, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func fragmentBytes(payload string) int64 {
	return int64(unsafe.Sizeof(intake.Entry{})+unsafe.Sizeof(fragment.Record{})) + int64(len(payload))
}

func TestPositiveLimitAndUninitializedStore(t *testing.T) {
	for _, n := range []int64{-1, 0} {
		if s, err := intake.New(n); err == nil || s != nil {
			t.Fatalf("invalid limit %d: %v %v", n, s, err)
		}
	}
	s := open(t, 1)
	if got := s.Stats(); got.LimitBytes != 1 || got.Bytes != 0 {
		t.Fatalf("empty store: %+v", got)
	}
	for _, s := range []*intake.Store{nil, new(intake.Store)} {
		if err := s.Write(fragment.Record{}); !errors.Is(err, intake.ErrUninitialized) {
			t.Errorf("uninitialized Write: %v", err)
		}
		if err := s.Connection(connection.Record{}); !errors.Is(err, intake.ErrUninitialized) {
			t.Errorf("uninitialized Connection: %v", err)
		}
		if s.Take() != nil {
			t.Error("uninitialized store returned an entry")
		}
		select {
		case <-s.Exhausted():
		default:
			t.Error("uninitialized store did not signal")
		}
	}
}

func TestFIFOOwnsPayloadAndOpaqueRecords(t *testing.T) {
	s := open(t, 1<<20)
	// Neither valid framing nor valid record metadata is a storage prerequisite.
	f := fragment.Record{Payload: []byte("unfinished\x00HTTP"), At: time.Now()}
	c := connection.Record{ID: 7}
	if err := s.Write(f); err != nil {
		t.Fatal(err)
	}
	if err := s.Connection(c); err != nil {
		t.Fatal(err)
	}
	f.Payload[0] = '!'
	one, two := s.Take(), s.Take()
	if one == nil || one.Fragment == nil || two == nil || two.Connection == nil {
		t.Fatal("both callback records must be available in FIFO order")
	}
	defer one.Release()
	defer two.Release()
	if string(one.Fragment.Payload) != "unfinished\x00HTTP" || two.Connection.ID != 7 {
		t.Fatal("owned record changed or FIFO changed")
	}
	if one.Connection != nil || two.Fragment != nil || s.Take() != nil {
		t.Fatal("entry kind or empty queue")
	}
	if st := s.Stats(); st.Fragments != 1 || st.Connections != 1 || st.Queued != 0 || st.Leased != 2 {
		t.Fatalf("counts: %+v", st)
	}
}

func TestConnectionOwnsNestedRecordsAndChargesLengths(t *testing.T) {
	s := open(t, 1<<20)
	c := connection.Record{
		Associations: []connection.Association{{Contended: []connection.Descriptor{{Number: 17}}, Endpoints: connection.Endpoints{Local: connection.At(netip.MustParseAddr("fe80::1%zone"), 80)}}},
		Placements:   []connection.Placement{{Lost: connection.Uncounted("unknown")}},
		Early:        []connection.Early{{Length: 3}}, Fragments: connection.Uncounted("missing"),
		FirstSeen: time.Date(2026, 1, 1, 0, 0, 0, 0, time.FixedZone("local", 3600)),
	}
	c.Instance.Executable = strings.Repeat("x", 19)
	want := int64(unsafe.Sizeof(intake.Entry{})+unsafe.Sizeof(c)+unsafe.Sizeof(connection.Association{})+unsafe.Sizeof(connection.Descriptor{})+unsafe.Sizeof(connection.Placement{})+unsafe.Sizeof(connection.Early{})) + 19 + 4 + 7 + 7
	if err := s.Connection(c); err != nil {
		t.Fatal(err)
	}
	if got := s.Stats().Bytes; got != want {
		t.Fatalf("accounted bytes=%d want %d", got, want)
	}
	c.Associations[0].Contended[0].Number = 99
	c.Placements[0].Lost.Why = "changed"
	c.Early[0].Length = 99
	e := s.Take()
	if e == nil || e.Connection == nil {
		t.Fatal("no connection available")
	}
	defer e.Release()
	r := e.Connection
	if r.Associations[0].Contended[0].Number != 17 || r.Placements[0].Lost.Why != "unknown" || r.Early[0].Length != 3 {
		t.Fatal("caller mutation changed stored metadata")
	}
	if r.FirstSeen.Location() != time.UTC || !r.FirstSeen.Equal(c.FirstSeen) {
		t.Fatal("time must preserve instant without retaining location tables")
	}
}

func TestSharedBoundRefusesWholeRecordAndRecoversAfterRelease(t *testing.T) {
	for _, kind := range []string{"fragment", "connection"} {
		t.Run(kind, func(t *testing.T) {
			cost := fragmentBytes("abc")
			s := open(t, cost)
			if err := s.Write(fragment.Record{Payload: []byte("abc")}); err != nil {
				t.Fatalf("exact-limit control: %v", err)
			}
			before := s.Stats()
			if before.Bytes != cost || before.Fragments != 1 {
				t.Fatalf("control was not held: %+v", before)
			}
			var err error
			if kind == "fragment" {
				err = s.Write(fragment.Record{})
			} else {
				err = s.Connection(connection.Record{})
			}
			if !errors.Is(err, intake.ErrLimit) {
				t.Fatalf("intended storage fault not reached: %v", err)
			}
			st := s.Stats()
			if st.Bytes != cost || st.Queued != 1 || !st.Exhausted {
				t.Fatalf("refused record changed storage: %+v", st)
			}
			if kind == "fragment" && st.FragmentsRefused != 1 || kind == "connection" && st.ConnectionsRefused != 1 {
				t.Fatalf("refusal not counted: %+v", st)
			}
			select {
			case <-s.Exhausted():
			default:
				t.Fatal("exhaustion not signalled")
			}
			e := s.Take()
			if e == nil {
				t.Fatal("accepted control disappeared")
			}
			e.Release()
			if err := s.Write(fragment.Record{}); err != nil {
				t.Fatalf("released capacity stayed unavailable: %v", err)
			}
			if next := s.Take(); next == nil {
				t.Fatal("fresh record was not retained")
			} else {
				next.Release()
			}
			if s.Stats().Bytes != 0 {
				t.Fatal("record release leaked bytes")
			}
		})
	}
}

func TestOversizedRecordAndExactFitControl(t *testing.T) {
	cost := fragmentBytes("abc")
	tooSmall := open(t, cost-1)
	if err := tooSmall.Write(fragment.Record{Payload: []byte("abc")}); !errors.Is(err, intake.ErrLimit) {
		t.Fatalf("oversize not reached: %v", err)
	}
	if st := tooSmall.Stats(); st.Bytes != 0 || st.Queued != 0 || st.FragmentsRefused != 1 {
		t.Fatalf("oversized storage: %+v", st)
	}
	fit := open(t, cost)
	if err := fit.Write(fragment.Record{Payload: []byte("abc")}); err != nil {
		t.Fatal(err)
	}
	if fit.Stats().Bytes != cost {
		t.Fatal("exact-fit control missing")
	}
}

func TestLeasedStorageRemainsChargedAndReleaseIsIdempotent(t *testing.T) {
	cost := fragmentBytes("abc")
	s := open(t, cost)
	f := fragment.Record{Payload: []byte("abc")}
	if err := s.Write(f); err != nil {
		t.Fatal(err)
	}
	e := s.Take()
	if e == nil {
		t.Fatal("no entry")
	}
	if st := s.Stats(); st.Bytes != cost || st.Leased != 1 || st.Queued != 0 {
		t.Fatalf("lease lost its charge: %+v", st)
	}
	e.Release()
	e.Release()
	if st := s.Stats(); st.Bytes != 0 || st.Leased != 0 || e.Fragment != nil {
		t.Fatalf("release: %+v entry=%+v", st, e)
	}
	if err := s.Write(f); err != nil {
		t.Fatalf("released capacity control: %v", err)
	}
	if st := s.Stats(); st.Fragments != 2 || st.Bytes != cost {
		t.Fatalf("reuse: %+v", st)
	}
}

func TestCloseDiscardsQueueButPreservesOutstandingLeaseCharge(t *testing.T) {
	s := open(t, 1<<20)
	f := fragment.Record{Payload: []byte("abc")}
	if err := s.Write(f); err != nil {
		t.Fatal(err)
	}
	if err := s.Connection(connection.Record{}); err != nil {
		t.Fatal(err)
	}
	e := s.Take()
	if e == nil {
		t.Fatal("no entry")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	before := s.Stats()
	if !before.Closed || before.Bytes != fragmentBytes("abc") || before.Queued != 0 || before.Leased != 1 || s.Take() != nil {
		t.Fatalf("close: %+v", before)
	}
	if err := s.Close(); err != nil || !reflect.DeepEqual(s.Stats(), before) {
		t.Fatal("second close changed state")
	}
	if err := s.Write(f); !errors.Is(err, intake.ErrClosed) {
		t.Fatalf("closed Write: %v", err)
	}
	if err := s.Connection(connection.Record{}); !errors.Is(err, intake.ErrClosed) {
		t.Fatalf("closed Connection: %v", err)
	}
	e.Release()
	if st := s.Stats(); st.Bytes != 0 || st.Leased != 0 || st.FragmentsRefused != 1 || st.ConnectionsRefused != 1 {
		t.Fatalf("closed release: %+v", st)
	}
}

func TestConcurrentCallbacksAccountEveryAcceptedRecord(t *testing.T) {
	s := open(t, 1<<20)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if err := s.Write(fragment.Record{Payload: []byte("data")}); err != nil {
					t.Error(err)
				}
				if err := s.Connection(connection.Record{}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	fragments, connections := 0, 0
	for e := s.Take(); e != nil; e = s.Take() {
		if e.Fragment != nil {
			fragments++
		}
		if e.Connection != nil {
			connections++
		}
		e.Release()
	}
	if fragments != 160 || connections != 160 {
		t.Fatalf("drained %d fragments, %d connections", fragments, connections)
	}
	if st := s.Stats(); st.Bytes != 0 || st.Queued != 0 || st.Leased != 0 || st.Fragments != 160 || st.Connections != 160 {
		t.Fatalf("concurrent totals: %+v", st)
	}
}
