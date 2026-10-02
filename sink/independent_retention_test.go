package sink_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/sink"
)

type churnSink struct{ writes atomic.Int64 }

func (s *churnSink) Write(_ context.Context, b []byte) (int, error) {
	s.writes.Add(1)
	return len(b), nil
}
func (*churnSink) Reopen(context.Context) error { return nil }
func (*churnSink) Close(context.Context) error  { return nil }

func TestIndependentSinkChurnRetainsOnlyDestinations(t *testing.T) {
	q, err := sink.NewQueue(32)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer func() { _ = q.Shutdown(ctx) }()
	target := &churnSink{}
	if err := q.Register("first", target); err != nil {
		t.Fatal(err)
	}
	if err := q.Register("second", target); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 160; i++ {
		name := "first"
		if i%2 == 1 {
			name = "second"
		}
		if err := q.Enqueue(name, []byte("{}\n")); err != nil {
			t.Fatalf("constant-population enqueue refused at%d: %v", i, err)
		}
		if err := q.Drain(ctx); err != nil {
			t.Fatal(err)
		}
		if target.writes.Load() != int64(i+1) {
			t.Fatal("wiring, not the property: sink did not consume one line")
		}
		stores, err := q.Retained()
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range stores {
			switch v.Store {
			case "sink.lines":
				if v.Held != 0 {
					t.Errorf("queue retains%d drained lines", v.Held)
				}
			case "sink.destinations":
				if v.Held != 2 {
					t.Errorf("destination population grew to%d", v.Held)
				}
			case "sink.lines_capacity":
				if v.Held > 10 {
					t.Errorf("backing capacity%d exceeds byte-bound population10", v.Held)
				}
			default:
				t.Errorf("uninventoried sink store%q", v.Store)
			}
		}
	}
	s := q.Stats()
	if s.Written != 160 || s.PendingBytes != 0 || s.Failed != 0 || s.Dropped != 0 {
		t.Errorf("queue churn refused or retained lines: %+v", s)
	}
	t.Logf("PRECONDITIONS churn=160 live_lines=0 destinations=2 byte_bound=32 stats=%+v", s)
}
