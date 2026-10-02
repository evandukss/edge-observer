package sink_test

import (
	"context"
	"errors"
	"fmt"
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

type retainedByteSink struct { permits chan struct{} }
func (s *retainedByteSink) Write(ctx context.Context, b []byte) (int, error) {
	select { case <-s.permits: return len(b), nil; case <-ctx.Done(): return 0, ctx.Err() }
}
func (*retainedByteSink) Reopen(context.Context) error { return nil }
func (*retainedByteSink) Close(context.Context) error { return nil }

func TestIndependentSinkSaturationKeepsBackingBounded(t *testing.T) {
	for _, limit := range []int64{32, 256} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			target := &retainedByteSink{permits: make(chan struct{}, 256)}
			q := independentQueue(t, limit, target)
			line := []byte("1234567\n")
			count := int(limit)/len(line)
			t.Cleanup(func() { for i := 0; i < count; i++ { target.permits <- struct{}{} } })
			for cycle := 0; cycle < 40; cycle++ {
				for i := 0; i < count; i++ { if err := q.Enqueue(independentName, line); err != nil { t.Fatal(err) } }
				if stats := q.Stats(); stats.PendingBytes != limit || stats.Pending != uint64(count) { t.Fatalf("wiring, not the property: byte limit not saturated: %+v", stats) }
				if err := q.Enqueue(independentName, line); !errors.Is(err, sink.ErrQueueFull) { t.Fatalf("full queue accepted excess: %v", err) }
				stores, err := q.Retained(); if err != nil { t.Fatal(err) }
				for _, v := range stores { if v.Store == "sink.lines" && v.Held != count { t.Errorf("positive queue population %d != %d", v.Held, count) } }
				for i := 0; i < count; i++ { target.permits <- struct{}{} }
				independentDrain(t, q)
				if stats := q.Stats(); stats.PendingBytes != 0 { t.Fatalf("drained queue retained byte charge: %+v", stats) }
				stores, err = q.Retained(); if err != nil { t.Fatal(err) }
				for _, v := range stores {
					if v.Store == "sink.lines" && v.Held != 0 { t.Errorf("drained queue holds %d lines", v.Held) }
					if v.Store == "sink.lines_capacity" && v.Held > 2*count { t.Errorf("backing capacity %d grows beyond saturated population %d", v.Held, count) }
				}
			}
			if stats := q.Stats(); stats.Written != uint64(40*count) || stats.Dropped != 40 || stats.Failed != 0 { t.Errorf("saturation conservation: %+v", stats) }
			t.Logf("PRECONDITIONS cycles=40 byte_bound=%d max_live_lines=%d exact_full_refusals=40", limit, count)
		})
	}
}
