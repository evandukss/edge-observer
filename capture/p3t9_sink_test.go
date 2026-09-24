package capture

import (
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

type p3t9Sink struct {
	fragment   func(fragment.Record)
	retirement func(connection.Record)
}

func (s p3t9Sink) Write(r fragment.Record) error {
	if s.fragment != nil {
		s.fragment(r)
	}
	return nil
}
func (s p3t9Sink) Connection(r connection.Record) error {
	if s.retirement != nil {
		s.retirement(r)
	}
	return nil
}

func p3t9Transfer(stamp uint64) probe.Transfer {
	return probe.Transfer{Instance: admission.Instance{Namespace: admission.Namespace{Device: 69, Inode: 171}, PID: 171, Generation: 1}, Process: fragment.Process{PID: 171}, Endpoint: 9, Stamp: stamp, Measured: true, Direction: fragment.Sent, Length: 4, Payload: []byte("data"), At: time.Unix(100, int64(stamp))}
}

// Existing capture characterization, not red-first T2 evidence. TryLock is
// executed INSIDE each reached callback with no other concurrent capture
// caller, so it decides the actual lock position without a timing guess.
func TestP3T9FragmentCallbackOutsideCaptureMutex(t *testing.T) {
	var s *Session
	called := 0
	sink := p3t9Sink{fragment: func(r fragment.Record) {
		called++
		if string(r.Payload) != "data" {
			t.Error("useful fragment missing")
		}
		if !s.mutex.TryLock() {
			t.Error("fragment callback holds the capture mutex")
			return
		}
		s.mutex.Unlock()
	}}
	s = Recording(sink, sink)
	s.Transfer(p3t9Transfer(1))
	if called != 1 || s.Stats().Records != 1 {
		t.Fatalf("fragment callback not reached successfully: calls %d stats %+v", called, s.Stats())
	}
}

func TestP3T9InterruptionRetirementInsideCaptureMutex(t *testing.T) {
	for _, gap := range []bool{false, true} {
		name := "ordinary_close_outside_control"
		if gap {
			name = "interruption_under_lock"
		}
		t.Run(name, func(t *testing.T) {
			var s *Session
			called := 0
			sink := p3t9Sink{retirement: func(r connection.Record) {
				called++
				want := connection.HandleReleasedEnding
				if gap {
					want = connection.EndingUnobserved
				}
				if r.How != want || !r.Fragments.Known || r.Fragments.Value != 1 {
					t.Errorf("wrong retirement reached: %+v", r)
				}
				unlocked := s.mutex.TryLock()
				if unlocked {
					s.mutex.Unlock()
				}
				if unlocked == gap {
					t.Errorf("callback mutex available=%v; interruption=%v", unlocked, gap)
				}
			}}
			s = Recording(sink, sink)
			first := p3t9Transfer(1)
			s.Transfer(first)
			if s.Stats().Records != 1 {
				t.Fatal("capture did not precede retirement")
			}
			if gap {
				s.Transfer(p3t9Transfer(3))
				if s.Stats().Lost != 1 || s.Stats().Interrupted != 1 {
					t.Fatalf("injected missing stamp did not retire pending stream: %+v", s.Stats())
				}
			} else {
				s.Closed(probe.Connection{Instance: first.Instance, Process: first.Process, Endpoint: first.Endpoint, Stamp: 2, At: time.Unix(101, 0)})
				if s.Stats().Closed != 1 || s.Stats().Lost != 0 {
					t.Fatalf("lossless close control failed: %+v", s.Stats())
				}
			}
			if called != 1 {
				t.Fatalf("retirement callback reached %d times", called)
			}
		})
	}
}
