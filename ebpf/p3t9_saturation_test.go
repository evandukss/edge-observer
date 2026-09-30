//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
)

// Transport characterization with the real kernel ring and decoded channel.
// This does not stand in for T2's missing bounded intake or T3's worker.
func TestP3T9ChannelToRingSaturationAfterCapture(t *testing.T) {
	for _, held := range []bool{false, true} {
		name := "draining_control"
		if held {
			name = "held_consumer"
		}
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.WriteString(w, "peer-confirmed:"+r.URL.Path+":end")
			}))
			t.Cleanup(peer.Close)
			port, err := strconv.Atoi(strings.TrimPrefix(peer.URL, "https://127.0.0.1:"))
			if err != nil {
				t.Fatal(err)
			}
			actor := independentActor(t, independentLossSource(1), port)
			p := loaded(t, int32(actor.command.Process.Pid))
			s, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, p), Admit: authorise(p)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.Close() })
			command := func(code byte) {
				if _, err := fmt.Fprintf(actor.input, "%c\n", code); err != nil {
					t.Fatal(err)
				}
				actorLine(t, actor, fmt.Sprintf("%c 0\n", code))
			}
			command('P')
			// Both directions must have crossed the real probe before we stop
			// consuming. The peer count alone cannot prove capture was active.
			var request, response bool
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			for !request || !response {
				select {
				case e := <-s.Events():
					request = request || (e.Direction == fragment.Sent && strings.Contains(string(e.Payload), "GET /before-0 "))
					response = response || (e.Direction == fragment.Received && strings.Contains(string(e.Payload), "peer-confirmed:/before-0:end"))
				case <-deadline.C:
					t.Fatal("both-direction capture witness missing before saturation")
				}
			}
			if d, err := s.Dropped(); err != nil || d != 0 {
				t.Fatalf("pre-fault control lost events: %d, %v", d, err)
			}
			var burstRequests atomic.Int64
			var reader sync.WaitGroup
			consume := func() {
				reader.Add(1)
				go func() {
					defer reader.Done()
					for e := range s.Events() {
						if e.Direction == fragment.Sent && strings.Contains(string(e.Payload), "GET /burst ") {
							burstRequests.Add(1)
						}
					}
				}()
			}
			if !held {
				consume()
			}
			command('B')
			if calls.Load() != 9001 {
				t.Fatalf("application workload did not complete at peer: %d", calls.Load())
			}
			dropped, err := s.Dropped()
			if err != nil {
				t.Fatal(err)
			}
			if held {
				if cap(s.Events()) == 0 || len(s.Events()) != cap(s.Events()) {
					t.Fatalf("decoded channel did not reach capacity: %d/%d", len(s.Events()), cap(s.Events()))
				}
				if dropped <= 0 {
					t.Fatal("full decoded channel did not propagate to actual kernel reservation loss")
				}
			} else if dropped != 0 {
				t.Fatalf("freely draining control lost %d reservations", dropped)
			}
			withdrawal, err := s.StopProducing()
			if err != nil || !withdrawal.Complete || withdrawal.Instances != 1 {
				t.Fatalf("kernel withdrawal failed: %+v %v", withdrawal, err)
			}
			if held {
				consume()
			}
			drained, err := s.Drain(3 * time.Second)
			if err != nil || !drained.Complete {
				t.Fatalf("released channel failed to drain: %+v %v", drained, err)
			}
			s.StopReading()
			reader.Wait()
			if !held && burstRequests.Load() != 9000 {
				t.Fatalf("draining control delivered %d/9000 request markers", burstRequests.Load())
			}
			t.Logf("held=%v peer_exchanges=%d burst_requests_delivered=%d ring_reservation_failures=%d channel_capacity=%d", held, calls.Load(), burstRequests.Load(), dropped, cap(s.Events()))
		})
	}
}

type p3t9HeldCallbacks struct {
	retirement bool
	armed      atomic.Bool
	entered    chan connection.Ending
	release    chan struct{}
	witness    chan struct{}
	once       sync.Once
	marker     sync.Once
}

func (s *p3t9HeldCallbacks) unblock() { s.once.Do(func() { close(s.release) }) }
func (s *p3t9HeldCallbacks) Write(r fragment.Record) error {
	if strings.Contains(string(r.Payload), "peer-confirmed:/before-0:end") {
		s.marker.Do(func() { close(s.witness) })
	}
	if !s.retirement && s.armed.CompareAndSwap(true, false) {
		s.entered <- connection.EndingUnset
		<-s.release
	}
	return nil
}
func (s *p3t9HeldCallbacks) Connection(r connection.Record) error {
	if s.retirement && s.armed.CompareAndSwap(true, false) {
		s.entered <- r.How
		<-s.release
	}
	return nil
}

// Inject exactly one missing production stamp AFTER a real captured control.
// The remaining delivery is the production adapter -> capture -> callback.
// The injected gap is not described as measured kernel loss.
type p3t9GapSink struct {
	capture *capture.Session
	gap     atomic.Bool
	offset  uint64 // delivery goroutine alone owns this field
}

func (s *p3t9GapSink) Transfer(v probe.Transfer) {
	if s.gap.CompareAndSwap(true, false) {
		s.offset++
	}
	v.Stamp += s.offset
	s.capture.Transfer(v)
}
func (s *p3t9GapSink) Closed(v probe.Connection) { v.Stamp += s.offset; s.capture.Closed(v) }

func p3t9SinkWithdrawal(t *testing.T, retirement bool) {
	t.Helper()
	for _, hold := range []bool{false, true} {
		name := "free_callback_control"
		if hold {
			name = "held_callback"
		}
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int64
			peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.WriteString(w, "peer-confirmed:"+r.URL.Path+":end")
			}))
			t.Cleanup(peer.Close)
			port, err := strconv.Atoi(strings.TrimPrefix(peer.URL, "https://127.0.0.1:"))
			if err != nil {
				t.Fatal(err)
			}
			actor := independentActor(t, independentLossSource(1), port)
			p := loaded(t, int32(actor.command.Process.Pid))
			callbacks := &p3t9HeldCallbacks{retirement: retirement, entered: make(chan connection.Ending, 1), release: make(chan struct{}), witness: make(chan struct{})}
			c := capture.Recording(callbacks, callbacks)
			sink := &p3t9GapSink{capture: c}
			g, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1000})
			if err != nil {
				t.Fatal(err)
			}
			live, err := attach.NeweBPF(process.Approval{}).Attach(probe.Request{Processes: []process.Process{p}, Admit: authorise(p), DeliveryGate: g}, sink)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = live.Close() })
			t.Cleanup(callbacks.unblock)
			producer, ok := live.(connection.Producer)
			if !ok {
				t.Fatal("attachment has no kernel withdrawal boundary")
			}
			command := func(code byte) {
				if _, err := fmt.Fprintf(actor.input, "%c\n", code); err != nil {
					t.Fatal(err)
				}
				actorLine(t, actor, fmt.Sprintf("%c 0\n", code))
			}
			command('P')
			select {
			case <-callbacks.witness:
			case <-time.After(3 * time.Second):
				t.Fatal("useful response not captured before callback fault")
			}
			callbacks.armed.Store(true)
			if !hold {
				callbacks.unblock()
			}
			if retirement {
				sink.gap.Store(true)
			}
			command('H')
			select {
			case ending := <-callbacks.entered:
				if retirement && ending != connection.EndingUnobserved {
					t.Fatalf("held ordinary close instead of interruption retirement: %v", ending)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("named callback was not reached")
			}
			// This is real allowlist deletion/readback, not g.Withdrawal().
			type result struct {
				withdrawal connection.Withdrawal
				err        error
			}
			withdrawn := make(chan result, 1)
			go func() { w, err := producer.StopProducing(); withdrawn <- result{w, err} }()
			select {
			case r := <-withdrawn:
				if r.err != nil || !r.withdrawal.Complete || r.withdrawal.Instances != 1 {
					t.Fatalf("kernel authority not withdrawn: %+v %v", r.withdrawal, r.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("held callback blocked kernel withdrawal")
			}
			// The application completes another exchange with the callback still
			// held and capture authority already withdrawn.
			command('A')
			if calls.Load() != 3 {
				t.Fatalf("application failed independent peer control: %d", calls.Load())
			}
			callbacks.unblock()
			drained, err := producer.Drain(3 * time.Second)
			if err != nil || !drained.Complete {
				t.Fatalf("released callback did not drain: %+v %v", drained, err)
			}
			if c.Stats().Records < 2 {
				t.Fatal("free/released callback never completed useful capture")
			}
			if retirement && (c.Stats().Interrupted != 1 || c.Stats().Lost != 1) {
				t.Fatalf("injected retirement was not exactly one missing stamp: %+v", c.Stats())
			}
			if state := g.Snapshot(); state.Reason != "" {
				t.Fatalf("different fault decided run: %+v", state)
			}
			t.Logf("retirement=%v held=%v peer_exchanges=%d captured_records=%d", retirement, hold, calls.Load(), c.Stats().Records)
		})
	}
}

func TestP3T9FragmentSinkAndKernelWithdrawal(t *testing.T)     { p3t9SinkWithdrawal(t, false) }
func TestP3T9InterruptionSinkAndKernelWithdrawal(t *testing.T) { p3t9SinkWithdrawal(t, true) }
