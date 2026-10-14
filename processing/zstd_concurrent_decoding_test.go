package processing_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

// The CONCURRENT zstd comparison (decision 586; criterion 119 row 1a rev 53).
// Unlike the sequential record (comment 4006), capture and feed run on their
// own goroutine WHILE the Run's workers decode on theirs, so the question it
// answers is the right one: while an expensive zstd decode is in flight, does
// ordinary traffic still get captured and delivered promptly? It records each
// ordinary message's feed-to-written latency, capture progress, offered and
// completed rates, allocation and GC, the allowance (the test's setting), and
// loss and cuts. It is a RECORD with light guards: ordinary traffic is
// delivered and nothing is cut; on T12's final tip with the history limit the
// rising scenario also shows its isolated content_decoding_too_costly
// exclusions. The bodies are the same existing window sequences; no new input.

// zcLog timestamps every approved line as it is written, on whatever worker
// goroutine writes it, and matches it to a message by request target.
type zcLog struct {
	mu        sync.Mutex
	writtenAt map[string]time.Time
	exchanges int
	conns     int
}

func (l *zcLog) WriteApproved(_ context.Context, a processing.Approved) error {
	now := time.Now()
	var art processing.Artifact
	if err := json.Unmarshal(a.Bytes(), &art); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	switch art.Record {
	case processing.ArtifactExchange:
		l.exchanges++
		if art.Reconstruction != nil && len(art.Reconstruction.Exchanges) == 1 {
			if m := art.Reconstruction.Exchanges[0].Request.Message; m != nil {
				if _, seen := l.writtenAt[m.Target]; !seen {
					l.writtenAt[m.Target] = now
				}
			}
		}
	case processing.ArtifactConnection:
		l.conns++
	}
	return nil
}

// zcFeeder drives one live capture session into a store, through the gate.
type zcFeeder struct {
	t       *testing.T
	gate    *probe.DeliveryGate
	capture *capture.Session
	stamp   uint64
	sent    map[uint64]uint64
	recv    map[uint64]uint64
}

func (f *zcFeeder) transfer(handle uint64, dir fragment.Direction, payload []byte) {
	f.stamp++
	num := f.sent
	if dir == fragment.Received {
		num = f.recv
	}
	num[handle]++
	p, instance := cutLinesIdentity()
	d := f.gate.Admit(probe.DeliveryTransfer, true)
	if !d.Admitted {
		f.t.Errorf("wiring, not the property: transfer refused on handle %d: %+v", handle, d)
		return
	}
	f.capture.Transfer(probe.Transfer{Process: p, Instance: instance, Endpoint: handle, Direction: dir,
		Measured: true, Length: uint32(len(payload)), Payload: payload, Stamp: f.stamp,
		Sequence: probe.Sequence{Occupancy: handle, Number: num[handle], Born: true}, At: time.Now(), Slot: d.Slot})
	if d.Slot != nil && !d.Slot.Kept() {
		d.Slot.Refund(held.Unretained)
	}
}

func (f *zcFeeder) connection(handle uint64, target string, coding string, body []byte) {
	f.transfer(handle, fragment.Sent, []byte("GET "+target+" HTTP/1.1\r\nHost: test\r\n\r\n"))
	f.transfer(handle, fragment.Received, zrResponse(coding, body))
	f.stamp++
	p, instance := cutLinesIdentity()
	d := f.gate.Admit(probe.DeliveryClose, false)
	if !d.Admitted {
		f.t.Errorf("wiring, not the property: retirement refused on handle %d", handle)
		return
	}
	f.capture.Closed(probe.Connection{Process: p, Instance: instance, Endpoint: handle,
		Sequence: probe.Sequence{Occupancy: handle, Born: true},
		Final:    probe.Final{Known: true, Sent: probe.Terminal{Last: f.sent[handle]}, Received: probe.Terminal{Last: f.recv[handle]}},
		Stamp:    f.stamp, At: time.Now(), Slot: d.Slot})
	if d.Slot != nil && !d.Slot.Kept() {
		d.Slot.Refund(held.Unretained)
	}
}

func TestZstdConcurrentComparison(t *testing.T) {
	const ordinary, zstdN, frames, workers = 48, 48, 105, 2
	ordinaryBody := []byte(`{"event":"ordinary","value":"plain-traffic-body-that-is-not-compressed"}`)
	for _, sc := range []struct {
		name   string
		rising bool
	}{{"flat", false}, {"rising", true}} {
		t.Run(sc.name, func(t *testing.T) {
			configuration := map[string]any{"version": "observer.config/1", "output": "/var/lib/observer",
				"write_content": true, "watch": []any{map[string]any{"name": "api", "exe": "/usr/bin/php"}}}
			data, _ := json.Marshal(configuration)
			compiled, findings := config.Compile(data, "")
			if compiled == nil || len(findings) != 0 {
				t.Fatalf("wiring, not the property: configuration: %+v", findings)
			}
			store, err := intake.New(1 << 30)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = store.Close() }()
			gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			log := &zcLog{writtenAt: map[string]time.Time{}}
			run, err := processing.Start(processing.Options{Session: "zstd-concurrent", PolicyRevision: "fixture",
				Plan: compiled.Plan, Intake: store, Gate: gate, Output: log, Workers: workers, ConnectionInput: 1 << 20})
			if err != nil {
				t.Fatalf("wiring, not the property: run: %v", err)
			}
			defer func() { _ = run.Close() }()
			feeder := &zcFeeder{t: t, gate: gate, capture: capture.Recording(store, store), sent: map[uint64]uint64{}, recv: map[uint64]uint64{}}

			// A router goroutine moves captured entries to the workers while the
			// feeder is still feeding, so processing overlaps capture.
			stop := make(chan struct{})
			var routing sync.WaitGroup
			routing.Add(1)
			go func() {
				defer routing.Done()
				for {
					select {
					case <-stop:
						return
					default:
						run.Route()
						time.Sleep(200 * time.Microsecond)
					}
				}
			}()

			feedAt := map[string]time.Time{}
			var handle uint64
			offered := 0
			runtime.GC()
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			started := time.Now()
			n := max(ordinary, zstdN)
			for i := 0; i < n; i++ {
				if i < ordinary {
					handle++
					target := fmt.Sprintf("/ord/%d", i)
					feedAt[target] = time.Now()
					feeder.connection(handle, target, "", ordinaryBody)
					offered++
				}
				if i < zstdN {
					handle++
					feeder.connection(handle, fmt.Sprintf("/z/%d", i), "zstd", zrBody(frames, sc.rising))
					offered++
				}
				// Pace the feed so capture and processing genuinely overlap rather
				// than the whole workload landing before the first drain.
				time.Sleep(200 * time.Microsecond)
			}
			close(stop)
			routing.Wait()
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			feeder.capture.Finish(time.Now())
			out, err := run.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true})
			if err != nil {
				t.Fatalf("finish: %v", err)
			}
			elapsed := time.Since(started)
			runtime.ReadMemStats(&after)
			cst := feeder.capture.Stats()

			// Ordinary delivery latencies, feed to written.
			var lat []time.Duration
			ordinaryWritten := 0
			log.mu.Lock()
			for i := 0; i < ordinary; i++ {
				target := fmt.Sprintf("/ord/%d", i)
				if w, ok := log.writtenAt[target]; ok {
					ordinaryWritten++
					lat = append(lat, w.Sub(feedAt[target]))
				}
			}
			log.mu.Unlock()
			sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })
			pick := func(q float64) int64 {
				if len(lat) == 0 {
					return 0
				}
				return lat[min(len(lat)-1, int(q*float64(len(lat))))].Nanoseconds()
			}

			// GUARDS (decision 586): ordinary traffic is delivered and nothing is
			// cut. On the pre-limit tree the rising bodies decode; on T12's final
			// tip with the history limit they are excluded too_costly. Either way
			// no cut and every ordinary message delivered.
			if ordinaryWritten != ordinary {
				t.Errorf("ordinary delivery: %d of %d ordinary messages written (excluded=%+v cut=%d failures=%d)",
					ordinaryWritten, ordinary, out.Excluded, out.ConnectionsCut, out.ProcessingFailures)
			}
			if out.ConnectionsCut != 0 || out.AllowanceCut != 0 || cst.Lost != 0 || cst.Cut != 0 {
				t.Errorf("concurrent run lost or cut traffic: cut=%d allowanceCut=%d captureLost=%d captureCut=%d",
					out.ConnectionsCut, out.AllowanceCut, cst.Lost, cst.Cut)
			}
			// On T12's final tip the rising-window bodies exceed the zstd history
			// limit and are excluded content_decoding_too_costly, one per zstd
			// message, while ordinary traffic is delivered and nothing is cut. The
			// flat baseline decodes, with no exclusion (decision 586).
			switch sc.name {
			case "rising":
				if out.Excluded.ContentDecodingTooCostly != uint64(zstdN) {
					t.Errorf("rising: %d content_decoding_too_costly exclusions, want %d (one per zstd message, the history limit refusing each)", out.Excluded.ContentDecodingTooCostly, zstdN)
				}
				if out.Excluded.Total() != out.Excluded.ContentDecodingTooCostly {
					t.Errorf("rising: other exclusions beside too_costly: %+v", out.Excluded)
				}
			case "flat":
				if out.Excluded.Total() != 0 {
					t.Errorf("flat baseline excluded traffic: %+v", out.Excluded)
				}
			}

			record := map[string]any{
				"scenario":                   sc.name,
				"ordinary_messages":          ordinary,
				"zstd_messages":              zstdN,
				"zstd_rising_window":         sc.rising,
				"frames_per_zstd":            frames,
				"workers":                    workers,
				"offered_exchanges":          offered,
				"ordinary_written":           ordinaryWritten,
				"exchange_lines":             log.exchanges,
				"connection_lines":           log.conns,
				"elapsed_ns":                 elapsed.Nanoseconds(),
				"ordinary_latency_ns_min":    pick(0),
				"ordinary_latency_ns_p50":    pick(0.5),
				"ordinary_latency_ns_p90":    pick(0.9),
				"ordinary_latency_ns_max":    pick(0.999),
				"total_alloc_bytes":          after.TotalAlloc - before.TotalAlloc,
				"num_gc":                     after.NumGC - before.NumGC,
				"gc_percent":                 100,
				"capture_records":            cst.Records,
				"capture_transfers":          cst.Transfers,
				"capture_lost":               cst.Lost,
				"capture_cut":                cst.Cut,
				"capture_gate_refused":       cst.GateRefused,
				"capture_intake_refused":     cst.IntakeRefused,
				"excluded_total":             out.Excluded.Total(),
				"excluded_too_costly":        out.Excluded.ContentDecodingTooCostly,
				"excluded_too_large":         out.Excluded.ContentDecodedTooLarge,
				"connections_cut":            out.ConnectionsCut,
				"allowance_cut":              out.AllowanceCut,
				"processing_failures":        out.ProcessingFailures,
				"written_total":              out.Written,
				"allowance_bytes":            int64(1) << 30,
				"gate_max_events":            1 << 20,
				"go":                         runtime.Version(),
				"arch":                       runtime.GOARCH,
				"gomaxprocs":                 runtime.GOMAXPROCS(0),
				"commit":                     os.Getenv("ZC_COMMIT"),
				"concurrent":                 true,
				"no_forced_gc_inside_decode": true,
				"label":                      "capture and feed run concurrently with the workers; ordinary latency is feed-to-written during decoding; a record with light guards; same existing window bodies, no new input",
			}
			line, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			t.Log("ZSTD_CONCURRENT " + string(line))
		})
	}
}
