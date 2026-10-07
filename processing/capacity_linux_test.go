package processing

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	outputsink "github.com/evandukss/edge-observer/sink"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/internal/workload"
	"github.com/evandukss/edge-observer/probe"
)

var (
	capacityConnections = flag.Int("capacity-connections", 4500, "connections per processing session; zero measures session overhead")
	capacityExchanges   = flag.Int("capacity-exchanges", 1, "exchanges per connection")
	capacityHeaders     = flag.Int("capacity-headers", 49, "extra header bytes per message, beyond Host and framing")
	capacityRequest     = flag.Int("capacity-request-body", 105, "request body bytes")
	capacityResponse    = flag.Int("capacity-response-body", 138, "response body bytes")
	capacityJSON        = flag.Float64("capacity-json", 1, "fraction of nonempty bodies that are JSON")
	capacityDefects     = flag.Float64("capacity-defects", 0, "fraction of connections with a defect")
	capacitySeed        = flag.Uint64("capacity-seed", 20260930, "workload seed")
)

type capacityBuffer struct{ bytes.Buffer }

func (b *capacityBuffer) Write(_ context.Context, p []byte) (int, error) { return b.Buffer.Write(p) }
func (*capacityBuffer) Reopen(context.Context) error                     { return nil }
func (*capacityBuffer) Close(context.Context) error                      { return nil }

// BenchmarkCapacity measures repeated processing sessions, including intake
// copies, worker startup and finalization, reconstruction, gate authorization,
// serialization and the real Writer. Only its private file is replaced for the
// memory comparison. Workload generation, configuration and file creation are
// outside the timer. Each operation is one session, not one request.
func BenchmarkCapacity(b *testing.B) {
	shape := workload.Shape{Connections: *capacityConnections, Exchanges: *capacityExchanges,
		HeaderBytes: *capacityHeaders, RequestBodyBytes: *capacityRequest, ResponseBodyBytes: *capacityResponse,
		JSONShare: *capacityJSON, DefectShare: *capacityDefects, Seed: *capacitySeed}
	input := &workload.Workload{Shape: shape}
	if shape.Connections != 0 {
		var err error
		input, err = workload.Generate(shape)
		if err != nil {
			b.Fatal(err)
		}
	}
	compiled, findings := config.Compile([]byte(`{"version":"observer.config/1","output":"/tmp/capacity","watch":[{"name":"service","exe":"/usr/bin/service"}]}`), "")
	if compiled == nil || len(findings) != 0 {
		b.Fatalf("configuration: %v", findings)
	}
	for _, sink := range []string{"file", "memory"} {
		for _, workers := range []int{1, 2, 4} {
			b.Run(fmt.Sprintf("%s/workers=%d", sink, workers), func(b *testing.B) {
				capacity(b, input, compiled.Plan, sink, workers)
			})
		}
	}
}

func capacity(b *testing.B, input *workload.Workload, plan *config.ProcessingPlan, sink string, workers int) {
	b.StopTimer()
	const intakeLimit = 1 << 30
	const outputLimit = 1 << 40
	var memory capacityBuffer
	var output *Writer
	if sink == "file" {
		var err error
		output, err = Open(b.TempDir(), outputLimit)
		if err != nil {
			b.Fatal(err)
		}
	} else {
		var err error
		output, err = OpenWriter(WriterOptions{Directory: b.TempDir(), QueueBytes: outputLimit, OpenSink: func(string) outputsink.Sink { return &memory }})
		if err != nil {
			b.Fatal(err)
		}
	}
	b.Cleanup(func() {
		if err := output.Close(); err != nil {
			b.Error(err)
		}
	})
	var last Outcome
	var lastBytes int64
	// Every session drains before the next one, so neither an output backlog
	// nor unbounded intake can turn throughput into an enqueue-only figure.
	one := func() {
		memory.Reset()
		before := output.Stats()
		store, err := intake.New(intakeLimit)
		if err != nil {
			b.Fatal(err)
		}
		gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1 << 40,
			IntakeExhausted: store.Exhausted()})
		if err != nil {
			b.Fatal(err)
		}
		run, err := Start(Options{Session: "capacity", Plan: plan, PolicyRevision: "capacity", Intake: store,
			Gate: gate, Output: output, Workers: workers})
		if err != nil {
			b.Fatal(err)
		}
		for start := 0; start < len(input.Entries); start += 256 {
			chunk := workload.Workload{Entries: input.Entries[start:min(start+256, len(input.Entries))]}
			if n, err := chunk.Write(store); err != nil || n != len(chunk.Entries) {
				b.Fatalf("intake clipped after %d entries: %v", n, err)
			}
			run.Route()
		}
		o, err := run.Finish(context.Background(), Finalization{Withdrawn: true, Drained: true})
		if err != nil {
			b.Fatal(err)
		}
		if err := output.Drain(context.Background()); err != nil {
			b.Fatal(err)
		}
		o = run.Snapshot()
		s := store.Stats()
		if s.FragmentsRefused != 0 || s.ConnectionsRefused != 0 || s.Exhausted || s.Bytes != 0 || s.Queued != 0 || s.Leased != 0 || o.Pending != 0 || o.OutputFailures != 0 || o.GateReason != "" {
			b.Fatalf("refusal or undrained input: intake=%+v outcome=%+v", s, o)
		}
		if o.Batches != uint64(len(input.Connections)) || o.Authorized != o.Written {
			b.Fatalf("incomplete processing: %+v", o)
		}
		if input.Shape.DefectShare == 0 && (o.ProcessingFailures != 0 || !o.Withheld.Known || o.Withheld.Value != 0 || o.ExchangeIDs != uint64(input.Exchanges) || o.Written != uint64(input.Exchanges+len(input.Connections))) {
			b.Fatalf("processing clipped: %+v", o)
		}
		last = o
		written := output.Stats()
		lastBytes = written.Bytes - before.Bytes
		if written.Written-before.Written != o.Written || (o.Written > 0 && lastBytes <= 0) {
			b.Fatalf("writer did not receive the approved lines: %+v -> %+v; outcome=%+v", before, written, o)
		}
		if err := run.Close(); err != nil {
			b.Fatal(err)
		}
		if err := store.Close(); err != nil {
			b.Fatal(err)
		}
	}
	for range 10 {
		one()
	}
	beforeBytes := output.Stats().Bytes
	var before, after syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &before); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.StartTimer()
	start := time.Now()
	for range b.N {
		one()
	}
	elapsed := time.Since(start)
	b.StopTimer()
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &after); err != nil {
		b.Fatal(err)
	}
	s := output.Stats()
	if s.Refused != 0 {
		b.Fatalf("writer clipped: %+v", s)
	}
	if sink == "file" {
		stat, err := os.Stat(filepath.Join(output.directory, ArtifactName))
		if err != nil {
			b.Fatal(err)
		}
		if stat.Size() != s.Bytes {
			b.Fatalf("file has %d bytes, writer counted %d", stat.Size(), s.Bytes)
		}
	} else if int64(memory.Len()) != lastBytes {
		b.Fatalf("memory has %d bytes, writer counted %d", memory.Len(), lastBytes)
	}
	cpu := float64(after.Utime.Nano()+after.Stime.Nano()-before.Utime.Nano()-before.Stime.Nano()) / 1e9
	requests := float64(b.N * input.Exchanges)
	if requests > 0 {
		b.ReportMetric(requests/elapsed.Seconds(), "requests/s")
		b.ReportMetric(requests/elapsed.Seconds()/float64(workers), "requests/s/worker")
		b.ReportMetric(float64(s.Bytes-beforeBytes)/requests, "output-B/request")
	}
	b.ReportMetric(cpu/elapsed.Seconds()*100, "CPU-percent")
	b.ReportMetric(float64(after.Maxrss)/1024, "peak-RSS-MiB")
	b.ReportMetric(0, "limit-refusals")
	b.Logf("shape=%+v sent=%d issued=%d written=%d processing-refusals=%d withheld=%s entries=%d workers=%d GOMAXPROCS=%d Go=%s intake=%d output=%d elapsed=%s CPU=%.6fs pid=%d",
		input.Shape, input.Exchanges, last.ExchangeIDs, last.Written, last.ProcessingFailures, last.Withheld, len(input.Entries), workers, runtime.GOMAXPROCS(0), runtime.Version(), intakeLimit, outputLimit, elapsed, cpu, os.Getpid())
}
