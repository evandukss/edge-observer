package processing_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contentcoding"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/internal/workload"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

func TestIndependentP4WorkerJoinObservesCallerDeadline(t *testing.T) {
	for _, held := range []bool{false, true} {
		name := "free"
		if held {
			name = "held"
		}
		t.Run(name, func(t *testing.T) {
			reached, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			out := &lines{}
			run, store := startRun(t, rulesPlan(t, ""), runOptions{workers: 1, output: out,
				taken: func(int, fragment.Process, fragment.ConnectionID) {
					once.Do(func() { close(reached) })
					if held {
						<-release
					}
				}})
			t.Cleanup(func() { close(release) })
			w := generate(t, workload.Shape{Connections: 1, Exchanges: 1, Seed: 44})
			feed(t, run, store, w)
			select {
			case <-reached:
			case <-time.After(time.Second):
				t.Fatal("wiring: actual worker did not take the routed input")
			}
			if held && store.Stats().Leased == 0 {
				t.Fatal("wiring: held worker owns no charged intake")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := run.FinishStages(ctx, processing.Finalization{Withdrawn: true, Drained: true}, nil)
				done <- err
			}()
			select {
			case err := <-done:
				if held {
					if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "processing workers") {
						t.Errorf("held worker outcome omitted deadline/stage: %v", err)
					}
					if len(out.all()) != 0 {
						t.Error("held worker published output")
					}
				} else if err != nil || len(out.all()) != 2 {
					t.Errorf("free worker control: err=%v records=%d want 2", err, len(out.all()))
				}
			case <-time.After(time.Second):
				t.Fatal("FinishStages waited on held worker beyond caller deadline")
			}
		})
	}
}

type it4ReleaseTap struct {
	writer   *processing.Writer
	accepted chan processing.Approved
}

func (o *it4ReleaseTap) WriteApproved(ctx context.Context, line processing.Approved) error {
	if err := o.writer.WriteApproved(ctx, line); err != nil {
		return err
	}
	o.accepted <- line
	return nil
}

// This reads the unfrozen Run after the held owner returns. Account snapshots
// alone cannot expose a late id or authorization hidden behind FreezeSnapshot.
func TestIndependentP4ReleaseCutoff(t *testing.T) {
	for _, stage := range []string{"decode-before-id", "authorization"} {
		for _, cutoff := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cutoff=%t", stage, cutoff), func(t *testing.T) {
				reached, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unhold := sync.OnceFunc(func() { close(release) })
				var armed atomic.Bool
				hold := func() { once.Do(func() { close(reached) }); <-release }
				writer, err := processing.OpenWriter(processing.WriterOptions{Directory: t.TempDir()})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = writer.Close() }()
				tap := &it4ReleaseTap{writer: writer, accepted: make(chan processing.Approved, 16)}
				run, store := startRun(t, rulesPlan(t, ""), runOptions{workers: 1, output: tap,
					gate: func(store *intake.Store) *probe.DeliveryGate {
						gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 100, IntakeExhausted: store.Exhausted(), BeforeAuthorize: func() {
							if stage == "authorization" && armed.Load() {
								hold()
							}
						}})
						if err != nil {
							t.Fatal(err)
						}
						return gate
					}, decoder: func(list contentcoding.List, encoded []byte, options contentcoding.Options) contentcoding.Result {
						if stage == "decode-before-id" && armed.Load() {
							hold()
						}
						return contentcoding.Decode(list, encoded, options)
					}})
				// Release before startRun's cleanup joins the worker, including on a guard failure.
				t.Cleanup(unhold)
				feedPair := func(id fragment.ConnectionID) {
					t.Helper()
					c := converse(t, id, codedGet("/independent"), read(codedResponse("gzip", gzipOf(t, "decidable body"))))
					for _, f := range c.fragments {
						if err := store.Write(f); err != nil {
							t.Fatal(err)
						}
					}
					if err := store.Connection(c.retirement); err != nil {
						t.Fatal(err)
					}
					run.Route()
				}
				feedPair(1)
				var reusable processing.Approved
				for range 2 {
					select {
					case reusable = <-tap.accepted:
					case <-time.After(time.Second):
						t.Fatal("wiring: nonzero free output control did not enqueue")
					}
				}
				armed.Store(true)
				feedPair(2)
				select {
				case <-reached:
				case <-time.After(time.Second):
					t.Fatal("wiring: actual release owner not held")
				}
				before := run.Snapshot()
				wantIDs := uint64(1)
				if stage == "authorization" {
					wantIDs = 2
				}
				if before.ExchangeIDs != wantIDs {
					t.Fatalf("wiring: hold reached wrong id boundary: %+v", before)
				}
				if cutoff {
					closed := make(chan struct{})
					go func() { run.CloseAdmission(); close(closed) }()
					select {
					case <-closed:
					case <-time.After(time.Second):
						t.Fatal("release cutoff waited on held owner")
					}
				}
				unhold()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				outcome, finishErr := run.Finish(ctx, settled)
				if errors.Is(finishErr, context.DeadlineExceeded) {
					t.Fatalf("wiring: released worker did not finish: %v", finishErr)
				}
				if cutoff {
					if outcome.ExchangeIDs != before.ExchangeIDs {
						t.Errorf("exchange id issued after cutoff: before=%d after=%d", before.ExchangeIDs, outcome.ExchangeIDs)
					}
					if len(tap.accepted) != 0 || outcome.Authorized != 2 {
						t.Errorf("late authorization/enqueue after cutoff: queued=%d outcome=%+v", len(tap.accepted), outcome)
					}
				} else if finishErr != nil || outcome.ExchangeIDs != 2 || outcome.Authorized != 4 || len(tap.accepted) != 2 {
					t.Errorf("released free control: err=%v queued=%d outcome=%+v", finishErr, len(tap.accepted), outcome)
				}
				// A genuine previously approved value proves the writer's own enqueue
				// closure, independently of the worker's authorization decision.
				writer.CloseAdmission()
				if err := writer.WriteApproved(context.Background(), reusable); !errors.Is(err, processing.ErrOutputClosed) {
					t.Errorf("writer accepted approved enqueue after closure: %v", err)
				}
			})
		}
	}
}
