package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/sink"
)

func TestStoppedDeliveryPreservesRoutingAndFrozenFacts(t *testing.T) {
	for _, constructed := range []bool{false, true} {
		t.Run(map[bool]string{false: "configured", true: "constructed"}[constructed], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "observer.log")
			var console bytes.Buffer
			var log *logger
			if constructed {
				file, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = file.Close() }()
				log = &logger{file: file, out: &console}
			} else {
				var err error
				log, err = openLog(policy.Settings{Log: path}, true, &console)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer func() { _ = log.close() }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			// No previous log write: freeze must initialize constructed destinations.
			if err := log.freeze(ctx); err != nil {
				t.Fatal(err)
			}
			before, destinations := log.queue.Stats(), log.destinationStats()
			record := stopped{Record: "stopped", Version: recordVersion, Session: "sealed-session", Sealed: true, Account: "actual-account"}
			if err := log.writeStopped(ctx, record); err != nil {
				t.Fatal(err)
			}
			if err := log.writeStopped(ctx, record); !errors.Is(err, sink.ErrClosed) {
				t.Fatalf("duplicate stopped: %v", err)
			}
			if err := log.write(state{Record: "state"}); !errors.Is(err, sink.ErrClosed) {
				t.Fatalf("ordinary admission: %v", err)
			}
			if err := log.close(); err != nil {
				t.Fatal(err)
			}
			want, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, '\n')
			file, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(file, want) || !bytes.Equal(console.Bytes(), want) {
				t.Fatalf("stopped routing: file=%q console=%q want=%q", file, console.Bytes(), want)
			}
			if log.queue.Stats() != before || !reflect.DeepEqual(log.destinationStats(), destinations) {
				t.Fatal("stopped changed sealed delivery facts")
			}
		})
	}
}

type terminalHeldWriter struct {
	entered chan struct{}
	release chan struct{}
	mutex   sync.Mutex
	calls   int
}

func (w *terminalHeldWriter) Write(p []byte) (int, error) {
	w.entered <- struct{}{}
	<-w.release
	w.mutex.Lock()
	w.calls++
	w.mutex.Unlock()
	return len(p), nil
}

func TestStoppedFreeDestinationSurvivesHeldDestination(t *testing.T) {
	held := &terminalHeldWriter{entered: make(chan struct{}, 8), release: make(chan struct{})}
	released := false
	defer func() {
		if !released {
			close(held.release)
		}
	}()
	console := &failingLogWriter{}
	q, err := sink.NewQueue(logQueueBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Register("file", &logOutput{out: held}); err != nil {
		t.Fatal(err)
	}
	if err := q.Register("stdout", &logOutput{out: console}); err != nil {
		t.Fatal(err)
	}
	log := &logger{queue: q, destinations: []string{"file", "stdout"}}
	defer func() { _ = log.close() }()
	if err := log.write(state{Record: "state"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-held.entered:
	case <-time.After(time.Second):
		t.Fatal("file write hold was not reached")
	}
	drain, cancelDrain := context.WithCancel(context.Background())
	cancelDrain()
	if err := log.freeze(drain); !errors.Is(err, context.Canceled) {
		t.Fatalf("held freeze: %v", err)
	}
	before, destinations := q.Stats(), log.destinationStats()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := log.writeStopped(ctx, stopped{Record: "stopped", Session: "terminal"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("held terminal: %v", err)
	}
	console.mutex.Lock()
	data := bytes.Clone(console.buffer.Bytes())
	console.mutex.Unlock()
	var got stopped
	if err := json.Unmarshal(data, &got); err != nil || got.Record != "stopped" || got.Session != "terminal" {
		t.Fatalf("free console lost terminal: %q %v", data, err)
	}
	close(held.release)
	released = true
	if err := log.close(); err != nil {
		t.Fatal(err)
	}
	held.mutex.Lock()
	calls := held.calls
	held.mutex.Unlock()
	if calls != 1 {
		t.Fatalf("terminal began after expired wait: %d calls", calls)
	}
	if q.Stats() != before || !reflect.DeepEqual(log.destinationStats(), destinations) {
		t.Fatal("late completion changed frozen facts")
	}
}
