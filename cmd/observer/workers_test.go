package main

import (
	"io"
	"sync"
	"testing"

	"github.com/evandukss/edge-observer/fragment"
)

// In a running session, limits.workers is the number of workers that take
// entries, and every entry of a connection reaches the same one.
func TestLimitsWorkersIsTheNumberOfWorkers(t *testing.T) {
	for _, n := range []int{1, 3} {
		t.Run(map[int]string{1: "one worker", 3: "three workers"}[n], func(t *testing.T) {
			var mutex sync.Mutex
			holders := map[fragment.ConnectionID]map[int]bool{}
			workers := map[int]bool{}
			f := processingControllerWith(t, controllerSetup{workers: n, events: 1000,
				taken: func(worker int, _ fragment.Process, id fragment.ConnectionID) {
					mutex.Lock()
					defer mutex.Unlock()
					if holders[id] == nil {
						holders[id] = map[int]bool{}
					}
					holders[id][worker] = true
					workers[worker] = true
				}})
			if f.d.policy.Settings.Workers != n {
				t.Fatalf("wiring, not the property: the configuration read %d workers, want %d", f.d.policy.Settings.Workers, n)
			}
			const connections = 60
			for c := range connections {
				endpoint := uint64(100 + c)
				f.transfer(t, endpoint, fragment.Sent, "GET /c HTTP/1.1\r\n\r\n")
				f.transfer(t, endpoint, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
				f.closed(t, endpoint)
			}
			f.halt(t)
			if err := f.finish(&logger{out: io.Discard}); err != nil {
				t.Fatal(err)
			}
			mutex.Lock()
			defer mutex.Unlock()
			if len(holders) != connections {
				t.Fatalf("wiring, not the property: workers took entries of %d connections, want %d", len(holders), connections)
			}
			if got := f.d.output.Stats().Written; got != 2*connections {
				t.Errorf("%d records written, want %d", got, 2*connections)
			}
			for worker := range workers {
				if worker < 0 || worker >= n {
					t.Errorf("worker %d took entries with limits.workers %d", worker, n)
				}
			}
			if len(workers) != n {
				t.Errorf("%d workers took entries with limits.workers %d", len(workers), n)
			}
			for id, held := range holders {
				if len(held) != 1 {
					t.Errorf("connection %d reached %d workers", id, len(held))
				}
			}
		})
	}
}
