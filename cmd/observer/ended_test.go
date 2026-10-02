package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/probe"
)

// Processes are admitted and end, at a live population of one. The account's
// processes return to the live one with the ended ones counted beside them, and
// each end is written to the operational log once, with its identity: the only
// record of which process it was.
func TestChurnedProcessesLeaveTheAccountHoldingOnlyTheLiveOnes(t *testing.T) {
	const processes = 500
	path := filepath.Join(t.TempDir(), "observer.log")
	log, err := openLog(policy.Settings{Log: path}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	namespace := admission.Namespace{Device: 3, Inode: 4}
	d := &daemon{session: "0123456789abcdef", log: log}
	ends := &endings{}
	ends.serve(d)
	d.plan.Processes = []attachment.Observed{{PID: 1, StartTime: 11, Namespace: namespace}}
	for i := 0; i < processes; i++ {
		pid := int32(100 + i)
		d.planMutex.Lock()
		d.plan.Processes = append(d.plan.Processes, attachment.Observed{PID: pid, StartTime: uint64(1000 + i),
			Namespace: namespace})
		d.planMutex.Unlock()
		ends.told(probe.Ended{Selection: admission.Selection{
			Instance: admission.Instance{Namespace: namespace, PID: pid, Start: admission.Determinate(admission.BootTicks(1000 + i)),
				Generation: admission.Generation(i + 1)},
			ObserverPID: pid, Provenance: admission.Provenance{Target: "churned", Number: 1},
		}, Evidence: "the program reported its last thread's exit", At: time.Unix(int64(i), 0)})
	}
	stores, err := d.Retained()
	if err != nil {
		t.Fatal(err)
	}
	for _, one := range stores {
		if one.Store == "observer.plan_processes" && one.Held != 1 {
			t.Errorf("the account holds %d processes after %d came and went, want the live one", one.Held, processes)
		}
	}
	d.planMutex.Lock()
	listed, ended := d.plan.Processes, d.plan.ProcessesEnded
	d.planMutex.Unlock()
	if ended != processes || len(listed) != 1 || listed[0].PID != 1 {
		t.Fatalf("the account lists %d processes with %d ended, want the live one and %d ended", len(listed),
			ended, processes)
	}

	if err := log.close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int32]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var record struct {
			Record    string            `json:"record"`
			Session   string            `json:"session"`
			Admission account.Admission `json:"admission"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("a log line is not a record: %q: %v", line, err)
		}
		if record.Record != "execution-ended" || record.Session != d.session {
			t.Fatalf("an unexpected log record: %q", line)
		}
		seen[record.Admission.Instance.PID]++
		if record.Admission.Instance.Start == nil || record.Admission.Target != "churned" || record.Admission.Why == "" {
			t.Errorf("an end was logged without its identity, target or evidence: %q", line)
		}
	}
	if len(seen) != processes {
		t.Fatalf("%d processes' ends were logged, want %d", len(seen), processes)
	}
	for pid, count := range seen {
		if count != 1 {
			t.Errorf("pid %d's end was logged %d times, want once", pid, count)
		}
	}
}
