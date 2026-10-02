package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/process"
)

// The attachment boundary is the existing reload stand-in. Process creation,
// identity checks, candidate loading, admission routing and account retention
// are real; this test makes no claim about kernel grant reclamation.
func TestIndependentReloadChurnReclaimsDeadAccountProcesses(t *testing.T) {
	first, stop := catRunning(t)
	d, attached, request := reloading(t, int32(first.Process.Pid))
	for i := 0; i < 40; i++ {
		if i > 0 {
			child, end := catRunning(t)
			stop = end
			_, _, next := reloading(t, int32(child.Process.Pid))
			content, err := os.ReadFile(d.path)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(content, &doc); err != nil {
				t.Fatal(err)
			}
			p := next.Processes[0]
			watch := doc["watch"].([]any)
			doc["watch"] = append(watch, map[string]any{"name": fmt.Sprintf("retained-%d", i), "exe": p.Executable, "args": p.Arguments[1:], "children": "none"})
			content, err = json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(d.path, content, 0600); err != nil {
				t.Fatal(err)
			}
			candidate, err := loadProcessing(d.path)
			if err != nil {
				t.Fatal(err)
			}
			next.Revision = candidate.Revision
			next.Resolution = candidate.Approval.Resolve(process.Host{Table: process.TableOf(p)})
			request = next
		}
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		r := d.reload(time.Now(), body)
		if r.Outcome != "activated" || r.Admitted != 1 || len(attached.admitted) != i+1 {
			t.Fatalf("wiring, not the property: reload %d never admitted its actual process: %+v", i, r)
		}
		rows, err := d.Retained()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, row := range rows {
			if row.Store == "observer.plan_processes" {
				found = true
				if row.Held > 1 {
					t.Errorf("account retains %d processes with one live participant after %d reloads", row.Held, i+1)
				}
			}
			if row.Store == "observer.plan_targets" && row.Held > i+2 {
				t.Errorf("target metadata exceeds current configuration: %d > %d", row.Held, i+2)
			}
		}
		if !found {
			t.Fatal("wiring, not the property: daemon process-store reading absent")
		}
		stop()
		if _, err := process.ReadExec(procfs, request.Processes[0].PID); !os.IsNotExist(err) {
			t.Fatalf("wiring, not the property: churn participant not reaped: %v", err)
		}
	}
	t.Log("PRECONDITIONS reloads=40 actual_processes=40 peak_live_participants=1 all_reaped=40 attachment_boundary=stand-in")
}
