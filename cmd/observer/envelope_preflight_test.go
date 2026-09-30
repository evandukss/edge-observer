package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"

	protected "github.com/evandukss/edge-observer/activation"
	"github.com/evandukss/edge-observer/preflight"
	"github.com/evandukss/edge-observer/process"
)

// The preflight command's envelope is start's check on the same process and
// the same selection: condition for condition, what activation.Envelope says
// when asked directly about the processes preflight selected. Whatever this
// host's cgroup is, the two agree.
func TestPreflightJudgesTheEnvelopeWithStartsOwnCheck(t *testing.T) {
	pid, path := sleeping(t, false)

	var out bytes.Buffer
	_ = run([]string{"preflight", path}, &out)
	var readiness preflight.Readiness
	if err := json.Unmarshal(out.Bytes(), &readiness); err != nil {
		t.Fatalf("wiring, not the property: preflight printed no readiness: %v\n%s", err, out.String())
	}
	// The selection as preflight made it, in its order: every process the
	// configuration matches, which may be more than this test's sleeper.
	table, err := process.Read(procfs)
	if err != nil {
		t.Fatalf("read the processes: %v", err)
	}
	var selected []process.Process
	for _, r := range readiness.Requirements {
		if r.Name != preflight.TLSLibrary || r.PID == 0 {
			continue
		}
		p, found := table.Lookup(r.PID)
		if !found {
			t.Fatalf("pid %d, which preflight judged, is not in the process table", r.PID)
		}
		selected = append(selected, p)
	}
	if !slices.ContainsFunc(selected, func(p process.Process) bool { return p.PID == pid }) {
		t.Fatalf("wiring, not the property: the sleeper, pid %d, was not selected: %+v", pid, readiness.Requirements)
	}
	direct := protected.Envelope(selected)
	if len(direct) == 0 {
		t.Fatalf("start's check judged no condition at all, so there is nothing to compare")
	}

	if len(readiness.Envelope) != len(direct) {
		t.Fatalf("preflight judged %d conditions and start's check %d: %+v against %+v",
			len(readiness.Envelope), len(direct), readiness.Envelope, direct)
	}
	for i, r := range readiness.Envelope {
		want := preflight.Met
		switch {
		case direct[i].Met:
		case direct[i].Unreadable:
			want = preflight.Indeterminate
		default:
			want = preflight.Missing
		}
		if r.Check != string(direct[i].Check) || r.Status != want || r.PID != direct[i].PID {
			t.Errorf("condition %d: preflight (%s, %s, pid %d), start's check (%s, %s, pid %d)",
				i, r.Check, r.Status, r.PID, direct[i].Check, want, direct[i].PID)
		}
	}
}
