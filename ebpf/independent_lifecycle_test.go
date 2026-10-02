//go:build attach

package ebpf_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

func TestIndependentMissingLifecycleCannotJoinDistinctConnections(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			refused := 0
			r := proofConfigured(t, nil, func(o *ebpf.Options) {
				for i := range o.Points {
					if failed && (o.Points[i].Symbol == "SSL_new" || o.Points[i].Symbol == "SSL_free") {
						o.Points[i].Path = "/independent-proof-missing-lifecycle"
						refused++
					}
				}
			})
			wantRefused := 0
			if failed {
				wantRefused = 2
			}
			if refused != wantRefused {
				t.Fatalf("UNPROVED: refused lifecycle points=%d", refused)
			}
			r.recording.Observing(r.session.Coverage().Narrow(probe.Capability{Backend: probe.BPF, Payload: true, Lifecycle: true}))
			old, _ := r.open(t, 0)
			r.command(t, "W 0 1")
			r.consume()
			r.command(t, "F 0")
			r.consume()
			out := r.command(t, fmt.Sprintf("R 0 %d", old))
			var index, attempts int
			var reused uint64
			if _, err := fmt.Sscanf(out, "R %d %d %d", &index, &reused, &attempts); err != nil || reused != old {
				t.Fatalf("UNPROVED: reuse %s", out)
			}
			select {
			case <-r.peers:
			case <-time.After(time.Second):
				t.Fatal("UNPROVED: second TLS peer absent")
			}
			r.command(t, "W 0 1")
			r.consume()
			r.finish(t)
			ids := []uint64{}
			numbers := []uint64{}
			for _, e := range r.events {
				if e.Direction == fragment.Sent && e.Length == 512 {
					ids = append(ids, e.Sequence.Occupancy)
					numbers = append(numbers, e.Sequence.Number)
				}
			}
			if len(ids) != 2 {
				t.Fatalf("UNPROVED: sent transfers=%d", len(ids))
			}
			t.Logf("PRECONDITIONS failed_lifecycle_points=%d actual_TLS_connections=2 address_reuses=1 allocation_attempts=%d occupancies=%v numbers=%v records=%d", refused, attempts, ids, numbers, len(r.collected.records))
			if len(r.session.Unprobed()) != wantRefused {
				t.Errorf("unprobed=%v want count%d", r.session.Unprobed(), wantRefused)
			}
			if failed {
				for _, id := range ids {
					if id != 0 {
						t.Errorf("COUNTEREXAMPLE: disabled lifecycle capture formed occupancy%d", id)
					}
				}
				for _, rec := range r.collected.records {
					p, _ := rec.Placement(fragment.Sent)
					if p.Whole() {
						t.Errorf("COUNTEREXAMPLE: missing lifecycle certified whole: %+v", p)
					}
				}
			} else {
				if ids[0] == 0 || ids[0] == ids[1] || len(r.collected.records) != 2 {
					t.Errorf("COUNTEREXAMPLE: full-placement control not distinct: ids=%v records=%d", ids, len(r.collected.records))
				}
				for _, rec := range r.collected.records {
					p, _ := rec.Placement(fragment.Sent)
					if !p.Whole() {
						t.Errorf("COUNTEREXAMPLE: full-placement control cut: %+v", p)
					}
				}
			}
		})
	}
}
