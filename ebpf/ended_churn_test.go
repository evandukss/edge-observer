package ebpf

import (
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
)

// Executions recorded and ended one after another, each new, leave the maps
// keyed by them empty and rebuilt, rather than holding what their deletions
// left behind.
func TestEndedExecutionsAreShedFromTheMapsKeyedByThem(t *testing.T) {
	const executions = 1000
	s := &Session{}
	for i := 0; i < executions; i++ {
		one := admission.Selection{Instance: admission.Instance{
			Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: int32(1000 + i), Generation: admission.Generation(i + 1)}}
		key := keyOf(one.Instance)
		s.recorded(one)
		s.see(key, admission.Determinate(admission.BootTicks(i)))
		s.held.Lock()
		if s.namedBy == nil {
			s.namedBy = make(map[instanceKey][]admission.Provenance)
		}
		s.namedBy[key] = []admission.Provenance{{Target: "t"}}
		s.held.Unlock()
		s.forgetEnded(key, "exited", time.Time{})
	}
	if total := s.EndedCounts(); len(total) != 1 || total[0].Count != executions {
		t.Fatalf("wiring, not the property: %v ended, want %d", total, executions)
	}
	if len(s.index) != 0 || len(s.seen) != 0 || len(s.namedBy) != 0 || len(s.inventory) != 0 {
		t.Errorf("after %d executions ended the session holds index %d, seen %d, named by %d, inventory %d",
			executions, len(s.index), len(s.seen), len(s.namedBy), len(s.inventory))
	}
	for name, rebuilds := range map[string]int{"index": s.indexChurn.Rebuilds(), "seen": s.seenChurn.Rebuilds(),
		"named by": s.namedByChurn.Rebuilds()} {
		if rebuilds == 0 {
			t.Errorf("%s was never rebuilt after %d executions ended", name, executions)
		}
	}
}
