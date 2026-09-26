package capture_test

import (
	"testing"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
)

// Events the delivery gate refused take their places in the production order:
// at the seal nothing is counted lost for them and no live stream is retired,
// where the same run without those places counts every refused event lost and
// retires the stream. A gap before a refused event is still a gap.
func TestARefusedEventTakesItsPlaceInTheOrderAndIsNotALoss(t *testing.T) {
	for name, one := range map[string]struct {
		refuse    []uint64
		produced  int64
		lost      int64
		retired   int64
		unobserve bool
	}{
		"the refused places taken":           {refuse: []uint64{2, 3, 4}, produced: 4},
		"the same run, the places not taken": {produced: 4, lost: 3, retired: 1, unobserve: true},
		"a place missing before a refusal": {refuse: []uint64{3, 4}, produced: 4, lost: 1, retired: 1,
			unobserve: true},
	} {
		t.Run(name, func(t *testing.T) {
			s, sink := session(t)
			first := transfer(worker, 0xa1, fragment.Sent, 10)
			first.Stamp = 1
			s.Transfer(first)
			if len(sink.records) != 1 || s.Open() != 1 {
				t.Fatalf("wiring, not the property: %d records and %d open streams, so no live stream exists to be "+
					"retired", len(sink.records), s.Open())
			}
			for _, stamp := range one.refuse {
				s.Refused(stamp, at)
			}
			s.Finish(at, connection.Counted(one.produced))

			stats := s.Stats()
			if stats.Lost != one.lost || stats.Interrupted != one.retired {
				t.Errorf("%d observations lost and %d streams retired, want %d and %d", stats.Lost, stats.Interrupted,
					one.lost, one.retired)
			}
			records := s.Records()
			if len(records) != 1 {
				t.Fatalf("%d connection records, want the one stream's", len(records))
			}
			if unobserved := records[0].How == connection.EndingUnobserved; unobserved != one.unobserve {
				t.Errorf("the stream ended %s, want retired as unobserved: %v", records[0].How, one.unobserve)
			}
		})
	}
}
