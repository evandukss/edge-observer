package ebpf

import (
	"slices"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/probe"
)

// endedTarget is the target an ended admission is counted under, as an account
// names it: the configured name, and the number where the name is empty.
type endedTarget struct {
	name   string
	number int
}

// endedAt lets go of the admission an execution-end event names: the program
// reports an execution's end once its last thread has exited, after the
// endings of its connections.
func (s *Session) endedAt(event Event) {
	key := instanceKey{
		NamespaceDevice: event.Namespace.Device,
		NamespaceInode:  event.Namespace.Inode,
		PID:             uint32(event.NamespacePID),
	}
	s.forgetEnded(key, "the program reported its last thread's exit", event.At)
}

// forgetEnded lets go of everything this session recorded for the instance at
// key, whose execution is established as ended: its inventory record, its
// grant's provenance and its start identity. It is counted under its target and
// told once to whoever asked (Options.Ended); a key holding nothing, or one
// already let go of, does nothing.
func (s *Session) forgetEnded(key instanceKey, evidence string, at time.Time) {
	s.held.Lock()
	i, recorded := s.index[key]
	if !recorded {
		s.held.Unlock()
		return
	}
	one := s.inventory[i]
	last := len(s.inventory) - 1
	if i != last {
		moved := s.inventory[last]
		s.inventory[i] = moved
		s.index[keyOf(moved.Instance)] = i
	}
	s.inventory[last] = admission.Selection{}
	s.inventory = s.inventory[:last]
	s.index = held.Deleted(s.index, key, &s.indexChurn)
	s.seen = held.Deleted(s.seen, key, &s.seenChurn)
	s.namedBy = held.Deleted(s.namedBy, key, &s.namedByChurn)
	s.accepted = slices.DeleteFunc(s.accepted, func(granted admission.Selection) bool {
		return keyOf(granted.Instance) == key
	})
	if s.endedBy == nil {
		s.endedBy = make(map[endedTarget]int)
	}
	s.endedBy[endedTarget{name: one.Provenance.Target, number: one.Provenance.Number}]++
	told := s.endedTo
	s.held.Unlock()

	if told != nil {
		told(probe.Ended{Selection: one, Evidence: evidence, At: at})
	}
}

// EndedCounts is how many recorded admissions this session has established as
// ended and let go of, by target.
func (s *Session) EndedCounts() []probe.EndedCount {
	s.held.Lock()
	defer s.held.Unlock()
	counts := make([]probe.EndedCount, 0, len(s.endedBy))
	for target, count := range s.endedBy {
		counts = append(counts, probe.EndedCount{Target: target.name, Number: target.number, Count: count})
	}
	slices.SortFunc(counts, func(x, y probe.EndedCount) int {
		if x.Number != y.Number {
			return x.Number - y.Number
		}
		if x.Target < y.Target {
			return -1
		}
		if x.Target > y.Target {
			return 1
		}
		return 0
	})
	return counts
}
