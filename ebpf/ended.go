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
	s.forgetEnded(key, event.Generation, "the program reported its last thread's exit", event.At)
}

// forgetEnded retires only the admission named by the observation. A queued
// end or an earlier Grants snapshot cannot retire a successor under the key.
// Generation zero names no admission and retires nothing.
func (s *Session) forgetEnded(key instanceKey, generation admission.Generation, evidence string, at time.Time) {
	s.held.Lock()
	ended := s.retireLocked(key, generation, evidence, at)
	s.held.Unlock()
	s.tellEnded(ended)
}

func (s *Session) retireLocked(key instanceKey, generation admission.Generation, evidence string, at time.Time) *probe.Ended {
	one, removed := s.removeRecordedLocked(key, generation)
	if !removed {
		return nil
	}
	if s.endedBy == nil {
		s.endedBy = make(map[endedTarget]int)
	}
	s.endedBy[endedTarget{name: one.Provenance.Target, number: one.Provenance.Number}]++
	return &probe.Ended{Selection: one, Evidence: evidence, At: at}
}

// removeRecordedLocked removes one generation without interpreting why it
// ended. Retraction therefore does not turn a rolled-back grant into coverage.
func (s *Session) removeRecordedLocked(key instanceKey, generation admission.Generation) (admission.Selection, bool) {
	i, recorded := s.index[key]
	if !recorded || generation == 0 || s.inventory[i].Instance.Generation != generation {
		return admission.Selection{}, false
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
	s.namedBy = held.Deleted(s.namedBy, key, &s.namedByChurn)
	s.accepted = slices.DeleteFunc(s.accepted, func(granted admission.Selection) bool {
		return granted.Instance.Same(one.Instance)
	})
	return one, true
}

func (s *Session) tellEnded(ended *probe.Ended) {
	if ended != nil && s.endedTo != nil {
		s.endedTo(*ended)
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
