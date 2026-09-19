package ebpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/probe"
)

// Admit adds grants to an attached session: the kernel half of a reload, for
// processes whose libraries the probes already cover.
//
// Every entry is decided before any is written (denied by an exclusion, an
// unenumerated namespace, a reused number, no start identity), and one that
// cannot be taken refuses the whole set with its reason. Writes then happen one
// at a time, and a failure takes back the earlier ones. There is no single
// instant at which every probe path sees the whole set; that would need a
// policy generation checked by every probe path. Existing grants are untouched.
//
// An already-recorded instance is skipped and returned: its grant is still
// held, or it ended at an exec, whose new image only a restart approves. No
// sockets are seeded for processes admitted here (the program's allocator is
// live), so they lose withdrawal across no-I/O calls for descriptors they
// already held, not the ability to bind (seedSockets).
func (s *Session) Admit(who []admission.Selection) ([]admission.Selection, []probe.Skip, error) {
	allowed := s.collection.Maps["allowed_processes"]
	if allowed == nil {
		return nil, nil, fmt.Errorf("%w: the program has no allowlist map", ErrUnavailable)
	}

	type prepared struct {
		key     instanceKey
		value   admissionValue
		granted admission.Selection
	}
	var (
		ready   []prepared
		skipped []probe.Skip
		refused []error
		offered = make(map[instanceKey]bool, len(who))
	)
	for _, one := range who {
		key := keyOf(one.Instance)
		s.held.Lock()
		_, recorded := s.index[key]
		s.held.Unlock()
		switch {
		case recorded:
			skipped = append(skipped, probe.Skip{Selection: one, Why: fmt.Sprintf(
				"this session already recorded pid %d: its grant is still held, or it ended at an exec "+
					"and only a restart approves the image it became", one.ObserverPID)})
			continue
		case offered[key]:
			skipped = append(skipped, probe.Skip{Selection: one, Why: "offered twice in one reload"})
			continue
		case s.denied[key]:
			refused = append(refused, fmt.Errorf("%s: pid %d in %s is denied by an exclusion, and a target "+
				"naming it does not override that", ExcludedBySubtree, one.Instance.PID, one.Instance.Namespace))
			continue
		case !s.resolvable(one.Instance.Namespace):
			refused = append(refused, fmt.Errorf("%s: pid %d is in %s, which this session did not enumerate "+
				"when it attached, so a restart is what can observe it", NamespaceUnenumerated,
				one.Instance.PID, one.Instance.Namespace))
			continue
		}
		if reason, err := s.confirm(one); err != nil {
			refused = append(refused, fmt.Errorf("%s: %w", reason, err))
			continue
		}
		offered[key] = true
		granted := one
		granted.Propagation = admission.CanPropagate
		ready = append(ready, prepared{key: key, granted: granted})
	}
	if len(refused) > 0 {
		return nil, skipped, fmt.Errorf("%w: %w", ErrNotAuthorised, errors.Join(refused...))
	}

	for i := range ready {
		s.generations++
		ready[i].granted.Instance.Generation = s.generations
		value, err := encode(ready[i].granted, s.threadsOf(ready[i].granted.ObserverPID))
		if err != nil {
			return nil, skipped, fmt.Errorf("%w: %v", ErrNotAuthorised, err)
		}
		ready[i].value = value
	}

	written := make([]instanceKey, 0, len(ready))
	for _, one := range ready {
		// NoExist, so a grant the fork hook wrote meanwhile is not overwritten; the
		// instance is then already this session's and the reload is taken back.
		if err := allowed.Update(one.key, one.value, ebpf.UpdateNoExist); err != nil {
			for _, back := range written {
				_ = allowed.Delete(back)
			}
			return nil, skipped, fmt.Errorf("%w: admit pid %d: %v; nothing this reload wrote is in force",
				ErrUnavailable, one.granted.ObserverPID, err)
		}
		written = append(written, one.key)
	}

	granted := make([]admission.Selection, 0, len(ready))
	for _, one := range ready {
		s.accepted = append(s.accepted, one.granted)
		s.recorded(one.granted)
		if s.namedBy == nil {
			s.namedBy = make(map[instanceKey][]admission.Provenance)
		}
		s.namedBy[one.key] = one.granted.NamedBy()
		granted = append(granted, one.granted)
	}
	return granted, skipped, nil
}

// Retract takes back grants Admit wrote when a later part of the same reload
// is refused. They were never in force as policy, so the inventory keeps no
// trace of them (a gone grant there would read as ended coverage).
func (s *Session) Retract(granted []admission.Selection) {
	allowed := s.collection.Maps["allowed_processes"]
	taken := make(map[instanceKey]bool, len(granted))
	for _, one := range granted {
		key := keyOf(one.Instance)
		taken[key] = true
		if allowed != nil {
			_ = allowed.Delete(key)
		}
		delete(s.namedBy, key)
	}
	kept := s.accepted[:0]
	for _, one := range s.accepted {
		if !taken[keyOf(one.Instance)] {
			kept = append(kept, one)
		}
	}
	s.accepted = kept

	s.held.Lock()
	defer s.held.Unlock()
	inventory := s.inventory[:0]
	for _, one := range s.inventory {
		if !taken[keyOf(one.Instance)] {
			inventory = append(inventory, one)
		}
	}
	s.inventory = inventory
	s.index = make(map[instanceKey]int, len(s.inventory))
	for i, one := range s.inventory {
		s.index[keyOf(one.Instance)] = i
	}
}
