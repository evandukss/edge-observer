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
// unenumerated namespace, no start identity), and one that
// cannot be taken refuses the whole set with its reason. Writes then happen one
// at a time, and a failure takes back the earlier ones. There is no single
// instant at which every probe path sees the whole set; that would need a
// policy generation checked by every probe path. Existing grants are untouched.
//
// A reused pid with a different confirmed birth receives a fresh generation.
// An already-recorded birth is skipped and returned: its grant is still
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
		stale   *admissionValue
	}
	var (
		ready   []prepared
		skipped []probe.Skip
		refused []error
		offered = make(map[instanceKey]admission.Start, len(who))
	)
	for _, one := range who {
		key := keyOf(one.Instance)
		if reason, err := s.confirm(one); err != nil {
			refused = append(refused, fmt.Errorf("%s: %w", reason, err))
			continue
		}
		// The kernel may carry a denial inherited after attach. Its birth is
		// independent of the initial, userspace exclusion snapshot.
		var current admissionValue
		err := allowed.Lookup(key, &current)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			refused = append(refused, fmt.Errorf("%w: read pid %d: %v", ErrUnavailable, one.ObserverPID, err))
			continue
		}
		deniedHere := s.denies(one.Instance) || (err == nil && current.Kind == denied &&
			(current.Birth == 0 || birth(current.Birth) == one.Instance.Start))
		offeredStart, offeredAlready := offered[key]
		switch {
		case s.recordedBirth(one.Instance):
			skipped = append(skipped, probe.Skip{Selection: one, Why: fmt.Sprintf(
				"this session already recorded pid %d: its grant is still held, or it ended at an exec "+
					"and only a restart approves the image it became", one.ObserverPID)})
			continue
		case offeredAlready && offeredStart != one.Instance.Start:
			refused = append(refused, fmt.Errorf("%s: pid %d was offered with two births in one reload", IdentityChanged, one.ObserverPID))
			continue
		case offeredAlready:
			skipped = append(skipped, probe.Skip{Selection: one, Why: "offered twice in one reload"})
			continue
		case deniedHere:
			refused = append(refused, fmt.Errorf("%s: pid %d in %s is denied by an exclusion, and a target "+
				"naming it does not override that", ExcludedBySubtree, one.Instance.PID, one.Instance.Namespace))
			continue
		case !s.resolvable(one.Instance.Namespace):
			refused = append(refused, fmt.Errorf("%s: pid %d is in %s, which this session did not enumerate "+
				"when it attached, so a restart is what can observe it", NamespaceUnenumerated,
				one.Instance.PID, one.Instance.Namespace))
			continue
		}
		offered[key] = one.Instance.Start
		granted := one
		granted.Propagation = admission.CanPropagate
		var stale *admissionValue
		if err == nil && current.Kind == denied && current.Birth != 0 && birth(current.Birth) != one.Instance.Start {
			stale = &current
		}
		ready = append(ready, prepared{key: key, granted: granted, stale: stale})
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
		value.Target = s.targetIdentity(ready[i].granted.Provenance)
		ready[i].value = value
	}

	written := make([]instanceKey, 0, len(ready))
	for _, one := range ready {
		// NoExist, so a grant the fork hook wrote meanwhile is not overwritten; the
		// instance is then already this session's and the reload is taken back.
		err := s.retireStaleDenial(allowed, one.key, one.granted, one.stale)
		if err == nil {
			err = allowed.Update(one.key, one.value, ebpf.UpdateNoExist)
		}
		if err != nil {
			taken := make([]uint64, 0, len(written))
			var rollbackErrors []error
			for i, back := range written {
				var current admissionValue
				if allowed.Lookup(back, &current) == nil && current.Generation == ready[i].value.Generation &&
					current.Kind != denied {
					removed, retireErr := s.deleteAdmission(allowed, "admit_rollback", back, current)
					if retireErr != nil {
						rollbackErrors = append(rollbackErrors, retireErr)
					}
					if removed {
						taken = append(taken, current.Generation)
					}
				}
			}
			s.reclaimReads(taken)
			return nil, skipped, fmt.Errorf("%w: admit pid %d: %w",
				ErrUnavailable, one.granted.ObserverPID, errors.Join(err, errors.Join(rollbackErrors...)))
		}
		written = append(written, one.key)
	}

	granted := make([]admission.Selection, 0, len(ready))
	for _, one := range ready {
		s.recordAdmission(one.granted)
		granted = append(granted, one.granted)
	}
	return granted, skipped, nil
}

// retireStaleDenial removes only the known denial observed for a different
// birth. Re-read after confirming the offered process; a changed slot belongs
// to another writer and is left for UpdateNoExist to refuse.
func (s *Session) retireStaleDenial(allowed *ebpf.Map, key instanceKey, one admission.Selection, stale *admissionValue) error {
	if stale == nil {
		return nil
	}
	if _, err := s.confirm(one); err != nil {
		return err
	}
	var current admissionValue
	if err := allowed.Lookup(key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	}
	if current.Kind != denied || current.Generation != stale.Generation || current.Birth != stale.Birth {
		return nil
	}
	if _, err := s.deleteAdmission(allowed, "stale_denial", key, current); err != nil {
		return err
	}
	return nil
}

// Retract takes back grants Admit wrote when a later part of the same reload
// is refused. They were never in force as policy, so the inventory keeps no
// trace of them (a gone grant there would read as ended coverage). The process
// runs on, so its exit will not find the grant: the reads counted under it are
// reclaimed here, by the generation the entry held. Rollback consumes the
// generation-bearing selections returned by Admit; a pre-admission selection
// with generation zero names no grant and removes nothing.
func (s *Session) Retract(granted []admission.Selection) {
	allowed := s.collection.Maps["allowed_processes"]
	ended := make([]uint64, 0, len(granted))
	s.held.Lock()
	defer s.held.Unlock()
	for _, one := range granted {
		key := keyOf(one.Instance)
		if allowed != nil {
			var value admissionValue
			if allowed.Lookup(key, &value) == nil && value.Kind != denied &&
				matchesGrant(one.Instance, value) {
				// Retract's interface has no error result. Preserve that contract and
				// reclaim reads only when this exact occupant was taken.
				if removed, _ := s.deleteAdmission(allowed, "retract", key, value); removed {
					ended = append(ended, value.Generation)
				}
			}
		}
		if i, found := s.index[key]; found {
			current := s.inventory[i].Instance
			if one.Instance.Generation != 0 && one.Instance.Same(current) {
				s.removeRecordedLocked(key, current.Generation)
			}
		}
	}
	s.reclaimReads(ended)
}

func matchesGrant(one admission.Instance, value admissionValue) bool {
	return one.Generation != 0 && uint64(one.Generation) == value.Generation
}
