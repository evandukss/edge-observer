package ebpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/evandukss/edge-observer/admission"
)

// deleteAdmission preserves the caller's guard and locks. A different occupant
// removed by the atomic take is restored without overwriting a newer write.
// Between take and restore that occupant is absent and may miss an event. If
// it exits in that gap, its restored entry can remain for the session: no later
// sweep is promised. Kernel admission authenticates birth, so that stale entry
// costs a map slot but does not admit a later process with a different birth.
//
// True means the expected birth and generation were actually removed. A missing
// key is a successful no-op. EEXIST on restore preserves the current occupant.
// Every other map error is returned; a failed restore can leave the taken
// occupant absent. Retract's existing void interface cannot return that error.
func (s *Session) deleteAdmission(allowed *ebpf.Map, operation string, key instanceKey, expected admissionValue) (bool, error) {
	identity := admission.Key{
		Namespace: admission.Namespace{Device: key.NamespaceDevice, Inode: key.NamespaceInode},
		PID:       int32(key.PID), Generation: admission.Generation(expected.Generation),
	}
	if s.beforeDeleteAdmission != nil {
		s.beforeDeleteAdmission(operation, identity)
	}
	var taken admissionValue
	if err := allowed.LookupAndDelete(key, &taken); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("%s atomic take: %w", operation, err)
	}
	matched := taken.Birth == expected.Birth && taken.Generation == expected.Generation
	if s.afterTakeAdmission != nil {
		s.afterTakeAdmission(operation, identity, matched)
	}
	if matched {
		return true, nil
	}
	if err := allowed.Update(key, taken, ebpf.UpdateNoExist); err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
		return false, fmt.Errorf("%s restore different occupant: %w", operation, err)
	}
	return false, nil
}
