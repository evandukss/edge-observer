package probe

import (
	"fmt"
	"slices"
	"sync"

	"github.com/evandukss/edge-observer/admission"
)

// Validate checks a returned batch before it is exposed as active. A rejected
// batch still belongs to its producer and must be retracted in full.
func (a Added) Validate() error {
	keys := make(map[admission.Key]bool, len(a.Selections))
	pids := make(map[int32]bool, len(a.Selections))
	for _, one := range a.Selections {
		key := one.Instance.Key()
		if keys[key] || pids[one.ObserverPID] {
			return fmt.Errorf("admission batch repeats a key or observer pid %d", one.ObserverPID)
		}
		keys[key] = true
		pids[one.ObserverPID] = true
		if len(a.Scopes) > 0 && a.Scopes[key] == nil {
			return fmt.Errorf("admission batch has no allocator scope for pid %d", one.ObserverPID)
		}
	}
	for key, scope := range a.Scopes {
		if !keys[key] || scope == nil {
			return fmt.Errorf("admission batch carries an unmatched or nil allocator scope")
		}
	}
	if len(a.Scopes) > 0 && a.Retract == nil {
		return fmt.Errorf("scoped admission batch has no retraction receipt")
	}
	return nil
}

// BindRetraction restricts an owner-bound operation to the original selections.
// Unknown identities are ignored; duplicate and repeated requests retract an
// original selection at most once. The original values, not caller-supplied
// provenance, reach the owner. No owner call holds the receipt mutex.
func BindRetraction(original []admission.Selection, retract func([]admission.Selection)) func([]admission.Selection) {
	pending := slices.Clone(original)
	for i := range pending {
		pending[i].AlsoNamedBy = slices.Clone(pending[i].AlsoNamedBy)
	}
	var mutex sync.Mutex
	return func(requested []admission.Selection) {
		mutex.Lock()
		var take, keep []admission.Selection
		for _, one := range pending {
			if slices.ContainsFunc(requested, func(asked admission.Selection) bool {
				return asked.ObserverPID == one.ObserverPID && asked.Instance.Same(one.Instance) && asked.Instance.Start == one.Instance.Start
			}) {
				take = append(take, one)
			} else {
				keep = append(keep, one)
			}
		}
		pending = keep
		mutex.Unlock()
		if len(take) > 0 {
			retract(take)
		}
	}
}
