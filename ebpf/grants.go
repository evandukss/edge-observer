package ebpf

import (
	"fmt"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// The proof status of MinimumKernel, as evidence rather than a claim about the
// kernel, naming the run that would settle it.
const (
	// FloorProved is whether the shipped programs have been loaded, placed and run
	// on a kernel at MinimumKernel. They have not; a successful capture on a newer
	// kernel says nothing about this.
	FloorProved = false

	// FloorEstablished is what IS known about the floor, and how.
	FloorEstablished = "what the shipped object needs: its atomic add-and-fetch instructions are read " +
		"out of the object itself, and the verifier refuses them below 5.12"

	// FloorWouldEstablish is the one run that would settle it.
	FloorWouldEstablish = "one run on a 5.15 amd64 host with no tracefs mounted: load the artifact and " +
		"keep the verifier's answer, place every probe before the capability drop, and put traffic " +
		"through an approved process afterwards"
)

// Grants is every admission this session recorded, each with its grant state
// in the kernel's allowlist now. An unreadable allowlist leaves every grant
// unknown with the reason, never a shorter list. Each grant found absent has
// its execution read once (process.Inspect, through inspect), and that
// reading's interval travels with it as evidence; what is reported is coverage.
// Cost: one allowlist reading plus one bounded inspection per absent grant (at
// most 64 operations, usually about seven). Frequent calls over many
// short-lived descendants could matter; that is not measured.
func (s *Session) Grants() []probe.Grant {
	held, err := s.holding()
	return grantsOf(s.Inventory(), held, err, time.Now(), s.inspect)
}

// holding is the generation of every grant the allowlist holds now, by key.
// Denials occupy keys too and are not grants, so they are left out.
func (s *Session) holding() (map[instanceKey]admission.Generation, error) {
	allowed := s.collection.Maps["allowed_processes"]
	if allowed == nil {
		return nil, fmt.Errorf("%w: the program has no allowlist map", ErrUnavailable)
	}
	var (
		key   instanceKey
		value admissionValue
	)
	held := make(map[instanceKey]admission.Generation)
	entries := allowed.Iterate()
	for entries.Next(&key, &value) {
		if value.Kind != denied {
			held[key] = admission.Generation(value.Generation)
		}
	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("%w: read the allowlist back: %v", ErrUnavailable, err)
	}
	return held, nil
}

// grantsOf decides each recorded admission's grant state from one allowlist
// reading; the reading and the execution reader are arguments, so no kernel is
// needed. A grant is held only under its own generation: a successor holding
// the key has its own, so presence alone would report the predecessor covered.
// An admission without a generation is unknown wherever its key is held.
func grantsOf(recorded []admission.Selection, held map[instanceKey]admission.Generation, err error,
	at time.Time, inspect func(admission.Selection) process.Execution) []probe.Grant {
	grants := make([]probe.Grant, 0, len(recorded))
	for _, one := range recorded {
		grant := probe.Grant{Selection: one, Read: at}
		generation, present := held[keyOf(one.Instance)]
		switch {
		case err != nil:
			grant.State, grant.Why = probe.GrantUnknown, "the allowlist could not be read: "+err.Error()
		case present && one.Instance.Generation == 0:
			grant.State = probe.GrantUnknown
			grant.Why = "the admission was recorded with no generation, so the grant under its key " +
				"cannot be told from a successor's"
		case present && generation == one.Instance.Generation:
			grant.State = probe.GrantHeld
		default:
			grant.State = probe.GrantAbsent
			grant.Evidence = inspect(one).Observed
		}
		grants = append(grants, grant)
	}
	return grants
}
