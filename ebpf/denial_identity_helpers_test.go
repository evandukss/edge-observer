//go:build attach

package ebpf

import (
	cilium "github.com/cilium/ebpf"
	"github.com/evandukss/edge-observer/admission"
)

// PlantStaleDenial constructs the delayed-write state, not a PID reuse event.
// Its consumer is the live fork tracepoint in the companion attach test.
func PlantStaleDenial(s *Session, instance admission.Instance) error {
	s.generations++
	return s.collection.Maps["allowed_processes"].Update(keyOf(instance), admissionValue{
		Generation: uint64(s.generations), Birth: uint64(instance.Start.Ticks),
		Kind: denied, Threads: 1, Propagate: propagateYes,
	}, cilium.UpdateNoExist)
}
