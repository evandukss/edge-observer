//go:build attach

package ebpf

import (
	"github.com/cilium/ebpf"
	"github.com/evandukss/edge-observer/admission"
)

type readBarrier struct {
	Generation uint64
	State      uint32
	Padding    uint32
}

func ArmReadBarrier(s *Session, generation admission.Generation) error {
	return s.collection.Maps["read_barrier"].Update(uint32(0), readBarrier{Generation: uint64(generation), State: 1}, ebpf.UpdateAny)
}

func ReadBarrierState(s *Session) (uint32, error) {
	var value readBarrier
	err := s.collection.Maps["read_barrier"].Lookup(uint32(0), &value)
	return value.State, err
}

func ReleaseReadBarrier(s *Session) error {
	var value readBarrier
	if err := s.collection.Maps["read_barrier"].Lookup(uint32(0), &value); err != nil {
		return err
	}
	value.State = 3
	return s.collection.Maps["read_barrier"].Update(uint32(0), value, ebpf.UpdateAny)
}
