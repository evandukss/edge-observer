//go:build attach

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
)

// Test-state helpers, excluded from the artifact by the attach tag; removing a
// map entry is not the supported capture shutdown.
func IndependentReplaceGrant(s *Session, instance admission.Instance, generation admission.Generation) (func() error, error) {
	m := s.collection.Maps["allowed_processes"]
	key := keyOf(instance)
	var original admissionValue
	if err := m.Lookup(key, &original); err != nil {
		return nil, err
	}
	replacement := original
	replacement.Generation = uint64(generation)
	var err error
	if generation == 0 {
		err = m.Delete(key)
	} else {
		err = m.Update(key, replacement, cilium.UpdateExist)
	}
	return func() error { return m.Update(key, original, cilium.UpdateAny) }, err
}

func IndependentSavedCall(s *Session, pid int32) (admission.Generation, uint32, bool, error) {
	// The actor calls OpenSSL only on its main thread. Read the saved call kind
	// from the map so a write in flight is not taken for the blocking read. Both
	// offsets come from the object's BTF: a field inserted ahead would move them
	// while literals still parse.
	spec, err := cilium.LoadCollectionSpecFromReader(bytes.NewReader(bpf.Full().Object))
	if err != nil {
		return 0, 0, false, err
	}
	valueType, ok := btf.UnderlyingType(spec.Maps["inflight"].Value).(*btf.Struct)
	if !ok {
		return 0, 0, false, fmt.Errorf("inflight value has no struct BTF")
	}
	key := uint64(uint32(pid))<<32 | uint64(uint32(pid))
	m := s.collection.Maps["inflight"]
	value := make([]byte, m.ValueSize())
	if err := m.Lookup(key, &value); err != nil {
		if errors.Is(err, cilium.ErrKeyNotExist) {
			return 0, 0, false, nil
		}
		return 0, 0, false, err
	}
	var generation uint64
	var function uint32
	fields := 0
	for _, member := range valueType.Members {
		offset := int(member.Offset / 8)
		width := 0
		switch member.Name {
		case "generation":
			width = 8
		case "func":
			width = 4
		default:
			continue
		}
		if member.Offset%8 != 0 || offset+width > len(value) {
			return 0, 0, false, fmt.Errorf("inflight %s lies outside value", member.Name)
		}
		fields++
		switch member.Name {
		case "generation":
			generation = binary.LittleEndian.Uint64(value[offset : offset+width])
		case "func":
			function = binary.LittleEndian.Uint32(value[offset : offset+width])
		}
	}
	if fields != 2 {
		return 0, 0, false, fmt.Errorf("inflight BTF exposed %d of 2 required fields", fields)
	}
	return admission.Generation(generation), function, true, nil
}

// Fill the evidence map with historical generations; a later real TLS read
// must be counted or make Reads report lost evidence.
func IndependentFillReadHistory(s *Session, live admission.Generation) error {
	m := s.collection.Maps["reads"]
	if m == nil {
		return ErrNoPayloadReads
	}
	for i := uint64(0); i < uint64(m.MaxEntries()); i++ {
		generation := uint64(admission.KernelGenerations) + i
		if generation == uint64(live) {
			return errors.New("historical fixture overlaps the live generation")
		}
		err := m.Update(generation, uint64(1), cilium.UpdateNoExist)
		if err != nil {
			// The live positive control already owns a slot; only a full map is the
			// desired state.
			if errors.Is(err, cilium.ErrKeyExist) {
				continue
			}
			var key, value uint64
			count := uint32(0)
			entries := m.Iterate()
			for entries.Next(&key, &value) {
				count++
			}
			if entries.Err() == nil && count == m.MaxEntries() {
				return nil
			}
			return fmt.Errorf("fill history reached %d/%d slots: %w", count, m.MaxEntries(), err)
		}
	}
	return nil
}
