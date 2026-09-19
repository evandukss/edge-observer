//go:build attach

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/evandukss/edge-observer/bpf"
)

// IndependentThreadCall reads the full pre-exec key. Offsets come from the
// compiled object's BTF so adding association fields cannot move the live bit
// away from the assertion unnoticed. It neither deletes nor reconciles state.
func IndependentThreadCall(s *Session, tgid, tid int32) (present, live bool, generation uint64, function uint32, err error) {
	spec, err := cilium.LoadCollectionSpecFromReader(bytes.NewReader(bpf.Full().Object))
	if err != nil {
		return false, false, 0, 0, err
	}
	valueType, ok := btf.UnderlyingType(spec.Maps["inflight"].Value).(*btf.Struct)
	if !ok {
		return false, false, 0, 0, fmt.Errorf("inflight value has no struct BTF")
	}
	m := s.collection.Maps["inflight"]
	value := make([]byte, m.ValueSize())
	key := uint64(uint32(tgid))<<32 | uint64(uint32(tid))
	if err := m.Lookup(key, &value); err != nil {
		if errors.Is(err, cilium.ErrKeyNotExist) {
			return false, false, 0, 0, nil
		}
		return false, false, 0, 0, err
	}
	fields := 0
	for _, member := range valueType.Members {
		offset := int(member.Offset / 8)
		width := 0
		switch member.Name {
		case "live":
			width = 1
		case "generation":
			width = 8
		case "func":
			width = 4
		default:
			continue
		}
		if member.Offset%8 != 0 || offset+width > len(value) {
			return false, false, 0, 0, fmt.Errorf("inflight %s lies outside value", member.Name)
		}
		fields++
		switch member.Name {
		case "live":
			live = value[offset] != 0
		case "generation":
			generation = binary.LittleEndian.Uint64(value[offset : offset+width])
		case "func":
			function = binary.LittleEndian.Uint32(value[offset : offset+width])
		}
	}
	if fields != 3 {
		return false, false, 0, 0, fmt.Errorf("inflight BTF exposed %d of 3 required fields", fields)
	}
	return true, live, generation, function, nil
}
