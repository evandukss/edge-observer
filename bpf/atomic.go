package bpf

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

// AtomicFetchFloor is the oldest kernel whose verifier accepts an atomic
// add-and-fetch, which the generation allocators compile to. Without the fetch
// the add returns nothing, so two callers could get one generation. Before
// 5.12 the verifier refuses the instruction ("BPF_XADD uses reserved fields"),
// so an object carrying one does not load at all on an older kernel.
const AtomicFetchFloor = "5.12"

// AtomicFetches is how many atomic add-and-fetch instructions an object holds,
// read from the compiled object because what forces the floor is what clang
// emitted (as for Helpers). The encoding is BPF_STX with BPF_ATOMIC mode and
// BPF_FETCH in the immediate: opcode 0xc3 (32-bit) or 0xdb (64-bit).
func AtomicFetches(object []byte) (int, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return 0, fmt.Errorf("read the object: %w", err)
	}

	const fetch = 0x01
	found := 0
	for _, program := range spec.Programs {
		for _, instruction := range program.Instructions {
			switch uint8(instruction.OpCode) {
			case 0xc3, 0xdb:
				if instruction.Constant&fetch != 0 {
					found++
				}
			}
		}
	}
	return found, nil
}
