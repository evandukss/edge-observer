//go:build attach

package ebpf_test

import (
	"bytes"
	"testing"

	cilium "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/evandukss/edge-observer/bpf"
)

// A dynamic Reads comparison cannot see a helper call that omits its recording
// altogether. This checks the compiled control flow for that bypass. Visiting
// the map does not prove a successful increment; the live read and exhaustion
// tests separately exercise that part of the evidence contract.
func TestUserReadSitesCannotBypassTheCounterMap(t *testing.T) {
	spec, err := cilium.LoadCollectionSpecFromReader(bytes.NewReader(bpf.Full().Object))
	if err != nil {
		t.Fatal(err)
	}
	readSites := 0
	for name, program := range spec.Programs {
		t.Run(name, func(t *testing.T) {
			instructions := program.Instructions
			pcs := make([]int, len(instructions))
			indices := make(map[int]int, len(instructions))
			pc := 0
			for i, instruction := range instructions {
				pcs[i], indices[pc] = pc, i
				pc += int(instruction.Size() / 8)
			}
			type state struct {
				index   int
				counted bool
			}
			queue := []state{{}}
			seen := make(map[state]bool)
			for len(queue) != 0 {
				current := queue[0]
				queue = queue[1:]
				if seen[current] {
					continue
				}
				seen[current] = true
				if current.index < 0 || current.index >= len(instructions) {
					t.Fatalf("control flow leaves the program at instruction %d", current.index)
				}
				instruction := instructions[current.index]
				if instruction.Reference() == "reads" {
					current.counted = true
				}
				if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == asm.FnProbeReadUser {
					readSites++
					if !current.counted {
						t.Errorf("user read at instruction %d is reachable without visiting the counter map since the previous read", current.index)
					}
					current.counted = false
				}
				jump := instruction.OpCode.JumpOp()
				if jump == asm.Exit {
					continue
				}
				if jump == asm.Call && !instruction.IsBuiltinCall() {
					t.Fatal("subprogram call requires interprocedural analysis before this check can establish counter coverage")
				}
				if jump != asm.InvalidJumpOp && jump != asm.Call {
					target, ok := indices[pcs[current.index]+1+int(instruction.Offset)]
					if !ok {
						t.Fatalf("jump at instruction %d has no decoded target", current.index)
					}
					queue = append(queue, state{target, current.counted})
				}
				if jump != asm.Ja {
					queue = append(queue, state{current.index + 1, current.counted})
				}
			}
		})
	}
	if readSites == 0 {
		t.Fatal("no reachable user reads were checked")
	}
}
