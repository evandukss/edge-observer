package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"

	obpf "github.com/evandukss/edge-observer/bpf"
)

// The two sides of this ABI are a C structure in bpf/ssl.bpf.h and a Go
// structure here, and no compiler compares them: a field added to one side
// decodes every later value one field out, as plausible numbers. So the
// compiled object's own BTF is asked what it holds.

func specOf(t *testing.T, program obpf.Program) *ciliumebpf.CollectionSpec {
	t.Helper()
	spec, err := ciliumebpf.LoadCollectionSpecFromReader(bytes.NewReader(program.Object))
	if err != nil {
		t.Fatalf("read the %s object: %v", program.Name, err)
	}
	return spec
}

func TestTheAllowlistIsTheSameShapeOnBothSidesOfTheProgram(t *testing.T) {
	for _, program := range obpf.Programs() {
		t.Run(program.Name, func(t *testing.T) {
			spec := specOf(t, program)

			sizes := map[string][2]int{
				"allowed_processes": {binary.Size(instanceKey{}), binary.Size(admissionValue{})},
				"namespaces":        {binary.Size(uint32(0)), binary.Size(namespaceValue{})},
				"generations":       {binary.Size(uint32(0)), binary.Size(uint64(0))},
				// The descriptor table: a disagreement would seed occupancies under keys the
				// program never looks up, silently.
				"sockets": {binary.Size(socketKey{}), binary.Size(socketLife{})},
				// The in-flight table: reading the wrong byte for Live would report calls in
				// flight that are not.
				"inflight": {binary.Size(uint64(0)), binary.Size(callValue{})},
				// The two allocators read as values: event order and descriptor occupancies.
				"attempts": {binary.Size(uint32(0)), binary.Size(uint64(0))},
				"bindings": {binary.Size(uint32(0)), binary.Size(uint64(0))},
				// The handle bindings: a disagreement would report a binding under the wrong
				// process.
				"handles": {binary.Size(handleKey{}), binary.Size(bindingValue{})},
			}
			for name, want := range sizes {
				held, found := spec.Maps[name]
				if !found {
					t.Errorf("the %s program has no %s map", program.Name, name)
					continue
				}
				if int(held.KeySize) != want[0] {
					t.Errorf("%s keys are %d bytes in the program and %d here", name, held.KeySize, want[0])
				}
				if int(held.ValueSize) != want[1] {
					t.Errorf("%s values are %d bytes in the program and %d here", name, held.ValueSize, want[1])
				}
			}

			if held, found := spec.Maps["namespaces"]; found && int(held.MaxEntries) != maxNamespaces {
				t.Errorf("the program enumerates %d pid namespaces and this expects %d",
					held.MaxEntries, maxNamespaces)
			}

			// A counter read by index and written by name. Past the end is a loud error; a
			// slot the program never writes would read as "nothing was refused".
			if held, found := spec.Maps["stats"]; found && held.MaxEntries <= 3 {
				t.Errorf("the program holds %d counters, and the refusal counter is index 3",
					held.MaxEntries)
			}

			// The event's layout: a ring buffer carries no type information, so the size
			// is pinned here and the offsets are proved where a real event arrives (the
			// attach suite).
			if held, found := spec.Maps["events"]; !found {
				t.Errorf("the %s program has no ring buffer", program.Name)
			} else if held.Type != ciliumebpf.RingBuf {
				t.Errorf("the events map is a %s", held.Type)
			}
		})
	}
}

func TestOnlyTheProgramThatReadsUserMemoryCountsThoseReads(t *testing.T) {
	// The read counter exists only where a user-memory read can happen; the
	// metadata-only object has no such map, so Reads answers ErrNoPayloadReads
	// there.
	for _, program := range obpf.Programs() {
		_, counted := specOf(t, program).Maps["reads"]
		if counted != program.ReadsPayload {
			t.Errorf("the %s program reads user memory: %v, and counts those reads: %v",
				program.Name, program.ReadsPayload, counted)
		}
	}
}
