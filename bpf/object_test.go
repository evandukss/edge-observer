package bpf

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf"
)

// Both committed objects are well-formed BPF ELFs the loader can read, which a
// mangled binary commit fails.
func TestTheCommittedObjectsLoad(t *testing.T) {
	for _, program := range Programs() {
		if _, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(program.Object)); err != nil {
			t.Errorf("%s object does not load: %v", program.Name, err)
		}
	}
}
