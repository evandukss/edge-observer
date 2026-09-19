package bpf

import (
	"bytes"
	"slices"
	"sort"
	"testing"

	"github.com/cilium/ebpf"
)

// programNames is the sorted program names in an object, which says two
// objects attach to the same points.
func programNames(t *testing.T, object []byte) []string {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		t.Fatalf("load the object: %v", err)
	}
	names := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// The full program may call exactly one memory-reading helper, so the only
// difference between the two programs is the payload read.
func TestTheFullProgramReadsUserMemoryAndNothingElseForbidden(t *testing.T) {
	called, err := Helpers(Full().Object)
	if err != nil {
		t.Fatalf("decode the full object's helpers: %v", err)
	}
	if !called["FnProbeReadUser"] {
		t.Error("the full program does not call FnProbeReadUser; it is meant to read the caller's buffer")
	}
	if err := Full().Verify(); err != nil {
		t.Errorf("the committed full object is not within its allowlist: %v", err)
	}
}

// The two programs are one source compiled twice, so they attach to the same
// functions: the metadata-only program is the same probes reporting less.
func TestBothProgramsCarryTheSameProbes(t *testing.T) {
	full := programNames(t, Full().Object)
	meta := programNames(t, Meta().Object)
	if !slices.Equal(full, meta) {
		t.Errorf("the two programs carry different probes:\n full: %v\n meta: %v", full, meta)
	}
	if len(full) == 0 {
		t.Fatal("the full program carries no probes; the objects did not load")
	}
}
