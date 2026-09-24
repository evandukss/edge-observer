package bpf

import "testing"

// The metadata-only program reads no process memory, checked here against the
// committed object. cmd/verify runs the same check over a freshly compiled
// object, which is what sees a source change; this catches a committed object
// that does not match its allowlist.
func TestTheMetadataProgramCallsNoMemoryReadHelper(t *testing.T) {
	called, err := Helpers(Meta().Object)
	if err != nil {
		t.Fatalf("decode the metadata object's helpers: %v", err)
	}
	if called["FnProbeReadUser"] {
		t.Error("the metadata-only program calls FnProbeReadUser; it must read no process memory")
	}
	if err := Meta().Verify(); err != nil {
		t.Errorf("the committed metadata object is not within its allowlist: %v", err)
	}
}

// Neither program writes the observed process's memory, whichever allowlist it
// is checked against.
func TestNeitherProgramWritesUserMemory(t *testing.T) {
	for _, program := range Programs() {
		called, err := Helpers(program.Object)
		if err != nil {
			t.Fatalf("%s: decode helpers: %v", program.Name, err)
		}
		if called["FnProbeWriteUser"] {
			t.Errorf("the %s program calls FnProbeWriteUser; no program may write process memory", program.Name)
		}
	}
}
