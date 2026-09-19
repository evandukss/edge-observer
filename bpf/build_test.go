package bpf

import "testing"

// No build tag: compiled as an ordinary build is. The plaintext-reading
// bytecode must be in that binary, checked by the helper its object calls.
func TestAnUntaggedBuildEmbedsThePlaintextProgram(t *testing.T) {
	programs := Programs()
	if len(programs) == 0 {
		t.Fatal("wiring, not the property: this build names no program at all")
	}
	for _, program := range programs {
		if !program.ReadsPayload {
			continue
		}
		called, err := Helpers(program.Object)
		if err != nil {
			t.Fatalf("decode the %s object's helpers: %v", program.Name, err)
		}
		if !called["FnProbeReadUser"] {
			t.Errorf("the %s program claims to read payload and its object calls no FnProbeReadUser", program.Name)
		}
		return
	}
	names := make([]string, 0, len(programs))
	for _, program := range programs {
		names = append(names, program.Name)
	}
	t.Errorf("an untagged build embeds %v and none of them reads plaintext", names)
}
