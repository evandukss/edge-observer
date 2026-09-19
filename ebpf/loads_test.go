package ebpf_test

import (
	"errors"
	"testing"

	obpf "github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
)

// A load check that cleared what the kernel never took would be a READY on a
// host that cannot capture, so the refusal has to come back, and as the error
// Attach gives.
func TestLoadsRefusesAnObjectThatIsNotAProgram(t *testing.T) {
	err := ebpf.Loads(obpf.Program{Name: "not a program", Object: []byte("not an ELF object")})
	if err == nil {
		t.Fatal("Loads accepted an object that is not a program")
	}
	if !errors.Is(err, ebpf.ErrUnavailable) {
		t.Errorf("Loads refused with %v, which is not ErrUnavailable", err)
	}
}
