package process_test

import (
	"os"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/process"
)

func TestMappingsHoldsTheExecutableTheProcessIsRunning(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	mappings, err := process.Mappings(procfs, int32(os.Getpid()))
	if err != nil {
		t.Fatalf("Mappings: %v", err)
	}

	var found bool
	for _, mapping := range mappings {
		if mapping.Path == executable {
			found = true
			if !mapping.Executable {
				t.Errorf("%s is mapped with nothing that may run", mapping.Path)
			}
		}
	}
	if !found {
		t.Fatalf("%s is absent from %d mappings", executable, len(mappings))
	}
}

// A program mapped in several regions is listed once, with the union of their
// permissions.
func TestMappingsHoldsEachFileOnce(t *testing.T) {
	mappings, err := process.Mappings(procfs, int32(os.Getpid()))
	if err != nil {
		t.Fatalf("Mappings: %v", err)
	}

	seen := make(map[string]bool, len(mappings))
	for _, mapping := range mappings {
		if seen[mapping.Path] {
			t.Errorf("%s is listed more than once", mapping.Path)
		}
		seen[mapping.Path] = true
	}
	if len(mappings) == 0 {
		t.Fatal("no file is mapped, not even the program being run")
	}
}

func TestMappingsLeavesOutWhatIsNotAFile(t *testing.T) {
	mappings, err := process.Mappings(procfs, int32(os.Getpid()))
	if err != nil {
		t.Fatalf("Mappings: %v", err)
	}

	for _, mapping := range mappings {
		if strings.HasPrefix(mapping.Path, "[") {
			t.Errorf("%q is a region the kernel named, not a file", mapping.Path)
		}
	}
}

func TestMappingsRefusesAProcessThatIsNotThere(t *testing.T) {
	if _, err := process.Mappings(procfs, 0); err == nil {
		t.Fatal("Mappings returned no error for a pid that cannot exist")
	}
}
