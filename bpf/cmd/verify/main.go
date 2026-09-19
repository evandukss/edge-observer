// Command verify decodes the helpers that freshly built BPF objects call and
// checks each against its program's allowlist. Run over objects just compiled
// from source, it fails when a user-memory read is added to the metadata-only
// program, which a check of the committed object cannot see. It reads the
// objects from disk, so it verifies the fresh build rather than what is
// embedded.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/evandukss/edge-observer/bpf"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(1)
	}
}

func run() error {
	objects, err := filepath.Glob("bpf/*.o")
	if err != nil {
		return err
	}
	// A glob that matched nothing would verify nothing and pass, so the count is
	// asserted first.
	if len(objects) < 4 {
		return fmt.Errorf("found %d objects to verify, expected at least four", len(objects))
	}

	checked := 0
	for _, path := range objects {
		program, err := programOf(path)
		if err != nil {
			return err
		}
		bytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := program.VerifyObject(bytes); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fmt.Printf("verified %s against the %s allowlist\n", filepath.Base(path), program.Name)
		checked++
	}
	fmt.Printf("verified %d objects\n", checked)
	return nil
}

// programOf is which program an object file holds, by its name: bpf2go writes
// full_* and meta_* objects.
func programOf(path string) (bpf.Program, error) {
	name := filepath.Base(path)
	switch {
	case strings.HasPrefix(name, "full_"):
		return bpf.Full(), nil
	case strings.HasPrefix(name, "meta_"):
		return bpf.Meta(), nil
	}
	return bpf.Program{}, fmt.Errorf("%s is neither a full nor a metadata object", name)
}
