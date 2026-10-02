package main

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/evandukss/edge-observer/examples/endpoint-inventory/checks"
)

// Copy only the files the Python checks execute or consume. A new, unused file
// stays unopened so the example guard can still report it.
func checkInventoryExample(examples fs.FS) map[string]error {
	failures := map[string]error{}
	directory, err := os.MkdirTemp("", "inventory-example")
	if err != nil {
		failures[""] = err
		return failures
	}
	defer func() { _ = os.RemoveAll(directory) }()
	for _, at := range []string{"inventory.py", "check_imports.py", "test_inventory.py", "testdata/session.jsonl"} {
		content, err := fs.ReadFile(examples, at)
		if err != nil {
			failures[at] = err
			continue
		}
		destination := filepath.Join(directory, filepath.FromSlash(at))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			failures[at] = err
		} else if err := os.WriteFile(destination, content, 0o600); err != nil {
			failures[at] = err
		}
	}
	if len(failures) != 0 {
		return failures
	}
	_, failures = checks.Run(directory)
	return failures
}
