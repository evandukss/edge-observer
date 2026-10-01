// Package checks runs the endpoint inventory's Python checks from one place.
package checks

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Run checks exactly the files in directory, including a caller's scratch copy.
// Failures name the Python suite or executable whose check failed.
func Run(directory string) (string, map[string]error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	failures := map[string]error{}
	var output strings.Builder
	for _, check := range []struct {
		file string
		args []string
	}{
		{"test_inventory.py", []string{"-B", "-m", "unittest", "-v", "test_inventory"}},
		{"inventory.py", []string{"-B", "check_imports.py", "inventory.py"}},
	} {
		command := exec.CommandContext(ctx, "python3", check.args...)
		command.Dir = directory
		result, err := command.CombinedOutput()
		_, _ = output.Write(result)
		if err != nil {
			failures[check.file] = fmt.Errorf("python3 %v: %w\n%s", check.args, err, result)
		}
	}
	return output.String(), failures
}
