// Package attach places the OpenSSL adapter's probes and reports what they
// see. It is separate so a program needing only to know whether a process can
// be observed cannot reach this machinery; a test over the import graph keeps
// that true.
package attach

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// noneAttached is why nothing was placed, one entry per requested process.
func noneAttached(request probe.Request, attached *set) []error {
	failures := make([]error, 0, len(request.Processes))
	for _, p := range request.Processes {
		if _, err := attached.Placements(p.PID); err != nil {
			failures = append(failures, err)
		}
	}
	return failures
}

// forked is the name of the probe on the process's own fork.
const forked = "fork"

// libcPrefix is what the C library's file is called before its version.
const libcPrefix = "libc.so"

// forkIn is where fork sits in the process's C library: the file as this
// process can open it (libcIn), and the offset.
func forkIn(root string, p process.Process, procfs string) (string, uint64, error) {
	path, err := libcIn(root, p, procfs)
	if err != nil {
		return "", 0, err
	}

	offsets, err := probe.SymbolOffsets(path, []string{forked})
	if err != nil {
		return "", 0, err
	}
	offset, resolved := offsets[forked]
	if !resolved {
		return "", 0, fmt.Errorf("%s exports no %s", path, forked)
	}
	return path, offset, nil
}

// libcIn is the observed process's own C library, reached through its own
// root: in another mount namespace the same path here is a different file,
// which would resolve every symbol and capture nothing.
func libcIn(root string, p process.Process, procfs string) (string, error) {
	mappings, err := process.Mappings(procfs, p.PID)
	if err != nil {
		return "", err
	}

	index := slices.IndexFunc(mappings, func(m process.Mapping) bool {
		return strings.HasPrefix(filepath.Base(m.Path), libcPrefix) && m.Executable
	})
	if index < 0 {
		return "", fmt.Errorf("pid %d maps no %s with code", p.PID, libcPrefix)
	}
	return filepath.Join(root, mappings[index].Path), nil
}
