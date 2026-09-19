package preflight_test

import (
	"bytes"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

const modulePath = "github.com/evandukss/edge-observer"

// What the package deciding a readiness verdict may reach, kept short on
// purpose: adding a package here is a deliberate claim that the verdict may do
// more.
//
// It establishes that this package and its tests import no capture, spool or
// export code. It does not establish that the program running it has none:
// `observer preflight` is a mode of the observer binary, which holds all of
// it, and hands this package one kernel action (the program load, via
// Host.Loads). Process-level separation would need a separate binary.
var reachable = []string{
	"admission",
	"fragment",
	"preflight",
	"probe",
	"probe/openssl",
	"process",
}

func TestPreflightReachesOnlyWhatItIsAllowedTo(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "-test", "-f", "{{if and (not .Standard) (not .ForTest)}}{{.ImportPath}}{{end}}", ".")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps -test: %v\n%s", err, stderr.String())
	}

	var reached []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		inner, inModule := strings.CutPrefix(line, modulePath+"/")
		if line == modulePath {
			inner, inModule = ".", true
		}
		if !inModule || strings.HasSuffix(inner, ".test") {
			continue
		}
		reached = append(reached, inner)
		if !slices.Contains(reachable, inner) {
			t.Errorf("preflight reaches %s, which is not on the list of what it may reach", inner)
		}
	}

	// The package depends on at least itself; an empty listing measured
	// nothing.
	if !slices.Contains(reached, "preflight") {
		t.Fatalf("go list -deps -test did not list preflight itself, so the boundary was not measured: %v", reached)
	}
}
