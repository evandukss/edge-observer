package attach_test

import (
	"bytes"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// tracefsPath is where a tracefs observation path would live. It could never
// copy plaintext, so a host that can only reach tracefs is refused rather than
// observed through it.
const tracefsPath = "github.com/evandukss/edge-observer/uprobe"

// No package in the module is the tracefs path, and none references it: with
// -deps, -e lists an imported package that does not exist as its own entry,
// so one listing answers both. Tracefs could return only as a catalogue
// adapter of its own, which is a decision to take here.
func TestTheObserverModuleHoldsNoTracefsObservationPath(t *testing.T) {
	cmd := exec.Command("go", "list", "-e", "-deps", "-test", "-f", "{{.ImportPath}}",
		"github.com/evandukss/edge-observer/...")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -e -deps -test over the observer module: %v\n%s", err, stderr.String())
	}

	listed := strings.Fields(string(out))
	// An empty or short listing looks like an empty module; this module holds at
	// least these.
	for _, present := range []string{
		"github.com/evandukss/edge-observer/probe/openssl/attach",
		"github.com/evandukss/edge-observer/ebpf",
		"github.com/evandukss/edge-observer/cmd/observer",
	} {
		if !slices.Contains(listed, present) {
			t.Fatalf("wiring, not the property: the listing of %d entries does not hold %s, so the "+
				"module was not measured", len(listed), present)
		}
	}

	for _, path := range listed {
		if path == tracefsPath || strings.HasPrefix(path, tracefsPath+"/") {
			t.Errorf("the observer module holds or references %s, the tracefs observation path", path)
		}
	}
}
