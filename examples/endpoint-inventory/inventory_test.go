package inventory_test

import (
	"testing"

	"github.com/evandukss/edge-observer/examples/endpoint-inventory/checks"
)

func TestInventoryPythonChecks(t *testing.T) {
	output, failures := checks.Run(".")
	t.Logf("%s", output)
	for file, err := range failures {
		t.Errorf("%s: %v", file, err)
	}
}
