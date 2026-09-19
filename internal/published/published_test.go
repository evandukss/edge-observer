package published

import (
	"os/exec"

	"slices"

	"strings"
	"testing"
)

// The observer command imports the contract account's producer: asserted
// directly, since no other suite here would notice its absence.
func TestTheObserverCommandDependsOnTheContractAccountsProducer(t *testing.T) {
	const module = "github.com/evandukss/edge-observer/"
	output, err := exec.Command("go", "list", "-deps", module+"cmd/observer").Output()
	if err != nil {
		t.Fatalf("list the observer command's dependencies: %v", err)
	}
	deps := strings.Fields(string(output))
	if !slices.Contains(deps, module+"spool") {
		t.Fatalf("wiring, not the property: the listing of %d packages does not hold the spool the command "+
			"certainly writes, so it is not the observer command's dependencies", len(deps))
	}
	for _, want := range []string{module + "internal/published", module + "contract/account"} {
		if !slices.Contains(deps, want) {
			t.Errorf("the observer command does not depend on %s, so nothing it runs produces the contract account", want)
		}
	}
}
