//go:build attach

package attach_test

import (
	"testing"

	"github.com/evandukss/edge-observer/probe/openssl/attach"
)

func TestTheProgramThisBuildCarriesLoadsOnThisKernel(t *testing.T) {
	if err := attach.Loads(); err != nil {
		t.Fatalf("Loads: %v", err)
	}
}
