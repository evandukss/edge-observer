package attach_test

import (
	"testing"

	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
)

// No build tag: compiled as an ordinary build is, so what it reads is what
// that binary states as its capability.
func TestAnUntaggedBuildReadsPlaintext(t *testing.T) {
	built := attach.Built()
	if built.Backend != probe.BPF {
		t.Fatalf("wiring, not the property: the build states backend %q, so it is not the BPF build being asked about", built.Backend)
	}
	if !built.Payload {
		t.Errorf("an untagged build states Program:%s, Payload:false; the one build reads plaintext", built.Program)
	}
	if built.Program != "full" {
		t.Errorf("an untagged build loads the %q program, want the full program", built.Program)
	}
}
