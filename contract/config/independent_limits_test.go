package config_test

import (
	"testing"

	"github.com/evandukss/edge-observer/contract/config"
)

// Output is best effort at stable paths and nothing bounds its total, so the
// approved output's allowance is no longer a key: a configuration naming it is
// refused, by the strict reader and by compilation, as a key that does not
// exist. Written from the contract, not from the reader.
func TestIndependentLimitsOutputMiBIsRefusedAsAnUnknownKey(t *testing.T) {
	const without = `{"version": "observer.config/1", "output": "/var/lib/observer", ` +
		`"watch": [{"name": "api", "exe": "/usr/bin/php"}], "limits": {"events": 16384}}`
	const with = `{"version": "observer.config/1", "output": "/var/lib/observer", ` +
		`"watch": [{"name": "api", "exe": "/usr/bin/php"}], "limits": {"output_mib": 64, "events": 16384}}`

	if _, findings := config.ReadFile([]byte(without)); len(findings) != 0 {
		t.Fatalf("wiring, not the property: the same configuration without output_mib is refused: %+v", findings)
	}
	if compiled, findings := config.Compile([]byte(without), ""); compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: the same configuration without output_mib does not compile: %+v", findings)
	}

	_, read := config.ReadFile([]byte(with))
	compiled, compiling := config.Compile([]byte(with), "")
	if compiled != nil {
		t.Error("a configuration naming limits.output_mib compiled")
	}
	for name, findings := range map[string][]config.Finding{"ReadFile": read, "Compile": compiling} {
		found := false
		for _, finding := range findings {
			if finding.Subject == "limits.output_mib" && finding.Reason == config.UnknownKey {
				found = true
			}
		}
		if !found {
			t.Errorf("%s did not refuse limits.output_mib as an unknown key: %+v", name, findings)
		}
	}
}
