package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Built-ins are not read by the structural check when a configuration is
// checked: they are compiled into the runtime and cannot vary between starts.
// Every rule over their values is a rule the compiler does not enforce, so the
// component rules a manifest's components are held to are run over the
// runtime's built-in set here, through the same function.
func TestEveryBuiltinSatisfiesTheComponentRules(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("examples", "runtime.json"))
	if err != nil {
		t.Fatalf("read the runtime inventory: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var available Available
	if err := decoder.Decode(&available); err != nil {
		t.Fatalf("decode the runtime inventory: %v", err)
	}
	if len(available.Builtins) != 5 {
		t.Fatalf("wiring, not the rules: %d built-ins where 5 are written, so nothing below measures the set", len(available.Builtins))
	}
	for index, builtin := range available.Builtins {
		f := &findings{document: "builtin"}
		component(f, "builtins["+builtin.Name+"]", builtin)
		if builtin.Execution != ExecutionBuiltin {
			t.Errorf("built-in %d %q declares execution %q", index, builtin.Name, builtin.Execution)
		}
		for _, finding := range f.list {
			t.Errorf("built-in %q: %s %s: %s", builtin.Name, finding.Subject, finding.Reason, finding.Detail)
		}
	}
}
