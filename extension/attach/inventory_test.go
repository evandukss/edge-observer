//go:build attach

package attach_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The tap copies exactly the bytes read by the example, without constructing
// protocol messages. /out preserves the capture beside the gate's logs.
const inventoryTap = `
import runpy, sys
from types import SimpleNamespace
source = sys.stdin.buffer
capture = open(sys.argv[2], "wb", buffering=0)
class Tap:
    def readline(self, size=-1):
        line = source.readline(size)
        capture.write(line)
        return line
sys.stdin = SimpleNamespace(buffer=Tap())
runpy.run_path(sys.argv[1], run_name="__main__")
`

func TestEndpointInventoryEntryAndSourceProvenance(t *testing.T) {
	binary := built(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	script := inventorySource(t)
	port := serving(t)
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			c := speaking(t, port)
			root := t.TempDir()
			output := filepath.Join(root, "state")
			received := filepath.Join(root, "received.jsonl")
			tap := filepath.Join(root, "tap.py")
			if err := os.WriteFile(tap, []byte(inventoryTap), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{}
			if len(c.process.Arguments) > 1 {
				args = c.process.Arguments[1:]
			}
			document := map[string]any{
				"version": "observer.config/1", "output": output, "log": filepath.Join(output, "observer.log"),
				"limits":    map[string]any{"output_mib": 4, "state_every_seconds": 1},
				"watch":     []any{map[string]any{"name": "client", "exe": c.process.Executable, "args": args, "children": "all"}},
				"libraries": []any{},
			}
			if enabled {
				document["extensions"] = []any{map[string]any{
					"name": "inventory", "command": []string{python, tap, script, received},
					"fields": []string{"request.line", "response.line"}, "timeout_ms": 5000,
				}}
			}
			content, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "observer.json")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatal(err)
			}
			s := started(t, binary, path, output)
			if enabled {
				waitForLine(t, received, `"type":"start"`)
				// Start is recorded just before ready; let the observer consume it.
				time.Sleep(time.Second)
			}
			for _, target := range []string{"/users/42", "/users/43", "/health"} {
				c.ask(t, target)
			}
			c.hangUp(t)
			if enabled {
				waitForLine(t, received, `"type":"connection_done"`)
			}
			sealed := s.ended(t)
			approved, err := os.ReadFile(filepath.Join(s.directory, "approved.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			ids := map[string]bool{}
			var written int
			for _, raw := range strings.Split(strings.TrimSpace(string(approved)), "\n") {
				var line struct {
					IDs            struct{ First, Last, Count string } `json:"exchange_ids"`
					Reconstruction struct{ Exchanges []json.RawMessage }
				}
				if err := json.Unmarshal([]byte(raw), &line); err != nil {
					t.Fatal(err)
				}
				written += len(line.Reconstruction.Exchanges)
				if line.IDs.Count == "0" {
					continue
				}
				first, e1 := strconv.ParseUint(line.IDs.First, 10, 64)
				last, e2 := strconv.ParseUint(line.IDs.Last, 10, 64)
				if e1 != nil || e2 != nil || first == 0 || last < first || last-first > 100 {
					t.Fatalf("invalid exchange range: %+v", line.IDs)
				}
				for id := first; id <= last; id++ {
					ids[strconv.FormatUint(id, 10)] = true
				}
			}
			if written != 3 {
				t.Fatalf("wiring, not the property: wrote %d exchanges, want the three requests", written)
			}
			derivedPath := filepath.Join(s.directory, "derived-inventory.jsonl")
			if !enabled {
				if _, err := os.Stat(derivedPath); !os.IsNotExist(err) {
					t.Fatalf("inventory output without an entry: %v", err)
				}
				return
			}
			derived, err := os.ReadFile(derivedPath)
			if err != nil {
				t.Fatal(err)
			}
			var batch struct {
				Sources []string
				Basis   string
				Session string
				Record  struct {
					Scope     string
					Exchanges string
					Endpoints []struct {
						Method    string
						Path      string `json:"path_template"`
						Exchanges string
						Sources   []string
					}
				}
			}
			if err := json.Unmarshal(derived, &batch); err != nil {
				t.Fatalf("expected one final batch: %v\n%s", err, derived)
			}
			if batch.Session != s.id || batch.Basis != "inferred" || len(batch.Sources) != 3 ||
				batch.Record.Exchanges != "3" || batch.Record.Scope != "exchanges this extension received" {
				t.Fatalf("wrong summary: %s", derived)
			}
			for _, id := range batch.Sources {
				if !ids[id] {
					t.Errorf("derived source %s lies in no approved range", id)
				}
			}
			want := map[string]string{"/users/{id}": "2", "/health": "1"}
			cited := map[string]bool{}
			if len(batch.Record.Endpoints) != len(want) {
				t.Fatalf("wrong endpoints: %s", derived)
			}
			for _, endpoint := range batch.Record.Endpoints {
				if endpoint.Method != "GET" || want[endpoint.Path] != endpoint.Exchanges || len(endpoint.Sources) == 0 {
					t.Errorf("unexpected endpoint: %+v", endpoint)
				}
				delete(want, endpoint.Path)
				count, err := strconv.Atoi(endpoint.Exchanges)
				if err != nil || count != len(endpoint.Sources) {
					t.Errorf("endpoint count differs from its sources: %+v", endpoint)
				}
				for _, id := range endpoint.Sources {
					if !ids[id] || cited[id] {
						t.Errorf("endpoint source %s missing from approved ranges or cited twice", id)
					}
					cited[id] = true
				}
			}
			for _, id := range batch.Sources {
				if !cited[id] {
					t.Errorf("batch source %s missing from endpoint summaries", id)
				}
			}
			if len(want) != 0 || sealed.Processing == nil || len(sealed.Processing.Extensions) != 1 ||
				sealed.Processing.Extensions[0].Unchanged != 3 || sealed.Processing.Extensions[0].Failed != 0 {
				t.Fatalf("missing summaries or exchanges not answered unchanged: %+v", sealed.Processing)
			}
			if info, err := os.Stat("/out"); err == nil && info.IsDir() {
				capture, err := os.ReadFile(received)
				if err != nil {
					t.Fatal(err)
				}
				for name, data := range map[string][]byte{"inventory-protocol.jsonl": capture,
					"inventory-approved.jsonl": approved, "inventory-derived.jsonl": derived} {
					if err := os.WriteFile(filepath.Join("/out", name), data, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func inventorySource(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		module, err := os.ReadFile(filepath.Join(directory, "go.mod"))
		if err == nil {
			if !strings.HasPrefix(string(module), "module github.com/evandukss/edge-observer\n") {
				t.Fatalf("nearest go.mod in %s is not the observer module", directory)
			}
			return filepath.Join(directory, "examples", "endpoint-inventory", "inventory.py")
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("no observer go.mod above this package")
		}
		directory = parent
	}
}
