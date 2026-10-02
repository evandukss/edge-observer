package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
	observerpolicy "github.com/evandukss/edge-observer/policy"
)

// The contract states the observer's defaults as values, and the observer turns
// the resolved values into its own settings. The observer is asked what it
// applies to a file that states neither, and the answer is held to the
// contract's.
func TestTheObserverDefaultsAgreeWithTheObserver(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("examples", "no-rules.config.json"))
	if err != nil {
		t.Fatalf("read the no-rules example: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode the no-rules example: %v", err)
	}
	delete(document, "limits")
	file, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode the configuration: %v", err)
	}
	loaded, err := observerpolicy.CompileProcessing(file, "")
	if err != nil {
		t.Fatalf("wiring, not the property: the observer refused a configuration stating neither setting: %v", err)
	}
	if loaded.Settings.ApprovedOutputBoundMiB != config.DefaultApprovedOutputBoundMiB {
		t.Errorf("the observer defaults the approved output bound to %d MiB and the contract to %d", loaded.Settings.ApprovedOutputBoundMiB, config.DefaultApprovedOutputBoundMiB)
	}
	if loaded.Settings.StateEvery != time.Duration(config.DefaultStateEverySeconds)*time.Second {
		t.Errorf("the observer defaults the state interval to %s and the contract to %ds", loaded.Settings.StateEvery, config.DefaultStateEverySeconds)
	}
	if int64(loaded.Settings.Workers) != config.DefaultWorkers {
		t.Errorf("the observer defaults the workers to %d and the contract to %d", loaded.Settings.Workers, config.DefaultWorkers)
	}
}
