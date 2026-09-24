package main

import (
	"bytes"

	"errors"

	"testing"
)

// A configuration still asks the running session; with none running, that is
// refused, not read as a finished session.
func TestInspectOfAConfigurationStillAsksTheRunningSession(t *testing.T) {
	directory := t.TempDir()
	path := contractConfiguration(t, func(document map[string]any) {
		document["observer"].(map[string]any)["directory"] = directory
		target(document, "gateway", "/usr/bin/php")
	})
	var out bytes.Buffer
	err := run([]string{"inspect", path}, &out)
	if !errors.Is(err, errNotRunning) {
		t.Errorf("inspect of a configuration with no running session gave %v, want the not-running refusal", err)
	}
}
