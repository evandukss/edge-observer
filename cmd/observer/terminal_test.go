package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/probe"
)

func TestTerminalCaptureFaultsSealAndReturnFailure(t *testing.T) {
	for _, kind := range []probe.DeliveryKind{probe.DeliveryTransfer, 255} {
		t.Run(string(rune('a'+kind)), func(t *testing.T) {
			f := processingController(t)
			f.liveControl(t)
			decision := f.d.gate.Admit(kind, false)
			if decision.Admitted || !decision.State.Reason.InvalidatesCapture() {
				t.Fatalf("wiring: terminal fault not reached: %+v", decision)
			}
			f.halt(t)
			var logs bytes.Buffer
			err := f.finish(&logger{out: &logs})
			if err == nil || !strings.Contains(err.Error(), string(decision.State.Reason)) {
				t.Fatalf("terminal capture returned %v", err)
			}
			content, readErr := os.ReadFile(filepath.Join(f.d.directory, sealedName))
			var sealed account.Account
			if readErr != nil || json.Unmarshal(content, &sealed) != nil || sealed.Kind != account.Sealed {
				t.Fatalf("fault did not leave a readable sealed account: %s %v", content, readErr)
			}
		})
	}
}

func TestRestartNamesAGapOnlyWhileItsSealedAccountIsReadable(t *testing.T) {
	f := processingController(t)
	f.liveControl(t)
	f.halt(t)
	if err := f.finish(&logger{}); err != nil {
		t.Fatal(err)
	}
	if got := f.d.follows(time.Now()); got == nil || got.Session != f.d.session || got.Gap == "" {
		t.Fatalf("readable sealed control has no gap: %+v", got)
	}
	if err := os.Remove(filepath.Join(f.d.directory, sealedName)); err != nil {
		t.Fatal(err)
	}
	if got := f.d.follows(time.Now()); got != nil {
		t.Fatalf("unreadable account claimed a gap: %+v", got)
	}
}
