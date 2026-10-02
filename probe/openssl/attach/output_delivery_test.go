//go:build attach

package attach_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/processing"
)

// This runs the shipped daemon and control commands. Directory destinations
// inject open failure; real TLS traffic establishes monitoring before recovery.
func TestUnavailableOutputActivatesAndControlReopenRotatesFiles(t *testing.T) {
	binary := built(t)
	port := t18Serving(t)
	clients := []conversation{speaking(t, port), speaking(t, port), speaking(t, port)}
	c := configuring(t, target("clients", clients[0].process))
	approved := filepath.Join(c.directory, processing.ArtifactName)
	for _, path := range []string{approved, c.log} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := exec.CommandContext(ctx, binary, "start", c.path, "--daemonize")
	intoEnvelope(t, start)
	if out, err := start.CombinedOutput(); err != nil {
		t.Fatalf("unavailable destinations refused activation: %v\n%s", err, out)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = exec.CommandContext(ctx, binary, "stop", c.path).Run()
		}
	})
	initial := inspected(t, binary, c)
	if initial.Session == "" {
		t.Fatal("wiring: no activated session identity")
	}
	for _, client := range clients {
		if !observes(initial, client.process.PID) {
			t.Fatalf("wiring: client %d not attached", client.process.PID)
		}
	}
	command := func(kind string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, binary, kind, c.path).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", kind, err, out)
		}
		if kind == "reopen" && !bytes.Contains(out, []byte(`"status":"reopened"`)) {
			t.Fatalf("missing reopen acknowledgement: %s", out)
		}
	}
	settled := func(authorized, written, failed uint64) account.Account {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			a := inspected(t, binary, c)
			if a.Processing != nil {
				d := a.Processing.Delivery
				if d.Authorized == authorized && d.Written == written && d.Failed == failed && d.Pending == 0 {
					return a
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("delivery did not settle: %+v", a.Processing)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	t18Ask(t, clients[0], "/unavailable")
	t18Hangup(clients[0])
	failed := settled(2, 0, 2)
	if failed.Processing.GateReason != "" || failed.LogDelivery == nil || failed.LogDelivery.Failed == 0 {
		t.Fatalf("failure invalidated monitoring or log failure absent: processing %+v log %+v", failed.Processing, failed.LogDelivery)
	}
	for _, path := range []string{approved, c.log} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	command("reopen")
	t18Ask(t, clients[1], "/before-rotation")
	t18Hangup(clients[1])
	settled(4, 2, 2)
	for _, path := range []string{approved, c.log} {
		if err := os.Rename(path, path+".1"); err != nil {
			t.Fatal(err)
		}
	}
	command("reopen")
	t18Ask(t, clients[2], "/after-rotation")
	t18Hangup(clients[2])
	settled(6, 4, 2)
	command("stop")
	stopped = true
	old, err := os.ReadFile(approved + ".1")
	if err != nil {
		t.Fatal(err)
	}
	active, err := os.ReadFile(approved)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(old, []byte("/before-rotation")) || bytes.Contains(old, []byte("/after-rotation")) || !bytes.Contains(active, []byte("/after-rotation")) {
		t.Fatalf("approved rotation populations: old %s active %s", old, active)
	}
	logs, err := os.ReadFile(c.log)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(logs, []byte(`"record":"stopped"`)) {
		t.Fatalf("post-ack log missing stop: %s", logs)
	}
	visits := 0
	if err := processing.ReadArtifactFiles(os.DirFS(c.directory), []string{processing.ArtifactName + ".1", processing.ArtifactName}, initial.Session, func(a processing.Artifact) error { visits++; return nil }); err != nil {
		t.Fatal(err)
	}
	if visits != 4 {
		t.Fatalf("reader saw %d retained lines, want four", visits)
	}
	sealedBytes, err := os.ReadFile(filepath.Join(c.sessions(), initial.Session, "account.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sealed account.Account
	if err := json.Unmarshal(sealedBytes, &sealed); err != nil {
		t.Fatal(err)
	}
	if sealed.Processing == nil || sealed.Processing.Delivery.Failed != 2 || sealed.Processing.Delivery.Written != 4 || sealed.LogDelivery == nil || sealed.LogDelivery.Failed == 0 || sealed.LogDelivery.Written == 0 || sealed.LogDelivery.Pending != 0 {
		t.Fatalf("sealed outcomes: processing %+v log %+v", sealed.Processing, sealed.LogDelivery)
	}
	t.Logf("actual detached activation, monitoring through failed opens, reopen recovery, rename and stop: approved %+v log %+v", sealed.Processing.Delivery, sealed.LogDelivery)
}
