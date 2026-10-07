package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/processing"
)

// The candidate activates an additional target with no matching process. The
// daemon's reload, processing run, intake, reservations and output are real;
// capture input and the unused attachment boundary are modelled.
type reloadBoundsAttachment struct{}

func (*reloadBoundsAttachment) Close() error                 { return nil }
func (*reloadBoundsAttachment) Capability() probe.Capability { return probe.Capability{} }
func (*reloadBoundsAttachment) Admit(probe.Request) (probe.Added, error) {
	return probe.Added{}, fmt.Errorf("fixture unexpectedly attempted kernel admission")
}
func (*reloadBoundsAttachment) Retract([]admission.Selection) {}

type reloadBoundsSlot struct {
	held.Slot
	calls atomic.Int32
}

func (s *reloadBoundsSlot) Refund(path held.Path) bool {
	s.calls.Add(1)
	return s.Slot.Refund(path)
}

type reloadBoundsFixture struct {
	d        *daemon
	run      *processingRun
	ctx      context.Context
	identity fragment.Identity
	evidence fragment.Evidence
	slots    []*reloadBoundsSlot
	taken    atomic.Int32
	document map[string]any
}

func newReloadBoundsFixture(t *testing.T) *reloadBoundsFixture {
	t.Helper()
	f := &reloadBoundsFixture{}
	var cancel context.CancelFunc
	f.ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	directory := t.TempDir()
	path := filepath.Join(directory, "observer.json")
	f.document = map[string]any{
		"version": "observer.config/1", "output": directory, "log": "stdout",
		"limits": map[string]any{"workers": 1},
		"watch":  []any{map[string]any{"name": "kept", "exe": "/nonexistent/reload-kept", "children": "none"}},
	}
	reloadBoundsWrite(t, path, f.document)
	policy, err := loadProcessing(path)
	if err != nil {
		t.Fatalf("wiring, not the property: initial configuration refused: %v", err)
	}
	store, err := intake.New(1 << 24)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 128})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := processing.OpenWriter(processing.WriterOptions{Directory: directory, QueueBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	f.d = &daemon{path: path, policy: policy, session: "reload-bounds", directory: directory,
		intake: store, gate: gate, output: writer, attached: &reloadBoundsAttachment{},
		plan:            account.Account{Version: account.Version, Session: "reload-bounds", Policy: account.Policy{Revision: policy.Revision, Generation: 1}},
		processingTaken: func(int, fragment.Process, fragment.ConnectionID) { f.taken.Add(1) },
	}
	f.d.startProcessing()
	f.run = f.d.processing
	if f.run == nil || f.run.run == nil {
		t.Fatal("wiring, not the property: daemon did not start its processing run")
	}
	t.Cleanup(func() {
		f.run.final <- processing.Finalization{}
		select {
		case <-f.run.done:
		case <-time.After(5 * time.Second):
			t.Error("processing cleanup did not finish")
		}
	})
	i := admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42, Start: admission.Determinate(7), Generation: 1}
	f.identity = fragment.Identity{Connection: 1, Process: fragment.Process{PID: 42, StartTime: 7}, Instance: i,
		Address: 7, Generation: 1, FirstSeen: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	f.evidence = fragment.Evidence{Identity: &f.identity, Occupancy: 1, Origin: fragment.OriginBirth}
	return f
}

func reloadBoundsWrite(t *testing.T, path string, document map[string]any) {
	t.Helper()
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *reloadBoundsFixture) feed(t *testing.T, dir fragment.Direction, text string) {
	t.Helper()
	d := f.d.gate.Admit(probe.DeliveryTransfer, true)
	if !d.Admitted || d.Slot == nil {
		t.Fatalf("wiring, not the property: source refused: %+v", d)
	}
	slot := &reloadBoundsSlot{Slot: d.Slot}
	one := &f.evidence.Sent
	if dir == fragment.Received {
		one = &f.evidence.Received
	}
	offset := one.Limit
	one.Limit += uint64(len(text))
	one.First = 1
	one.Numbered++
	one.Resolved++
	f.evidence.Through++
	r := fragment.Record{Process: f.identity.Process, Connection: 1, Direction: dir, Sequence: f.evidence.Through,
		Offset: offset, Length: uint32(len(text)), Produced: one.Numbered, Payload: []byte(text),
		At: f.identity.FirstSeen.Add(time.Duration(f.evidence.Through) * time.Millisecond), Evidence: f.evidence, Slot: slot}
	if err := r.Evidenced(); err != nil {
		t.Fatalf("wiring, not the property: invalid capture evidence: %v", err)
	}
	if err := f.d.intake.Write(r); err != nil {
		t.Fatalf("wiring, not the property: input did not reach intake: %v", err)
	}
	f.slots = append(f.slots, slot)
}

func (f *reloadBoundsFixture) await(t *testing.T, why string, ready func() bool) {
	t.Helper()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-f.ctx.Done():
			t.Fatalf("%s: taken=%d worker=%+v intake=%+v gate=%+v", why, f.taken.Load(), f.run.run.Snapshot(), f.d.intake.Stats(), f.d.gate.Snapshot())
		case <-tick.C:
		}
	}
}

func reloadBoundsCase(t *testing.T, additive bool) {
	t.Helper()
	f := newReloadBoundsFixture(t)
	f.feed(t, fragment.Sent, "GET /survives-reload HTTP/1.1\r\nHo")
	f.await(t, "wiring, not the property: half-message never reached a completed worker drain", func() bool {
		return f.taken.Load() == 1 && f.run.run.Snapshot().Pending == 1
	})
	before := f.d.intake.Stats()
	gateBefore := f.d.gate.Snapshot()
	if before.Queued != 0 || before.Leased != 1 || before.Bytes <= 0 || gateBefore.Held != 1 || gateBefore.Charged != 1 || f.slots[0].calls.Load() != 0 {
		t.Fatalf("wiring, not the property: no charged half-message before reload: intake=%+v gate=%+v", before, gateBefore)
	}
	originalPlan, originalGate, originalIntake, originalOutput := f.d.policy.Processing, f.d.gate, f.d.intake, f.d.output
	originalRevision := f.d.policy.Revision
	if additive {
		f.document["watch"] = append(f.document["watch"].([]any), map[string]any{"name": "added", "exe": "/nonexistent/reload-added", "children": "none"})
	} else {
		f.document["remove"] = map[string]any{"headers": []string{"X-Secret"}}
	}
	reloadBoundsWrite(t, f.d.path, f.document)
	candidate, err := loadProcessing(f.d.path)
	if err != nil {
		t.Fatalf("wiring, not the property: candidate refused before reload: %v", err)
	}
	if candidate.Revision == originalRevision {
		t.Fatal("wiring, not the property: reload candidate did not change")
	}
	request := reloadRequest{Revision: candidate.Revision, Resolution: candidate.Approval.Resolve(process.Host{Table: process.TableOf()})}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	result := f.d.reload(time.Now(), body)
	if additive {
		if result.Outcome != "activated" || result.Generation != 2 || len(result.Added) != 1 || result.Added[0] != "added" || f.d.policy.Revision != candidate.Revision {
			t.Fatalf("wiring, not the property: additive reload did not activate the new target: %+v", result)
		}
	} else if result.Outcome != "refused" || !strings.Contains(result.Reason, "changes processing") || f.d.policy.Revision != originalRevision {
		t.Fatalf("wiring, not the property: processing-change reload was not refused without changing policy: %+v", result)
	}
	if f.d.processing != f.run || f.d.policy.Processing != originalPlan || f.d.gate != originalGate || f.d.intake != originalIntake || f.d.output != originalOutput {
		t.Fatal("reload replaced an owner of unfinished processing")
	}
	if after := f.d.intake.Stats(); after != before {
		t.Errorf("reload changed exact retained intake charges: before=%+v after=%+v", before, after)
	}
	if after := f.d.gate.Snapshot(); after != gateBefore || f.slots[0].calls.Load() != 0 {
		t.Errorf("reload refunded unfinished source: before=%+v after=%+v calls=%d", gateBefore, after, f.slots[0].calls.Load())
	}
	f.feed(t, fragment.Sent, "st: example.test\r\n\r\n")
	f.feed(t, fragment.Received, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	f.await(t, "completed reloaded pair did not leave its open connection", func() bool { return f.run.run.Snapshot().Authorized >= 1 })
	if err := f.d.output.Drain(f.ctx); err != nil {
		t.Fatal(err)
	}
	var records []processing.Artifact
	if err := processing.ReadArtifacts(os.DirFS(f.d.directory), func(a processing.Artifact) error { records = append(records, a); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("reload lost or duplicated the one completed exchange: records=%d", len(records))
	}
	a := records[0]
	if a.Record != processing.ArtifactExchange || a.Index == nil || *a.Index != 0 || a.ExchangeID != "1" || a.Reconstruction == nil || len(a.Reconstruction.Exchanges) != 1 {
		t.Fatalf("reloaded pair has wrong identity: %+v", a)
	}
	pair := a.Reconstruction.Exchanges[0]
	if !pair.Complete || pair.Request.Message == nil || pair.Request.Message.Target != "/survives-reload" || pair.Response.Message == nil || pair.Response.Message.Status == nil || *pair.Response.Message.Status != 200 {
		t.Errorf("reload lost or mispaired the half-message: %+v", pair)
	}
	if stats := f.d.intake.Stats(); stats.Bytes != 0 || stats.Leased != 0 || stats.Queued != 0 {
		t.Errorf("completed reload population remains retained: %+v", stats)
	}
	if stats := f.d.gate.Snapshot(); stats.Held != 0 || stats.Charged != 3 || stats.Refunded.Processed != 3 || stats.DoubleRefunds != 0 {
		t.Errorf("reload settlement refund mismatch: %+v", stats)
	}
	for n, slot := range f.slots {
		if got := slot.calls.Load(); got != 1 {
			t.Errorf("event %d refunded %d times, want once", n, got)
		}
	}
}

func TestReloadBoundsAdditiveReloadPreservesOwnedHalfMessage(t *testing.T) { reloadBoundsCase(t, true) }
func TestReloadBoundsRefusedReloadPreservesOwnedHalfMessage(t *testing.T)  { reloadBoundsCase(t, false) }
