package extension_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/internal/extensiontest"
	"github.com/evandukss/edge-observer/internal/workload"
	"github.com/evandukss/edge-observer/processing"
)

// An extension runs in a process group of its own, with a core limit of one
// byte soft and hard, a parent-death signal, the highest out-of-memory score,
// and no descriptor of the observer's beyond its three pipes: not one opened
// without close-on-exec, and not another extension's pipes.
func TestAnExtensionHoldsItsOwnGroupItsPipesAndNothingElseOfTheObservers(t *testing.T) {
	directory := t.TempDir()
	leaked := filepath.Join(directory, "opened-without-close-on-exec")
	fd, err := syscall.Open(leaked, syscall.O_CREAT|syscall.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	if flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0); errno != 0 ||
		flags&syscall.FD_CLOEXEC != 0 {
		t.Fatalf("wiring, not the property: descriptor %d is close-on-exec, so it tests nothing", fd)
	}
	first, second := filepath.Join(directory, "first.json"), filepath.Join(directory, "second.json")
	plan := planOf(t, "",
		entry{name: "first", fields: []string{config.FieldRequestLine}, does: extensiontest.Config{Report: first}},
		entry{name: "second", fields: []string{config.FieldRequestLine}, does: extensiontest.Config{Report: second}})
	started(t, plan, 1<<26, nil).ready(t, plan)
	reports := map[string]extensiontest.Held{}
	for name, path := range map[string]string{"first": first, "second": second} {
		held, err := extensiontest.ReadHeld(path)
		if err != nil {
			t.Fatalf("wiring, not the property: %v", err)
		}
		reports[name] = held
	}
	pipes := func(h extensiontest.Held) []string {
		var own []string
		for _, n := range []string{"0", "1", "2"} {
			if strings.HasPrefix(h.FDs[n], "pipe:") {
				own = append(own, h.FDs[n])
			}
		}
		return own
	}
	for name, h := range reports {
		if h.PGID != h.PID || h.PID == 0 {
			t.Errorf("%s: process group %d, pid %d: not a group of its own", name, h.PGID, h.PID)
		}
		if len(h.Core) != 2 || h.Core[0] != 1 || h.Core[1] != 1 {
			t.Errorf("%s: core limit %v, want 1 soft and 1 hard", name, h.Core)
		}
		if h.PDeathSig != int(syscall.SIGKILL) {
			t.Errorf("%s: parent-death signal %d, want SIGKILL", name, h.PDeathSig)
		}
		if h.OOMScoreAdj != "1000" {
			t.Errorf("%s: oom_score_adj %q, want 1000", name, h.OOMScoreAdj)
		}
		if len(pipes(h)) != 3 {
			t.Errorf("%s: standard streams %v are not three pipes", name, h.FDs)
		}
		for n, target := range h.FDs {
			if target == leaked {
				t.Errorf("%s: descriptor %s is the observer's %s, opened without close-on-exec", name, n, leaked)
			}
		}
	}
	for _, pair := range [][2]string{{"first", "second"}, {"second", "first"}} {
		for n, target := range reports[pair[0]].FDs {
			if n != "0" && n != "1" && n != "2" && strings.HasPrefix(target, "pipe:") {
				for _, other := range pipes(reports[pair[1]]) {
					if target == other {
						t.Errorf("%s holds %s's pipe %s as descriptor %s", pair[0], pair[1], other, n)
					}
				}
			}
		}
	}
}

// An exchange's deadline starts when it is queued, before it is written: a
// message whose write the extension held back for almost the whole timeout
// is due when the timeout has passed since it was queued, not since it was
// written.
func TestAnExchangeDeadlineStartsWhenItIsQueuedNotWhenItIsWritten(t *testing.T) {
	clock := extensiontest.NewManual(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	directory := t.TempDir()
	hold, received := filepath.Join(directory, "hold"), filepath.Join(directory, "received")
	plan := planOf(t, "", entry{name: "slow", fields: []string{config.FieldResponseBody},
		does: extensiontest.Config{HoldInput: hold, NeverAnswer: true, Received: received}})
	s := started(t, plan, 1<<26, clock).ready(t, plan)
	// A body far over a pipe's buffer, so the write blocks until the
	// extension reads.
	s.feed(t, generate(t, workload.Shape{Connections: 1, Exchanges: 1, ResponseBodyBytes: 400_000, Seed: 9}))
	// Admitted at this reading of the clock, which does not move until the
	// supervisor waits on a timer due a timeout from now: the count of
	// issued ids moves before the call is admitted, so it cannot say this.
	timeout := 2000 * time.Millisecond
	waitArmed(t, clock, timeout, "the exchange's deadline")
	clock.Advance(timeout - time.Millisecond)
	if err := os.WriteFile(hold, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		content, _ := os.ReadFile(received)
		if strings.Contains(string(content), `"type":"exchange"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("wiring, not the property: the extension never read the exchange")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if retired := s.events.retired(); len(retired) != 0 {
		t.Fatalf("wiring, not the property: retired before its deadline: %+v", retired)
	}
	clock.Advance(time.Millisecond)
	retired, _ := s.events.next(t, 0, func(e extension.Event) bool { return e.Kind == extension.Retired })
	if retired.Cause != extension.Timeout {
		t.Fatalf("retired as %q, want %s", retired.Cause, extension.Timeout)
	}
	o := s.finish(t)
	if c := counts(t, o, "slow"); c.FailedBy[extension.Timeout] != 1 || c.RetiredBy[extension.Timeout] != 1 {
		t.Errorf("failed as timeout %d, retired as timeout %d, want 1 and 1", c.FailedBy[extension.Timeout],
			c.RetiredBy[extension.Timeout])
	}
	conserved(t, o)
}

// waitArmed waits until the supervisor waits on clock for d from its current
// reading.
func waitArmed(t *testing.T, clock *extensiontest.Manual, d time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !clock.Armed(d) {
		if time.Now().After(deadline) {
			t.Fatalf("wiring, not the property: nothing waited on %s within 30s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func (e *events) retired() []extension.Event {
	var out []extension.Event
	for _, one := range e.snapshot() {
		if one.Kind == extension.Retired {
			out = append(out, one)
		}
	}
	return out
}

// A generation that never answers ready is retired at the start-up bound,
// counted from start being written, and the next starts after the backoff.
func TestAGenerationThatNeverAnswersReadyIsRetiredAtTheStartupBound(t *testing.T) {
	clock := extensiontest.NewManual(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	plan := planOf(t, "", entry{name: "mute", fields: []string{config.FieldRequestLine},
		does: extensiontest.Config{NoReady: true}})
	s := started(t, plan, 1<<26, clock)
	// Start is written at this reading of the clock, which does not move
	// until the supervisor waits on the start-up bound from now. The
	// extension reading start can come before the observer records the
	// write, so the extension's own record cannot say this.
	waitArmed(t, clock, extension.StartupBound, "the start-up bound")
	clock.Advance(extension.StartupBound - time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	if retired := s.events.retired(); len(retired) != 0 {
		t.Fatalf("retired before the start-up bound: %+v", retired)
	}
	clock.Advance(time.Millisecond)
	retired, _ := s.events.next(t, 0, func(e extension.Event) bool { return e.Kind == extension.Retired })
	if retired.Cause != extension.StartupTimeout || retired.Backoff != extension.BackoffMin {
		t.Fatalf("retired as %q with a %v wait, want %s and %v", retired.Cause, retired.Backoff,
			extension.StartupTimeout, extension.BackoffMin)
	}
}

// An orderly stop of an extension that ignores shutdown and SIGTERM, and that
// started a process which ignores SIGTERM too, leaves neither running: each
// grace passes, then SIGKILL goes to the whole group.
func TestAnOrderlyStopKillsAnExtensionThatIgnoresTermWithItsGroup(t *testing.T) {
	report := filepath.Join(t.TempDir(), "report.json")
	plan := planOf(t, "", entry{name: "stubborn", fields: []string{config.FieldRequestLine},
		does: extensiontest.Config{Report: report, Child: true, IgnoreTerm: true, HangOnShutdown: true}})
	s := started(t, plan, 1<<26, nil).ready(t, plan)
	held, err := extensiontest.ReadHeld(report)
	if err != nil || held.Child == 0 {
		t.Fatalf("wiring, not the property: no child was started: %+v %v", held, err)
	}
	if !alive(held.Child) || !alive(held.PID) {
		t.Fatalf("wiring, not the property: the extension or its child is not running before the stop")
	}
	began := time.Now()
	s.finish(t)
	took := time.Since(began)
	for name, pid := range map[string]int{"the extension": held.PID, "its child": held.Child} {
		gone := false
		for range 200 {
			if !alive(pid) {
				gone = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !gone {
			t.Errorf("%s, pid %d, is still running after the stop", name, pid)
		}
	}
	if took < 2*extension.TerminationGrace || took > 2*extension.TerminationGrace+10*time.Second {
		t.Errorf("the stop took %v, want both graces, %v, and not much more", took, 2*extension.TerminationGrace)
	}
}

// alive is a process that exists and is not a zombie.
func alive(pid int) bool {
	content, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(content)[strings.LastIndexByte(string(content), ')')+1:])
	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}

// Standard error is copied into the log at most stderr_lines_per_second
// lines a second, each cut at stderr_line_bytes and marked cut; the rest are
// counted and dropped. The clock does not move, so one second's worth is all
// there is.
func TestStandardErrorIsCopiedWithinItsBounds(t *testing.T) {
	clock := extensiontest.NewManual(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	plan := planOf(t, "", entry{name: "noisy", fields: []string{config.FieldRequestLine},
		does: extensiontest.Config{StderrLines: 30, StderrLineBytes: 2000}})
	s := started(t, plan, 1<<26, clock).ready(t, plan)
	o := s.waitFor(t, "every line of standard error read", func(o processing.Outcome) bool {
		return len(o.Extensions) == 1 && o.Extensions[0].StderrDropped == 30-extension.StderrLinesPerSecond
	})
	var copied []extension.Event
	for _, e := range s.events.snapshot() {
		if e.Kind == extension.Stderr {
			copied = append(copied, e)
		}
	}
	if len(copied) != extension.StderrLinesPerSecond {
		t.Fatalf("%d lines copied, want %d: %+v", len(copied), extension.StderrLinesPerSecond, o.Extensions[0])
	}
	for _, e := range copied {
		if !e.Cut || e.Line != strings.Repeat("e", extension.StderrLineBytes) {
			t.Errorf("a %d byte line copied as %d bytes, cut %v, want %d and cut", 2000, len(e.Line), e.Cut,
				extension.StderrLineBytes)
		}
	}
}

// While one connection waits on an extension, a worker goes on writing
// others: with one worker, a connection whose answer is held back does not
// hold back the next connection's lines.
func TestOtherConnectionsAreWrittenWhileOneWaitsOnAnExtension(t *testing.T) {
	directory := t.TempDir()
	release, received := filepath.Join(directory, "release"), filepath.Join(directory, "received")
	plan := planOf(t, "", entry{name: "holding", fields: []string{config.FieldRequestLine},
		does: extensiontest.Config{HoldTarget: "/items/0/0", Release: release, Received: received}})
	s := startedWith(t, plan, 1<<26, nil, 1).ready(t, plan)
	w := generate(t, workload.Shape{Connections: 2, Exchanges: 2, Seed: 10})
	s.feed(t, w)
	s.waitFor(t, "the second connection's lines", func(o processing.Outcome) bool { return o.Written == 3 })
	if o := s.run.Snapshot(); o.Extensions[0].Pending != 2 || o.Pending != 1 {
		t.Fatalf("wiring, not the property: the first connection is not waiting on the extension: %+v", o)
	}
	// One outstanding exchange per connection: the first connection's second
	// exchange is not sent while its first waits.
	content, _ := os.ReadFile(received)
	if !strings.Contains(string(content), "/items/0/0") || strings.Contains(string(content), "/items/0/1") {
		t.Fatalf("while the first exchange waits, the extension received:\n%s", content)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	o := s.finish(t)
	if o.Written != 6 {
		t.Fatalf("written %d lines, want both connections' 6", o.Written)
	}
	conserved(t, o)
}

func TestACommandThatCannotStartIsRetiredAsStartFailed(t *testing.T) {
	clock := extensiontest.NewManual(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	directory := t.TempDir()
	command := filepath.Join(directory, "extension")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	document := `{"version": "observer.config/1", "output": "/var/lib/observer", ` +
		`"watch": [{"name": "api", "exe": "/usr/bin/php"}], "extensions": [{"name": "gone", "command": [` +
		strconv.Quote(command) + `], "fields": ["request.line"], "timeout_ms": 2000}]}`
	compiled, findings := config.Compile([]byte(document), "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: %+v", findings)
	}
	if err := os.Remove(command); err != nil {
		t.Fatal(err)
	}
	s := started(t, compiled.Plan, 1<<26, clock)
	retired, _ := s.events.next(t, 0, func(e extension.Event) bool { return e.Kind == extension.Retired })
	if retired.Cause != extension.StartFailed || retired.Backoff != extension.BackoffMin || retired.PID != 0 {
		t.Fatalf("retired as %q with a %v wait and pid %d, want %s, %v and no process", retired.Cause, retired.Backoff,
			retired.PID, extension.StartFailed, extension.BackoffMin)
	}
	if c := counts(t, s.run.Snapshot(), "gone"); c.RetiredBy[extension.StartFailed] != 1 || c.RetiredBy[extension.Crash] != 0 {
		t.Fatalf("retired_by %v, want one start_failed and no crash", c.RetiredBy)
	}
}

// A connection holding more intake bytes than an extension's waiting-byte
// bound - half the intake allowance over the extensions - skips it at once as
// busy rather than waiting on it.
func TestAConnectionOverTheWaitingByteBoundSkipsAsBusy(t *testing.T) {
	const limit = 64 << 10
	plan := planOf(t, "", entry{name: "bounded", fields: []string{config.FieldRequestLine}})
	store, err := intake.New(limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	s := startedOn(t, plan, 1<<26, nil, 1, store).ready(t, plan)
	w := generate(t, workload.Shape{Connections: 1, Exchanges: 2, ResponseBodyBytes: 20 << 10, Seed: 14})
	if n, err := w.Write(store); err != nil || n != len(w.Entries) {
		t.Fatalf("wiring, not the property: %d of %d entries reached the intake: %v", n, len(w.Entries), err)
	}
	if held := store.Stats().Bytes; held <= extension.WaitingBytes(limit, 1) {
		t.Fatalf("wiring, not the property: the connection holds %d intake bytes, within the %d byte bound", held,
			extension.WaitingBytes(limit, 1))
	}
	s.run.Route()
	o := s.finish(t)
	if c := counts(t, o, "bounded"); c.FailedBy[extension.Busy] != 2 || c.Unchanged != 0 {
		t.Errorf("busy %d of 2, unchanged %d", c.FailedBy[extension.Busy], c.Unchanged)
	}
	conserved(t, o)
}

// An extension holds in_flight exchanges outstanding at once, 4096, and the
// next one offered while they are skips it at once as busy. Every connection
// ending together is a burst: the one a session's end makes of every open
// connection.
func TestAnExtensionTakes4096ExchangesAtOnceAndTheNextSkipsAsBusy(t *testing.T) {
	const bound, beyond = 4096, 6
	directory := t.TempDir()
	release, received := filepath.Join(directory, "release"), filepath.Join(directory, "received")
	plan := planOf(t, "", entry{name: "holding", fields: []string{config.FieldRequestLine}, timeout: 60_000,
		does: extensiontest.Config{HoldTarget: "/items/", Release: release, Received: received}})
	s := started(t, plan, 1<<26, nil).ready(t, plan)
	const connections = bound + beyond
	s.feed(t, generate(t, workload.Shape{Connections: connections, Exchanges: 1, Seed: 15}))
	s.waitFor(t, "every connection dispatched", func(o processing.Outcome) bool {
		return len(o.Extensions) == 1 && o.Extensions[0].Considered == connections &&
			o.Extensions[0].Pending+o.Extensions[0].Failed == connections
	})
	// The guard: the extension really holds this many exchanges, sent and
	// unanswered, while the rest skipped it.
	deadline := time.Now().Add(60 * time.Second)
	for {
		content, _ := os.ReadFile(received)
		sent := strings.Count(string(content), `"type":"exchange"`)
		o := s.run.Snapshot()
		if sent == bound && o.Extensions[0].Pending == bound {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("held %d exchanges sent and %d pending; want %d of each before anything is released: %+v",
				sent, o.Extensions[0].Pending, bound, o.Extensions[0])
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.WriteFile(release, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	o := s.finish(t)
	if c := counts(t, o, "holding"); c.FailedBy[extension.Busy] != beyond || c.Unchanged != bound {
		t.Errorf("busy %d, unchanged %d; want %d and %d", c.FailedBy[extension.Busy], c.Unchanged, beyond, bound)
	}
	conserved(t, o)
}
