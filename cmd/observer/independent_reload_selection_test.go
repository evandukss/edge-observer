package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	protected "github.com/evandukss/edge-observer/activation"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// The command, control transport, daemon reload and resolver are real. Probe
// support and the attachment's grant store are doubles: this does not measure
// kernel admission. Access is serialized by the fixture's daemon mutex.
type independentReloadAttachment struct {
	grants []admission.Selection
	writes int
}

func (*independentReloadAttachment) Close() error                 { return nil }
func (*independentReloadAttachment) Capability() probe.Capability { return probe.Capability{} }
func (a *independentReloadAttachment) Admit(r probe.Request) (probe.Added, error) {
	a.writes++
	a.grants = append(a.grants, r.Admit...)
	return probe.Added{Selections: r.Admit}, nil
}
func (a *independentReloadAttachment) Retract(taken []admission.Selection) {
	for _, one := range taken {
		a.grants = slices.DeleteFunc(a.grants, func(s admission.Selection) bool {
			return s.ObserverPID == one.ObserverPID && s.Instance == one.Instance
		})
	}
}

func TestIndependentReloadChurnLeavesSessionAndGrantsUnchanged(t *testing.T) {
	self, err := process.Identify(procfs, int32(os.Getpid()))
	if err != nil || self.StartTime == 0 || self.ArgumentEvidence != process.ArgumentsKnown {
		t.Fatalf("wiring, not property: cannot read stable control process: %+v %v", self, err)
	}
	directory := t.TempDir()
	path := filepath.Join(t.TempDir(), "observer.json")
	kept := map[string]any{"name": "kept", "exe": "/fixture/kept", "children": "none"}
	added := map[string]any{"name": "added", "exe": self.Executable, "args": self.Arguments[1:], "children": "none"}
	write := func(watch ...map[string]any) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"version": "observer.config/1", "output": directory,
			"log": "stdout", "watch": watch, "ignore": []any{}, "libraries": []any{}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(kept)
	current, err := loadProcessing(path)
	if err != nil {
		t.Fatal(err)
	}
	write(kept, added)
	candidate, err := loadProcessing(path)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision == candidate.Revision || current.ProcessingRevision != candidate.ProcessingRevision {
		t.Fatal("wiring, not property: candidate does not add only an observation target")
	}
	attached := &independentReloadAttachment{grants: []admission.Selection{{ObserverPID: 424242}}}
	d := &daemon{policy: current, path: path, session: "0123456789abcdef", attached: attached,
		plan: account.Account{Policy: account.Policy{Revision: current.Revision, Generation: 1}}}
	d.gate, err = probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: uint64(current.Settings.AdmittedEventLimit)})
	if err != nil {
		t.Fatal(err)
	}
	d.verifyParticipants = func(gate *probe.DeliveryGate, participants []process.Process) (protected.Posture, error) {
		if gate != d.gate || len(participants) != 1 || participants[0].PID != self.PID {
			return protected.Posture{}, fmt.Errorf("wiring: wrong gate or control participant")
		}
		return protected.Posture{}, nil
	}
	held, err := acquire(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer held.release()
	if err := held.record(os.Getpid(), d.session); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	requests := 0
	serving := &controller{directory: filepath.Join(directory, sessionsName, d.session)}
	serving.answer = func(kind string, body []byte) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		if kind != "reload" {
			return nil, fmt.Errorf("wiring: unexpected request kind %q", kind)
		}
		var request reloadRequest
		if err := json.Unmarshal(body, &request); err != nil {
			return nil, err
		}
		// Substitute only catalogue support, after the real command has read
		// identity and argv. The stable control must reach the real grant call.
		for pid, reading := range request.Read {
			if pid != self.PID || reading.Exec.StartTime != self.StartTime {
				return nil, fmt.Errorf("wiring: control request carries another process")
			}
			reading.Report = probe.Report{Process: self.Identity(), Supported: true, Adapter: "openssl",
				Support: []probe.Support{{Adapter: "openssl", Supported: true, Reason: "fixture attachment support"}}}
			request.Read[pid] = reading
		}
		body, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}
		return json.Marshal(d.reload(time.Now(), body))
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1)
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-signals:
				serving.serve()
			case <-stop:
				return
			}
		}
	}()
	defer func() { signal.Stop(signals); close(stop); <-stopped }()

	planBefore, err := json.Marshal(d.plan)
	if err != nil {
		t.Fatal(err)
	}
	grantsBefore := slices.Clone(attached.grants)
	processingBefore := d.policy.Processing
	now := time.Unix(700, 0)
	snapshots, reads := 0, 0
	churning := func(approval process.Approval) (process.Resolution, process.Table, error) {
		return approval.ResolveWith(process.ResolutionReader{
			Now: func() time.Time { return now }, Sleep: func(dt time.Duration) { now = now.Add(dt) },
			Snapshot: func(time.Time) (process.Host, error) {
				snapshots++
				if snapshots > 5 {
					t.Fatal("property: churning reload exceeded the rebuild bound")
				}
				p := self
				p.StartTime += uint64(snapshots)
				p.ArgumentEvidence, p.Arguments = process.ArgumentsUndetermined, nil
				return process.Host{Table: process.TableOf(p)}, nil
			},
			Process: func(pid int32) (process.Process, error) {
				reads++
				p := self
				p.StartTime += uint64(snapshots + 1)
				return p, nil
			},
		})
	}
	var stdout bytes.Buffer
	err = reloadCommandWithResolver(path, &stdout, churning)
	if reads == 0 {
		t.Fatal("wiring, not property: reload never read the changing candidate")
	}
	if err == nil || !strings.Contains(err.Error(), strconv.Itoa(int(self.PID))) || snapshots != 4 || reads != 4 {
		t.Errorf("property: continuous churn must exhaust three rebuilds naming its candidate: snapshots=%d reads=%d error=%v", snapshots, reads, err)
	}
	mu.Lock()
	planAfter, marshalErr := json.Marshal(d.plan)
	if marshalErr != nil {
		t.Error(marshalErr)
	}
	if requests != 0 || attached.writes != 0 || !reflect.DeepEqual(attached.grants, grantsBefore) ||
		!bytes.Equal(planBefore, planAfter) || d.policy.Revision != current.Revision || d.policy.Processing != processingBefore || stdout.Len() != 0 {
		t.Errorf("property: refused churn contacted or changed the running session: requests=%d writes=%d grants=%+v generation=%d output=%q", requests, attached.writes, attached.grants, d.plan.Policy.Generation, stdout.String())
	}
	mu.Unlock()

	// Construct the earlier selected namespace while the live final reader still
	// observes this process. This exercises the production closing check and
	// error propagation, without claiming a live PID or namespace reuse.
	identityCalls := 0
	mixedIdentity := func(approval process.Approval) (process.Resolution, process.Table, error) {
		identityCalls++
		p := self
		p.Namespace.Inode++
		table := process.TableOf(p)
		resolution := approval.Resolve(process.Host{Table: table})
		if len(resolution.Selections) != 1 || resolution.Selections[0].Instance.Namespace == self.Namespace {
			t.Fatal("wiring, not property: selected namespace mismatch was not constructed")
		}
		return resolution, table, resolution.Err()
	}
	stdout.Reset()
	err = reloadCommandWithResolver(path, &stdout, mixedIdentity)
	if identityCalls != 1 {
		t.Fatal("wiring, not property: command did not consume the mixed-identity selection")
	}
	if err == nil || !strings.Contains(err.Error(), strconv.Itoa(int(self.PID))) {
		t.Errorf("property: assembled reading with another selected namespace was accepted: %v", err)
	}
	mu.Lock()
	identityPlan, identityMarshalErr := json.Marshal(d.plan)
	if identityMarshalErr != nil {
		t.Error(identityMarshalErr)
	}
	if requests != 0 || attached.writes != 0 || !reflect.DeepEqual(attached.grants, grantsBefore) ||
		!bytes.Equal(planBefore, identityPlan) || d.policy.Revision != current.Revision || stdout.Len() != 0 {
		t.Errorf("property: final identity refusal did not stop before request and grant mutation: requests=%d writes=%d grants=%+v generation=%d", requests, attached.writes, attached.grants, d.plan.Policy.Generation)
	}
	mu.Unlock()

	stable := func(approval process.Approval) (process.Resolution, process.Table, error) {
		return approval.ResolveWith(process.ResolutionReader{
			Snapshot: func(time.Time) (process.Host, error) { return process.Host{Table: process.TableOf(self)}, nil },
			Process:  func(int32) (process.Process, error) { return self, nil },
		})
	}
	stdout.Reset()
	if err := reloadCommandWithResolver(path, &stdout, stable); err != nil {
		t.Fatalf("wiring, not property: stable control command failed: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 || attached.writes != 1 || len(attached.grants) != 2 ||
		attached.grants[1].ObserverPID != self.PID || d.plan.Policy.Generation != 2 || d.policy.Revision != candidate.Revision {
		t.Fatalf("wiring, not property: stable command did not reach session and grant write exactly once: requests=%d writes=%d grants=%+v generation=%d", requests, attached.writes, attached.grants, d.plan.Policy.Generation)
	}
	t.Log("REACHED stable command crossed control transport, activated generation 2, wrote one grant; attachment support/store are doubles")
}

// This constructed procfs retains captured kernel stat/status/cgroup/argv and
// the real PID namespace inode. Only the field named by a case is changed.
// It proves a closing-reader verdict, not a live kernel reuse occurrence.
func independentReloadIdentityTree(t *testing.T) (string, process.Process, probe.Reading) {
	t.Helper()
	root := t.TempDir()
	pid := int32(os.Getpid())
	dir := filepath.Join(root, strconv.Itoa(int(pid)))
	if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"stat", "status", "cgroup", "cmdline"} {
		body, err := os.ReadFile(filepath.Join("/proc/self", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/proc/self/ns/pid", filepath.Join(dir, "ns", "pid")); err != nil {
		t.Fatal(err)
	}
	p, err := process.Identify(root, pid)
	if err != nil || p.StartTime == 0 || !p.Namespace.Known() || p.NamespacePID <= 0 || p.ArgumentEvidence != process.ArgumentsKnown {
		t.Fatalf("wiring, not property: captured identity is not determined: %+v %v", p, err)
	}
	execution, err := process.ReadExec(root, pid)
	if err != nil || execution.StartTime != p.StartTime || execution.ArgumentEvidence != process.ArgumentsKnown || execution.Cmdline == "" {
		t.Fatalf("wiring, not property: captured execution does not join process: %+v %v", execution, err)
	}
	return root, p, probe.Reading{Exec: execution}
}

func TestIndependentReloadClosingIdentityRejectsMixedReadings(t *testing.T) {
	for _, scenario := range []string{"stable", "same_executable_new_birth", "unknown_final_birth", "selected_namespace_mismatch", "unknown_final_namespace"} {
		t.Run(scenario, func(t *testing.T) {
			root, p, reading := independentReloadIdentityTree(t)
			if why, same := reloadIdentityUnchanged(root, p, reading); !same {
				t.Fatalf("wiring, not property: unchanged captured identity refused: %s", why)
			}
			dir := filepath.Join(root, strconv.Itoa(int(p.PID)))
			switch scenario {
			case "same_executable_new_birth":
				path := filepath.Join(dir, "stat")
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				end := strings.LastIndexByte(string(body), ')')
				if end < 0 {
					t.Fatal("wiring, not property: captured stat has no comm terminator")
				}
				fields := strings.Fields(string(body[end+1:]))
				if len(fields) <= 19 {
					t.Fatal("wiring, not property: captured stat lacks field 22")
				}
				fields[19] = strconv.FormatUint(p.StartTime+1, 10)
				if err := os.WriteFile(path, []byte(string(body[:end+1])+" "+strings.Join(fields, " ")+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				after, err := process.Identify(root, p.PID)
				if err != nil || after.StartTime != p.StartTime+1 || after.Executable != p.Executable ||
					!slices.Equal(after.Arguments, p.Arguments) || after.Namespace != p.Namespace || after.NamespacePID != p.NamespacePID {
					t.Fatalf("wiring, not property: successor differs by more than birth: %+v %v", after, err)
				}
			case "unknown_final_birth":
				if err := os.Remove(filepath.Join(dir, "stat")); err != nil {
					t.Fatal(err)
				}
			case "selected_namespace_mismatch":
				p.Namespace.Inode++
			case "unknown_final_namespace":
				if err := os.Remove(filepath.Join(dir, "ns", "pid")); err != nil {
					t.Fatal(err)
				}
			}
			// The old closing comparison sees the same executable in EVERY case.
			exe, err := os.Readlink(filepath.Join(dir, "exe"))
			if err != nil || exe != p.Executable {
				t.Fatalf("wiring, not property: executable-only control differs: %s %v", exe, err)
			}
			why, same := reloadIdentityUnchanged(root, p, reading)
			if scenario == "stable" {
				if !same || why != "" {
					t.Fatalf("property: stable captured identity refused: %s", why)
				}
			} else if same || why == "" {
				t.Fatalf("property: %s accepted a mixed or unknown final identity: same=%t reason=%q", scenario, same, why)
			}
		})
	}
}
