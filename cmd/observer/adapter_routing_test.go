package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

type routedAdapter struct {
	name            string
	pid             int32
	requests        []probe.Request
	failure         error
	returnWithError bool
	live            *routedAttachment
}

func (a *routedAdapter) Name() string { return a.name }
func (a *routedAdapter) Inspect(p process.Process) probe.Support {
	return probe.Support{Supported: p.PID == a.pid, Reason: a.name + " support verdict", Runtime: a.name,
		Probes: []probe.Probe{{Symbol: a.name + "_read"}}}
}
func (a *routedAdapter) Attach(r probe.Request, _ probe.Sink) (probe.Attachment, error) {
	a.requests = append(a.requests, r)
	if a.failure != nil && !a.returnWithError {
		return nil, a.failure
	}
	a.live = &routedAttachment{name: a.name}
	return a.live, a.failure
}

type routedAttachment struct {
	name   string
	closes int
}

func (a *routedAttachment) Close() error { a.closes++; return nil }
func (a *routedAttachment) Capability() probe.Capability {
	return probe.Capability{Program: a.name, Payload: true}
}
func (a *routedAttachment) Placements(int32) ([]probe.Placement, error) {
	return []probe.Placement{{Symbol: a.name + "_read", Confirmed: true}}, nil
}

type routingSink struct{}

func (routingSink) Transfer(probe.Transfer) {}
func (routingSink) Closed(probe.Connection) {}

func TestSelectedAdaptersOwnTheirRequestsAndAttestationsInEitherOrder(t *testing.T) {
	self, err := process.Identify(procfs, int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	child, _ := catRunning(t)
	other, err := process.Identify(procfs, int32(child.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	uncovered, _ := catRunning(t)
	unsupported, err := process.Identify(procfs, int32(uncovered.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, reverse := range []bool{false, true} {
		order := "forward"
		if reverse {
			order = "reverse"
		}
		for _, failure := range []string{"none", "first", "second", "second_owned"} {
			t.Run(order+"/"+failure, func(t *testing.T) {
				a := &routedAdapter{name: "alpha", pid: self.PID}
				b := &routedAdapter{name: "beta", pid: other.PID}
				adapters := []probe.Inspector{a, b}
				if reverse {
					adapters = []probe.Inspector{b, a}
				}
				first, second := adapters[0].(*routedAdapter), adapters[1].(*routedAdapter)
				if failure == "first" {
					first.failure = errors.New(first.name + " selected refusal")
				}
				if strings.HasPrefix(failure, "second") {
					second.returnWithError = failure == "second_owned"
					second.failure = errors.New(second.name + " selected refusal")
				}
				catalog, err := probe.NewCatalog(adapters...)
				if err != nil {
					t.Fatal(err)
				}
				for _, p := range []process.Process{self, other} {
					r := catalog.Inspect(p)
					if !r.Supported {
						t.Fatal("wiring: selected process not supported")
					}
				}
				if catalog.Inspect(unsupported).Supported {
					t.Fatal("wiring: unsupported process has an owner")
				}
				resolution := process.Resolution{Selections: []admission.Selection{{ObserverPID: self.PID}, {ObserverPID: other.PID}, {ObserverPID: unsupported.PID}}}
				gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 10})
				if err != nil {
					t.Fatal(err)
				}
				live, observed, err := observe(catalog, resolution, process.TableOf(self, other, unsupported), routingSink{}, gate, nil)
				if len(observed) != 3 {
					t.Fatalf("observed %d processes, want 3", len(observed))
				}
				if observed[2].Outcome != attachment.NotAttached || !strings.Contains(observed[2].Reason, "unsupported") {
					t.Fatalf("unsupported reason: %+v", observed[2])
				}
				if failure != "none" {
					failed := first
					if strings.HasPrefix(failure, "second") {
						failed = second
					}
					if err == nil || !strings.Contains(err.Error(), failed.name+" selected refusal") || live != nil {
						t.Fatalf("selected refusal: live %v, err %v", live, err)
					}
					if strings.HasPrefix(failure, "second") && (first.live == nil || first.live.closes != 1) {
						t.Fatal("already attached owner was not closed exactly once")
					}
					if failure == "second_owned" && (second.live == nil || second.live.closes != 1) {
						t.Fatal("attachment returned with error was not closed")
					}
					if failure == "first" && len(second.requests) != 0 {
						t.Fatal("startup continued after selected adapter failed")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, at := range []*routedAdapter{a, b} {
					if len(at.requests) != 1 || len(at.requests[0].Processes) != 1 || at.requests[0].Processes[0].PID != at.pid || len(at.requests[0].Admit) != 1 || at.requests[0].Admit[0].ObserverPID != at.pid {
						t.Fatalf("adapter %s received another owner's request: %+v", at.name, at.requests)
					}
					if at.requests[0].DeliveryGate != gate {
						t.Fatal("delivery gate changed during routing")
					}
				}
				for i, at := range []*routedAdapter{a, b} {
					if observed[i].Outcome != attachment.Attached || observed[i].Capability.Program != at.name {
						t.Fatalf("owner attribution: %+v", observed[i])
					}
				}
				if err := live.Close(); err != nil {
					t.Fatal(err)
				}
				if err := live.Close(); err != nil {
					t.Fatal(err)
				}
				if a.live.closes != 1 || b.live.closes != 1 {
					t.Fatalf("close calls %d/%d", a.live.closes, b.live.closes)
				}
			})
		}
	}
}
