package process_test

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/process"
)

// These are readings at the public resolver boundary, not a model of procfs.
// Namespace, liveness and probe support are deliberately outside this fixture.
func independentSelectionProcess(pid int32, exe string) process.Process {
	return process.Process{PID: pid, NamespacePID: pid, StartTime: uint64(pid),
		Executable: exe, Arguments: []string{exe}, ArgumentEvidence: process.ArgumentsKnown}
}

func independentSelectionPIDs(r process.Resolution) []int32 {
	ids := make([]int32, 0, len(r.Selections))
	for _, s := range r.Selections {
		ids = append(ids, s.ObserverPID)
	}
	slices.Sort(ids)
	return ids
}

func independentSelectionUnknown(p process.Process) process.Process {
	p.Arguments = nil
	p.ArgumentEvidence = process.ArgumentsUndetermined
	return p
}

func TestIndependentSelectionRebuildsAllSelectionFacts(t *testing.T) {
	for _, fact := range []string{"listener", "ancestor", "exclusion", "boot", "prepared_interface"} {
		for _, change := range []string{"exec", "exit"} {
			t.Run(fact+"/"+change, func(t *testing.T) {
				trigger := independentSelectionProcess(101, "/fixture/trigger")
				chosen := independentSelectionProcess(202, "/fixture/service")
				parent := independentSelectionProcess(303, "/fixture/parent")
				approval := process.Approval{Rules: []process.Rule{
					{Name: "trigger", Executable: trigger.Executable, Mode: admission.ModeNone},
				}}
				oldHost := process.Host{Table: process.TableOf(independentSelectionUnknown(trigger), chosen, parent), Boot: "boot-old"}
				newHost := process.Host{Table: process.TableOf(chosen, parent), Boot: "boot-new"}
				listener := process.Listener{Inode: 77, Port: 8443, Address: netip.MustParseAddr("192.0.2.10")}
				switch fact {
				case "listener":
					approval.Rules = append(approval.Rules, process.Rule{Name: "service", Port: 8443, Mode: admission.ModeNone})
					oldHost.Table = oldHost.Table.WithListeners(process.Listeners{Sockets: []process.ListeningSocket{{Listener: listener, Owners: []int32{303}}}})
					newHost.Table = newHost.Table.WithListeners(process.Listeners{Sockets: []process.ListeningSocket{{Listener: listener, Owners: []int32{202}}}})
				case "ancestor":
					approval.Rules = append(approval.Rules, process.Rule{Name: "parent", Executable: parent.Executable, Mode: admission.ModeExisting})
					chosen.PPID = parent.PID
					newHost.Table = process.TableOf(chosen, parent)
				case "exclusion":
					approval.Rules = append(approval.Rules, process.Rule{Name: "service", Executable: chosen.Executable, Mode: admission.ModeNone})
					approval.Exclusions = []process.Rule{{Executable: parent.Executable}}
					oldChild := chosen
					oldChild.PPID = parent.PID
					oldHost.Table = process.TableOf(independentSelectionUnknown(trigger), oldChild, parent)
				case "boot":
					approval.Rules = append(approval.Rules, process.Rule{Name: "service", PID: &process.PIDGuard{PID: chosen.PID, Start: chosen.StartTime, Boot: "boot-new"}, Mode: admission.ModeNone})
				case "prepared_interface":
					approval.Rules = append(approval.Rules, process.Rule{Name: "service", Port: 8443, Interface: "fixture0", Mode: admission.ModeNone})
					listeners := process.Listeners{Sockets: []process.ListeningSocket{{Listener: listener, Owners: []int32{202}}}}
					oldHost.Table = oldHost.Table.WithListeners(listeners)
					newHost.Table = newHost.Table.WithListeners(listeners)
					oldHost.Interfaces = func(string) ([]netip.Prefix, error) {
						return []netip.Prefix{netip.MustParsePrefix("192.0.2.11/24")}, nil
					}
					newHost.Interfaces = func(string) ([]netip.Prefix, error) {
						return []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")}, nil
					}
				}
				want := []int32{202}
				if fact == "ancestor" {
					want = []int32{202, 303}
				}
				if got := independentSelectionPIDs(approval.Resolve(newHost)); !slices.Equal(got, want) {
					t.Fatalf("wiring, not property: stable NEW fixture selects %v, want %v", got, want)
				}
				if slices.Equal(independentSelectionPIDs(approval.Resolve(oldHost)), want) {
					t.Fatal("wiring, not property: old facts do not distinguish the selection")
				}
				now := time.Unix(100, 0)
				snapshots, reads := 0, 0
				got, table, err := approval.ResolveWith(process.ResolutionReader{
					Now: func() time.Time { return now }, Sleep: func(d time.Duration) { now = now.Add(d) },
					Snapshot: func(deadline time.Time) (process.Host, error) {
						snapshots++
						if snapshots == 1 {
							return oldHost, nil
						}
						if snapshots > 2 {
							t.Fatal("property: stable rebuilt snapshot was rebuilt again")
						}
						return newHost, nil
					},
					Process: func(pid int32) (process.Process, error) {
						reads++
						if pid != trigger.PID {
							t.Fatalf("wiring, not property: unexpected reread pid %d", pid)
						}
						if change == "exit" {
							return process.Process{}, os.ErrNotExist
						}
						changed := trigger
						changed.Executable = "/fixture/replaced"
						return changed, nil
					},
				})
				if reads == 0 {
					t.Fatal("wiring, not property: changed candidate was never reread")
				}
				if err != nil || snapshots != 2 || !slices.Equal(independentSelectionPIDs(got), want) {
					t.Fatalf("property: complete rebuild after %s must use new %s: error=%v snapshots=%d selected=%v want=%v", change, fact, err, snapshots, independentSelectionPIDs(got), want)
				}
				if !reflect.DeepEqual(table.All(), newHost.Table.All()) {
					t.Fatal("property: returned table retains an old process or old process facts")
				}
			})
		}
	}
}

func TestIndependentSelectionThirdRebuildAndFourthRefusal(t *testing.T) {
	for _, changes := range []int{0, 1, 3, 4} {
		t.Run(fmt.Sprintf("changes_%d", changes), func(t *testing.T) {
			p := independentSelectionProcess(411, "/fixture/churn")
			a := process.Approval{Rules: []process.Rule{{Executable: p.Executable}}}
			now := time.Unix(200, 0)
			snapshots, reads := 0, 0
			got, _, err := a.ResolveWith(process.ResolutionReader{
				Now: func() time.Time { return now }, Sleep: func(d time.Duration) { now = now.Add(d) },
				Snapshot: func(time.Time) (process.Host, error) {
					snapshots++
					if snapshots > 6 {
						t.Fatal("property: rebuild count is unbounded")
					}
					q := p
					q.StartTime += uint64(snapshots)
					if snapshots <= changes {
						q = independentSelectionUnknown(q)
					}
					return process.Host{Table: process.TableOf(q)}, nil
				},
				Process: func(int32) (process.Process, error) {
					reads++
					q := p
					q.StartTime += uint64(snapshots + 1)
					return q, nil
				},
			})
			if changes > 0 && reads == 0 {
				t.Fatal("wiring, not property: churn never reached a reread")
			}
			if changes <= 3 {
				if err != nil || snapshots != changes+1 || !slices.Equal(independentSelectionPIDs(got), []int32{p.PID}) {
					t.Fatalf("property: %d rebuilds must settle: error=%v snapshots=%d selections=%v", changes, err, snapshots, independentSelectionPIDs(got))
				}
			} else if err == nil || snapshots != 4 || len(got.Selections) != 0 || !strings.Contains(err.Error(), "411") {
				t.Fatalf("property: fourth required rebuild must refuse naming candidate 411: error=%v snapshots=%d selections=%v", err, snapshots, independentSelectionPIDs(got))
			}
		})
	}
}

func TestIndependentSelectionOuterDeadlineIsShared(t *testing.T) {
	p := independentSelectionProcess(511, "/fixture/clock")
	a := process.Approval{Rules: []process.Rule{{Executable: p.Executable}}}
	now := time.Unix(300, 0)
	var deadlines []time.Time
	snapshots, reads := 0, 0
	got, _, err := a.ResolveWith(process.ResolutionReader{
		Now: func() time.Time { return now }, Sleep: func(d time.Duration) { now = now.Add(d) },
		Snapshot: func(deadline time.Time) (process.Host, error) {
			snapshots++
			deadlines = append(deadlines, deadline)
			q := p
			q.StartTime += uint64(snapshots)
			if snapshots > 1 {
				now = now.Add(400 * time.Millisecond)
			}
			if snapshots < 4 {
				q = independentSelectionUnknown(q)
			}
			return process.Host{Table: process.TableOf(q)}, nil
		},
		Process: func(int32) (process.Process, error) {
			reads++
			q := p
			q.StartTime += uint64(snapshots + 1)
			return q, nil
		},
	})
	if reads == 0 {
		t.Fatal("wiring, not property: change was never observed")
	}
	if snapshots != 4 {
		t.Fatalf("property: expected three rebuilds reaching outer expiry, got %d snapshots (%v)", snapshots, err)
	}
	if !deadlines[0].IsZero() || !deadlines[1].Equal(time.Unix(301, 0)) || !deadlines[2].Equal(deadlines[1]) || !deadlines[3].Equal(deadlines[1]) {
		t.Fatalf("property: outer second was not anchored once at first change: %v", deadlines)
	}
	if err == nil || len(got.Selections) != 0 || !strings.Contains(err.Error(), "511") {
		t.Fatalf("property: late stable snapshot must refuse naming 511: result=%+v error=%v", got, err)
	}
}

func TestIndependentSelectionExpiryDuringInnerWork(t *testing.T) {
	for _, stage := range []string{"wait", "read"} {
		t.Run(stage, func(t *testing.T) {
			p := independentSelectionProcess(611, "/fixture/inner")
			a := process.Approval{Rules: []process.Rule{{Executable: p.Executable}}}
			now := time.Unix(400, 0)
			outer := now.Add(time.Second)
			snapshots, reads, sleeps := 0, 0, 0
			var slept time.Duration
			got, _, err := a.ResolveWith(process.ResolutionReader{
				Now:   func() time.Time { return now },
				Sleep: func(d time.Duration) { sleeps++; slept += d; now = now.Add(d) },
				Snapshot: func(time.Time) (process.Host, error) {
					snapshots++
					q := independentSelectionUnknown(p)
					q.StartTime += uint64(snapshots)
					if snapshots > 1 {
						now = outer.Add(-500 * time.Microsecond)
					}
					return process.Host{Table: process.TableOf(q)}, nil
				},
				Process: func(int32) (process.Process, error) {
					reads++
					q := p
					q.StartTime += 2
					if reads == 1 {
						return q, nil
					}
					if stage == "read" {
						now = outer.Add(time.Millisecond)
						return q, nil
					}
					return independentSelectionUnknown(q), nil
				},
			})
			if snapshots < 2 || reads < 2 {
				t.Fatalf("wiring, not deadline property: inner stage never reached, snapshots=%d reads=%d error=%v", snapshots, reads, err)
			}
			if err == nil || len(got.Selections) != 0 || !strings.Contains(err.Error(), "611") {
				t.Errorf("property: expired %s must refuse naming 611: result=%+v error=%v", stage, got, err)
			}
			if reads != 2 || snapshots != 2 {
				t.Errorf("property: a new read began after outer expiry: snapshots=%d reads=%d", snapshots, reads)
			}
			if stage == "wait" && (sleeps != 1 || slept != 500*time.Microsecond) {
				t.Errorf("property: inner wait must clamp to the remaining outer budget: sleeps=%d total=%v", sleeps, slept)
			}
		})
	}
}

func TestIndependentSelectionUncertainExclusionNeverAdmits(t *testing.T) {
	for _, evidence := range []string{"unknown", "unreadable", "prohibited", "allowed"} {
		t.Run(evidence, func(t *testing.T) {
			p := independentSelectionProcess(711, "/fixture/service")
			p.Cgroup = "/fixture/scope"
			a := process.Approval{Rules: []process.Rule{{Cgroup: p.Cgroup}}, Exclusions: []process.Rule{{Executable: p.Executable, Arguments: []string{"--prohibited"}}}}
			now := time.Unix(500, 0)
			snapshots, reads := 0, 0
			got, _, err := a.ResolveWith(process.ResolutionReader{
				Now: func() time.Time { return now }, Sleep: func(d time.Duration) { now = now.Add(d) },
				Snapshot: func(time.Time) (process.Host, error) {
					snapshots++
					return process.Host{Table: process.TableOf(independentSelectionUnknown(p))}, nil
				},
				Process: func(int32) (process.Process, error) {
					reads++
					switch evidence {
					case "unknown":
						return independentSelectionUnknown(p), nil
					case "unreadable":
						return process.Process{}, errors.New("permission denied by fixture")
					case "prohibited":
						p.Arguments = []string{p.Executable, "--prohibited"}
					}
					return p, nil
				},
			})
			if reads == 0 {
				t.Fatal("wiring, not property: exclusion uncertainty did not reach a reread")
			}
			if snapshots != 1 {
				t.Errorf("property: unreadable or stable evidence must not trigger a rebuild: %d", snapshots)
			}
			if evidence == "allowed" {
				if err != nil || !slices.Equal(independentSelectionPIDs(got), []int32{p.PID}) {
					t.Fatalf("property: known argv[0]-only control not selected: %+v %v", got, err)
				}
			} else if len(got.Selections) != 0 || ((evidence == "unknown" || evidence == "unreadable") && err == nil) {
				t.Fatalf("property: exclusion %s authorized a possible prohibited candidate: %+v %v", evidence, got, err)
			}
			if evidence == "unknown" && now.Sub(time.Unix(500, 0)) != 50*time.Millisecond {
				t.Errorf("property: argument allowance is not 50ms: %v", now.Sub(time.Unix(500, 0)))
			}
		})
	}
}

func TestIndependentSelectionRebuiltArgumentsKeepTheirOwnAllowance(t *testing.T) {
	p := independentSelectionProcess(811, "/fixture/allowance")
	a := process.Approval{Rules: []process.Rule{{Executable: p.Executable}}}
	now := time.Unix(600, 0)
	snapshots, reads := 0, 0
	var rebuiltAt time.Time
	got, _, err := a.ResolveWith(process.ResolutionReader{
		Now: func() time.Time { return now }, Sleep: func(d time.Duration) { now = now.Add(d) },
		Snapshot: func(time.Time) (process.Host, error) {
			snapshots++
			q := independentSelectionUnknown(p)
			q.StartTime += uint64(snapshots)
			if snapshots > 1 {
				now = now.Add(300 * time.Millisecond)
				rebuiltAt = now
			}
			return process.Host{Table: process.TableOf(q)}, nil
		},
		Process: func(int32) (process.Process, error) {
			reads++
			q := independentSelectionUnknown(p)
			q.StartTime += 2
			return q, nil
		},
	})
	if snapshots < 2 || reads < 2 {
		t.Fatalf("wiring, not allowance property: rebuilt argument wait never reached: snapshots=%d reads=%d error=%v", snapshots, reads, err)
	}
	if err == nil || len(got.Selections) != 0 || snapshots != 2 || now.Sub(rebuiltAt) != 50*time.Millisecond {
		t.Fatalf("property: unknown rebuilt arguments get 50ms without another rebuild: snapshots=%d duration=%v selection=%v error=%v", snapshots, now.Sub(rebuiltAt), independentSelectionPIDs(got), err)
	}
}

func TestIndependentSelectionRebuiltReadMustFinishWithinAllowance(t *testing.T) {
	for _, elapsed := range []time.Duration{49 * time.Millisecond, 50 * time.Millisecond} {
		t.Run(elapsed.String(), func(t *testing.T) {
			p := independentSelectionProcess(911, "/fixture/read-allowance")
			a := process.Approval{Rules: []process.Rule{{Executable: p.Executable}}}
			now := time.Unix(800, 0)
			snapshots, reads := 0, 0
			got, _, err := a.ResolveWith(process.ResolutionReader{
				Now: func() time.Time { return now }, Sleep: func(d time.Duration) { now = now.Add(d) },
				Snapshot: func(time.Time) (process.Host, error) {
					snapshots++
					q := independentSelectionUnknown(p)
					q.StartTime += uint64(snapshots)
					return process.Host{Table: process.TableOf(q)}, nil
				},
				Process: func(int32) (process.Process, error) {
					reads++
					q := p
					q.StartTime += 2
					if reads > 1 {
						now = now.Add(elapsed)
					}
					return q, nil
				},
			})
			if snapshots != 2 || reads != 2 {
				t.Fatalf("wiring, not property: rebuilt in-flight read was not reached once: snapshots=%d reads=%d error=%v", snapshots, reads, err)
			}
			if elapsed < 50*time.Millisecond {
				if err != nil || !slices.Equal(independentSelectionPIDs(got), []int32{p.PID}) {
					t.Fatalf("property: read completing within rebuilt allowance must select: %+v %v", got, err)
				}
			} else if err == nil || len(got.Selections) != 0 {
				t.Fatalf("property: read completing at rebuilt allowance must refuse before acceptance: %+v %v", got, err)
			}
		})
	}
}
