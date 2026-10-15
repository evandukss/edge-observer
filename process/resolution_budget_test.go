package process_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/process"
)

// Scripted process readings model only selection identities and argv. Kernel
// admission, namespace identity and actual procfs timing are not modelled.
func TestResolutionRebuildBudgetCountsCompleteSnapshots(t *testing.T) {
	for _, changes := range []int{1, 3, 4} {
		t.Run(fmt.Sprint(changes), func(t *testing.T) {
			at := time.Unix(100, 0)
			snapshots, reads := 0, 0
			candidate := process.Process{PID: 41, StartTime: 100, Executable: "/worker", ArgumentEvidence: process.ArgumentsUndetermined}
			approval := process.Approval{Rules: []process.Rule{{Executable: "/worker"}}}
			reader := process.ResolutionReader{
				Now:   func() time.Time { return at },
				Sleep: func(d time.Duration) { at = at.Add(d) },
				Snapshot: func(time.Time) (process.Host, error) {
					snapshots++
					candidate.StartTime++
					return process.Host{Table: process.TableOf(candidate)}, nil
				},
				Process: func(pid int32) (process.Process, error) {
					if pid != candidate.PID {
						t.Fatalf("wiring: reread pid %d, want %d", pid, candidate.PID)
					}
					reads++
					next := candidate
					next.ArgumentEvidence = process.ArgumentsKnown
					next.Arguments = []string{"/worker"}
					if reads <= changes {
						next.StartTime++
					}
					return next, nil
				},
			}
			resolution, table, err := approval.ResolveWith(reader)
			want := min(changes+1, 4)
			if snapshots != want || reads != want {
				t.Errorf("snapshots=%d, rereads=%d; want %d initial plus rebuild attempts", snapshots, reads, want)
			}
			if changes == 4 {
				if err == nil || len(resolution.Selections) != 0 || !strings.Contains(err.Error(), "41") {
					t.Fatalf("fourth needed rebuild must refuse the named candidate without grants: %+v, %v", resolution, err)
				}
			} else {
				if err != nil || len(resolution.Selections) != 1 {
					t.Fatalf("stable rebuild must select: %+v, %v", resolution, err)
				}
				got, ok := table.Lookup(candidate.PID)
				if !ok || got.StartTime != candidate.StartTime {
					t.Fatalf("returned stale table: %+v, found=%v", got, ok)
				}
			}
		})
	}
}

func TestResolutionUnreadableEvidenceDoesNotRebuild(t *testing.T) {
	candidate := process.Process{PID: 41, StartTime: 100, Executable: "/worker", ArgumentEvidence: process.ArgumentsUndetermined}
	snapshots := 0
	resolution, _, err := (process.Approval{Rules: []process.Rule{{Executable: "/worker"}}}).ResolveWith(process.ResolutionReader{
		Snapshot: func(time.Time) (process.Host, error) {
			snapshots++
			return process.Host{Table: process.TableOf(candidate)}, nil
		},
		Process: func(int32) (process.Process, error) { return process.Process{}, os.ErrPermission },
	})
	if snapshots != 1 || err == nil || !strings.Contains(err.Error(), "41") || len(resolution.Selections) != 0 {
		t.Fatalf("unreadable evidence rebuilt or authorized: snapshots=%d resolution=%+v err=%v", snapshots, resolution, err)
	}
}

func TestResolutionExitRebuildsWithoutKeepingTheOldCandidate(t *testing.T) {
	candidate := process.Process{PID: 41, StartTime: 100, Executable: "/worker", ArgumentEvidence: process.ArgumentsUndetermined}
	replacement := process.Process{PID: 42, StartTime: 200, Executable: "/worker", Arguments: []string{"/worker"}}
	snapshots := 0
	resolution, table, err := (process.Approval{Rules: []process.Rule{{Executable: "/worker"}}}).ResolveWith(process.ResolutionReader{
		Snapshot: func(time.Time) (process.Host, error) {
			snapshots++
			if snapshots == 1 {
				return process.Host{Table: process.TableOf(candidate)}, nil
			}
			return process.Host{Table: process.TableOf(replacement)}, nil
		},
		Process: func(int32) (process.Process, error) { return process.Process{}, os.ErrNotExist },
	})
	if snapshots != 2 || err != nil || len(resolution.Selections) != 1 || resolution.Selections[0].ObserverPID != replacement.PID {
		t.Fatalf("exit did not settle into new selection: snapshots=%d resolution=%+v err=%v", snapshots, resolution, err)
	}
	if _, exists := table.Lookup(candidate.PID); exists {
		t.Fatal("exited candidate remains in rebuilt table")
	}
}

func TestResolutionOuterDeadlineCoversSnapshotReadAndArgumentWait(t *testing.T) {
	for _, where := range []string{"snapshot", "read", "wait"} {
		t.Run(where, func(t *testing.T) {
			at := time.Unix(100, 0)
			began := at
			snapshots, reads := 0, 0
			candidate := process.Process{PID: 41, StartTime: 100, Executable: "/worker", ArgumentEvidence: process.ArgumentsUndetermined}
			reader := process.ResolutionReader{
				Now: func() time.Time { return at },
				Sleep: func(d time.Duration) {
					if d <= 0 || d > time.Millisecond {
						t.Fatalf("invalid wait %v", d)
					}
					at = at.Add(d)
				},
				Snapshot: func(time.Time) (process.Host, error) {
					snapshots++
					if snapshots == 2 {
						switch where {
						case "snapshot":
							at = at.Add(time.Second)
						case "wait":
							at = at.Add(980 * time.Millisecond)
						}
					}
					return process.Host{Table: process.TableOf(candidate)}, nil
				},
				Process: func(int32) (process.Process, error) {
					if snapshots > 1 && !at.Before(began.Add(time.Second)) {
						t.Fatal("a new read started at or after the outer deadline")
					}
					reads++
					next := candidate
					if reads == 1 {
						next.StartTime++
						return next, nil
					}
					if where == "read" {
						at = at.Add(time.Second)
						next.ArgumentEvidence = process.ArgumentsKnown
						next.Arguments = []string{"/worker"}
					}
					return next, nil
				},
			}
			resolution, _, err := (process.Approval{Rules: []process.Rule{{Executable: "/worker"}}}).ResolveWith(reader)
			if snapshots != 2 {
				t.Errorf("wiring: expiry case reached %d snapshots, want initial and rebuild", snapshots)
			}
			if err == nil || len(resolution.Selections) != 0 || !strings.Contains(err.Error(), "41") {
				t.Fatalf("outer deadline accepted or lost candidate: %+v %v", resolution, err)
			}
			if at.Sub(began) != time.Second {
				t.Errorf("budget ran for %v, want one second shared by rebuild and wait", at.Sub(began))
			}
			if where == "snapshot" && reads != 1 {
				t.Errorf("expired snapshot started %d extra reads", reads-1)
			}
			var refusal process.ArgumentsRefusal
			if !errors.As(err, &refusal) {
				t.Errorf("refusal lost typed candidate: %v", err)
			}
		})
	}
}

// The socket and owner reading are real. Only the table's birth is changed;
// this demonstrates the join, not an actual kernel PID-reuse sequence.
func TestListenersNeverJoinToAnotherBirth(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	p, err := process.Identify("/proc", int32(os.Getpid()))
	if err != nil || p.StartTime == 0 {
		t.Fatalf("wiring: no live owner identity: %+v, %v", p, err)
	}
	listeners, err := process.ReadListeners("/proc")
	if err != nil {
		t.Fatal(err)
	}
	control, _ := process.TableOf(p).WithListeners(listeners).Lookup(p.PID)
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	found := false
	for _, socket := range control.Listening {
		if socket.Port == port {
			found = true
		}
	}
	if !found {
		t.Fatal("wiring: the live birth did not receive its own listener")
	}
	p.StartTime++
	other, _ := process.TableOf(p).WithListeners(listeners).Lookup(p.PID)
	for _, socket := range other.Listening {
		if socket.Port == port {
			t.Fatal("a different birth received the observed owner's listener")
		}
	}
}

func TestResolutionChurnDoesNotRestartTheOuterDeadline(t *testing.T) {
	at := time.Unix(100, 0)
	began := at
	snapshots, reads := 0, 0
	candidate := process.Process{PID: 41, StartTime: 100, Executable: "/worker", ArgumentEvidence: process.ArgumentsUndetermined}
	resolution, _, err := (process.Approval{Rules: []process.Rule{{Executable: "/worker"}}}).ResolveWith(process.ResolutionReader{
		Now: func() time.Time { return at },
		Snapshot: func(deadline time.Time) (process.Host, error) {
			snapshots++
			if snapshots > 1 {
				if !deadline.Equal(began.Add(time.Second)) {
					t.Errorf("rebuild %d received a reset deadline: %s", snapshots-1, deadline)
				}
				at = at.Add(400 * time.Millisecond)
			}
			return process.Host{Table: process.TableOf(candidate)}, nil
		},
		Process: func(int32) (process.Process, error) {
			if !at.Before(began.Add(time.Second)) {
				t.Fatal("a new candidate read started after the shared deadline")
			}
			reads++
			next := candidate
			next.StartTime++
			return next, nil
		},
	})
	if snapshots != 4 || reads != 3 {
		t.Errorf("snapshots=%d reads=%d; want third rebuild to finish late without another candidate read", snapshots, reads)
	}
	if err == nil || len(resolution.Selections) != 0 || !strings.Contains(err.Error(), "41") {
		t.Fatalf("continuous changes reset the deadline or lost the candidate: %+v %v", resolution, err)
	}
}

func TestRebuiltArgumentsRespectTheSettleAllowance(t *testing.T) {
	for _, duration := range []time.Duration{49 * time.Millisecond, 50 * time.Millisecond} {
		t.Run(duration.String(), func(t *testing.T) {
			at := time.Unix(100, 0)
			snapshots, reads := 0, 0
			candidate := process.Process{PID: 41, StartTime: 100, Executable: "/worker", ArgumentEvidence: process.ArgumentsUndetermined}
			resolution, _, err := (process.Approval{Rules: []process.Rule{{Executable: "/worker"}}}).ResolveWith(process.ResolutionReader{
				Now: func() time.Time { return at },
				Snapshot: func(time.Time) (process.Host, error) {
					snapshots++
					return process.Host{Table: process.TableOf(candidate)}, nil
				},
				Process: func(int32) (process.Process, error) {
					reads++
					next := candidate
					if reads == 1 {
						next.StartTime++
						return next, nil
					}
					at = at.Add(duration)
					next.ArgumentEvidence, next.Arguments = process.ArgumentsKnown, []string{"/worker"}
					return next, nil
				},
			})
			if snapshots != 2 || reads != 2 {
				t.Fatalf("wiring: snapshots=%d reads=%d, want a reached reread in the first rebuild", snapshots, reads)
			}
			if duration < process.ArgumentReadBound {
				if err != nil || len(resolution.Selections) != 1 {
					t.Fatalf("free control refused: %+v %v", resolution, err)
				}
			} else if err == nil || len(resolution.Selections) != 0 {
				t.Fatalf("late rebuilt argv accepted: %+v %v", resolution, err)
			}
		})
	}
}
