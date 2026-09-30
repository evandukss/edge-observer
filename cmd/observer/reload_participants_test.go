package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	protected "github.com/evandukss/edge-observer/activation"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// reloadingTwo is reloading with two processes the added target selects, both
// read by the reload command, and the session verifying them with the real
// verifier over readings: this process as a payload holder in a bounded cgroup
// of its own (as the verifier's own tests construct it), and each participant
// as the kernel reads it unless state says otherwise.
func reloadingTwo(t *testing.T, first, second *exec.Cmd,
	state func(pid int, kernel func(int) (protected.ParticipantState, error)) (protected.ParticipantState, error),
) (*daemon, *admitting, reloadRequest) {
	t.Helper()
	d, attached, request := reloading(t, int32(first.Process.Pid))

	table, err := process.Read(procfs)
	if err != nil {
		t.Fatalf("read the processes: %v", err)
	}
	var both []process.Process
	for _, one := range []*exec.Cmd{first, second} {
		p, found := table.Lookup(int32(one.Process.Pid))
		if !found {
			t.Fatalf("pid %d is not in the table", one.Process.Pid)
		}
		both = append(both, p)
	}
	read, err := process.ReadExec(procfs, both[1].PID)
	if err != nil {
		t.Fatalf("read what pid %d runs: %v", both[1].PID, err)
	}
	candidate, err := loadProcessing(d.path)
	if err != nil {
		t.Fatalf("load the candidate: %v", err)
	}
	request.Resolution = candidate.Approval.Resolve(process.Host{Table: process.TableOf(both...)})
	request.Processes = both
	reading := request.Read[both[0].PID]
	reading.Exec = read
	reading.Report.Process = both[1].Identity()
	request.Read[both[1].PID] = reading
	for _, p := range both {
		if !slices.ContainsFunc(request.Resolution.Selections, func(one admission.Selection) bool {
			return one.ObserverPID == p.PID && one.Provenance.Target == "added"
		}) {
			t.Fatalf("wiring, not the property: the candidate does not select pid %d for target added: %+v",
				p.PID, request.Resolution.Targets)
		}
	}

	kernel := protected.KernelReadings()
	self := os.Getpid()
	readings := protected.Readings{
		State: func(pid int) (protected.ParticipantState, error) {
			if pid == self {
				return protected.ParticipantState{PID: int32(self), StartTime: 10, Cgroup: "/payload"}, nil
			}
			return state(pid, kernel.State)
		},
		Link:      func(string) (string, error) { return strconv.Itoa(self), nil },
		Directory: func(string) (string, error) { return "/fixture", nil },
		File: func(name string) ([]byte, error) {
			if filepath.Base(name) == "cgroup.procs" {
				return []byte(strconv.Itoa(self)), nil
			}
			return []byte("domain"), nil
		},
		Number: func(_, name string, _ bool) (uint64, error) {
			if name == "memory.max" {
				return 1 << 30, nil
			}
			return 0, nil
		},
		Dumpable: func() (int, error) { return 0, nil },
	}
	d.verifyParticipants = func(gate *probe.DeliveryGate, participants []process.Process) (protected.Posture, error) {
		return protected.VerifyActiveReading(gate, participants, readings)
	}
	return d, attached, request
}

func encoded(t *testing.T, request reloadRequest) []byte {
	t.Helper()
	content, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encode the request: %v", err)
	}
	return content
}

func pidsOf(batches [][]admission.Selection) []int32 {
	var pids []int32
	for _, batch := range batches {
		for _, one := range batch {
			pids = append(pids, one.ObserverPID)
		}
	}
	slices.Sort(pids)
	return pids
}

// Reload verifies what it adds with the verifier start uses. A participant that
// exits while it is being verified is counted, not refused: the reload applies,
// and the write that followed is taken back, so it has no grant. One whose
// reading is refused refuses the reload whole, and the plan in force stays.
func TestReloadVerifiesItsParticipantsWithStartsVerifier(t *testing.T) {
	sorted := func(pids ...int32) []int32 {
		slices.Sort(pids)
		return pids
	}

	t.Run("every participant present: the reload applies", func(t *testing.T) {
		first, _ := catRunning(t)
		second, _ := catRunning(t)
		d, attached, request := reloadingTwo(t, first, second,
			func(pid int, kernel func(int) (protected.ParticipantState, error)) (protected.ParticipantState, error) {
				return kernel(pid)
			})

		record := d.reload(time.Now(), encoded(t, request))

		both := sorted(int32(first.Process.Pid), int32(second.Process.Pid))
		if record.Outcome != "activated" || record.Admitted != 2 || !slices.Equal(pidsOf(attached.admitted), both) ||
			len(attached.retracted) != 0 || d.plan.Policy.Generation != 2 {
			t.Errorf("the reload answered %+v at generation %d, wrote %v and took back %v; want both admitted, "+
				"nothing taken back, generation 2", record, d.plan.Policy.Generation, pidsOf(attached.admitted),
				pidsOf(attached.retracted))
		}
	})

	t.Run("a participant exits while it is verified: the reload applies and it has no grant", func(t *testing.T) {
		first, _ := catRunning(t)
		second, reap := catRunning(t)
		gone := second.Process.Pid
		d, attached, request := reloadingTwo(t, first, second,
			func(pid int, kernel func(int) (protected.ParticipantState, error)) (protected.ParticipantState, error) {
				if pid == gone {
					reap()
				}
				return kernel(pid)
			})

		record := d.reload(time.Now(), encoded(t, request))

		if _, err := os.Stat(filepath.Join(procfs, strconv.Itoa(gone))); err == nil {
			t.Fatalf("wiring, not the property: pid %d was never reaped, so nothing exited", gone)
		}
		if record.Outcome != "activated" || d.plan.Policy.Generation != 2 {
			t.Fatalf("the reload answered %+v at generation %d; want it applied at generation 2",
				record, d.plan.Policy.Generation)
		}
		if !slices.Equal(pidsOf(attached.retracted), []int32{int32(gone)}) || record.Admitted != 1 ||
			!slices.ContainsFunc(record.Retracted, func(line string) bool {
				return strings.HasPrefix(line, "pid "+strconv.Itoa(gone)+":")
			}) {
			t.Errorf("the reload admitted %d, took back %v and says %v; want pid %d, which exited, taken back "+
				"and the other admitted", record.Admitted, pidsOf(attached.retracted), record.Retracted, gone)
		}
	})

	t.Run("a participant's reading is refused: the reload is refused and the plan stays", func(t *testing.T) {
		first, _ := catRunning(t)
		second, _ := catRunning(t)
		denied := second.Process.Pid
		d, attached, request := reloadingTwo(t, first, second,
			func(pid int, kernel func(int) (protected.ParticipantState, error)) (protected.ParticipantState, error) {
				if pid == denied {
					return protected.ParticipantState{}, &fs.PathError{Op: "open",
						Path: filepath.Join(procfs, strconv.Itoa(pid), "stat"), Err: fs.ErrPermission}
				}
				return kernel(pid)
			})
		policy, revision := d.policy.Revision, d.plan.Policy.Revision

		record := d.reload(time.Now(), encoded(t, request))

		if record.Outcome != "refused" || !strings.Contains(record.Reason, string(protected.ParticipantOutsideEnvelope)) {
			t.Errorf("the reload answered %q (%s); want it refused naming participant_outside_envelope",
				record.Outcome, record.Reason)
		}
		if len(attached.admitted) != 0 || d.policy.Revision != policy || d.plan.Policy.Generation != 1 ||
			d.plan.Policy.Revision != revision {
			t.Errorf("a refused reload wrote %v and left generation %d revision %s; want nothing written and "+
				"generation 1 revision %s in force", pidsOf(attached.admitted), d.plan.Policy.Generation,
				d.plan.Policy.Revision, revision)
		}
	})
}
