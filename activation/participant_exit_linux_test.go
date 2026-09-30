package activation

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// participantProcess is a real process this test owns. It runs until end
// closes its input and reaps it.
type participantProcess struct {
	process.Process
	command *exec.Cmd
	input   io.WriteCloser
}

func startParticipant(t *testing.T) *participantProcess {
	t.Helper()
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Fatalf("setup: a participant is a cat process, and there is none: %v", err)
	}
	command := exec.Command(cat)
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("setup: start a participant: %v", err)
	}
	p := &participantProcess{command: command, input: input}
	t.Cleanup(func() {
		if p.command.ProcessState == nil {
			_ = p.input.Close()
			_ = p.command.Wait()
		}
	})
	state, err := processState(command.Process.Pid)
	if err != nil {
		t.Fatalf("setup: read the running participant: %v", err)
	}
	p.Process = process.Process{PID: state.PID, StartTime: state.StartTime}
	return p
}

// end reaps the participant and establishes that its entry is gone.
func (p *participantProcess) end(t *testing.T) {
	t.Helper()
	_ = p.input.Close()
	if err := p.command.Wait(); err != nil {
		t.Fatalf("setup: reap participant %d: %v", p.PID, err)
	}
	if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(int(p.PID)))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("wiring, not the property: reaped participant %d still has an entry (%v), so nothing below measures an exited one", p.PID, err)
	}
}

// hostParticipantReads reads the payload holder from the fixture and every
// participant from the host, so a participant's absence is the kernel's.
func hostParticipantReads() postureReads {
	reads, _ := postureReadFixture()
	payload := reads.state
	reads.state = func(pid int) (ParticipantState, error) {
		if pid == os.Getpid() {
			return payload(pid)
		}
		return processState(pid)
	}
	return reads
}

// activate is verify's decision over these readers: read, then judge.
func activate(t *testing.T, participants []process.Process, reads postureReads) (Posture, error) {
	t.Helper()
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 16})
	if err != nil {
		t.Fatal(err)
	}
	posture, err := readPostureUsing(participants, reads)
	if err != nil {
		return posture, err
	}
	return posture, CheckPosture(gate, posture)
}

func requireProceeds(t *testing.T, posture Posture, err error, exited int, running ...*participantProcess) {
	t.Helper()
	if err != nil {
		t.Fatalf("activation refused: %v", err)
	}
	if posture.ParticipantsExited != exited || len(posture.Participants) != len(running) {
		t.Fatalf("verified %d participants and counted %d exited; want %d verified and %d exited: %+v",
			len(posture.Participants), posture.ParticipantsExited, len(running), exited, posture.Participants)
	}
	for i, one := range running {
		if got := posture.Participants[i]; got.PID != one.PID || got.StartTime != one.StartTime {
			t.Fatalf("verified participant %d is pid %d start %d; want pid %d start %d", i, got.PID, got.StartTime, one.PID, one.StartTime)
		}
	}
}

func TestPostureDropsAndCountsAParticipantWhoseEntryIsGone(t *testing.T) {
	t.Run("absent_at_open", func(t *testing.T) {
		reads := hostParticipantReads()
		staying, leaving := startParticipant(t), startParticipant(t)
		participants := []process.Process{staying.Process, leaving.Process}
		posture, err := activate(t, participants, reads)
		requireProceeds(t, posture, err, 0, staying, leaving)

		leaving.end(t)
		posture, err = activate(t, participants, reads)
		requireProceeds(t, posture, err, 1, staying)
	})
	// A handle opened while the participant ran and read after it was reaped
	// fails with ESRCH: the same exit, met one call later.
	t.Run("reaped_between_open_and_read", func(t *testing.T) {
		reads := hostParticipantReads()
		staying, leaving := startParticipant(t), startParticipant(t)
		participants := []process.Process{staying.Process, leaving.Process}
		handle, err := os.Open(filepath.Join("/proc", strconv.Itoa(int(leaving.PID)), "stat"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = handle.Close() }()
		posture, err := activate(t, participants, reads)
		requireProceeds(t, posture, err, 0, staying, leaving)

		leaving.end(t)
		_, gone := io.ReadAll(handle)
		if !errors.Is(gone, syscall.ESRCH) {
			t.Fatalf("wiring, not the property: the reaped participant's open handle read %v, not ESRCH", gone)
		}
		host := reads.state
		reads.state = func(pid int) (ParticipantState, error) {
			if pid == int(leaving.PID) {
				return ParticipantState{}, fmt.Errorf("read pid %d identity: %w", pid, gone)
			}
			return host(pid)
		}
		posture, err = activate(t, participants, reads)
		requireProceeds(t, posture, err, 1, staying)
	})
}

// A pid that names a process started after the one resolved is the pid reused.
func TestPostureDropsAndCountsAParticipantWhosePidWasReused(t *testing.T) {
	reads := hostParticipantReads()
	staying, current := startParticipant(t), startParticipant(t)
	posture, err := activate(t, []process.Process{staying.Process, current.Process}, reads)
	requireProceeds(t, posture, err, 0, staying, current)

	if current.StartTime <= 1 {
		t.Fatalf("setup: participant %d start %d leaves no earlier start to resolve", current.PID, current.StartTime)
	}
	resolved := current.Process
	resolved.StartTime--
	if now, err := processState(int(current.PID)); err != nil || now.StartTime == resolved.StartTime {
		t.Fatalf("wiring, not the property: pid %d does not now carry a start other than the resolved %d: %+v %v", current.PID, resolved.StartTime, now, err)
	}
	posture, err = activate(t, []process.Process{staying.Process, resolved}, reads)
	requireProceeds(t, posture, err, 1, staying)
}

// A read that fails for any other reason cannot say whether the participant
// exists, so it refuses as unreadable rather than counting an exit.
func TestPostureRefusesAParticipantItCannotRead(t *testing.T) {
	for _, fault := range []struct {
		name string
		err  func(pid int) error
	}{
		{"permission", func(pid int) error {
			path := filepath.Join("/proc", strconv.Itoa(pid), "stat")
			return fmt.Errorf("read pid %d identity: %w", pid, &fs.PathError{Op: "open", Path: path, Err: syscall.EACCES})
		}},
		{"parse", func(pid int) error { return fmt.Errorf("pid %d stat has no matching identity", pid) }},
	} {
		t.Run(fault.name, func(t *testing.T) {
			reads := hostParticipantReads()
			staying, unread := startParticipant(t), startParticipant(t)
			participants := []process.Process{staying.Process, unread.Process}
			posture, err := activate(t, participants, reads)
			requireProceeds(t, posture, err, 0, staying, unread)

			host := reads.state
			reads.state = func(pid int) (ParticipantState, error) {
				if pid == int(unread.PID) {
					return ParticipantState{}, fault.err(pid)
				}
				return host(pid)
			}
			_, err = activate(t, participants, reads)
			var refusal *Refusal
			if !errors.As(err, &refusal) {
				t.Fatalf("an unreadable participant did not refuse: %v", err)
			}
			if refusal.Check != ParticipantOutsideEnvelope || !refusal.Unreadable || !strings.Contains(refusal.Error(), string(PostureUnreadable)) {
				t.Fatalf("refused as %s unreadable=%t (%v); want %s unreadable", refusal.Check, refusal.Unreadable, refusal, ParticipantOutsideEnvelope)
			}
		})
	}
}

func TestActivationRefusesWhenEverySelectedProcessHadExited(t *testing.T) {
	reads := hostParticipantReads()
	reaped, reused := startParticipant(t), startParticipant(t)
	participants := []process.Process{reaped.Process, reused.Process}
	posture, err := activate(t, participants, reads)
	requireProceeds(t, posture, err, 0, reaped, reused)

	reaped.end(t)
	participants[1].StartTime--
	posture, err = activate(t, participants, reads)
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("activation with every participant exited did not refuse: %v (%+v)", err, posture)
	}
	if refusal.Check != NoParticipantRunning || refusal.Unreadable || posture.ParticipantsExited != 2 {
		t.Fatalf("refused as %s unreadable=%t with %d exited; want %s, not unreadable, 2 exited: %v",
			refusal.Check, refusal.Unreadable, posture.ParticipantsExited, NoParticipantRunning, refusal)
	}
	if strings.Contains(refusal.Error(), string(ParticipantOutsideEnvelope)) {
		t.Fatalf("the refusal names a participant outside the envelope, which is not the cause: %v", refusal)
	}
}
