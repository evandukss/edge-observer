package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	protected "github.com/evandukss/edge-observer/activation"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
)

// catRunning is a process this test owns, running until its input closes. It
// returns once /proc shows the process running cat, so a reader that looks at
// once never finds it between its exec and its command line.
func catRunning(t *testing.T) (*exec.Cmd, func()) {
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
	end := func() {
		_ = input.Close()
		_ = command.Wait()
	}
	t.Cleanup(end)
	waitRunning(t, int32(command.Process.Pid), "cat", cat)
	return command, end
}

// A participant that exits between resolution and activation is counted where
// the activation record prints the posture, and the account lists it as not
// attached because it is gone. The activation package's tests establish that a
// reaped participant produces the count; this reads it where a reader does.
func TestAParticipantThatExitedBeforeActivationIsCountedAndReportedGone(t *testing.T) {
	staying, _ := catRunning(t)
	leaving, reap := catRunning(t)
	table, err := process.Read(procfs)
	if err != nil {
		t.Fatal(err)
	}
	var selections []admission.Selection
	for _, one := range []*exec.Cmd{staying, leaving} {
		pid := int32(one.Process.Pid)
		if _, found := table.Lookup(pid); !found {
			t.Fatalf("wiring, not the property: the table read while pid %d ran does not hold it", pid)
		}
		selections = append(selections, admission.Selection{ObserverPID: pid})
	}
	resolution := process.Resolution{Selections: selections}

	reap()
	gone := int32(leaving.Process.Pid)
	if _, err := os.Stat(filepath.Join(procfs, strconv.Itoa(int(gone)))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("wiring, not the property: reaped participant %d still has an entry (%v)", gone, err)
	}

	t.Run("account", func(t *testing.T) {
		catalog, err := probe.NewCatalog(attach.NeweBPF(process.Approval{}))
		if err != nil {
			t.Fatal(err)
		}
		recording, store, err := recordingIntake(1)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = store.Close() }()
		gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1})
		if err != nil {
			t.Fatal(err)
		}
		_, observed, err := observe(catalog, resolution, table, recording, gate, nil)
		t.Logf("observe returned %v", err)
		plan := account.Plan(time.Now(), account.Policy{Generation: 1}, resolution, attach.Built(), nil)
		plan.Attached(account.Live, "0123456789abcdef", observed, probe.Capability{})
		written, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		var read struct {
			Processes []struct {
				PID     int32
				Outcome attachment.Outcome
				Reason  string
			} `json:"processes"`
		}
		if err := json.Unmarshal(written, &read); err != nil {
			t.Fatal(err)
		}
		reasons := map[int32]string{}
		for _, one := range read.Processes {
			if one.PID == gone && one.Outcome != attachment.NotAttached {
				t.Errorf("the exited participant %d is %s in the account, want %s", gone, one.Outcome, attachment.NotAttached)
			}
			reasons[one.PID] = one.Reason
		}
		if why, listed := reasons[gone]; !listed || !strings.Contains(why, "is gone") {
			t.Errorf("the account says of exited participant %d: %q (listed %t), want that it is gone", gone, why, listed)
		}
		if why, listed := reasons[int32(staying.Process.Pid)]; !listed || strings.Contains(why, "is gone") {
			t.Errorf("the account says of running participant %d: %q (listed %t), want it listed and not gone",
				staying.Process.Pid, why, listed)
		}
	})

	t.Run("activation_record", func(t *testing.T) {
		live := account.Plan(time.Now(), account.Policy{Generation: 1}, resolution, attach.Built(), nil)
		for _, exited := range []int{0, 1} {
			content, err := json.Marshal(activated("0123456789abcdef", 4242, time.Now(), live,
				protected.Posture{ParticipantsExited: exited}))
			if err != nil {
				t.Fatal(err)
			}
			var read struct {
				Posture map[string]json.RawMessage `json:"payload_posture"`
			}
			if err := json.Unmarshal(content, &read); err != nil {
				t.Fatal(err)
			}
			raw, present := read.Posture["participants_exited"]
			if !present || string(raw) != strconv.Itoa(exited) {
				t.Errorf("the activation record's posture says participants_exited %s (present %t), want %d", raw, present, exited)
			}
		}
	})
}
