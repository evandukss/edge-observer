package activation

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/process"
)

func postureReadFixture() (postureReads, []process.Process) {
	self := ParticipantState{PID: int32(os.Getpid()), StartTime: 10, Cgroup: "/payload"}
	participant := ParticipantState{PID: self.PID + 1, StartTime: 20, Cgroup: "/participant"}
	reads := postureReads{
		state: func(pid int) (ParticipantState, error) {
			if pid == int(self.PID) {
				return self, nil
			}
			return participant, nil
		},
		link:      func(string) (string, error) { return strconv.Itoa(os.Getpid()), nil },
		directory: func(string) (string, error) { return "/fixture", nil },
		file: func(name string) ([]byte, error) {
			if filepath.Base(name) == "cgroup.procs" {
				return []byte(strconv.Itoa(os.Getpid())), nil
			}
			return []byte("domain"), nil
		},
		number: func(_, name string, _ bool) (uint64, error) {
			if name == "memory.max" {
				return 1 << 30, nil
			}
			return 0, nil
		},
		dumpable: func() (int, error) { return 0, nil },
	}
	return reads, []process.Process{{PID: participant.PID, StartTime: participant.StartTime}}
}

func TestPostureReadingClassifiesEachRefusal(t *testing.T) {
	for _, test := range []struct {
		site       string
		check      Check
		unreadable bool
		detail     string
	}{
		{"initial_identity", PayloadMembership, true, "unavailable"},
		{"final_identity", PayloadMembership, true, "unavailable"},
		{"link_io", PayloadMembership, true, "unavailable"},
		{"wrong_link", PayloadMembership, false, "does not identify payload"},
		{"mount", ExecutionMemory, true, "unavailable"},
		{"cgroup.procs", PayloadMembership, true, "unavailable"},
		{"malformed_member", PayloadMembership, true, "unreadable process identity"},
		{"cgroup.type", ExecutionMemory, true, "unavailable"},
		{"memory.max", ExecutionMemory, true, "unavailable"},
		{"malformed_number", ExecutionMemory, true, "not a readable nonnegative value"},
		{"memory.swap.max", AnonymousSwap, true, "unavailable"},
		{"memory.swap.current", AnonymousSwap, true, "unavailable"},
		{"dumpability", CoreDumps, true, "unavailable"},
		{"participant_io", ParticipantOutsideEnvelope, true, "unavailable"},
		{"incomplete_participant", ParticipantOutsideEnvelope, false, "no complete start identity"},
		{"changed_payload", PayloadMembership, false, "changed while verifying posture"},
	} {
		t.Run(test.site, func(t *testing.T) {
			reads, participants := postureReadFixture()
			if _, err := readPostureUsing(participants, reads); err != nil {
				t.Fatalf("complete control refused before fault: %v", err)
			}
			unavailable := errors.New("reading unavailable")
			switch test.site {
			case "initial_identity", "final_identity", "participant_io", "changed_payload":
				original := reads.state
				selfReads := 0
				reads.state = func(pid int) (ParticipantState, error) {
					state, err := original(pid)
					if pid == os.Getpid() {
						selfReads++
					}
					if (test.site == "initial_identity" && selfReads == 1) ||
						(test.site == "final_identity" && selfReads == 2) ||
						(test.site == "participant_io" && pid != os.Getpid()) {
						return ParticipantState{}, unavailable
					}
					if test.site == "changed_payload" && selfReads == 2 {
						state.Cgroup = "/moved"
					}
					return state, err
				}
			case "link_io":
				reads.link = func(string) (string, error) { return "", unavailable }
			case "wrong_link":
				reads.link = func(string) (string, error) { return strconv.Itoa(os.Getpid() + 1), nil }
			case "mount":
				reads.directory = func(string) (string, error) { return "", unavailable }
			case "cgroup.procs", "cgroup.type", "malformed_member":
				original := reads.file
				reads.file = func(name string) ([]byte, error) {
					if test.site == "malformed_member" && filepath.Base(name) == "cgroup.procs" {
						return []byte("not-a-pid"), nil
					}
					if filepath.Base(name) == test.site {
						return nil, unavailable
					}
					return original(name)
				}
			case "memory.max", "memory.swap.max", "memory.swap.current":
				original := reads.number
				reads.number = func(dir, name string, allowMax bool) (uint64, error) {
					if name == test.site {
						return 0, unavailable
					}
					return original(dir, name, allowMax)
				}
			case "malformed_number":
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte("not-a-limit"), 0o600); err != nil {
					t.Fatal(err)
				}
				reads.number = func(_, name string, allowMax bool) (uint64, error) {
					return cgroupNumber(dir, name, allowMax)
				}
			case "dumpability":
				reads.dumpable = func() (int, error) { return 0, unavailable }
			case "incomplete_participant":
				participants[0].StartTime = 0
			default:
				t.Fatalf("unhandled fault %q", test.site)
			}
			_, err := readPostureUsing(participants, reads)
			var refusal *Refusal
			if !errors.As(err, &refusal) {
				t.Fatalf("fault did not refuse: %v", err)
			}
			if refusal.Check != test.check || refusal.Unreadable != test.unreadable || refusal.PID != os.Getpid() || !strings.Contains(refusal.Detail, test.detail) {
				t.Fatalf("Check=%s Unreadable=%t PID=%d Detail=%q; want Check=%s Unreadable=%t own PID and detail containing %q", refusal.Check, refusal.Unreadable, refusal.PID, refusal.Detail, test.check, test.unreadable, test.detail)
			}
			if strings.Contains(refusal.Error(), string(PostureUnreadable)) != test.unreadable {
				t.Fatalf("error text disagrees with classification: %v", refusal)
			}
		})
	}
}
