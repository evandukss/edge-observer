package activation

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/evandukss/edge-observer/process"
	"golang.org/x/sys/unix"
)

// readPosture only reads the payload holder and the supplied participant set.
// It neither moves a process nor changes a limit or dumpability. In particular,
// these readings cannot establish where any earlier allocation was charged.
func readPosture(participants []process.Process) (Posture, error) {
	return readPostureUsing(participants, KernelReadings().reads())
}

// Each call owns its readers. This permits deterministic coverage of identity
// changes between readings without mutable process-wide hooks or extra reads.
type postureReads struct {
	state     func(int) (ParticipantState, error)
	link      func(string) (string, error)
	directory func(string) (string, error)
	file      func(string) ([]byte, error)
	number    func(string, string, bool) (uint64, error)
	dumpable  func() (int, error)
}

func readDumpability() (int, error) {
	dumpable, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, unix.PR_GET_DUMPABLE, 0, 0, 0, 0, 0)
	if errno != 0 {
		return 0, fmt.Errorf("read payload dumpability: %w", errno)
	}
	return int(dumpable), nil
}

func readPostureUsing(participants []process.Process, reads postureReads) (Posture, error) {
	posture := Posture{PID: os.Getpid()}
	refuse := func(check Check, unreadable bool, err error) (Posture, error) {
		return posture, &Refusal{Check: check, PID: posture.PID, Detail: err.Error(), Unreadable: unreadable}
	}
	self, err := reads.state(posture.PID)
	if err != nil {
		return refuse(PayloadMembership, true, err)
	}
	posture.StartTime, posture.Cgroup = self.StartTime, self.Cgroup
	// /proc/self must name the same process as Getpid and /proc/<pid>.
	// A proc mount from another PID namespace cannot prove our membership.
	selfLink, err := reads.link("/proc/self")
	if err != nil || selfLink != strconv.Itoa(posture.PID) {
		// A readable wrong identity fails provenance; an I/O error supplies none.
		return refuse(PayloadMembership, err != nil, fmt.Errorf("procfs does not identify payload pid %d in this PID namespace: link=%q error=%v", posture.PID, selfLink, err))
	}
	directory, err := reads.directory(posture.Cgroup)
	if err != nil {
		return refuse(ExecutionMemory, true, err)
	}
	members, err := reads.file(filepath.Join(directory, "cgroup.procs"))
	if err != nil {
		return refuse(PayloadMembership, true, fmt.Errorf("read payload cgroup membership: %w", err))
	}
	for _, value := range strings.Fields(string(members)) {
		pid, err := strconv.Atoi(value)
		if err != nil || pid <= 0 {
			// Bytes without a valid identity cannot establish presence or absence.
			return refuse(PayloadMembership, true, fmt.Errorf("cgroup.procs contains an unreadable process identity %q", value))
		}
		if pid == posture.PID {
			posture.Member = true
		}
	}
	domain, err := reads.file(filepath.Join(directory, "cgroup.type"))
	if err != nil {
		return refuse(ExecutionMemory, true, fmt.Errorf("read payload cgroup domain: %w", err))
	}
	posture.Domain = strings.TrimSpace(string(domain))
	posture.MemoryMax, err = reads.number(directory, "memory.max", true)
	if err != nil {
		return refuse(ExecutionMemory, true, err)
	}
	posture.SwapMax, err = reads.number(directory, "memory.swap.max", true)
	if err != nil {
		return refuse(AnonymousSwap, true, err)
	}
	posture.SwapCurrent, err = reads.number(directory, "memory.swap.current", false)
	if err != nil {
		return refuse(AnonymousSwap, true, err)
	}
	posture.Dumpable, err = reads.dumpable()
	if err != nil {
		return refuse(CoreDumps, true, err)
	}
	for _, expected := range participants {
		if expected.PID <= 0 || expected.StartTime == 0 {
			return refuse(ParticipantOutsideEnvelope, false, fmt.Errorf("participant pid %d has no complete start identity", expected.PID))
		}
		actual, err := reads.state(int(expected.PID))
		if exited(err) || (err == nil && actual.StartTime != expected.StartTime) {
			// The selected process no longer exists, so it cannot be inside the
			// envelope. A reused pid carries a later process's start.
			posture.ParticipantsExited++
			continue
		}
		if err != nil {
			return refuse(ParticipantOutsideEnvelope, true, err)
		}
		posture.Participants = append(posture.Participants, actual)
	}
	// A move during these reads is not evidence about either envelope. This
	// catches an observed change; the launch precondition still requires the
	// administrator to keep membership and limits fixed for the entire capture.
	after, err := reads.state(posture.PID)
	if err != nil {
		return refuse(PayloadMembership, true, err)
	}
	if after.StartTime != posture.StartTime || after.Cgroup != posture.Cgroup {
		// Two complete readings establish instability, not an inability to read.
		return refuse(PayloadMembership, false, fmt.Errorf("payload process identity or cgroup changed while verifying posture"))
	}
	return posture, nil
}

// exited is positive evidence that a process is gone: its entry is absent at
// open (ENOENT), or a handle opened before it was reaped reads ESRCH. A zombie
// still has its entry. Any other failure says nothing about existence.
func exited(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

func processState(pid int) (ParticipantState, error) {
	state := ParticipantState{PID: int32(pid)}
	proc := filepath.Join("/proc", strconv.Itoa(pid))
	readStart := func() (uint64, error) {
		content, err := os.ReadFile(filepath.Join(proc, "stat"))
		if err != nil {
			return 0, fmt.Errorf("read pid %d identity: %w", pid, err)
		}
		// comm may contain spaces and parentheses. The final ')' ends field 2;
		// starttime is field 22, index 19 in the remaining fields.
		line := string(content)
		open, close := strings.IndexByte(line, '('), strings.LastIndexByte(line, ')')
		if open < 1 || close <= open || strings.TrimSpace(line[:open]) != strconv.Itoa(pid) {
			return 0, fmt.Errorf("pid %d stat has no matching identity", pid)
		}
		fields := strings.Fields(line[close+1:])
		if len(fields) <= 19 {
			return 0, fmt.Errorf("pid %d stat has no start time", pid)
		}
		start, err := strconv.ParseUint(fields[19], 10, 64)
		if err != nil || start == 0 {
			return 0, fmt.Errorf("pid %d stat has an unreadable start time", pid)
		}
		return start, nil
	}
	start, err := readStart()
	if err != nil {
		return state, err
	}
	content, err := os.ReadFile(filepath.Join(proc, "cgroup"))
	if err != nil {
		return state, fmt.Errorf("read pid %d cgroup: %w", pid, err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		if group, ok := strings.CutPrefix(line, "0::"); ok {
			if state.Cgroup != "" || !cleanCgroup(group) {
				return state, fmt.Errorf("pid %d has ambiguous or unresolvable cgroup membership", pid)
			}
			state.Cgroup = group
		}
	}
	if state.Cgroup == "" {
		return state, fmt.Errorf("pid %d has no unified cgroup membership", pid)
	}
	after, err := readStart()
	if err != nil {
		return state, err
	}
	if start != after {
		// No coherent membership reading belongs to either process identity.
		return state, fmt.Errorf("pid %d was reused while reading cgroup membership", pid)
	}
	state.StartTime = start
	return state, nil
}

func cgroupNumber(directory, name string, allowMax bool) (uint64, error) {
	content, err := os.ReadFile(filepath.Join(directory, name))
	if err != nil {
		return 0, fmt.Errorf("read payload envelope %s: %w", name, err)
	}
	value := strings.TrimSpace(string(content))
	if allowMax && value == "max" {
		return math.MaxUint64, nil
	}
	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("payload envelope %s is not a readable nonnegative value: %w", name, err)
	}
	return number, nil
}

func cgroupDirectory(group string) (string, error) {
	content, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", fmt.Errorf("read payload cgroup mount: %w", err)
	}
	unescape := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\")
	var directory string
	longestRoot := -1
	for _, line := range strings.Split(string(content), "\n") {
		before, after, found := strings.Cut(line, " - ")
		if !found {
			continue
		}
		kind, fields := strings.Fields(after), strings.Fields(before)
		if len(kind) < 1 || kind[0] != "cgroup2" || len(fields) < 6 {
			continue
		}
		root, mount := unescape.Replace(fields[3]), unescape.Replace(fields[4])
		if !cleanCgroup(root) || !filepath.IsAbs(mount) || !withinCgroup(group, root) || len(root) <= longestRoot {
			continue
		}
		directory = filepath.Join(mount, strings.TrimPrefix(strings.TrimPrefix(group, root), "/"))
		longestRoot = len(root)
	}
	if directory == "" {
		return "", fmt.Errorf("no cgroup v2 mount exposes payload envelope %q", group)
	}
	var filesystem unix.Statfs_t
	if err := unix.Statfs(directory, &filesystem); err != nil {
		return "", fmt.Errorf("read payload envelope filesystem: %w", err)
	}
	if filesystem.Type != unix.CGROUP2_SUPER_MAGIC {
		return "", fmt.Errorf("payload envelope is not on the cgroup v2 filesystem")
	}
	return directory, nil
}
