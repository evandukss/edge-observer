package process

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Thread is one reading of one task of a process: what it was doing and how
// often it had been switched out. Two readings taken either side of a moment
// say whether the task ran across it (Still).
type Thread struct {
	TID int32

	// Start is the task's start time in clock ticks since boot, which tells a
	// task from a later one given its number.
	Start uint64

	// InCall is a task blocked inside a system call, from
	// /proc/<pid>/task/<tid>/syscall: Call is its number and FD its first
	// argument, whatever that argument is for this call. False is a task that was
	// running, or blocked outside any system call.
	InCall bool
	Call   int64
	FD     int64

	// Switches is the task's voluntary and involuntary context switches added
	// together, from its status.
	Switches uint64
}

// Still says this reading and a later one are of one task that did not run
// between them: the same task, inside the same system call on the same first
// argument, switched out no further. A task that ran and came back to the same
// call has switched at least once more.
func (t Thread) Still(later Thread) bool {
	return t.InCall && later.InCall && t.TID == later.TID && t.Start == later.Start &&
		t.Call == later.Call && t.FD == later.FD && t.Switches == later.Switches
}

// Same says two readings are of one task: its number and its start time.
func (t Thread) Same(later Thread) bool { return t.TID == later.TID && t.Start == later.Start }

// Threads reads every task of pid. A task that ended between the listing and its
// reading is left out, since it is inside nothing. Any other failure to read is
// an error, never a shorter list. Reading a task's system call needs the access
// a tracer has (CAP_SYS_PTRACE for another user's process).
func Threads(root string, pid int32) ([]Thread, error) {
	directory := filepath.Join(root, strconv.FormatInt(int64(pid), 10), "task")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("list the threads of pid %d: %w", pid, err)
	}
	found := make([]Thread, 0, len(entries))
	for _, entry := range entries {
		tid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		one, err := readThread(filepath.Join(directory, entry.Name()), int32(tid))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read thread %d of pid %d: %w", tid, pid, err)
		}
		found = append(found, one)
	}
	return found, nil
}

func readThread(directory string, tid int32) (Thread, error) {
	one := Thread{TID: tid}

	stat, err := os.ReadFile(filepath.Join(directory, "stat"))
	if err != nil {
		return Thread{}, err
	}
	if _, one.Start, _, err = parseStat(stat); err != nil {
		return Thread{}, fmt.Errorf("stat: %w", err)
	}

	call, err := os.ReadFile(filepath.Join(directory, "syscall"))
	if err != nil {
		return Thread{}, err
	}
	if one.InCall, one.Call, one.FD, err = parseSyscall(call); err != nil {
		return Thread{}, fmt.Errorf("syscall: %w", err)
	}

	status, err := os.ReadFile(filepath.Join(directory, "status"))
	if err != nil {
		return Thread{}, err
	}
	if one.Switches, err = parseSwitches(status); err != nil {
		return Thread{}, fmt.Errorf("status: %w", err)
	}
	return one, nil
}

// parseSyscall reads /proc/<pid>/task/<tid>/syscall, which the kernel writes in
// three shapes (fs/proc/base.c, proc_pid_syscall): "running" for a task on a
// CPU; "-1 SP PC" for one blocked outside a system call; and "NR A1 A2 A3 A4 A5
// A6 SP PC", the arguments in hexadecimal, for one blocked inside call NR.
func parseSyscall(content []byte) (inCall bool, number, first int64, err error) {
	fields := strings.Fields(string(content))
	switch {
	case len(fields) == 1 && fields[0] == "running":
		return false, 0, 0, nil
	case len(fields) == 3 && fields[0] == "-1":
		return false, 0, 0, nil
	case len(fields) == 9:
		if number, err = strconv.ParseInt(fields[0], 10, 64); err != nil || number < 0 {
			return false, 0, 0, fmt.Errorf("%q names no system call", fields[0])
		}
		argument, err := strconv.ParseUint(strings.TrimPrefix(fields[1], "0x"), 16, 64)
		if err != nil {
			return false, 0, 0, fmt.Errorf("%q is not an argument", fields[1])
		}
		return true, number, int64(argument), nil
	default:
		return false, 0, 0, fmt.Errorf("%q is none of the shapes the kernel writes", strings.TrimSpace(string(content)))
	}
}

// parseSwitches adds the two context-switch counts in a status file. Both are
// required: one alone would let a task that was only preempted read as still.
func parseSwitches(status []byte) (uint64, error) {
	var total uint64
	found := 0
	for line := range strings.Lines(string(status)) {
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || (name != "voluntary_ctxt_switches" && name != "nonvoluntary_ctxt_switches") {
			continue
		}
		count, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%s is %q", name, strings.TrimSpace(value))
		}
		total += count
		found++
	}
	if found != 2 {
		return 0, fmt.Errorf("%d of the two context-switch counts", found)
	}
	return total, nil
}

// IsSocket says whether descriptor fd of pid is a socket, and fails where the
// descriptor cannot be read.
func IsSocket(root string, pid int32, fd int64) (bool, error) {
	target, err := os.Readlink(filepath.Join(root, strconv.FormatInt(int64(pid), 10), "fd",
		strconv.FormatInt(fd, 10)))
	if err != nil {
		return false, fmt.Errorf("read descriptor %d of pid %d: %w", fd, pid, err)
	}
	return strings.HasPrefix(target, "socket:["), nil
}
