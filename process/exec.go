package process

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Exec is what anyone may read of which program a process runs: its thread
// group's start (unchanged by exec, changed by pid reuse) and its name and
// command line (changed by exec). None needs ptrace access, so a session
// without capabilities can read it. It narrows and does not identify: the name
// is 15 bytes the process chooses and the command line is memory it may
// rewrite.
type Exec struct {
	StartTime uint64 `json:"start_time"`
	Comm      string `json:"comm"`
	Cmdline   string `json:"cmdline"`
}

// ReadExec reads what anyone may read of which program pid runs, from
// /proc/<pid>/stat and /proc/<pid>/cmdline.
func ReadExec(root string, pid int32) (Exec, error) {
	directory := filepath.Join(root, strconv.FormatInt(int64(pid), 10))
	stat, err := os.ReadFile(filepath.Join(directory, "stat"))
	if err != nil {
		return Exec{}, err
	}
	_, start, _, err := parseStat(stat)
	if err != nil {
		return Exec{}, fmt.Errorf("%s/stat: %w", directory, err)
	}
	// The name runs from the first parenthesis to the last, since it may hold one.
	open, end := bytes.IndexByte(stat, '('), bytes.LastIndexByte(stat, ')')
	if open < 0 || end < open {
		return Exec{}, fmt.Errorf("%s/stat: no process name", directory)
	}
	cmdline, err := os.ReadFile(filepath.Join(directory, "cmdline"))
	if err != nil {
		return Exec{}, err
	}
	return Exec{StartTime: start, Comm: string(stat[open+1 : end]), Cmdline: string(cmdline)}, nil
}
