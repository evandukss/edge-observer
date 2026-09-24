package process_test

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/evandukss/edge-observer/process"
)

// A pid one process reports for another means what the reader's pids mean
// only within one pid namespace, and nothing in a pid says which. These tests
// build a procfs because the nested case needs privileges the unit suite
// lacks; the kernel's real output is measured in the attach suite (package
// ebpf).

// fakeProcess writes the files Read needs for one process with the given
// status. An empty status writes no file, like a kernel without the line.
func fakeProcess(t *testing.T, root string, pid int32, status string) {
	t.Helper()
	directory := filepath.Join(root, strconv.FormatInt(int64(pid), 10))
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatalf("make %s: %v", directory, err)
	}
	// Field 22 is the start time; the name holds a space and a parenthesis, which
	// the reader must survive.
	stat := "" +
		strconv.FormatInt(int64(pid), 10) + " (a name (with parens)) S 1 " +
		"0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 981 " +
		"0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
	if err := os.WriteFile(filepath.Join(directory, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatalf("write stat: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "cmdline"),
		[]byte("/usr/bin/interpreter\x00/srv/one/main\x00"), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	if err := os.Symlink("/usr/bin/interpreter", filepath.Join(directory, "exe")); err != nil {
		t.Fatalf("link exe: %v", err)
	}
	if status == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(directory, "status"), []byte(status), 0o644); err != nil {
		t.Fatalf("write status: %v", err)
	}
}

func numbering(t *testing.T, status string) process.Process {
	t.Helper()
	root := t.TempDir()
	fakeProcess(t, root, 4321, status)
	table, err := process.Read(root)
	if err != nil {
		t.Fatalf("read the process table: %v", err)
	}
	p, held := table.Lookup(4321)
	if !held {
		t.Fatal("the table holds no process 4321, so its numbering was not read at all")
	}
	return p
}

func TestAProcessInANamespaceOfItsOwnIsNotReadAsSharingTheReadersNumbering(t *testing.T) {
	p := numbering(t, "Name:\tinterpreter\nNStgid:\t4321\t7\nNSpid:\t4321\t7\n")
	if p.Numbering != process.NumberingNested {
		t.Errorf("a process whose status reports pid 4321 here and 7 in its own namespace "+
			"is %v, and a number it reports is not one the reader can use", p.Numbering)
	}
}

func TestAProcessInTheReadersOwnNamespaceIsReadAsSharingItsNumbering(t *testing.T) {
	p := numbering(t, "Name:\tinterpreter\nNStgid:\t4321\nNSpid:\t4321\n")
	if p.Numbering != process.NumberingShared {
		t.Errorf("a process whose status reports one pid, the reader's own, is %v", p.Numbering)
	}
}

func TestAProcessWhoseStatusNamesNoNamespaceIsUnknownRatherThanShared(t *testing.T) {
	p := numbering(t, "Name:\tinterpreter\nState:\tS (sleeping)\n")
	if p.Numbering != process.NumberingUnknown {
		t.Errorf("a status with no NSpid line is %v, and not knowing which numbering a "+
			"process uses is not the same as knowing it is the reader's", p.Numbering)
	}
}

func TestAProcessWithNoStatusFileIsStillReadAndItsNumberingIsUnknown(t *testing.T) {
	p := numbering(t, "")
	if p.PID != 4321 {
		t.Errorf("the process was dropped from the table for want of a status file")
	}
	if p.Numbering != process.NumberingUnknown {
		t.Errorf("a process with no status file is %v", p.Numbering)
	}
}
