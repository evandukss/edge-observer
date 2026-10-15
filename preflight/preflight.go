// Package preflight reports what a host offers a capture before one runs: its
// kernel, the caller's privilege, and whether the selected processes carry
// a TLS runtime an adapter knows.
//
// It captures and attaches nothing, opens no socket, and reads no process
// memory or transferred file: only what the kernel publishes and the symbol
// tables of libraries on disk. It reports no process's arguments, since
// command lines hold secrets; process judgments are named by pid.
package preflight

import (
	"errors"
	"os"
	"runtime"

	"github.com/evandukss/edge-observer/process"
)

// File is whether a path is there and what it is, without reading it.
type File struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`

	// Error is why the answer is unknown, empty when known. An unexaminable path
	// is not an absent one.
	Error string `json:"error,omitempty"`
}

// Host is where a preflight reads from, so tests can use a constructed tree.
type Host struct {
	ProcFS string
	SysFS  string

	// OS is the operating system this program was built for and is running
	// on.
	OS string

	// Machine is uname's machine name. Under emulation it is the emulated
	// machine, hence the kernel's own file beside it (Architecture).
	Machine func() (string, error)

	// Loads loads the capture program and closes it, placing no probe, and says
	// why the kernel refused it. The caller supplies it so this package reaches
	// no capture code. Running leaves it nil.
	Loads func() error

	// Envelope judges the execution envelope start activates in - this
	// process's own cgroup and the selected processes - with start's own check,
	// and returns one judgment per condition. The caller supplies it
	// (activation.Envelope) so this package reaches no capture code. Running
	// leaves it nil.
	Envelope func(selected []process.Process) []EnvelopeJudgment
}

// EnvelopeJudgment is one condition start's envelope check decides, as that
// check judged it. Check is start's own name for the condition, the name its
// refusal would carry.
type EnvelopeJudgment struct {
	Check      string
	Met        bool
	Unreadable bool
	PID        int32
	Detail     string
}

// Running is the host this process is on.
func Running() Host {
	return Host{ProcFS: "/proc", SysFS: "/sys", OS: runtime.GOOS, Machine: machine}
}

// needed is the capability set attachment uses, by kernel number: the ones
// whose absence stops an attachment.
var needed = []struct {
	Name string
	Bit  uint
}{
	{"CAP_DAC_READ_SEARCH", 2},
	{"CAP_SYS_PTRACE", 19},
	{"CAP_SYS_ADMIN", 21},
	{"CAP_SYS_RESOURCE", 24},
	{"CAP_PERFMON", 38},
	{"CAP_BPF", 39},
}

// textLimit bounds a single-value kernel file, which holds a word.
const textLimit = 4096

// stat is whether a path is there, without opening it.
func stat(path string) File {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return File{Path: path, Present: true}
	case errors.Is(err, os.ErrNotExist):
		return File{Path: path}
	default:
		return File{Path: path, Error: err.Error()}
	}
}
