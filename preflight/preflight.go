// Package preflight reports what a host offers a capture before one runs: its
// kernel, the tracing it exposes, the caller's privilege, and whether the
// approved processes carry a TLS library an adapter knows.
//
// It captures and attaches nothing, opens no socket, and reads no process
// memory or transferred file: only what the kernel publishes and the symbol
// tables of libraries on disk. It reports no process's arguments, since
// command lines hold secrets; rules are named by executable or cgroup.
package preflight

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl"
	"github.com/evandukss/edge-observer/process"
)

// Report is everything one preflight run found: all that leaves the host.
type Report struct {
	TakenAt   time.Time  `json:"taken_at"`
	Binary    Binary     `json:"binary"`
	Kernel    Kernel     `json:"kernel"`
	Tracing   Tracing    `json:"tracing"`
	Privilege Privilege  `json:"privilege"`
	Approved  []Approved `json:"approved"`
}

// Binary is what was run, useful when a report comes back from an unwatched
// host.
type Binary struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Toolset string `json:"toolset"`
}

// Kernel is which kernel this is; the version decides how uprobes are reached.
type Kernel struct {
	Release string `json:"release"`
	Version string `json:"version"`
}

// Tracing is what the kernel exposes to something that would attach a probe.
type Tracing struct {
	// BTF is the kernel's own type information, which a portable BPF object is
	// relocated against.
	BTF File `json:"btf"`

	// UprobeEvents is the tracefs uprobe interface, at both mount points.
	UprobeEvents []File `json:"uprobe_events"`

	// BPFFS is where pinned BPF objects live.
	BPFFS File `json:"bpffs"`

	// The knobs that can refuse an otherwise possible attachment, as the kernel
	// writes them.
	UnprivilegedBPFDisabled string `json:"unprivileged_bpf_disabled"`
	PerfEventParanoid       string `json:"perf_event_paranoid"`
	PtraceScope             string `json:"ptrace_scope"`
}

// File is whether a path is there and what it is, without reading it.
type File struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	Size    int64  `json:"size,omitempty"`

	// Error is why the answer is unknown, empty when known. An unexaminable path
	// is not an absent one.
	Error string `json:"error,omitempty"`
}

// Privilege is what the caller may do.
type Privilege struct {
	UID int `json:"uid"`

	// Effective, Permitted and Bounding are the capability masks as
	// /proc/self/status writes them.
	Effective string `json:"effective"`
	Permitted string `json:"permitted"`
	Bounding  string `json:"bounding"`

	// Holds names the capabilities attachment needs that are effective now.
	Holds []string `json:"holds"`

	// Lacks names those of the same set that are not effective.
	Lacks []string `json:"lacks"`
}

// Approved is one rule of the approval and what it matched. The rule's
// arguments are omitted: they hold command-line secrets, and this report
// leaves the host.
type Approved struct {
	Rule       int    `json:"rule"`
	Executable string `json:"executable,omitempty"`
	Arguments  int    `json:"arguments,omitempty"`

	// Cgroup is the other selector a rule may use, reported whole: it names a
	// service, not a command line.
	Cgroup string `json:"cgroup,omitempty"`

	Processes []Matched `json:"processes"`
}

// Matched is one process the approval selected, and what an adapter says about
// it.
type Matched struct {
	PID       int32  `json:"pid"`
	StartTime uint64 `json:"start_time"`

	// Executable is the file the kernel is running, which differs from the rule's
	// path for a descendant.
	Executable string `json:"executable"`

	// Named reports whether a rule matched this process itself, rather than an
	// ancestor.
	Named bool `json:"named"`

	Support   probe.Report      `json:"support"`
	Libraries []openssl.Library `json:"libraries,omitempty"`
}

// Host is where a preflight reads from, so tests can use a constructed tree.
type Host struct {
	ProcFS string
	SysFS  string
	Debug  string

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
}

// Running is the host this process is on.
func Running() Host {
	return Host{ProcFS: "/proc", SysFS: "/sys", Debug: "/sys/kernel/debug", OS: runtime.GOOS, Machine: machine}
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

// Take runs a preflight against the host and the approval.
func Take(host Host, approval process.Approval, catalog probe.Catalog) (Report, error) {
	table, err := process.Read(host.ProcFS)
	if err != nil {
		return Report{}, err
	}

	report := Report{
		TakenAt: time.Now().UTC(),
		Binary: Binary{
			OS:      runtime.GOOS,
			Arch:    runtime.GOARCH,
			Toolset: runtime.Version(),
		},
		Kernel:    kernel(host),
		Tracing:   tracing(host),
		Privilege: privilege(host),
	}

	selected := approval.Select(table)
	for i, rule := range approval.Rules {
		approved := Approved{
			Rule:       i + 1,
			Executable: rule.Executable,
			Arguments:  len(rule.Arguments),
			Cgroup:     rule.Cgroup,
		}
		for _, p := range selected {
			named := rule.Matches(p)
			if !named && !descends(table, approval, rule, p) {
				continue
			}
			matched := Matched{
				PID:        p.PID,
				StartTime:  p.StartTime,
				Executable: p.Executable,
				Named:      named,
				Support:    catalog.Inspect(p),
			}
			if mappings, err := process.Mappings(host.ProcFS, p.PID); err == nil {
				// Through that process's own root: a path from its mappings names a file in
				// its root, which may differ from the same path here.
				root := filepath.Join(host.ProcFS, strconv.FormatInt(int64(p.PID), 10), "root")
				matched.Libraries = openssl.Libraries(root, mappings)
			}
			approved.Processes = append(approved.Processes, matched)
		}
		report.Approved = append(report.Approved, approved)
	}
	return report, nil
}

// descends reports whether p is observed because this rule matched an ancestor
// of it.
func descends(table process.Table, approval process.Approval, rule process.Rule, p process.Process) bool {
	for steps := 0; steps <= len(table.All()); steps++ {
		parent, ok := table.Lookup(p.PPID)
		if !ok || parent.PID == p.PID {
			return false
		}
		if rule.Matches(parent) {
			return true
		}
		// An ancestor another rule named ends the walk, so a process is attributed to
		// the nearest rule above it.
		if approval.Observes(parent) {
			return false
		}
		p = parent
	}
	return false
}

func kernel(host Host) Kernel {
	return Kernel{
		Release: text(filepath.Join(host.ProcFS, "sys/kernel/osrelease")),
		Version: text(filepath.Join(host.ProcFS, "version")),
	}
}

func tracing(host Host) Tracing {
	return Tracing{
		BTF: stat(filepath.Join(host.SysFS, "kernel/btf/vmlinux")),
		UprobeEvents: []File{
			stat(filepath.Join(host.SysFS, "kernel/tracing/uprobe_events")),
			stat(filepath.Join(host.Debug, "tracing/uprobe_events")),
		},
		BPFFS:                   stat(filepath.Join(host.SysFS, "fs/bpf")),
		UnprivilegedBPFDisabled: text(filepath.Join(host.ProcFS, "sys/kernel/unprivileged_bpf_disabled")),
		PerfEventParanoid:       text(filepath.Join(host.ProcFS, "sys/kernel/perf_event_paranoid")),
		PtraceScope:             text(filepath.Join(host.ProcFS, "sys/kernel/yama/ptrace_scope")),
	}
}

func privilege(host Host) Privilege {
	status := Privilege{UID: os.Getuid()}

	content, err := os.ReadFile(filepath.Join(host.ProcFS, "self/status"))
	if err != nil {
		status.Effective = "unknown: " + err.Error()
		return status
	}

	for line := range strings.Lines(string(content)) {
		name, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch name {
		case "CapEff":
			status.Effective = value
		case "CapPrm":
			status.Permitted = value
		case "CapBnd":
			status.Bounding = value
		}
	}

	effective, err := strconv.ParseUint(status.Effective, 16, 64)
	if err != nil {
		return status
	}
	for _, capability := range needed {
		if effective&(1<<capability.Bit) != 0 {
			status.Holds = append(status.Holds, capability.Name)
			continue
		}
		status.Lacks = append(status.Lacks, capability.Name)
	}
	return status
}

// textLimit bounds a single-value kernel file, which holds a word.
const textLimit = 4096

// text is a one-line kernel file's contents, or why it could not be read. An
// absent knob and an unreadable one are different answers.
func text(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "absent"
		}
		return "unknown: " + err.Error()
	}
	// procfs files report size 0; a larger regular file is not the knob.
	if info.Size() > textLimit {
		return fmt.Sprintf("unknown: %d bytes, past the %d this reads", info.Size(), textLimit)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return "unknown: " + err.Error()
	}
	if len(content) > textLimit {
		content = content[:textLimit]
	}
	return strings.TrimSpace(string(content))
}

// stat is whether a path is there, without opening it.
func stat(path string) File {
	info, err := os.Stat(path)
	switch {
	case err == nil:
		return File{Path: path, Present: true, Size: info.Size()}
	case errors.Is(err, os.ErrNotExist):
		return File{Path: path}
	default:
		return File{Path: path, Error: err.Error()}
	}
}
