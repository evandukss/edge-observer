// Package process reads the processes on the host and decides which of them a
// configuration approved for observation. Nothing no rule names is observed,
// and an approval with no rules approves nothing.
package process

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/fragment"
)

// Process is one process as the kernel describes it.
type Process struct {
	PID       int32
	PPID      int32
	StartTime uint64

	// Executable is where /proc/<pid>/exe points: the file the kernel runs, not
	// the argv[0] the process chose.
	Executable string

	// Arguments is the process's argv, argv[0] first, as the kernel holds it now,
	// including a rewrite and its trailing padding; matching strips the padding.
	Arguments []string

	// Cgroup is the process's path on the unified (v2) hierarchy from
	// /proc/<pid>/cgroup, empty where none. A process cannot rewrite it, and it is
	// read at resolution, not tracked.
	Cgroup string

	// Numbering is whether the pids this process hands out (its fork's return
	// value among them) mean what the reader's pids mean. From /proc/<pid>/status.
	Numbering Numbering

	// Namespace is the pid namespace this process is in: the device and inode of
	// /proc/<pid>/ns/pid. Zero where unread, which is not the reader's own.
	Namespace admission.Namespace

	// NamespacePID is the thread group id inside Namespace: the process's own
	// number, which its fork returns. It equals PID in the reader's namespace, and
	// is zero where status was unreadable. It comes from the same NSpid line as
	// Numbering.
	NamespacePID int32

	// Threads is the thread count when read, from /proc/<pid>/status; zero where
	// unreadable. It cannot tell a group whose leader exited while a worker runs
	// from one whose tasks all exited awaiting reaping: both report the same count
	// until reaped. Inspect (execution.go) separates them by task state.
	Threads int32

	// Listening is the listening sockets this process holds; empty where none or
	// not read (Table.WithListeners says which).
	Listening []Listener
}

// Instance is the process instance as far as /proc establishes it: everything
// but the admission generation, which is stamped at admission.
func (p Process) Instance() admission.Instance {
	return admission.Instance{
		Namespace:  p.Namespace,
		PID:        p.NamespacePID,
		Start:      p.Start(),
		Executable: p.Executable,
	}
}

// Start is this process's start identity. An unread start is indeterminate,
// not zero.
func (p Process) Start() admission.Start {
	if p.StartTime == 0 {
		return admission.Indeterminate()
	}
	return admission.Determinate(admission.BootTicks(p.StartTime))
}

// Numbering is how a process's pid namespace relates to the reader's. A pid
// carries no namespace, so one process's number is usable by another only
// within one namespace.
type Numbering uint8

const (
	// NumberingUnknown is a status saying nothing about pid namespaces: no such
	// line, or unreadable. Not the same as shared.
	NumberingUnknown Numbering = iota

	// NumberingShared is a process in the reader's own pid namespace: a pid it
	// reports is a pid the reader can use.
	NumberingShared

	// NumberingNested is a process in a pid namespace below the reader's.
	NumberingNested
)

func (n Numbering) String() string {
	switch n {
	case NumberingShared:
		return "in the reader's own pid namespace"
	case NumberingNested:
		return "in a pid namespace of its own"
	default:
		return "in a pid namespace nothing here names"
	}
}

// Identity is what a captured fragment carries: enough to name this process
// across a pid reuse.
func (p Process) Identity() fragment.Process {
	return fragment.Process{PID: p.PID, StartTime: p.StartTime}
}

// Table is one reading of the processes on the host: a snapshot.
type Table struct {
	processes []Process
	byPID     map[int32]Process

	// listeners is the reading of listening sockets this table's processes
	// carry, and nil where none was taken.
	listeners *Listeners

	// unreadable is every process whose executable this reader was refused, as
	// against one that has none.
	unreadable []int32
}

func (t Table) All() []Process { return t.processes }

// Unreadable is every running process left out of the table because this
// reader may not see what it runs.
func (t Table) Unreadable() []int32 { return t.unreadable }

// unreadableLink is a process whose executable link exists and was refused.
type unreadableLink struct{ error }

func (t Table) Lookup(pid int32) (Process, bool) {
	p, ok := t.byPID[pid]
	return p, ok
}

// Read reads every process the caller can see under root (/proc on a running
// host). A process that exits mid-read is skipped; a root that cannot be
// listed is an error, not an empty host.
func Read(root string) (Table, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return Table{}, fmt.Errorf("read %s: %w", root, err)
	}

	table := Table{byPID: make(map[int32]Process, len(entries))}
	for _, entry := range entries {
		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		p, err := readProcess(root, int32(pid))
		if _, closed := err.(unreadableLink); closed {
			table.unreadable = append(table.unreadable, int32(pid))
			continue
		}
		if err != nil {
			continue
		}
		table.processes = append(table.processes, p)
		table.byPID[p.PID] = p
	}

	if len(table.processes) == 0 {
		// The caller itself is under this root, so an empty table measured nothing.
		return Table{}, fmt.Errorf("read %s: no process is readable, not even the reader", root)
	}
	return table, nil
}

func readProcess(root string, pid int32) (Process, error) {
	directory := filepath.Join(root, strconv.FormatInt(int64(pid), 10))

	stat, err := os.ReadFile(filepath.Join(directory, "stat"))
	if err != nil {
		return Process{}, err
	}
	// The state is not read here: selection consults no state (Inspect,
	// execution.go reads it for liveness).
	ppid, startTime, _, err := parseStat(stat)
	if err != nil {
		return Process{}, fmt.Errorf("%s/stat: %w", directory, err)
	}

	executable, err := os.Readlink(filepath.Join(directory, "exe"))
	if err != nil {
		// No executable link: a kernel thread or an exited process, neither nameable
		// by a rule. A link that exists and is refused is a process this reader may
		// not look at (another user's without CAP_SYS_PTRACE, or any once capabilities
		// are dropped). Both are left out; only the second is named, since the two
		// send an operator to different places.
		if os.IsNotExist(err) {
			return Process{}, err
		}
		return Process{}, unreadableLink{err}
	}

	cmdline, err := os.ReadFile(filepath.Join(directory, "cmdline"))
	if err != nil {
		return Process{}, err
	}

	// The cgroup is read last and may be absent: without a unified hierarchy a
	// cgroup rule matches nothing, which is reported (Approval.Matches).
	cgroup, err := os.ReadFile(filepath.Join(directory, "cgroup"))
	if err != nil {
		cgroup = nil
	}

	// The status is read last and may be absent too; unread is NumberingUnknown,
	// and the caller decides what that costs.
	status, err := os.ReadFile(filepath.Join(directory, "status"))
	if err != nil {
		status = nil
	}
	numbering, namespacePID := parseNumbering(status)

	return Process{
		Threads:      parseThreads(status),
		PID:          pid,
		PPID:         ppid,
		StartTime:    startTime,
		Executable:   executable,
		Arguments:    parseCmdline(cmdline),
		Cgroup:       parseCgroup(cgroup),
		Numbering:    numbering,
		Namespace:    namespaceOf(directory),
		NamespacePID: namespacePID,
	}, nil
}

// namespaceOf names the pid namespace a process is in, from /proc/<pid>/ns/pid.
// The device and inode are what bpf_get_ns_current_pid_tgid resolves a pid
// with. An unread namespace is zero, never the reader's own.
func namespaceOf(directory string) admission.Namespace {
	info, err := os.Stat(filepath.Join(directory, "ns", "pid"))
	if err != nil {
		return admission.Namespace{}
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return admission.Namespace{}
	}
	return admission.Namespace{Device: uint64(stat.Dev), Inode: stat.Ino}
}

// parseNumbering reads /proc/<pid>/status's NSpid line: the pid in each
// namespace from the reader's inwards. One entry is the reader's namespace;
// more means a namespace below, whose number (the last entry) is what the
// allowlist is keyed by. No such line (no pid namespaces, or unreadable) is
// unknown with no number.
func parseNumbering(status []byte) (Numbering, int32) {
	for line := range strings.Lines(string(status)) {
		rest, found := strings.CutPrefix(line, "NSpid:")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return NumberingUnknown, 0
		}
		innermost, err := strconv.ParseInt(fields[len(fields)-1], 10, 32)
		if err != nil {
			return NumberingUnknown, 0
		}
		if len(fields) > 1 {
			return NumberingNested, int32(innermost)
		}
		return NumberingShared, int32(innermost)
	}
	return NumberingUnknown, 0
}

// parseThreads reads the Threads line. Unreadable reports none, and none is
// not one.
func parseThreads(status []byte) int32 {
	for line := range strings.Lines(string(status)) {
		rest, found := strings.CutPrefix(line, "Threads:")
		if !found {
			continue
		}
		count, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 32)
		if err != nil {
			return 0
		}
		return int32(count)
	}
	return 0
}

// parseCgroup reads the unified hierarchy's path ("0::/path") out of
// /proc/<pid>/cgroup. Legacy-only hosts return nothing, never a legacy path.
func parseCgroup(content []byte) string {
	for line := range strings.Lines(string(content)) {
		if path, found := strings.CutPrefix(strings.TrimSpace(line), "0::"); found {
			return path
		}
	}
	return ""
}

// statFieldsBeforeState is how many /proc/<pid>/stat fields sit at or before
// the process name.
const statFieldsBeforeState = 2

// statState, statPPID and statStartTime are proc(5)'s one-based field numbers.
const (
	statState     = 3
	statPPID      = 4
	statStartTime = 22
)

// parseStat reads the parent pid, start time and state character from
// /proc/<pid>/stat, returning the state uninterpreted (TaskState classifies
// it). The name (field 2) may contain spaces and parentheses, so later fields
// are found from the last closing parenthesis.
func parseStat(stat []byte) (ppid int32, startTime uint64, state byte, err error) {
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, 0, 0, errors.New("no process name")
	}

	fields := strings.Fields(string(stat[end+1:]))
	wanted := statStartTime - statFieldsBeforeState
	if len(fields) < wanted {
		return 0, 0, 0, fmt.Errorf("%d fields after the process name, want at least %d", len(fields), wanted)
	}

	// The state is one character; any other length comes back unread.
	if first := fields[statState-statFieldsBeforeState-1]; len(first) == 1 {
		state = first[0]
	}

	ppid64, err := strconv.ParseInt(fields[statPPID-statFieldsBeforeState-1], 10, 32)
	if err != nil {
		return 0, 0, state, fmt.Errorf("parent pid: %w", err)
	}
	startTime, err = strconv.ParseUint(fields[wanted-1], 10, 64)
	if err != nil {
		return 0, 0, state, fmt.Errorf("start time: %w", err)
	}
	return int32(ppid64), startTime, state, nil
}

// parseCmdline splits /proc/<pid>/cmdline: argv with a NUL after every entry.
func parseCmdline(cmdline []byte) []string {
	cmdline = bytes.TrimSuffix(cmdline, []byte{0})
	if len(cmdline) == 0 {
		return nil
	}

	parts := bytes.Split(cmdline, []byte{0})
	arguments := make([]string, len(parts))
	for i, part := range parts {
		arguments[i] = string(part)
	}
	return arguments
}

// Rule is one approved target: every condition it names must hold, and those
// it does not name are not consulted. It names at least one; a rule naming
// none would be host-wide observation.
//
// Executable and arguments: an exact path run with exactly these arguments,
// neither a pattern, since one interpreter commonly runs several scripts. The
// arguments are those the process reports now (a program may rewrite its
// command line), so rules are written from what the host shows, not from a
// service file.
//
// Trailing empty arguments are padding and ignored on both sides: a process
// rewriting its argv pads with NULs to the original length (nginx and php-fpm
// do), and that count changes when the start command does.
//
// Arguments without an executable match any file run with exactly those
// arguments. An executable with arguments omitted means no arguments after
// argv[0].
//
// Cgroup: a unified-hierarchy path the process's cgroup must equal or sit
// below. A snapshot selector, decided at resolution: a process moved out keeps
// its grant, one moved in is selected at the next resolution (a restart). Its
// descendants follow the entry's mode (admission.Mode), and resolution records
// the cgroup object as well as the path.
//
// Pid: one instance by its number in the observer's namespace, its start and
// its boot (PIDGuard); the boot is checked in Approval.Resolve.
//
// Port: the processes holding a listening TCP socket on the port in the
// observer's network namespace (a forking server's parent and workers). It
// finds processes and does not narrow traffic; an outbound-only process holds
// no listener. Interface narrows a port to listeners bound to that interface's
// addresses or to every address, and is never a condition alone.
type Rule struct {
	// Executable is an absolute path, matched against the target of
	// /proc/<pid>/exe.
	Executable string `json:"executable,omitempty"`
	// Arguments is argv after argv[0], matched entry for entry, as reported now
	// and without trailing padding.
	Arguments []string `json:"arguments,omitempty"`

	// Cgroup is an absolute unified-hierarchy path; it matches that cgroup and any
	// below it.
	Cgroup string `json:"cgroup,omitempty"`

	// The fields below come from the configuration file (package policy).

	// Name is the configured label for this target, which an account uses, so
	// naming a target never repeats its arguments.
	Name string `json:"-"`

	PID       *PIDGuard `json:"-"`
	Port      uint16    `json:"-"`
	Interface string    `json:"-"`

	// Mode is the target's descendant mode, required in the configuration file; a
	// rule built in code without one means LegacyMode.
	Mode admission.Mode `json:"-"`

	// addresses is what Interface resolved to; an unresolved interface matches no
	// process.
	addresses         []netip.Prefix
	resolvedInterface bool
}

// Matches reports whether p meets every condition this rule names.
func (r Rule) Matches(p Process) bool {
	if !r.conditions() {
		return false
	}
	if r.PID != nil && (p.PID != r.PID.PID || p.StartTime != r.PID.Start) {
		return false
	}
	if r.Executable != "" && r.Executable != p.Executable {
		return false
	}
	if r.argumentsNamed() {
		arguments := p.Arguments
		if len(arguments) > 0 {
			arguments = arguments[1:]
		}
		if !slices.Equal(unpadded(r.Arguments), unpadded(arguments)) {
			return false
		}
	}
	if r.Cgroup != "" && !under(r.Cgroup, p.Cgroup) {
		return false
	}
	if r.Port != 0 && !r.listens(p) {
		return false
	}
	return true
}

// conditions reports whether this rule names any condition at all.
func (r Rule) conditions() bool {
	return r.PID != nil || r.Executable != "" || r.Arguments != nil || r.Cgroup != "" || r.Port != 0
}

// argumentsNamed reports whether the arguments are a condition: written, or
// implied empty beside an executable.
func (r Rule) argumentsNamed() bool { return r.Arguments != nil || r.Executable != "" }

// listens reports whether p holds a listener this rule's port and interface
// name.
func (r Rule) listens(p Process) bool {
	for _, listener := range p.Listening {
		if listener.Port == r.Port && r.bound(listener.Address) {
			return true
		}
	}
	return false
}

// bound reports whether a listener at this address is one the interface
// admits: any where none is named, else the interface's addresses or every
// address.
func (r Rule) bound(address netip.Addr) bool {
	if r.Interface == "" {
		return true
	}
	if !r.resolvedInterface {
		return false
	}
	address = address.Unmap()
	if address.IsUnspecified() {
		return true
	}
	for _, prefix := range r.addresses {
		if prefix.Addr().Unmap() == address {
			return true
		}
	}
	return false
}

// unpadded drops the trailing empty entries argv padding leaves. An empty
// entry between non-empty ones is real and stays. Applied to rules too, so one
// written with the padding still matches.
func unpadded(arguments []string) []string {
	end := len(arguments)
	for end > 0 && arguments[end-1] == "" {
		end--
	}
	return arguments[:end]
}

// under reports whether a cgroup path is the approved one or below it (where
// a service's forks land).
func under(approved, path string) bool {
	if path == "" {
		return false
	}
	approved = strings.TrimSuffix(approved, "/")
	return path == approved || strings.HasPrefix(path, approved+"/")
}

// String names this rule by its conditions, arguments included: local view
// only; label is what an account uses.
func (r Rule) String() string {
	var parts []string
	if r.PID != nil {
		parts = append(parts, fmt.Sprintf("pid %d started at tick %d", r.PID.PID, r.PID.Start))
	}
	if r.Executable != "" || len(r.Arguments) > 0 {
		parts = append(parts, strings.TrimSpace(r.Executable+" "+strings.Join(r.Arguments, " ")))
	}
	if r.Cgroup != "" {
		parts = append(parts, "cgroup "+r.Cgroup)
	}
	if r.Port != 0 {
		port := fmt.Sprintf("port %d", r.Port)
		if r.Interface != "" {
			port += " on " + r.Interface
		}
		parts = append(parts, port)
	}
	return strings.Join(parts, ", ")
}

// label is the rule's configured name, or its conditions where it has none (a
// rule built in code).
func (r Rule) label() string {
	if r.Name != "" {
		return r.Name
	}
	return r.String()
}

// Validate refuses a rule that approves nothing or more than it reads as;
// such a rule attaches to nothing and the run looks like a quiet host.
// Conditions combine, so only a rule that can match nothing is refused.
func (r Rule) Validate() error {
	if !r.conditions() {
		return errors.New("a target names at least one of a pid, an executable, arguments, a cgroup or a port, " +
			"and this one names none")
	}
	if r.Executable != "" && !filepath.IsAbs(r.Executable) {
		// Relative paths match nothing: /proc/<pid>/exe is absolute.
		return fmt.Errorf("%q is not an absolute path", r.Executable)
	}
	if r.Executable == "" && r.Arguments != nil && len(r.Arguments) == 0 {
		return errors.New("arguments alone with none written approve every process run with no arguments, " +
			"whatever file it runs")
	}
	if r.Cgroup != "" {
		if !filepath.IsAbs(r.Cgroup) {
			return fmt.Errorf("%q is not an absolute cgroup path", r.Cgroup)
		}
		if strings.TrimSuffix(r.Cgroup, "/") == "" {
			// The root cgroup holds every process: host-wide observation.
			return errors.New("the root cgroup is every process on the host, which is not something an approval may name")
		}
	}
	if r.Interface != "" {
		if r.Port == 0 {
			return errors.New("an interface narrows a port, and this target names no port")
		}
		if strings.TrimSpace(r.Interface) != r.Interface || strings.ContainsAny(r.Interface, " /") {
			return fmt.Errorf("%q is not an interface name", r.Interface)
		}
	}
	if r.PID != nil {
		switch {
		case r.PID.PID <= 0:
			return fmt.Errorf("pid %d names no process", r.PID.PID)
		case r.PID.Start == 0:
			return fmt.Errorf("pid %d names no start time, so it would match whatever holds the number "+
				"when it is read", r.PID.PID)
		case r.PID.Boot == "":
			return fmt.Errorf("pid %d names no boot, so the same number and start in another boot "+
				"would match it", r.PID.PID)
		}
	}
	return nil
}

// Approval is what a configuration approved for observation: the processes,
// and optionally the exact library builds and offsets a probe may use.
type Approval struct {
	Rules []Rule `json:"rules"`

	// Exclusions deny a subtree: matched instances and all their descendants are
	// never observed, and no rule overrides that. They are resolved together with
	// the rules, so an excluded program absent at the first scan cannot escape.
	Exclusions []Rule `json:"exclusions,omitempty"`

	// Libraries is the attach policy: approved libssl builds by build id, with
	// every entry point's offset. Empty places a probe on whatever the process
	// maps. Non-empty refuses a library or offset nobody approved, rather than
	// trusting the resolver. preflight.Take produces the offsets.
	Libraries []LibraryApproval `json:"libraries,omitempty"`
}

// LibraryApproval is one approved build of a library and the offsets its entry
// points are approved at.
type LibraryApproval struct {
	// BuildID is the GNU build id, lowercase hex, as readelf -n prints it: it pins
	// the exact binary.
	BuildID string `json:"build_id"`

	// Symbols maps an entry point to its approved file offset. A resolved offset
	// not named, or named differently, is refused.
	Symbols map[string]uint64 `json:"symbols"`
}

// Validate reports what would make a library approval unusable.
func (l LibraryApproval) Validate() error {
	if l.BuildID == "" {
		return errors.New("a library approval names a build by its build id, and this one names none")
	}
	if len(l.Symbols) == 0 {
		return errors.New("a library approval names the offsets its entry points are approved at, and this one names none")
	}
	return nil
}

// ApproveLibrary reports whether a resolved library is within the policy: its
// build id approved and every resolved offset the approved one. An empty
// policy approves any library. The caller refuses the whole attachment on an
// error rather than dropping one probe.
func (a Approval) ApproveLibrary(buildID string, offsets map[string]uint64) error {
	if len(a.Libraries) == 0 {
		return nil
	}
	var approved *LibraryApproval
	for i := range a.Libraries {
		if a.Libraries[i].BuildID == buildID {
			approved = &a.Libraries[i]
			break
		}
	}
	if approved == nil {
		return fmt.Errorf("the library's build id %s is not approved", buildID)
	}
	for symbol, offset := range offsets {
		want, named := approved.Symbols[symbol]
		if !named {
			return fmt.Errorf("%s resolves to offset %#x, which the policy does not name", symbol, offset)
		}
		if want != offset {
			return fmt.Errorf("%s resolves to offset %#x, but the policy approves it at %#x", symbol, offset, want)
		}
	}
	return nil
}

// Observes reports whether p is approved in its own right; Select handles
// ancestry.
func (a Approval) Observes(p Process) bool {
	return slices.ContainsFunc(a.Rules, func(rule Rule) bool { return rule.Matches(p) })
}

// Match is one rule and the processes it named in the table. Descendants
// belong to the named process, not the rule.
type Match struct {
	// Rule is the configured rule; Number its position from one.
	Rule   Rule
	Number int

	Matched []Process
}

// Matches is what each rule named in this table, in order, including rules
// that named nothing - otherwise invisible downstream, since the run attaches
// to what other rules matched.
func (a Approval) Matches(t Table) []Match {
	matches := make([]Match, len(a.Rules))
	for i, rule := range a.Rules {
		matches[i] = Match{Rule: rule, Number: i + 1}
		for _, p := range t.processes {
			if rule.Matches(p) {
				matches[i].Matched = append(matches[i].Matched, p)
			}
		}
	}
	return matches
}

// Select is every observed process in the table: those a rule names and their
// descendants (a per-connection forking server transfers in its children). A
// descendant of an unnamed process is not included.
func (a Approval) Select(t Table) []Process {
	if len(a.Rules) == 0 {
		return nil
	}

	observed := make(map[int32]bool, len(t.processes))
	for _, p := range t.processes {
		if a.Observes(p) {
			observed[p.PID] = true
		}
	}

	// Each process is walked up to a named one or the top, bounded by the table
	// size since a racing read can hand back a dangling parent link.
	var selected []Process
	for _, p := range t.processes {
		if _, found := a.root(t, observed, p); found {
			selected = append(selected, p)
		}
	}
	return selected
}

// LegacyMode is what an approval with no mode field means: take the existing
// descendants and follow new ones, which is follow. The configuration file
// states a mode explicitly.
const LegacyMode = admission.ModeFollow

// Denials is what the exclusions deny in this table: matched instances and
// all their descendants, each with the exclusion and, for a descendant, the
// instance the denial came from. Existing descendants are included here
// because the fork hook sees only what is created afterwards.
func (a Approval) Denials(t Table) []admission.Denial {
	if len(a.Exclusions) == 0 {
		return nil
	}

	matched := make(map[int32]int, len(t.processes))
	for _, p := range t.processes {
		for i, rule := range a.Exclusions {
			if rule.Matches(p) {
				matched[p.PID] = i + 1
				break
			}
		}
	}
	if len(matched) == 0 {
		return nil
	}

	excluded := make(map[int32]bool, len(matched))
	for pid := range matched {
		excluded[pid] = true
	}

	var denials []admission.Denial
	for _, p := range t.processes {
		root, found := a.root(t, excluded, p)
		if !found {
			continue
		}
		number := matched[root.PID]
		denial := admission.Denial{
			Instance:    p.Instance(),
			Provenance:  admission.Provenance{Target: a.Exclusions[number-1].String(), Number: number},
			ObserverPID: p.PID,
		}
		if root.PID != p.PID {
			denial.Provenance.Parent = admission.Key{
				Namespace: root.Namespace,
				PID:       root.NamespacePID,
			}
		}
		denials = append(denials, denial)
	}
	return denials
}

// Selections is what to admit, one entry per process, with why: the rule, its
// position and, for a descendant, the instance the grant came from. Denied
// subtrees are absent. Every rule naming a process is carried, not just the
// first (admission.Selection.AlsoNamedBy), so withdrawing one rule removes a
// reason rather than the grant.
func (a Approval) Selections(t Table) []admission.Selection {
	if len(a.Rules) == 0 {
		return nil
	}
	return a.Resolve(Host{Table: t}).Selections
}

func (a Approval) provenance(number int) admission.Provenance {
	return admission.Provenance{Target: a.Rules[number-1].label(), Number: number}
}

// root is p's nearest marked ancestor, p itself if marked: one definition of
// a subtree for both selection and denial.
func (a Approval) root(t Table, observed map[int32]bool, p Process) (Process, bool) {
	for steps := 0; steps <= len(t.processes); steps++ {
		if observed[p.PID] {
			return p, true
		}
		parent, ok := t.Lookup(p.PPID)
		if !ok || parent.PID == p.PID {
			return Process{}, false
		}
		p = parent
	}
	return Process{}, false
}

// Mapping is one file-backed region of a process's address space from
// /proc/<pid>/maps; anonymous and kernel-named regions are omitted.
type Mapping struct {
	// Path is the file as resolved when mapped; a replaced or removed file keeps
	// its old path with the kernel's marker.
	Path string
	// Executable reports whether any part of the file is mapped executable: a
	// running library rather than a file being read.
	Executable bool
}

// mapsFields is how many maps fields precede the path; the path is the rest,
// since file names may hold spaces.
const mapsFields = 5

// Network is a process's network namespace, as its nsfs device and inode. It
// must be read before the capability drop, which refuses /proc/<pid>/ns/net
// (and /proc/<pid>/fd) for other users' processes; an unread namespace stays
// unknown. It scopes an address: two containers can each hold 10.0.0.2:8443.
func Network(root string, pid int32) (uint64, uint64, error) {
	path := filepath.Join(root, strconv.FormatInt(int64(pid), 10), "ns", "net")
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, fmt.Errorf("read the network namespace of pid %d: %w", pid, err)
	}
	held, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("the network namespace of pid %d is not a file this can name", pid)
	}
	return uint64(held.Dev), held.Ino, nil
}

// Sockets is the descriptors a process holds that are sockets, from
// /proc/<pid>/fd ("socket:[inode]" links), in descriptor order. An unreadable
// link is a descriptor closed mid-read and is skipped.
func Sockets(root string, pid int32) ([]int32, error) {
	directory := filepath.Join(root, strconv.FormatInt(int64(pid), 10), "fd")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read the descriptors of pid %d: %w", pid, err)
	}

	held := make([]int32, 0, len(entries))
	for _, entry := range entries {
		number, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		target, err := os.Readlink(filepath.Join(directory, entry.Name()))
		if err != nil {
			continue
		}
		if !strings.HasPrefix(target, "socket:[") {
			continue
		}
		held = append(held, int32(number))
	}
	slices.Sort(held)
	return held, nil
}

// Mappings is the files this process maps, one entry per file, in kernel
// order.
func Mappings(root string, pid int32) ([]Mapping, error) {
	path := filepath.Join(root, strconv.FormatInt(int64(pid), 10), "maps")

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var mappings []Mapping
	seen := make(map[string]int)
	for line := range strings.Lines(string(content)) {
		fields := strings.SplitN(strings.TrimSpace(line), " ", mapsFields+1)
		if len(fields) <= mapsFields {
			continue
		}
		file := strings.TrimSpace(fields[mapsFields])
		// Kernel-named regions (stack, heap, vdso) are bracketed and are not files.
		if file == "" || strings.HasPrefix(file, "[") {
			continue
		}

		executable := strings.Contains(fields[1], "x")
		if at, ok := seen[file]; ok {
			mappings[at].Executable = mappings[at].Executable || executable
			continue
		}
		seen[file] = len(mappings)
		mappings = append(mappings, Mapping{Path: file, Executable: executable})
	}
	return mappings, nil
}

// Identify reads one process directly, for one that appears mid-watch.
func Identify(root string, pid int32) (Process, error) {
	p, err := readProcess(root, pid)
	if err != nil {
		return Process{}, fmt.Errorf("read pid %d: %w", pid, err)
	}
	return p, nil
}

// Descends reports whether pid is below ancestor. The walk is bounded: racing
// reads can hand back dangling parent links, and orphans are reparented.
func Descends(root string, pid, ancestor int32) bool {
	const generations = 64

	for at, steps := pid, 0; steps < generations; steps++ {
		if at == ancestor {
			return true
		}
		p, err := readProcess(root, at)
		if err != nil || p.PPID == at || p.PPID <= 0 {
			return false
		}
		at = p.PPID
	}
	return false
}

// Descendants is a process and everything below it in one reading, so a
// forking server's children are known while alive. The whole table is read:
// the per-thread children files are not reliable (observed empty while a
// child existed).
func (t Table) Descendants(ancestor int32) []Process {
	var found []Process
	for _, p := range t.processes {
		if t.descends(p, ancestor) {
			found = append(found, p)
		}
	}
	return found
}

func (t Table) descends(p Process, ancestor int32) bool {
	for steps := 0; steps <= len(t.processes); steps++ {
		if p.PID == ancestor {
			return true
		}
		parent, ok := t.Lookup(p.PPID)
		if !ok || parent.PID == p.PID {
			return false
		}
		p = parent
	}
	return false
}

// StartTimesAreOffset reports whether /proc start times are shifted from the
// kernel's own, and by how much. In a time namespace of its own, the reader
// sees starts moved by that namespace's boottime offset while a BPF program
// reads the unmoved value; the shift is one constant for every process. It is
// read from /proc/self/timens_offsets; a kernel without time namespaces has no
// such file, which is an offset of zero.
func StartTimesAreOffset(root string) (offset time.Duration, err error) {
	content, err := os.ReadFile(filepath.Join(root, "self", "timens_offsets"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read the time namespace offsets: %w", err)
	}

	for line := range strings.Lines(string(content)) {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "boottime" {
			continue
		}
		seconds, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("the boottime offset's seconds: %w", err)
		}
		nanoseconds, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("the boottime offset's nanoseconds: %w", err)
		}
		return time.Duration(seconds)*time.Second + time.Duration(nanoseconds), nil
	}
	// The file exists and names no boottime offset: an unknown shape, not zero.
	return 0, errors.New("the time namespace offsets name no boottime")
}
