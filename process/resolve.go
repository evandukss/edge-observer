package process

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/evandukss/edge-observer/admission"
)

// PIDGuard names one process instance by its number in the observer's pid
// namespace, its start time and its boot. Pids are reused within a boot and
// restart at boot, so a number held by anything else is refused, never
// re-resolved.
type PIDGuard struct {
	PID int32

	// Start is the start time in clock ticks since boot (/proc/<pid>/stat field
	// 22), as a dry run prints it.
	Start uint64

	// Boot is the boot id from /proc/sys/kernel/random/boot_id.
	Boot string
}

// Listener is one listening TCP socket a process holds.
type Listener struct {
	Inode   uint64
	Port    uint16
	Address netip.Addr
}

func (l Listener) String() string {
	return netip.AddrPortFrom(l.Address, l.Port).String()
}

// ListeningSocket is one listening TCP socket in the reader's network namespace
// and every process found holding it.
type ListeningSocket struct {
	Listener
	Owners []int32
}

// Listeners is one reading of the listening sockets in the reader's network
// namespace and who holds each. Unreadable is every process whose descriptor
// table could not be read: a socket no readable table holds has an unknown
// owner, not none.
type Listeners struct {
	Sockets    []ListeningSocket
	Unreadable []int32
}

// listenState is TCP_LISTEN as /proc/net/tcp writes it.
const listenState = "0A"

// ReadListeners reads the listening TCP sockets of the reader's own network
// namespace under root (/proc on a running host) and which processes hold
// each. Another namespace's same port is an unrelated socket. Holders are found
// by socket inode in their descriptor tables, whatever their namespace.
func ReadListeners(root string) (Listeners, error) {
	var sockets []ListeningSocket
	for _, table := range []struct {
		name     string
		required bool
	}{{"tcp", true}, {"tcp6", false}} {
		found, err := listeningIn(filepath.Join(root, "net", table.name))
		if errors.Is(err, fs.ErrNotExist) && !table.required {
			// A kernel without IPv6 publishes no tcp6 table.
			continue
		}
		if err != nil {
			return Listeners{}, err
		}
		sockets = append(sockets, found...)
	}

	at := make(map[uint64]int, len(sockets))
	for i, one := range sockets {
		at[one.Inode] = i
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return Listeners{}, fmt.Errorf("read %s: %w", root, err)
	}
	var unreadable []int32
	for _, entry := range entries {
		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		directory := filepath.Join(root, entry.Name(), "fd")
		descriptors, err := os.ReadDir(directory)
		if errors.Is(err, fs.ErrNotExist) {
			// Gone between listing and reading: ordinary.
			continue
		}
		if err != nil {
			unreadable = append(unreadable, int32(pid))
			continue
		}
		// Listing the directory and reading a link are separate checks: the listing
		// passes with CAP_DAC_OVERRIDE, but each link is a ptrace access check that
		// another user's process refuses without CAP_SYS_PTRACE. So an unreadable link
		// makes the table unreadable; only a vanished link is skipped.
		refused := false
		for _, descriptor := range descriptors {
			target, err := os.Readlink(filepath.Join(directory, descriptor.Name()))
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) && !refused {
					refused = true
					unreadable = append(unreadable, int32(pid))
				}
				continue
			}
			inode, isSocket := socketInode(target)
			if !isSocket {
				continue
			}
			if index, listening := at[inode]; listening {
				sockets[index].Owners = append(sockets[index].Owners, int32(pid))
			}
		}
	}
	return Listeners{Sockets: sockets, Unreadable: unreadable}, nil
}

// socketInode reads the inode out of a descriptor link the kernel writes as
// "socket:[inode]".
func socketInode(target string) (uint64, bool) {
	inside, found := strings.CutPrefix(target, "socket:[")
	if !found {
		return 0, false
	}
	inside, found = strings.CutSuffix(inside, "]")
	if !found {
		return 0, false
	}
	inode, err := strconv.ParseUint(inside, 10, 64)
	return inode, err == nil
}

// listeningIn reads one kernel TCP table and keeps the listening sockets. The
// local address is written in hex one 32-bit word at a time in host order, and
// is converted back to network order here.
func listeningIn(path string) ([]ListeningSocket, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var found []ListeningSocket
	lines := bufio.NewScanner(file)
	first := true
	for lines.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(lines.Text())
		if len(fields) < 10 || fields[3] != listenState {
			continue
		}
		address, port, err := parseLocal(fields[1])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: inode %q: %w", path, fields[9], err)
		}
		found = append(found, ListeningSocket{Listener: Listener{Inode: inode, Port: port, Address: address}})
	}
	if err := lines.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return found, nil
}

func parseLocal(field string) (netip.Addr, uint16, error) {
	hexAddress, hexPort, found := strings.Cut(field, ":")
	if !found {
		return netip.Addr{}, 0, fmt.Errorf("local address %q has no port", field)
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("port %q: %w", hexPort, err)
	}
	raw, err := hex.DecodeString(hexAddress)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, fmt.Errorf("local address %q is not an address", hexAddress)
	}
	for word := 0; word < len(raw); word += 4 {
		raw[word], raw[word+1], raw[word+2], raw[word+3] = raw[word+3], raw[word+2], raw[word+1], raw[word]
	}
	address, _ := netip.AddrFromSlice(raw)
	return address, uint16(port), nil
}

// ReadBoot reads the boot id under root: what a pid condition's start time is
// relative to.
func ReadBoot(root string) (string, error) {
	content, err := os.ReadFile(filepath.Join(root, "sys", "kernel", "random", "boot_id"))
	if err != nil {
		return "", fmt.Errorf("read the boot id: %w", err)
	}
	boot := strings.TrimSpace(string(content))
	if boot == "" {
		return "", errors.New("read the boot id: the file is empty")
	}
	return boot, nil
}

// TableOf is a table holding exactly these processes.
func TableOf(processes ...Process) Table {
	table := Table{processes: processes, byPID: make(map[int32]Process, len(processes))}
	for _, p := range processes {
		table.byPID[p.PID] = p
	}
	return table
}

// WithListeners is this table with each process carrying its listening sockets,
// keeping the reading so an unresolved port can say why.
func (t Table) WithListeners(listeners Listeners) Table {
	held := make(map[int32][]Listener)
	for _, socket := range listeners.Sockets {
		for _, owner := range socket.Owners {
			held[owner] = append(held[owner], socket.Listener)
		}
	}
	processes := make([]Process, len(t.processes))
	for i, p := range t.processes {
		p.Listening = held[p.PID]
		processes[i] = p
	}
	table := TableOf(processes...)
	table.listeners = &listeners
	table.unreadable = t.unreadable
	return table
}

// Host is everything a resolution reads besides the policy: processes, boot,
// interface addresses and the cgroup mount.
type Host struct {
	Table Table

	// Boot is the host's boot id, empty where unread; a pid condition then refuses
	// to match.
	Boot string

	// Interfaces turns an interface name into its addresses; nil uses
	// net.InterfaceByName.
	Interfaces func(name string) ([]netip.Prefix, error)

	// CgroupRoot is where the unified hierarchy is mounted; empty is
	// /sys/fs/cgroup.
	CgroupRoot string
}

// defaultCgroupRoot is the conventional unified hierarchy mount point.
const defaultCgroupRoot = "/sys/fs/cgroup"

// CgroupObject is the object a cgroup path resolved to: its inode, which is
// the kernel's cgroup id. A recreated path is a new object.
type CgroupObject struct {
	Path  string
	Inode uint64

	// Why is where the path named no readable object; empty where Inode holds one.
	Why string
}

// Resolved is one target and what it resolved to at that moment.
type Resolved struct {
	Number int
	Name   string
	Mode   admission.Mode

	// Conditions is the target's conditions, arguments included: local view only.
	Conditions string

	// Roots is every process meeting every condition and not denied; Denied is
	// those an exclusion denies.
	Roots  []Process
	Denied []Process

	// Descendants is every already-running process below a root that this
	// target's mode admits (none under ModeNone).
	Descendants []Process

	// Unresolved is why the target selected nothing; empty where it selected
	// something.
	Unresolved string

	// Cgroup is the object a cgroup condition resolved to; nil if none named.
	Cgroup *CgroupObject

	// Listeners is every listening socket a port condition resolved to, with its
	// holders; nil if none named.
	Listeners []ListeningSocket
}

// Excluded is one exclusion and what it denied: matched processes and
// everything below them.
type Excluded struct {
	Number int
	Roots  []Process
	Denied []Process
}

// Resolution is a policy resolved against one reading of the host: per target
// and exclusion what it came to, and the grants and denials for the kernel
// side.
type Resolution struct {
	Targets    []Resolved
	Exclusions []Excluded
	Selections []admission.Selection
	Denials    []admission.Denial
}

// Resolve resolves the approval against the host in one traversal, so every
// answer (naming target, denying exclusion, admitted descendants, why nothing
// was selected) comes from the same walk. A process named by several targets
// is selected once, filed under the first, carrying the others, with the
// union of their modes.
func (a Approval) Resolve(host Host) Resolution {
	prepared, refused := a.prepare(host)
	table := host.Table

	named := make(map[int32][]int)
	matched := make([][]Process, len(prepared.Rules))
	for _, p := range table.processes {
		for i, rule := range prepared.Rules {
			if refused[i] != "" {
				continue
			}
			if rule.Matches(p) {
				named[p.PID] = append(named[p.PID], i+1)
				matched[i] = append(matched[i], p)
			}
		}
	}

	denials := prepared.Denials(table)
	forbidden := make(map[int32]bool, len(denials))
	for _, one := range denials {
		forbidden[one.ObserverPID] = true
	}

	resolution := Resolution{Denials: denials}
	descendants := make([][]Process, len(prepared.Rules))
	for _, p := range table.processes {
		if forbidden[p.PID] {
			continue
		}
		numbers, isNamed := named[p.PID]
		granting, inherits := prepared.granting(table, named, p)
		switch {
		case isNamed:
			selection := admission.Selection{
				Instance:    p.Instance(),
				Kind:        admission.ByTarget,
				Provenance:  prepared.provenance(numbers[0]),
				Mode:        prepared.union(numbers),
				ObserverPID: p.PID,
			}
			for _, number := range numbers[1:] {
				selection.AlsoNamedBy = append(selection.AlsoNamedBy, prepared.provenance(number))
			}
			if inherits {
				// Named in its own right and below an admitting root: it keeps its own
				// reasons and the broader permission.
				selection.Mode = broader(selection.Mode, prepared.union(named[granting.PID]))
			}
			resolution.Selections = append(resolution.Selections, selection)
		case inherits:
			through := named[granting.PID]
			selection := admission.Selection{
				Instance:    p.Instance(),
				Kind:        admission.ByDescent,
				Provenance:  prepared.provenance(through[0]),
				Mode:        prepared.union(through),
				ObserverPID: p.PID,
			}
			for _, number := range through[1:] {
				selection.AlsoNamedBy = append(selection.AlsoNamedBy, prepared.provenance(number))
			}
			// A descendant's grant belongs to the instance it was inherited from, so
			// withdrawing that grant can find this one. The allowlist stamps the
			// generation.
			selection.Provenance.Parent = admission.Key{Namespace: granting.Namespace, PID: granting.NamespacePID}
			resolution.Selections = append(resolution.Selections, selection)
			descendants[through[0]-1] = append(descendants[through[0]-1], p)
		}
	}

	cgroupRoot := host.CgroupRoot
	if cgroupRoot == "" {
		cgroupRoot = defaultCgroupRoot
	}
	for i, rule := range prepared.Rules {
		one := Resolved{Number: i + 1, Name: rule.label(), Mode: modeOf(rule), Conditions: rule.String(),
			Descendants: descendants[i]}
		for _, p := range matched[i] {
			if forbidden[p.PID] {
				one.Denied = append(one.Denied, p)
			} else {
				one.Roots = append(one.Roots, p)
			}
		}
		if rule.Cgroup != "" {
			one.Cgroup = objectOf(cgroupRoot, rule.Cgroup)
		}
		if rule.Port != 0 && table.listeners != nil {
			one.Listeners = rule.sockets(*table.listeners)
		}
		if len(one.Roots) == 0 {
			one.Unresolved = prepared.unresolved(rule, refused[i], one, table, host.Boot)
		}
		resolution.Targets = append(resolution.Targets, one)
	}

	for i, exclusion := range prepared.Exclusions {
		one := Excluded{Number: i + 1}
		for _, p := range table.processes {
			if exclusion.Matches(p) {
				one.Roots = append(one.Roots, p)
			}
		}
		for _, denial := range denials {
			if denial.Provenance.Number == i+1 {
				if p, found := table.Lookup(denial.ObserverPID); found {
					one.Denied = append(one.Denied, p)
				}
			}
		}
		resolution.Exclusions = append(resolution.Exclusions, one)
	}
	return resolution
}

// prepare resolves every named interface to addresses and gives the reason
// each target was refused before any process was examined: a pid for another
// boot, an unread boot, a missing interface. An exclusion whose interface
// cannot be resolved resolves to no address and denies nothing.
func (a Approval) prepare(host Host) (Approval, []string) {
	lookup := host.Interfaces
	if lookup == nil {
		lookup = interfaceAddresses
	}
	prepared := a
	prepared.Rules = make([]Rule, len(a.Rules))
	refused := make([]string, len(a.Rules))
	for i, rule := range a.Rules {
		if rule.PID != nil {
			switch {
			case host.Boot == "":
				refused[i] = fmt.Sprintf("the host's boot id was not read, so pid %d written for boot %s "+
					"cannot be told from the same number in another boot", rule.PID.PID, rule.PID.Boot)
			case host.Boot != rule.PID.Boot:
				refused[i] = fmt.Sprintf("pid %d was written for boot %s and this host is boot %s, so the "+
					"number names nothing this target was written for", rule.PID.PID, rule.PID.Boot, host.Boot)
			}
		}
		if rule.Interface != "" {
			addresses, err := lookup(rule.Interface)
			if err != nil && refused[i] == "" {
				refused[i] = fmt.Sprintf("interface %s could not be resolved to addresses: %v", rule.Interface, err)
			}
			rule.addresses, rule.resolvedInterface = addresses, err == nil
		}
		prepared.Rules[i] = rule
	}
	prepared.Exclusions = make([]Rule, len(a.Exclusions))
	for i, exclusion := range a.Exclusions {
		if exclusion.Interface != "" {
			addresses, err := lookup(exclusion.Interface)
			exclusion.addresses, exclusion.resolvedInterface = addresses, err == nil
		}
		prepared.Exclusions[i] = exclusion
	}
	return prepared, refused
}

func interfaceAddresses(name string) ([]netip.Prefix, error) {
	held, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addresses, err := held.Addrs()
	if err != nil {
		return nil, err
	}
	var prefixes []netip.Prefix
	for _, one := range addresses {
		network, isNetwork := one.(*net.IPNet)
		if !isNetwork {
			continue
		}
		address, ok := netip.AddrFromSlice(network.IP)
		if !ok {
			continue
		}
		bits, _ := network.Mask.Size()
		prefixes = append(prefixes, netip.PrefixFrom(address.Unmap(), bits))
	}
	return prefixes, nil
}

// granting is p's nearest ancestor that a target named and whose modes admit
// existing descendants, walking past named ancestors whose modes do not.
// Bounded by the table size.
func (a Approval) granting(t Table, named map[int32][]int, p Process) (Process, bool) {
	at := p
	for steps := 0; steps <= len(t.processes); steps++ {
		parent, found := t.Lookup(at.PPID)
		if !found || parent.PID == at.PID {
			return Process{}, false
		}
		if numbers, isNamed := named[parent.PID]; isNamed && a.union(numbers).Answers().Existing {
			return parent, true
		}
		at = parent
	}
	return Process{}, false
}

// union is the broadest mode among these targets.
func (a Approval) union(numbers []int) admission.Mode {
	mode := admission.ModeUnset
	for _, number := range numbers {
		mode = broader(mode, modeOf(a.Rules[number-1]))
	}
	return mode
}

// broader is whichever of two modes permits more.
func broader(one, other admission.Mode) admission.Mode {
	rank := func(mode admission.Mode) int {
		switch mode {
		case admission.ModeNone:
			return 1
		case admission.ModeExisting:
			return 2
		case admission.ModeFollow:
			return 3
		default:
			return 0
		}
	}
	if rank(other) > rank(one) {
		return other
	}
	return one
}

// modeOf is a rule's descendant mode: LegacyMode for a rule built in code
// without one; configuration rules always carry one (package policy refuses
// otherwise).
func modeOf(rule Rule) admission.Mode {
	if rule.Mode == admission.ModeUnset {
		return LegacyMode
	}
	return rule.Mode
}

// objectOf is the object a cgroup path names now.
func objectOf(root, path string) *CgroupObject {
	info, err := os.Stat(filepath.Join(root, path))
	if err != nil {
		return &CgroupObject{Path: path, Why: fmt.Sprintf("the path names no cgroup that could be read: %v", err)}
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return &CgroupObject{Path: path, Why: "this platform does not say which object the path is"}
	}
	return &CgroupObject{Path: path, Inode: stat.Ino}
}

// sockets is every listening socket this rule's port and interface resolve to.
func (r Rule) sockets(listeners Listeners) []ListeningSocket {
	var found []ListeningSocket
	for _, socket := range listeners.Sockets {
		if socket.Port == r.Port && r.bound(socket.Address) {
			found = append(found, socket)
		}
	}
	return found
}

// unresolved is why a target selected nothing, most specific reason first.
func (a Approval) unresolved(rule Rule, refused string, one Resolved, table Table, boot string) string {
	switch {
	case refused != "":
		return refused
	case len(one.Denied) > 0:
		return "every process it matches is denied by an exclusion"
	}
	if rule.PID != nil {
		held, found := table.Lookup(rule.PID.PID)
		switch {
		case !found && slices.Contains(table.unreadable, rule.PID.PID):
			return fmt.Sprintf("pid %d is held by a process this observer may not read, so whether it is the "+
				"instance this target was written for is not known", rule.PID.PID)
		case !found:
			return fmt.Sprintf("no process holds pid %d", rule.PID.PID)
		case held.StartTime != rule.PID.Start:
			return fmt.Sprintf("pid %d is held by a process that started at tick %d, and this target was "+
				"written for the one that started at tick %d", rule.PID.PID, held.StartTime, rule.PID.Start)
		}
	}
	if rule.Port != 0 {
		if table.listeners == nil {
			return fmt.Sprintf("the listening sockets were not read, so port %d finds nothing", rule.Port)
		}
		where := "in the observer's network namespace"
		if rule.Interface != "" {
			where = "on interface " + rule.Interface
		}
		if len(one.Listeners) == 0 {
			return fmt.Sprintf("nothing listens on port %d %s", rule.Port, where)
		}
		owned := false
		for _, socket := range one.Listeners {
			owned = owned || len(socket.Owners) > 0
		}
		if !owned {
			// Two different reasons: a holder this observer may not see, and one that
			// closed the socket between the two readings.
			if unreadable := len(table.listeners.Unreadable); unreadable > 0 {
				return fmt.Sprintf("a listener on port %d %s exists and no descriptor table that could be read "+
					"holds it: the tables of %d processes could not be read, so its owner could not be read",
					rule.Port, where, unreadable)
			}
			return fmt.Sprintf("a listener on port %d %s exists and no process was found holding it with every "+
				"descriptor table read, so its holder closed it between the two readings", rule.Port, where)
		}
	}
	if unreadable := len(table.unreadable); unreadable > 0 {
		return fmt.Sprintf("no process this observer could read matches every condition of this target, and %d "+
			"processes could not be read, so whether one of them matches is not known", unreadable)
	}
	return "no process matches every condition of this target"
}
