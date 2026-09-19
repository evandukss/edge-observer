package process_test

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/process"
)

// The resolver's own logic, over processes described field by field; Read is
// tested against the real /proc elsewhere, and listeners come from real
// sockets.

var host = admission.Namespace{Device: 4, Inode: 4026531836}

// member is a process satisfying every predicate a target can name, so a case
// can remove exactly one.
func member(pid int32) process.Process {
	return process.Process{
		PID:          pid,
		PPID:         1,
		StartTime:    5000 + uint64(pid),
		Executable:   "/usr/bin/interpreter",
		Arguments:    []string{"interpreter", "/srv/one/main"},
		Cgroup:       "/system.slice/one.service",
		Namespace:    host,
		NamespacePID: pid,
	}
}

// listening is these processes' listeners: one socket each on the given port,
// bound to every address.
func listening(ports map[int32]uint16) process.Listeners {
	var sockets []process.ListeningSocket
	for pid, port := range ports {
		sockets = append(sockets, process.ListeningSocket{
			Listener: process.Listener{Inode: 7000 + uint64(pid), Port: port, Address: netip.IPv4Unspecified()},
			Owners:   []int32{pid},
		})
	}
	return process.Listeners{Sockets: sockets}
}

func selectedPIDs(resolution process.Resolution) []int32 {
	found := make([]int32, 0, len(resolution.Selections))
	for _, one := range resolution.Selections {
		found = append(found, one.ObserverPID)
	}
	slices.Sort(found)
	return found
}

// Four ANDed conditions, each falsified alone by a process matching the other
// three: this separates AND from OR and from a conjunction ignoring a term.
func TestATargetSelectsOnlyAProcessMatchingEveryCondition(t *testing.T) {
	all := member(10)

	noExecutable := member(11)
	noExecutable.Executable = "/usr/bin/other"

	noArguments := member(12)
	noArguments.Arguments = []string{"interpreter", "/srv/two/main"}

	noCgroup := member(13)
	noCgroup.Cgroup = "/system.slice/two.service"

	noPort := member(14)

	outside := member(15)
	outside.Executable, outside.Arguments, outside.Cgroup = "/usr/bin/unrelated", []string{"unrelated"}, "/user.slice"

	ports := map[int32]uint16{10: 8443, 11: 8443, 12: 8443, 13: 8443, 14: 9443, 15: 8443}
	table := process.TableOf(all, noExecutable, noArguments, noCgroup, noPort, outside).WithListeners(listening(ports))

	target := process.Rule{
		Name: "gateway", Executable: "/usr/bin/interpreter", Arguments: []string{"/srv/one/main"},
		Cgroup: "/system.slice/one.service", Port: 8443, Mode: admission.ModeNone,
	}
	got := selectedPIDs((process.Approval{Rules: []process.Rule{target}}).Resolve(process.Host{Table: table}))
	if !slices.Equal(got, []int32{10}) {
		t.Fatalf("a target naming four conditions selected %v, want only pid 10, which matches all four", got)
	}
}

// Each condition alone selects exactly the processes satisfying it, so the
// case above cannot pass vacuously.
func TestEachConditionAloneSelectsWhatSatisfiesIt(t *testing.T) {
	bare := member(20)
	bare.Arguments = []string{"interpreter"}
	withArguments := member(21)
	elsewhere := member(22)
	elsewhere.Executable, elsewhere.Cgroup = "/usr/bin/other", "/system.slice/two.service"

	ports := map[int32]uint16{20: 9443, 21: 8443, 22: 9443}
	table := process.TableOf(bare, withArguments, elsewhere).WithListeners(listening(ports))

	cases := []struct {
		name string
		rule process.Rule
		want []int32
	}{
		// An executable with arguments omitted means no arguments after argv[0].
		{"exe", process.Rule{Executable: "/usr/bin/interpreter"}, []int32{20}},
		{"args", process.Rule{Arguments: []string{"/srv/one/main"}}, []int32{21, 22}},
		{"cgroup", process.Rule{Cgroup: "/system.slice/one.service"}, []int32{20, 21}},
		{"port", process.Rule{Port: 8443}, []int32{21}},
	}
	for _, one := range cases {
		t.Run(one.name, func(t *testing.T) {
			one.rule.Name, one.rule.Mode = one.name, admission.ModeNone
			got := selectedPIDs((process.Approval{Rules: []process.Rule{one.rule}}).Resolve(process.Host{Table: table}))
			if !slices.Equal(got, one.want) {
				t.Errorf("%s alone selected %v, want %v", one.name, got, one.want)
			}
		})
	}
}

// A target's existing descendants get its mode's answer, and only that.
func TestTheModeDecidesWhichExistingDescendantsAreSelected(t *testing.T) {
	root := member(30)
	child := member(31)
	child.PPID = 30
	child.Executable, child.Arguments = "/usr/bin/worker", []string{"worker"}
	grandchild := member(32)
	grandchild.PPID = 31
	grandchild.Executable, grandchild.Arguments = "/usr/bin/worker", []string{"worker"}
	table := process.TableOf(root, child, grandchild)

	for _, one := range []struct {
		mode admission.Mode
		want []int32
	}{
		{admission.ModeNone, []int32{30}},
		{admission.ModeExisting, []int32{30, 31, 32}},
		{admission.ModeFollow, []int32{30, 31, 32}},
	} {
		t.Run(one.mode.String(), func(t *testing.T) {
			rule := process.Rule{Name: "root", Executable: "/usr/bin/interpreter",
				Arguments: []string{"/srv/one/main"}, Mode: one.mode}
			resolution := (process.Approval{Rules: []process.Rule{rule}}).Resolve(process.Host{Table: table})
			if got := selectedPIDs(resolution); !slices.Equal(got, one.want) {
				t.Fatalf("under %s the selection is %v, want %v", one.mode, got, one.want)
			}
			for _, selection := range resolution.Selections {
				if selection.Mode != one.mode {
					t.Errorf("pid %d carries mode %s under a target whose mode is %s",
						selection.ObserverPID, selection.Mode, one.mode)
				}
				if selection.ObserverPID != 30 && selection.Kind != admission.ByDescent {
					t.Errorf("descendant pid %d is %s, want admitted by descent", selection.ObserverPID, selection.Kind)
				}
			}
			if len(resolution.Targets) != 1 || len(resolution.Targets[0].Descendants) != len(one.want)-1 {
				t.Errorf("the target's account lists %v as its existing descendants, want %d of them",
					resolution.Targets, len(one.want)-1)
			}
		})
	}
}

// A process named by two targets is observed once, carries both reasons and
// gets the union: the broader mode admits its existing children even when the
// narrower target is listed first.
func TestAProcessNamedTwiceIsSelectedOnceWithBothReasonsAndTheUnionOfTheirModes(t *testing.T) {
	root := member(40)
	child := member(41)
	child.PPID = 40
	child.Executable, child.Arguments = "/usr/bin/worker", []string{"worker"}
	table := process.TableOf(root, child)

	approval := process.Approval{Rules: []process.Rule{
		{Name: "by-executable", Executable: "/usr/bin/interpreter", Arguments: []string{"/srv/one/main"}, Mode: admission.ModeNone},
		{Name: "by-cgroup", Cgroup: "/system.slice/one.service", Mode: admission.ModeExisting},
	}}
	resolution := approval.Resolve(process.Host{Table: table})

	var named *admission.Selection
	for i, one := range resolution.Selections {
		if one.ObserverPID == 40 {
			if named != nil {
				t.Fatal("pid 40 is selected twice")
			}
			named = &resolution.Selections[i]
		}
	}
	if named == nil {
		t.Fatalf("the process both targets name is not selected: %v", resolution.Selections)
	}
	var reasons []string
	for _, one := range named.NamedBy() {
		reasons = append(reasons, one.Target)
	}
	if !slices.Equal(reasons, []string{"by-executable", "by-cgroup"}) {
		t.Errorf("pid 40 is named by %v, want both targets in the order they are written", reasons)
	}
	if named.Mode != admission.ModeExisting {
		t.Errorf("pid 40 carries %s, want existing, the union of none and existing", named.Mode)
	}
	if got := selectedPIDs(resolution); !slices.Equal(got, []int32{40, 41}) {
		t.Errorf("the selection is %v, want the child admitted under the broader target", got)
	}
}

// A pid target names its start and boot; a number held by anything else is
// refused with the reason.
func TestAPIDTargetSelectsOnlyTheInstanceItWasWrittenFor(t *testing.T) {
	written := member(50)
	guard := &process.PIDGuard{PID: 50, Start: written.StartTime, Boot: "boot-one"}

	replaced := member(50)
	replaced.StartTime = written.StartTime + 1

	cases := []struct {
		name    string
		table   process.Table
		boot    string
		want    []int32
		because string
	}{
		{"the instance it names", process.TableOf(written), "boot-one", []int32{50}, ""},
		{"another process holding the number", process.TableOf(replaced), "boot-one", nil, "started at tick"},
		{"the same numbers in another boot", process.TableOf(written), "boot-two", nil, "boot"},
		{"a boot nobody read", process.TableOf(written), "", nil, "boot"},
		{"the number held by nothing", process.TableOf(member(51)), "boot-one", nil, "no process holds pid 50"},
	}
	for _, one := range cases {
		t.Run(one.name, func(t *testing.T) {
			rule := process.Rule{Name: "legacy-batch", PID: guard, Mode: admission.ModeNone}
			resolution := (process.Approval{Rules: []process.Rule{rule}}).Resolve(process.Host{Table: one.table, Boot: one.boot})
			if got := selectedPIDs(resolution); !slices.Equal(got, one.want) {
				t.Fatalf("selected %v, want %v", got, one.want)
			}
			if one.because == "" {
				if resolution.Targets[0].Unresolved != "" {
					t.Errorf("a resolved target says it is unresolved: %s", resolution.Targets[0].Unresolved)
				}
				return
			}
			if !strings.Contains(resolution.Targets[0].Unresolved, one.because) {
				t.Errorf("the target is reported as %q, want a reason naming %q", resolution.Targets[0].Unresolved, one.because)
			}
		})
	}
}

// A cgroup target records the object its path resolved to, so a recreated
// path is a different object.
func TestACgroupTargetRecordsTheObjectItsPathResolvedTo(t *testing.T) {
	cgroups := t.TempDir()
	path := "/system.slice/one.service"
	directory := filepath.Join(cgroups, path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatalf("make %s: %v", directory, err)
	}

	resolve := func() *process.CgroupObject {
		rule := process.Rule{Name: "service", Cgroup: path, Mode: admission.ModeNone}
		resolution := (process.Approval{Rules: []process.Rule{rule}}).Resolve(
			process.Host{Table: process.TableOf(member(60)), CgroupRoot: cgroups})
		return resolution.Targets[0].Cgroup
	}

	first := resolve()
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatalf("stat %s: %v", directory, err)
	}
	if first == nil || first.Inode != info.Sys().(*syscall.Stat_t).Ino {
		t.Fatalf("the target resolved to %+v, want the object at inode %d", first, info.Sys().(*syscall.Stat_t).Ino)
	}

	// A placeholder keeps the old inode from being reused at once.
	if err := os.Remove(directory); err != nil {
		t.Fatalf("remove %s: %v", directory, err)
	}
	placeholder := filepath.Join(cgroups, "placeholder")
	if err := os.Mkdir(placeholder, 0o755); err != nil {
		t.Fatalf("make %s: %v", placeholder, err)
	}
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatalf("recreate %s: %v", directory, err)
	}
	second := resolve()
	if second == nil || second.Inode == first.Inode {
		t.Fatalf("a recreated path resolved to %+v, the same object as before (%+v)", second, first)
	}

	if err := os.Remove(directory); err != nil {
		t.Fatalf("remove %s: %v", directory, err)
	}
	if gone := resolve(); gone == nil || gone.Inode != 0 || gone.Why == "" {
		t.Errorf("a path naming no object resolved to %+v, want no inode and a reason", gone)
	}
}

// Each target here approves nothing, or more than it reads as.
func TestValidateRefusesATargetThatCanMatchNothingOrReadsNarrowerThanItIs(t *testing.T) {
	cases := map[string]process.Rule{
		"a target naming no condition":       {},
		"a relative executable":              {Executable: "interpreter"},
		"a relative cgroup path":             {Cgroup: "system.slice/x.service"},
		"the root cgroup":                    {Cgroup: "/"},
		"an interface with no port":          {Interface: "lo"},
		"arguments alone and none of them":   {Arguments: []string{}},
		"a pid with no start":                {PID: &process.PIDGuard{PID: 8127, Boot: "b"}},
		"a pid with no boot":                 {PID: &process.PIDGuard{PID: 8127, Start: 1}},
		"a pid that names no process":        {PID: &process.PIDGuard{PID: 0, Start: 1, Boot: "b"}},
		"an interface naming nothing at all": {Port: 8443, Interface: " "},
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			if err := rule.Validate(); err == nil {
				t.Fatalf("Validate accepted %s", name)
			}
		})
	}
}

// Conditions once refused together are one ANDed target now.
func TestValidateAcceptsConditionsCombined(t *testing.T) {
	for _, rule := range []process.Rule{
		{Executable: "/usr/bin/interpreter", Cgroup: "/system.slice/one.service"},
		{Cgroup: "/system.slice/one.service", Arguments: []string{"--serve"}},
		{Arguments: []string{"/srv/one/main"}},
		{Port: 8443, Interface: "lo"},
		{PID: &process.PIDGuard{PID: 8127, Start: 1, Boot: "b"}, Executable: "/usr/bin/php"},
	} {
		if err := rule.Validate(); err != nil {
			t.Errorf("Validate refused %+v: %v", rule, err)
		}
	}
}

// listen binds a TCP listener and returns its file for a child to inherit.
func listen(t *testing.T, address string) (*net.TCPListener, *os.File) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("listen on %s: %v", address, err)
	}
	tcp := listener.(*net.TCPListener)
	file, err := tcp.File()
	if err != nil {
		t.Fatalf("take the listener's file: %v", err)
	}
	t.Cleanup(func() {
		_ = file.Close()
		_ = tcp.Close()
	})
	return tcp, file
}

// holding starts /bin/sleep with the given files as descriptors 3 onward, as a
// forking server's worker holds the listener.
func holding(t *testing.T, credential *syscall.Credential, files ...*os.File) int32 {
	t.Helper()
	command := exec.Command("/bin/sleep", "600")
	command.ExtraFiles = files
	if credential != nil {
		command.SysProcAttr = &syscall.SysProcAttr{Credential: credential}
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start a holder: %v", err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	// Waited for on its command line, since a holder of another user is left out
	// of the table but its command line stays readable.
	pid := int32(command.Process.Pid)
	for range 200 {
		cmdline, err := os.ReadFile(filepath.Join(procfs, strconv.Itoa(int(pid)), "cmdline"))
		if err == nil && strings.HasPrefix(string(cmdline), "/bin/sleep\x00") {
			return pid
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid %d is not running sleep after two seconds", pid)
	return 0
}

func portOf(t *testing.T, listener *net.TCPListener) uint16 {
	t.Helper()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func resolvedWithListeners(t *testing.T, rule process.Rule, interfaces func(string) ([]netip.Prefix, error)) process.Resolution {
	t.Helper()
	listeners, err := process.ReadListeners(procfs)
	if err != nil {
		t.Fatalf("read the listeners: %v", err)
	}
	table := read(t).WithListeners(listeners)
	rule.Mode = admission.ModeNone
	if rule.Name == "" {
		rule.Name = "listener"
	}
	return (process.Approval{Rules: []process.Rule{rule}}).Resolve(process.Host{Table: table, Interfaces: interfaces})
}

// A port finds the family holding the listener: the binder and every
// inheritor, on real sockets.
func TestAPortTargetResolvesToEveryProcessHoldingTheListener(t *testing.T) {
	listener, file := listen(t, "127.0.0.1:0")
	worker := holding(t, nil, file)
	self := int32(os.Getpid())

	resolution := resolvedWithListeners(t, process.Rule{Port: portOf(t, listener)}, nil)
	got := selectedPIDs(resolution)
	want := []int32{self, worker}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("a port target selected %v, want the process that bound it and the one that inherited it %v", got, want)
	}
	if len(resolution.Targets[0].Listeners) != 1 {
		t.Errorf("the target resolved to %d listeners, want the one socket both hold", len(resolution.Targets[0].Listeners))
	}
}

// Two services on one port, bound to different addresses: the interface
// selects one. Its addresses are given, since a container may have one
// interface.
func TestAnInterfaceNarrowsAPortToTheListenerBoundToItsAddresses(t *testing.T) {
	v4, v4file := listen(t, "127.0.0.1:0")
	port := portOf(t, v4)
	_, v6file := listen(t, "[::1]:"+strconv.Itoa(int(port)))
	onV4 := holding(t, nil, v4file)
	onV6 := holding(t, nil, v6file)
	// The test binary holds both; the holders one each.
	_ = v4file.Close()
	_ = v6file.Close()

	interfaces := func(name string) ([]netip.Prefix, error) {
		if name != "front" {
			return nil, errors.New("no such interface")
		}
		return []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}, nil
	}
	got := selectedPIDs(resolvedWithListeners(t, process.Rule{Port: port, Interface: "front"}, interfaces))
	if !slices.Contains(got, onV4) || slices.Contains(got, onV6) {
		t.Fatalf("port %d on interface front selected %v, want pid %d and not pid %d", port, got, onV4, onV6)
	}

	// The real loopback holds both addresses, so both are found there.
	got = selectedPIDs(resolvedWithListeners(t, process.Rule{Port: port, Interface: "lo"}, nil))
	if !slices.Contains(got, onV4) || !slices.Contains(got, onV6) {
		t.Errorf("port %d on lo selected %v, want both %d and %d", port, got, onV4, onV6)
	}
}

// A port nothing listens on is unresolved with that reason.
func TestAPortNothingListensOnIsUnresolvedWithTheReason(t *testing.T) {
	// Both halves closed: the file is a second descriptor keeping it listening.
	closed, file := listen(t, "127.0.0.1:0")
	port := portOf(t, closed)
	_ = file.Close()
	_ = closed.Close()

	resolution := resolvedWithListeners(t, process.Rule{Port: port}, nil)
	if got := selectedPIDs(resolution); len(got) != 0 {
		t.Fatalf("a port nothing listens on selected %v", got)
	}
	if why := resolution.Targets[0].Unresolved; !strings.Contains(why, "nothing listens on port "+strconv.Itoa(int(port))) {
		t.Errorf("the target is reported as %q, want that nothing listens on port %d", why, port)
	}
}

// A listener held only by a process whose descriptors are unreadable has an
// unknown owner, and that is said. The holder runs as another user.
func TestAListenerWhoseOwnerCannotBeReadIsUnresolvedRatherThanEmpty(t *testing.T) {
	listener, file := listen(t, "127.0.0.1:0")
	holder := holding(t, &syscall.Credential{Uid: 65534, Gid: 65534}, file)
	_ = file.Close()
	_ = listener.Close()

	// Wiring, not the property: the holder's descriptor link must really be
	// closed to this reader. The link is checked, not the directory, which
	// CAP_DAC_OVERRIDE lists anyway.
	if _, err := os.Readlink(filepath.Join(procfs, strconv.Itoa(int(holder)), "fd", "3")); err == nil {
		t.Fatalf("precondition: pid %d's inherited descriptor is readable here, so no owner is unknown and this case measures nothing", holder)
	}

	// The reading names whose table it could not read.
	listeners, err := process.ReadListeners(procfs)
	if err != nil {
		t.Fatalf("read the listeners: %v", err)
	}
	if !slices.Contains(listeners.Unreadable, holder) {
		t.Fatalf("pid %d holds the listener behind a descriptor this reader cannot read, and the reading names "+
			"%v as unreadable", holder, listeners.Unreadable)
	}

	resolution := resolvedWithListeners(t, process.Rule{Port: portOf(t, listener)}, nil)
	if got := selectedPIDs(resolution); len(got) != 0 {
		t.Fatalf("a listener nobody readable holds selected %v", got)
	}
	if why := resolution.Targets[0].Unresolved; !strings.Contains(why, "could not be read") {
		t.Errorf("the target is reported as %q, want that the owner could not be read", why)
	}
}

// A process this reader may not look at is not an absence: a target selecting
// nothing says some processes could not be compared.
func TestAProcessThisReaderMayNotReadIsNamedAsUnreadableRatherThanAbsent(t *testing.T) {
	// Its argument is unique here, so no readable process satisfies the target
	// instead.
	sleeper := exec.Command("/bin/sleep", "600.125")
	sleeper.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if err := sleeper.Start(); err != nil {
		t.Fatalf("start a process under another user: %v", err)
	}
	t.Cleanup(func() {
		_ = sleeper.Process.Kill()
		_ = sleeper.Wait()
	})
	holder := int32(sleeper.Process.Pid)
	for attempt := 0; ; attempt++ {
		cmdline, err := os.ReadFile(filepath.Join(procfs, strconv.Itoa(int(holder)), "cmdline"))
		if err == nil && string(cmdline) == "/bin/sleep\x00600.125\x00" {
			break
		}
		if attempt == 200 {
			t.Fatalf("pid %d is not running sleep after two seconds", holder)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Wiring, not the property: this reader must really be refused the holder's
	// executable.
	if _, err := os.Readlink(filepath.Join(procfs, strconv.Itoa(int(holder)), "exe")); err == nil {
		t.Fatalf("precondition: pid %d's executable is readable here, so nothing is unreadable and this case "+
			"measures nothing", holder)
	}

	table := read(t)
	if _, found := table.Lookup(holder); found {
		t.Fatalf("pid %d is in the table although what it runs could not be read", holder)
	}
	if !slices.Contains(table.Unreadable(), holder) {
		t.Fatalf("the table names %v as unreadable, want pid %d among them", table.Unreadable(), holder)
	}

	// The same reading through the listening sockets, held by this readable test
	// process, which does not run what the target names.
	listener, file := listen(t, "127.0.0.1:0")
	_ = file.Close()
	listeners, err := process.ReadListeners(procfs)
	if err != nil {
		t.Fatalf("read the listeners: %v", err)
	}
	listening := table.WithListeners(listeners)

	for _, one := range []struct {
		name string
		on   process.Table
		rule process.Rule
		want string
	}{
		{"by its executable and arguments", table,
			process.Rule{Name: "sleeper", Executable: "/usr/bin/sleep", Arguments: []string{"600.125"}},
			"could not be read"},
		{"by its pid", table,
			process.Rule{Name: "sleeper", PID: &process.PIDGuard{PID: holder, Start: 1, Boot: "boot"}},
			"pid " + strconv.Itoa(int(holder)) + " is held by a process this observer may not read"},
		{"by a port a readable process holds and an executable it does not run", listening,
			process.Rule{Name: "sleeper", Port: portOf(t, listener), Executable: "/usr/bin/sleep",
				Arguments: []string{"600.125"}},
			"could not be read"},
	} {
		t.Run(one.name, func(t *testing.T) {
			one.rule.Mode = admission.ModeNone
			resolution := (process.Approval{Rules: []process.Rule{one.rule}}).Resolve(
				process.Host{Table: one.on, Boot: "boot"})
			if got := selectedPIDs(resolution); len(got) != 0 {
				t.Fatalf("wiring, not the property: the target selected %v, so a readable process matches and "+
					"nothing unreadable is being measured", got)
			}
			if one.rule.Port != 0 && len(resolution.Targets[0].Listeners) != 1 {
				t.Fatalf("wiring, not the property: the port resolved to %d listeners, want the one this test "+
					"holds, so the reason below was not reached through the listening sockets",
					len(resolution.Targets[0].Listeners))
			}
			if why := resolution.Targets[0].Unresolved; !strings.Contains(why, one.want) {
				t.Errorf("the target is reported as %q, want %q", why, one.want)
			}
		})
	}
}

// A listener no readable holder was found for, with every table read, is a
// race (the holder closed it between readings): described, not staged.
func TestAListenerHeldByNoProcessWithEveryTableReadIsNotBlamedOnAnUnreadableOwner(t *testing.T) {
	orphan := process.Listeners{Sockets: []process.ListeningSocket{{
		Listener: process.Listener{Inode: 9001, Port: 8443, Address: netip.IPv4Unspecified()},
	}}}
	table := process.TableOf(member(70)).WithListeners(orphan)
	rule := process.Rule{Name: "front", Port: 8443, Mode: admission.ModeNone}
	why := (process.Approval{Rules: []process.Rule{rule}}).Resolve(process.Host{Table: table}).Targets[0].Unresolved
	if strings.Contains(why, "could not be read") || !strings.Contains(why, "closed it between the two readings") {
		t.Errorf("a listener no readable table holds, with every table read, is reported as %q", why)
	}
}
