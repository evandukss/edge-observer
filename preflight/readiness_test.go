package preflight_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/preflight"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl"
	"github.com/evandukss/edge-observer/process"
)

// every capability attachment needs, effective: bits 0 to 40.
const allCapabilities = "000001ffffffffff"

// constructed is a host on disk meeting every requirement, so a case changes
// exactly the reading it is about.
type constructed struct {
	t       *testing.T
	root    string
	host    preflight.Host
	machine string

	// refused is the kernel's answer to the program (nil accepts); loads counts
	// how often it was asked.
	refused error
	loads   int
}

func meeting(t *testing.T) *constructed {
	t.Helper()
	root := t.TempDir()
	c := &constructed{t: t, root: root, machine: "x86_64"}
	c.host = preflight.Host{
		ProcFS: filepath.Join(root, "proc"),
		SysFS:  filepath.Join(root, "sys"),
		Debug:  filepath.Join(root, "debug"),
		OS:     "linux",
	}
	c.host.Machine = func() (string, error) { return c.machine, nil }
	c.host.Loads = func() error {
		c.loads++
		return c.refused
	}
	c.write("proc/sys/kernel/arch", "x86_64\n")
	c.write("proc/sys/kernel/osrelease", "6.1.0-18-amd64\n")
	c.write("proc/self/status", "Name:\tobserver\nCapInh:\t0000000000000000\nCapPrm:\t"+allCapabilities+
		"\nCapEff:\t"+allCapabilities+"\nCapBnd:\t"+allCapabilities+"\n")
	c.write("sys/kernel/btf/vmlinux", "btf")
	return c
}

func (c *constructed) write(path, content string) {
	c.t.Helper()
	full := filepath.Join(c.root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		c.t.Fatalf("make %s: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		c.t.Fatalf("write %s: %v", full, err)
	}
}

func (c *constructed) remove(path string) {
	c.t.Helper()
	if err := os.RemoveAll(filepath.Join(c.root, path)); err != nil {
		c.t.Fatalf("remove %s: %v", path, err)
	}
}

// catalog reads the constructed procfs, as Assess requires.
func (c *constructed) catalog() probe.Catalog {
	c.t.Helper()
	built, err := probe.NewCatalog(openssl.Adapter{ProcFS: c.host.ProcFS, Runtime: probe.OpenSSL})
	if err != nil {
		c.t.Fatalf("NewCatalog: %v", err)
	}
	return built
}

// live links a running OpenSSL process's real directory into the constructed
// procfs.
func (c *constructed) live() process.Process {
	c.t.Helper()
	_, pid := approved(c.t)
	p, err := process.Identify("/proc", pid)
	if err != nil {
		c.t.Fatalf("Identify(%d): %v", pid, err)
	}
	name := strconv.Itoa(int(pid))
	if err := os.Symlink(filepath.Join("/proc", name), filepath.Join(c.host.ProcFS, name)); err != nil {
		c.t.Fatalf("link pid %d into the constructed procfs: %v", pid, err)
	}
	return p
}

// fake is a process only in the constructed procfs, mapping the named files,
// each written under its own root.
func (c *constructed) fake(pid int32, files map[string]string, executable map[string]bool) process.Process {
	c.t.Helper()
	name := strconv.Itoa(int(pid))
	var maps strings.Builder
	address := 0x7f0000000000
	for path, content := range files {
		permissions := "r--p"
		if executable[path] {
			permissions = "r-xp"
		}
		maps.WriteString(strconv.FormatInt(int64(address), 16) + "-" + strconv.FormatInt(int64(address+0x1000), 16) +
			" " + permissions + " 00000000 fd:01 1234 " + path + "\n")
		address += 0x10000
		c.write(filepath.Join("proc", name, "root", path), content)
	}
	c.write(filepath.Join("proc", name, "maps"), maps.String())
	return process.Process{PID: pid, Executable: "/usr/bin/constructed"}
}

func assess(c *constructed, selected ...process.Process) preflight.Readiness {
	c.t.Helper()
	return preflight.Assess(c.host, selected, c.catalog())
}

func requirement(t *testing.T, readiness preflight.Readiness, name string) preflight.Requirement {
	t.Helper()
	var found []preflight.Requirement
	for _, r := range readiness.Requirements {
		if r.Name == name {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d requirements named %q, want 1: %+v", len(found), name, readiness.Requirements)
	}
	return found[0]
}

var hostRequirements = []string{
	preflight.OperatingSystem, preflight.Architecture, preflight.KernelRelease,
	preflight.KernelBTF, preflight.Capabilities, preflight.ProgramLoad,
}

// only asserts that exactly the named host requirement has the given status
// and every other is Met, except those named as following it.
func only(t *testing.T, readiness preflight.Readiness, name string, status preflight.Status,
	following ...string) preflight.Requirement {
	t.Helper()
	var subject preflight.Requirement
	for _, other := range hostRequirements {
		r := requirement(t, readiness, other)
		if r.Found == "" {
			t.Errorf("%s says nothing about what was found", other)
		}
		if other == name {
			subject = r
			continue
		}
		if slices.Contains(following, other) {
			if r.Status != preflight.Indeterminate {
				t.Errorf("%s is %s (%s), and it cannot be established while %s is not met", other, r.Status, r.Found, name)
			}
			continue
		}
		if r.Status != preflight.Met {
			t.Errorf("%s is %s (%s), and this case changed only %s", other, r.Status, r.Found, name)
		}
	}
	if subject.Status != status {
		t.Errorf("%s is %s (%s), want %s", name, subject.Status, subject.Found, status)
	}
	return subject
}

func TestAHostMeetingEveryDeclaredRequirementIsReady(t *testing.T) {
	c := meeting(t)
	p := c.live()

	// Wiring, not the property: the judged process must be reachable through the
	// constructed procfs.
	mappings, err := process.Mappings(c.host.ProcFS, p.PID)
	if err != nil || len(openssl.Libraries(filepath.Join(c.host.ProcFS, strconv.Itoa(int(p.PID)), "root"), mappings)) == 0 {
		t.Fatalf("wiring, not the property: pid %d's OpenSSL is not reachable through %s: %v", p.PID, c.host.ProcFS, err)
	}

	readiness := assess(c, p)

	if readiness.Verdict != preflight.Ready {
		t.Errorf("Verdict = %q, want %q: %+v", readiness.Verdict, preflight.Ready, readiness.Requirements)
	}
	var names []string
	for _, r := range readiness.Requirements {
		names = append(names, r.Name)
		if r.Status != preflight.Met {
			t.Errorf("%s is %s: %s", r.Name, r.Status, r.Found)
		}
		if r.Found == "" || r.Declared == "" {
			t.Errorf("%s carries no evidence: %+v", r.Name, r)
		}
	}
	want := append(slices.Clone(hostRequirements), preflight.TLSLibrary)
	if !slices.Equal(names, want) {
		t.Errorf("requirements = %v, want %v", names, want)
	}
	if tls := requirement(t, readiness, preflight.TLSLibrary); tls.PID != p.PID {
		t.Errorf("the TLS requirement is about pid %d, want %d", tls.PID, p.PID)
	}
}

// Each case removes one requirement from a host that meets all of them; READY
// on any would be a capture failing later with another diagnosis.
func TestAHostMissingOneDeclaredRequirementIsNotReadyAndNamesIt(t *testing.T) {
	cases := []struct {
		name      string
		change    func(*constructed)
		missing   string
		mentioned []string
	}{
		{"another operating system", func(c *constructed) { c.host.OS = "darwin" },
			preflight.OperatingSystem, []string{"darwin"}},
		{"an arm64 kernel", func(c *constructed) {
			c.write("proc/sys/kernel/arch", "aarch64\n")
			c.machine = "aarch64"
		}, preflight.Architecture, []string{"aarch64"}},
		{"an x86-64 program emulated on an arm64 kernel", func(c *constructed) {
			c.write("proc/sys/kernel/arch", "aarch64\n")
		}, preflight.Architecture, []string{"aarch64", "x86_64"}},
		{"an arm64 machine with no kernel arch file", func(c *constructed) {
			c.remove("proc/sys/kernel/arch")
			c.machine = "aarch64"
		}, preflight.Architecture, []string{"aarch64"}},
		{"a kernel one minor release below the floor", func(c *constructed) {
			c.write("proc/sys/kernel/osrelease", "5.14.21-150400.24-default\n")
		}, preflight.KernelRelease, []string{"5.14.21"}},
		{"a kernel of an older major release", func(c *constructed) {
			c.write("proc/sys/kernel/osrelease", "4.19.0-26-amd64\n")
		}, preflight.KernelRelease, []string{"4.19.0"}},
		{"no kernel BTF", func(c *constructed) { c.remove("sys/kernel/btf/vmlinux") },
			preflight.KernelBTF, []string{"vmlinux"}},
		{"a kernel that refuses the program", func(c *constructed) {
			c.refused = errors.New("load program: permission denied: 0: R1 invalid mem access")
		}, preflight.ProgramLoad, []string{"R1 invalid mem access"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := meeting(t)
			tc.change(c)
			readiness := assess(c, c.live())

			if readiness.Verdict != preflight.NotReady {
				t.Errorf("Verdict = %q, want %q", readiness.Verdict, preflight.NotReady)
			}
			missing := only(t, readiness, tc.missing, preflight.Missing)
			for _, word := range tc.mentioned {
				if !strings.Contains(missing.Found, word) {
					t.Errorf("%s says %q, which does not name %s", tc.missing, missing.Found, word)
				}
			}
		})
	}
}

// Without the capabilities a load needs, no load is attempted: a refusal would
// be about privilege, not the kernel.
func TestMissingCapabilitiesAreNamedAndTheLoadIsNotAttempted(t *testing.T) {
	cases := []struct {
		name    string
		mask    string
		lacking []string
	}{
		{"CAP_BPF not effective", "0000017fffffffff", []string{"CAP_BPF"}},
		{"no capability effective", "0000000000000000", []string{"CAP_BPF", "CAP_PERFMON", "CAP_SYS_ADMIN",
			"CAP_SYS_PTRACE", "CAP_SYS_RESOURCE", "CAP_DAC_READ_SEARCH"}},
	}
	all := []string{"CAP_BPF", "CAP_PERFMON", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_RESOURCE", "CAP_DAC_READ_SEARCH"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := meeting(t)
			c.write("proc/self/status", "CapPrm:\t"+allCapabilities+"\nCapEff:\t"+tc.mask+"\nCapBnd:\t"+allCapabilities+"\n")
			readiness := assess(c, c.live())

			if readiness.Verdict != preflight.NotReady {
				t.Errorf("Verdict = %q, want %q", readiness.Verdict, preflight.NotReady)
			}
			capabilities := requirement(t, readiness, preflight.Capabilities)
			if capabilities.Status != preflight.Missing {
				t.Errorf("capabilities is %s (%s), want missing", capabilities.Status, capabilities.Found)
			}
			for _, name := range all {
				named := strings.Contains(capabilities.Found, name)
				if lacking := slices.Contains(tc.lacking, name); named != lacking {
					t.Errorf("%s: lacking %v, named %v, in %q", name, lacking, named, capabilities.Found)
				}
			}
			load := requirement(t, readiness, preflight.ProgramLoad)
			if load.Status != preflight.Indeterminate || load.Found == "" {
				t.Errorf("the program load is %s (%s), want indeterminate with a reason", load.Status, load.Found)
			}
			if c.loads != 0 {
				t.Errorf("the program was loaded %d times without the capabilities a load needs", c.loads)
			}
		})
	}
}

func TestTheProgramIsLoadedOnceWhenTheCapabilitiesAreHeld(t *testing.T) {
	c := meeting(t)
	only(t, assess(c, c.live()), preflight.ProgramLoad, preflight.Met)
	if c.loads != 1 {
		t.Errorf("the program was loaded %d times, want once", c.loads)
	}
}

// The floor is compared numerically: a larger major with a smaller minor clears
// it, and so does the floor itself.
func TestAKernelAtOrAboveTheFloorMeetsIt(t *testing.T) {
	for _, release := range []string{"5.15.0-105-generic", "5.15", "6.0.0", "7.0.12-linuxkit", "5.100.1"} {
		t.Run(release, func(t *testing.T) {
			c := meeting(t)
			c.write("proc/sys/kernel/osrelease", release+"\n")
			only(t, assess(c, c.live()), preflight.KernelRelease, preflight.Met)
		})
	}
}

func TestTheKernelsOwnArchitectureDecidesWhenUnameCannotBeRead(t *testing.T) {
	c := meeting(t)
	c.host.Machine = func() (string, error) { return "", errors.New("uname refused") }
	only(t, assess(c, c.live()), preflight.Architecture, preflight.Met)
}

func TestUnameDecidesWhereTheKernelPublishesNoArchitecture(t *testing.T) {
	c := meeting(t)
	c.remove("proc/sys/kernel/arch")
	only(t, assess(c, c.live()), preflight.Architecture, preflight.Met)
}

// An unreadable requirement is neither met nor missing, and a host whose only
// doubt is one of those is not ready.
func TestARequirementThatCannotBeReadIsIndeterminate(t *testing.T) {
	cases := []struct {
		name      string
		change    func(*constructed)
		which     string
		following []string
	}{
		{"no operating system reading", func(c *constructed) { c.host.OS = "" }, preflight.OperatingSystem, nil},
		{"neither architecture reading", func(c *constructed) {
			c.remove("proc/sys/kernel/arch")
			c.host.Machine = nil
		}, preflight.Architecture, nil},
		{"uname failing and no kernel arch file", func(c *constructed) {
			c.remove("proc/sys/kernel/arch")
			c.host.Machine = func() (string, error) { return "", errors.New("uname refused") }
		}, preflight.Architecture, nil},
		{"no kernel release", func(c *constructed) { c.remove("proc/sys/kernel/osrelease") }, preflight.KernelRelease, nil},
		{"a kernel release that is not a version", func(c *constructed) {
			c.write("proc/sys/kernel/osrelease", "linuxkit\n")
		}, preflight.KernelRelease, nil},
		{"a BTF path that cannot be looked at", func(c *constructed) {
			// kernel/btf as a file, so looking under it fails rather than answering
			// absent.
			c.remove("sys/kernel/btf")
			c.write("sys/kernel/btf", "not a directory")
		}, preflight.KernelBTF, nil},
		{"no status file", func(c *constructed) { c.remove("proc/self/status") }, preflight.Capabilities,
			[]string{preflight.ProgramLoad}},
		{"a status with no CapEff", func(c *constructed) { c.write("proc/self/status", "Name:\tobserver\n") },
			preflight.Capabilities, []string{preflight.ProgramLoad}},
		{"a CapEff that is not a mask", func(c *constructed) { c.write("proc/self/status", "CapEff:\tzzzz\n") },
			preflight.Capabilities, []string{preflight.ProgramLoad}},
		{"nothing to load the program with", func(c *constructed) { c.host.Loads = nil }, preflight.ProgramLoad, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := meeting(t)
			tc.change(c)
			readiness := assess(c, c.live())

			if readiness.Verdict != preflight.Undetermined {
				t.Errorf("Verdict = %q, want %q", readiness.Verdict, preflight.Undetermined)
			}
			only(t, readiness, tc.which, preflight.Indeterminate, tc.following...)
			if slices.Contains(tc.following, preflight.ProgramLoad) && c.loads != 0 {
				t.Errorf("the program was loaded %d times with the capabilities unknown", c.loads)
			}
		})
	}
}

func TestOneMissingRequirementOutweighsAnIndeterminateOne(t *testing.T) {
	c := meeting(t)
	c.remove("sys/kernel/btf/vmlinux")
	c.remove("proc/sys/kernel/osrelease")
	readiness := assess(c, c.live())

	if readiness.Verdict != preflight.NotReady {
		t.Errorf("Verdict = %q, want %q", readiness.Verdict, preflight.NotReady)
	}
	if got := requirement(t, readiness, preflight.KernelBTF).Status; got != preflight.Missing {
		t.Errorf("BTF is %s, want missing", got)
	}
	if got := requirement(t, readiness, preflight.KernelRelease).Status; got != preflight.Indeterminate {
		t.Errorf("the kernel release is %s, want indeterminate", got)
	}
}

func TestNoSelectedProcessLeavesTheTLSLibraryIndeterminate(t *testing.T) {
	c := meeting(t)
	readiness := assess(c)

	if readiness.Verdict != preflight.Undetermined {
		t.Errorf("Verdict = %q, want %q", readiness.Verdict, preflight.Undetermined)
	}
	var tls []preflight.Requirement
	for _, r := range readiness.Requirements {
		if r.Name == preflight.TLSLibrary {
			tls = append(tls, r)
		}
	}
	if len(tls) != 1 {
		t.Fatalf("%d TLS requirements with nothing selected, want 1", len(tls))
	}
	if tls[0].Status != preflight.Indeterminate || tls[0].PID != 0 || tls[0].Found == "" {
		t.Errorf("TLS requirement = %+v, want indeterminate, pid 0, with a reason", tls[0])
	}
}

func TestTheTLSLibraryOfEachSelectedProcess(t *testing.T) {
	notELF := "not an ELF file"
	sleep, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatalf("read /bin/sleep, an ELF file exporting none of OpenSSL's functions: %v", err)
	}

	cases := []struct {
		name       string
		files      map[string]string
		executable map[string]bool
		absent     bool
		status     preflight.Status
		mentioned  string
	}{
		{name: "its mapped files cannot be read", absent: true, status: preflight.Indeterminate},
		{name: "no libssl mapped",
			files:      map[string]string{"/usr/lib/libc.so.6": notELF},
			executable: map[string]bool{"/usr/lib/libc.so.6": true},
			status:     preflight.Missing, mentioned: "libssl"},
		{name: "libssl mapped without code",
			files:  map[string]string{"/usr/lib/libssl.so.3": notELF},
			status: preflight.Missing, mentioned: "libssl"},
		{name: "OpenSSL 1.1 by its file name",
			files:      map[string]string{"/usr/lib/libssl.so.1.1": notELF},
			executable: map[string]bool{"/usr/lib/libssl.so.1.1": true},
			status:     preflight.Missing, mentioned: "1.1"},
		{name: "OpenSSL 1.1 by what libcrypto states",
			files: map[string]string{
				"/usr/lib/libssl.so":    notELF,
				"/usr/lib/libcrypto.so": "header OpenSSL 1.1.1w  11 Sep 2023 trailer",
			},
			executable: map[string]bool{"/usr/lib/libssl.so": true},
			status:     preflight.Missing, mentioned: "1.1.1w"},
		{name: "a version nothing states",
			files:      map[string]string{"/usr/lib/libssl.so": notELF},
			executable: map[string]bool{"/usr/lib/libssl.so": true},
			status:     preflight.Indeterminate},
		{name: "OpenSSL 3 whose symbols cannot be read",
			files:      map[string]string{"/usr/lib/libssl.so.3": notELF},
			executable: map[string]bool{"/usr/lib/libssl.so.3": true},
			status:     preflight.Indeterminate},
		{name: "OpenSSL 3 by name exporting none of its functions",
			files:      map[string]string{"/usr/lib/libssl.so.3": string(sleep)},
			executable: map[string]bool{"/usr/lib/libssl.so.3": true},
			status:     preflight.Missing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := meeting(t)
			p := process.Process{PID: 4242, Executable: "/usr/bin/constructed"}
			if !tc.absent {
				p = c.fake(4242, tc.files, tc.executable)
			}
			readiness := assess(c, p)

			tls := requirement(t, readiness, preflight.TLSLibrary)
			if tls.PID != 4242 {
				t.Errorf("the TLS requirement is about pid %d, want 4242", tls.PID)
			}
			if tls.Status != tc.status {
				t.Errorf("TLS library is %s (%s), want %s", tls.Status, tls.Found, tc.status)
			}
			if tls.Found == "" || !strings.Contains(tls.Found, tc.mentioned) {
				t.Errorf("TLS library says %q, which does not name %q", tls.Found, tc.mentioned)
			}
			want := map[preflight.Status]preflight.Verdict{
				preflight.Missing: preflight.NotReady, preflight.Indeterminate: preflight.Undetermined,
			}[tc.status]
			if readiness.Verdict != want {
				t.Errorf("Verdict = %q, want %q", readiness.Verdict, want)
			}
		})
	}
}

func TestEverySelectedProcessIsJudgedInTheOrderGiven(t *testing.T) {
	c := meeting(t)
	unsupported := c.fake(4243, map[string]string{"/usr/lib/libc.so.6": "x"}, map[string]bool{"/usr/lib/libc.so.6": true})
	supported := c.live()
	readiness := assess(c, supported, unsupported)

	if readiness.Verdict != preflight.NotReady {
		t.Errorf("Verdict = %q, want %q", readiness.Verdict, preflight.NotReady)
	}
	var tls []preflight.Requirement
	for _, r := range readiness.Requirements {
		if r.Name == preflight.TLSLibrary {
			tls = append(tls, r)
		}
	}
	if len(tls) != 2 {
		t.Fatalf("%d TLS requirements for two processes: %+v", len(tls), tls)
	}
	if tls[0].PID != supported.PID || tls[0].Status != preflight.Met {
		t.Errorf("first = %+v, want pid %d met", tls[0], supported.PID)
	}
	if tls[1].PID != 4243 || tls[1].Status != preflight.Missing {
		t.Errorf("second = %+v, want pid 4243 missing", tls[1])
	}
}
