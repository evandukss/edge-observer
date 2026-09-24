package preflight_test

// The expected population is six host requirements in the documented order,
// then one TLS requirement per selected pid in caller order (an empty selection
// has one indeterminate TLS requirement with pid zero). Expectations are
// literal names and statuses, never a population obtained from Assess.
//
// What the constructed host models:
//
//	TLS mappings        captured at test time from an idle `openssl base64`
//	                    process and redirected into each constructed root;
//	                    device and inode are kept but are not the identity
//	                    of the redirected links
//	library files       links to the host's real OpenSSL 3 objects, which
//	                    the real inspector must accept first; this measures
//	                    library inspection on the test architecture only
//	other majors        the real libssl exposed as libssl.so.1.1, testing the
//	                    filename rule; OpenSSL 1.1 code is not modelled
//	catalogue refusal   a libcrypto ELF under the libssl name, which the
//	                    catalogue must refuse before the assertion runs
//	unreadable library  a libssl mapping naming a missing file
//	selection           constructed pids; lifetime, namespaces, reuse and
//	                    approval resolution are not modelled
//	OS and machine      controlled values; architecture disagreement is
//	                    constructed and no emulation is exercised
//	kernel release      controlled strings including the 5.15 floor
//	capabilities        synthetic status rows varying effective bits with
//	                    permitted and bounding complete; uid, namespace
//	                    privilege and seccomp are not modelled
//	BTF                 a presence marker, removed or made a link loop
//	unreadable paths    a symlink loop, a real filesystem error even as root
//	program load        a callback with a call counter; nothing is loaded
//	debug filesystem    supplied as a path, not populated

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/preflight"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl"
	"github.com/evandukss/edge-observer/process"
)

// Literal requirements and capability numbers: the oracle is the
// documentation, not Assess or the implementation's capability set.
var independentNames = []string{
	"operating system", "architecture", "kernel release", "kernel BTF",
	"capabilities", "BPF program", "TLS library",
}

var independentCaps = []struct {
	name string
	bit  uint
}{
	{"CAP_DAC_READ_SEARCH", 2},
	{"CAP_SYS_PTRACE", 19},
	{"CAP_SYS_ADMIN", 21},
	{"CAP_SYS_RESOURCE", 24},
	{"CAP_PERFMON", 38},
	{"CAP_BPF", 39},
}

const independentMask uint64 = 1<<2 | 1<<19 | 1<<21 | 1<<24 | 1<<38 | 1<<39

type independentLibraries struct {
	maps, ssl, crypto string
}

// approved only starts an idle openssl process and waits for its mappings; no
// preflight result feeds the expectations.
func independentCaptureLibraries(t *testing.T) independentLibraries {
	t.Helper()
	_, pid := approved(t)
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		t.Fatalf("fixture wiring: capture real maps: %v", err)
	}
	libs := independentLibraries{maps: string(data)}
	for _, line := range strings.Split(libs.maps, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.Contains(fields[1], "x") {
			continue
		}
		switch filepath.Base(fields[5]) {
		case "libssl.so.3":
			libs.ssl = fields[5]
		case "libcrypto.so.3":
			libs.crypto = fields[5]
		}
	}
	if libs.ssl == "" || libs.crypto == "" {
		t.Fatal("fixture wiring: real openssl must map executable libssl.so.3 and libcrypto.so.3")
	}
	return libs
}

type independentHost struct {
	host     preflight.Host
	selected []process.Process
	catalog  probe.Catalog
	libs     independentLibraries
	loads    int
}

func independentFixture(t *testing.T, libs independentLibraries) *independentHost {
	t.Helper()
	root := t.TempDir()
	f := &independentHost{libs: libs}
	f.host = preflight.Host{
		ProcFS:  filepath.Join(root, "proc"),
		SysFS:   filepath.Join(root, "sys"),
		Debug:   filepath.Join(root, "debug"),
		OS:      "linux",
		Machine: func() (string, error) { return "x86_64", nil },
		Loads: func() error {
			f.loads++
			return nil
		},
	}
	f.write(t, "sys/kernel/arch", "x86_64\n")
	f.write(t, "sys/kernel/osrelease", "5.15.0-independent\n")
	f.capabilities(t, independentMask)
	independentWrite(t, filepath.Join(f.host.SysFS, "kernel/btf/vmlinux"), "presence only; BTF contents are not modelled\n")
	var err error
	f.catalog, err = probe.NewCatalog(openssl.Adapter{ProcFS: f.host.ProcFS, Runtime: probe.OpenSSL})
	if err != nil {
		t.Fatalf("fixture wiring: catalog: %v", err)
	}
	f.selected = []process.Process{{PID: 3101}}
	f.process(t, 3101, "libssl.so.3", libs.ssl, true, true)
	if report := f.catalog.Inspect(f.selected[0]); !report.Supported {
		t.Fatalf("fixture wiring: actual catalog must support the baseline library: %+v", report)
	}
	return f
}

func independentWrite(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}
}

func (f *independentHost) write(t *testing.T, path, data string) {
	t.Helper()
	independentWrite(t, filepath.Join(f.host.ProcFS, path), data)
}

func (f *independentHost) capabilities(t *testing.T, mask uint64) {
	t.Helper()
	// Permitted and bounding stay complete: only EFFECTIVE may clear the gate.
	f.write(t, "self/status", fmt.Sprintf("Name:\tobserver\nCapPrm:\t%016x\nCapEff:\t%016x\nCapBnd:\t%016x\n", independentMask, mask, independentMask))
}

func independentRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

// ELOOP is deterministic even as root; chmod(000) would not be.
func independentUnreadable(t *testing.T, path string) {
	t.Helper()
	independentRemove(t, path)
	if err := os.Symlink(filepath.Base(path), path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fixture wiring: %s must be unreadable, not absent: %v", path, err)
	}
}

func (f *independentHost) process(t *testing.T, pid int32, sslName, sslSource string, code, crypto bool) {
	t.Helper()
	base := filepath.Join(f.host.ProcFS, strconv.Itoa(int(pid)))
	sslPath := "/independent/" + sslName
	cryptoPath := "/independent/libcrypto.so.3"
	var lines []string
	for _, line := range strings.Split(f.libs.maps, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		switch fields[5] {
		case f.libs.ssl:
			fields[5] = sslPath
			if !code {
				fields[1] = strings.ReplaceAll(fields[1], "x", "-")
			}
		case f.libs.crypto:
			if !crypto {
				continue
			}
			fields[5] = cryptoPath
		default:
			continue
		}
		lines = append(lines, strings.Join(fields, " "))
	}
	if len(lines) == 0 {
		t.Fatal("fixture wiring: no captured mapping rows were retained")
	}
	independentWrite(t, filepath.Join(base, "maps"), strings.Join(lines, "\n")+"\n")
	for name, source := range map[string]string{sslPath: sslSource, cryptoPath: f.libs.crypto} {
		path := filepath.Join(base, "root", name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if err := os.Symlink(source, path); err != nil {
			t.Fatal(err)
		}
	}
}

func independentCheck(t *testing.T, got preflight.Readiness, verdict preflight.Verdict, pids []int32, statuses map[string]preflight.Status) {
	t.Helper()
	if got.Verdict != verdict {
		t.Errorf("verdict = %q, want %q", got.Verdict, verdict)
	}
	if len(pids) == 0 {
		pids = []int32{0}
	}
	wantCount := 6 + len(pids)
	if len(got.Requirements) != wantCount {
		t.Errorf("requirement population = %d, want %d (six host requirements plus every selected PID)", len(got.Requirements), wantCount)
	}
	for i := 0; i < wantCount; i++ {
		name, pid := independentNames[min(i, 6)], int32(0)
		if i >= 6 {
			pid = pids[i-6]
		}
		key := fmt.Sprintf("%s/%d", name, pid)
		want := preflight.Met
		if status, ok := statuses[key]; ok {
			want = status
		}
		if i >= len(got.Requirements) {
			t.Errorf("requirement %s absent, want status %q at index %d", key, want, i)
			continue
		}
		r := got.Requirements[i]
		if r.Name != name || r.PID != pid || r.Status != want {
			t.Errorf("requirement[%d] = (%q, PID %d, %q), want (%q, PID %d, %q)", i, r.Name, r.PID, r.Status, name, pid, want)
		}
		if strings.TrimSpace(r.Declared) == "" || strings.TrimSpace(r.Found) == "" {
			t.Errorf("requirement %s must carry declaration and evidence: %+v", key, r)
		}
	}
}

func independentEvidence(t *testing.T, got preflight.Readiness, name string, pid int32, needles ...string) {
	t.Helper()
	for _, r := range got.Requirements {
		if r.Name != name || r.PID != pid {
			continue
		}
		for _, needle := range needles {
			if !strings.Contains(r.Found, needle) {
				t.Errorf("%s/%d evidence %q does not name %q", name, pid, r.Found, needle)
			}
		}
		return
	}
	t.Errorf("no evidence for %s/%d", name, pid)
}

func TestReadinessReady(t *testing.T) {
	f := independentFixture(t, independentCaptureLibraries(t))
	got := preflight.Assess(f.host, f.selected, f.catalog)
	independentCheck(t, got, preflight.Ready, []int32{3101}, nil)
	if f.loads == 0 {
		t.Error("READY requires actually asking Loads; it was never called")
	}
}

func TestReadinessEachMissingHostRequirement(t *testing.T) {
	libs := independentCaptureLibraries(t)
	cases := []struct {
		name, requirement, evidence string
		change                      func(*testing.T, *independentHost)
	}{
		{"operating-system", "operating system", "darwin", func(t *testing.T, f *independentHost) { f.host.OS = "darwin" }},
		{"architecture", "architecture", "aarch64", func(t *testing.T, f *independentHost) {
			f.write(t, "sys/kernel/arch", "aarch64\n")
			f.host.Machine = func() (string, error) { return "aarch64", nil }
		}},
		{"kernel", "kernel release", "5.14", func(t *testing.T, f *independentHost) { f.write(t, "sys/kernel/osrelease", "5.14.99\n") }},
		{"btf", "kernel BTF", "", func(t *testing.T, f *independentHost) {
			independentRemove(t, filepath.Join(f.host.SysFS, "kernel/btf/vmlinux"))
		}},
		{"program-load", "BPF program", "independent verifier rejection", func(t *testing.T, f *independentHost) {
			f.host.Loads = func() error { f.loads++; return errors.New("independent verifier rejection") }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := independentFixture(t, libs)
			tc.change(t, f)
			got := preflight.Assess(f.host, f.selected, f.catalog)
			independentCheck(t, got, preflight.NotReady, []int32{3101}, map[string]preflight.Status{tc.requirement + "/0": preflight.Missing})
			if tc.evidence != "" {
				independentEvidence(t, got, tc.requirement, 0, tc.evidence)
			}
		})
	}
}

func TestReadinessCapabilitiesMustBeEffective(t *testing.T) {
	libs := independentCaptureLibraries(t)
	for _, capability := range independentCaps {
		t.Run(capability.name, func(t *testing.T) {
			f := independentFixture(t, libs)
			f.capabilities(t, independentMask&^(1<<capability.bit))
			got := preflight.Assess(f.host, f.selected, f.catalog)
			independentCheck(t, got, preflight.NotReady, []int32{3101}, map[string]preflight.Status{
				"capabilities/0": preflight.Missing, "BPF program/0": preflight.Indeterminate,
			})
			independentEvidence(t, got, "capabilities", 0, capability.name)
			if f.loads != 0 {
				t.Errorf("Loads called %d times without effective %s", f.loads, capability.name)
			}
		})
	}
	t.Run("all-missing", func(t *testing.T) {
		f := independentFixture(t, libs)
		f.capabilities(t, 0)
		got := preflight.Assess(f.host, f.selected, f.catalog)
		independentCheck(t, got, preflight.NotReady, []int32{3101}, map[string]preflight.Status{
			"capabilities/0": preflight.Missing, "BPF program/0": preflight.Indeterminate,
		})
		for _, capability := range independentCaps {
			independentEvidence(t, got, "capabilities", 0, capability.name)
		}
		if f.loads != 0 {
			t.Errorf("Loads called %d times with no effective capabilities", f.loads)
		}
	})
}

func TestReadinessUnreadableHostRequirements(t *testing.T) {
	libs := independentCaptureLibraries(t)
	cases := []struct {
		name, requirement string
		change            func(*testing.T, *independentHost)
	}{
		{"zero-os", "operating system", func(t *testing.T, f *independentHost) { f.host.OS = "" }},
		{"zero-machine-no-kernel-reading", "architecture", func(t *testing.T, f *independentHost) {
			independentRemove(t, filepath.Join(f.host.ProcFS, "sys/kernel/arch"))
			f.host.Machine = nil
		}},
		{"uname-error-no-kernel-reading", "architecture", func(t *testing.T, f *independentHost) {
			independentRemove(t, filepath.Join(f.host.ProcFS, "sys/kernel/arch"))
			f.host.Machine = func() (string, error) { return "", errors.New("uname unavailable") }
		}},
		{"absent-release", "kernel release", func(t *testing.T, f *independentHost) {
			independentRemove(t, filepath.Join(f.host.ProcFS, "sys/kernel/osrelease"))
		}},
		{"unreadable-release", "kernel release", func(t *testing.T, f *independentHost) {
			independentUnreadable(t, filepath.Join(f.host.ProcFS, "sys/kernel/osrelease"))
		}},
		{"unreadable-btf", "kernel BTF", func(t *testing.T, f *independentHost) {
			independentUnreadable(t, filepath.Join(f.host.SysFS, "kernel/btf/vmlinux"))
		}},
		{"absent-status", "capabilities", func(t *testing.T, f *independentHost) {
			independentRemove(t, filepath.Join(f.host.ProcFS, "self/status"))
		}},
		{"unreadable-status", "capabilities", func(t *testing.T, f *independentHost) {
			independentUnreadable(t, filepath.Join(f.host.ProcFS, "self/status"))
		}},
		{"absent-cap-eff", "capabilities", func(t *testing.T, f *independentHost) { f.write(t, "self/status", "CapPrm:\tffffffffffffffff\n") }},
		{"malformed-cap-eff", "capabilities", func(t *testing.T, f *independentHost) { f.write(t, "self/status", "CapEff:\tnot-hex\n") }},
		{"overflow-cap-eff", "capabilities", func(t *testing.T, f *independentHost) { f.write(t, "self/status", "CapEff:\t1ffffffffffffffff\n") }},
		{"nil-loads", "BPF program", func(t *testing.T, f *independentHost) { f.host.Loads = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := independentFixture(t, libs)
			tc.change(t, f)
			statuses := map[string]preflight.Status{tc.requirement + "/0": preflight.Indeterminate}
			if tc.requirement == "capabilities" {
				statuses["BPF program/0"] = preflight.Indeterminate
			}
			got := preflight.Assess(f.host, f.selected, f.catalog)
			independentCheck(t, got, preflight.Undetermined, []int32{3101}, statuses)
			if tc.requirement == "capabilities" && f.loads != 0 {
				t.Errorf("Loads called %d times while capabilities could not be established", f.loads)
			}
		})
	}
}

// Where Machine is absent, the kernel's own architecture file decides, and
// Indeterminate is reserved for neither being readable: qemu-user fakes uname
// while /proc/sys/kernel/arch reports the real kernel.
func TestReadinessNilMachineWithAReadableKernelIsMet(t *testing.T) {
	libs := independentCaptureLibraries(t)
	f := independentFixture(t, libs)
	f.host.Machine = nil
	independentCheck(t, preflight.Assess(f.host, f.selected, f.catalog), preflight.Ready, []int32{3101}, map[string]preflight.Status{"architecture/0": preflight.Met})
}

func TestReadinessKernelFloor(t *testing.T) {
	libs := independentCaptureLibraries(t)
	for _, tc := range []struct {
		release string
		status  preflight.Status
		verdict preflight.Verdict
	}{
		{"5.15", preflight.Met, preflight.Ready},
		{"5.15.0-rc1", preflight.Met, preflight.Ready},
		{"5.100.1", preflight.Met, preflight.Ready},
		{"6.0.0", preflight.Met, preflight.Ready},
		{"5.9.200", preflight.Missing, preflight.NotReady},
		{"4.99.0", preflight.Missing, preflight.NotReady},
		{"", preflight.Indeterminate, preflight.Undetermined},
		{"5", preflight.Indeterminate, preflight.Undetermined},
		{"Linux 6.0", preflight.Indeterminate, preflight.Undetermined},
		{"5.x.0", preflight.Indeterminate, preflight.Undetermined},
	} {
		t.Run(strconv.Quote(tc.release), func(t *testing.T) {
			f := independentFixture(t, libs)
			f.write(t, "sys/kernel/osrelease", tc.release+"\n")
			independentCheck(t, preflight.Assess(f.host, f.selected, f.catalog), tc.verdict, []int32{3101}, map[string]preflight.Status{"kernel release/0": tc.status})
		})
	}
}

func TestReadinessArchitectureFallbackAndDisagreement(t *testing.T) {
	libs := independentCaptureLibraries(t)
	for _, tc := range []struct {
		kernel, machine string
		status          preflight.Status
		verdict         preflight.Verdict
	}{
		{"", "x86_64", preflight.Met, preflight.Ready},
		{"", "aarch64", preflight.Missing, preflight.NotReady},
		{"aarch64", "x86_64", preflight.Missing, preflight.NotReady},
		{"x86_64", "aarch64", preflight.Missing, preflight.NotReady},
	} {
		t.Run(tc.kernel+"-"+tc.machine, func(t *testing.T) {
			f := independentFixture(t, libs)
			if tc.kernel == "" {
				independentRemove(t, filepath.Join(f.host.ProcFS, "sys/kernel/arch"))
			} else {
				f.write(t, "sys/kernel/arch", tc.kernel+"\n")
			}
			f.host.Machine = func() (string, error) { return tc.machine, nil }
			got := preflight.Assess(f.host, f.selected, f.catalog)
			independentCheck(t, got, tc.verdict, []int32{3101}, map[string]preflight.Status{"architecture/0": tc.status})
			if tc.kernel != "" {
				independentEvidence(t, got, "architecture", 0, tc.kernel, tc.machine)
			}
		})
	}
}

func TestReadinessTLSStates(t *testing.T) {
	libs := independentCaptureLibraries(t)
	cases := []struct {
		name    string
		status  preflight.Status
		verdict preflight.Verdict
		change  func(*testing.T, *independentHost)
	}{
		{"unversioned-with-crypto-version", preflight.Met, preflight.Ready, func(t *testing.T, f *independentHost) { f.process(t, 3101, "libssl.so", libs.ssl, true, true) }},
		{"other-major", preflight.Missing, preflight.NotReady, func(t *testing.T, f *independentHost) { f.process(t, 3101, "libssl.so.1.1", libs.ssl, true, true) }},
		{"not-executable", preflight.Missing, preflight.NotReady, func(t *testing.T, f *independentHost) { f.process(t, 3101, "libssl.so.3", libs.ssl, false, true) }},
		{"empty-maps", preflight.Missing, preflight.NotReady, func(t *testing.T, f *independentHost) { f.write(t, "3101/maps", "") }},
		{"absent-maps", preflight.Indeterminate, preflight.Undetermined, func(t *testing.T, f *independentHost) {
			independentRemove(t, filepath.Join(f.host.ProcFS, "3101/maps"))
		}},
		{"unreadable-maps", preflight.Indeterminate, preflight.Undetermined, func(t *testing.T, f *independentHost) {
			independentUnreadable(t, filepath.Join(f.host.ProcFS, "3101/maps"))
		}},
		{"unknown-major", preflight.Indeterminate, preflight.Undetermined, func(t *testing.T, f *independentHost) { f.process(t, 3101, "libssl.so", libs.ssl, true, false) }},
		{"catalog-cannot-read-library", preflight.Indeterminate, preflight.Undetermined, func(t *testing.T, f *independentHost) {
			f.process(t, 3101, "libssl.so.3", filepath.Join(t.TempDir(), "absent-library"), true, true)
			r := f.catalog.Inspect(f.selected[0])
			if r.Supported || len(r.Support) != 1 || r.Support[0].Error == "" {
				t.Fatalf("fixture wiring: need an unknown catalog reading: %+v", r)
			}
		}},
		{"catalog-refuses-readable-library", preflight.Missing, preflight.NotReady, func(t *testing.T, f *independentHost) {
			f.process(t, 3101, "libssl.so.3", libs.crypto, true, true)
			r := f.catalog.Inspect(f.selected[0])
			if r.Supported || len(r.Support) != 1 || r.Support[0].Error != "" {
				t.Fatalf("fixture wiring: need a determinate catalog refusal: %+v", r)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := independentFixture(t, libs)
			tc.change(t, f)
			independentCheck(t, preflight.Assess(f.host, f.selected, f.catalog), tc.verdict, []int32{3101}, map[string]preflight.Status{"TLS library/3101": tc.status})
		})
	}
}

func TestReadinessSelectionPopulation(t *testing.T) {
	libs := independentCaptureLibraries(t)
	t.Run("no-selected-process", func(t *testing.T) {
		f := independentFixture(t, libs)
		// A supported process exists in procfs, but the caller did not select it.
		independentCheck(t, preflight.Assess(f.host, nil, f.catalog), preflight.Undetermined, nil, map[string]preflight.Status{"TLS library/0": preflight.Indeterminate})
	})
	t.Run("caller-order-and-every-pid", func(t *testing.T) {
		f := independentFixture(t, libs)
		f.process(t, 19, "libssl.so.3", libs.ssl, true, true)
		f.write(t, "19/maps", "")
		// 404 has no maps at all; it must survive in the result as unknown.
		selected := []process.Process{{PID: 404}, {PID: 3101}, {PID: 19}}
		independentCheck(t, preflight.Assess(f.host, selected, f.catalog), preflight.NotReady, []int32{404, 3101, 19}, map[string]preflight.Status{
			"TLS library/404": preflight.Indeterminate, "TLS library/19": preflight.Missing,
		})
	})
}

func TestReadinessVerdictFold(t *testing.T) {
	libs := independentCaptureLibraries(t)
	states := []preflight.Status{preflight.Met, preflight.Missing, preflight.Indeterminate}
	for _, osStatus := range states {
		for _, kernelStatus := range states {
			for _, tlsStatus := range states {
				t.Run(string(osStatus)+"-"+string(kernelStatus)+"-"+string(tlsStatus), func(t *testing.T) {
					f := independentFixture(t, libs)
					if osStatus == preflight.Missing {
						f.host.OS = "freebsd"
					}
					if osStatus == preflight.Indeterminate {
						f.host.OS = ""
					}
					if kernelStatus == preflight.Missing {
						f.write(t, "sys/kernel/osrelease", "4.19.0\n")
					}
					if kernelStatus == preflight.Indeterminate {
						f.write(t, "sys/kernel/osrelease", "unknown\n")
					}
					if tlsStatus == preflight.Missing {
						f.write(t, "3101/maps", "")
					}
					if tlsStatus == preflight.Indeterminate {
						independentRemove(t, filepath.Join(f.host.ProcFS, "3101/maps"))
					}
					want := preflight.Ready
					if osStatus == preflight.Indeterminate || kernelStatus == preflight.Indeterminate || tlsStatus == preflight.Indeterminate {
						want = preflight.Undetermined
					}
					if osStatus == preflight.Missing || kernelStatus == preflight.Missing || tlsStatus == preflight.Missing {
						want = preflight.NotReady
					}
					independentCheck(t, preflight.Assess(f.host, f.selected, f.catalog), want, []int32{3101}, map[string]preflight.Status{
						"operating system/0": osStatus, "kernel release/0": kernelStatus, "TLS library/3101": tlsStatus,
					})
				})
			}
		}
	}
}
