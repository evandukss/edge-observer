package preflight

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl"
	"github.com/evandukss/edge-observer/process"
)

// Readiness answers whether a capture can run on this host for these
// processes, against the declared support: Linux on x86-64, a kernel of
// MinimumKernel or newer publishing its BTF, the capabilities attachment
// needs, and OpenSSL 3.x linked dynamically into every selected process. Each
// requirement says what was declared, what was found, and whether it is enough.
type Readiness struct {
	Verdict      Verdict       `json:"verdict"`
	Requirements []Requirement `json:"requirements"`
}

// Verdict is the whole answer.
//
//	Ready         every requirement is Met
//	NotReady      at least one requirement is Missing, whatever the others are
//	Undetermined  none is Missing and at least one is Indeterminate
//
// Ready only when every requirement was read and found enough: a host this
// check could not see into is not cleared.
type Verdict string

const (
	Ready        Verdict = "READY"
	NotReady     Verdict = "NOT READY"
	Undetermined Verdict = "INDETERMINATE"
)

// Status is one requirement's answer.
//
//	Met            it was read, and what was read satisfies the declaration
//	Missing        it was read, and what was read does not
//	Indeterminate  it could not be read, or what was read does not say either
//	               way. Found says why. It is never Met and never Missing
type Status string

const (
	Met           Status = "met"
	Missing       Status = "missing"
	Indeterminate Status = "indeterminate"
)

// The requirements, by the Name a Requirement carries. Host requirements appear
// once each, in this order; TLSLibrary appears once per selected process, after
// them, in the order the processes were given.
const (
	// OperatingSystem is Linux. Read from Host.OS.
	OperatingSystem = "operating system"

	// Architecture is x86-64 as the kernel runs it, from <ProcFS>/sys/kernel/arch
	// and Host.Machine (uname). If they disagree the program is emulated and a
	// probe on an emulated process never fires: Missing, naming both. Without the
	// kernel's file, Host.Machine decides; with neither, Indeterminate.
	Architecture = "architecture"

	// KernelRelease is MinimumKernel or newer, from
	// <ProcFS>/sys/kernel/osrelease compared on major and minor. Unreadable or
	// unparseable is Indeterminate.
	KernelRelease = "kernel release"

	// KernelBTF is <SysFS>/kernel/btf/vmlinux being present. Absent is Missing;
	// a path that could not be looked at is Indeterminate.
	KernelBTF = "kernel BTF"

	// Capabilities is every capability attachment needs being effective, from
	// CapEff in <ProcFS>/self/status: the checker's own, so the answer holds for
	// start run the same way. Missing names each; unreadable is Indeterminate.
	Capabilities = "capabilities"

	// ProgramLoad is the kernel accepting the capture program, loaded via
	// Host.Loads and closed with no probe placed. A refusal refuses every capture:
	// the build requires plaintext, with no degraded fallback.
	//
	//   - Host.Loads is nil                                   Indeterminate
	//   - Capabilities is not Met: Loads is NOT called        Indeterminate
	//   - Loads returns nil                                   Met
	//   - Loads returns an error                              Missing, carrying it
	//
	// Without the capabilities a refusal would say nothing about the kernel.
	ProgramLoad = "BPF program"

	// TLSLibrary is one selected process running OpenSSL 3.x as a shared
	// library, and the catalogue saying it can observe it. Its PID is set.
	//
	//   - its mapped files cannot be read                     Indeterminate
	//   - no libssl.so is mapped with code                    Missing
	//   - the major version is not 3                          Missing
	//   - the major version cannot be established             Indeterminate
	//   - the catalogue could not find out                    Indeterminate
	//   - the catalogue says no                               Missing
	//
	// The major version comes from the libssl file name (libssl.so.3), or else
	// from the version the libcrypto mapped beside it states. With no selected
	// process, one TLSLibrary requirement appears with PID zero, Indeterminate.
	TLSLibrary = "TLS library"
)

// MinimumKernel is the oldest kernel release the observer declares support
// for: the floor ebpf.MinimumKernel publishes, held equal by a test.
const MinimumKernel = "5.15"

// Architectures is what the declared support calls x86-64, in the spellings a
// kernel uses for it.
var Architectures = []string{"x86_64"}

// Requirement is one declared requirement and what this host has of it.
type Requirement struct {
	// Name is one of the requirement names above.
	Name string `json:"name"`

	// Declared is what the declared support asks for, in words.
	Declared string `json:"declared"`

	Status Status `json:"status"`

	// Found is what was read, or why it could not be. Never empty.
	Found string `json:"found"`

	// PID is the process a TLSLibrary requirement is about, and zero for every
	// other requirement.
	PID int32 `json:"pid,omitempty"`
}

// Assess judges the host and the selected processes against the declared
// support. selected is exactly the set the observer would attach to, and
// catalog the catalogue a capture would use, reading host.ProcFS.
//
// A zero field of host (empty OS, nil Machine, nil Loads) is a reading not
// taken: Indeterminate, never Met, unless another reading decides (the
// kernel's architecture file when Machine is nil).
func Assess(host Host, selected []process.Process, catalog probe.Catalog) Readiness {
	capabilities := capabilitiesOf(host)
	requirements := []Requirement{
		operatingSystem(host),
		architecture(host),
		kernelRelease(host),
		kernelBTF(host),
		capabilities,
		programLoad(host, capabilities),
	}
	if len(selected) == 0 {
		requirements = append(requirements, Requirement{
			Name: TLSLibrary, Declared: declaredTLS, Status: Indeterminate,
			Found: "no process was selected, so which TLS library the targets use cannot be established",
		})
	}
	for _, p := range selected {
		requirements = append(requirements, tlsLibrary(host, p, catalog))
	}
	return Readiness{Verdict: fold(requirements), Requirements: requirements}
}

func fold(requirements []Requirement) Verdict {
	verdict := Ready
	for _, r := range requirements {
		switch r.Status {
		case Missing:
			return NotReady
		case Met:
		default:
			// Anything not Met, including an unset status, counts against Ready.
			verdict = Undetermined
		}
	}
	return verdict
}

func operatingSystem(host Host) Requirement {
	r := Requirement{Name: OperatingSystem, Declared: "linux"}
	switch host.OS {
	case "":
		r.Status, r.Found = Indeterminate, "the operating system was not read"
	case "linux":
		r.Status, r.Found = Met, "linux"
	default:
		r.Status, r.Found = Missing, "this is "+host.OS
	}
	return r
}

func architecture(host Host) Requirement {
	r := Requirement{Name: Architecture, Declared: strings.Join(Architectures, " or ")}
	path := filepath.Join(host.ProcFS, "sys/kernel/arch")
	kernelArch, kernelErr := readWord(path)

	var machine string
	machineErr := errors.New("uname was not read")
	if host.Machine != nil {
		machine, machineErr = host.Machine()
	}

	switch {
	case kernelErr == nil && machineErr == nil && machine != kernelArch:
		r.Status = Missing
		r.Found = fmt.Sprintf("the kernel is %s and this program is told it runs on %s, so it runs emulated, "+
			"and a probe on an emulated process never fires", kernelArch, machine)
	case kernelErr == nil:
		r.Status, r.Found = supported(kernelArch), "the kernel is "+kernelArch+" ("+path+")"
	case !errors.Is(kernelErr, os.ErrNotExist):
		r.Status, r.Found = Indeterminate, "the kernel's architecture could not be read: "+kernelErr.Error()
	case machineErr == nil:
		r.Status, r.Found = supported(machine), "uname says "+machine+"; this kernel publishes no "+path
	default:
		r.Status = Indeterminate
		r.Found = "neither " + path + " nor uname could be read: " + machineErr.Error()
	}
	return r
}

func supported(arch string) Status {
	if slices.Contains(Architectures, arch) {
		return Met
	}
	return Missing
}

func kernelRelease(host Host) Requirement {
	r := Requirement{Name: KernelRelease, Declared: MinimumKernel + " or newer"}
	release, err := readWord(filepath.Join(host.ProcFS, "sys/kernel/osrelease"))
	if err != nil {
		r.Status, r.Found = Indeterminate, "the kernel release could not be read: "+err.Error()
		return r
	}
	major, minor, ok := majorMinor(release)
	floorMajor, floorMinor, _ := majorMinor(MinimumKernel)
	switch {
	case !ok:
		r.Status, r.Found = Indeterminate, "the kernel release "+release+" does not begin with a version"
	case major > floorMajor || (major == floorMajor && minor >= floorMinor):
		r.Status, r.Found = Met, release
	default:
		r.Status, r.Found = Missing, release+" is older than "+MinimumKernel
	}
	return r
}

// majorMinor is the two leading numbers of a release, as numbers.
func majorMinor(release string) (int, int, bool) {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	digits := parts[1]
	if end := strings.IndexFunc(digits, func(c rune) bool { return c < '0' || c > '9' }); end >= 0 {
		digits = digits[:end]
	}
	minor, err := strconv.Atoi(digits)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func kernelBTF(host Host) Requirement {
	r := Requirement{Name: KernelBTF, Declared: "the kernel's own BTF"}
	file := stat(filepath.Join(host.SysFS, "kernel/btf/vmlinux"))
	switch {
	case file.Error != "":
		r.Status, r.Found = Indeterminate, file.Path+" could not be looked at: "+file.Error
	case file.Present:
		r.Status, r.Found = Met, file.Path
	default:
		r.Status, r.Found = Missing, file.Path+" is absent"
	}
	return r
}

func capabilitiesOf(host Host) Requirement {
	names := make([]string, len(needed))
	for i, capability := range needed {
		names[i] = capability.Name
	}
	r := Requirement{Name: Capabilities, Declared: strings.Join(names, " ") + ", effective"}

	path := filepath.Join(host.ProcFS, "self/status")
	content, err := os.ReadFile(path)
	if err != nil {
		r.Status, r.Found = Indeterminate, "the capabilities held could not be read: "+err.Error()
		return r
	}
	var mask string
	var found bool
	for line := range strings.Lines(string(content)) {
		if value, is := strings.CutPrefix(strings.TrimSpace(line), "CapEff:"); is {
			mask, found = strings.TrimSpace(value), true
		}
	}
	effective, err := strconv.ParseUint(mask, 16, 64)
	if !found || err != nil {
		r.Status, r.Found = Indeterminate, path+" carries no effective capability mask this reads: "+strconv.Quote(mask)
		return r
	}

	var lacking []string
	for _, capability := range needed {
		if effective&(1<<capability.Bit) == 0 {
			lacking = append(lacking, capability.Name)
		}
	}
	if len(lacking) > 0 {
		r.Status, r.Found = Missing, "not effective: "+strings.Join(lacking, " ")
		return r
	}
	r.Status, r.Found = Met, "all effective ("+mask+")"
	return r
}

func programLoad(host Host, capabilities Requirement) Requirement {
	r := Requirement{Name: ProgramLoad, Declared: "the kernel loads the capture program"}
	switch {
	case host.Loads == nil:
		r.Status, r.Found = Indeterminate, "nothing was given to load the program with"
	case capabilities.Status != Met:
		r.Status = Indeterminate
		r.Found = "not attempted: a load without the capabilities it needs says nothing about this kernel"
	default:
		if err := host.Loads(); err != nil {
			r.Status, r.Found = Missing, "the kernel refused it: "+err.Error()
		} else {
			r.Status, r.Found = Met, "loaded and closed, no probe placed"
		}
	}
	return r
}

const declaredTLS = "OpenSSL 3.x, linked dynamically"

func tlsLibrary(host Host, p process.Process, catalog probe.Catalog) Requirement {
	r := Requirement{Name: TLSLibrary, Declared: declaredTLS, PID: p.PID}

	mappings, err := process.Mappings(host.ProcFS, p.PID)
	if err != nil {
		r.Status, r.Found = Indeterminate, "the files it has mapped could not be read: "+err.Error()
		return r
	}
	root := filepath.Join(host.ProcFS, strconv.FormatInt(int64(p.PID), 10), "root")
	libraries := openssl.Libraries(root, mappings)

	index := slices.IndexFunc(libraries, func(l openssl.Library) bool {
		return strings.HasPrefix(l.Name, "libssl.so") && l.Code
	})
	if index < 0 {
		r.Status = Missing
		r.Found = "no libssl.so is mapped with code: it does not use OpenSSL as a shared library, " +
			"or carries a TLS stack linked into itself"
		return r
	}
	libssl := libraries[index]

	major, stated, err := majorOf(libssl, libraries)
	switch {
	case err != nil:
		r.Status, r.Found = Indeterminate, libssl.Path+": which OpenSSL it is could not be read: "+err.Error()
		return r
	case major == "":
		r.Status, r.Found = Indeterminate, libssl.Path+" states no OpenSSL version, and no libcrypto beside it does"
		return r
	case major != "3":
		r.Status, r.Found = Missing, libssl.Path+" is OpenSSL "+stated
		return r
	}

	report := catalog.Inspect(p)
	if report.Supported {
		r.Status, r.Found = Met, libssl.Path+" is OpenSSL "+stated+"; "+report.Reason()
		return r
	}
	for _, support := range report.Support {
		if support.Error != "" {
			r.Status = Indeterminate
			r.Found = libssl.Path + " is OpenSSL " + stated + ", and whether it can be observed is unknown: " +
				report.Reason() + ": " + support.Error
			return r
		}
	}
	r.Status, r.Found = Missing, libssl.Path+" is OpenSSL "+stated+", and "+report.Reason()
	return r
}

// majorOf is the OpenSSL major version behind libssl: from the file name, or
// from what the libcrypto beside it states.
func majorOf(libssl openssl.Library, libraries []openssl.Library) (major, stated string, err error) {
	if named := strings.TrimPrefix(libssl.Name, "libssl.so."); named != libssl.Name && named != "" {
		major, _, _ = strings.Cut(named, ".")
		return major, named, nil
	}
	var unread error
	for _, library := range libraries {
		if !strings.HasPrefix(library.Name, "libcrypto.so") {
			continue
		}
		if library.VersionError != "" {
			unread = errors.New(library.Path + ": " + library.VersionError)
			continue
		}
		if version := strings.TrimPrefix(library.Version, "OpenSSL "); version != "" {
			major, _, _ = strings.Cut(version, ".")
			return major, version, nil
		}
	}
	return "", "", unread
}

// readWord is a one-word kernel file. Unlike text, an absent file is an error.
func readWord(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(content) > textLimit {
		return "", fmt.Errorf("%s is %d bytes, past the %d this reads", path, len(content), textLimit)
	}
	word := strings.TrimSpace(string(content))
	if word == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return word, nil
}
