package openssl_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl"
	"github.com/evandukss/edge-observer/process"
)

const procfs = "/proc"

// root is where a process's own filesystem is reached from.
func root(pid int32) string {
	return filepath.Join(procfs, strconv.FormatInt(int64(pid), 10), "root")
}

// A real process running real OpenSSL, as the kernel describes it, rather than
// a written /proc tree and ELF. The command waits on a pipe nobody writes to,
// so it stays up idle.
func openSSLProcess(t *testing.T) process.Process {
	t.Helper()

	command := exec.Command("openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-k", "unused")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	command.Stdout = nil
	if err := command.Start(); err != nil {
		t.Fatalf("start openssl, which this test needs on the host: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	// The kernel points /proc/<pid>/exe at the new program before the loader maps
	// its libraries, so waiting for the exec is not enough.
	pid := int32(command.Process.Pid)
	for range 200 {
		table, err := process.Read(procfs)
		if err != nil {
			t.Fatalf("Read(%s): %v", procfs, err)
		}
		p, ok := table.Lookup(pid)
		if ok && filepath.Base(p.Executable) == "openssl" && loaded(t, pid) {
			return p
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pid %d has not loaded openssl and its libraries after two seconds", pid)
	return process.Process{}
}

// loaded reports whether the process has finished mapping its OpenSSL
// libraries: libssl states no version and libcrypto does, so in between the
// process's libraries state none. It waits for the fixture, not for the answer
// under test.
func loaded(t *testing.T, pid int32) bool {
	t.Helper()

	mappings, err := process.Mappings(procfs, pid)
	if err != nil {
		return false
	}
	libraries := openssl.Libraries(root(pid), mappings)
	if len(libraries) == 0 {
		return false
	}
	for _, library := range libraries {
		if library.Version != "" {
			return true
		}
	}
	return false
}

func self(t *testing.T) process.Process {
	t.Helper()

	table, err := process.Read(procfs)
	if err != nil {
		t.Fatalf("Read(%s): %v", procfs, err)
	}
	p, ok := table.Lookup(int32(os.Getpid()))
	if !ok {
		t.Fatalf("pid %d is absent from its own process table", os.Getpid())
	}
	return p
}

func TestAProcessRunningOpenSSLIsSupported(t *testing.T) {
	support := openssl.New().Inspect(openSSLProcess(t))

	if !support.Supported {
		t.Fatalf("a process running OpenSSL is unsupported: %s %s", support.Reason, support.Error)
	}
	if !strings.HasPrefix(support.Runtime, "libssl.so") {
		t.Errorf("Runtime = %q, want the library it found", support.Runtime)
	}
	if support.Error != "" {
		t.Errorf("Error = %q on a process it could read", support.Error)
	}
}

func TestTheProbesAreTheEntryPointsPlaintextCrossesAtTheirOffsetsInTheLibrary(t *testing.T) {
	support := openssl.New().Inspect(openSSLProcess(t))

	at := make(map[string]uint64, len(support.Probes))
	for _, p := range support.Probes {
		if p.Path == "" || filepath.Base(p.Path) == "" {
			t.Errorf("probe %s names no file", p.Symbol)
		}
		if p.Offset == 0 {
			t.Errorf("probe %s is at offset 0 of %s", p.Symbol, p.Path)
		}
		if _, repeated := at[p.Symbol]; repeated {
			t.Errorf("%s has two probes", p.Symbol)
		}
		at[p.Symbol] = p.Offset
	}

	for _, symbol := range []string{"SSL_read", "SSL_write"} {
		if _, ok := at[symbol]; !ok {
			t.Errorf("no probe on %s, which is where plaintext crosses", symbol)
		}
	}
	if at["SSL_read"] == at["SSL_write"] {
		t.Errorf("SSL_read and SSL_write share offset %#x", at["SSL_read"])
	}
}

// The count is only known when the call returns; the buffer size is not it.
func TestTheProbedSymbolsAreTheOnesThatReportTheirOwnByteCount(t *testing.T) {
	support := openssl.New().Inspect(openSSLProcess(t))

	probed := make(map[string]bool, len(support.Probes))
	for _, p := range support.Probes {
		probed[p.Symbol] = true
	}

	// Present since OpenSSL 1.1.1 and used by modern processes: they must be
	// probed.
	for _, symbol := range []string{"SSL_read_ex", "SSL_write_ex"} {
		if !probed[symbol] {
			t.Errorf("no probe on %s, which this library exports", symbol)
		}
	}
}

// A statically linked program carries its TLS inside itself: unsupported, and
// never inferred from socket traffic.
func TestAProcessWithNoOpenSSLMappedIsUnsupportedAndSaysWhy(t *testing.T) {
	support := openssl.New().Inspect(self(t))

	if support.Supported {
		t.Fatal("a statically linked program is reported as running OpenSSL")
	}
	if support.Reason == "" {
		t.Fatal("the refusal gives no reason")
	}
	if !strings.Contains(support.Reason, "libssl") {
		t.Errorf("Reason = %q, which does not say what was looked for", support.Reason)
	}
	if len(support.Probes) != 0 {
		t.Errorf("%d probes on a process it will not attach to", len(support.Probes))
	}
}

// Unreadable mapped files are not an absence of OpenSSL.
func TestAProcessThatCouldNotBeReadIsNotReportedAsOneWithoutOpenSSL(t *testing.T) {
	support := openssl.New().Inspect(process.Process{PID: 0, Executable: "/usr/bin/interpreter"})

	if support.Supported {
		t.Fatal("a process that could not be read is reported supported")
	}
	if support.Error == "" {
		t.Fatal("a process that could not be read carries no error, so it reads as a definite no")
	}
	if !strings.Contains(support.Reason, "unknown") {
		t.Errorf("Reason = %q, which reads as an answer rather than as not having one", support.Reason)
	}
}

func TestTheLibrariesFoundCarryTheVersionOpenSSLStatesForItself(t *testing.T) {
	mappings, err := process.Mappings(procfs, openSSLProcess(t).PID)
	if err != nil {
		t.Fatalf("Mappings: %v", err)
	}

	libraries := openssl.Libraries(root(openSSLProcess(t).PID), mappings)
	if len(libraries) == 0 {
		t.Fatal("a process running openssl has mapped no OpenSSL library")
	}

	var versioned int
	for _, library := range libraries {
		if !strings.HasPrefix(library.Name, "lib") {
			t.Errorf("%q is not a library file name", library.Name)
		}
		if library.Version == "" {
			continue
		}
		versioned++
		if !strings.HasPrefix(library.Version, "OpenSSL ") {
			t.Errorf("%s reports version %q", library.Name, library.Version)
		}
		if strings.Count(library.Version, ".") < 2 {
			t.Errorf("%s reports version %q, which is not a version", library.Name, library.Version)
		}
	}
	if versioned == 0 {
		// A library read and stating no version differs from one that could not be
		// read: the second is indeterminate.
		var unreadable []string
		for _, library := range libraries {
			if library.VersionError != "" {
				unreadable = append(unreadable, library.VersionError)
			}
		}
		if len(unreadable) > 0 {
			t.Fatalf("no version could be READ from any of the %d OpenSSL libraries: %v", len(libraries), unreadable)
		}
		t.Fatalf("none of the %d OpenSSL libraries states a version", len(libraries))
	}
}

// An unreadable file and a file stating no version are different answers.
func TestAnUnreadableLibraryIsIndeterminateNotVersionless(t *testing.T) {
	// A path that is not a file cannot be read: an error, not an absence.
	missing := filepath.Join(t.TempDir(), "does-not-exist", "libssl.so.3")
	libraries := openssl.Libraries("/", []process.Mapping{{Path: missing, Executable: true}})
	if len(libraries) != 1 {
		t.Fatalf("%d libraries, want 1", len(libraries))
	}
	if libraries[0].VersionError == "" {
		t.Error("an unreadable library reported no version-read error; indeterminate was collapsed into absent")
	}
	if libraries[0].Version != "" {
		t.Errorf("an unreadable library stated a version %q", libraries[0].Version)
	}

	// A file that reads fine and names no version is an absence.
	present := filepath.Join(t.TempDir(), "libssl.so.3")
	if err := os.WriteFile(present, []byte("no version marker in here"), 0o644); err != nil {
		t.Fatalf("write %s: %v", present, err)
	}
	stated := openssl.Libraries("/", []process.Mapping{{Path: present, Executable: true}})
	if stated[0].VersionError != "" {
		t.Errorf("a readable file reported a version-read error: %q", stated[0].VersionError)
	}
	if stated[0].Version != "" {
		t.Errorf("a file with no marker stated a version %q", stated[0].Version)
	}
}

// A non-OpenSSL file states no OpenSSL version, whatever bytes it contains.
func TestAFileThatIsNotOpenSSLStatesNoVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "libssl.so.9")
	if err := os.WriteFile(path, []byte("OpenSSL is mentioned here but no version follows it"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}

	libraries := openssl.Libraries("/", []process.Mapping{{Path: path, Executable: true}})

	if len(libraries) != 1 {
		t.Fatalf("%d libraries, want 1", len(libraries))
	}
	if libraries[0].Version != "" {
		t.Fatalf("Version = %q for a file that states none", libraries[0].Version)
	}
}

func probed(support probe.Support) map[string]uint64 {
	at := make(map[string]uint64, len(support.Probes))
	for _, p := range support.Probes {
		at[p.Symbol] = p.Offset
	}
	return at
}

// TLS 1.3 early data travels before the handshake finishes, and a missing
// probe on it is invisible where early data is not used, so the hooks are
// asserted against the library.
func TestEarlyDataIsProbedInBothDirections(t *testing.T) {
	at := probed(openssl.New().Inspect(openSSLProcess(t)))

	for _, symbol := range []string{"SSL_read_early_data", "SSL_write_early_data"} {
		if at[symbol] == 0 {
			t.Errorf("no probe on %s, which carries application bytes before the handshake finishes", symbol)
		}
	}
	if at["SSL_read_early_data"] == at["SSL_write_early_data"] {
		t.Error("the two early-data functions resolve to one offset")
	}
	for _, ordinary := range []string{"SSL_read", "SSL_write"} {
		if at[ordinary] == at["SSL_read_early_data"] || at[ordinary] == at["SSL_write_early_data"] {
			t.Errorf("%s and an early-data function resolve to one offset", ordinary)
		}
	}
}

// A peek's bytes are returned again by the next read; probing both would
// double them.
func TestPeekIsCataloguedAndNotProbed(t *testing.T) {
	at := probed(openssl.New().Inspect(openSSLProcess(t)))

	for _, symbol := range []string{"SSL_peek", "SSL_peek_ex"} {
		function, catalogued := probe.OpenSSL.Lookup(symbol)
		if !catalogued {
			t.Errorf("%s is exported by this library and the catalogue does not name it", symbol)
			continue
		}
		if function.Probed {
			t.Errorf("%s is probed, and the bytes it returns are returned again by the next read", symbol)
		}
		if function.Note == "" {
			t.Errorf("%s is in the family and not probed, and nothing says why", symbol)
		}
		if at[symbol] != 0 {
			t.Errorf("%s has a probe at %#x", symbol, at[symbol])
		}
	}
}

// Where the catalogue meets a real runtime: an uncatalogued export would be
// silently missed traffic.
func TestTheCatalogueNamesEveryPlaintextFunctionThisLibraryExports(t *testing.T) {
	support := openssl.New().Inspect(openSSLProcess(t))

	if len(support.Unknown) != 0 {
		t.Fatalf("this library exports %v, which the catalogue does not name", support.Unknown)
	}
	if len(support.Missing) != 0 {
		t.Fatalf("the catalogue expects %v of this library's version and it exports none of them", support.Missing)
	}
}

// The uncatalogued report must be able to say something.
func TestAnExportedFunctionTheCatalogueDoesNotNameIsReported(t *testing.T) {
	narrowed := openssl.New()
	narrowed.Runtime = probe.Runtime{
		Name:     "openssl",
		Prefixes: probe.OpenSSL.Prefixes,
		Functions: []probe.Function{
			{Symbol: "SSL_read", Since: "0.9.8", Direction: fragment.Received, Probed: true},
			{Symbol: "SSL_write", Since: "0.9.8", Direction: fragment.Sent, Probed: true},
		},
	}

	support := narrowed.Inspect(openSSLProcess(t))

	if !support.Supported {
		t.Fatalf("a process running OpenSSL is unsupported: %s %s", support.Reason, support.Error)
	}
	if !slices.Contains(support.Unknown, "SSL_read_early_data") {
		t.Fatalf("Unknown = %v, and it does not name a function this library exports", support.Unknown)
	}
}

// A function expected for the claimed version and not exported: a short
// resolution, not an old library.
func TestAFunctionTheCatalogueExpectsAndTheLibraryLacksIsReportedMissing(t *testing.T) {
	invented := openssl.New()
	invented.Runtime = probe.Runtime{
		Name:     "openssl",
		Prefixes: probe.OpenSSL.Prefixes,
		Functions: append(slices.Clone(probe.OpenSSL.Functions), probe.Function{
			Symbol: "SSL_write_through_a_side_channel", Since: "1.0.0",
			Direction: fragment.Sent, Probed: true,
		}),
	}

	support := invented.Inspect(openSSLProcess(t))

	if !slices.Contains(support.Missing, "SSL_write_through_a_side_channel") {
		t.Fatalf("Missing = %v, and it does not name the function the catalogue expects", support.Missing)
	}
	if !support.Supported {
		t.Error("one absent function makes a library with both directions unsupported")
	}
}

// A library resolving only one direction is misidentified.
func TestARuntimeThatResolvesOneDirectionOnlyIsUnsupported(t *testing.T) {
	half := openssl.New()
	half.Runtime = probe.Runtime{
		Name:     "openssl",
		Prefixes: probe.OpenSSL.Prefixes,
		Functions: []probe.Function{
			{Symbol: "SSL_write", Since: "0.9.8", Direction: fragment.Sent, Probed: true},
		},
	}

	support := half.Inspect(openSSLProcess(t))

	if support.Supported {
		t.Fatal("a runtime resolving only one direction is reported supported")
	}
	if !strings.Contains(support.Reason, "reads plaintext") {
		t.Errorf("Reason = %q, which does not say which direction is missing", support.Reason)
	}
}

func TestTheRuntimeReportedNamesTheOpenSSLReleaseTheLibraryStates(t *testing.T) {
	support := openssl.New().Inspect(openSSLProcess(t))

	if !strings.Contains(support.Runtime, "OpenSSL ") {
		t.Fatalf("Runtime = %q, which does not name a release", support.Runtime)
	}
	if !strings.HasPrefix(support.Runtime, "libssl.so") {
		t.Fatalf("Runtime = %q, which does not name the library", support.Runtime)
	}
}

// A probe names the file under the observed process's own root; otherwise it
// is a same-named, different build, and probes land at wrong offsets.
func TestAProbeNamesTheLibraryThroughTheObservedProcessesOwnFilesystem(t *testing.T) {
	observed := openSSLProcess(t)
	support := openssl.New().Inspect(observed)

	if len(support.Probes) == 0 {
		t.Fatal("no probes to check")
	}
	for _, p := range support.Probes {
		if !strings.HasPrefix(p.Path, root(observed.PID)+"/") {
			t.Errorf("probe %s names %s, which is not read through %s", p.Symbol, p.Path, root(observed.PID))
		}
	}
}

// The lifecycle entry point is resolved with the plaintext ones, in the same
// library: everything downstream reads this list, and a missing ending lets a
// reused SSL address continue an old stream.
func TestTheLifecycleEntryPointIsResolvedWithThePlaintextOnes(t *testing.T) {
	support := openssl.New().Inspect(openSSLProcess(t))
	if !support.Supported {
		t.Fatalf("a process running OpenSSL is unsupported: %s", support.Reason)
	}

	at := probed(support)
	for _, function := range probe.OpenSSL.Lifecycle {
		if !function.Probed {
			continue
		}
		offset, resolved := at[function.Symbol]
		if !resolved {
			t.Errorf("%s is probed in the catalogue and resolved to no offset", function.Symbol)
			continue
		}
		if offset == 0 {
			t.Errorf("%s resolved to offset 0, which is not where a function is", function.Symbol)
		}
	}
	if len(probe.OpenSSL.Lifecycle) == 0 {
		t.Fatal("the catalogue names no lifecycle function, so nothing was measured")
	}
}
