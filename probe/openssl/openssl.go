// Package openssl observes processes moving plaintext through OpenSSL's
// libssl: the first implementation of the adapter contract, not its shape. It
// attaches at the library's entry points, on the process side of the
// encryption; nothing here terminates or trusts a certificate or decrypts.
package openssl

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// Name is what this adapter is called in the catalog and in what it reports.
const Name = "openssl"

// libraryPrefix is an OpenSSL library's file name before its version. libssl
// holds the plaintext entry points; libcrypto states the version.
const (
	pluginPrefix = "libssl.so"
	versionFrom  = "libcrypto.so"
)

// Adapter answers whether a process can be observed through OpenSSL, and how.
// It does not attach (probe/openssl/attach does, so a program needing only the
// answer cannot reach that machinery). The entry points and their introducing
// releases are the catalogue's (probe.OpenSSL).
type Adapter struct {
	// ProcFS is where the kernel publishes process state (/proc on a running
	// host).
	ProcFS string

	// Runtime is what the catalogue says about OpenSSL.
	Runtime probe.Runtime
}

// New builds the adapter against the running host and the catalogue.
func New() Adapter { return Adapter{ProcFS: "/proc", Runtime: probe.OpenSSL} }

func (a Adapter) Name() string { return a.Runtime.Name }

// Path is where the probes for this support would go.
func Path(support probe.Support) string {
	if len(support.Probes) == 0 {
		return ""
	}
	return support.Probes[0].Path
}

// Library is one OpenSSL library a process has mapped.
type Library struct {
	// Path is the file as the process that mapped it sees it.
	Path string `json:"path"`

	// Through is the same file reached under the observed process's own root:
	// where symbols are read from and probes placed.
	Through string `json:"-"`

	Name string `json:"name"`

	// Version is what the file states about itself (only libcrypto does; libssl's
	// major is in its name). Empty means read and stating nothing; an unreadable
	// file is VersionError instead, since the function set depends on the version
	// (SSL_write_ex2 exists on 3.3 and not 3.0).
	Version string `json:"version,omitempty"`

	// VersionError is why the version could not be read, set instead of Version:
	// indeterminate, not absent.
	VersionError string `json:"version_error,omitempty"`

	// Code reports whether the file is mapped executable: a running library
	// rather than an open file.
	Code bool `json:"code"`
}

// Libraries is the OpenSSL libraries among a process's mapped files, in kernel
// order. root is /proc/<pid>/root: a mapped path names a file in that process's
// filesystem, and the same path here may be a different build with functions
// at different offsets.
func Libraries(root string, mappings []process.Mapping) []Library {
	var libraries []Library
	for _, mapping := range mappings {
		name := filepath.Base(mapping.Path)
		if !strings.HasPrefix(name, pluginPrefix) && !strings.HasPrefix(name, versionFrom) {
			continue
		}
		through := filepath.Join(root, mapping.Path)
		stated, err := version(through)
		library := Library{
			Path:    mapping.Path,
			Through: through,
			Name:    name,
			Version: stated,
			Code:    mapping.Executable,
		}
		if err != nil {
			library.VersionError = err.Error()
		}
		libraries = append(libraries, library)
	}
	return libraries
}

// Inspect answers whether this adapter can observe the process, reading its
// mapped files and the library's symbol table and touching nothing it holds.
func (a Adapter) Inspect(p process.Process) probe.Support {
	mappings, err := process.Mappings(a.ProcFS, p.PID)
	if err != nil {
		return probe.Support{
			Reason: "the files this process has mapped could not be read, so whether it uses OpenSSL is unknown",
			Error:  err.Error(),
		}
	}

	root := filepath.Join(a.ProcFS, strconv.FormatInt(int64(p.PID), 10), "root")
	libraries := Libraries(root, mappings)
	index := slices.IndexFunc(libraries, func(l Library) bool {
		return strings.HasPrefix(l.Name, pluginPrefix) && l.Code
	})
	if index < 0 {
		return probe.Support{
			Reason: "no " + pluginPrefix + " is mapped with code, so this process either does not use OpenSSL or carries its own TLS inside itself",
		}
	}
	library := libraries[index]
	found := probe.Support{Runtime: runtime(library, libraries)}

	exported, err := probe.ExportedSymbols(library.Through)
	if err != nil {
		found.Reason = "the symbols of " + library.Path + " could not be read, so what it exports is unknown"
		found.Error = err.Error()
		return found
	}
	found.Unknown = unknown(a.Runtime, exported)

	probed := a.Runtime.Probed()
	offsets, err := probe.SymbolOffsets(library.Through, symbols(probed))
	if err != nil {
		found.Reason = "the symbols of " + library.Path + " could not be resolved to offsets"
		found.Error = err.Error()
		return found
	}

	var directions [2]bool
	for _, function := range probed {
		offset, resolved := offsets[function.Symbol]
		if !resolved {
			continue
		}
		found.Probes = append(found.Probes, probe.Probe{
			Symbol: function.Symbol,
			Path:   library.Through,
			Offset: offset,
		})
		if function.Direction == fragment.Sent {
			directions[0] = true
		}
		if function.Direction == fragment.Received {
			directions[1] = true
		}
	}
	// Lifecycle entry points are resolved with the plaintext ones, since the
	// attach policy, preflight.Take and the attachment all read this list. A
	// missing connection-ending probe is invisible: a reused SSL address continues
	// the previous connection's stream.
	for _, function := range a.Runtime.Lifecycle {
		if !function.Probed {
			continue
		}
		lifecycle, err := probe.SymbolOffsets(library.Through, []string{function.Symbol})
		if err != nil {
			continue
		}
		if offset, resolved := lifecycle[function.Symbol]; resolved {
			found.Probes = append(found.Probes, probe.Probe{
				Symbol: function.Symbol,
				Path:   library.Through,
				Offset: offset,
			})
		}
	}
	slices.SortFunc(found.Probes, func(x, y probe.Probe) int { return strings.Compare(x.Symbol, y.Symbol) })

	// Catalogued for this version and not exported: a short resolution, not an old
	// library.
	for _, function := range a.Runtime.ExpectedIn(release(library, libraries)) {
		if _, resolved := offsets[function.Symbol]; !resolved && function.Probed {
			found.Missing = append(found.Missing, function.Symbol)
		}
	}

	// A library exporting only one direction is misidentified, not half
	// observable.
	if !directions[0] || !directions[1] {
		found.Reason = library.Path + " exports none of " + strings.Join(missingDirections(directions), " and none of ")
		return found
	}

	found.Supported = true
	found.Reason = library.Path + " exports " + strings.Join(symbolsOf(found.Probes), ", ")
	return found
}

// unknown is what the library's plaintext family exports that the catalogue
// does not name.
func unknown(runtime probe.Runtime, exported []string) []string {
	named := make(map[string]bool, len(runtime.Functions))
	for _, symbol := range runtime.Symbols() {
		named[symbol] = true
	}

	var found []string
	for _, symbol := range exported {
		if runtime.Family(symbol) && !named[symbol] {
			found = append(found, symbol)
		}
	}
	slices.Sort(found)
	return found
}

func symbols(functions []probe.Function) []string {
	names := make([]string, len(functions))
	for i, function := range functions {
		names[i] = function.Symbol
	}
	return names
}

func symbolsOf(probes []probe.Probe) []string {
	names := make([]string, len(probes))
	for i, p := range probes {
		names[i] = p.Symbol
	}
	return names
}

func missingDirections(directions [2]bool) []string {
	var names []string
	if !directions[0] {
		names = append(names, "the functions a process writes plaintext through")
	}
	if !directions[1] {
		names = append(names, "the functions a process reads plaintext through")
	}
	return names
}

// runtime is the one line a report carries about what was found.
func runtime(library Library, libraries []Library) string {
	if version := release(library, libraries); version != "" {
		return library.Name + " (OpenSSL " + version + ")"
	}
	return library.Name
}

// release is the OpenSSL version behind this library, or "" when nothing
// states one. libssl has no version string, so it comes from the libcrypto of
// the same build.
func release(library Library, libraries []Library) string {
	stated := library.Version
	if stated == "" {
		for _, other := range libraries {
			if strings.HasPrefix(other.Name, versionFrom) && other.Version != "" {
				stated = other.Version
				break
			}
		}
	}
	return strings.TrimPrefix(stated, string(versionMarker))
}

// versionMarker is what an OpenSSL library calls itself in its own read-only
// data.
var versionMarker = []byte("OpenSSL ")

// versionLimit caps a version's length, so a foreign file cannot return an
// arbitrary run of bytes.
const versionLimit = 16

// versionScanLimit caps what is read looking for it: well past any OpenSSL
// library (about a megabyte).
const versionScanLimit = 32 << 20

// version is what the library says about itself: an error when the file could
// not be read, ("", nil) when read and stating no recognised version. It reads
// for a fixed marker and accepts what follows only while it looks like a
// version.
func version(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	content, err := readAtMost(file, versionScanLimit)
	if err != nil {
		return "", err
	}

	for at := 0; at < len(content); {
		found := bytes.Index(content[at:], versionMarker)
		if found < 0 {
			return "", nil
		}
		at += found + len(versionMarker)
		if number := versionAt(content[at:]); number != "" {
			return string(versionMarker) + number, nil
		}
	}
	return "", nil
}

// versionAt reads a version off the front of content, or returns an empty
// string when what is there is not one.
func versionAt(content []byte) string {
	if len(content) == 0 || content[0] < '0' || content[0] > '9' {
		return ""
	}

	end := 0
	for end < len(content) && end < versionLimit {
		c := content[end]
		if (c >= '0' && c <= '9') || c == '.' || (c >= 'a' && c <= 'z') {
			end++
			continue
		}
		break
	}
	if end == 0 || bytes.Count(content[:end], []byte(".")) < 2 {
		return ""
	}
	return string(content[:end])
}

func readAtMost(file *os.File, limit int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s is %d bytes, past the %d this reads", file.Name(), info.Size(), limit)
	}
	return os.ReadFile(file.Name())
}
