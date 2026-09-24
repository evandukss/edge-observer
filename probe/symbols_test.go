package probe_test

import (
	"debug/elf"
	"path/filepath"
	"testing"

	"github.com/evandukss/edge-observer/probe"
)

// The host's own libssl, read as it is on disk rather than a hand-written ELF.
func library(t *testing.T) string {
	t.Helper()

	for _, pattern := range []string{"/lib/*/libc.so.6", "/usr/lib/*/libc.so.6"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		if len(matches) > 0 {
			return matches[0]
		}
	}
	t.Fatal("no libc.so.6 on this host, so there is no shared library to read symbols from")
	return ""
}

func TestSymbolOffsetsFindsWhatALibraryExports(t *testing.T) {
	path := library(t)

	offsets, err := probe.SymbolOffsets(path, []string{"read", "write"})
	if err != nil {
		t.Fatalf("SymbolOffsets(%s): %v", path, err)
	}

	for _, symbol := range []string{"read", "write"} {
		if offsets[symbol] == 0 {
			t.Fatalf("%s is at offset %d in %s", symbol, offsets[symbol], path)
		}
	}
	if offsets["read"] == offsets["write"] {
		t.Fatalf("two symbols share one offset, %d", offsets["read"])
	}
}

// File offsets derived through sections must agree with those derived through
// segments. Symbols are chosen where the two numbers differ, since in this
// library functions sit where they coincide.
func TestSymbolOffsetsTranslatesAddressesIntoOffsetsIntoTheFile(t *testing.T) {
	path := library(t)

	file, err := elf.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = file.Close() }()

	symbols, err := file.DynamicSymbols()
	if err != nil {
		t.Fatalf("dynamic symbols of %s: %v", path, err)
	}

	// A symbol in a section with no file space has no offset and is refused.
	var names []string
	want := make(map[string]uint64, len(symbols))
	for _, symbol := range symbols {
		if symbol.Value == 0 || int(symbol.Section) >= len(file.Sections) {
			continue
		}
		if elf.ST_TYPE(symbol.Info) == elf.STT_TLS {
			// Thread-local: a per-thread block offset, not an address, so it is left out.
			continue
		}
		section := file.Sections[symbol.Section]
		if section.Type == elf.SHT_NOBITS || section.Addr == section.Offset {
			continue
		}
		names = append(names, symbol.Name)
		want[symbol.Name] = symbol.Value - section.Addr + section.Offset
	}
	if len(names) == 0 {
		t.Fatalf("no symbol of %s sits where its address and its offset differ, so the translation cannot be measured here", path)
	}

	offsets, err := probe.SymbolOffsets(path, names)
	if err != nil {
		t.Fatalf("SymbolOffsets(%s): %v", path, err)
	}

	var checked int
	for name, offset := range offsets {
		if offset != want[name] {
			t.Errorf("%s is at offset %#x through the segments and %#x through the sections", name, offset, want[name])
		}
		checked++
	}
	if checked == 0 {
		t.Fatalf("none of the %d symbols asked for came back, so the translation was not measured", len(names))
	}
}

func TestSymbolOffsetsLeavesOutASymbolTheLibraryDoesNotExport(t *testing.T) {
	path := library(t)

	offsets, err := probe.SymbolOffsets(path, []string{"read", "no_such_symbol_exists_here"})
	if err != nil {
		t.Fatalf("SymbolOffsets(%s): %v", path, err)
	}

	if _, ok := offsets["no_such_symbol_exists_here"]; ok {
		t.Fatal("a symbol the library does not export has an offset")
	}
	if len(offsets) != 1 {
		t.Fatalf("%d offsets, want 1", len(offsets))
	}
}

func TestSymbolOffsetsRefusesAFileThatIsNotAnObject(t *testing.T) {
	if _, err := probe.SymbolOffsets("/etc/hostname", []string{"read"}); err == nil {
		t.Fatal("SymbolOffsets read symbols out of a file that is not an object")
	}
}

// SSL_read and SSL_read@@OPENSSL_3.0.0 answer alike: matching the whole
// string would find nothing on a versioned library.
func TestSymbolOffsetsMatchesAVersionedNameEitherWayItIsWritten(t *testing.T) {
	path := library(t)

	file, err := elf.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = file.Close() }()

	versions, err := file.DynamicVersions()
	if err != nil {
		t.Fatalf("dynamic versions of %s: %v", path, err)
	}
	if len(versions) == 0 {
		t.Fatalf("%s binds no symbol to a version, so there is nothing to measure here", path)
	}

	symbols, err := file.DynamicSymbols()
	if err != nil {
		t.Fatalf("dynamic symbols of %s: %v", path, err)
	}

	var bare string
	for _, symbol := range symbols {
		if symbol.Value != 0 && symbol.Library == "" && symbol.Version != "" {
			bare = symbol.Name
			break
		}
	}
	if bare == "" {
		t.Fatalf("%s exports no versioned symbol, so there is nothing to measure here", path)
	}

	offsets, err := probe.SymbolOffsets(path, []string{bare + "@@SOMEVERSION"})
	if err != nil {
		t.Fatalf("SymbolOffsets(%s): %v", path, err)
	}

	if offsets[bare] == 0 {
		t.Fatalf("%s asked for by its versioned name resolves to %d", bare, offsets[bare])
	}
}
