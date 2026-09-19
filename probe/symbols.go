package probe

import (
	"debug/elf"
	"fmt"
	"strings"
)

// SymbolOffsets is where each named symbol begins in the file, as the file
// offset a uprobe is placed by. A missing symbol is absent, not an error.
//
// It reads the dynamic symbols (the other table is usually stripped). Names
// match up to their version, so SSL_read and SSL_read@@OPENSSL_3.0.0 answer
// alike. The offset is translated through the loadable segment containing the
// address: file offsets and virtual addresses diverge after the first segment.
func SymbolOffsets(path string, symbols []string) (map[string]uint64, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	dynamic, err := file.DynamicSymbols()
	if err != nil {
		return nil, fmt.Errorf("read the dynamic symbols of %s: %w", path, err)
	}

	wanted := make(map[string]bool, len(symbols))
	for _, symbol := range symbols {
		wanted[unversioned(symbol)] = true
	}

	offsets := make(map[string]uint64, len(symbols))
	for _, symbol := range dynamic {
		name := unversioned(symbol.Name)
		if !wanted[name] || symbol.Value == 0 {
			continue
		}
		if elf.ST_TYPE(symbol.Info) == elf.STT_TLS {
			// A thread-local symbol's value is a per-thread block offset, not a file
			// address.
			continue
		}
		offset, ok := fileOffset(file, symbol.Value)
		if !ok {
			return nil, fmt.Errorf("%s: %s is at address %#x, which is in no loadable segment", path, symbol.Name, symbol.Value)
		}
		offsets[name] = offset
	}
	return offsets, nil
}

// unversioned is a symbol name without its version (after @ or @@).
func unversioned(symbol string) string {
	name, _, _ := strings.Cut(symbol, "@")
	return name
}

// fileOffset translates a virtual address into an offset into the file, through
// the loadable segment that maps it.
func fileOffset(file *elf.File, address uint64) (uint64, bool) {
	for _, segment := range file.Progs {
		if segment.Type != elf.PT_LOAD {
			continue
		}
		if address < segment.Vaddr || address >= segment.Vaddr+segment.Memsz {
			continue
		}
		if address >= segment.Vaddr+segment.Filesz {
			// A segment's tail can be larger in memory than in the file.
			return 0, false
		}
		return address - segment.Vaddr + segment.Off, true
	}
	return 0, false
}

// ExportedSymbols is every function a shared library exports, without
// versions, so uncatalogued entry points can be found.
func ExportedSymbols(path string) ([]string, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	dynamic, err := file.DynamicSymbols()
	if err != nil {
		return nil, fmt.Errorf("read the dynamic symbols of %s: %w", path, err)
	}

	seen := make(map[string]bool, len(dynamic))
	names := make([]string, 0, len(dynamic))
	for _, symbol := range dynamic {
		// An undefined symbol is imported, not exported.
		if symbol.Value == 0 || elf.ST_TYPE(symbol.Info) != elf.STT_FUNC {
			continue
		}
		name := unversioned(symbol.Name)
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, nil
}
