package probe

import (
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// BuildID is the GNU build id of an ELF file, as lowercase hex (readelf -n).
// An attach policy names a library by it: builds with one version string have
// different ids. A file with no .note.gnu.build-id returns an empty id and no
// error; the policy decides whether that is acceptable.
func BuildID(path string) (string, error) {
	file, err := elf.Open(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	for _, section := range file.Sections {
		if section.Type != elf.SHT_NOTE {
			continue
		}
		data, err := section.Data()
		if err != nil {
			return "", fmt.Errorf("read the notes of %s: %w", path, err)
		}
		if id, found := buildIDFromNotes(data, file.ByteOrder); found {
			return id, nil
		}
	}
	return "", nil
}

// buildIDFromNotes walks the notes in one section (name, type, descriptor,
// each 4-byte padded) and returns the build id if present.
func buildIDFromNotes(data []byte, order binary.ByteOrder) (string, bool) {
	const noteGNUBuildID = 3
	const gnu = "GNU\x00"

	for len(data) >= 12 {
		nameSize := order.Uint32(data[0:4])
		descSize := order.Uint32(data[4:8])
		noteType := order.Uint32(data[8:12])
		data = data[12:]

		namePadded := align4(nameSize)
		descPadded := align4(descSize)
		if int(namePadded)+int(descPadded) > len(data) {
			return "", false
		}
		name := data[:nameSize]
		desc := data[namePadded : namePadded+descSize]
		data = data[namePadded+descPadded:]

		if noteType == noteGNUBuildID && string(name) == gnu {
			return hex.EncodeToString(desc), true
		}
	}
	return "", false
}

func align4(n uint32) uint32 { return (n + 3) &^ 3 }
