package bpf

import (
	_ "embed"
	"strconv"
	"strings"
	"testing"
)

// widths is what each of the program's fixed-width type spellings occupies.
var widths = map[string]int{
	"__u8": 1, "__s8": 1,
	"__u16": 2, "__s16": 2,
	"__u32": 4, "__s32": 4,
	"__u64": 8, "__s64": 8,
}

// Fields is the members of one structure in the program's source, in declared
// order. It reads the source because the compiled object carries type
// information only for what a map declares.
func Fields(source, structure string) []Field {
	opening := "struct " + structure + " {"
	start := strings.Index(source, opening)
	if start < 0 {
		return nil
	}
	body := source[start+len(opening):]
	if end := strings.Index(body, "\n};"); end >= 0 {
		body = body[:end]
	}

	var held []Field
	for line := range strings.Lines(body) {
		text := strings.TrimSpace(line)
		if before, _, found := strings.Cut(text, "//"); found {
			text = strings.TrimSpace(before)
		}
		if !strings.HasSuffix(text, ";") {
			continue
		}
		fields := strings.Fields(strings.TrimSuffix(text, ";"))
		if len(fields) != 2 {
			continue
		}
		width, known := widths[fields[0]]
		if !known {
			continue
		}
		name := fields[1]
		// An array member carries its count in the name; the count is part of the
		// width.
		if open := strings.Index(name, "["); open >= 0 {
			count, err := strconv.Atoi(strings.TrimSuffix(name[open+1:], "]"))
			if err != nil {
				continue
			}
			width *= count
			name = name[:open]
		}
		held = append(held, Field{Name: name, Bytes: width})
	}
	return held
}

// A Go mirror of a program structure names every field the program has, in
// the program's order. An insertion paid for out of trailing padding keeps
// the size (struct call once gained a field that shifted every later read by
// one byte), so this compares order and names.
func TestTheInFlightMirrorNamesEveryFieldTheProgramDeclares(t *testing.T) {
	declared := Fields(source, "call")
	if len(declared) < 8 {
		t.Fatalf("read %d fields out of struct call, which cannot be right", len(declared))
	}

	// The mirror as package ebpf spells it, written out because bpf cannot import
	// ebpf (ebpf imports bpf); one line per field, checked here.
	mirrored := []Field{
		{"ssl", 8}, {"buf", 8}, {"cap", 8}, {"pcount", 8}, {"generation", 8}, {"sequence", 8},
		{"func", 4}, {"fd", 4}, {"fds", 1},
		{"socket", 8}, {"socket_ino", 8}, {"socket_gen", 8}, {"socket_occ", 8},
		{"net_ino", 8}, {"opened", 8}, {"local", 16}, {"peer", 16}, {"lport", 2}, {"dport", 2},
		{"socket_fd", 4}, {"sockets", 1}, {"ends", 1},
		{"outcome", 1}, {"io", 1},
		{"dir", 1}, {"count", 1}, {"early", 1}, {"deferred", 1}, {"live", 1}, {"live_padding", 3},
	}

	if len(declared) != len(mirrored) {
		t.Fatalf("the program declares %d fields in struct call and the mirror names %d: %s",
			len(declared), len(mirrored), disagreement(declared, mirrored))
	}
	for i := range declared {
		if declared[i] != mirrored[i] {
			t.Errorf("field %d of struct call is %s of %d bytes in the program and %s of %d here, "+
				"so this field and every one after it reads from the wrong place",
				i, declared[i].Name, declared[i].Bytes, mirrored[i].Name, mirrored[i].Bytes)
		}
	}
}

// The allowlist's value decides whether a process is observed at all, so a
// mirror reading a field early authenticates against the wrong bytes.
func TestTheAdmissionMirrorNamesEveryFieldTheProgramDeclares(t *testing.T) {
	declared := Fields(source, "admission")
	if len(declared) < 8 {
		t.Fatalf("read %d fields out of struct admission, which cannot be right", len(declared))
	}

	// The mirror as package ebpf spells it, written out for the same reason.
	mirrored := []Field{
		{"generation", 8}, {"birth", 8}, {"parent_generation", 8},
		{"parent_ns_dev", 8}, {"parent_ns_ino", 8},
		{"parent_pid", 4}, {"target", 4}, {"rule", 4}, {"threads", 4},
		{"kind", 1}, {"mode", 1}, {"propagate", 1}, {"leader_gone", 1},
		{"reserved", 4},
	}

	if len(declared) != len(mirrored) {
		t.Fatalf("the program declares %d fields in struct admission and the mirror names %d: %s",
			len(declared), len(mirrored), disagreement(declared, mirrored))
	}
	for i := range declared {
		if declared[i] != mirrored[i] {
			t.Errorf("field %d of struct admission is %s of %d bytes in the program and %s of %d here, "+
				"so this field and every one after it reads from the wrong place",
				i, declared[i].Name, declared[i].Bytes, mirrored[i].Name, mirrored[i].Bytes)
		}
	}
}

// disagreement names the first place two field lists differ.
func disagreement(declared, mirrored []Field) string {
	for i := range min(len(declared), len(mirrored)) {
		if declared[i] != mirrored[i] {
			return "they first differ at field " + strconv.Itoa(i) + ": the program has " +
				declared[i].Name + " and the mirror has " + mirrored[i].Name
		}
	}
	if len(declared) > len(mirrored) {
		return "the mirror stops at " + strconv.Itoa(len(mirrored)) + " and the program continues with " +
			declared[len(mirrored)].Name
	}
	return "the program stops at " + strconv.Itoa(len(declared)) + " and the mirror continues with " +
		mirrored[len(declared)].Name
}

// The event's layout and the offsets its reader takes fields from. struct
// event crosses the ring buffer, so the object has no type information for it
// and package ebpf decodes it by hand-written byte ranges. This pins order,
// names and offsets: a field inserted anywhere but the end moves every later
// offset. data is excluded: its extent is a macro, and the payload begins at
// the end of the fixed part, bounded by the kept count.
func TestTheEventReaderTakesEachFieldFromWhereTheProgramPutsIt(t *testing.T) {
	declared := Fields(source, "event")
	// Fields skips a member whose extent is not a literal (data). If it becomes
	// one, drop it here rather than read the payload as header.
	if n := len(declared); n > 0 && declared[n-1].Name == "data" {
		declared = declared[:n-1]
	}
	if len(declared) < 15 {
		t.Fatalf("read %d fields out of struct event, which cannot be right", len(declared))
	}

	// One line per field: the program's spelling, its width, and the offset package
	// ebpf reads it at, written out because bpf cannot import ebpf.
	type placed struct {
		Field
		At int
	}
	reader := []placed{
		{Field{"stamp", 8}, 0}, {Field{"binding", 8}, 8}, {Field{"ssl", 8}, 16},
		{Field{"generation", 8}, 24}, {Field{"ns_dev", 8}, 32}, {Field{"ns_ino", 8}, 40},
		{Field{"socket", 8}, 48},
		{Field{"pid", 4}, 56}, {Field{"tid", 4}, 60}, {Field{"nspid", 4}, 64},
		{Field{"length", 4}, 68}, {Field{"kept", 4}, 72}, {Field{"fd", 4}, 76},
		{Field{"dir", 1}, 80}, {Field{"early", 1}, 81}, {Field{"measured", 1}, 82},
		{Field{"kind", 1}, 83}, {Field{"fd_state", 1}, 84}, {Field{"outcome", 1}, 85},
		{Field{"ends", 1}, 86}, {Field{"padding", 1}, 87}, {Field{"net_ino", 8}, 88},
		{Field{"local", 16}, 96}, {Field{"peer", 16}, 112},
		{Field{"lport", 2}, 128}, {Field{"dport", 2}, 130}, {Field{"padding_end", 4}, 132},
		{Field{"opened", 8}, 136},
	}

	if len(declared) != len(reader) {
		mirrored := make([]Field, len(reader))
		for i, one := range reader {
			mirrored[i] = one.Field
		}
		t.Fatalf("the program declares %d fields in struct event and the reader names %d: %s",
			len(declared), len(reader), disagreement(declared, mirrored))
	}

	at := 0
	for i := range declared {
		if declared[i] != reader[i].Field {
			t.Errorf("field %d of struct event is %s of %d bytes in the program and %s of %d here, "+
				"so this field and every one after it is read from the wrong place",
				i, declared[i].Name, declared[i].Bytes, reader[i].Name, reader[i].Bytes)
			return
		}
		if at != reader[i].At {
			t.Errorf("%s sits at offset %d in the program and the reader takes it from %d",
				declared[i].Name, at, reader[i].At)
		}
		at += declared[i].Bytes
	}

	// The payload begins where the fixed part ends (rawHeader in package ebpf). A
	// field added at the end moves it without moving any offset above.
	if at != 144 {
		t.Errorf("the fixed part of struct event is %d bytes and package ebpf reads its payload "+
			"from offset 144, so every payload it copies starts in the wrong place", at)
	}
}
