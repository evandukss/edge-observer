package bpf

// The fields of the program's own structures, in order, so a Go mirror of one
// can be compared against it. A field inserted mid-structure that the mirror
// does not name can leave the total size unchanged, so a size check passes
// while every later field is read from the wrong bytes. Names are compared
// rather than types: two u8 fields have one type and different meanings.

// Field is one member of a structure in the program's source: its name and
// the width its type occupies.
type Field struct {
	Name  string
	Bytes int
}
