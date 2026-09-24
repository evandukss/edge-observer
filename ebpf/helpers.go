package ebpf

import "bytes"

// newReader is a reader over the embedded object bytes, so the loader takes a
// byte slice rather than a file.
func newReader(object []byte) *bytes.Reader { return bytes.NewReader(object) }
