package bpf

// metaObject is the compiled metadata-only program for this architecture.
// bpf2go writes one object and binding per architecture behind build
// constraints, so _MetaBytes resolves to this binary's. Full is in full.go.
func metaObject() []byte { return _MetaBytes }
