package bpf

// fullObject is the compiled full program for this build's architecture.
func fullObject() []byte { return _FullBytes }

// Full is the observer's program: it reads the caller's plaintext buffer.
// Every build carries and loads it.
func Full() Program { return Program{Name: "full", Object: fullObject(), ReadsPayload: true} }

// Programs is both programs, which is what a check over the pair iterates.
func Programs() []Program { return []Program{Full(), Meta()} }
