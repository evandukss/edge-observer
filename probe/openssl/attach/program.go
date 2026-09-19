package attach

import "github.com/evandukss/edge-observer/bpf"

// defaultProgram is the program every build loads: the full one, which reads
// plaintext.
func defaultProgram() bpf.Program { return bpf.Full() }
