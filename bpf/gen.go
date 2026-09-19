// Package bpf embeds the observer's two compiled BPF programs and the checks
// that keep them honest.
//
// The two programs are one source compiled twice (ssl.bpf.h): the full program
// reads the caller's plaintext buffer, and the metadata-only program reads no
// process memory at all. Every build embeds both and the observer loads the
// full one. What each can read is a property of its compiled object, which
// Verify proves by decoding the helpers each program calls.
//
// bpf2go compiles each .c for both architectures and writes the objects and
// their Go bindings beside this file. They are committed so building the
// observer needs no BPF toolchain; regenerating with clang must reproduce them
// byte for byte.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64,arm64 -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include/aarch64-linux-gnu" full ./sslfull.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target amd64,arm64 -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include/aarch64-linux-gnu" meta ./sslmeta.bpf.c
