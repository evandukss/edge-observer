module github.com/evandukss/edge-observer

go 1.27

require (
	// Tests only: their fixtures, and the original decoder that internal/brotli
	// is checked against. The program links internal/brotli.
	github.com/andybalholm/brotli v1.2.6
	github.com/cilium/ebpf v0.22.0
	github.com/klauspost/compress v1.20.1
	golang.org/x/sys v0.43.0
)
