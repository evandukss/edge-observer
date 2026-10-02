//go:build attach

package bpf

// ReadBarrier is an attach-test program with a bounded return barrier. It is
// absent from ordinary builds and requires bpf_loop support in the test kernel.
func ReadBarrier() Program {
	p := ReadBarrierVerification()
	p.Object = _BarrierBytes
	return p
}
