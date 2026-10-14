package contentcoding

import (
	"errors"
	"io"
)

// A decoder library is code this package does not own, so a panic inside it
// is contained instead of ending the process: the stage is DecodingFailed with
// Fault set, and its decoder is discarded without being closed, so nothing the
// decoder holds goes back to a pool its library keeps. Only the library's own
// operations run under the guard: making or resetting a decoder, reading from
// it and closing it. The Reserver, the Observe callback and this package's
// accounting run outside it, so a panic there is not contained. The recovered
// value is only compared with nil and then dropped: it can carry captured
// content, and formatting it can run its methods.

// errDecoderFault is what a guarded read returns in place of a panic.
var errDecoderFault = errors.New("decoder fault")

// operation is one of the decoder library's operations a stage runs under its
// guard.
type operation int

const (
	operationMake operation = iota + 1
	operationReset
	operationRead
	operationClose
)

// library is one stage's guard over its decoder library, and whether any of
// the library's operations panicked. inject, when set, runs at the start of
// every guarded operation, inside the guard.
type library struct {
	coding  Coding
	inject  func(Coding, operation)
	faulted bool
}

// call runs operation op, f, under the guard, and reports false when it
// panicked.
func (l *library) call(op operation, f func()) (ok bool) {
	defer func() {
		if recover() != nil {
			l.faulted = true
			ok = false
		}
	}()
	if l.inject != nil {
		l.inject(l.coding, op)
	}
	f()
	return true
}

// close closes a decoder under the guard, unless the stage has faulted: a
// faulted decoder is discarded unclosed.
func (l *library) close(f func()) {
	if !l.faulted {
		l.call(operationClose, f)
	}
}

// guarded is a decoder whose reads run under its stage's guard. After a fault
// it reads nothing more.
type guarded struct {
	lib     *library
	decoder io.Reader
}

func (g guarded) Read(p []byte) (n int, err error) {
	if g.lib.faulted || !g.lib.call(operationRead, func() { n, err = g.decoder.Read(p) }) {
		return 0, errDecoderFault
	}
	return n, err
}
