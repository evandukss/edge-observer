package processing

import (
	"unsafe"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/reconstruct"
)

// The fixed parts of what a worker charges to the shared allowance, in
// accounted bytes (the package documentation, "Held work and the shared
// allowance"). They are the sizes of the structures they stand for in this
// build.
const (
	// messageCharge is one message descriptor: a message parsing has begun, or
	// a message a copy holds.
	messageCharge = int64(unsafe.Sizeof(reconstruct.Message{}))
	// fieldCharge is one header or trailer a copy holds, apart from the lengths
	// of its name and value.
	fieldCharge = int64(unsafe.Sizeof(http1.Header{}))
	// readingCharge is a connection's reading state: its pairing, the pairing's
	// two parsers, and the worker's reading state and reserver for it.
	readingCharge = int64(unsafe.Sizeof(reconstruct.Pairing{}) + 2*unsafe.Sizeof(http1.Parser{}) +
		unsafe.Sizeof(parsing{}) + unsafe.Sizeof(ceiling{}))
)

// parsingUnits is what an http1.Charge costs: its bytes, and a descriptor for
// each message.
func parsingUnits(c http1.Charge) int64 {
	return c.Bytes + c.Messages*messageCharge
}

// copyUnits is what a copy of c costs: for each message, a descriptor, the
// lengths of its method, target, protocol and reason, each header and trailer
// as a field plus its name and value, and its body.
func copyUnits(c reconstruct.Connection) int64 {
	var n int64
	for _, e := range c.Exchanges {
		n += messageUnits(e.Request) + messageUnits(e.Response)
	}
	return n
}

func messageUnits(m *reconstruct.Message) int64 {
	if m == nil {
		return 0
	}
	n := messageCharge + int64(len(m.Method)+len(m.Target)+len(m.Protocol)+len(m.Reason)+len(m.Body))
	for _, fields := range [][]http1.Header{m.Headers, m.Trailers} {
		for _, h := range fields {
			n += fieldCharge + int64(len(h.Name)+len(h.Value))
		}
	}
	return n
}

// policyCopy makes a pipeline's copy of source and applies its slots to it.
// The copy is charged to Policy at its units before it is made, and a slot
// that grows it has the growth charged before the grown copy is kept; held is
// what the copy is charged when it returns. failed is a slot that failed.
// refused is a reservation the allowance refused: then nothing is kept and
// nothing stays charged.
func (w *Worker) policyCopy(b *batch, source reconstruct.Connection, slots []config.EffectiveSlot) (
	processed reconstruct.Connection, run *slotRun, held int64, failed, refused bool) {
	held = copyUnits(source)
	if !w.reservePolicy(b, held) {
		return reconstruct.Connection{}, nil, 0, false, true
	}
	processed = copyConnection(source)
	run = &slotRun{source: source, evidence: exclusionEvidence{fields: []PolicyExclusion{}},
		bodies: map[*reconstruct.Message]string{}, shapes: w.options.Limits.JSON}
	for _, slot := range slots {
		if !run.apply(&processed, slot) {
			return processed, run, held, true, false
		}
		if now := copyUnits(processed); now > held {
			if !w.reservePolicy(b, now-held) {
				w.returnPolicy(b, held)
				return reconstruct.Connection{}, nil, 0, false, true
			}
			held = now
		}
	}
	return processed, run, held, false, false
}

// cutByAllowance cuts a connection whose growth the shared allowance refused,
// counting it apart from a cut at the connection's own bound.
func (w *Worker) cutByAllowance(b *batch) {
	if !b.cut {
		w.outcome.AllowanceCut++
	}
	w.cut(b)
}

// cutRefused cuts a connection whose reading was refused growth, by the
// cause its reserver recorded.
func (w *Worker) cutRefused(b *batch) {
	if p := b.parse; p != nil && p.reserver.full {
		w.cutByAllowance(b)
		return
	}
	w.cut(b)
}

// reservePolicy charges n to Policy for a copy of b's.
func (w *Worker) reservePolicy(b *batch, n int64) bool {
	if !w.options.Intake.Reserve(intake.Policy, n) {
		return false
	}
	b.policy += n
	return true
}

// returnPolicy gives back n of b's copies' charge.
func (w *Worker) returnPolicy(b *batch, n int64) {
	w.options.Intake.Return(intake.Policy, n)
	b.policy -= n
}
