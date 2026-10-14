package processing

import (
	"strings"

	"github.com/evandukss/edge-observer/contentcoding"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/reconstruct"
)

// verdict is what release does with one exchange the pairing handed over.
type verdict uint8

const (
	// verdictWrite is an exchange whose lines are written: complete and
	// supported, each encoded body decoded. prepared.exchange is what is
	// copied and written.
	verdictWrite verdict = iota + 1
	// verdictStop is a terminal stop: the exchange is excluded, so is every
	// later one of its connection, and the connection's suffix starts at it
	// (parsing.omitted).
	verdictStop
	// verdictExclude is an exchange excluded alone, under prepared.reason: it
	// takes its id and index, no line carries it, it is counted once
	// (excludeAlone), and the exchanges after it go on.
	verdictExclude
	// verdictCut is a decoding reservation the shared allowance refused. The
	// connection is cut by the existing counted cut (cutByAllowance): nothing
	// of the exchange is released, accounted or counted, and every charge the
	// decoding held was given back before prepare returned.
	verdictCut
)

// prepared is one exchange the pairing handed over, as release reads it.
type prepared struct {
	verdict verdict
	// reason is the exclusion reason with verdictExclude: one of
	// ReasonContentCodingUnsupported, ReasonContentDecodingFailed,
	// ReasonContentDecodedTooLarge and ReasonContentDecodingTooCostly.
	reason string
	// exchange is, with verdictWrite and verdictExclude, the exchange to copy:
	// the one handed over, with each message whose body was decoded replaced
	// by a copy holding the decoded content, its shape derived again from
	// those bytes and the shape taken from the encoded ones discarded, its
	// captured length, holes, framing and stream offsets kept, and its Content
	// recording the decoding. With verdictExclude a message whose decoding
	// did not complete, or was never begun, is the one handed over, encoded:
	// the extension chain sends the decoded ones and omits it. The messages
	// handed over are not changed.
	exchange reconstruct.Exchange
	// index is the connection index the exchange takes if it is released or
	// excluded alone: the connection's next one when it was prepared.
	index int
	// content is, for the request and the response, what its decoded content
	// holds in the shared allowance, as intake.Parsing, until releaseContent
	// gives it back: the last stage's last output buffer. Zero Bytes for a
	// message not decoded.
	content [2]contentcoding.Charge
}

// chargeEvent is what happened to one charge a decoding asked the shared
// allowance for.
type chargeEvent uint8

const (
	// chargeReserving is a charge about to be asked of the allowance: nothing
	// of it is held yet.
	chargeReserving chargeEvent = iota + 1
	// chargeReserved is a charge the allowance granted, now held.
	chargeReserved
	// chargeRefused is a charge the allowance refused; nothing of it is held.
	chargeRefused
	// chargeReturned is a held charge given back.
	chargeReturned
)

// decodeCharge is one event of what a decoding charged, and the exchange it was
// for: its connection, the index it takes if it is released or excluded alone
// (prepared.index), and whether the message decoded is its request.
type decodeCharge struct {
	Process    fragment.Process
	Connection fragment.ConnectionID
	Index      int
	Request    bool
	Event      chargeEvent
	Charge     contentcoding.Charge
}

// observeCharge tells Options.decodeCharges of one charge event, where a test
// set it.
func (w *Worker) observeCharge(b *batch, index int, request bool, event chargeEvent, c contentcoding.Charge) {
	if w.options.decodeCharges != nil {
		w.options.decodeCharges(decodeCharge{Process: b.process, Connection: b.id, Index: index, Request: request,
			Event: event, Charge: c})
	}
}

// prepare reads one exchange the pairing handed over, complete and certified,
// and decides what release does with it. It is the one place an exchange is
// classified and its bodies decoded, on the path without extensions and on the
// extension chain alike. The caller has established the connection's identity
// (Worker.identity); a failure there is a stop the caller takes without
// preparing.
//
// The order is fixed, and only bounded work decides it:
//
//  1. A stop: the connection already stopped (parsing.excluded), or the
//     exchange is not complete, or a standing stop applies to either message
//     (eligibleMessage), a malformed Content-Encoding included. verdictStop.
//  2. Header-only, on both messages: a message with a body whose captured
//     Content-Encoding names a coding this observer does not undo, or more
//     than one, is ReasonContentCodingUnsupported. No decoder runs for
//     either message then: nothing it could return outranks that reason but
//     a refused reservation, and no decoding is needed to exclude it.
//  3. Decoding, the request before the response: each message with a body and
//     a non-identity coding list is decoded within the per-message body bound,
//     to its first decisive result. A refused reservation ends it at once as
//     verdictCut, the response not decoded where the request was refused. A
//     decoder library that failed and was contained (contentcoding.Result's
//     Fault) is a failed decoding, and is counted in Outcome.DecoderFaults
//     too; nothing of the failure is kept.
//  4. The reason, between the outcomes the two messages established
//     (ranked): ReasonContentCodingUnsupported over
//     ReasonContentDecodingFailed over ReasonContentDecodedTooLarge over
//     ReasonContentDecodingTooCostly, the request's on a tie. With no reason,
//     verdictWrite.
//
// A message whose captured framing establishes no content bytes - its framing
// has no body, or Content-Length 0, or a chunked body whose first chunk is the
// last, complete with its trailer section - encodes nothing whatever its
// Content-Encoding says: it is not decoded, excluded or given a reason, and
// it is written as any message is, with no record of a decoding. That is read
// from the captured extent (http1.Message.BodyLength), never from the bytes
// retained, and only after step 1, so every stop that stops it today still
// does. A nonempty captured body none of whose bytes were retained is not in
// this class.
//
// What it decoded is held in the shared allowance for the caller, with
// verdictWrite and verdictExclude alike, until the caller gives it back
// (releaseContent). With verdictCut it gave everything back before it
// returned.
func (w *Worker) prepare(b *batch, x reconstruct.Exchange, _ reconstruct.Role) prepared {
	p := b.parse
	if p.excluded || !x.Complete || !eligibleMessage(x.Request) || !eligibleMessage(x.Response) {
		return prepared{verdict: verdictStop, index: p.exchanges}
	}
	sides := [2]*reconstruct.Message{x.Request, x.Response}
	var lists [2]contentcoding.List
	for i, m := range sides {
		if bodiless(m) {
			continue
		}
		list, verdict := contentcoding.ParseList(contentEncodings(m))
		if verdict == contentcoding.Unsupported {
			return prepared{verdict: verdictExclude, reason: ReasonContentCodingUnsupported, exchange: x, index: p.exchanges}
		}
		lists[i] = list
	}
	out := prepared{verdict: verdictWrite, exchange: x, index: p.exchanges}
	var reasons [2]string
	for i, m := range sides {
		if lists[i].Len() == 0 {
			continue
		}
		reserver := decodeReserver{w: w, b: b, index: out.index, request: i == 0}
		decode := contentcoding.Decode
		if w.options.decoder != nil {
			decode = w.options.decoder
		}
		result := decode(lists[i], m.Body, contentcoding.Options{Bound: bodyBound(w.options.Limits.HTTP), Reserver: reserver})
		switch result.Outcome {
		case contentcoding.Decoded:
			out.content[i] = contentcoding.Charge{Kind: contentcoding.OutputCharge, Stage: lists[i].Len(),
				Bytes: result.Charge}
			names := make([]string, lists[i].Len())
			for n := range names {
				names[n] = lists[i].At(n).String()
			}
			decoded := reconstruct.Decoded(m, result.Body, reconstruct.Content{Codings: names,
				Fields: contentEncodings(m), Length: uint64(len(result.Body))}, w.options.Limits.JSON)
			if i == 0 {
				out.exchange.Request = decoded
			} else {
				out.exchange.Response = decoded
			}
		case contentcoding.Refused:
			w.releaseContent(b, &out)
			return prepared{verdict: verdictCut, index: out.index}
		case contentcoding.DecodingFailed, contentcoding.DecodedTooLarge, contentcoding.DecodingTooCostly:
			reasons[i] = result.Outcome.Reason()
			if result.Fault {
				// The decoder library failed and was contained: the exchange is
				// excluded as a failed decoding, and the fault is counted apart.
				w.outcome.DecoderFaults++
			}
		default:
			// Decode has no other outcome for a list with codings; one that is
			// not known is not written.
			reasons[i] = ReasonContentDecodingFailed
		}
	}
	if reason := ranked(reasons); reason != "" {
		out.verdict, out.reason = verdictExclude, reason
	}
	return out
}

// ranked is the reason an exchange takes between the decoding outcomes its two
// messages established, request first: ReasonContentDecodingFailed over
// ReasonContentDecodedTooLarge over ReasonContentDecodingTooCostly, and ""
// where neither established one. ReasonContentCodingUnsupported outranks all
// three, and is decided before any decoding (prepare).
func ranked(reasons [2]string) string {
	for _, reason := range []string{ReasonContentDecodingFailed, ReasonContentDecodedTooLarge,
		ReasonContentDecodingTooCostly} {
		if reasons[0] == reason || reasons[1] == reason {
			return reason
		}
	}
	return ""
}

// eligibleMessage is a message release reads further: no standing stop applies
// to it (unstopped), and its Content-Encoding, if any, is a list of codings. A
// malformed one (contentcoding.Malformed) is a defect and stops it, as it
// always did; a coding it names, known or not, is the classification's to
// decide.
func eligibleMessage(m *reconstruct.Message) bool {
	if !unstopped(m) {
		return false
	}
	fields := contentEncodings(m)
	if len(fields) == 0 {
		return true
	}
	_, verdict := contentcoding.ParseList(fields)
	return verdict == contentcoding.Supported || verdict == contentcoding.Unsupported
}

// bodiless is a message whose captured framing establishes no content bytes:
// none by its framing, Content-Length 0, or a chunked body whose first chunk
// is the last. It is read from the captured extent, never from the bytes
// retained, and only of a message eligibleMessage admitted, which is complete,
// with no hole and nothing elided.
func bodiless(m *reconstruct.Message) bool {
	return m.BodyLength == 0
}

// contentEncodings is the values of a message's captured Content-Encoding
// fields, in the order they were captured.
func contentEncodings(m *reconstruct.Message) []string {
	var values []string
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, "content-encoding") {
			values = append(values, h.Value)
		}
	}
	return values
}

// bodyBound is the per-message body bound limits apply, MaxBodyBytes, with
// http1's default where it is not set: the most bytes any decoding stage may
// produce.
func bodyBound(limits http1.Limits) int {
	if limits.MaxBodyBytes <= 0 {
		return http1.DefaultLimits().MaxBodyBytes
	}
	return limits.MaxBodyBytes
}

// decodeReserver charges what one message's decoding holds to the shared
// allowance as intake.Parsing, on its connection's reading: a decoding is part
// of reading an exchange. A charge the allowance refuses is refused, and the
// connection is cut for it (verdictCut). Each charge is told to a test that
// observes them (observeCharge) with the exchange it is for.
type decodeReserver struct {
	w       *Worker
	b       *batch
	index   int
	request bool
}

func (r decodeReserver) Reserve(c contentcoding.Charge) bool {
	r.w.observeCharge(r.b, r.index, r.request, chargeReserving, c)
	if !r.w.options.Intake.Reserve(intake.Parsing, c.Bytes) {
		r.w.observeCharge(r.b, r.index, r.request, chargeRefused, c)
		return false
	}
	r.b.parse.charged += c.Bytes
	r.w.observeCharge(r.b, r.index, r.request, chargeReserved, c)
	return true
}

func (r decodeReserver) Release(c contentcoding.Charge) {
	r.w.options.Intake.Return(intake.Parsing, c.Bytes)
	r.b.parse.charged -= c.Bytes
	r.w.observeCharge(r.b, r.index, r.request, chargeReturned, c)
}

// excludeAlone records an exchange excluded alone under reason, as release
// and the extension chain both do: it issues the exchange its index and id,
// counts it once, on its connection and in the worker's outcome, and moves the
// connection's accounted boundary past both its messages (parsing.released),
// so a later truncation describes only what follows it. A later cut or capture
// loss never changes its count or its reason. It writes nothing; the caller
// reports it, and on the chain sends it to the extensions as excluded with
// its reason.
func (w *Worker) excludeAlone(b *batch, x reconstruct.Exchange, role reconstruct.Role, reason string) (int, uint64) {
	p := b.parse
	index := p.exchanges
	p.exchanges++
	id := w.release.nextID()
	if id == 0 {
		return index, 0
	}
	p.exclusions.add(reason)
	w.outcome.Excluded.add(reason)
	request, response := directions(role)
	for _, side := range []struct {
		direction fragment.Direction
		message   *reconstruct.Message
	}{{request, x.Request}, {response, x.Response}} {
		if side.message != nil && side.direction != fragment.Unknown {
			p.released[side.direction] = max(p.released[side.direction], side.message.End)
		}
	}
	return index, id
}

// releaseContent gives back what the decoded content of a prepared exchange
// holds in the shared allowance, each message's once: after its lines are
// written, or when it is let go without them.
func (w *Worker) releaseContent(b *batch, prep *prepared) {
	for i, held := range prep.content {
		if held.Bytes == 0 {
			continue
		}
		w.options.Intake.Return(intake.Parsing, held.Bytes)
		if b.parse != nil {
			b.parse.charged -= held.Bytes
		}
		w.observeCharge(b, prep.index, i == 0, chargeReturned, held)
		prep.content[i] = contentcoding.Charge{}
	}
}

// add counts one exchange under reason.
func (e *Exclusions) add(reason string) {
	switch reason {
	case ReasonContentCodingUnsupported:
		e.ContentCodingUnsupported++
	case ReasonContentDecodingFailed:
		e.ContentDecodingFailed++
	case ReasonContentDecodedTooLarge:
		e.ContentDecodedTooLarge++
	case ReasonContentDecodingTooCostly:
		e.ContentDecodingTooCostly++
	}
}
