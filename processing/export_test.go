package processing

import (
	"github.com/evandukss/edge-observer/contentcoding"
	"github.com/evandukss/edge-observer/fragment"
)

// BatchesOf is the worker's map of connections whose input it holds, for a test
// measuring what the map allocates.
func BatchesOf(w *Worker) any { return w.batches }

// Turn is one round of a worker's scheduler, as it was when it ended.
type Turn = turn

// Released is one exchange a turn issued an id to, and what its release came
// to.
type Released = released

// ReleaseOutcome is what one exchange's release came to.
type ReleaseOutcome = releaseOutcome

const (
	ReleaseEnqueued     = releaseEnqueued
	ReleaseDropped      = releaseDropped
	ReleaseWithdrawn    = releaseWithdrawn
	ReleaseUnauthorized = releaseUnauthorized
	ReleaseExcluded     = releaseExcluded
)

// TurnEntries is the most entries a worker takes from its queue in one turn.
const TurnEntries = turnEntries

// ObserveTurns is options with observe told of every turn each worker ends,
// on that worker's goroutine: a Run's workers call it concurrently.
func ObserveTurns(options Options, observe func(Turn)) Options {
	options.turns = observe
	return options
}

// HeldConnection is what a worker holds for one connection: the intake
// entries it keeps leased, Pending, the count Options.ConnectionInput bounds,
// Bytes, the intake's charge for those entries, and Parsing, what its reading
// holds in the shared allowance as intake.Parsing.
//
// Exchanges is how many exchanges its reading handed over, Excluded those of
// them excluded alone, by reason, and Chain the exchanges still on their way
// through the extensions. Apart from the entries, the chain, what its reading
// retains (Parsing) and the set of the plan's pipelines that failed on it,
// what a worker keeps for a connection is fixed in size - offsets and stops
// per direction, and counts - so nothing else grows with the exchanges it has
// consumed.
type HeldConnection struct {
	Process    fragment.Process
	Connection fragment.ConnectionID
	Entries    int
	Pending    int
	Bytes      int64
	Parsing    int64
	Exchanges  int
	Excluded   Exclusions
	Chain      int
}

// Connections is every connection w holds input for, in the order it
// examines them. Its owner reads it, never while Drain or Finish runs.
func Connections(w *Worker) []HeldConnection {
	var out []HeldConnection
	for _, key := range w.order {
		if b := w.batches[key]; b != nil {
			one := HeldConnection{Process: key.process, Connection: key.id, Entries: b.entries(),
				Pending: b.pending(), Bytes: b.bytes(), Chain: len(b.chain)}
			if b.parse != nil {
				one.Parsing = b.parse.charged
				one.Exchanges, one.Excluded = b.parse.exchanges, b.parse.exclusions
			}
			out = append(out, one)
		}
	}
	return out
}

// The fixed parts of the charges, in accounted bytes: a message descriptor, a
// header or trailer apart from its name and value, and a connection's reading
// state.
const (
	MessageCharge = messageCharge
	FieldCharge   = fieldCharge
	ReadingCharge = readingCharge
)

// Submission is one extension call as a worker is about to submit it.
type Submission = submission

// ObserveSubmits is options with observe told of every extension call a
// worker is about to submit, on that worker's goroutine, after the call's
// message is encoded and before Submit is asked: what the worker holds then
// is what it holds before the supervisor accepts anything.
func ObserveSubmits(options Options, observe func(Submission)) Options {
	options.submits = observe
	return options
}

// DecodeCharge is one event of what a decoding asks the shared allowance for,
// with the exchange it was for: the connection, the index the exchange takes
// if it is released or excluded alone - the connection's next one when it was
// decoded; a cut issues it to nothing - and whether the message is its
// request. Charge is the decoder's own charge: its kind, stage and bytes.
type DecodeCharge = decodeCharge

// ChargeEvent is what happened to one charge.
type ChargeEvent = chargeEvent

const (
	// ChargeReserving is a charge about to be asked of the allowance, nothing
	// of it held yet: an observer that takes what is left of the allowance
	// here makes the request a refusal, with no intake event between.
	ChargeReserving = chargeReserving
	// ChargeReserved is a charge the allowance granted, and ChargeRefused one
	// it refused.
	ChargeReserved = chargeReserved
	ChargeRefused  = chargeRefused
	// ChargeReturned is a held charge given back: a workspace or an output
	// buffer when the decoding is done with it, and the decoded content's when
	// its exchange is let go.
	ChargeReturned = chargeReturned
)

// ObserveDecodeCharges is options with observe told of every charge a decoding
// asks the shared allowance for and every one it gives back, in order, on the
// worker's goroutine: ChargeReserving before the allowance is asked, then
// ChargeReserved or ChargeRefused, and ChargeReturned when it comes back.
func ObserveDecodeCharges(options Options, observe func(DecodeCharge)) Options {
	options.decodeCharges = observe
	return options
}

// DecodeWith is options whose workers decode with decode in place of
// contentcoding.Decode: a test returns a result no input produces, such as a
// contained decoder fault (contentcoding.Result's Fault).
func DecodeWith(options Options, decode func(contentcoding.List, []byte, contentcoding.Options) contentcoding.Result) Options {
	options.decoder = decode
	return options
}
