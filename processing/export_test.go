package processing

import "github.com/evandukss/edge-observer/fragment"

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
type HeldConnection struct {
	Process    fragment.Process
	Connection fragment.ConnectionID
	Entries    int
	Pending    int
	Bytes      int64
	Parsing    int64
}

// Connections is every connection w holds input for, in the order it
// examines them. Its owner reads it, never while Drain or Finish runs.
func Connections(w *Worker) []HeldConnection {
	var out []HeldConnection
	for _, key := range w.order {
		if b := w.batches[key]; b != nil {
			one := HeldConnection{Process: key.process, Connection: key.id, Entries: b.entries(),
				Pending: b.pending(), Bytes: b.bytes()}
			if b.parse != nil {
				one.Parsing = b.parse.charged
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
