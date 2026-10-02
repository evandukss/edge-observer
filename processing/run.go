package processing

import (
	"context"
	"slices"
	"sort"
	"sync"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/intake"
)

// Run is Options.Workers workers processing one intake. Its owner routes the
// intake's entries to them with Route; each worker owns the connections
// routed to it, keeps their order and processes them on its own goroutine.
// The intake's allowance, the release point, the gate and the output are one
// for all of them, and their outcomes are summed.
type Run struct {
	options    Options
	router     router
	release    *release
	extensions *extensions
	workers    []*running
	pending    [][]routed
	ctx        context.Context
	cancel     context.CancelFunc
	failed     chan struct{}
	stopped    sync.WaitGroup

	mutex    sync.Mutex
	outcomes []Outcome
	err      error
	ended    bool
	closed   bool
}

type running struct {
	worker *Worker
	queue  *queue
	end    chan ending
}

// ending is what a worker's goroutine does last: finish with these facts, or
// close.
type ending struct {
	ctx   context.Context
	final Finalization
	close bool
}

// routeChunk is how many entries Route gathers for one worker before handing
// them over, so a worker starts on a long backlog before all of it is routed.
const routeChunk = 256

// Start validates Options as New does and starts the workers, and the plan's
// extensions, each with its derived file created in Derived's directory. It
// performs no capture, parsing or approved write. A plan with extensions
// needs Session and Derived, and at most one reconstruction pipeline, which
// is the one extensions follow.
func Start(options Options) (*Run, error) {
	if !options.valid() {
		return nil, ErrOptions
	}
	if len(options.Plan.Extensions()) > 0 {
		reconstructions := 0
		for _, p := range options.Plan.Pipelines() {
			if p.Input == config.ReconstructionInput {
				reconstructions++
			}
		}
		if options.Session == "" || options.Derived == nil || reconstructions > 1 {
			return nil, ErrOptions
		}
	}
	n := max(options.Workers, 1)
	shared := &release{gate: options.Gate, output: options.Output}
	supervised, err := startExtensions(options, shared)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Run{options: options, release: shared, extensions: supervised, pending: make([][]routed, n),
		ctx: ctx, cancel: cancel, failed: make(chan struct{}), outcomes: make([]Outcome, n)}
	for i := range n {
		q := &queue{wake: make(chan struct{}, 1)}
		r.workers = append(r.workers, &running{worker: newWorker(options, i, q, r.release, supervised), queue: q, end: make(chan ending, 1)})
		r.outcomes[i] = Outcome{Withheld: connection.Counted(0)}
	}
	r.stopped.Add(n)
	for i := range r.workers {
		go r.serve(i)
	}
	return r, nil
}

// Route takes every entry queued in the intake and hands it to the worker
// that owns its connection. It never waits on a worker: a worker's queue
// holds leased intake entries, so the intake's one allowance bounds every
// queue together, and a full intake refuses capture's next record rather than
// holding any connection back. Route has one caller at a time, the intake's
// owner, and does nothing once the Run has finished or closed.
func (r *Run) Route() {
	if r == nil || r.over() {
		return
	}
	for e := r.options.Intake.Take(); e != nil; e = r.options.Intake.Take() {
		key := keyOf(e)
		i := route(key, len(r.workers))
		r.pending[i] = append(r.pending[i], routed{entry: e, first: r.router.first(uint64(key.id))})
		if len(r.pending[i]) == routeChunk {
			r.workers[i].queue.push(r.pending[i])
			r.pending[i] = r.pending[i][:0]
		}
	}
	for i, items := range r.pending {
		if len(items) != 0 {
			r.workers[i].queue.push(items)
			r.pending[i] = items[:0]
		}
	}
}

// Snapshot is the workers' last returned outcomes, summed, with the gate's
// reason where it has one. It never waits on a worker or on writer I/O.
func (r *Run) Snapshot() Outcome {
	r.mutex.Lock()
	o := r.sumLocked()
	r.mutex.Unlock()
	if reason := r.options.Gate.Snapshot().Reason; reason != "" {
		o.GateReason = reason
	}
	o.Extensions = r.extensions.counts()
	o = deliveryOutcome(o, r.options.Output)
	return o
}

// Failed closes when a worker stops on an error. Every worker stops with it:
// none authorizes or writes again, and Finish returns that first error.
func (r *Run) Failed() <-chan struct{} { return r.failed }

// Finish routes the final queue, then every worker finishes as Worker.Finish
// does, concurrently, and the Run ends. It returns the summed outcome and the
// first error any worker stopped on.
func (r *Run) Finish(ctx context.Context, final Finalization) (Outcome, error) {
	if r == nil {
		return Outcome{}, ErrFinished
	}
	if r.over() {
		return r.Snapshot(), ErrFinished
	}
	r.Route()
	r.mutex.Lock()
	r.ended = true
	r.mutex.Unlock()
	for _, one := range r.workers {
		one.end <- ending{ctx: ctx, final: final}
	}
	r.stopped.Wait()
	// Every batch is written; the extensions are ended in order, so their
	// last derived records are taken before the counts are read.
	r.extensions.end()
	r.cancel()
	r.mutex.Lock()
	o, err := r.sumLocked(), r.err
	r.mutex.Unlock()
	o.Extensions = r.extensions.counts()
	o = deliveryOutcome(o, r.options.Output)
	return o, err
}

// Close ends every worker without output, releasing what each holds. It does
// not close Intake or Output. It is idempotent and safe after Finish.
func (r *Run) Close() error {
	if r == nil {
		return nil
	}
	r.mutex.Lock()
	if r.closed {
		r.mutex.Unlock()
		return nil
	}
	ended := r.ended
	r.closed, r.ended = true, true
	r.mutex.Unlock()
	r.cancel()
	if !ended {
		for _, one := range r.workers {
			one.end <- ending{close: true}
		}
		r.stopped.Wait()
	}
	r.extensions.abort()
	return nil
}

func (r *Run) over() bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.ended
}

func (r *Run) serve(i int) {
	defer r.stopped.Done()
	one := r.workers[i]
	for {
		select {
		case <-one.queue.wake:
			o, err := one.worker.Drain(r.ctx)
			r.record(i, o, err)
		case end := <-one.end:
			if end.close {
				_ = one.worker.Close()
				one.queue.release()
				return
			}
			o, err := one.worker.Finish(end.ctx, end.final)
			r.record(i, o, err)
			return
		}
	}
}

func (r *Run) record(i int, o Outcome, err error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.outcomes[i] = o
	if err != nil && r.err == nil {
		r.err = err
		close(r.failed)
		r.cancel()
	}
}

func (r *Run) sumLocked() Outcome {
	total := Outcome{Withheld: connection.Counted(0)}
	for _, o := range r.outcomes {
		total = total.plus(o)
	}
	total.ExchangeIDs = r.release.issued.Load()
	total.Extensions = []account.ExtensionCounts{}
	return total
}

// route is the worker that owns a connection: a hash of the whole batch key,
// process and connection id, so every entry of a connection reaches one
// worker and connections spread over all of them.
func route(key batchKey, workers int) int {
	if workers == 1 {
		return 0
	}
	h := mix(uint64(key.id))
	h = mix(h ^ uint64(uint32(key.process.PID)))
	h = mix(h ^ key.process.StartTime)
	return int(h % uint64(workers))
}

// mix is the splitmix64 finalizer.
func mix(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// routed is an entry and whether it is the first routed for its connection id.
type routed struct {
	entry *intake.Entry
	first bool
}

// source is where a worker takes its entries from.
type source interface {
	take() (routed, bool)
}

// direct is one worker taking straight from the intake, routing for itself.
type direct struct {
	intake *intake.Store
	router router
}

func (d *direct) take() (routed, bool) {
	e := d.intake.Take()
	if e == nil {
		return routed{}, false
	}
	return routed{entry: e, first: d.router.first(uint64(keyOf(e).id))}, true
}

// queue is one worker's entries, in the order they were routed, and the
// extensions' results for its batches. It has no bound of its own: every
// entry in it is leased from the intake, and a result exists only for a call
// an extension admitted.
type queue struct {
	mutex sync.Mutex
	items []routed
	done  []completion
	wake  chan struct{}
}

// complete hands an extension's result to the worker and wakes it. It never
// waits on the worker.
func (q *queue) complete(c completion) {
	q.mutex.Lock()
	q.done = append(q.done, c)
	q.mutex.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *queue) completions() []completion {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	done := q.done
	q.done = nil
	return done
}

func (q *queue) push(items []routed) {
	q.mutex.Lock()
	q.items = append(q.items, items...)
	q.mutex.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *queue) take() (routed, bool) {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	if len(q.items) == 0 {
		return routed{}, false
	}
	r := q.items[0]
	q.items[0] = routed{}
	q.items = q.items[1:]
	if len(q.items) == 0 {
		q.items = nil
	}
	return r, true
}

func (q *queue) release() {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	for _, r := range q.items {
		r.entry.Release()
	}
	q.items = nil
}

// router records which connection ids have been routed, to tell a
// connection's first entry from a late one: an entry for an id routed before
// whose batch is no longer held is late. Capture numbers a session's
// connections from one counter, so ids arrive nearly in order. The record is
// the highest id routed and the spans of ids below it not yet routed, so a
// completed connection is never forgotten and the record stays as small as
// the ids still in flight, however many connections complete.
//
// Where ids skip, the spans accumulate. Past unroutedBound the lowest span is
// taken as routed, so a first entry that arrives there later is late too:
// released at once and counted, never held until the session finishes.
type router struct {
	any  bool
	top  uint64
	gaps []span
}

// span is the ids from through to, inclusive.
type span struct{ from, to uint64 }

const unroutedBound = 1024

// first records id as routed and reports whether it had not been before.
func (r *router) first(id uint64) bool {
	switch {
	case !r.any:
		r.any, r.top = true, id
		if id > 0 {
			r.gaps = append(r.gaps, span{0, id - 1})
		}
	case id > r.top:
		if id > r.top+1 {
			r.gaps = append(r.gaps, span{r.top + 1, id - 1})
		}
		r.top = id
	default:
		i := sort.Search(len(r.gaps), func(i int) bool { return r.gaps[i].to >= id })
		if i == len(r.gaps) || r.gaps[i].from > id {
			return false
		}
		switch g := r.gaps[i]; {
		case g.from == id && g.to == id:
			r.gaps = slices.Delete(r.gaps, i, i+1)
		case g.from == id:
			r.gaps[i].from++
		case g.to == id:
			r.gaps[i].to--
		default:
			r.gaps[i].to = id - 1
			r.gaps = slices.Insert(r.gaps, i+1, span{id + 1, g.to})
		}
	}
	if over := len(r.gaps) - unroutedBound; over > 0 {
		r.gaps = slices.Delete(r.gaps, 0, over)
	}
	return true
}
