package sink

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/evandukss/edge-observer/held"
)

type destination struct {
	sink     Sink
	boundary chan struct{}
	stats    Stats
	dirty    bool
}
type queued struct {
	destination *destination
	line        []byte
	discarded   bool
}

type queueState struct {
	mutex        sync.Mutex
	destinations map[string]*destination
	items        []*queued
	inflight     *queued
	stats        Stats
	closed       bool
	wake         chan struct{}
	changed      chan struct{}
}

func newQueue(limit int64) (*Queue, error) {
	if limit <= 0 {
		return nil, errors.New("sink queue requires positive byte bound")
	}
	q := &Queue{state: &queueState{destinations: map[string]*destination{}, stats: Stats{LimitBytes: limit}, wake: make(chan struct{}, 1), changed: make(chan struct{})}}
	go q.run()
	return q, nil
}
func (q *Queue) register(name string, s Sink) error {
	if q == nil || q.state == nil || s == nil || name == "" {
		return ErrClosed
	}
	st := q.state
	st.mutex.Lock()
	defer st.mutex.Unlock()
	if st.closed {
		return ErrClosed
	}
	if _, exists := st.destinations[name]; exists {
		return errors.New("duplicate sink destination")
	}
	st.destinations[name] = &destination{sink: s, boundary: make(chan struct{}, 1), stats: Stats{LimitBytes: st.stats.LimitBytes}}
	return nil
}
func (q *Queue) enqueue(name string, line []byte) error {
	if q == nil || q.state == nil {
		return ErrClosed
	}
	st := q.state
	st.mutex.Lock()
	defer st.mutex.Unlock()
	d := st.destinations[name]
	if d == nil {
		return errors.New("unknown sink destination")
	}
	if len(line) == 0 || line[len(line)-1] != '\n' {
		return errors.New("sink requires a complete line")
	}
	st.stats.Authorized++
	d.stats.Authorized++
	if st.closed {
		st.stats.Dropped++
		d.stats.Dropped++
		return ErrClosed
	}
	n := int64(len(line))
	if n > st.stats.LimitBytes-st.stats.PendingBytes {
		st.stats.Dropped++
		d.stats.Dropped++
		return ErrQueueFull
	}
	st.items = append(st.items, &queued{destination: d, line: line})
	for _, v := range []*Stats{&st.stats, &d.stats} {
		v.Pending++
		v.PendingBytes += n
		if v.PendingBytes > v.HighWaterBytes {
			v.HighWaterBytes = v.PendingBytes
		}
	}
	st.signal()
	select {
	case st.wake <- struct{}{}:
	default:
	}
	return nil
}
func (st *queueState) signal() { close(st.changed); st.changed = make(chan struct{}) }
func (q *Queue) run() {
	st := q.state
	for {
		st.mutex.Lock()
		if len(st.items) == 0 {
			closed := st.closed
			st.mutex.Unlock()
			if closed {
				return
			}
			<-st.wake
			continue
		}
		item := st.items[0]
		st.items[0] = nil
		st.items = st.items[1:]
		st.inflight = item
		st.mutex.Unlock()
		d := item.destination
		d.boundary <- struct{}{}
		n, err := 0, error(nil)
		if d.dirty {
			var repaired int
			repaired, err = d.sink.Write(context.Background(), []byte{'\n'})
			if err == nil && repaired != 1 {
				err = io.ErrShortWrite
			}
			if err == nil {
				d.dirty = false
			}
		}
		if err == nil {
			n, err = d.sink.Write(context.Background(), item.line)
		}
		if n < 0 || n > len(item.line) {
			n = 0
			err = io.ErrShortWrite
		}
		if n != len(item.line) && err == nil {
			err = io.ErrShortWrite
		}
		if n > 0 {
			d.dirty = item.line[n-1] != '\n'
		}
		<-d.boundary
		st.mutex.Lock()
		for _, v := range []*Stats{&st.stats, &d.stats} {
			v.PendingBytes -= int64(len(item.line))
			if !item.discarded {
				v.Pending--
				v.Bytes += int64(n)
				if err != nil {
					v.Failed++
				} else {
					v.Written++
				}
			}
		}
		st.inflight = nil
		st.signal()
		st.mutex.Unlock()
	}
}

// Retained is what this queue holds now: the lines queued and the one being
// written, and its destinations. The lines' bound is in bytes (Stats), not
// lines.
func (q *Queue) Retained() ([]held.Occupancy, error) {
	if q == nil || q.state == nil {
		return nil, nil
	}
	st := q.state
	st.mutex.Lock()
	defer st.mutex.Unlock()
	lines := len(st.items)
	if st.inflight != nil {
		lines++
	}
	return []held.Occupancy{
		{Store: "sink.lines", Held: lines},
		{Store: "sink.destinations", Held: len(st.destinations)},
	}, nil
}

func (q *Queue) stats(name string) Stats {
	if q == nil || q.state == nil {
		return Stats{}
	}
	st := q.state
	st.mutex.Lock()
	defer st.mutex.Unlock()
	if name == "" {
		return st.stats
	}
	if d := st.destinations[name]; d != nil {
		return d.stats
	}
	return Stats{}
}
func (q *Queue) drain(ctx context.Context) error {
	if q == nil || q.state == nil {
		return nil
	}
	st := q.state
	for {
		st.mutex.Lock()
		pending, changed := st.stats.Pending, st.changed
		st.mutex.Unlock()
		if pending == 0 {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
func (q *Queue) shutdown(ctx context.Context) error {
	if q == nil || q.state == nil {
		return nil
	}
	st := q.state
	st.mutex.Lock()
	st.closed = true
	st.mutex.Unlock()
	select {
	case st.wake <- struct{}{}:
	default:
	}
	err := q.drain(ctx)
	st.mutex.Lock()
	discard := func(item *queued, inflight bool) {
		if item.discarded {
			return
		}
		item.discarded = true
		for _, v := range []*Stats{&st.stats, &item.destination.stats} {
			v.Pending--
			v.Dropped++
			v.Discarded++
			if !inflight {
				v.PendingBytes -= int64(len(item.line))
			}
		}
	}
	for _, item := range st.items {
		discard(item, false)
	}
	st.items = nil
	if st.inflight != nil {
		discard(st.inflight, true)
	}
	ds := make([]*destination, 0, len(st.destinations))
	for _, d := range st.destinations {
		ds = append(ds, d)
	}
	st.signal()
	st.mutex.Unlock()
	for _, d := range ds {
		if e := atBoundary(ctx, d, func() error { return d.sink.Close(ctx) }); e != nil {
			err = errors.Join(err, e)
			go func() {
				d.boundary <- struct{}{}
				defer func() { <-d.boundary }()
				_ = d.sink.Close(context.Background())
			}()
		}
	}
	return err
}
func atBoundary(ctx context.Context, d *destination, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case d.boundary <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	// A destination may block inside an operating-system call. Keep ownership
	// of its boundary until it returns, even when the caller's deadline expires.
	done := make(chan error, 1)
	go func() { defer func() { <-d.boundary }(); done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (q *Queue) reopen(ctx context.Context) error {
	if q == nil || q.state == nil {
		return ErrClosed
	}
	st := q.state
	st.mutex.Lock()
	if st.closed {
		st.mutex.Unlock()
		return ErrClosed
	}
	ds := make([]*destination, 0, len(st.destinations))
	for _, d := range st.destinations {
		ds = append(ds, d)
	}
	st.mutex.Unlock()
	var errs []error
	for _, d := range ds {
		if err := atBoundary(ctx, d, func() error {
			err := d.sink.Reopen(ctx)
			if err == nil {
				d.dirty = false
			}
			return err
		}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
