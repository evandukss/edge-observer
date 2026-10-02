// Package intake holds capture records in bounded volatile storage. It does
// not parse payload, establish completeness, admit events, or authorize output.
package intake

import (
	"errors"
	"strings"
	"sync"
	"unsafe"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/held"
)

var (
	ErrLimit         = errors.New("volatile intake storage limit reached")
	ErrClosed        = errors.New("volatile intake is closed")
	ErrUninitialized = errors.New("volatile intake is uninitialized")
)

// Stats counts storage, never admission or durable writes. Bytes includes
// queued and leased entries. Accepted counters are cumulative; Release does
// not refund those counters. Refused counts every callback that returns an
// error, separately for fragments and connection records.
type Stats struct {
	LimitBytes         int64
	Bytes              int64
	Queued             int64
	Leased             int64
	Fragments          int64
	Connections        int64
	FragmentsRefused   int64
	ConnectionsRefused int64
	Exhausted          bool
	Closed             bool
}

// Store is a FIFO shared by both capture sinks and one processing owner.
// Construct it with New; a zero value refuses work. Do not copy it.
//
// The limit's unit is accounted record bytes: the fixed entry and record
// structs (including slice/string headers), plus the lengths of payload,
// executable and reason strings, IP zone strings, and all nested record
// slices. Spare capacity in caller slices is neither retained nor charged.
// Time values are retained in UTC, without caller-owned location tables.
// This is a storage allowance, not a Go heap or process-memory limit:
// allocator overhead, runtime metadata and the caller's original are outside
// it. The process execution envelope separately bounds those costs.
//
// An insertion exceeding the shared limit is refused whole with ErrLimit.
// Exhaustion is permanent; subsequent writes fail even after Release. There
// is no eviction, spill, parsing, structural validation or gate operation.
// Callers may store malformed or incomplete records for the worker to judge.
// The controller consumes Exhausted to stop capture; pending entries are not
// evidence of complete input after a storage refusal.
type Store struct {
	mutex      sync.Mutex
	stats      Stats
	head, tail *Entry
	exhausted  chan struct{}
}

// Entry has exactly one non-nil record. Take transfers exclusive use of its
// data to the worker; storage remains charged until Release. Release is called
// only after every use of the record, including processing and writing, ends.
// The worker must not retain aliases after Release, copy Entry, or modify Entry itself.
// Queue order is callback arrival order, not proof of lifecycle completeness:
// a concurrent retirement can arrive before an outstanding fragment callback.
type Entry struct {
	Fragment   *fragment.Record
	Connection *connection.Record
	owner      *Store
	next       *Entry
	bytes      int64
	released   bool
}

// New requires a positive limitBytes. It has no filesystem effects.
func New(limitBytes int64) (*Store, error) {
	if limitBytes <= 0 {
		return nil, errors.New("volatile intake requires a positive byte limit")
	}
	return &Store{stats: Stats{LimitBytes: limitBytes}, exhausted: make(chan struct{})}, nil
}

// Write copies one fragment into volatile storage, under the shared bound.
// It retains no caller-owned payload backing array.
func (s *Store) Write(record fragment.Record) error {
	if s == nil {
		return ErrUninitialized
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err := s.ready(); err != nil {
		s.stats.FragmentsRefused++
		return err
	}
	budget := allowance{left: s.stats.LimitBytes - s.stats.Bytes}
	if !budget.add(1, unsafe.Sizeof(Entry{})+unsafe.Sizeof(record)) || !budget.add(len(record.Payload), 1) {
		s.stats.FragmentsRefused++
		return s.full()
	}
	record.Payload = copySlice(record.Payload)
	record.At = record.At.UTC()
	s.append(&Entry{Fragment: &record}, s.stats.LimitBytes-s.stats.Bytes-budget.left)
	s.stats.Fragments++
	return nil
}

// Connection copies one retirement record, including its nested slices and
// strings. It does bounded storage work even when capture holds its mutex.
func (s *Store) Connection(record connection.Record) error {
	if s == nil {
		return ErrUninitialized
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err := s.ready(); err != nil {
		s.stats.ConnectionsRefused++
		return err
	}
	budget := allowance{left: s.stats.LimitBytes - s.stats.Bytes}
	if !budget.connection(record) {
		s.stats.ConnectionsRefused++
		return s.full()
	}
	record = copyConnection(record)
	s.append(&Entry{Connection: &record}, s.stats.LimitBytes-s.stats.Bytes-budget.left)
	s.stats.Connections++
	return nil
}

// Take never waits for input. It returns nil when no queued entry is available.
// It does not inspect completeness or authorize the returned entry. A worker
// processes and writes only after Take returns, holding no intake lock.
func (s *Store) Take() *Entry {
	if s == nil {
		return nil
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	e := s.head
	if e == nil {
		return nil
	}
	s.head = e.next
	e.next = nil
	if s.head == nil {
		s.tail = nil
	}
	s.stats.Queued--
	s.stats.Leased++
	return e
}

// Bytes is the entry's charge: the accounted record bytes it holds until
// Release.
func (e *Entry) Bytes() int64 {
	if e == nil {
		return 0
	}
	return e.bytes
}

// Release discards the entry and returns its charge, as input given up
// unprocessed (ReleaseAs, held.Discarded).
func (e *Entry) Release() { e.ReleaseAs(held.Discarded) }

// ReleaseAs discards the entry and returns its charge, and the slot of the
// event it came from along path. It is idempotent and safe on nil. Only the
// single owner may access its data while it runs.
func (e *Entry) ReleaseAs(path held.Path) {
	if e == nil || e.owner == nil {
		return
	}
	s := e.owner
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if e.released {
		return
	}
	e.released = true
	e.Fragment = nil
	e.Connection = nil
	s.stats.Bytes -= e.bytes
	s.stats.Leased--
}

// Retained is the entries this store holds now: queued for a worker, and
// leased to one and not yet released. Its bound is in bytes (Stats), not
// entries.
func (s *Store) Retained() ([]held.Occupancy, error) {
	stats := s.Stats()
	return []held.Occupancy{{Store: "intake.entries", Held: int(stats.Queued + stats.Leased)}}, nil
}

func (s *Store) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.stats
}

// Exhausted closes on the first storage-limit refusal; nil and zero stores
// return an already-closed signal. No receiver is needed for a callback to
// return. This requests controller action, not release authorization.
func (s *Store) Exhausted() <-chan struct{} {
	if s == nil || s.exhausted == nil {
		return uninitialized
	}
	return s.exhausted
}

var uninitialized = func() <-chan struct{} {
	closed := make(chan struct{})
	close(closed)
	return closed
}()

// Close refuses future input and discards queued records. Leased records stay
// charged until their owner releases them. Close is idempotent.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.stats.Closed = true
	for e := s.head; e != nil; {
		next := e.next
		e.Fragment = nil
		e.Connection = nil
		e.next = nil
		e.released = true
		s.stats.Bytes -= e.bytes
		e = next
	}
	s.head, s.tail = nil, nil
	s.stats.Queued = 0
	return nil
}

// All helpers below run under the storage lock. They call no consumer; the
// only scans and copies are bounded by the remaining storage allowance.
func (s *Store) ready() error {
	if s.exhausted == nil {
		return ErrUninitialized
	}
	if s.stats.Closed {
		return ErrClosed
	}
	if s.stats.Exhausted {
		return ErrLimit
	}
	return nil
}

func (s *Store) full() error {
	s.stats.Exhausted = true
	close(s.exhausted)
	return ErrLimit
}

func (s *Store) append(e *Entry, bytes int64) {
	e.owner, e.bytes = s, bytes
	if s.tail == nil {
		s.head = e
	} else {
		s.tail.next = e
	}
	s.tail = e
	s.stats.Bytes += bytes
	s.stats.Queued++
}

type allowance struct{ left int64 }

// Division before multiplication prevents overflow even for caller-owned
// slices whose sizes exceed the store. No copy is allocated before this check.
func (a *allowance) add(count int, size uintptr) bool {
	if uint64(count) > uint64(a.left)/uint64(size) {
		return false
	}
	a.left -= int64(uint64(count) * uint64(size))
	return true
}

func (a *allowance) connection(r connection.Record) bool {
	if !a.add(1, unsafe.Sizeof(Entry{})+unsafe.Sizeof(r)) ||
		!a.add(len(r.Instance.Executable), 1) || !a.add(len(r.Fragments.Why), 1) ||
		!a.add(len(r.Associations), unsafe.Sizeof(connection.Association{})) ||
		!a.add(len(r.Placements), unsafe.Sizeof(connection.Placement{})) ||
		!a.add(len(r.Early), unsafe.Sizeof(connection.Early{})) {
		return false
	}
	for _, one := range r.Associations {
		if !a.add(len(one.Contended), unsafe.Sizeof(connection.Descriptor{})) ||
			!a.add(len(one.Endpoints.Local.IP.Zone()), 1) ||
			!a.add(len(one.Endpoints.Remote.IP.Zone()), 1) {
			return false
		}
	}
	for _, one := range r.Placements {
		if !a.add(len(one.Lost.Why), 1) {
			return false
		}
	}
	return true
}

func copySlice[T any](source []T) []T {
	if source == nil {
		return nil
	}
	out := make([]T, len(source))
	copy(out, source)
	return out
}

func copyConnection(r connection.Record) connection.Record {
	r.Instance.Executable = strings.Clone(r.Instance.Executable)
	r.Fragments.Why = strings.Clone(r.Fragments.Why)
	r.FirstSeen, r.Opened, r.Ended = r.FirstSeen.UTC(), r.Opened.UTC(), r.Ended.UTC()
	r.Associations = copySlice(r.Associations)
	for i := range r.Associations {
		one := &r.Associations[i]
		one.Contended = copySlice(one.Contended)
		one.Valid.From, one.Valid.Until = one.Valid.From.UTC(), one.Valid.Until.UTC()
		one.Endpoints.Local.IP = one.Endpoints.Local.IP.WithZone(strings.Clone(one.Endpoints.Local.IP.Zone()))
		one.Endpoints.Remote.IP = one.Endpoints.Remote.IP.WithZone(strings.Clone(one.Endpoints.Remote.IP.Zone()))
	}
	r.Placements = copySlice(r.Placements)
	for i := range r.Placements {
		r.Placements[i].Lost.Why = strings.Clone(r.Placements[i].Lost.Why)
	}
	r.Early = copySlice(r.Early)
	return r
}
