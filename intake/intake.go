// Package intake holds capture records in bounded volatile storage. It does
// not parse payload, establish completeness, admit events, or authorize output.
//
// # The shared work allowance
//
// A Store's limit is one allowance for the whole session: every connection and
// every worker draws on the same one, and none is given an allowance of its
// own. It is charged in one unit, accounted bytes, by three owners:
//
//   - the intake itself, for each entry from its insertion until it is
//     released, at the unit Store states;
//   - Parsing, for what reading a connection retains;
//   - Policy, for the copies of exchanges the configuration's rules transform.
//
// What Parsing and Policy charge for each representation is stated where they
// are charged, in package processing. An insertion is refused when it does not
// fit beside every entry and every work charge (ErrLimit). A work charge is
// reserved before the representation it pays for is kept (Reserve), and given
// back once, when that representation stops being owned by the work that
// charged it (Return). A source and a copy of it are each charged while both
// exist, so giving back one gives back nothing of the other. A reservation that
// does not fit is refused, charging nothing, and counted against its owner; it
// never waits for room.
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
	// Parsing and Policy are the work charges those owners hold now, in
	// accounted bytes. The allowance left is LimitBytes - Bytes - Parsing -
	// Policy.
	Parsing int64
	Policy  int64
	// ParsingRefused and PolicyRefused count the reservations each owner was
	// refused because they did not fit. A reservation refused as invalid is not
	// counted.
	ParsingRefused int64
	PolicyRefused  int64
}

// Owner is who holds a work charge in the shared allowance, besides the
// intake's own entries.
type Owner uint8

const (
	// Parsing is what reading a connection retains: its reading state, what its
	// parsers and pairing keep, and exchanges they handed over that the worker
	// has not let go.
	Parsing Owner = iota + 1
	// Policy is the copies of exchanges the configuration's rules transform,
	// from before each is made until it is dropped.
	Policy
)

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
// An insertion that does not fit in what the limit has left beside every entry
// and every work charge (Reserve) is refused whole with ErrLimit.
// The refused record's loss token stops its connection outside this queue.
// Release makes capacity available again; Exhausted remains a diagnostic that
// at least one insertion was refused. There is no eviction, spill or parsing.
// Callers may store malformed or incomplete records for the worker to judge.
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
	// slot is the delivery gate's slot for the event the record came from,
	// returned when the entry is released.
	slot held.Slot
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
	left := s.left()
	budget := allowance{left: left}
	if !budget.add(1, unsafe.Sizeof(Entry{})+unsafe.Sizeof(record)) || !budget.add(len(record.Payload), 1) {
		s.stats.FragmentsRefused++
		record.Loss.Stop("intake_exhausted")
		return s.full()
	}
	record.Payload = copySlice(record.Payload)
	record.At = record.At.UTC()
	reserved := record.Slot
	record.Slot = nil
	s.append(&Entry{Fragment: &record, slot: kept(reserved)}, left-budget.left)
	s.stats.Fragments++
	return nil
}

// kept takes a stored record's slot into its entry, which returns it at
// Release.
func kept(reserved held.Slot) held.Slot {
	if reserved != nil {
		reserved.Keep()
	}
	return reserved
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
	left := s.left()
	budget := allowance{left: left}
	if !budget.connection(record) {
		s.stats.ConnectionsRefused++
		record.Loss.Stop("intake_exhausted")
		return s.full()
	}
	reserved := record.Slot
	record = copyConnection(record)
	record.Slot = nil
	s.append(&Entry{Connection: &record, slot: kept(reserved)}, left-budget.left)
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
	if e.released {
		s.mutex.Unlock()
		return
	}
	e.released = true
	e.Fragment = nil
	e.Connection = nil
	s.stats.Bytes -= e.bytes
	s.stats.Leased--
	reserved := e.slot
	e.slot = nil
	s.mutex.Unlock()
	// Returned outside the intake's lock: the gate takes its own.
	if reserved != nil {
		reserved.Refund(path)
	}
}

// Reserve charges n accounted bytes to owner, if they fit in what the limit
// has left beside every entry and every work charge, and reports whether it
// did. A refusal charges nothing and is counted against owner. It never waits.
// Close does not affect it: a closed store refuses input, and work it already
// holds may still grow while room is left. Zero is granted and charges
// nothing. A negative n, an owner other than Parsing or Policy, or a nil or
// zero Store is refused and not counted.
func (s *Store) Reserve(owner Owner, n int64) bool {
	if s == nil || (owner != Parsing && owner != Policy) || n < 0 {
		return false
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.exhausted == nil {
		return false
	}
	if n > s.left() {
		if owner == Parsing {
			s.stats.ParsingRefused++
		} else {
			s.stats.PolicyRefused++
		}
		return false
	}
	if owner == Parsing {
		s.stats.Parsing += n
	} else {
		s.stats.Policy += n
	}
	return true
}

// Return gives back n accounted bytes that owner reserved and no longer
// holds. Each charge is given back once; a balance below zero is the caller's
// defect, and Stats shows it rather than hiding it. A zero or negative n, an
// owner other than Parsing or Policy, or a nil Store does nothing.
func (s *Store) Return(owner Owner, n int64) {
	if s == nil || n <= 0 {
		return
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	switch owner {
	case Parsing:
		s.stats.Parsing -= n
	case Policy:
		s.stats.Policy -= n
	}
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
// return. It is diagnostic, not a request to stop capture.
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
	return nil
}

// left is what the limit has left beside every entry and every work charge,
// never below zero.
func (s *Store) left() int64 {
	return max(s.stats.LimitBytes-s.stats.Bytes-s.stats.Parsing-s.stats.Policy, 0)
}

func (s *Store) full() error {
	if !s.stats.Exhausted {
		s.stats.Exhausted = true
		close(s.exhausted)
	}
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
