package extension

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/evandukss/edge-observer/held"
)

// Config is one extension as a Supervisor runs it.
type Config struct {
	Name string
	// Command is the argument vector; its first element is an absolute path.
	Command []string
	// Fields are the fields the entry selects, in the protocol's order.
	Fields       []string
	TimeoutMS    int64
	Session      string
	Revision     string
	WriteContent bool
	// WaitingBytes is the charge in the observer's shared allowance that the
	// connections waiting on this extension may hold together, each as its
	// Call.Bytes (WaitingBytes).
	WaitingBytes int64
	Clock        Clock
	// Events receives every Event; nil discards them.
	Events func(Event)
	// Issued is how many exchange ids the session has issued so far, so a
	// derived record's source is valid when it is at most this.
	Issued func() uint64
	// Derived enqueues one stamped line, including LF. It returns an empty
	// string on acceptance or a refusal reason such as DerivedQueueFull or
	// DerivedStopped. Acceptance is not evidence of sink completion.
	Derived func(line []byte) string
}

// Call is one exchange sent to an extension.
type Call struct {
	ID uint64
	// Bytes is its connection's charge in the observer's shared allowance when
	// the call is made: its captured input, what its reading keeps and the
	// copies of its exchanges, all of which it holds while it waits. It is
	// what the call is admitted at against WaitingBytes, never the message's
	// length.
	Bytes int64
	// Message is the exchange message, one JSON object and its line feed.
	Message []byte
	// Done receives the call's one result, on a goroutine of the supervisor's,
	// and must not block.
	Done func(Result)
}

// Result is an extension's answer for one exchange, or the failure that stood
// for one. Outcome is Unchanged, Changed or Failed; with Failed, Reason is the
// protocol's reason; with Changed, Changes holds each replaced field's
// replacement, not yet checked against the exchange.
type Result struct {
	Outcome string
	Reason  string
	Changes map[string]json.RawMessage
}

// Counts is what a Supervisor counts about the extension's processes and
// derived records. Exchange outcomes are counted by whoever submits them.
type Counts struct {
	RetiredBy        map[string]uint64
	Restarts         uint64
	StateResets      uint64
	Late             uint64
	Duplicate        uint64
	DerivedWritten   uint64
	DerivedBytes     uint64
	DerivedRefused   uint64
	DerivedRefusedBy map[string]uint64
	StderrDropped    uint64
}

// RetirementCauses and DerivedRefusals are the vocabularies Counts is kept by.
var (
	RetirementCauses = []string{StartFailed, StartupTimeout, Timeout, Crash, ProtocolError, OversizedFrame, UnknownID, Flood}
	DerivedRefusals  = []string{DerivedMalformed, DerivedUnknownSource, DerivedRate, DerivedQueueFull,
		DerivedStopped, DerivedWriteFailed}
)

// Supervisor runs one extension for one session: one generation at a time,
// started again after a retirement, until End or Close. Its methods are safe
// for concurrent use. It never blocks a caller on the extension: Submit and
// ConnectionDone queue and return, and every wait is the supervisor's own.
type Supervisor struct {
	config Config
	clock  Clock

	mutex   sync.Mutex
	changed *sync.Cond
	// after is what to run once the mutex is released: callbacks and events,
	// which never run under it.
	after []func()

	current *generation
	number  uint64
	ready   bool // some generation has answered ready
	backoff time.Duration
	restart time.Time // when the next generation starts; zero for none
	// spawning is a generation being started outside the mutex.
	spawning bool
	ending   bool
	closed   bool
	counts   Counts

	derived       [][]byte
	derivedBytes  int64
	derivedActive bool

	// logRate is what the log takes of standard error lines and failed
	// results' reasons together.
	logRate bucket

	rearm     chan struct{}
	quit      chan struct{}
	abort     chan struct{}
	loopDone  chan struct{}
	teardowns sync.WaitGroup
	workers   sync.WaitGroup
}

// Start runs the extension's first generation.
func Start(c Config) *Supervisor {
	if c.Clock == nil {
		c.Clock = System()
	}
	s := &Supervisor{config: c, clock: c.Clock, backoff: BackoffMin, rearm: make(chan struct{}, 1),
		quit: make(chan struct{}), abort: make(chan struct{}), loopDone: make(chan struct{})}
	s.changed = sync.NewCond(&s.mutex)
	s.counts.RetiredBy = zeroes(RetirementCauses)
	s.counts.DerivedRefusedBy = zeroes(DerivedRefusals)
	now := s.clock.Now()
	s.logRate = newBucket(StderrLinesPerSecond, now)
	s.restart = now
	s.workers.Add(1)
	go s.writeDerived()
	go s.loop()
	return s
}

func zeroes(vocabulary []string) map[string]uint64 {
	counts := make(map[string]uint64, len(vocabulary))
	for _, key := range vocabulary {
		counts[key] = 0
	}
	return counts
}

// unlock releases the mutex and then runs what was deferred under it.
func (s *Supervisor) unlock() {
	after := s.after
	s.after = nil
	s.mutex.Unlock()
	for _, f := range after {
		f()
	}
}

func (s *Supervisor) event(e Event) {
	if s.config.Events == nil {
		return
	}
	e.Extension = s.config.Name
	s.after = append(s.after, func() { s.config.Events(e) })
}

func (s *Supervisor) wake() {
	select {
	case s.rearm <- struct{}{}:
	default:
	}
	s.changed.Broadcast()
}

// Submit sends one exchange to the ready generation and returns "", or
// returns at once the reason it skips the extension: Unavailable where no
// generation is ready, TooLarge where its message is over the frame bound,
// Busy where the in-flight or waiting-byte bound is full. An admitted call's
// deadline starts now, before it is queued or written.
func (s *Supervisor) Submit(c Call) string {
	s.mutex.Lock()
	defer s.unlock()
	g := s.current
	switch {
	case g == nil || g.state != ready || s.ending:
		return Unavailable
	case len(c.Message) > FrameBytesToExtension:
		return TooLarge
	case len(g.outstanding) >= InFlight || g.waiting+c.Bytes > s.config.WaitingBytes:
		return Busy
	}
	g.outstanding[c.ID] = &pending{call: c, deadline: s.clock.Now().Add(s.timeout())}
	g.waiting += c.Bytes
	g.send(outgoing{line: c.Message})
	s.wake()
	return ""
}

// ConnectionDone sends a connection_done message to the ready generation,
// and drops it where none is ready.
func (s *Supervisor) ConnectionDone(message []byte) {
	s.mutex.Lock()
	defer s.unlock()
	if g := s.current; g != nil && g.state == ready && !s.ending {
		g.send(outgoing{line: message})
	}
}

// End stops the extension in order: session_ending to a ready generation,
// shutdown once nothing is outstanding, then the termination grace before
// SIGTERM and again before SIGKILL. It starts no generation after, and
// returns once every process of the extension's is gone and every derived
// record it wrote is written or refused. Every wait is bounded by the
// extension's deadlines and the grace.
func (s *Supervisor) End() {
	s.mutex.Lock()
	if s.ending {
		s.unlock()
		s.wait()
		return
	}
	s.ending = true
	s.restart = time.Time{}
	if g := s.current; g != nil {
		switch g.state {
		case ready:
			g.send(outgoing{line: []byte(`{"type":"session_ending"}` + "\n")})
		case starting:
			s.stopLocked(g)
		}
	}
	s.wake()
	s.unlock()
	s.wait()
}

// wait returns once no generation runs and every derived record is settled.
func (s *Supervisor) wait() {
	s.mutex.Lock()
	for s.current != nil || s.spawning {
		s.changed.Wait()
	}
	s.mutex.Unlock()
	s.teardowns.Wait()
	s.mutex.Lock()
	for len(s.derived) > 0 || s.derivedActive {
		s.changed.Wait()
	}
	s.mutex.Unlock()
	s.finish()
}

func (s *Supervisor) finish() {
	s.mutex.Lock()
	select {
	case <-s.quit:
	default:
		close(s.quit)
	}
	s.changed.Broadcast()
	s.mutex.Unlock()
	<-s.loopDone
	s.workers.Wait()
}

// Close ends the extension at once, with SIGKILL to every generation's
// process group, and returns once they are reaped. Derived records not yet
// written are dropped. It is safe after End.
func (s *Supervisor) Close() {
	s.mutex.Lock()
	if !s.closed {
		s.closed = true
		s.ending = true
		s.restart = time.Time{}
		close(s.abort)
		if g := s.current; g != nil {
			s.stopLocked(g)
		}
		s.derived, s.derivedBytes = nil, 0
		s.wake()
	}
	s.unlock()
	s.mutex.Lock()
	for s.current != nil || s.spawning {
		s.changed.Wait()
	}
	s.mutex.Unlock()
	s.teardowns.Wait()
	s.finish()
}

// Retained is what this supervisor holds now, store by store: the calls its
// current generation has outstanding and the messages queued for it, the
// spans of ids it has answered, the derived lines waiting to be written, and
// the callbacks waiting for the mutex to be released.
func (s *Supervisor) Retained() ([]held.Occupancy, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	outstanding, queued, answered, rebuilds := 0, 0, 0, 0
	if g := s.current; g != nil {
		outstanding, queued, answered = len(g.outstanding), len(g.queue), len(g.answered.spans)
		rebuilds = g.churn.Rebuilds()
	}
	return []held.Occupancy{
		{Store: "extension.outstanding", Held: outstanding, Rebuilds: rebuilds},
		{Store: "extension.queue", Held: queued},
		{Store: "extension.answered", Held: answered, Bound: spanBound},
		{Store: "extension.derived", Held: len(s.derived)},
		{Store: "extension.after", Held: len(s.after)},
	}, nil
}

// Counts is the supervisor's counts now.
func (s *Supervisor) Counts() Counts {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	c := s.counts
	c.RetiredBy = maps.Clone(c.RetiredBy)
	c.DerivedRefusedBy = maps.Clone(c.DerivedRefusedBy)
	return c
}

func (s *Supervisor) timeout() time.Duration {
	return time.Duration(s.config.TimeoutMS) * time.Millisecond
}

// loop owns every deadline: it sleeps on the Clock until the earliest is due
// or the state changes, then acts on what is due.
func (s *Supervisor) loop() {
	defer close(s.loopDone)
	for {
		s.mutex.Lock()
		due := s.dueLocked()
		s.mutex.Unlock()
		var timer Timer
		var fire <-chan time.Time
		if !due.IsZero() {
			timer = s.clock.NewTimer(due.Sub(s.clock.Now()))
			fire = timer.C()
		}
		select {
		case <-fire:
		case <-s.rearm:
		case <-s.quit:
			if timer != nil {
				timer.Stop()
			}
			return
		}
		if timer != nil {
			timer.Stop()
		}
		s.mutex.Lock()
		start := s.tickLocked(s.clock.Now())
		s.unlock()
		if start {
			s.startGeneration()
		}
	}
}

func (s *Supervisor) dueLocked() time.Time {
	var due time.Time
	earliest := func(t time.Time) {
		if !t.IsZero() && (due.IsZero() || t.Before(due)) {
			due = t
		}
	}
	if s.current == nil && !s.spawning {
		earliest(s.restart)
	}
	if g := s.current; g != nil {
		if g.state == starting && !g.startWritten.IsZero() {
			earliest(g.startWritten.Add(StartupBound))
		}
		if !g.writingSince.IsZero() {
			earliest(g.writingSince.Add(s.timeout()))
		}
		for _, p := range g.outstanding {
			earliest(p.deadline)
		}
	}
	return due
}

// tickLocked acts on what is due at now, and reports whether a generation is
// to be started.
func (s *Supervisor) tickLocked(now time.Time) bool {
	if g := s.current; g != nil {
		switch {
		case g.state == starting && !g.startWritten.IsZero() && !now.Before(g.startWritten.Add(StartupBound)):
			s.retireLocked(g, StartupTimeout)
		case !g.writingSince.IsZero() && !now.Before(g.writingSince.Add(s.timeout())):
			s.retireLocked(g, Timeout)
		default:
			for _, p := range g.outstanding {
				if !now.Before(p.deadline) {
					s.retireLocked(g, Timeout)
					break
				}
			}
		}
	}
	if g := s.current; g != nil && g.state == ready && s.ending && len(g.outstanding) == 0 {
		s.stopLocked(g)
	}
	if s.current == nil && !s.spawning && !s.ending && !s.restart.IsZero() && !now.Before(s.restart) {
		s.restart = time.Time{}
		s.spawning = true
		return true
	}
	return false
}

// retireLocked retires g under cause: every exchange it has outstanding fails
// under the cause, it is stopped with SIGTERM to its group and SIGKILL after
// the grace, and the next generation is due after the backoff.
func (s *Supervisor) retireLocked(g *generation, cause string) {
	if g.state == retiring || g.state == stopping {
		return
	}
	now := s.clock.Now()
	g.state = retiring
	s.counts.RetiredBy[cause]++
	s.failOutstandingLocked(g, cause)
	if !g.readyAt.IsZero() && now.Sub(g.readyAt) >= HealthyInterval {
		s.backoff = BackoffMin
	}
	wait := time.Duration(0)
	if !s.ending {
		wait = s.backoff
		s.restart = now.Add(wait)
		s.backoff = min(2*s.backoff, BackoffMax)
	}
	s.event(Event{Generation: g.number, Kind: Retired, At: now, PID: g.pid, Cause: cause, Backoff: wait})
	s.detachLocked(g, false)
}

// stopLocked stops g in order, counting no retirement. A ready generation is
// sent shutdown first; one that is not ready has its input closed.
func (s *Supervisor) stopLocked(g *generation) {
	if g.state == retiring || g.state == stopping {
		return
	}
	wasReady := g.state == ready
	g.state = stopping
	s.failOutstandingLocked(g, Timeout)
	if wasReady && !s.closed {
		g.send(outgoing{line: []byte(`{"type":"shutdown"}` + "\n")})
	}
	s.detachLocked(g, !s.closed)
}

func (s *Supervisor) failOutstandingLocked(g *generation, reason string) {
	ids := slices.Sorted(maps.Keys(g.outstanding))
	for _, id := range ids {
		p := g.outstanding[id]
		done := p.call.Done
		s.after = append(s.after, func() { done(Result{Outcome: Failed, Reason: reason}) })
	}
	clear(g.outstanding)
	g.waiting = 0
}

// detachLocked makes g no longer the current generation and starts its
// teardown. Orderly, its pending output is written and its input closed
// before the grace starts; otherwise what was queued is dropped.
func (s *Supervisor) detachLocked(g *generation, orderly bool) {
	if s.current == g {
		s.current = nil
	}
	g.closing = true
	if !orderly {
		g.queue = nil
		g.interrupt = true
		// A write blocked on a pipe the extension stopped reading returns
		// once its descriptor is closed.
		if stdin := g.stdin; stdin != nil {
			s.after = append(s.after, func() { _ = stdin.Close() })
		}
	}
	g.wrote.Broadcast()
	s.teardowns.Add(1)
	go g.terminate(orderly)
	s.wake()
}

// exited is g's process having exited: a crash unless g was already being
// stopped.
func (s *Supervisor) exited(g *generation) {
	s.mutex.Lock()
	defer s.unlock()
	if g.state == starting || g.state == ready {
		s.retireLocked(g, Crash)
	}
}

// pending is one admitted exchange.
type pending struct {
	call     Call
	deadline time.Time
}

// readLine reads one line of at most limit bytes, line feed included, and
// returns it without the line feed. errOversized is a line that reached limit
// bytes with no line feed.
func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > limit || (len(line) == limit && line[len(line)-1] != '\n') {
			return nil, errOversized
		}
		switch {
		case err == nil:
			return line[:len(line)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			if len(line) > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
}

var errOversized = errors.New("a line over the frame bound")

// incoming is any message an extension writes.
type incoming struct {
	Type     *string         `json:"type"`
	Protocol json.RawMessage `json:"protocol"`
	ID       json.RawMessage `json:"id"`
	Outcome  json.RawMessage `json:"outcome"`
	Changes  json.RawMessage `json:"changes"`
	Reason   json.RawMessage `json:"reason"`
	Sources  json.RawMessage `json:"sources"`
	Basis    json.RawMessage `json:"basis"`
	Record   json.RawMessage `json:"record"`
}

// handle acts on one line g wrote.
func (s *Supervisor) handle(g *generation, line []byte) {
	var m incoming
	valid := utf8.Valid(line) && len(line) > 0 && line[0] == '{' && json.Unmarshal(line, &m) == nil && m.Type != nil
	s.mutex.Lock()
	defer s.unlock()
	live := g.state == starting || g.state == ready
	if !valid {
		if live {
			s.retireLocked(g, ProtocolError)
		}
		return
	}
	switch *m.Type {
	case "ready":
		var version string
		if !live {
			return
		}
		if json.Unmarshal(m.Protocol, &version) != nil || version != Protocol || g.state != starting {
			s.retireLocked(g, ProtocolError)
			return
		}
		g.state = ready
		g.readyAt = s.clock.Now()
		if s.ready {
			s.counts.StateResets++
		}
		s.ready = true
		s.event(Event{Generation: g.number, Kind: Ready, At: g.readyAt, PID: g.pid})
		s.wake()
	case "result":
		s.resultLocked(g, m)
	case "derived":
		s.derivedLocked(g, m, line)
	default:
		if live {
			s.retireLocked(g, ProtocolError)
		}
	}
}

func (s *Supervisor) resultLocked(g *generation, m incoming) {
	var text string
	id, err := uint64(0), json.Unmarshal(m.ID, &text)
	if err == nil {
		id, err = parseID(text)
	}
	if g.state == retiring || g.state == stopping {
		s.counts.Late++
		return
	}
	if err != nil {
		s.retireLocked(g, ProtocolError)
		return
	}
	p, outstanding := g.outstanding[id]
	switch {
	case outstanding:
	case g.answered.contains(id):
		s.counts.Duplicate++
		return
	default:
		s.retireLocked(g, UnknownID)
		return
	}
	g.outstanding = held.Deleted(g.outstanding, id, &g.churn)
	g.waiting -= p.call.Bytes
	g.answered.add(id)
	result := s.answerOf(g, m)
	done := p.call.Done
	s.after = append(s.after, func() { done(result) })
	s.wake()
}

// answerOf checks an answer's shape: one of the three outcomes, a changed one
// with an object of changes, a failed one with a reason.
func (s *Supervisor) answerOf(g *generation, m incoming) Result {
	var outcome string
	if json.Unmarshal(m.Outcome, &outcome) != nil {
		return Result{Outcome: Failed, Reason: Malformed}
	}
	switch outcome {
	case Unchanged:
		return Result{Outcome: Unchanged}
	case Changed:
		var changes map[string]json.RawMessage
		if len(m.Changes) == 0 || m.Changes[0] != '{' || json.Unmarshal(m.Changes, &changes) != nil || len(changes) == 0 {
			return Result{Outcome: Failed, Reason: Malformed}
		}
		return Result{Outcome: Changed, Changes: changes}
	case Failed:
		var reason string
		if json.Unmarshal(m.Reason, &reason) != nil {
			return Result{Outcome: Failed, Reason: Malformed}
		}
		if s.logRate.take(s.clock.Now()) {
			text, cut := escaped(reason, ReasonBytes)
			s.event(Event{Generation: g.number, Kind: Reason, At: s.clock.Now(), Line: text, Cut: cut})
		}
		return Result{Outcome: Failed, Reason: Declined}
	}
	return Result{Outcome: Failed, Reason: Malformed}
}

// parseID reads a positive decimal id with no sign and no leading zero.
func parseID(text string) (uint64, error) {
	if text == "" || text[0] == '0' {
		return 0, errors.New("not a positive decimal id")
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return 0, errors.New("not a positive decimal id")
		}
	}
	return strconv.ParseUint(text, 10, 64)
}

// escaped is text cut at limit bytes, then escaped to printable ASCII, and
// whether it was cut.
func escaped(text string, limit int) (string, bool) {
	cut := len(text) > limit
	if cut {
		text = text[:limit]
	}
	quoted := strconv.QuoteToASCII(text)
	return quoted[1 : len(quoted)-1], cut
}

// derivedLocked checks a derived record, stamps it and queues it, or refuses
// it under its reason.
func (s *Supervisor) derivedLocked(g *generation, m incoming, line []byte) {
	refuse := func(reason string) {
		s.counts.DerivedRefused++
		s.counts.DerivedRefusedBy[reason]++
	}
	if g.readyAt.IsZero() {
		refuse(DerivedMalformed)
		return
	}
	var sources []string
	var basis string
	if json.Unmarshal(m.Sources, &sources) != nil || len(sources) == 0 || len(sources) > DerivedSources ||
		json.Unmarshal(m.Basis, &basis) != nil || (basis != "observed" && basis != "inferred") ||
		len(m.Record) == 0 || m.Record[0] != '{' {
		refuse(DerivedMalformed)
		return
	}
	issued := s.config.Issued()
	for _, source := range sources {
		id, err := parseID(source)
		if err != nil {
			refuse(DerivedMalformed)
			return
		}
		if id > issued {
			refuse(DerivedUnknownSource)
			return
		}
	}
	now := s.clock.Now()
	if !g.derivedRate.take(now) {
		refuse(DerivedRate)
		switch second := now.Unix(); second {
		case g.floodSecond:
		case g.floodSecond + 1:
			g.floodRun++
		default:
			g.floodRun = 1
		}
		g.floodSecond = now.Unix()
		if g.floodRun >= DerivedFloodSeconds && (g.state == starting || g.state == ready) {
			s.retireLocked(g, Flood)
		}
		return
	}
	stamped, err := json.Marshal(derivedLine{Version: DerivedVersion, Extension: s.config.Name,
		Session: s.config.Session, Generation: strconv.FormatUint(g.number, 10), Revision: s.config.Revision,
		Effects: Effects, Sources: sources, Basis: basis, Record: m.Record})
	if err != nil {
		refuse(DerivedMalformed)
		return
	}
	stamped = append(stamped, '\n')
	if s.derivedBytes+int64(len(stamped)) > DerivedQueueBytes {
		refuse(DerivedQueueFull)
		return
	}
	s.derived = append(s.derived, stamped)
	s.derivedBytes += int64(len(stamped))
	s.changed.Broadcast()
}

// derivedLine is one line of an extension's derived file.
type derivedLine struct {
	Version    string          `json:"version"`
	Extension  string          `json:"extension"`
	Session    string          `json:"session"`
	Generation string          `json:"generation"`
	Revision   string          `json:"processing_revision"`
	Effects    string          `json:"effects"`
	Sources    []string        `json:"sources"`
	Basis      string          `json:"basis"`
	Record     json.RawMessage `json:"record"`
}

// writeDerived writes queued derived records, one at a time, outside the
// mutex, so reading the extension never waits behind it.
func (s *Supervisor) writeDerived() {
	defer s.workers.Done()
	for {
		s.mutex.Lock()
		for len(s.derived) == 0 {
			select {
			case <-s.quit:
				s.mutex.Unlock()
				return
			default:
			}
			s.changed.Wait()
		}
		line := s.derived[0]
		s.derived[0] = nil
		s.derived = s.derived[1:]
		s.derivedBytes -= int64(len(line))
		s.derivedActive = true
		s.mutex.Unlock()
		reason := s.config.Derived(line)
		s.mutex.Lock()
		s.derivedActive = false
		if reason == "" {
			s.counts.DerivedWritten++
			s.counts.DerivedBytes += uint64(len(line))
		} else {
			s.counts.DerivedRefused++
			s.counts.DerivedRefusedBy[reason]++
		}
		s.changed.Broadcast()
		s.mutex.Unlock()
	}
}

// bucket admits rate events a second, holding one second's worth.
type bucket struct {
	rate   float64
	tokens float64
	last   time.Time
}

func newBucket(rate int, now time.Time) bucket {
	return bucket{rate: float64(rate), tokens: float64(rate), last: now}
}

func (b *bucket) take(now time.Time) bool {
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(b.rate, b.tokens+b.rate*elapsed.Seconds())
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// idSet is the ids a generation answered, as spans. Past spanBound the
// lowest spans are folded into floor, every id at or below which is taken as
// answered: an answer to an id that old is counted a duplicate, never taken
// as an unknown id that retires the generation.
type idSet struct {
	spans []span
	floor uint64
}

type span struct{ from, to uint64 }

const spanBound = 4096

func (set *idSet) contains(id uint64) bool {
	if id <= set.floor {
		return true
	}
	i, found := slices.BinarySearchFunc(set.spans, id, func(s span, id uint64) int {
		switch {
		case s.to < id:
			return -1
		case s.from > id:
			return 1
		}
		return 0
	})
	return found && i < len(set.spans)
}

func (set *idSet) add(id uint64) {
	i, found := slices.BinarySearchFunc(set.spans, id, func(s span, id uint64) int {
		switch {
		case s.to < id:
			return -1
		case s.from > id:
			return 1
		}
		return 0
	})
	if found {
		return
	}
	joinsBelow := i > 0 && set.spans[i-1].to+1 == id
	joinsAbove := i < len(set.spans) && set.spans[i].from == id+1
	switch {
	case joinsBelow && joinsAbove:
		set.spans[i-1].to = set.spans[i].to
		set.spans = slices.Delete(set.spans, i, i+1)
	case joinsBelow:
		set.spans[i-1].to = id
	case joinsAbove:
		set.spans[i].from = id
	default:
		set.spans = slices.Insert(set.spans, i, span{id, id})
	}
	if over := len(set.spans) - spanBound; over > 0 {
		set.floor = max(set.floor, set.spans[over-1].to)
		set.spans = slices.Delete(set.spans, 0, over)
	}
}
