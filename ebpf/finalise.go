package ebpf

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"

	"github.com/evandukss/edge-observer/connection"
)

// The finalisation boundary's kernel half: withdrawing capture authority,
// draining what was left in flight, and reading the counters after the drain.
// Close takes the maps with it, so these give a moment that is neither live
// nor gone.

// StopProducing withdraws capture authority by emptying the allowlist. Every
// probe path already reads the allowlist before acting (entry, return, the
// connection-ending probe, the fork probe), so this stops production
// everywhere at once. A call already inside the library returns to find its
// admission gone: its payload is not read and it is counted as refused. It
// reports what it withdrew, read back from the map; entries left behind make
// an incomplete Withdrawal rather than an error, so finalisation continues and
// the seal says the run was still producing.
func (s *Session) StopProducing() (connection.Withdrawal, error) {
	withdrawal := connection.Withdrawal{At: time.Now()}

	allowed := s.collection.Maps["allowed_processes"]
	if allowed == nil {
		return withdrawal, fmt.Errorf("%w: the program has no allowlist map, so nothing here can "+
			"withdraw its authority to capture", ErrUnavailable)
	}

	// Two rounds, because the fork probe can admit a descendant between iteration
	// and delete. After the first no parent holds a grant, so anything left after
	// the second is reported, not retried.
	var last error
	for round := 0; round < 2; round++ {
		var key instanceKey
		var value admissionValue
		entries := allowed.Iterate()
		for entries.Next(&key, &value) {
			if err := allowed.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				last = err
				continue
			}
			withdrawal.Instances++
		}
		if err := entries.Err(); err != nil {
			last = err
		}
	}

	left, err := s.remaining(allowed)
	switch {
	case err != nil:
		withdrawal.Because = "the allowlist could not be read back, so whether authority was " +
			"withdrawn is not established: " + err.Error()
	case left > 0:
		withdrawal.Because = fmt.Sprintf("%d admissions are still in the allowlist, so the probes "+
			"are still producing", left)
	case last != nil:
		withdrawal.Because = "an allowlist entry would not delete: " + last.Error()
	default:
		withdrawal.Complete = true
	}
	return withdrawal, nil
}

// remaining is how many admissions the allowlist still holds.
func (s *Session) remaining(allowed *ebpf.Map) (int, error) {
	var (
		key   instanceKey
		value admissionValue
		count int
	)
	entries := allowed.Iterate()
	for entries.Next(&key, &value) {
		count++
	}
	if err := entries.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

// quiet is how long a read must find nothing before the ring buffer is taken to
// be empty (read only by the reading goroutine). The reader wakes on the
// buffer's own notification, so with production stopped this long means empty;
// long enough that a scheduler delay does not look empty.
const quiet = 50 * time.Millisecond

// Drain reads what production left in the ring buffer, up to within, and says
// what was still outstanding. It is meaningful only after StopProducing. A read
// finding nothing for quiet has emptied the buffer (outstanding zero); a drain
// that runs out of time while events still arrive leaves outstanding unknown,
// and every stream those events belonged to has lost a position.
func (s *Session) Drain(within time.Duration) (connection.Drained, error) {
	drained := connection.Drained{Delivered: connection.Counted(0)}
	if s.reader == nil {
		drained.Outstanding = connection.Uncounted("this session has no ring reader")
		drained.Because = "there is no ring buffer to drain"
		return drained, nil
	}
	if within <= 0 {
		drained.Outstanding = connection.Uncounted("the drain was given no time to run")
		drained.Because = fmt.Sprintf("a drain waits for a stated time, and %s is not one", within)
		return drained, nil
	}

	before := s.delivered.Load()
	// Signals already waiting predate this drain; clear them so the one awaited
	// comes from a read after production stopped.
	for empty := false; !empty; {
		select {
		case <-s.idle:
		default:
			empty = true
		}
	}

	waited := time.NewTimer(within)
	defer waited.Stop()

	select {
	case <-s.stopped:
		// The reader is gone, so no signal will come. A reader that failed held the
		// buffer and its contents are unreadable; one told to stop had emptied it.
		drained.Delivered = connection.Counted(s.delivered.Load() - before)
		failure := s.readerFailure()
		if failure == "" {
			drained.Outstanding = connection.Counted(0)
			drained.Complete = true
			return drained, nil
		}
		drained.Outstanding = connection.Uncounted(
			"the ring reader failed, so what it still held was never read: " + failure)
		drained.Because = failure
		return drained, nil
	case <-s.idle:
		drained.Delivered = connection.Counted(s.delivered.Load() - before)
		if failure := s.readerFailure(); failure != "" {
			drained.Outstanding = connection.Uncounted(
				"the ring reader failed, so what it still held was never read: " + failure)
			drained.Because = failure
			return drained, nil
		}
		drained.Outstanding = connection.Counted(0)
		drained.Complete = true
		return drained, nil
	case <-waited.C:
		drained.Delivered = connection.Counted(s.delivered.Load() - before)
		drained.Outstanding = connection.Uncounted(
			"the ring buffer was still delivering when the drain ran out of time, so what it " +
				"still held was never counted")
		drained.Because = fmt.Sprintf("the ring buffer had not emptied after %s", within)
		return drained, nil
	}
}

// Account is this session's counters, read after the drain. Reservation
// attempts, granted reservations and submitted events are not all counted by
// the program, and stages it cannot evaluate say so rather than report zero
// (package connection, Identity).
func (s *Session) Account() (connection.Counters, error) {
	counters := connection.Counters{
		Delivered:   connection.Counted(s.delivered.Load()),
		Undecodable: connection.Counted(s.undecodable.Load()),
	}
	counters.RefusedInFlight = counted(s.Refused())
	counters.StillExecuting = counted(s.Executing())
	counters.SocketsUnrecorded = counted(s.SocketsUnrecorded())
	counters.BindingsUnrecorded = counted(s.BindingsUnrecorded())
	counters.DenialsUnrecorded = counted(s.DenialsUnrecorded())
	counters.DeferredDiscarded = counted(s.DiscardedDeferred())

	counters.Ordered = counted(s.Attempts())
	counters.ReservationFailures = counted(s.Dropped())
	// A call refused at the read boundary took a place in the order and attempted
	// no reservation, so it comes off the attempts before grants are derived.
	counters.ReservationAttempts = subtract(counters.Ordered, counters.RefusedInFlight)
	// Granted and submitted are derived (every reservation taken is submitted),
	// and an unknown term makes the result unknown rather than invented.
	counters.Reservations = subtract(counters.ReservationAttempts, counters.ReservationFailures)
	counters.Submitted = counters.Reservations
	counters.UnmatchedReturns = counted(s.Unmatched())
	counters.UnmeasurableCalls = counted(s.Unmeasurable())

	switch failure := s.readerFailure(); {
	case failure != "":
		// The reader stopped before the buffer was empty: how much was lost is
		// unknown, not zero.
		counters.LostAfterSubmission = connection.Uncounted(
			"the ring reader failed during the run, so what it still held was never read: " + failure)
	case s.abandoned.Load() > 0:
		counters.LostAfterSubmission = connection.Counted(s.abandoned.Load())
	default:
		counters.LostAfterSubmission = connection.Counted(0)
	}
	return counters, nil
}

// subtract is one stage minus another, with an unknown term carrying through.
func subtract(from, take connection.Count) connection.Count {
	if !from.Known {
		return from
	}
	if !take.Known {
		return take
	}
	return connection.Counted(from.Value - take.Value)
}

// counted turns one counter read into a Count; an unreadable counter is
// reported as unreadable, not zero.
func counted(value int64, err error) connection.Count {
	if err != nil {
		return connection.Uncounted(err.Error())
	}
	return connection.Counted(value)
}
