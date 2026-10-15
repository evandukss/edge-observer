package attachment

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/evandukss/edge-observer/connection"
)

type withdrawal = connection.Withdrawal
type drained = connection.Drained

var _ Lifecycle = (*Group)(nil)

func (g *Group) StopProducing() (connection.Withdrawal, error) {
	return g.StopProducingContext(context.Background())
}

func (g *Group) StopProducingContext(ctx context.Context) (connection.Withdrawal, error) {
	for _, at := range g.owners {
		at.stop.start(func() (withdrawal, error) {
			if producer, ok := at.live.(connection.Producer); ok {
				return producer.StopProducing()
			}
			return withdrawal{}, errors.New("cannot withdraw capture authority")
		})
	}
	whole := withdrawal{Complete: true}
	var failures []error
	for _, at := range g.owners {
		one, err := at.stop.wait(ctx)
		whole.Instances += one.Instances
		if one.At.After(whole.At) {
			whole.At = one.At
		}
		if err != nil || !one.Complete {
			whole.Complete = false
			if err == nil {
				err = errors.New(one.Because)
				if one.Because == "" {
					err = errors.New("withdrawal incomplete")
				}
			}
			failures = append(failures, fmt.Errorf("adapter %s withdrawal: %w", at.name, err))
		}
	}
	if err := errors.Join(failures...); err != nil {
		whole.Because = err.Error()
	}
	return whole, errors.Join(failures...)
}

func (g *Group) Drain(within time.Duration) (connection.Drained, error) {
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	return g.DrainContext(ctx, within)
}

func (g *Group) DrainContext(ctx context.Context, within time.Duration) (connection.Drained, error) {
	ctx, cancel := context.WithTimeout(ctx, within)
	defer cancel()
	for _, at := range g.owners {
		at.drain.start(func() (drained, error) {
			if producer, ok := at.live.(connection.Producer); ok {
				return producer.Drain(within)
			}
			return drained{}, errors.New("cannot drain submitted events")
		})
	}
	whole := drained{Complete: true, Delivered: connection.Counted(0), Outstanding: connection.Counted(0)}
	var failures []error
	for _, at := range g.owners {
		one, err := at.drain.wait(ctx)
		if err != nil {
			why := fmt.Sprintf("adapter %s drain: %v", at.name, err)
			one.Delivered, one.Outstanding = connection.Uncounted(why), connection.Uncounted(why)
		}
		whole.Delivered = whole.Delivered.Add(one.Delivered)
		whole.Outstanding = whole.Outstanding.Add(one.Outstanding)
		if err != nil || !one.Complete {
			whole.Complete = false
			if err == nil {
				err = errors.New(one.Because)
				if one.Because == "" {
					err = errors.New("drain incomplete")
				}
			}
			failures = append(failures, fmt.Errorf("adapter %s drain: %w", at.name, err))
		}
	}
	if err := errors.Join(failures...); err != nil {
		whole.Because = err.Error()
	}
	return whole, errors.Join(failures...)
}

func (g *Group) Account() (connection.Counters, error) { return g.AccountContext(context.Background()) }

func (g *Group) AccountContext(ctx context.Context) (connection.Counters, error) {
	// Account is also read while running; only the withdrawal, drain and close
	// operations are memoized. Every accounting read has its own detached calls.
	calls := make([]call[connection.Counters], len(g.owners))
	for i, at := range g.owners {
		calls[i].start(func() (connection.Counters, error) {
			if producer, ok := at.live.(connection.Producer); ok {
				return producer.Account()
			}
			return connection.Counters{}, errors.New("cannot read producer counters")
		})
	}
	var whole connection.Counters
	var failures []error
	for i, at := range g.owners {
		one, err := calls[i].wait(ctx)
		if err != nil {
			err = fmt.Errorf("adapter %s account: %w", at.name, err)
			failures = append(failures, err)
			one = unknownCounters(err.Error())
		}
		if i == 0 {
			whole = one
		} else {
			whole = sumCounters(whole, one)
		}
	}
	return whole, errors.Join(failures...)
}

func sumCounters(whole, one connection.Counters) connection.Counters {
	whole.Ordered = whole.Ordered.Add(one.Ordered)
	whole.ReservationAttempts = whole.ReservationAttempts.Add(one.ReservationAttempts)
	whole.Reservations = whole.Reservations.Add(one.Reservations)
	whole.ReservationFailures = whole.ReservationFailures.Add(one.ReservationFailures)
	whole.Submitted = whole.Submitted.Add(one.Submitted)
	whole.Delivered = whole.Delivered.Add(one.Delivered)
	whole.Undecodable = whole.Undecodable.Add(one.Undecodable)
	whole.LostAfterSubmission = whole.LostAfterSubmission.Add(one.LostAfterSubmission)
	whole.Outstanding = whole.Outstanding.Add(one.Outstanding)
	whole.StillExecuting = whole.StillExecuting.Add(one.StillExecuting)
	whole.UnmatchedReturns = whole.UnmatchedReturns.Add(one.UnmatchedReturns)
	whole.UnmeasurableCalls = whole.UnmeasurableCalls.Add(one.UnmeasurableCalls)
	whole.SocketsUnrecorded = whole.SocketsUnrecorded.Add(one.SocketsUnrecorded)
	whole.BindingsUnrecorded = whole.BindingsUnrecorded.Add(one.BindingsUnrecorded)
	whole.DenialsUnrecorded = whole.DenialsUnrecorded.Add(one.DenialsUnrecorded)
	whole.DeferredDiscarded = whole.DeferredDiscarded.Add(one.DeferredDiscarded)
	whole.RefusedInFlight = whole.RefusedInFlight.Add(one.RefusedInFlight)
	whole.Transfers = whole.Transfers.Add(one.Transfers)
	whole.Unmeasured = whole.Unmeasured.Add(one.Unmeasured)
	whole.Empty = whole.Empty.Add(one.Empty)
	whole.Fragments = whole.Fragments.Add(one.Fragments)
	whole.FragmentsRefused = whole.FragmentsRefused.Add(one.FragmentsRefused)
	whole.Persisted = whole.Persisted.Add(one.Persisted)
	whole.PersistedDropped = whole.PersistedDropped.Add(one.PersistedDropped)
	whole.PersistedRefused = whole.PersistedRefused.Add(one.PersistedRefused)
	whole.Discards = whole.Discards.Add(one.Discards)
	whole.UnplacedBytes = whole.UnplacedBytes.Add(one.UnplacedBytes)
	return whole
}

func unknownCounters(why string) connection.Counters {
	return connection.Counters{
		Ordered:             connection.Uncounted(why),
		ReservationAttempts: connection.Uncounted(why),
		Reservations:        connection.Uncounted(why),
		ReservationFailures: connection.Uncounted(why),
		Submitted:           connection.Uncounted(why),
		Delivered:           connection.Uncounted(why),
		Undecodable:         connection.Uncounted(why),
		LostAfterSubmission: connection.Uncounted(why),
		Outstanding:         connection.Uncounted(why),
		StillExecuting:      connection.Uncounted(why),
		UnmatchedReturns:    connection.Uncounted(why),
		UnmeasurableCalls:   connection.Uncounted(why),
		SocketsUnrecorded:   connection.Uncounted(why),
		BindingsUnrecorded:  connection.Uncounted(why),
		DenialsUnrecorded:   connection.Uncounted(why),
		DeferredDiscarded:   connection.Uncounted(why),
		RefusedInFlight:     connection.Uncounted(why),
		Transfers:           connection.Uncounted(why),
		Unmeasured:          connection.Uncounted(why),
		Empty:               connection.Uncounted(why),
		Fragments:           connection.Uncounted(why),
		FragmentsRefused:    connection.Uncounted(why),
		Persisted:           connection.Uncounted(why),
		PersistedDropped:    connection.Uncounted(why),
		PersistedRefused:    connection.Uncounted(why),
		Discards:            connection.Uncounted(why),
		UnplacedBytes:       connection.Uncounted(why),
	}
}
