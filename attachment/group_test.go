package attachment

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/probe"
)

type lifecycleOwner struct {
	closeEntered chan struct{}
	closeHold    chan struct{}
	stopEntered  chan struct{}
	stopHold     chan struct{}
	readEntered  chan struct{}
	readHold     chan struct{}
	closes       atomic.Int32
	stops        atomic.Int32
	counters     connection.Counters
}

func (a *lifecycleOwner) Capability() probe.Capability { return probe.Capability{Payload: true} }
func (a *lifecycleOwner) Close() error {
	a.closes.Add(1)
	if a.closeEntered != nil {
		close(a.closeEntered)
	}
	if a.closeHold != nil {
		<-a.closeHold
	}
	return nil
}
func (a *lifecycleOwner) StopProducing() (connection.Withdrawal, error) {
	a.stops.Add(1)
	if a.stopEntered != nil {
		close(a.stopEntered)
	}
	if a.stopHold != nil {
		<-a.stopHold
	}
	return connection.Withdrawal{At: time.Now(), Instances: 3, Complete: true}, nil
}
func (a *lifecycleOwner) Drain(time.Duration) (connection.Drained, error) {
	if a.readEntered != nil {
		close(a.readEntered)
	}
	if a.readHold != nil {
		<-a.readHold
	}
	return connection.Drained{Delivered: connection.Counted(2), Outstanding: connection.Counted(0), Complete: true}, nil
}
func (a *lifecycleOwner) Account() (connection.Counters, error) {
	if a.readEntered != nil {
		close(a.readEntered)
	}
	if a.readHold != nil {
		<-a.readHold
	}
	return a.counters, nil
}
func waitOwner(t *testing.T, reached <-chan struct{}) {
	t.Helper()
	select {
	case <-reached:
	case <-time.After(time.Second):
		t.Fatal("wiring: owner operation was not reached")
	}
}

func TestHeldOwnerDoesNotPreventOtherOwnersFromClosingOrWithdrawing(t *testing.T) {
	for _, operation := range []string{"close", "withdraw"} {
		t.Run(operation, func(t *testing.T) {
			held, free := &lifecycleOwner{}, &lifecycleOwner{}
			hold := make(chan struct{})
			entered := make(chan struct{})
			other := make(chan struct{})
			release := sync.OnceFunc(func() { close(hold) })
			defer release()
			if operation == "close" {
				held.closeHold = hold
				held.closeEntered = entered
				free.closeEntered = other
			} else {
				held.stopHold = hold
				held.stopEntered = entered
				free.stopEntered = other
			}
			g := &Group{owners: []*owner{{name: "held", live: held}, {name: "free", live: free}}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			var withdrawn connection.Withdrawal
			go func() {
				if operation == "close" {
					result <- g.CloseContext(ctx)
				} else {
					var err error
					withdrawn, err = g.StopProducingContext(ctx)
					result <- err
				}
			}()
			waitOwner(t, entered)
			waitOwner(t, other)
			// The free call must have returned, not merely entered, before checking
			// the aggregate's preservation of its known withdrawal.
			if operation == "withdraw" {
				_, err := g.owners[1].stop.wait(context.Background())
				if err != nil {
					t.Fatal(err)
				}
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "held") {
					t.Fatalf("pending owner error %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("context expiry waited on held owner")
			}
			before := withdrawn
			if operation == "withdraw" && (withdrawn.Complete || withdrawn.Instances != 3) {
				t.Fatalf("withdrawal lost known owner or claimed held owner: %+v", withdrawn)
			}
			release()
			if operation == "close" {
				if err := g.Close(); err != nil {
					t.Fatal(err)
				}
				if held.closes.Load() != 1 || free.closes.Load() != 1 {
					t.Fatal("close repeated an owner operation")
				}
			} else {
				if _, err := g.StopProducing(); err != nil {
					t.Fatal(err)
				}
				if held.stops.Load() != 1 || free.stops.Load() != 1 {
					t.Fatal("withdrawal repeated an owner operation")
				}
				if withdrawn != before {
					t.Fatal("late completion mutated a returned withdrawal")
				}
			}
		})
	}
}

type silentOwner struct{}

func (silentOwner) Close() error                 { return nil }
func (silentOwner) Capability() probe.Capability { return probe.Capability{} }

func TestUnknownOwnerFactsRemainUnknownInEitherOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		known := &owner{name: "known", live: &lifecycleOwner{counters: connection.Counters{Ordered: connection.Counted(7)}}}
		unknown := &owner{name: "silent", live: silentOwner{}}
		owners := []*owner{known, unknown}
		if reverse {
			owners = []*owner{unknown, known}
		}
		g := &Group{owners: owners}
		counts, err := g.Account()
		if err == nil || counts.Ordered.Known || !strings.Contains(counts.Ordered.Why, "silent") {
			t.Fatalf("unknown count became known: %+v %v", counts.Ordered, err)
		}
		losses, err := g.Losses()
		if err == nil || losses.UnderWay.Known {
			t.Fatalf("unknown losses: %+v %v", losses, err)
		}
		if _, err := g.Grants(); err == nil {
			t.Fatal("unknown grants became an empty known list")
		}
		if _, err := g.Withdrawals(); err == nil {
			t.Fatal("unknown withdrawals became an empty known list")
		}
		if _, err := g.EndedCounts(); err == nil {
			t.Fatal("unknown ended counts became an empty known list")
		}
		if _, err := g.Retained(); err == nil {
			t.Fatal("unknown retention became an empty known list")
		}
		if _, err := g.Refusals(); err == nil {
			t.Fatal("unknown refusals became zero")
		}
	}
}

func TestOwnerCountersAndDrainSumOnlyEstablishedFacts(t *testing.T) {
	a := &lifecycleOwner{counters: connection.Counters{Ordered: connection.Counted(3), Submitted: connection.Counted(4)}}
	b := &lifecycleOwner{counters: connection.Counters{Ordered: connection.Counted(5), Submitted: connection.Uncounted("owner could not count submission")}}
	g := &Group{owners: []*owner{{name: "a", live: a}, {name: "b", live: b}}}
	withdrawal, err := g.StopProducing()
	if err != nil || !withdrawal.Complete || withdrawal.Instances != 6 {
		t.Fatalf("withdrawal %+v %v", withdrawal, err)
	}
	drained, err := g.Drain(time.Second)
	if err != nil || !drained.Complete || !drained.Delivered.Known || drained.Delivered.Value != 4 || !drained.Outstanding.Known || drained.Outstanding.Value != 0 {
		t.Fatalf("drain %+v %v", drained, err)
	}
	counts, err := g.Account()
	if err != nil || !counts.Ordered.Known || counts.Ordered.Value != 8 || counts.Submitted.Known || counts.Submitted.Why != "owner could not count submission" {
		t.Fatalf("counters %+v %v", counts, err)
	}
}

func TestHeldOwnerAccountingAndDrainReturnDetachedUnknowns(t *testing.T) {
	for _, operation := range []string{"account", "drain"} {
		t.Run(operation, func(t *testing.T) {
			hold := make(chan struct{})
			entered := make(chan struct{})
			other := make(chan struct{})
			release := sync.OnceFunc(func() { close(hold) })
			defer release()
			held := &lifecycleOwner{readHold: hold, readEntered: entered, counters: connection.Counters{Ordered: connection.Counted(8)}}
			free := &lifecycleOwner{readEntered: other, counters: connection.Counters{Ordered: connection.Counted(3)}}
			g := &Group{owners: []*owner{{name: "held", live: held}, {name: "free", live: free}}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			var counts connection.Counters
			var drained connection.Drained
			go func() {
				var err error
				if operation == "account" {
					counts, err = g.AccountContext(ctx)
				} else {
					drained, err = g.DrainContext(ctx, time.Minute)
				}
				result <- err
			}()
			waitOwner(t, entered)
			waitOwner(t, other)
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "held") {
					t.Fatalf("pending owner error %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("context expiry waited on held owner")
			}
			if operation == "account" {
				if counts.Ordered.Known || !strings.Contains(counts.Ordered.Why, "held") {
					t.Fatalf("held owner counted: %+v", counts.Ordered)
				}
			} else {
				if drained.Complete || drained.Delivered.Known || drained.Outstanding.Known {
					t.Fatalf("held drain reported complete: %+v", drained)
				}
			}
			beforeCounts, beforeDrain := counts, drained
			release()
			if operation == "drain" {
				if _, err := g.DrainContext(context.Background(), time.Second); err != nil {
					t.Fatal(err)
				}
			}
			if counts != beforeCounts || drained != beforeDrain {
				t.Fatal("late completion changed a returned value")
			}
		})
	}
}
