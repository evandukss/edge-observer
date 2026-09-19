package connection_test

import (
	"errors"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/connection"
)

// producer records the order the boundary drove it in, so the order is
// asserted: counters read before the drain look plausible either way.
type producer struct {
	order []string

	withdrawal  connection.Withdrawal
	withdrawErr error

	drained  connection.Drained
	drainErr error
	within   time.Duration

	counters   connection.Counters
	accountErr error
}

func (p *producer) StopProducing() (connection.Withdrawal, error) {
	p.order = append(p.order, "stop")
	return p.withdrawal, p.withdrawErr
}

func (p *producer) Drain(within time.Duration) (connection.Drained, error) {
	p.order = append(p.order, "drain")
	p.within = within
	return p.drained, p.drainErr
}

func (p *producer) Account() (connection.Counters, error) {
	p.order = append(p.order, "account")
	return p.counters, p.accountErr
}

// stopping does every step cleanly: the control each case breaks once.
func stopping() *producer {
	return &producer{
		withdrawal: connection.Withdrawal{At: at, Instances: 3, Complete: true},
		drained: connection.Drained{
			Delivered:   connection.Counted(12),
			Outstanding: connection.Counted(0),
			Complete:    true,
		},
		counters: connection.Counters{
			Ordered:             connection.Counted(104),
			ReservationAttempts: connection.Counted(100),
			Reservations:        connection.Counted(98),
			ReservationFailures: connection.Counted(2),
			Submitted:           connection.Counted(98),
			Delivered:           connection.Counted(98),
			Undecodable:         connection.Counted(0),
			LostAfterSubmission: connection.Counted(0),
			Outstanding:         connection.Counted(0),
			UnmatchedReturns:    connection.Counted(0),
			RefusedInFlight:     connection.Counted(4),
			Transfers:           connection.Counted(98),
			Unmeasured:          connection.Counted(0),
			Empty:               connection.Counted(0),
			Fragments:           connection.Counted(98),
			FragmentsRefused:    connection.Counted(0),
			Persisted:           connection.Counted(98),
			PersistedDropped:    connection.Counted(0),
			PersistedRefused:    connection.Counted(0),
		},
	}
}

func sealer(p *producer) *connection.Sealer {
	return &connection.Sealer{Producer: p, Within: 5 * time.Second, Now: func() time.Time { return at }}
}

// The control, and the order: production stops first, counters read after the
// drain.
func TestTheBoundaryStopsProducesDrainsAndOnlyThenReadsTheCounters(t *testing.T) {
	live := stopping()
	seal, err := sealer(live).Stop()
	if err != nil {
		t.Fatalf("the boundary refused a producer that does every step: %v", err)
	}
	if got := live.order; len(got) != 3 || got[0] != "stop" || got[1] != "drain" || got[2] != "account" {
		t.Fatalf("the boundary ran %v, want stop then drain then account", got)
	}
	if !seal.Complete {
		t.Fatalf("a clean run did not seal: %v", seal.Because)
	}
	if !seal.Sound() {
		t.Fatalf("a clean run whose identities hold is not sound: %s", seal.Counters.Report())
	}
	if seal.Withdrawal.Instances != 3 {
		t.Errorf("the seal reports %d admissions withdrawn, want 3", seal.Withdrawal.Instances)
	}
	if got := seal.Interrupted; !got.Known || got.Value != 4 {
		t.Errorf("Interrupted = %s, want the 4 calls refused in flight", got)
	}
	if live.within != 5*time.Second {
		t.Errorf("the drain was given %s, and the boundary was configured with 5s", live.within)
	}
}

// A run is sealed once.
func TestARunIsSealedOnce(t *testing.T) {
	one := sealer(stopping())
	if _, err := one.Stop(); err != nil {
		t.Fatalf("the first seal failed: %v", err)
	}
	seal, err := one.Stop()
	if !errors.Is(err, connection.ErrSealed) {
		t.Fatalf("a second stop returned %v, want ErrSealed", err)
	}
	if seal.Complete {
		t.Error("a refused second stop reports a complete seal")
	}
}

// A withdrawal that left probes producing: the seal says so and keeps what it
// established.
func TestAWithdrawalThatLeftTheProbesProducingSealsIncompleteAndSaysSo(t *testing.T) {
	live := stopping()
	live.withdrawal = connection.Withdrawal{
		At: at, Instances: 1,
		Because: "2 admissions are still in the allowlist, so the probes are still producing",
	}

	seal, err := sealer(live).Stop()
	if err != nil {
		t.Fatalf("the boundary refused to run: %v", err)
	}
	if seal.Complete {
		t.Fatal("a run that was still producing sealed complete")
	}
	if len(seal.Because) == 0 {
		t.Fatal("an incomplete seal gives no reason")
	}
	if seal.Sound() {
		t.Error("a run that was still producing is sound")
	}
	// The rest of the boundary still ran.
	if got := live.order; len(got) != 3 {
		t.Errorf("the boundary ran %v after an incomplete withdrawal, want all three steps", got)
	}
	if got := seal.Counters.RefusedInFlight; !got.Known || got.Value != 4 {
		t.Errorf("the counters were not carried through an incomplete seal: %s", got)
	}
}

// A drain that ran out of time leaves outstanding unknown, and the inventory
// takes the drain's answer, not the kernel's.
func TestADrainThatRanOutOfTimeLeavesTheOutstandingCountUnknown(t *testing.T) {
	live := stopping()
	live.drained = connection.Drained{
		Delivered:   connection.Counted(7),
		Outstanding: connection.Uncounted("the ring buffer was still delivering"),
		Because:     "the ring buffer had not emptied after 5s",
	}

	seal, err := sealer(live).Stop()
	if err != nil {
		t.Fatalf("the boundary refused to run: %v", err)
	}
	if seal.Complete {
		t.Fatal("a run whose drain did not finish sealed complete")
	}
	if seal.Counters.Outstanding.Known {
		t.Fatalf("Outstanding = %s, and the drain never established it", seal.Counters.Outstanding)
	}
	holds, evaluated := seal.Accounted()
	if evaluated {
		t.Error("every identity was evaluated over an unknown outstanding count")
	}
	if !holds {
		t.Error("an identity FAILED where a term of it was merely unknown")
	}
}

// Unreadable counters report that, never zero.
func TestCountersThatCouldNotBeReadAreUnknownAndNotZero(t *testing.T) {
	live := stopping()
	live.counters.ReservationFailures = connection.Uncounted("the counters map is gone")

	seal, err := sealer(live).Stop()
	if err != nil {
		t.Fatalf("the boundary refused to run: %v", err)
	}
	if seal.Counters.ReservationFailures.Known {
		t.Fatal("an unreadable counter reports a value")
	}

	found := false
	for _, identity := range seal.Counters.Identities() {
		if identity.Evaluated {
			continue
		}
		found = true
		if identity.Holds {
			t.Errorf("%q was not evaluated and reports that it holds", identity.Name)
		}
	}
	if !found {
		t.Fatal("an identity over an unreadable counter was evaluated anyway")
	}
	if seal.Sound() {
		t.Error("a run with an unreadable counter is sound")
	}
}

// An inventory that does not add up differs from one that could not be
// checked.
func TestAnInventoryThatDoesNotAddUpFailsRatherThanGoingUnevaluated(t *testing.T) {
	live := stopping()
	live.counters.Delivered = connection.Counted(90)

	seal, err := sealer(live).Stop()
	if err != nil {
		t.Fatalf("the boundary refused to run: %v", err)
	}
	holds, evaluated := seal.Accounted()
	if !evaluated {
		t.Fatal("an identity over readable counters was not evaluated")
	}
	if holds {
		t.Fatal("98 submitted against 90 delivered, 0 lost and 0 outstanding balances")
	}
	if seal.Sound() {
		t.Error("a run whose inventory does not add up is sound")
	}
}

// An account failure is its own reason and does not stop the boundary.
func TestAnAccountThatCouldNotBeReadSealsIncompleteAndKeepsTheDrain(t *testing.T) {
	live := stopping()
	live.accountErr = errors.New("the program has no counters map")

	seal, err := sealer(live).Stop()
	if err != nil {
		t.Fatalf("the boundary refused to run: %v", err)
	}
	if seal.Complete {
		t.Fatal("a run whose counters could not be read sealed complete")
	}
	if got := seal.Drain.Delivered; !got.Known || got.Value != 12 {
		t.Errorf("the drain's own answer was lost with the account: %s", got)
	}
	if seal.Withdrawal.Instances != 3 {
		t.Errorf("the withdrawal's own answer was lost with the account")
	}
}

// No producer or no drain budget: refused, never reported as a clean end.
func TestABoundaryWithNothingToStopOrNoTimeToDrainRefuses(t *testing.T) {
	empty := &connection.Sealer{Within: time.Second}
	if _, err := empty.Stop(); err == nil {
		t.Error("a boundary with no producer sealed")
	}

	untimed := &connection.Sealer{Producer: stopping()}
	if _, err := untimed.Stop(); err == nil {
		t.Error("a boundary with no drain budget sealed")
	}
}

// An unknown term makes a sum unknown.
func TestAnUnknownTermCarriesThroughASum(t *testing.T) {
	known := connection.Counted(3)
	unknown := connection.Uncounted("the counter is gone")

	if got := known.Add(known); !got.Known || got.Value != 6 {
		t.Fatalf("3 plus 3 is %s", got)
	}
	if got := known.Add(unknown); got.Known {
		t.Fatalf("3 plus an unknown is %s", got)
	}
	if got := unknown.Add(known); got.Known {
		t.Fatalf("an unknown plus 3 is %s", got)
	}
	if unknown.Value != 0 || unknown.Known {
		t.Fatal("an unknown count carries a value a reader could act on")
	}
}

// A call refused at the read boundary takes a production-order place and no
// reservation, so reservation attempts are places less refusals. This balances
// every run that stops production with a call in flight.
func TestARefusalAtTheReadBoundaryTakesAPlaceAndTheInventoryStillBalances(t *testing.T) {
	live := stopping()
	seal, err := sealer(live).Stop()
	if err != nil {
		t.Fatalf("the boundary refused to run: %v", err)
	}
	holds, evaluated := seal.Accounted()
	if !evaluated {
		t.Fatal("an identity over readable counters was not evaluated")
	}
	if !holds {
		t.Fatalf("104 places over 100 attempts and 4 refusals does not balance:\n%s",
			seal.Counters.Report())
	}

	// The identity does the work: places not accounting for refusals fail.
	short := stopping()
	short.counters.Ordered = connection.Counted(100)
	seal, err = sealer(short).Stop()
	if err != nil {
		t.Fatalf("the boundary refused to run: %v", err)
	}
	holds, evaluated = seal.Accounted()
	if !evaluated {
		t.Fatal("an identity over readable counters was not evaluated")
	}
	if holds {
		t.Fatal("100 places over 100 attempts and 4 refusals balances")
	}
}

// A call not finished and an event not delivered are different facts: bytes
// that may not have crossed, versus bytes that crossed and are missing.
func TestCallsStillExecutingAreNeverFoldedIntoOutstandingEvents(t *testing.T) {
	live := stopping()
	live.counters.StillExecuting = connection.Counted(2)
	live.drained = connection.Drained{
		Delivered:   connection.Counted(12),
		Outstanding: connection.Counted(0),
		Complete:    true,
	}

	seal, err := sealer(live).Stop()
	if err != nil {
		t.Fatalf("the boundary refused to run: %v", err)
	}
	if got := seal.Counters.StillExecuting; !got.Known || got.Value != 2 {
		t.Fatalf("StillExecuting = %s, want 2", got)
	}
	if got := seal.Counters.Outstanding; !got.Known || got.Value != 0 {
		t.Fatalf("Outstanding = %s, and two calls still executing are not outstanding events", got)
	}

	// The identities are over events, so unfinished calls are on neither side and
	// the inventory still balances.
	holds, evaluated := seal.Accounted()
	if !evaluated {
		t.Fatal("an identity over readable counters was not evaluated")
	}
	if !holds {
		t.Fatalf("calls still executing unbalanced an inventory of events:\n%s", seal.Counters.Report())
	}
}

// An unreadable still-executing count is unknown, not zero.
func TestACountOfCallsStillExecutingThatCouldNotBeReadIsUnknown(t *testing.T) {
	live := stopping()
	live.counters.StillExecuting = connection.Uncounted("the in-flight table is gone")

	seal, err := sealer(live).Stop()
	if err != nil {
		t.Fatalf("the boundary refused to run: %v", err)
	}
	if seal.Counters.StillExecuting.Known {
		t.Fatal("a count nobody could read reports a value")
	}
	if got := seal.Counters.StillExecuting.String(); got != "not known: the in-flight table is gone" {
		t.Errorf("it reads as %q rather than saying it could not be read", got)
	}
}
