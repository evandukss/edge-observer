package connection

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// The finalisation boundary: where a run's accounting ends.
//
// Loss counters read while probes are live, and a ring reader closed before
// the links detach, would miss events submitted in between: the run would
// report no loss and be missing its tail. So there is one order:
//
//	1. Stop production.       Withdraw capture authority: nothing new is
//	                          produced, and calls already inside the library
//	                          return to a withdrawn grant.
//	2. Account for what is in flight.
//	3. Drain it or invalidate it explicitly.
//	4. Read the final counters, after the drain.
//	5. Seal.
//
// Stopping is a capture-authority withdrawal, which makes the read boundary
// testable: a call that entered under a live grant returns to a withdrawn one,
// its payload unread, and is accounted for. Every probe path re-reads the
// grant before acting.

// ErrSealed is what a second finalisation fails with: a run is sealed once.
var ErrSealed = errors.New("this run has already been sealed")

// Withdrawal is the capture-authority withdrawal that stops production.
// Instances is read back, not taken from the request: an authority that could
// not be withdrawn leaves probes producing, and Complete is then false.
type Withdrawal struct {
	At        time.Time `json:"at"`
	Instances int       `json:"instances"`

	Complete bool   `json:"complete"`
	Because  string `json:"because,omitempty"`
}

// Drained is what the drain found: what arrived after production stopped, and
// what was still unaccounted for. Outstanding is allowed but never silent:
// each stream it belonged to has lost a position.
type Drained struct {
	Delivered   Count `json:"delivered"`
	Outstanding Count `json:"outstanding"`

	Complete bool   `json:"complete"`
	Because  string `json:"because,omitempty"`
}

// Producer is the capture side a finalisation drives, as three calls because
// their order matters: a single Close would read counters before the drain.
type Producer interface {
	// StopProducing withdraws capture authority from every probe path, reporting
	// what it actually withdrew. An incomplete withdrawal is not an error: the
	// finalisation still runs and the seal says the run was still producing.
	StopProducing() (Withdrawal, error)

	// Drain waits for what was already submitted to be delivered, up to within,
	// and reports what was still outstanding when it stopped waiting.
	Drain(within time.Duration) (Drained, error)

	// Account is the final counters, read after the drain. An unreadable counter
	// is an unknown Count, never zero.
	Account() (Counters, error)
}

// Seal is a finished run's account of its own end. Complete is read first. An
// incomplete seal keeps every number that was established, and Because says
// which steps failed.
type Seal struct {
	// Stopped is when capture authority was withdrawn; Sealed is when accounting
	// closed. Between them is the drain.
	Stopped time.Time `json:"stopped"`
	Sealed  time.Time `json:"sealed"`

	Withdrawal Withdrawal `json:"withdrawal"`
	Drain      Drained    `json:"drain"`
	Counters   Counters   `json:"counters"`

	// Interrupted is calls inside the library when authority was withdrawn: their
	// bytes crossed and are absent from their streams.
	Interrupted Count `json:"interrupted"`

	Complete bool     `json:"complete"`
	Because  []string `json:"because,omitempty"`
}

// Accounted reports whether every conservation identity the seal's counters can
// state holds, and whether every one of them could be evaluated.
func (s Seal) Accounted() (holds bool, complete bool) { return s.Counters.Balanced() }

// Sound reports whether this run is clean: the seal completed and every
// identity was evaluated and holds. Use it rather than Complete alone.
func (s Seal) Sound() bool {
	holds, evaluated := s.Accounted()
	return s.Complete && holds && evaluated
}

func (s Seal) String() string {
	if s.Complete {
		return fmt.Sprintf("sealed at %s, %s withdrawn from %d instances, %s outstanding, %s interrupted",
			s.Sealed.UTC().Format(time.RFC3339Nano), s.Stopped.UTC().Format(time.RFC3339Nano),
			s.Withdrawal.Instances, s.Drain.Outstanding, s.Interrupted)
	}
	return fmt.Sprintf("sealed at %s and INCOMPLETE: %s",
		s.Sealed.UTC().Format(time.RFC3339Nano), strings.Join(s.Because, "; "))
}

// Finaliser is what a caller ends a run with; a stop command uses it rather
// than a shutdown path of its own.
type Finaliser interface {
	// Stop runs the boundary once, in order. It returns a Seal on every path that
	// reached the end, including failed steps; the error is for a run that cannot
	// finalise at all (already sealed).
	Stop() (Seal, error)
}

// Sealer drives the boundary over one producer: one implementation of the
// order.
type Sealer struct {
	// Producer is the capture side.
	Producer Producer

	// Within is how long the drain waits. It has no default; a Sealer without one
	// refuses to run.
	Within time.Duration

	// Now is the clock, for tests. Nil is time.Now.
	Now func() time.Time

	sealed bool
}

// Stop runs the boundary.
func (s *Sealer) Stop() (Seal, error) {
	if s.sealed {
		return Seal{}, ErrSealed
	}
	if s.Producer == nil {
		return Seal{}, fmt.Errorf("%w: a finalisation with no producer stops nothing", ErrInvalid)
	}
	if s.Within <= 0 {
		return Seal{}, fmt.Errorf("%w: a drain waits for a stated time, and %s is not one",
			ErrInvalid, s.Within)
	}
	s.sealed = true

	now := s.Now
	if now == nil {
		now = time.Now
	}

	seal := Seal{Complete: true, Interrupted: Uncounted("the counters were not read")}

	// 1. Stop production: everything after is accounting over a set no longer
	// growing.
	withdrawal, err := s.Producer.StopProducing()
	if err != nil {
		withdrawal.Complete = false
		withdrawal.Because = err.Error()
	}
	if withdrawal.At.IsZero() {
		withdrawal.At = now()
	}
	seal.Withdrawal = withdrawal
	seal.Stopped = withdrawal.At
	if !withdrawal.Complete {
		// Still producing when sealed: every count below was read from a moving set.
		seal.Complete = false
		seal.Because = append(seal.Because,
			"capture authority was not withdrawn, so the run was still producing when it was "+
				"sealed: "+reason(withdrawal.Because))
	}

	// 2 and 3. Account for what is in flight, and drain it.
	drained, err := s.Producer.Drain(s.Within)
	if err != nil {
		drained.Complete = false
		drained.Because = err.Error()
	}
	if !drained.Delivered.Known && drained.Delivered.Why == "" {
		drained.Delivered = Uncounted("the drain did not say what it delivered")
	}
	if !drained.Outstanding.Known && drained.Outstanding.Why == "" {
		drained.Outstanding = Uncounted("the drain did not say what was left outstanding")
	}
	seal.Drain = drained
	if !drained.Complete {
		seal.Complete = false
		seal.Because = append(seal.Because,
			"what was in flight was not drained, so the streams it belonged to are short by an "+
				"unknown amount: "+reason(drained.Because))
	}

	// 4. The final counters, after the drain.
	counters, err := s.Producer.Account()
	if err != nil {
		seal.Complete = false
		seal.Because = append(seal.Because, "the final counters could not be read: "+err.Error())
	}
	// The drain knows what it left outstanding; the kernel's counters do not.
	counters.Outstanding = drained.Outstanding
	seal.Counters = counters
	// Not capture's Stats().Interrupted, which counts streams a located loss
	// retired (reported as "retired"); this is the one the report prints.
	seal.Interrupted = counters.RefusedInFlight

	// 5. Seal.
	seal.Sealed = now()
	return seal, nil
}

// reason fills an empty explanation, so a seal never says a step failed for
// nothing.
func reason(why string) string {
	if strings.TrimSpace(why) == "" {
		return "no reason was given"
	}
	return why
}
