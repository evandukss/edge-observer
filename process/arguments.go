package process

import (
	"errors"
	"fmt"
	"time"
)

// ArgumentEvidence distinguishes a supplied argv from a reading that could not
// establish it. The zero value preserves explicitly constructed Process values;
// procfs readers must classify their evidence, including zero-byte readings.
type ArgumentEvidence uint8

const (
	ArgumentsKnown ArgumentEvidence = iota
	ArgumentsUndetermined
)

// Decision preserves a rule's uncertainty separately from a definite mismatch.
type Decision uint8

const (
	NoMatch Decision = iota
	MatchFound
	Indeterminate
)

// ArgumentsRefusal names a process whose argument evidence cannot support a
// selection decision. Detail distinguishes an unread argv from a changed birth
// or executable during a reread; none asserts that an exec happened.
type ArgumentsRefusal struct {
	PID        int32
	Executable string
	Detail     string
}

func (r ArgumentsRefusal) Error() string {
	return fmt.Sprintf("pid %d (%s): arguments undetermined: %s", r.PID, r.Executable, r.Detail)
}

// ArgumentReadBound is the shared startup, preflight and reload retry budget.
// It applies to the whole candidate set, not once per process.
const ArgumentReadBound = 50 * time.Millisecond

// Decide is the rule's three-way selection result.
func (r Rule) Decide(p Process) Decision {
	if r.Matches(p) {
		return MatchFound
	}
	return NoMatch
}

// Decide is the approval's result for a process in its own right.
func (a Approval) Decide(p Process) Decision {
	if a.Observes(p) {
		return MatchFound
	}
	return NoMatch
}

// CheckArguments reports argument evidence that leaves an inclusion or an
// exclusion undecidable. Boolean convenience methods cannot convey its reason.
func (a Approval) CheckArguments(t Table) error { return nil }

// SettleArguments rereads undecidable candidates while the caller still holds
// privileges, retaining their birth and executable across the bounded retry.
func (a Approval) SettleArguments(root string, t Table) (Table, error) { return t, nil }

// Err refuses a resolution that could not decide its argument conditions.
func (r Resolution) Err() error {
	var refusals []error
	for _, refusal := range r.ArgumentsUndetermined {
		refusals = append(refusals, refusal)
	}
	return errors.Join(refusals...)
}
