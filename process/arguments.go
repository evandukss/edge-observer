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

// Decide is the approval's result for a process in its own right. An
// undecidable exclusion must never be interpreted as permission to capture.
func (a Approval) Decide(p Process) Decision {
	result := NoMatch
	for _, rule := range a.Rules {
		switch rule.Decide(p) {
		case Indeterminate:
			result = Indeterminate
		case MatchFound:
			if result != Indeterminate {
				result = MatchFound
			}
		}
	}
	for _, rule := range a.Exclusions {
		switch rule.Decide(p) {
		case MatchFound:
			return NoMatch
		case Indeterminate:
			result = Indeterminate
		}
	}
	return result
}

// CheckArguments reports argument evidence that leaves an inclusion or an
// exclusion undecidable. Boolean convenience methods cannot convey its reason.
func (a Approval) CheckArguments(t Table) error {
	return (Resolution{ArgumentsUndetermined: a.argumentRefusals(t)}).Err()
}

func (a Approval) argumentRefusals(t Table) []ArgumentsRefusal {
	var refused []ArgumentsRefusal
	for _, p := range t.processes {
		uncertain := false
		for _, rules := range [][]Rule{a.Rules, a.Exclusions} {
			for _, rule := range rules {
				if rule.Decide(p) == Indeterminate {
					uncertain = true
				}
			}
		}
		if uncertain {
			refused = append(refused, ArgumentsRefusal{PID: p.PID, Executable: p.Executable,
				Detail: "the command line could not be established"})
		}
	}
	return refused
}

func argumentEvidence(cmdline []byte, err error) ArgumentEvidence {
	if err != nil || len(cmdline) == 0 {
		return ArgumentsUndetermined
	}
	return ArgumentsKnown
}

// SettleArguments rereads undecidable candidates while the caller still holds
// privileges. Each candidate keeps its original birth and executable; a changed
// identity is refused, never silently replaced by a newly matching process.
// Reads retry at 1 ms intervals for at most ArgumentReadBound across the set
// (plus the final in-flight procfs read). Two empty readings remain unknown.
func (a Approval) SettleArguments(root string, t Table) (Table, error) {
	deadline := time.Now().Add(ArgumentReadBound)
	pending := a.argumentRefusals(t)
	if len(pending) == 0 {
		return t, nil
	}
	current := TableOf(append([]Process(nil), t.processes...)...)
	current.listeners, current.unreadable = t.listeners, t.unreadable
	original := t
	for len(pending) != 0 {
		if !time.Now().Before(deadline) {
			return current, (Resolution{ArgumentsUndetermined: pending}).Err()
		}
		for _, refusal := range pending {
			if !time.Now().Before(deadline) {
				return current, (Resolution{ArgumentsUndetermined: pending}).Err()
			}
			before, _ := original.Lookup(refusal.PID)
			after, err := readProcess(root, before.PID)
			if err != nil {
				return current, ArgumentsRefusal{PID: before.PID, Executable: before.Executable,
					Detail: fmt.Sprintf("the candidate could not be reread: %v", err)}
			}
			if before.StartTime == 0 {
				return current, ArgumentsRefusal{PID: before.PID, Executable: before.Executable,
					Detail: "the candidate's birth could not be established during the reread"}
			}
			if after.StartTime != before.StartTime || after.Executable != before.Executable {
				return current, ArgumentsRefusal{PID: before.PID, Executable: before.Executable,
					Detail: "the candidate's birth or executable changed during the reread"}
			}
			after.Listening = before.Listening
			current.byPID[after.PID] = after
			for i := range current.processes {
				if current.processes[i].PID == after.PID {
					current.processes[i] = after
					break
				}
			}
		}
		pending = a.argumentRefusals(current)
		if len(pending) != 0 {
			time.Sleep(min(time.Millisecond, max(0, time.Until(deadline))))
		}
	}
	return current, nil
}

// ResolveArguments is the privileged resolution path. Preparing the rules first
// preserves port/interface conditions and refusals for a different boot.
func (a Approval) ResolveArguments(root string, host Host) (Resolution, Table, error) {
	prepared, refused := a.prepare(host)
	for i, reason := range refused {
		if reason != "" {
			prepared.Rules[i] = Rule{}
		}
	}
	table, err := prepared.SettleArguments(root, host.Table)
	if err != nil {
		return Resolution{}, table, err
	}
	host.Table = table
	resolution := a.Resolve(host)
	return resolution, table, resolution.Err()
}

// Err refuses a resolution that could not decide its argument conditions.
func (r Resolution) Err() error {
	var refusals []error
	for _, refusal := range r.ArgumentsUndetermined {
		refusals = append(refusals, refusal)
	}
	return errors.Join(refusals...)
}
