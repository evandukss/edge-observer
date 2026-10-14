package process

import (
	"errors"
	"fmt"
	"os"
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

// ResolutionRebuildBound starts at the first established change, not at each
// snapshot. The initial snapshot does not consume one of the three rebuilds.
const ResolutionRebuildBound = time.Second
const ResolutionRebuildLimit = 3

type candidateChanged struct{ ArgumentsRefusal }

func (c candidateChanged) Unwrap() error { return c.ArgumentsRefusal }

func (c candidateChanged) Error() string {
	return fmt.Sprintf("pid %d (%s): selection changed: %s", c.PID, c.Executable, c.Detail)
}

var errResolutionDeadline = errors.New("the selection rebuild deadline expired")

func checkResolutionDeadline(deadline time.Time) error {
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return errResolutionDeadline
	}
	return nil
}

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

// ResolutionReader supplies complete host snapshots and candidate rereads. Snapshot
// must refresh processes, listeners and boot identity together. It receives the
// outer deadline (zero before a change is established), and must check it before
// each per-process or listener-table read, never starting another after expiry.
// A synchronous read already in flight may finish; its internal file reads are
// not separately bounded. Now and Sleep default to wall time when nil. Snapshot
// and Process are required.
type ResolutionReader struct {
	Snapshot func(deadline time.Time) (Host, error)
	Process  func(int32) (Process, error)
	Now      func() time.Time
	Sleep    func(time.Duration)
}

func (r ResolutionReader) clock() ResolutionReader {
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Sleep == nil {
		r.Sleep = time.Sleep
	}
	return r
}

// ResolveWith resolves from the supplied reader while privileges are available.
func (a Approval) ResolveWith(reader ResolutionReader) (Resolution, Table, error) {
	reader = reader.clock()
	var deadline time.Time
	var last candidateChanged
	var table Table
	exhausted := func(rebuilds int) (Resolution, Table, error) {
		return Resolution{}, table, fmt.Errorf("selection did not settle within %d rebuilds and %s: %w",
			rebuilds, ResolutionRebuildBound, last)
	}
	for rebuilds := 0; ; rebuilds++ {
		if !deadline.IsZero() && !reader.Now().Before(deadline) {
			return exhausted(rebuilds - 1)
		}
		host, err := reader.Snapshot(deadline)
		if !deadline.IsZero() && !reader.Now().Before(deadline) {
			return exhausted(rebuilds)
		}
		var resolution Resolution
		if err == nil {
			resolution, table, err = a.resolveArguments(reader, host, deadline)
		}
		var changed candidateChanged
		if errors.As(err, &changed) {
			last = changed
			if deadline.IsZero() {
				deadline = reader.Now().Add(ResolutionRebuildBound)
			}
			if rebuilds == ResolutionRebuildLimit || !reader.Now().Before(deadline) {
				return exhausted(rebuilds)
			}
			continue
		}
		if !deadline.IsZero() && !reader.Now().Before(deadline) {
			return exhausted(rebuilds)
		}
		return resolution, table, err
	}
}

// SettleArguments rereads undecidable candidates while the caller still holds
// privileges. Each candidate keeps its original birth and executable; a changed
// identity is refused, never silently replaced by a newly matching process.
// Reads retry at 1 ms intervals for at most ArgumentReadBound across the set
// (plus the final in-flight procfs read). Two empty readings remain unknown.
func (a Approval) SettleArguments(root string, t Table) (Table, error) {
	return a.settleArguments(ResolutionReader{Process: func(pid int32) (Process, error) { return readProcess(root, pid) }}.clock(), t, time.Time{})
}

func (a Approval) settleArguments(reader ResolutionReader, t Table, outer time.Time) (Table, error) {
	deadline := reader.Now().Add(ArgumentReadBound)
	if !outer.IsZero() && outer.Before(deadline) {
		deadline = outer
	}
	if err := a.listenerEvidence(t); err != nil {
		return t, err
	}
	for _, p := range t.processes {
		if !p.argumentChanged {
			continue
		}
		for _, rules := range [][]Rule{a.Rules, a.Exclusions} {
			for _, rule := range rules {
				if rule.Decide(p) != NoMatch {
					return t, candidateChanged{ArgumentsRefusal{PID: p.PID, Executable: p.Executable,
						Detail: "the candidate changed or exited during the snapshot read"}}
				}
			}
		}
	}
	pending := a.argumentRefusals(t)
	if len(pending) == 0 {
		return t, nil
	}
	current := TableOf(append([]Process(nil), t.processes...)...)
	current.listeners, current.unreadable = t.listeners, t.unreadable
	original := t
	for len(pending) != 0 {
		if !reader.Now().Before(deadline) {
			return current, (Resolution{ArgumentsUndetermined: pending}).Err()
		}
		for _, refusal := range pending {
			if !reader.Now().Before(deadline) {
				return current, (Resolution{ArgumentsUndetermined: pending}).Err()
			}
			before, _ := original.Lookup(refusal.PID)
			after, err := reader.Process(before.PID)
			if !outer.IsZero() && !reader.Now().Before(deadline) {
				return current, (Resolution{ArgumentsUndetermined: pending}).Err()
			}
			if err != nil {
				refusal := ArgumentsRefusal{PID: before.PID, Executable: before.Executable,
					Detail: fmt.Sprintf("the candidate could not be reread: %v", err)}
				if os.IsNotExist(err) {
					return current, candidateChanged{refusal}
				}
				return current, refusal
			}
			if before.StartTime == 0 || after.StartTime == 0 {
				return current, ArgumentsRefusal{PID: before.PID, Executable: before.Executable,
					Detail: "the candidate's birth could not be established during the reread"}
			}
			if after.argumentChanged || after.StartTime != before.StartTime || after.Executable != before.Executable {
				return current, candidateChanged{ArgumentsRefusal{PID: before.PID, Executable: before.Executable,
					Detail: "the candidate's birth or executable changed during the reread"}}
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
			reader.Sleep(min(time.Millisecond, max(0, deadline.Sub(reader.Now()))))
		}
	}
	return current, nil
}

// ResolveArguments settles a caller-provided snapshot, refusing a changed
// candidate. ResolveFrom also rebuilds the complete snapshot after a change.
// Preparing rules preserves port/interface conditions and boot refusals.
func (a Approval) ResolveArguments(root string, host Host) (Resolution, Table, error) {
	return a.resolveArguments(ResolutionReader{Process: func(pid int32) (Process, error) { return readProcess(root, pid) }}.clock(), host, time.Time{})
}

func (a Approval) resolveArguments(reader ResolutionReader, host Host, deadline time.Time) (Resolution, Table, error) {
	prepared, refused := a.prepare(host)
	for i, reason := range refused {
		if reason != "" {
			prepared.Rules[i] = Rule{}
		}
	}
	table, err := prepared.settleArguments(reader, host.Table, deadline)
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
