package process

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/evandukss/edge-observer/admission"
)

// This file answers one question: is an execution somebody already knows
// about still running? It is separate from Table, which drops a process with
// no exe (such as a group whose leader exited while workers run), so absence
// from the table would wrongly read as "ended". This reads identity and
// liveness only, and answers "unestablished" whenever evidence is missing.

// InspectionBudget is how many procfs operations one Inspect may spend (a
// directory opened, a batch of task entries listed, a file read, or a retry).
// A usual reading spends seven; a many-threaded group stops here with a
// partial reading. A design bound, not a measurement.
const InspectionBudget = 64

// taskBatch is how many task entries are listed at once, so the budget bounds
// the read itself.
const taskBatch = 16

// TaskState is the state character /proc/<pid>/stat reports for one task, as
// written: the character is the evidence, readable by someone who disagrees
// about what counts as running.
type TaskState byte

// NoTaskState is a state nobody read, which is not a state the kernel has.
const NoTaskState TaskState = 0

// nonterminalStates are the state characters of a task that has not exited
// (proc(5), stat field 3). The list is positive: an unknown character is
// unrecognised, never alive.
const nonterminalStates = "RSDTtWKPI"

// terminalStates are the state characters of a task that has exited: a zombie
// awaiting reaping, and dead in either spelling.
const terminalStates = "ZXx"

// Nonterminal reports whether this task had not exited when read; no promise
// about later.
func (s TaskState) Nonterminal() bool {
	return s != NoTaskState && strings.IndexByte(nonterminalStates, byte(s)) >= 0
}

// Terminal reports whether this task had exited when it was read.
func (s TaskState) Terminal() bool {
	return s != NoTaskState && strings.IndexByte(terminalStates, byte(s)) >= 0
}

// Recognised reports whether this code knows the state character. An unknown
// one is neither nonterminal nor terminal.
func (s TaskState) Recognised() bool { return s.Nonterminal() || s.Terminal() }

func (s TaskState) String() string {
	switch {
	case s == NoTaskState:
		return "a state that was not read"
	case !s.Recognised():
		return fmt.Sprintf("state %q, which is not a state this knows", string(byte(s)))
	default:
		return fmt.Sprintf("state %s", string(byte(s)))
	}
}

// Group is a thread group's identity as /proc establishes it: pid namespace,
// thread group id inside it, and the leader's birth. No executable and no
// generation.
type Group struct {
	Namespace    admission.Namespace
	NamespacePID int32

	// Start is the leader's birth; a sibling thread's is a different number.
	Start admission.Start
}

// Established reports whether every component was determined; an incomplete
// identity names no group.
func (g Group) Established() bool {
	return g.Namespace.Known() && g.NamespacePID > 0 && g.Start.Determined
}

// Same reports whether both identities are established and name one group.
func (g Group) Same(other Group) bool {
	return g.Established() && other.Established() && g == other
}

// Different reports whether both identities are established and name different
// groups. It is not !Same: an unknown field is not an unequal one.
func (g Group) Different(other Group) bool {
	return g.Established() && other.Established() && g != other
}

func (g Group) String() string {
	return fmt.Sprintf("pid %d in %s, %s", g.NamespacePID, g.Namespace, g.Start)
}

// Witness is the task whose own state established that a group is running: a
// positive observation.
type Witness struct {
	// TID is the task's number in the reader's own pid namespace.
	TID int32

	// State is what that task was doing when it was read.
	State TaskState

	// Start is the witness's own birth, kept apart from the group's.
	Start admission.Start
}

// Established reports whether a witness was found at all.
func (w Witness) Established() bool { return w.TID > 0 && w.State.Nonterminal() }

func (w Witness) String() string {
	if !w.Established() {
		return "no task was witnessed running"
	}
	return fmt.Sprintf("task %d is in %s and %s", w.TID, w.State, w.Start)
}

// Interval is when a reading happened, [From, To], describing only that
// window. Both carry wall and monotonic readings, and travel with the record
// since the tasks are gone by the time anyone reads it.
type Interval struct {
	From time.Time
	To   time.Time
}

// Clock names what From and To were read from.
func (i Interval) Clock() string {
	return "the host's clock as time.Now reports it, wall against the Unix epoch with a monotonic reading"
}

func (i Interval) String() string {
	return fmt.Sprintf("read between %s and %s by %s",
		i.From.Format(time.RFC3339Nano), i.To.Format(time.RFC3339Nano), i.Clock())
}

// Operation is one read that did not answer, so a reading that established
// nothing says what stopped it.
type Operation struct {
	// What was being read, in the reader's own words.
	What string

	// Err is what the host said; nil for a refusal this code decided itself.
	Err error
}

func (o Operation) String() string {
	if o.Err == nil {
		return o.What
	}
	return fmt.Sprintf("%s: %v", o.What, o.Err)
}

// Liveness is what a focused reading established about an expected execution:
// observations about tasks and number holders, not about grants.
type Liveness uint8

const (
	// LivenessUnestablished is a reading that settled nothing. It is the zero
	// value, and always carries the failed operation or the bound hit.
	LivenessUnestablished Liveness = iota

	// LivenessRunning is a task of the expected group, authenticated against its
	// identity, in a state it had not exited from: the leader, or a sibling if the
	// leader exited.
	LivenessRunning

	// LivenessTerminated is a complete read of the group's task list with every
	// task exited (a zombie leader with nothing running, or all threads awaiting
	// a tracer). A list that lost a task mid-read does not support it: that task
	// could have cloned a sibling this reading never saw.
	LivenessTerminated

	// LivenessGone is a number holding no process, on a procfs that does not hide
	// processes; otherwise the absence is unestablished.
	LivenessGone

	// LivenessReplaced is a number held by an established identity other than the
	// expected one. Nothing about the new occupant is borrowed for the old.
	LivenessReplaced
)

func (l Liveness) String() string {
	switch l {
	case LivenessRunning:
		return "a task of it was witnessed running"
	case LivenessTerminated:
		return "every task of it had exited"
	case LivenessGone:
		return "its number holds no process"
	case LivenessReplaced:
		return "its number is held by a different execution"
	default:
		return "whether it is still running could not be established"
	}
}

// Execution is one focused reading of one expected thread group, with the
// question and the evidence: witness and state, the number's current
// identity, the interval, failed operations and cost.
type Execution struct {
	// Expected is the identity the caller recorded at admission.
	Expected Group

	// ObserverPID is the number looked at, in the reader's namespace.
	ObserverPID int32

	Liveness Liveness

	// Current is the number's identity now, zero where unread: compare with Same
	// and Different, never !=.
	Current Group

	// Witness is the task that established LivenessRunning; empty otherwise.
	Witness Witness

	// Observed is when this reading opened and closed.
	Observed Interval

	// Failed is every operation that did not answer, in order.
	Failed []Operation

	// Capped is whether the budget stopped the reading: a partial task list is not
	// an empty group.
	Capped bool

	// Budget and Spent are the operations allowed and used.
	Budget int
	Spent  int
}

// Evidence is what this reading found, as a sentence.
func (e Execution) Evidence() string {
	var detail string
	switch e.Liveness {
	case LivenessRunning:
		detail = fmt.Sprintf("%s, authenticated against %s", e.Witness, e.Expected)
	case LivenessTerminated:
		detail = fmt.Sprintf("every task of %s had exited", e.Expected)
	case LivenessGone:
		detail = fmt.Sprintf("no process holds pid %d and this procfs hides none", e.ObserverPID)
	case LivenessReplaced:
		detail = fmt.Sprintf("pid %d holds %s, and what was admitted is %s",
			e.ObserverPID, e.Current, e.Expected)
	default:
		detail = fmt.Sprintf("nothing established whether %s is still running", e.Expected)
	}

	parts := []string{detail, e.Observed.String()}
	if e.Capped {
		parts = append(parts, fmt.Sprintf("the reading stopped at its budget of %d operations", e.Budget))
	}
	for _, one := range e.Failed {
		parts = append(parts, one.String())
	}
	parts = append(parts, fmt.Sprintf("%d of %d operations", e.Spent, e.Budget))
	return strings.Join(parts, "; ")
}

// Inspect reads whether one expected execution is still running. root is the
// procfs mount, observerPID the group's number in the reader's namespace, and
// expected the identity recorded at admission. It never returns an error:
// every failure is part of the answer.
func Inspect(root string, observerPID int32, expected Group) (read Execution) {
	read = Execution{
		Expected:    expected,
		ObserverPID: observerPID,
		Budget:      InspectionBudget,
		Observed:    Interval{From: time.Now()},
	}
	// The interval closes on the return value, not a local copy.
	defer func() { read.Observed.To = time.Now() }()
	reading := &read

	if observerPID <= 0 {
		reading.failed("no number in the reader's own pid namespace names this execution", nil)
		return
	}

	// Without the expected identity neither authentication nor comparison is
	// possible, so nothing can be established.
	if !expected.Established() {
		reading.failed(fmt.Sprintf("the identity recorded for pid %d is not determined, "+
			"so no reading can establish that what is there now is the same execution", observerPID), nil)
		return
	}

	directory := filepath.Join(root, strconv.FormatInt(int64(observerPID), 10))
	reading.spend()
	// The directory is held open for the whole reading and files are opened
	// relative to it, so a pid reused mid-reading fails rather than reading the
	// new process. Whether it named the expected execution is the identity read's
	// job.
	held, err := os.OpenRoot(directory)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			reading.gone(root, observerPID)
			return
		}
		reading.failed(fmt.Sprintf("open %s", directory), err)
		return
	}
	defer func() { _ = held.Close() }()

	first, ok := reading.identify(held, directory)
	if !ok {
		return
	}
	reading.Current = first.Group

	switch {
	case first.Group.Different(expected):
		reading.Liveness = LivenessReplaced
		return
	case !first.Group.Same(expected):
		// Neither same nor different: a component was unestablished. The failed read,
		// or the missing value, is named on the reading.
		reading.failed(fmt.Sprintf("pid %d holds %s and what was admitted is %s, and the two "+
			"cannot be told apart or told together", observerPID, first.Group, expected), nil)
		return
	}

	witness, everyTaskExited, listed := reading.witness(held, directory, observerPID, first)

	// The group is re-read after the walk: it stops a reused number's live thread
	// certifying the old execution, and its thread count (after the walk) is what
	// the walk is reconciled against.
	second, ok := reading.identify(held, directory)
	if !ok {
		return
	}
	if !second.Group.Same(first.Group) {
		reading.Current = second.Group
		reading.failed(fmt.Sprintf("pid %d held %s when the reading opened and %s when it closed, "+
			"so the two readings do not agree about what is there",
			observerPID, first.Group, second.Group), nil)
		return
	}

	switch {
	case witness.Established():
		reading.Witness = witness
		reading.Liveness = LivenessRunning
	case everyTaskExited:
		reading.terminated(directory, listed, second.Threads)
	}
	return
}

// terminated decides whether a complete walk with every task exited
// establishes that the group ended. Task states are one-way, but a live task
// can create another, so the walk may miss a task: gone before read (the
// failed read unsettles the walk), or never listed (batched listing). The
// group's own task count, read after the walk, catches a count larger than
// the listing.
//
// This is not proof: the count is one observation, and a task gained while
// another is reaped between walk and count reconciles while hiding it. A live
// task must evade every observation here to be missed.
func (e *Execution) terminated(directory string, listed int, threads int32) {
	switch {
	case threads <= 0:
		e.failed(fmt.Sprintf("%s/status names no thread count, so the tasks this walk listed "+
			"cannot be reconciled against the tasks the group holds", directory), nil)
	case int(threads) > listed:
		e.failed(fmt.Sprintf("the group holds %d tasks and this walk listed %d, so it holds one "+
			"this reading never saw", threads, listed), nil)
	default:
		e.Liveness = LivenessTerminated
	}
}

// spend charges one procfs operation against the budget, reporting whether
// one was left.
func (e *Execution) spend() bool {
	if e.Spent >= e.Budget {
		e.Capped = true
		return false
	}
	e.Spent++
	return true
}

func (e *Execution) failed(what string, err error) {
	e.Failed = append(e.Failed, Operation{What: what, Err: err})
}

// gone decides what an absent pid directory means: gone only where this procfs
// does not hide processes (hidepid answers ENOENT for running ones).
func (e *Execution) gone(root string, pid int32) {
	e.spend()
	shown, err := ProcessesAreVisible(root)
	if err != nil {
		e.failed(fmt.Sprintf("pid %d has no directory, and whether this procfs would show one "+
			"could not be established", pid), err)
		return
	}
	if !shown {
		e.failed(fmt.Sprintf("pid %d has no directory, and this procfs hides processes from "+
			"this reader, so the absence is a refusal rather than an ending", pid), nil)
		return
	}
	e.Liveness = LivenessGone
}

// leaderReading is one reading of the group leader: identity, state, and the
// group's task count, taken together.
type leaderReading struct {
	Group Group
	State TaskState

	// Threads is the group's own task count from its status file; zero where the
	// line is missing, and zero is not a count.
	Threads int32
}

// identify reads the group identity of the leader through the held directory,
// with its state and its thread count.
func (e *Execution) identify(held *os.Root, directory string) (leaderReading, bool) {
	if !e.spend() {
		return leaderReading{}, false
	}
	stat, err := held.ReadFile("stat")
	if err != nil {
		e.failed(fmt.Sprintf("read %s/stat", directory), err)
		return leaderReading{}, false
	}
	_, startTime, state, err := parseStat(stat)
	if err != nil {
		e.failed(fmt.Sprintf("parse %s/stat", directory), err)
		return leaderReading{}, false
	}

	if !e.spend() {
		return leaderReading{}, false
	}
	status, err := held.ReadFile("status")
	if err != nil {
		e.failed(fmt.Sprintf("read %s/status", directory), err)
		return leaderReading{}, false
	}
	_, groupPID := parseGroupNumbering(status)
	if groupPID <= 0 {
		e.failed(fmt.Sprintf("%s/status names no thread group id in its own pid namespace", directory), nil)
		return leaderReading{}, false
	}

	if !e.spend() {
		return leaderReading{}, false
	}
	// The namespace link resolves to an nsfs inode, so it is read by path rather
	// than through the held handle; the final identity re-read covers the gap.
	namespace := namespaceOf(directory)
	if !namespace.Known() {
		e.failed(fmt.Sprintf("read %s/ns/pid", directory), nil)
		return leaderReading{}, false
	}

	start := admission.Indeterminate()
	if startTime != 0 {
		start = admission.Determinate(admission.BootTicks(startTime))
	}
	return leaderReading{
		Group:   Group{Namespace: namespace, NamespacePID: groupPID, Start: start},
		State:   TaskState(state),
		Threads: parseThreads(status),
	}, true
}

// witness looks for one task of the group that had not exited, and reports
// whether every listed task was read and had exited. The leader is its own
// witness unless it exited (pthread_exit leaves a zombie while workers serve);
// then siblings are walked.
//
// An unreadable candidate stops the "all exited" answer: a task listed and
// gone before being read was alive at listing and could have cloned a sibling
// the iterator never returns. Walking again only moves that window, so the
// listed count is returned for reconciliation in terminated instead.
func (e *Execution) witness(held *os.Root, directory string, leaderTID int32, leader leaderReading) (found Witness, everyTaskExited bool, listed int) {
	switch {
	case leader.State.Nonterminal():
		// The leader is its own witness; its birth is the group's.
		return Witness{TID: leaderTID, State: leader.State, Start: leader.Group.Start}, false, 0
	case !leader.State.Recognised():
		e.failed(fmt.Sprintf("%s/stat reports %s", directory, leader.State), nil)
		return Witness{}, false, 0
	}

	if !e.spend() {
		return Witness{}, false, 0
	}
	tasks, err := held.Open("task")
	if err != nil {
		e.failed(fmt.Sprintf("open %s/task", directory), err)
		return Witness{}, false, 0
	}
	defer func() { _ = tasks.Close() }()

	everyTaskExited = true
	var lost []int32
	for {
		if !e.spend() {
			return Witness{}, false, listed
		}
		// A batch at a time, so a many-threaded group costs its budget and no more.
		entries, err := tasks.ReadDir(taskBatch)
		for _, entry := range entries {
			tid, parseErr := strconv.ParseInt(entry.Name(), 10, 32)
			if parseErr != nil {
				continue
			}
			// Every entry counts toward the listing, the leader's included.
			listed++
			if int32(tid) == leaderTID {
				continue
			}
			candidate, outcome := e.candidate(held, directory, int32(tid))
			switch {
			case candidate.Established():
				return candidate, false, listed
			case outcome == taskLost:
				lost = append(lost, int32(tid))
				everyTaskExited = false
			case outcome != taskExited:
				everyTaskExited = false
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			e.failed(fmt.Sprintf("list %s/task", directory), err)
			return Witness{}, false, listed
		}
	}

	// A lost candidate is read once more: if it answers it is a witness; if not,
	// it has exited.
	for _, tid := range lost {
		if candidate, _ := e.candidate(held, directory, tid); candidate.Established() {
			return candidate, false, listed
		}
	}
	return Witness{}, everyTaskExited, listed
}

// taskOutcome is what reading one candidate task settled, for a candidate that
// did not become the witness.
type taskOutcome uint8

const (
	// taskUnreadable is a candidate whose state could not be interpreted: neither
	// running nor exited, so the group cannot be called terminated.
	taskUnreadable taskOutcome = iota
	// taskExited is a candidate read in a state it had exited from.
	taskExited
	// taskLost is a candidate listed and gone before read: it exited, but it may
	// have cloned first, so it unsettles the walk.
	taskLost
	// taskRunning is a live candidate that could not be authenticated as the
	// expected group's.
	taskRunning
)

// candidate reads one task and decides whether it is the witness: it must not
// have exited and its own group reading must match the expected one, since
// thread ids are reused.
func (e *Execution) candidate(held *os.Root, directory string, tid int32) (Witness, taskOutcome) {
	if !e.spend() {
		return Witness{}, taskUnreadable
	}
	at := filepath.Join("task", strconv.FormatInt(int64(tid), 10))
	stat, err := held.ReadFile(filepath.Join(at, "stat"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Recorded as a failed operation: the only record of why the walk could not
			// account for every task.
			e.failed(fmt.Sprintf("read %s/%s/stat", directory, at), err)
			return Witness{}, taskLost
		}
		e.failed(fmt.Sprintf("read %s/%s/stat", directory, at), err)
		return Witness{}, taskUnreadable
	}
	_, startTime, state, err := parseStat(stat)
	if err != nil {
		e.failed(fmt.Sprintf("parse %s/%s/stat", directory, at), err)
		return Witness{}, taskUnreadable
	}
	switch task := TaskState(state); {
	case task.Terminal():
		return Witness{}, taskExited
	case !task.Recognised():
		e.failed(fmt.Sprintf("%s/%s/stat reports %s", directory, at, task), nil)
		return Witness{}, taskUnreadable
	default:
		if !e.authenticate(held, directory, at, tid) {
			return Witness{}, taskRunning
		}
		start := admission.Indeterminate()
		if startTime != 0 {
			start = admission.Determinate(admission.BootTicks(startTime))
		}
		return Witness{TID: tid, State: task, Start: start}, taskRunning
	}
}

// authenticate reports whether one task belongs to the expected group: its
// thread group id (reader's numbering and its own) and pid namespace must all
// agree. It uses NStgid, never NSpid, which names the thread.
func (e *Execution) authenticate(held *os.Root, directory, at string, tid int32) bool {
	if !e.spend() {
		return false
	}
	status, err := held.ReadFile(filepath.Join(at, "status"))
	if err != nil {
		e.failed(fmt.Sprintf("read %s/%s/status", directory, at), err)
		return false
	}
	leader, groupPID := parseGroupNumbering(status)
	if leader != e.ObserverPID || groupPID != e.Expected.NamespacePID {
		e.failed(fmt.Sprintf("task %d is running and belongs to pid %d, %d in its own namespace, "+
			"which is not the group that was admitted", tid, leader, groupPID), nil)
		return false
	}

	if !e.spend() {
		return false
	}
	namespace := namespaceOf(filepath.Join(directory, at))
	if !namespace.Known() {
		e.failed(fmt.Sprintf("read %s/%s/ns/pid", directory, at), nil)
		return false
	}
	if namespace != e.Expected.Namespace {
		e.failed(fmt.Sprintf("task %d is running in %s, which is not the namespace that was admitted",
			tid, namespace), nil)
		return false
	}
	return true
}

// parseGroupNumbering reads which group a task belongs to from its status
// file: Tgid (reader's numbering) and NStgid (innermost namespace). Never
// NSpid, which names the thread on a sibling. Neither line is unknown, not
// zero.
func parseGroupNumbering(status []byte) (leader int32, groupPID int32) {
	for line := range strings.Lines(string(status)) {
		if rest, found := strings.CutPrefix(line, "Tgid:"); found {
			if value, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 32); err == nil {
				leader = int32(value)
			}
			continue
		}
		if rest, found := strings.CutPrefix(line, "NStgid:"); found {
			fields := strings.Fields(rest)
			if len(fields) == 0 {
				continue
			}
			if value, err := strconv.ParseInt(fields[len(fields)-1], 10, 32); err == nil {
				groupPID = int32(value)
			}
		}
	}
	return leader, groupPID
}

// ProcessesAreVisible reports whether an absent pid directory under this
// procfs is evidence that no such process exists. hidepid levels 2 and 4
// (invisible, ptraceable) hide other processes and answer ENOENT for running
// ones; 0 and 1 do not (1 answers EACCES). Read from the mount table this
// procfs publishes; none published is an error, never a permissive default.
func ProcessesAreVisible(root string) (bool, error) {
	root = filepath.Clean(root)
	// A directory below the mount point is answered by its mount.
	table, at, err := mountTable(root)
	if err != nil {
		return false, err
	}

	for line := range strings.Lines(string(table)) {
		fields := strings.Fields(line)
		// id parent major:minor root mountpoint options [optional...] - fstype source superopts
		separator := slices.Index(fields, "-")
		if separator < 0 || separator+3 > len(fields) || separator < mountinfoOptions+1 {
			continue
		}
		if fields[mountinfoMountPoint] != at || fields[separator+1] != "proc" {
			continue
		}
		// hidepid is read from both option fields, so reporting it per mount cannot
		// hide it.
		for _, options := range []string{fields[mountinfoOptions], fields[separator+3]} {
			for _, option := range strings.Split(options, ",") {
				value, found := strings.CutPrefix(option, "hidepid=")
				if !found {
					continue
				}
				switch value {
				case "2", "4", "invisible", "ptraceable":
					return false, nil
				}
			}
		}
		return true, nil
	}
	return false, fmt.Errorf("%s publishes no proc mount at %s, so what an absent pid directory "+
		"there means is not established", filepath.Join(root, "self", "mountinfo"), at)
}

// mountinfoMountPoint and mountinfoOptions are proc_pid_mountinfo(5)'s
// zero-based field numbers.
const (
	mountinfoMountPoint = 4
	mountinfoOptions    = 5
)

// mountTable reads the mount table a procfs root publishes about itself and
// says which mount point the root sits at, walking up from a root below the
// mount point.
func mountTable(root string) (content []byte, at string, err error) {
	for directory := root; ; directory = filepath.Dir(directory) {
		content, err = os.ReadFile(filepath.Join(directory, "self", "mountinfo"))
		if err == nil {
			return content, directory, nil
		}
		if parent := filepath.Dir(directory); parent == directory {
			return nil, root, fmt.Errorf("no mount table under %s: %w", root, err)
		}
	}
}
