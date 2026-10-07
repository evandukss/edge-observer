// Package extension supervises extensions: a user's own executables the
// observer starts and feeds its records to, over the protocol in
// contract/extension/PROTOCOL.md. One process per extension sees every
// connection; each start of it is a generation. The package owns the process,
// the framing, the deadlines, retirement and restart, standard error and the
// derived records an extension emits. What an exchange is, which of its fields
// an extension is given and what an answer may change belong to processing.
package extension

import "time"

// Protocol is the protocol version, matched exactly in start and ready.
const Protocol = "observer.extension/1"

// DerivedVersion is the version of every line the observer writes to an
// extension's derived file.
const DerivedVersion = "observer.derived/1"

// Effects labels what an extension changes and emits: its own declaration,
// which the observer checks for shape and attribution and never for truth.
const Effects = "extension_declared_not_observer_enforced"

// The bounds, each the protocol document's (Bounds), and each disclosed in
// start under the name in its comment. Durations are read from the Clock.
const (
	// StartupBound is startup_ms: from start written to ready read.
	StartupBound = 5 * time.Second
	// FrameBytesToExtension is frame_bytes_to_extension: the longest line the
	// observer writes, line feed included. A longer exchange skips as too_large.
	FrameBytesToExtension = 32 << 20
	// FrameBytesFromExtension is frame_bytes_from_extension: the longest line
	// an extension may write, line feed included.
	FrameBytesFromExtension = 4 << 20
	// InFlight is in_flight: exchanges outstanding at one extension at once.
	InFlight = 4096
	// HealthyInterval is healthy_ms: a generation up this long returns the
	// backoff to BackoffMin.
	HealthyInterval = 60 * time.Second
	// BackoffMin and BackoffMax are backoff_min_ms and backoff_max_ms: the wait
	// before a restart doubles from the first to the second.
	BackoffMin = 100 * time.Millisecond
	BackoffMax = 5 * time.Second
	// TerminationGrace is termination_grace_ms: from shutdown or SIGTERM to the
	// next step.
	TerminationGrace = 2 * time.Second
	// StderrLinesPerSecond and StderrLineBytes are stderr_lines_per_second and
	// stderr_line_bytes.
	StderrLinesPerSecond = 10
	StderrLineBytes      = 1024
	// DerivedLinesPerSecond is derived_lines_per_second, a bucket that refills
	// at this rate and holds one second's worth.
	DerivedLinesPerSecond = 1000
	// DerivedFloodSeconds is derived_flood_seconds: consecutive seconds with a
	// rate refusal before the generation is retired as flood.
	DerivedFloodSeconds = 10
	// DerivedQueueBytes is derived_queue_bytes: an extension's derived records
	// waiting to be written.
	DerivedQueueBytes = 1 << 20
	// DerivedSources is derived_sources: the source ids one derived record may
	// name.
	DerivedSources = 1024
	// ReasonBytes is reason_bytes: a failed result's reason is cut here.
	ReasonBytes = 256
)

// WaitingBytes is waiting_bytes for one of extensions extensions over a shared
// allowance of intakeBytes: the charge the connections waiting on it may hold
// in that allowance, each read when its call is made (Call.Bytes), so that all
// of them together are admitted within half the allowance.
func WaitingBytes(intakeBytes int64, extensions int) int64 {
	if extensions <= 0 || intakeBytes <= 0 {
		return 0
	}
	return intakeBytes / (2 * int64(extensions))
}

// The outcomes of one exchange at one extension. Each exchange has exactly
// one at each extension.
const (
	Unchanged = "unchanged"
	Changed   = "changed"
	Failed    = "failed"
)

// The reasons an exchange fails at an extension, from the protocol. The first
// six are causes of retirement too; StartupTimeout and StartFailed are causes
// only, since a generation that never answered ready was sent no exchange.
const (
	Timeout        = "timeout"
	Crash          = "crash"
	ProtocolError  = "protocol"
	OversizedFrame = "oversized_frame"
	UnknownID      = "unknown_id"
	Flood          = "flood"
	StartupTimeout = "startup_timeout"
	// StartFailed is a process that could not be started: running the
	// command failed.
	StartFailed = "start_failed"

	Malformed      = "malformed"
	NotGiven       = "not_given"
	ReadOnly       = "read_only"
	RemovedContent = "removed_content"
	Excluded       = "excluded"
	Declined       = "declined"
	NoRoom         = "no_room"
	Unavailable    = "unavailable"
	Busy           = "busy"
	TooLarge       = "too_large"
	Withdrawn      = "withdrawn"
)

// The reasons a derived record is refused, from the protocol.
const (
	DerivedMalformed     = "malformed"
	DerivedUnknownSource = "unknown_source"
	DerivedRate          = "rate"
	DerivedQueueFull     = "queue_full"
	DerivedStopped       = "stopped"
	DerivedWriteFailed   = "write_failed"
)

// Clock is what supervision reads time from: exchange deadlines, the start-up
// bound, backoff, the healthy interval, the termination grace, and the derived
// and standard error rates. A test supplies its own to control them.
type Clock interface {
	// Now is the clock's current reading.
	Now() time.Time
	// NewTimer returns a timer that delivers the clock's reading on C once,
	// when d has passed on this clock. A d of zero or less is due at once.
	NewTimer(d time.Duration) Timer
}

// Timer is one pending reading of a Clock.
type Timer interface {
	// C delivers the reading once, when the timer is due. It is buffered, so
	// a timer nobody receives from never blocks the clock.
	C() <-chan time.Time
	// Stop prevents a timer that has not fired from firing, and reports
	// whether it did that.
	Stop() bool
}

// System is the host's clock.
func System() Clock { return systemClock{} }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) NewTimer(d time.Duration) Timer { return systemTimer{time.NewTimer(d)} }

type systemTimer struct{ timer *time.Timer }

func (t systemTimer) C() <-chan time.Time { return t.timer.C }

func (t systemTimer) Stop() bool { return t.timer.Stop() }

// EventKind is what an Event reports.
type EventKind string

const (
	// Started is a generation's process started, before start is written.
	// PID is its process id, which is also its process group id.
	Started EventKind = "started"
	// Ready is a generation that answered ready.
	Ready EventKind = "ready"
	// Retired is a generation retired under Cause. Backoff is the wait before
	// the next generation starts, or zero where none will.
	Retired EventKind = "retired"
	// Exited is a generation's process exited and reaped, after its process
	// group was killed: nothing of that generation is left running unless it
	// left its process group.
	Exited EventKind = "exited"
	// Stderr is one line of standard error copied into the log: Line, escaped
	// and cut at StderrLineBytes, with Cut where it was cut.
	Stderr EventKind = "stderr"
	// Reason is a failed result's reason copied into the log: Line, escaped
	// and cut at ReasonBytes, with Cut where it was cut.
	Reason EventKind = "reason"
)

// Event is one step in an extension's supervision, reported as it happens on
// the supervisor's own goroutine, so whatever receives it must not block. The
// observer logs Stderr and Reason; a test reads the rest.
type Event struct {
	Extension  string
	Generation uint64
	Kind       EventKind
	// At is the clock's reading when it happened.
	At      time.Time
	PID     int
	Cause   string
	Backoff time.Duration
	Line    string
	Cut     bool
}
