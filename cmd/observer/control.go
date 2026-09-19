package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/policy"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/spool"
)

// Everything a session keeps in the configured directory, beside its spools.
const (
	// pidName is the file a running session holds locked for its whole life.
	pidName = "observer.pid"

	// controlName is where a command leaves a request and a session its answer.
	// Nothing listens: a request is a file plus a signal.
	controlName = "control"

	// sessionsName holds one directory per session: its spool and sealed account.
	sessionsName = "sessions"

	// sealedName is the account a session writes once, when it ends.
	sealedName = "account.json"

	// lastName is the most recent session to seal, from which the next measures
	// its capture gap.
	lastName = "last-sealed.json"
)

// recordVersion is the shape of every log record. A reader refuses a version
// it does not know.
const recordVersion = 1

// errAlreadyRunning refuses a second start; errNotRunning is what a command
// finds when no session runs.
var (
	errAlreadyRunning = errors.New("an observer is already running for this configuration")
	errNotRunning     = errors.New("no observer is running for this configuration")
)

// errNeverSealed is a session directory holding a spool and no sealed account:
// a capture nothing accounts for. errNotASession is a directory holding
// neither.
var (
	errNeverSealed = errors.New("this session never sealed: its spool is here and no account was written beside it")
	errNotASession = errors.New("this directory holds no sealed account and no spool, so it is no session's directory")
)

// lock is the pid file a session holds for its whole life, as an advisory
// lock rather than the file's existence: a file left by a killed session is
// retaken, and two racing starts cannot both take it.
type lock struct{ file *os.File }

// acquire takes the pid file for this session, or refuses naming the session
// that holds it.
func acquire(directory string) (*lock, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("make %s: %w", directory, err)
	}
	path := filepath.Join(directory, pidName)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		content, _ := os.ReadFile(path)
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s holds %s", errAlreadyRunning, describeHolder(content), path)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	if err := file.Truncate(0); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("clear %s: %w", path, err)
	}
	return &lock{file: file}, nil
}

// record writes which process and session hold the lock, once it has activated.
func (l *lock) record(pid int, session string) error {
	if err := l.file.Truncate(0); err != nil {
		return err
	}
	_, err := l.file.WriteAt([]byte(fmt.Sprintf("%d %s\n", pid, session)), 0)
	return err
}

// release empties the pid file and gives up the lock.
func (l *lock) release() {
	if l == nil || l.file == nil {
		return
	}
	_ = l.file.Truncate(0)
	_ = l.file.Close()
	l.file = nil
}

func describeHolder(content []byte) string {
	fields := strings.Fields(string(content))
	if len(fields) != 2 {
		return "a session that has not finished starting"
	}
	return fmt.Sprintf("pid %s, session %s", fields[0], fields[1])
}

// holder is the process and session holding the pid file, or errNotRunning.
// It asks the lock, not the file's content.
func holder(directory string) (int, string, error) {
	path := filepath.Join(directory, pidName)
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, "", fmt.Errorf("%w: %s does not exist", errNotRunning, path)
	}
	if err != nil {
		return 0, "", fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err == nil {
		return 0, "", fmt.Errorf("%w: nothing holds %s", errNotRunning, path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, "", fmt.Errorf("read %s: %w", path, err)
	}
	fields := strings.Fields(string(content))
	if len(fields) != 2 {
		return 0, "", fmt.Errorf("a session holds %s and has not activated yet, so it answers nothing", path)
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, "", fmt.Errorf("%s names %q as its process: %w", path, fields[0], err)
	}
	return pid, fields[1], nil
}

// newIdentity is a random identity for a session or a request.
func newIdentity() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// A failed random source is not papered over with a colliding counter.
		panic(fmt.Sprintf("read the system's random source: %v", err))
	}
	return hex.EncodeToString(raw[:])
}

// ask leaves one request for the running session, signals it, and waits up to
// within for the answer.
func ask(directory, kind string, body []byte, within time.Duration) ([]byte, error) {
	pid, _, err := holder(directory)
	if err != nil {
		return nil, err
	}
	control := filepath.Join(directory, controlName)
	if err := os.MkdirAll(control, 0o700); err != nil {
		return nil, fmt.Errorf("make %s: %w", control, err)
	}
	nonce := newIdentity()
	asked := filepath.Join(control, nonce+".request")
	answered := filepath.Join(control, nonce+".answer")
	if err := place(asked, append([]byte(kind+"\n"), body...)); err != nil {
		return nil, err
	}
	if err := syscall.Kill(pid, syscall.SIGUSR1); err != nil {
		_ = os.Remove(asked)
		return nil, fmt.Errorf("signal pid %d: %w", pid, err)
	}
	for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		content, err := os.ReadFile(answered)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		_ = os.Remove(answered)
		if err != nil {
			return nil, fmt.Errorf("read the answer: %w", err)
		}
		return content, nil
	}
	_ = os.Remove(asked)
	return nil, fmt.Errorf("pid %d did not answer %s within %s", pid, kind, within)
}

// place writes a file whole, via a rename, so a poller never reads half.
func place(path string, content []byte) error {
	temporary := path + ".writing"
	if err := os.WriteFile(temporary, content, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", temporary, err)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("place %s: %w", path, err)
	}
	return nil
}

// controller answers the requests left for a running session.
type controller struct {
	directory string
	answer    func(kind string, body []byte) ([]byte, error)
}

// serve answers every waiting request and says how many. A failure is written
// as an error answer, so the asker learns why instead of timing out.
func (c *controller) serve() int {
	control := filepath.Join(c.directory, controlName)
	entries, err := os.ReadDir(control)
	if err != nil {
		return 0
	}
	answered := 0
	for _, entry := range entries {
		nonce, isRequest := strings.CutSuffix(entry.Name(), ".request")
		if !isRequest {
			continue
		}
		asked := filepath.Join(control, entry.Name())
		request, err := os.ReadFile(asked)
		_ = os.Remove(asked)
		if err != nil {
			continue
		}
		// The kind is the first line, and whatever follows it is the body.
		kind, body, _ := strings.Cut(string(request), "\n")
		content, err := c.answer(strings.TrimSpace(kind), []byte(body))
		if err != nil {
			content, _ = json.Marshal(map[string]string{"error": err.Error()})
		}
		if place(filepath.Join(control, nonce+".answer"), content) == nil {
			answered++
		}
	}
	return answered
}

// logger writes log records to the configured file, plus standard output in
// the foreground, or to standard output alone where configured.
type logger struct {
	mutex sync.Mutex
	file  *os.File
	out   io.Writer
}

func openLog(settings policy.Settings, foreground bool, stdout io.Writer) (*logger, error) {
	if settings.Log == policy.Stdout {
		if !foreground {
			return nil, errors.New("the log is configured as stdout, and a detached observer has no standard " +
				"output: configure a file, or run it in the foreground")
		}
		return &logger{out: stdout}, nil
	}
	if err := os.MkdirAll(filepath.Dir(settings.Log), 0o750); err != nil {
		return nil, fmt.Errorf("make the log's directory: %w", err)
	}
	file, err := os.OpenFile(settings.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open the log: %w", err)
	}
	opened := &logger{file: file}
	if foreground {
		opened.out = stdout
	}
	return opened, nil
}

// write puts one record on one line wherever the log goes. A failed
// destination is reported, and the other still written.
func (l *logger) write(record any) error {
	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode a log record: %w", err)
	}
	line = append(line, '\n')
	l.mutex.Lock()
	defer l.mutex.Unlock()
	var failed []error
	if l.file != nil {
		if _, err := l.file.Write(line); err != nil {
			failed = append(failed, fmt.Errorf("write the log file: %w", err))
		}
	}
	if l.out != nil {
		if _, err := l.out.Write(line); err != nil {
			failed = append(failed, fmt.Errorf("write standard output: %w", err))
		}
	}
	return errors.Join(failed...)
}

func (l *logger) close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

// targetCoverage is one target in a log record: what it selected, what the
// kernel confirms attached, and whose grant is held, or why that is unknown.
type targetCoverage struct {
	Number      int     `json:"number"`
	Name        string  `json:"name"`
	Selected    int     `json:"selected"`
	Attached    int     `json:"attached"`
	Partial     int     `json:"partial"`
	Covered     *int    `json:"covered"`
	Ended       *int    `json:"ended"`
	Unknown     *int    `json:"unknown"`
	NotKnownWhy string  `json:"not_known_why,omitempty"`
	Unresolved  string  `json:"unresolved,omitempty"`
	Unsupported int     `json:"unsupported"`
	Denied      int     `json:"denied"`
	Mode        string  `json:"mode"`
	Answers     answers `json:"answers"`
}

type answers struct {
	Existing bool `json:"existing"`
	Future   bool `json:"future"`
}

// coverageOf is each target's coverage in an account.
func coverageOf(a account.Account) []targetCoverage {
	outcomes := make(map[int32]attachment.Outcome, len(a.Processes))
	for _, one := range a.Processes {
		outcomes[one.PID] = one.Outcome
	}
	byTarget := make(map[string]account.TargetCoverage)
	if a.Admissions != nil {
		for _, one := range a.Admissions.ByTarget {
			byTarget[one.Target] = one
		}
	}

	found := make([]targetCoverage, 0, len(a.Targets))
	for _, target := range a.Targets {
		one := targetCoverage{
			Number: target.Number, Name: target.Name, Mode: target.Mode,
			Selected:   len(target.Roots) + len(target.Descendants),
			Unresolved: target.Unresolved, Unsupported: len(target.Unsupported), Denied: len(target.Denied),
			Answers: answers{Existing: target.Answers.Existing, Future: target.Answers.Future},
		}
		for _, p := range append(append([]account.Instance{}, target.Roots...), target.Descendants...) {
			switch outcomes[p.PID] {
			case attachment.Attached:
				one.Attached++
			case attachment.Partial, attachment.Unconfirmed:
				one.Partial++
			}
		}
		switch {
		case a.Admissions == nil:
			one.NotKnownWhy = "no grant was read for this record"
		case a.Admissions.Unavailable != "":
			one.NotKnownWhy = a.Admissions.Unavailable
		default:
			counts := byTarget[target.Name]
			one.Covered, one.Ended, one.Unknown = &counts.Covered, &counts.Ended, &counts.Unknown
		}
		found = append(found, one)
	}
	return found
}

// features is what was asked of this session against what it holds.
type features struct {
	Requested probe.Capability `json:"requested"`
	Available probe.Capability `json:"available"`
}

// follows is the session this one follows and the unobserved gap between.
type follows struct {
	Session string    `json:"session"`
	Sealed  time.Time `json:"sealed"`
	Gap     string    `json:"gap"`
}

// activation is the record written once activation has succeeded: probes
// placed, grants written, capabilities dropped and posture read back. It
// states the observer's state rather than a bare word to match.
type activation struct {
	Record   string           `json:"record"`
	Version  int              `json:"version"`
	Session  string           `json:"session"`
	PID      int              `json:"pid"`
	At       time.Time        `json:"at"`
	Policy   account.Policy   `json:"policy"`
	Features features         `json:"features"`
	Capture  string           `json:"capturing"`
	Coverage []targetCoverage `json:"coverage"`
	Follows  *follows         `json:"follows,omitempty"`
}

func activated(session string, pid int, at time.Time, a account.Account) activation {
	available := probe.Capability{}
	if a.Capability != nil {
		available = *a.Capability
	}
	return activation{
		Record: "activation-completed", Version: recordVersion, Session: session, PID: pid, At: at,
		Policy: a.Policy, Features: features{Requested: a.Build, Available: available},
		Capture: a.Capturing, Coverage: coverageOf(a),
	}
}

// state restates the session's state on a cadence, so an old activation record
// cannot stand for current health.
type state struct {
	Record   string            `json:"record"`
	Version  int               `json:"version"`
	Session  string            `json:"session"`
	At       time.Time         `json:"at"`
	Policy   account.Policy    `json:"policy"`
	Coverage []targetCoverage  `json:"coverage"`
	Loss     *account.Loss     `json:"loss,omitempty"`
	Admitted *account.Admitted `json:"admitted,omitempty"`
	Spool    *spool.Stats      `json:"spool,omitempty"`
	Changes  []string          `json:"changes"`
}

func stated(session string, at time.Time, now, before account.Account) state {
	record := state{
		Record: "state", Version: recordVersion, Session: session, At: at, Policy: now.Policy,
		Coverage: coverageOf(now), Loss: now.Loss, Admitted: now.Admitted, Spool: now.Spool,
		Changes: changes(before, now),
	}
	return record
}

// changes is what moved since the previous record, in terms an operator acts
// on: a target whose coverage went to nothing, a loss, a spool that began to
// drop.
func changes(before, now account.Account) []string {
	found := []string{}
	was := make(map[string]int)
	for _, one := range coverageOf(before) {
		if one.Covered != nil {
			was[one.Name] = *one.Covered
		}
	}
	for _, one := range coverageOf(now) {
		if one.Covered == nil {
			found = append(found, fmt.Sprintf("target %d (%s): coverage is not known: %s", one.Number, one.Name, one.NotKnownWhy))
			continue
		}
		if previous, known := was[one.Name]; known && previous > 0 && *one.Covered == 0 {
			found = append(found, fmt.Sprintf("target %d (%s): coverage ended and has not resumed; no grant it "+
				"made is held", one.Number, one.Name))
		}
	}
	if now.Loss != nil && before.Loss != nil && now.Loss.Known && before.Loss.Known {
		if dropped := now.Loss.Dropped - before.Loss.Dropped; dropped > 0 {
			found = append(found, fmt.Sprintf("%d events the kernel could not buffer since the last record", dropped))
		}
		if unmatched := now.Loss.Unmatched - before.Loss.Unmatched; unmatched > 0 {
			found = append(found, fmt.Sprintf("%d returns with no entry recorded since the last record", unmatched))
		}
	}
	if now.Loss != nil && !now.Loss.Known {
		found = append(found, "what the capture lost is not known: "+now.Loss.Why)
	}
	if now.Spool != nil && before.Spool != nil {
		if dropped := now.Spool.Dropped - before.Spool.Dropped; dropped > 0 {
			found = append(found, fmt.Sprintf("the spool dropped %d records at its bound since the last record", dropped))
		}
	}
	return found
}

// failedStart is the record a start that did not activate leaves.
type failedStart struct {
	Record  string    `json:"record"`
	Version int       `json:"version"`
	Session string    `json:"session"`
	At      time.Time `json:"at"`
	Error   string    `json:"error"`
}

func startFailed(session string, at time.Time, err error) failedStart {
	return failedStart{Record: "start-failed", Version: recordVersion, Session: session, At: at, Error: err.Error()}
}

// stopped is the record a session leaves as it ends: whether it sealed, where
// its account is, and why not where it did not.
type stopped struct {
	Record   string    `json:"record"`
	Version  int       `json:"version"`
	Session  string    `json:"session"`
	At       time.Time `json:"at"`
	Sealed   bool      `json:"sealed"`
	Complete bool      `json:"complete"`
	Account  string    `json:"account,omitempty"`
	Error    string    `json:"error,omitempty"`

	// Contract is where the contract-form account was sealed; ContractError why
	// not.
	Contract      string `json:"contract,omitempty"`
	ContractError string `json:"contract_error,omitempty"`

	// LogFailures is how many records could not be written to the log. The
	// account holds what they would have restated.
	LogFailures int `json:"log_failures"`
}
