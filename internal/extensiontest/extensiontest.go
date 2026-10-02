// Package extensiontest is what tests of extensions run: a cooperative
// extension, served by the test binary itself when a test names it as an
// extension's command, and a clock a test moves by hand.
//
// A test package whose tests run this extension has a TestMain that, where
// Requested reports true, exits with the status Serve returns before running
// any test, and names it with Command. Nothing here is the observer's: the extension
// knows the protocol only from contract/extension/PROTOCOL.md.
package extensiontest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/evandukss/edge-observer/extension"
	"golang.org/x/sys/unix"
)

// Argument is the first argument that makes a test binary serve the
// extension, followed by its Config as JSON.
const Argument = "observer-test-extension"

// Config is what one test extension does. The zero value answers ready, then
// unchanged to every exchange, and exits at shutdown or end of input.
type Config struct {
	// Changes answers every eligible exchange changed with these
	// replacements, by field. Empty answers unchanged.
	Changes map[string]json.RawMessage `json:"changes,omitempty"`
	// ChangeExcluded answers excluded exchanges with Changes too.
	ChangeExcluded bool `json:"change_excluded,omitempty"`
	// Summary emits one derived record at session_ending citing every id this
	// generation received, in the order received.
	Summary bool `json:"summary,omitempty"`
	// DerivedSizeFile names a file a test writes a decimal size into. On each
	// exchange, where the file holds a positive size, the extension emits one
	// derived record citing that exchange whose payload pads to that many
	// bytes, then empties the file, so each size written is emitted once.
	DerivedSizeFile string `json:"derived_size_file,omitempty"`
	// ExitBeforeReady makes every generation numbered at most this exit at
	// once, status 1, without answering ready.
	ExitBeforeReady int `json:"exit_before_ready,omitempty"`
	// ExitOnExchange makes a generation that answered ready exit, status 1, on
	// the first exchange it is sent.
	ExitOnExchange bool `json:"exit_on_exchange,omitempty"`
	// Received names a file every message received is appended to, one line
	// each, prefixed with the generation.
	Received string `json:"received,omitempty"`
	// Log is the observer's log. At start and at its first exchange the
	// extension appends to Witness one line saying whether the log then held
	// an activation record listing this extension.
	Log     string `json:"log,omitempty"`
	Witness string `json:"witness,omitempty"`

	// Report names a file the extension writes once, at start, with what it
	// holds: its pid and process group, its core limit, its parent-death
	// signal, its out-of-memory score, its open descriptors, its capability
	// sets and no_new_privs, and Child's pid.
	Report string `json:"report,omitempty"`
	// NoReady never answers ready.
	NoReady bool `json:"no_ready,omitempty"`
	// HoldInput names a file: after answering ready the extension reads
	// nothing more until it exists.
	HoldInput string `json:"hold_input,omitempty"`
	// NeverAnswer reads exchanges and answers none.
	NeverAnswer bool `json:"never_answer,omitempty"`
	// HoldTarget holds the answer to an exchange whose request target
	// contains it until Release exists, answering others at once.
	HoldTarget string `json:"hold_target,omitempty"`
	Release    string `json:"release,omitempty"`
	// IgnoreTerm ignores SIGTERM; HangOnShutdown goes on running after
	// shutdown and the end of its input.
	IgnoreTerm     bool `json:"ignore_term,omitempty"`
	HangOnShutdown bool `json:"hang_on_shutdown,omitempty"`
	// Child starts one process in the extension's process group, which
	// ignores SIGTERM and sleeps until killed.
	Child bool `json:"child,omitempty"`
	// Sleep is that child: it ignores SIGTERM and sleeps.
	Sleep bool `json:"sleep,omitempty"`
	// StderrLines lines of StderrLineBytes bytes each are written to
	// standard error at start, before ready.
	StderrLines     int `json:"stderr_lines,omitempty"`
	StderrLineBytes int `json:"stderr_line_bytes,omitempty"`
}

// Command is the argument vector that runs binary, a test binary whose
// TestMain serves this extension, as an extension doing c.
func Command(binary string, c Config) []string {
	// Config holds strings, numbers, booleans and raw JSON its author wrote,
	// so it always encodes.
	encoded, _ := json.Marshal(c)
	return []string{binary, Argument, string(encoded)}
}

// Requested reports whether this process was started to serve the extension.
func Requested() bool { return len(os.Args) == 3 && os.Args[1] == Argument }

// Serve runs the extension over standard input and output and returns its
// exit status.
func Serve() int {
	var c Config
	if err := json.Unmarshal([]byte(os.Args[2]), &c); err != nil {
		fmt.Fprintln(os.Stderr, "test extension: configuration:", err)
		return 2
	}
	return serve(c, os.Stdin, os.Stdout)
}

type message struct {
	Type       string `json:"type"`
	Protocol   string `json:"protocol"`
	Extension  string `json:"extension"`
	Generation string `json:"generation"`
	ID         string `json:"id"`
	Output     struct {
		State string `json:"state"`
	} `json:"output"`
	Exchange struct {
		Request struct {
			Message struct {
				Target string `json:"target"`
			} `json:"message"`
		} `json:"request"`
	} `json:"exchange"`
}

func serve(c Config, in *os.File, out *os.File) int {
	if c.IgnoreTerm || c.Sleep {
		signal.Ignore(syscall.SIGTERM)
	}
	if c.Sleep {
		select {}
	}
	lines := bufio.NewReaderSize(in, 1<<16)
	var writing sync.Mutex
	writer := bufio.NewWriter(out)
	send := func(v any) {
		encoded, _ := json.Marshal(v)
		writing.Lock()
		defer writing.Unlock()
		_, _ = writer.Write(append(encoded, '\n'))
		_ = writer.Flush()
	}
	var ids []string
	var name, generation string
	exchanges := 0
	held := &holding{release: c.Release, answer: func(id string) {
		send(map[string]string{"type": "result", "id": id, "outcome": "unchanged"})
	}}
	for {
		line, err := lines.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			if c.HangOnShutdown {
				select {}
			}
			return 0
		}
		var m message
		if json.Unmarshal(line, &m) != nil {
			fmt.Fprintln(os.Stderr, "test extension: unreadable message")
			return 2
		}
		if m.Type == "start" {
			name, generation = m.Extension, m.Generation
		}
		if c.Received != "" {
			appendLine(c.Received, generation+" "+strings.TrimRight(string(line), "\n"))
		}
		switch m.Type {
		case "start":
			if n, _ := strconv.Atoi(generation); n <= c.ExitBeforeReady {
				return 1
			}
			witness(c, name, "start")
			for range c.StderrLines {
				fmt.Fprintln(os.Stderr, strings.Repeat("e", c.StderrLineBytes))
			}
			if c.Report != "" {
				report(c)
			}
			if c.NoReady {
				continue
			}
			send(map[string]string{"type": "ready", "protocol": m.Protocol})
			for c.HoldInput != "" {
				if _, err := os.Stat(c.HoldInput); err == nil {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
		case "exchange":
			exchanges++
			if exchanges == 1 {
				witness(c, name, "exchange")
			}
			if c.ExitOnExchange {
				return 1
			}
			ids = append(ids, m.ID)
			if c.NeverAnswer {
				continue
			}
			if c.HoldTarget != "" && strings.Contains(m.Exchange.Request.Message.Target, c.HoldTarget) {
				held.hold(m.ID)
				continue
			}
			if size := takeSize(c.DerivedSizeFile); size > 0 {
				send(map[string]any{"type": "derived", "sources": []string{m.ID}, "basis": "observed",
					"record": map[string]string{"pad": strings.Repeat("x", size)}})
			}
			if len(c.Changes) == 0 || (m.Output.State != "eligible" && !c.ChangeExcluded) {
				send(map[string]string{"type": "result", "id": m.ID, "outcome": "unchanged"})
				continue
			}
			send(map[string]any{"type": "result", "id": m.ID, "outcome": "changed", "changes": c.Changes})
		case "session_ending":
			if c.Summary && len(ids) > 0 {
				send(map[string]any{"type": "derived", "sources": slices.Clone(ids), "basis": "observed",
					"record": map[string]any{"exchanges": strconv.Itoa(len(ids))}})
			}
		case "shutdown":
			if c.HangOnShutdown {
				select {}
			}
			return 0
		}
	}
}

// holding is the answers held until a release file exists: one goroutine
// watches for it, however many answers are held, and answers them all.
type holding struct {
	release string
	answer  func(id string)
	mutex   sync.Mutex
	ids     []string
	freed   bool
	once    sync.Once
}

func (h *holding) hold(id string) {
	h.mutex.Lock()
	if h.freed {
		h.mutex.Unlock()
		h.answer(id)
		return
	}
	h.ids = append(h.ids, id)
	h.mutex.Unlock()
	h.once.Do(func() { go h.watch() })
}

func (h *holding) watch() {
	for {
		if _, err := os.Stat(h.release); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.mutex.Lock()
	h.freed = true
	ids := h.ids
	h.ids = nil
	h.mutex.Unlock()
	for _, id := range ids {
		h.answer(id)
	}
}

// report writes what this process holds to c.Report.
func report(c Config) {
	held := map[string]any{"pid": os.Getpid()}
	if pgid, err := syscall.Getpgid(0); err == nil {
		held["pgid"] = pgid
	}
	var core unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_CORE, &core) == nil {
		held["core"] = []uint64{core.Cur, core.Max}
	}
	var signal int
	if unix.Prctl(unix.PR_GET_PDEATHSIG, uintptr(unsafe.Pointer(&signal)), 0, 0, 0) == nil {
		held["pdeathsig"] = signal
	}
	if score, err := os.ReadFile("/proc/self/oom_score_adj"); err == nil {
		held["oom_score_adj"] = strings.TrimSpace(string(score))
	}
	descriptors := map[string]string{}
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		for _, entry := range entries {
			if target, err := os.Readlink("/proc/self/fd/" + entry.Name()); err == nil {
				descriptors[entry.Name()] = target
			}
		}
	}
	held["fds"] = descriptors
	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		fields := map[string]string{}
		for line := range strings.Lines(string(status)) {
			name, value, found := strings.Cut(line, ":")
			if found && (strings.HasPrefix(name, "Cap") || name == "NoNewPrivs") {
				fields[name] = strings.TrimSpace(value)
			}
		}
		held["status"] = fields
	}
	if c.Child {
		binary, _ := os.Executable()
		child := exec.Command(binary, Argument, `{"sleep": true}`)
		if child.Start() == nil {
			held["child"] = child.Process.Pid
		}
	}
	encoded, _ := json.Marshal(held)
	_ = os.WriteFile(c.Report, encoded, 0o600)
}

// Held is what Report writes.
type Held struct {
	PID         int               `json:"pid"`
	PGID        int               `json:"pgid"`
	Core        []uint64          `json:"core"`
	PDeathSig   int               `json:"pdeathsig"`
	OOMScoreAdj string            `json:"oom_score_adj"`
	FDs         map[string]string `json:"fds"`
	Status      map[string]string `json:"status"`
	Child       int               `json:"child"`
}

// ReadHeld waits up to 30 seconds for path to hold a report and reads it.
func ReadHeld(path string) (Held, error) {
	var held Held
	deadline := time.Now().Add(30 * time.Second)
	for {
		content, err := os.ReadFile(path)
		if err == nil && json.Unmarshal(content, &held) == nil {
			return held, nil
		}
		if time.Now().After(deadline) {
			return held, fmt.Errorf("no report at %s within 30s: %v", path, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func appendLine(path, line string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(line + "\n")
}

// takeSize reads the size in path and empties the file.
func takeSize(path string) int {
	if path == "" {
		return 0
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	size, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil || size <= 0 {
		return 0
	}
	_ = os.WriteFile(path, nil, 0o600)
	return size
}

// witness records whether the observer's log holds the activation record
// listing this extension, labelled, at the moment named.
func witness(c Config, name, moment string) {
	if c.Witness == "" {
		return
	}
	held := false
	if content, err := os.ReadFile(c.Log); err == nil {
		for line := range strings.Lines(string(content)) {
			var record struct {
				Record     string `json:"record"`
				Extensions []struct {
					Name    string `json:"name"`
					Effects string `json:"effects"`
				} `json:"extensions"`
			}
			if json.Unmarshal([]byte(line), &record) != nil || record.Record != "activation-completed" {
				continue
			}
			for _, one := range record.Extensions {
				if one.Name == name && one.Effects == "extension_declared_not_observer_enforced" {
					held = true
				}
			}
		}
	}
	encoded, _ := json.Marshal(map[string]any{"moment": moment, "activation_held": held})
	appendLine(c.Witness, string(encoded))
}

// Manual is a clock a test moves by hand. Its timers fire, in order, as
// Advance passes their time; one due at or before the reading when it is made
// fires at once.
type Manual struct {
	mutex  sync.Mutex
	now    time.Time
	timers []*manualTimer
}

// NewManual is a Manual reading at.
func NewManual(at time.Time) *Manual { return &Manual{now: at} }

func (m *Manual) Now() time.Time {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.now
}

func (m *Manual) NewTimer(d time.Duration) extension.Timer {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	t := &manualTimer{clock: m, at: m.now.Add(d), c: make(chan time.Time, 1)}
	if d <= 0 {
		t.c <- m.now
		return t
	}
	m.timers = append(m.timers, t)
	return t
}

// Advance moves the clock by d, firing every timer it passes.
func (m *Manual) Advance(d time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.now = m.now.Add(d)
	slices.SortStableFunc(m.timers, func(a, b *manualTimer) int { return a.at.Compare(b.at) })
	kept := m.timers[:0]
	for _, t := range m.timers {
		if t.at.After(m.now) {
			kept = append(kept, t)
			continue
		}
		t.c <- m.now
	}
	clear(m.timers[len(kept):])
	m.timers = kept
}

// Armed reports whether a timer is pending that is due d from the clock's
// reading now: what something waiting on this clock for d is waiting on.
func (m *Manual) Armed(d time.Duration) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return slices.ContainsFunc(m.timers, func(t *manualTimer) bool { return t.at.Equal(m.now.Add(d)) })
}

// Pending is how many timers have not fired or been stopped.
func (m *Manual) Pending() int {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return len(m.timers)
}

type manualTimer struct {
	clock *Manual
	at    time.Time
	c     chan time.Time
}

func (t *manualTimer) C() <-chan time.Time { return t.c }

func (t *manualTimer) Stop() bool {
	m := t.clock
	m.mutex.Lock()
	defer m.mutex.Unlock()
	for i, one := range m.timers {
		if one == t {
			m.timers = slices.Delete(m.timers, i, i+1)
			return true
		}
	}
	return false
}
