package extension

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// state is where a generation is in its life.
type state int

const (
	// starting is started and not yet ready: start is written or queued.
	starting state = iota
	ready
	// retiring is retired under a cause and being stopped.
	retiring
	// stopping is being stopped in order, with no cause.
	stopping
)

// outgoing is one message queued for a generation's standard input.
type outgoing struct {
	line  []byte
	start bool
}

// generation is one process of the extension.
type generation struct {
	s      *Supervisor
	number uint64
	pid    int
	state  state

	stdin, stdout, stderr *os.File

	queue []outgoing
	// wrote wakes the writer; it waits on the supervisor's mutex.
	wrote *sync.Cond
	// closing is no more messages: the writer closes standard input once the
	// queue is written, or at once where interrupt is set.
	closing, interrupt bool

	writingSince time.Time
	startWritten time.Time
	readyAt      time.Time

	outstanding map[uint64]*pending
	waiting     int64
	answered    idSet

	derivedRate bucket
	floodSecond int64
	floodRun    int

	// exited closes when the process has exited. It is not reaped until its
	// group has been killed, so the group id cannot be reused meanwhile.
	exited  chan struct{}
	readers sync.WaitGroup
}

// send queues a message. The caller holds the supervisor's mutex.
func (g *generation) send(o outgoing) {
	if g.closing {
		return
	}
	g.queue = append(g.queue, o)
	g.wrote.Signal()
}

// startGeneration starts the next generation and sends it start. A process
// that cannot be started is a generation retired as start_failed.
func (s *Supervisor) startGeneration() {
	s.mutex.Lock()
	if s.ending {
		s.spawning = false
		s.wake()
		s.unlock()
		return
	}
	s.number++
	number := s.number
	s.mutex.Unlock()

	g, err := s.spawn(number)

	s.mutex.Lock()
	defer s.unlock()
	s.spawning = false
	if err != nil {
		failed := &generation{s: s, number: number, state: starting, outstanding: map[uint64]*pending{}}
		failed.wrote = sync.NewCond(&s.mutex)
		s.retireLocked(failed, StartFailed)
		return
	}
	now := s.clock.Now()
	if number > 1 {
		s.counts.Restarts++
	}
	s.current = g
	start, _ := json.Marshal(startMessage{Type: "start", Protocol: Protocol, Extension: s.config.Name,
		Session: s.config.Session, Generation: strconv.FormatUint(number, 10), Revision: s.config.Revision,
		WriteContent: s.config.WriteContent, Fields: s.config.Fields, TimeoutMS: s.config.TimeoutMS,
		Bounds: s.bounds()})
	g.send(outgoing{line: append(start, '\n'), start: true})
	s.event(Event{Generation: number, Kind: Started, At: now, PID: g.pid})
	g.readers.Add(2)
	go g.write()
	go g.read()
	go g.drainStderr()
	go g.watch()
	if s.ending {
		s.stopLocked(g)
	}
	s.wake()
}

type startMessage struct {
	Type         string           `json:"type"`
	Protocol     string           `json:"protocol"`
	Extension    string           `json:"extension"`
	Session      string           `json:"session"`
	Generation   string           `json:"generation"`
	Revision     string           `json:"processing_revision"`
	WriteContent bool             `json:"write_content"`
	Fields       []string         `json:"fields"`
	TimeoutMS    int64            `json:"timeout_ms"`
	Bounds       map[string]int64 `json:"bounds"`
}

// bounds is every bound, under the name start discloses it by.
func (s *Supervisor) bounds() map[string]int64 {
	return map[string]int64{
		"startup_ms":                 StartupBound.Milliseconds(),
		"frame_bytes_to_extension":   FrameBytesToExtension,
		"frame_bytes_from_extension": FrameBytesFromExtension,
		"in_flight":                  InFlight,
		"waiting_bytes":              s.config.WaitingBytes,
		"healthy_ms":                 HealthyInterval.Milliseconds(),
		"backoff_min_ms":             BackoffMin.Milliseconds(),
		"backoff_max_ms":             BackoffMax.Milliseconds(),
		"termination_grace_ms":       TerminationGrace.Milliseconds(),
		"stderr_lines_per_second":    StderrLinesPerSecond,
		"stderr_line_bytes":          StderrLineBytes,
		"derived_lines_per_second":   DerivedLinesPerSecond,
		"derived_flood_seconds":      DerivedFloodSeconds,
		"derived_queue_bytes":        DerivedQueueBytes,
		"derived_sources":            DerivedSources,
		"reason_bytes":               ReasonBytes,
	}
}

// spawn starts the extension's process with its standard streams on pipes.
func (s *Supervisor) spawn(number uint64) (*generation, error) {
	var ends [6]*os.File
	closeAll := func() {
		for _, f := range ends {
			if f != nil {
				_ = f.Close()
			}
		}
	}
	for i := 0; i < 6; i += 2 {
		r, w, err := os.Pipe()
		if err != nil {
			closeAll()
			return nil, err
		}
		ends[i], ends[i+1] = r, w
	}
	stdinR, stdinW, stdoutR, stdoutW, stderrR, stderrW := ends[0], ends[1], ends[2], ends[3], ends[4], ends[5]
	pid, err := forkExec(s.config.Command, []*os.File{stdinR, stdoutW, stderrW})
	for _, child := range []*os.File{stdinR, stdoutW, stderrW} {
		_ = child.Close()
	}
	if err != nil {
		for _, parent := range []*os.File{stdinW, stdoutR, stderrR} {
			_ = parent.Close()
		}
		return nil, err
	}
	// The kernel prefers the extension to the observer when memory runs out.
	// Raising a score needs no privilege.
	if f, err := os.OpenFile(filepath.Join("/proc", strconv.Itoa(pid), "oom_score_adj"), os.O_WRONLY, 0); err == nil {
		_, _ = f.WriteString("1000")
		_ = f.Close()
	}
	now := s.clock.Now()
	g := &generation{s: s, number: number, pid: pid, state: starting, stdin: stdinW, stdout: stdoutR,
		stderr: stderrR, outstanding: map[uint64]*pending{}, derivedRate: newBucket(DerivedLinesPerSecond, now),
		exited: make(chan struct{})}
	g.wrote = sync.NewCond(&s.mutex)
	return g, nil
}

// write writes queued messages to standard input, one at a time, outside the
// mutex. The loop reads writingSince, so a write held longer than timeout_ms
// retires the generation.
func (g *generation) write() {
	s := g.s
	for {
		s.mutex.Lock()
		for len(g.queue) == 0 && !g.closing {
			g.wrote.Wait()
		}
		if len(g.queue) == 0 || g.interrupt {
			s.mutex.Unlock()
			_ = g.stdin.Close()
			return
		}
		o := g.queue[0]
		g.queue[0] = outgoing{}
		g.queue = g.queue[1:]
		g.writingSince = s.clock.Now()
		s.wake()
		s.mutex.Unlock()

		_, err := g.stdin.Write(o.line)

		s.mutex.Lock()
		g.writingSince = time.Time{}
		if err != nil {
			if g.state == starting || g.state == ready {
				s.retireLocked(g, Crash)
			}
			s.unlock()
			_ = g.stdin.Close()
			return
		}
		if o.start {
			g.startWritten = s.clock.Now()
		}
		s.wake()
		s.unlock()
	}
}

// read reads the extension's messages until end of file. A line over the
// frame bound ends the reading: nothing after it can be framed.
func (g *generation) read() {
	defer g.readers.Done()
	s := g.s
	r := bufio.NewReaderSize(g.stdout, 64<<10)
	for {
		line, err := readLine(r, FrameBytesFromExtension)
		if err != nil {
			s.mutex.Lock()
			if g.state == starting || g.state == ready {
				if errors.Is(err, errOversized) {
					s.retireLocked(g, OversizedFrame)
				} else {
					s.retireLocked(g, Crash)
				}
			}
			s.unlock()
			return
		}
		s.handle(g, line)
	}
}

// drainStderr reads standard error continuously, so the extension never
// blocks writing it, and copies it into the log within the stderr bounds.
func (g *generation) drainStderr() {
	defer g.readers.Done()
	s := g.s
	r := bufio.NewReaderSize(g.stderr, 4096)
	for {
		line, cut, err := readCut(r, StderrLineBytes)
		if line == nil && err != nil {
			return
		}
		s.mutex.Lock()
		now := s.clock.Now()
		if s.logRate.take(now) {
			text, _ := escaped(string(line), StderrLineBytes)
			s.event(Event{Generation: g.number, Kind: Stderr, At: now, PID: g.pid, Line: text, Cut: cut})
		} else {
			s.counts.StderrDropped++
		}
		s.unlock()
		if err != nil {
			return
		}
	}
}

// readCut reads one line, keeping at most limit bytes of it, and reports
// whether more was dropped. A last line with no line feed is returned with
// the error that ended it.
func readCut(r *bufio.Reader, limit int) ([]byte, bool, error) {
	var line []byte
	cut := false
	for {
		chunk, err := r.ReadSlice('\n')
		data := chunk
		if err == nil {
			data = chunk[:len(chunk)-1]
		}
		if room := limit - len(line); len(data) > room {
			cut = true
			data = data[:room]
		}
		line = append(line, data...)
		switch {
		case err == nil:
			return nonNil(line), cut, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case len(line) == 0 && len(chunk) == 0 && !cut:
			return nil, false, err
		default:
			return nonNil(line), cut, err
		}
	}
}

func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// watch waits for the process to exit without reaping it.
func (g *generation) watch() {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, g.pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	close(g.exited)
	g.s.exited(g)
}

// terminate stops the process and everything left in its process group, then
// reaps it. In order, a generation first has the grace to exit after its
// standard input closes; otherwise it is sent SIGTERM at once. Either way
// SIGKILL follows the grace, and the group is killed before the reap, while
// the leader's pid still holds the group id.
func (g *generation) terminate(orderly bool) {
	s := g.s
	defer s.teardowns.Done()
	if g.pid == 0 {
		return
	}
	if !orderly || !g.waitExit(TerminationGrace) {
		g.signal(unix.SIGTERM)
		if !g.waitExit(TerminationGrace) {
			g.signal(unix.SIGKILL)
			<-g.exited
		}
	}
	g.signal(unix.SIGKILL)
	var status unix.WaitStatus
	for {
		_, err := unix.Wait4(g.pid, &status, 0, nil)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	// What the process wrote before it exited is still read; a descendant
	// that left the group and holds a pipe open is not waited for past the
	// grace.
	read := make(chan struct{})
	go func() {
		g.readers.Wait()
		close(read)
	}()
	if !g.waitFor(read, TerminationGrace) {
		_ = g.stdout.Close()
		_ = g.stderr.Close()
		<-read
	}
	_ = g.stdout.Close()
	_ = g.stderr.Close()
	s.mutex.Lock()
	s.event(Event{Generation: g.number, Kind: Exited, At: s.clock.Now(), PID: g.pid})
	s.changed.Broadcast()
	s.unlock()
}

func (g *generation) signal(sig unix.Signal) { _ = unix.Kill(-g.pid, sig) }

func (g *generation) waitExit(d time.Duration) bool { return g.waitFor(g.exited, d) }

// waitFor waits for done for d on the supervisor's clock, and not at all once
// the supervisor is closed.
func (g *generation) waitFor(done <-chan struct{}, d time.Duration) bool {
	select {
	case <-done:
		return true
	default:
	}
	timer := g.s.clock.NewTimer(d)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C():
		return false
	case <-g.s.abort:
		select {
		case <-done:
			return true
		default:
			return false
		}
	}
}

// The parent-death signal is sent when the THREAD that forked a process
// exits, not the process, and Go ends threads under goroutines that locked
// them. So every extension is forked from one locked thread whose goroutine
// never returns: its signal comes only when the observer itself ends.
var spawner struct {
	once     sync.Once
	requests chan spawnRequest
}

type spawnRequest struct {
	argv  []string
	files []*os.File
	reply chan spawnReply
}

type spawnReply struct {
	pid int
	err error
}

func forkExec(argv []string, files []*os.File) (int, error) {
	spawner.once.Do(func() {
		spawner.requests = make(chan spawnRequest)
		go spawnLoop(spawner.requests)
	})
	reply := make(chan spawnReply, 1)
	spawner.requests <- spawnRequest{argv: argv, files: files, reply: reply}
	r := <-reply
	return r.pid, r.err
}

func spawnLoop(requests <-chan spawnRequest) {
	runtime.LockOSThread()
	for r := range requests {
		pid, err := spawnOne(r.argv, r.files)
		r.reply <- spawnReply{pid: pid, err: err}
	}
}

func spawnOne(argv []string, files []*os.File) (int, error) {
	// The core limit is the observer's own, set before every fork, so the
	// extension holds it from its first instruction: 1 byte, which the
	// kernel also honours where core dumps go to a pipe, as 0 is not. The
	// observer itself is not dumpable, so the limit takes nothing from it.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 1, Max: 1}); err != nil {
		return 0, err
	}
	if err := closeOnExec(); err != nil {
		return 0, err
	}
	fds := make([]uintptr, len(files))
	for i, f := range files {
		fds[i] = f.Fd()
	}
	pid, err := syscall.ForkExec(argv[0], argv, &syscall.ProcAttr{Env: os.Environ(), Files: fds,
		Sys: &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}})
	runtime.KeepAlive(files)
	return pid, err
}

// closeOnExec marks every descriptor above standard error close-on-exec, so
// an extension starts holding its three pipes and nothing of the observer's,
// whatever opened a descriptor without the flag.
func closeOnExec() error {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd <= 2 {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			// The directory's own descriptor, closed since it was listed.
			continue
		}
		if flags&unix.FD_CLOEXEC == 0 {
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
				return err
			}
		}
	}
	return nil
}
