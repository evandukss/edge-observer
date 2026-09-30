//go:build attach

package attach_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/evandukss/edge-observer/account"
)

// t25Watch is one observer started under the write-boundary filter, with the
// launcher and the counting of TestT18TheWriteBoundaryCountsWhatItCouldNotRead:
// every write it makes is read whole before it proceeds, or counted as unread.
type t25Watch struct {
	command  *exec.Cmd
	boundary *t18Boundary
	session  string
	exited   chan struct{}
	stop     atomic.Bool
	served   chan struct{}

	mutex  sync.Mutex
	stdout []string
	stderr bytes.Buffer
	err    error
	state  *os.ProcessState
}

// t25Watched starts the observer over c under the filter and returns it once
// its activation record is out. serve answers the filter's notifications; nil
// is t18Boundary.serve, which answers each write as soon as it is read.
func t25Watched(t *testing.T, binary string, c configured, serve func(w *t25Watch, listener int)) *t25Watch {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(pair[0]) })
	childSocket := os.NewFile(uintptr(pair[1]), "t25-boundary-child")
	w := &t25Watch{boundary: t18NewBoundary(), exited: make(chan struct{}), served: make(chan struct{})}
	w.command = exec.Command(os.Args[0], "-test.run=^TestT18TheWriteBoundaryCountsWhatItCouldNotRead$", "-test.count=1")
	w.command.Env = append(os.Environ(), t18BoundaryLauncher+"=1", t18BoundaryBinary+"="+binary, t18BoundaryConfig+"="+c.path)
	w.command.ExtraFiles = []*os.File{childSocket}
	out, err := w.command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	w.command.Stderr = &t25Locked{w: w}
	intoEnvelope(t, w.command)
	if err := w.command.Start(); err != nil {
		t.Fatalf("start the launcher: %v", err)
	}
	_ = childSocket.Close()
	t.Cleanup(func() { _ = w.command.Process.Kill(); <-w.exited })
	listener := t17RecvFd(t, pair[0])
	t.Cleanup(func() { _ = unix.Close(listener) })
	go func() {
		defer close(w.served)
		if serve == nil {
			w.boundary.serve(listener, &w.stop)
			return
		}
		serve(w, listener)
	}()
	t.Cleanup(func() { w.stop.Store(true); <-w.served })

	activated := make(chan string, 1)
	go func() {
		lines := bufio.NewScanner(out)
		lines.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for lines.Scan() {
			w.mutex.Lock()
			w.stdout = append(w.stdout, lines.Text())
			w.mutex.Unlock()
			if record, ok := recordOf(lines.Bytes()); ok && record.Record == "activation-completed" {
				select {
				case activated <- record.Session:
				default:
				}
			}
		}
		err := w.command.Wait()
		w.mutex.Lock()
		w.err, w.state = err, w.command.ProcessState
		w.mutex.Unlock()
		close(w.exited)
	}()
	select {
	case w.session = <-activated:
	case <-w.exited:
		t.Fatalf("the observer ended before it activated under the filter: %v\n%s", w.err, w.stderrText())
	case <-time.After(60 * time.Second):
		t.Fatalf("the observer never activated under the filter: %s", w.boundary)
	}
	return w
}

// t25Locked hands the observer's stderr to the watch under its lock.
type t25Locked struct{ w *t25Watch }

func (l *t25Locked) Write(p []byte) (int, error) {
	l.w.mutex.Lock()
	defer l.w.mutex.Unlock()
	return l.w.stderr.Write(p)
}

func (w *t25Watch) stderrText() string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.stderr.String()
}

func (w *t25Watch) directory(c configured) string { return filepath.Join(c.sessions(), w.session) }

// ended waits for the observer to end, however it ends, and stops serving.
func (w *t25Watch) ended(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case <-w.exited:
	case <-time.After(within):
		t.Fatalf("the observer had not ended %s later: %s\n%s", within, w.boundary, w.stderrText())
	}
	w.stop.Store(true)
	<-w.served
	t.Logf("boundary: %s", w.boundary)
}

// signal sends sig and waits for the observer to end.
func (w *t25Watch) signal(t *testing.T, sig syscall.Signal) {
	t.Helper()
	if err := w.command.Process.Signal(sig); err != nil {
		t.Fatalf("signal the observer %v: %v", sig, err)
	}
	w.ended(t, t18StopWithin)
}

// records is every record of this kind the observer printed on stdout, which
// mirrors its log in the foreground.
func (w *t25Watch) records(kind string) []map[string]any {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	var found []map[string]any
	for _, line := range w.stdout {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) == nil && record["record"] == kind {
			found = append(found, record)
		}
	}
	return found
}

// t25Decided is a closed connection whose one exchange carries both markers:
// the policy removes the protected one, and the permitted one is decided and
// written independently of whatever the case does next. The client must exist
// before the session starts, since targets resolve at start. It returns once
// the session has written the exchange.
func t25Decided(t *testing.T, binary string, c configured, client conversation) {
	t.Helper()
	t18Ask(t, client, "/?asked=t25-decided", "X-Public: "+t18BoundaryPermitted, "Authorization: Bearer "+t18BoundaryProtected)
	t18Hangup(client)
	t18Until(t, binary, c, 10*time.Second, "wiring, not the property: the decided connection was never written",
		func(a account.Account) bool { return t18Written(a) >= 1 })
}

// t25Clean fails on every reason the boundary is not established, and is the
// property every case asserts once its guard has shown the fault occurred.
func t25Clean(t *testing.T, w *t25Watch) {
	t.Helper()
	for _, problem := range w.boundary.verdict() {
		t.Error(problem)
	}
	if strings.Contains(w.stderrText(), t18BoundaryProtected) {
		t.Error("the protected marker is in the observer's collected stderr")
	}
}

// t25Filled mounts a tmpfs of size bytes at directory, for the observer's
// sessions, and returns a function that fills whatever space is left.
func t25Filled(t *testing.T, directory string, size int) func() int64 {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatalf("make %s: %v", directory, err)
	}
	if err := unix.Mount("tmpfs", directory, "tmpfs", 0, fmt.Sprintf("size=%d,mode=0700", size)); err != nil {
		t.Fatalf("mount a tmpfs at %s: %v", directory, err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(directory, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount %s: %v", directory, err)
		}
	})
	return func() int64 {
		filler, err := os.Create(filepath.Join(directory, "t25-filler"))
		if err != nil {
			t.Fatalf("create the filler: %v", err)
		}
		defer func() { _ = filler.Close() }()
		block := make([]byte, 4096)
		var written int64
		for {
			n, err := filler.Write(block)
			written += int64(n)
			if err != nil {
				if !strings.Contains(err.Error(), "no space left") {
					t.Fatalf("fill %s: %v", directory, err)
				}
				return written
			}
		}
	}
}

// t25Holding serves as t18Boundary.serve does - each write read whole and
// counted, or counted unread - except that a write whose bytes contain hold is
// left unanswered, so the thread making it stays blocked in the kernel, until
// release is closed or serving stops. Held writes are answered in arrival
// order. held counts them.
func t25Holding(hold []byte, release <-chan struct{}, held *atomic.Int64) func(w *t25Watch, listener int) {
	return func(w *t25Watch, listener int) {
		b := w.boundary
		var pending []uint64
		answer := func(id uint64) {
			response := t17SeccompNotifResp{ID: id, Flags: uint32(unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE)}
			if err := t17Ioctl(listener, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&response)); err != nil && err != unix.ENOENT {
				b.fail(fmt.Sprintf("answer a notification: %v", err))
			}
		}
		released := func() bool {
			select {
			case <-release:
				return true
			default:
				return false
			}
		}
		defer func() {
			for _, id := range pending {
				answer(id)
			}
		}()
		fds := []unix.PollFd{{Fd: int32(listener), Events: unix.POLLIN}}
		for !w.stop.Load() {
			if released() {
				for _, id := range pending {
					answer(id)
				}
				pending = nil
			}
			fds[0].Revents = 0
			n, err := unix.Poll(fds, 100)
			if err == unix.EINTR || n == 0 {
				continue
			}
			if err != nil {
				b.fail(fmt.Sprintf("poll the listener: %v", err))
				return
			}
			if fds[0].Revents&unix.POLLIN == 0 {
				return
			}
			var notification t17SeccompNotif
			if err := t17Ioctl(listener, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&notification)); err != nil {
				if err != unix.ENOENT && err != unix.EINTR {
					b.fail(fmt.Sprintf("receive a notification: %v", err))
				}
				continue
			}
			chunks, asked, readErr := t18WriteChunks(&notification)
			holding := false
			if t17NotifIDValid(listener, notification.ID) {
				b.mutex.Lock()
				b.calls[notification.Data.NR]++
				if readErr != nil {
					b.unread++
					b.unreadBytes += int64(asked)
					b.why[readErr.Error()]++
				} else {
					b.read++
					b.readBytes += int64(asked)
					for _, chunk := range chunks {
						b.scan(notification.Data.Args[0], chunk)
						holding = holding || bytes.Contains(chunk, hold)
					}
				}
				b.mutex.Unlock()
			}
			if holding && !released() {
				held.Add(1)
				pending = append(pending, notification.ID)
				continue
			}
			answer(notification.ID)
		}
	}
}
