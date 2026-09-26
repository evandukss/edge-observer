//go:build attach

package attach_test

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"runtime"
	"slices"
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

const (
	t18BoundaryLauncher = "T18_BOUNDARY_LAUNCHER"
	t18BoundaryBinary   = "T18_BOUNDARY_BINARY"
	t18BoundaryConfig   = "T18_BOUNDARY_CONFIG"

	// The markers, each a token nothing but this test produces.
	t18BoundaryProtected = "T18_BOUNDARY_PROTECTED_61c2e0"
	t18BoundaryPermitted = "T18_BOUNDARY_PERMITTED_3f7a94"

	// t18BoundaryLargest is the largest single write this instrument reads. A
	// larger one is counted as unread rather than read in part.
	t18BoundaryLargest = 64 << 20
)

// t18Boundary is what the servicer saw of the observer's writes, counted both
// ways: a write whose bytes were read whole, and a write whose bytes could not
// be. Markers are searched per descriptor with the bytes a marker could
// straddle carried from one write to the next, so nothing is capped and a
// marker split across two writes to one descriptor is still found.
type t18Boundary struct {
	mutex       sync.Mutex
	read        int64
	readBytes   int64
	unread      int64
	unreadBytes int64
	why         map[string]int
	calls       map[int32]int
	found       map[string]int
	tails       map[uint64][]byte
	failures    []string
}

func t18NewBoundary() *t18Boundary {
	return &t18Boundary{why: map[string]int{}, calls: map[int32]int{},
		found: map[string]int{t18BoundaryProtected: 0, t18BoundaryPermitted: 0}, tails: map[uint64][]byte{}}
}

func (b *t18Boundary) scan(descriptor uint64, chunk []byte) {
	joined := append(b.tails[descriptor], chunk...)
	for marker := range b.found {
		b.found[marker] += bytes.Count(joined, []byte(marker))
	}
	keep := len(t18BoundaryProtected) - 1
	if len(joined) > keep {
		joined = joined[len(joined)-keep:]
	}
	b.tails[descriptor] = append([]byte(nil), joined...)
}

// t18ReadWhole reads length bytes at addr in pid, and reports anything short of
// all of them as an error.
func t18ReadWhole(pid int, addr, length uint64) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}
	if length > t18BoundaryLargest {
		return nil, fmt.Errorf("a %d-byte buffer is over the %d this instrument reads", length, t18BoundaryLargest)
	}
	local := make([]byte, length)
	got, err := unix.ProcessVMReadv(pid, []unix.Iovec{{Base: &local[0], Len: length}},
		[]unix.RemoteIovec{{Base: uintptr(addr), Len: int(length)}}, 0)
	if err != nil {
		return nil, err
	}
	if uint64(got) != length {
		return nil, fmt.Errorf("read %d of %d bytes", got, length)
	}
	return local, nil
}

// t18WriteChunks is the buffers one intercepted write hands the kernel, read
// whole, with the number of bytes it asked to write.
func t18WriteChunks(notification *t17SeccompNotif) ([][]byte, uint64, error) {
	pid, args := int(notification.Pid), notification.Data.Args
	switch int(notification.Data.NR) {
	case unix.SYS_WRITE, unix.SYS_PWRITE64:
		chunk, err := t18ReadWhole(pid, args[1], args[2])
		return [][]byte{chunk}, args[2], err
	case unix.SYS_WRITEV, unix.SYS_PWRITEV, unix.SYS_PWRITEV2:
		// The kernel refuses more than 1024 vectors, so a larger count writes
		// nothing; it is still read as far as the instrument can.
		count := args[2]
		vectors, err := t18ReadWhole(pid, args[1], count*16)
		if err != nil {
			return nil, 0, fmt.Errorf("the %d-entry vector: %w", count, err)
		}
		var chunks [][]byte
		var total uint64
		for i := 0; i+16 <= len(vectors); i += 16 {
			base, length := binary.LittleEndian.Uint64(vectors[i:]), binary.LittleEndian.Uint64(vectors[i+8:])
			total += length
			chunk, err := t18ReadWhole(pid, base, length)
			if err != nil {
				return nil, total, fmt.Errorf("vector %d: %w", i/16, err)
			}
			chunks = append(chunks, chunk)
		}
		return chunks, total, nil
	}
	return nil, 0, fmt.Errorf("syscall %d is not one this filter intercepts", notification.Data.NR)
}

// serve answers every write notification until stop, reading each buffer
// while the write is held and only then checking that the notification is still
// valid, as seccomp_unotify(2) orders it. A write that is still pending after
// its buffer could not be read is counted as unread, never skipped.
func (b *t18Boundary) serve(listener int, stop *atomic.Bool) {
	fds := []unix.PollFd{{Fd: int32(listener), Events: unix.POLLIN}}
	for !stop.Load() {
		fds[0].Revents = 0
		n, err := unix.Poll(fds, 200)
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
				}
			}
			b.mutex.Unlock()
		}
		response := t17SeccompNotifResp{ID: notification.ID, Flags: uint32(unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE)}
		if err := t17Ioctl(listener, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&response)); err != nil && err != unix.ENOENT {
			b.fail(fmt.Sprintf("answer a notification: %v", err))
		}
	}
}

func (b *t18Boundary) fail(why string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.failures = append(b.failures, why)
}

// verdict is every reason the boundary is not established by what was seen.
func (b *t18Boundary) verdict() []string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	var problems []string
	if b.unread != 0 {
		problems = append(problems, fmt.Sprintf("%d writes (%d bytes) could not be read whole, so what they wrote "+
			"is not known: %v", b.unread, b.unreadBytes, b.why))
	}
	if b.read == 0 || b.readBytes == 0 {
		problems = append(problems, fmt.Sprintf("no write was read (%d writes, %d bytes), so nothing was measured", b.read, b.readBytes))
	}
	if b.found[t18BoundaryPermitted] == 0 {
		problems = append(problems, "the permitted marker crossed no write that was read")
	}
	if n := b.found[t18BoundaryProtected]; n != 0 {
		problems = append(problems, fmt.Sprintf("the protected marker crossed the write boundary %d times", n))
	}
	problems = append(problems, b.failures...)
	return problems
}

func (b *t18Boundary) String() string {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	calls := []string{}
	for _, nr := range slices.Sorted(maps.Keys(b.calls)) {
		calls = append(calls, fmt.Sprintf("%d:%d", nr, b.calls[nr]))
	}
	return fmt.Sprintf("read %d writes (%d bytes); unread %d writes (%d bytes) %v; syscalls by number %v; markers %v",
		b.read, b.readBytes, b.unread, b.unreadBytes, b.why, calls, b.found)
}

// t18BoundaryLaunch installs the write-intercepting filter and execs the
// observer, which keeps it. A seccomp filter belongs to the thread that
// installs it, and execve keeps only the calling thread, so both run on one
// locked OS thread; otherwise the observer can start with no filter at all.
func t18BoundaryLaunch() {
	runtime.LockOSThread()
	program, err := t17WriteFilterProgram()
	if err != nil {
		os.Exit(3)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		os.Exit(4)
	}
	fprog := unix.SockFprog{Len: uint16(len(program)), Filter: &program[0]}
	listener, _, errno := unix.Syscall(unix.SYS_SECCOMP, uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER), uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		os.Exit(5)
	}
	if err := unix.Sendmsg(3, []byte{0}, unix.UnixRights(int(listener)), nil, 0); err != nil {
		os.Exit(6)
	}
	binaryPath := os.Getenv(t18BoundaryBinary)
	_ = syscall.Exec(binaryPath, []string{binaryPath, "start", os.Getenv(t18BoundaryConfig)}, os.Environ())
	os.Exit(7)
}

// t18DropPtrace removes CAP_SYS_PTRACE from the calling OS thread only. The
// observer makes itself non-dumpable before it attaches, so without the
// capability this thread cannot read the observer's memory.
func t18DropPtrace() error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return err
	}
	data[unix.CAP_SYS_PTRACE/32].Effective &^= 1 << (unix.CAP_SYS_PTRACE % 32)
	return unix.Capset(&header, &data[0])
}

// t18BoundaryRun starts the observer under the filter, drives one complete
// exchange carrying both markers, stops it, and returns what the servicer saw.
// readable false makes the servicer's thread unable to read the observer.
func t18BoundaryRun(t *testing.T, readable bool) *t18Boundary {
	t.Helper()
	binary := built(t)
	client := speaking(t, t18Serving(t))
	c := configuring(t, target("under-test", client.process))
	t18Edit(t, c, t18Removing)

	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(pair[0]) })
	childSocket := os.NewFile(uintptr(pair[1]), "t18-boundary-child")
	command := exec.Command(os.Args[0], "-test.run=^TestT18TheWriteBoundaryCountsWhatItCouldNotRead$", "-test.count=1")
	command.Env = append(os.Environ(), t18BoundaryLauncher+"=1", t18BoundaryBinary+"="+binary, t18BoundaryConfig+"="+c.path)
	command.ExtraFiles = []*os.File{childSocket}
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	command.Stderr = os.Stderr
	intoEnvelope(t, command)
	if err := command.Start(); err != nil {
		t.Fatalf("start the launcher: %v", err)
	}
	_ = childSocket.Close()
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	listener := t17RecvFd(t, pair[0])
	t.Cleanup(func() { _ = unix.Close(listener) })

	boundary := t18NewBoundary()
	var stop atomic.Bool
	served := make(chan struct{})
	go func() {
		defer close(served)
		if !readable {
			// Never unlocked: the thread with the reduced capability ends with
			// this goroutine instead of returning to the scheduler.
			runtime.LockOSThread()
			if err := t18DropPtrace(); err != nil {
				boundary.fail(fmt.Sprintf("drop CAP_SYS_PTRACE from the servicer: %v", err))
			}
		}
		boundary.serve(listener, &stop)
	}()

	activated := make(chan struct{}, 1)
	go func() {
		lines := bufio.NewScanner(out)
		lines.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for lines.Scan() {
			if record, ok := recordOf(lines.Bytes()); ok && record.Record == "activation-completed" {
				select {
				case activated <- struct{}{}:
				default:
				}
			}
		}
	}()
	select {
	case <-activated:
	case <-time.After(60 * time.Second):
		stop.Store(true)
		t.Fatalf("the observer never activated under the filter: %s", boundary)
	}

	t18Ask(t, client, "/?asked=t18-boundary", "X-Public: "+t18BoundaryPermitted, "Authorization: Bearer "+t18BoundaryProtected)
	t18Until(t, binary, c, 10*time.Second, "wiring, not the property: the exchange never reached capture",
		func(a account.Account) bool { return a.Seen != nil && a.Seen.Records >= 2 })

	_ = command.Process.Signal(syscall.SIGTERM)
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	select {
	case err := <-exited:
		if err != nil {
			t.Errorf("the observer under the filter exited %v", err)
		}
	case <-time.After(t18StopWithin):
		stop.Store(true)
		t.Fatalf("the observer under the filter did not end: %s", boundary)
	}
	stop.Store(true)
	<-served
	t.Logf("%s", boundary)
	return boundary
}

// Row 1's write boundary, instrumented so it cannot pass having measured
// nothing. Every write the observer makes is held until its buffer has been
// read out of the observer; a buffer that cannot be read whole is COUNTED as
// unread and fails the verdict, and a second count - writes whose buffers were
// read, which must not be zero - shows the instrument measured something. No
// cap limits what is scanned.
//
// The second case is the fault the first cannot show by itself: the servicer's
// thread gives up CAP_SYS_PTRACE, so it cannot read the non-dumpable observer.
// It must reach unreadable writes, and the verdict must refuse on them rather
// than report a clean boundary.
func TestT18TheWriteBoundaryCountsWhatItCouldNotRead(t *testing.T) {
	if os.Getenv(t18BoundaryLauncher) == "1" {
		t18BoundaryLaunch()
		return
	}
	t.Run("every buffer readable", func(t *testing.T) {
		boundary := t18BoundaryRun(t, true)
		if boundary.read == 0 || boundary.readBytes == 0 {
			t.Fatalf("wiring, not the property: no write buffer was read: %s", boundary)
		}
		for _, problem := range boundary.verdict() {
			t.Error(problem)
		}
	})
	t.Run("the servicer cannot read the observer", func(t *testing.T) {
		boundary := t18BoundaryRun(t, false)
		if boundary.unread == 0 {
			t.Fatalf("wiring, not the property: with CAP_SYS_PTRACE dropped every buffer was still read, so the "+
				"unreadable case was never reached: %s", boundary)
		}
		problems := boundary.verdict()
		if len(problems) == 0 || !slices.ContainsFunc(problems, func(one string) bool {
			return strings.Contains(one, "could not be read whole")
		}) {
			t.Errorf("the instrument left %d writes unread and its verdict did not refuse on them: %v", boundary.unread, problems)
		}
	})
}
