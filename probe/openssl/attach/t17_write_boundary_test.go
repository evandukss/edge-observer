//go:build attach

// Exit-criterion row 1: the WRITE BOUNDARY. Every byte the observer writes from
// activation to exit is observed at the point the bytes are fixed - the moment
// of the write syscall, before the buffer can change and before any later
// cleanup could remove a file. A grep of the finished directory cannot see a
// write-then-delete and passes a run where nothing happened; this instrument
// sees the write itself.
//
// The instrument is a seccomp user-notification filter installed on the observer
// before it execs, intercepting the write family (write, writev, pwrite64,
// pwritev, pwritev2) across every descriptor - files (including temporary and
// deleted ones), stdout, stderr, the log and any pipe. Each intercepted write
// blocks in the kernel until this test has read the buffer out of the observer's
// address space and answered CONTINUE, so no write can complete unobserved and
// none can be missed by racing it.
//
// What it CANNOT see, stated so the evidence is not read as more than it is:
//   - bytes a single write places beyond t17WriteReadCap into one buffer (bounded
//     read); the tests here write far less than that per call;
//   - a write by a process the observer execs (it execs nothing after activation);
//   - memory-mapped file stores flushed by msync rather than a write syscall (the
//     observer's durable output is written, not mmapped);
//   - anything before the filter is installed, which is before the observer image
//     is exec'd, so the observer makes no write in that window.
package attach_test

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	t17BoundaryLauncherEnv = "T17_BOUNDARY_LAUNCHER"
	t17BoundaryBinEnv      = "T17_BOUNDARY_OBSERVER_BIN"
	t17BoundaryCfgEnv      = "T17_BOUNDARY_OBSERVER_CONFIG"

	// Classic BPF opcodes for the seccomp filter program.
	t17BpfLdWAbs = 0x20 // BPF_LD | BPF_W | BPF_ABS
	t17BpfJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	t17BpfRetK   = 0x06 // BPF_RET | BPF_K
	t17RetAllow  = 0x7fff0000

	// Offsets into struct seccomp_data.
	t17SeccompArchOffset = 4
	t17SeccompNROffset   = 0

	t17WriteReadCap  = 1 << 20  // bytes read from one write buffer
	t17WriteTotalCap = 32 << 20 // bytes accumulated across all writes
)

// The kernel structures the seccomp user-notification ioctls exchange. Their
// sizes are fixed by the ioctl request encodings (RECV is 80 bytes, SEND 24),
// which is what pins these layouts.
// Blank fields hold the ABI's arch, instruction pointer, per-notif flags, val
// and error words this instrument does not read, keeping each struct's exact
// size (seccomp_notif 80, seccomp_notif_resp 24) without naming a field nothing
// uses.
type t17SeccompData struct {
	NR   int32
	_    uint32 // arch
	_    uint64 // instruction pointer
	Args [6]uint64
}

type t17SeccompNotif struct {
	ID   uint64
	Pid  uint32
	_    uint32 // flags
	Data t17SeccompData
}

type t17SeccompNotifResp struct {
	ID    uint64
	_     int64 // val
	_     int32 // error
	Flags uint32
}

// TestT17WriteBoundary runs in two roles. As the launcher child it installs the
// write-intercepting filter and execs the observer; as the parent it services
// the notifications, drives one exchange, and asserts that the protected marker
// crossed no write while the permitted marker did.
func TestT17WriteBoundary(t *testing.T) {
	if os.Getenv(t17BoundaryLauncherEnv) == "1" {
		t17BoundaryLaunch()
		return
	}

	binary := built(t)
	port := serving(t)
	client := speaking(t, port)
	c := configuring(t, target("under-test", client.process))
	// The operator selects the authorization header for removal; the protected
	// marker rides it and must cross no write. X-Public is the paired permitted
	// marker that must be written, so "nothing ran" cannot pass.
	t17RemoveAuthorization(t, c)

	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	childSock := os.NewFile(uintptr(pair[1]), "t17-boundary-child-sock")
	defer func() { _ = unix.Close(pair[0]) }()

	cmd := exec.Command(os.Args[0], "-test.run=^TestT17WriteBoundary$")
	cmd.Env = append(os.Environ(),
		t17BoundaryLauncherEnv+"=1",
		t17BoundaryBinEnv+"="+binary,
		t17BoundaryCfgEnv+"="+c.path)
	cmd.ExtraFiles = []*os.File{childSock}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	// The observer is created into the bounded no-swap cgroup its activation
	// verifies; the launcher inherits it and the exec keeps it.
	intoEnvelope(t, cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the launcher: %v", err)
	}
	_ = childSock.Close()
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	listenerFd := t17RecvFd(t, pair[0])
	defer func() { _ = unix.Close(listenerFd) }()

	recorder := &t17WriteRecorder{}
	var stop int32
	var servicing sync.WaitGroup
	servicing.Add(1)
	go func() {
		defer servicing.Done()
		t17ServiceWrites(listenerFd, recorder, &stop)
	}()

	// Drain stdout and watch for activation. Draining is not optional: an
	// undrained pipe fills and the observer stalls on its next log write.
	activated := make(chan struct{}, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			if record, ok := recordOf(scanner.Bytes()); ok && record.Record == "activation-completed" {
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
		t.Fatal("the observer never activated under the write-boundary instrument")
	}

	// One complete exchange: X-Public permitted, Authorization protected.
	t17Complete(t, client, "boundary")
	t17SeenAtLeast(t, binary, c, 2)

	// Stop and let it seal. The complete exchange is processed and written to
	// approved output during finalisation; every one of those writes blocks on
	// this instrument, so cmd.Wait returning means all of them were observed.
	_ = cmd.Process.Signal(syscall.SIGTERM)
	_ = cmd.Wait()
	atomic.StoreInt32(&stop, 1)
	servicing.Wait()

	writes, seen := recorder.snapshot()
	all := recorder.bytesSeen()
	if writes == 0 {
		t.Fatal("wiring, not the property: the instrument observed no write, so it measured nothing")
	}
	if !bytes.Contains(all, []byte(t17Permitted)) {
		t.Fatalf("the permitted marker was written to no observed output, so 'nothing ran' would pass this row "+
			"(%d writes, %d bytes observed)", writes, seen)
	}
	if bytes.Contains(all, []byte(t17Secret)) {
		t.Fatalf("the protected marker crossed the write boundary in one of %d observed writes", writes)
	}
	t.Logf("write-boundary instrument observed %d writes, %d bytes; permitted present, protected absent", writes, seen)
}

// t17BoundaryLaunch installs the write-intercepting filter on this process and
// execs the observer, which inherits the filter. It writes nothing between
// installing the filter and the exec: a write there would block on a servicer
// that is not yet reading, so the only syscalls it makes after install are the
// fd hand-off (sendmsg, not intercepted) and execve.
func t17BoundaryLaunch() {
	program, err := t17WriteFilterProgram()
	if err != nil {
		fmt.Fprintln(os.Stderr, "t17 launcher:", err)
		os.Exit(3)
	}
	binaryPath := os.Getenv(t17BoundaryBinEnv)
	configPath := os.Getenv(t17BoundaryCfgEnv)

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		os.Exit(4)
	}
	fprog := unix.SockFprog{Len: uint16(len(program)), Filter: &program[0]}
	listener, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER),
		uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		os.Exit(5)
	}
	// fd 3 is the first ExtraFile the parent passed.
	if err := unix.Sendmsg(3, []byte{0}, unix.UnixRights(int(listener)), nil, 0); err != nil {
		os.Exit(6)
	}
	_ = syscall.Exec(binaryPath, []string{binaryPath, "start", configPath}, os.Environ())
	os.Exit(7)
}

// t17WriteFilterProgram builds a classic-BPF seccomp program that returns
// USER_NOTIF for the write family on this architecture and ALLOW for everything
// else, so only writes are intercepted and the observer's other syscalls run
// unimpeded.
func t17WriteFilterProgram() ([]unix.SockFilter, error) {
	var arch uint32
	switch runtime.GOARCH {
	case "arm64":
		arch = unix.AUDIT_ARCH_AARCH64
	case "amd64":
		arch = unix.AUDIT_ARCH_X86_64
	default:
		return nil, fmt.Errorf("write-boundary instrument does not know this architecture: %s", runtime.GOARCH)
	}
	writes := []uint32{unix.SYS_WRITE, unix.SYS_WRITEV, unix.SYS_PWRITE64, unix.SYS_PWRITEV, unix.SYS_PWRITEV2}
	allowIndex := 3 + len(writes)
	notifIndex := allowIndex + 1
	program := make([]unix.SockFilter, 0, notifIndex+1)
	program = append(program, unix.SockFilter{Code: t17BpfLdWAbs, K: t17SeccompArchOffset})
	program = append(program, unix.SockFilter{Code: t17BpfJeqK, K: arch, Jt: 0, Jf: uint8(allowIndex - 2)})
	program = append(program, unix.SockFilter{Code: t17BpfLdWAbs, K: t17SeccompNROffset})
	for i, write := range writes {
		index := 3 + i
		program = append(program, unix.SockFilter{Code: t17BpfJeqK, K: write, Jt: uint8(notifIndex - index - 1), Jf: 0})
	}
	program = append(program, unix.SockFilter{Code: t17BpfRetK, K: t17RetAllow})
	program = append(program, unix.SockFilter{Code: t17BpfRetK, K: uint32(unix.SECCOMP_RET_USER_NOTIF)})
	return program, nil
}

// t17RecvFd receives one file descriptor sent over a unix socket.
func t17RecvFd(t *testing.T, sock int) int {
	t.Helper()
	buffer := make([]byte, 8)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(sock, buffer, oob, 0)
	if err != nil {
		t.Fatalf("receive the listener fd: %v", err)
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(messages) == 0 {
		t.Fatalf("parse the control message: %v", err)
	}
	fds, err := unix.ParseUnixRights(&messages[0])
	if err != nil || len(fds) == 0 {
		t.Fatalf("parse the passed fd: %v", err)
	}
	return fds[0]
}

// t17ServiceWrites reads write notifications, copies each write's buffer out of
// the observer at the point it is fixed, records it, and answers CONTINUE so the
// real write proceeds. It polls with a timeout and checks stop rather than
// blocking in the recv ioctl, so it always returns once the parent has set stop
// after the observer exits - it never leaves the gate to time out on a hang.
func t17ServiceWrites(listenerFd int, recorder *t17WriteRecorder, stop *int32) {
	fds := []unix.PollFd{{Fd: int32(listenerFd), Events: unix.POLLIN}}
	for {
		if atomic.LoadInt32(stop) != 0 {
			return
		}
		fds[0].Revents = 0
		n, err := unix.Poll(fds, 200)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		if n == 0 {
			continue
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			// A hang-up or error with no pending notification: the observer is gone.
			return
		}
		var notif t17SeccompNotif
		if err := t17Ioctl(listenerFd, unix.SECCOMP_IOCTL_NOTIF_RECV, unsafe.Pointer(&notif)); err != nil {
			// EINTR, or the target died between poll and recv (ENOENT): try again.
			continue
		}
		if t17NotifIDValid(listenerFd, notif.ID) {
			for _, chunk := range t17WriteBuffers(&notif) {
				recorder.add(chunk)
			}
		}
		resp := t17SeccompNotifResp{ID: notif.ID, Flags: uint32(unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE)}
		_ = t17Ioctl(listenerFd, unix.SECCOMP_IOCTL_NOTIF_SEND, unsafe.Pointer(&resp))
	}
}

// t17WriteBuffers reads the bytes one intercepted write would put on its
// descriptor, out of the observer's address space while the syscall is held.
func t17WriteBuffers(notif *t17SeccompNotif) [][]byte {
	pid := int(notif.Pid)
	switch int(notif.Data.NR) {
	case unix.SYS_WRITE, unix.SYS_PWRITE64:
		return [][]byte{t17ReadRemote(pid, notif.Data.Args[1], int(notif.Data.Args[2]))}
	case unix.SYS_WRITEV, unix.SYS_PWRITEV, unix.SYS_PWRITEV2:
		count := int(notif.Data.Args[2])
		if count < 0 || count > 1024 {
			count = 1024
		}
		vectors := t17ReadRemote(pid, notif.Data.Args[1], count*16)
		var chunks [][]byte
		for i := 0; i+16 <= len(vectors); i += 16 {
			base := binary.LittleEndian.Uint64(vectors[i:])
			length := int(binary.LittleEndian.Uint64(vectors[i+8:]))
			chunks = append(chunks, t17ReadRemote(pid, base, length))
		}
		return chunks
	default:
		return nil
	}
}

// t17ReadRemote copies up to t17WriteReadCap bytes from addr in the process pid.
func t17ReadRemote(pid int, addr uint64, length int) []byte {
	if length <= 0 || addr == 0 {
		return nil
	}
	if length > t17WriteReadCap {
		length = t17WriteReadCap
	}
	local := make([]byte, length)
	got, err := unix.ProcessVMReadv(pid,
		[]unix.Iovec{{Base: &local[0], Len: uint64(length)}},
		[]unix.RemoteIovec{{Base: uintptr(addr), Len: length}}, 0)
	if err != nil || got <= 0 {
		return nil
	}
	return local[:got]
}

func t17Ioctl(fd int, request uint, arg unsafe.Pointer) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

func t17NotifIDValid(fd int, id uint64) bool {
	return t17Ioctl(fd, unix.SECCOMP_IOCTL_NOTIF_ID_VALID, unsafe.Pointer(&id)) == nil
}

// t17WriteRecorder accumulates observed write bytes under a bound, for a scan
// that no single-write marker can escape.
type t17WriteRecorder struct {
	mutex  sync.Mutex
	buffer []byte
	writes int
	bytes  int
}

func (r *t17WriteRecorder) add(chunk []byte) {
	if len(chunk) == 0 {
		return
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.writes++
	r.bytes += len(chunk)
	if len(r.buffer)+len(chunk) <= t17WriteTotalCap {
		r.buffer = append(r.buffer, chunk...)
	}
}

func (r *t17WriteRecorder) snapshot() (int, int) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.writes, r.bytes
}

func (r *t17WriteRecorder) bytesSeen() []byte {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return append([]byte(nil), r.buffer...)
}
