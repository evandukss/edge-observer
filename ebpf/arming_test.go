//go:build attach

package ebpf_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/evandukss/edge-observer/bpf"
	observerebpf "github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

const armingProcessSource = `
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static SSL_CTX *context;
static int port;
static char *self;
static pid_t live_child;
static pid_t second_child;
static pid_t exec_child;
static pid_t failed_child;
static pid_t transient_child;

// Every transfer carries the pid of the process that made it.
static int transfer(void) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in address = {0};
	address.sin_family = AF_INET;
	address.sin_port = htons((unsigned short)port);
	inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) return 1;

	SSL *ssl = SSL_new(context);
	if (ssl == NULL) return 2;
	SSL_set_fd(ssl, fd);
	if (SSL_connect(ssl) != 1) return 3;
	char request[160];
	snprintf(request, sizeof(request),
	         "GET /arming-window-marker-%d HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	         (int)getpid());
	if (SSL_write(ssl, request, (int)strlen(request)) != (int)strlen(request)) return 4;
	char response[4096];
	while (SSL_read(ssl, response, sizeof(response)) > 0) {}
	SSL_free(ssl);
	close(fd);
	return 0;
}

// moves: 0 exits without transferring, 1 transfers, 2 forks a transferring
// child and then transfers, 3 execs this binary in transfer-only mode, 4
// attempts an exec that fails and then transfers.
static pid_t held_child(int moves) {
	pid_t child = fork();
	if (child != 0) return child;
	raise(SIGSTOP);
	if (moves == 2) {
		pid_t grand = fork();
		if (grand == 0) _exit(transfer());
		int status = 0;
		waitpid(grand, &status, 0);
	}
	if (moves == 3) {
		char number[16];
		snprintf(number, sizeof(number), "%d", port);
		execl(self, self, number, "transfer", (char *)NULL);
		_exit(20);
	}
	if (moves == 4) {
		char number[16];
		snprintf(number, sizeof(number), "%d", port);
		execl("/observer-fixture-that-does-not-exist", self, number, "transfer", (char *)NULL);
	}
	_exit(moves ? transfer() : 0);
}

int main(int argc, char **argv) {
	if (argc < 2) return 10;
	self = argv[0];
	port = atoi(argv[1]);
	context = SSL_CTX_new(TLS_client_method());
	if (context == NULL) return 11;
	SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);

	// The image an exec lands in: this same binary, transferring once, so the exec
	// is real.
	if (argc == 3 && strcmp(argv[2], "transfer") == 0) {
		int code = transfer();
		SSL_CTX_free(context);
		return code;
	}

	printf("ready\n");
	fflush(stdout);

	char command[8];
	while (fgets(command, sizeof(command), stdin) != NULL) {
		if (command[0] == 'L') {
			live_child = held_child(1);
			printf("live %d\n", live_child);
		} else if (command[0] == 'T') {
			transient_child = held_child(0);
			printf("transient %d\n", transient_child);
		} else if (command[0] == 'X') {
			kill(transient_child, SIGCONT);
			int status = 0;
			waitpid(transient_child, &status, 0);
			printf("transient-exited %d\n", status);
		} else if (command[0] == 'G') {
			kill(live_child, SIGCONT);
			int status = 0;
			waitpid(live_child, &status, 0);
			printf("live-exited %d\n", status);
		} else if (command[0] == 'M') {
			second_child = held_child(1);
			printf("second %d\n", second_child);
		} else if (command[0] == 'N') {
			kill(second_child, SIGCONT);
			int status = 0;
			waitpid(second_child, &status, 0);
			printf("second-exited %d\n", status);
		} else if (command[0] == 'D') {
			live_child = held_child(2);
			printf("deep %d\n", live_child);
		} else if (command[0] == 'E') {
			exec_child = held_child(3);
			printf("exec %d\n", exec_child);
		} else if (command[0] == 'F') {
			kill(exec_child, SIGCONT);
			int status = 0;
			waitpid(exec_child, &status, 0);
			printf("exec-exited %d\n", status);
		} else if (command[0] == 'B') {
			failed_child = held_child(4);
			printf("failed %d\n", failed_child);
		} else if (command[0] == 'C') {
			kill(failed_child, SIGCONT);
			int status = 0;
			waitpid(failed_child, &status, 0);
			printf("failed-exited %d\n", status);
		} else if (command[0] == 'S') {
			int code = transfer();
			printf("self %d %d\n", (int)getpid(), code);
		} else if (command[0] == 'Q') {
			// The root leaves its descendants running and goes, since what happens to a
			// family after its root exits is the question.
			printf("leaving %d\n", (int)getpid());
			fflush(stdout);
			if (live_child) kill(live_child, SIGCONT);
			if (second_child) kill(second_child, SIGCONT);
			_exit(0);
		}
		fflush(stdout);
	}
	SSL_CTX_free(context);
	return 0;
}
`

type armingProcess struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Reader
}

func startArmingProcess(t *testing.T, port int) *armingProcess {
	t.Helper()
	directory := t.TempDir()
	source := filepath.Join(directory, "arming_process.c")
	if err := os.WriteFile(source, []byte(armingProcessSource), 0o600); err != nil {
		t.Fatalf("write the arming-process source: %v", err)
	}
	binary := filepath.Join(directory, "arming_process")
	if output, err := exec.Command("cc", "-O2", "-o", binary, source, "-lssl", "-lcrypto").CombinedOutput(); err != nil {
		t.Fatalf("compile the arming process: %v\n%s", err, output)
	}

	command := exec.Command(binary, fmt.Sprint(port))
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("open the arming process input: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open the arming process output: %v", err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start the arming process: %v", err)
	}
	t.Cleanup(func() { _ = input.Close(); _ = command.Process.Kill(); _ = command.Wait() })

	fixture := &armingProcess{command: command, input: input, output: bufio.NewReader(stdout)}
	line, err := fixture.output.ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("the arming process did not become ready: %q %v", line, err)
	}
	return fixture
}

func (p *armingProcess) child(command byte, kind string) (int32, error) {
	if _, err := fmt.Fprintf(p.input, "%c\n", command); err != nil {
		return 0, err
	}
	line, err := p.output.ReadString('\n')
	if err != nil {
		return 0, err
	}
	var pid int32
	if _, err := fmt.Sscanf(line, kind+" %d", &pid); err != nil {
		return 0, fmt.Errorf("read %s child from %q: %w", kind, line, err)
	}
	return pid, nil
}

func (p *armingProcess) finish(command byte, kind string) error {
	if _, err := fmt.Fprintf(p.input, "%c\n", command); err != nil {
		return err
	}
	line, err := p.output.ReadString('\n')
	if err != nil {
		return err
	}
	var status int
	if _, err := fmt.Sscanf(line, kind+"-exited %d", &status); err != nil {
		return fmt.Errorf("read %s exit from %q: %w", kind, line, err)
	}
	if status != 0 {
		return fmt.Errorf("%s child exited with wait status %d", kind, status)
	}
	return nil
}

func forkPoint(t *testing.T, p process.Process) observerebpf.Point {
	t.Helper()
	mappings, err := process.Mappings(procfs, p.PID)
	if err != nil {
		t.Fatalf("read the arming process mappings: %v", err)
	}
	for _, mapping := range mappings {
		if !mapping.Executable || !strings.HasPrefix(filepath.Base(mapping.Path), "libc.so") {
			continue
		}
		path := filepath.Join(procfs, fmt.Sprint(p.PID), "root", mapping.Path)
		offsets, err := probe.SymbolOffsets(path, []string{"fork"})
		if err != nil {
			t.Fatalf("resolve fork in the arming process: %v", err)
		}
		offset, ok := offsets["fork"]
		if !ok {
			t.Fatalf("the arming process C library exports no fork symbol: %s", path)
		}
		// Built by the constructor rather than as a literal, so the point carries both
		// its entry and return programs.
		return observerebpf.ForkPoint("fork", path, offset)
	}
	t.Fatal("the arming process maps no executable C library")
	return observerebpf.Point{}
}

type seccompData struct {
	Number             int32
	Architecture       uint32
	InstructionPointer uint64
	Arguments          [6]uint64
}

type seccompNotification struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  seccompData
}

type seccompResponse struct {
	ID    uint64
	Value int64
	Error int32
	Flags uint32
}

const (
	classicLoadWordAbsolute = 0x20
	classicJumpEqual        = 0x15
	classicReturn           = 0x06
	seccompSetModeFilter    = 1
	seccompReturnAllow      = 0x7fff0000
)

func installArmingListener() (int, error) {
	filter := []unix.SockFilter{
		{Code: classicLoadWordAbsolute, K: 0},
		{Code: classicJumpEqual, Jf: 1, K: uint32(unix.SYS_OPENAT)},
		{Code: classicReturn, K: unix.SECCOMP_RET_USER_NOTIF},
		{Code: classicJumpEqual, Jf: 1, K: uint32(unix.SYS_BPF)},
		{Code: classicReturn, K: unix.SECCOMP_RET_USER_NOTIF},
		{Code: classicReturn, K: seccompReturnAllow},
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return -1, fmt.Errorf("set no-new-privileges for the arming fixture: %w", err)
	}
	fd, _, errno := unix.Syscall(unix.SYS_SECCOMP, seccompSetModeFilter,
		unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, uintptr(unsafe.Pointer(&program)))
	if errno != 0 {
		return -1, fmt.Errorf("install the arming syscall listener: %w", errno)
	}
	return int(fd), nil
}

// notificationPath reads a trapped call's path argument from the process that
// made the call, by the pid the kernel reports, since the address is only valid
// in that process. An actor that traps here must be visible in this pid
// namespace and readable by this process under ptrace rules. The read stands
// only if the call is still pending afterwards, so the pid was not reused.
func notificationPath(listener int, request seccompNotification) (string, error) {
	const maximum = 4096
	page := uintptr(os.Getpagesize())
	address := uintptr(request.Data.Arguments[1])
	var path []byte
	for len(path) < maximum {
		// To the end of the page, so a path that ends before an unmapped page reads.
		chunk := make([]byte, page-address%page)
		local := []unix.Iovec{{Base: &chunk[0]}}
		local[0].SetLen(len(chunk))
		remote := []unix.RemoteIovec{{Base: address, Len: len(chunk)}}
		n, err := unix.ProcessVMReadv(int(request.PID), local, remote, 0)
		if err != nil {
			return "", fmt.Errorf("read the path argument of pid %d: %w", request.PID, err)
		}
		if n == 0 {
			return "", fmt.Errorf("read the path argument of pid %d: no bytes at %#x", request.PID, address)
		}
		if end := bytes.IndexByte(chunk[:n], 0); end >= 0 {
			path = append(path, chunk[:end]...)
			// Re-check that the call is still pending: between the read above and
			// here the trapping task can exit and its pid be reused, and the bytes
			// would then be another process's. Removing this leaves every test
			// passing, because none can reuse a pid inside this window on demand,
			// so none exercises it. That holds until such a window can be staged.
			id := request.ID
			if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(listener),
				unix.SECCOMP_IOCTL_NOTIF_ID_VALID, uintptr(unsafe.Pointer(&id))); errno != 0 {
				return "", fmt.Errorf("the call pid %d trapped was not pending after its path was read: %w", request.PID, errno)
			}
			return string(path), nil
		}
		path = append(path, chunk[:n]...)
		address += uintptr(n)
	}
	return "", fmt.Errorf("the path argument of pid %d is not terminated within %d bytes", request.PID, maximum)
}

func notification(listener int, request *seccompNotification) error {
	for {
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(listener),
			unix.SECCOMP_IOCTL_NOTIF_RECV, uintptr(unsafe.Pointer(request)))
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			return errno
		}
		return nil
	}
}

func continueNotification(listener int, request seccompNotification) error {
	response := seccompResponse{ID: request.ID, Flags: unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(listener),
		unix.SECCOMP_IOCTL_NOTIF_SEND, uintptr(unsafe.Pointer(&response)))
	if errno != 0 {
		return errno
	}
	return nil
}

type armingChildren struct {
	live      int32
	transient int32
}

type armingCoordination struct {
	children chan armingChildren
	exited   chan struct{}
	errors   chan error
}

func coordinateArming(listener int, fixture *armingProcess) armingCoordination {
	coordination := armingCoordination{
		children: make(chan armingChildren, 1),
		exited:   make(chan struct{}, 1),
		errors:   make(chan error, 1),
	}
	go func() {
		windowOpen := false
		transientExited := false
		var children armingChildren
		for {
			var request seccompNotification
			if err := notification(listener, &request); err != nil {
				coordination.errors <- fmt.Errorf("receive an arming syscall: %w", err)
				return
			}

			var actionErr error
			opensProcfs := false
			if request.Data.Number == int32(unix.SYS_OPENAT) && !windowOpen {
				var path string
				path, actionErr = notificationPath(listener, request)
				opensProcfs = actionErr == nil && path == procfs
			}
			switch {
			case opensProcfs:
				children.live, actionErr = fixture.child('L', "live")
				if actionErr == nil {
					children.transient, actionErr = fixture.child('T', "transient")
				}
				if actionErr == nil {
					windowOpen = true
					coordination.children <- children
				}
			case request.Data.Number == int32(unix.SYS_BPF) && windowOpen && !transientExited:
				actionErr = fixture.finish('X', "transient")
				if actionErr == nil {
					transientExited = true
					coordination.exited <- struct{}{}
				}
			}

			if err := continueNotification(listener, request); actionErr == nil {
				actionErr = err
			}
			if actionErr != nil {
				coordination.errors <- actionErr
				return
			}
		}
	}()
	return coordination
}

const armingHelperEnvironment = "OBSERVER_ARMING_WINDOW_HELPER"

func exerciseArmingWindow(t *testing.T) {
	_, port := serving(t)
	fixture := startArmingProcess(t, port)
	parent := loaded(t, int32(fixture.command.Process.Pid))
	moveToCgroup(t, fmt.Sprintf("obs-arming-%d", os.Getpid()), parent.PID)

	runtime.LockOSThread()
	listener, err := installArmingListener()
	if err != nil {
		t.Fatalf("expose the interval between probe placement and descendant adoption: %v", err)
	}
	coordination := coordinateArming(listener, fixture)

	requested := append([]observerebpf.Point{forkPoint(t, parent)}, points(t, parent)...)
	session, err := observerebpf.Attach(observerebpf.Options{
		Program: bpf.Full(),
		Points:  requested,
		Admit:   authorise(parent),
	})
	if err != nil {
		t.Fatalf("attach while the children fork in the arming interval: %v", err)
	}
	defer func() { _ = session.Close() }()

	var children armingChildren
	select {
	case children = <-coordination.children:
	default:
		t.Fatal("the attachment completed without exposing the interval after probe placement and before descendant adoption")
	}
	select {
	case <-coordination.exited:
	default:
		t.Fatal("the transient child did not exit after the adoption reading and before its allowlist write")
	}
	select {
	case err := <-coordination.errors:
		t.Fatalf("coordinate children inside the arming interval: %v", err)
	default:
	}

	// What the kernel holds, read back through the session: an entry for a gone
	// process is an approval waiting for its number to be reused.
	held, err := session.Admissions()
	if err != nil {
		t.Fatalf("read back what the session admitted: %v", err)
	}
	if len(held) == 0 {
		t.Fatal("the session admitted nothing, so an absent entry for the exited child proves nothing")
	}
	for _, one := range held {
		if one.Instance.Namespace == parent.Namespace && one.Instance.PID == children.transient {
			t.Errorf("a child that exited during arming left %s behind", one)
		}
	}

	if err := fixture.finish('G', "live"); err != nil {
		t.Fatalf("the live child did not move its planted plaintext: %v", err)
	}
	captured := drain(session, 700*time.Millisecond)
	const marker = "arming-window-marker"
	appearances := 0
	for _, event := range captured.events {
		if event.Kind == observerebpf.Transfer && event.Direction == fragment.Sent &&
			strings.Contains(string(event.Payload), marker) {
			appearances++
		}
	}
	if appearances == 0 {
		t.Error("a child forked during arming moved planted plaintext, and none of its bytes appeared")
	}
	if appearances != 1 {
		t.Errorf("a child forked during arming produced %d copies of one planted plaintext transfer, want exactly one", appearances)
	}
}

func TestAChildForkedDuringArmingIsObservedExactlyOnceAndLeavesNoApproval(t *testing.T) {
	if os.Getenv(armingHelperEnvironment) == "1" {
		exerciseArmingWindow(t)
		return
	}

	arguments := []string{
		"-test.run=^TestAChildForkedDuringArmingIsObservedExactlyOnceAndLeavesNoApproval$",
		"-test.v",
	}
	arguments = append(arguments, childDeadline(t))

	command := exec.Command(os.Args[0], arguments...)
	command.Env = append(os.Environ(), armingHelperEnvironment+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("the arming-window property failed in its syscall-isolated process: %v\n%s", err, output)
	}
}

// childDeadlineMargin is what the child needs after giving up to dump every
// goroutine and exit, and the parent to read the output, before the parent's
// deadline.
const childDeadlineMargin = 30 * time.Second

// childDeadlineAlone is the child's deadline when the parent has none (the
// binary run directly), bounding a hang.
const childDeadlineAlone = 4 * time.Minute

// childDeadline is the isolated child's timeout, derived in the parent and
// passed down. The child runs under exec with no deadline of its own, so
// without this a blocked child is outlived by the parent's timeout, whose
// panic shows only the parent's goroutines. The parent's deadline is the
// package's, partly consumed by earlier tests, so the remaining budget
// (t.Deadline) is the input. Asking inside the child would reinstate the
// problem: it has no deadline by construction.
func childDeadline(t *testing.T) string {
	t.Helper()
	deadline, set := t.Deadline()
	if !set {
		return "-test.timeout=" + childDeadlineAlone.String()
	}
	budget := time.Until(deadline) - childDeadlineMargin
	if budget <= 0 {
		// Too little of the parent's budget is left for the child to give up inside
		// it.
		return "-test.timeout=0"
	}
	return "-test.timeout=" + budget.String()
}
