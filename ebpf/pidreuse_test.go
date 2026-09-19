//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/process"
)

// An unselected supervisor creates the selected root and, later, an unselected
// replacement for a child that root has reaped. PID allocation is controlled
// inside this fixture's private pid namespace, which the observer shares, so
// the sweep sees the reused number itself.
func reuseFamilySource() string {
	prefix, _, _ := strings.Cut(immediateForkSource(), "static int wait_in_parent;")
	return "#define _GNU_SOURCE\n" + prefix + `
#include <fcntl.h>
#include <sys/mount.h>

static int hostproc;
struct identity { int local; int observer; };
static int observer_pid(void) {
	int fd = openat(hostproc, "self/status", O_RDONLY);
	if (fd < 0) _exit(40);
	char data[8192] = {0};
	if (read(fd, data, sizeof(data)-1) <= 0) _exit(41);
	close(fd);
	char *line = strstr(data, "NSpid:");
	int pid = 0;
	if (!line || sscanf(line, "NSpid: %d", &pid) != 1) _exit(42);
	return pid;
}
static void put(int fd, const void *p, size_t n) {
	if (write(fd, p, n) != (ssize_t)n) _exit(43);
}
static void get(int fd, void *p, size_t n) {
	if (read(fd, p, n) != (ssize_t)n) _exit(44);
}
static void root_loop(int commands, int answers) {
	int host = observer_pid(); put(answers, &host, sizeof(host));
	pid_t old = 0;
	char command;
	while (read(commands, &command, 1) == 1) {
		if (command == 'T') {
			int identity_pipe[2];
			if (pipe(identity_pipe)) _exit(45);
			old = fork();
			if (old < 0) _exit(46);
			if (old == 0) {
				close(identity_pipe[0]);
				struct identity who = {getpid(), observer_pid()};
				put(identity_pipe[1], &who, sizeof(who));
				raise(SIGSTOP);
				_exit(0);
			}
			close(identity_pipe[1]);
			struct identity who; get(identity_pipe[0], &who, sizeof(who)); close(identity_pipe[0]);
			int status;
			if (waitpid(old, &status, WUNTRACED) != old || !WIFSTOPPED(status)) _exit(47);
			put(answers, &who, sizeof(who));
		} else if (command == 'X') {
			// Distinguish start ticks even if adoption reads this tiny family
			// faster than one clock tick.
			usleep(30000);
			if (kill(old, SIGCONT)) _exit(48);
			int status;
			if (waitpid(old, &status, 0) != old || status != 0) _exit(49);
			put(answers, &status, sizeof(status));
		} else if (command == 'P') {
			int result = transfer("/independent-reuse-control");
			put(answers, &result, sizeof(result));
		}
	}
	_exit(0);
}
int main(int argc, char **argv) {
	if (argc != 2) return 10;
	port = atoi(argv[1]);
	hostproc = open("/proc", O_RDONLY|O_DIRECTORY);
	if (hostproc < 0) return 50;
	if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)) return 51;
	if (mount("proc", "/proc", "proc", 0, NULL)) return 52;
	context = SSL_CTX_new(TLS_client_method());
	if (!context) return 11;
	SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
	int to_root[2], from_root[2];
	if (pipe(to_root) || pipe(from_root)) return 53;
	pid_t root = fork();
	if (root < 0) return 54;
	if (root == 0) {
		close(to_root[1]); close(from_root[0]);
		root_loop(to_root[0], from_root[1]);
	}
	close(to_root[0]); close(from_root[1]);
	int root_host; get(from_root[0], &root_host, sizeof(root_host));
	printf("ready\nselected %d\n", root_host); fflush(stdout);
	struct identity old = {0};
	pid_t replacement = 0;
	char command[8];
	while (fgets(command, sizeof(command), stdin)) {
		if (command[0] == 'T') {
			put(to_root[1], "T", 1);
			get(from_root[0], &old, sizeof(old));
			printf("old %d %d\n", old.local, old.observer);
		} else if (command[0] == 'X') {
			put(to_root[1], "X", 1);
			int result; get(from_root[0], &result, sizeof(result));
			int last = open("/proc/sys/kernel/ns_last_pid", O_WRONLY);
			if (last < 0 || dprintf(last, "%d", old.local-1) <= 0) return 55;
			close(last);
			int identity_pipe[2];
			if (pipe(identity_pipe)) return 56;
			replacement = fork();
			if (replacement < 0) return 57;
			if (replacement == 0) {
				close(identity_pipe[0]);
				struct identity who = {getpid(), observer_pid()};
				put(identity_pipe[1], &who, sizeof(who));
				raise(SIGSTOP);
				_exit(transfer("/independent-reused-key"));
			}
			close(identity_pipe[1]);
			struct identity who; get(identity_pipe[0], &who, sizeof(who)); close(identity_pipe[0]);
			int status;
			if (waitpid(replacement, &status, WUNTRACED) != replacement || !WIFSTOPPED(status)) return 58;
			printf("replacement %d %d\n", who.local, who.observer);
		} else if (command[0] == 'G') {
			if (kill(replacement, SIGCONT)) return 59;
			int status;
			if (waitpid(replacement, &status, 0) != replacement) return 60;
			printf("replacement-exited %d\n", status);
		} else if (command[0] == 'P') {
			put(to_root[1], "P", 1);
			int result; get(from_root[0], &result, sizeof(result));
			printf("parent %d\n", result);
		}
		fflush(stdout);
	}
	return 0;
}
`
}

type reusedIdentity struct {
	local, observer int32
}

func reuseCommand(actor *armingProcess, command, kind string) (reusedIdentity, error) {
	if _, err := io.WriteString(actor.input, command+"\n"); err != nil {
		return reusedIdentity{}, err
	}
	line, err := actor.output.ReadString('\n')
	var who reusedIdentity
	if _, scanErr := fmt.Sscanf(line, kind+" %d %d", &who.local, &who.observer); err != nil || scanErr != nil || who.local <= 0 || who.observer <= 0 {
		return who, fmt.Errorf("%s identity: %q: %v, %v", kind, line, err, scanErr)
	}
	return who, nil
}

func exerciseIndependentPIDReuse(t *testing.T) {
	port, received := independentPeer(t)
	actor := independentActor(t, reuseFamilySource(), port)
	line, err := actor.output.ReadString('\n')
	var rootPID int32
	if _, scanErr := fmt.Sscanf(line, "selected %d", &rootPID); err != nil || scanErr != nil || rootPID <= 0 {
		t.Fatalf("selected root: %q: %v, %v", line, err, scanErr)
	}
	root := loaded(t, rootPID)
	type result struct {
		old, replacement process.Process
		err              error
	}
	coordinated := make(chan result, 1)
	runtime.LockOSThread()
	listener, err := installArmingListener()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		var staged result
		var old reusedIdentity
		opened, replaced := false, false
		for {
			var request seccompNotification
			if err := notification(listener, &request); err != nil {
				coordinated <- result{err: err}
				return
			}
			switch {
			case !opened && request.Data.Number == int32(unix.SYS_OPENAT) && notificationPath(request.Data.Arguments[1]) == procfs:
				old, staged.err = reuseCommand(actor, "T", "old")
				if staged.err == nil {
					staged.old, staged.err = process.Identify(procfs, old.observer)
				}
				opened = true
			case opened && !replaced && request.Data.Number == int32(unix.SYS_BPF):
				var next reusedIdentity
				next, staged.err = reuseCommand(actor, "X", "replacement")
				if staged.err == nil && next.local != old.local {
					staged.err = fmt.Errorf("replacement local pid %d did not reuse %d", next.local, old.local)
				}
				if staged.err == nil {
					staged.replacement, staged.err = process.Identify(procfs, next.observer)
				}
				replaced = true
				coordinated <- staged
			}
			if err := continueNotification(listener, request); err != nil {
				coordinated <- result{err: err}
				return
			}
			if staged.err != nil {
				if !replaced {
					coordinated <- staged
				}
				return
			}
		}
	}()
	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(), Points: append(points(t, root), independentForkPoint(t, root)), Admit: authorise(root),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	var staged result
	select {
	case staged = <-coordinated:
		if staged.err != nil {
			t.Fatal(staged.err)
		}
	default:
		t.Fatal("adoption completed without the independently controlled pid reuse")
	}
	if staged.old.PID != staged.replacement.PID || staged.old.Namespace != staged.replacement.Namespace || staged.old.NamespacePID != staged.replacement.NamespacePID ||
		staged.old.StartTime == staged.replacement.StartTime || staged.old.PPID != rootPID || staged.replacement.PPID == rootPID {
		t.Fatalf("reuse and unselected replacement parent were not established: old %+v, new %+v", staged.old, staged.replacement)
	}
	if _, err := io.WriteString(actor.input, "P\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "parent 0\n")
	peerReceived(t, received, "/independent-reuse-control")
	if attribution(drain(session, 100*time.Millisecond), "/independent-reuse-control") == nil {
		t.Fatal("approved root control was not captured")
	}
	if err := actor.finish('G', "replacement"); err != nil {
		t.Fatal(err)
	}
	peerReceived(t, received, "/independent-reused-key")
	if got := attribution(drain(session, 100*time.Millisecond), "/independent-reused-key"); got != nil {
		t.Errorf("pid reused between adoption's read and sweep admitted an unselected sibling's transfer: %+v", got)
	}
}

func TestPIDReusedBetweenAdoptionAndSweepIsNotAdmitted(t *testing.T) {
	const environment = "OBSERVER_INDEPENDENT_REUSE_HELPER"
	if os.Getenv(environment) == "1" {
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mount("proc", "/proc", "proc", 0, ""); err != nil {
			t.Fatal(err)
		}
		exerciseIndependentPIDReuse(t)
		return
	}
	command := exec.Command(os.Args[0], "-test.run=^TestPIDReusedBetweenAdoptionAndSweepIsNotAdmitted$", "-test.v", "-test.timeout=45s")
	command.Env = append(os.Environ(), environment+"=1")
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWPID | unix.CLONE_NEWNS}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("pid reuse property failed in its syscall-isolated process: %v\n%s", err, output)
	}
}
