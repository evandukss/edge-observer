//go:build attach

package ebpf_test

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/process"
)

// The kernel raises one fork event for a new process and for a new thread. A
// thread admitted as a process would leave an entry no lookup uses and no exit
// removes; a process taken for a thread would go unobserved silently. The
// fixture creates one of each in one run.
const birthProcessSource = `
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static SSL_CTX *context;
static int port;

// Every transfer carries the id of the task that made it (the thread id), which
// tells a thread's transfer from its process's.
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
	         "GET /birth-marker-%d HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
	         (int)syscall(SYS_gettid));
	if (SSL_write(ssl, request, (int)strlen(request)) != (int)strlen(request)) return 4;
	char response[4096];
	while (SSL_read(ssl, response, sizeof(response)) > 0) {}
	SSL_free(ssl);
	close(fd);
	return 0;
}

static long thread_id;
static pid_t held_process;

static void *worker(void *unused) {
	(void)unused;
	thread_id = (long)syscall(SYS_gettid);
	transfer();
	return NULL;
}

int main(int argc, char **argv) {
	if (argc < 2) return 10;
	port = atoi(argv[1]);
	context = SSL_CTX_new(TLS_client_method());
	if (context == NULL) return 11;
	SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);

	printf("ready\n");
	fflush(stdout);

	char command[8];
	while (fgets(command, sizeof(command), stdin) != NULL) {
		if (command[0] == 'T') {
			// A thread of this process, transferring, so a capture says whether the
			// group's grant covers it.
			pthread_t worker_thread;
			thread_id = 0;
			if (pthread_create(&worker_thread, NULL, worker, NULL) != 0) {
				printf("thread 0\n");
			} else {
				pthread_join(worker_thread, NULL);
				printf("thread %ld\n", thread_id);
			}
		} else if (command[0] == 'H') {
			// A process that stops itself, so it can be read while alive: an exited child
			// holds no entry and appears in no table.
			pid_t child = fork();
			if (child == 0) {
				raise(SIGSTOP);
				_exit(transfer());
			}
			held_process = child;
			printf("held %d\n", (int)child);
		} else if (command[0] == 'R') {
			kill(held_process, SIGCONT);
			int status = 0;
			waitpid(held_process, &status, 0);
			printf("held-exited %d\n", status);
		} else if (command[0] == 'N') {
			// A child in its own, unenumerated pid namespace: unshare puts the next fork's
			// child there.
			if (unshare(CLONE_NEWPID) != 0) {
				printf("namespaced -1\n");
			} else {
				pid_t child = fork();
				if (child == 0) _exit(transfer());
				int status = 0;
				waitpid(child, &status, 0);
				printf("namespaced %d\n", (int)child);
			}
		}
		fflush(stdout);
	}
	SSL_CTX_free(context);
	return 0;
}
`

type birthProcess struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Reader

	// stopped is every child left stopped, killed at the end: they inherited the
	// test binary's stdout, and one left behind keeps that pipe open, so the runner
	// waits a minute ("Test I/O incomplete 1m0s after exiting").
	stopped []int32
}

func startBirthProcess(t *testing.T, port int) *birthProcess {
	t.Helper()
	directory := t.TempDir()
	source := filepath.Join(directory, "birth_process.c")
	if err := os.WriteFile(source, []byte(birthProcessSource), 0o600); err != nil {
		t.Fatalf("write the fixture source: %v", err)
	}
	binary := filepath.Join(directory, "birth_process")
	build := exec.Command("cc", "-O2", "-o", binary, source, "-lssl", "-lcrypto", "-lpthread")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile the fixture: %v\n%s", err, output)
	}

	command := exec.Command(binary, fmt.Sprint(port))
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("open the fixture input: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("open the fixture output: %v", err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start the fixture: %v", err)
	}

	fixture := &birthProcess{command: command, input: input, output: bufio.NewReader(stdout)}
	t.Cleanup(func() {
		for _, pid := range fixture.stopped {
			_ = syscall.Kill(int(pid), syscall.SIGKILL)
		}
		_ = input.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	line, err := fixture.output.ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("the fixture did not become ready: %q %v", line, err)
	}
	return fixture
}

// task drives one command and reads back the id the fixture reports for it.
func (p *birthProcess) task(command byte, kind string) (int32, error) {
	if _, err := fmt.Fprintf(p.input, "%c\n", command); err != nil {
		return 0, err
	}
	line, err := p.output.ReadString('\n')
	if err != nil {
		return 0, err
	}
	var id int32
	if _, err := fmt.Sscanf(line, kind+" %d", &id); err != nil {
		return 0, fmt.Errorf("read the %s id from %q: %w", kind, line, err)
	}
	if kind == "held" && id > 0 {
		p.stopped = append(p.stopped, id)
	}
	return id, nil
}

// release lets the held child run, so its transfer happens where a capture can
// see it.
func (p *birthProcess) release() error {
	if _, err := fmt.Fprintf(p.input, "R\n"); err != nil {
		return err
	}
	line, err := p.output.ReadString('\n')
	if err != nil {
		return err
	}
	var status int
	if _, err := fmt.Sscanf(line, "held-exited %d", &status); err != nil {
		return fmt.Errorf("read the held child's exit from %q: %w", line, err)
	}
	if status != 0 {
		return fmt.Errorf("the held child exited with wait status %d", status)
	}
	return nil
}

// entryFor is the allowlist row for one number in the root's namespace, as the
// kernel holds it. Held, not Admissions, which reconciles and removes entries
// first.
func entryFor(t *testing.T, session *ebpf.Session, root process.Process, pid int32) (ebpf.Entry, bool) {
	t.Helper()
	held, err := session.Held()
	if err != nil {
		t.Fatalf("read the allowlist as the kernel holds it: %v", err)
	}
	if len(held) == 0 {
		t.Fatal("the allowlist is empty, so an absent entry says nothing about what put entries there")
	}
	for _, one := range held {
		if one.Instance.Namespace == root.Namespace && one.Instance.PID == pid {
			return one, true
		}
	}
	return ebpf.Entry{}, false
}

func TestAThreadIsNotAdmittedAsAProcessAndAProcessIsStillAdmitted(t *testing.T) {
	_, port := serving(t)
	fixture := startBirthProcess(t, port)
	root := loaded(t, int32(fixture.command.Process.Pid))

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  append([]ebpf.Point{forkPoint(t, root)}, points(t, root)...),
		Admit:   admitting(root, admission.ModeFollow),
	})
	if err != nil {
		t.Fatalf("attach to the fixture: %v", err)
	}
	defer func() { _ = session.Close() }()

	thread, err := fixture.task('T', "thread")
	if err != nil {
		t.Fatalf("the fixture did not run a thread: %v", err)
	}
	if thread == 0 {
		t.Fatal("the fixture could not create a thread, so nothing here measures what one does")
	}
	child, err := fixture.task('H', "held")
	if err != nil {
		t.Fatalf("the fixture did not fork a process: %v", err)
	}
	held(t, child)

	// The control: the same event in the same run admitted a process, read while
	// it is alive.
	if _, admitted := entryFor(t, session, root, child); !admitted {
		t.Fatalf("the process the fixture forked, pid %d, holds no entry while it is alive, so a "+
			"thread holding none proves nothing about how threads are treated", child)
	}
	if one, admitted := entryFor(t, session, root, thread); admitted {
		t.Errorf("the thread the fixture created, task %d, holds an entry of its own: %v. The "+
			"allowlist is keyed by the thread group, so nothing looks that number up and no "+
			"process exit removes it", thread, one)
	}

	// And the thread's transfer is observed under its group's grant: not admitted,
	// not lost.
	if err := fixture.release(); err != nil {
		t.Fatalf("the held child did not transfer: %v", err)
	}
	captured := drain(session, 900*time.Millisecond)
	var moved []string
	moved = append(moved, captured.plaintext(fragment.Sent)...)
	moved = append(moved, captured.plaintext(fragment.Received)...)
	if !containsSubstring(moved, fmt.Sprintf("birth-marker-%d", thread)) {
		t.Errorf("the thread's own transfer produced no bytes, so its group's grant did not cover it")
	}
	if !containsSubstring(moved, fmt.Sprintf("birth-marker-%d", child)) {
		t.Errorf("the forked process's transfer produced no bytes")
	}
}

// A child given its own pid namespace is in one nobody enumerated, so no entry
// for it could be found. It is refused, counted and named at the session's
// surface as itself: not a naming failure (a host condition) but a short
// enumeration an operator can lengthen.
func TestAChildInANamespaceNobodyEnumeratedIsRefusedAndCounted(t *testing.T) {
	_, port := serving(t)
	fixture := startBirthProcess(t, port)
	root := loaded(t, int32(fixture.command.Process.Pid))

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  append([]ebpf.Point{forkPoint(t, root)}, points(t, root)...),
		Admit:   admitting(root, admission.ModeFollow),
	})
	if err != nil {
		t.Fatalf("attach to the fixture: %v", err)
	}
	defer func() { _ = session.Close() }()

	before, err := session.Refusals()
	if err != nil {
		t.Fatalf("read the refusals before anything was refused: %v", err)
	}
	if before.Counted[ebpf.ChildNamespaceUnenumerated] != 0 {
		t.Fatalf("the run began with %d children already in a namespace nobody enumerated, so a "+
			"rise proves nothing", before.Counted[ebpf.ChildNamespaceUnenumerated])
	}

	// The control first, in the same run: an ordinary child, admitted.
	ordinary, err := fixture.task('H', "held")
	if err != nil {
		t.Fatalf("the fixture did not fork a process: %v", err)
	}
	held(t, ordinary)
	if _, admitted := entryFor(t, session, root, ordinary); !admitted {
		t.Fatalf("the ordinary child, pid %d, holds no entry, so a refusal below cannot be told "+
			"from a fork event that admits nothing at all", ordinary)
	}

	if _, err := fixture.task('N', "namespaced"); err != nil {
		t.Fatalf("the fixture did not fork into a namespace of its own: %v", err)
	}

	after, err := session.Refusals()
	if err != nil {
		t.Fatalf("read the refusals: %v", err)
	}
	if after.Counted[ebpf.ChildNamespaceUnenumerated] <= before.Counted[ebpf.ChildNamespaceUnenumerated] {
		t.Errorf("a child was created in a pid namespace this session did not enumerate and the "+
			"count of exactly that stayed at %d, so the refusal is not reported anywhere a reader "+
			"would find it", after.Counted[ebpf.ChildNamespaceUnenumerated])
	}

	// Neither of the two counters a reader acts differently on may absorb this.
	if after.Counted[ebpf.ChildUnnameable] != before.Counted[ebpf.ChildUnnameable] {
		t.Errorf("a child created in an unenumerated namespace moved the count of children that "+
			"could not be named, from %d to %d, so the two facts are one number and a reader "+
			"cannot tell a host condition from an enumeration that is short",
			before.Counted[ebpf.ChildUnnameable], after.Counted[ebpf.ChildUnnameable])
	}
	if after.Counted[ebpf.NotTheApprovedOccupant] != before.Counted[ebpf.NotTheApprovedOccupant] {
		t.Errorf("a child that could not be named moved the count of tasks refused for not being "+
			"the approved occupant, from %d to %d: a reader acts differently on the two and they "+
			"must not be one number",
			before.Counted[ebpf.NotTheApprovedOccupant], after.Counted[ebpf.NotTheApprovedOccupant])
	}
}

// A surviving descendant keeps its grant when its root exits and keeps
// admitting what it creates, although grants are bound to a thread group's
// birth and the root is gone.
func TestASurvivorsGrantIsAuthenticatedAgainstItsOwnBirthAndNotItsRoots(t *testing.T) {
	_, port := serving(t)
	fixture := startBirthProcess(t, port)
	root := loaded(t, int32(fixture.command.Process.Pid))

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  append([]ebpf.Point{forkPoint(t, root)}, points(t, root)...),
		Admit:   admitting(root, admission.ModeFollow),
	})
	if err != nil {
		t.Fatalf("attach to the fixture: %v", err)
	}
	defer func() { _ = session.Close() }()

	child, err := fixture.task('H', "held")
	if err != nil {
		t.Fatalf("the fixture did not fork a process: %v", err)
	}
	held(t, child)
	entry, admitted := entryFor(t, session, root, child)
	if !admitted {
		t.Fatalf("the child the fixture forked, pid %d, holds no entry", child)
	}
	if !entry.Instance.Start.Determined {
		t.Fatalf("the child's grant carries no birth, so nothing separates it from the next "+
			"process to hold pid %d", child)
	}

	// The birth the kernel established for the child is the child's own; both are
	// alive, so the parent's would pass every other assertion.
	parent, found := entryFor(t, session, root, root.NamespacePID)
	if !found {
		t.Fatalf("the approved root holds no entry of its own")
	}
	if entry.Instance.Start == parent.Instance.Start {
		t.Errorf("the child's grant carries the same birth as its parent's, %v, so it names the "+
			"parent's thread group and not the child's", entry.Instance.Start)
	}
	if entry.Parent.PID != root.NamespacePID {
		t.Errorf("the child's grant names parent pid %d and its creator was %d",
			entry.Parent.PID, root.NamespacePID)
	}
}

// The birth a grant carries is the one /proc reports for the same process,
// though established by different code on each side of the kernel boundary; a
// wrong conversion would refuse every read inexplicably.
func TestTheBirthAGrantCarriesIsTheOneProcReportsForThatProcess(t *testing.T) {
	_, port := serving(t)
	fixture := startBirthProcess(t, port)
	root := loaded(t, int32(fixture.command.Process.Pid))

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  append([]ebpf.Point{forkPoint(t, root)}, points(t, root)...),
		Admit:   admitting(root, admission.ModeFollow),
	})
	if err != nil {
		t.Fatalf("attach to the fixture: %v", err)
	}
	defer func() { _ = session.Close() }()

	// A child, whose entry the kernel wrote from a task_struct, against /proc (the
	// root's entry was written from /proc by userspace), read while the child is
	// alive.
	child, err := fixture.task('H', "held")
	if err != nil {
		t.Fatalf("the fixture did not fork a process: %v", err)
	}
	held(t, child)

	entry, admitted := entryFor(t, session, root, child)
	if !admitted {
		t.Fatalf("the child the fixture forked, pid %d, holds no entry, so there is no kernel-side "+
			"birth here to compare against", child)
	}
	if entry.Kind != admission.ByDescent {
		t.Fatalf("pid %d holds an entry of kind %v, and only one the fork event wrote carries a "+
			"birth this session did not read out of /proc itself", child, entry.Kind)
	}
	table, err := process.Read(procfs)
	if err != nil {
		t.Fatalf("read the process table: %v", err)
	}
	reported, found := table.Lookup(child)
	if !found {
		t.Fatalf("pid %d is not in the process table while it is stopped, so nothing here compares "+
			"the two sides", child)
	}
	if !reported.Start().Determined {
		t.Fatalf("/proc reports no start for pid %d", child)
	}
	if reported.Start() != entry.Instance.Start {
		t.Errorf("pid %d holds a grant born %v and /proc reports %v for the same process, so the "+
			"number the kernel establishes and the number userspace reads are not one identity - "+
			"every grant userspace writes would then be authenticated against the wrong value",
			child, entry.Instance.Start, reported.Start())
	}
}
