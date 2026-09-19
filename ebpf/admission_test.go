//go:build attach

package ebpf_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/process"
)

// The peer is a Go TLS server, so the OpenSSL probes cannot observe it. Its
// receipt and the client's checked response establish both halves of each
// exchange independently of the observer and of the client's stdout.
func independentPeer(t *testing.T) (int, <-chan string) {
	t.Helper()
	received := make(chan string, 32)
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.URL.Path
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, "peer-confirmed:"+r.URL.Path)
	}))
	t.Cleanup(peer.Close)
	port, err := strconv.Atoi(strings.TrimPrefix(peer.URL, "https://127.0.0.1:"))
	if err != nil {
		t.Fatalf("peer endpoint: %s: %v", peer.URL, err)
	}
	return port, received
}

func peerReceived(t *testing.T, received <-chan string, want string) {
	t.Helper()
	select {
	case got := <-received:
		if got != want {
			t.Fatalf("peer received %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("peer did not receive %s", want)
	}
}

// The OpenSSL setup comes from the arming fixture; this actor takes an
// explicit path argument and verifies the peer response.
const independentTransferSource = `
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static SSL_CTX *context;
static int port;
static pid_t live_child;
static pid_t transient_child;
static int transfer(const char *path) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) return 1;
    SSL *ssl = SSL_new(context);
    if (!ssl) return 2;
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) return 3;
    char request[512];
    snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path);
    if (SSL_write(ssl, request, (int)strlen(request)) != (int)strlen(request)) return 4;
    char response[8192] = {0};
    size_t used = 0;
    int n;
    while (used < sizeof(response)-1 && (n = SSL_read(ssl, response+used, sizeof(response)-1-used)) > 0) used += n;
    char expected[512];
    snprintf(expected, sizeof(expected), "peer-confirmed:%s", path);
    if (strstr(response, expected) == NULL) return 5;
    SSL_free(ssl);
    close(fd);
    return 0;
}
`

// libc invokes this callback before fork returns in the parent. The child is
// never stopped; the callback waits for its completed transfer and exit.
func immediateForkSource() string {
	return independentTransferSource + `
static int wait_in_parent;
static int parent_wait_status;
static void before_parent_return(void) {
	if (!wait_in_parent) return;
	if (waitpid(-1, &parent_wait_status, 0) <= 0) _exit(20);
	printf("before-parent-return %d\n", parent_wait_status);
	fflush(stdout);
}
int main(int argc, char **argv) {
	if (argc != 2) return 10;
	port = atoi(argv[1]);
	context = SSL_CTX_new(TLS_client_method());
	if (context == NULL) return 11;
	SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
	if (pthread_atfork(NULL, before_parent_return, NULL) != 0) return 12;
	printf("ready\n"); fflush(stdout);
	char command[8];
	while (fgets(command, sizeof(command), stdin)) {
		if (command[0] == 'P') {
			printf("parent %d\n", transfer("/independent-parent"));
		} else if (command[0] == 'F') {
			wait_in_parent = 1;
			pid_t child = fork();
			if (child < 0) return 13;
			if (child == 0) {
				printf("child %d\n", getpid()); fflush(stdout);
				_exit(transfer("/independent-immediate-child"));
			}
			printf("parent-returned %d\n", child);
		}
		fflush(stdout);
	}
	return 0;
}
`
}

func independentActor(t *testing.T, source string, port int) *armingProcess {
	t.Helper()
	return independentActorIn(t, source, port, 0)
}

func independentActorIn(t *testing.T, source string, port int, cloneflags uintptr) *armingProcess {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "actor.c")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "actor")
	if out, err := exec.Command("cc", "-O2", "-pthread", "-o", binary, path, "-lssl", "-lcrypto").CombinedOutput(); err != nil {
		t.Fatalf("compile actor: %v\n%s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, binary, fmt.Sprint(port))
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Cloneflags: cloneflags}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close(); _ = command.Cancel(); _ = command.Wait() })
	actor := &armingProcess{command: command, input: input, output: bufio.NewReader(output)}
	actorLine(t, actor, "ready\n")
	return actor
}

func actorLine(t *testing.T, actor *armingProcess, want string) {
	t.Helper()
	got, err := actor.output.ReadString('\n')
	if err != nil || got != want {
		t.Fatalf("actor said %q, want %q: %v", got, want, err)
	}
}

func TestChildTransfersBeforeItsParentsForkReturn(t *testing.T) {
	port, received := independentPeer(t)
	actor := independentActor(t, immediateForkSource(), port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(), Points: append(points(t, parent), independentForkPoint(t, parent)), Admit: authorise(parent),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	if _, err := io.WriteString(actor.input, "P\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "parent 0\n")
	peerReceived(t, received, "/independent-parent")
	control := drain(session, 100*time.Millisecond)
	if attribution(control, "/independent-parent") == nil {
		t.Fatal("approved parent control was not captured")
	}
	if _, err := io.WriteString(actor.input, "F\n"); err != nil {
		t.Fatal(err)
	}
	line, err := actor.output.ReadString('\n')
	var child int32
	if _, scanErr := fmt.Sscanf(line, "child %d", &child); err != nil || scanErr != nil || child <= 0 {
		t.Fatalf("child identity: %q: %v, %v", line, err, scanErr)
	}
	actorLine(t, actor, "before-parent-return 0\n")
	actorLine(t, actor, fmt.Sprintf("parent-returned %d\n", child))
	peerReceived(t, received, "/independent-immediate-child")
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", child)); !os.IsNotExist(err) {
		t.Fatalf("child was not reaped before the parent's fork return: %v", err)
	}
	got := drain(session, 100*time.Millisecond)
	descendants, descendantsErr := session.Descendants()
	if descendantsErr != nil {
		t.Fatalf("same-run descendant admission counter could not be read: %v", descendantsErr)
	}
	t.Logf("same-run DESCENDANTS=%d after the child completed and was reaped before the parent's fork return", descendants)
	count := 0
	for _, event := range got.events {
		if event.Kind != ebpf.Transfer || event.Direction != fragment.Sent || !strings.Contains(string(event.Payload), "/independent-immediate-child") {
			continue
		}
		count++
		if event.Namespace != parent.Namespace || event.NamespacePID != child || !event.Generation.FromKernel() {
			t.Errorf("child transfer has the wrong instance: %+v", event)
		}
	}
	if count != 1 {
		t.Errorf("peer-confirmed child transfer before the parent's fork return appeared %d times, want 1", count)
	}
	held, err := session.Admissions()
	if err != nil {
		t.Fatal(err)
	}
	for _, one := range held {
		if one.Instance.Namespace == parent.Namespace && one.Instance.PID == child {
			t.Errorf("child reaped before admission left a live grant: %s", one)
		}
	}
}

func TestEqualLocalPIDsDoNotShareApproval(t *testing.T) {
	port, received := independentPeer(t)
	approvedPID, approvedSaid, approvedTalk := namespacedProcess(t, port)
	unapprovedPID, unapprovedSaid, unapprovedTalk := namespacedProcess(t, port)
	approved, unapproved := loaded(t, approvedPID), loaded(t, unapprovedPID)
	if approved.NamespacePID != unapproved.NamespacePID || approved.Namespace == unapproved.Namespace {
		t.Fatalf("fixture did not establish equal local pids in different namespaces: %+v, %+v", approved, unapproved)
	}
	selection := admit(approved)
	selection.Mode = admission.ModeFollow
	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(), Points: append(points(t, approved), independentForkPoint(t, approved)), Admit: []admission.Selection{selection},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	for _, actor := range []struct {
		talk func()
		said *bufio.Reader
	}{{unapprovedTalk, unapprovedSaid}, {approvedTalk, approvedSaid}} {
		actor.talk()
		for {
			line, err := actor.said.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if line == "done\n" {
				break
			}
		}
		peerReceived(t, received, "/ns-parent")
		peerReceived(t, received, "/ns-child")
	}
	got := drain(session, 150*time.Millisecond)
	var control int
	for _, event := range got.events {
		if event.Kind != ebpf.Transfer || event.Direction != fragment.Sent {
			continue
		}
		if event.PID == approvedPID && strings.Contains(string(event.Payload), "/ns-parent") {
			control++
		}
		if event.PID == unapprovedPID || event.Namespace == unapproved.Namespace {
			t.Errorf("unapproved process sharing local pid %d was read: %+v", approved.NamespacePID, event)
		}
	}
	if control != 1 {
		t.Fatalf("approved control appeared %d times, want 1", control)
	}
}

// Resolve the actor's actual library with the existing fixture, then use the
// published constructor so the fork window has both entry and return hooks.
func independentForkPoint(t *testing.T, actor process.Process) ebpf.Point {
	t.Helper()
	resolved := forkPoint(t, actor)
	return ebpf.ForkPoint(resolved.Symbol, resolved.Path, resolved.Offset)
}
