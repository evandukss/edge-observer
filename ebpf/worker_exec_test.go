//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
)

const independentWorkerExecSource = independentTransferSource + `
#include <sys/syscall.h>

static char *self_path, *port_text;
static int exec_on_read;

static long exec_during_read(BIO *bio, int operation, const char *data,
                            size_t length, int argi, long argl, int result,
                            size_t *processed) {
    if (exec_on_read && operation == BIO_CB_READ) {
        exec_on_read = 0;
        printf("inside-read %ld\n", syscall(SYS_gettid)); fflush(stdout);
        char command[8];
        if (!fgets(command, sizeof(command), stdin) || command[0] != 'X') _exit(30);
        execl(self_path, self_path, port_text, "after-exec", NULL);
        _exit(31);
    }
    return result;
}

static void *exec_worker(void *unused) {
    char command[8];
    printf("worker %ld\n", syscall(SYS_gettid)); fflush(stdout);
    if (!fgets(command, sizeof(command), stdin) || command[0] != 'P') _exit(20);
    printf("control %d\n", transfer("/independent-worker-before-exec")); fflush(stdout);
    if (!fgets(command, sizeof(command), stdin) || command[0] != 'E') _exit(21);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) _exit(22);
    SSL *ssl = SSL_new(context);
    if (!ssl || SSL_set_fd(ssl, fd) != 1 || SSL_connect(ssl) != 1) _exit(23);
    BIO_set_callback_ex(SSL_get_rbio(ssl), exec_during_read);
    exec_on_read = 1;
    char buffer[512];
    SSL_read(ssl, buffer, sizeof(buffer));
    _exit(24); // a successful exec cannot return through this call
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) return 10;
    port = atoi(argv[1]);
    self_path = argv[0]; port_text = argv[1];
    context = SSL_CTX_new(TLS_client_method());
    if (!context) return 11;
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
    if (argc == 3) {
        printf("after-exec %d %ld\n", getpid(), syscall(SYS_gettid)); fflush(stdout);
        char command[8];
        while (fgets(command, sizeof(command), stdin)) {
            if (command[0] == 'P') {
                printf("parent %d\n", transfer("/independent-parent")); fflush(stdout);
            }
        }
        return 0;
    }
    printf("ready\n"); fflush(stdout);
    char command[8];
    if (!fgets(command, sizeof(command), stdin) || command[0] != 'W') return 12;
    pthread_t thread;
    if (pthread_create(&thread, NULL, exec_worker, NULL) != 0) return 13;
    pthread_join(thread, NULL);
    return 14;
}
`

func TestWorkerExecDisposesTheCallUnderItsPreExecThreadKey(t *testing.T) {
	port, received := independentPeer(t)
	actor := independentActor(t, independentWorkerExecSource, port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, parent), Admit: authorise(parent)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	command := func(letter string) {
		t.Helper()
		if _, err := io.WriteString(actor.input, letter+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	command("W")
	line, err := actor.output.ReadString('\n')
	var worker int32
	if _, scanErr := fmt.Sscanf(line, "worker %d", &worker); err != nil || scanErr != nil || worker <= 0 || worker == parent.PID {
		t.Fatalf("non-leader worker identity: %q: %v, %v", line, err, scanErr)
	}
	command("P")
	actorLine(t, actor, "control 0\n")
	peerReceived(t, received, "/independent-worker-before-exec")
	control := attribution(drain(session, 100*time.Millisecond), "/independent-worker-before-exec")
	if control == nil || control.TID != worker || control.Generation == 0 {
		t.Fatalf("execing worker did not establish its own captured control: %+v", control)
	}
	command("E")
	actorLine(t, actor, fmt.Sprintf("inside-read %d\n", worker))
	present, live, generation, function, err := ebpf.IndependentThreadCall(session, parent.PID, worker)
	if err != nil || !present || !live || generation != uint64(control.Generation) || function != 1 {
		t.Fatalf("worker did not hold its own live SSL_read before exec: present=%t live=%t generation=%d function=%d err=%v", present, live, generation, function, err)
	}
	command("X")
	actorLine(t, actor, fmt.Sprintf("after-exec %d %d\n", parent.PID, parent.PID))
	after := loaded(t, parent.PID)
	if after.PID != parent.PID || after.Namespace != parent.Namespace || after.NamespacePID != parent.NamespacePID {
		t.Fatalf("exec changed the process numbering instead of only the worker identity: before=%+v after=%+v", parent, after)
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/task/%d", parent.PID, worker)); !os.IsNotExist(err) {
		t.Fatalf("pre-exec worker identity still exists after the worker became leader: %v", err)
	}
	if held, err := ebpf.IndependentKernelGrantPresent(session, parent.Instance()); err != nil || held {
		t.Fatalf("successful worker exec did not revoke its grant: held=%t err=%v", held, err)
	}
	present, live, generation, function, err = ebpf.IndependentThreadCall(session, parent.PID, worker)
	if err != nil {
		t.Fatal(err)
	}
	if !present || !live || generation != uint64(control.Generation) || function != 1 {
		t.Logf("pre-exec residual is not reachable through the new leader key: present=%t live=%t generation=%d function=%d", present, live, generation, function)
	}
	command("P")
	actorLine(t, actor, "parent 0\n")
	peerReceived(t, received, "/independent-parent")
	got := attribution(drain(session, 100*time.Millisecond), "/independent-parent")
	if got != nil {
		t.Errorf("a later call crossed the read boundary after exec revoked the grant: %+v", got)
	}
}
