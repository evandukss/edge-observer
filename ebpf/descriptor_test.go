//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/spool"
)

func independentDescriptorReplacementSource() string {
	prefix, _, _ := strings.Cut(independentHandleReuseSource, "int main(int argc")
	return prefix + `
#include <sys/stat.h>
int main(int argc, char **argv) {
    if (argc != 2) return 10;
    port = atoi(argv[1]);
    context = SSL_CTX_new(TLS_client_method());
    if (!context) return 11;
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
    printf("ready\n"); fflush(stdout);
    SSL *ssl = NULL;
    int fd = -1;
    char command[8], buffer[128];
    while (fgets(command, sizeof(command), stdin)) {
        if (command[0] == 'C') {
            ssl = SSL_new(context);
            if (!ssl) return 12;
            fd = connect_handle(ssl);
            if (fd < 0) return 13;
            const char *want = "peer-control-";
            int n = SSL_read(ssl, buffer, strlen(want));
            if (n != (int)strlen(want) || memcmp(buffer, want, n)) return 14;
            int pending = SSL_pending(ssl);
            if (pending != (int)strlen("socket")) return 15;
            printf("control %llu %d %d\n", (unsigned long long)(uintptr_t)ssl, fd, pending);
        } else if (command[0] == 'D') {
            struct stat before, after;
            if (fstat(fd, &before) != 0) return 16;
            int replacement = socket(AF_INET, SOCK_STREAM, 0);
            if (replacement < 0 || replacement == fd) return 17;
            if (dup2(replacement, fd) != fd) return 18;
            if (fstat(fd, &after) != 0 || before.st_ino == after.st_ino) return 19;
            if (forbid_socket_io(fd, replacement) != 0) return 20;
            // No SSL/BIO operation occurs between dup2 and the next command.
            printf("replaced %d %llu %llu\n", fd, (unsigned long long)before.st_ino, (unsigned long long)after.st_ino);
        } else if (command[0] == 'R') {
            const char *want = "socket";
            int n = SSL_read(ssl, buffer, strlen(want));
            if (n != (int)strlen(want) || memcmp(buffer, want, n)) return 21;
            printf("buffered-read %d\n", n);
        } else if (command[0] == 'F') {
            SSL_free(ssl);
            ssl = NULL;
            printf("freed\n");
        }
        fflush(stdout);
    }
    return 0;
}
`
}

func TestDup2InvalidatesABufferedHandlesBindingWithoutATLSRebind(t *testing.T) {
	port, written := independentGreetingPeer(t)
	actor := independentActor(t, independentDescriptorReplacementSource(), port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	disk, err := spool.Open(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = disk.Close() })
	sink := &independentBindingSink{recording: capture.Recording(disk, disk), transfers: make(chan probe.Transfer, 8)}
	live, err := attach.NeweBPF(process.Approval{}).Attach(probe.Request{Processes: []process.Process{parent}, Admit: authorise(parent)}, sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Close() })
	command := func(letter string) {
		t.Helper()
		if _, err := io.WriteString(actor.input, letter+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	command("C")
	line, err := actor.output.ReadString('\n')
	var handle uint64
	var descriptor int32
	var pending int
	if _, scanErr := fmt.Sscanf(line, "control %d %d %d", &handle, &descriptor, &pending); err != nil || scanErr != nil || handle == 0 || descriptor < 0 || pending != len("socket") {
		t.Fatalf("live binding and unread buffered bytes control: %q, %v, %v", line, err, scanErr)
	}
	peerReceived(t, written, "peer-control-socket")
	control := independentBindingTransfer(t, sink, "peer-control-")
	if control.Endpoint != handle || control.Bound != probe.BoundTo || control.Descriptor != descriptor || control.Binding == 0 {
		t.Fatalf("first socket read did not establish a binding: %+v", control)
	}
	command("D")
	line, err = actor.output.ReadString('\n')
	var replaced int32
	var before, after uint64
	if _, scanErr := fmt.Sscanf(line, "replaced %d %d %d", &replaced, &before, &after); err != nil || scanErr != nil || replaced != descriptor || before == 0 || after == 0 || before == after {
		t.Fatalf("same descriptor did not acquire a different kernel socket: %q, %v, %v", line, err, scanErr)
	}
	command("R")
	actorLine(t, actor, "buffered-read 6\n")
	current := independentBindingTransfer(t, sink, "socket")
	if current.Endpoint != handle || current.Bound != probe.BoundInvalidated {
		t.Errorf("buffered read inherited a descriptor binding invalidated by dup2 without a TLS rebind: before=%+v after=%+v", control, current)
	}
	command("F")
	actorLine(t, actor, "freed\n")
	waitIndependentLifecycleConnections(t, disk, 1)
	records := independentLifecycleConnections(t, disk.ConnectionsPath())
	if len(records) != 1 {
		t.Fatalf("descriptor uncertainty split one TLS stream into %d connections", len(records))
	}
	association, ok := records[0].Association(fragment.Received)
	if !ok || association.State != connection.Invalidated || association.Joinable() {
		t.Errorf("persisted stream hid the descriptor replacement: %+v", association)
	}
}
