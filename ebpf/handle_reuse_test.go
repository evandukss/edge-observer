//go:build attach

package ebpf_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
	"github.com/evandukss/edge-observer/spool"
)

const independentHandleReuseSource = independentTransferSource + `
#include <stddef.h>
#include <stdint.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

// Once the second response is buffered, any network I/O on either socket
// kills the actor. Stdout and the command pipe remain usable. A successful
// read after this filter cannot have refreshed a binding through socket I/O.
static int forbid_socket_io(int first, int second) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 8, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_readv, 7, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_recvfrom, 6, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_recvmsg, 5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_writev, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendto, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendmsg, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, first, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, second, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { sizeof(filter)/sizeof(filter[0]), filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

static int connect_handle(SSL *ssl) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) return -1;
    if (SSL_set_fd(ssl, fd) != 1 || SSL_connect(ssl) != 1) return -1;
    return fd;
}

int main(int argc, char **argv) {
    if (argc != 2) return 10;
    port = atoi(argv[1]);
    context = SSL_CTX_new(TLS_client_method());
    if (!context) return 11;
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
    printf("ready\n"); fflush(stdout);
    char command[8], buffer[128];
    SSL *ssl = NULL;
    uintptr_t original = 0;
    int first = -1, second = -1;
    while (fgets(command, sizeof(command), stdin)) {
        if (command[0] == 'C') {
            ssl = SSL_new(context);
            if (!ssl) return 12;
            original = (uintptr_t)ssl;
            first = connect_handle(ssl);
            if (first < 0) return 13;
            const char *want = "peer-control-socket";
            int n = SSL_read(ssl, buffer, sizeof(buffer));
            if (n != (int)strlen(want) || memcmp(buffer, want, n)) return 14;
            printf("control %llu %d\n", (unsigned long long)original, first);
        } else if (command[0] == 'F') {
            // SSL_set_fd installs a BIO which does not close the descriptor.
            // Keeping that occupancy live separates handle reuse from fd reuse.
            SSL_free(ssl);
            ssl = NULL;
            printf("freed\n");
        } else if (command[0] == 'N') {
            for (int attempts = 0; attempts < 256; attempts++) {
                ssl = SSL_new(context);
                if (!ssl) return 15;
                if ((uintptr_t)ssl == original) break;
                SSL_free(ssl);
                ssl = NULL;
            }
            if (!ssl) { printf("address-not-reused\n"); fflush(stdout); return 16; }
            second = connect_handle(ssl);
            if (second < 0 || second == first) return 17;
            const char *want = "peer-reused-socket";
            int n = SSL_peek(ssl, buffer, sizeof(buffer));
            if (n != (int)strlen(want) || memcmp(buffer, want, n)) return 18;
            if (SSL_pending(ssl) < n) return 19;
            if (forbid_socket_io(first, second) != 0) return 20;
            printf("buffered %llu %d %d\n", (unsigned long long)(uintptr_t)ssl, second, n);
        } else if (command[0] == 'R') {
            const char *want = "peer-reused-socket";
            int n = SSL_read(ssl, buffer, (int)strlen(want));
            if (n != (int)strlen(want) || memcmp(buffer, want, n)) return 21;
            printf("read-without-socket-io %d\n", n);
        }
        fflush(stdout);
    }
    return 0;
}
`

// The peer writes application bytes immediately after each TLS handshake. The
// new handle therefore needs no SSL_write to solicit them; SSL_peek primes its
// read buffer without a transfer observed by the OpenSSL adapter.
func independentGreetingPeer(t *testing.T) (int, <-chan string) {
	t.Helper()
	certificate := httptest.NewTLSServer(nil)
	t.Cleanup(certificate.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	written := make(chan string, 2)
	go func() {
		for _, greeting := range []string{"peer-control-socket", "peer-reused-socket"} {
			raw, err := listener.Accept()
			if err != nil {
				written <- fmt.Sprintf("accept failed: %v", err)
				return
			}
			peer := tls.Server(raw, certificate.TLS)
			go func() {
				defer func() { _ = peer.Close() }()
				_ = peer.SetDeadline(time.Now().Add(15 * time.Second))
				if err := peer.Handshake(); err != nil {
					written <- fmt.Sprintf("handshake failed: %v", err)
					return
				}
				if n, err := io.WriteString(peer, greeting); err != nil || n != len(greeting) {
					written <- fmt.Sprintf("greeting failed: %d, %v", n, err)
					return
				}
				written <- greeting
				<-release
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, written
}

type independentBindingSink struct {
	recording *capture.Session
	transfers chan probe.Transfer
}

func (s *independentBindingSink) Transfer(one probe.Transfer) {
	s.recording.Transfer(one)
	s.transfers <- one
}

func (s *independentBindingSink) Closed(one probe.Connection) { s.recording.Closed(one) }

func independentBindingTransfer(t *testing.T, sink *independentBindingSink, payload string) probe.Transfer {
	t.Helper()
	select {
	case one := <-sink.transfers:
		if one.Direction != fragment.Received || string(one.Payload) != payload {
			t.Fatalf("captured transfer differs from the peer-confirmed bytes: %+v", one)
		}
		return one
	case <-time.After(3 * time.Second):
		t.Fatal("peer-confirmed transfer never reached the real attachment sink")
		return probe.Transfer{}
	}
}

func TestReleasedHandleCannotLendItsBindingToABufferedReadAtTheSameAddress(t *testing.T) {
	port, written := independentGreetingPeer(t)
	actor := independentActor(t, independentHandleReuseSource, port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	disk, err := spool.Open(t.TempDir(), 8<<20)
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
	var original uint64
	var first int32
	if _, scanErr := fmt.Sscanf(line, "control %d %d", &original, &first); err != nil || scanErr != nil || original == 0 || first < 0 {
		t.Fatalf("control identity: %q: %v, %v", line, err, scanErr)
	}
	peerReceived(t, written, "peer-control-socket")
	control := independentBindingTransfer(t, sink, "peer-control-socket")
	if control.Endpoint != original || control.Bound != probe.BoundTo || control.Descriptor != first || control.Binding == 0 {
		t.Fatalf("socket read did not establish the live handle's binding control: %+v", control)
	}
	command("F")
	actorLine(t, actor, "freed\n")
	waitIndependentLifecycleConnections(t, disk, 1)
	before := independentLifecycleConnections(t, disk.ConnectionsPath())
	if len(before) != 1 {
		t.Fatalf("released control did not persist exactly once: %d", len(before))
	}
	association, ok := before[0].Association(fragment.Received)
	if !ok || association.State != connection.Established {
		t.Fatalf("released control did not retain its binding: it is %s: %+v",
			association.State, association)
	}
	command("N")
	line, err = actor.output.ReadString('\n')
	var reused uint64
	var second, pending int
	if _, scanErr := fmt.Sscanf(line, "buffered %d %d %d", &reused, &second, &pending); err != nil || scanErr != nil || reused != original || second < 0 || second == int(first) || pending != len("peer-reused-socket") {
		t.Fatalf("actual handle reuse, distinct socket and buffered bytes were not established: %q: %v, %v", line, err, scanErr)
	}
	peerReceived(t, written, "peer-reused-socket")
	command("R")
	actorLine(t, actor, fmt.Sprintf("read-without-socket-io %d\n", pending))
	after := independentBindingTransfer(t, sink, "peer-reused-socket")
	if after.Endpoint != original || after.Instance.Key() != control.Instance.Key() {
		t.Fatalf("buffered transfer did not use the reused handle in the same admitted execution: %+v", after)
	}
	command("F")
	actorLine(t, actor, "freed\n")
	waitIndependentLifecycleConnections(t, disk, 2)
	records := independentLifecycleConnections(t, disk.ConnectionsPath())
	if len(records) != 2 || records[1].ID == records[0].ID {
		t.Fatalf("handle reuse did not produce two distinct persisted connections: %+v", records)
	}
	current, ok := records[1].Association(fragment.Received)
	if !ok {
		t.Fatal("buffered transfer's binding state was not persisted")
	}
	if current.State == connection.Established {
		t.Errorf("released handle's new occupant inherited an established binding without a socket call: old=%+v new=%+v actual-new-fd=%d", association, current, second)
	}
}
