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

func independentCustomBIOSource(sidePort int) string {
	return fmt.Sprintf("#define SIDE_PORT %d\n", sidePort) + independentTransferSource + `
#include <stdint.h>
static int transport, other, ambiguous;
static struct sockaddr_in side;
static int bio_read(BIO *bio, char *out, int length) {
    if (ambiguous && sendto(other, "side", 4, 0, (struct sockaddr *)&side, sizeof(side)) != 4) return -1;
    return recvfrom(transport, out, length, 0, NULL, NULL);
}
static int bio_write(BIO *bio, const char *in, int length) {
    return sendto(transport, in, length, 0, NULL, 0);
}
static long bio_ctrl(BIO *bio, int command, long value, void *pointer) {
    if (command == BIO_CTRL_FLUSH) return 1;
    if (command == BIO_C_GET_FD) return -1;
    return 0;
}
static int bio_create(BIO *bio) { BIO_set_init(bio, 1); return 1; }
static int bio_destroy(BIO *bio) { return 1; }
int main(int argc, char **argv) {
    if (argc != 2) return 10;
    port = atoi(argv[1]);
    context = SSL_CTX_new(TLS_client_method());
    if (!context) return 11;
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
    BIO_METHOD *method = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(), "transport");
    if (!method || !BIO_meth_set_read(method, bio_read) || !BIO_meth_set_write(method, bio_write) ||
        !BIO_meth_set_ctrl(method, bio_ctrl) || !BIO_meth_set_create(method, bio_create) ||
        !BIO_meth_set_destroy(method, bio_destroy)) return 12;
    side.sin_family = AF_INET;
    side.sin_port = htons(SIDE_PORT);
    inet_pton(AF_INET, "127.0.0.1", &side.sin_addr);
    printf("ready\n"); fflush(stdout);
    char command[8], buffer[128];
    SSL *ssl = NULL;
    int round = 0;
    while (fgets(command, sizeof(command), stdin)) {
        if (command[0] == 'H') {
            ambiguous = 0;
            transport = socket(AF_INET, SOCK_STREAM, 0);
            other = socket(AF_INET, SOCK_DGRAM, 0);
            struct sockaddr_in address = {0};
            address.sin_family = AF_INET;
            address.sin_port = htons(port);
            inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
            if (transport < 0 || other < 0 || transport == other || connect(transport, (struct sockaddr *)&address, sizeof(address))) return 13;
            ssl = SSL_new(context);
            BIO *bio = BIO_new(method);
            if (!ssl || !bio) return 14;
            SSL_set_bio(ssl, bio, bio);
            if (SSL_connect(ssl) != 1) return 15;
            if (SSL_get_fd(ssl) != -1) return 16;
            printf("handshake %llu %d %d -1\n", (unsigned long long)(uintptr_t)ssl, transport, other);
        } else if (command[0] == 'R') {
            ambiguous = round;
            const char *want = round ? "second-response" : "first-response";
            int n = SSL_read(ssl, buffer, sizeof(buffer));
            if (n != (int)strlen(want) || memcmp(buffer, want, n)) return 17;
            printf("read %d\n", round);
        } else if (command[0] == 'F') {
            SSL_free(ssl); close(transport); close(other);
            ssl = NULL; round++;
            printf("freed\n");
        }
        fflush(stdout);
    }
    return 0;
}
`
}

func TestCustomBIOBindsOneSocketAndReportsTwoDescriptorsAsAmbiguous(t *testing.T) {
	certificate := httptest.NewTLSServer(nil)
	t.Cleanup(certificate.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	side, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = side.Close() })
	// Nothing can prime an SSL read buffer during the handshake: the peer
	// waits until the actor has returned from SSL_connect before sending.
	release := make(chan string)
	finished := make(chan struct{})
	t.Cleanup(func() { close(finished) })
	written := make(chan string, 2)
	go func() {
		for range 2 {
			raw, err := listener.Accept()
			if err != nil {
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
				select {
				case message := <-release:
					if n, err := io.WriteString(peer, message); err != nil || n != len(message) {
						written <- fmt.Sprintf("peer write failed: %d %v", n, err)
						return
					}
					written <- message
				case <-finished:
					return
				}
				<-finished
			}()
		}
	}()
	actor := independentActor(t, independentCustomBIOSource(side.LocalAddr().(*net.UDPAddr).Port), listener.Addr().(*net.TCPAddr).Port)
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
	for round, message := range []string{"first-response", "second-response"} {
		command("H")
		line, err := actor.output.ReadString('\n')
		var handle uint64
		var transport, extra, exposed int32
		if _, scanErr := fmt.Sscanf(line, "handshake %d %d %d %d", &handle, &transport, &extra, &exposed); err != nil || scanErr != nil || handle == 0 || transport < 0 || extra < 0 || transport == extra || exposed != -1 {
			t.Fatalf("custom BIO did not establish two distinct sockets without exposing its fd: %q, %v, %v", line, err, scanErr)
		}
		command("R")
		select {
		case release <- message:
		case <-time.After(3 * time.Second):
			t.Fatal("peer did not finish the handshake before the application read")
		}
		actorLine(t, actor, fmt.Sprintf("read %d\n", round))
		peerReceived(t, written, message)
		if round == 1 {
			if err := side.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 16)
			n, _, err := side.ReadFrom(buffer)
			if err != nil || string(buffer[:n]) != "side" {
				t.Fatalf("second descriptor did not transfer inside the same SSL_read callback: %q, %v", buffer[:n], err)
			}
		}
		one := independentBindingTransfer(t, sink, message)
		want := probe.BoundTo
		if round == 1 {
			want = probe.BoundAmbiguously
		}
		if one.Endpoint != handle || one.Bound != want || (round == 0 && one.Descriptor != transport) {
			t.Errorf("custom BIO round %d reported %s, want %s with the peer-confirmed socket work: %+v", round, one.Bound, want, one)
		}
		command("F")
		actorLine(t, actor, "freed\n")
		waitIndependentLifecycleConnections(t, disk, int64(round+1))
	}
	records := independentLifecycleConnections(t, disk.ConnectionsPath())
	if len(records) != 2 || records[0].ID == records[1].ID {
		t.Fatalf("two completed TLS lifetimes did not retain separate stream identities: %+v", records)
	}
	for round, record := range records {
		association, ok := record.Association(fragment.Received)
		want := connection.Established
		if round == 1 {
			want = connection.Ambiguous
		}
		if !ok || association.State != want {
			t.Errorf("persisted custom BIO round %d is %s, want %s: %+v",
				round, association.State, want, association)
		}
	}
}
