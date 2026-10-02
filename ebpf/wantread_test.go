//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
)

// wantReadSource reads its response with SSL_read_ex on a non-blocking socket,
// as CPython's timed socket does: a read before the response arrives returns 0
// with SSL_ERROR_WANT_READ, moving nothing, and is retried once the socket is
// readable.
const wantReadSource = `
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
	if (argc != 2) return 10;
	int port = atoi(argv[1]);
	SSL_CTX *context = SSL_CTX_new(TLS_client_method());
	if (context == NULL) return 11;
	SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
	printf("ready\n"); fflush(stdout);
	char command[8];
	while (fgets(command, sizeof(command), stdin)) {
		if (command[0] != 'W') continue;
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in address = {0};
		address.sin_family = AF_INET;
		address.sin_port = htons((unsigned short)port);
		inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
		if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) return 1;
		SSL *ssl = SSL_new(context);
		SSL_set_fd(ssl, fd);
		if (SSL_connect(ssl) != 1) return 3;
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
		const char *request = "GET /delayed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
		size_t written = 0;
		if (SSL_write_ex(ssl, request, strlen(request), &written) != 1) return 4;
		char response[4096] = {0};
		size_t used = 0, got = 0;
		int wants = 0;
		while (used < sizeof(response)-1 && !strstr(response, "\r\n\r\nok")) {
			if (SSL_read_ex(ssl, response+used, sizeof(response)-1-used, &got) == 1) {
				used += got;
				continue;
			}
			if (SSL_get_error(ssl, 0) != SSL_ERROR_WANT_READ) break;
			wants++;
			struct pollfd readable = {fd, POLLIN, 0};
			if (poll(&readable, 1, 5000) != 1) break;
		}
		printf("read %d %s\n", wants, strstr(response, "\r\n\r\nok") ? "complete" : "incomplete");
		fflush(stdout);
		SSL_free(ssl);
		close(fd);
	}
	return 0;
}
`

// A no-data return of the out-parameter family, SSL_read_ex's status 0 with
// SSL_ERROR_WANT_READ, is a measured transfer of nothing, never an unmeasured
// one: the read that follows it and the complete response are captured as
// they would be without it. An unmeasured transfer is what ends a session as
// unknown_length.
func TestAWantReadReturnIsAMeasuredNothing(t *testing.T) {
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The delay that makes the client's first read find nothing to read.
		time.Sleep(200 * time.Millisecond)
		w.Header().Set("Content-Length", "2")
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(peer.Close)
	port, err := strconv.Atoi(strings.TrimPrefix(peer.URL, "https://127.0.0.1:"))
	if err != nil {
		t.Fatal(err)
	}
	actor := independentActor(t, wantReadSource, port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, parent), Admit: authorise(parent)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()

	if _, err := io.WriteString(actor.input, "W\n"); err != nil {
		t.Fatal(err)
	}
	line, err := actor.output.ReadString('\n')
	var wants int
	var outcome string
	if _, scanErr := fmt.Sscanf(line, "read %d %s", &wants, &outcome); err != nil || scanErr != nil || outcome != "complete" {
		t.Fatalf("wiring, not the property: the client did not read the whole response: %q: %v, %v", line, err, scanErr)
	}
	if wants == 0 {
		t.Fatalf("wiring, not the property: no read returned SSL_ERROR_WANT_READ, so the no-data return was " +
			"never produced")
	}

	var received strings.Builder
	nothing := 0
	for _, event := range drain(session, 300*time.Millisecond).events {
		if event.Kind != ebpf.Transfer || int(event.PID) != int(parent.PID) {
			continue
		}
		if !event.Measured {
			t.Errorf("a transfer was reported unmeasured: %s of %d bytes, stamp %d", event.Direction, event.Length, event.Stamp)
		}
		if event.Direction != fragment.Received {
			continue
		}
		if event.Length == 0 {
			nothing++
		}
		received.Write(event.Payload)
	}
	if nothing < wants {
		t.Errorf("%d reads returned WANT_READ and %d were reported as measured transfers of nothing", wants, nothing)
	}
	if !strings.Contains(received.String(), "200 OK") || !strings.HasSuffix(received.String(), "\r\n\r\nok") {
		t.Errorf("the response read after the retry was not captured whole: %q", received.String())
	}
}
