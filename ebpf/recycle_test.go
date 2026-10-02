//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
)

// recycleSource makes two real TLS connections, one after the other, on one SSL
// object: the second after SSL_clear, with no SSL_free and no SSL_new between
// them, on a new socket.
const recycleSource = `
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static SSL_CTX *context;
static int port;

static int one(SSL *ssl, const char *path) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in address = {0};
	address.sin_family = AF_INET;
	address.sin_port = htons((unsigned short)port);
	inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) return 1;
	if (SSL_set_fd(ssl, fd) != 1) return 2;
	if (SSL_connect(ssl) != 1) return 3;
	char request[256];
	snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path);
	if (SSL_write(ssl, request, (int)strlen(request)) != (int)strlen(request)) return 4;
	char response[4096] = {0};
	size_t used = 0;
	int n;
	while (used < sizeof(response)-1 && (n = SSL_read(ssl, response+used, sizeof(response)-1-used)) > 0) used += n;
	char expected[256];
	snprintf(expected, sizeof(expected), "peer-confirmed:%s", path);
	if (strstr(response, expected) == NULL) return 5;
	SSL_shutdown(ssl);
	close(fd);
	return 0;
}

int main(int argc, char **argv) {
	if (argc != 2) return 10;
	port = atoi(argv[1]);
	context = SSL_CTX_new(TLS_client_method());
	if (context == NULL) return 11;
	SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
	printf("ready\n"); fflush(stdout);
	char command[8];
	while (fgets(command, sizeof(command), stdin)) {
		if (command[0] == 'R') {
			SSL *ssl = SSL_new(context);
			if (!ssl) return 12;
			int first = one(ssl, "/before-clear");
			int cleared = SSL_clear(ssl);
			int second = one(ssl, "/after-clear");
			printf("recycled %d %d %d %llu\n", first, cleared, second, (unsigned long long)(uintptr_t)ssl);
			SSL_free(ssl);
		}
		fflush(stdout);
	}
	return 0;
}
`

// recycled runs the two connections and returns the handle they shared.
func recycled(t *testing.T, actor *armingProcess, received <-chan string) uint64 {
	t.Helper()
	if _, err := io.WriteString(actor.input, "R\n"); err != nil {
		t.Fatal(err)
	}
	line, err := actor.output.ReadString('\n')
	var first, cleared, second int
	var handle uint64
	if _, scanErr := fmt.Sscanf(line, "recycled %d %d %d %d", &first, &cleared, &second, &handle); err != nil ||
		scanErr != nil || first != 0 || cleared != 1 || second != 0 || handle == 0 {
		t.Fatalf("wiring, not the property: the two connections on one recycled object did not both complete: %q: %v, %v",
			line, err, scanErr)
	}
	peerReceived(t, received, "/before-clear")
	peerReceived(t, received, "/after-clear")
	return handle
}

// One SSL object recycled with SSL_clear across two real TLS connections is
// two connections: the clear ends the first occupancy, and the second begins
// its own, numbered from one at offset zero with its own binding. Joined, the
// second connection's bytes would continue the first's stream.
func TestARecycledHandleIsTwoConnections(t *testing.T) {
	port, received := independentPeer(t)
	actor := independentActor(t, recycleSource, port)
	run := deliverHeldWith(t, actor, ebpf.Options{})
	handle := recycled(t, actor, received)
	records := run.seal(t)

	var shared []connection.Record
	for _, one := range records {
		if one.Handle.Address == handle {
			shared = append(shared, one)
		}
	}
	if len(shared) != 2 {
		t.Fatalf("one recycled object across two connections produced %d connection records, want two: %+v",
			len(shared), shared)
	}
	if shared[0].ID == shared[1].ID || shared[0].Handle.Generation == shared[1].Handle.Generation {
		t.Errorf("the two connections share an identity: %+v and %+v", shared[0].Handle, shared[1].Handle)
	}
	if shared[0].How != connection.HandleReleasedEnding {
		t.Errorf("the first connection ended %q, want the recycle's release", shared[0].How)
	}
	for _, one := range shared {
		for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
			placed, ok := one.Placement(direction)
			if !ok || placed.Positions != connection.PositionsEstablished {
				t.Errorf("connection %d's %s positions are %+v, want established", one.ID, direction, placed)
			}
		}
	}
	paths := map[fragment.ConnectionID][]string{}
	for _, one := range run.fragments.all() {
		if one.Offset == 0 && one.Direction == fragment.Sent {
			paths[one.Connection] = append(paths[one.Connection], strings.Fields(string(one.Payload))[1])
		}
		if one.Produced == 0 {
			t.Errorf("connection %d carries a fragment the producer numbered nothing for", one.Connection)
		}
	}
	if !slices.Equal(paths[shared[0].ID], []string{"/before-clear"}) || !slices.Equal(paths[shared[1].ID], []string{"/after-clear"}) {
		t.Errorf("each connection does not begin with its own request at offset zero: %v", paths)
	}
}

// With the SSL_clear probe refused while the byte movers are held, capture is
// not live: no occupancy forms and the session names the refused probe, so a
// recycled handle cannot join two connections into one placed stream.
func TestARefusedRecycleProbeLeavesCaptureNotLive(t *testing.T) {
	port, received := independentPeer(t)
	actor := independentActor(t, recycleSource, port)
	run := deliverHeldWith(t, actor, ebpf.Options{FailEntry: []string{"SSL_clear"}})
	if !slices.Contains(run.session.Unprobed(), "SSL_clear") {
		t.Fatalf("the refused SSL_clear probe is not named: unprobed %v", run.session.Unprobed())
	}
	if !slices.Contains(run.session.Coverage().Unprobed, "SSL_clear") {
		t.Errorf("coverage does not name the refused SSL_clear probe: %+v", run.session.Coverage())
	}
	recycled(t, actor, received)
	run.seal(t)
	numbered := 0
	fragments := run.fragments.all()
	for _, one := range fragments {
		if one.Produced != 0 {
			numbered++
		}
	}
	if len(fragments) == 0 {
		t.Fatal("wiring, not the property: the recycled connections reached capture with no fragment")
	}
	if numbered != 0 {
		t.Errorf("%d of %d fragments carry a producer number with capture not live", numbered, len(fragments))
	}
}
