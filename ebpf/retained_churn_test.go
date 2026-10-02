//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/probe"
)

// churnSource is a parent that forks children one at a time. Each child makes
// one TLS exchange with the peer and exits holding everything: no SSL_free and
// no close, so nothing but its exit ends its handle, binding, descriptor and
// admission.
const churnSource = `
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static SSL_CTX *context;
static int port;

static int exchange_and_hold(void) {
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
	const char *request = "GET /churn HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
	if (SSL_write(ssl, request, (int)strlen(request)) != (int)strlen(request)) return 4;
	char response[4096] = {0};
	size_t used = 0;
	int n;
	while (used < sizeof(response)-1 && (n = SSL_read(ssl, response+used, sizeof(response)-1-used)) > 0) used += n;
	return strstr(response, "peer-confirmed:/churn") ? 0 : 5;
}

int main(int argc, char **argv) {
	if (argc != 2) return 10;
	port = atoi(argv[1]);
	context = SSL_CTX_new(TLS_client_method());
	if (context == NULL) return 11;
	SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
	printf("ready\n"); fflush(stdout);
	char command[32];
	while (fgets(command, sizeof(command), stdin)) {
		if (command[0] == 'C') {
			int n = atoi(command + 2), failed = 0;
			for (int i = 0; i < n; i++) {
				pid_t child = fork();
				if (child < 0) return 13;
				if (child == 0) _exit(exchange_and_hold());
				int status = 0;
				if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) failed++;
			}
			printf("churned %d\n", failed);
		}
		fflush(stdout);
	}
	return 0;
}
`

// churnPeer is a Go TLS server the probes cannot observe, counting what it
// answered, so each child's exchange is confirmed independently of the
// observer.
func churnPeer(t *testing.T) (int, *atomic.Int64) {
	t.Helper()
	var answered atomic.Int64
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answered.Add(1)
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, "peer-confirmed:"+r.URL.Path)
	}))
	t.Cleanup(peer.Close)
	port, err := strconv.Atoi(strings.TrimPrefix(peer.URL, "https://127.0.0.1:"))
	if err != nil {
		t.Fatalf("peer endpoint: %s: %v", peer.URL, err)
	}
	return port, &answered
}

// The kernel tables an execution's entries are keyed by, each churned past a
// bound reduced at load time: the production bounds (16384 occupancies and
// holders, 8192 sockets, operations and discoveries, 4096 handles and
// allowlist entries, 65536 read records) are too large to churn here. Every
// child exits holding a handle, a binding, a descriptor and its admission, so
// only its exit can end them. A table that keeps any of it fills, and its
// refusal counter moves.
var churnedTables = map[string]uint32{
	"occupancies": 16, "handles": 16, "sockets": 16, "operations": 16, "discovered": 16,
	"reads": 16, "holders": 16, "allowed_processes": 16, "inflight": 16,
}

// The refusal counters of those tables, which must not move.
var churnRefusals = map[string]uint32{
	"OBS_STAT_OCCUPANCY_UNRECORDED":  bpf.StatOccupancyUnrecorded,
	"OBS_STAT_BINDING_UNRECORDED":    bpf.StatBindingUnrecorded,
	"OBS_STAT_SOCKET_UNRECORDED":     bpf.StatSocketUnrecorded,
	"OBS_STAT_OPERATION_UNRECORDED":  bpf.StatOperationUnrecorded,
	"OBS_STAT_SOCKET_UNDISCOVERED":   bpf.StatSocketUndiscovered,
	"OBS_STAT_READ_UNRECORDED":       bpf.StatReadUnrecorded,
	"OBS_STAT_HOLDER_UNRECORDED":     bpf.StatHolderUnrecorded,
	"OBS_STAT_DESCENDANT_UNRECORDED": bpf.StatDescendantUnrecorded,
	"OBS_STAT_CALL_UNRECORDED":       bpf.StatCallUnrecorded,
}

func TestChurnedExecutionsLeaveNothingInTheKernelTablesOrTheSession(t *testing.T) {
	const children = 64
	port, answered := churnPeer(t)
	actor := independentActor(t, churnSource, port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	points := append(points(t, parent), independentForkPoint(t, parent))
	points = append(points, socketPointsFor(t, parent)...)
	var ended []probe.Ended
	endedAt := make(chan probe.Ended, children)
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points, Admit: authorise(parent),
		Resize: churnedTables, Ended: func(one probe.Ended) { endedAt <- one }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()

	exited := make(chan int, 1)
	go func() {
		count := 0
		for event := range session.Events() {
			if event.Kind == ebpf.Exited {
				count++
			}
		}
		exited <- count
	}()

	before := map[string]int64{}
	for name, index := range churnRefusals {
		value, err := ebpf.Counter(session, index)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		before[name] = value
	}

	if _, err := io.WriteString(actor.input, fmt.Sprintf("C %d\n", children)); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "churned 0\n")
	// Wiring, not the property: the children reached the peer, so each made the
	// entries the tables below are judged on.
	if got := answered.Load(); got != children {
		t.Fatalf("wiring, not the property: the peer answered %d of %d children, so not every child churned "+
			"the tables", got, children)
	}
	// Each child's end reaches the session through the ring; it is waited for and
	// judged with the tables, since telling of it is part of what an end does.
	deadline := time.After(10 * time.Second)
waiting:
	for len(ended) < children {
		select {
		case one := <-endedAt:
			ended = append(ended, one)
		case <-deadline:
			break waiting
		}
	}
	if len(ended) != children {
		t.Errorf("%d of %d children's ends reached the session", len(ended), children)
	}

	stores, err := session.Retained()
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]int{}
	for _, one := range stores {
		held[one.Store] = one.Held
	}
	// The live population after the churn is the parent alone: its admission and
	// at most its own threads' saved calls. No child is alive and the parent holds
	// no TLS handle or socket of its own.
	live := map[string]int{
		"bpf.occupancies": 0, "bpf.handles": 0, "bpf.sockets": 0, "bpf.operations": 0, "bpf.discovered": 0,
		"bpf.reads": 0, "bpf.holders": 0, "bpf.allowed_processes": 1, "bpf.inflight": 1,
		"ebpf.inventory": 1, "ebpf.index": 1, "ebpf.accepted": 1, "ebpf.named_by": 1,
	}
	for store, most := range live {
		got, listed := held[store]
		if !listed {
			t.Errorf("%s is not among the session's stores: %v", store, stores)
			continue
		}
		if got > most {
			t.Errorf("%s holds %d after %d children came and went, want at most the live %d", store, got,
				children, most)
		}
	}
	for name, index := range churnRefusals {
		value, err := ebpf.Counter(session, index)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if value != before[name] {
			t.Errorf("%s moved from %d to %d over the churn", name, before[name], value)
		}
	}
	counts := session.EndedCounts()
	total := 0
	for _, one := range counts {
		total += one.Count
	}
	if total != children {
		t.Errorf("%d admissions counted as ended, want the %d children: %v", total, children, counts)
	}
	_ = session.Close()
	if got := <-exited; got != children {
		t.Errorf("%d execution ends were delivered, want one per child, %d", got, children)
	}
}
