//go:build attach

package ebpf_test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// The per-connection sequence against the real producer. Each case drives a
// compiled OpenSSL client, delivers what the program produced to a capture
// session through a loop the case can hold, and settles the open connections
// against the program's own occupancy table once production stopped. What
// would show the sequence broken is read off the program's counters and the
// capture's records of the same run.

// sequencePeer serves keep-alive requests over TLS: each "GET <path>" is
// answered with a body naming the path. The OpenSSL probes cannot observe it.
// stall, when set, holds a connection after its handshake, sending nothing,
// until the channel closes; it then writes one record and reads until the
// connection ends.
func sequencePeer(t *testing.T, stall <-chan struct{}) int {
	t.Helper()
	certificate := httptest.NewTLSServer(nil)
	t.Cleanup(certificate.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				peer := tls.Server(raw, certificate.TLS)
				defer func() { _ = peer.Close() }()
				_ = peer.SetDeadline(time.Now().Add(60 * time.Second))
				if err := peer.Handshake(); err != nil {
					return
				}
				if stall != nil {
					<-stall
					_, _ = io.WriteString(peer, "peer-confirmed:/overlap:end")
					_, _ = io.Copy(io.Discard, peer)
					return
				}
				serveSequenceRequests(peer)
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

// serveSequenceRequests answers requests on one connection until it ends.
func serveSequenceRequests(conn io.ReadWriter) {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		fields := strings.Fields(line)
		for {
			header, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if header == "\r\n" {
				break
			}
		}
		if len(fields) < 2 {
			return
		}
		body := "peer-confirmed:" + fields[1] + ":end"
		if _, err := fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body); err != nil {
			return
		}
	}
}

// nestedPeer terminates an outer TLS connection and serves requests over a
// second TLS connection carried inside it.
func nestedPeer(t *testing.T) int {
	t.Helper()
	certificate := httptest.NewTLSServer(nil)
	t.Cleanup(certificate.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		outer := tls.Server(raw, certificate.TLS)
		defer func() { _ = outer.Close() }()
		_ = outer.SetDeadline(time.Now().Add(60 * time.Second))
		if err := outer.Handshake(); err != nil {
			return
		}
		inner := tls.Server(outer, certificate.TLS)
		if err := inner.Handshake(); err != nil {
			return
		}
		serveSequenceRequests(inner)
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

// sequenceActorSource is a client holding numbered handles, driven by stdin:
//
//	O n           open handles 0..n-1 (SSL_new, connect, handshake)
//	X i tag       one keep-alive exchange on handle i
//	C n r tag     n threads, thread i doing r exchanges on handle i
//	F i           free handle i, printing its address
//	N i           a new handle in slot i, printing its address
//	R i           a thread reading on handle i, and a second read entered on
//	              the same handle while the first waits, made to return at once
//	              (the handle marked as having received a shutdown for that
//	              moment, so OpenSSL touches no record state); reports the second
//	S i           shut handle i's socket down and report the first read
//	Q             free every handle
const sequenceActorSource = `
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define HANDLES 64
static SSL_CTX *context;
static int port;
static SSL *ssl_of[HANDLES];
static int fd_of[HANDLES];

static int open_handle(int i) {
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
    ssl_of[i] = ssl; fd_of[i] = fd;
    return 0;
}

static int exchange(int i, const char *path) {
    SSL *ssl = ssl_of[i];
    char request[512];
    snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: localhost\r\n\r\n", path);
    if (SSL_write(ssl, request, (int)strlen(request)) != (int)strlen(request)) return 4;
    char response[8192] = {0}, expected[512];
    snprintf(expected, sizeof(expected), "peer-confirmed:%s:end", path);
    size_t used = 0;
    while (!strstr(response, expected)) {
        if (used >= sizeof(response) - 1) return 5;
        int n = SSL_read(ssl, response + used, (int)(sizeof(response) - 1 - used));
        if (n <= 0) return 6;
        used += n;
    }
    return 0;
}

struct job { int index; int rounds; int result; char tag[32]; };

static void *worker(void *argument) {
    struct job *job = argument;
    for (int round = 0; round < job->rounds && !job->result; round++) {
        char path[96];
        snprintf(path, sizeof(path), "/%s-%d-%d", job->tag, job->index, round);
        job->result = exchange(job->index, path);
    }
    return NULL;
}

struct reader { int index; int result; char data[256]; };
static struct reader readers[2];
static pthread_t reading[2];
static void *read_once(void *argument) {
    struct reader *reader = argument;
    reader->result = SSL_read(ssl_of[reader->index], reader->data, (int)sizeof(reader->data) - 1);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 10;
    port = atoi(argv[1]);
    context = SSL_CTX_new(TLS_client_method());
    if (!context) return 11;
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
    printf("ready\n"); fflush(stdout);
    char line[256];
    while (fgets(line, sizeof(line), stdin)) {
        int i = 0, n = 0, rounds = 0;
        char tag[32] = {0};
        if (line[0] == 'O' && sscanf(line + 1, "%d", &n) == 1) {
            int result = 0;
            for (i = 0; i < n && !result; i++) result = open_handle(i);
            printf("O %d\n", result);
        } else if (line[0] == 'X' && sscanf(line + 1, "%d %31s", &i, tag) == 2) {
            char path[96];
            snprintf(path, sizeof(path), "/%s-%d", tag, i);
            printf("X %d\n", exchange(i, path));
        } else if (line[0] == 'C' && sscanf(line + 1, "%d %d %31s", &n, &rounds, tag) == 3) {
            pthread_t threads[HANDLES];
            struct job jobs[HANDLES];
            for (i = 0; i < n; i++) {
                jobs[i].index = i; jobs[i].rounds = rounds; jobs[i].result = 0;
                snprintf(jobs[i].tag, sizeof(jobs[i].tag), "%s", tag);
                pthread_create(&threads[i], NULL, worker, &jobs[i]);
            }
            int result = 0;
            for (i = 0; i < n; i++) { pthread_join(threads[i], NULL); if (!result) result = jobs[i].result; }
            printf("C %d\n", result);
        } else if (line[0] == 'F' && sscanf(line + 1, "%d", &i) == 1) {
            printf("F %lu\n", (unsigned long)ssl_of[i]);
            SSL_free(ssl_of[i]); close(fd_of[i]); ssl_of[i] = NULL;
        } else if (line[0] == 'N' && sscanf(line + 1, "%d", &i) == 1) {
            int result = open_handle(i);
            printf("N %d %lu\n", result, (unsigned long)ssl_of[i]);
        } else if (line[0] == 'R' && sscanf(line + 1, "%d", &i) == 1) {
            for (int r = 0; r < 2; r++) { readers[r].index = i; readers[r].result = -9; }
            pthread_create(&reading[0], NULL, read_once, &readers[0]);
            usleep(300000);
            SSL_set_shutdown(ssl_of[i], SSL_RECEIVED_SHUTDOWN);
            pthread_create(&reading[1], NULL, read_once, &readers[1]);
            pthread_join(reading[1], NULL);
            SSL_set_shutdown(ssl_of[i], 0);
            printf("R ready %d\n", readers[1].result);
        } else if (line[0] == 'S' && sscanf(line + 1, "%d", &i) == 1) {
            shutdown(fd_of[i], SHUT_RDWR);
            pthread_join(reading[0], NULL);
            printf("S %d\n", readers[0].result);
        } else if (line[0] == 'Q') {
            for (i = 0; i < HANDLES; i++) if (ssl_of[i]) { SSL_free(ssl_of[i]); close(fd_of[i]); ssl_of[i] = NULL; }
            printf("Q 0\n");
        }
        fflush(stdout);
    }
    return 0;
}
`

// nestedActorSource carries one TLS connection inside another: the inner
// handle's BIO writes and reads through SSL_write_ex and SSL_read on the outer
// handle, so every outer call after the inner handshake runs inside an inner
// one.
const nestedActorSource = `
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static SSL *outer;
static int outer_write(BIO *bio, const char *data, int length) {
    (void)bio;
    size_t written = 0;
    if (SSL_write_ex(outer, data, (size_t)length, &written) != 1) return -1;
    return (int)written;
}
static int outer_read(BIO *bio, char *data, int length) {
    (void)bio;
    return SSL_read(outer, data, length);
}
static long outer_ctrl(BIO *bio, int command, long number, void *pointer) {
    (void)bio; (void)number; (void)pointer;
    return command == BIO_CTRL_FLUSH ? 1 : 0;
}
static int outer_create(BIO *bio) { BIO_set_init(bio, 1); return 1; }

int main(int argc, char **argv) {
    if (argc != 2) return 10;
    int port = atoi(argv[1]);
    SSL_CTX *context = SSL_CTX_new(TLS_client_method());
    if (!context) return 11;
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
    printf("ready\n"); fflush(stdout);
    char line[64];
    SSL *inner = NULL;
    while (fgets(line, sizeof(line), stdin)) {
        if (line[0] == 'I') {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in address = {0};
            address.sin_family = AF_INET;
            address.sin_port = htons((unsigned short)port);
            inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
            if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) { printf("I 1\n"); fflush(stdout); continue; }
            outer = SSL_new(context);
            SSL_set_fd(outer, fd);
            if (SSL_connect(outer) != 1) { printf("I 2\n"); fflush(stdout); continue; }
            BIO_METHOD *method = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(), "outer");
            BIO_meth_set_write(method, outer_write);
            BIO_meth_set_read(method, outer_read);
            BIO_meth_set_ctrl(method, outer_ctrl);
            BIO_meth_set_create(method, outer_create);
            BIO *carrier = BIO_new(method);
            inner = SSL_new(context);
            SSL_set_bio(inner, carrier, carrier);
            printf("I %d %lu %lu\n", SSL_connect(inner) == 1 ? 0 : 3, (unsigned long)outer, (unsigned long)inner);
        } else if (line[0] == 'X') {
            const char *request = "GET /nested HTTP/1.1\r\nHost: localhost\r\n\r\n";
            size_t written = 0;
            int result = SSL_write_ex(inner, request, strlen(request), &written) == 1 ? 0 : 4;
            char response[4096] = {0};
            size_t used = 0;
            while (!result && !strstr(response, "peer-confirmed:/nested:end")) {
                int n = SSL_read(inner, response + used, (int)(sizeof(response) - 1 - used));
                if (n <= 0) { result = 6; break; }
                used += n;
            }
            printf("X %d\n", result);
        }
        fflush(stdout);
    }
    return 0;
}
`

// heldDelivery is the delivery path a case can stop: decoded events go from
// the session to a capture session, named as the adapter names them, and
// wait while held. With the session's staging channel shallow and its ring
// small, holding makes the ring refuse reservations after a handful of events.
type heldDelivery struct {
	session   *ebpf.Session
	recording *capture.Session
	fragments *sequenceFragments

	mutex    sync.Mutex
	release  chan struct{}
	known    map[int32]process.Process
	finished chan struct{}
}

type sequenceFragments struct {
	mutex   sync.Mutex
	records []fragment.Record
}

func (f *sequenceFragments) Write(record fragment.Record) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.records = append(f.records, record)
	return nil
}

func (f *sequenceFragments) all() []fragment.Record {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return append([]fragment.Record(nil), f.records...)
}

// deliverHeld attaches to one actor with the capacities given and starts the
// delivery loop.
func deliverHeld(t *testing.T, actor *armingProcess, resize map[string]uint32, staging int) *heldDelivery {
	t.Helper()
	parent := loaded(t, int32(actor.command.Process.Pid))
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, parent), Admit: authorise(parent),
		Resize: resize, Staging: staging})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	fragments := &sequenceFragments{}
	held := &heldDelivery{session: session, fragments: fragments, known: make(map[int32]process.Process),
		finished: make(chan struct{})}
	held.recording = capture.Recording(fragments, nil, capture.Settles(session))
	go held.deliver()
	return held
}

func (h *heldDelivery) hold() {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if h.release == nil {
		h.release = make(chan struct{})
	}
}

func (h *heldDelivery) flow() {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if h.release != nil {
		close(h.release)
		h.release = nil
	}
}

func (h *heldDelivery) deliver() {
	defer close(h.finished)
	for event := range h.session.Events() {
		h.mutex.Lock()
		wait := h.release
		h.mutex.Unlock()
		if wait != nil {
			<-wait
		}
		who, found := h.known[event.PID]
		if !found {
			who, _ = process.Identify(procfs, event.PID)
			h.known[event.PID] = who
		}
		instance := admission.Instance{Namespace: event.Namespace, PID: event.NamespacePID,
			Generation: event.Generation, Start: who.Start(), Executable: who.Executable}
		switch event.Kind {
		case ebpf.Closed:
			h.recording.Closed(probe.Connection{Process: who.Identity(), Instance: instance, Stamp: event.Stamp,
				Sequence: event.Sequence, Final: event.Final, Endpoint: event.SSL, At: event.At})
		case ebpf.Transfer:
			h.recording.Transfer(probe.Transfer{Process: who.Identity(), Instance: instance, Stamp: event.Stamp,
				Sequence: event.Sequence, Descriptor: event.Descriptor, Binding: event.Binding, Bound: event.Bound,
				Socket: event.Socket, Ends: event.Endpoints, Outcome: event.Outcome, Endpoint: event.SSL,
				Direction: event.Direction, Length: event.Length, Payload: event.Payload, Early: event.Early,
				Measured: event.Measured, At: event.At})
		}
	}
}

// seal stops production, drains, and settles every open connection against
// the program's occupancy table, as the session's finalisation does.
func (h *heldDelivery) seal(t *testing.T) []connection.Record {
	t.Helper()
	h.flow()
	if _, err := h.session.StopProducing(); err != nil {
		t.Fatal(err)
	}
	drained, err := h.session.Drain(3 * time.Second)
	if err != nil || !drained.Complete {
		t.Fatalf("the ring did not drain: %+v, %v", drained, err)
	}
	h.recording.Finish(time.Now())
	return h.recording.Records()
}

func command(t *testing.T, actor *armingProcess, line, want string) {
	t.Helper()
	if _, err := io.WriteString(actor.input, line+"\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, want+"\n")
}

// counter reads one of the program's counters, failing the case where it
// cannot be read: an unread counter is not a zero.
func counter(t *testing.T, read func() (int64, error)) int64 {
	t.Helper()
	value, err := read()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// firstGap is, per connection and direction, the offset of the first fragment
// whose producer number skips one, or false where none does; and the numbers
// missing between delivered fragments.
type directionKey struct {
	connection fragment.ConnectionID
	direction  fragment.Direction
}

func firstGaps(records []fragment.Record) (map[directionKey]uint64, map[directionKey]int64) {
	gaps := make(map[directionKey]uint64)
	missing := make(map[directionKey]int64)
	last := make(map[directionKey]uint64)
	for _, one := range records {
		key := directionKey{one.Connection, one.Direction}
		if one.Produced != last[key]+1 {
			if _, cut := gaps[key]; !cut {
				gaps[key] = one.Offset
			}
			missing[key] += int64(one.Produced - last[key] - 1)
		}
		last[key] = one.Produced
	}
	return gaps, missing
}

// The ring refusing reservations while delivery is held, over many handles in
// flight at once. Every refused reservation is a number missing from exactly
// one connection's direction, so the losses the records count add up to the
// reservations the kernel refused; each direction is cut where its first
// missing transfer would have begun, a direction that lost nothing stays
// established, and a connection begun after the loss is whole.
func TestRingLossIsLocatedToTheConnectionsThatLostAndCountedThere(t *testing.T) {
	for name, one := range map[string]struct {
		handles, rounds int
		ring            uint32
	}{
		// Fifteen events fit the ring and one waits in staging.
		"a small ring": {handles: 2, rounds: 10, ring: 64 << 10},
		// About two hundred and forty fit, against twenty-four threads at once.
		"many concurrent handles": {handles: 24, rounds: 12, ring: 1 << 20},
	} {
		t.Run(name, func(t *testing.T) {
			port := sequencePeer(t, nil)
			actor := independentActor(t, sequenceActorSource, port)
			run := deliverHeld(t, actor, map[string]uint32{"events": one.ring}, 1)

			command(t, actor, fmt.Sprintf("O %d", one.handles), "O 0")
			for i := 0; i < one.handles; i++ {
				command(t, actor, fmt.Sprintf("X %d before", i), "X 0")
			}
			time.Sleep(200 * time.Millisecond)
			if dropped := counter(t, run.session.Dropped); dropped != 0 {
				t.Fatalf("wiring, not the property: the control exchanges already lost %d events", dropped)
			}

			run.hold()
			command(t, actor, fmt.Sprintf("C %d %d burst", one.handles, one.rounds), "C 0")
			run.flow()
			time.Sleep(300 * time.Millisecond)
			command(t, actor, fmt.Sprintf("C %d 1 after", one.handles), "C 0")
			// The fresh connection: a handle born after the loss.
			if _, err := fmt.Fprintf(actor.input, "N %d\n", one.handles); err != nil {
				t.Fatal(err)
			}
			if line, err := actor.output.ReadString('\n'); err != nil || !strings.HasPrefix(line, "N 0 ") {
				t.Fatalf("fresh handle: %q: %v", line, err)
			}
			command(t, actor, fmt.Sprintf("X %d fresh", one.handles), "X 0")
			records := run.seal(t)

			dropped := counter(t, run.session.Dropped)
			unlocated, err := run.session.Unlocated()
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("precondition: %d reservations refused, %d unlocated, %d records", dropped, unlocated, len(records))
			if dropped == 0 {
				t.Fatalf("UNPROVED, not a pass: the ring refused no reservation, so nothing below measured a loss")
			}
			if unlocated != 0 {
				t.Fatalf("%d losses the producer placed in no occupancy, and every handle had one", unlocated)
			}

			gaps, missing := firstGaps(run.fragments.all())
			var counted, lossy, whole int64
			freshID := fragment.ConnectionID(0)
			for _, one := range run.fragments.all() {
				if strings.Contains(string(one.Payload), "/fresh-") {
					freshID = one.Connection
				}
			}
			if freshID == 0 {
				t.Fatal("wiring, not the property: the fresh connection's exchange never reached capture")
			}
			for _, record := range records {
				for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
					placement, found := record.Placement(direction)
					if !found {
						continue
					}
					if placement.Lost.Known {
						counted += placement.Lost.Value
					} else {
						t.Errorf("connection %d %s has an uncounted loss: %s", record.ID, direction, placement)
					}
					key := directionKey{record.ID, direction}
					offset, gapped := gaps[key]
					switch {
					case record.ID == freshID && !placement.Whole():
						t.Errorf("the connection begun after the loss is %s", placement)
					case gapped && (placement.Positions != connection.PositionsUnknownFrom &&
						placement.Positions != connection.PositionsUnknownThroughout || placement.From > offset ||
						placement.Placeable(offset)):
						t.Errorf("connection %d %s skipped a number at offset %d and is %s", record.ID, direction,
							offset, placement)
					case !gapped && placement.Lost.Known && placement.Lost.Value == 0 && !placement.Whole():
						t.Errorf("connection %d %s lost nothing and is %s", record.ID, direction, placement)
					}
					if placement.Lost.Known && placement.Lost.Value > 0 {
						lossy++
					} else if placement.Whole() {
						whole++
					}
					if placement.Lost.Known && placement.Lost.Value < missing[key] {
						t.Errorf("connection %d %s counts %d lost and skipped %d between delivered fragments",
							record.ID, direction, placement.Lost.Value, missing[key])
					}
				}
			}
			t.Logf("directions with a located loss: %d; whole: %d; transfers counted lost: %d", lossy, whole, counted)
			if counted != dropped {
				t.Errorf("the records count %d transfers lost and the kernel refused %d reservations: a refused "+
					"reservation that is no connection's loss, or a loss no refusal explains", counted, dropped)
			}
		})
	}
}

// Two calls in one direction on one handle at once, which OpenSSL's supported
// use forbids: a read waiting on a silent peer, and a second read entered on the
// same handle from another thread meanwhile. Two reads genuinely racing on one
// handle crash the client (measured), so the second is made to return before
// OpenSSL touches the record layer; its entry is what the producer sees. The
// producer marks the direction at that entry, so the first read, receiving the
// one record the peer then sends, carries the mark, and capture refuses the
// direction.
func TestOverlappingReadsOnOneHandleAreMarkedAndRefused(t *testing.T) {
	send := make(chan struct{})
	port := sequencePeer(t, send)
	actor := independentActor(t, sequenceActorSource, port)
	run := deliverHeld(t, actor, nil, 0)

	command(t, actor, "O 1", "O 0")
	command(t, actor, "R 0", "R ready 0")
	overlapped := counter(t, run.session.Overlapped)
	close(send)
	time.Sleep(500 * time.Millisecond)
	if _, err := io.WriteString(actor.input, "S 0\n"); err != nil {
		t.Fatal(err)
	}
	reads, err := actor.output.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	records := run.seal(t)
	t.Logf("precondition: %d overlapping entries before the record was sent; reads %q", overlapped,
		strings.TrimSpace(reads))
	if overlapped == 0 {
		t.Fatal("UNPROVED, not a pass: the second read did not enter while the first was in flight")
	}
	if len(records) != 1 {
		t.Fatalf("%d records, want the one handle's", len(records))
	}
	placement, found := records[0].Placement(fragment.Received)
	if !found {
		t.Fatalf("wiring, not the property: neither overlapping read delivered a transfer (reads %q)",
			strings.TrimSpace(reads))
	}
	if placement.Whole() || placement.Because != connection.OperationsOverlapped {
		t.Errorf("a direction two calls overlapped in is %s", placement)
	}
}

// A TLS connection carried inside another: every outer call after the inner
// handshake runs inside an inner call on the same thread, so nothing reports
// its bytes, and each takes a number as a loss in the outer handle's
// occupancy. The inner connection, the outermost call, is whole; the outer one
// is cut where the nested calls began. SSL_write_ex reaching SSL_write_ex2 on
// its own handle is a wrapper, whose bytes the outer call reports.
func TestCallsNestedInsideAnotherHandlesCallAreNumberedAsLost(t *testing.T) {
	port := nestedPeer(t)
	actor := independentActor(t, nestedActorSource, port)
	run := deliverHeld(t, actor, nil, 0)

	if _, err := io.WriteString(actor.input, "I\n"); err != nil {
		t.Fatal(err)
	}
	line, err := actor.output.ReadString('\n')
	var result int
	var outer, inner uint64
	if _, scanErr := fmt.Sscanf(line, "I %d %d %d", &result, &outer, &inner); err != nil || scanErr != nil || result != 0 {
		t.Fatalf("the nested connection was not established: %q: %v, %v", line, err, scanErr)
	}
	command(t, actor, "X", "X 0")
	time.Sleep(200 * time.Millisecond)
	elsewhere := counter(t, run.session.NestedElsewhere)
	wrappers := counter(t, run.session.NestedWrappers)
	records := run.seal(t)
	t.Logf("precondition: %d calls nested in another handle's, %d wrapper calls", elsewhere, wrappers)
	if elsewhere == 0 {
		t.Fatal("UNPROVED, not a pass: no call ran inside another handle's")
	}
	byHandle := make(map[uint64]connection.Record)
	for _, record := range records {
		byHandle[record.Handle.Address] = record
	}
	innerRecord, found := byHandle[inner]
	if !found {
		t.Fatal("wiring, not the property: the inner connection has no record")
	}
	for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
		if placement, ok := innerRecord.Placement(direction); !ok || !placement.Whole() {
			t.Errorf("the inner connection's %s direction is %+v, and nothing of it was lost", direction, placement)
		}
	}
	outerRecord, found := byHandle[outer]
	if !found {
		t.Fatal("wiring, not the property: the outer connection, which carried the inner handshake, has no record")
	}
	cut := 0
	for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
		placement, ok := outerRecord.Placement(direction)
		if ok && !placement.Whole() {
			cut++
			if placement.Because != connection.ObservationLost || !placement.Lost.Known || placement.Lost.Value == 0 {
				t.Errorf("the outer connection's %s direction is %s", direction, placement)
			}
		}
	}
	if cut == 0 {
		t.Error("the outer connection, whose nested calls nothing reported, is whole")
	}
}

// A handle released while delivery is held, its ending refused by the full
// ring, and its address taken by the next handle born: the program's next
// occupancy there is a different one whatever was delivered, so capture
// retires the old connection with its tail unsettled and the new one is whole.
func TestAHandleReusedAfterALostEndingIsANewOccupancy(t *testing.T) {
	port := sequencePeer(t, nil)
	actor := independentActor(t, sequenceActorSource, port)
	run := deliverHeld(t, actor, map[string]uint32{"events": 16384}, 1)

	command(t, actor, "O 2", "O 0")
	command(t, actor, "X 0 first", "X 0")
	time.Sleep(200 * time.Millisecond)

	run.hold()
	// Fill staging and the ring from the other handle, then release handle 0.
	for _, tag := range []string{"f1", "f2", "f3", "f4"} {
		command(t, actor, "X 1 "+tag, "X 0")
	}
	droppedBefore := counter(t, run.session.Dropped)
	if _, err := io.WriteString(actor.input, "F 0\n"); err != nil {
		t.Fatal(err)
	}
	var freed uint64
	if line, err := actor.output.ReadString('\n'); err != nil || func() error {
		_, scan := fmt.Sscanf(line, "F %d", &freed)
		return scan
	}() != nil {
		t.Fatalf("release: %q: %v", line, err)
	}
	droppedAtRelease := counter(t, run.session.Dropped) - droppedBefore
	var reused uint64
	var opened int
	for attempt := 0; attempt < 8; attempt++ {
		if _, err := io.WriteString(actor.input, "N 0\n"); err != nil {
			t.Fatal(err)
		}
		line, err := actor.output.ReadString('\n')
		if _, scan := fmt.Sscanf(line, "N %d %d", &opened, &reused); err != nil || scan != nil || opened != 0 {
			t.Fatalf("new handle: %q: %v, %v", line, err, scan)
		}
		if reused == freed {
			break
		}
	}
	run.flow()
	time.Sleep(300 * time.Millisecond)
	command(t, actor, "X 0 second", "X 0")
	records := run.seal(t)
	retired := run.recording.Stats().Retired
	t.Logf("precondition: address reused %v (%#x), %d reservations refused by the release, %d retired",
		reused == freed, freed, droppedAtRelease, retired)
	if reused != freed {
		t.Fatal("UNPROVED, not a pass: no new handle took the released address")
	}
	if droppedAtRelease != 1 {
		t.Fatalf("UNPROVED, not a pass: the ring refused %d events while the release alone was produced, "+
			"want its ending, exactly", droppedAtRelease)
	}
	var old, next *connection.Record
	for i := range records {
		if records[i].Handle.Address != freed {
			continue
		}
		if records[i].How == connection.EndingUnobserved {
			old = &records[i]
		} else if records[i].How == connection.StillOpen {
			next = &records[i]
		}
	}
	if old == nil || next == nil {
		t.Fatalf("records for the address: retired %v, open %v; want one of each (%d retired)", old != nil,
			next != nil, retired)
	}
	if sent, ok := old.Placement(fragment.Sent); !ok || sent.Whole() || sent.Because != connection.TerminalUnsettled {
		t.Errorf("the connection whose ending was lost claims a settled tail: %+v", sent)
	}
	for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
		if placement, ok := next.Placement(direction); !ok || !placement.Whole() {
			t.Errorf("the next occupancy's %s direction is %+v", direction, placement)
		}
	}
}

// connectionCarrying is the connection whose fragments carry text.
func connectionCarrying(t *testing.T, fragments []fragment.Record, text string) fragment.ConnectionID {
	t.Helper()
	for _, one := range fragments {
		if strings.Contains(string(one.Payload), text) {
			return one.Connection
		}
	}
	t.Fatalf("wiring, not the property: no fragment carries %q", text)
	return 0
}

// The occupancy table full: the program keeps no sequence for a handle it
// cannot enter, its transfers carry none, and each refused occupancy is a loss
// placed nowhere. Capture applies the conservative rule: the unsequenced
// connection establishes nothing, every connection live across the refusal is
// cut where it stood, and a connection begun after it establishes nothing.
func TestAFullOccupancyTableFallsBackToTheConservativeRule(t *testing.T) {
	port := sequencePeer(t, nil)
	actor := independentActor(t, sequenceActorSource, port)
	run := deliverHeld(t, actor, map[string]uint32{"occupancies": 2}, 0)

	command(t, actor, "O 2", "O 0")
	command(t, actor, "X 0 before", "X 0")
	command(t, actor, "X 1 before", "X 0")
	// A third handle the table cannot take.
	if _, err := io.WriteString(actor.input, "N 2\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := actor.output.ReadString('\n'); err != nil || !strings.HasPrefix(line, "N 0 ") {
		t.Fatalf("third handle: %q: %v", line, err)
	}
	command(t, actor, "X 2 unsequenced", "X 0")
	command(t, actor, "X 0 after", "X 0")
	// Room again, and a handle born after the refusals.
	if _, err := io.WriteString(actor.input, "F 1\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := actor.output.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(actor.input, "N 3\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := actor.output.ReadString('\n'); err != nil || !strings.HasPrefix(line, "N 0 ") {
		t.Fatalf("fourth handle: %q: %v", line, err)
	}
	command(t, actor, "X 3 later", "X 0")
	time.Sleep(200 * time.Millisecond)
	refused := counter(t, run.session.OccupanciesUnrecorded)
	records := run.seal(t)
	unlocated, err := run.session.Unlocated()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("precondition: %d occupancies refused, %d losses placed nowhere", refused, unlocated)
	if refused == 0 || unlocated == 0 {
		t.Fatal("UNPROVED, not a pass: the table refused no occupancy")
	}

	fragments := run.fragments.all()
	placementIn := func(id fragment.ConnectionID, direction fragment.Direction) connection.Placement {
		t.Helper()
		for _, record := range records {
			if record.ID == id {
				if placement, ok := record.Placement(direction); ok {
					return placement
				}
			}
		}
		t.Fatalf("wiring, not the property: connection %d has no %s placement", id, direction)
		return connection.Placement{}
	}
	unsequenced := connectionCarrying(t, fragments, "/unsequenced-2")
	if placement := placementIn(unsequenced, fragment.Sent); placement.Positions != connection.PositionsUnknownThroughout ||
		placement.Because != connection.SequenceUnavailable {
		t.Errorf("the connection the table refused is %s", placement)
	}
	live := connectionCarrying(t, fragments, "/before-0")
	before := uint64(0)
	for _, one := range fragments {
		if one.Connection == live && one.Direction == fragment.Sent && strings.Contains(string(one.Payload), "/before-0") {
			before = one.End()
		}
	}
	if placement := placementIn(live, fragment.Sent); placement.Positions != connection.PositionsUnknownFrom ||
		placement.From != before || placement.Because != connection.ObservationLost || placement.Lost.Known {
		t.Errorf("a connection live across the refusals is %s, want unknown from %d with the count undetermined",
			placement, before)
	}
	later := connectionCarrying(t, fragments, "/later-3")
	if placement := placementIn(later, fragment.Sent); placement.Positions != connection.PositionsUnknownThroughout {
		t.Errorf("a connection begun after the refusals is %s", placement)
	}
}
