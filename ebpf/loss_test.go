//go:build attach

package ebpf_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
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

func independentLossSource(streams int) string {
	prefix, _, _ := strings.Cut(independentTransferSource, "static int transfer(")
	return fmt.Sprintf("#define STREAMS %d\n", streams) + prefix + `
static SSL *streams[STREAMS];
static int sockets[STREAMS];
static int exchange(int index, const char *path) {
    SSL *ssl = streams[index];
    if (!ssl) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET;
        address.sin_port = htons((unsigned short)port);
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
        if (connect(fd, (struct sockaddr *)&address, sizeof(address))) return 1;
        ssl = SSL_new(context);
        if (!ssl) return 2;
        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) != 1) return 3;
        streams[index] = ssl; sockets[index] = fd;
    }
    char request[512];
    snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: localhost\r\n\r\n", path);
    if (SSL_write(ssl, request, strlen(request)) != (int)strlen(request)) return 4;
    char response[8192] = {0}, expected[512];
    snprintf(expected, sizeof(expected), "peer-confirmed:%s:end", path);
    size_t used = 0;
    while (!strstr(response, expected)) {
        if (used >= sizeof(response)-1) return 5;
        int n = SSL_read(ssl, response+used, sizeof(response)-1-used);
        if (n <= 0) return 6;
        used += n;
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 2) return 10;
    port = atoi(argv[1]);
    context = SSL_CTX_new(TLS_client_method());
    if (!context) return 11;
    SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
    printf("ready\n"); fflush(stdout);
    char command[8];
    while (fgets(command, sizeof(command), stdin)) {
        int result = 0;
        if (command[0] == 'P' || command[0] == 'A') {
            for (int i=0; i<STREAMS && !result; i++) {
                char path[64]; snprintf(path, sizeof(path), "/%s-%d", command[0]=='P' ? "before" : "after", i);
                result = exchange(i, path);
            }
        } else if (command[0] == 'H') {
            result = exchange(0, "/hold");
        } else if (command[0] == 'B') {
            for (int i=0; i<9000 && !result; i++) result = exchange(i%STREAMS, "/burst");
        } else if (command[0] == 'Q') {
            for (int i=0; i<STREAMS; i++) { SSL_free(streams[i]); close(sockets[i]); }
        }
        printf("%c %d\n", command[0], result); fflush(stdout);
    }
    return 0;
}
`
}

func independentFragments(t *testing.T, path string) []fragment.Record {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var records []fragment.Record
	decoder := json.NewDecoder(file)
	for {
		var record fragment.Record
		err := decoder.Decode(&record)
		// This reader polls a file while capture appends. A partial final
		// object is not consumed; the next poll reads it after the write ends.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return records
		}
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
}

func waitIndependentMarker(t *testing.T, disk *spool.Spool, marker string) fragment.ConnectionID {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		for _, record := range independentFragments(t, disk.Path()) {
			if record.Direction == fragment.Received && strings.Contains(string(record.Payload), "peer-confirmed:"+marker+":end") {
				return record.Connection
			}
		}
		select {
		case <-deadline.C:
			t.Fatalf("peer-confirmed response for %s never reached the persisted stream", marker)
		case <-tick.C:
		}
	}
}

func exerciseIndependentStreamLoss(t *testing.T, streams int) {
	var peerCalls atomic.Int64
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerCalls.Add(1)
		_, _ = io.WriteString(w, "peer-confirmed:"+r.URL.Path+":end")
	}))
	t.Cleanup(peer.Close)
	port, err := strconv.Atoi(strings.TrimPrefix(peer.URL, "https://127.0.0.1:"))
	if err != nil {
		t.Fatal(err)
	}
	actor := independentActor(t, independentLossSource(streams), port)
	parent := loaded(t, int32(actor.command.Process.Pid))
	disk, err := spool.Open(t.TempDir(), 32<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = disk.Close() })
	recording := capture.Recording(disk, disk)
	sink := &independentHeldSink{capture: recording, entered: make(chan struct{}), release: make(chan struct{})}
	live, err := attach.NeweBPF(process.Approval{}).Attach(probe.Request{Processes: []process.Process{parent}, Admit: authorise(parent)}, sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = live.Close() })
	t.Cleanup(sink.unblock)
	counting, ok := live.(probe.Counting)
	if !ok {
		t.Fatal("the real backend cannot report ring loss")
	}
	producer, ok := live.(connection.Producer)
	if !ok {
		t.Fatal("the real backend cannot seal production")
	}
	command := func(code byte) {
		if _, err := fmt.Fprintf(actor.input, "%c\n", code); err != nil {
			t.Fatal(err)
		}
		actorLine(t, actor, fmt.Sprintf("%c 0\n", code))
	}
	command('P')
	ids := make(map[fragment.ConnectionID]bool)
	for i := 0; i < streams; i++ {
		ids[waitIndependentMarker(t, disk, fmt.Sprintf("/before-%d", i))] = true
	}
	if len(ids) != streams {
		t.Fatalf("positive controls merged %d live TLS handles into %d streams", streams, len(ids))
	}
	before, err := counting.Losses()
	if err != nil || before.Dropped != 0 {
		t.Fatalf("control run already lost events: %+v, %v", before, err)
	}
	sink.armed.Store(true)
	command('H')
	select {
	case <-sink.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("delivery never reached the held sink")
	}
	command('B')
	if got := peerCalls.Load(); got != int64(streams+1+9000) {
		t.Fatalf("burst did not complete at the independent peer: %d calls", got)
	}
	lost, err := counting.Losses()
	if err != nil || lost.Dropped <= 0 {
		t.Fatalf("the real ring never reached reservation loss: %+v, %v", lost, err)
	}
	sink.unblock()
	// Let the queued prefix drain before the late transfers. Whether those
	// later bytes arrived is asserted on disk, not inferred from this pause.
	time.Sleep(200 * time.Millisecond)
	command('A')
	for i := 0; i < streams; i++ {
		_ = waitIndependentMarker(t, disk, fmt.Sprintf("/after-%d", i))
	}
	command('Q')
	finalLoss, err := counting.Losses()
	if err != nil {
		t.Fatal(err)
	}
	sealer := connection.Sealer{Producer: producer, Within: time.Second}
	seal, err := sealer.Stop()
	if err != nil {
		t.Fatal(err)
	}
	if !seal.Counters.ReservationFailures.Known || seal.Counters.ReservationFailures.Value != finalLoss.Dropped {
		t.Fatalf("the measured reservation loss did not reach the seal: %+v", seal)
	}
	if !seal.Counters.Ordered.Known {
		t.Fatalf("the real finalisation did not expose the production allocator: %+v", seal.Counters.Ordered)
	}
	recording.Finish(seal.Sealed, seal.Counters.Ordered)
	records := independentConnections(t, disk.ConnectionsPath())
	if len(records) < streams {
		t.Fatalf("persisted population lost physical streams: %d records for %d streams", len(records), streams)
	}
	fragments := independentFragments(t, disk.Path())
	for _, record := range records {
		hasAfter := false
		for _, one := range fragments {
			if one.Connection == record.ID && strings.Contains(string(one.Payload), "/after-") {
				hasAfter = true
				break
			}
		}
		if !hasAfter {
			for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
				placement, ok := record.Placement(direction)
				if !ok || placement.Positions == connection.PositionsEstablished || record.Placeable(direction) {
					t.Errorf("retired stream %d claimed placeability after a lost observation: %+v", record.ID, placement)
				}
			}
			continue
		}
		for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
			var afterOffset uint64
			found := false
			for _, one := range fragments {
				if one.Connection == record.ID && one.Direction == direction && strings.Contains(string(one.Payload), "/after-") {
					if !found || one.Offset < afterOffset {
						afterOffset = one.Offset
					}
					found = true
				}
			}
			if !found {
				t.Fatalf("stream %d %s has no persisted peer-confirmed after-loss fragment", record.ID, direction)
			}
			placement, ok := record.Placement(direction)
			// Production stamps can establish a prefix now. The guarantee is
			// that lost bytes do not become invented positions, not that the
			// observer must discard knowledge of the prefix it can locate.
			// Bound that claim by the ACTUAL persisted after-loss offset in
			// each direction of EVERY stream, rather than accepting any prefix.
			unknown := placement.Positions == connection.PositionsUnknownThroughout ||
				(placement.Positions == connection.PositionsUnknownFrom && placement.From <= afterOffset)
			if !ok || !unknown || placement.Placeable(afterOffset) || record.Placeable(direction) {
				t.Errorf("ring loss left persisted stream %d %s claiming positions at after-loss offset %d: %+v", record.ID, direction, afterOffset, placement)
			}
		}
	}
}

func TestOneStreamKeepsItsBytesAndLosesItsPlacementAfterRingLoss(t *testing.T) {
	exerciseIndependentStreamLoss(t, 1)
}
func TestUnlocalizableRingLossInvalidatesBothInterleavedStreams(t *testing.T) {
	exerciseIndependentStreamLoss(t, 2)
}
