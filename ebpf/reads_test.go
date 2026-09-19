//go:build attach

package ebpf_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
)

func readActorSource(outparam bool) string {
	source := immediateForkSource()
	if !outparam {
		return source
	}
	source = strings.Replace(source, "static int transfer(const char *path)", `static int read_step(SSL *ssl, void *buf, int cap) {
	size_t moved = 0;
	return SSL_read_ex(ssl, buf, cap, &moved) == 1 ? (int)moved : 0;
}
static int transfer(const char *path)`, 1)
	return strings.Replace(source, "SSL_read(ssl, response+used", "read_step(ssl, response+used", 1)
}

func savedRead(t *testing.T, session *ebpf.Session, pid int32, outparam bool) admission.Generation {
	t.Helper()
	want := uint32(1)
	if outparam {
		want = 3
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		generation, function, found, err := ebpf.IndependentSavedCall(session, pid)
		if err != nil {
			t.Fatal(err)
		}
		if found && function == want {
			return generation
		}
		select {
		case <-deadline.C:
			t.Fatalf("actor never entered the blocking read, last saved function %d", function)
		case <-tick.C:
		}
	}
}

// This covers a missing grant and a replaced generation in the real loaded
// program. It deliberately does not claim that deleting an allowlist entry is
// the production capture-authority withdrawal operation.
func TestSavedReadRequiresItsOwnLiveGeneration(t *testing.T) {
	for _, outparam := range []bool{false, true} {
		for _, replace := range []bool{false, true} {
			t.Run(fmt.Sprintf("outparam=%t/replaced=%t", outparam, replace), func(t *testing.T) {
				release := make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				received := make(chan string, 4)
				peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					received <- r.URL.Path
					<-release
					w.Header().Set("Connection", "close")
					_, _ = io.WriteString(w, "peer-confirmed:"+r.URL.Path)
				}))
				t.Cleanup(peer.Close)
				port, err := strconv.Atoi(strings.TrimPrefix(peer.URL, "https://127.0.0.1:"))
				if err != nil {
					t.Fatal(err)
				}
				actor := independentActor(t, readActorSource(outparam), port)
				process := loaded(t, int32(actor.command.Process.Pid))
				session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, process), Admit: authorise(process)})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = session.Close() }()
				if _, err := io.WriteString(actor.input, "P\n"); err != nil {
					t.Fatal(err)
				}
				peerReceived(t, received, "/independent-parent")
				old := savedRead(t, session, process.PID, outparam)
				before, err := session.Reads()
				if err != nil || before[old] == 0 {
					t.Fatalf("approved request did not establish a read-counter control: %v, %v", before, err)
				}
				var next admission.Generation
				if replace {
					next = old + 100000
				}
				restore, err := ebpf.IndependentReplaceGrant(session, process.Instance(), next)
				if err != nil {
					t.Fatal(err)
				}
				unblock()
				actorLine(t, actor, "parent 0\n")
				after, err := session.Reads()
				if err != nil {
					t.Fatal(err)
				}
				if after[old] != before[old] || after[next] != before[next] {
					t.Errorf("forbidden user-memory read after grant transition: old generation %d: %d -> %d; new generation %d: %d -> %d", old, before[old], after[old], next, before[next], after[next])
				}
				refused, err := session.Refused()
				if err != nil || refused != 1 {
					t.Errorf("return with a stale saved call was not accounted once: %d, %v", refused, err)
				}
				if err := restore(); err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(actor.input, "P\n"); err != nil {
					t.Fatal(err)
				}
				actorLine(t, actor, "parent 0\n")
				peerReceived(t, received, "/independent-parent")
				live, err := session.Reads()
				if err != nil || live[old] <= after[old] {
					t.Fatalf("restored grant did not read a fresh call: %v, %v", live, err)
				}
			})
		}
	}
}

func TestReadEvidenceCannotSilentlyDisappearWhenHistoryIsFull(t *testing.T) {
	port, received := independentPeer(t)
	actor := independentActor(t, immediateForkSource(), port)
	process := loaded(t, int32(actor.command.Process.Pid))
	session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, process), Admit: authorise(process)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	transfer := func() {
		if _, err := io.WriteString(actor.input, "P\n"); err != nil {
			t.Fatal(err)
		}
		actorLine(t, actor, "parent 0\n")
		peerReceived(t, received, "/independent-parent")
	}
	transfer()
	initial, err := session.Reads()
	if err != nil || len(initial) != 1 {
		t.Fatalf("live read control: %v, %v", initial, err)
	}
	var old admission.Generation
	for generation, count := range initial {
		old = generation
		if count == 0 {
			t.Fatal("control recorded zero reads")
		}
	}
	if err := ebpf.IndependentFillReadHistory(session, old); err != nil {
		t.Fatal(err)
	}
	next := old + 100000
	if _, err := ebpf.IndependentReplaceGrant(session, process.Instance(), next); err != nil {
		t.Fatal(err)
	}
	transfer()
	reads, err := session.Reads()
	if err == nil && reads[next] == 0 {
		t.Error("peer-confirmed transfer took user-memory reads under a new generation, but full history silently reported zero")
	}
}
