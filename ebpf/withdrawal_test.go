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
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
)

type independentPendingRead struct {
	actor      *armingProcess
	session    *ebpf.Session
	pid        int32
	generation admission.Generation
	reads      uint64
	release    func()
}

// The same execution completes a peer-confirmed call, with captured response
// bytes and a moving read counter, before its next call is held inside libssl.
// The peer holds the response; the actor has no invalid pointer or fake return.
func independentlyPendingRead(t *testing.T, outparam bool) independentPendingRead {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	received := make(chan string, 4)
	var calls atomic.Int32
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.URL.Path
		if calls.Add(1) > 1 {
			<-release
		}
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
	t.Cleanup(func() { _ = session.Close() })
	t.Cleanup(unblock)
	if _, err := io.WriteString(actor.input, "P\n"); err != nil {
		t.Fatal(err)
	}
	actorLine(t, actor, "parent 0\n")
	peerReceived(t, received, "/independent-parent")
	control := drain(session, 100*time.Millisecond)
	response := false
	for _, event := range control.events {
		if event.Direction == fragment.Received && strings.Contains(string(event.Payload), "peer-confirmed:/independent-parent") {
			response = true
		}
	}
	if !response || attribution(control, "/independent-parent") == nil {
		t.Fatal("completed same-process call did not establish captured request and response controls")
	}
	reads, err := session.Reads()
	if err != nil || len(reads) != 1 {
		t.Fatalf("completed control's reads: %v, %v", reads, err)
	}
	for _, count := range reads {
		if count == 0 {
			t.Fatal("completed control took no recorded reads")
		}
	}
	if _, err := io.WriteString(actor.input, "P\n"); err != nil {
		t.Fatal(err)
	}
	peerReceived(t, received, "/independent-parent")
	generation := savedRead(t, session, process.PID, outparam)
	before, err := session.Reads()
	if err != nil || before[generation] <= reads[generation] {
		t.Fatalf("second call did not enter under the live generation: %v, %v", before, err)
	}
	refused, err := session.Refused()
	if err != nil || refused != 0 {
		t.Fatalf("pre-withdrawal refusal control: %d, %v", refused, err)
	}
	return independentPendingRead{actor, session, process.PID, generation, before[generation], unblock}
}

// This wrapper returns the real producer's result unchanged and only releases
// the peer the instant the real withdrawal completes, so no scheduling delay
// is used as proof.
type independentObservedWithdrawal struct {
	*ebpf.Session
	after func(connection.Withdrawal, error)
}

func (p independentObservedWithdrawal) StopProducing() (connection.Withdrawal, error) {
	withdrawal, err := p.Session.StopProducing()
	p.after(withdrawal, err)
	return withdrawal, err
}

func TestStopProducingRefusesTheReturningCallAndSealsItsCount(t *testing.T) {
	for _, outparam := range []bool{false, true} {
		t.Run(fmt.Sprintf("outparam=%t", outparam), func(t *testing.T) {
			pending := independentlyPendingRead(t, outparam)
			coordinated := independentObservedWithdrawal{Session: pending.session, after: func(withdrawal connection.Withdrawal, err error) {
				if err != nil || !withdrawal.Complete || withdrawal.Instances != 1 {
					t.Fatalf("withdrawal did not report the one real grant: %+v, %v", withdrawal, err)
				}
				left, err := pending.session.Admissions()
				if err != nil || len(left) != 0 {
					t.Fatalf("withdrawal left live admissions: %v, %v", left, err)
				}
				pending.release()
				actorLine(t, pending.actor, "parent 0\n")
				after, err := pending.session.Reads()
				if err != nil {
					t.Fatal(err)
				}
				if after[pending.generation] != pending.reads {
					t.Errorf("withdrawn returning call read user memory: generation %d reads %d -> %d", pending.generation, pending.reads, after[pending.generation])
				}
				refused, err := pending.session.Refused()
				if err != nil || refused != 1 {
					t.Errorf("withdrawn return was not counted exactly once at the refusal boundary: %d, %v", refused, err)
				}
				for _, event := range drain(pending.session, 100*time.Millisecond).events {
					if event.Direction == fragment.Received && event.Length > 0 {
						t.Errorf("withdrawn response reached capture: %+v", event)
					}
				}
			}}
			sealer := connection.Sealer{Producer: coordinated, Within: time.Second}
			seal, err := sealer.Stop()
			if err != nil || !seal.Interrupted.Known || seal.Interrupted.Value != 1 {
				t.Errorf("the accounted refusal disappeared at seal: %+v, %v", seal, err)
			}
		})
	}
}

func TestSealDoesNotCallAnExecutingReadAnEmptyRun(t *testing.T) {
	pending := independentlyPendingRead(t, false)
	sealer := connection.Sealer{Producer: pending.session, Within: 200 * time.Millisecond}
	seal, err := sealer.Stop()
	if err != nil {
		t.Fatal(err)
	}
	// The peer has not released its response, so the real operation remains
	// inside libssl. A correct stop may already have accounted for and removed
	// its saved entry; the test does not require that entry to survive.
	if !seal.Counters.StillExecuting.Known || seal.Counters.StillExecuting.Value != 1 {
		t.Errorf("seal did not retain the explicit one-call StillExecuting population while the peer held the call: %+v", seal)
	}
	pending.release()
	actorLine(t, pending.actor, "parent 0\n")
	refused, err := pending.session.Refused()
	if err != nil || refused != 1 {
		t.Fatalf("held call never reached the refusal boundary after the seal: %d, %v", refused, err)
	}
}

func TestRingReaderFailureCannotSealAsZeroLoss(t *testing.T) {
	pending := independentlyPendingRead(t, false)
	if err := ebpf.IndependentFailRingReader(pending.session); err != nil {
		t.Fatal(err)
	}
	pending.release()
	actorLine(t, pending.actor, "parent 0\n")
	reads, err := pending.session.Reads()
	if err != nil || reads[pending.generation] <= pending.reads {
		t.Fatalf("post-failure peer-confirmed response never reached the live probe: %v, %v", reads, err)
	}
	sealer := connection.Sealer{Producer: pending.session, Within: time.Second}
	seal, err := sealer.Stop()
	if err != nil {
		t.Fatal(err)
	}
	if seal.Complete || seal.Drain.Complete || seal.Drain.Outstanding.Known || seal.Counters.LostAfterSubmission.Known || seal.Counters.LostAfterSubmission.Why == "" || seal.Sound() {
		t.Errorf("reader failure left a seal claiming known empty loss or a sound run: %+v", seal)
	}
}

func TestRestartDoesNotReadThePreviousAdmissionsSavedCall(t *testing.T) {
	for _, outparam := range []bool{false, true} {
		t.Run(fmt.Sprintf("outparam=%t", outparam), func(t *testing.T) {
			pending := independentlyPendingRead(t, outparam)
			withdrawal, err := pending.session.StopProducing()
			if err != nil || !withdrawal.Complete || withdrawal.Instances != 1 {
				t.Fatalf("old authority was not withdrawn: %+v, %v", withdrawal, err)
			}
			// Each session owns its admission and read-counter maps. Their numeric
			// generations need not differ; the old call must be refused by its
			// original session and must not appear in the newly activated one.
			current := loaded(t, pending.pid)
			next, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: points(t, current), Admit: authorise(current)})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = next.Close() }()
			grants, err := next.Admissions()
			if err != nil {
				t.Fatal(err)
			}
			var generation admission.Generation
			for _, grant := range grants {
				if grant.Instance.Namespace == current.Namespace && grant.Instance.PID == current.NamespacePID {
					generation = grant.Instance.Generation
				}
			}
			if generation == 0 {
				t.Fatal("restart did not establish the actor's admission in the new session")
			}
			pending.release()
			actorLine(t, pending.actor, "parent 0\n")
			oldReads, err := pending.session.Reads()
			if err != nil {
				t.Fatal(err)
			}
			newReads, err := next.Reads()
			if err != nil {
				t.Fatal(err)
			}
			if oldReads[pending.generation] != pending.reads || newReads[generation] != 0 {
				t.Errorf("old saved call read through withdrawn or newly activated authority: old %d -> %d, new %d", pending.reads, oldReads[pending.generation], newReads[generation])
			}
			for _, event := range drain(next, 100*time.Millisecond).events {
				if event.Direction == fragment.Received && event.Length > 0 {
					t.Errorf("restart captured the previous admission's returning call: %+v", event)
				}
			}
			refused, err := pending.session.Refused()
			if err != nil || refused != 1 {
				t.Errorf("old saved call was not accounted at its own refusal boundary: %d, %v", refused, err)
			}
			if _, err := io.WriteString(pending.actor.input, "P\n"); err != nil {
				t.Fatal(err)
			}
			actorLine(t, pending.actor, "parent 0\n")
			if attribution(drain(next, 100*time.Millisecond), "/independent-parent") == nil {
				t.Fatal("new admission did not capture a fresh peer-confirmed call")
			}
			liveReads, err := next.Reads()
			if err != nil || liveReads[generation] == 0 {
				t.Fatalf("new admission's positive read control failed: %v, %v", liveReads, err)
			}
		})
	}
}
