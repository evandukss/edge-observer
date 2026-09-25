//go:build attach

package attach_test

import (
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/process"
)

// t13Workers is every child the server has other than those in known, once
// there is at least one.
func t13Workers(t *testing.T, server int32, known ...int32) []int32 {
	t.Helper()
	for range 300 {
		table, err := process.Read(procfs)
		if err != nil {
			t.Fatalf("read the process table: %v", err)
		}
		var found []int32
		for _, p := range table.All() {
			if p.PPID == server && !slices.Contains(known, p.PID) {
				found = append(found, p.PID)
			}
		}
		if len(found) > 0 {
			return found
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("wiring, not the property: the server %d forked no worker beyond %v", server, known)
	return nil
}

// Live inspect of a running session that has seen traffic shows the target
// attached and confirmed, transfers seen and admissions covered, and says in
// text that events arrived. The same inspect of an idle session says it is
// idle, so the two are told apart by what crossed and by nothing else.
func TestLiveInspectSaysEventsArrivedAfterTrafficAndSaysNoneArrivedWhileIdle(t *testing.T) {
	binary := built(t)
	for _, traffic := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "after an exchange"}[traffic], func(t *testing.T) {
			client := speaking(t, serving(t))
			c := configuring(t, target("under-test", client.process))
			observer := started(t, binary, c)
			if traffic {
				t13Exchange(t, client, "t13-inspected", "")
			}

			live := inspected(t, binary, c)
			// Transfers reach the session's counts through the ring buffer, after the
			// client has read its answer; the idle case waits for nothing.
			for tries := 0; traffic && (live.Seen == nil || live.Seen.Transfers == 0) && tries < 50; tries++ {
				time.Sleep(100 * time.Millisecond)
				live = inspected(t, binary, c)
			}
			if live.Kind != account.Live || live.Session != observer.session || !observes(live, client.process.PID) {
				t.Fatalf("wiring, not the property: inspect answered a %s account of session %q observing %v, "+
					"not the running session %s over pid %d", live.Kind, live.Session, live.Processes,
					observer.session, client.process.PID)
			}

			if len(live.Processes) != 1 || live.Processes[0].Outcome != attachment.Attached ||
				live.Processes[0].Requested == 0 || live.Processes[0].Confirmed != live.Processes[0].Requested {
				t.Errorf("the live account says %+v about the one approved process", live.Processes)
			}
			if live.Admissions == nil || live.Admissions.Covered < 1 {
				t.Errorf("the live account covers %+v while the approved process runs", live.Admissions)
			}
			switch {
			case live.Seen == nil:
				t.Errorf("the live account carries no transfer count")
			case traffic && live.Seen.Transfers == 0:
				t.Errorf("the live account saw no transfer after an exchange crossed the approved process")
			case !traffic && live.Seen.Transfers != 0:
				t.Errorf("the live account saw %d transfers while nothing crossed", live.Seen.Transfers)
			}

			text, err := exec.Command(binary, "inspect", c.path, "--text").Output()
			if err != nil {
				t.Fatalf("inspect the running session as text: %v", err)
			}
			want, other := "state      attached, and events arrived", "state      attached, and no event arrived"
			if !traffic {
				want, other = other, want
			}
			if !strings.Contains(string(text), want) || strings.Contains(string(text), other) {
				t.Errorf("the text account does not say %q alone:\n%s", want, text)
			}
		})
	}
}

// An additive reload admits the new process and its exchange is captured. The
// connection already observed goes on as one stream across the reload: each
// exchange before and after it is retained once, and in each direction every
// message starts where the one before it ended, so a repeat shows as an
// offset behind and a loss as one ahead. A reload adding nothing answers
// unchanged, and the stream goes on across it the same way.
func TestAnAdditiveReloadAdmitsTheNewProcessAndTheObservedConnectionGoesOnWithNoGapAndNoRepeat(t *testing.T) {
	binary := built(t)
	kept := speaking(t, serving(t))
	added := speaking(t, serving(t))
	c := configuring(t, target("kept", kept.process))
	observer := started(t, binary, c)
	t13Exchange(t, kept, "t13-before-the-reload", "")

	c.rewrite(t, []map[string]any{target("kept", kept.process), target("added", added.process)}, nil)
	answer, err := reloaded(t, binary, c)
	if err != nil || answer.Outcome != "activated" || answer.Generation != 2 {
		t.Fatalf("the additive reload answered %+v with %v, want generation 2 activated", answer, err)
	}
	t13Exchange(t, kept, "t13-after-the-reload", "")
	t13Exchange(t, added, "t13-added-by-the-reload", "")
	unchanged, err := reloaded(t, binary, c)
	if err != nil || unchanged.Outcome != "unchanged" || unchanged.Generation != 2 {
		t.Errorf("a reload adding nothing answered %+v with %v, want unchanged at generation 2", unchanged, err)
	}
	t13Exchange(t, kept, "t13-after-the-unchanged-reload", "")
	live := inspected(t, binary, c)
	ended(t, observer, c)

	messages := t13Messages(t, observer.directory(c))
	if len(t13Asked(messages, kept.process.PID, "t13-before-the-reload")) == 0 {
		t.Fatalf("wiring, not the property: the exchange before any reload is not in the approved output, so " +
			"nothing below measures what a reload did to the stream")
	}
	for _, marker := range []string{"t13-before-the-reload", "t13-after-the-reload", "t13-after-the-unchanged-reload"} {
		if got := len(t13Asked(messages, kept.process.PID, marker)); got != 1 {
			t.Errorf("the observed process's exchange %s is retained %d times, want once", marker, got)
		}
	}
	if got := len(t13Asked(messages, added.process.PID, "t13-added-by-the-reload")); got != 1 {
		t.Errorf("the newly admitted process's exchange is retained %d times, want once", got)
	}
	if live.Policy.Generation != 2 || !observes(live, added.process.PID) {
		t.Errorf("after the reloads the live account is at generation %d and observes the added process: %v",
			live.Policy.Generation, observes(live, added.process.PID))
	}

	streams := map[string][]t13Message{}
	connections := map[string]bool{}
	for _, one := range messages {
		if one.pid == kept.process.PID {
			streams[one.direction] = append(streams[one.direction], one)
			connections[one.connection] = true
		}
	}
	if len(connections) != 1 {
		t.Errorf("the observed process's exchanges are retained on %d connections, want its one: %v",
			len(connections), connections)
	}
	for direction, stream := range streams {
		sort.SliceStable(stream, func(i, j int) bool { return stream[i].offset < stream[j].offset })
		for i := 1; i < len(stream); i++ {
			if stream[i].offset != stream[i-1].end {
				was := "repeats what already crossed"
				if stream[i].offset > stream[i-1].end {
					was = "leaves a gap"
				}
				t.Errorf("the %s stream has a %s at offset %d after one ending at %d: it %s (%s after %s)", direction,
					stream[i].kind, stream[i].offset, stream[i-1].end, was, stream[i].target, stream[i-1].target)
			}
		}
		if len(stream) != 3 {
			t.Errorf("the %s stream retains %d messages across three exchanges, want 3", direction, len(stream))
		}
	}
	if len(streams) != 2 {
		t.Errorf("the observed process's messages cross %d directions, want both", len(streams))
	}
}

// A port target on a server forking a worker per connection resolves to the
// parent and the worker running at activation, and captures that worker. The
// mode decides a worker forked after activation: follow covers it and none
// does not.
func TestAPortTargetOnAForkingServerCoversItsWorkersAndItsModeDecidesTheOnesForkedAfter(t *testing.T) {
	binary := built(t)
	for _, one := range []struct {
		mode  string
		later bool
	}{{"follow", true}, {"none", false}} {
		t.Run(one.mode, func(t *testing.T) {
			server, port := forkingServer(t)
			early := speaking(t, port)
			t13Exchange(t, early, "t13-early", "")
			existing := t13Workers(t, server.PID)

			c := configuring(t, map[string]any{"name": "server", "port": port, "descendants": one.mode})
			observer := started(t, binary, c)
			roots := pidsIn(named(inspected(t, binary, c), "server").Roots)
			if !slices.Contains(roots, server.PID) || !slices.Contains(roots, existing[0]) {
				t.Errorf("the port resolved to %v, want the server %d and its running worker %d", roots, server.PID,
					existing[0])
			}

			late := speaking(t, port)
			t13Exchange(t, late, "t13-late", "")
			forkedAfter := t13Workers(t, server.PID, existing...)
			t13Exchange(t, early, "t13-early-again", "")
			t13Exchange(t, early, "t13-early-third", "")
			t13Exchange(t, late, "t13-late-again", "")
			sealed := ended(t, observer, c)

			messages := t13Messages(t, observer.directory(c))
			// The worker running at activation is covered under both modes, so it is
			// what makes the later worker's absence under none a measurement. Its
			// FIRST exchange after activation is not the one read: the worker was
			// already inside SSL_read when the probes were placed, so that request
			// is never seen and its response is withheld as unpaired (measured: an
			// unpaired_exchange truncation on the worker's sent stream). The exchange
			// after it enters the library under the grant.
			if got := len(t13Asked(messages, existing[0], "t13-early-third")); got != 1 {
				t.Fatalf("the worker running at activation, pid %d, had its exchange retained %d times, want once; "+
					"without it the answer for the later worker measures nothing\n%s", existing[0], got, rendered(sealed))
			}
			captured := len(t13Asked(messages, forkedAfter[0], "t13-late")) + len(t13Asked(messages, forkedAfter[0], "t13-late-again"))
			if got := captured > 0; got != one.later {
				t.Errorf("under %s the worker forked after activation, pid %d, had %d exchanges retained, want "+
					"captured %v\n%s", one.mode, forkedAfter[0], captured, one.later, rendered(sealed))
			}
		})
	}
}

// A stop while traffic is flowing seals an account of what was in flight: how
// much was outstanding, known or with the reason it is not, and a seal that
// calls itself complete only where every in-flight quantity is accounted for.
// Stop says how the session sealed, and says it as the account does.
func TestAStopWithTrafficFlowingSealsAnAccountOfWhatWasInFlightAndSaysHowItSealed(t *testing.T) {
	binary := built(t)
	witness := t.TempDir()
	_, flood := looping(t, serving(t), "F", witness, "flood")
	c := configuring(t, target("flooding", flood))
	observer := started(t, binary, c)
	go func() {
		for observer.lines.Scan() {
		}
	}()

	roles := map[string]int32{"F": flood.PID}
	waitWitnessed(t, witness, roles, map[string]int{"F": witnessed(witness, "F", flood.PID)}, 20)
	if live := inspected(t, binary, c); live.Seen == nil || live.Seen.Transfers == 0 {
		t.Fatalf("wiring, not the property: the session saw no transfer from the flood, so a stop measures an " +
			"idle session")
	}
	before := witnessed(witness, "F", flood.PID)
	stopped, err := exec.Command(binary, "stop", c.path).CombinedOutput()
	if err != nil {
		t.Fatalf("stop with traffic flowing: %v\n%s", err, stopped)
	}
	if after := witnessed(witness, "F", flood.PID); after <= before {
		t.Fatalf("wiring, not the property: the flood completed %d exchanges before the stop and %d after it "+
			"returned, so nothing shows traffic flowing when it arrived", before, after)
	}

	sealed := t13Sealed(t, c, observer.session)
	if sealed.Seal == nil {
		t.Fatalf("the account says nothing of its seal: %s", sealed.SealError)
	}
	seal := *sealed.Seal
	t.Logf("sealed complete %v: drain delivered %+v outstanding %+v, interrupted %+v, because %v", seal.Complete,
		seal.Drain.Delivered, seal.Drain.Outstanding, seal.Interrupted, seal.Because)

	outstanding := seal.Drain.Outstanding
	switch {
	case !outstanding.Known && outstanding.Why == "":
		t.Errorf("the seal neither counts what was outstanding nor says why it cannot")
	case !outstanding.Known && seal.Complete:
		t.Errorf("the seal calls itself complete while what was outstanding is unknown: %s", outstanding.Why)
	case outstanding.Known && outstanding.Value > 0 && (seal.Complete || seal.Drain.Because == ""):
		t.Errorf("%d were outstanding at the seal, and it is complete %v with the drain saying %q", outstanding.Value,
			seal.Complete, seal.Drain.Because)
	}
	if !seal.Interrupted.Known && seal.Complete {
		t.Errorf("the seal calls itself complete while the calls interrupted in flight are unknown: %s",
			seal.Interrupted.Why)
	}
	inFlight := 0
	for _, identity := range seal.Counters.Identities() {
		if !strings.Contains(identity.Name, "outstanding") && !strings.Contains(identity.Name, "refusal at the read boundary") {
			continue
		}
		inFlight++
		if seal.Complete && (!identity.Evaluated || !identity.Holds) {
			t.Errorf("the seal calls itself complete and does not account for what was in flight: %s", identity)
		}
	}
	if inFlight != 2 {
		t.Errorf("the seal states %d identities over what was in flight, want the two over outstanding events and "+
			"calls refused at the read boundary", inFlight)
	}

	how := "sealed INCOMPLETE"
	if seal.Complete {
		how = "sealed complete"
	}
	if !strings.Contains(string(stopped), how) {
		t.Errorf("the account is %s and stop says:\n%s", how, stopped)
	}
}
