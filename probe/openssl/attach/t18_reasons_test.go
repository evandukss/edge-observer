//go:build attach

package attach_test

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/probe"
)

// t18Reason is how one capture-invalidating reason is witnessed: a live
// session that ends under it, or a declared reason it cannot be produced live
// and the test in this package that covers it instead.
type t18Reason struct {
	scenario  func(t *testing.T, binary string) account.Account
	exception string
	covers    string
}

// t18Reasons is keyed by the reason's string, not its constant, so an entry
// can exist for a reason this tree does not declare yet.
var t18Reasons = map[string]t18Reason{
	"input_limit":       {scenario: t18InputLimit},
	"unknown_length":    {scenario: t18UnknownLength},
	"storage_exhausted": {scenario: t18StorageExhausted},
	"intake_exhausted":  {scenario: t18IntakeExhausted},
	"unknown_kind": {
		exception: "the program emits only kind 1, a transfer, and kind 2, a close (bpf/ssl.bpf.h obs_emit), and " +
			"decoding keeps the kind byte as the program wrote it (ebpf/ebpf.go decode), so only a modified " +
			"program object produces another kind",
		covers: "TestDeliveryGateEntryClassifiesUncertaintyBeforeEitherSink",
	},
}

// t18EndedByItself runs drive against a session started over c and returns
// the account the session sealed when it ended without being signalled.
func t18EndedByItself(t *testing.T, binary string, c configured, drive func(s *t18Session)) account.Account {
	t.Helper()
	s := t18Started(t, binary, c)
	drive(s)
	s.awaited(t, 30*time.Second)
	if s.signaled || s.err != nil {
		t.Fatalf("the session did not end by itself cleanly: signalled %v, %v:\n%s", s.signaled, s.err, s.transcript())
	}
	return t18Sealed(t, s.directory(c), s.session)
}

func t18InputLimit(t *testing.T, binary string) account.Account {
	client := speaking(t, t18Serving(t))
	c := configuring(t, target("client", client.process))
	t18Edit(t, c, t18Removing, t18Setting("events", 30))
	return t18EndedByItself(t, binary, c, func(s *t18Session) {
		for i := 0; i < 40 && !s.ended(); i++ {
			t18Ask(t, client, fmt.Sprintf("/?asked=t18-reason-limit-%d", i))
		}
	})
}

func t18UnknownLength(t *testing.T, binary string) account.Account {
	reader := t18Reading(t, t18Serving(t))
	c := configuring(t, target("reader", reader.process))
	t18Edit(t, c, t18Removing)
	return t18EndedByItself(t, binary, c, func(s *t18Session) {
		if answer := reader.say(t, "G /?asked=t18-reason-length"); answer != "done 200" {
			t.Fatalf("wiring, not the property: the reader's exchange answered %q", answer)
		}
		if answer := reader.say(t, "W"); answer != "would-block 0 2" {
			t.Fatalf("wiring, not the property: the out-parameter read answered %q", answer)
		}
	})
}

// t18StorageExhausted is a loaded run: forty 3000-byte answers per closed
// connection, one approved record per connection and route, against the 1 MiB
// bound configuring writes, until a record does not fit.
func t18StorageExhausted(t *testing.T, binary string) account.Account {
	port := t18Serving(t)
	clients := make([]conversation, 8)
	for i := range clients {
		clients[i] = speaking(t, port)
	}
	c := configuring(t, target("clients", clients[0].process))
	t18Edit(t, c, t18Removing)
	return t18EndedByItself(t, binary, c, func(s *t18Session) {
		for i, client := range clients {
			if s.ended() {
				return
			}
			for j := range 40 {
				t18Ask(t, client, fmt.Sprintf("/blob?asked=t18-reason-storage-%d-%d", i, j))
			}
			t18Hangup(client)
			t18Settled(t, binary, c, s, uint64(2*(i+1)), 20*time.Second)
		}
	})
}

// t18IntakeExhausted keeps one connection open and reads answers larger than
// an event carries, so every event holds a full payload in the volatile intake
// until it fills before the event allowance does.
func t18IntakeExhausted(t *testing.T, binary string) account.Account {
	client := speaking(t, t18Serving(t))
	c := configuring(t, target("client", client.process))
	t18Edit(t, c, t18Removing, t18Setting("events", 8192))
	return t18EndedByItself(t, binary, c, func(s *t18Session) {
		for i := 0; i < 400 && !s.ended(); i++ {
			t18Ask(t, client, fmt.Sprintf("/mega?asked=t18-reason-intake-%d", i))
		}
	})
}

// t18Declared counts the test functions of this name the package's source
// declares, read from the directory the test runs in.
func t18Declared(t *testing.T, name string) int {
	t.Helper()
	files, err := filepath.Glob("*_test.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("wiring, not the property: no test source found beside the test (%v)", err)
	}
	found := 0
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		found += strings.Count(string(content), "\nfunc "+name+"(t *testing.T) {")
	}
	return found
}

// Row 17, over the population the type declares. Every gate reason the type
// classifies as invalidating capture is either produced in a live session,
// whose sealed account must give exactly that reason, or declared as not
// producible live with why and the test covering it, which must exist. A
// reason with neither fails. The population comes from the type, so a reason
// added later joins it without anybody remembering to add it here.
func TestT18EveryCaptureInvalidatingReasonIsWitnessedInALiveAccount(t *testing.T) {
	yielded := map[string]bool{}
	for _, reason := range probe.GateReasons() {
		if reason.InvalidatesCapture() {
			yielded[string(reason)] = true
		}
	}
	if len(yielded) == 0 {
		t.Fatal("wiring, not the property: the type yields no capture-invalidating reason")
	}
	for _, name := range slices.Sorted(maps.Keys(t18Reasons)) {
		if !yielded[name] {
			t.Logf("scenario for %s: the type does not yield it here", name)
		}
	}
	if own := t18Declared(t, "TestT18EveryCaptureInvalidatingReasonIsWitnessedInALiveAccount"); own != 1 {
		t.Fatalf("wiring, not the property: the search for declared tests finds this one %d times", own)
	}
	binary := built(t)
	for _, reason := range slices.Sorted(maps.Keys(yielded)) {
		t.Run(reason, func(t *testing.T) {
			entry, found := t18Reasons[reason]
			switch {
			case !found:
				t.Fatalf("%s invalidates capture and has neither a live scenario nor a declared exception", reason)
			case entry.exception != "":
				if declared := t18Declared(t, entry.covers); declared != 1 {
					t.Fatalf("the exception for %s names %s, which this package declares %d times", reason, entry.covers, declared)
				}
				t.Logf("%s is not produced live: %s. Covered by %s", reason, entry.exception, entry.covers)
			default:
				sealed := entry.scenario(t, binary)
				if sealed.Processing == nil || string(sealed.Processing.GateReason) != reason {
					t.Errorf("the session ended with its account giving %+v, want the reason %s", sealed.Processing, reason)
				}
			}
		})
	}
}
