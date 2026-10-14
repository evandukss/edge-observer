//go:build attach

package attach_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
)

// liveSettled waits until the running session has written at least want
// records, or has ended; it never fails on the session ending, because ending
// is one of the outcomes the caller is measuring.
func liveSettled(t *testing.T, binary string, c configured, s *liveSession, want uint64, within time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if s.ended() {
			return
		}
		// A session can end between the check above and this question, so an
		// unanswered question is asked again rather than failed.
		stdout, _, err := liveCommand(t, 30*time.Second, binary, "inspect", c.path)
		var live account.Account
		if err == nil && json.Unmarshal([]byte(stdout), &live) == nil && liveWritten(live) >= want {
			return
		}
	}
	t.Fatalf("wiring, not the property: the session neither wrote %d records nor ended in %s:\n%s", want, within, s.transcript())
}

// The event allowance, on the running program with real traffic. With
// limits.events N, one connection is exchanged, closed, processed and written,
// refunding its input, and four unfinished request bodies keep their event
// reservations until the shared allowance refuses. What the allowance costs is
// those connections: the refusals are counted apart from capture loss, the
// account names no reason the session ended for, the session runs on, and a
// connection idle through the overload exchanges afterwards and is written. The
// credential is written nowhere.
//
// The control is the same workload under the default allowance: it refuses
// nothing and admits more than N, so N in the limited run is the limit's doing.
func TestTheAdmissionLimitCostsConnectionsAndTheSessionGoesOn(t *testing.T) {
	binary := built(t)
	const limit = 60
	const chunks = 80
	const secret = "Bearer liv-limit-secret"
	for _, limited := range []bool{true, false} {
		name := map[bool]string{true: "at the limit", false: "under the default limit"}[limited]
		t.Run(name, func(t *testing.T) {
			peer := unfinishedServing(t)
			port := peer.port
			decided := speaking(t, port)
			undecided := liveOpenConnections(t, port, 4)
			later := speaking(t, port)
			c := configuring(t, target("clients", decided.process))
			liveEdit(t, c, liveRemoving)
			if limited {
				liveEdit(t, c, liveSetting("events", limit))
			}
			s := liveStarted(t, binary, c)

			liveAsk(t, decided, "/?asked=liv-decided", "Authorization: "+secret)
			liveHangup(decided)
			before := liveUntil(t, binary, c, 10*time.Second,
				"wiring, not the property: the connection closed first was never written",
				func(a account.Account) bool { return liveWritten(a) >= 1 })
			if admitted := liveAdmitted(before); admitted <= 0 || admitted >= limit {
				t.Fatalf("wiring, not the property: %d events were admitted before the open connections began, "+
					"so the limit is not reached across them", admitted)
			}
			for n, client := range undecided {
				peer.begin(t, client, fmt.Sprintf("/?asked=liv-undecided-%d", n), "Authorization: "+secret, "X-Chunk-Size: 64")
			}
			// Four headers and eighty separately acknowledged body calls exceed
			// sixty events, while each connection has just one pending message.
			// Small chunks keep bytes below the separate shared byte allowance.
			for sent := 0; sent < chunks; sent++ {
				peer.chunk(t, undecided[sent%len(undecided)], 64)
			}
			overloaded := liveUntil(t, binary, c, 10*time.Second,
				"wiring, not the property: unfinished bodies did not reach the admission allowance",
				func(a account.Account) bool {
					if limited {
						return a.Seen != nil && a.Seen.GateRefused > 0
					}
					return liveAdmitted(a) > limit
				})
			if limited && (overloaded.Seen == nil || overloaded.Seen.GateRefused == 0) {
				t.Fatalf("wiring, not the property: %d body chunks on four unfinished requests refused nothing at an allowance of %d: %+v",
					chunks, limit, overloaded.Seen)
			}
			if s.ended() {
				t.Fatalf("the session ended at the allowance:\n%s", s.transcript())
			}

			liveAsk(t, later, "/?asked=liv-later", "Authorization: "+secret)
			liveHangup(later)
			liveUntil(t, binary, c, 20*time.Second, "the connection exchanged after the overload was never written",
				func(a account.Account) bool { return liveWritten(a) > liveWritten(overloaded) })
			sealed := s.stop(t, c)
			t.Logf("%d body chunks on unfinished requests; %d events admitted; seen %+v; stopped record %v",
				chunks, liveAdmitted(sealed), sealed.Seen, s.records("stopped"))

			targets := liveTargets(liveApproved(t, s.directory(c)))
			for _, want := range []string{"/?asked=liv-decided", "/?asked=liv-later"} {
				if !slices.Contains(targets, want) {
					t.Errorf("%s is not in the approved output: %s", want, targets)
				}
			}
			if sealed.Loss == nil || !sealed.Loss.Known || sealed.Loss.Dropped != 0 {
				t.Errorf("the kernel refused events, so the allowance cannot be told from saturation: loss %+v", sealed.Loss)
			}
			// A refused transfer supplies its number without retaining payload, so
			// it is not counted as a missing per-direction observation.
			if sealed.Seen.Lost != 0 {
				t.Errorf("the account counts %d missing per-direction observations: a refusal at the admission gate reads as capture loss",
					sealed.Seen.Lost)
			}
			if sealed.Processing == nil || sealed.Processing.GateReason != "" {
				t.Errorf("the account gives %+v as a reason the session ended; it was stopped", sealed.Processing)
			}
			if holding := liveHolding(t, c.directory, secret); len(holding) != 0 {
				t.Errorf("the credential reached %v", holding)
			}
			files := liveFiles(t, s.directory(c))
			slices.Sort(files)
			if want := []string{"account.json", "contract-account.json"}; !slices.Equal(files, want) {
				t.Errorf("the session directory holds %v, want only %v: approved output is at its stable path", files, want)
			}
			if !limited {
				if sealed.Seen.GateRefused != 0 {
					t.Errorf("the control refused %d events under the default allowance", sealed.Seen.GateRefused)
				}
				if admitted := liveAdmitted(sealed); admitted <= limit {
					t.Fatalf("wiring, not the property: the workload admits %d events under the default allowance, "+
						"not more than %d, so the limited run cannot show the limit acting", admitted, limit)
				}
			}
		})
	}
}

// The other exhaustion. The volatile intake is charged each record's metadata
// as well as its payload, so with events carrying a full payload it fills
// before the event allowance does. Four connections are kept open with
// unfinished request bodies. Each separately acknowledged TLS write fits one
// event, and both source and parser representations stay charged until the
// intake refuses records. Nothing is refused by the kernel or at the allowance.
// What that costs is those connections: the refusals are counted, the account
// names no reason the session ended for, the session runs on, and a connection
// idle through it exchanges afterwards and is written. Nothing is spilled and
// the credential is written nowhere.
func TestAFullVolatileIntakeCostsConnectionsAndTheSessionGoesOn(t *testing.T) {
	binary := built(t)
	const allowance = 8192
	peer := unfinishedServing(t)
	port := peer.port
	open := liveOpenConnections(t, port, 4)
	later := speaking(t, port)
	c := configuring(t, target("client", open[0].process))
	liveEdit(t, c, liveRemoving, liveSetting("events", allowance))
	s := liveStarted(t, binary, c)
	liveAsk(t, open[0], "/?asked=liv-intake-first", "Authorization: Bearer liv-intake-secret")
	liveUntil(t, binary, c, 10*time.Second, "wiring, not the property: nothing was captured before the load",
		func(a account.Account) bool { return a.Seen != nil && a.Seen.Records >= 2 })
	for n, client := range open {
		peer.begin(t, client, fmt.Sprintf("/?asked=liv-intake-%d", n), "Authorization: Bearer liv-intake-secret")
	}
	sent := 0
	var full account.Account
	for sent < allowance {
		peer.chunk(t, open[sent%len(open)], unfinishedChunk)
		sent++
		if sent%64 == 0 {
			if full = inspected(t, binary, c); full.Seen != nil && full.Seen.IntakeRefused > 0 {
				break
			}
		}
	}
	// The session goes on, so admissions keep growing as slots are returned; what
	// distinguishes intake exhaustion is that the event allowance refused nothing.
	if full.Seen == nil || full.Seen.IntakeRefused == 0 || full.Seen.GateRefused != 0 {
		t.Fatalf("wiring, not the property: after %d unfinished-body bytes the intake refused %+v at an allowance of %d, "+
			"so the exhaustion reached is not the intake's alone", sent*unfinishedChunk, full.Seen, allowance)
	}
	if s.ended() {
		t.Fatalf("the session ended when the volatile intake was full:\n%s", s.transcript())
	}

	liveAsk(t, later, "/?asked=liv-intake-later", "Authorization: Bearer liv-intake-secret")
	liveHangup(later)
	liveUntil(t, binary, c, 20*time.Second, "the connection exchanged after the full intake was never written",
		func(a account.Account) bool { return liveWritten(a) > liveWritten(full) })
	sealed := s.stop(t, c)
	t.Logf("%d unfinished-body bytes; %d events admitted; seen %+v; processing %+v; seal %+v; stopped record %v",
		sent*unfinishedChunk, liveAdmitted(sealed), sealed.Seen, sealed.Processing, sealed.Seal, s.records("stopped"))

	if !slices.Contains(liveTargets(liveApproved(t, s.directory(c))), "/?asked=liv-intake-later") {
		t.Errorf("the exchange after the full intake is not in the approved output")
	}
	if sealed.Loss == nil || !sealed.Loss.Known || sealed.Loss.Dropped != 0 {
		t.Errorf("the kernel refused events, so the intake's exhaustion is not the only one reached: %+v", sealed.Loss)
	}
	if sealed.Processing == nil || sealed.Processing.GateReason != "" {
		t.Errorf("the account gives %+v as a reason the session ended; it was stopped", sealed.Processing)
	}
	files := liveFiles(t, s.directory(c))
	slices.Sort(files)
	if want := []string{"account.json", "contract-account.json"}; !slices.Equal(files, want) {
		t.Errorf("the session directory holds %v, want only %v: approved output is at its stable path", files, want)
	}
	if holding := liveHolding(t, c.directory, "liv-intake-secret"); len(holding) != 0 {
		t.Errorf("the credential reached %v", holding)
	}
}
