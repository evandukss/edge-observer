//go:build attach

package attach_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/probe"
)

// t18Settled waits until the running session has written at least want
// records, or has ended; it never fails on the session ending, because ending
// is one of the outcomes the caller is measuring.
func t18Settled(t *testing.T, binary string, c configured, s *t18Session, want uint64, within time.Duration) {
	t.Helper()
	for deadline := time.Now().Add(within); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if s.ended() {
			return
		}
		// A session can end between the check above and this question, so an
		// unanswered question is asked again rather than failed.
		stdout, _, err := t18Command(t, 30*time.Second, binary, "inspect", c.path)
		var live account.Account
		if err == nil && json.Unmarshal([]byte(stdout), &live) == nil && t18Written(live) >= want {
			return
		}
	}
	t.Fatalf("wiring, not the property: the session neither wrote %d records nor ended in %s:\n%s", want, within, s.transcript())
}

// t18Rendered is the sealed session as the public command prints it.
func t18Rendered(t *testing.T, binary, directory string) string {
	t.Helper()
	stdout, stderr, err := t18Command(t, 30*time.Second, binary, "inspect", directory, "--text")
	if err != nil {
		t.Fatalf("inspect %s: %v\n%s", directory, err, stderr)
	}
	return stdout
}

// Rows 4, 10 and 17, the event allowance, on the running program with real
// traffic. With limits.events N, one connection is exchanged, closed,
// processed and written, refunding its input, and four connections are kept
// open and exchanged on in turn. Each stays below the per-connection cut.
// The account must name the shared input limit, admit at least N further
// events, and leave the undecided connections' payload
// nowhere, and show the channel drained freely, so the limit cannot be
// saturation under another name.
//
// The control is the same workload under the default allowance: it runs until
// stopped, admits more than N - so N in the limited run is the limit's doing -
// and writes the second connection's exchanges, so their absence under the
// limit is not an exchange that could never have been written.
func TestT18TheAdmissionLimitEndsTheSessionUnderItsReasonAndKeepsOnlyWhatWasDecided(t *testing.T) {
	binary := built(t)
	const limit = 60
	const exchanges = 40
	const secret = "Bearer t18-limit-secret"
	for _, limited := range []bool{true, false} {
		name := map[bool]string{true: "at the limit", false: "under the default limit"}[limited]
		t.Run(name, func(t *testing.T) {
			port := t18Serving(t)
			decided := speaking(t, port)
			undecided := t18OpenConnections(t, port, 4)
			c := configuring(t, target("clients", decided.process))
			t18Edit(t, c, t18Removing)
			if limited {
				t18Edit(t, c, t18Setting("events", limit))
			}
			s := t18Started(t, binary, c)

			t18Ask(t, decided, "/?asked=t18-decided", "Authorization: "+secret)
			t18Hangup(decided)
			before := t18Until(t, binary, c, 10*time.Second,
				"wiring, not the property: the connection closed first was never written",
				func(a account.Account) bool { return t18Written(a) >= 1 })
			if admitted := t18Admitted(before); admitted <= 0 || admitted >= limit {
				t.Fatalf("wiring, not the property: %d events were admitted before the open connection began, "+
					"so the limit is not reached across both connections", admitted)
			}

			asked := 0
			for ; asked < exchanges && (!limited || !s.ended()); asked++ {
				t18Ask(t, undecided[asked%len(undecided)], fmt.Sprintf("/?asked=t18-undecided-%d", asked), "Authorization: "+secret)
			}
			var sealed account.Account
			if limited {
				s.awaited(t, 30*time.Second)
				if s.err != nil {
					t.Fatalf("the session that ended at the limit exited %v:\n%s", s.err, s.transcript())
				}
				sealed = t18Sealed(t, s.directory(c), s.session)
			} else {
				sealed = s.stop(t, c)
			}
			t.Logf("%d exchanges on the open connection; %d events admitted; stopped record %v",
				asked, t18Admitted(sealed), s.records("stopped"))

			written := t18Approved(t, s.directory(c))
			targets := t18Targets(written)
			if !slices.Contains(targets, "/?asked=t18-decided") {
				t.Fatalf("wiring, not the property: the connection decided before the limit is not in the approved output: %s", targets)
			}
			if sealed.Loss == nil || !sealed.Loss.Known || sealed.Loss.Dropped != 0 {
				t.Errorf("the kernel refused events, so the limit cannot be told from saturation: loss %+v", sealed.Loss)
			}
			// A refused transfer supplies its number without retaining payload.
			// It must not count as a missing per-direction observation. The
			// control, with no refusal, also counts none.
			if sealed.Seen.Lost != 0 {
				t.Errorf("the account counts %d missing per-direction observations where the ring dropped %d: a refusal at the admission gate reads as capture loss",
					sealed.Seen.Lost, sealed.Loss.Dropped)
			}
			if holding := t18Holding(t, c.directory, secret); len(holding) != 0 {
				t.Errorf("the credential reached %v", holding)
			}

			if !limited {
				if sealed.Processing == nil || sealed.Processing.GateReason != "" {
					t.Errorf("the control's gate says %+v, want no reason", sealed.Processing)
				}
				if admitted := t18Admitted(sealed); admitted <= limit {
					t.Fatalf("wiring, not the property: the workload admits %d events under the default allowance, "+
						"not more than %d, so the limited run cannot show the limit acting", admitted, limit)
				}
				if !slices.Contains(targets, "/?asked=t18-undecided-0") {
					t.Errorf("the control did not write the open connection's exchanges, so their absence under the limit "+
						"measures nothing: %s", targets)
				}
				return
			}

			if sealed.Processing == nil || sealed.Processing.ConnectionsCut != 0 {
				t.Fatalf("wiring, not the property: a per-connection cut confounded the shared bound: %+v", sealed.Processing)
			}
			if s.signaled {
				t.Fatal("wiring: the limited session was signalled")
			}
			if sealed.Processing == nil || sealed.Processing.GateReason != probe.GateInputLimit {
				t.Errorf("the account gives %+v as the reason, want %s", sealed.Processing, probe.GateInputLimit)
			}
			if admitted := t18Admitted(sealed) - t18Admitted(before); admitted < limit {
				t.Errorf("%d further events were admitted, fewer than the held allowance %d: seen %+v", admitted, limit, sealed.Seen)
			}
			if slices.ContainsFunc(targets, func(one string) bool { return strings.HasPrefix(one, "/?asked=t18-undecided-") }) {
				t.Errorf("exchanges undecided when the limit was reached were written: %s", targets)
			}
			if holding := t18Holding(t, c.directory, "t18-undecided"); len(holding) != 0 {
				t.Errorf("undecided payload reached %v", holding)
			}
			files := t18Files(t, s.directory(c))
			slices.Sort(files)
			if want := []string{"account.json", "contract-account.json"}; !slices.Equal(files, want) {
				t.Errorf("the session directory holds %v, want only %v: approved output is at its stable path", files, want)
			}
			if text := t18Rendered(t, binary, s.directory(c)); !strings.Contains(text, "release    refused: "+string(probe.GateInputLimit)) {
				t.Errorf("the public command does not state the reason:\n%s", text)
			}
		})
	}
}

// Rows 4 and 17, the other exhaustion. The volatile intake is charged each
// record's metadata as well as its payload, so with events carrying a full
// payload it fills before the event allowance does. Four connections are kept
// open and read in calls larger than an event carries, so nothing is
// released and no individual connection reaches its cut. What must be reached is the
// intake's refusal - records refused while fewer events than the allowance
// were admitted, with nothing refused by the kernel - and the account must say
// why the session ended: a gate reason, or a seal that is not complete and
// says why. Nothing is spilled and the credential is written nowhere.
func TestT18AFullVolatileIntakeEndsTheSessionUnderAStatedReason(t *testing.T) {
	binary := built(t)
	const allowance = 8192
	open := t18OpenConnections(t, t18Serving(t), 4)
	c := configuring(t, target("client", open[0].process))
	t18Edit(t, c, t18Removing, t18Setting("events", allowance))
	s := t18Started(t, binary, c)
	t18Ask(t, open[0], "/?asked=t18-intake-first", "Authorization: Bearer t18-intake-secret")
	t18Until(t, binary, c, 10*time.Second, "wiring, not the property: nothing was captured before the load",
		func(a account.Account) bool { return a.Seen != nil && a.Seen.Records >= 2 })
	asked := 0
	for ; asked < 400 && !s.ended(); asked++ {
		t18Ask(t, open[asked%len(open)], fmt.Sprintf("/mega?asked=t18-intake-%d", asked))
	}
	s.awaited(t, 30*time.Second)
	if s.signaled || s.err != nil {
		t.Fatalf("the session did not end by itself cleanly: signalled %v, %v:\n%s", s.signaled, s.err, s.transcript())
	}
	sealed := t18Sealed(t, s.directory(c), s.session)
	t.Logf("%d answers of a mebibyte; %d events admitted; seen %+v; processing %+v; seal %+v; stopped record %v",
		asked, t18Admitted(sealed), sealed.Seen, sealed.Processing, sealed.Seal, s.records("stopped"))

	if sealed.Processing == nil || sealed.Processing.ConnectionsCut != 0 {
		t.Fatalf("wiring, not the property: connection cutting confounded intake exhaustion: %+v", sealed.Processing)
	}
	if sealed.Seen.Rejected == 0 || t18Admitted(sealed) >= allowance {
		t.Fatalf("wiring, not the property: %d records refused by the intake with %d of %d events admitted, so the "+
			"exhaustion reached is not the intake's", sealed.Seen.Rejected, t18Admitted(sealed), allowance)
	}
	if sealed.Loss == nil || !sealed.Loss.Known || sealed.Loss.Dropped != 0 {
		t.Errorf("the kernel refused events, so the intake's exhaustion is not the only one reached: %+v", sealed.Loss)
	}
	because := []string{}
	if sealed.Seal != nil {
		because = sealed.Seal.Because
	}
	stated := (sealed.Processing != nil && sealed.Processing.GateReason != "") ||
		(sealed.Seal != nil && !sealed.Seal.Complete && len(because) != 0)
	if !stated {
		t.Errorf("FINDING: the session ended when the volatile intake refused %d records, and its account states no "+
			"reason: gate %+v, seal complete %v because %q", sealed.Seen.Rejected, sealed.Processing,
			sealed.Seal != nil && sealed.Seal.Complete, because)
	}
	files := t18Files(t, s.directory(c))
	slices.Sort(files)
	if want := []string{"account.json", "contract-account.json"}; !slices.Equal(files, want) {
		t.Errorf("the session directory holds %v, want only %v: approved output is at its stable path", files, want)
	}
	if holding := t18Holding(t, c.directory, "t18-intake-secret"); len(holding) != 0 {
		t.Errorf("the credential reached %v", holding)
	}
}
