//go:build attach

package attach_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
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
// processed and written - released from volatile intake - and a second is
// kept open and exchanged on until the session ends by itself. The account
// must name the limit as the reason and nothing else, admit exactly N events
// counted across both connections, leave the undecided connection's payload
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
			undecided := speaking(t, port)
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
				t18Ask(t, undecided, fmt.Sprintf("/?asked=t18-undecided-%d", asked), "Authorization: "+secret)
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
			// The one event the gate refused never reaches capture, which sees a
			// gap in the production order and counts it as an observation a
			// located loss accounts for. The control, with no refusal, counts none.
			if sealed.Seen.Lost != 0 {
				t.Errorf("FINDING: the account counts %d observations as accounted for by located losses and %d streams "+
					"retired by them, where the ring dropped %d: a refusal at the admission gate reads as capture loss",
					sealed.Seen.Lost, sealed.Seen.Interrupted, sealed.Loss.Dropped)
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

			if s.signaled {
				t.Fatal("wiring: the limited session was signalled")
			}
			if sealed.Processing == nil || sealed.Processing.GateReason != probe.GateInputLimit {
				t.Errorf("the account gives %+v as the reason, want %s", sealed.Processing, probe.GateInputLimit)
			}
			if admitted := t18Admitted(sealed); admitted != limit {
				t.Errorf("%d events were admitted, want exactly the allowance %d: seen %+v", admitted, limit, sealed.Seen)
			}
			if sealed.Processing != nil && len(sealed.Processing.StoppedPipelines) != 0 {
				t.Errorf("the limit is reported as a pipeline stop: %v", sealed.Processing.StoppedPipelines)
			}
			if slices.ContainsFunc(targets, func(one string) bool { return strings.HasPrefix(one, "/?asked=t18-undecided-") }) {
				t.Errorf("exchanges undecided when the limit was reached were written: %s", targets)
			}
			if holding := t18Holding(t, c.directory, "t18-undecided"); len(holding) != 0 {
				t.Errorf("undecided payload reached %v", holding)
			}
			files := t18Files(t, s.directory(c))
			slices.Sort(files)
			if want := []string{"account.json", processing.ArtifactName, "contract-account.json"}; !slices.Equal(files, want) {
				t.Errorf("the session directory holds %v, want only %v", files, want)
			}
			if text := t18Rendered(t, binary, s.directory(c)); !strings.Contains(text, "release    refused: "+string(probe.GateInputLimit)) {
				t.Errorf("the public command does not state the reason:\n%s", text)
			}
		})
	}
}

// Rows 7, 10 and 17, the approved-output bound, on a loaded run of the running
// program. Each connection is forty 3000-byte answers, closed, then written as
// one record per route; limits.output_mib is 1 as configuring writes
// it. Two connections fit. Eight do not: the first record that does not fit is
// refused whole, nothing of that connection is written, the records before it
// stay whole, and the session ends by itself with an output failure and the
// storage reason - not a processing failure, not capture loss, and not the
// policy's own removal, which the written records carry beside it.
func TestT18TheApprovedOutputBoundRefusesALoadedRunBesideABelowLimitSuccess(t *testing.T) {
	binary := built(t)
	const perConnection = 40
	const secret = "Bearer t18-bound-secret"
	for _, connections := range []int{2, 8} {
		over := connections == 8
		name := map[bool]string{false: "below the bound", true: "over the bound"}[over]
		t.Run(name, func(t *testing.T) {
			port := t18Serving(t)
			clients := make([]conversation, connections)
			for i := range clients {
				clients[i] = speaking(t, port)
			}
			c := configuring(t, target("clients", clients[0].process))
			t18Edit(t, c, t18Removing)
			s := t18Started(t, binary, c)

			for i, client := range clients {
				if s.ended() {
					break
				}
				for j := range perConnection {
					t18Ask(t, client, fmt.Sprintf("/blob?asked=t18-c%d-%d", i, j), "Authorization: "+secret)
				}
				t18Hangup(client)
				t18Settled(t, binary, c, s, uint64(2*(i+1)), 20*time.Second)
			}
			var sealed account.Account
			if over {
				s.awaited(t, 30*time.Second)
				if s.err != nil {
					t.Fatalf("the session that reached the bound exited %v:\n%s", s.err, s.transcript())
				}
				sealed = t18Sealed(t, s.directory(c), s.session)
			} else {
				sealed = s.stop(t, c)
			}
			t.Logf("%d events admitted; processing %+v; seal %+v; stopped record %v",
				t18Admitted(sealed), sealed.Processing, sealed.Seal, s.records("stopped"))

			info, err := os.Stat(filepath.Join(s.directory(c), processing.ArtifactName))
			if err != nil || info.Size() > 1<<20 {
				t.Errorf("the approved output is %v bytes (%v), over the 1 MiB bound", info.Size(), err)
			}
			written := t18Approved(t, s.directory(c))
			if sealed.Processing == nil || uint64(len(written)) != sealed.Processing.Written {
				t.Errorf("the approved output holds %d whole records and the account says %+v", len(written), sealed.Processing)
			}
			targets := t18Targets(written)
			refused := -1
			for i := range connections {
				whole := slices.Contains(targets, fmt.Sprintf("/blob?asked=t18-c%d-0", i))
				last := slices.Contains(targets, fmt.Sprintf("/blob?asked=t18-c%d-%d", i, perConnection-1))
				switch {
				case whole && last && refused < 0:
				case !whole && !last:
					if refused < 0 {
						refused = i
					}
				default:
					t.Errorf("connection %d is written in part, or after a refusal (first-exchange %v, last %v, refused from %d)",
						i, whole, last, refused)
				}
			}
			if t18Excluded(written, "authorization") == 0 {
				t.Errorf("the written records carry no policy removal, so the output failure is not shown beside it")
			}
			if holding := t18Holding(t, c.directory, secret); len(holding) != 0 {
				t.Errorf("the credential reached %v", holding)
			}
			if sealed.Loss == nil || !sealed.Loss.Known || sealed.Loss.Dropped != 0 || sealed.Seen.Lost != 0 {
				t.Errorf("capture lost events, so the output failure is not shown apart from capture loss: %+v, lost %d",
					sealed.Loss, sealed.Seen.Lost)
			}
			if sealed.Processing != nil && sealed.Processing.ProcessingFailures != 0 {
				t.Errorf("%d processing failures, where every exchange was decidable", sealed.Processing.ProcessingFailures)
			}

			if !over {
				if refused >= 0 || sealed.Processing.OutputFailures != 0 || sealed.Processing.GateReason != "" ||
					sealed.Seal == nil || !sealed.Seal.Complete {
					t.Fatalf("below the bound: connection %d refused, processing %+v, seal %+v", refused, sealed.Processing, sealed.Seal)
				}
				return
			}
			if refused < 1 {
				t.Fatalf("wiring, not the property: the refusal fell at connection %d, so no record written before it "+
					"shows the bound keeps what fitted: %s", refused, targets)
			}
			if s.signaled {
				t.Fatal("wiring: the session over the bound was signalled")
			}
			if sealed.Processing.OutputFailures == 0 || sealed.Processing.GateReason != probe.GateStorageExhausted {
				t.Errorf("over the bound the account says %+v, want an output failure and %s",
					sealed.Processing, probe.GateStorageExhausted)
			}
			because := ""
			if sealed.Seal != nil {
				because = strings.Join(sealed.Seal.Because, "; ")
			}
			if sealed.Seal == nil || sealed.Seal.Complete || !strings.Contains(because, "processing did not finish") {
				t.Errorf("the seal over the bound reads complete=%v because %q", sealed.Seal != nil && sealed.Seal.Complete, because)
			}
			if text := t18Rendered(t, binary, s.directory(c)); !strings.Contains(text, "release    refused: "+string(probe.GateStorageExhausted)) {
				t.Errorf("the public command does not state the reason:\n%s", text)
			}
		})
	}
}

// Rows 4 and 17, the other exhaustion. The volatile intake is charged each
// record's metadata as well as its payload, so with events carrying a full
// payload it fills before the event allowance does. One connection is kept
// open and read in calls larger than an event carries, so nothing is
// released, until the session ends by itself. What must be reached is the
// intake's refusal - records refused while fewer events than the allowance
// were admitted, with nothing refused by the kernel - and the account must say
// why the session ended: a gate reason, or a seal that is not complete and
// says why. Nothing is spilled and the credential is written nowhere.
func TestT18AFullVolatileIntakeEndsTheSessionUnderAStatedReason(t *testing.T) {
	binary := built(t)
	const allowance = 8192
	client := speaking(t, t18Serving(t))
	c := configuring(t, target("client", client.process))
	t18Edit(t, c, t18Removing, t18Setting("events", allowance))
	s := t18Started(t, binary, c)
	t18Ask(t, client, "/?asked=t18-intake-first", "Authorization: Bearer t18-intake-secret")
	t18Until(t, binary, c, 10*time.Second, "wiring, not the property: nothing was captured before the load",
		func(a account.Account) bool { return a.Seen != nil && a.Seen.Records >= 2 })
	asked := 0
	for ; asked < 400 && !s.ended(); asked++ {
		t18Ask(t, client, fmt.Sprintf("/mega?asked=t18-intake-%d", asked))
	}
	s.awaited(t, 30*time.Second)
	if s.signaled || s.err != nil {
		t.Fatalf("the session did not end by itself cleanly: signalled %v, %v:\n%s", s.signaled, s.err, s.transcript())
	}
	sealed := t18Sealed(t, s.directory(c), s.session)
	t.Logf("%d answers of a mebibyte; %d events admitted; seen %+v; processing %+v; seal %+v; stopped record %v",
		asked, t18Admitted(sealed), sealed.Seen, sealed.Processing, sealed.Seal, s.records("stopped"))

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
	if sealed.Processing != nil && len(sealed.Processing.StoppedPipelines) != 0 {
		t.Errorf("the intake's exhaustion is reported as a pipeline stop: %v", sealed.Processing.StoppedPipelines)
	}
	files := t18Files(t, s.directory(c))
	slices.Sort(files)
	if want := []string{"account.json", processing.ArtifactName, "contract-account.json"}; !slices.Equal(files, want) {
		t.Errorf("the session directory holds %v, want only %v", files, want)
	}
	if holding := t18Holding(t, c.directory, "t18-intake-secret"); len(holding) != 0 {
		t.Errorf("the credential reached %v", holding)
	}
}
