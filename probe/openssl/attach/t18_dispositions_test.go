//go:build attach

package attach_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/probe"
)

// t18Dispositions is what one sealed session says happened to what it saw,
// under the four labels row 7 requires kept apart.
type t18Dispositions struct {
	excluded   int              // policy removals the written records carry
	processing uint64           // processing failures
	output     uint64           // output failures
	dropped    int64            // capture loss: events the kernel could not buffer
	located    int64            // observations capture found missing from the order
	reason     probe.GateReason // the capture-wide reason, which is none of the four
}

func t18Disposed(t *testing.T, sealed account.Account, written []t18Artifact) t18Dispositions {
	t.Helper()
	if sealed.Processing == nil || sealed.Loss == nil || !sealed.Loss.Known || sealed.Seen == nil {
		t.Fatalf("the sealed account cannot say what happened: processing %+v, loss %+v, seen %+v",
			sealed.Processing, sealed.Loss, sealed.Seen)
	}
	return t18Dispositions{
		excluded: t18Excluded(written, "authorization"), processing: sealed.Processing.ProcessingFailures,
		output: sealed.Processing.OutputFailures, dropped: sealed.Loss.Dropped, located: sealed.Seen.Lost,
		reason: sealed.Processing.GateReason,
	}
}

// Row 7, three of the four on the running program with real traffic, each
// injected on its own and read from the account the session sealed and the
// records it wrote. The fourth, output failure, is the approved-output bound
// (TestT18TheApprovedOutputBoundRefusesALoadedRunBesideABelowLimitSuccess),
// which reads the same labels.
//
//	policy suppression   the configured removal of the authorization header
//	processing failure   an answer in a content encoding processing refuses to
//	                     decide, carrying the same header
//	capture loss         the observer stopped by a signal while the client reads
//	                     past the ring's capacity, then resumed
//
// Each moves its own label and no other, except that a stream damaged by loss
// is also refused by processing; what that case establishes is that refusing
// the damaged record leaves the loss reported.
func TestT18TheSealedAccountTellsTheDispositionsApart(t *testing.T) {
	binary := built(t)
	port := t18Serving(t)
	const secret = "Bearer t18-disposition-secret"
	t.Run("policy suppression", func(t *testing.T) {
		client := speaking(t, port)
		c := configuring(t, target("client", client.process))
		t18Edit(t, c, t18Removing)
		s := t18Started(t, binary, c)
		t18Ask(t, client, "/?asked=t18-suppressed", "Authorization: "+secret)
		t18Hangup(client)
		t18Settled(t, binary, c, s, 2, 10*time.Second)
		sealed := s.stop(t, c)
		written := t18Approved(t, s.directory(c))
		if !slices.Contains(t18Targets(written), "/?asked=t18-suppressed") {
			t.Fatalf("wiring, not the property: the exchange was not written: %v", t18Targets(written))
		}
		got := t18Disposed(t, sealed, written)
		if got.excluded == 0 || got.processing != 0 || got.output != 0 || got.dropped != 0 || got.located != 0 || got.reason != "" {
			t.Errorf("policy suppression alone reads %+v", got)
		}
		if sealed.Seal == nil || !sealed.Seal.Complete {
			t.Errorf("the session sealed %+v", sealed.Seal)
		}
		if holding := t18Holding(t, c.directory, secret); len(holding) != 0 {
			t.Errorf("the credential reached %v", holding)
		}
	})
	t.Run("processing failure", func(t *testing.T) {
		client := speaking(t, port)
		c := configuring(t, target("client", client.process))
		t18Edit(t, c, t18Removing)
		s := t18Started(t, binary, c)
		t18Ask(t, client, "/gzip?asked=t18-undecodable", "Authorization: "+secret)
		t18Hangup(client)
		t18Settled(t, binary, c, s, 1, 10*time.Second)
		sealed := s.stop(t, c)
		written := t18Approved(t, s.directory(c))
		if len(written) == 0 {
			t.Fatalf("wiring, not the property: the session wrote not even the connection's record, so nothing was processed")
		}
		if targets := t18Targets(written); len(targets) != 0 {
			t.Errorf("the undecodable exchange was written: %v", targets)
		}
		got := t18Disposed(t, sealed, written)
		if got.processing == 0 || got.excluded != 0 || got.output != 0 || got.dropped != 0 || got.located != 0 || got.reason != "" {
			t.Errorf("a processing failure alone reads %+v", got)
		}
		if holding := t18Holding(t, c.directory, secret); len(holding) != 0 {
			t.Errorf("the credential reached %v", holding)
		}
	})
	t.Run("capture loss", func(t *testing.T) {
		client := speaking(t, port)
		c := configuring(t, target("client", client.process))
		t18Edit(t, c, t18Removing)
		s := t18Started(t, binary, c)
		t18Ask(t, client, "/?asked=t18-before-the-loss", "Authorization: "+secret)
		t18Until(t, binary, c, 10*time.Second, "wiring, not the property: nothing was captured before the loss",
			func(a account.Account) bool { return a.Seen != nil && a.Seen.Records >= 2 })
		if err := syscall.Kill(s.pid(), syscall.SIGSTOP); err != nil {
			t.Fatalf("stop the observer's process: %v", err)
		}
		// Each answer is a mebibyte read in calls the ring holds up to 4096 bytes
		// of; 120 of them are over seven times its 16 MiB.
		for i := range 120 {
			if _, err := t18Exchange(client, fmt.Sprintf("/mega?asked=t18-flood-%d", i)); err != nil {
				_ = syscall.Kill(s.pid(), syscall.SIGCONT)
				t.Fatal(err)
			}
		}
		if err := syscall.Kill(s.pid(), syscall.SIGCONT); err != nil {
			t.Fatalf("resume the observer's process: %v", err)
		}
		sealed := s.stop(t, c)
		written := t18Approved(t, s.directory(c))
		got := t18Disposed(t, sealed, written)
		// Capture's own ordering is the witness that events went missing; the
		// kernel's count of what it could not buffer is the capture loss the
		// account must still report while the damaged stream is refused.
		if got.located == 0 {
			t.Fatalf("wiring, not the property: capture found nothing missing while the observer was stopped (%+v)", got)
		}
		if got.dropped == 0 {
			t.Errorf("capture found %d observations missing and the account reports no capture loss: %+v", got.located, got)
		}
		if got.output != 0 || got.reason != "" {
			t.Errorf("capture loss reads %+v", got)
		}
		if slices.ContainsFunc(t18Targets(written), func(one string) bool { return strings.HasPrefix(one, "/mega") }) {
			t.Errorf("an exchange from the damaged stream was written: %v", t18Targets(written))
		}
		t.Logf("capture loss: %+v, seen %+v", got, sealed.Seen)
	})
}

// Row 7's abrupt death, on the running program. A session that has written an
// approved record is killed outright, or killed by the kernel when its envelope
// is made too small for what it then holds; neither leaves an account, the
// public command refuses to read the directory as a finished session, and the
// record of the last sealed session does not name it. The control is the same
// session stopped, which seals complete and reads.
func TestT18ASessionThatDiesLeavesNoCompleteAccount(t *testing.T) {
	binary := built(t)
	port := t18Serving(t)
	for _, death := range []string{"stopped", "killed after an approved write", "killed by memory pressure"} {
		t.Run(death, func(t *testing.T) {
			approved := speaking(t, port)
			flooding := speaking(t, port)
			c := configuring(t, target("clients", approved.process))
			t18Edit(t, c, t18Removing)
			s := t18Started(t, binary, c)
			t18Ask(t, approved, "/?asked=t18-approved", "Authorization: Bearer t18-death-secret")
			t18Hangup(approved)
			t18Settled(t, binary, c, s, 1, 10*time.Second)
			if s.ended() {
				t.Fatalf("wiring: the session ended by itself:\n%s", s.transcript())
			}

			switch death {
			case "stopped":
				sealed := s.stop(t, c)
				if sealed.Seal == nil || !sealed.Seal.Complete {
					t.Fatalf("wiring, not the property: the stopped control did not seal complete: %+v", sealed.Seal)
				}
				if _, stderr, err := t18Command(t, 30*time.Second, binary, "inspect", s.directory(c), "--text"); err != nil {
					t.Fatalf("the stopped control does not read: %v\n%s", err, stderr)
				}
				return
			case "killed after an approved write":
				if err := syscall.Kill(s.pid(), syscall.SIGKILL); err != nil {
					t.Fatalf("kill the observer: %v", err)
				}
				s.awaited(t, 30*time.Second)
			case "killed by memory pressure":
				envelope := t18CgroupOf(t, int32(s.pid()))
				content, err := os.ReadFile(filepath.Join(envelope, "memory.current"))
				if err != nil {
					t.Fatalf("read the envelope's use: %v", err)
				}
				current, err := strconv.ParseInt(strings.TrimSpace(string(content)), 10, 64)
				if err != nil {
					t.Fatalf("the envelope's use reads %q", content)
				}
				killed := t18Event(t, envelope, "oom_kill")
				limit := strconv.FormatInt(current+8<<20, 10)
				if err := os.WriteFile(filepath.Join(envelope, "memory.max"), []byte(limit), 0o644); err != nil {
					t.Fatalf("lower the envelope to %s: %v", limit, err)
				}
				for i := 0; i < 400 && !s.ended(); i++ {
					if _, err := t18Exchange(flooding, fmt.Sprintf("/mega?asked=t18-pressure-%d", i)); err != nil {
						t.Fatal(err)
					}
				}
				s.awaited(t, 30*time.Second)
				if after := t18Event(t, envelope, "oom_kill"); after <= killed {
					t.Fatalf("wiring, not the property: the session ended and the envelope records no OOM kill (%d, before %d):\n%s",
						after, killed, s.transcript())
				}
				t.Logf("envelope %s lowered from %d in use to %s", envelope, current, limit)
			}

			if s.state == nil {
				t.Fatalf("the session's end was not recorded")
			}
			if status, ok := s.state.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Errorf("the session ended %v, not by SIGKILL", s.state)
			}
			if !slices.Contains(t18Targets(t18Approved(t, s.directory(c))), "/?asked=t18-approved") {
				t.Fatalf("wiring, not the property: no approved record was written before the death")
			}
			if _, err := os.Stat(filepath.Join(s.directory(c), "account.json")); !os.IsNotExist(err) {
				t.Errorf("a session that died left an account (%v)", err)
			}
			for _, text := range [][]string{{"inspect", s.directory(c)}, {"inspect", s.directory(c), "--text"}} {
				stdout, stderr, err := t18Command(t, 30*time.Second, binary, text...)
				if err == nil || !strings.Contains(stderr, "never sealed") {
					t.Errorf("observer %v over the dead session answered %v:\n%s%s", text, err, stdout, stderr)
				}
			}
			if last, err := os.ReadFile(filepath.Join(c.directory, "last-sealed.json")); err == nil && strings.Contains(string(last), s.session) {
				t.Errorf("the last sealed session names the one that died: %s", last)
			}
		})
	}
}
