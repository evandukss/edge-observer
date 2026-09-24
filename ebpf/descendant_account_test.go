//go:build attach

package ebpf_test

import (
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl"
	"github.com/evandukss/edge-observer/probe/openssl/attach"
	"github.com/evandukss/edge-observer/process"
)

// A false descendant answer under none is the operator's policy, not a broken
// attachment. The real session's coverage and kernel confirmations go through
// the account, with captured traffic as the working-attachment control. The
// failure control spoils a real transfer point: its refusal is named, while
// the descendant mechanism still answers true for follow.
// This tests Session -> narrowing -> account; it does not drive the CLI.
func TestNoDescendantsIsReportedAsPolicyRatherThanPlacementFailure(t *testing.T) {
	const policyReason = "this target admits no descendant at all, so nothing it would have covered is lost"
	for _, tc := range []struct {
		name   string
		mode   admission.Mode
		broken bool
	}{
		{"none with working probes", admission.ModeNone, false},
		{"follow with working probes", admission.ModeFollow, false},
		{"follow with a refused transfer point", admission.ModeFollow, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pid, port := serving(t)
			p := loaded(t, pid)
			moveToCgroup(t, "obs-policy-account", pid)
			selected := admitting(p, tc.mode)
			asked := points(t, p)
			if tc.broken {
				asked = spoiling(asked, unheldAt, "SSL_read")
			}
			session, err := ebpf.Attach(ebpf.Options{Program: bpf.Full(), Points: asked, Admit: selected})
			if err != nil {
				t.Fatalf("construct session: %v", err)
			}
			defer func() { _ = session.Close() }()

			coverage := session.Coverage()
			if want := tc.mode == admission.ModeFollow; coverage.Descendants != want {
				t.Fatalf("descendants %s: Session.Coverage().Descendants = %t, want %t", tc.mode, coverage.Descendants, want)
			}
			placements := session.Confirmed()
			refused := unconfirmed(session)
			if tc.broken {
				if len(refused) != 1 || refused["SSL_read"] == "" {
					t.Fatalf("mechanism control did not reach exactly one explained SSL_read refusal: %v", refused)
				}
			} else if len(placements) == 0 || len(refused) != 0 {
				t.Fatalf("working-probe control: %d placements, refusals %v", len(placements), refused)
			}

			speaking(t, port).ask(t, "/?asked=policy-account")
			taken := drain(session, 500*time.Millisecond)
			if !containsSubstring(taken.plaintext(fragment.Sent), "policy-account") {
				t.Fatal("the real response was not captured; the working-attachment control is not established")
			}

			catalog, err := probe.NewCatalog(openssl.New())
			if err != nil {
				t.Fatal(err)
			}
			observed := attachment.Describe(attachment.Attempt{
				Process: p, Alive: true, Support: catalog.Inspect(p),
				Admitted: selected[0], Attested: true, Placements: placements,
				Capability: coverage.Narrow(attach.Built()),
			})
			wantOutcome := attachment.Attached
			if tc.broken {
				wantOutcome = attachment.Partial
			}
			if observed.Outcome != wantOutcome {
				t.Fatalf("account construction: outcome %q, want %q: %s", observed.Outcome, wantOutcome, observed.Reason)
			}
			var out strings.Builder
			attachment.Of([]process.Match{{Number: 1, Rule: process.Rule{Executable: p.Executable}, Matched: []process.Process{p}}},
				[]attachment.Observed{observed}).Report(&out)
			report := out.String()
			t.Logf("account under %s (broken=%t):\n%s", tc.mode, tc.broken, report)
			if tc.mode == admission.ModeNone {
				if !strings.Contains(report, policyReason) {
					t.Errorf("descendants none is not explained as policy in the account:\n%s", report)
				}
				if observed.Reason != "" || strings.Contains(report, "FROM NOW ON is unobserved") {
					t.Errorf("policy exclusion is reported as a mechanism failure:\n%s", report)
				}
			} else if strings.Contains(report, policyReason) {
				t.Errorf("follow is falsely explained as policy excluding all descendants:\n%s", report)
			}
			if tc.broken && (!strings.Contains(report, "SSL_read") || !strings.Contains(report, refused["SSL_read"])) {
				t.Errorf("mechanism failure lost its actual kernel evidence:\n%s", report)
			}
		})
	}
}
