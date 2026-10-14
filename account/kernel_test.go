package account_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/probe"
)

// sessionKernel is the release a kernel line says the session ran on, parsed
// whole, or false where the line names none.
func sessionKernel(line string) (string, bool) {
	_, after, found := strings.Cut(line, "ran on kernel ")
	if !found {
		return "", false
	}
	release, _, found := strings.Cut(after, ",")
	return release, found
}

// The floor statement names the build's declared minimum in both of its
// branches and at both moments a session is inspected, never says UNPROVED, and
// never reads as a range every newer kernel is promised. The unproved branch
// carries what is known and what would settle it.
func TestTheFloorStatementNamesTheDeclaredMinimumInBothBranchesWithoutUNPROVED(t *testing.T) {
	const published = "5.15"
	statements := map[bool]string{}
	for _, proved := range []bool{false, true} {
		for _, kind := range []account.Kind{account.Live, account.Sealed} {
			a := ran(t, probe.Losses{})
			a.Kind = kind
			a.Floor.Proved = proved
			if a.Floor.Published != published || a.Floor.Established == "" || a.Floor.WouldEstablish == "" {
				t.Fatalf("wiring, not the property: the account's floor is %+v, so the statement below is not "+
					"about the build's floor", a.Floor)
			}
			floor := line(t, rendered(a, false), "floor")
			if !strings.Contains(floor, "kernel "+published+" ") {
				t.Errorf("proved %v, %s: the floor line does not name the declared minimum %s: %q", proved, kind,
					published, floor)
			}
			for _, forbidden := range []string{"UNPROVED", "or newer"} {
				if strings.Contains(floor, forbidden) {
					t.Errorf("proved %v, %s: the floor line says %q: %q", proved, kind, forbidden, floor)
				}
			}
			carries := strings.Contains(floor, a.Floor.Established) && strings.Contains(floor, a.Floor.WouldEstablish)
			if carries == proved {
				t.Errorf("proved %v, %s: the floor line carries what would settle the floor %v times: %q", proved, kind,
					carries, floor)
			}
			if previous, seen := statements[proved]; seen && previous != floor {
				t.Errorf("proved %v: the floor line differs between moments, %q and %q", proved, previous, floor)
			}
			statements[proved] = floor
		}
	}
	if statements[false] == statements[true] {
		t.Errorf("the proved and unproved floor lines are the same: %q", statements[false])
	}
}

// The kernel line names the release the account recorded. Two accounts with
// different recorded releases render different lines, so the line is the
// account's and not the rendering host's, which is the same for both.
func TestTheKernelLineNamesTheReleaseTheAccountRecorded(t *testing.T) {
	for _, kind := range []account.Kind{account.Live, account.Sealed} {
		lines := map[string]string{}
		for _, release := range []string{"5.15.0-recorded-one", "6.8.0-recorded-two"} {
			a := ran(t, probe.Losses{})
			a.Kind = kind
			a.Kernel = &account.Kernel{Release: release}
			kernel := line(t, rendered(a, false), "kernel")
			if got, found := sessionKernel(kernel); !found || got != release {
				t.Errorf("%s: a session recorded on %s renders the kernel line %q", kind, release, kernel)
			}
			for _, wrong := range []string{"not recorded", "could not be read"} {
				if strings.Contains(kernel, wrong) {
					t.Errorf("%s: a recorded release's kernel line says %q: %q", kind, wrong, kernel)
				}
			}
			lines[release] = kernel
		}
		if lines["5.15.0-recorded-one"] == lines["6.8.0-recorded-two"] {
			t.Errorf("%s: two different recorded releases render one line %q", kind, lines["5.15.0-recorded-one"])
		}
	}
}

// A release that could not be read says so with its reason, and an account
// without the record - one written before sessions recorded their kernel - says
// the kernel was not recorded. The two are not read as each other, and neither
// names a release.
func TestAnUnreadKernelSaysWhyAndAnOlderAccountSaysTheKernelWasNotRecorded(t *testing.T) {
	const why = "open /proc/sys/kernel/osrelease: permission denied"
	for _, kind := range []account.Kind{account.Live, account.Sealed} {
		unread := ran(t, probe.Losses{})
		unread.Kind = kind
		unread.Kernel = &account.Kernel{Why: why}
		kernel := line(t, rendered(unread, false), "kernel")
		if !strings.Contains(kernel, "could not be read") || !strings.Contains(kernel, why) ||
			strings.Contains(kernel, "not recorded") {
			t.Errorf("%s: an unread release renders %q, want it could not be read and why", kind, kernel)
		}
		if release, found := sessionKernel(kernel); found {
			t.Errorf("%s: an unread release's line names the release %q", kind, release)
		}

		recorded := ran(t, probe.Losses{})
		recorded.Kind = kind
		recorded.Kernel = &account.Kernel{Release: "6.8.0-recorded"}
		content, err := json.Marshal(recorded)
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(content, &document); err != nil {
			t.Fatal(err)
		}
		if _, present := document["kernel"]; !present {
			t.Fatalf("wiring, not the property: the encoded %s account has no kernel member to leave out, so "+
				"nothing below reads an account without one", kind)
		}
		delete(document, "kernel")
		older, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		var read account.Account
		if err := json.Unmarshal(older, &read); err != nil {
			t.Fatalf("%s: an account without the kernel member does not read: %v", kind, err)
		}
		kernel = line(t, rendered(read, false), "kernel")
		if !strings.Contains(kernel, "not recorded") || strings.Contains(kernel, "could not be read") {
			t.Errorf("%s: an account without the record renders %q, want the kernel was not recorded", kind, kernel)
		}
		if release, found := sessionKernel(kernel); found {
			t.Errorf("%s: an account without the record names the release %q", kind, release)
		}
	}
}

// A dry run has no session, so it says nothing about a session's kernel.
func TestADryRunHasNoKernelLine(t *testing.T) {
	text := rendered(planned(t), false)
	for one := range strings.Lines(text) {
		if strings.HasPrefix(one, "kernel ") {
			t.Errorf("a dry run renders a kernel line: %q", strings.TrimSpace(one))
		}
	}
	if !strings.Contains(text, "floor ") {
		t.Fatalf("wiring, not the property: the dry run rendered no floor line, so its silence about the kernel "+
			"says nothing:\n%s", text)
	}
}
