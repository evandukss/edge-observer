package account_test

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

var (
	namespace = admission.Namespace{Device: 4, Inode: 4026531836}
	moment    = time.Date(2026, 9, 11, 7, 0, 0, 0, time.UTC)
)

func proc(pid, parent int32, executable string, arguments ...string) process.Process {
	return process.Process{
		PID: pid, PPID: parent, StartTime: 9000 + uint64(pid), Executable: executable,
		Arguments: append([]string{executable}, arguments...), Namespace: namespace, NamespacePID: pid,
	}
}

// planned is a dry run's account for one target with a root and an existing
// child, and one port target that cannot resolve.
func planned(t *testing.T) account.Account {
	t.Helper()
	table := process.TableOf(
		proc(10, 1, "/usr/bin/interpreter", "/srv/one/main", "--token=s3cret"),
		proc(11, 10, "/usr/bin/worker"),
	)
	approval := process.Approval{Rules: []process.Rule{
		{Name: "gateway", Executable: "/usr/bin/interpreter", Arguments: []string{"/srv/one/main", "--token=s3cret"},
			Mode: admission.ModeExisting},
		{Name: "front", Port: 8443, Mode: admission.ModeNone},
	}}
	resolution := approval.Resolve(process.Host{Table: table})
	return account.Plan(moment, account.Policy{Revision: "sha256:abc", Generation: 0}, resolution,
		probe.Capability{Backend: probe.BPF, Program: "full", Payload: true}, nil)
}

func encoded(t *testing.T, a account.Account) string {
	t.Helper()
	content, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("encode the account: %v", err)
	}
	return string(content)
}

func rendered(a account.Account, local bool) string {
	var out bytes.Buffer
	account.Render(&out, a, local)
	return out.String()
}

// line is the one rendered line beginning with a word, which must be there once.
func line(t *testing.T, text, word string) string {
	t.Helper()
	var found []string
	for one := range strings.Lines(text) {
		if strings.HasPrefix(one, word+" ") {
			found = append(found, strings.TrimSpace(one))
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d lines begin with %q, want one:\n%s", len(found), word, text)
	}
	return found[0]
}

// integers is every whole number in a line, parsed whole: "2 of" must not
// match "12 of".
func integers(text string) []int64 {
	var found []int64
	for _, field := range strings.FieldsFunc(text, func(r rune) bool { return r < '0' || r > '9' }) {
		if number, err := strconv.ParseInt(field, 10, 64); err == nil {
			found = append(found, number)
		}
	}
	return found
}

// A dry run states per target what would be selected, under which mode, and
// why a target selects nothing - and carries no process's arguments. Only the
// local view shows them, and it says so.
func TestADryRunStatesWhatEachTargetWouldSelectAndCarriesNoArgument(t *testing.T) {
	a := planned(t)

	if a.Kind != account.Planned || a.Version != account.Version {
		t.Errorf("a dry run is %s version %d, want planned version %d", a.Kind, a.Version, account.Version)
	}
	if len(a.Targets) != 2 {
		t.Fatalf("%d targets, want 2", len(a.Targets))
	}
	gateway, front := a.Targets[0], a.Targets[1]
	if gateway.Name != "gateway" || gateway.Mode != "existing" || !gateway.Answers.Existing || gateway.Answers.Future {
		t.Errorf("the first target is %+v", gateway)
	}
	if len(gateway.Roots) != 1 || gateway.Roots[0].PID != 10 || len(gateway.Descendants) != 1 || gateway.Descendants[0].PID != 11 {
		t.Errorf("the first target selects roots %v and descendants %v, want pid 10 and its child 11",
			gateway.Roots, gateway.Descendants)
	}
	if front.Unresolved == "" || len(front.Roots) != 0 {
		t.Errorf("a port target with no listener read is %+v, want unresolved with its reason", front)
	}
	if a.Processes != nil || a.Seal != nil || a.Loss != nil {
		t.Error("a dry run carries an attachment, a loss or a seal, and nothing has attached")
	}

	if strings.Contains(encoded(t, a), "s3cret") {
		t.Error("the account carries a process's argument")
	}
	if text := rendered(a, false); strings.Contains(text, "s3cret") {
		t.Errorf("the ordinary rendering carries a process's argument:\n%s", text)
	}
	local := rendered(a, true)
	if !strings.Contains(local, "s3cret") || !strings.Contains(local, "local view") {
		t.Errorf("the local rendering does not show the target's conditions or does not say it is local:\n%s", local)
	}
}

// ran is a sealed account of a successful run, with the losses given.
func ran(t *testing.T, losses probe.Losses) account.Account {
	t.Helper()
	a := planned(t)
	a.Attached(account.Sealed, "0123456789abcdef", []attachment.Observed{{PID: 10, Requested: 9, Confirmed: 9,
		Outcome: attachment.Attached}}, probe.Capability{Backend: probe.BPF, Program: "full", Payload: true})
	a.Ran(moment.Add(time.Minute), account.Run{
		Seen:     capture.Stats{Transfers: 20, Records: 12, Connections: 2},
		Losses:   losses,
		Refusals: map[string]int64{},
	})
	a.Closed(connection.Seal{Complete: true, Sealed: moment.Add(2 * time.Minute)}, nil)
	return a
}

// The lost line carries only the two genuine losses; admitted descendants have
// a line of their own. Numbers are parsed whole.
func TestTheLostLineCarriesGenuineLossesAndAdmittedDescendantsStandApart(t *testing.T) {
	admittedOnly := ran(t, probe.Losses{Dropped: 0, Unmatched: 0, Descendants: 7})
	text := rendered(admittedOnly, false)

	if got := integers(line(t, text, "lost")); len(got) != 2 || got[0] != 0 || got[1] != 0 {
		t.Errorf("with nothing lost, the lost line carries %v, want exactly the two losses at zero", got)
	}
	admitted := line(t, text, "admitted")
	if got := integers(admitted); len(got) != 1 || got[0] != 7 {
		t.Errorf("the admitted line carries %v, want the 7 descendants admitted", got)
	}
	if !strings.Contains(admitted, "descendant") || strings.Contains(admitted, "miss") || strings.Contains(admitted, "lost") {
		t.Errorf("the admitted line reads %q, want descendants admitted and nothing about a loss", admitted)
	}
	if admittedOnly.Admitted == nil || admittedOnly.Admitted.Descendants != 7 {
		t.Errorf("the account's admitted field is %+v, want 7 descendants", admittedOnly.Admitted)
	}
	if strings.Contains(encoded(t, admittedOnly), `"loss":{"known":true,"dropped":0,"unmatched":0,"when":{"first":0,"last":0,"handle":0,"pid":0,"tid":0},"descendants"`) ||
		admittedOnly.Loss == nil || admittedOnly.Loss.Dropped != 0 || admittedOnly.Loss.Unmatched != 0 {
		t.Errorf("the account's loss is %+v, want both losses at zero and no descendants in it", admittedOnly.Loss)
	}

	// The controls: genuine losses reach the lost line.
	lost := ran(t, probe.Losses{Dropped: 3, Unmatched: 5, Descendants: 0})
	text = rendered(lost, false)
	if got := integers(line(t, text, "lost")); len(got) != 2 || got[0] != 3 || got[1] != 5 {
		t.Errorf("the lost line carries %v, want 3 dropped then 5 unmatched", got)
	}
	if got := integers(line(t, text, "admitted")); len(got) != 1 || got[0] != 0 {
		t.Errorf("the admitted line carries %v with none admitted", got)
	}
}

// The published floor and its proof status reach the account from the build,
// and a successful run does not prove it.
func TestTheFloorAndItsProofStatusReachTheAccountAndACapturedRunDoesNotProveIt(t *testing.T) {
	const published = "5.15"

	for name, a := range map[string]account.Account{"a dry run": planned(t), "a run that captured": ran(t, probe.Losses{})} {
		t.Run(name, func(t *testing.T) {
			if a.Floor.Published != published {
				t.Errorf("the account publishes floor %q, want %q", a.Floor.Published, published)
			}
			if a.Floor.Proved {
				t.Error("the account says the floor is proved, and it has never been loaded at the floor")
			}
			if a.Floor.Established == "" || a.Floor.WouldEstablish == "" {
				t.Errorf("the floor says %+v, want what is established and what would establish the rest", a.Floor)
			}
			if !strings.Contains(encoded(t, a), `"floor":{"published":"5.15","proved":false`) {
				t.Errorf("the encoded account carries no unproved floor claim")
			}

			// The rendering is read against the same account.
			floor := line(t, rendered(a, false), "floor")
			if !strings.Contains(floor, published) || !strings.Contains(floor, "UNPROVED") {
				t.Errorf("the floor line reads %q", floor)
			}
		})
	}
}

// Coverage over a declared population: an admission whose grant is gone is
// listed once, a held one counted, an unreadable one unknown - never
// "nothing ended".
func TestCoverageListsEveryUngrantedAdmissionOnceAndAnUnreadGrantIsUnknown(t *testing.T) {
	selection := func(pid int32) admission.Selection {
		return admission.Selection{
			Instance:    admission.Instance{Namespace: namespace, PID: pid, Generation: admission.Generation(pid)},
			Kind:        admission.ByTarget,
			Provenance:  admission.Provenance{Target: "gateway", Number: 1},
			Mode:        admission.ModeFollow,
			ObserverPID: pid,
		}
	}
	interval := process.Interval{From: moment.Add(time.Second), To: moment.Add(2 * time.Second)}
	held, running, ended, unreadable := selection(20), selection(21), selection(22), selection(23)
	declared := map[int32]bool{21: true, 22: true, 23: true}

	a := ran(t, probe.Losses{})
	a.Ran(moment.Add(time.Minute), account.Run{Grants: []probe.Grant{
		{Selection: held, State: probe.GrantHeld, Read: moment},
		{Selection: running, State: probe.GrantAbsent, Read: moment, Evidence: interval},
		{Selection: ended, State: probe.GrantAbsent, Read: moment, Evidence: interval},
		{Selection: unreadable, State: probe.GrantAbsent, Read: moment, Evidence: interval},
	}})
	if a.Admissions == nil {
		t.Fatal("the account carries no admissions")
	}
	if a.Admissions.Covered != 1 || a.Admissions.Rule == "" {
		t.Errorf("admissions are %+v, want the one held grant counted under a stated rule", a.Admissions)
	}
	listed := make(map[int32]int)
	for _, one := range a.Admissions.CoverageEnded {
		listed[one.Instance.PID]++
		if one.NoLaterThan == nil || !one.NoLaterThan.Equal(moment) || one.Read == nil {
			t.Errorf("pid %d's coverage ending carries %+v, want the grant reading's time and the execution's reading", one.Instance.PID, one)
		}
	}
	for pid := range declared {
		if listed[pid] != 1 {
			t.Errorf("pid %d is listed %d times among the endings, want once", pid, listed[pid])
		}
	}
	if len(listed) != len(declared) || len(a.Admissions.GrantUnknown) != 0 {
		t.Errorf("endings %v and unknowns %v, want exactly the declared three and no unknown", listed, a.Admissions.GrantUnknown)
	}

	// Per target, so one target going dark is not read as the run.
	other := selection(24)
	other.Provenance = admission.Provenance{Target: "front", Number: 2}
	split := ran(t, probe.Losses{})
	split.Ran(moment.Add(time.Minute), account.Run{Grants: []probe.Grant{
		{Selection: running, State: probe.GrantAbsent, Read: moment, Evidence: interval},
		{Selection: other, State: probe.GrantHeld, Read: moment},
	}})
	byTarget := make(map[string]account.TargetCoverage)
	for _, one := range split.Admissions.ByTarget {
		byTarget[one.Target] = one
	}
	if byTarget["gateway"] != (account.TargetCoverage{Target: "gateway", Covered: 0, Ended: 1}) ||
		byTarget["front"] != (account.TargetCoverage{Target: "front", Covered: 1}) || len(byTarget) != 2 {
		t.Errorf("coverage by target is %v, want gateway ended at zero and front still covered", split.Admissions.ByTarget)
	}

	text := encoded(t, a)
	for liveness := process.LivenessUnestablished; liveness <= process.LivenessReplaced; liveness++ {
		if strings.Contains(text, liveness.String()) {
			t.Errorf("the account publishes the execution classification %q", liveness.String())
		}
	}

	// An unreadable grant is unknown, and the population stays whole.
	unread := ran(t, probe.Losses{})
	var grants []probe.Grant
	for _, one := range []admission.Selection{held, running, ended, unreadable} {
		grants = append(grants, probe.Grant{Selection: one, State: probe.GrantUnknown, Read: moment, Why: "the iterator failed"})
	}
	unread.Ran(moment.Add(time.Minute), account.Run{Grants: grants})
	if unread.Admissions == nil || len(unread.Admissions.GrantUnknown) != 4 || len(unread.Admissions.CoverageEnded) != 0 ||
		unread.Admissions.Covered != 0 {
		t.Errorf("after a failed read the admissions are %+v, want all four unknown and none ended or covered", unread.Admissions)
	}

	// A backend that cannot answer says so; that is not an empty set.
	cannot := ran(t, probe.Losses{})
	cannot.Ran(moment.Add(time.Minute), account.Run{GrantsErr: errFixed("this backend records no admissions")})
	if cannot.Admissions == nil || cannot.Admissions.Unavailable == "" {
		t.Errorf("a backend that cannot answer gives admissions %+v, want it said", cannot.Admissions)
	}
}

type errFixed string

func (e errFixed) Error() string { return string(e) }
