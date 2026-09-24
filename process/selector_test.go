package process_test

import (
	"os"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/process"
)

// rewritten is a process that overwrote its argv with a status line and padded
// the rest with NULs (nginx and php-fpm do; an nginx worker shows "nginx:
// worker process" and about 27 NULs). The padding length belongs to the start
// command.
func rewritten(padding int) process.Process {
	arguments := make([]string, 1+padding)
	arguments[0] = "nginx: worker process"
	return process.Process{PID: 41, Executable: "/usr/sbin/nginx", Arguments: arguments}
}

// A rule for such a process names no arguments and matches it; enumerating the
// padding would stop matching when the command line's length changes.
func TestARuleMatchesAProcessThatRewroteItsArgvWithoutEnumeratingThePadding(t *testing.T) {
	rule := process.Rule{Executable: "/usr/sbin/nginx"}

	for _, padding := range []int{0, 1, 27, 92} {
		if !rule.Matches(rewritten(padding)) {
			t.Errorf("a rule naming no arguments does not match a process padded with %d empty entries", padding)
		}
	}
}

// That rule does not approve the same executable run with a real argument.
func TestARuleNamingNoArgumentsStillRefusesAProcessThatHasOne(t *testing.T) {
	rule := process.Rule{Executable: "/usr/sbin/nginx"}

	p := rewritten(3)
	p.Arguments[2] = "-c/etc/nginx/other.conf"

	if rule.Matches(p) {
		t.Error("a rule naming no arguments matched a process that has one")
	}
}

// An empty entry followed by a real argument is an argument.
func TestAnEmptyArgumentBetweenTwoRealOnesIsNotPadding(t *testing.T) {
	p := process.Process{
		Executable: "/usr/bin/interpreter",
		Arguments:  []string{"/usr/bin/interpreter", "--label", "", "/srv/one/main"},
	}

	approves := process.Rule{Executable: "/usr/bin/interpreter", Arguments: []string{"--label", "", "/srv/one/main"}}
	if !approves.Matches(p) {
		t.Error("a rule naming an empty argument between two real ones does not match the process that has one")
	}

	drops := process.Rule{Executable: "/usr/bin/interpreter", Arguments: []string{"--label", "/srv/one/main"}}
	if drops.Matches(p) {
		t.Error("a rule that dropped an argument the process really has matched it anyway")
	}
}

// A rule written with the padding still matches: it is dropped from both
// sides.
func TestARuleThatEnumeratedThePaddingStillMatches(t *testing.T) {
	rule := process.Rule{Executable: "/usr/sbin/nginx", Arguments: []string{"", "", ""}}

	if !rule.Matches(rewritten(27)) {
		t.Error("a rule that enumerated the padding no longer matches the process it was written for")
	}
}

func inCgroup(pid int32, path string) process.Process {
	return process.Process{PID: pid, Executable: "/usr/bin/interpreter", Cgroup: path}
}

// The second selector: a service's cgroup approves it and everything below
// it, with no walk and no fork race.
func TestACgroupRuleMatchesTheServiceAndWhatIsBelowIt(t *testing.T) {
	rule := process.Rule{Cgroup: "/system.slice/one.service"}

	for _, path := range []string{
		"/system.slice/one.service",
		"/system.slice/one.service/worker",
		"/system.slice/one.service/worker/deeper",
	} {
		if !rule.Matches(inCgroup(7, path)) {
			t.Errorf("a cgroup rule does not match a process in %s", path)
		}
	}
}

// It reaches nothing else: a sibling, a name-prefix match, or a process on no
// unified hierarchy.
func TestACgroupRuleReachesNothingBesideIt(t *testing.T) {
	rule := process.Rule{Cgroup: "/system.slice/one.service"}

	for _, path := range []string{
		"/system.slice/two.service",
		"/system.slice/one.service.other",
		"/user.slice",
		"",
	} {
		if rule.Matches(inCgroup(9, path)) {
			t.Errorf("a cgroup rule matched a process in %q", path)
		}
	}
}

// Two programs under one supervisor share a cgroup: one rule approves both,
// and they stay two processes for attribution.
func TestTwoProcessesUnderOneSupervisorShareACgroupAndStayDistinct(t *testing.T) {
	shared := "/system.slice/app.service"
	gateway := process.Process{
		PID: 11, StartTime: 900, Executable: "/usr/bin/php", Cgroup: shared,
		Arguments: []string{"php", "/srv/app/gateway/main.php"},
	}
	worker := process.Process{
		PID: 12, StartTime: 901, Executable: "/usr/bin/php", Cgroup: shared,
		Arguments: []string{"php", "/srv/app/worker/main.php"},
	}

	byCgroup := process.Rule{Cgroup: shared}
	if !byCgroup.Matches(gateway) || !byCgroup.Matches(worker) {
		t.Fatal("one cgroup rule does not approve both processes under that cgroup")
	}
	if gateway.Identity() == worker.Identity() {
		t.Fatal("two processes under one cgroup have one identity, so nothing could tell their traffic apart")
	}

	// The other selector still separates them.
	onlyGateway := process.Rule{
		Executable: "/usr/bin/php",
		Arguments:  []string{"/srv/app/gateway/main.php"},
	}
	if !onlyGateway.Matches(gateway) {
		t.Error("an argument rule does not match the gateway")
	}
	if onlyGateway.Matches(worker) {
		t.Error("an argument rule for the gateway matched the worker, so the two are not separable")
	}
}

// Each would approve nothing.
func TestValidateRefuses(t *testing.T) {
	cases := map[string]process.Rule{
		"a rule naming neither selector": {},
		"a relative cgroup path":         {Cgroup: "system.slice/x.service"},
		"the root cgroup":                {Cgroup: "/"},
		"a relative executable":          {Executable: "interpreter"},
	}

	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			if err := rule.Validate(); err == nil {
				t.Fatalf("Validate accepted %s", name)
			}
		})
	}
}

func TestValidateAcceptsEitherSelector(t *testing.T) {
	for _, rule := range []process.Rule{
		{Executable: "/usr/bin/interpreter", Arguments: []string{"/srv/one/main"}},
		{Cgroup: "/system.slice/one.service"},
	} {
		if err := rule.Validate(); err != nil {
			t.Errorf("Validate refused %s: %v", rule, err)
		}
	}
}

// A report names a rule by its selector.
func TestARuleNamesItselfByTheSelectorItUsed(t *testing.T) {
	byArguments := process.Rule{Executable: "/usr/bin/php", Arguments: []string{"/srv/one/main"}}
	if got, want := byArguments.String(), "/usr/bin/php /srv/one/main"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if got, want := (process.Rule{Cgroup: "/system.slice/one.service"}).String(),
		"cgroup /system.slice/one.service"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// The cgroup comes off the running kernel.
func TestReadReportsTheProcessesOwnUnifiedCgroup(t *testing.T) {
	content, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatalf("read this process's cgroup: %v", err)
	}

	var want string
	for line := range strings.Lines(string(content)) {
		if path, found := strings.CutPrefix(strings.TrimSpace(line), "0::"); found {
			want = path
		}
	}
	if want == "" {
		t.Fatalf("this host puts the reader on no unified hierarchy, so there is nothing to measure:\n%s", content)
	}

	self := find(t, read(t), int32(os.Getpid()))
	if self.Cgroup != want {
		t.Errorf("Read reports the reader's cgroup as %q, and /proc/self/cgroup says %q", self.Cgroup, want)
	}
}

// A rule that matched nothing is reported: nothing downstream reveals it.
func TestMatchesNamesTheRuleThatMatchedNothing(t *testing.T) {
	directory := t.TempDir()
	running := sleeper(t, directory+"/running")

	approval := process.Approval{Rules: []process.Rule{
		{Executable: directory + "/running", Arguments: []string{"600"}},
		{Executable: directory + "/absent", Arguments: []string{"600"}},
	}}

	matches := approval.Matches(read(t))
	if len(matches) != 2 {
		t.Fatalf("%d matches for 2 rules", len(matches))
	}

	if matches[0].Number != 1 || len(matches[0].Matched) != 1 || matches[0].Matched[0].PID != running {
		t.Errorf("rule 1 matched %v, want the one process at pid %d", matches[0].Matched, running)
	}
	if matches[1].Number != 2 || len(matches[1].Matched) != 0 {
		t.Errorf("rule 2 matched %d processes, and nothing on this host runs %s", len(matches[1].Matched), directory+"/absent")
	}
}
