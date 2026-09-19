package process_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/process"
)

func write(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "approval.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestLoadApprovalReadsTheRulesTheOperatorWrote(t *testing.T) {
	path := write(t, `{"rules": [
		{"executable": "/usr/bin/interpreter", "arguments": ["/srv/one/main"]},
		{"executable": "/usr/bin/interpreter", "arguments": ["/srv/two/main"]}
	]}`)

	approval, err := process.LoadApproval(path)
	if err != nil {
		t.Fatalf("LoadApproval: %v", err)
	}

	if got := len(approval.Rules); got != 2 {
		t.Fatalf("%d rules, want 2", got)
	}
	if got, want := approval.Rules[1].Arguments, []string{"/srv/two/main"}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("second rule's arguments = %q, want %q", got, want)
	}
}

// Each would read as an empty approval observing nothing, which looks like a
// correct run on a quiet host, so each is refused.
func TestLoadApprovalRefuses(t *testing.T) {
	cases := map[string]string{
		"a file that is not JSON at all":     `rules: /usr/bin/interpreter`,
		"JSON that is truncated":             `{"rules": [{"executable": "/usr/bin/interpreter"`,
		"an approval holding no rules":       `{"rules": []}`,
		"an approval with no rules key":      `{}`,
		"a rule naming a relative path":      `{"rules": [{"executable": "interpreter"}]}`,
		"a key the format does not define":   `{"rules": [{"executable": "/usr/bin/x", "user": "root"}]}`,
		"a rule naming a path with no entry": `{"rules": [{"executable": ""}]}`,
		"a rule naming the root cgroup":      `{"rules": [{"cgroup": "/"}]}`,
		"a condition only the configuration file defines": `{"rules": [
			{"executable": "/usr/bin/x", "port": 8443}]}`,
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := process.LoadApproval(write(t, content)); err == nil {
				t.Fatalf("LoadApproval accepted %s", name)
			}
		})
	}
}

// Conditions are ANDed: two narrow the rule, and arguments alone are a
// condition.
func TestLoadApprovalReadsARuleWhoseConditionsCombine(t *testing.T) {
	for name, content := range map[string]string{
		"an executable and a cgroup":   `{"rules": [{"executable": "/usr/bin/x", "cgroup": "/system.slice/x.service"}]}`,
		"a cgroup and arguments":       `{"rules": [{"cgroup": "/system.slice/x.service", "arguments": ["--serve"]}]}`,
		"arguments with no executable": `{"rules": [{"arguments": ["/srv/one/main"]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := process.LoadApproval(write(t, content)); err != nil {
				t.Fatalf("LoadApproval refused %s: %v", name, err)
			}
		})
	}
}

func TestLoadApprovalRefusesAFileThatIsNotThere(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")

	_, err := process.LoadApproval(path)
	if err == nil {
		t.Fatal("LoadApproval accepted a file that does not exist")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error does not name the file it looked for: %v", err)
	}
}

// A rule naming no arguments approves the program run with none, not with
// some.
func TestARuleNamingNoArgumentsApprovesOnlyAProcessThatHasNone(t *testing.T) {
	approval, err := process.LoadApproval(write(t, `{"rules": [{"executable": "/usr/bin/daemon"}]}`))
	if err != nil {
		t.Fatalf("LoadApproval: %v", err)
	}

	bare := process.Process{Executable: "/usr/bin/daemon", Arguments: []string{"/usr/bin/daemon"}}
	configured := process.Process{Executable: "/usr/bin/daemon", Arguments: []string{"/usr/bin/daemon", "--serve"}}

	if !approval.Observes(bare) {
		t.Error("a rule naming no arguments does not approve a process run with none")
	}
	if approval.Observes(configured) {
		t.Error("a rule naming no arguments approves a process run with some")
	}
}

// The other selector, read from an approval file.
func TestLoadApprovalReadsACgroupRule(t *testing.T) {
	approval, err := process.LoadApproval(write(t, `{"rules": [{"cgroup": "/system.slice/one.service"}]}`))
	if err != nil {
		t.Fatalf("LoadApproval: %v", err)
	}
	if got, want := approval.Rules[0].Cgroup, "/system.slice/one.service"; got != want {
		t.Fatalf("the rule's cgroup = %q, want %q", got, want)
	}
}
