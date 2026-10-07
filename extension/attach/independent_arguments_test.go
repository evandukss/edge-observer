//go:build attach

package attach_test

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/attachment"
	"github.com/evandukss/edge-observer/contract/config"
)

// These cases are written from process/arguments.go's published comments and
// the requirement that start, preflight and reload never decide a process on
// arguments they could not read, not from the implementation.
//
// Start, preflight and reload read the host's own /proc, so the state is made
// real rather than constructed: a copy of this test binary sets the end of its
// argument area to its start with prctl(PR_SET_MM, PR_SET_MM_ARG_END), which
// needs CAP_SYS_RESOURCE, and from then on its executable link reads as usual
// and its cmdline reads 0 bytes, for as long as it runs.

const (
	undeterminedArgument    = "independent-undetermined-arguments"
	undeterminedEnvironment = "INDEPENDENT_UNDETERMINED_ARGUMENTS"
)

func init() {
	if os.Getenv(undeterminedEnvironment) != "1" || len(os.Args) != 2 || os.Args[1] != undeterminedArgument {
		return
	}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		fmt.Println("refused: read /proc/self/stat:", err)
		os.Exit(3)
	}
	text := string(stat)
	// Field 48 is arg_start; the fields after the command's closing parenthesis
	// begin at field 3.
	fields := strings.Fields(text[strings.LastIndexByte(text, ')')+2:])
	start, err := strconv.ParseUint(fields[45], 10, 64)
	if err != nil {
		fmt.Println("refused: arg_start:", err)
		os.Exit(3)
	}
	if err := unix.Prctl(unix.PR_SET_MM, unix.PR_SET_MM_ARG_END, uintptr(start), 0, 0); err != nil {
		fmt.Println("refused: PR_SET_MM_ARG_END:", err)
		os.Exit(3)
	}
	fmt.Println("emptied")
	for {
		time.Sleep(time.Hour)
	}
}

// undetermined is a running process whose executable reads and whose
// arguments read empty.
type undetermined struct {
	pid        int32
	executable string
	arguments  []string
}

// refusal is the published text of the refusal naming it.
func (u undetermined) refusal() string {
	return fmt.Sprintf("pid %d (%s): arguments undetermined", u.pid, u.executable)
}

// obsUndetermined starts the helper, in cgroup where given, and returns once
// its arguments read empty and stay so.
func obsUndetermined(t *testing.T, cgroup *os.File) undetermined {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err := filepath.EvalSymlinks(self)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, undeterminedArgument)
	command.Env = append(os.Environ(), undeterminedEnvironment+"=1")
	if cgroup != nil {
		command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
	}
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("wiring, not the property: start the helper: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "emptied\n" {
		t.Fatalf("wiring, not the property: the helper did not empty its arguments: %q %v", line, err)
	}
	u := undetermined{pid: int32(command.Process.Pid), executable: executable, arguments: []string{undeterminedArgument}}
	entry := filepath.Join("/proc", strconv.Itoa(int(u.pid)))
	for range 5 {
		link, linkErr := os.Readlink(filepath.Join(entry, "exe"))
		cmdline, cmdlineErr := os.ReadFile(filepath.Join(entry, "cmdline"))
		if linkErr != nil || link != executable || cmdlineErr != nil || len(cmdline) != 0 {
			t.Fatalf("wiring, not the property: pid %d reads executable %q (%v) and %d bytes of arguments (%v), want "+
				"%s and 0 bytes", u.pid, link, linkErr, len(cmdline), cmdlineErr, executable)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return u
}

// obsHelperCgroup is a plain cgroup the helper is created into, so a rule can
// name it without consulting arguments.
func obsHelperCgroup(t *testing.T, name string) (string, *os.File) {
	t.Helper()
	path := "/independent-helper-" + name
	directory := filepath.Join("/sys/fs/cgroup", path)
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatalf("wiring, not the property: make cgroup %s: %v", directory, err)
	}
	t.Cleanup(func() { obsEmptyCgroup(directory) })
	held, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	return path, held
}

// obsRuleKind is one way a configuration consults the helper's arguments.
type obsRuleKind struct {
	name string
	// configure returns the watch and ignore entries for u, cgroup being the
	// cgroup path u runs in.
	configure func(u undetermined, cgroup string) (watch, ignore []map[string]any)
}

var obsRuleKinds = []obsRuleKind{
	{"inclusion", func(u undetermined, _ string) ([]map[string]any, []map[string]any) {
		return []map[string]any{{"name": "helper", "exe": u.executable, "args": u.arguments, "children": config.ChildrenNone}}, nil
	}},
	{"executable-only", func(u undetermined, _ string) ([]map[string]any, []map[string]any) {
		return []map[string]any{{"name": "helper", "exe": u.executable, "children": config.ChildrenNone}}, nil
	}},
	{"exclusion", func(u undetermined, cgroup string) ([]map[string]any, []map[string]any) {
		return []map[string]any{{"name": "group", "cgroup": cgroup, "children": config.ChildrenNone}},
			[]map[string]any{{"exe": u.executable, "args": u.arguments}}
	}},
}

// obsRefusedStart runs observer start and reports whether it activated (a
// live session answered, after which it is killed) and what it printed.
func obsRefusedStart(t *testing.T, binary string, c obsConfig, suffix string) (string, bool) {
	t.Helper()
	s := obsLaunch(t, binary, c, suffix)
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-s.done:
			s.done <- err
			var exit *exec.ExitError
			if err == nil || !errors.As(err, &exit) || exit.ExitCode() == 0 {
				t.Errorf("start ended with %v, not with a refusal", err)
			}
			return s.printed(), false
		default:
		}
		if obsRecorded(c) {
			if live, err := obsInspect(binary, c); err == nil && live.Kind == account.Live {
				_ = s.command.Process.Kill()
				return s.printed(), true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("start neither refused nor activated within 90s:\n%s", s.printed())
	return "", false
}

// Start refuses a configuration whose inclusion, executable-only rule or
// exclusion meets a process whose arguments stay unreadable, naming the
// process, and never activates.
func TestIndependentArgumentsStartRefusesAProcessWhoseArgumentsStayUnreadable(t *testing.T) {
	binary := obsBinary(t)
	for _, kind := range obsRuleKinds {
		t.Run(kind.name, func(t *testing.T) {
			cgroup, held := obsHelperCgroup(t, "start-"+kind.name)
			u := obsUndetermined(t, held)
			watch, ignore := kind.configure(u, cgroup)
			c := obsConfigure(t, t.TempDir(), "", watch, ignore, nil)
			printed, activated := obsRefusedStart(t, binary, c, kind.name)
			if activated {
				t.Errorf("start activated a session over pid %d, whose arguments are undetermined:\n%s", u.pid, printed)
			}
			if !strings.Contains(printed, u.refusal()) {
				t.Errorf("start did not refuse naming %q:\n%s", u.refusal(), printed)
			}
			if strings.Contains(printed, "no process on this host matches") {
				t.Errorf("start reported no match for a process whose arguments are undetermined:\n%s", printed)
			}
		})
	}
}

// Preflight answers for start: it refuses the same configurations, naming the
// process.
func TestIndependentArgumentsPreflightRefusesAProcessWhoseArgumentsStayUnreadable(t *testing.T) {
	binary := obsBinary(t)
	for _, kind := range obsRuleKinds {
		t.Run(kind.name, func(t *testing.T) {
			cgroup, held := obsHelperCgroup(t, "preflight-"+kind.name)
			u := obsUndetermined(t, held)
			watch, ignore := kind.configure(u, cgroup)
			c := obsConfigure(t, t.TempDir(), "", watch, ignore, nil)
			printed, err := exec.Command(binary, "preflight", c.path, "--text").CombinedOutput()
			if err == nil {
				t.Errorf("preflight answered READY over pid %d, whose arguments are undetermined:\n%s", u.pid, printed)
			}
			if !strings.Contains(string(printed), u.refusal()) {
				t.Errorf("preflight did not refuse naming %q:\n%s", u.refusal(), printed)
			}
		})
	}
}

// A reload that adds a target meeting a process whose arguments stay
// unreadable is refused naming the process, and grants it nothing; the
// session goes on.
func TestIndependentArgumentsReloadRefusesAProcessWhoseArgumentsStayUnreadable(t *testing.T) {
	binary := obsBinary(t)
	port := obsServing(t)
	for _, kind := range obsRuleKinds[:2] {
		t.Run(kind.name, func(t *testing.T) {
			client := obsSpeaking(t, port)
			u := obsUndetermined(t, nil)
			root := t.TempDir()
			c := obsConfigure(t, root, "", []map[string]any{obsWatch("client", client.process)}, nil, nil)
			s := obsStart(t, binary, c, "reload-"+kind.name)
			added, _ := kind.configure(u, "")
			obsConfigure(t, root, "", append([]map[string]any{obsWatch("client", client.process)}, added...), nil, nil)

			printed, _ := exec.Command(binary, "reload", c.path).CombinedOutput()
			if !strings.Contains(string(printed), u.refusal()) {
				t.Errorf("reload did not refuse naming %q:\n%s", u.refusal(), printed)
			}
			live, err := obsInspect(binary, c)
			if err != nil {
				t.Fatalf("the session no longer answers after the reload: %v\n%s", err, s.printed())
			}
			if slices.ContainsFunc(live.Processes, func(one attachment.Observed) bool { return one.PID == u.pid }) {
				t.Errorf("the reload granted capture to pid %d, whose arguments are undetermined", u.pid)
			}
			if printed, _, err := obsStop(t, binary, c, s); err != nil {
				t.Errorf("stopping the session failed: %v\n%s", err, printed)
			}
		})
	}
}
