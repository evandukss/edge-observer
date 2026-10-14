//go:build attach

package attach_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/internal/published"
	"github.com/evandukss/edge-observer/processing"
)

// kernelUname is this host's kernel release as uname reports it: a second
// instrument beside the procfs file the observer reads.
func kernelUname(t *testing.T) string {
	t.Helper()
	var name unix.Utsname
	if err := unix.Uname(&name); err != nil {
		t.Fatalf("wiring, not the property: uname failed: %v", err)
	}
	release := unix.ByteSliceToString(name.Release[:])
	if release == "" {
		t.Fatal("wiring, not the property: uname reports no release, so no recorded one can be compared with it")
	}
	return release
}

// kernelLine is the one line of an inspection beginning with word.
func kernelLine(t *testing.T, text, word string) string {
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

// kernelNamed is the release a kernel line says the session ran on, parsed
// whole, or empty where the line names none.
func kernelNamed(line string) string {
	_, after, found := strings.Cut(line, "ran on kernel ")
	if !found {
		return ""
	}
	release, _, _ := strings.Cut(after, ",")
	return release
}

// kernelInspected is inspect --text over what, run from a directory holding no
// configuration.
func kernelInspected(t *testing.T, binary string, what ...string) string {
	t.Helper()
	command := exec.Command(binary, append(append([]string{"inspect"}, what...), "--text")...)
	command.Dir = t.TempDir()
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect %v as text: %v\n%s", what, err, out)
	}
	return string(out)
}

// kernelCopy copies a sealed session's account and approved output to a fresh
// directory, as somebody taking it to another host would, with the account's
// kernel member changed by change first.
func kernelCopy(t *testing.T, sessionDirectory string, change func(document map[string]json.RawMessage)) string {
	t.Helper()
	copied := t.TempDir()
	content, err := os.ReadFile(filepath.Join(sessionDirectory, "account.json"))
	if err != nil {
		t.Fatalf("read the sealed account: %v", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode the sealed account: %v", err)
	}
	if _, present := document["kernel"]; !present {
		t.Fatal("the sealed account carries no kernel member")
	}
	change(document)
	if content, err = json.Marshal(document); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copied, "account.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	approved, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(sessionDirectory)), processing.ArtifactName))
	if err != nil || len(approved) == 0 {
		t.Fatalf("wiring, not the property: the session's approved output is unreadable or empty (%v), so text "+
			"inspection of a copy cannot run", err)
	}
	if err := os.WriteFile(filepath.Join(copied, processing.ArtifactName), approved, 0o600); err != nil {
		t.Fatal(err)
	}
	return copied
}

// A session records the kernel it ran on when it activates, and inspection
// shows that recorded release beside the build's declared minimum, live and
// sealed. A copy whose recorded release is not this host's shows the recorded
// one and not this host's, and a copy whose account has no record says the
// session's kernel was not recorded.
func TestASessionRecordsItsKernelAndInspectionShowsTheRecordedOneRatherThanTheInspectingHosts(t *testing.T) {
	host := kernelUname(t)
	binary := built(t)
	client := speaking(t, serving(t))
	c := configuring(t, target("under-test", client.process))
	observer := started(t, binary, c)
	sessionExchange(t, client, "krn-recorded", "")

	live := inspected(t, binary, c)
	if live.Kind != account.Live || live.Session != observer.session {
		t.Fatalf("wiring, not the property: inspect answered a %s account of session %q, not the running "+
			"session %s", live.Kind, live.Session, observer.session)
	}
	if live.Kernel == nil || live.Kernel.Release != host || live.Kernel.Why != "" {
		t.Errorf("the live account records the kernel %+v, want release %s", live.Kernel, host)
	}
	floorAndKernel := func(moment, text string) {
		t.Helper()
		floor := kernelLine(t, text, "floor")
		if strings.Contains(floor, "UNPROVED") || !strings.Contains(floor, "kernel "+live.Floor.Published+" ") {
			t.Errorf("%s: the floor line reads %q, want the declared minimum %s and no UNPROVED", moment, floor,
				live.Floor.Published)
		}
		if got := kernelNamed(kernelLine(t, text, "kernel")); got != host {
			t.Errorf("%s: the kernel line names %q, want the session's %s", moment, got, host)
		}
	}
	liveText, err := exec.Command(binary, "inspect", c.path, "--text").Output()
	if err != nil {
		t.Fatalf("inspect the running session as text: %v", err)
	}
	floorAndKernel("live", string(liveText))

	sealed := ended(t, observer, c)
	if sealed.Kernel == nil || sealed.Kernel.Release != host || sealed.Kernel.Why != "" {
		t.Errorf("the sealed account records the kernel %+v, want release %s", sealed.Kernel, host)
	}
	content, err := os.ReadFile(filepath.Join(observer.directory(c), published.Name))
	if err != nil {
		t.Fatalf("read the published account: %v", err)
	}
	var projected struct {
		Provenance struct {
			Kernel *struct {
				State   string `json:"state"`
				Release string `json:"release"`
			} `json:"kernel"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(content, &projected); err != nil {
		t.Fatalf("decode the published account: %v", err)
	}
	if k := projected.Provenance.Kernel; k == nil || k.State != "carried" || k.Release != host {
		t.Errorf("the published account's provenance.kernel is %+v, want carried with release %s", k, host)
	}
	floorAndKernel("sealed", kernelInspected(t, binary, observer.directory(c)))

	// A copy inspected where the kernel differs: the recorded release is changed
	// rather than the host, which the inspection cannot tell apart.
	const elsewhere = "4.19.0-elsewhere"
	if elsewhere == host {
		t.Fatalf("wiring, not the property: this host's kernel is %s, the release planted to stand for another "+
			"host's", host)
	}
	moved := kernelCopy(t, observer.directory(c), func(document map[string]json.RawMessage) {
		document["kernel"] = json.RawMessage(`{"release":"` + elsewhere + `"}`)
	})
	movedLine := kernelLine(t, kernelInspected(t, binary, moved), "kernel")
	if got := kernelNamed(movedLine); got != elsewhere || strings.Contains(movedLine, host) {
		t.Errorf("a copy recording %s, inspected on %s, renders the kernel line %q", elsewhere, host, movedLine)
	}

	// A copy whose account predates the record.
	older := kernelCopy(t, observer.directory(c), func(document map[string]json.RawMessage) {
		delete(document, "kernel")
	})
	olderLine := kernelLine(t, kernelInspected(t, binary, older), "kernel")
	if !strings.Contains(olderLine, "not recorded") || kernelNamed(olderLine) != "" || strings.Contains(olderLine, host) {
		t.Errorf("a copy with no kernel record renders the kernel line %q, want the kernel was not recorded",
			olderLine)
	}
}
