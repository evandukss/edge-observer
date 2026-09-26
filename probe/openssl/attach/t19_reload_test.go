//go:build attach

package attach_test

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// t19Inserted is the target the reload puts first in the configuration, so the
// candidate numbers it 1 and the parent's target 2.
const t19Inserted = "t19-inserted"

// A child forked under the policy that admitted its parent, and first read
// after an additive reload that renumbers the targets, is credited to its
// parent's target and not to whichever target holds the parent's old number
// now. The child can make no TLS call before the reload: nothing listens on
// its port until afterwards, and its exchange fails at the connect, before
// any TLS call.
func TestT19AChildFirstReadAfterAReloadThatRenumbersTargetsIsCreditedToItsParentsTarget(t *testing.T) {
	binary := built(t)
	boot := thisBoot(t)
	witness := t.TempDir()
	port := free(t)

	a := rooted(t, port, "A", witness)
	_, inserted := looping(t, serving(t), "U", t.TempDir(), "loop")
	c := configuring(t, exactly(t19Target, a.root, boot, "follow"))
	observer := started(t, binary, c)
	child := a.child(t, "fork", "C")

	c.rewrite(t, []map[string]any{exactly(t19Inserted, inserted, boot, "none"),
		exactly(t19Target, a.root, boot, "follow")}, nil)
	answer, err := reloaded(t, binary, c)
	if err != nil || answer.Outcome != "activated" || !slices.Equal(answer.Added, []string{t19Inserted}) {
		t.Fatalf("wiring, not the property: the reload answered %+v with %v, want %q added and activated",
			answer, err, t19Inserted)
	}
	// The session keeps the parent's target under the number it resolved to at
	// the start and adds the new one under its number in the candidate, so both
	// read 1: one number now names two programs.
	live := inspected(t, binary, c)
	if first, second := named(live, t19Inserted).Number, named(live, t19Target).Number; first != 1 || second != 1 {
		t.Fatalf("wiring, not the property: after the reload %q is target %d and %q is target %d, want both 1, "+
			"so no number names two targets", t19Inserted, first, t19Target, second)
	}
	if !observes(live, inserted.PID) {
		t.Fatalf("wiring, not the property: the reload admitted nothing under %q (pid %d), so no grant written "+
			"after it holds the number the parent's target held before", t19Inserted, inserted.PID)
	}
	if got := witnessed(witness, "C", child.PID); got != 0 {
		t.Fatalf("wiring, not the property: the child pid %d completed %d exchanges before the reload, so its "+
			"first event may have been read under the old numbering", child.PID, got)
	}

	t19ServingOn(t, port)
	waitWitnessed(t, witness, map[string]int32{"C": child.PID}, map[string]int{"C": 0}, 3)
	sealed := ended(t, observer, c)

	if by := observedBy(t, observer.directory(c)); by[child.PID] == 0 {
		t.Fatalf("wiring, not the property: the approved output holds nothing for the child pid %d, so it was "+
			"not admitted or transferred nothing", child.PID)
	}
	if sealed.Admitted == nil || !sealed.Admitted.Known || sealed.Admitted.Descendants < 1 {
		t.Fatalf("wiring, not the property: the kernel reports no descendant admitted (%+v)", sealed.Admitted)
	}
	if sealed.Admissions == nil || sealed.Admissions.Unavailable != "" {
		t.Fatalf("wiring, not the property: the sealed account carries no admissions (%+v)", sealed.Admissions)
	}
	descendant, found := t19Listed(sealed.Admissions, child.PID)
	if !found {
		t.Fatalf("wiring, not the property: the child pid %d is not listed among the admissions whose coverage "+
			"ended or whose grant was unknown: %+v", child.PID, sealed.Admissions)
	}

	if descendant.Target != t19Target || !descendant.Inherited {
		t.Errorf("the child pid %d, forked under %q before the reload and read after it, is listed under %q with "+
			"inherited %v, want %q and true", child.PID, t19Target, descendant.Target, descendant.Inherited, t19Target)
	}
}

// t19ServingOn starts the HTTPS server on a port chosen beforehand, for a
// case that needs its clients running before anything listens.
func t19ServingOn(t *testing.T, port int) {
	t.Helper()
	certificate, key := certificate(t)
	script := filepath.Join(t.TempDir(), "server.py")
	if err := os.WriteFile(script, []byte(tlsServer), 0o600); err != nil {
		t.Fatalf("write the server: %v", err)
	}
	command := exec.Command("python3", script, fmt.Sprint(port), certificate, key, t.TempDir())
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start the server: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || !strings.HasPrefix(line, "ready") {
		t.Fatalf("the server on port %d did not come up: %q %v", port, line, err)
	}
}
