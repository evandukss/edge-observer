//go:build attach

package attach_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/evandukss/edge-observer/account"
	contract "github.com/evandukss/edge-observer/contract/account"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/internal/published"
	"github.com/evandukss/edge-observer/processing"
)

// t13Detached starts the observer detached over c and returns what the parent
// printed, the log as it stood the moment the parent exited, and the parent's
// pid. The log is read before anything else runs, so an activation found in it
// was written before the parent returned rather than while the test waited.
func t13Detached(t *testing.T, binary string, c configured, envelope *os.File, command string) ([]byte, []byte, int) {
	t.Helper()
	parent := exec.Command(binary, command, c.path)
	if command == "start" {
		parent.Args = append(parent.Args, "--daemonize")
	}
	parent.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(envelope.Fd())}
	output, err := parent.CombinedOutput()
	logged, _ := os.ReadFile(c.log)
	if err != nil {
		t.Fatalf("%s detached exited with %v:\n%s", command, err, output)
	}
	return output, logged, parent.Process.Pid
}

// t13Envelope opens the bounded envelope a test creates its detached commands
// into. It is made once per test because it is named after the test, so every
// command the test starts shares it.
func t13Envelope(t *testing.T) *os.File {
	t.Helper()
	held, err := os.Open(envelopeFor(t))
	if err != nil {
		t.Fatalf("open the observer's envelope: %v", err)
	}
	t.Cleanup(func() { _ = held.Close() })
	return held
}

// t13Sealed is the operational account a finished session sealed.
func t13Sealed(t *testing.T, c configured, session string) account.Account {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(c.sessions(), session, "account.json"))
	if err != nil {
		t.Fatalf("read session %s's sealed account: %v", session, err)
	}
	var sealed account.Account
	if err := json.Unmarshal(content, &sealed); err != nil {
		t.Fatalf("decode session %s's sealed account: %v", session, err)
	}
	return sealed
}

// A detached start exits zero only once its child has activated: the log
// already holds the child's activation when the parent has gone. The pid file
// names the child, which holds no capability, and an exchange that crosses
// after the parent exited is in what the session approved. Stop seals it.
func TestADetachedStartExitsZeroOnlyOnceItsChildActivatedAndTheChildGoesOnCapturing(t *testing.T) {
	binary := built(t)
	client := speaking(t, serving(t))
	c := configuring(t, target("under-test", client.process))
	envelope := t13Envelope(t)

	output, atExit, parent := t13Detached(t, binary, c, envelope, "start")
	pid, session := t13SessionOf(t, c)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })

	if running := runningWith(t, c.path); !slices.Contains(running, int32(pid)) {
		t.Fatalf("wiring, not the property: pid %d from the pid file is not a running process started over %s "+
			"(running: %v), so nothing below measures the detached child", pid, c.path, running)
	}

	// The property's first half, read off the log as it stood at the parent's exit.
	records := t13RecordsIn(atExit)
	activation := t13Find(records, "activation-completed", session)
	if activation < 0 {
		t.Errorf("when the parent exited zero the log held no activation for session %s, so it returned before its "+
			"child activated; the log held %d records", session, len(records))
	} else if records[activation].PID != pid {
		t.Errorf("session %s's activation names pid %d and the pid file names %d", session, records[activation].PID, pid)
	}
	if pid == parent {
		t.Errorf("the pid file names the parent, pid %d, which has exited", parent)
	}
	if !strings.Contains(string(output), session) {
		t.Errorf("the parent does not name the session it started:\n%s", output)
	}
	for _, field := range []string{"CapEff", "CapPrm"} {
		if capabilities := held(t, pid, field); strings.Trim(capabilities, "0") != "" {
			t.Errorf("the detached observer holds %s %s after activating", field, capabilities)
		}
	}

	// The parent has exited; this exchange crosses a session only the child holds.
	t13Exchange(t, client, "after-the-parent", "")
	stopped, err := exec.Command(binary, "stop", c.path).CombinedOutput()
	if err != nil {
		t.Fatalf("stop the detached observer: %v\n%s", err, stopped)
	}
	if !strings.HasPrefix(string(stopped), "stopped    session "+session+", sealed ") {
		t.Errorf("stop does not say it sealed session %s:\n%s", session, stopped)
	}
	if sealed := t13Sealed(t, c, session); sealed.Kind != account.Sealed || sealed.Session != session {
		t.Errorf("the detached session's account is a %s account of session %q", sealed.Kind, sealed.Session)
	}

	messages := t13Messages(t, filepath.Join(c.sessions(), session))
	if asked := t13Asked(messages, client.process.PID, "after-the-parent"); len(asked) != 1 {
		t.Errorf("the exchange sent after the parent exited is in the approved output %d times, want once; "+
			"the output retains %d messages", len(asked), len(messages))
	}
}

// A restart seals the first session before the second begins: the first's
// stopped record precedes the second's activation and its seal is no later than
// that activation. The second activation names the session it follows and the
// gap, and last-sealed.json names the first while the second runs.
func TestARestartSealsTheFirstSessionBeforeTheSecondBeginsAndTheSecondNamesIt(t *testing.T) {
	binary := built(t)
	client := speaking(t, serving(t))
	c := configuring(t, target("under-test", client.process))
	envelope := t13Envelope(t)

	t13Detached(t, binary, c, envelope, "start")
	firstPID, first := t13SessionOf(t, c)
	t.Cleanup(func() { _ = syscall.Kill(firstPID, syscall.SIGKILL) })
	t13Exchange(t, client, "first", "")

	output, _, _ := t13Detached(t, binary, c, envelope, "restart")
	secondPID, second := t13SessionOf(t, c)
	t.Cleanup(func() { _ = syscall.Kill(secondPID, syscall.SIGKILL) })
	if second == first {
		t.Fatalf("the restart left session %s in place:\n%s", first, output)
	}
	// Read while the second session runs, so it can only name the first.
	last, err := os.ReadFile(filepath.Join(c.directory, "last-sealed.json"))
	if err != nil {
		t.Fatalf("read last-sealed.json while the second session runs: %v", err)
	}

	sealed := t13Sealed(t, c, first)
	if asked := t13Asked(t13Messages(t, filepath.Join(c.sessions(), first)), client.process.PID, "first"); len(asked) != 1 {
		t.Fatalf("wiring, not the property: the first session's approved output holds the exchange it saw %d "+
			"times, so it is not a session that observed anything", len(asked))
	}

	records := t13Logged(t, c)
	stopped := t13Find(records, "stopped", first)
	activation := t13Find(records, "activation-completed", second)
	switch {
	case stopped < 0 || activation < 0:
		t.Fatalf("the log holds the first session's stopped record at %d and the second's activation at %d of %d",
			stopped, activation, len(records))
	case stopped > activation:
		t.Errorf("the second session activated (record %d) before the first recorded its stop (record %d)",
			activation, stopped)
	}
	if sealed.Seal == nil {
		t.Fatalf("the first session's account carries no seal: %s", sealed.SealError)
	}
	began := records[activation]
	if began.At.Before(sealed.Seal.Sealed) {
		t.Errorf("the second session activated at %s, before the first sealed at %s: the two overlap", began.At,
			sealed.Seal.Sealed)
	}
	switch follows := began.Follows; {
	case follows == nil:
		t.Errorf("the second session's activation names no session it follows")
	case follows.Session != first || follows.Gap == "" || !follows.Sealed.Equal(sealed.Seal.Sealed):
		t.Errorf("the second session's activation follows %+v, want session %s sealed at %s with the gap", *follows,
			first, sealed.Seal.Sealed)
	}

	var named struct {
		Session string `json:"session"`
	}
	if err := json.Unmarshal(last, &named); err != nil || named.Session != first {
		t.Errorf("last-sealed.json names %q (%v) while the second session runs, want the first, %s: %s",
			named.Session, err, first, last)
	}
	if out, err := exec.Command(binary, "stop", c.path).CombinedOutput(); err != nil {
		t.Fatalf("stop the second session: %v\n%s", err, out)
	}
}

// credential is an Authorization value a client sends.
const credential = "Bearer b7c1f4e09a2d"

// A finished session's contract account, bundled, passes the account
// contract's validator and carries none of the plaintext the session approved.
// The session seals no record in the record contracts, so the bundle's record
// members are empty and the account is what is validated.
func TestAFinishedSessionsContractAccountPassesTheValidatorAndCarriesNoPlaintext(t *testing.T) {
	binary := built(t)
	client := speaking(t, serving(t))
	c := configuring(t, target("under-test", client.process))

	observer := started(t, binary, c)
	t13Exchange(t, client, "t13-contract-marker", "Authorization: "+credential+"\r\n")
	ended(t, observer, c)
	directory := observer.directory(c)

	// The needles are what this session approved, so each is known to have crossed.
	messages := t13Asked(t13Messages(t, directory), client.process.PID, "t13-contract-marker")
	if len(messages) != 1 || !slices.Contains(messages[0].headers, credential) {
		t.Fatalf("wiring, not the property: the approved output holds %d requests carrying the marker, and the "+
			"credential in %v, so absence from the account below would measure nothing", len(messages), messages)
	}
	needles := []string{"t13-contract-marker", credential}
	for _, one := range t13Messages(t, directory) {
		for _, value := range one.headers {
			if len(value) >= 12 {
				needles = append(needles, value)
			}
		}
		if raw, err := base64.StdEncoding.DecodeString(one.body); err == nil && len(raw) >= 12 {
			needles = append(needles, one.body, string(raw))
		}
	}

	content, err := os.ReadFile(filepath.Join(directory, published.Name))
	if err != nil {
		t.Fatalf("read the sealed contract account: %v", err)
	}
	var sealed contract.Account
	if err := json.Unmarshal(content, &sealed); err != nil {
		t.Fatalf("decode the sealed contract account: %v", err)
	}
	if sealed.Moment != contract.Sealed || sealed.Session != observer.session {
		t.Fatalf("the contract account beside session %s is a %s account of session %s", observer.session,
			sealed.Moment, sealed.Session)
	}

	checked := 0
	for _, needle := range needles {
		checked++
		if bytes.Contains(content, []byte(needle)) {
			t.Errorf("the contract account carries %q, which the session approved as plaintext", needle)
		}
	}
	for _, member := range []string{`"headers"`, `"body"`, `"start_line"`, `"kept"`} {
		if bytes.Contains(content, []byte(member)) {
			t.Errorf("the contract account carries a %s member", member)
		}
	}
	t.Logf("the contract account is %d bytes; %d plaintext needles were looked for in it", len(content), checked)

	files, err := contract.Bundle(sealed, contract.Records{Reassembly: record.Reassembly{
		Record: record.KindReassembly, Version: record.Version,
		Discards: []record.Discard{}, Duplicates: []record.Duplicate{},
	}})
	if err != nil {
		t.Fatalf("bundle the sealed contract account: %v", err)
	}
	root := t.TempDir()
	for path, member := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, path), member, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result := contract.Validate(os.DirFS(root))
	if result.Outcome != contract.Validated || result.Examined.Members != len(contract.Roles) || result.Examined.Blocks == 0 {
		t.Errorf("the validator answers %s over %s for the session's contract account, examining %+v: %+v",
			result.Outcome, result.Validated, result.Examined, result.Findings)
	}
}

// Only the approved process is captured, in both directions, beside an
// unapproved one exchanging at the same time. The session's directory holds
// exactly its named files while it runs and once it has sealed, and a run
// whose traffic finished seals complete.
func TestOnlyTheApprovedProcessIsCapturedInBothDirectionsAndTheDirectoriesHoldOnlyTheirFiles(t *testing.T) {
	binary := built(t)
	approved := speaking(t, serving(t))
	unapproved := speaking(t, serving(t))
	c := configuring(t, target("approved", approved.process))
	observer := started(t, binary, c)
	directory := observer.directory(c)

	if got, want := names(t, c.directory), []string{"observer.log", "observer.pid", "sessions"}; !slices.Equal(got, want) {
		t.Errorf("the observer's directory holds %v while the session runs, want %v", got, want)
	}
	if got, want := names(t, directory), []string{processing.ArtifactName}; !slices.Equal(got, want) {
		t.Errorf("the session's directory holds %v while it runs, want %v", got, want)
	}

	t13Exchange(t, approved, "t13-approved", "")
	t13Exchange(t, unapproved, "t13-unapproved", "")
	sealed := ended(t, observer, c)

	messages := t13Messages(t, directory)
	asked := t13Asked(messages, approved.process.PID, "t13-approved")
	if len(asked) != 1 {
		t.Fatalf("wiring, not the property: the approved process's own exchange is in the approved output %d "+
			"times, so an absence of the other's would measure nothing", len(asked))
	}
	directions := map[string]map[string]int{}
	for _, one := range messages {
		if one.pid != approved.process.PID {
			t.Errorf("the approved output retains a %s from pid %d, and only %d was approved (the unapproved "+
				"client is %d)", one.kind, one.pid, approved.process.PID, unapproved.process.PID)
			continue
		}
		if directions[one.kind] == nil {
			directions[one.kind] = map[string]int{}
		}
		directions[one.kind][one.direction]++
	}
	if len(t13Asked(messages, unapproved.process.PID, "t13-unapproved")) != 0 {
		t.Errorf("the unapproved process's exchange is in the approved output")
	}
	if directions["request"]["sent"] == 0 || directions["response"]["received"] == 0 {
		t.Errorf("the approved process's messages cross %v, want its requests sent and its responses received",
			directions)
	}

	if got, want := names(t, directory), []string{"account.json", processing.ArtifactName, published.Name}; !slices.Equal(got, want) {
		t.Errorf("the session's directory holds %v once it has sealed, want %v", got, want)
	}
	if got, want := names(t, c.directory), []string{"last-sealed.json", "observer.log", "observer.pid", "sessions"}; !slices.Equal(got, want) {
		t.Errorf("the observer's directory holds %v once the session has sealed, want %v", got, want)
	}
	if sealed.Seal == nil || !sealed.Seal.Complete {
		t.Errorf("a run whose traffic finished did not seal complete: %+v %s", sealed.Seal, sealed.SealError)
	}
}
