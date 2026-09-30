//go:build attach

package attach_test

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/processing"
)

// The pack these cases enable, its name, and the values it and an edit of it
// mask the authorization header with.
const (
	maskingPack = "masking"
	byThePack   = "withheld-by-pack"
	byAnEdit    = "withheld-by-edit"
	credential  = "Bearer b7c1f4e09a2d"
)

// enabling writes c's configuration with these targets and these packs
// enabled, and installs the masking pack beside it.
func enabling(t *testing.T, c configured, packs []string, targets ...map[string]any) {
	t.Helper()
	c.rewrite(t, targets, nil)
	content, err := os.ReadFile(c.path)
	if err != nil {
		t.Fatalf("read %s: %v", c.path, err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("decode %s: %v", c.path, err)
	}
	document["packs"] = packs
	written, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("encode the configuration: %v", err)
	}
	if err := os.WriteFile(c.path, written, 0o600); err != nil {
		t.Fatalf("write %s: %v", c.path, err)
	}
	installPack(t, c, maskingPackBytes(t, byThePack))
}

// maskingPackBytes is the masking pack, masking the authorization header with
// value.
func maskingPackBytes(t *testing.T, value string) []byte {
	t.Helper()
	content, err := json.Marshal(map[string]any{"version": config.PackVersion, "name": maskingPack,
		"mask": map[string]any{"headers": map[string]any{"authorization": value}}})
	if err != nil {
		t.Fatalf("encode the masking pack: %v", err)
	}
	return content
}

// installPack places content as the masking pack beside c's configuration,
// replacing whatever is there.
func installPack(t *testing.T, c configured, content []byte) {
	t.Helper()
	directory := filepath.Join(filepath.Dir(c.path), "packs")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatalf("make %s: %v", directory, err)
	}
	if err := os.WriteFile(filepath.Join(directory, maskingPack+".json"), content, 0o600); err != nil {
		t.Fatalf("install the pack: %v", err)
	}
}

// sendCredential sends one request carrying the credential over the open
// connection and reads the whole response back, so the client has read every
// byte of the exchange before anything stops. The connection stays open.
//
// The server writes the headers and the body separately. A client stopped
// after the status line has not yet read the body, so the exchange the
// session captured is incomplete, and processing withholds it.
func sendCredential(t *testing.T, c conversation, marker string) {
	t.Helper()
	request := "GET /?asked=" + marker + " HTTP/1.1\r\nHost: localhost\r\nAuthorization: " + credential + "\r\n\r\n"
	if _, err := io.WriteString(c.send, request); err != nil {
		t.Fatalf("send a request: %v", err)
	}
	line, err := c.receive.ReadString('\n')
	if err != nil || !strings.Contains(line, "200") {
		t.Fatalf("the server answered %q, %v", line, err)
	}
	length := -1
	for {
		header, err := c.receive.ReadString('\n')
		if err != nil {
			t.Fatalf("read the response headers: %v", err)
		}
		if header == "\r\n" {
			break
		}
		if name, value, found := strings.Cut(header, ":"); found && strings.EqualFold(name, "content-length") {
			if length, err = strconv.Atoi(strings.TrimSpace(value)); err != nil {
				t.Fatalf("the response states a length of %q", value)
			}
		}
	}
	if length < 0 {
		t.Fatal("wiring, not the property: the response states no length, so its end cannot be read")
	}
	if _, err := io.ReadFull(c.receive, make([]byte, length)); err != nil {
		t.Fatalf("read the %d-byte response body: %v", length, err)
	}
}

// authorizationWritten is every authorization value the session wrote for the
// request carrying marker from pid, read from its approved output. sealed is the
// session's sealed account, quoted where the output holds no such request so
// the failure says what processing recorded.
func authorizationWritten(t *testing.T, directory string, sealed account.Account, pid int32, marker string) []string {
	t.Helper()
	var values []string
	requests := 0
	err := processing.ReadArtifacts(os.DirFS(directory), func(artifact processing.Artifact) error {
		if artifact.Reconstruction == nil || artifact.Connection.Process.PID != pid {
			return nil
		}
		for _, exchange := range artifact.Reconstruction.Exchanges {
			message := exchange.Request.Message
			if message == nil || !strings.Contains(message.Target, "asked="+marker) {
				continue
			}
			requests++
			for _, field := range message.Headers {
				if strings.EqualFold(field.Name, "authorization") {
					values = append(values, field.Value)
				}
			}
		}
		return nil
	})
	if err != nil || requests == 0 {
		processed, _ := json.Marshal(sealed.Processing)
		seal, _ := json.Marshal(sealed.Seal)
		t.Fatalf("wiring, not the property: the approved output of %s holds no request %s from pid %d (%v), so "+
			"nothing below measured what processing did to it; the session sealed processing %s, seal %s",
			directory, marker, pid, err, processed, seal)
	}
	return values
}

func onlyValue(t *testing.T, values []string, want, why string) {
	t.Helper()
	if len(values) == 0 || strings.Contains(strings.Join(values, ""), credential) {
		t.Fatalf("%s: the authorization values written are %q, where the credential must not survive", why, values)
	}
	for _, value := range values {
		if value != want {
			t.Errorf("%s: an authorization value written is %q, want %q; all: %q", why, value, want, values)
		}
	}
}

// Reload rereads every enabled pack in the running session, after it has given
// up its capabilities: a pack whose bytes changed on disk refuses the reload
// and leaves the generation and the plan in force, and the same bytes restored
// beside an added target reload.
func TestAReloadRereadsTheEnabledPackAfterTheCapabilitiesAreGone(t *testing.T) {
	binary := built(t)
	kept := speaking(t, serving(t))
	added := speaking(t, serving(t))
	c := configuring(t, target("kept", kept.process))
	enabling(t, c, []string{maskingPack}, target("kept", kept.process))
	observer := started(t, binary, c)
	if capabilities := held(t, observer.command.Process.Pid, "CapEff"); strings.Trim(capabilities, "0") != "" {
		t.Fatalf("wiring, not the property: the session holds %s, so a reread would not be one after the drop", capabilities)
	}
	before := inspected(t, binary, c)

	installPack(t, c, maskingPackBytes(t, byAnEdit))
	answer, err := reloaded(t, binary, c)
	if err == nil || answer.Outcome != "refused" || !strings.Contains(answer.Reason, "changes processing -") {
		t.Fatalf("a reload over an edited pack answered %+v with %v, want a refusal naming a processing change", answer, err)
	}
	after := inspected(t, binary, c)
	if after.Policy.Generation != before.Policy.Generation || after.Policy.Revision != before.Policy.Revision {
		t.Errorf("the refused reload moved the policy from %+v to %+v", before.Policy, after.Policy)
	}
	sendCredential(t, kept, "after-the-refusal")

	enabling(t, c, []string{maskingPack}, target("kept", kept.process), target("added", added.process))
	answer, err = reloaded(t, binary, c)
	if err != nil || answer.Outcome != "activated" || answer.Generation != before.Policy.Generation+1 {
		t.Fatalf("a reload adding a target beside the unchanged pack answered %+v with %v, want the next generation",
			answer, err)
	}

	sealed := ended(t, observer, c)
	onlyValue(t, authorizationWritten(t, observer.directory(c), sealed, kept.process.PID, "after-the-refusal"), byThePack,
		"after a refused reload over an edited pack")
}

// Stop and inspect of a running session read only where the session is, so a
// configuration that now enables a pack nobody installed still reaches it. The
// control is the same session with its configuration unchanged; the dry run
// beside each shows which of the two the program would refuse.
func TestStopAndInspectReachASessionWhoseConfigurationNamesAMissingPack(t *testing.T) {
	binary := built(t)
	for _, broken := range []bool{false, true} {
		name := map[bool]string{false: "configuration unchanged", true: "configuration names a missing pack"}[broken]
		t.Run(name, func(t *testing.T) {
			client := speaking(t, serving(t))
			c := configuring(t, target("under-test", client.process))
			enabling(t, c, []string{maskingPack}, target("under-test", client.process))
			detached := exec.Command(binary, "start", c.path, "--daemonize")
			intoEnvelope(t, detached)
			if out, err := detached.CombinedOutput(); err != nil {
				t.Fatalf("start detached: %v\n%s", err, out)
			}
			pid, session := sessionOf(t, c)
			t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })

			if broken {
				enabling(t, c, []string{maskingPack, "never-installed"}, target("under-test", client.process))
			}
			out, err := exec.Command(binary, "dry-run", c.path).CombinedOutput()
			refused := strings.Contains(string(out), "packs[1]: unknown_pack") &&
				strings.Contains(string(out), "never-installed.json")
			if broken != (err != nil && refused) {
				t.Fatalf("wiring, not the property: the dry run answered %v:\n%s", err, out)
			}

			answer, err := exec.Command(binary, "inspect", c.path).Output()
			if err != nil {
				var exited *exec.ExitError
				if errors.As(err, &exited) {
					t.Fatalf("inspect of the running session failed: %v\n%s", err, exited.Stderr)
				}
				t.Fatalf("inspect of the running session failed: %v", err)
			}
			var live account.Account
			if err := json.Unmarshal(answer, &live); err != nil || live.Session != session || live.Kind != account.Live {
				t.Fatalf("inspect answered %v, session %q kind %q, want session %s live", err, live.Session, live.Kind, session)
			}

			if out, err := exec.Command(binary, "stop", c.path).CombinedOutput(); err != nil {
				t.Fatalf("stop the running session: %v\n%s", err, out)
			}
			if _, err := os.Stat(filepath.Join(c.sessions(), session, "account.json")); err != nil {
				t.Errorf("the stopped session sealed no account: %v", err)
			}
		})
	}
}
