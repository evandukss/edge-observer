//go:build attach

package ebpf_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
)

func TestAuthorisationExcludesAProcessInTheSameCgroup(t *testing.T) {
	approvedPID, approvedPort := serving(t)
	approved := loaded(t, approvedPID)
	unapprovedPID, unapprovedPort := serving(t)
	unapproved := loaded(t, unapprovedPID)

	shared := fmt.Sprintf("obs-same-cgroup-%d", os.Getpid())
	approvedCgroup := moveToCgroup(t, shared, approved.PID)
	unapprovedCgroup := moveToCgroup(t, shared, unapproved.PID)
	if approvedCgroup != unapprovedCgroup {
		t.Fatalf("the approved and unapproved processes are in cgroups %d and %d, so process authorisation was not measured",
			approvedCgroup, unapprovedCgroup)
	}

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  points(t, approved),
		Admit:   authorise(approved),
	})
	if err != nil {
		t.Fatalf("attach to approved pid %d: %v", approved.PID, err)
	}
	defer func() { _ = session.Close() }()

	unapprovedClient := speaking(t, unapprovedPort)
	unapprovedClient.ask(t, "/same-cgroup-unapproved")
	approvedClient := speaking(t, approvedPort)
	approvedClient.ask(t, "/same-cgroup-approved")

	got := drain(session, 700*time.Millisecond)
	var plaintext []string
	plaintext = append(plaintext, got.plaintext(fragment.Received)...)
	plaintext = append(plaintext, got.plaintext(fragment.Sent)...)
	if !containsSubstring(plaintext, "same-cgroup-approved") {
		t.Fatal("the approved process produced no plaintext in the same run, so exclusion of its cgroup peer would prove nothing")
	}
	for _, text := range plaintext {
		if strings.Contains(text, "same-cgroup-unapproved") {
			t.Errorf("plaintext from unapproved pid %d sharing the approved pid's cgroup was copied: %q",
				unapproved.PID, text)
		}
	}
}

func TestAuthorisationDoesNotFollowAReusedPID(t *testing.T) {
	approvedPID, approvedPort := serving(t)
	approved := loaded(t, approvedPID)
	replacementPID, replacementPort, childPID, childPort := servingFamily(t)
	replacement := loaded(t, replacementPID)
	child := loaded(t, childPID)
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", child.PID))
	if err != nil {
		t.Fatalf("read the live child's parent: %v", err)
	}
	if !strings.Contains(string(status), fmt.Sprintf("PPid:\t%d\n", replacement.PID)) {
		t.Fatalf("pid %d is not a live child of replacement pid %d", child.PID, replacement.PID)
	}
	if replacement.StartTime == 0 {
		t.Fatal("the replacement process has no start time, so PID reuse cannot be represented")
	}

	// This is the allowlist left by an earlier occupant of replacement.PID:
	// the number has been reused, while the process identity has not.
	stale := admit(replacement)
	stale.Instance.Start = admission.Determinate(admission.BootTicks(replacement.StartTime - 1))
	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  points(t, approved),
		Admit: []admission.Selection{
			admit(approved),
			stale,
		},
	})
	if err != nil {
		t.Fatalf("attach with one current and one stale process identity: %v", err)
	}
	defer func() { _ = session.Close() }()

	// Read each complete, distinct response before checking capture. In particular,
	// absence of the child's bytes is meaningful only if that child really moved them.
	familyRequest(t, childPort, "/pid-reuse-child")
	familyRequest(t, replacementPort, "/pid-reuse-replacement")
	familyRequest(t, approvedPort, "/pid-reuse-control")
	t.Logf("completed distinct TLS exchanges with control pid %d, replacement pid %d, and its pre-existing child pid %d",
		approved.PID, replacement.PID, child.PID)

	got := drain(session, 700*time.Millisecond)
	var plaintext []string
	plaintext = append(plaintext, got.plaintext(fragment.Received)...)
	plaintext = append(plaintext, got.plaintext(fragment.Sent)...)
	var controlObserved bool
	for _, event := range got.events {
		if event.Kind == ebpf.Transfer && event.PID == approved.PID &&
			bytes.Contains(event.Payload, []byte("pid-reuse-control")) {
			controlObserved = true
		}
	}
	if !controlObserved {
		t.Fatal("the process authorised with its current start time produced no plaintext, so the stale-identity refusal would prove nothing")
	}
	for _, text := range plaintext {
		if strings.Contains(text, "pid-reuse-replacement") {
			t.Errorf("plaintext from pid %d at start time %d was copied under an approval that named %s: %q",
				replacement.PID, replacement.StartTime, stale.Instance.Start, text)
		}
		if strings.Contains(text, "pid-reuse-child") {
			t.Errorf("plaintext from child pid %d of refused pid %d was copied under the parent's stale approval: %q",
				child.PID, replacement.PID, text)
		}
	}
}

// servingFamily starts two HTTPS servers with a real parent-child relationship.
// Both report readiness before Attach, and both stay alive through capture.
func servingFamily(t *testing.T) (parentPID int32, parentPort int, childPID int32, childPort int) {
	t.Helper()
	cert, key := certificate(t)
	script := filepath.Join(t.TempDir(), "family_server.py")
	const parent = `
import ssl, subprocess, sys
child = subprocess.Popen([sys.executable, sys.argv[4], "0", sys.argv[2], sys.argv[3]],
                         stdout=subprocess.PIPE, text=True)
ready = child.stdout.readline().strip()
if not ready.startswith("ready "):
    raise RuntimeError("child did not become ready: " + ready)
print("child", child.pid, ready.split()[1], flush=True)
exec(open(sys.argv[4]).read())
`
	// Let the kernel choose each port; the child already owns its port when the
	// parent binds, so the two listeners cannot race for the same free port.
	server := strings.Replace(tlsServer, `print("ready", flush=True)`,
		`print("ready", server.server_port, flush=True)`, 1)
	if err := os.WriteFile(script, []byte(server), 0o600); err != nil {
		t.Fatalf("write the family listener: %v", err)
	}
	command := exec.Command("python3", "-c", parent, "0", cert, key, script)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("family stdout: %v", err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start the family: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
	})
	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read child readiness: %v", err)
	}
	if _, err := fmt.Sscanf(line, "child %d %d", &childPID, &childPort); err != nil || childPID <= 0 || childPort <= 0 {
		t.Fatalf("child did not become ready: %q %v", line, err)
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read parent readiness: %v", err)
	}
	if _, err := fmt.Sscanf(line, "ready %d", &parentPort); err != nil || parentPort <= 0 {
		t.Fatalf("parent did not become ready: %q %v", line, err)
	}
	return int32(command.Process.Pid), parentPort, childPID, childPort
}

func familyRequest(t *testing.T, port int, path string) {
	t.Helper()
	c := speaking(t, port)
	if _, err := fmt.Fprintf(c.send, "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path); err != nil {
		t.Fatalf("send family request %s: %v", path, err)
	}
	response, err := http.ReadResponse(c.receive, nil)
	if err != nil {
		t.Fatalf("read family response %s: %v", path, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	want := "PLAINTEXT-RESPONSE-" + path
	if err != nil || response.StatusCode != http.StatusOK || string(body) != want {
		t.Fatalf("server on port %d did not transfer %q: status %d, body %q, error %v",
			port, want, response.StatusCode, body, err)
	}
}

const exactWriterSource = `
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int send_file(SSL_CTX *ctx, int port, const char *path) {
	FILE *file = fopen(path, "rb");
	if (file == NULL) return 1;
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	rewind(file);
	unsigned char *source = malloc((size_t)size);
	if (source == NULL || fread(source, 1, (size_t)size, file) != (size_t)size) return 2;
	fclose(file);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in address = {0};
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) return 3;

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);
	if (SSL_connect(ssl) != 1) return 4;
	int written = SSL_write(ssl, source, (int)size);
	printf("wrote %ld returned %d\n", size, written);
	fflush(stdout);
	SSL_free(ssl);
	close(fd);
	free(source);
	return written == size ? 0 : 5;
}

int main(int argc, char **argv) {
	if (argc != 4) return 10;
	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	printf("ready\n");
	fflush(stdout);
	char go[4];
	if (fgets(go, sizeof(go), stdin) == NULL) return 11;
	int status = send_file(ctx, atoi(argv[1]), argv[2]);
	if (status == 0) status = send_file(ctx, atoi(argv[1]), argv[3]);
	SSL_CTX_free(ctx);
	return status;
}
`

func exactRequest(size int) []byte {
	prefix := []byte("GET /size/1 HTTP/1.1\r\nHost: localhost\r\nX-Source: ")
	suffix := []byte("\r\nConnection: close\r\n\r\n")
	source := append([]byte(nil), prefix...)
	alphabet := []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	for len(source) < size-len(suffix) {
		source = append(source, alphabet[(len(source)-len(prefix))%len(alphabet)])
	}
	return append(source, suffix...)
}

func exactWriter(t *testing.T, port int, sources ...[]byte) (int32, func(), *bufio.Reader) {
	t.Helper()
	if len(sources) != 2 {
		t.Fatalf("exact writer needs two sources, got %d", len(sources))
	}

	directory := t.TempDir()
	paths := make([]string, len(sources))
	for i, source := range sources {
		paths[i] = filepath.Join(directory, fmt.Sprintf("source-%d", i))
		if err := os.WriteFile(paths[i], source, 0o600); err != nil {
			t.Fatalf("write source %d: %v", i, err)
		}
	}
	sourcePath := filepath.Join(directory, "exact_writer.c")
	if err := os.WriteFile(sourcePath, []byte(exactWriterSource), 0o600); err != nil {
		t.Fatalf("write exact writer source: %v", err)
	}
	binary := filepath.Join(directory, "exact_writer")
	if output, err := exec.Command("cc", "-O2", "-o", binary, sourcePath, "-lssl", "-lcrypto").CombinedOutput(); err != nil {
		t.Fatalf("compile exact writer: %v\n%s", err, output)
	}

	command := exec.Command(binary, fmt.Sprint(port), paths[0], paths[1])
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("exact writer stdin: %v", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("exact writer stdout: %v", err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start exact writer: %v", err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })

	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("exact writer did not become ready: %q %v", line, err)
	}
	return int32(command.Process.Pid), func() { _, _ = io.WriteString(stdin, "go\n") }, reader
}

func TestCapturedPayloadEqualsTheSourceAtAndBeyond4096Bytes(t *testing.T) {
	_, port := serving(t)
	sources := [][]byte{exactRequest(4096), exactRequest(4097)}
	pid, proceed, out := exactWriter(t, port, sources...)
	client := loaded(t, pid)
	moveToCgroup(t, fmt.Sprintf("obs-exact-%d", os.Getpid()), client.PID)

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  points(t, client),
		Admit:   authorise(client),
	})
	if err != nil {
		t.Fatalf("attach to exact writer: %v", err)
	}
	defer func() { _ = session.Close() }()

	proceed()
	for _, size := range []int{4096, 4097} {
		line, err := out.ReadString('\n')
		if err != nil {
			t.Fatalf("exact writer did not report its %d-byte call: %v", size, err)
		}
		if line != fmt.Sprintf("wrote %d returned %d\n", size, size) {
			t.Fatalf("the fixture did not make one exact %d-byte TLS call: %q", size, line)
		}
	}

	got := drain(session, 700*time.Millisecond)
	for i, source := range sources {
		want := source[:min(len(source), chunkForTest)]
		var matching []ebpf.Event
		for _, event := range got.events {
			if event.Kind == ebpf.Transfer && event.PID == client.PID &&
				event.Direction == fragment.Sent && int(event.Length) == len(source) {
				matching = append(matching, event)
			}
		}
		if len(matching) != 1 {
			t.Errorf("source %d (%d bytes) produced %d matching transfer events, want exactly one", i+1, len(source), len(matching))
			continue
		}
		if !bytes.Equal(matching[0].Payload, want) {
			at := 0
			for at < len(matching[0].Payload) && at < len(want) && matching[0].Payload[at] == want[at] {
				at++
			}
			if at < len(matching[0].Payload) && at < len(want) {
				t.Errorf("the captured bytes for the %d-byte call do not equal the source prefix: first mismatch at byte %d, got %#02x, want %#02x (captured %d, want %d)",
					len(source), at, matching[0].Payload[at], want[at], len(matching[0].Payload), len(want))
			} else {
				t.Errorf("the captured bytes for the %d-byte call do not equal the source prefix: captured %d bytes, want %d",
					len(source), len(matching[0].Payload), len(want))
			}
		}
	}
}

func TestAOneByteEventContainsNoResidueFromAPriorFullEvent(t *testing.T) {
	_, port := serving(t)
	full := bytes.Repeat([]byte{'R'}, chunkForTest)
	one := []byte{'Z'}
	pid, proceed, out := exactWriter(t, port, full, one)
	client := loaded(t, pid)
	moveToCgroup(t, fmt.Sprintf("obs-residue-%d", os.Getpid()), client.PID)

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  points(t, client),
		Admit:   authorise(client),
	})
	if err != nil {
		t.Fatalf("attach to the two-event writer: %v", err)
	}
	defer func() { _ = session.Close() }()

	proceed()
	for _, size := range []int{len(full), len(one)} {
		line, err := out.ReadString('\n')
		if err != nil {
			t.Fatalf("the fixture did not report its %d-byte control transfer: %v", size, err)
		}
		if line != fmt.Sprintf("wrote %d returned %d\n", size, size) {
			t.Fatalf("the fixture did not move its %d-byte control transfer: %q", size, line)
		}
	}

	got := drain(session, 700*time.Millisecond)
	var fullEvent, oneEvent *ebpf.Event
	for i := range got.events {
		event := &got.events[i]
		if event.Kind != ebpf.Transfer || event.PID != client.PID || event.Direction != fragment.Sent {
			continue
		}
		switch int(event.Length) {
		case len(full):
			fullEvent = event
		case len(one):
			oneEvent = event
		}
	}
	if fullEvent == nil || oneEvent == nil {
		t.Fatalf("the fixture moved a %d-byte event followed by a one-byte event, but capture reported full=%t one=%t",
			len(full), fullEvent != nil, oneEvent != nil)
	}
	if !bytes.Equal(fullEvent.Payload, full) {
		t.Errorf("the full control event contains bytes it did not copy from its source: got %d bytes beginning %q, want %d nonzero source bytes",
			len(fullEvent.Payload), fullEvent.Payload[:min(16, len(fullEvent.Payload))], len(full))
	}
	if !bytes.Equal(oneEvent.Payload, one) {
		t.Errorf("the one-byte event after a full event contains residue: got %d bytes %q, want exactly %q",
			len(oneEvent.Payload), oneEvent.Payload, one)
	}
}
