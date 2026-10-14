//go:build attach

package attach_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/processing"
)

// inflightThread is one reading of a thread: the system call it is inside, if any,
// and how many times it has been switched out. Two readings with the same call
// and the same switch count are a thread that never ran between them.
type inflightThread struct {
	running  bool
	number   int64
	fd       int64
	switches uint64
}

func (r inflightThread) String() string {
	if r.running {
		return fmt.Sprintf("running, %d switches", r.switches)
	}
	return fmt.Sprintf("in system call %d on descriptor %d, %d switches", r.number, r.fd, r.switches)
}

// inflightRead reads one thread of pid from /proc.
func inflightRead(t *testing.T, pid, tid int) inflightThread {
	t.Helper()
	task := filepath.Join(procfs, strconv.Itoa(pid), "task", strconv.Itoa(tid))

	content, err := os.ReadFile(filepath.Join(task, "syscall"))
	if err != nil {
		t.Fatalf("read the system call of pid %d thread %d: %v", pid, tid, err)
	}
	var reading inflightThread
	fields := strings.Fields(string(content))
	switch {
	case len(fields) == 1 && fields[0] == "running":
		reading.running = true
	case len(fields) >= 2:
		if reading.number, err = strconv.ParseInt(fields[0], 10, 64); err != nil {
			t.Fatalf("pid %d thread %d reports system call %q: %v", pid, tid, content, err)
		}
		if reading.fd, err = strconv.ParseInt(strings.TrimPrefix(fields[1], "0x"), 16, 64); err != nil {
			t.Fatalf("pid %d thread %d reports first argument %q: %v", pid, tid, content, err)
		}
	default:
		t.Fatalf("pid %d thread %d reports system call %q, which is no reading", pid, tid, content)
	}

	status, err := os.ReadFile(filepath.Join(task, "status"))
	if err != nil {
		t.Fatalf("read the status of pid %d thread %d: %v", pid, tid, err)
	}
	found := 0
	for line := range strings.Lines(string(status)) {
		name, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || (name != "voluntary_ctxt_switches" && name != "nonvoluntary_ctxt_switches") {
			continue
		}
		count, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			t.Fatalf("pid %d thread %d reports %s %q: %v", pid, tid, name, value, err)
		}
		reading.switches += count
		found++
	}
	if found != 2 {
		t.Fatalf("pid %d thread %d reports %d of the two switch counts", pid, tid, found)
	}
	return reading
}

// inflightSocket says whether pid's descriptor fd is a socket.
func inflightSocket(t *testing.T, pid int, fd int64) bool {
	t.Helper()
	target, err := os.Readlink(filepath.Join(procfs, strconv.Itoa(pid), "fd", strconv.FormatInt(fd, 10)))
	if err != nil {
		t.Fatalf("read descriptor %d of pid %d: %v", fd, pid, err)
	}
	return strings.HasPrefix(target, "socket:[")
}

// inflightAsking is one request over an open connection, read back to the end of
// its answer, so the next request starts on a clean stream. The target is
// what the approved output is searched for.
func inflightAsking(t *testing.T, c conversation, marker string) {
	t.Helper()
	if _, err := io.WriteString(c.send, "GET "+inflightTarget(marker)+" HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatalf("send %s: %v", marker, err)
	}
	status, err := c.receive.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("the answer to %s began %q: %v", marker, status, err)
	}
	length := -1
	for {
		line, err := c.receive.ReadString('\n')
		if err != nil {
			t.Fatalf("read the answer to %s: %v", marker, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(name, "Content-Length") {
			if length, err = strconv.Atoi(strings.TrimSpace(value)); err != nil {
				t.Fatalf("the answer to %s gives a length of %q", marker, value)
			}
		}
	}
	if length < 0 {
		t.Fatalf("the answer to %s gives no length", marker)
	}
	if _, err := io.ReadFull(c.receive, make([]byte, length)); err != nil {
		t.Fatalf("read the body of the answer to %s: %v", marker, err)
	}
}

func inflightTarget(marker string) string { return "/inf?asked=" + marker }

// inflightRetained is how many exchanges of pid the session approved whose request
// asked for exactly this marker's target.
func inflightRetained(t *testing.T, directory string, pid int32, marker string) int {
	t.Helper()
	file, err := os.Open(filepath.Join(directory, processing.ArtifactName))
	if errors.Is(err, fs.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatalf("read the approved output: %v", err)
	}
	defer func() { _ = file.Close() }()

	count := 0
	lines := bufio.NewScanner(file)
	lines.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for lines.Scan() {
		var artifact processing.Artifact
		if err := json.Unmarshal(lines.Bytes(), &artifact); err != nil {
			t.Fatalf("a sealed session's approved output holds a line that is not a record: %v", err)
		}
		if artifact.Connection.Process.PID != pid {
			continue
		}
		if artifact.ReconstructionTruncation != nil {
			t.Logf("approved record of pid %d is truncated: %+v", pid, artifact.ReconstructionTruncation.Stops)
		}
		if artifact.Reconstruction == nil {
			continue
		}
		for _, exchange := range artifact.Reconstruction.Exchanges {
			if message := exchange.Request.Message; message != nil && message.Target == inflightTarget(marker) {
				count++
			}
		}
	}
	if err := lines.Err(); err != nil {
		t.Fatalf("read the approved output: %v", err)
	}
	return count
}

// inflightUnderWay is the loss block's reading of calls under way when the probes
// were placed, from an account as JSON. Decoded without the account's own
// types, so an account that does not carry it says so rather than failing to
// compile.
func inflightUnderWay(t *testing.T, which string, raw []byte) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode the %s account: %v", which, err)
	}
	loss, ok := document["loss"].(map[string]any)
	if !ok {
		t.Fatalf("the %s account carries no loss block", which)
	}
	if known, _ := loss["known"].(bool); !known {
		t.Fatalf("the %s account's loss block is not known: %v", which, loss["why"])
	}
	under, ok := loss["under_way"].(map[string]any)
	if !ok {
		t.Errorf("the %s account's loss block does not say whether any call was under way when the probes "+
			"were placed; it carries %v", which, inflightKeys(loss))
		return nil
	}
	return under
}

func inflightKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// inflightWhole is a JSON number that is a whole number, or the reason it is not.
func inflightWhole(value any) (int64, error) {
	number, ok := value.(float64)
	if !ok || number != float64(int64(number)) {
		return 0, fmt.Errorf("%v is not a whole number", value)
	}
	return int64(number), nil
}

// inflightLine is the first rendered line starting with label, and the whole number
// that follows the label.
func inflightLine(text, label string) (string, int64, bool) {
	for line := range strings.Lines(text) {
		rest, found := strings.CutPrefix(line, label)
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return strings.TrimSpace(line), 0, false
		}
		count, err := strconv.ParseInt(fields[0], 10, 64)
		return strings.TrimSpace(line), count, err == nil
	}
	return "", 0, false
}

// inflightInspected is the running session's live account, as JSON and as text.
func inflightInspected(t *testing.T, binary string, c configured) ([]byte, string) {
	t.Helper()
	raw, err := exec.Command(binary, "inspect", c.path).Output()
	if err != nil {
		t.Fatalf("inspect the running session: %v", err)
	}
	text, err := exec.Command(binary, "inspect", c.path, "--text").Output()
	if err != nil {
		t.Fatalf("inspect the running session as text: %v", err)
	}
	return raw, string(text)
}

// inflightStopped ends the session through the stop command, as an operator does,
// and returns the line stop printed. The foreground process is then waited for.
func inflightStopped(t *testing.T, binary string, c configured, observer running) string {
	t.Helper()
	printed, err := exec.Command(binary, "stop", c.path).Output()
	if err != nil {
		t.Fatalf("stop the session: %v\n%s", err, printed)
	}
	for observer.lines.Scan() {
	}
	if err := observer.command.Wait(); err != nil {
		t.Fatalf("the observer exited with %v", err)
	}
	for line := range strings.Lines(string(printed)) {
		if strings.HasPrefix(line, "stopped ") {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("stop printed no line saying how the session ended:\n%s", printed)
	return ""
}

// inflightComplete is the seal line of an account's text, once stop and that line
// both say the session sealed complete: stop in words, the account by its
// complete form, which carries no INCOMPLETE and no NOT SEALED.
func inflightComplete(t *testing.T, stopped, text string) string {
	t.Helper()
	seal, _, _ := inflightLine(text, "sealed ")
	if !strings.Contains(stopped, "sealed complete") || seal == "" || strings.Contains(seal, "INCOMPLETE") ||
		strings.Contains(seal, "NOT SEALED") {
		t.Fatalf("wiring, not the property: the session did not seal complete (stop %q, seal line %q), so no line "+
			"below says it did", stopped, seal)
	}
	return seal
}

// inflightLost is the whole number of threads a line says were under way, from its
// LOST clause, or false where the line has no such clause.
func inflightLost(line string) (int64, bool) {
	_, clause, found := strings.Cut(line, "LOST ")
	if !found {
		return 0, false
	}
	before, _, found := strings.Cut(clause, " threads under way")
	if !found {
		return 0, false
	}
	fields := strings.Fields(before)
	if len(fields) == 0 {
		return 0, false
	}
	count, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
	return count, err == nil
}

// inflightSealed is a finished session's account, as the file it sealed and as
// inspect renders it.
func inflightSealed(t *testing.T, binary, directory string) ([]byte, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(directory, "account.json"))
	if err != nil {
		t.Fatalf("read the sealed account: %v", err)
	}
	text, err := exec.Command(binary, "inspect", directory, "--text").Output()
	if err != nil {
		t.Fatalf("inspect the sealed session as text: %v", err)
	}
	return raw, string(text)
}
