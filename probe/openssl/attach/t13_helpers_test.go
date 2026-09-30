//go:build attach

package attach_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/processing"
)

// t13Exchange sends one request naming marker over the open connection, with
// any extra header lines, and reads the whole response, so the client has read
// every byte of the exchange before the test goes on. Processing withholds an
// exchange it holds only part of, so an exchange the client did not finish is
// not one the session can be expected to write.
func t13Exchange(t *testing.T, c conversation, marker, headers string) {
	t.Helper()
	request := "GET /?asked=" + marker + " HTTP/1.1\r\nHost: localhost\r\n" + headers + "\r\n"
	if _, err := io.WriteString(c.send, request); err != nil {
		t.Fatalf("wiring, not the property: the client could not send request %s: %v", marker, err)
	}
	status, err := c.receive.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("wiring, not the property: request %s was answered %q (%v), so no exchange completed", marker,
			status, err)
	}
	length := -1
	for {
		header, err := c.receive.ReadString('\n')
		if err != nil {
			t.Fatalf("wiring, not the property: the response to %s ended inside its headers: %v", marker, err)
		}
		if header == "\r\n" {
			break
		}
		if name, value, found := strings.Cut(header, ":"); found && strings.EqualFold(name, "content-length") {
			if length, err = strconv.Atoi(strings.TrimSpace(value)); err != nil {
				t.Fatalf("wiring, not the property: the response to %s states a length of %q", marker, value)
			}
		}
	}
	if length < 0 {
		t.Fatalf("wiring, not the property: the response to %s states no length, so its end cannot be read", marker)
	}
	if _, err := io.ReadFull(c.receive, make([]byte, length)); err != nil {
		t.Fatalf("wiring, not the property: the client did not read the %d-byte body answering %s: %v", length,
			marker, err)
	}
}

// t13Message is one retained message of the approved output, as far as these
// cases read it.
type t13Message struct {
	pid        int32
	connection string
	target     string
	kind       string
	direction  string
	offset     int64
	end        int64
	headers    []string
	body       string
}

// t13Messages is every message the session's approved output retains, in file
// order, request before response within an exchange. A missing or empty output
// is an empty list, and the count is logged so a caller finding nothing can
// tell an empty output from one that holds other processes' messages.
func t13Messages(t *testing.T, directory string) []t13Message {
	t.Helper()
	var messages []t13Message
	err := processing.ReadArtifacts(os.DirFS(directory), func(artifact processing.Artifact) error {
		// Said per record, so a caller finding nothing can see what the output did hold.
		if truncated := artifact.ReconstructionTruncation; truncated != nil {
			t.Logf("approved %s record of pid %d connection %s is truncated: %+v", artifact.Route.Kind,
				artifact.Connection.Process.PID, artifact.Connection.ID, truncated.Stops)
		} else {
			t.Logf("approved %s record of pid %d connection %s", artifact.Route.Kind,
				artifact.Connection.Process.PID, artifact.Connection.ID)
		}
		if artifact.Reconstruction == nil {
			return nil
		}
		for _, exchange := range artifact.Reconstruction.Exchanges {
			target := ""
			if exchange.Request.Message != nil {
				target = exchange.Request.Message.Target
			}
			for _, message := range []*record.Message{exchange.Request.Message, exchange.Response.Message} {
				if message == nil {
					continue
				}
				offset, errOffset := strconv.ParseInt(message.Stream.Offset, 10, 64)
				end, errEnd := strconv.ParseInt(message.Stream.End, 10, 64)
				if errOffset != nil || errEnd != nil {
					return fmt.Errorf("a retained message's stream range is not two decimal offsets: %q %q",
						message.Stream.Offset, message.Stream.End)
				}
				one := t13Message{
					pid: artifact.Connection.Process.PID, connection: artifact.Connection.ID, target: target,
					kind: message.Kind, direction: message.Stream.Direction, offset: offset, end: end,
					body: message.Body.Kept,
				}
				for _, field := range message.Headers {
					one.headers = append(one.headers, field.Value)
				}
				messages = append(messages, one)
			}
		}
		return nil
	})
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, processing.ErrNoArtifacts):
	case err != nil:
		t.Fatalf("read the approved output of %s: %v", directory, err)
	}
	t.Logf("approved output of %s retains %d messages", filepath.Base(directory), len(messages))
	return messages
}

// t13Asked is the requests for marker among messages, from pid. The target is
// compared whole: a marker is a prefix of a longer one ("late" of
// "late-again"), so a substring match counts both.
func t13Asked(messages []t13Message, pid int32, marker string) []t13Message {
	var found []t13Message
	for _, one := range messages {
		if one.pid == pid && one.kind == "request" && one.target == "/?asked="+marker {
			found = append(found, one)
		}
	}
	return found
}

// t13SessionOf is the process and session the pid file names once a detached
// session has recorded itself there.
func t13SessionOf(t *testing.T, c configured) (int, string) {
	t.Helper()
	for range 200 {
		content, err := os.ReadFile(c.pidFile())
		if fields := strings.Fields(string(content)); err == nil && len(fields) == 2 {
			if pid, err := strconv.Atoi(fields[0]); err == nil {
				return pid, fields[1]
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the pid file %s names no running session", c.pidFile())
	return 0, ""
}

// t13Record is one line of the observer's log, as far as these cases read it.
type t13Record struct {
	Record   string    `json:"record"`
	Version  int       `json:"version"`
	Session  string    `json:"session"`
	PID      int       `json:"pid"`
	At       time.Time `json:"at"`
	Sealed   bool      `json:"sealed"`
	Complete bool      `json:"complete"`
	Follows  *struct {
		Session string    `json:"session"`
		Sealed  time.Time `json:"sealed"`
		Gap     string    `json:"gap"`
	} `json:"follows"`
}

// t13Logged is every record in the log, in the order written.
func t13Logged(t *testing.T, c configured) []t13Record {
	t.Helper()
	content, err := os.ReadFile(c.log)
	if err != nil {
		t.Fatalf("read the log %s: %v", c.log, err)
	}
	return t13RecordsIn(content)
}

func t13RecordsIn(content []byte) []t13Record {
	var records []t13Record
	for line := range strings.Lines(string(content)) {
		var one t13Record
		if json.Unmarshal([]byte(line), &one) == nil && one.Record != "" {
			records = append(records, one)
		}
	}
	return records
}

// t13Find is the position of the first record of this kind for session, or -1.
func t13Find(records []t13Record, kind, session string) int {
	return slices.IndexFunc(records, func(one t13Record) bool { return one.Record == kind && one.Session == session })
}
