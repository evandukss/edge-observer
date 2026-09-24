package privilege_test

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/privilege"
)

const self = "/proc/self"

// Drop is exercised against the observer binary in the attach suite: the
// all-threads call refuses in a cgo program, and a test binary is one.

// The control: the check can find a listening socket.
func TestASocketThatIsListeningIsFound(t *testing.T) {
	if sockets, err := privilege.Listening(self); err != nil {
		t.Fatalf("Listening: %v", err)
	} else if len(sockets) != 0 {
		t.Fatalf("this process is already listening on %v", sockets)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	sockets, err := privilege.Listening(self)
	if err != nil {
		t.Fatalf("Listening: %v", err)
	}
	if len(sockets) != 1 {
		t.Fatalf("%d listening sockets found, want the one just opened: %v", len(sockets), sockets)
	}
	if sockets[0].Kind != "net/tcp" && sockets[0].Kind != "net/tcp6" {
		t.Errorf("the socket is reported as %q", sockets[0].Kind)
	}
	if sockets[0].Address == "" {
		t.Error("the socket is reported with no address")
	}
}

func TestAUnixSocketThatIsListeningIsFound(t *testing.T) {
	path := t.TempDir() + "/socket"

	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	sockets, err := privilege.Listening(self)
	if err != nil {
		t.Fatalf("Listening: %v", err)
	}
	var found bool
	for _, socket := range sockets {
		if socket.Kind == "net/unix" && strings.Contains(socket.Address, "socket") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a unix socket accepting connections is not among %v", sockets)
	}
}

// Effective is compared with the status file read independently.
func TestEffectiveIsWhatTheKernelWroteInTheProcessStatus(t *testing.T) {
	held, err := privilege.Effective(self)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}

	content, err := os.ReadFile(self + "/status")
	if err != nil {
		t.Fatalf("read the status: %v", err)
	}
	var written string
	for line := range strings.Lines(string(content)) {
		if name, value, found := strings.Cut(strings.TrimSpace(line), ":"); found && name == "CapEff" {
			written = strings.TrimSpace(value)
		}
	}
	if written == "" {
		t.Fatal("the kernel wrote no effective set for this process")
	}
	if got := strconv.FormatUint(held, 16); got != strings.TrimLeft(written, "0") && "0"+got != written {
		want, err := strconv.ParseUint(written, 16, 64)
		if err != nil {
			t.Fatalf("the kernel wrote %q: %v", written, err)
		}
		if held != want {
			t.Fatalf("Effective = %#x, and the kernel wrote %#x", held, want)
		}
	}
}
