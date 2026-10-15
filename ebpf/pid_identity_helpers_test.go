//go:build attach

package ebpf

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	cilium "github.com/cilium/ebpf"
	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/probe/openssl"
	"github.com/evandukss/edge-observer/process"
	"golang.org/x/sys/unix"
)

// The observer and the fixture share this private namespace. The parent test
// reads the child's exit status, so a namespace or fixture failure cannot skip.
func pidIdentityNamespace(t *testing.T) bool {
	t.Helper()
	const marker = "OBSERVER_PID_IDENTITY_NAMESPACE"
	if os.Getenv(marker) == "1" {
		if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
			t.Fatalf("wiring: private mounts: %v", err)
		}
		if err := unix.Mount("proc", "/proc", "proc", 0, ""); err != nil {
			t.Fatalf("wiring: namespace procfs: %v", err)
		}
		return true
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v", "-test.timeout=180s")
	cmd.Env = append(os.Environ(), marker+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWPID | unix.CLONE_NEWNS}
	out, err := cmd.CombinedOutput()
	t.Logf("private namespace output:\n%s", out)
	if err != nil {
		t.Fatalf("namespace case exited unsuccessfully: %v", err)
	}
	if !bytes.Contains(out, []byte("PID-IDENTITY-CASE-COMPLETE")) {
		t.Fatal("wiring: namespace subprocess did not complete its property assertions")
	}
	return false
}

type pidIdentityActor struct {
	input  io.WriteCloser
	output *bufio.Reader
	pid    int32
}

func pidIdentityStart(t *testing.T) *pidIdentityActor {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "process-fixture")
	out, err := exec.Command("cc", "-Wall", "-Wextra", "-Werror", "-O0", "-o", binary,
		"testdata/pid_identity.c", "-lssl", "-lcrypto").CombinedOutput()
	if err != nil {
		t.Fatalf("wiring: compile process fixture: %v\n%s", err, out)
	}
	cmd := exec.Command(binary)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	a := &pidIdentityActor{input: input, output: bufio.NewReader(output), pid: int32(cmd.Process.Pid)}
	t.Cleanup(func() {
		_ = input.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("wiring: process fixture cleanup: %v", err)
		}
	})
	if got := a.line(t); got != fmt.Sprintf("supervisor %d", a.pid) {
		t.Fatalf("wiring: supervisor identity %q", got)
	}
	return a
}

func (a *pidIdentityActor) line(t *testing.T) string {
	t.Helper()
	line, err := a.output.ReadString('\n')
	if err != nil {
		t.Fatalf("wiring: process response %q: %v", line, err)
	}
	return strings.TrimSuffix(line, "\n")
}

func (a *pidIdentityActor) command(t *testing.T, command string) string {
	t.Helper()
	if _, err := io.WriteString(a.input, command+"\n"); err != nil {
		t.Fatalf("wiring: command %q: %v", command, err)
	}
	return a.line(t)
}

func (a *pidIdentityActor) child(t *testing.T, command string) process.Process {
	t.Helper()
	line := a.command(t, command)
	text, ok := strings.CutPrefix(line, "child ")
	pid, err := strconv.ParseInt(text, 10, 32)
	if !ok || err != nil || pid <= 0 {
		t.Fatalf("wiring: child identity %q: %v", line, err)
	}
	return pidIdentityReadProcess(t, int32(pid))
}

func pidIdentityReadProcess(t *testing.T, pid int32) process.Process {
	t.Helper()
	table, err := process.Read("/proc")
	if err != nil {
		t.Fatalf("wiring: process table: %v", err)
	}
	p, found := table.Lookup(pid)
	if !found || !p.Start().Determined || !p.Namespace.Known() || p.NamespacePID != pid {
		t.Fatalf("wiring: process identity missing or outside shared namespace: found=%v process=%+v", found, p)
	}
	return p
}

func pidIdentityLiveSelection(p process.Process, number int, name string) admission.Selection {
	return admission.Selection{Instance: p.Instance(), ObserverPID: p.PID,
		Kind: admission.ByTarget, Mode: admission.ModeNone,
		Provenance: admission.Provenance{Target: name, Number: number}}
}

func pidIdentityPoints(t *testing.T, p process.Process) []Point {
	t.Helper()
	adapter := openssl.New()
	support := adapter.Inspect(p)
	if !support.Supported {
		t.Fatalf("wiring: process has no supported probes: %s", support.Reason)
	}
	points, discarded := PointsFrom(support.Probes, adapter.Runtime)
	if len(points) == 0 || len(discarded) != 0 {
		t.Fatalf("wiring: resolved points=%d discarded=%+v", len(points), discarded)
	}
	return points
}

func pidIdentityReuseGuard(t *testing.T, before, after process.Process) {
	t.Helper()
	if before.PID != after.PID || before.Namespace != after.Namespace || before.NamespacePID != after.NamespacePID ||
		!before.Start().Determined || !after.Start().Determined || before.Start() == after.Start() {
		t.Fatalf("wiring: one reuse attempt did not establish same namespace/pid with different births: before=%+v after=%+v", before, after)
	}
	t.Logf("actual reuse: namespace=%v pid=%d old_birth=%v new_birth=%v attempts=1", before.Namespace, before.PID, before.Start(), after.Start())
}

func pidIdentityMapSession(t *testing.T) (*Session, *cilium.Map) {
	t.Helper()
	// This is a constructed map, explicitly not a loaded producer program.
	allowed, err := cilium.NewMap(&cilium.MapSpec{Type: cilium.Hash,
		KeySize: uint32(binary.Size(instanceKey{})), ValueSize: uint32(binary.Size(admissionValue{})), MaxEntries: 8})
	if err != nil {
		t.Fatalf("wiring: create constructed allowlist: %v", err)
	}
	t.Cleanup(func() { _ = allowed.Close() })
	return &Session{collection: &cilium.Collection{Maps: map[string]*cilium.Map{"allowed_processes": allowed}}}, allowed
}

// pidIdentityTLSPeer is a TLS listener the fixture's children write to. It is
// Go's TLS, not OpenSSL, so the observer sees only the children's side.
func pidIdentityTLSPeer(t *testing.T) int {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("wiring: peer key: %v", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1),
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("wiring: peer certificate: %v", err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatalf("wiring: peer listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

// pidIdentityAwaitEnd reads delivered events until the execution end of one
// generation arrives. The reader calls endedAt before it delivers an Exited
// event, so its arrival here proves the retirement attempt already ran.
func pidIdentityAwaitEnd(t *testing.T, s *Session, pid int32, generation admission.Generation) {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case e, open := <-s.Events():
			if !open {
				t.Fatalf("wiring: event stream closed before the end of generation %d", generation)
			}
			if e.Kind == Exited && e.NamespacePID == pid && e.Generation == generation {
				t.Logf("wiring: execution end delivered: pid=%d generation=%d", pid, generation)
				return
			}
		case <-deadline:
			t.Fatalf("wiring: no execution end for pid %d generation %d within 20s", pid, generation)
		}
	}
}
