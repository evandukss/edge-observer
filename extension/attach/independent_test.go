//go:build attach

package attach_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/processing"
)

// Collected by the attach gate. This fixture drives an ordinary HTTPS
// client through the shipped observer; its cgroup is also the memory instrument.
const independentTLS = `
import http.server, ssl, sys
if sys.argv[1] == "server":
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        def log_message(self, *args): pass
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(sys.argv[2], sys.argv[3])
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(server.server_port, flush=True)
    server.serve_forever()

`

const independentClient = `
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return 3;
    puts("ready"); fflush(stdout);
    char path[256];
    while (fgets(path, sizeof(path), stdin)) {
        path[strcspn(path, "\r\n")] = 0;
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET;
        address.sin_port = htons(atoi(argv[1]));
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof(address))) return 4;
        SSL *ssl = SSL_new(ctx);
        if (!ssl || !SSL_set_fd(ssl,fd) || SSL_connect(ssl) != 1) return 5;
        char request[1024];
        int n = snprintf(request,sizeof(request),"GET /%s HTTP/1.1\r\nHost: localhost\r\nAuthorization: private-fixture-value\r\nX-Canary: public-fixture-value\r\nConnection: close\r\n\r\n",path);
        if (SSL_write(ssl,request,n) != n) return 6;
        char response[4096]; int used = 0, received;
        while ((received = SSL_read(ssl,response+used,sizeof(response)-1-used)) > 0) {
            used += received;
            if (used >= sizeof(response)-1) return 7;
        }
        response[used] = 0;
        if (!strstr(response,"200 OK") || used < 2 || strcmp(response+used-2,"ok")) return 8;
        SSL_free(ssl); close(fd);
        puts("completed"); fflush(stdout);
    }
    SSL_CTX_free(ctx);
    return 0;
}
`

type independentLive struct {
	observer                                       *exec.Cmd
	client                                         *exec.Cmd
	send                                           io.WriteCloser
	replies                                        *bufio.Reader
	config, dir, log, group, binary, audit, second string
	done                                           chan error
}

func independentBuild(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	build := func(name, pkg string) string {
		bin := filepath.Join(dir, name)
		cmd := exec.Command("go", "build", "-o", bin, pkg)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("wiring, not the property: build %s: %v: %s", pkg, err, out)
		}
		return bin
	}
	return build("observer", "github.com/evandukss/edge-observer/cmd/observer"), build("broken-extension", "github.com/evandukss/edge-observer/internal/cmd/broken-extension")
}

func independentWait(t *testing.T, why string, test func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if test() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s", why)
}

func independentLiveStart(t *testing.T, binary, peer, mode string, count int, two bool) *independentLive {
	t.Helper()
	f := &independentLive{dir: t.TempDir(), binary: binary, done: make(chan error, 1)}
	f.config = filepath.Join(f.dir, "config.json")
	f.log = filepath.Join(f.dir, "observer.log")
	f.audit = filepath.Join(f.dir, "received.jsonl")
	f.second = filepath.Join(f.dir, "second.jsonl")
	cert, key := filepath.Join(f.dir, "cert.pem"), filepath.Join(f.dir, "key.pem")
	if out, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost").CombinedOutput(); err != nil {
		t.Fatalf("wiring, not the property: certificate: %v %s", err, out)
	}
	script := filepath.Join(f.dir, "traffic.py")
	if err := os.WriteFile(script, []byte(independentTLS), 0600); err != nil {
		t.Fatal(err)
	}
	start := func(cmd *exec.Cmd) *bufio.Reader {
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return bufio.NewReader(out)
	}
	server := exec.Command("python3", script, "server", cert, key)
	serverOut := start(server)
	port, err := serverOut.ReadString('\n')
	if err != nil {
		t.Fatalf("wiring, not the property: server: %v", err)
	}
	clientSource := filepath.Join(f.dir, "client.c")
	clientBinary := filepath.Join(f.dir, "client")
	if err := os.WriteFile(clientSource, []byte(independentClient), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-o", clientBinary, clientSource, "-lssl", "-lcrypto").CombinedOutput(); err != nil {
		t.Fatalf("wiring, not the property: build TLS client: %v: %s", err, out)
	}
	f.client = exec.Command(clientBinary, strings.TrimSpace(port))
	f.send, err = f.client.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	f.replies = start(f.client)
	if ready, err := f.replies.ReadString('\n'); err != nil || ready != "ready\n" {
		t.Fatalf("wiring, not the property: client readiness %q %v", ready, err)
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", f.client.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	entries := []any{map[string]any{"name": "fault", "command": []string{peer, "--mode", mode, "--record", f.audit, "--count", strconv.Itoa(count)}, "fields": []string{"request.line", "request.headers"}, "timeout_ms": 1000}}
	if two {
		entries = append(entries, map[string]any{"name": "second", "command": []string{peer, "--mode", "record", "--record", f.second}, "fields": []string{"request.line"}, "timeout_ms": 1000})
	}
	document := map[string]any{"version": "observer.config/1", "output": filepath.Join(f.dir, "state"), "log": f.log, "watch": []any{map[string]any{"name": "client", "exe": exe, "args": f.client.Args[1:]}}, "extensions": entries, "remove": map[string]any{"headers": []string{"authorization"}}, "limits": map[string]any{"state_every_seconds": 1}, "libraries": []any{}}
	b, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.config, b, 0600); err != nil {
		t.Fatal(err)
	}
	f.group = filepath.Join("/sys/fs/cgroup", fmt.Sprintf("extension-independent-%d-%d", os.Getpid(), time.Now().UnixNano()))
	if err := os.Mkdir(f.group, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Join(f.group, "cgroup.kill"), []byte("1"), 0600)
		_ = os.Remove(f.group)
	})
	for name, value := range map[string]string{"memory.max": "536870912", "memory.swap.max": "0"} {
		if err := os.WriteFile(filepath.Join(f.group, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	held, err := os.Open(f.group)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	f.observer = exec.Command(binary, "start", f.config)
	f.observer.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(held.Fd())}
	stderr, err := os.Create(filepath.Join(f.dir, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stderr.Close() })
	f.observer.Stderr = stderr
	if err := f.observer.Start(); err != nil {
		t.Fatalf("wiring, not the property: start observer: %v", err)
	}
	go func() { f.done <- f.observer.Wait() }()
	t.Cleanup(func() { _ = f.observer.Process.Kill() })
	independentWait(t, "wiring, not the property: observer did not activate", func() bool {
		b, _ := os.ReadFile(f.log)
		return bytes.Contains(b, []byte(`"record":"activation-completed"`))
	})
	independentWait(t, "wiring, not the property: extension did not answer ready", func() bool { return independentReady(f.audit) > 0 })
	if two {
		independentWait(t, "wiring, not the property: second extension did not answer ready", func() bool { return independentReady(f.second) > 0 })
	}
	t.Cleanup(func() {
		if t.Failed() {
			select {
			case err := <-f.done:
				t.Logf("observer exited: %v", err)
			default:
				t.Log("observer has not exited")
			}
			paths := []string{f.log, f.audit, f.second, filepath.Join(f.dir, "stderr"), filepath.Join(f.group, "memory.events"), filepath.Join(f.group, "memory.peak")}
			accounts, _ := filepath.Glob(filepath.Join(f.dir, "state", "sessions", "*", "account.json"))
			paths = append(paths, accounts...)
			for _, path := range paths {
				b, err := os.ReadFile(path)
				if err == nil {
					if len(b) > 24000 {
						b = b[len(b)-24000:]
					}
					t.Logf("diagnostic %s: %s", filepath.Base(path), b)
				}
			}
		}
	})
	return f
}

func independentMessages(path string) []map[string]any {
	b, _ := os.ReadFile(path)
	var result []map[string]any
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		var m map[string]any
		if json.Unmarshal(line, &m) == nil {
			result = append(result, m)
		}
	}
	return result
}

func independentReady(path string) int {
	n := 0
	for _, m := range independentMessages(path) {
		if sent, ok := m["sent"].(map[string]any); ok && sent["type"] == "ready" {
			n++
		}
	}
	return n
}
func independentPIDs(path string) []int {
	var result []int
	for _, m := range independentMessages(path) {
		if p, ok := m["process"].(float64); ok {
			result = append(result, int(p))
		}
	}
	return result
}
func independentChildren(path string) []int {
	var result []int
	for _, m := range independentMessages(path) {
		if p, ok := m["descendant"].(float64); ok {
			result = append(result, int(p))
		}
	}
	return result
}
func independentAlive(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	_, tail, ok := strings.Cut(string(b), ") ")
	return ok && !strings.HasPrefix(tail, "Z ")
}

func (f *independentLive) request(t *testing.T, label string) {
	t.Helper()
	if _, err := fmt.Fprintln(f.send, label); err != nil {
		t.Fatal(err)
	}
	answer := make(chan string, 1)
	go func() { line, _ := f.replies.ReadString('\n'); answer <- line }()
	select {
	case line := <-answer:
		if line != "completed\n" {
			t.Fatalf("application did not complete: %q", line)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("application stalled")
	}
}

func (f *independentLive) inspect(t *testing.T) account.Account {
	t.Helper()
	out, err := exec.Command(f.binary, "inspect", f.config).Output()
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	var a account.Account
	if err := json.Unmarshal(out, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *independentLive) stop(t *testing.T) account.Account {
	t.Helper()
	if err := f.observer.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-f.done:
		if err != nil {
			t.Fatalf("orderly stop: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("shutdown exceeded its bound")
	}
	paths, err := filepath.Glob(filepath.Join(f.dir, "state", "sessions", "*", "account.json"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("wiring, not the property: sealed account paths=%v err=%v", paths, err)
	}
	b, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	var a account.Account
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestIndependentRestartedExtensionsHaveNoCapabilitiesOrInheritedFiles(t *testing.T) {
	binary, peer := independentBuild(t)
	f := independentLiveStart(t, binary, peer, "record", 3, true)
	f.request(t, "before-restart")
	independentWait(t, "wiring, not the property: first exchange never reached extension", func() bool {
		for _, m := range independentMessages(f.audit) {
			if m["type"] == "exchange" {
				return true
			}
		}
		return false
	})
	first := independentPIDs(f.audit)
	if len(first) != 1 {
		t.Fatal("wiring, not the property: no initial pid")
	}
	if err := syscall.Kill(first[0], syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	independentWait(t, "extension did not restart after kill", func() bool { return independentReady(f.audit) >= 2 })
	f.request(t, "after-restart")
	pids := independentPIDs(f.audit)
	second := independentPIDs(f.second)
	if len(pids) < 2 || len(second) != 1 {
		t.Fatal("wiring, not the property: missing restarted/second generation")
	}
	parent := independentFDs(t, f.observer.Process.Pid)
	for _, name := range []string{"approved.jsonl", "derived-fault.jsonl", "derived-second.jsonl"} {
		present := false
		for _, target := range parent {
			if filepath.Base(target) == name {
				present = true
			}
		}
		if !present {
			t.Fatalf("wiring, not the property: observer does not hold %s during descriptor inspection", name)
		}
	}
	for _, pid := range []int{pids[len(pids)-1], second[0]} {
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			t.Fatalf("wiring, not the property: extension not running: %v", err)
		}
		values := map[string]string{}
		for _, line := range strings.Split(string(status), "\n") {
			k, v, ok := strings.Cut(line, ":")
			if ok {
				values[k] = strings.TrimSpace(v)
			}
		}
		for _, key := range []string{"CapPrm", "CapEff", "CapInh", "CapAmb"} {
			n, err := strconv.ParseUint(values[key], 16, 64)
			if err != nil || n != 0 {
				t.Errorf("pid %d %s=%s err=%v", pid, key, values[key], err)
			}
		}
		if values["NoNewPrivs"] != "1" {
			t.Errorf("pid %d NoNewPrivs=%s", pid, values["NoNewPrivs"])
		}
		for fd, target := range independentFDs(t, pid) {
			if fd > 2 {
				for _, p := range parent {
					if p == target && target != "anon_inode:[eventpoll]" && target != "anon_inode:[eventfd]" {
						t.Errorf("pid %d inherited observer fd %d: %s", pid, fd, target)
					}
				}
			}
		}
	}
	a, b := independentFDs(t, pids[len(pids)-1]), independentFDs(t, second[0])
	for _, x := range a {
		if strings.HasPrefix(x, "pipe:") {
			for _, y := range b {
				if x == y {
					t.Errorf("extensions share pipe %s", x)
				}
			}
		}
	}
	sealed := f.stop(t)
	if sealed.Processing == nil || len(sealed.Processing.Extensions) != 2 {
		t.Fatal("wiring, not the property: no extension counts")
	}
	c := sealed.Processing.Extensions[0]
	if c.Restarts < 1 || c.StateResets < 1 {
		t.Errorf("restart/reset uncounted: %+v", c)
	}
}

func independentFDs(t *testing.T, pid int) map[int]string {
	t.Helper()
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	result := map[int]string{}
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		target, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err == nil {
			result[n] = target
		}
	}
	return result
}

func TestIndependentExtensionDescendantsEndOnRetirementAndShutdown(t *testing.T) {
	binary, peer := independentBuild(t)
	for _, retire := range []bool{false, true} {
		t.Run(strconv.FormatBool(retire), func(t *testing.T) {
			f := independentLiveStart(t, binary, peer, "descendant", 3, false)
			children := independentChildren(f.audit)
			pids := independentPIDs(f.audit)
			if len(children) != 1 || !independentAlive(children[0]) {
				t.Fatal("wiring, not the property: no living descendant holding stdout")
			}
			if retire {
				if err := syscall.Kill(pids[0], syscall.SIGKILL); err != nil {
					t.Fatal(err)
				}
				independentWait(t, "descendant survived generation retirement", func() bool { return !independentAlive(children[0]) })
				independentWait(t, "extension did not restart after retirement", func() bool { return independentReady(f.audit) >= 2 })
			}
			f.stop(t)
			for _, pid := range append(independentPIDs(f.audit), independentChildren(f.audit)...) {
				if independentAlive(pid) {
					t.Errorf("extension/descendant %d survived orderly shutdown", pid)
				}
			}
		})
	}
}

func TestIndependentExtensionDiesWithObserver(t *testing.T) {
	binary, peer := independentBuild(t)
	// This peer stops reading after ready, so EOF cannot make it exit on its own.
	f := independentLiveStart(t, binary, peer, "blocked-stdin", 3, false)
	pids := independentPIDs(f.audit)
	if len(pids) != 1 || !independentAlive(pids[0]) {
		t.Fatal("wiring, not the property: extension was never alive")
	}
	if err := f.observer.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	independentWait(t, "extension survived observer death", func() bool { return !independentAlive(pids[0]) })
}

func TestIndependentExtensionFloodsKeepCaptureAndMemoryBounded(t *testing.T) {
	binary, peer := independentBuild(t)
	for _, mode := range []string{"stderr-flood", "derived-flood"} {
		t.Run(mode, func(t *testing.T) {
			var peaks []int64
			for _, size := range []int{2000, 20000} {
				t.Run(strconv.Itoa(size), func(t *testing.T) {
					f := independentLiveStart(t, binary, peer, mode, size, false)
					f.request(t, "flood")
					independentWait(t, "wiring, not the property: flood exchange not received", func() bool {
						for _, m := range independentMessages(f.audit) {
							if m["type"] == "exchange" {
								return true
							}
						}
						return false
					})
					pids := independentPIDs(f.audit)
					if len(pids) != 1 {
						t.Fatalf("wiring, not the property: flood has %d peer generations before membership inspection", len(pids))
					}
					pid := pids[0]
					membership, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
					if err != nil || !bytes.Contains(membership, []byte("/"+filepath.Base(f.group)+"\n")) {
						t.Fatalf("wiring, not the property: flood peer %d is not in measured cgroup %s: %s (%v)", pid, f.group, membership, err)
					}
					members, err := os.ReadFile(filepath.Join(f.group, "cgroup.procs"))
					if err != nil {
						t.Fatal(err)
					}
					present := false
					for _, member := range strings.Fields(string(members)) {
						if member == strconv.Itoa(pid) {
							present = true
						}
					}
					if !present {
						t.Fatalf("wiring, not the property: measured cgroup omits live flood peer %d", pid)
					}
					t.Logf("flood %d peer %d membership %s", size, pid, bytes.TrimSpace(membership))
					before := f.inspect(t)
					if before.Seen == nil || before.Seen.Records == 0 {
						t.Fatal("wiring, not the property: capture never saw traffic")
					}
					f.request(t, "progress")
					independentWait(t, "capture did not advance during flood", func() bool { a := f.inspect(t); return a.Seen != nil && a.Seen.Records > before.Seen.Records })
					sealed := f.stop(t)
					if sealed.Processing == nil {
						t.Fatal("wiring, not the property: no processing account")
					}
					p := sealed.Processing
					if sealed.Session == "" || len(p.Extensions) != 1 {
						t.Fatal("wiring, not the property: missing session or extension population")
					}
					t.Logf("configured flood %d, final extension counts: %+v", size, p.Extensions[0])
					for _, c := range p.Extensions {
						if c.Considered != p.ExchangeIDs || c.Pending != 0 || c.Considered != c.Changed+c.Unchanged+c.Failed {
							t.Errorf("seal not conserved: %+v", c)
						}
					}
					b, err := os.ReadFile(filepath.Join(f.dir, "state", processing.ArtifactName))
					if err != nil {
						t.Fatalf("wiring, not the property: no approved file: %v", err)
					}
					if bytes.Contains(b, []byte("private-fixture-value")) {
						t.Error("removed content leaked")
					}
					if !bytes.Contains(b, []byte("public-fixture-value")) {
						t.Error("continued sanitized output absent")
					}
					var lines int
					for _, line := range bytes.Split(bytes.TrimSpace(b), []byte{'\n'}) {
						var a processing.Artifact
						if json.Unmarshal(line, &a) == nil && a.Reconstruction != nil {
							lines++
						}
					}
					if lines < 2 {
						t.Errorf("other connection did not reach output: %d", lines)
					}
					peak, err := os.ReadFile(filepath.Join(f.group, "memory.peak"))
					if err != nil {
						t.Fatal(err)
					}
					n, err := strconv.ParseInt(strings.TrimSpace(string(peak)), 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					peaks = append(peaks, n)
					t.Logf("flood size %d memory.peak %d", size, n)
					if mode == "stderr-flood" {
						logged, err := os.ReadFile(f.log)
						if err != nil {
							t.Fatal(err)
						}
						var records int
						for _, line := range bytes.Split(logged, []byte{'\n'}) {
							var m map[string]any
							if json.Unmarshal(line, &m) == nil && m["record"] == "extension-stderr" {
								records++
								if m["extension"] != "fault" || m["generation"] == nil || m["session"] != sealed.Session || m["cut"] != true {
									t.Errorf("stderr record attribution/cut: %s", line)
								}
							}
						}
						if records == 0 {
							t.Error("no extension-stderr log record")
						}
					}
				})
			}
			if len(peaks) != 2 {
				t.Fatal("wiring, not the property: missing flood measurements")
			}
			if peaks[1] > peaks[0]+32<<20 {
				t.Errorf("10x flood grew memory beyond fixed 32MiB slack: %v", peaks)
			}
		})
	}
}

func TestIndependentExtensionReasonsAreEscapedBoundedAndAttributed(t *testing.T) {
	binary, peer := independentBuild(t)
	f := independentLiveStart(t, binary, peer, "declined", 3, false)
	f.request(t, "declined")
	independentWait(t, "wiring, not the property: declined result never sent", func() bool {
		for _, m := range independentMessages(f.audit) {
			if sent, ok := m["sent"].(map[string]any); ok && sent["outcome"] == "failed" {
				return true
			}
		}
		return false
	})
	sealed := f.stop(t)
	if sealed.Session == "" || sealed.Processing == nil || len(sealed.Processing.Extensions) != 1 {
		t.Fatal("wiring, not the property: missing extension account")
	}
	if sealed.Processing.Extensions[0].FailedBy["declined"] != 1 {
		t.Errorf("declined result not counted: %+v", sealed.Processing.Extensions[0])
	}
	var reasons int
	for _, m := range independentMessages(f.log) {
		if m["record"] != "extension-reason" {
			continue
		}
		reasons++
		line, ok := m["line"].(string)
		retained, err := strconv.Unquote(`"` + line + `"`)
		if !ok || err != nil || len(retained) > 256 || strings.ContainsAny(line, "\x1b\t\r\n") || m["cut"] != true {
			t.Errorf("reason is not escaped and bounded: %+v", m)
		}
		if m["extension"] != "fault" || m["generation"] != "1" || m["session"] != sealed.Session || m["at"] == nil {
			t.Errorf("reason lacks attribution: %+v", m)
		}
	}
	if reasons != 1 {
		t.Errorf("extension-reason records=%d want 1", reasons)
	}
}
