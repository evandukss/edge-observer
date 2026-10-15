//go:build linux

package process

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The stat and TCP contents come from the running kernel. PID directories are
// synthetic and stat's PID is adjusted to agree. Namespace, cgroup, descriptor
// ownership and liveness are not modelled; this fixture observes read starts.
func independentSnapshotTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range []string{"101", "202"} {
		dir := filepath.Join(root, pid)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		_, rest, ok := strings.Cut(string(stat), " ")
		if !ok {
			t.Fatal("wiring, not property: captured stat has no PID boundary")
		}
		for name, body := range map[string][]byte{"stat": []byte(pid + " " + rest), "cmdline": []byte(exe + "\x00")} {
			if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "net"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tcp", "tcp6"} {
		body, err := os.ReadFile(filepath.Join("/proc/net", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "net", name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func independentSnapshotWatch(t *testing.T, path string) func() bool {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Close(fd); err != nil {
			t.Error(err)
		}
	})
	if _, err := unix.InotifyAddWatch(fd, path, unix.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	return func() bool {
		buf := make([]byte, 4096)
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EAGAIN) {
			return false
		}
		if err != nil || n < unix.SizeofInotifyEvent {
			t.Fatalf("wiring, not property: cannot read inotify evidence: bytes=%d error=%v", n, err)
		}
		return true
	}
}

func independentSnapshotHold(t *testing.T, path string) (<-chan error, func(), <-chan error) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	reached := make(chan error, 1)
	finished := make(chan error, 1)
	release := make(chan struct{})
	var once sync.Once
	unhold := func() { once.Do(func() { close(release) }) }
	go func() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		reached <- err
		if err != nil {
			finished <- err
			return
		}
		<-release
		_, writeErr := f.Write(body)
		finished <- errors.Join(writeErr, f.Close())
	}()
	t.Cleanup(func() {
		unhold()
		// If the subject refused before opening the FIFO, unblock the writer too.
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			if err := unix.Close(fd); err != nil {
				t.Error(err)
			}
		}
	})
	return reached, unhold, finished
}

func TestIndependentSnapshotDeadlineStopsLaterReads(t *testing.T) {
	for _, boundary := range []string{"process", "listener"} {
		for _, expires := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/expired_%t", boundary, expires), func(t *testing.T) {
				root := independentSnapshotTree(t)
				held, later := filepath.Join(root, "101", "cmdline"), filepath.Join(root, "202", "stat")
				if boundary == "listener" {
					held, later = filepath.Join(root, "net", "tcp"), filepath.Join(root, "net", "tcp6")
				}
				opened := independentSnapshotWatch(t, later)
				reached, release, finished := independentSnapshotHold(t, held)
				deadline := time.Time{}
				if expires {
					deadline = time.Now().Add(250 * time.Millisecond)
				}
				type result struct {
					host Host
					err  error
				}
				done := make(chan result, 1)
				go func() {
					h, err := (Approval{Rules: []Rule{{Port: 8443}}}).readHost(root, deadline)
					done <- result{h, err}
				}()
				select {
				case err := <-reached:
					if err != nil {
						t.Fatalf("wiring, not property: held read not opened: %v", err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("wiring, not property: read never reached the hold")
				}
				if expires {
					if !time.Now().Before(deadline) {
						t.Fatal("wiring, not property: hold was not observed before expiry")
					}
					<-time.After(time.Until(deadline) + 5*time.Millisecond)
				}
				select {
				case <-done:
					t.Fatal("wiring, not property: subject returned while its synchronous read was held")
				default:
				}
				release()
				select {
				case err := <-finished:
					if err != nil {
						t.Fatalf("wiring, not property: release failed: %v", err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("wiring, not property: held read did not release")
				}
				var got result
				select {
				case got = <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("wiring, not property: assembly did not return")
				}
				laterOpened := opened()
				if !expires {
					if got.err != nil || len(got.host.Table.All()) != 2 || !laterOpened {
						t.Fatalf("wiring, not property: free control failed: processes=%d later_open=%t error=%v", len(got.host.Table.All()), laterOpened, got.err)
					}
					return
				}
				t.Logf("REACHED held=%s before_deadline=true released_after_deadline=true later_open=%t", boundary, laterOpened)
				if laterOpened {
					t.Error("property: a later synchronous read started after assembly budget expired")
				}
				if got.err == nil {
					t.Error("property: assembly accepted an in-flight read that returned over budget")
				}
			})
		}
	}
}
