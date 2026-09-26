//go:build attach

package attach_test

import (
	"strings"
	"syscall"
	"testing"
	"time"
)

// A TLS read already blocked when the probes are placed has no entry, and its
// return is never seen: the exchange it carries is lost. The account counts the
// thread that was inside socket I/O throughout placement, so that loss is
// counted rather than read as none, and prints it beside the seal where stop
// and inspect say the session sealed complete. A thread blocked throughout in a
// call that is not socket I/O is not counted, and its session prints no loss.
func TestAThreadInsideSocketIOWhileTheProbesArePlacedIsCountedAsUnderWay(t *testing.T) {
	binary := built(t)

	t.Run("blocked in a TLS read", func(t *testing.T) {
		server, port := forkingServer(t, "single")
		pid := int(server.PID)
		client := speaking(t, port)
		// Answered, so the handshake is done and the server is back in SSL_read.
		// After the handshake the fixture touches the connection only through the
		// TLS library, so a read of it is SSL_read's.
		t23Asking(t, client, "t23-before")

		var before t23Thread
		for range 200 {
			if before = t23Read(t, pid, pid); !before.running && before.number == syscall.SYS_READ {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if before.running || before.number != syscall.SYS_READ || !t23Socket(t, pid, before.fd) {
			t.Fatalf("wiring, not the property: the server's thread is %s, not blocked reading its connection, "+
				"so no TLS read is under way to be counted", before)
		}

		c := configuring(t, target("server", server))
		observer := started(t, binary, c)
		if after := t23Read(t, pid, pid); after != before {
			t.Fatalf("wiring, not the property: the server's thread was %s before activation and %s after, so it "+
				"ran while the probes were placed and the read it is in may have begun after them", before, after)
		}

		// The first request is what the blocked read returns; the second is read
		// by a call the probes see.
		t23Asking(t, client, "t23-second")
		t23Asking(t, client, "t23-third")
		live, liveText := t23Inspected(t, binary, c)
		stopped := t23Stopped(t, binary, c, observer)
		directory := observer.directory(c)
		sealed, sealedText := t23Sealed(t, binary, directory)

		if n := t23Retained(t, directory, server.PID, "t23-third"); n != 1 {
			t.Fatalf("wiring, not the property: the exchange after the lost one is retained %d times, want once, "+
				"so the connection was not captured at all and nothing below measures a single lost call", n)
		}
		t.Logf("the exchange the blocked read carried is retained %d times",
			t23Retained(t, directory, server.PID, "t23-second"))
		t.Logf("stop printed: %s", stopped)

		for _, one := range []struct {
			which string
			raw   []byte
			text  string
		}{{"live", live, liveText}, {"sealed", sealed, sealedText}} {
			under := t23UnderWay(t, one.which, one.raw)
			if under == nil {
				continue
			}
			if known, _ := under["known"].(bool); !known {
				t.Errorf("the %s account does not know whether a call was under way: %v", one.which, under["why"])
				continue
			}
			if threads, err := t23Whole(under["threads"]); err != nil || threads != 1 {
				t.Errorf("the %s account counts %v threads inside socket I/O while the probes were placed, want 1: %v",
					one.which, under["threads"], err)
			}
			if undetermined, err := t23Whole(under["undetermined"]); err != nil || undetermined != 0 {
				t.Errorf("the %s account counts %v threads that ran while the probes were placed, and the only "+
					"thread did not run: %v", one.which, under["undetermined"], err)
			}
			first, _ := under["first"].(map[string]any)
			for field, want := range map[string]int64{"pid": int64(pid), "tid": int64(pid), "fd": before.fd} {
				if got, err := t23Whole(first[field]); err != nil || got != want {
					t.Errorf("the %s account names the first thread's %s as %v, want %d: %v",
						one.which, field, first[field], want, err)
				}
			}
			if call, _ := first["call"].(string); call != "read" {
				t.Errorf("the %s account names the first thread's call as %v, want read", one.which, first["call"])
			}
			if line, count, ok := t23Line(one.text, "under way"); !ok || count != 1 {
				t.Errorf("the %s account as text says %q, want it to count 1 thread under way", one.which, line)
			}
		}

		// Where the session is said to have sealed complete, the loss is on that line.
		seal := t23Complete(t, stopped, sealedText)
		for which, line := range map[string]string{"stop": stopped, "inspect's seal line": seal} {
			if count, found := t23Lost(line); !found || count != 1 {
				t.Errorf("%s says the session sealed and does not count the 1 thread under way on the same line: %q",
					which, line)
			}
		}
	})

	t.Run("blocked in accept", func(t *testing.T) {
		server, port := forkingServer(t, "single")
		pid := int(server.PID)

		var before t23Thread
		for range 200 {
			if before = t23Read(t, pid, pid); !before.running &&
				(before.number == syscall.SYS_ACCEPT || before.number == syscall.SYS_ACCEPT4) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if before.running || (before.number != syscall.SYS_ACCEPT && before.number != syscall.SYS_ACCEPT4) {
			t.Fatalf("wiring, not the property: the server's thread is %s, not blocked in accept", before)
		}

		c := configuring(t, target("server", server))
		observer := started(t, binary, c)
		if after := t23Read(t, pid, pid); after != before {
			t.Fatalf("wiring, not the property: the server's thread was %s before activation and %s after, so "+
				"it was not blocked throughout, and a zero below would not show that a blocked call outside socket "+
				"I/O is left uncounted", before, after)
		}

		client := speaking(t, port)
		t23Asking(t, client, "t23-control")
		live, liveText := t23Inspected(t, binary, c)
		stopped := t23Stopped(t, binary, c, observer)
		directory := observer.directory(c)
		sealed, sealedText := t23Sealed(t, binary, directory)

		if n := t23Retained(t, directory, server.PID, "t23-control"); n != 1 {
			t.Fatalf("wiring, not the property: the control exchange is retained %d times, want once, so the "+
				"session did not capture and its zero would say nothing", n)
		}
		t.Logf("stop printed: %s", stopped)

		for _, one := range []struct {
			which string
			raw   []byte
			text  string
		}{{"live", live, liveText}, {"sealed", sealed, sealedText}} {
			under := t23UnderWay(t, one.which, one.raw)
			if under == nil {
				continue
			}
			if known, _ := under["known"].(bool); !known {
				t.Errorf("the %s account does not know whether a call was under way: %v", one.which, under["why"])
				continue
			}
			for _, count := range []string{"threads", "undetermined"} {
				if n, err := t23Whole(under[count]); err != nil || n != 0 {
					t.Errorf("the %s account counts %v %s where the only thread was blocked in accept throughout, "+
						"want 0: %v", one.which, under[count], count, err)
				}
			}
			if line, count, ok := t23Line(one.text, "under way"); !ok || count != 0 {
				t.Errorf("the %s account as text says %q, want it to count 0 threads under way", one.which, line)
			}
		}

		seal := t23Complete(t, stopped, sealedText)
		for which, line := range map[string]string{"stop": stopped, "inspect's seal line": seal} {
			if strings.Contains(line, "LOST") {
				t.Errorf("%s prints a loss for a session that lost nothing: %q", which, line)
			}
		}
	})
}
