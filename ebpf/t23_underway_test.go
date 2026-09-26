package ebpf

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// One process's threads between the two readings: only a thread still in the
// same socket call on a socket is under way, and every thread that ran, started
// or reused a number is undetermined rather than none.
func TestOnlyAThreadStillInASocketCallIsUnderWayAndOneThatRanIsUndetermined(t *testing.T) {
	read := func(tid int32, start uint64, call int64, fd int64, switches uint64) process.Thread {
		return process.Thread{TID: tid, Start: start, InCall: true, Call: call, FD: fd, Switches: switches}
	}
	earlier := []process.Thread{
		read(10, 100, unix.SYS_READ, 5, 40),    // still in a socket read
		read(11, 100, unix.SYS_READ, 6, 40),    // ran, and is back in the same read
		read(12, 100, unix.SYS_ACCEPT4, 3, 40), // still in accept
		read(13, 100, unix.SYS_READ, 7, 40),    // still in a read of a file
		read(14, 100, unix.SYS_READ, 8, 40),    // its number is another thread's by the second reading
		read(15, 100, unix.SYS_WRITE, 9, 40),   // still in a write whose descriptor cannot be read
	}
	now := []process.Thread{
		read(16, 200, unix.SYS_READ, 5, 1), // started between the readings
		read(15, 100, unix.SYS_WRITE, 9, 40),
		read(14, 300, unix.SYS_READ, 8, 40),
		read(13, 100, unix.SYS_READ, 7, 40),
		read(12, 100, unix.SYS_ACCEPT4, 3, 40),
		read(11, 100, unix.SYS_READ, 6, 41),
		read(10, 100, unix.SYS_READ, 5, 40),
	}
	sockets := map[int64]bool{5: true, 6: true, 3: true, 8: true}
	socket := func(fd int64) (bool, error) {
		if fd == 9 {
			return false, errors.New("descriptor gone")
		}
		return sockets[fd], nil
	}

	under := probe.UnderWay{Known: true}
	unknown := tally(&under, 42, earlier, now, socket)

	if under.Threads != 1 {
		t.Errorf("%d threads under way, want the one still in its socket read", under.Threads)
	}
	if under.First == nil || *under.First != (probe.Blocked{PID: 42, TID: 10, FD: 5, Call: "read"}) {
		t.Errorf("the first thread under way is %+v, want pid 42 thread 10 in read on descriptor 5", under.First)
	}
	if under.Undetermined != 3 {
		t.Errorf("%d threads undetermined, want 3: the one that ran, the one that started and the reused number",
			under.Undetermined)
	}
	if len(unknown) != 1 || !strings.Contains(unknown[0], "thread 15 of pid 42") {
		t.Errorf("what could not be read is %q, want thread 15's descriptor named", unknown)
	}
}
