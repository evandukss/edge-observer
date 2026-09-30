package process

import "testing"

// The three shapes the kernel writes a task's system call in, and the two
// switch counts, read into what a thread was doing. The shape inside a call is
// captured, from a task blocked reading a pipe (arm64, where read is 63, on
// kernel 7.0.12), and repeated with its first argument set to 5 so a descriptor
// is read rather than assumed zero; the other two are constructed from the
// kernel's format (fs/proc/base.c, proc_pid_syscall).
func TestAThreadReadingSaysWhetherItIsInsideACallAndOnWhat(t *testing.T) {
	for content, want := range map[string]struct {
		inCall bool
		number int64
		first  int64
	}{
		"running\n":              {},
		"-1 0x7ffc1c2d 0x7f3a\n": {},
		"63 0x0 0xffff8f57f000 0x40000 0x0 0x0 0x0 0xffffce2be940 0xffff8f64263c\n": {inCall: true, number: 63},
		"63 0x5 0xffff8f57f000 0x40000 0x0 0x0 0x0 0xffffce2be940 0xffff8f64263c\n": {inCall: true, number: 63, first: 5},
	} {
		inCall, number, first, err := parseSyscall([]byte(content))
		if err != nil || inCall != want.inCall || number != want.number || first != want.first {
			t.Errorf("%q reads as in a call %v, number %d, first argument %d (%v); want %+v",
				content, inCall, number, first, err, want)
		}
	}
	for _, content := range []string{"", "63 0x5\n", "x 0x5 0x0 0x0 0x0 0x0 0x0 0x0 0x0\n"} {
		if _, _, _, err := parseSyscall([]byte(content)); err == nil {
			t.Errorf("%q reads as a system call", content)
		}
	}

	switches, err := parseSwitches([]byte("Name:\tserver\nvoluntary_ctxt_switches:\t40\nnonvoluntary_ctxt_switches:\t2\n"))
	if err != nil || switches != 42 {
		t.Errorf("the two switch counts add to %d (%v), want 42", switches, err)
	}
	if _, err := parseSwitches([]byte("voluntary_ctxt_switches:\t40\n")); err == nil {
		t.Error("one switch count alone reads as a total, and a task only preempted would read as still")
	}
}

// Two readings are of a task that did not run only where it is the same task,
// inside the same call on the same argument, and switched out no further.
func TestATaskIsStillOnlyWhereNothingAboutItMoved(t *testing.T) {
	first := Thread{TID: 10, Start: 100, InCall: true, Call: 63, FD: 5, Switches: 40}
	if !first.Still(first) {
		t.Fatal("wiring, not the property: a reading is not still against itself, so nothing below is measured")
	}
	for name, later := range map[string]Thread{
		"switched out once more": {TID: 10, Start: 100, InCall: true, Call: 63, FD: 5, Switches: 41},
		"another task, same tid": {TID: 10, Start: 101, InCall: true, Call: 63, FD: 5, Switches: 40},
		"another call":           {TID: 10, Start: 100, InCall: true, Call: 64, FD: 5, Switches: 40},
		"another descriptor":     {TID: 10, Start: 100, InCall: true, Call: 63, FD: 6, Switches: 40},
		"running":                {TID: 10, Start: 100, Switches: 40},
	} {
		if first.Still(later) {
			t.Errorf("a task %s reads as still", name)
		}
	}
}
