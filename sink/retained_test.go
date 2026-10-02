package sink

import "testing"

// Lines come and go, each written before the next is offered, past many times
// what the queue holds at once: the queue returns to holding nothing, and the
// array behind it keeps no more room than one line needed.
func TestChurnedLinesLeaveTheQueueHoldingNothing(t *testing.T) {
	const lines = 10000
	written := &controlledSink{}
	q := queueFor(t, written, 64)
	for i := 0; i < lines; i++ {
		if err := q.Enqueue("records", []byte("line\n")); err != nil {
			t.Fatalf("line %d refused: %v", i, err)
		}
		if err := q.Drain(timeout(t)); err != nil {
			t.Fatal(err)
		}
	}
	if stats := q.Stats(); stats.Written != lines {
		t.Fatalf("wiring, not the property: %d of %d lines written: %+v", stats.Written, lines, stats)
	}
	stores, err := q.Retained()
	if err != nil {
		t.Fatal(err)
	}
	for _, one := range stores {
		switch one.Store {
		case "sink.lines":
			if one.Held != 0 {
				t.Errorf("%d lines held after every line was written", one.Held)
			}
		case "sink.lines_capacity":
			if one.Held > 1 {
				t.Errorf("the queue keeps room for %d lines after %d came one at a time", one.Held, lines)
			}
		}
	}
}
