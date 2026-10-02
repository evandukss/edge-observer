package processing_test

import (
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/processing"
)

// The callback is paused after capture assigned its fragment number. Retirement
// can therefore name more fragments than processing has received. The shared
// loss token already forbids content, so this delay must not hold its loss line.
type delayedLossInput struct {
	*intake.Store
	entered chan struct{}
	release chan struct{}
}

func (s *delayedLossInput) Write(r fragment.Record) error {
	if r.Sequence == 2 {
		close(s.entered)
		<-s.release
	}
	return s.Store.Write(r)
}

func TestIndependentGateLossRetirementIsWrittenBeforeDelayedInputAndFinish(t *testing.T) {
	f := cutLinesStarted(t, 4, 8)
	input := &delayedLossInput{Store: f.store, entered: make(chan struct{}), release: make(chan struct{})}
	f.capture = capture.Recording(input, f.store)
	var once sync.Once
	unblock := func() { once.Do(func() { close(input.release) }) }
	done := make(chan struct{})
	t.Cleanup(func() {
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("delayed callback did not leave its barrier")
		}
	})

	f.transfer(51, true)
	go func() {
		defer close(done)
		f.transfer(51, true)
	}()
	select {
	case <-input.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("wiring, not the property: second captured fragment never reached the delay barrier")
	}
	if f.store.Stats().Fragments != 1 || f.gate.Snapshot().Held != 2 {
		t.Fatal("wiring, not the property: one stored fragment and one in-flight reservation were not established")
	}
	unpress := f.pressure(2)
	f.transfer(51, false)
	f.reachedLoss(1)
	unpress()
	f.retire(51)
	if f.store.Stats().Connections != 1 || f.store.Stats().Queued != 2 || f.capture.Open() != 0 {
		t.Fatal("wiring, not the property: retirement did not reach intake beside the first fragment while the second was delayed")
	}
	select {
	case <-done:
		t.Fatal("wiring, not the property: the delayed callback escaped before retirement was drained")
	default:
	}

	f.drain(2, false)
	lines := 0
	for _, line := range f.output.artifacts {
		if line.Record == processing.ArtifactConnection && line.Connection.Handle.Address == "51" {
			lines++
		}
	}
	if lines != 1 {
		t.Errorf("ordinary retirement drain wrote %d loss lines, want one before delayed input or Finish", lines)
	}

	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("delayed callback did not complete after release")
	}
	out := f.drain(3, false)
	f.check(out, []uint64{51}, 0, 0)
}
