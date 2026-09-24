package capture

import (
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

type positionSink struct {
	session          *Session
	fragmentUnlocked []bool
	retirementLocked []bool
}

func (p *positionSink) Write(fragment.Record) error {
	unlocked := p.session.mutex.TryLock()
	if unlocked {
		p.session.mutex.Unlock()
	}
	p.fragmentUnlocked = append(p.fragmentUnlocked, unlocked)
	return nil
}

func (p *positionSink) Connection(connection.Record) error {
	unlocked := p.session.mutex.TryLock()
	if unlocked {
		p.session.mutex.Unlock()
	}
	p.retirementLocked = append(p.retirementLocked, !unlocked)
	return nil
}

func TestFragmentOutsideAndRetirementUnderCaptureMutex(t *testing.T) {
	sink := &positionSink{}
	s := Recording(sink, sink)
	sink.session = s
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	one := probe.Transfer{
		Process:  fragment.Process{PID: 42, StartTime: 3},
		Instance: admission.Instance{Namespace: admission.Namespace{Inode: 1}, PID: 42, Generation: 1},
		Endpoint: 7, Direction: fragment.Sent, Measured: true, Length: 1,
		Payload: []byte("x"), At: at, Stamp: 1,
	}
	s.Transfer(one)
	if len(sink.fragmentUnlocked) != 1 || !sink.fragmentUnlocked[0] {
		t.Fatal("fragment callback did not run outside capture mutex")
	}
	// Missing stamp 2 retires the already witnessed stream under the mutex.
	one.Stamp = 3
	s.Transfer(one)
	if st := s.Stats(); st.Transfers != 2 || st.Interrupted != 1 || st.Lost != 1 {
		t.Fatalf("retirement fault was not reached: %+v", st)
	}
	if len(sink.retirementLocked) != 1 || !sink.retirementLocked[0] {
		t.Fatal("retirement callback did not run under capture mutex")
	}
	if len(sink.fragmentUnlocked) != 2 || !sink.fragmentUnlocked[1] {
		t.Fatal("post-retirement fragment callback did not run outside capture mutex")
	}
}
