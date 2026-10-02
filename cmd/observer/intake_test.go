package main

import (
	"math"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

func TestRecordingIntakeDerivesBoundFromEventPayloadCeiling(t *testing.T) {
	for _, events := range []uint64{1, 2, math.MaxInt64 / ebpf.MaxEventPayloadBytes} {
		recording, store, err := recordingIntake(events)
		if err != nil || recording == nil || store == nil {
			t.Fatalf("representable %d events refused: %v", events, err)
		}
		if got := store.Stats().LimitBytes; got != int64(events)*ebpf.MaxEventPayloadBytes {
			t.Errorf("%d events: %d bytes, want %d", events, got, int64(events)*ebpf.MaxEventPayloadBytes)
		}
		_ = store.Close()
	}
}

func TestRecordingIntakeRefusesUnrepresentableAllowance(t *testing.T) {
	// Each refusal is beside a representable positive control.
	for _, events := range []uint64{0, math.MaxInt64/ebpf.MaxEventPayloadBytes + 1, math.MaxUint64} {
		_, control, err := recordingIntake(1)
		if err != nil || control == nil {
			t.Fatalf("positive control refused: %v", err)
		}
		_ = control.Close()
		recording, store, err := recordingIntake(events)
		if err == nil || recording != nil || store != nil {
			t.Fatalf("unrepresentable %d events: recording=%v store=%v error=%v", events, recording, store, err)
		}
	}
}

func TestRecordingIntakeUsesBothSinkInterfaces(t *testing.T) {
	recording, store, err := recordingIntake(2)
	if err != nil || recording == nil || store == nil {
		t.Fatalf("positive control refused: %v", err)
	}
	defer func() { _ = store.Close() }()
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	instance := admission.Instance{Namespace: admission.Namespace{Inode: 1}, PID: 42, Generation: 1}
	process := fragment.Process{PID: 42, StartTime: 3}
	recording.Transfer(probe.Transfer{Process: process, Instance: instance, Endpoint: 7, Direction: fragment.Sent, Measured: true, Length: 5, Payload: []byte("hello"), Stamp: 1, Sequence: probe.Sequence{Occupancy: 1, Number: 1}, At: at})
	recording.Closed(probe.Connection{Process: process, Instance: instance, Endpoint: 7, Stamp: 2, Sequence: probe.Sequence{Occupancy: 1},
		Final: probe.Final{Known: true, Sent: probe.Terminal{Last: 1}}, At: at})
	if seen := recording.Stats(); seen.Transfers != 1 || seen.Closed != 1 || seen.Rejected != 0 || seen.ConnectionsUnrecorded != 0 {
		t.Fatalf("both callbacks were not reached: %+v", seen)
	}
	one, two := store.Take(), store.Take()
	if one == nil || one.Fragment == nil || two == nil || two.Connection == nil {
		t.Fatal("capture did not hand both records to the same intake")
	}
	defer one.Release()
	defer two.Release()
	if string(one.Fragment.Payload) != "hello" || two.Connection.ID != one.Fragment.Connection {
		t.Fatal("capture records were not retained with their join identity")
	}
}
