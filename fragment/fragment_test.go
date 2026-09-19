package fragment_test

import (
	"errors"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/fragment"
)

// at is a fixed capture time; a zero one is invalid.
var at = time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)

func valid() fragment.Record {
	return fragment.Record{
		Process:    fragment.Process{PID: 1731, StartTime: 90210},
		Connection: 18,
		Direction:  fragment.Sent,
		Sequence:   3,
		Offset:     4096,
		Length:     11,
		Payload:    []byte("POST /v2/x\n"),
		At:         at,
	}
}

func TestStreamSeparatesTheTwoDirectionsOfOneConnection(t *testing.T) {
	sent := valid()
	received := valid()
	received.Direction = fragment.Received

	if sent.Stream() == received.Stream() {
		t.Fatalf("the two directions of connection %d share a stream: %v", sent.Connection, sent.Stream())
	}
}

func TestStreamSeparatesTwoConnectionsOfOneProcess(t *testing.T) {
	first := valid()
	second := valid()
	second.Connection++

	if first.Stream() == second.Stream() {
		t.Fatalf("connections %d and %d share a stream: %v", first.Connection, second.Connection, first.Stream())
	}
}

// Pids are reused: one pid with two start times is two processes.
func TestStreamSeparatesAReusedPID(t *testing.T) {
	before := valid()
	after := valid()
	after.Process.StartTime++

	if before.Stream() == after.Stream() {
		t.Fatalf("pid %d before and after a reuse share a stream: %v", before.Process.PID, before.Stream())
	}
}

func TestStreamGroupsTwoFragmentsOfOneDirection(t *testing.T) {
	first := valid()
	second := valid()
	second.Sequence++
	second.Offset = first.End()

	if first.Stream() != second.Stream() {
		t.Fatalf("consecutive fragments of one stream do not group: %v and %v", first.Stream(), second.Stream())
	}
}

// End advances by the bytes transferred, not the bytes kept, or a truncated
// fragment's successor would look like a gap.
func TestEndAdvancesByTheBytesTransferredNotByThePayloadKept(t *testing.T) {
	record := valid()
	record.Length = 4096
	record.Payload = record.Payload[:8]

	if got, want := record.End(), record.Offset+4096; got != want {
		t.Fatalf("End() = %d, want %d", got, want)
	}
}

func TestTruncatedWhenCaptureKeptFewerBytesThanTheCallTransferred(t *testing.T) {
	record := valid()
	record.Length = 4096

	if !record.Truncated() {
		t.Fatalf("a record with %d bytes kept of %d transferred does not report truncated", len(record.Payload), record.Length)
	}
}

func TestNotTruncatedWhenCaptureKeptEveryByte(t *testing.T) {
	if record := valid(); record.Truncated() {
		t.Fatalf("a record with %d bytes kept of %d transferred reports truncated", len(record.Payload), record.Length)
	}
}

// A payload wholly lost is a valid, truncated record: a hole not to read
// across. A call that transferred nothing is invalid.
func TestAFragmentWhosePayloadWasWhollyLostIsValidAndTruncated(t *testing.T) {
	record := valid()
	record.Payload = nil

	if err := record.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if !record.Truncated() {
		t.Fatal("a record that kept none of its bytes does not report truncated")
	}
	if got, want := record.End(), record.Offset+uint64(record.Length); got != want {
		t.Fatalf("End() = %d, want %d", got, want)
	}
}

func TestValidateAcceptsARecordCarryingEverythingReconstructionNeeds(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*fragment.Record){
		"a direction the capture side never assigned": func(r *fragment.Record) { r.Direction = fragment.Unknown },
		"a direction outside the two defined":         func(r *fragment.Record) { r.Direction = fragment.Received + 1 },
		"no process":                                  func(r *fragment.Record) { r.Process.PID = 0 },
		"a negative pid":                              func(r *fragment.Record) { r.Process.PID = -1 },
		"a call that transferred nothing":             func(r *fragment.Record) { r.Length = 0; r.Payload = nil },
		"more bytes kept than were transferred":       func(r *fragment.Record) { r.Length = uint32(len(r.Payload)) - 1 },
		"no capture time":                             func(r *fragment.Record) { r.At = time.Time{} },
	}

	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			record := valid()
			spoil(&record)

			err := record.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want an error for %s", name)
			}
			if !errors.Is(err, fragment.ErrInvalid) {
				t.Fatalf("Validate() = %v, which is not a %v", err, fragment.ErrInvalid)
			}
		})
	}
}

func TestDirectionNamesTheSideTheProcessWasOn(t *testing.T) {
	for direction, want := range map[fragment.Direction]string{
		fragment.Sent:     "sent",
		fragment.Received: "received",
		fragment.Unknown:  "unknown",
	} {
		if got := direction.String(); got != want {
			t.Errorf("Direction(%d).String() = %q, want %q", direction, got, want)
		}
	}
}
