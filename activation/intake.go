package activation

import (
	"errors"
	"math"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/intake"
)

// RecordingIntake derives the session's one allowance for held work from the
// event admission count and the decoder's enforced payload ceiling. Metadata
// also consumes it, and so does the work processing holds beside the intake's
// entries - what reading a connection retains and the copies policy transforms
// (intake.Parsing, intake.Policy) - so it may fill before N maximum-payload
// events. This is not a process-memory limit; the execution envelope covers the
// remaining allocations, including decoding, the ring, the channel, and what
// one processing step builds and hands over or drops before it returns.
func RecordingIntake(maxEvents uint64) (*capture.Session, *intake.Store, error) {
	if maxEvents == 0 {
		return nil, nil, errors.New("capture intake requires a positive event allowance")
	}
	if maxEvents > math.MaxInt64/ebpf.MaxEventPayloadBytes {
		return nil, nil, errors.New("capture intake byte allowance exceeds int64")
	}
	limitBytes := int64(maxEvents) * ebpf.MaxEventPayloadBytes
	store, err := intake.New(limitBytes)
	if err != nil {
		return nil, nil, err
	}
	return capture.Recording(store, store), store, nil
}
