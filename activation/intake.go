package activation

import (
	"errors"
	"math"

	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/intake"
)

// RecordingIntake derives a storage allowance from the event admission count
// and the decoder's enforced payload ceiling. Metadata also consumes this
// store's allowance, so it may fill before N maximum-payload events. This is
// not a process-memory limit; the execution envelope covers the remaining
// allocations, including decoding, parser scratch, the ring and the channel.
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
