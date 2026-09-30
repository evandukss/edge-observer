package main

import (
	protected "github.com/evandukss/edge-observer/activation"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/intake"
)

// recordingIntake shares activation's single derivation of the volatile bound.
func recordingIntake(maxEvents uint64) (*capture.Session, *intake.Store, error) {
	return protected.RecordingIntake(maxEvents)
}
