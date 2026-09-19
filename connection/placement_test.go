package connection_test

import (
	"testing"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
)

// A direction silent about placeability would read as whole.
func TestAPlacementThatSaysNothingIsRefused(t *testing.T) {
	one := connection.Placement{Connection: 7, Direction: fragment.Sent}
	if err := one.Validate(); err == nil {
		t.Fatal("a placement carrying no answer is accepted")
	}
	if one.Whole() {
		t.Fatal("a placement carrying no answer reports a whole stream")
	}
	if one.Placeable(0) {
		t.Fatal("a placement carrying no answer places its first byte")
	}
}

// A located gap is placeable below the offset and not at or above it. The
// control: the same stream fully established places every offset.
func TestALocatedGapIsPlaceableOnlyBelowIt(t *testing.T) {
	whole := connection.Placement{
		Connection: 7, Direction: fragment.Sent,
		Positions: connection.PositionsEstablished,
	}
	holed := connection.Placement{
		Connection: 7, Direction: fragment.Sent,
		Positions: connection.PositionsUnknownFrom,
		From:      10,
		Because:   connection.ObservationLost,
		Lost:      connection.Counted(1),
	}

	for _, offset := range []uint64{0, 9, 10, 11, 4096} {
		if !whole.Placeable(offset) {
			t.Errorf("the control does not place offset %d, so nothing below proves anything", offset)
		}
	}
	for _, offset := range []uint64{0, 9} {
		if !holed.Placeable(offset) {
			t.Errorf("offset %d below the gap is not placeable", offset)
		}
	}
	for _, offset := range []uint64{10, 11, 4096} {
		if holed.Placeable(offset) {
			t.Errorf("offset %d at or above the gap is placeable", offset)
		}
	}
	if holed.Whole() {
		t.Error("a stream with a located gap reports itself whole")
	}
	if err := holed.Validate(); err != nil {
		t.Errorf("a located gap is refused: %v", err)
	}
}

// An unlocated loss leaves no known-good prefix, and From means nothing for it.
func TestALossNobodyCouldLocateLeavesNoPlaceablePrefix(t *testing.T) {
	unlocated := connection.Placement{
		Connection: 7, Direction: fragment.Received,
		Positions: connection.PositionsUnknownThroughout,
		Because:   connection.ObservationLost,
		Lost:      connection.Uncounted("the reservation failure carried no connection identity"),
	}
	if err := unlocated.Validate(); err != nil {
		t.Fatalf("an unlocated loss is refused: %v", err)
	}

	// A leftover From on it is refused and still places nothing.
	stale := unlocated
	stale.From = 10
	if err := stale.Validate(); err == nil {
		t.Error("a placement whose loss nothing located names where the gap begins")
	}
	for _, offset := range []uint64{0, 1, 9} {
		if stale.Placeable(offset) {
			t.Errorf("offset %d is placeable below an offset nothing established", offset)
		}
	}

	for _, offset := range []uint64{0, 1, 10, 4096} {
		if unlocated.Placeable(offset) {
			t.Errorf("offset %d is placeable on a stream whose loss nothing located", offset)
		}
	}
	if unlocated.Whole() {
		t.Error("a stream whose loss nothing located reports itself whole")
	}
	if unlocated.Lost.Known {
		t.Error("a loss nobody could count reports a count")
	}
}

// A non-whole placement must say why; a whole one must not.
func TestAPlacementSaysWhyExactlyWhenItIsNotWhole(t *testing.T) {
	silent := connection.Placement{
		Connection: 7, Direction: fragment.Sent,
		Positions: connection.PositionsUnknownFrom, From: 10,
	}
	if err := silent.Validate(); err == nil {
		t.Fatal("a stream that lost its positions and says nothing about why is accepted")
	}

	contradictory := connection.Placement{
		Connection: 7, Direction: fragment.Sent,
		Positions: connection.PositionsEstablished,
		Because:   connection.ObservationLost,
	}
	if err := contradictory.Validate(); err == nil {
		t.Fatal("a fully placeable stream that names a loss is accepted")
	}
}

// Placeable is vacuously true for a direction with no bytes, and false for one
// that lost its positions.
func TestARecordWithoutAPlacementForADirectionIsVacuouslyPlaceable(t *testing.T) {
	record := held()
	record.Placements = record.Placements[:1]
	if !record.Placeable(fragment.Received) {
		t.Fatal("a direction that carried nothing is not placeable")
	}

	record.Placements[0].Positions = connection.PositionsUnknownThroughout
	record.Placements[0].Because = connection.ObservationLost
	if record.Placeable(record.Placements[0].Direction) {
		t.Fatal("a direction that lost every position is placeable")
	}
}
