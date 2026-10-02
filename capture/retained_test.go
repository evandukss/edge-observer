package capture_test

import (
	"testing"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

// Connections come and go on four handle addresses, each address reused for
// thousands of occupancies, at a constant live population of four. What the
// session holds returns to the live population, and every occupancy is still a
// connection of its own: no table of past occupancies is kept to tell them
// apart.
func TestChurnedConnectionsLeaveTheSessionHoldingOnlyTheLiveOnes(t *testing.T) {
	const live, occupancies = 4, 10000
	records := &keptRecords{}
	s := produced(&collected{}, records)
	generations := make(map[connection.Generation]bool, occupancies)
	for i := 0; i < occupancies; i++ {
		endpoint := uint64(0x40 + i%live)
		if i >= live {
			// The connection begun live occupancies ago on this address ends first.
			ending := ending(worker, endpoint)
			ending.Sequence = probe.Sequence{Occupancy: uint64(i - live + 1), Born: true}
			ending.Final = probe.Final{Known: true, Sent: probe.Terminal{Last: 1}}
			s.Closed(ending)
		}
		one := transfer(worker, endpoint, fragment.Sent, 8)
		one.Sequence = probe.Sequence{Occupancy: uint64(i + 1), Number: 1, Born: true}
		s.Transfer(one)
	}
	stores, err := s.Retained()
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]int{}
	for _, one := range stores {
		held[one.Store] = one.Held
	}
	if _, listed := held["capture.streams"]; !listed {
		t.Fatalf("wiring, not the property: the session lists no streams: %v", stores)
	}
	for store, most := range map[string]int{"capture.streams": live, "capture.early": 0, "capture.settlers": 1} {
		if held[store] > most {
			t.Errorf("%s holds %d after %d occupancies, want at most the live %d", store, held[store], occupancies, most)
		}
	}
	for store := range held {
		switch store {
		case "capture.streams", "capture.early", "capture.settlers":
		default:
			t.Errorf("the session keeps %s, which no live connection accounts for", store)
		}
	}
	if len(records.records) != occupancies-live {
		t.Fatalf("wiring, not the property: %d connection records handed on, want %d", len(records.records), occupancies-live)
	}
	for _, record := range records.records {
		if generations[record.Handle.Generation] {
			t.Fatalf("generation %d names two occupancies", record.Handle.Generation)
		}
		generations[record.Handle.Generation] = true
	}
	if s.Stats().EndingsUnmatched != 0 || s.Stats().Retired != 0 {
		t.Errorf("every ending was its own connection's, yet capture counted %+v", s.Stats())
	}
}

// An ending raised because the execution ended while holding the handle is
// recorded as an end known and not observed, never as a release of the handle.
func TestAnEndingAtTheExecutionsExitIsNotRecordedAsARelease(t *testing.T) {
	records := &keptRecords{}
	s := produced(&collected{}, records)
	one := transfer(worker, 0x50, fragment.Sent, 8)
	one.Sequence = probe.Sequence{Occupancy: 7, Number: 1, Born: true}
	s.Transfer(one)
	exited := ending(worker, 0x50)
	exited.Sequence = probe.Sequence{Occupancy: 7, Born: true}
	exited.Final = probe.Final{Known: true, Sent: probe.Terminal{Last: 1}, Exited: true}
	s.Closed(exited)
	if len(records.records) != 1 {
		t.Fatalf("wiring, not the property: %d records for one connection", len(records.records))
	}
	if got := records.records[0].How; got != connection.EndingUnobserved {
		t.Errorf("an ending at the execution's exit is recorded as %q, want %q", got, connection.EndingUnobserved)
	}
	placed, ok := records.records[0].Placement(fragment.Sent)
	if !ok || placed.Positions != connection.PositionsEstablished {
		t.Errorf("an exit with every transfer delivered left the direction %+v, want established", placed)
	}
}
