package spool_test

import (
	"bufio"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/spool"
)

func record(sequence uint64) fragment.Record {
	return fragment.Record{
		Process:    fragment.Process{PID: 1731, StartTime: 90210},
		Connection: 18,
		Direction:  fragment.Sent,
		Sequence:   sequence,
		Offset:     sequence * 16,
		Length:     16,
		At:         time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC),
	}
}

func open(t *testing.T, limit int64) (*spool.Spool, string) {
	t.Helper()

	dir := t.TempDir()
	opened, err := spool.Open(dir, limit)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	return opened, dir
}

func lines(t *testing.T, dir string) []fragment.Record {
	t.Helper()

	file, err := os.Open(filepath.Join(dir, spool.Name))
	if err != nil {
		t.Fatalf("open the spool: %v", err)
	}
	defer func() { _ = file.Close() }()

	var records []fragment.Record
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var record fragment.Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("read a spooled record: %v", err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read the spool: %v", err)
	}
	return records
}

func TestARecordGoesInAndComesBackOut(t *testing.T) {
	written, dir := open(t, 1<<20)

	if err := written.Write(record(1)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	records := lines(t, dir)
	if len(records) != 1 {
		t.Fatalf("%d records in the spool, want 1", len(records))
	}
	if records[0].Sequence != 1 || records[0].Length != 16 || records[0].Direction != fragment.Sent {
		t.Fatalf("the record came back as %+v", records[0])
	}
	if stats := written.Stats(); stats.Written != 1 || stats.Dropped != 0 {
		t.Fatalf("Stats = %+v", stats)
	}
}

// At its bound the spool stops writing, counts what it dropped, and stays
// under the bound.
func TestAtItsBoundTheSpoolDropsAndCountsAndStaysUnderIt(t *testing.T) {
	const limit = 400
	written, dir := open(t, limit)

	for i := range uint64(50) {
		if err := written.Write(record(i)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	stats := written.Stats()
	if stats.Dropped == 0 {
		t.Fatal("nothing was dropped, so the bound was never reached")
	}
	if stats.Written == 0 {
		t.Fatal("nothing was written, so the bound was reached before anything was measured")
	}
	if stats.Written+stats.Dropped != 50 {
		t.Fatalf("%d written and %d dropped, want 50 accounted for", stats.Written, stats.Dropped)
	}

	info, err := os.Stat(filepath.Join(dir, spool.Name))
	if err != nil {
		t.Fatalf("stat the spool: %v", err)
	}
	if info.Size() > limit {
		t.Fatalf("the spool is %d bytes, past its bound of %d", info.Size(), limit)
	}
	if got := int64(len(lines(t, dir))); got != stats.Written {
		t.Fatalf("%d records in the file, %d counted as written", got, stats.Written)
	}
}

// Half a record in the file can be neither parsed nor skipped.
func TestARecordIsDroppedWholeRatherThanWrittenUpToTheBound(t *testing.T) {
	written, dir := open(t, 200)

	for i := range uint64(20) {
		if err := written.Write(record(i)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	// lines fails on a partial line.
	records := lines(t, dir)
	if len(records) == 0 {
		t.Fatal("nothing readable in the spool")
	}
	if got := int64(len(records)); got != written.Stats().Written {
		t.Fatalf("%d records readable, %d counted as written", got, written.Stats().Written)
	}
}

// An unplaceable record is a capture defect, counted apart from the bound.
func TestARecordThatCannotBePlacedInAStreamIsRefusedAndCountedApart(t *testing.T) {
	written, dir := open(t, 1<<20)

	broken := record(1)
	broken.Length = 0

	if err := written.Write(broken); err == nil {
		t.Fatal("Write accepted a record that carries no bytes")
	}

	stats := written.Stats()
	if stats.Refused != 1 {
		t.Fatalf("Refused = %d, want 1", stats.Refused)
	}
	if stats.Dropped != 0 {
		t.Fatalf("Dropped = %d; a refusal is not a bound being reached", stats.Dropped)
	}
	if got := len(lines(t, dir)); got != 0 {
		t.Fatalf("%d records in the spool", got)
	}
}

// A bound is required.
func TestASpoolWithNoBoundIsRefused(t *testing.T) {
	for _, limit := range []int64{0, -1} {
		if _, err := spool.Open(t.TempDir(), limit); err == nil {
			t.Errorf("Open accepted a bound of %d", limit)
		}
	}
}

func TestTheSpoolIsReadableByNobodyElse(t *testing.T) {
	written, dir := open(t, 1<<20)
	if err := written.Write(record(1)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	info, err := os.Stat(filepath.Join(dir, spool.Name))
	if err != nil {
		t.Fatalf("stat the spool: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Fatalf("the spool is mode %o, which lets somebody else read the captured traffic", mode)
	}
}

// A connection record round-trips as one line of the connections file.
func TestAConnectionRecordIsWrittenBesideTheFragmentsAndReadsBackWhole(t *testing.T) {
	dir := t.TempDir()
	held, err := spool.Open(dir, 1<<20)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	record := joined()
	if err := held.Connection(record); err != nil {
		t.Fatalf("write a connection record: %v", err)
	}
	if err := held.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if got := filepath.Base(held.ConnectionsPath()); got != spool.ConnectionsName {
		t.Fatalf("the connection records are in %s", got)
	}
	content, err := os.ReadFile(filepath.Join(dir, spool.ConnectionsName))
	if err != nil {
		t.Fatalf("read the connection records: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("%d lines in the connection file, want 1", len(lines))
	}

	var back connection.Record
	if err := json.Unmarshal([]byte(lines[0]), &back); err != nil {
		t.Fatalf("read the record back: %v", err)
	}
	if back.ID != record.ID || back.Handle != record.Handle {
		t.Fatalf("the record came back as %+v", back.Handle)
	}
	if !back.Joinable(fragment.Sent) {
		t.Fatal("a joinable record came back unjoinable, so the endpoints did not survive")
	}
	if got, _ := back.Association(fragment.Sent); got.Descriptor != connection.Held(7) {
		t.Fatalf("the descriptor came back as %s", got.Descriptor)
	}
	if got := held.Stats(); got.Connections != 1 || got.ConnectionsRefused != 0 || got.ConnectionsDropped != 0 {
		t.Fatalf("Stats = %+v", got)
	}
}

// An unplaceable connection record is refused on its own counter, never the
// fragments'.
func TestAConnectionRecordThatCannotBePlacedIsRefusedOnItsOwnCounter(t *testing.T) {
	dir := t.TempDir()
	held, err := spool.Open(dir, 1<<20)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = held.Close() }()

	// The control first, so the refusal below is not a spool that never worked.
	if err := held.Connection(joined()); err != nil {
		t.Fatalf("the control record was refused: %v", err)
	}

	nameless := joined()
	nameless.Handle.Generation = 0
	if err := held.Connection(nameless); err == nil {
		t.Fatal("a record whose handle carries no occupancy was accepted")
	}

	got := held.Stats()
	if got.Connections != 1 {
		t.Errorf("Connections = %d, want the one control", got.Connections)
	}
	if got.ConnectionsRefused != 1 {
		t.Errorf("ConnectionsRefused = %d, want 1", got.ConnectionsRefused)
	}
	if got.Refused != 0 {
		t.Errorf("a refused connection record moved the FRAGMENT refusal counter to %d", got.Refused)
	}
}

// The bound covers both files; a connection record past it is dropped on its
// own counter.
func TestAConnectionRecordPastTheBoundIsDroppedOnItsOwnCounter(t *testing.T) {
	dir := t.TempDir()
	record := joined()
	line, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Room for one record and its newline, and nothing after it.
	held, err := spool.Open(dir, int64(len(line)+1))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = held.Close() }()

	if err := held.Connection(record); err != nil {
		t.Fatalf("the first record was refused: %v", err)
	}
	second := record
	second.Handle.Address = 0x20
	if err := held.Connection(second); err != nil {
		t.Fatalf("a record past the bound is an error rather than a drop: %v", err)
	}

	got := held.Stats()
	if got.Connections != 1 || got.ConnectionsDropped != 1 {
		t.Fatalf("Stats = %+v, want one written and one dropped", got)
	}
	if got.Dropped != 0 {
		t.Errorf("a dropped connection record moved the FRAGMENT drop counter to %d", got.Dropped)
	}
}

// joined is a connection record with both directions established.
func joined() connection.Record {
	instance := admission.Instance{
		Namespace:  admission.Namespace{Device: 4, Inode: 4026531836},
		PID:        1731,
		Start:      admission.Determinate(90210),
		Generation: 1,
		Executable: "/usr/bin/service",
	}
	seen := time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)
	record := connection.Record{
		ID:        7,
		Handle:    connection.Handle{Instance: instance.Key(), Address: 0x18, Generation: 1},
		Instance:  instance,
		Process:   fragment.Process{PID: 1731, StartTime: 90210},
		FirstSeen: seen,
		How:       connection.StillOpen,
		Fragments: connection.Counted(2),
	}
	for _, direction := range []fragment.Direction{fragment.Sent, fragment.Received} {
		record.Associations = append(record.Associations, connection.Association{
			Connection: record.ID,
			Direction:  direction,
			State:      connection.Established,
			Join:       connection.Joins,
			Binding:    3,
			Source:     connection.SetterArgument,
			Valid:      connection.Since(seen),
			Descriptor: connection.Held(7),
			Endpoints: connection.Endpoints{
				Local:  connection.At(netip.MustParseAddr("172.25.0.4"), 37707),
				Remote: connection.At(netip.MustParseAddr("172.25.0.8"), 8443),
				Netns:  connection.Netns{Device: 4, Inode: 4026532567},
			},
		})
		record.Placements = append(record.Placements, connection.Placement{
			Connection: record.ID,
			Direction:  direction,
			Positions:  connection.PositionsEstablished,
			Lost:       connection.Counted(0),
		})
	}
	return record
}
