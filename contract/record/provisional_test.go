package record_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
)

// provisionalFixture is a retired connection and capture's identity of it,
// which that retirement agrees with.
func provisionalFixture(t *testing.T, opened time.Time) (connection.Record, fragment.Identity) {
	t.Helper()
	at := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	instance := admission.Instance{Namespace: admission.Namespace{Device: 1, Inode: 2}, PID: 42,
		Start: admission.Determinate(7), Generation: 3, Executable: "/usr/bin/app"}
	process := fragment.Process{PID: 4242, StartTime: 7}
	identity := fragment.Identity{Connection: 9, Process: process, Instance: instance, Address: 0x1000, Generation: 5,
		NetworkDevice: 4, NetworkInode: 6, FirstSeen: at, Opened: opened}
	r := connection.Record{ID: 9, Handle: connection.Handle{Instance: instance.Key(), Address: 0x1000, Generation: 5},
		Instance: instance, Process: process, Network: connection.Netns{Device: 4, Inode: 6}, FirstSeen: at,
		Opened: opened, OpenedKnown: !opened.IsZero(), Ended: at.Add(time.Second), How: connection.HandleReleasedEnding,
		Fragments: connection.Counted(1)}
	evidence := fragment.Evidence{Identity: &identity, Occupancy: 1, Origin: fragment.OriginBirth, Through: 1,
		Sent: fragment.DirectionEvidence{First: 1, Numbered: 1, Resolved: 1}}
	if err := r.Agrees(evidence); err != nil {
		t.Fatalf("wiring, not the property: the fixture's retirement does not agree with its identity, so "+
			"nothing below compares one connection's two records: %v", err)
	}
	return r, identity
}

// The provisional record states what stays true for the whole of a connection,
// exactly as the final record states it, and none of the lifecycle or totals.
func TestProvisionalRecordIsTheFinalRecordsIdentity(t *testing.T) {
	for _, opened := range []time.Time{{}, time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)} {
		r, identity := provisionalFixture(t, opened)
		final, err := record.FromConnection(r)
		if err != nil {
			t.Fatal(err)
		}
		provisional, err := record.FromIdentity(identity)
		if err != nil {
			t.Fatal(err)
		}
		if !provisional.Provisional || final.Provisional {
			t.Fatalf("the provisional record is marked %t and the final one %t", provisional.Provisional, final.Provisional)
		}
		if final.Lifecycle() != [6]bool{true, true, true, true, true, true} {
			t.Fatalf("the final record carries lifecycle and totals %v, not all six", final.Lifecycle())
		}
		if provisional.Lifecycle() != [6]bool{} {
			t.Fatalf("the provisional record carries lifecycle or totals %v", provisional.Lifecycle())
		}
		if !reflect.DeepEqual(provisional, final.Identified()) {
			t.Fatalf("the provisional record differs from the final record's identity:\n%+v\n%+v", provisional, final.Identified())
		}
		encoded, err := json.Marshal(provisional)
		if err != nil {
			t.Fatal(err)
		}
		var members map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &members); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"ending", "associations", "placements", "fragments", "early", "early_unmeasured"} {
			if _, present := members[name]; present {
				t.Errorf("the provisional record writes %q: %s", name, encoded)
			}
		}
		if string(members["provisional"]) != "true" {
			t.Errorf("the provisional record is not marked on the wire: %s", encoded)
		}
		encoded, err = json.Marshal(final)
		if err != nil {
			t.Fatal(err)
		}
		members = nil
		if err := json.Unmarshal(encoded, &members); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"ending", "associations", "placements", "fragments", "early", "early_unmeasured"} {
			if _, present := members[name]; !present {
				t.Errorf("the final record omits %q: %s", name, encoded)
			}
		}
		if _, present := members["provisional"]; present {
			t.Errorf("the final record writes provisional: %s", encoded)
		}
	}
}

func TestProvisionalRecordRefusesAnIdentityWithNoGeneration(t *testing.T) {
	_, identity := provisionalFixture(t, time.Time{})
	identity.Generation = 0
	if _, err := record.FromIdentity(identity); err == nil {
		t.Fatal("an identity with no handle generation was projected")
	}
}
