package processing_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"testing/fstest"

	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

// formLines is one connection's exchange line and connection line as the
// worker writes them, recast as version 4: the exchange line with the
// provisional record, the connection line with the final one.
func formLines(t *testing.T) (processing.Artifact, processing.Artifact) {
	t.Helper()
	out := &outputLog{}
	w, store := worker(t, rulesPlan(t, ""), out)
	enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
	drain(t, w)
	if len(out.artifacts) != 2 || out.artifacts[0].Record != processing.ArtifactExchange ||
		out.artifacts[1].Record != processing.ArtifactConnection {
		t.Fatalf("wiring, not the property: the fixture did not produce one exchange line and one connection "+
			"line, so no form below is a line the worker writes: %d lines", len(out.artifacts))
	}
	exchange, retirement := out.artifacts[0], out.artifacts[1]
	exchange.Version, retirement.Version = processing.ArtifactVersion4, processing.ArtifactVersion4
	exchange.Connection = exchange.Connection.Identified()
	reconstruction := *exchange.Reconstruction
	total := reconstruction.Unplaced
	reconstruction.Unplaced = record.Count{State: record.Undetermined, Unit: record.Bytes, Why: record.WhyProvisional}
	exchange.Reconstruction = &reconstruction
	retirement.ReconstructionUnplaced = &total
	return exchange, retirement
}

// readLines is what the shipped reader makes of these lines as one file.
func readLines(t *testing.T, artifacts ...processing.Artifact) error {
	t.Helper()
	var file []byte
	for _, a := range artifacts {
		line, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		file = append(append(file, line...), '\n')
	}
	return processing.ReadArtifacts(fstest.MapFS{processing.ArtifactName: {Data: file}},
		func(processing.Artifact) error { return nil })
}

func TestVersionFourLinesCarryTheirConnectionRecordInTheirOwnForm(t *testing.T) {
	exchange, retirement := formLines(t)
	if err := readLines(t, exchange, retirement); err != nil {
		t.Fatalf("wiring, not the property: the reader refuses the well-formed version 4 pair, so no refusal "+
			"below is about the form it names: %v", err)
	}
	for _, a := range []processing.Artifact{exchange, retirement} {
		if err := processing.RenderArtifact(io.Discard, a); err != nil {
			t.Fatalf("the renderer refuses a well-formed version 4 %s line: %v", a.Record, err)
		}
	}
	final := retirement.Connection
	lifecycle := map[string]func(*record.Connection){
		"ending":           func(c *record.Connection) { c.Ending = final.Ending },
		"associations":     func(c *record.Connection) { c.Associations = []record.Association{} },
		"placements":       func(c *record.Connection) { c.Placements = []record.Placement{} },
		"fragments":        func(c *record.Connection) { c.Fragments = final.Fragments },
		"early":            func(c *record.Connection) { c.Early = []record.Range{} },
		"early_unmeasured": func(c *record.Connection) { c.EarlyUnmeasured = final.EarlyUnmeasured },
	}
	for name, add := range lifecycle {
		bad := exchange
		add(&bad.Connection)
		if err := readLines(t, bad); err == nil {
			t.Errorf("an exchange line whose provisional record carries %s was read", name)
		}
	}
	absent := map[string]func(*record.Connection){
		"ending":           func(c *record.Connection) { c.Ending = record.Ending{} },
		"associations":     func(c *record.Connection) { c.Associations = nil },
		"placements":       func(c *record.Connection) { c.Placements = nil },
		"fragments":        func(c *record.Connection) { c.Fragments = record.Count{} },
		"early":            func(c *record.Connection) { c.Early = nil },
		"early_unmeasured": func(c *record.Connection) { c.EarlyUnmeasured = record.Count{} },
	}
	for name, remove := range absent {
		bad := retirement
		remove(&bad.Connection)
		if err := readLines(t, bad); err == nil {
			t.Errorf("a connection line whose final record lacks %s was read", name)
		}
	}
	finalOnExchange := exchange
	finalOnExchange.Connection = final
	if err := readLines(t, finalOnExchange); err == nil {
		t.Error("an exchange line carrying the final record was read")
	}
	unmarked := exchange
	unmarked.Connection.Provisional = false
	if err := readLines(t, unmarked); err == nil {
		t.Error("an exchange line whose identity-only record is not marked provisional was read")
	}
	provisionalRetirement := retirement
	provisionalRetirement.Connection.Provisional = true
	if err := readLines(t, provisionalRetirement); err == nil {
		t.Error("a connection line marked provisional was read")
	}
	identityRetirement := retirement
	identityRetirement.Connection = exchange.Connection
	if err := readLines(t, identityRetirement); err == nil {
		t.Error("a connection line carrying the provisional record was read")
	}
	for name, unplaced := range map[string]*record.Count{
		"absent":                      nil,
		"determined with no value":    {State: record.Determined, Unit: record.Bytes},
		"determined with a reason":    {State: record.Determined, Unit: record.Bytes, Value: "0", Why: "provisional"},
		"not decimal":                 {State: record.Determined, Unit: record.Bytes, Value: "-1"},
		"undetermined with no reason": {State: record.Undetermined, Unit: record.Bytes},
		"undetermined with a value":   {State: record.Undetermined, Unit: record.Bytes, Value: "0", Why: "not_read"},
		"another unit":                {State: record.Determined, Unit: record.Events, Value: "0"},
		"not carried":                 {State: record.NotCarried, Unit: record.Bytes},
	} {
		bad := retirement
		bad.ReconstructionUnplaced = unplaced
		if err := readLines(t, bad); err == nil {
			t.Errorf("a connection line whose unplaced total is %s was read", name)
		}
	}
	for _, unplaced := range []record.Count{
		{State: record.Determined, Unit: record.Bytes, Value: "17"},
		{State: record.Undetermined, Unit: record.Bytes, Why: "connection_cut"},
	} {
		good := retirement
		good.ReconstructionUnplaced = &unplaced
		if err := readLines(t, good); err != nil {
			t.Errorf("a connection line whose unplaced total is %+v was refused: %v", unplaced, err)
		}
	}
	misplaced := exchange
	misplaced.ReconstructionUnplaced = retirement.ReconstructionUnplaced
	if err := readLines(t, misplaced); err == nil {
		t.Error("an exchange line carrying an unplaced total was read")
	}
	for _, unplaced := range []record.Count{
		{State: record.Determined, Unit: record.Bytes, Value: "0"},
		{State: record.Undetermined, Unit: record.Bytes, Why: "connection_open"},
		{State: record.Undetermined, Unit: record.Bytes},
		{State: record.Undetermined, Unit: record.Events, Why: record.WhyProvisional},
		{},
	} {
		bad := exchange
		reconstruction := *exchange.Reconstruction
		reconstruction.Unplaced = unplaced
		bad.Reconstruction = &reconstruction
		if err := readLines(t, bad); err == nil {
			t.Errorf("a version 4 exchange line stating unplaced %+v was read", unplaced)
		}
	}
}

func TestEarlierVersionsNeverCarryAProvisionalRecord(t *testing.T) {
	exchange, retirement := formLines(t)
	exchange.Version, retirement.Version = processing.ArtifactVersion3, processing.ArtifactVersion3
	exchange.Connection = retirement.Connection
	total := retirement.ReconstructionUnplaced
	retirement.ReconstructionUnplaced = nil
	reconstruction := *exchange.Reconstruction
	reconstruction.Unplaced = record.Count{State: record.Determined, Unit: record.Bytes, Value: "0"}
	exchange.Reconstruction = &reconstruction
	if err := readLines(t, exchange, retirement); err != nil {
		t.Fatalf("wiring, not the property: the reader refuses the version 3 pair the worker writes: %v", err)
	}
	for _, a := range []processing.Artifact{exchange, retirement} {
		marked := a
		marked.Connection.Provisional = true
		if err := readLines(t, marked); err == nil {
			t.Errorf("a version 3 %s line marked provisional was read", a.Record)
		}
		carrying := a
		carrying.ReconstructionUnplaced = total
		if err := readLines(t, carrying); err == nil {
			t.Errorf("a version 3 %s line carrying an unplaced total was read", a.Record)
		}
	}
}

// A provisional exchange line decodes and encodes again to the same bytes: the
// absent members stay absent, rather than coming back as zero values.
func TestProvisionalExchangeLineSurvivesTheReader(t *testing.T) {
	exchange, _ := formLines(t)
	line, err := json.Marshal(exchange)
	if err != nil {
		t.Fatal(err)
	}
	var visited []processing.Artifact
	if err := processing.ReadArtifacts(fstest.MapFS{processing.ArtifactName: {Data: append(line, '\n')}},
		func(a processing.Artifact) error { visited = append(visited, a); return nil }); err != nil || len(visited) != 1 {
		t.Fatalf("wiring, not the property: the line was not read back once: %v, %d", err, len(visited))
	}
	again, err := json.Marshal(visited[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(line, again) {
		t.Fatalf("the provisional line changed through the reader:\n%s\n%s", line, again)
	}
}

// turnWorker is a worker that reports its turns, with its intake and gate.
func turnWorker(t *testing.T, output processing.Output) (*processing.Worker, *intake.Store, *probe.DeliveryGate, *[]processing.Turn) {
	t.Helper()
	store, err := intake.New(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1000, IntakeExhausted: store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	turns := &[]processing.Turn{}
	options := processing.ObserveTurns(processing.Options{Session: "turns", Plan: rulesPlan(t, ""),
		PolicyRevision: "turns-policy", Intake: store, Gate: gate, Output: output},
		func(one processing.Turn) { *turns = append(*turns, one) })
	w, err := processing.New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, store, gate, turns
}

func TestTurnsReportTheWorkTakenAndTheExchangesReleased(t *testing.T) {
	for _, c := range []struct {
		name       string
		output     processing.Output
		invalidate bool
		want       processing.ReleaseOutcome
	}{
		{"enqueued", &outputLog{}, false, processing.ReleaseEnqueued},
		{"dropped", outputFunc(func(context.Context, processing.Approved) error { return errors.New("queue full") }),
			false, processing.ReleaseDropped},
		{"unauthorized", &outputLog{}, true, processing.ReleaseUnauthorized},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, store, gate, turns := turnWorker(t, c.output)
			enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
			if c.invalidate {
				if gate.Admit(probe.DeliveryKind(255), true).Admitted || gate.Snapshot().Reason == "" {
					t.Fatal("wiring, not the property: the gate was not invalidated")
				}
			}
			if _, err := w.Drain(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(*turns) != 1 {
				t.Fatalf("wiring, not the property: one drain reported %d turns", len(*turns))
			}
			one := (*turns)[0]
			if one.Number != 1 || one.Taken != 3 || one.Backlog ||
				one.Fed != uint64(len(goodRequest)+len(goodResponse)) {
				t.Fatalf("the turn reports %+v: want turn 1, 3 entries taken, every byte fed, no backlog", one)
			}
			if len(one.Released) != 1 {
				t.Fatalf("the turn reports %d exchanges released, want 1: %+v", len(one.Released), one.Released)
			}
			if r := one.Released[0]; r.Connection != 1 || r.Index != 0 || r.ID != 1 || r.Outcome != c.want {
				t.Fatalf("the release reported is %+v (%s), want connection 1 index 0 id 1 %s", r, r.Outcome, c.want)
			}
		})
	}
}
