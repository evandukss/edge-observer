package processing_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

func TestExchangeLinesKeepIdentityAcrossMultipleExchanges(t *testing.T) {
	var output outputLog
	w, store := worker(t, rulesPlan(t, ""), &output)
	enqueue(t, store, batch(t, 1, goodRequest+goodRequest, goodResponse+goodResponse))
	result := drain(t, w)
	if result.Authorized != 3 || len(output.artifacts) != 3 {
		t.Fatalf("two exchanges and one retirement: %+v, %d lines", result, len(output.artifacts))
	}
	seen := map[string]int{}
	connections := 0
	for _, a := range output.artifacts {
		if a.Session != "fixture-session" || a.ExchangeIDs != nil {
			t.Fatalf("session envelope: %+v", a)
		}
		switch a.Record {
		case processing.ArtifactExchange:
			if a.Index == nil || a.Reconstruction == nil || len(a.Reconstruction.Exchanges) != 1 {
				t.Fatalf("exchange population: %+v", a)
			}
			seen[a.ExchangeID] = *a.Index
		case processing.ArtifactConnection:
			connections++
			if a.Reconstruction != nil || a.Index != nil || a.ExchangeID != "" {
				t.Fatal("exchange content on retirement")
			}
		default:
			t.Fatalf("record kind %q", a.Record)
		}
	}
	if len(seen) != 2 || seen["1"] != 0 || seen["2"] != 1 || connections != 1 {
		t.Fatalf("identities %v retirements %d", seen, connections)
	}
}
func TestReaderSelectsSessionAcrossExplicitFiles(t *testing.T) {
	_, a := readableArtifact(t)
	line := func(session, id string) []byte {
		one := a
		one.Session = session
		one.ExchangeID = id
		b, err := json.Marshal(one)
		if err != nil {
			t.Fatal(err)
		}
		return append(b, '\n')
	}
	files := fstest.MapFS{"active": {Data: append(line("a", "1"), line("b", "1")...)}, "rotated": {Data: line("a", "2")}}
	var ids []string
	if err := processing.ReadArtifactFiles(files, []string{"active", "rotated"}, "a", func(a processing.Artifact) error {
		if a.Session != "a" {
			t.Fatal("foreign session")
		}
		ids = append(ids, a.ExchangeID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids, ",") != "1,2" {
		t.Fatalf("filtered ids %v", ids)
	}
	if err := processing.ReadArtifactFiles(files, []string{"active"}, "absent", func(processing.Artifact) error { return nil }); !errors.Is(err, processing.ErrNoArtifacts) {
		t.Fatalf("absent session: %v", err)
	}
}
func TestReaderReportsPartialRecordAsMalformed(t *testing.T) {
	line, _ := readableArtifact(t)
	files := fstest.MapFS{"active": {Data: append([]byte("{broken\n"), line...)}}
	called := false
	err := processing.ReadArtifactFiles(files, []string{"active"}, "fixture-session", func(processing.Artifact) error { called = true; return nil })
	if err == nil || !strings.Contains(err.Error(), "malformed") || called {
		t.Fatalf("damaged record: called %t, %v", called, err)
	}
}
func TestStableWriterAppendsAndRejectsUnapprovedValues(t *testing.T) {
	root := t.TempDir()
	for _, session := range []string{"first-session", "second-session"} {
		writer, err := processing.OpenWriter(processing.WriterOptions{Directory: root})
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.WriteApproved(context.Background(), processing.Approved{}); !errors.Is(err, processing.ErrUnapproved) {
			t.Fatalf("unapproved: %v", err)
		}
		w, store := workerSession(t, rulesPlan(t, ""), writer, session)
		enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
		drain(t, w)
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if st := writer.DeliveryStats(); st.Authorized != 2 || st.Written != 2 || st.Pending != 0 {
			t.Fatalf("delivery: %+v", st)
		}
	}
	data, err := os.ReadFile(filepath.Join(root, processing.ArtifactName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "\n") != 4 {
		t.Fatalf("appended population: %s", data)
	}
	for _, session := range []string{"first-session", "second-session"} {
		count := 0
		if err := processing.ReadArtifactFiles(os.DirFS(root), []string{processing.ArtifactName}, session, func(a processing.Artifact) error {
			if a.Session != session {
				t.Fatal("foreign session")
			}
			count++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if count != 2 {
			t.Fatalf("session %s retained %d lines, want exchange and retirement", session, count)
		}
	}
	info, err := os.Stat(filepath.Join(root, processing.ArtifactName))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("mode: %v %v", info, err)
	}
}
func TestReaderRejectsVersionThreeMissingOrMultipleExchangeIdentities(t *testing.T) {
	_, base := readableArtifact(t)
	for _, edit := range []func(*processing.Artifact){
		func(a *processing.Artifact) { a.Session = "" },
		func(a *processing.Artifact) { a.ExchangeID = "0" },
		func(a *processing.Artifact) { a.Index = nil },
		func(a *processing.Artifact) {
			r := *a.Reconstruction
			r.Exchanges = append(r.Exchanges, r.Exchanges[0])
			a.Reconstruction = &r
		},
	} {
		a := base
		edit(&a)
		line, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		if err := processing.ReadArtifactFiles(fstest.MapFS{"x": {Data: append(line, '\n')}}, []string{"x"}, "", func(processing.Artifact) error { return nil }); err == nil {
			t.Fatal("malformed identity accepted")
		}
	}
}

func TestCanceledWriteDoesNotPoisonLaterDelivery(t *testing.T) {
	writer, err := processing.OpenWriter(processing.WriterOptions{Directory: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	output := outputFunc(func(ctx context.Context, a processing.Approved) error {
		calls++
		if calls == 1 {
			if err := writer.WriteApproved(canceled, a); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation: %v", err)
			}
		}
		return writer.WriteApproved(ctx, a)
	})
	w, store := worker(t, rulesPlan(t, ""), output)
	enqueue(t, store, batch(t, 1, goodRequest, goodResponse))
	drain(t, w)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if st := writer.DeliveryStats(); calls != 2 || st.Written != 2 || st.Failed != 0 {
		t.Fatalf("later delivery: calls %d stats %+v", calls, st)
	}
}

func TestDroppedExchangeDoesNotRenumberLaterExchange(t *testing.T) {
	var kept outputLog
	attempts := 0
	out := outputFunc(func(ctx context.Context, a processing.Approved) error {
		attempts++
		if attempts == 1 {
			return errors.New("injected queue refusal")
		}
		return kept.WriteApproved(ctx, a)
	})
	w, store := worker(t, rulesPlan(t, ""), out)
	enqueue(t, store, batch(t, 1, goodRequest+goodRequest, goodResponse+goodResponse))
	result := drain(t, w)
	if attempts != 3 || result.Authorized != 3 || result.Written != 2 || result.OutputFailures != 1 || len(kept.artifacts) != 2 {
		t.Fatalf("refusal control: attempts %d outcome %+v kept %d", attempts, result, len(kept.artifacts))
	}
	next := kept.artifacts[0]
	if next.Record != processing.ArtifactExchange || next.ExchangeID != "2" || next.Index == nil || *next.Index != 1 {
		t.Fatalf("dropped line renumbered successor: %+v", next)
	}
	if kept.artifacts[1].Record != processing.ArtifactConnection {
		t.Fatal("retirement lost after refusal")
	}
}

func TestWorkerRequiresSessionIdentity(t *testing.T) {
	plan := rulesPlan(t, "")
	_, store := worker(t, plan, &outputLog{})
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 10})
	if err != nil {
		t.Fatal(err)
	}
	if w, err := processing.New(processing.Options{Plan: plan, PolicyRevision: "policy", Intake: store, Gate: gate, Output: &outputLog{}}); w != nil || !errors.Is(err, processing.ErrOptions) {
		t.Fatalf("missing session accepted: worker %v error %v", w, err)
	}
}
