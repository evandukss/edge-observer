package processing_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/internal/workload"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

// Collected by the unit gate. Expectations below are the published protocol,
// account and approved-output contracts; the peer imports none of their code.
func independentPeer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "broken-extension")
	c := exec.Command("go", "build", "-o", bin, "github.com/evandukss/edge-observer/internal/cmd/broken-extension")
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("wiring, not the property: build peer: %v: %s", err, out)
	}
	return bin
}

type independentRun struct {
	run        *processing.Run
	store      *intake.Store
	writer     *processing.Writer
	out        *lines
	dir, audit string
	events     chan extension.Event
}

type independentOutput struct {
	writer *processing.Writer
	log    *lines
}

func (o independentOutput) WriteApproved(ctx context.Context, a processing.Approved) error {
	if err := o.writer.WriteApproved(ctx, a); err != nil {
		return err
	}
	return o.log.WriteApproved(ctx, a)
}

func independentStart(t *testing.T, bin, mode, rules string, fields []string, workers int, allowance, intakeBytes int64, clock extension.Clock, args ...string) *independentRun {
	t.Helper()
	f := &independentRun{dir: t.TempDir(), out: &lines{}, events: make(chan extension.Event, 10000)}
	f.audit = filepath.Join(f.dir, "received.jsonl")
	command := append([]string{bin, "--mode", mode, "--record", f.audit}, args...)
	timeout := 250
	if mode == "derived-flood" {
		timeout = 60000
	}
	entry := map[string]any{"name": "fault", "command": command, "fields": fields, "timeout_ms": timeout}
	entries := []any{entry}
	if mode == "two-hangs" {
		entry["command"] = []string{bin, "--mode", "loop", "--record", f.audit}
		entries = append(entries, map[string]any{"name": "second", "command": []string{bin, "--mode", "loop", "--record", f.audit + ".second"}, "fields": fields, "timeout_ms": 250})
	}
	if mode == "none" {
		entries = []any{}
	}
	b, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if rules != "" {
		rules += ","
	}
	plan := rulesPlan(t, rules+`"extensions":`+string(b))
	if allowance == 0 {
		allowance = 64 << 20
	}
	if intakeBytes == 0 {
		intakeBytes = 128 << 20
	}
	f.store, err = intake.New(intakeBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1 << 40, IntakeExhausted: f.store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	f.writer, err = processing.Open(f.dir, allowance)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.writer.Close() })
	f.run, err = processing.Start(processing.Options{Plan: plan, PolicyRevision: "independent-contract", Session: "independent-session", Intake: f.store, Gate: gate, Output: independentOutput{f.writer, f.out}, Derived: f.writer, Workers: workers, Clock: clock, Supervision: func(e extension.Event) { f.events <- e }})
	if err != nil {
		t.Fatalf("wiring, not the property: start: %v", err)
	}
	t.Cleanup(func() { _ = f.run.Close() })
	if c, ok := clock.(*independentClock); ok {
		independentPump(t, f, c)
	}
	if mode != "none" {
		f.event(t, extension.Ready)
	}
	if mode == "two-hangs" {
		f.event(t, extension.Ready)
	}
	return f
}

func (f *independentRun) event(t *testing.T, kind extension.EventKind) extension.Event {
	t.Helper()
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case e := <-f.events:
			if e.Kind == kind {
				return e
			}
		case <-deadline.C:
			t.Fatalf("wiring, not the property: extension never reached %s", kind)
			return extension.Event{}
		}
	}
}

func (f *independentRun) finish(t *testing.T) processing.Outcome {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	o, err := f.run.Finish(ctx, settled)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	return o
}

func independentAudit(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("wiring, not the property: no peer audit: %v", err)
	}
	var result []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte{'\n'}) {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("wiring, not the property: audit is incomplete: %v", err)
		}
		result = append(result, m)
	}
	return result
}

func independentReceived(t *testing.T, f *independentRun) []map[string]any {
	t.Helper()
	var got []map[string]any
	for _, m := range independentAudit(t, f.audit) {
		if m["type"] == "exchange" {
			got = append(got, m)
		}
	}
	if len(got) == 0 {
		t.Fatal("wiring, not the property: no exchange reached the faulty peer")
	}
	return got
}

func independentConserved(t *testing.T, o processing.Outcome) account.ExtensionCounts {
	t.Helper()
	if o.ExchangeIDs == 0 || len(o.Extensions) != 1 {
		t.Fatalf("wiring, not the property: no issued population or extension account: %+v", o)
	}
	c := o.Extensions[0]
	if c.Considered != o.ExchangeIDs || c.Considered != c.Changed+c.Unchanged+c.Failed+c.Pending || c.Pending != 0 {
		t.Errorf("seal does not conserve: ids=%d, counts=%+v", o.ExchangeIDs, c)
	}
	var failures, refused uint64
	for _, n := range c.FailedBy {
		failures += n
	}
	for _, n := range c.DerivedRefusedBy {
		refused += n
	}
	if failures != c.Failed || refused != c.DerivedRefused {
		t.Errorf("reason counts do not conserve: %+v", c)
	}
	return c
}

func independentCore(t *testing.T, out *lines) []string {
	t.Helper()
	var result []string
	for _, b := range out.all() {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		delete(m, "exchange_ids")
		delete(m, "exchange_id")
		delete(m, "extension_outcomes")
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, string(b))
	}
	slices.Sort(result)
	return result
}

func TestIndependentExtensionFailureRetainsSanitizedOutput(t *testing.T) {
	bin := independentPeer(t)
	for _, tc := range []struct {
		mode, reason string
		args         []string
	}{
		{"malformed", "malformed", nil}, {"unknown-id", "unknown_id", nil}, {"protocol", "protocol", nil},
		{"oversized", "oversized_frame", nil}, {"read-only", "read_only", nil}, {"not-given", "not_given", nil},
		{"declined", "declined", nil}, {"loop", "timeout", nil}, {"ignore-term", "timeout", nil},
		{"crash", "crash", []string{"--count", "3"}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			w := generate(t, workload.Shape{Connections: 8, Exchanges: 1, HeaderBytes: 160, RequestBodyBytes: 50, Seed: 371})
			rules := `"remove":{"headers":["x-field-1"]},"mask":{"headers":{"x-field-2":"MASKED"}}`
			control := independentStart(t, bin, "none", rules, []string{"request.line"}, 1, 0, 0, nil)
			feed(t, control.run, control.store, w)
			base := control.finish(t)
			f := independentStart(t, bin, tc.mode, rules, []string{"request.line", "request.headers"}, 2, 0, 0, nil, tc.args...)
			feed(t, f.run, f.store, w)
			o := f.finish(t)
			got := independentReceived(t, f)
			if tc.mode == "crash" && len(got) < 3 {
				t.Fatal("wiring, not the property: crash did not have three pending connections")
			}
			sent := map[uint64]bool{}
			for _, m := range got {
				id, err := strconv.ParseUint(m["id"].(string), 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				sent[id] = true
			}
			c := independentConserved(t, o)
			if c.FailedBy[tc.reason] == 0 {
				t.Errorf("failure %s was not counted: %+v", tc.reason, c)
			}
			if !reflect.DeepEqual(independentCore(t, control.out), independentCore(t, f.out)) {
				t.Error("failed extension changed or lost sanitized core output")
			}
			if o.Written != base.Written || o.Batches != base.Batches {
				t.Errorf("other connections or processing failed to progress: baseline=%+v actual=%+v", base, o)
			}
			outcomes := map[uint64]int{}
			for _, b := range f.out.all() {
				var a processing.Artifact
				if err := json.Unmarshal(b, &a); err != nil {
					t.Fatal(err)
				}
				for _, e := range a.ExtensionOutcomes {
					if a.ExchangeID == "" || a.Index == nil || *a.Index != e.Exchange {
						t.Fatalf("an outcome for exchange %d is on a line with exchange id %q and index %v", e.Exchange,
							a.ExchangeID, a.Index)
					}
					id, err := strconv.ParseUint(a.ExchangeID, 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					outcomes[id]++
					if sent[id] && e.Reason != tc.reason {
						t.Errorf("received id %d failed under %s, want %s", id, e.Reason, tc.reason)
					}
					if e.Outcome != "failed" || (e.Reason != tc.reason && e.Reason != "unavailable") {
						t.Errorf("wrong terminal outcome: %+v", e)
					}
				}
			}
			if len(outcomes) != w.Exchanges {
				t.Errorf("terminal outcomes cover %d of %d exchanges", len(outcomes), w.Exchanges)
			}
			for id, count := range outcomes {
				if count != 1 {
					t.Errorf("id %d has %d terminal outcomes", id, count)
				}
			}
		})
	}
}

func TestIndependentExtensionProjectionAndExcludedInput(t *testing.T) {
	bin := independentPeer(t)
	for _, defect := range []float64{0, 1} {
		t.Run(fmt.Sprint(defect), func(t *testing.T) {
			w := generate(t, workload.Shape{Connections: 2, Exchanges: 2, HeaderBytes: 160, RequestBodyBytes: 120, ResponseBodyBytes: 80, JSONShare: 1, DefectShare: defect, DefectKinds: []string{workload.DefectUnsupported}, Seed: 372})
			f := independentStart(t, bin, "record", `"remove":{"headers":["x-field-1"],"bodies":["request"]}`, []string{"request.headers", "request.body"}, 2, 0, 0, nil)
			feed(t, f.run, f.store, w)
			o := f.finish(t)
			got := independentReceived(t, f)
			var canary, excluded bool
			for _, m := range got {
				canary = false
				request := m["exchange"].(map[string]any)["request"].(map[string]any)["message"].(map[string]any)
				for _, v := range request["headers"].([]any) {
					h := v.(map[string]any)
					if h["name"] == "X-Field-2" && h["value"] != "" {
						canary = true
					}
				}
				if !canary {
					t.Fatal("wiring, not the property: selected unremoved canary never arrived in this exchange")
				}
				if m["output"].(map[string]any)["state"] == "excluded" {
					excluded = true
				}
			}
			if !canary {
				t.Fatal("wiring, not the property: selected unremoved canary never arrived")
			}
			if defect == 1 && !excluded {
				t.Fatal("wiring, not the property: no excluded exchange reached the peer")
			}
			var protected []string
			for _, entry := range w.Entries {
				if entry.Fragment == nil {
					continue
				}
				wire := string(entry.Fragment.Payload)
				for _, line := range strings.Split(wire, "\r\n") {
					if value, ok := strings.CutPrefix(line, "X-Field-1: "); ok {
						protected = append(protected, value)
					}
				}
				if strings.HasPrefix(wire, "POST ") {
					_, body, ok := strings.Cut(wire, "\r\n\r\n")
					if ok {
						protected = append(protected, base64.StdEncoding.EncodeToString([]byte(body)))
						var content map[string]any
						if json.Unmarshal([]byte(body), &content) == nil {
							if text, ok := content["text"].(string); ok && text != "" {
								protected = append(protected, text)
							}
						}
					}
				}
			}
			if len(protected) < 4 {
				t.Fatal("wiring, not the property: protected fixture values not established")
			}
			audit, err := os.ReadFile(f.audit)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(audit, []byte(`"detail":`)) {
				t.Error("parser diagnostic detail reached the peer")
			}
			for _, value := range protected {
				if bytes.Contains(audit, []byte(value)) {
					t.Error("a removed value reached the peer audit")
				}
			}
			for _, m := range got {
				e := m["exchange"].(map[string]any)
				request := e["request"].(map[string]any)["message"].(map[string]any)
				for field := range request {
					switch field {
					case "kind", "complete", "framed", "defect", "headers", "trailers", "body", "framing", "structure":
					default:
						t.Errorf("unselected or undefined request field %s was sent", field)
					}
				}
				if _, present := m["connection"]; present {
					t.Error("unselected connection record sent")
				}
				if len(e["response"].(map[string]any)) != 0 {
					t.Error("unselected response sent")
				}
				for _, v := range request["headers"].([]any) {
					h := v.(map[string]any)
					if h["name"] == "X-Field-1" {
						t.Error("removed header sent")
					}
					if h["name"] == "X-Field-2" && h["value"] != "" {
						canary = true
					}
				}
				body := request["body"].(map[string]any)
				if body["kept"] != "" {
					t.Errorf("removed body sent: %v", body)
				}
				if len(e["removed"].([]any)) < 2 {
					t.Error("removed fields were not marked in this exchange")
				}
				if m["output"].(map[string]any)["state"] == "excluded" {
					excluded = true
				}
			}
			if !canary {
				t.Fatal("wiring, not the property: selected unremoved canary never arrived")
			}
			if defect == 1 && !excluded {
				t.Fatal("wiring, not the property: no excluded exchange reached the peer")
			}
			independentConserved(t, o)
		})
	}
}

func TestIndependentExtensionBodyAndExclusionRefusals(t *testing.T) {
	bin := independentPeer(t)
	for _, tc := range []struct {
		mode, rules, reason string
		defect              float64
	}{
		{"removed-content", `"remove":{"bodies":["request"]}`, "removed_content", 0},
		{"excluded", "", "excluded", 1},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			w := generate(t, workload.Shape{Connections: 3, Exchanges: 2, RequestBodyBytes: 80, ResponseBodyBytes: 80, JSONShare: 1, DefectShare: tc.defect, DefectKinds: []string{workload.DefectUnsupported}, Seed: 373})
			control := independentStart(t, bin, "none", tc.rules, []string{"request.line", "request.body"}, 1, 0, 0, nil)
			feed(t, control.run, control.store, w)
			control.finish(t)
			f := independentStart(t, bin, tc.mode, tc.rules, []string{"request.line", "request.body"}, 2, 0, 0, nil)
			feed(t, f.run, f.store, w)
			o := f.finish(t)
			independentReceived(t, f)
			c := independentConserved(t, o)
			if c.FailedBy[tc.reason] == 0 {
				t.Errorf("missing refusal %s: %+v", tc.reason, c)
			}
			if !reflect.DeepEqual(independentCore(t, control.out), independentCore(t, f.out)) {
				t.Error("rejected replacement changed core output")
			}
		})
	}
}

func TestIndependentExtensionReplacementRunsPositionalRemoval(t *testing.T) {
	bin := independentPeer(t)
	f := independentStart(t, bin, "replacement", `"remove":{"json":{"request":["/items/0"]}}`, []string{"request.body"}, 1, 0, 0, nil)
	w := generate(t, workload.Shape{Connections: 2, Exchanges: 1, RequestBodyBytes: 80, JSONShare: 1, Seed: 374})
	feed(t, f.run, f.store, w)
	o := f.finish(t)
	independentReceived(t, f)
	c := independentConserved(t, o)
	if c.Changed != 2 {
		t.Errorf("replacement not accepted: %+v", c)
	}
	var replacements int
	for _, b := range f.out.all() {
		var a processing.Artifact
		if err := json.Unmarshal(b, &a); err != nil {
			t.Fatal(err)
		}
		if a.Reconstruction == nil {
			continue
		}
		for _, e := range a.Reconstruction.Exchanges {
			data, err := base64.StdEncoding.DecodeString(e.Request.Message.Body.Kept)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "remove-this") || !strings.Contains(string(data), "keep-this") {
				t.Errorf("replacement bypassed positional removal: %s", data)
			}
		}
		replacements += len(a.ReplacementExclusions)
	}
	if replacements != 2 {
		t.Errorf("replacement removals=%d want 2", replacements)
	}
}

func TestIndependentExtensionWorkerSetsIDsAndWireOrder(t *testing.T) {
	bin := independentPeer(t)
	w := generate(t, workload.Shape{Connections: 25, Exchanges: 4, Processes: 3, Concurrency: 7, HeaderBytes: 80, RequestBodyBytes: 100, JSONShare: .5, Seed: 375})
	var baseline []string
	var base processing.Outcome
	for _, workers := range []int{1, 4} {
		t.Run(strconv.Itoa(workers), func(t *testing.T) {
			f := independentStart(t, bin, "record", "", []string{"request.line", "response.line"}, workers, 0, 0, nil)
			feed(t, f.run, f.store, w)
			o := f.finish(t)
			got := independentReceived(t, f)
			if len(got) != w.Exchanges {
				t.Fatalf("wiring, not the property: peer saw %d of %d exchanges", len(got), w.Exchanges)
			}
			if o.ExchangeIDs != uint64(w.Exchanges) {
				t.Fatalf("issued ids=%d want %d", o.ExchangeIDs, w.Exchanges)
			}
			c := independentConserved(t, o)
			if c.Unchanged != uint64(w.Exchanges) {
				t.Errorf("unchanged=%d want %d", c.Unchanged, w.Exchanges)
			}
			seen := map[uint64]bool{}
			lineOf := map[uint64]string{}
			indexes := map[string]map[int]uint64{}
			retired := map[string]bool{}
			for _, b := range f.out.all() {
				var a processing.Artifact
				if err := json.Unmarshal(b, &a); err != nil {
					t.Fatal(err)
				}
				switch a.Route.Pipeline {
				case "exchanges":
					if a.ExchangeID == "" || a.Index == nil {
						t.Fatalf("an exchange line carries no exchange id or index: %s", b)
					}
					id, err := strconv.ParseUint(a.ExchangeID, 10, 64)
					if err != nil || id == 0 {
						t.Fatalf("exchange id %q is not a positive decimal: %v", a.ExchangeID, err)
					}
					if seen[id] {
						t.Errorf("exchange id %d is on two lines", id)
					}
					seen[id] = true
					lineOf[id] = a.Connection.ID
					if indexes[a.Connection.ID] == nil {
						indexes[a.Connection.ID] = map[int]uint64{}
					}
					if _, twice := indexes[a.Connection.ID][*a.Index]; twice {
						t.Errorf("connection %s has two lines at index %d", a.Connection.ID, *a.Index)
					}
					indexes[a.Connection.ID][*a.Index] = id
				case "connections":
					if a.ExchangeID != "" || a.Index != nil {
						t.Errorf("connection %s's retirement line carries exchange id %q and index %v", a.Connection.ID,
							a.ExchangeID, a.Index)
					}
					if retired[a.Connection.ID] {
						t.Errorf("connection %s has two retirement lines", a.Connection.ID)
					}
					retired[a.Connection.ID] = true
				}
			}
			if len(indexes) != 25 || len(retired) != 25 {
				t.Fatalf("wiring, not the property: exchange lines for %d and retirement lines for %d of 25 connections",
					len(indexes), len(retired))
			}
			for connection, byIndex := range indexes {
				for index := range 4 {
					if _, found := byIndex[index]; !found {
						t.Errorf("connection %s has no line at index %d", connection, index)
					}
				}
			}
			for id := uint64(1); id <= o.ExchangeIDs; id++ {
				if !seen[id] {
					t.Errorf("missing id %d", id)
				}
			}
			if uint64(len(seen)) != o.ExchangeIDs {
				t.Error("the lines' ids do not cover the issued ids")
			}
			pending := map[string]string{}
			next := map[string]int{}
			byID := map[string]string{}
			done := map[string]bool{}
			for _, m := range independentAudit(t, f.audit) {
				if sent, ok := m["sent"].(map[string]any); ok && sent["type"] == "result" {
					id := sent["id"].(string)
					delete(pending, byID[id])
					continue
				}
				switch m["type"] {
				case "exchange":
					key, ok := m["connection_id"].(string)
					if !ok || key == "" {
						t.Fatalf("exchange has no connection identity: %v", m)
					}
					id := m["id"].(string)
					if pending[key] != "" || done[key] {
						t.Error("overlap or exchange after connection_done")
					}
					index := int(m["index"].(float64))
					issued, err := strconv.ParseUint(id, 10, 64)
					if err != nil || !seen[issued] {
						t.Errorf("wire id %s is not an issued id", id)
					}
					if line := lineOf[issued]; line != key || indexes[key][index] != issued {
						t.Errorf("wire id %s at index %d is not the id on the line of its connection at that index", id, index)
					}
					if index != next[key] {
						t.Errorf("wire index=%d want=%d", index, next[key])
					}
					next[key]++
					pending[key] = id
					byID[id] = key
				case "connection_done":
					key, ok := m["connection_id"].(string)
					if !ok || key == "" {
						t.Fatalf("connection_done has no connection identity: %v", m)
					}
					if pending[key] != "" || next[key] != 4 {
						t.Errorf("early connection_done for %s", key)
					}
					if done[key] || m["count"] != "4" {
						t.Errorf("duplicate connection_done or wrong issued count: %v", m)
					}
					done[key] = true
				}
			}
			if len(done) != 25 {
				t.Errorf("connection_done=%d want 25", len(done))
			}
			core := independentCore(t, f.out)
			o.Extensions = nil
			o.ExchangeIDs = 0
			if baseline == nil {
				baseline = core
				base = o
			} else {
				if !reflect.DeepEqual(core, baseline) {
					t.Error("worker count changed core line set")
				}
				if !reflect.DeepEqual(o, base) {
					t.Errorf("worker count changed processing counts: %+v != %+v", o, base)
				}
			}
		})
	}
}

func TestIndependentExtensionUnchangedAndDerivedFlood(t *testing.T) {
	bin := independentPeer(t)
	w := generate(t, workload.Shape{Connections: 8, Exchanges: 1, HeaderBytes: 40, Seed: 376})
	control := independentStart(t, bin, "none", "", []string{"request.line"}, 2, 0, 0, nil)
	feed(t, control.run, control.store, w)
	base := control.finish(t)
	for _, mode := range []string{"unchanged", "cpu", "derived-flood", "summary", "stderr-flood", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			f := independentStart(t, bin, mode, "", []string{"request.line"}, 2, 0, 0, nil, "--count", "200")
			feed(t, f.run, f.store, w)
			o := f.finish(t)
			independentReceived(t, f)
			c := independentConserved(t, o)
			if !reflect.DeepEqual(independentCore(t, control.out), independentCore(t, f.out)) {
				t.Error("extension altered core records")
			}
			if o.Batches != base.Batches || o.Written != base.Written || o.ProcessingFailures != base.ProcessingFailures || o.OutputFailures != base.OutputFailures {
				t.Error("extension changed processing counts")
			}
			if mode == "derived-flood" {
				if c.DerivedWritten == 0 {
					t.Fatal("wiring, not the property: no derived line reached writer")
				}
			}
			if mode == "summary" && c.DerivedWritten != 1 {
				t.Errorf("shutdown summary lost: %+v", c)
			}
			if mode == "stderr-flood" {
				var events []extension.Event
				for len(f.events) > 0 {
					e := <-f.events
					if e.Kind == extension.Stderr {
						events = append(events, e)
					}
				}
				if len(events) == 0 {
					t.Fatal("wiring, not the property: stderr never reached the log callback")
				}
				if c.StderrDropped == 0 {
					t.Error("stderr flood not counted")
				}
				if uint64(len(events))+c.StderrDropped != uint64(200*w.Exchanges) {
					t.Errorf("stderr log/drop counts lost lines: logged=%d dropped=%d", len(events), c.StderrDropped)
				}
				for _, e := range events {
					retained, err := strconv.Unquote(`"` + e.Line + `"`)
					if err != nil || len(retained) > 1024 || !e.Cut || strings.ContainsAny(e.Line, "\x1b\t\r\n") {
						t.Errorf("stderr was not escaped and cut: %+v", e)
					}
				}
				span := events[len(events)-1].At.Sub(events[0].At)
				if len(events) > 10+int(span*10/time.Second) {
					t.Errorf("stderr log exceeded rate: %d in %s", len(events), span)
				}
			}
			if mode == "duplicate" && c.Duplicate != uint64(w.Exchanges) {
				t.Errorf("duplicate=%d want %d", c.Duplicate, w.Exchanges)
			}
			if c.DerivedWritten > 0 {
				b, err := os.ReadFile(filepath.Join(f.dir, "derived-fault.jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				for _, line := range bytes.Split(bytes.TrimSpace(b), []byte{'\n'}) {
					var d map[string]any
					if err := json.Unmarshal(line, &d); err != nil {
						t.Fatal(err)
					}
					if d["extension"] != "fault" || d["session"] != "independent-session" || (d["basis"] != "observed" && d["basis"] != "inferred") {
						t.Errorf("derived attribution: %s", line)
					}
				}
			}
		})
	}
}

// This clock publishes every armed timer, letting the test advance only after
// admission, instead of confusing an issued id with a queued extension call.
type independentClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*independentTimer
	armed  chan time.Duration
}
type independentTimer struct {
	clock   *independentClock
	at      time.Time
	ch      chan time.Time
	stopped bool
}

func (c *independentClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *independentClock) NewTimer(d time.Duration) extension.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &independentTimer{clock: c, at: c.now.Add(d), ch: make(chan time.Time, 1)}
	if d <= 0 {
		t.stopped = true
		t.ch <- c.now
	} else {
		// An already-fired timer has no future event to retain.
		c.timers = append(c.timers, t)
	}
	// Observation must not block supervision or cleanup under a faulty timer loop.
	select {
	case c.armed <- d:
	default:
	}
	return t
}

func TestIndependentExtensionChainWaitIsSumOfDeadlines(t *testing.T) {
	bin := independentPeer(t)
	c := &independentClock{now: time.Unix(1000, 0), armed: make(chan time.Duration, 10000)}
	f := independentStart(t, bin, "two-hangs", "", []string{"request.line"}, 1, 0, 0, c)
	pump := independentPump(t, f, c)
	w := generate(t, workload.Shape{Connections: 1, Exchanges: 1, Seed: 384})
	// Discard startup observations before admitting the exchanges.
	for len(c.armed) > 0 {
		<-c.armed
	}
	feed(t, f.run, f.store, w)
	for i := 0; i < 2; i++ {
		deadline := time.After(5 * time.Second)
		found := false
		for !found {
			select {
			case d := <-c.armed:
				found = d > 0
			case <-deadline:
				t.Fatal("wiring, not the property: next extension never admitted a call")
			}
		}
		path := f.audit
		if i == 1 {
			path += ".second"
		}
		independentEventually(t, "wiring, not the property: next peer did not receive its admitted call", func() bool {
			b, err := os.ReadFile(path)
			return err == nil && bytes.Contains(b, []byte(`"type":"exchange"`))
		})
		c.advance(250 * time.Millisecond)
		independentEventually(t, "extension held exchange beyond its own timeout", func() bool {
			o := f.run.Snapshot()
			return len(o.Extensions) == 2 && o.Extensions[i].FailedBy["timeout"] == 1
		})
	}
	independentEventually(t, "chain held exchange beyond sum of timeouts", func() bool { return len(f.out.all()) > 0 })
	if c.Now() != time.Unix(1000, 0).Add(500*time.Millisecond) {
		t.Fatal("wiring, not the property: clock moved outside the two deadlines")
	}
	pump()
	o := f.finish(t)
	independentReceived(t, f)
	for _, e := range o.Extensions {
		if e.Considered != o.ExchangeIDs || e.Considered != e.Failed+e.Changed+e.Unchanged || e.Pending != 0 || e.FailedBy["timeout"] != 1 {
			t.Errorf("chain account: %+v", e)
		}
	}
}
func (t *independentTimer) C() <-chan time.Time { return t.ch }
func (t *independentTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	was := !t.stopped
	t.stopped = true
	return was
}
func (c *independentClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, t := range c.timers {
		if !t.stopped && !t.at.After(c.now) {
			t.stopped = true
			t.ch <- c.now
		}
	}
}

func TestIndependentExtensionDeadlineDoesNotHoldOtherConnections(t *testing.T) {
	bin := independentPeer(t)
	c := &independentClock{now: time.Unix(1000, 0), armed: make(chan time.Duration, 10000)}
	f := independentStart(t, bin, "hold-first", "", []string{"request.line"}, 1, 0, 0, c)
	// Cleanup must also advance supervision's termination grace if an assertion
	// fails before Finish; otherwise a useful red would strand its own peer.
	stop := make(chan struct{})
	var pump sync.Once
	startPump := func() {
		pump.Do(func() {
			go func() {
				for {
					select {
					case <-stop:
						return
					case <-time.After(time.Millisecond):
						c.advance(time.Second)
					}
				}
			}()
		})
	}
	t.Cleanup(func() { startPump(); _ = f.run.Close(); close(stop) })
	w := generate(t, workload.Shape{Connections: 3, Exchanges: 1, Seed: 377})
	// Discard startup observations before admitting the exchanges.
	for len(c.armed) > 0 {
		<-c.armed
	}
	feed(t, f.run, f.store, w)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case d := <-c.armed:
			if d > 0 {
				goto admitted
			}
		case <-deadline:
			t.Fatal("wiring, not the property: no admitted deadline timer")
		}
	}
admitted:
	limit := time.Now().Add(5 * time.Second)
	for len(f.out.all()) < 2 && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	if len(f.out.all()) < 2 {
		t.Fatal("other connections stalled behind the unanswered exchange")
	}
	c.advance(250 * time.Millisecond)
	limit = time.Now().Add(5 * time.Second)
	for f.run.Snapshot().Extensions[0].FailedBy["timeout"] == 0 && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	if f.run.Snapshot().Extensions[0].FailedBy["timeout"] != 1 {
		t.Error("admitted exchange did not expire at its deadline")
	}
	c.advance(10 * time.Second)
	// Finish may arm shutdown timers after this call; keep moving only once the
	// deadline and independent progress assertions above are settled.
	startPump()
	o := f.finish(t)
	independentReceived(t, f)
	independentConserved(t, o)
}

func independentEventually(t *testing.T, why string, ready func() bool) {
	t.Helper()
	until := time.Now().Add(12 * time.Second)
	for time.Now().Before(until) {
		if ready() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(why)
}

func independentPump(t *testing.T, f *independentRun, c *independentClock) func() {
	t.Helper()
	stop := make(chan struct{})
	var once sync.Once
	start := func() {
		once.Do(func() {
			go func() {
				for {
					select {
					case <-stop:
						return
					case <-time.After(time.Millisecond):
						c.advance(time.Second)
					}
				}
			}()
		})
	}
	t.Cleanup(func() { start(); _ = f.run.Close(); close(stop) })
	return start
}

func TestIndependentExtensionAdmissionBoundsSkipBusy(t *testing.T) {
	bin := independentPeer(t)
	for _, which := range []string{"in-flight", "waiting-bytes"} {
		t.Run(which, func(t *testing.T) {
			c := &independentClock{now: time.Unix(1000, 0), armed: make(chan time.Duration, 20000)}
			shape := workload.Shape{Connections: 4097, Exchanges: 1, Seed: 378}
			intakeBytes := int64(128 << 20)
			if which == "waiting-bytes" {
				shape.Connections = 8
				shape.RequestBodyBytes = 12000
				// Intake, parser and policy copies must fit before admission is tested.
				intakeBytes = 512 << 10
			}
			f := independentStart(t, bin, "loop", "", []string{"request.line"}, 4, 0, intakeBytes, c)
			pump := independentPump(t, f, c)
			w := generate(t, shape)
			feed(t, f.run, f.store, w)
			independentEventually(t, "wiring, not the property: generated batches did not reach extension accounting", func() bool {
				o := f.run.Snapshot()
				return o.ExchangeIDs == uint64(w.Exchanges) && len(o.Extensions) == 1
			})
			independentEventually(t, "full extension bound did not produce busy skips", func() bool { return f.run.Snapshot().Extensions[0].FailedBy["busy"] > 0 })
			independentEventually(t, "busy connections did not reach output", func() bool { return f.run.Snapshot().Written > 0 })
			snapshot := f.run.Snapshot()
			counts := snapshot.Extensions[0]
			if which == "in-flight" && counts.Pending != 4096 {
				t.Errorf("in-flight pending=%d want 4096", counts.Pending)
			}
			if which == "waiting-bytes" && (counts.Pending == 0 || counts.Pending >= 8) {
				t.Errorf("waiting bytes did not bound the pending population: %+v", counts)
			}
			if snapshot.Written == 0 {
				t.Error("busy connections made no processing progress")
			}
			select {
			case <-f.store.Exhausted():
				t.Error("extension exhausted intake")
			default:
			}
			c.advance(250 * time.Millisecond)
			pump()
			o := f.finish(t)
			independentReceived(t, f)
			independentConserved(t, o)
		})
	}
}

func TestIndependentExtensionBlockedPipeDeadlineIncludesWrite(t *testing.T) {
	bin := independentPeer(t)
	c := &independentClock{now: time.Unix(1000, 0), armed: make(chan time.Duration, 10000)}
	f := independentStart(t, bin, "blocked-stdin", "", []string{"request.body"}, 2, 0, 0, c)
	pump := independentPump(t, f, c)
	w := generate(t, workload.Shape{Connections: 4, Exchanges: 1, RequestBodyBytes: 512 << 10, Seed: 379})
	control := independentStart(t, bin, "none", "", []string{"request.body"}, 1, 0, 0, nil)
	feed(t, control.run, control.store, w)
	base := control.finish(t)
	var startupTimers []time.Duration
	for len(c.armed) > 0 {
		startupTimers = append(startupTimers, <-c.armed)
	}
	t.Logf("startup timer observations discarded before blocked-pipe admission: %v", startupTimers)
	feed(t, f.run, f.store, w)
	independentEventually(t, "wiring, not the property: large exchange never admitted to blocked pipe", func() bool { o := f.run.Snapshot(); return len(o.Extensions) == 1 && o.Extensions[0].Pending > 0 })
	deadline := time.After(5 * time.Second)
	for {
		select {
		case d := <-c.armed:
			if d > 0 {
				t.Logf("blocked-pipe timer armed after feed: %s", d)
				goto armed
			}
		case <-deadline:
			t.Fatal("wiring, not the property: no blocked-write deadline")
		}
	}
armed:
	c.advance(250 * time.Millisecond)
	independentEventually(t, "blocked write held exchange past its deadline", func() bool { return f.run.Snapshot().Extensions[0].FailedBy["timeout"] > 0 })
	pump()
	o := f.finish(t)
	independentConserved(t, o)
	if o.Written != base.Written || o.Batches != base.Batches || !reflect.DeepEqual(independentCore(t, control.out), independentCore(t, f.out)) {
		t.Errorf("blocked pipe lost or changed eligible core output: %+v", o)
	}
	for _, m := range independentAudit(t, f.audit) {
		if m["type"] == "exchange" {
			t.Fatal("wiring, not the property: blocked peer read an exchange")
		}
	}
}

func TestIndependentExtensionRestartDoesNotReplayAndCountsStateLoss(t *testing.T) {
	bin := independentPeer(t)
	f := independentStart(t, bin, "crash", "", []string{"request.line"}, 2, 0, 0, nil, "--count", "1", "--first-generation")
	w := generate(t, workload.Shape{Connections: 2, Exchanges: 1, Seed: 380})
	var first, second workload.Workload
	for _, e := range w.Entries {
		id := uint64(0)
		if e.Fragment != nil {
			id = uint64(e.Fragment.Connection)
		} else {
			id = uint64(e.Connection.ID)
		}
		if id == uint64(w.Connections[0].ID) {
			first.Entries = append(first.Entries, e)
		} else {
			second.Entries = append(second.Entries, e)
		}
	}
	feed(t, f.run, f.store, &first)
	f.event(t, extension.Retired)
	f.event(t, extension.Ready)
	feed(t, f.run, f.store, &second)
	o := f.finish(t)
	got := independentReceived(t, f)
	c := independentConserved(t, o)
	if len(got) != 2 || got[0]["id"] == got[1]["id"] {
		t.Errorf("restart replayed or lost a received exchange: %v", got)
	}
	if c.FailedBy["crash"] != 1 || c.Unchanged != 1 || c.Restarts != 1 || c.StateResets != 1 {
		t.Errorf("restart state/counts: %+v", c)
	}
}

func TestIndependentExtensionResultTimeoutRaceHasOneTerminalOutcome(t *testing.T) {
	bin := independentPeer(t)
	for _, delay := range []string{"1ms", "250ms", "400ms"} {
		t.Run(delay, func(t *testing.T) {
			f := independentStart(t, bin, "race", "", []string{"request.line"}, 2, 0, 0, nil, "--delay", delay)
			w := generate(t, workload.Shape{Connections: 12, Exchanges: 1, Seed: 381})
			feed(t, f.run, f.store, w)
			o := f.finish(t)
			independentReceived(t, f)
			c := independentConserved(t, o)
			if delay == "1ms" && c.Unchanged != 12 {
				t.Errorf("in-time results failed: %+v", c)
			}
			if delay == "400ms" && c.FailedBy["timeout"] == 0 {
				t.Error("late result won over elapsed deadline")
			}
			if o.Batches != 12 || o.Written == 0 {
				t.Error("race lost core output")
			}
		})
	}
}

func TestIndependentExtensionPersistentDerivedFloodRetiresWithoutBlockingResults(t *testing.T) {
	bin := independentPeer(t)
	c := &independentClock{now: time.Unix(1000, 0), armed: make(chan time.Duration, 10000)}
	f := independentStart(t, bin, "derived-flood", "", []string{"request.line"}, 2, 0, 0, c, "--count", "0")
	pump := independentPump(t, f, c)
	w := generate(t, workload.Shape{Connections: 2, Exchanges: 1, Seed: 382})
	feed(t, f.run, f.store, w)
	independentEventually(t, "wiring, not the property: derived flood never exceeded the rate", func() bool {
		return len(f.run.Snapshot().Extensions) == 1 && f.run.Snapshot().Extensions[0].DerivedRefusedBy["rate"] > 0
	})
	for i := 0; i < 11; i++ {
		before := f.run.Snapshot().Extensions[0]
		if before.RetiredBy["flood"] > 0 {
			break
		}
		c.advance(time.Second)
		independentEventually(t, "flood did not reach the next rate window", func() bool {
			now := f.run.Snapshot().Extensions[0]
			return now.RetiredBy["flood"] > 0 || now.DerivedRefusedBy["rate"] > before.DerivedRefusedBy["rate"]+1100
		})
		now := f.run.Snapshot().Extensions[0]
		t.Logf("controlled second %d: rate refusals %d -> %d, flood retirements %d", i+1, before.DerivedRefusedBy["rate"], now.DerivedRefusedBy["rate"], now.RetiredBy["flood"])
	}
	if f.run.Snapshot().Extensions[0].RetiredBy["flood"] != 1 {
		t.Errorf("persistent rate refusal did not retire flood: %+v", f.run.Snapshot().Extensions[0])
	}
	pump()
	o := f.finish(t)
	independentReceived(t, f)
	counts := independentConserved(t, o)
	if counts.FailedBy["flood"] == 0 || counts.FailedBy["timeout"] != 0 {
		t.Errorf("flood retired under wrong cause: %+v", counts)
	}
	if o.Written == 0 || o.Batches != 2 {
		t.Errorf("flood stopped processing: %+v", o)
	}
}

func TestIndependentExtensionLateResultIsCountedApartFromItsFailure(t *testing.T) {
	bin := independentPeer(t)
	c := &independentClock{now: time.Unix(1000, 0), armed: make(chan time.Duration, 10000)}
	f := independentStart(t, bin, "late", "", []string{"request.line"}, 1, 0, 0, c)
	pump := independentPump(t, f, c)
	w := generate(t, workload.Shape{Connections: 1, Exchanges: 1, Seed: 383})
	feed(t, f.run, f.store, w)
	deadline := time.After(5 * time.Second)
	for {
		select {
		case d := <-c.armed:
			independentEventually(t, "wiring, not the property: late peer never received its admitted exchange", func() bool {
				b, err := os.ReadFile(f.audit)
				return err == nil && bytes.Contains(b, []byte(`"type":"exchange"`))
			})
			if d == 250*time.Millisecond {
				goto armed
			}
		case <-deadline:
			t.Fatal("wiring, not the property: no admitted call")
		}
	}
armed:
	// The peer answers in its TERM handler, so the result can only be late.
	c.advance(250 * time.Millisecond)
	f.event(t, extension.Retired)
	independentEventually(t, "late answer was not counted", func() bool { return f.run.Snapshot().Extensions[0].Late == 1 })
	pump()
	o := f.finish(t)
	independentReceived(t, f)
	counts := independentConserved(t, o)
	if counts.FailedBy["timeout"] != 1 || counts.Unchanged != 0 || counts.Late != 1 {
		t.Errorf("late answer changed the terminal outcome: %+v", counts)
	}
}
