package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

const (
	p3t9bSecret  = "T9B_PROTECTED_6d2e9a"
	p3t9bSuffix  = "T9B_SUFFIX_4c8b1f"
	p3t9bPublic  = "T9B_PERMITTED_8f3a6c"
	p3t9bBody    = "T9B_BODY_9a7c2e"
	p3t9bReplace = "T9B_REPLACED_5a1d"
)

// Independent condition-2 acceptance. Production capture/controller/worker/
// writer receive synthetic measured events in an exited child process. Only
// account.json and approved.jsonl survive; observations are made through the
// public binary. This is not a kernel-attachment or whole-run-write monitor.
func TestP3T9BCondition2PublicInspection(t *testing.T) {
	if destination := os.Getenv("P3T9B_PRODUCER_DEST"); destination != "" {
		p3t9bProduce(t, destination, os.Getenv("P3T9B_CASE"))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "observer")
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("apparatus: build public command: %v\n%s", err, out)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"removed", "never_present", "legacy_absent", "legacy_null", "suffix_withheld", "suffix_complete", "replaced", "truncated"} {
		t.Run(name, func(t *testing.T) {
			source := t.TempDir()
			producer := exec.CommandContext(ctx, self, "-test.run=^TestP3T9BCondition2PublicInspection$")
			producer.Env = append(os.Environ(), "P3T9B_PRODUCER_DEST="+source, "P3T9B_CASE="+name)
			if out, err := producer.CombinedOutput(); err != nil {
				t.Fatalf("apparatus: producer failed before inspection: %v\n%s", err, out)
			} else {
				t.Logf("producer witness: %s", out)
			}
			if producer.ProcessState == nil || !producer.ProcessState.Exited() || !producer.ProcessState.Success() {
				t.Fatal("apparatus: producer exit not established")
			}
			directory := t.TempDir()
			for _, file := range []string{sealedName, processing.ArtifactName} {
				data, err := os.ReadFile(filepath.Join(source, file))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(directory, file), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.RemoveAll(source); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 2 {
				t.Fatalf("apparatus: copy population: %v %v", entries, err)
			}
			path := filepath.Join(directory, processing.ArtifactName)
			wire, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var members map[string]json.RawMessage
			if err := json.Unmarshal(wire, &members); err != nil {
				t.Fatal(err)
			}
			if name == "legacy_absent" || name == "legacy_null" {
				delete(members, "policy_exclusions")
				wire, err = json.Marshal(members)
				if err != nil {
					t.Fatal(err)
				}
				if name == "legacy_null" {
					// Actual public-type round trip, not a hand-written null.
					var legacy processing.Artifact
					if err := json.Unmarshal(wire, &legacy); err != nil {
						t.Fatal(err)
					}
					if legacy.PolicyExclusions != nil {
						t.Fatal("apparatus: absent key did not decode nil")
					}
					wire, err = json.Marshal(legacy)
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(path, append(wire, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
			members = nil
			if err := json.Unmarshal(wire, &members); err != nil {
				t.Fatal(err)
			}
			form, present := members["policy_exclusions"]
			switch name {
			case "legacy_absent":
				if present {
					t.Fatal("apparatus: absent wire member is present")
				}
			case "legacy_null":
				if !present || string(form) != "null" {
					t.Fatalf("apparatus: null wire form=%s", form)
				}
			case "removed":
				if !present || len(form) < 3 || form[0] != '[' {
					t.Fatalf("apparatus: populated wire form=%s", form)
				}
			default:
				if !present || string(form) != "[]" {
					t.Fatalf("apparatus: empty-array wire form=%s", form)
				}
			}
			// Install a valid changed local policy. Public inspection must read
			// the persisted result rather than use this new removal rule.
			local := t.TempDir()
			changed := p3t9bConfiguration(t, config.RemoveHeaders, `{"headers":["x-public"]}`)
			policyPath := filepath.Join(local, "observer.config.json")
			if err := os.WriteFile(policyPath, changed, 0600); err != nil {
				t.Fatal(err)
			}
			policy, err := loadProcessing(policyPath)
			if err != nil {
				t.Fatalf("apparatus: changed policy refused: %v", err)
			}
			var persisted processing.Artifact
			if err := json.Unmarshal(wire, &persisted); err != nil {
				t.Fatal(err)
			}
			if policy.ProcessingRevision == persisted.PolicyRevision {
				t.Fatal("apparatus: policy identity did not change")
			}
			command := exec.CommandContext(ctx, binary, "inspect", directory, "--text")
			command.Dir = local
			out, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("PUBLIC_READ: unexpected refusal: %v\n%s", err, out)
			}
			p3t9bAssertOutput(t, name, out, persisted.PolicyRevision)
		})
	}
}

func p3t9bAssertOutput(t *testing.T, name string, out []byte, revision string) {
	t.Helper()
	text := string(out)
	// Check the whole public output, including account, diagnostics and the
	// renderer's decoded body section. This is an explicit marker oracle, not
	// an assertion that every possible encoding or unrelated value is covered.
	for _, forbidden := range []string{p3t9bSecret} {
		p3t9bAbsent(t, "PROTECTED_ABSENCE", out, forbidden)
	}
	if name == "suffix_withheld" {
		p3t9bAbsent(t, "SUFFIX_ABSENCE", out, p3t9bSuffix)
	}
	for _, want := range []string{p3t9bPublic, p3t9bBody, "policy_revision=" + strconv.Quote(revision), `pipeline="exchanges"`, `sink="account"`, `"direction": "sent"`, `"offset": "0"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("USEFUL_OUTPUT: public output omitted %q\n%s", want, out)
		}
	}
	a := p3t9bPublicArtifact(t, text)
	if a.Reconstruction == nil || len(a.Reconstruction.Exchanges) == 0 {
		t.Fatal("USEFUL_OUTPUT: no retained exchange")
	}
	first := a.Reconstruction.Exchanges[0]
	if first.Request.Message == nil || first.Response.Message == nil {
		t.Fatal("USEFUL_OUTPUT: missing message")
	}
	if got, err := base64.StdEncoding.DecodeString(first.Response.Message.Body.Kept); err != nil || string(got) != p3t9bBody {
		t.Fatalf("USEFUL_OUTPUT: retained body=%q err=%v", got, err)
	}
	var want []processing.PolicyExclusion
	if name == "removed" {
		for _, side := range []string{"request", "response"} {
			for _, section := range []string{"headers", "trailers"} {
				want = append(want, processing.PolicyExclusion{Exchange: 0, Message: side, Field: config.HeaderFieldPrefix + "authorization", Section: section, Disposition: processing.DispositionRemoved})
			}
		}
	}
	for _, side := range []record.Side{first.Request, first.Response} {
		for _, fields := range [][]record.Field{side.Message.Headers, side.Message.Trailers} {
			for _, f := range fields {
				if strings.EqualFold(f.Name, "authorization") {
					t.Fatal("REMOVED_FIELD: protected field remains present")
				}
			}
		}
	}
	switch name {
	case "legacy_absent", "legacy_null":
		if a.PolicyExclusions != nil || !strings.Contains(text, "policy exclusions  unavailable:") || strings.Contains(text, "policy exclusions  none excluded") || strings.Contains(text, "policy excluded  exchange=") {
			t.Fatalf("LEGACY_UNAVAILABLE: legacy evidence misrepresented\n%s", out)
		}
	case "removed":
		if a.Version != processing.ArtifactVersion {
			t.Fatalf("EXCLUSION_TUPLES: artifact version %q, want %q", a.Version, processing.ArtifactVersion)
		}
		got := make(map[processing.PolicyExclusion]bool)
		for _, e := range a.PolicyExclusions {
			got[e] = true
		}
		if len(a.PolicyExclusions) != len(want) || len(got) != len(want) {
			t.Fatalf("EXCLUSION_TUPLES: got %+v want %+v", a.PolicyExclusions, want)
		}
		rendered := t20iRenderedEntries(text, want[0].Field)
		for _, e := range want {
			if !got[e] || t20iRenderedCount(rendered, e) != 1 {
				t.Fatalf("EXCLUSION_TUPLES: missing/duplicate entry %+v\n%s", e, out)
			}
		}
		if len(rendered) != len(want) || strings.Contains(text, "policy exclusions  unavailable:") || strings.Contains(text, "policy exclusions  none excluded") {
			t.Fatal("EXCLUSION_TUPLES: contradictory disposition")
		}
	default:
		if a.PolicyExclusions == nil || len(a.PolicyExclusions) != 0 || !strings.Contains(text, "policy exclusions  none excluded in retained messages; no claim about an indeterminate suffix") || strings.Contains(text, "policy exclusions  unavailable:") || strings.Contains(text, "policy excluded  exchange=") {
			t.Fatalf("NONE_EXCLUDED: known empty evidence misrepresented\n%s", out)
		}
	}
	if name == "suffix_withheld" {
		trunc := a.ReconstructionTruncation
		if trunc == nil || trunc.State != "truncated" || trunc.Suffix != "indeterminate" || len(trunc.Stops) != 1 {
			t.Fatalf("SUFFIX_EVIDENCE: missing truncation: %+v", trunc)
		}
		stop := trunc.Stops[0]
		if stop.Direction != "sent" || stop.Offset != strconv.Itoa(len(p3t9bRequest(""))) || stop.Reason != "incomplete_message" || stop.EvidenceOffset != strconv.Itoa(len(p3t9bRequest("")+p3t9bTail(false))) {
			t.Fatalf("SUFFIX_EVIDENCE: wrong boundary: %+v", stop)
		}
		u := a.Reconstruction.Unplaced
		if u.State != record.Undetermined || u.Unit != record.Bytes || u.Value != "" || u.Why != "reconstruction_truncated" || len(a.Reconstruction.Exchanges) != 1 {
			t.Fatalf("SUFFIX_EVIDENCE: not a useful prefix with unknown remainder: %+v", a.Reconstruction)
		}
	} else if a.ReconstructionTruncation != nil {
		t.Fatalf("DECIDABLE_CONTROL: unexpected truncation: %+v", a.ReconstructionTruncation)
	}
	if name == "suffix_complete" {
		if len(a.Reconstruction.Exchanges) != 2 || a.Reconstruction.Exchanges[1].Request.Message.Target != "/"+p3t9bSuffix || !strings.Contains(text, p3t9bSuffix) {
			t.Fatal("SUFFIX_CONTROL: completed suffix was not displayed")
		}
	}
	if name == "replaced" || name == "truncated" {
		value := p3t9bReplace
		if name == "truncated" {
			value = "KEEP"
		}
		seen := false
		for _, f := range first.Request.Message.Headers {
			if strings.EqualFold(f.Name, "x-transform") {
				seen = f.Value == value
			}
		}
		if !seen {
			t.Fatalf("TRANSFORM_PRESENT: %s must keep transformed field value %q", name, value)
		}
	}
}

// t20iRenderedEntries are the lines of the text rendering, outside the
// indented artifact, that name this field, a message and the removed
// disposition. The version 2 line has no published format, so an entry is
// matched by what it names rather than by its layout.
func t20iRenderedEntries(text, field string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.ContainsAny(trimmed[:1], "\"{}[]") {
			continue
		}
		if strings.Contains(line, field) && strings.Contains(line, processing.DispositionRemoved) &&
			(strings.Contains(line, "request") || strings.Contains(line, "response")) {
			lines = append(lines, line)
		}
	}
	return lines
}

// t20iRenderedCount is how many rendered lines name e's message and section.
// The section is looked for outside the field, which itself holds "headers".
func t20iRenderedCount(lines []string, e processing.PolicyExclusion) int {
	count := 0
	for _, line := range lines {
		rest := strings.ReplaceAll(line, e.Field, "")
		if strings.Contains(rest, e.Message) && strings.Contains(rest, e.Section) {
			count++
		}
	}
	return count
}

func p3t9bAbsent(t *testing.T, assertion string, out []byte, value string) {
	t.Helper()
	for _, representation := range []string{value, base64.StdEncoding.EncodeToString([]byte(value))} {
		if bytes.Contains(out, []byte(representation)) {
			t.Fatalf("%s: forbidden marker in public output", assertion)
		}
	}
}

func p3t9bPublicArtifact(t *testing.T, text string) processing.Artifact {
	t.Helper()
	start := strings.Index(text, "approved artifact  version=")
	if start < 0 {
		t.Fatal("USEFUL_OUTPUT: public artifact heading absent")
	}
	start += strings.IndexByte(text[start:], '\n') + 1
	var a processing.Artifact
	if err := json.NewDecoder(strings.NewReader(text[start:])).Decode(&a); err != nil {
		t.Fatalf("PUBLIC_SHAPE: %v", err)
	}
	return a
}

func p3t9bRequest(extra string) string {
	return "GET /retained HTTP/1.1\r\nX-Public: " + p3t9bPublic + "\r\n" + extra + "\r\n"
}

func p3t9bTail(complete bool) string {
	tail := "GET /" + p3t9bSuffix + " HTTP/1.1\r\nX-Tail: received"
	if complete {
		tail += "\r\n\r\n"
	}
	return tail
}

func p3t9bProduce(t *testing.T, destination, name string) {
	t.Helper()
	implementation, arguments := config.RemoveHeaders, `{"headers":["authorization"]}`
	if name == "replaced" {
		implementation, arguments = config.ReplaceHeaderValues, `{"headers":["x-transform"],"value":"`+p3t9bReplace+`"}`
	}
	if name == "truncated" {
		implementation, arguments = config.TruncateHeaderValues, `{"headers":["x-transform"],"length":4}`
	}
	f := p3t9bController(t, p3t9bConfiguration(t, implementation, arguments))
	request := p3t9bRequest("")
	response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(p3t9bBody), p3t9bBody)
	switch name {
	case "removed":
		// Duplicate mixed-case fields must produce one lowercase tuple per
		// section, not values, configured-name guesses, or duplicate evidence.
		fields := "Authorization: " + p3t9bSecret + "\r\naUtHoRiZaTiOn: " + p3t9bSecret + "\r\n"
		request = "POST /retained HTTP/1.1\r\nX-Public: " + p3t9bPublic + "\r\nTransfer-Encoding: chunked\r\n" + fields + "\r\n0\r\n" + fields + "\r\n"
		response = fmt.Sprintf("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n%s\r\n%x\r\n%s\r\n0\r\n%s\r\n", fields, len(p3t9bBody), p3t9bBody, fields)
	case "suffix_withheld", "suffix_complete":
		request += p3t9bTail(name == "suffix_complete")
		if name == "suffix_complete" {
			response += "HTTP/1.1 204 No Content\r\n\r\n"
		}
	case "replaced":
		request = p3t9bRequest("X-Transform: " + p3t9bSecret + "\r\n")
	case "truncated":
		request = p3t9bRequest("X-Transform: KEEP" + p3t9bSecret + "\r\n")
	}
	if name == "removed" || name == "replaced" || name == "truncated" {
		if !strings.Contains(request, p3t9bSecret) {
			t.Fatal("apparatus: protected input not constructed")
		}
	}
	if strings.HasPrefix(name, "suffix_") && !strings.Contains(request, p3t9bSuffix) {
		t.Fatal("apparatus: suffix input not constructed")
	}
	f.transfer(t, 7, fragment.Sent, request)
	f.transfer(t, 7, fragment.Received, response)
	// Withheld case remains open at observer finalization. Its completed
	// neighbor is also open, changing only framing and the paired response.
	if !strings.HasPrefix(name, "suffix_") {
		f.closed(t, 7)
	}
	f.live = true
	f.halt(t)
	if err := f.finish(&logger{}); err != nil {
		t.Fatal(err)
	}
	if got := f.d.capture.Stats(); got.Transfers != 2 || got.Rejected != 0 {
		t.Fatalf("apparatus: capture did not accept both supplied transfers: %+v", got)
	}
	if got := f.d.output.Stats(); got.Written != 1 || !got.Closed {
		t.Fatalf("apparatus: useful output not sealed: %+v", got)
	}
	for _, file := range []string{sealedName, processing.ArtifactName} {
		data, err := os.ReadFile(filepath.Join(f.d.directory, file))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, file), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Printf("REACHED case=%s transfers=2 rejected=0 request_bytes=%d response_bytes=%d protected_input=%t suffix_input=%t writer_records=1 sealed=true\n", name, len(request), len(response), strings.Contains(request, p3t9bSecret), strings.Contains(request, p3t9bSuffix))
}

func p3t9bConfiguration(t *testing.T, implementation, arguments string) []byte {
	t.Helper()
	raw, err := config.Examples.ReadFile("examples/no-extension.config.json")
	if err != nil {
		t.Fatal(err)
	}
	var c config.Configuration
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.Pipelines = []config.Pipeline{{Name: "exchanges", Input: "reconstruction", Sinks: []string{"account"}, Slots: []config.Slot{{Name: "condition2", Implementation: implementation, Configuration: json.RawMessage(arguments), OnFailure: config.OnFailureDropAndAccount}}}}
	raw, err = json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Reuse only the existing synthetic producer's mechanical transfer/lifecycle
// helpers. Configuration, witnesses and every acceptance assertion are owned
// by this file; no implementer's condition-2 assertion is invoked or edited.
func p3t9bController(t *testing.T, configuration []byte) *processingControllerFixture {
	t.Helper()
	read := loaded(t, string(configuration))
	read.Settings.Directory = t.TempDir()
	directory := filepath.Join(read.Settings.Directory, sessionsName, "condition2")
	output, err := processing.Open(directory, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	recording, store, err := recordingIntake(100)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 100, StorageExhausted: output.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	f := &processingControllerFixture{stop: make(chan os.Signal, 1), done: make(chan struct{})}
	f.producer = &processingProducer{withdrawn: true, drained: true, stamp: &f.stamp}
	f.d = &daemon{policy: read, session: "condition2", directory: directory, capture: recording,
		intake: store, gate: gate, output: output, storageExhausted: output.Exhausted(), attached: f.producer,
		plan: account.Account{Version: account.Version, Session: "condition2", Policy: account.Policy{Revision: read.Revision, Generation: 1}},
	}
	go func() { f.d.serveUntilStop(f.stop, nil, nil, nil, nil, account.Account{}); close(f.done) }()
	t.Cleanup(func() {
		if !f.ended {
			f.halt(t)
		}
		if f.live && !f.finalized {
			_ = f.finish(&logger{})
		}
		_ = output.Close()
		_ = store.Close()
	})
	return f
}
