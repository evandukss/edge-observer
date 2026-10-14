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
	"sync"
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
	inspectionSecret  = "INS_PROTECTED_6d2e9a"
	inspectionSuffix  = "INS_SUFFIX_4c8b1f"
	inspectionPublic  = "INS_PERMITTED_8f3a6c"
	inspectionBody    = "INS_BODY_9a7c2e"
	inspectionReplace = "INS_REPLACED_5a1d"
)

// Independent condition-2 acceptance. Production capture/controller/worker/
// writer receive synthetic measured events in an exited child process. Only
// account.json and approved.jsonl survive; observations are made through the
// public binary. This is not a kernel-attachment or whole-run-write monitor.
func TestPublicInspectionOfAnExitedProducer(t *testing.T) {
	if destination := os.Getenv("INSPECTION_PRODUCER_DEST"); destination != "" {
		inspectionProduce(t, destination, os.Getenv("INSPECTION_CASE"))
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
			producer := exec.CommandContext(ctx, self, "-test.run=^TestPublicInspectionOfAnExitedProducer$")
			producer.Env = append(os.Environ(), "INSPECTION_PRODUCER_DEST="+source, "INSPECTION_CASE="+name)
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
			file, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			lines, exchanges := inspectionRoutes(t, file, inspectionExchanges(name))
			wire := lines[exchanges[0]]
			var members map[string]json.RawMessage
			if err := json.Unmarshal(wire, &members); err != nil {
				t.Fatal(err)
			}
			if name == "legacy_absent" || name == "legacy_null" {
				var final processing.Artifact
				for _, line := range lines {
					var candidate processing.Artifact
					if err := json.Unmarshal(line, &candidate); err != nil {
						t.Fatal(err)
					}
					if candidate.Record == processing.ArtifactConnection {
						final = candidate
					}
				}
				if final.Connection.ID == "" || final.Connection.Provisional {
					t.Fatal("wiring, not the property: legacy fixture has no final connection record")
				}
				// An artifact written before the member existed lacks it on
				// every record, the connection record included. Only a
				// historical version may lack it, so the records are made
				// version 1 records: that version's label, and none of the
				// members a later version added. Every historical line carries
				// the connection's final record, including exchange lines.
				for i, line := range lines {
					var current processing.Artifact
					if err := json.Unmarshal(line, &current); err != nil {
						t.Fatal(err)
					}
					if current.Session != final.Session || current.Connection.ID != final.Connection.ID ||
						current.Connection.Process != final.Connection.Process {
						t.Fatal("wiring, not the property: legacy line does not join its final connection record")
					}
					var each map[string]json.RawMessage
					if err := json.Unmarshal(line, &each); err != nil {
						t.Fatal(err)
					}
					each["connection"], err = json.Marshal(final.Connection)
					if err != nil {
						t.Fatal(err)
					}
					if current.Reconstruction != nil && final.ReconstructionUnplaced != nil {
						current.Reconstruction.Unplaced = *final.ReconstructionUnplaced
						each["reconstruction"], err = json.Marshal(current.Reconstruction)
						if err != nil {
							t.Fatal(err)
						}
					}
					delete(each, "policy_exclusions")
					for _, later := range []string{"record", "session", "exchange_id", "index", "reconstruction_unplaced",
						"excluded_exchanges"} {
						delete(each, later)
					}
					each["version"] = json.RawMessage(strconv.Quote(processing.ArtifactVersion1))
					line, err = json.Marshal(each)
					if err != nil {
						t.Fatal(err)
					}
					if name == "legacy_null" {
						// Actual public-type round trip, not a hand-written null.
						var legacy processing.Artifact
						if err := json.Unmarshal(line, &legacy); err != nil {
							t.Fatal(err)
						}
						if legacy.PolicyExclusions != nil {
							t.Fatal("apparatus: absent key did not decode nil")
						}
						line, err = json.Marshal(legacy)
						if err != nil {
							t.Fatal(err)
						}
					}
					lines[i] = line
				}
				wire = lines[exchanges[0]]
				if err := os.WriteFile(path, append(bytes.Join(lines, []byte{'\n'}), '\n'), 0600); err != nil {
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
			changed := inspectionConfiguration(t, config.RemoveHeaders, `{"headers":["x-public"]}`)
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
			inspectionAssertOutput(t, name, out, inspectionSections(t, string(out), config.ExchangesPipeline, inspectionExchanges(name)),
				inspectionSections(t, string(out), config.ConnectionsPipeline, 1)[0], persisted.PolicyRevision)
		})
	}
}

// inspectionAssertOutput reads the public text: exchanges is each exchange
// record's rendering in order, connection the retirement record's.
func inspectionAssertOutput(t *testing.T, name string, out []byte, exchanges []string, connection string, revision string) {
	t.Helper()
	text := exchanges[0]
	// Check the whole public output, including account, diagnostics and the
	// renderer's decoded body section. This is an explicit marker oracle, not
	// an assertion that every possible encoding or unrelated value is covered.
	for _, forbidden := range []string{inspectionSecret} {
		inspectionAbsent(t, "PROTECTED_ABSENCE", out, forbidden)
	}
	if name == "suffix_withheld" {
		inspectionAbsent(t, "SUFFIX_ABSENCE", out, inspectionSuffix)
	}
	for _, want := range []string{inspectionPublic, inspectionBody, "policy_revision=" + strconv.Quote(revision), `pipeline="exchanges"`, `sink="account"`, `"direction": "sent"`, `"offset": "0"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("USEFUL_OUTPUT: public output omitted %q\n%s", want, out)
		}
	}
	a := inspectionPublicArtifact(t, text)
	if a.Reconstruction == nil || len(a.Reconstruction.Exchanges) == 0 {
		t.Fatal("USEFUL_OUTPUT: no retained exchange")
	}
	first := a.Reconstruction.Exchanges[0]
	if first.Request.Message == nil || first.Response.Message == nil {
		t.Fatal("USEFUL_OUTPUT: missing message")
	}
	if got, err := base64.StdEncoding.DecodeString(first.Response.Message.Body.Kept); err != nil || string(got) != inspectionBody {
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
		rendered := renderedEntries(text, want[0].Field)
		for _, e := range want {
			if !got[e] || renderedCount(rendered, e) != 1 {
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
	// Truncation evidence describes the connection's incomplete suffix, so it is
	// on the retirement record; an exchange record holds one complete pair.
	retired := inspectionPublicArtifact(t, connection)
	if a.ReconstructionTruncation != nil {
		t.Fatalf("DECIDABLE_CONTROL: an exchange record carries truncation: %+v", a.ReconstructionTruncation)
	}
	if name == "suffix_withheld" {
		trunc := retired.ReconstructionTruncation
		if trunc == nil || trunc.State != "truncated" || trunc.Suffix != "indeterminate" || len(trunc.Stops) != 1 {
			t.Fatalf("SUFFIX_EVIDENCE: missing truncation: %+v", trunc)
		}
		stop := trunc.Stops[0]
		if stop.Direction != "sent" || stop.Offset != strconv.Itoa(len(inspectionRequest(""))) || stop.Reason != "incomplete_message" || stop.EvidenceOffset != strconv.Itoa(len(inspectionRequest("")+inspectionTail(false))) {
			t.Fatalf("SUFFIX_EVIDENCE: wrong boundary: %+v", stop)
		}
		if first.Request.Message.Target != "/retained" {
			t.Fatalf("SUFFIX_EVIDENCE: the exchange record is not the useful prefix: %+v", first.Request.Message)
		}
	} else if retired.ReconstructionTruncation != nil {
		t.Fatalf("DECIDABLE_CONTROL: unexpected truncation: %+v", retired.ReconstructionTruncation)
	}
	if name == "suffix_complete" {
		second := inspectionPublicArtifact(t, exchanges[1])
		if second.Reconstruction == nil || len(second.Reconstruction.Exchanges) != 1 ||
			second.Reconstruction.Exchanges[0].Request.Message.Target != "/"+inspectionSuffix || !strings.Contains(exchanges[1], inspectionSuffix) {
			t.Fatal("SUFFIX_CONTROL: completed suffix was not displayed")
		}
	}
	if name == "replaced" || name == "truncated" {
		value := inspectionReplace
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

// renderedEntries are the lines of the text rendering, outside the
// indented artifact, that name this field, a message and the removed
// disposition. The version 2 line has no published format, so an entry is
// matched by what it names rather than by its layout.
func renderedEntries(text, field string) []string {
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

// renderedCount is how many rendered lines name e's message and section.
// The section is looked for outside the field, which itself holds "headers".
func renderedCount(lines []string, e processing.PolicyExclusion) int {
	count := 0
	for _, line := range lines {
		rest := strings.ReplaceAll(line, e.Field, "")
		if strings.Contains(rest, e.Message) && strings.Contains(rest, e.Section) {
			count++
		}
	}
	return count
}

// inspectionExchanges is how many exchange records a case makes: one per complete
// pair, so two where the suffix completes.
func inspectionExchanges(name string) int {
	if name == "suffix_complete" {
		return 2
	}
	return 1
}

// inspectionRoutes is the approved output's lines, which must be exactly want
// exchanges records and one connections record by route.pipeline, and the
// indexes of the exchanges ones. A total would absorb a missing exchanges
// record beside an extra connections record.
func inspectionRoutes(t *testing.T, file []byte, want int) ([][]byte, []int) {
	t.Helper()
	var lines [][]byte
	var exchanges []int
	counts := map[string]int{}
	for _, line := range bytes.Split(bytes.TrimSpace(file), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var route struct {
			Route struct {
				Pipeline string `json:"pipeline"`
			} `json:"route"`
		}
		if err := json.Unmarshal(line, &route); err != nil {
			t.Fatalf("apparatus: an approved line does not decode: %v", err)
		}
		counts[route.Route.Pipeline]++
		if route.Route.Pipeline == config.ExchangesPipeline {
			exchanges = append(exchanges, len(lines))
		}
		lines = append(lines, line)
	}
	if counts[config.ExchangesPipeline] != want {
		t.Fatalf("apparatus, not the property: the approved output holds %d exchanges records, want %d; records by route %v",
			counts[config.ExchangesPipeline], want, counts)
	}
	if counts[config.ConnectionsPipeline] != 1 || len(counts) != 2 {
		t.Fatalf("apparatus: the approved output holds records by route %v, want %d exchanges and one connections record",
			counts, want)
	}
	return lines, exchanges
}

// inspectionSections is the public text rendering of each record of one route, in
// order: from its heading to the next record's heading or the end.
func inspectionSections(t *testing.T, text, pipeline string, want int) []string {
	t.Helper()
	const heading = "approved artifact  version="
	var sections []string
	var current []string
	in := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, heading) {
			if in {
				sections = append(sections, strings.Join(current, "\n"))
			}
			current, in = nil, strings.Contains(line, `pipeline="`+pipeline+`"`)
		}
		if in {
			current = append(current, line)
		}
	}
	if in {
		sections = append(sections, strings.Join(current, "\n"))
	}
	if len(sections) != want {
		t.Fatalf("apparatus, not the property: the public text renders %d %s records, want %d\n%s", len(sections),
			pipeline, want, text)
	}
	return sections
}

func inspectionAbsent(t *testing.T, assertion string, out []byte, value string) {
	t.Helper()
	for _, representation := range []string{value, base64.StdEncoding.EncodeToString([]byte(value))} {
		if bytes.Contains(out, []byte(representation)) {
			t.Fatalf("%s: forbidden marker in public output", assertion)
		}
	}
}

func inspectionPublicArtifact(t *testing.T, text string) processing.Artifact {
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

func inspectionRequest(extra string) string {
	return "GET /retained HTTP/1.1\r\nX-Public: " + inspectionPublic + "\r\n" + extra + "\r\n"
}

func inspectionTail(complete bool) string {
	tail := "GET /" + inspectionSuffix + " HTTP/1.1\r\nX-Tail: received"
	if complete {
		tail += "\r\n\r\n"
	}
	return tail
}

func inspectionProduce(t *testing.T, destination, name string) {
	t.Helper()
	implementation, arguments := config.RemoveHeaders, `{"headers":["authorization"]}`
	if name == "replaced" {
		implementation, arguments = config.ReplaceHeaderValues, `{"headers":["x-transform"],"value":"`+inspectionReplace+`"}`
	}
	if name == "truncated" {
		implementation, arguments = config.TruncateHeaderValues, `{"headers":["x-transform"],"length":4}`
	}
	f, settler := inspectionController(t, inspectionConfiguration(t, implementation, arguments))
	request := inspectionRequest("")
	response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(inspectionBody), inspectionBody)
	switch name {
	case "removed":
		// Duplicate mixed-case fields must produce one lowercase tuple per
		// section, not values, configured-name guesses, or duplicate evidence.
		fields := "Authorization: " + inspectionSecret + "\r\naUtHoRiZaTiOn: " + inspectionSecret + "\r\n"
		request = "POST /retained HTTP/1.1\r\nX-Public: " + inspectionPublic + "\r\nTransfer-Encoding: chunked\r\n" + fields + "\r\n0\r\n" + fields + "\r\n"
		response = fmt.Sprintf("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n%s\r\n%x\r\n%s\r\n0\r\n%s\r\n", fields, len(inspectionBody), inspectionBody, fields)
	case "suffix_withheld", "suffix_complete":
		request += inspectionTail(name == "suffix_complete")
		if name == "suffix_complete" {
			response += "HTTP/1.1 204 No Content\r\n\r\n"
		}
	case "replaced":
		request = inspectionRequest("X-Transform: " + inspectionSecret + "\r\n")
	case "truncated":
		request = inspectionRequest("X-Transform: KEEP" + inspectionSecret + "\r\n")
	}
	if name == "removed" || name == "replaced" || name == "truncated" {
		if !strings.Contains(request, inspectionSecret) {
			t.Fatal("apparatus: protected input not constructed")
		}
	}
	if strings.HasPrefix(name, "suffix_") && !strings.Contains(request, inspectionSuffix) {
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
	// A connection left open is settled at finish against the producer's
	// numbers. Where the settler was never asked, a cut tail is the fixture's,
	// not the product's.
	if strings.HasPrefix(name, "suffix_") && settler.consulted() == 0 {
		t.Fatalf("wiring, not the property: the capture never asked the settler for the open connection's " +
			"occupancy, so any truncation below was made by the fixture")
	}
	if got := f.d.output.Stats(); !got.Closed {
		t.Fatalf("apparatus: useful output not sealed: %+v", got)
	}
	written, err := os.ReadFile(filepath.Join(f.d.directory, processing.ArtifactName))
	if err != nil {
		t.Fatal(err)
	}
	inspectionRoutes(t, written, inspectionExchanges(name))
	for _, file := range []string{sealedName, processing.ArtifactName} {
		data, err := os.ReadFile(filepath.Join(f.d.directory, file))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, file), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Printf("REACHED case=%s transfers=2 rejected=0 request_bytes=%d response_bytes=%d protected_input=%t suffix_input=%t exchanges_records=%d connections_records=1 sealed=true settled=%d\n", name, len(request), len(response), strings.Contains(request, inspectionSecret), strings.Contains(request, inspectionSuffix), inspectionExchanges(name), settler.consulted())
}

func inspectionConfiguration(t *testing.T, implementation, arguments string) []byte {
	t.Helper()
	raw, err := config.Examples.ReadFile("examples/no-rules.config.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	// The one operation, written as the rule a user writes for it.
	var operation struct {
		Headers []string `json:"headers"`
		Value   string   `json:"value"`
		Length  int      `json:"length"`
	}
	if err := json.Unmarshal([]byte(arguments), &operation); err != nil {
		t.Fatal(err)
	}
	each := func(value any) map[string]any {
		headers := map[string]any{}
		for _, name := range operation.Headers {
			headers[name] = value
		}
		return map[string]any{"headers": headers}
	}
	switch implementation {
	case config.RemoveHeaders:
		document["remove"] = map[string]any{"headers": operation.Headers}
	case config.ReplaceHeaderValues:
		document["mask"] = each(operation.Value)
	case config.TruncateHeaderValues:
		document["truncate"] = each(operation.Length)
	default:
		t.Fatalf("no rule a user writes compiles to %s", implementation)
	}
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// inspectionSettler answers, as the kernel producer does once production stops,
// the occupancy and last numbers the fixture's stand-in producer gave a
// handle. That producer keys a handle's occupancy by its endpoint and numbers
// each direction from 1, keeping the numbers it took; the answer is read from
// that record. It counts the handles it is asked about.
type inspectionSettler struct {
	fixture *processingControllerFixture
	mutex   sync.Mutex
	asked   int
}

func (s *inspectionSettler) Settled(handle probe.Handle) (probe.Settlement, error) {
	s.mutex.Lock()
	s.asked++
	s.mutex.Unlock()
	sent := s.fixture.numbers[fragmentKey{handle.Endpoint, fragment.Sent}]
	received := s.fixture.numbers[fragmentKey{handle.Endpoint, fragment.Received}]
	if sent == 0 && received == 0 {
		return probe.Settlement{}, nil
	}
	return probe.Settlement{Occupancy: handle.Endpoint, Final: probe.Final{Known: true,
		Sent: probe.Terminal{Last: sent}, Received: probe.Terminal{Last: received}}}, nil
}

func (*inspectionSettler) Unlocated() (uint64, error) { return 0, nil }

func (s *inspectionSettler) consulted() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.asked
}

// Reuse only the existing synthetic producer's mechanical transfer/lifecycle
// helpers. Configuration, witnesses and every acceptance assertion are owned
// by this file; no implementer's condition-2 assertion is invoked or edited.
func inspectionController(t *testing.T, configuration []byte) (*processingControllerFixture, *inspectionSettler) {
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
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 100})
	if err != nil {
		t.Fatal(err)
	}
	f := &processingControllerFixture{stop: make(chan os.Signal, 1), done: make(chan struct{})}
	f.producer = &processingProducer{withdrawn: true, drained: true, stamp: &f.stamp}
	settler := &inspectionSettler{fixture: f}
	recording.Settling(settler)
	f.d = &daemon{policy: read, session: "condition2", directory: directory, capture: recording,
		intake: store, gate: gate, output: output, attached: f.producer,
		plan: account.Account{Version: account.Version, Session: "condition2", Policy: account.Policy{Revision: read.Revision, Generation: 1}},
	}
	f.d.plan.Attached(account.Live, f.d.session, nil, f.d.attached.Capability())
	f.d.plan.Extensions = account.ExtensionsOf(read.Processing.Extensions())
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
	return f, settler
}
