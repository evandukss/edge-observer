package extension_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/internal/extensiontest"
	"github.com/evandukss/edge-observer/internal/workload"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
)

// The test binary serves the test extension when a case names it as an
// extension's command.
func TestMain(m *testing.M) {
	if extensiontest.Requested() {
		os.Exit(extensiontest.Serve())
	}
	os.Exit(m.Run())
}

// entry is one extensions entry run by the test extension, with a timeout of
// timeout milliseconds, or 2000 where it is zero.
type entry struct {
	name    string
	fields  []string
	does    extensiontest.Config
	timeout int
}

// planOf compiles a configuration with these rules, given as the
// configuration's own members (`"remove": {...}`) or none, and these
// extensions.
func planOf(t *testing.T, rules string, entries ...entry) *config.ProcessingPlan {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, one := range entries {
		timeout := one.timeout
		if timeout == 0 {
			timeout = 2000
		}
		encoded, err := json.Marshal(map[string]any{"name": one.name,
			"command": extensiontest.Command(binary, one.does), "fields": one.fields, "timeout_ms": timeout})
		if err != nil {
			t.Fatal(err)
		}
		listed = append(listed, string(encoded))
	}
	document := `{"version": "observer.config/1", "output": "/var/lib/observer", ` +
		`"watch": [{"name": "api", "exe": "/usr/bin/php"}], "extensions": [` + strings.Join(listed, ", ") + `]`
	if rules != "" {
		document += ", " + rules
	}
	compiled, findings := config.Compile([]byte(document+"}"), "")
	if compiled == nil || len(findings) != 0 {
		t.Fatalf("wiring, not the property: the fixture's configuration was refused: %+v", findings)
	}
	if got := len(compiled.Plan.Extensions()); got != len(entries) {
		t.Fatalf("wiring, not the property: the plan holds %d extensions, want %d", got, len(entries))
	}
	return compiled.Plan
}

// session is one in-process run from an intake through the workers to the
// approved output and the derived files, with extensions.
type session struct {
	directory string
	writer    *processing.Writer
	run       *processing.Run
	store     *intake.Store
	events    *events
}

// events is every supervision event, in the order reported.
type events struct {
	mutex sync.Mutex
	all   []extension.Event
	added chan struct{}
}

func (e *events) add(one extension.Event) {
	e.mutex.Lock()
	e.all = append(e.all, one)
	e.mutex.Unlock()
	select {
	case e.added <- struct{}{}:
	default:
	}
}

// next waits for the first event after the first skip events that matches.
func (e *events) next(t *testing.T, skip int, match func(extension.Event) bool) (extension.Event, int) {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		e.mutex.Lock()
		for i := skip; i < len(e.all); i++ {
			if match(e.all[i]) {
				one := e.all[i]
				e.mutex.Unlock()
				return one, i + 1
			}
		}
		e.mutex.Unlock()
		select {
		case <-e.added:
		case <-deadline:
			t.Fatalf("no matching supervision event within 30s; events so far: %+v", e.snapshot())
		}
	}
}

func (e *events) snapshot() []extension.Event {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	return append([]extension.Event(nil), e.all...)
}

// started runs plan with outputBytes of retained queue capacity, two
// workers and clock (nil for the host's).
func started(t *testing.T, plan *config.ProcessingPlan, outputBytes int64, clock extension.Clock) *session {
	t.Helper()
	return startedWith(t, plan, outputBytes, clock, 2)
}

// startedWith is started with this many workers.
func startedWith(t *testing.T, plan *config.ProcessingPlan, outputBytes int64, clock extension.Clock, workers int) *session {
	t.Helper()
	store, err := intake.New(1 << 30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return startedOn(t, plan, outputBytes, clock, workers, store)
}

// startedOn is startedWith over this intake.
func startedOn(t *testing.T, plan *config.ProcessingPlan, outputBytes int64, clock extension.Clock, workers int,
	store *intake.Store) *session {
	t.Helper()
	s := &session{directory: t.TempDir(), events: &events{added: make(chan struct{}, 1)}, store: store}
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 1 << 40, IntakeExhausted: s.store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	if s.writer, err = processing.Open(s.directory, outputBytes); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.writer.Close() })
	s.run, err = processing.Start(processing.Options{Plan: plan, PolicyRevision: "sha256:extension-tests",
		Intake: s.store, Gate: gate, Output: s.writer, Derived: s.writer, Workers: workers, Session: "extension-tests",
		Clock: clock, Supervision: s.events.add})
	if err != nil || s.run == nil {
		t.Fatalf("wiring, not the property: the run did not start: %v", err)
	}
	t.Cleanup(func() { _ = s.run.Close() })
	return s
}

// ready waits until every extension of plan has a generation that answered
// ready: an exchange reaching an extension before then skips it.
func (s *session) ready(t *testing.T, plan *config.ProcessingPlan) *session {
	t.Helper()
	for _, one := range plan.Extensions() {
		s.events.next(t, 0, func(e extension.Event) bool { return e.Kind == extension.Ready && e.Extension == one.Name })
	}
	return s
}

func generate(t *testing.T, shape workload.Shape) *workload.Workload {
	t.Helper()
	w, err := workload.Generate(shape)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// feed writes every entry of w to the intake and routes them.
func (s *session) feed(t *testing.T, w *workload.Workload) {
	t.Helper()
	if n, err := w.Write(s.store); err != nil || n != len(w.Entries) {
		t.Fatalf("wiring, not the property: %d of %d entries reached the intake: %v", n, len(w.Entries), err)
	}
	s.run.Route()
}

func (s *session) finish(t *testing.T) processing.Outcome {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err := s.run.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil {
		t.Fatalf("the run did not finish: %v", err)
	}
	if err := s.writer.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	return s.run.Snapshot()
}

// lines is the approved output's lines of one pipeline, read back by the
// reader.
func (s *session) lines(t *testing.T, pipeline string) []processing.Artifact {
	t.Helper()
	var out []processing.Artifact
	err := processing.ReadArtifacts(os.DirFS(s.directory), func(a processing.Artifact) error {
		if a.Route.Pipeline == pipeline {
			out = append(out, a)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("the approved output does not read back: %v", err)
	}
	return out
}

// waitFor polls the run's snapshot until done holds, or fails after 30s.
func (s *session) waitFor(t *testing.T, what string, done func(processing.Outcome) bool) processing.Outcome {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		o := s.run.Snapshot()
		if done(o) {
			return o
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within 30s: %+v", what, o)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// counts is the named extension's counts in o.
func counts(t *testing.T, o processing.Outcome, name string) account.ExtensionCounts {
	t.Helper()
	for _, one := range o.Extensions {
		if one.Name == name {
			return one
		}
	}
	t.Fatalf("wiring, not the property: the outcome carries no counts for %q: %+v", name, o.Extensions)
	return account.ExtensionCounts{}
}

// conserved requires every extension's counts to conserve over the ids the run
// issued, with nothing pending after a clean finish.
func conserved(t *testing.T, o processing.Outcome) {
	t.Helper()
	if o.ExchangeIDs == 0 {
		t.Fatal("wiring, not the property: the run issued no exchange id")
	}
	for _, c := range o.Extensions {
		failed := uint64(0)
		for _, n := range c.FailedBy {
			failed += n
		}
		if c.Considered != o.ExchangeIDs || c.Changed+c.Unchanged+c.Failed+c.Pending != c.Considered ||
			failed != c.Failed || c.Pending != 0 {
			t.Errorf("%s: considered %d of %d ids, changed %d + unchanged %d + failed %d (by reason %d) + "+
				"pending %d", c.Name, c.Considered, o.ExchangeIDs, c.Changed, c.Unchanged, c.Failed, failed, c.Pending)
		}
	}
}

// written is how many exchanges the lines write.
func written(lines []processing.Artifact) int {
	n := 0
	for _, a := range lines {
		if a.Reconstruction != nil {
			n += len(a.Reconstruction.Exchanges)
		}
	}
	return n
}

func kept(t *testing.T, encoded string) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("a kept body is not base64: %v", err)
	}
	return string(decoded)
}

func body(content string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"kept": %q}`, base64.StdEncoding.EncodeToString([]byte(content))))
}

// A change to a body goes through the configuration's rules once, as a new
// representation: a positional removal takes the first element of the
// replacement once, not twice and not never. The removal is recorded apart
// from removals of captured content, with the extension that supplied it.
func TestAPositionalRemovalAppliesOnceToAReplacementBodyAndIsRecordedApart(t *testing.T) {
	plan := planOf(t, `"remove": {"json": {"response": ["/0"]}}`, entry{name: "replacer",
		fields: []string{config.FieldResponseBody},
		does:   extensiontest.Config{Changes: map[string]json.RawMessage{config.FieldResponseBody: body(`["a","b","c"]`)}}})
	s := started(t, plan, 1<<26, nil).ready(t, plan)
	s.feed(t, generate(t, workload.Shape{Connections: 4, Exchanges: 2, ResponseBodyBytes: 60, JSONShare: 1, Seed: 3}))
	o := s.finish(t)
	lines := s.lines(t, config.ExchangesPipeline)
	if written(lines) != 8 {
		t.Fatalf("wiring, not the property: %d exchanges written, want 8", written(lines))
	}
	for _, a := range lines {
		for _, e := range a.Reconstruction.Exchanges {
			if got := kept(t, e.Response.Message.Body.Kept); got != `["b","c"]` {
				t.Errorf("exchange %d: the written body is %s, want the replacement with its first element "+
					"removed once", e.Index, got)
			}
		}
		for _, p := range a.PolicyExclusions {
			if p.Field == config.JSONFieldPrefix+"/0" {
				t.Errorf("a removal from replacement content is recorded as one from captured content: %+v", p)
			}
		}
		apart := map[int]bool{}
		for _, r := range a.ReplacementExclusions {
			if r.Field == config.JSONFieldPrefix+"/0" && r.Message == config.MessageResponse &&
				r.Disposition == processing.DispositionRemoved && r.Extension == "replacer" {
				apart[r.Exchange] = true
			}
		}
		if len(apart) != len(a.Reconstruction.Exchanges) {
			t.Errorf("replacement exclusions name %d of %d exchanges: %+v", len(apart), len(a.Reconstruction.Exchanges),
				a.ReplacementExclusions)
		}
	}
	if c := counts(t, o, "replacer"); c.Changed != 8 {
		t.Errorf("changed %d, want 8: %+v", c.Changed, c)
	}
	conserved(t, o)
}

// A body remove took out whole was not given, so an answer supplying one fails
// as removed_content, and the exchange is written as it was before.
func TestSupplyingRemovedContentFailsTheAnswer(t *testing.T) {
	plan := planOf(t, `"remove": {"bodies": ["response"]}`, entry{name: "restorer",
		fields: []string{config.FieldResponseBody},
		does:   extensiontest.Config{Changes: map[string]json.RawMessage{config.FieldResponseBody: body("restored")}}})
	s := started(t, plan, 1<<26, nil).ready(t, plan)
	s.feed(t, generate(t, workload.Shape{Connections: 3, Exchanges: 2, ResponseBodyBytes: 40, Seed: 4}))
	o := s.finish(t)
	lines := s.lines(t, config.ExchangesPipeline)
	if written(lines) != 6 {
		t.Fatalf("wiring, not the property: %d exchanges written, want 6", written(lines))
	}
	for _, a := range lines {
		for _, e := range a.Reconstruction.Exchanges {
			if e.Response.Message.Body.Kept != "" || e.Response.Message.Structure.State != "removed" {
				t.Errorf("exchange %d: the removed body was restored: %+v", e.Index, e.Response.Message.Body)
			}
		}
		for _, outcome := range a.ExtensionOutcomes {
			if outcome.Outcome != extension.Failed || outcome.Reason != extension.RemovedContent {
				t.Errorf("exchange %d: %+v, want failed as %s", outcome.Exchange, outcome, extension.RemovedContent)
			}
		}
	}
	if c := counts(t, o, "restorer"); c.FailedBy[extension.RemovedContent] != 6 || c.Changed != 0 {
		t.Errorf("failed as removed_content %d of 6, changed %d", c.FailedBy[extension.RemovedContent], c.Changed)
	}
	conserved(t, o)
}

// An excluded exchange can be read and never changed: a changed answer for
// one is counted failed as excluded, and it never reaches the output.
func TestAChangeToAnExcludedExchangeIsCountedFailed(t *testing.T) {
	plan := planOf(t, "", entry{name: "marker", fields: []string{config.FieldResponseHeaders},
		does: extensiontest.Config{ChangeExcluded: true, Changes: map[string]json.RawMessage{
			config.FieldResponseHeaders: json.RawMessage(`{"headers": [{"name": "X-Marked", "value": "yes"}], "trailers": []}`)}}})
	s := started(t, plan, 1<<26, nil).ready(t, plan)
	s.feed(t, generate(t, workload.Shape{Connections: 20, Exchanges: 3, ResponseBodyBytes: 20, DefectShare: 1,
		DefectKinds: []string{workload.DefectUnsupported}, Seed: 5}))
	o := s.finish(t)
	lines := s.lines(t, config.ExchangesPipeline)
	// The workload supplies sixty exchanges, including the excluded suffixes.
	issued := 60
	if o.ExchangeIDs != uint64(issued) {
		t.Fatalf("issued %d ids for sixty source exchanges", o.ExchangeIDs)
	}
	excluded := issued - written(lines)
	if excluded == 0 {
		t.Fatal("wiring, not the property: the workload produced no excluded exchange")
	}
	c := counts(t, o, "marker")
	if c.FailedBy[extension.Excluded] != uint64(excluded) || c.Changed != uint64(written(lines)) {
		t.Errorf("failed as excluded %d of %d excluded exchanges; changed %d of %d written",
			c.FailedBy[extension.Excluded], excluded, c.Changed, written(lines))
	}
	conserved(t, o)
}

// Two extensions changing one field: the later one's change is written, and
// the record says which change survived and which was overwritten.
func TestTwoExtensionsChangingOneFieldRecordWhichChangeSurvived(t *testing.T) {
	headers := func(by string) map[string]json.RawMessage {
		return map[string]json.RawMessage{config.FieldResponseHeaders: json.RawMessage(
			`{"headers": [{"name": "X-Changed-By", "value": "` + by + `"}], "trailers": []}`)}
	}
	plan := planOf(t, "",
		entry{name: "first", fields: []string{config.FieldResponseHeaders}, does: extensiontest.Config{Changes: headers("first")}},
		entry{name: "second", fields: []string{config.FieldResponseHeaders}, does: extensiontest.Config{Changes: headers("second")}})
	s := started(t, plan, 1<<26, nil).ready(t, plan)
	s.feed(t, generate(t, workload.Shape{Connections: 3, Exchanges: 2, Seed: 6}))
	o := s.finish(t)
	lines := s.lines(t, config.ExchangesPipeline)
	if written(lines) != 6 {
		t.Fatalf("wiring, not the property: %d exchanges written, want 6", written(lines))
	}
	for _, a := range lines {
		for _, e := range a.Reconstruction.Exchanges {
			h := e.Response.Message.Headers
			if len(h) != 1 || h[0].Name != "X-Changed-By" || h[0].Value != "second" {
				t.Errorf("exchange %d: written headers %+v, want the second extension's", e.Index, h)
			}
			var first, second *processing.ExtensionOutcome
			for i, one := range a.ExtensionOutcomes {
				if one.Exchange != e.Index {
					continue
				}
				switch one.Extension {
				case "first":
					first = &a.ExtensionOutcomes[i]
				case "second":
					second = &a.ExtensionOutcomes[i]
				}
			}
			if first == nil || second == nil {
				t.Fatalf("exchange %d: outcomes %+v do not name both extensions", e.Index, a.ExtensionOutcomes)
			}
			if first.Outcome != extension.Changed || strings.Join(first.Changed, ",") != config.FieldResponseHeaders ||
				strings.Join(first.Overwritten, ",") != config.FieldResponseHeaders {
				t.Errorf("exchange %d: the first extension's change is not recorded as overwritten: %+v", e.Index, *first)
			}
			if second.Outcome != extension.Changed || strings.Join(second.Changed, ",") != config.FieldResponseHeaders ||
				second.Overwritten == nil || len(second.Overwritten) != 0 {
				t.Errorf("exchange %d: the second extension's change is not recorded as surviving: %+v", e.Index, *second)
			}
		}
	}
	conserved(t, o)
}

// A generation that dies is followed by the next after a wait that doubles
// from 100 ms to 5 s, read off the supervision clock, and a generation that
// stayed up the healthy interval returns the wait to 100 ms.
func TestTheBackoffDoublesFrom100msTo5sAndResetsAfterTheHealthyInterval(t *testing.T) {
	clock := extensiontest.NewManual(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	plan := planOf(t, "", entry{name: "dying", fields: []string{config.FieldRequestLine},
		does: extensiontest.Config{ExitBeforeReady: 8, ExitOnExchange: true}})
	s := started(t, plan, 1<<26, clock)
	is := func(kind extension.EventKind, generation uint64) func(extension.Event) bool {
		return func(e extension.Event) bool { return e.Kind == kind && e.Generation == generation }
	}
	_, at := s.events.next(t, 0, is(extension.Started, 1))
	want := []time.Duration{100, 200, 400, 800, 1600, 3200, 5000, 5000}
	for i, wait := range want {
		generation := uint64(i + 1)
		var retired extension.Event
		retired, at = s.events.next(t, at, is(extension.Retired, generation))
		if retired.Cause != extension.Crash || retired.Backoff != wait*time.Millisecond {
			t.Fatalf("generation %d retired as %q with a %v wait, want %s and %v", generation, retired.Cause,
				retired.Backoff, extension.Crash, wait*time.Millisecond)
		}
		clock.Advance(wait * time.Millisecond)
		var begun extension.Event
		begun, at = s.events.next(t, at, is(extension.Started, generation+1))
		if gap := begun.At.Sub(retired.At); gap != wait*time.Millisecond {
			t.Fatalf("generation %d started %v after the retirement, want %v", generation+1, gap, wait*time.Millisecond)
		}
	}
	s.events.next(t, at, is(extension.Ready, 9))
	clock.Advance(extension.HealthyInterval)
	s.feed(t, generate(t, workload.Shape{Connections: 1, Exchanges: 1, Seed: 8}))
	retired, _ := s.events.next(t, at, is(extension.Retired, 9))
	if retired.Cause != extension.Crash || retired.Backoff != extension.BackoffMin {
		t.Fatalf("a generation up the healthy interval retired as %q with a %v wait, want %s and %v", retired.Cause,
			retired.Backoff, extension.Crash, extension.BackoffMin)
	}
	o := s.finish(t)
	if c := counts(t, o, "dying"); c.Restarts != 8 || c.RetiredBy[extension.Crash] != 9 || c.StateResets != 0 {
		t.Errorf("restarts %d, want 8; retired as crash %d, want 9; state resets %d, want 0", c.Restarts,
			c.RetiredBy[extension.Crash], c.StateResets)
	}
	conserved(t, o)
}

// An answer is validated whole: one with a valid change beside a malformed
// one fails as malformed, and neither is applied.
func TestAnAnswerWithOneMalformedChangeAppliesNoneOfIt(t *testing.T) {
	plan := planOf(t, "", entry{name: "half", fields: []string{config.FieldRequestLine, config.FieldResponseHeaders},
		does: extensiontest.Config{Changes: map[string]json.RawMessage{
			config.FieldResponseHeaders: json.RawMessage(`{"headers": [{"name": "X-Half", "value": "yes"}], "trailers": []}`),
			config.FieldRequestLine:     json.RawMessage(`{"method": "GET", "target": "has space", "protocol": "HTTP/1.1"}`)}}})
	s := started(t, plan, 1<<26, nil).ready(t, plan)
	s.feed(t, generate(t, workload.Shape{Connections: 2, Exchanges: 2, Seed: 16}))
	o := s.finish(t)
	lines := s.lines(t, config.ExchangesPipeline)
	if written(lines) != 4 {
		t.Fatalf("wiring, not the property: %d exchanges written, want 4", written(lines))
	}
	for _, a := range lines {
		for _, e := range a.Reconstruction.Exchanges {
			for _, h := range e.Response.Message.Headers {
				if h.Name == "X-Half" {
					t.Errorf("exchange %d: the valid half of a malformed answer was applied", e.Index)
				}
			}
		}
		for _, outcome := range a.ExtensionOutcomes {
			if outcome.Outcome != extension.Failed || outcome.Reason != extension.Malformed {
				t.Errorf("exchange %d: %+v, want failed as %s", outcome.Exchange, outcome, extension.Malformed)
			}
		}
	}
	if c := counts(t, o, "half"); c.FailedBy[extension.Malformed] != 4 {
		t.Errorf("failed as malformed %d of 4", c.FailedBy[extension.Malformed])
	}
	conserved(t, o)
}

// Every exchange of the established prefix reaches an extension after the
// built-in rules, the ones the output will not write and those with a side
// missing included: a removed header is in none of them, while a header the
// rules keep arrives.
func TestExcludedAndOneSidedExchangesReachAnExtensionAfterTheRules(t *testing.T) {
	received := filepath.Join(t.TempDir(), "received")
	plan := planOf(t, `"remove": {"headers": ["x-field-1"]}`, entry{name: "reader",
		fields: []string{config.FieldRequestHeaders, config.FieldResponseHeaders},
		does:   extensiontest.Config{Received: received}})
	s := started(t, plan, 1<<26, nil).ready(t, plan)
	s.feed(t, generate(t, workload.Shape{Connections: 100, Exchanges: 3, HeaderBytes: 150, ResponseBodyBytes: 500,
		JSONShare: 0.5, DefectShare: 1, Processes: 2, Concurrency: 8, Seed: 41}))
	o := s.finish(t)
	content, err := os.ReadFile(received)
	if err != nil {
		t.Fatal(err)
	}
	var exchanges, excluded, oneSided int
	for _, line := range strings.Split(string(content), "\n") {
		if !strings.Contains(line, `"type":"exchange"`) {
			continue
		}
		exchanges++
		if strings.Contains(line, `"state":"excluded"`) {
			excluded++
		}
		if strings.Contains(line, `"state":"absent"`) {
			oneSided++
		}
		if strings.Contains(line, `"name":"X-Field-1"`) {
			t.Errorf("an exchange reached the extension with the header the rules remove: %.300s", line)
		}
		if !strings.Contains(line, `"name":"X-Field-2"`) && !strings.Contains(line, `"state":"absent"`) {
			t.Errorf("an exchange reached the extension without the header the rules keep: %.300s", line)
		}
	}
	if excluded == 0 || oneSided == 0 {
		t.Fatalf("wiring, not the property: of %d exchanges sent, %d excluded and %d with a side missing", exchanges,
			excluded, oneSided)
	}
	// An exchange that skips the extension at once is never sent.
	c := counts(t, o, "reader")
	skipped := c.FailedBy[extension.Busy] + c.FailedBy[extension.Unavailable] + c.FailedBy[extension.TooLarge]
	if uint64(exchanges)+skipped != o.ExchangeIDs {
		t.Errorf("%d exchanges reached the extension and %d skipped it, of %d ids issued: %v", exchanges, skipped,
			o.ExchangeIDs, c.FailedBy)
	}
	conserved(t, o)
}
