package processing_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/intake"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/processing"
	"github.com/evandukss/edge-observer/reconstruct"
)

// streamed is a Run of one worker whose plan holds the given extensions, each
// the test extension recording what it receives, writing through a Writer.
// Its input is given a fragment at a time, so a connection can be left open.
type streamed struct {
	t      *testing.T
	store  *intake.Store
	run    *processing.Run
	out    *lines
	audits []string

	mutex  sync.Mutex
	calls  []processing.Submission
	events []extension.Event
}

// streamedExtension is one configured extension: its name, the test
// extension's mode and further arguments.
type streamedExtension struct {
	name string
	mode string
	args []string
}

type streamedOptions struct {
	limit           int64
	connectionInput int
	timeoutMS       int
	fields          []string
	limits          reconstruct.Limits
	extensions      []streamedExtension
}

func newStreamed(t *testing.T, o streamedOptions) *streamed {
	t.Helper()
	if o.limit == 0 {
		o.limit = 16 << 20
	}
	if o.timeoutMS == 0 {
		o.timeoutMS = 5000
	}
	if o.fields == nil {
		o.fields = []string{"request.line", "request.body"}
	}
	s := &streamed{t: t, out: &lines{}}
	dir := t.TempDir()
	bin := extensionBinary(t)
	var entries []any
	for i, one := range o.extensions {
		audit := filepath.Join(dir, fmt.Sprintf("received-%d.jsonl", i))
		s.audits = append(s.audits, audit)
		entries = append(entries, map[string]any{"name": one.name, "fields": o.fields, "timeout_ms": o.timeoutMS,
			"command": append([]string{bin, "--mode", one.mode, "--record", audit}, one.args...)})
	}
	configured, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	s.store, err = intake.New(o.limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.store.Close() })
	gate, err := probe.NewDeliveryGate(probe.DeliveryGateOptions{MaxEvents: 4096, IntakeExhausted: s.store.Exhausted()})
	if err != nil {
		t.Fatal(err)
	}
	writer, err := processing.OpenWriter(processing.WriterOptions{Directory: dir, QueueBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	output := outputFunc(func(ctx context.Context, a processing.Approved) error {
		if err := writer.WriteApproved(ctx, a); err != nil {
			return err
		}
		return s.out.WriteApproved(ctx, a)
	})
	options := processing.ObserveSubmits(processing.Options{Session: "streamed",
		Plan: rulesPlan(t, `"extensions":`+string(configured)), PolicyRevision: "streamed-policy", Intake: s.store,
		Gate: gate, Output: output, Derived: writer, Workers: 1, ConnectionInput: o.connectionInput, Limits: o.limits,
		Supervision: func(e extension.Event) {
			s.mutex.Lock()
			s.events = append(s.events, e)
			s.mutex.Unlock()
		}}, func(one processing.Submission) {
		s.mutex.Lock()
		s.calls = append(s.calls, one)
		s.mutex.Unlock()
	})
	s.run, err = processing.Start(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.run.Close() })
	for _, one := range o.extensions {
		s.until("the extension "+one.name+" answered ready", func() bool { return s.generations(one.name, extension.Ready) >= 1 })
	}
	return s
}

// give writes fragments to the intake and routes them, leaving their
// connection open.
func (s *streamed) give(fragments ...fragment.Record) {
	s.t.Helper()
	for _, f := range fragments {
		if err := s.store.Write(f); err != nil {
			s.t.Fatalf("wiring, not the property: the intake refused a fragment of the fixture: %v", err)
		}
	}
	s.run.Route()
}

// end writes a connection's retirement and routes it.
func (s *streamed) end(c conversation) {
	s.t.Helper()
	if err := s.store.Connection(c.retirement); err != nil {
		s.t.Fatalf("wiring, not the property: the intake refused the fixture's retirement: %v", err)
	}
	s.run.Route()
}

// until waits up to five seconds for done, failing the case as wiring with
// what.
func (s *streamed) until(what string, done func() bool) {
	s.t.Helper()
	if !s.within(5*time.Second, done) {
		s.t.Fatalf("wiring, not the property: %s", what)
	}
}

// within reports whether done holds within limit.
func (s *streamed) within(limit time.Duration, done func() bool) bool {
	deadline := time.Now().Add(limit)
	for !done() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

// generations counts the extension's events of kind.
func (s *streamed) generations(name string, kind extension.EventKind) int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	n := 0
	for _, e := range s.events {
		if e.Extension == name && e.Kind == kind {
			n++
		}
	}
	return n
}

// received is every message extension k recorded receiving, in order, of the
// given type. A line still being written is not yet a message.
func (s *streamed) received(k int, kind string) []map[string]any {
	content, err := os.ReadFile(s.audits[k])
	if err != nil {
		return nil
	}
	var out []map[string]any
	for _, line := range bytes.Split(content, []byte{'\n'}) {
		var m map[string]any
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		if m["type"] == kind {
			out = append(out, m)
		}
	}
	return out
}

// asked is one request per target, none of them answered.
func asked(targets ...string) []call {
	var out []call
	for _, target := range targets {
		out = append(out, wrote("GET "+target+" HTTP/1.1\r\nHost: a\r\n\r\n"))
	}
	return out
}

// finish settles the run with both of capture's final facts.
func (s *streamed) finish() processing.Outcome {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	o, err := s.run.Finish(ctx, processing.Finalization{Withdrawn: true, Drained: true})
	if err != nil {
		s.t.Fatal(err)
	}
	return o
}

// written is the artifacts of connection id's lines, of kind.
func (s *streamed) written(kind string, id fragment.ConnectionID) []processing.Artifact {
	var out []processing.Artifact
	for _, line := range s.out.allFor(id) {
		var a processing.Artifact
		if err := json.Unmarshal(line, &a); err != nil {
			s.t.Fatal(err)
		}
		if a.Record == kind {
			out = append(out, a)
		}
	}
	return out
}

// settledCounts requires every extension's counts to conserve over the ids
// the run issued, with nothing pending, and returns them by name.
func settledCounts(t *testing.T, o processing.Outcome) map[string]map[string]uint64 {
	t.Helper()
	out := map[string]map[string]uint64{}
	for _, c := range o.Extensions {
		if c.Considered != o.ExchangeIDs || c.Considered != c.Changed+c.Unchanged+c.Failed+c.Pending || c.Pending != 0 {
			t.Errorf("extension %s does not settle over %d ids: considered %d, changed %d, unchanged %d, failed %d, pending %d",
				c.Name, o.ExchangeIDs, c.Considered, c.Changed, c.Unchanged, c.Failed, c.Pending)
		}
		counts := map[string]uint64{"unchanged": c.Unchanged, "changed": c.Changed, "failed": c.Failed,
			"late": c.Late, "restarts": c.Restarts, "state_resets": c.StateResets}
		for reason, n := range c.FailedBy {
			counts["failed_by."+reason] = n
		}
		out[c.Name] = counts
	}
	return out
}

// sentTarget is an exchange message's request target, where its request line was
// selected.
func sentTarget(m map[string]any) string {
	request, _ := m["exchange"].(map[string]any)["request"].(map[string]any)
	message, _ := request["message"].(map[string]any)
	value, _ := message["target"].(string)
	return value
}

// requireOneDone requires extension k to have received exactly one
// connection_done, for connection id, counting count ids, and returns it.
func (s *streamed) requireOneDone(k int, id fragment.ConnectionID, count int) map[string]any {
	s.t.Helper()
	dones := s.received(k, "connection_done")
	if len(dones) != 1 {
		s.t.Fatalf("extension %d received %d connection_done messages, want exactly one: %v", k, len(dones), dones)
	}
	done := dones[0]
	if _, ranged := done["ids"]; ranged {
		s.t.Errorf("connection_done carries an id range: %v", done)
	}
	if done["connection_id"] != strconv.FormatUint(uint64(id), 10) || done["count"] != strconv.Itoa(count) {
		s.t.Errorf("connection_done names connection %v and count %v, want %d and %d", done["connection_id"],
			done["count"], id, count)
	}
	// Nothing of the connection is sent after it.
	content, err := os.ReadFile(s.audits[k])
	if err != nil {
		s.t.Fatal(err)
	}
	seen, after := false, 0
	for _, line := range bytes.Split(content, []byte{'\n'}) {
		var m map[string]any
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		switch {
		case m["type"] == "connection_done":
			seen = true
		case seen && m["type"] == "exchange" && m["connection_id"] == done["connection_id"]:
			after++
		}
	}
	if after != 0 {
		s.t.Errorf("extension %d was sent %d exchanges of connection %d after its connection_done", k, after, id)
	}
	return done
}

// An extension is sent each exchange of a connection that is still open, as
// the exchange is released, with its own id, its connection's id and its index
// and no range of ids. Only once the connection ends is it sent
// connection_done, once, counting the ids issued on the connection.
func TestAnExtensionReceivesExchangesWhileTheirConnectionIsOpen(t *testing.T) {
	s := newStreamed(t, streamedOptions{extensions: []streamedExtension{{name: "watching", mode: "unchanged"}}})
	c := converse(t, 3, pairs("/a", "/b", "/c")...)
	s.give(c.fragments...)
	s.until("the open connection reached the worker", func() bool { return s.run.Snapshot().Pending == 1 })
	if !s.within(5*time.Second, func() bool { return len(s.received(0, "exchange")) == 3 }) {
		t.Fatalf("while its connection is open the extension received %d of its 3 exchanges",
			len(s.received(0, "exchange")))
	}
	for i, m := range s.received(0, "exchange") {
		if _, ranged := m["ids"]; ranged {
			t.Errorf("exchange %d carries an id range: %v", i, m)
		}
		if m["id"] != strconv.Itoa(i+1) || m["connection_id"] != "3" || m["index"] != float64(i) {
			t.Errorf("exchange %d carries id %v, connection %v and index %v, want %d, 3 and %d", i, m["id"],
				m["connection_id"], m["index"], i+1, i)
		}
		if want := []string{"/a", "/b", "/c"}[i]; sentTarget(m) != want {
			t.Errorf("exchange %d is %q, want %q", i, sentTarget(m), want)
		}
	}
	s.until("the open connection's exchange lines were written", func() bool {
		return len(s.written(processing.ArtifactExchange, 3)) == 3
	})
	if n := len(s.received(0, "connection_done")); n != 0 || len(s.written(processing.ArtifactConnection, 3)) != 0 {
		t.Fatalf("an open connection was sent %d connection_done and written %d connection lines", n,
			len(s.written(processing.ArtifactConnection, 3)))
	}
	s.end(c)
	s.until("the ended connection's line was written", func() bool {
		return len(s.written(processing.ArtifactConnection, 3)) == 1
	})
	o := s.finish()
	s.requireOneDone(0, 3, 3)
	if counts := settledCounts(t, o)["watching"]; counts["unchanged"] != 3 {
		t.Errorf("the extension's counts: %v", counts)
	}
}

// A connection cut after its first exchanges were sent is sent exactly one
// connection_done once it ends, counting the ids issued on it: the exchanges
// sent before the cut and nothing it discarded. Its bound is room for two
// exchanges in flight, which count against it, and is reached by six
// unanswered requests.
func TestACutAfterEarlyDeliverySendsOneConnectionDoneCountingTheIdsIssued(t *testing.T) {
	s := newStreamed(t, streamedOptions{connectionInput: 6, extensions: []streamedExtension{{name: "watching", mode: "unchanged"}}})
	c := converse(t, 4, append(pairs("/a", "/b"), asked("/c", "/d", "/e", "/f", "/g", "/h")...)...)
	s.give(c.fragments[:4]...)
	if !s.within(5*time.Second, func() bool { return len(s.written(processing.ArtifactExchange, 4)) == 2 }) {
		t.Fatalf("wiring, not the property: the first two exchanges were not written while the connection was open "+
			"(%d lines, %d exchanges received), so no cut can follow early delivery",
			len(s.written(processing.ArtifactExchange, 4)), len(s.received(0, "exchange")))
	}
	s.give(c.fragments[4:]...)
	s.until("the unanswered requests cut the connection", func() bool { return s.run.Snapshot().ConnectionsCut == 1 })
	if n := len(s.received(0, "connection_done")); n != 0 {
		t.Fatalf("a cut connection that has not ended was sent %d connection_done", n)
	}
	s.end(c)
	s.until("the cut connection's line was written", func() bool {
		return len(s.written(processing.ArtifactConnection, 4)) == 1
	})
	o := s.finish()
	if o.ExchangeIDs != 2 {
		t.Fatalf("the run issued %d ids, want the 2 sent before the cut", o.ExchangeIDs)
	}
	s.requireOneDone(0, 4, 2)
	stops := s.written(processing.ArtifactConnection, 4)[0].ReconstructionTruncation
	if stops == nil || len(stops.Stops) == 0 || stops.Stops[0].Reason != processing.TruncationConnectionCut {
		t.Errorf("the cut connection's line: %+v", stops)
	}
	settledCounts(t, o)
}

// A result that arrives after its call timed out, on a connection cut while
// the call was outstanding, changes nothing: the exchange is written once, as
// it was sent, its timeout and the late answer are each counted, one
// connection_done follows, and nothing it held stays charged.
func TestALateResultAfterACutResurrectsNothing(t *testing.T) {
	s := newStreamed(t, streamedOptions{connectionInput: 4, timeoutMS: 300,
		extensions: []streamedExtension{{name: "late", mode: "late"}}})
	c := converse(t, 5, append(pairs("/a"), asked("/c", "/d", "/e", "/f")...)...)
	s.give(c.fragments[:2]...)
	if !s.within(5*time.Second, func() bool { return len(s.received(0, "exchange")) == 1 }) {
		t.Fatal("wiring, not the property: the open connection's exchange never reached the extension, so nothing is outstanding at the cut")
	}
	s.give(c.fragments[2:]...)
	s.until("the unanswered requests cut the connection", func() bool { return s.run.Snapshot().ConnectionsCut == 1 })
	s.until("the late answer was counted", func() bool {
		o := s.run.Snapshot()
		return len(o.Extensions) == 1 && o.Extensions[0].Late == 1
	})
	s.until("the timed-out exchange's line was written", func() bool {
		return len(s.written(processing.ArtifactExchange, 5)) == 1
	})
	s.until("the next generation answered ready", func() bool { return s.generations("late", extension.Ready) == 2 })
	before := s.out.allFor(5)
	s.end(c)
	s.until("the cut connection's line was written", func() bool {
		return len(s.written(processing.ArtifactConnection, 5)) == 1
	})
	o := s.finish()
	exchanges := s.written(processing.ArtifactExchange, 5)
	if len(exchanges) != 1 || exchanges[0].ExchangeID != "1" || *exchanges[0].Index != 0 {
		t.Fatalf("after the late answer the connection has %d exchange lines: %+v", len(exchanges), exchanges)
	}
	if outcomes := exchanges[0].ExtensionOutcomes; len(outcomes) != 1 || outcomes[0].Outcome != extension.Failed ||
		outcomes[0].Reason != extension.Timeout {
		t.Errorf("the timed-out exchange's outcome: %+v", outcomes)
	}
	if after := s.out.allFor(5); !bytes.Equal(after[0], before[0]) {
		t.Errorf("the released line changed after the late answer:\n%s\n%s", before[0], after[0])
	}
	s.requireOneDone(0, 5, 1)
	counts := settledCounts(t, o)["late"]
	if counts["failed_by.timeout"] != 1 || counts["late"] != 1 || counts["changed"] != 0 {
		t.Errorf("the extension's counts: %v", counts)
	}
	if held := s.store.Stats(); held.Bytes != 0 || held.Parsing != 0 || held.Policy != 0 {
		t.Errorf("after settlement the store holds %+v", held)
	}
}

// An extension retired between two releases of one connection - its
// generation crashing, or timing out - is restarted, and the connection's
// later exchanges reach the new generation in index order with their own
// ids. Every exchange is written once, and every id is counted once.
func TestARetirementBetweenReleasesKeepsOrderAndCounts(t *testing.T) {
	for _, one := range []struct {
		mode, reason string
		args         []string
	}{
		{"crash", extension.Crash, []string{"--count", "1", "--first-generation"}},
		{"hold-first", extension.Timeout, []string{"--first-generation"}},
	} {
		t.Run(one.mode, func(t *testing.T) {
			s := newStreamed(t, streamedOptions{timeoutMS: 300,
				extensions: []streamedExtension{{name: "failing", mode: one.mode, args: one.args}}})
			c := converse(t, 6, pairs("/a", "/b", "/c")...)
			s.give(c.fragments[:2]...)
			s.until("the first generation was retired and the second answered ready", func() bool {
				return s.generations("failing", extension.Retired) == 1 && s.generations("failing", extension.Ready) == 2
			})
			s.give(c.fragments[2:4]...)
			s.until("the second exchange was answered", func() bool {
				return len(s.written(processing.ArtifactExchange, 6)) == 2
			})
			s.give(c.fragments[4:]...)
			s.end(c)
			s.until("the connection's line was written", func() bool {
				return len(s.written(processing.ArtifactConnection, 6)) == 1
			})
			o := s.finish()
			exchanges := s.written(processing.ArtifactExchange, 6)
			if len(exchanges) != 3 {
				t.Fatalf("%d exchange lines, want 3", len(exchanges))
			}
			for i, a := range exchanges {
				want := extension.Unchanged
				if i == 0 {
					want = extension.Failed
				}
				if a.ExchangeID != strconv.Itoa(i+1) || *a.Index != i || len(a.ExtensionOutcomes) != 1 ||
					a.ExtensionOutcomes[0].Outcome != want {
					t.Errorf("line %d: id %s, index %d, outcomes %+v", i, a.ExchangeID, *a.Index, a.ExtensionOutcomes)
				}
			}
			var ids []string
			for _, m := range s.received(0, "exchange") {
				ids = append(ids, m["id"].(string))
			}
			if strings.Join(ids, ",") != "1,2,3" {
				t.Errorf("the generations received ids %v, want 1, 2 and 3 in order", ids)
			}
			s.requireOneDone(0, 6, 3)
			counts := settledCounts(t, o)["failing"]
			if counts["failed_by."+one.reason] != 1 || counts["unchanged"] != 2 || counts["restarts"] != 1 ||
				counts["state_resets"] != 1 {
				t.Errorf("the extension's counts: %v", counts)
			}
		})
	}
}

// An exchange the output will not write, and every one after it, is sent as
// excluded as soon as nothing later can change the reason its connection's
// line records for it: after a compressed response, at once while the
// connection is open; a one-sided request, at the connection's end; and one
// whose reason waits on later input in its direction, at a cut that comes
// first, with connection_cut.
func TestTheExcludedTailIsSentOnceItsReasonIsDecidable(t *testing.T) {
	gzipped := read("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nzz")
	t.Run("as soon as decidable, and at the end", func(t *testing.T) {
		s := newStreamed(t, streamedOptions{extensions: []streamedExtension{{name: "watching", mode: "unchanged"}}})
		c := converse(t, 7, append(pairs("/a"), wrote("GET /b HTTP/1.1\r\nHost: a\r\n\r\n"), gzipped,
			wrote("GET /c HTTP/1.1\r\nHost: a\r\n\r\n"), read("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n/c"),
			wrote("GET /d HTTP/1.1\r\nHost: a\r\n\r\n"))...)
		s.give(c.fragments...)
		s.until("the three exchanges with responses were issued their ids", func() bool {
			return s.run.Snapshot().ExchangeIDs == 3
		})
		if !s.within(5*time.Second, func() bool { return len(s.received(0, "exchange")) == 3 }) {
			t.Fatalf("while the connection is open the extension received %d of the 3 exchanges whose reasons are decidable",
				len(s.received(0, "exchange")))
		}
		s.end(c)
		s.until("the connection's line was written", func() bool {
			return len(s.written(processing.ArtifactConnection, 7)) == 1
		})
		o := s.finish()
		got := s.received(0, "exchange")
		if len(got) != 4 {
			t.Fatalf("the extension received %d exchanges, want 4", len(got))
		}
		reasons := map[string]bool{}
		for _, stop := range s.written(processing.ArtifactConnection, 7)[0].ReconstructionTruncation.Stops {
			reasons[stop.Reason] = true
		}
		for i, m := range got[1:] {
			output := m["output"].(map[string]any)
			if output["state"] != "excluded" || !reasons[output["reason"].(string)] || m["index"] != float64(i+1) {
				t.Errorf("excluded exchange %d: output %v at index %v, the line's reasons %v", i+1, output, m["index"], reasons)
			}
		}
		s.requireOneDone(0, 7, 4)
		settledCounts(t, o)
	})
	t.Run("at a cut", func(t *testing.T) {
		// A body past the limit is elided and stops its exchange at its end:
		// until more of that direction is read, a later stop of capture's
		// there could still take the reason over.
		s := newStreamed(t, streamedOptions{connectionInput: 6, limits: reconstruct.Limits{HTTP: http1.Limits{MaxBodyBytes: 4}},
			extensions: []streamedExtension{{name: "watching", mode: "unchanged"}}})
		c := converse(t, 8, append(append(pairs("/a"), wrote("GET /b HTTP/1.1\r\nHost: a\r\n\r\n"),
			read("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n/long")), asked("/c", "/d", "/e", "/f", "/g", "/h")...)...)
		s.give(c.fragments[:4]...)
		s.until("the elided exchange was issued its id with the first one answered", func() bool {
			o := s.run.Snapshot()
			return o.ExchangeIDs == 2 && o.Extensions[0].Unchanged == 1
		})
		if got := s.received(0, "exchange"); len(got) != 1 {
			t.Fatalf("before its reason was decidable the extension received %d exchanges, want only the eligible one",
				len(got))
		}
		s.give(c.fragments[4:]...)
		s.until("the unanswered requests cut the connection", func() bool { return s.run.Snapshot().ConnectionsCut == 1 })
		if !s.within(5*time.Second, func() bool { return len(s.received(0, "exchange")) == 2 }) {
			t.Fatal("the cut did not send the held excluded exchange")
		}
		if output := s.received(0, "exchange")[1]["output"].(map[string]any); output["state"] != "excluded" ||
			output["reason"] != processing.TruncationConnectionCut {
			t.Errorf("the excluded exchange sent at the cut: %v", output)
		}
		s.end(c)
		o := s.finish()
		s.requireOneDone(0, 8, 2)
		settledCounts(t, o)
	})
}

// A slow extension costs extension processing before it costs a connection:
// a call is admitted at its connection's whole charge, so once the waiting
// connections hold the extension's share, the next call skips it as busy and
// its exchange is written unchanged, and no connection is cut. A waiting
// connection holds its captured input, its parsed copy and its processed
// copy, about three times its input: admitted at its intake bytes alone, the
// waiting connections would together hold more than the allowance, and capture
// or a connection would be cut first.
func TestAnExtensionSlowerThanItsLoadIsSkippedBeforeAnyConnectionIsCut(t *testing.T) {
	const limit, connections = 512 << 10, 30
	s := newStreamed(t, streamedOptions{limit: limit, timeoutMS: 4000,
		extensions: []streamedExtension{{name: "slow", mode: "loop"}}})
	body := strings.Repeat("b", 3900)
	for n := 1; n <= connections; n++ {
		id := fragment.ConnectionID(100 + n)
		head := "POST /n" + strconv.Itoa(n) + " HTTP/1.1\r\nHost: a\r\nContent-Length: " + strconv.Itoa(2*len(body)) + "\r\n\r\n"
		c := converse(t, id, wrote(head+body), wrote(body), read("HTTP/1.1 204 No Content\r\n\r\n"))
		for _, f := range c.fragments {
			if err := s.store.Write(f); err != nil {
				o := s.run.Snapshot()
				t.Fatalf("capture was refused at connection %d (%v) while the slow extension had refused %d calls as busy",
					n, err, o.Extensions[0].FailedBy[extension.Busy])
			}
		}
		if err := s.store.Connection(c.retirement); err != nil {
			t.Fatalf("capture was refused at connection %d's end (%v)", n, err)
		}
		s.run.Route()
		if !s.within(5*time.Second, func() bool {
			o := s.run.Snapshot()
			return len(o.Extensions) == 1 && o.Extensions[0].Considered == uint64(n) || o.ConnectionsCut > 0
		}) {
			t.Fatalf("wiring, not the property: connection %d was never issued an id or cut", n)
		}
	}
	snapshot := s.run.Snapshot()
	counts := snapshot.Extensions[0]
	if snapshot.ConnectionsCut != 0 || snapshot.AllowanceCut != 0 {
		t.Fatalf("connections were cut (%d, %d by the allowance) while the slow extension had refused %d calls as busy",
			snapshot.ConnectionsCut, snapshot.AllowanceCut, counts.FailedBy[extension.Busy])
	}
	if counts.FailedBy[extension.Busy] == 0 || counts.Pending == 0 {
		t.Fatalf("the slow extension: busy %d, pending %d", counts.FailedBy[extension.Busy], counts.Pending)
	}
	s.mutex.Lock()
	for _, call := range s.calls {
		if call.Bytes != call.Charged {
			t.Errorf("call %d was admitted at %d, not its connection's charge %d", call.ID, call.Bytes, call.Charged)
		}
	}
	s.mutex.Unlock()
	busy := 0
	for n := 1; n <= connections; n++ {
		for _, a := range s.written(processing.ArtifactExchange, fragment.ConnectionID(100+n)) {
			if len(a.ExtensionOutcomes) == 1 && a.ExtensionOutcomes[0].Reason == extension.Busy {
				busy++
				if got := a.Reconstruction.Exchanges[0].Request.Message.Target; got != "/n"+strconv.Itoa(n) {
					t.Errorf("a busy exchange was written as %q", got)
				}
			}
		}
	}
	if uint64(busy) != counts.FailedBy[extension.Busy] {
		t.Errorf("%d busy exchanges were written of %d counted busy", busy, counts.FailedBy[extension.Busy])
	}
	settledCounts(t, s.finish())
}

// An answer whose replacement the shared allowance has no room to keep fails
// at its extension as no_room: nothing of it is applied, the exchange goes on
// to the next extension as it was, and its line is written; the connection is
// cut, and every extension's counts settle.
func TestAReplacementWithNoRoomFailsAsNoRoomAndTheExchangeGoesOn(t *testing.T) {
	s := newStreamed(t, streamedOptions{limit: 1 << 20, extensions: []streamedExtension{
		{name: "replacing", mode: "replacement", args: []string{"--delay", "500ms"}}, {name: "after", mode: "unchanged"}}})
	c := converse(t, 9, pairs("/kept")...)
	s.give(c.fragments...)
	// The answer is delayed, so the room is taken while the call is
	// outstanding.
	s.until("the open connection's exchange reached the extension", func() bool {
		return len(s.received(0, "exchange")) == 1
	})
	held := s.store.Stats()
	hold := held.LimitBytes - held.Bytes - held.Parsing - held.Policy
	if !s.store.Reserve(intake.Policy, hold) {
		t.Fatalf("wiring, not the property: the fixture could not take the %d left", hold)
	}
	if !s.within(5*time.Second, func() bool { return len(s.received(1, "exchange")) == 1 }) {
		t.Fatalf("after its no_room answer the exchange did not go on to the next extension: %d lines written",
			len(s.written(processing.ArtifactExchange, 9)))
	}
	s.end(c)
	o := s.finish()
	exchanges := s.written(processing.ArtifactExchange, 9)
	if len(exchanges) != 1 {
		t.Fatalf("an exchange whose replacement had no room wrote %d lines, want 1", len(exchanges))
	}
	request := exchanges[0].Reconstruction.Exchanges[0].Request.Message
	if request.Target != "/kept" || request.Body.Kept != "" {
		t.Errorf("the exchange was written as %q with body %q, not as it was", request.Target, request.Body.Kept)
	}
	outcomes := exchanges[0].ExtensionOutcomes
	if len(outcomes) != 2 || outcomes[0].Reason != extension.NoRoom || outcomes[1].Outcome != extension.Unchanged {
		t.Errorf("the outcomes: %+v", outcomes)
	}
	if len(s.received(1, "exchange")) != 1 {
		t.Errorf("the next extension received %d exchanges, want the one", len(s.received(1, "exchange")))
	}
	if o.AllowanceCut != 1 || o.ConnectionsCut != 1 || s.store.Stats().PolicyRefused != 1 {
		t.Errorf("AllowanceCut %d, ConnectionsCut %d and Policy refusals %d, want the connection cut for its one refusal",
			o.AllowanceCut, o.ConnectionsCut, s.store.Stats().PolicyRefused)
	}
	if left := s.store.Stats(); left.Bytes != 0 || left.Parsing != 0 || left.Policy != hold {
		t.Errorf("settled, the store holds %+v beside the fixture's %d", left, hold)
	}
	counts := settledCounts(t, o)
	if counts["replacing"]["failed_by."+extension.NoRoom] != 1 || counts["after"]["unchanged"] != 1 {
		t.Errorf("the counts: %v", counts)
	}
	s.requireOneDone(0, 9, 1)
	s.requireOneDone(1, 9, 1)
}

// An answer whose replacement has no room, arriving after its connection
// ended and every exchange of it was released, fails as no_room and cuts the
// connection, whose line's truncation states only what was not written: each
// direction stops at its last byte, where nothing after it was discarded.
func TestANoRoomCutAfterItsConnectionEndedStatesOnlyWhatWasNotWritten(t *testing.T) {
	s := newStreamed(t, streamedOptions{limit: 1 << 20, extensions: []streamedExtension{
		{name: "replacing", mode: "replacement", args: []string{"--delay", "500ms"}}}})
	c := converse(t, 10, pairs("/ended")...)
	var last [3]uint64
	for _, f := range c.fragments {
		last[f.Direction] = max(last[f.Direction], f.End())
	}
	s.give(c.fragments...)
	s.end(c)
	s.until("the connection ended while its exchange's call was outstanding", func() bool {
		o := s.run.Snapshot()
		return len(s.received(0, "exchange")) == 1 && o.Batches == 1 && o.Pending == 1
	})
	held := s.store.Stats()
	hold := held.LimitBytes - held.Bytes - held.Parsing - held.Policy
	if !s.store.Reserve(intake.Policy, hold) {
		t.Fatalf("wiring, not the property: the fixture could not take the %d left", hold)
	}
	o := s.finish()
	counts := settledCounts(t, o)["replacing"]
	if counts["failed_by."+extension.NoRoom] != 1 || o.AllowanceCut != 1 {
		t.Fatalf("wiring, not the property: the answer did not fail as no_room with its cut, so nothing was "+
			"refused: %v, AllowanceCut %d", counts, o.AllowanceCut)
	}
	lines := s.written(processing.ArtifactConnection, 10)
	if len(lines) != 1 || len(s.written(processing.ArtifactExchange, 10)) != 1 {
		t.Fatalf("the ended connection wrote %d connection lines and %d exchange lines, want one each", len(lines),
			len(s.written(processing.ArtifactExchange, 10)))
	}
	if o.InputCut != 0 {
		t.Errorf("a cut after the connection ended counted %d input entries discarded", o.InputCut)
	}
	truncation := lines[0].ReconstructionTruncation
	if truncation == nil || len(truncation.Stops) != 2 {
		t.Fatalf("the cut connection's line: %+v", truncation)
	}
	for _, stop := range truncation.Stops {
		direction := fragment.Sent
		if stop.Direction == fragment.Received.String() {
			direction = fragment.Received
		}
		end := strconv.FormatUint(last[direction], 10)
		if stop.Reason != processing.TruncationConnectionCut || stop.Offset != end || stop.EvidenceOffset != end {
			t.Errorf("the %s stop claims %s through %s as not written, where the direction's last byte is %s",
				stop.Direction, stop.Offset, stop.EvidenceOffset, end)
		}
	}
}

// A capture loss while exchanges of its connection wait their turn withdraws
// them: each skips every extension as withdrawn and is never sent, nothing of
// the connection is written after the loss, every id is still accounted for,
// and connection_done follows once the connection ends.
func TestACaptureLossWithdrawsTheExchangesWaitingTheirTurn(t *testing.T) {
	s := newStreamed(t, streamedOptions{extensions: []streamedExtension{
		{name: "slow", mode: "unchanged", args: []string{"--delay", "500ms"}}}})
	c := converse(t, 11, pairs("/a", "/b", "/c")...)
	s.give(c.fragments...)
	s.until("the first exchange reached the extension with the others issued ids behind it", func() bool {
		return len(s.received(0, "exchange")) == 1 && s.run.Snapshot().ExchangeIDs == 3
	})
	if c.fragments[0].Loss == nil {
		t.Fatal("wiring, not the property: the fixture's fragments carry no loss token")
	}
	c.fragments[0].Loss.Stop("intake_exhausted")
	s.until("the first exchange was answered", func() bool {
		return s.run.Snapshot().Extensions[0].Unchanged == 1
	})
	s.end(c)
	o := s.finish()
	if got := len(s.received(0, "exchange")); got != 1 {
		t.Errorf("the extension was sent %d exchanges, want only the one sent before the loss", got)
	}
	counts := settledCounts(t, o)["slow"]
	if counts["failed_by."+extension.Withdrawn] != 2 || counts["unchanged"] != 1 || counts["failed_by.unavailable"] != 0 {
		t.Errorf("the extension's counts after the loss: %v", counts)
	}
	if lines := s.written(processing.ArtifactExchange, 11); len(lines) != 0 {
		t.Errorf("%d exchange lines were written after the loss", len(lines))
	}
	s.requireOneDone(0, 11, 3)
}

// A compressed response early on a long connection begins its excluded tail,
// and with extensions configured each excluded exchange is sent and let go as
// soon as its reason is decidable: the connection's held work plateaus, it is
// not cut at its bound, and the extension receives every exchange while the
// connection is open.
func TestAnExcludedTailDoesNotGrowOnALongConnection(t *testing.T) {
	const later = 30
	s := newStreamed(t, streamedOptions{connectionInput: 8, extensions: []streamedExtension{
		{name: "watching", mode: "unchanged"}}})
	gzipped := read("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\nzz")
	calls := append(pairs("/a"), wrote("GET /b HTTP/1.1\r\nHost: a\r\n\r\n"), gzipped)
	for n := range later {
		calls = append(calls, pair("/n"+strconv.Itoa(n))...)
	}
	c := converse(t, 12, calls...)
	var held []int64
	for k := 1; k <= later+2; k++ {
		s.give(c.fragments[2*(k-1) : 2*k]...)
		if !s.within(5*time.Second, func() bool { return s.run.Snapshot().Extensions[0].Unchanged == uint64(k) }) {
			o := s.run.Snapshot()
			t.Fatalf("while the connection is open the extension answered %d of %d exchanges; %d cut", o.Extensions[0].Unchanged,
				k, o.ConnectionsCut)
		}
		one := s.store.Stats()
		held = append(held, one.Bytes+one.Parsing+one.Policy)
	}
	if o := s.run.Snapshot(); o.ConnectionsCut != 0 || o.ExchangeIDs != later+2 {
		t.Fatalf("the long connection: %d cut, %d ids", o.ConnectionsCut, o.ExchangeIDs)
	}
	got := s.received(0, "exchange")
	if output := got[1]["output"].(map[string]any); output["state"] != "excluded" {
		t.Fatalf("wiring, not the property: the compressed exchange was not excluded: %v", output)
	}
	early, late := slices.Max(held[2:12]), slices.Max(held[len(held)-10:])
	if late > early {
		t.Errorf("held work grows along the excluded tail: at most %d over exchanges 3 to 12, %d over the last 10: %v",
			early, late, held)
	}
	s.end(c)
	o := s.finish()
	s.requireOneDone(0, 12, later+2)
	settledCounts(t, o)
}

// A released exchange's captured input stays held while it waits on its
// extensions, and goes back once its lines are written, each entry at its last
// retained byte: one fragment wholly inside the first exchange goes back with
// the first exchange's lines, and a fragment shared with the second stays
// until the second's lines are written.
func TestAnExchangesInputGoesBackOnceItsLinesAreWritten(t *testing.T) {
	s := newStreamed(t, streamedOptions{extensions: []streamedExtension{
		{name: "slow", mode: "unchanged", args: []string{"--delay", "500ms"}}}})
	c := converse(t, 13, wrote("GET /a HTTP/1.1\r\nHost: a\r\n\r\n"), wrote("GET /b HTTP/1.1\r\nHost: a\r\n\r\n"),
		read("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n/aHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n/b"))
	s.give(c.fragments...)
	s.until("both exchanges were handed over with the first one's call outstanding", func() bool {
		return len(s.received(0, "exchange")) == 1 && s.run.Snapshot().ExchangeIDs == 2
	})
	if held := s.store.Stats(); held.Leased != 3 {
		t.Errorf("while the first exchange waits on its extension the connection holds %d of its 3 entries", held.Leased)
	}
	if !s.within(5*time.Second, func() bool {
		return len(s.written(processing.ArtifactExchange, 13)) == 1 && s.store.Stats().Leased == 2
	}) {
		t.Errorf("after the first exchange's lines: %d lines, %d entries held; want 1 line, and the fragment shared "+
			"with the second exchange held beside the second request", len(s.written(processing.ArtifactExchange, 13)),
			s.store.Stats().Leased)
	}
	if !s.within(5*time.Second, func() bool {
		return len(s.written(processing.ArtifactExchange, 13)) == 2 && s.store.Stats().Leased == 0
	}) {
		t.Errorf("after both exchanges' lines: %d lines, %d entries held", len(s.written(processing.ArtifactExchange, 13)),
			s.store.Stats().Leased)
	}
	s.end(c)
	settledCounts(t, s.finish())
}
