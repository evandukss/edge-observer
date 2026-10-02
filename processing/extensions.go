package processing

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/jsonshape"
	"github.com/evandukss/edge-observer/reconstruct"
)

// extensions is a Run's extensions: one supervisor each, and the observer's
// own count of every exchange's outcome at each.
type extensions struct {
	entries     []config.Extension
	supervisors []*extension.Supervisor
	files       []*derivedFile

	mutex   sync.Mutex
	tallies []tally
}

// tally is one extension's exchange counts. Every id issued adds to
// considered and pending; each outcome moves one from pending.
type tally struct {
	considered, changed, unchanged, failed, pending uint64
	failedBy                                        map[string]uint64
}

// startExtensions starts a supervisor per configured extension, each with its
// derived file open. It returns nil where none is configured.
func startExtensions(options Options, r *release) (*extensions, error) {
	entries := options.Plan.Extensions()
	if len(entries) == 0 {
		return nil, nil
	}
	clock := options.Clock
	if clock == nil {
		clock = extension.System()
	}
	writeContent := slices.ContainsFunc(options.Plan.Pipelines(), func(p config.EffectivePipeline) bool {
		return p.Input == config.ReconstructionInput
	})
	waiting := extension.WaitingBytes(options.Intake.Stats().LimitBytes, len(entries))
	e := &extensions{entries: entries}
	for _, one := range entries {
		file, err := options.Derived.openDerived(one.Name)
		if err != nil {
			e.close()
			return nil, err
		}
		e.files = append(e.files, file)
		e.tallies = append(e.tallies, tally{failedBy: zeroed(account.ExtensionFailureReasons)})
	}
	for i, one := range entries {
		file := e.files[i]
		e.supervisors = append(e.supervisors, extension.Start(extension.Config{
			Name: one.Name, Command: one.Command, Fields: ordered(one.Fields), TimeoutMS: one.TimeoutMS,
			Session: options.Session, Revision: options.PolicyRevision, WriteContent: writeContent,
			WaitingBytes: waiting, Clock: clock, Events: options.Supervision,
			Issued:  r.issued.Load,
			Derived: func(line []byte) string { return r.writeDerived(options.Derived, file, line) },
		}))
	}
	return e, nil
}

func zeroed(vocabulary []string) map[string]uint64 {
	counts := make(map[string]uint64, len(vocabulary))
	for _, key := range vocabulary {
		counts[key] = 0
	}
	return counts
}

// ordered is fields in the protocol's order.
func ordered(fields []string) []string {
	var out []string
	for _, f := range config.ExtensionFields {
		if slices.Contains(fields, f) {
			out = append(out, f)
		}
	}
	return out
}

// end stops every extension in order, together, and closes the derived files.
func (e *extensions) end() {
	if e == nil {
		return
	}
	var done sync.WaitGroup
	for _, s := range e.supervisors {
		done.Go(s.End)
	}
	done.Wait()
	e.close()
}

// abort ends every extension at once and closes the derived files.
func (e *extensions) abort() {
	if e == nil {
		return
	}
	var done sync.WaitGroup
	for _, s := range e.supervisors {
		done.Go(s.Close)
	}
	done.Wait()
	e.close()
}

func (e *extensions) close() {
	for _, f := range e.files {
		_ = f.close()
	}
}

// issue adds n ids to every extension's considered and pending.
func (e *extensions) issue(n uint64) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	for i := range e.tallies {
		e.tallies[i].considered += n
		e.tallies[i].pending += n
	}
}

// count moves one exchange at extension k from pending to its outcome.
func (e *extensions) count(k int, outcome, reason string) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	t := &e.tallies[k]
	t.pending--
	switch outcome {
	case extension.Changed:
		t.changed++
	case extension.Unchanged:
		t.unchanged++
	default:
		t.failed++
		t.failedBy[reason]++
	}
}

// counts is every extension's counts now, in the order they run.
func (e *extensions) counts() []account.ExtensionCounts {
	if e == nil {
		return []account.ExtensionCounts{}
	}
	out := make([]account.ExtensionCounts, 0, len(e.entries))
	for i, one := range e.entries {
		lifecycle := e.supervisors[i].Counts()
		e.mutex.Lock()
		t := e.tallies[i]
		c := account.NoCounts(one.Name)
		c.Considered, c.Changed, c.Unchanged, c.Failed, c.Pending = t.considered, t.changed, t.unchanged, t.failed, t.pending
		c.FailedBy = maps.Clone(t.failedBy)
		e.mutex.Unlock()
		c.RetiredBy = lifecycle.RetiredBy
		c.Restarts, c.StateResets, c.Late, c.Duplicate = lifecycle.Restarts, lifecycle.StateResets, lifecycle.Late, lifecycle.Duplicate
		c.DerivedWritten, c.DerivedBytes, c.DerivedRefused = lifecycle.DerivedWritten, lifecycle.DerivedBytes, lifecycle.DerivedRefused
		c.DerivedRefusedBy = lifecycle.DerivedRefusedBy
		c.StderrDropped = lifecycle.StderrDropped
		out = append(out, c)
	}
	return out
}

// dispatch is one batch from its reconstruction to its lines: what each
// pipeline made of it, and, with extensions, where it is in their chain. It
// holds the batch's intake leases until its lines are written.
type dispatch struct {
	b        *batch
	metadata record.Connection
	// lines are the batch's pipelines in plan order: an artifact to write, or
	// none where the pipeline failed, and whether a refused suffix is counted
	// against it once written.
	lines []pipelineLine
	// ids is the range issued to the batch's exchanges.
	ids   IDRange
	first uint64
	// refusedWhole is a batch whose reconstruction was refused: it sends an
	// extension nothing, not even connection_done.
	refusedWhole bool

	// The reconstruction pipeline's state, for extensions: the connection as
	// parsed and as the chain left it, every exchange of each, the chain's
	// evidence and what it did to bodies, how many exchanges the output
	// writes, and why each one after those is excluded.
	reconstruction int
	source         reconstruct.Connection
	processed      reconstruct.Connection
	run            *slotRun
	good           int
	excluded       []string
	truncation     *ReconstructionTruncation

	outcomes []ExtensionOutcome
	replaced []ReplacementExclusion
	// changedBy is, per exchange, the outcome that last changed each field.
	changedBy []map[string]int

	// i and k are the exchange and the extension the chain is at.
	i, k  int
	bytes int64
	dead  bool
}

type pipelineLine struct {
	name     string
	input    string
	artifact *Artifact
	refused  bool
}

// completion is an extension's result for the call a dispatch waits on.
type completion struct {
	d      *dispatch
	k      int
	result extension.Result
}

// step submits d's next call, resolving every one that skips its extension
// at once, and reports whether d now waits for a result. Every exchange of d
// was projected when it was dispatched and after each change, so a message
// that cannot be encoded is the observer's defect, returned as terminal.
func (w *Worker) step(d *dispatch) (bool, error) {
	exts := w.extensions
	for d.i < len(d.processed.Exchanges) {
		k := d.k
		message, err := w.exchangeMessage(d, d.i, k)
		if err != nil {
			return false, errors.New("internal observer defect: cannot encode an exchange for an extension")
		}
		reason := exts.supervisors[k].Submit(extension.Call{ID: d.first + uint64(d.i), Bytes: d.bytes,
			Message: message, Done: func(result extension.Result) {
				w.queue.complete(completion{d: d, k: k, result: result})
			}})
		if reason == "" {
			return true, nil
		}
		w.resolve(d, k, extension.Result{Outcome: extension.Failed, Reason: reason})
	}
	return false, nil
}

// resolve applies extension k's result for the exchange d is at, counts it,
// sends connection_done after the connection's last exchange, and moves d to
// the next call.
func (w *Worker) resolve(d *dispatch, k int, result extension.Result) {
	exts := w.extensions
	i := d.i
	name := exts.entries[k].Name
	outcome := ExtensionOutcome{Exchange: i, Extension: name, Outcome: result.Outcome}
	switch result.Outcome {
	case extension.Changed:
		changed, reason := w.change(d, i, k, result.Changes)
		if reason != "" {
			outcome = ExtensionOutcome{Exchange: i, Extension: name, Outcome: extension.Failed, Reason: reason}
			break
		}
		outcome.Changed, outcome.Overwritten = changed, []string{}
		for _, field := range changed {
			if previous, ok := d.changedBy[i][field]; ok {
				d.outcomes[previous].Overwritten = append(d.outcomes[previous].Overwritten, field)
			}
			d.changedBy[i][field] = len(d.outcomes)
		}
	case extension.Unchanged:
	default:
		outcome.Outcome, outcome.Reason = extension.Failed, result.Reason
	}
	d.outcomes = append(d.outcomes, outcome)
	exts.count(k, outcome.Outcome, outcome.Reason)
	if i == len(d.processed.Exchanges)-1 && !d.dead {
		w.connectionDone(d, k)
	}
	d.k++
	if d.k == len(exts.supervisors) {
		d.k = 0
		d.i++
	}
}

// connectionDone tells extension k that d's connection has no more exchanges.
func (w *Worker) connectionDone(d *dispatch, k int) {
	message := map[string]any{"type": "connection_done", "ids": d.ids, "ending": d.metadata.Ending}
	if slices.Contains(w.extensions.entries[k].Fields, config.FieldConnection) {
		message["connection"] = d.metadata
	}
	line, err := json.Marshal(message)
	if err != nil {
		return
	}
	w.extensions.supervisors[k].ConnectionDone(append(line, '\n'))
}

// settle applies every result that has arrived, writing the lines of each
// dispatch that no longer waits.
func (w *Worker) settle(ctx context.Context) error {
	if w.queue == nil {
		return nil
	}
	for _, c := range w.queue.completions() {
		d := c.d
		w.resolve(d, c.k, c.result)
		if d.dead {
			// Discarded: its result is counted, and nothing more is sent.
			continue
		}
		waits, err := w.step(d)
		if err != nil {
			return err
		}
		if waits {
			continue
		}
		delete(w.waiting, d)
		err = w.write(ctx, d)
		d.b.release()
		if err != nil {
			return err
		}
	}
	return nil
}

// exchangeMessage is the exchange message for exchange i of d at extension k:
// the fields its entry selects, as the chain left them.
func (w *Worker) exchangeMessage(d *dispatch, i, k int) ([]byte, error) {
	entry := w.extensions.entries[k]
	selected := func(field string) bool { return slices.Contains(entry.Fields, field) }
	e := d.processed.Exchanges[i]
	projected, err := w.project(d, i)
	if err != nil {
		return nil, err
	}
	side := func(m *reconstruct.Message, s record.Side, request bool) map[string]any {
		prefix := "response."
		if request {
			prefix = "request."
		}
		line, headers, body := selected(prefix+"line"), selected(prefix+"headers"), selected(prefix+"body")
		if !line && !headers && !body {
			return map[string]any{}
		}
		if m == nil || s.Message == nil {
			return map[string]any{"state": record.Absent}
		}
		r := s.Message
		out := map[string]any{"kind": r.Kind, "complete": r.Complete, "framed": r.Framed, "defect": r.Defect}
		if line {
			if request {
				out["method"], out["target"] = r.Method, r.Target
			} else {
				out["status"], out["reason"] = r.Status, r.Reason
			}
			out["protocol"] = r.Protocol
		}
		if headers {
			out["headers"], out["trailers"] = r.Headers, r.Trailers
		}
		if body {
			out["body"], out["framing"], out["structure"] = r.Body, r.Framing, r.Structure
		}
		return map[string]any{"state": record.Present, "message": out}
	}
	removed := []map[string]string{}
	for _, entry := range w.removals(d, i) {
		if !selected(fieldOfRemoval(entry)) {
			continue
		}
		one := map[string]string{"message": entry.Message, "field": entry.Field, "disposition": entry.Disposition}
		if entry.Section != "" {
			one["section"] = entry.Section
		}
		removed = append(removed, one)
	}
	output := map[string]string{"state": "eligible"}
	if i >= d.good {
		output = map[string]string{"state": "excluded", "reason": d.excluded[i]}
	}
	message := map[string]any{
		"type": "exchange", "id": strconv.FormatUint(d.first+uint64(i), 10), "ids": d.ids, "index": i,
		"output": output,
		"exchange": map[string]any{"index": i, "complete": e.Complete, "request": side(e.Request, projected.Request, true),
			"response": side(e.Response, projected.Response, false), "removed": removed},
	}
	if selected(config.FieldConnection) {
		message["connection"] = d.metadata
	}
	line, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	return append(line, '\n'), nil
}

// removals is every removal the rules made in exchange i: from captured
// content and from replacement content, once each.
func (w *Worker) removals(d *dispatch, i int) []PolicyExclusion {
	var out []PolicyExclusion
	for _, entry := range d.run.evidence.fields {
		if entry.Exchange == i {
			out = append(out, entry)
		}
	}
	for _, entry := range d.replaced {
		if entry.Exchange == i && !slices.Contains(out, entry.PolicyExclusion) {
			out = append(out, entry.PolicyExclusion)
		}
	}
	return out
}

// fieldOfRemoval is the extension field a removal lies in.
func fieldOfRemoval(e PolicyExclusion) string {
	prefix := e.Message + "."
	switch {
	case strings.HasPrefix(e.Field, config.HeaderFieldPrefix):
		return prefix + "headers"
	case e.Field == config.TargetQueryField || strings.HasPrefix(e.Field, config.QueryFieldPrefix):
		return prefix + "line"
	default:
		return prefix + "body"
	}
}

// project is exchange i of d as the record writes it, bodies marked as the
// chain left them.
func (w *Worker) project(d *dispatch, i int) (record.Exchange, error) {
	one := d.processed
	one.Exchanges = []reconstruct.Exchange{d.processed.Exchanges[i]}
	projected, _, err := record.FromReconstruction(reconstruct.Reconstruction{Connections: []reconstruct.Connection{one}}, nil)
	if err != nil {
		return record.Exchange{}, err
	}
	d.run.mark(&projected[0], one)
	e := projected[0].Exchanges[0]
	e.Index = i
	return e, nil
}

// The replacement rules of the protocol.
var (
	protocolPattern = regexp.MustCompile(`^HTTP/[0-9]\.[0-9]$`)
	// readOnly are members of a component an answer names that cannot be
	// replaced; any other unknown member is malformed.
	readOnly = []string{"kind", "complete", "framed", "defect", "state", "length", "holed", "elided", "encoding",
		"framing", "structure", "stream", "detail", "index", "id"}
)

const (
	maxHeaders      = 128
	maxTrailers     = 32
	maxHeaderBytes  = 65536
	maxReplacedBody = 8 << 20
)

// replacement is one accepted change, decoded and checked, not yet applied.
type replacement struct {
	field   string
	request bool
	method  string
	target  string
	proto   string
	status  int
	reason  string
	headers []http1.Header
	trails  []http1.Header
	body    []byte
}

// change checks extension k's changes to exchange i whole and, where every
// one is valid, applies each through the chain once. It returns the fields
// changed, in the protocol's order, or the reason the answer failed, in which
// case nothing of it is applied.
func (w *Worker) change(d *dispatch, i, k int, changes map[string]json.RawMessage) ([]string, string) {
	if i >= d.good {
		return nil, extension.Excluded
	}
	entry := w.extensions.entries[k]
	e := d.processed.Exchanges[i]
	names := slices.Sorted(maps.Keys(changes))
	for _, name := range names {
		if name == config.FieldConnection {
			return nil, extension.ReadOnly
		}
		if !slices.Contains(config.ExtensionFields, name) {
			return nil, extension.Malformed
		}
	}
	var replacements []replacement
	for _, name := range ordered(names) {
		if !slices.Contains(entry.Fields, name) {
			return nil, extension.NotGiven
		}
		request := strings.HasPrefix(name, "request.")
		m := e.Response
		if request {
			m = e.Request
		}
		if m == nil {
			return nil, extension.NotGiven
		}
		if strings.HasSuffix(name, ".body") {
			if disposition := d.run.bodies[m]; disposition == DispositionRemoved || disposition == DispositionValuesRemoved {
				return nil, extension.RemovedContent
			}
		}
		r, reason := decodeReplacement(name, request, changes[name])
		if reason != "" {
			return nil, reason
		}
		replacements = append(replacements, r)
	}
	// Kept whole, so a change whose result cannot be projected is undone:
	// the chain replaces components and never edits one in place.
	var saved [2]reconstruct.Message
	for side, m := range []*reconstruct.Message{e.Request, e.Response} {
		if m != nil {
			saved[side] = *m
		}
	}
	keptBodies := maps.Clone(d.run.bodies)
	replacedBefore := len(d.replaced)
	var fields []string
	for _, r := range replacements {
		w.rechain(d, i, entry.Name, r)
		fields = append(fields, r.field)
	}
	if _, err := w.project(d, i); err != nil {
		for side, m := range []*reconstruct.Message{e.Request, e.Response} {
			if m != nil {
				*m = saved[side]
			}
		}
		d.run.bodies = keptBodies
		d.replaced = d.replaced[:replacedBefore]
		return nil, extension.Malformed
	}
	return fields, ""
}

// decodeReplacement reads one replacement under the protocol's rules.
func decodeReplacement(field string, request bool, raw json.RawMessage) (replacement, string) {
	r := replacement{field: field, request: request}
	var members map[string]json.RawMessage
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &members) != nil {
		return r, extension.Malformed
	}
	var want []string
	switch {
	case strings.HasSuffix(field, ".line") && request:
		want = []string{"method", "target", "protocol"}
	case strings.HasSuffix(field, ".line"):
		want = []string{"status", "reason", "protocol"}
	case strings.HasSuffix(field, ".headers"):
		want = []string{"headers", "trailers"}
	default:
		want = []string{"kept"}
	}
	for name := range members {
		if slices.Contains(want, name) {
			continue
		}
		if slices.Contains(readOnly, name) {
			return r, extension.ReadOnly
		}
		return r, extension.Malformed
	}
	for _, name := range want {
		if _, ok := members[name]; !ok {
			return r, extension.Malformed
		}
	}
	text := func(name string) (string, bool) {
		var s string
		return s, json.Unmarshal(members[name], &s) == nil
	}
	switch {
	case strings.HasSuffix(field, ".line"):
		proto, ok := text("protocol")
		if !ok || !protocolPattern.MatchString(proto) {
			return r, extension.Malformed
		}
		r.proto = proto
		if request {
			method, ok1 := text("method")
			target, ok2 := text("target")
			if !ok1 || !ok2 || !isToken(method) || !printable(target, false) || target == "" {
				return r, extension.Malformed
			}
			r.method, r.target = method, target
			break
		}
		var status json.Number
		decoder := json.NewDecoder(strings.NewReader(string(members["status"])))
		decoder.UseNumber()
		reason, ok := text("reason")
		if decoder.Decode(&status) != nil || !ok || !printable(reason, true) {
			return r, extension.Malformed
		}
		n, err := strconv.Atoi(status.String())
		if err != nil || n < 100 || n > 999 {
			return r, extension.Malformed
		}
		r.status, r.reason = n, reason
	case strings.HasSuffix(field, ".headers"):
		var headers, trailers []map[string]json.RawMessage
		if json.Unmarshal(members["headers"], &headers) != nil || json.Unmarshal(members["trailers"], &trailers) != nil ||
			members["headers"][0] != '[' || members["trailers"][0] != '[' ||
			len(headers) > maxHeaders || len(trailers) > maxTrailers {
			return r, extension.Malformed
		}
		total := 0
		convert := func(items []map[string]json.RawMessage) ([]http1.Header, bool) {
			out := []http1.Header{}
			for _, item := range items {
				var name, value string
				if len(item) != 2 || json.Unmarshal(item["name"], &name) != nil || json.Unmarshal(item["value"], &value) != nil ||
					!isToken(name) || strings.ContainsAny(value, "\r\n\x00") {
					return nil, false
				}
				total += len(name) + len(value)
				out = append(out, http1.Header{Name: name, Value: value})
			}
			return out, true
		}
		var ok1, ok2 bool
		r.headers, ok1 = convert(headers)
		r.trails, ok2 = convert(trailers)
		if !ok1 || !ok2 || total > maxHeaderBytes {
			return r, extension.Malformed
		}
	default:
		kept, ok := text("kept")
		if !ok {
			return r, extension.Malformed
		}
		body, err := base64.StdEncoding.Strict().DecodeString(kept)
		if err != nil || len(body) > maxReplacedBody {
			return r, extension.Malformed
		}
		r.body = body
	}
	return r, ""
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0 {
			continue
		}
		return false
	}
	return true
}

// printable is visible ASCII, and with spaces, space and tab too.
func printable(s string, spaces bool) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x21 && c <= 0x7e || spaces && (c == ' ' || c == '\t') {
			continue
		}
		return false
	}
	return true
}

// rechain applies one replacement to exchange i as a new representation of
// its component: the component alone goes through the whole chain once, and
// what the chain removes from it is recorded apart, attributed to the
// extension that supplied it. Body operations read the captured message's
// header facts, as they do for captured content.
func (w *Worker) rechain(d *dispatch, i int, name string, r replacement) {
	m := d.processed.Exchanges[i].Response
	if r.request {
		m = d.processed.Exchanges[i].Request
	}
	scratch := &reconstruct.Message{}
	scratch.Kind, scratch.Complete, scratch.Framed, scratch.Defect = m.Kind, m.Complete, m.Framed, m.Defect
	switch {
	case strings.HasSuffix(r.field, ".line"):
		scratch.Method, scratch.Target, scratch.Protocol = r.method, r.target, r.proto
		scratch.Status, scratch.Reason = r.status, r.reason
	case strings.HasSuffix(r.field, ".headers"):
		scratch.Headers, scratch.Trailers = r.headers, r.trails
	default:
		scratch.Body = r.body
		scratch.BodyLength, scratch.BodyHoled, scratch.BodyElided = m.BodyLength, m.BodyHoled, m.BodyElided
		if shape, err := jsonshape.Extract(r.body, w.options.Limits.JSON); err == nil {
			scratch.Shape = &shape
		} else if len(r.body) > 0 {
			scratch.ShapeRefused = "body structure unavailable"
		}
	}
	exchange := reconstruct.Exchange{Response: scratch}
	parsed := reconstruct.Exchange{Response: d.source.Exchanges[i].Response}
	if r.request {
		exchange = reconstruct.Exchange{Request: scratch}
		parsed = reconstruct.Exchange{Request: d.source.Exchanges[i].Request}
	}
	connection := reconstruct.Connection{Process: d.processed.Process, ID: d.processed.ID, Role: d.processed.Role,
		Exchanges: []reconstruct.Exchange{exchange}}
	run := slotRun{source: reconstruct.Connection{Exchanges: []reconstruct.Exchange{parsed}},
		evidence: exclusionEvidence{fields: []PolicyExclusion{}}, bodies: map[*reconstruct.Message]string{},
		shapes: w.options.Limits.JSON}
	for _, slot := range w.pipelines[d.reconstruction].Slots {
		run.apply(&connection, slot)
	}
	for _, entry := range run.evidence.fields {
		entry.Exchange = i
		one := ReplacementExclusion{PolicyExclusion: entry, Extension: name}
		if !slices.Contains(d.replaced, one) {
			d.replaced = append(d.replaced, one)
		}
	}
	switch {
	case strings.HasSuffix(r.field, ".line"):
		m.Method, m.Target, m.Protocol, m.Status, m.Reason = scratch.Method, scratch.Target, scratch.Protocol, scratch.Status, scratch.Reason
	case strings.HasSuffix(r.field, ".headers"):
		m.Headers, m.Trailers = scratch.Headers, scratch.Trailers
	default:
		m.Body, m.Shape, m.ShapeRefused = scratch.Body, scratch.Shape, scratch.ShapeRefused
		if disposition, ok := run.bodies[scratch]; ok {
			d.run.bodies[m] = disposition
		} else {
			delete(d.run.bodies, m)
		}
	}
}

// derivedFile is one extension's derived output. The Writer's mutex guards
// it.
type derivedFile struct {
	writer *Writer
	file   *os.File
	// failed is a write that failed: a partial line may be in the file, so
	// nothing more is written to it.
	failed bool
}

func (f *derivedFile) close() error {
	f.writer.mutex.Lock()
	defer f.writer.mutex.Unlock()
	if f.file == nil {
		return nil
	}
	err := f.file.Close()
	f.file = nil
	return err
}

// writeDerived writes one derived line under the session's release and stop
// gate, the same authorization the observer's own lines need, and within the
// derived budget. A refusal is a reason, never a failure of the release.
func (r *release) writeDerived(w *Writer, f *derivedFile, line []byte) string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.err != nil {
		return extension.DerivedStopped
	}
	if decision := r.gate.Authorize(releaseEvidence); !decision.Authorized {
		return extension.DerivedStopped
	}
	return w.writeDerived(f, line)
}
