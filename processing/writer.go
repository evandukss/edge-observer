package processing

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/evandukss/edge-observer/sink"
	"path/filepath"
	"sync"
	"time"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/extension"
	"github.com/evandukss/edge-observer/held"
)

const (
	ArtifactName = "approved.jsonl"
	// ArtifactVersion is what the worker writes. The reader also reads
	// ArtifactVersion1, under that version's rules; a reader of version 1
	// alone refuses a version 2 artifact.
	ArtifactVersion  = ArtifactVersion3
	ArtifactVersion2 = "observer.approved/2"
	ArtifactVersion1 = "observer.approved/1"
)

// Dispositions of a version 2 policy exclusion entry.
const (
	// DispositionRemoved is the named field removed: a header, a query or
	// form parameter, a JSON member or element, the query, or the whole body
	// by remove-body or by reduce-body-to-structure where no structure was
	// derived.
	DispositionRemoved = "removed"
	// DispositionValuesRemoved is a body's bytes removed with its derived
	// structure (member names, nesting and value kinds) kept.
	DispositionValuesRemoved = "values_removed"
	// DispositionRemovedUndecidable is a whole body or query removed because a
	// field operation could not decide what it held: not strictly valid JSON
	// within the bounds for a JSON field operation, not admitted as urlencoded
	// for a form field operation, or a malformed percent escape for a form or
	// query parameter operation.
	DispositionRemovedUndecidable = "removed_undecidable"
)

var (
	ErrUnapproved   = errors.New("record has no release authorization")
	ErrOutputClosed = errors.New("approved output is closed")
)

// ArtifactVersion3 identifies one exchange per line, or a retirement line.
const ArtifactVersion3 = "observer.approved/3"

const (
	ArtifactExchange   = "exchange"
	ArtifactConnection = "connection"
)

// Artifact is one JSON line, followed by LF, in approved.jsonl. All pipelines
// and sinks share this file. Route carries the compiled pipeline, sink and kind;
// PolicyRevision identifies the configuration used at capture, never at read.
// Connection is the published metadata record, including the actual ending.
// Reconstruction is present only on reconstruction routes and contains only
// processed, decidable exchanges. Its published Body.Kept is base64 payload,
// and headers/trailers retain permitted values. Connection routes omit it.
// ReconstructionTruncation is carried on the retirement line, describing an
// incomplete suffix independently of the connection's ending. Exchange lines
// carry one complete pair; they never assert that a whole stream is complete.
// PolicyExclusions names actual removals by policy in retained messages,
// independently for this pipeline. New artifacts always carry an array: empty
// means no field was removed from the published population, including metadata
// routes. It says nothing about an unpublished or indeterminate suffix. Older
// artifacts without this member decode to nil: evidence unavailable, not none.
// A null member likewise means unavailable. Readers must preserve this distinction.
// A body removed whole keeps its Body.Length and framing, has an empty
// Body.Kept and Structure.State "removed"; a body whose values were removed
// keeps its derived structure and has an empty Body.Kept.
// No raw observation, undecidable tail, or source copy accompanies this line.
// A reader decodes this shape directly and must not re-run local policy.
type Artifact struct {
	Record     string `json:"record,omitempty"`
	Session    string `json:"session,omitempty"`
	ExchangeID string `json:"exchange_id,omitempty"`
	Index      *int   `json:"index,omitempty"`

	Version                  string                    `json:"version"`
	PolicyRevision           string                    `json:"policy_revision"`
	Route                    config.DurableRoute       `json:"route"`
	Connection               record.Connection         `json:"connection"`
	Reconstruction           *record.Reconstruction    `json:"reconstruction,omitempty"`
	ReconstructionTruncation *ReconstructionTruncation `json:"reconstruction_truncation,omitempty"`
	PolicyExclusions         []PolicyExclusion         `json:"policy_exclusions"`
	// ExchangeIDs is historical version 2 data. Version 3 uses ExchangeID
	// on each exchange line; versions 1 and 3 have no range.
	ExchangeIDs *IDRange `json:"exchange_ids,omitempty"`
	// ExtensionOutcomes is, per retained exchange and configured extension in
	// the order they ran, what the extension did to it. Empty with no
	// extension configured and on a connections route.
	ExtensionOutcomes []ExtensionOutcome `json:"extension_outcomes"`
	// ReplacementExclusions is what the configuration's rules removed from
	// content an extension supplied, apart from PolicyExclusions, which is
	// only what they removed from captured content.
	ReplacementExclusions []ReplacementExclusion `json:"replacement_exclusions"`
}

// IDRange is the exchange ids issued to one connection's exchanges: the
// exchange at index i has id First + i. Every member is a decimal string.
// Count is "0", with no First or Last, where none was issued.
type IDRange struct {
	First string `json:"first,omitempty"`
	Last  string `json:"last,omitempty"`
	Count string `json:"count"`
}

// ExtensionOutcome is what one extension did to one retained exchange.
// Outcome is extension.Unchanged, Changed or Failed. With Changed, Changed
// lists the fields its accepted answer replaced and Overwritten those of them
// a later extension replaced again, so they are not what is written; both are
// present lists. With Failed, Reason is one of the protocol's reasons.
type ExtensionOutcome struct {
	Exchange    int      `json:"exchange"`
	Extension   string   `json:"extension"`
	Outcome     string   `json:"outcome"`
	Changed     []string `json:"changed,omitempty"`
	Overwritten []string `json:"overwritten,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

// MarshalJSON writes Changed and Overwritten as lists, empty ones included,
// where the outcome is Changed, and neither otherwise.
func (o ExtensionOutcome) MarshalJSON() ([]byte, error) {
	type plain ExtensionOutcome
	if o.Outcome != extension.Changed {
		o.Changed, o.Overwritten = nil, nil
		return json.Marshal(plain(o))
	}
	listed := func(fields []string) []string {
		if fields == nil {
			return []string{}
		}
		return fields
	}
	return json.Marshal(struct {
		Exchange    int      `json:"exchange"`
		Extension   string   `json:"extension"`
		Outcome     string   `json:"outcome"`
		Changed     []string `json:"changed"`
		Overwritten []string `json:"overwritten"`
	}{o.Exchange, o.Extension, o.Outcome, listed(o.Changed), listed(o.Overwritten)})
}

// ReplacementExclusion is a removal the configuration's rules made from
// replacement content, with the extension that supplied it. Its other members
// follow PolicyExclusion's rules.
type ReplacementExclusion struct {
	PolicyExclusion
	Extension string `json:"extension"`
}

// PolicyExclusion records that policy removed a field, never its value.
// Exchange is the Index of an exchange in this artifact's Reconstruction and
// Message is request or response.
//
// In version 2, Field is the exclusion field form of what was removed
// (message.headers.<name>, message.body, message.body.values,
// message.target.query, message.query.<name>, message.form.<name> or
// message.body.json<pointer>, with the pointer as configured) and Disposition
// is one of the Disposition constants. Section is headers or trailers for a
// header field and absent otherwise. Name is absent.
//
// In version 1, Section is headers or trailers, Name is the lowercase HTTP
// field name, and Field and Disposition are absent.
//
// An entry exists only where the component was present: a body with bytes, a
// target with a "?", a parameter, member or header the message carried. Each
// entry occurs once even if a field repeated or several slots selected it.
// Array order has no meaning. Configured names absent from the message,
// replacement and truncation add no entry.
type PolicyExclusion struct {
	Exchange    int    `json:"exchange"`
	Message     string `json:"message"`
	Field       string `json:"field,omitempty"`
	Section     string `json:"section,omitempty"`
	Name        string `json:"name,omitempty"`
	Disposition string `json:"disposition,omitempty"`
}

// ReconstructionTruncation describes the boundary of the approved exchanges,
// never the connection's lifetime. State is truncated, Suffix is indeterminate,
// and Stops is nonempty, ordered sent then received, at most one per direction.
// It contains structural evidence only, with no discarded source or parser text.
type ReconstructionTruncation struct {
	State  string           `json:"state"`
	Suffix string           `json:"suffix"`
	Stops  []TruncationStop `json:"stops"`
}

// TruncationStop names a direction (sent or received) and two decimal byte
// offsets in that direction. Offset is the first byte excluded from the
// approved reconstruction, immediately after its last retained message.
// EvidenceOffset locates the evidence that prevented retaining more: the first
// missing/unplaced byte, the end reached in an incomplete or malformed message,
// or the start of an unsupported, unpaired or unparsed message. These differ
// when a hole lies inside a message which must be withheld in its entirety.
// Reason is one of capture_hole, positions_unknown, incomplete_message,
// malformed_message, ambiguous_framing, processing_limit, unsupported_message,
// unpaired_exchange, unparsed_suffix, or connection_cut
// (TruncationConnectionCut). These codes never describe source text.
// TruncationConnectionCut is the stop of a connection cut because it held as
// much input as one connection may while waiting to be processed: its input
// was discarded from its first byte, so the stop's offset is zero and its
// evidence offset is how far that direction's discarded input ran.
const TruncationConnectionCut = "connection_cut"

type TruncationStop struct {
	Direction      string `json:"direction"`
	Offset         string `json:"offset"`
	Reason         string `json:"reason"`
	EvidenceOffset string `json:"evidence_offset"`
}

// Approved is an immutable, already encoded artifact with a completed gate
// authorization. Only Worker constructs it. Its zero value is refused by Writer;
// callers cannot turn an Artifact or an eligibility snapshot into Approved.
// Each value is for one write only; Output implementations must not replay it.
type Approved struct{ line []byte }

// Bytes returns a detached copy of the encoded JSON line, including LF, for an
// output boundary or inspection test. Mutating it cannot alter the approved data.
func (a Approved) Bytes() []byte { return append([]byte(nil), a.line...) }

// WriterStats describes best-effort attempts for one session. LimitBytes is
// the retained queue bound, never a total disk allowance. Bytes includes partial
// failed writes.
type WriterStats struct {
	LimitBytes     int64
	Bytes          int64
	DerivedBytes   int64
	Written        uint64
	Refused        uint64
	Closed         bool
	Authorized     uint64
	Failed         uint64
	Dropped        uint64
	Pending        uint64
	Discarded      uint64
	PendingBytes   int64
	HighWaterBytes int64
}

type Writer struct {
	mutex     sync.Mutex
	directory string
	queue     *sink.Queue
	factory   sink.Factory
	closed    bool
	derived   []string
}

// Open opens stable output with a bound on queued and in-flight bytes.
// An unavailable destination is a failed attempt when a line reaches it,
// never a construction error. Use Reopen to recover it.
func Open(dir string, queueBytes int64) (*Writer, error) {
	return OpenWriter(WriterOptions{Directory: dir, QueueBytes: queueBytes})
}
func (w *Writer) WriteApproved(ctx context.Context, result Approved) error {
	if w == nil || w.queue == nil {
		return ErrOutputClosed
	}
	if len(result.line) == 0 {
		return ErrUnapproved
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return w.queue.Enqueue(ArtifactName, result.line)
}

// Retained is what this writer holds now: the derived files it has opened,
// and what its sink queue holds.
func (w *Writer) Retained() ([]held.Occupancy, error) {
	if w == nil {
		return nil, nil
	}
	w.mutex.Lock()
	derived := len(w.derived)
	w.mutex.Unlock()
	out := []held.Occupancy{{Store: "processing.derived_files", Held: derived}}
	queue, err := w.queue.Retained()
	if err != nil {
		return nil, err
	}
	return append(out, queue...), nil
}

func (w *Writer) Stats() WriterStats {
	if w == nil {
		return WriterStats{Closed: true}
	}
	approved, all := w.DeliveryStats(), w.queue.Stats()
	w.mutex.Lock()
	closed := w.closed
	var derivedBytes int64
	for _, route := range w.derived {
		derivedBytes += w.queue.DestinationStats(route).Bytes
	}
	w.mutex.Unlock()
	return WriterStats{LimitBytes: all.LimitBytes, Bytes: approved.Bytes, DerivedBytes: derivedBytes,
		Written: approved.Written, Refused: approved.Dropped, Closed: closed, Authorized: approved.Authorized,
		Failed: approved.Failed, Dropped: approved.Dropped, Pending: approved.Pending, Discarded: approved.Discarded,
		PendingBytes: all.PendingBytes, HighWaterBytes: all.HighWaterBytes}
}
func DerivedName(name string) string { return "derived-" + name + ".jsonl" }
func (w *Writer) openDerived(name string) (*derivedFile, error) {
	if w == nil || !config.ExtensionName.MatchString(name) {
		return nil, ErrOptions
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if w.closed {
		return nil, ErrOutputClosed
	}
	route := DerivedName(name)
	if err := w.queue.Register(route, w.factory(filepath.Join(w.directory, route))); err != nil {
		return nil, err
	}
	w.derived = append(w.derived, route)
	return &derivedFile{writer: w, name: route}, nil
}
func (w *Writer) writeDerived(f *derivedFile, line []byte) string {
	err := w.queue.Enqueue(f.name, line)
	switch {
	case err == nil:
		return ""
	case errors.Is(err, sink.ErrQueueFull):
		return extension.DerivedQueueFull
	default:
		return extension.DerivedStopped
	}
}
func (w *Writer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return w.Shutdown(ctx)
}
