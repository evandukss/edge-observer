package processing

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/contract/record"
	"github.com/evandukss/edge-observer/extension"
)

const (
	ArtifactName = "approved.jsonl"
	// ArtifactVersion is what the worker writes. The reader also reads
	// ArtifactVersion1, under that version's rules; a reader of version 1
	// alone refuses a version 2 artifact.
	ArtifactVersion  = "observer.approved/2"
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
	ErrOutputLimit  = errors.New("approved output storage limit reached")
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
// ReconstructionTruncation accompanies a retained prefix whose suffix could
// not be established. On those records Reconstruction.Unplaced is undetermined,
// has no numeric value, and gives reconstruction_truncated as its reason. A
// reader must retain both facts; a complete exchange is not a complete stream.
// Connection routes omit both reconstruction fields. Untruncated reconstructions
// omit ReconstructionTruncation; that omission never asserts a transport close.
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
	// ExchangeIDs is the range of exchange ids issued to this connection's
	// exchanges, on every route. Version 1 artifacts have none.
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
// unpaired_exchange, or unparsed_suffix. These codes never describe source text.
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

// WriterStats counts encoded disk bytes, including LF and JSON/base64 overhead.
// Written counts complete lines. Bytes includes a partial failed write; a partial
// write is an output failure and permanently stops the writer, never a delivery.
// Exhausted reports a permanent write refusal, whether from the byte allowance
// or a terminal I/O failure. It is not a count of successful writes.
type WriterStats struct {
	LimitBytes int64
	Bytes      int64
	// DerivedBytes is what the extensions' derived files hold, which shares
	// LimitBytes: at most half of it, and never so much that Bytes and
	// DerivedBytes together pass it.
	DerivedBytes int64
	Written      uint64
	Refused      uint64
	Exhausted    bool
	Closed       bool
}

// Writer owns the aggregate approved-output allowance for one session. Every
// route and both record types share it, in encoded bytes in approved.jsonl.
// There are no other payload files, spill files or temporary output files.
// The session account files are metadata owned by the controller and outside
// this allowance, as they were outside the legacy spool's two-file allowance.
// The controller passes the resolved ApprovedOutputBoundMiB converted to bytes; this is
// independent of volatile intake accounting and is not a heap budget.
//
// A line exceeding the remaining allowance is refused whole with ErrOutputLimit
// before writing any of it. Exhaustion is sticky, including after Close. No
// eviction, rotation, refund or overwrite makes room. Previously written lines
// stay usable. Output failure never retries or falls back to source bytes.
// The private file is an io.WriteCloser so tests can force partial writes and
// I/O errors deterministically. Open always supplies the exclusively created
// *os.File; this seam does not add a public output-injection API.
type Writer struct {
	mutex     sync.Mutex
	directory string
	file      io.WriteCloser
	stats     WriterStats
	exhausted chan struct{}
	failed    bool
}

// Open requires nonempty dir and positive limitBytes. Relative and absolute
// directory paths are accepted. Parents may already exist; missing directories
// are created with mode 0700. approved.jsonl is created exclusively with mode
// 0600: any existing entry (including a symlink) refuses activation. No append
// or resume is supported. Parent symlinks follow ordinary filesystem resolution.
func Open(dir string, limitBytes int64) (*Writer, error) {
	if dir == "" || limitBytes <= 0 {
		return nil, ErrOptions
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("create approved output directory")
	}
	f, err := os.OpenFile(filepath.Join(dir, ArtifactName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, errors.New("create fresh approved output file")
	}
	return &Writer{directory: dir, file: f, stats: WriterStats{LimitBytes: limitBytes}, exhausted: make(chan struct{})}, nil
}

func (w *Writer) WriteApproved(ctx context.Context, result Approved) error {
	if w == nil {
		return ErrOutputClosed
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if w.file == nil || w.failed {
		return ErrOutputClosed
	}
	if w.stats.Exhausted {
		w.stats.Refused++
		return ErrOutputLimit
	}
	if len(result.line) == 0 {
		w.stats.Refused++
		return ErrUnapproved
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Subtraction prevents overflow. Every byte passed to Write fits the same
	// allowance, even if the filesystem accepts only part of this line, and
	// derived output holds part of it.
	if int64(len(result.line)) > w.stats.LimitBytes-w.stats.Bytes-w.stats.DerivedBytes {
		w.stats.Refused++
		w.stats.Exhausted = true
		close(w.exhausted)
		return ErrOutputLimit
	}
	n, err := w.file.Write(result.line)
	w.stats.Bytes += int64(n)
	if err != nil || n != len(result.line) {
		w.failed = true
		w.stats.Exhausted = true
		// The mutex serializes all attempts. failed refuses every later call
		// before either closure site; byte exhaustion also returns before I/O.
		close(w.exhausted)
		if err == nil {
			return io.ErrShortWrite
		}
		return errors.New("write approved output failed")
	}
	w.stats.Written++
	return nil
}

// Exhausted closes on permanent write refusal, with no receiver required: this
// owner can no longer write. Byte-limit refusal, an I/O error and a short write
// all close it; cancellation before I/O leaves it open and permits a later call.
// The signal is sticky, including after Close. The controller consumes it to
// withdraw capture. Nil/zero writers are unusable and expose a closed signal.
// A writer error is reported independently of gate permission: permission never
// asserts that output succeeded.
func (w *Writer) Exhausted() <-chan struct{} {
	if w == nil || w.exhausted == nil {
		return unusableWriter
	}
	return w.exhausted
}

var unusableWriter = func() <-chan struct{} { c := make(chan struct{}); close(c); return c }()

func (w *Writer) Stats() WriterStats {
	if w == nil {
		return WriterStats{Closed: true}
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.stats
}

// DerivedName is the derived file of the extension named name.
func DerivedName(name string) string { return "derived-" + name + ".jsonl" }

// openDerived creates the derived file of the extension named name beside
// approved.jsonl, exclusively, with mode 0600. The name is the configuration's
// validated extension name, which cannot leave the directory.
func (w *Writer) openDerived(name string) (*derivedFile, error) {
	if w == nil || w.directory == "" {
		return nil, ErrOptions
	}
	f, err := os.OpenFile(filepath.Join(w.directory, DerivedName(name)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, errors.New("create fresh derived output file")
	}
	return &derivedFile{writer: w, file: f}, nil
}

// writeDerived writes one derived line of n bytes only where D + n <= M/2 and
// C + D + n <= M, with M the allowance, C the approved bytes and D the derived
// bytes, and returns "" or why it did not. A refusal never exhausts the
// approved output; an exhausted or closed approved output stops derived
// output too.
func (w *Writer) writeDerived(f *derivedFile, line []byte) string {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if w.file == nil || w.failed || w.stats.Exhausted || f.file == nil {
		return extension.DerivedStopped
	}
	if f.failed {
		return extension.DerivedWriteFailed
	}
	n, limit := int64(len(line)), w.stats.LimitBytes
	if n > limit/2-w.stats.DerivedBytes || n > limit-w.stats.Bytes-w.stats.DerivedBytes {
		return extension.DerivedBudget
	}
	written, err := f.file.Write(line)
	w.stats.DerivedBytes += int64(written)
	if err != nil || written != len(line) {
		f.failed = true
		return extension.DerivedWriteFailed
	}
	return ""
}

func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.stats.Closed = true
	if w.file == nil {
		return nil
	}
	f := w.file
	w.file = nil
	if err := f.Close(); err != nil {
		return errors.New("close approved output failed")
	}
	return nil
}
