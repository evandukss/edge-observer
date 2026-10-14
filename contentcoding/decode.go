package contentcoding

import (
	"io"
)

// The exclusion reasons, as the connection line and the account spell them.
const (
	ReasonCodingUnsupported = "content_coding_unsupported"
	ReasonDecodingFailed    = "content_decoding_failed"
	ReasonDecodedTooLarge   = "content_decoded_too_large"
	ReasonDecodingTooCostly = "content_decoding_too_costly"
)

// Outcome is how a Decode ended.
type Outcome uint8

const (
	// Decoded is the stage completed, with its integrity and end checks.
	// Result.Body is the content.
	Decoded Outcome = iota + 1
	// Identity is a List with no coding: there was nothing to undo, nothing
	// was reserved and the captured body is the content.
	Identity
	// DecodingFailed is a stage whose input is not a valid stream of its
	// coding: corrupt, truncated, failing a checksum or length check, needing
	// a preset dictionary, or followed by bytes after its last member or frame.
	// Its exclusion reason is ReasonDecodingFailed.
	DecodingFailed
	// DecodedTooLarge is a stage that would produce more than the bound, or a
	// stream whose header declares a window larger than the bound allows. Its
	// exclusion reason is ReasonDecodedTooLarge.
	DecodedTooLarge
	// Refused is a reservation the Reserver refused. Every charge the decode
	// held was released before it returned. It is not an exclusion reason.
	Refused
	// DecodingTooCostly is a brotli stage whose next operation would take its
	// work past the budget (BrotliWorkBase), so it was not done, or a zstd
	// stage whose next frame would make the decoder's history a fourth time,
	// so that frame was not decoded. Nothing is returned and every charge was
	// released. Its exclusion reason is ReasonDecodingTooCostly.
	DecodingTooCostly
)

// Reason is the exclusion reason the outcome carries: ReasonDecodingFailed,
// ReasonDecodedTooLarge and ReasonDecodingTooCostly for those three outcomes,
// and "" for the others.
func (o Outcome) Reason() string {
	switch o {
	case DecodingFailed:
		return ReasonDecodingFailed
	case DecodedTooLarge:
		return ReasonDecodedTooLarge
	case DecodingTooCostly:
		return ReasonDecodingTooCostly
	}
	return ""
}

// ChargeKind is what a charge is for.
type ChargeKind uint8

const (
	// WorkspaceCharge is a stage's decoder: Workspace(coding, input, bound),
	// planned from the stage's input and reserved whole before the decoder is
	// created, and released after it is closed.
	WorkspaceCharge ChargeKind = iota + 1
	// OutputCharge is one of a stage's output buffers, its whole capacity. A
	// growth reserves the new buffer while the old one is still held, then
	// allocates it, copies into it and releases the old one.
	OutputCharge
)

// Charge is one reservation or release.
type Charge struct {
	Kind ChargeKind
	// Stage is the stage the charge belongs to: 1, the message's one coding.
	Stage int
	// Bytes is how many bytes are reserved or released. It is never negative,
	// and a charge of zero bytes is never asked for.
	Bytes int64
}

// Reserver accounts for what a decode holds, and is supplied by its caller.
// Every charge is reserved before the memory it stands for is allocated.
type Reserver interface {
	// Reserve asks for a charge. False refuses it: nothing of it is held, and
	// the decode returns Refused after releasing everything it held.
	Reserve(Charge) bool
	// Release returns a charge reserved earlier, each exactly once: a
	// workspace whole, and an output buffer for its whole capacity, the one a
	// growth replaced as soon as it is replaced.
	Release(Charge)
}

// StageIO is what one stage read and returned, counted at the stage's input
// and at the coding's output, around the decoder rather than inside it, and
// what its workspace plan read and reserved.
type StageIO struct {
	Stage  int
	Coding Coding
	// Input is the length of the stage's input.
	Input int64
	// Read is how many of those bytes the decoder read.
	Read int64
	// Returned is how many bytes the decoder returned.
	Returned int64
	// Planned is how many bytes of the input the workspace plan read before
	// the decoder existed, apart from Read: a brotli stream's first byte, and
	// the frame and block headers of a zstd stream. Zero for gzip and deflate,
	// whose workspace is fixed.
	Planned int64
	// Workspace is what was reserved for the stage's decoder.
	Workspace int64
	// Work is the work a brotli stage counted against its budget, in the
	// budget's units; zero for the other codings, which have none.
	Work int64
}

// Options are what one Decode works within.
type Options struct {
	// Bound is the most bytes a stage may produce: the per-message body
	// bound, MaxBodyBytes. A negative bound is read as zero, and one above
	// 1 TiB as 1 TiB.
	Bound int
	// Reserver holds every charge. Nil grants everything.
	Reserver Reserver
	// Observe, when set, is called once if the stage's decoder was created,
	// after the decoder is closed.
	Observe func(StageIO)
}

// Result is what Decode returns.
type Result struct {
	Outcome Outcome
	// Body is the decoded content when the outcome is Decoded, and nil
	// otherwise.
	Body []byte
	// Charge is what the Reserver still holds for Body: the stage's last
	// output buffer, cap(Body) bytes of kind OutputCharge. It passes to the
	// caller, who releases it when it lets Body go. Zero unless the outcome is
	// Decoded.
	Charge int64
	// Stage is 1 when the stage decided an outcome other than Decoded and
	// Identity, and 0 otherwise.
	Stage int
	// Fault reports a decoder fault: the decoder library panicked while the
	// stage made, read or closed its decoder, and the panic was contained. The
	// outcome is then DecodingFailed. Nothing of the panic's value is kept.
	Fault bool
}

// Decode undoes the coding in list from encoded, as one stage, and returns the
// first decisive outcome in validation order.
//
// The list is validated whole before Decode is called (ParseList); a list of
// no coding returns Identity at once. Otherwise the result is decided by the
// first of these to happen:
//
//  1. The stage's header check, for brotli only: a declared window,
//     (1 << WBITS) - 16 bytes, larger than max(bound, 1008) is
//     DecodedTooLarge; the large-window extension, which RFC 7932 does not
//     define, is DecodingFailed; an empty input is DecodingFailed.
//  2. The workspace reservation, Workspace(coding, input, bound), planned
//     from the stream's headers and made before the stage's decoder exists.
//     Refused if refused. The plan decides nothing: what it cannot read is
//     decided by the decoder when, and if, it gets there.
//  3. The stage's output, read into a buffer of at most bound + 1 bytes. Each
//     growth reserves the whole new buffer while the old one is held, and
//     releases the old one after copying; a refusal is Refused, with nothing
//     new allocated. As soon as bound + 1 bytes have arrived the stage stops:
//     DecodedTooLarge, whatever the rest of its input holds. So an output of
//     exactly bound bytes passes, and one byte more does not.
//  4. For br, the work budget (BrotliWorkBase): an operation that would take
//     the stage's work past it is DecodingTooCostly, where that operation
//     would have run. For zstd, the history: the decoder makes it at most
//     three times, so a frame that would make it a fourth is never read, the
//     decoder is given only the complete frames before it, and once it has
//     decoded them the stage is DecodingTooCostly. What the stage decided
//     before either stays decided.
//  5. The decoder's own failures in input order, each DecodingFailed: a
//     corrupt or truncated stream, a failed checksum or length, a window the
//     decoder refuses, a preset dictionary. A zstd frame whose window is
//     larger than max(bound, 1024), or whose declared content size is larger
//     than that, is DecodedTooLarge at its frame header.
//  6. The end checks, each DecodingFailed: any byte after the last gzip
//     member, deflate stream, brotli stream or zstd frame, and an empty input.
//
// Then the stage's decoder is closed and its workspace released, and the
// outcome is Decoded.
//
// A panic inside the decoder library, while the stage makes its decoder, reads
// from it or closes it, ends the stage where it happens: DecodingFailed, with
// Fault set. The decoder and its partial output are discarded and every charge
// is released once. The panic's value is not kept, formatted or passed to
// anything. A panic in the Reserver or the Observe callback is not contained.
//
// gzip accepts concatenated members, each with its own header, CRC-32 and
// length checked; reserved header flag bits, and a header CRC that does not
// match, are DecodingFailed. deflate is zlib when the first two bytes satisfy
// CM 8, CINFO at most 7 and (CMF*256 + FLG) divisible by 31, with no retry
// as raw deflate when the zlib stream then fails; a zlib header asking for a
// preset dictionary is DecodingFailed; the zlib stream's Adler-32 is checked.
// Otherwise, including a body shorter than two bytes, the body is raw deflate.
// zstd accepts concatenated and skippable frames, and checks each frame's
// content checksum where it has one; a frame naming a dictionary is
// DecodingFailed.
//
// Nothing partial is returned: a decode that ends other than Decoded returns
// no body, and has released every charge it held, each exactly once: the
// workspace and the output buffer. Decode never retains encoded and never
// writes to it. It runs on the calling goroutine and starts no other. No
// decoder outlives its stage; the zstd decoder takes its entropy tables from a
// pool its library keeps for the process.
func Decode(list List, encoded []byte, options Options) Result {
	return decodeWithin(list, encoded, options, within{budget: workBudget{BrotliWorkBase, BrotliWorkPerByte, brotliWorkCeiling}})
}

// within is what Decode holds fixed: a brotli stage's work budget, and what
// the decoder library reads a stage's input through.
type within struct {
	budget workBudget
	// feed, when set, is what the library reads the input through; nil reads
	// it directly.
	feed func(io.Reader) io.Reader
	// inject, when set, runs at the start of each of the library's guarded
	// operations, inside its guard.
	inject func(Coding, operation)
}

// decodeWithin is Decode within w.
func decodeWithin(list List, encoded []byte, options Options, w within) Result {
	if list.n == 0 {
		return Result{Outcome: Identity}
	}
	d := decode{bound: clampBound(options.Bound), reserver: options.Reserver, observe: options.Observe, within: w}
	if d.reserver == nil {
		d.reserver = granted{}
	}

	out, outcome, fault := d.stage(1, list.codings[0], encoded)
	if outcome != Decoded {
		if out != nil {
			d.release(OutputCharge, 1, out.charge)
		}
		return Result{Outcome: outcome, Stage: 1, Fault: fault}
	}
	return Result{Outcome: Decoded, Body: out.buf, Charge: out.charge}
}

// decode is one Decode's settings.
type decode struct {
	bound    int
	reserver Reserver
	observe  func(StageIO)
	within
}

func (d *decode) release(kind ChargeKind, stage int, n int64) {
	if n > 0 {
		d.reserver.Release(Charge{Kind: kind, Stage: stage, Bytes: n})
	}
}

// stage runs one coding over in, and reports whether its decoder library
// faulted. It allocates nothing before the workspace is reserved. The output's
// charge is in the returned output whatever the outcome, and the workspace is
// released before it returns.
func (d *decode) stage(stage int, coding Coding, in []byte) (*output, Outcome, bool) {
	if coding == Brotli {
		if outcome := brotliHeader(in, d.bound); outcome != 0 {
			return nil, outcome, false
		}
	}
	workspace, planned := plan(coding, in, d.bound)
	if !d.reserver.Reserve(Charge{Kind: WorkspaceCharge, Stage: stage, Bytes: workspace}) {
		return nil, Refused, false
	}
	src := &input{b: in}
	var feed io.Reader = src
	if d.feed != nil {
		feed = d.feed(src)
	}
	out := &output{limit: int64(d.bound) + 1, stage: stage, reserver: d.reserver}
	lib := &library{coding: coding, inject: d.inject}
	var outcome Outcome
	var work int64
	switch coding {
	case Gzip:
		outcome = gzipStage(src, feed, out, lib)
	case Deflate:
		outcome = deflateStage(src, feed, out, lib)
	case Brotli:
		outcome, work = brotliStage(src, feed, out, d.budget, lib)
	case Zstd:
		outcome = zstdStage(src, feed, out, d.bound, lib)
	default:
		outcome = DecodingFailed
	}
	if lib.faulted {
		outcome = DecodingFailed
	}
	d.release(WorkspaceCharge, stage, workspace)
	if d.observe != nil {
		d.observe(StageIO{
			Stage: stage, Coding: coding,
			Input: int64(len(in)), Read: int64(src.pos), Returned: out.returned,
			Planned: int64(planned), Workspace: workspace, Work: work,
		})
	}
	return out, outcome, lib.faulted
}

// granted is the Reserver a nil one stands for.
type granted struct{}

func (granted) Reserve(Charge) bool { return true }
func (granted) Release(Charge)      {}

// input is a stage's input, read forward once and never past its end. It is
// an io.ByteReader so that a deflate decoder reads no byte past its stream.
type input struct {
	b   []byte
	pos int
}

func (in *input) Read(p []byte) (int, error) {
	if in.pos >= len(in.b) {
		return 0, io.EOF
	}
	n := copy(p, in.b[in.pos:])
	in.pos += n
	return n, nil
}

func (in *input) ReadByte() (byte, error) {
	if in.pos >= len(in.b) {
		return 0, io.EOF
	}
	c := in.b[in.pos]
	in.pos++
	return c, nil
}

// next takes the next n bytes, or reports that fewer remain.
func (in *input) next(n int) ([]byte, bool) {
	if n < 0 || len(in.b)-in.pos < n {
		return nil, false
	}
	b := in.b[in.pos : in.pos+n]
	in.pos += n
	return b, true
}

func (in *input) remaining() int { return len(in.b) - in.pos }

// output is a stage's output buffer. Its capacity never exceeds limit, the
// bound plus the one byte that tells an output at the bound from one over it,
// and every buffer is reserved whole before it is allocated. charge is what
// the current buffer holds reserved.
type output struct {
	buf      []byte
	limit    int64
	charge   int64
	returned int64
	stage    int
	reserver Reserver
}

// firstCapacity is the capacity an output starts from, or limit when that is
// smaller.
const firstCapacity = 4096

// grow raises the capacity to the next of limit, limit/2, limit/4 ... rounded
// up, from firstCapacity. Each is at most twice the one before, so the buffer
// it replaces is at most ceil(limit/2) bytes. The new buffer is reserved
// while the old one is still held, and the old one released once copied; a
// refusal allocates nothing and leaves the old one held.
func (o *output) grow() bool {
	current := int64(cap(o.buf))
	next := o.limit
	for shift := 1; shift < 63; shift++ {
		smaller := ceilShift(o.limit, shift)
		if smaller <= current || smaller < firstCapacity {
			break
		}
		next = smaller
	}
	if !o.reserver.Reserve(Charge{Kind: OutputCharge, Stage: o.stage, Bytes: next}) {
		return false
	}
	grown := make([]byte, len(o.buf), next)
	copy(grown, o.buf)
	o.buf = grown
	if o.charge > 0 {
		o.reserver.Release(Charge{Kind: OutputCharge, Stage: o.stage, Bytes: o.charge})
	}
	o.charge = next
	return true
}

// fill reads r into the buffer until r ends. It returns Decoded when r
// returned io.EOF, DecodedTooLarge as soon as limit bytes are held, Refused
// when growth was refused, and DecodingFailed for any error from r, which it
// returns beside it.
func (o *output) fill(r io.Reader) (Outcome, error) {
	idle := 0
	for {
		if len(o.buf) == cap(o.buf) {
			if int64(cap(o.buf)) >= o.limit {
				return DecodedTooLarge, nil
			}
			if !o.grow() {
				return Refused, nil
			}
		}
		space := o.buf[len(o.buf):cap(o.buf)]
		n, err := r.Read(space)
		if n < 0 || n > len(space) {
			return DecodingFailed, io.ErrShortBuffer
		}
		o.buf = o.buf[:len(o.buf)+n]
		o.returned += int64(n)
		if int64(len(o.buf)) >= o.limit {
			return DecodedTooLarge, nil
		}
		switch {
		case err == io.EOF:
			return Decoded, nil
		case err != nil:
			return DecodingFailed, err
		case n == 0:
			// A reader that returns nothing and no error makes no progress.
			idle++
			if idle == 100 {
				return DecodingFailed, io.ErrNoProgress
			}
		default:
			idle = 0
		}
	}
}
