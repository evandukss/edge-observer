package http1

import (
	"errors"
	"fmt"
	"strings"

	"github.com/evandukss/edge-observer/stream"
)

// Result is why a Parser, or a pairing of a request parser and a response
// parser, returned.
type Result uint8

const (
	// NeedInput is input used up with the direction still open: every offset of
	// the part was consumed, and the next part continues the message in progress
	// or begins the next one. It is never a verdict on a message.
	NeedInput Result = iota
	// Head is a message whose field section has been read and which goes on past
	// it: its start line and fields are final, and its body follows. A request's
	// method is then known, which is what the response answering it needs. A
	// request that ends with its field section returns Framed, or its stop, at
	// once instead; a response always returns Head, because it cannot be framed
	// before Parser.Answer. The rest of the part is fed next.
	Head
	// NeedRequest is a response whose field section has been read and whose body
	// cannot be framed until the request it answers is known (Parser.Answer): a
	// response to HEAD carries none, whatever it declares. Nothing after the field
	// section was consumed.
	NeedRequest
	// Framed is a message whose end is known, so what follows begins the next
	// one. A hole may still have taken bytes of its body (Message.Complete). The
	// rest of the part is fed next.
	Framed
	// Malformed is a message no strict endpoint would accept, including one
	// declaring two framings at once. The direction stops.
	Malformed
	// Limit is a message that reached one of the caller's bounds. The direction
	// stops.
	Limit
	// Unsupported is where this observer stops reading a direction it can frame
	// no further: a response whose body only the connection closing would end.
	// A pairing also stops at an informational response, a CONNECT request, a
	// message carrying Upgrade, and a connection neither direction of which
	// begins as HTTP/1. The direction stops.
	Unsupported
	// Cut is a hole where the parser needed structure - a start line, a field
	// line, a chunk size, the end of a chunk or a trailer - rather than inside a
	// body whose length is known. The direction stops, and nothing after the hole
	// is read as the start of a message.
	Cut
	// End is input declared finished: a message in progress is handed over
	// incomplete.
	End
	// Refused is growth the Reserver refused. Nothing of it was retained and the
	// offsets that needed it were not consumed: the state is what it was when the
	// growth was asked for, and the rest of the part can be fed again.
	Refused
)

func (r Result) String() string {
	switch r {
	case NeedInput:
		return "need-input"
	case Head:
		return "head"
	case NeedRequest:
		return "need-request"
	case Framed:
		return "framed"
	case Malformed:
		return "malformed"
	case Limit:
		return "limit"
	case Unsupported:
		return "unsupported"
	case Cut:
		return "cut"
	case End:
		return "end"
	case Refused:
		return "refused"
	default:
		return fmt.Sprintf("result(%d)", uint8(r))
	}
}

// Stopped reports whether a direction that returned r reads no further:
// Malformed, Limit, Unsupported and Cut.
func (r Result) Stopped() bool {
	return r == Malformed || r == Limit || r == Unsupported || r == Cut
}

// Charge is state a Parser or a pairing retains: the captured bytes it has
// copied and keeps, and the messages it has begun and not handed over.
type Charge struct {
	// Bytes counts captured bytes copied into a retained representation: a line
	// not yet ended, a start line and its field lines, the body bytes kept,
	// trailer lines, and input held until it can be read.
	Bytes int64
	// Messages counts messages begun and not yet handed over: the pending
	// message descriptors a per-connection ceiling counts. A message counts from
	// its first byte.
	Messages int64
}

// Add is the sum of two charges.
func (c Charge) Add(o Charge) Charge {
	return Charge{Bytes: c.Bytes + o.Bytes, Messages: c.Messages + o.Messages}
}

// IsZero reports whether the charge holds nothing.
func (c Charge) IsZero() bool { return c == Charge{} }

// Reserver accounts for what a Parser or a pairing retains, and is supplied by
// its caller. Every charge is reserved before it is retained, and leaves the
// asker exactly once: handed over with what it was retained for, or released.
// So what a reserver has granted, less what it was given back, is what the
// asker retains (Retained) plus every charge it has handed over.
type Reserver interface {
	// Reserve asks for growth before it is retained. False refuses it: the asker
	// retains none of it and returns Refused.
	Reserve(Charge) bool
	// Release returns a charge the asker no longer retains and is not handing
	// over.
	Release(Charge)
}

// Progress is what one call to a Parser did.
type Progress struct {
	// Consumed is how many of the part's offsets the call accounted for, from
	// its first: read, or counted as unplaced after the direction stopped. It is
	// less than the part's Length only at Head, NeedRequest, Framed and Refused;
	// the rest is fed next, from Next. Answer and End consume nothing.
	Consumed uint64
	Result   Result
	// Message is the message the call concerns: the one whose field section was
	// read (Head), that ended (Framed), that stopped the direction (Malformed,
	// Limit, Unsupported, Cut), or that End found in progress. Nil otherwise. At
	// Head it is a copy of the head and the parser keeps reading the message;
	// otherwise it is handed over and the parser never touches it again.
	Message *Message
	// Charge is what the parser retained for Message and hands over with it. It
	// is zero unless Message is handed over.
	Charge Charge
}

var (
	// ErrKind is a parser asked for a kind of message other than Request or
	// Response.
	ErrKind = errors.New("a parser reads requests or responses")
	// ErrReserver is a parser or a pairing given no Reserver.
	ErrReserver = errors.New("a parser needs a reserver")
	// ErrOffset is a part that does not begin where the direction stands.
	ErrOffset = errors.New("the part does not begin where the direction stands")
	// ErrEnded is input after End.
	ErrEnded = errors.New("the input was declared finished")
	// ErrAnswer is an Answer no response head is waiting for.
	ErrAnswer = errors.New("no response is waiting on the request it answers")
)

// Parser reads one direction of one connection as it arrives, one part at a
// time, resuming where the previous part left off. It applies Parse's framing
// rules, strict validation and per-message bounds, and examines each byte
// once: new input costs work in proportion to itself, never a rescan of what
// came before. Before it retains anything it asks its Reserver.
//
// Its input rules, each refused with an error and no change to the parser:
//
//   - a part passes stream.Part.Validate (stream.ErrInvalidPart);
//   - the first part may begin at any offset, as capture may attach part way
//     through a connection, and every later part begins where the parser stands
//     (Next), so parts arrive in order with holes given as parts of their own
//     (ErrOffset);
//   - nothing is fed after End (ErrEnded);
//   - Answer is called only on a response parser, after Feed returned Head for
//     a response and before that response is framed (ErrAnswer).
//
// A Parser is not safe for concurrent use.
type Parser struct {
	kind     Kind
	limits   Limits
	reserver Reserver

	// started is whether a part has been fed, next where the next one begins.
	started bool
	next    uint64
	ended   bool
	// stop is what stopped the direction, NeedInput while it is open. settled is
	// where the last message handed over ends: what lies between it and next is
	// unplaced once the direction has stopped or ended.
	stop    Result
	settled uint64

	phase phase
	// message is the message in progress and charge what is retained for it, the
	// line in progress included.
	message *Message
	charge  Charge

	// line is a line not yet ended, and sawCR a carriage return at its end that
	// waits on the byte after it, as stream.Cursor.ReadLine reads a line.
	line  []byte
	sawCR bool

	headerBytes int
	// remaining is what is left of a declared body, or of the chunk in progress.
	remaining uint64
	chunks    int
	// The chunk in progress counts into the message only once its data has all
	// arrived: Parse takes no chunk the stream ends inside, so End undoes it.
	chunkStart, chunkSize              uint64
	chunkKept, chunkHoled, chunkElided uint64
	// endSeen is how many bytes after a chunk's data have been read, endFirst the
	// first: the pair is judged only when both are in.
	endSeen  int
	endFirst byte

	// examined counts the bytes looked at, each time one is.
	examined uint64
}

// phase is where in a message the parser stands.
type phase uint8

const (
	betweenMessages phase = iota
	inStartLine
	inFields
	awaitingAnswer
	inDeclaredBody
	inChunkSize
	inChunkData
	inChunkEnd
	inTrailers
)

// NewParser returns a parser for one direction of one connection, reading
// messages of this kind within these limits (a zero field takes its default),
// and asking reserver before it retains anything.
func NewParser(kind Kind, limits Limits, reserver Reserver) (*Parser, error) {
	if kind != Request && kind != Response {
		return nil, fmt.Errorf("%w: %s", ErrKind, kind)
	}
	if reserver == nil {
		return nil, ErrReserver
	}
	return newParser(kind, limits, reserver), nil
}

// newParser takes any kind: Parse refuses a message of no kind after its start
// line, as it always has.
func newParser(kind Kind, limits Limits, reserver Reserver) *Parser {
	return &Parser{kind: kind, limits: limits.orDefaults(), reserver: reserver}
}

// Feed reads part from where the parser stands. It returns at the first of: the
// part used up (NeedInput), a message's field section read (Head), a response
// waiting on its answer (NeedRequest), a message ended (Framed), the direction
// stopped (Malformed, Limit, Unsupported, Cut), and growth refused (Refused).
// After the direction stops it consumes every part as unplaced and returns the
// same result, with no message.
func (p *Parser) Feed(part stream.Part) (Progress, error) {
	if err := p.admit(part); err != nil {
		return Progress{}, err
	}
	if !p.started {
		p.started, p.next, p.settled = true, part.Offset, part.Offset
	}
	if p.stop != NeedInput {
		p.next += part.Length
		return Progress{Consumed: part.Length, Result: p.stop}, nil
	}
	if p.phase == awaitingAnswer {
		return Progress{Result: NeedRequest}, nil
	}

	for p.next < part.Offset+part.Length {
		var progress Progress
		var event bool
		if part.Gap != stream.GapNone {
			progress, event = p.hole(part.Gap, part.Offset+part.Length-p.next)
		} else {
			progress, event = p.bytes(part.Bytes[p.next-part.Offset:])
		}
		if !event {
			continue
		}
		if progress.Result.Stopped() {
			// What follows the stop in this part is unplaced.
			p.next = part.Offset + part.Length
		}
		progress.Consumed = p.next - part.Offset
		return progress, nil
	}
	return Progress{Consumed: part.Length, Result: NeedInput}, nil
}

// admit checks part against the input rules, changing nothing.
func (p *Parser) admit(part stream.Part) error {
	if p.ended {
		return ErrEnded
	}
	if err := part.Validate(); err != nil {
		return err
	}
	if p.started && part.Offset != p.next {
		return fmt.Errorf("%w: it begins at %d and the direction stands at %d", ErrOffset, part.Offset, p.next)
	}
	return nil
}

// bytes reads from in, which begins where the parser stands, until it has an
// event to return or has used in up. Each step consumes by advancing next.
func (p *Parser) bytes(in []byte) (Progress, bool) {
	switch p.phase {
	case betweenMessages:
		return p.begin()

	case inStartLine:
		done, progress, event := p.readLine(in, p.limits.MaxStartLine, "reading the start line")
		if event || !done {
			return progress, event
		}
		return p.startLine()

	case inFields:
		done, progress, event := p.readLine(in, p.limits.MaxHeaderLine, "reading a field line")
		if event || !done {
			return progress, event
		}
		return p.fieldLine()

	case inDeclaredBody, inChunkData:
		return p.body(in)

	case inChunkSize:
		done, progress, event := p.readLine(in, p.limits.MaxHeaderLine, "reading a chunk size")
		if event || !done {
			return progress, event
		}
		size, ok := chunkSize(string(p.line))
		p.dropLine()
		if !ok {
			return p.refuse(DefectMalformed, "a chunk size no decoder would accept")
		}
		if size == 0 {
			p.phase = inTrailers
			return Progress{}, false
		}
		p.phase, p.remaining = inChunkData, size
		p.chunkStart, p.chunkSize = p.next, size
		p.chunkKept, p.chunkHoled, p.chunkElided = 0, 0, 0
		return Progress{}, false

	case inChunkEnd:
		b := in[0]
		p.examined++
		p.next++
		if p.endSeen == 0 {
			p.endSeen, p.endFirst = 1, b
			return Progress{}, false
		}
		p.endSeen = 0
		if p.endFirst != '\r' || b != '\n' {
			return p.refuse(DefectMalformed, "a chunk not followed by CRLF")
		}
		p.chunks++
		return p.chunkSizeNext()

	case inTrailers:
		done, progress, event := p.readLine(in, p.limits.MaxHeaderLine, "reading a trailer field")
		if event || !done {
			return progress, event
		}
		return p.trailerLine()
	}
	// awaitingAnswer never reaches here: Feed returns NeedRequest first.
	return Progress{Result: NeedRequest}, true
}

// hole reads a hole of n offsets from where the parser stands. Inside a body
// whose length is known it is counted and the message stays framed; anywhere
// else it is a cut.
func (p *Parser) hole(gap stream.GapReason, n uint64) (Progress, bool) {
	context := ""
	switch p.phase {
	case betweenMessages:
		return p.begin()
	case inDeclaredBody, inChunkData:
		take := min(n, p.remaining)
		p.next += take
		p.remaining -= take
		if p.phase == inDeclaredBody {
			p.message.BodyHoled += take
		} else {
			p.chunkHoled += take
		}
		return p.bodyStep()
	case inStartLine:
		context = "reading the start line"
	case inFields:
		context = "reading a field line"
	case inChunkSize:
		context = "reading a chunk size"
	case inChunkEnd:
		context = "reading the end of a chunk"
	case inTrailers:
		context = "reading a trailer field"
	}
	p.dropLine()
	err := fmt.Errorf("%w: %s at offset %d", stream.ErrGap, gap, p.next)
	return p.refuse(DefectHole, context+": "+err.Error())
}

// begin starts a message where the parser stands, its first byte or hole
// still to read.
func (p *Parser) begin() (Progress, bool) {
	if !p.reserver.Reserve(Charge{Messages: 1}) {
		return Progress{Result: Refused}, true
	}
	p.message = &Message{Kind: p.kind, Offset: p.next}
	p.charge = Charge{Messages: 1}
	p.phase, p.headerBytes, p.chunks = inStartLine, 0, 0
	return Progress{}, false
}

// readLine reads the line in progress from in, as stream.Cursor.ReadLine reads
// a line: only CRLF ends it, a carriage return before anything else stays in
// it, and it is refused the moment it is longer than max. It reports whether
// the line ended; event is set where growth was refused or the bound reached.
func (p *Parser) readLine(in []byte, max int, context string) (bool, Progress, bool) {
	s := scanLine(in, len(p.line), p.sawCR, max)
	p.examined += uint64(s.consumed)
	if s.tooLong {
		p.next += uint64(s.consumed)
		p.dropLine()
		progress, event := p.refuse(DefectLimit, context+": "+stream.ErrTooLong.Error())
		return false, progress, event
	}
	grow := int64(s.to)
	if s.prependCR {
		grow++
	}
	if grow > 0 && !p.reserver.Reserve(Charge{Bytes: grow}) {
		return false, Progress{Result: Refused}, true
	}
	if s.prependCR {
		p.line = append(p.line, '\r')
	}
	p.line = append(p.line, in[:s.to]...)
	p.charge.Bytes += grow
	p.sawCR = s.sawCR
	p.next += uint64(s.consumed)
	return s.done, Progress{}, false
}

// scanned is what scanLine found.
type scanned struct {
	// consumed is how many bytes of the input the line took.
	consumed int
	done     bool
	tooLong  bool
	// prependCR is a carriage return held from before that turned out to be part
	// of the line; in[:to] is the rest of what the line gains.
	prependCR bool
	to        int
	sawCR     bool
}

// scanLine follows stream.Cursor.ReadLine byte by byte over in, from a line of
// length bytes and a held carriage return, without changing anything.
func scanLine(in []byte, length int, sawCR bool, max int) scanned {
	var s scanned
	for i, b := range in {
		s.consumed = i + 1
		if sawCR {
			if b == '\n' {
				s.done = true
				if i > 0 {
					s.to = i - 1
				}
				return s
			}
			sawCR = false
			length++
			s.prependCR = s.prependCR || i == 0
			if length > max {
				s.tooLong = true
				return s
			}
		}
		if b == '\r' {
			sawCR = true
			continue
		}
		length++
		if length > max {
			s.tooLong = true
			return s
		}
	}
	s.sawCR, s.to = sawCR, len(in)
	if sawCR {
		s.to--
	}
	return s
}

// takeLine is the line that has just ended, now retained as text, and the
// buffer cleared for the next. Its charge stays with the message.
func (p *Parser) takeLine() string {
	line := string(p.line)
	p.line, p.sawCR = p.line[:0], false
	return line
}

// dropLine discards the line in progress and releases its charge.
func (p *Parser) dropLine() {
	p.release(int64(len(p.line)))
	p.line, p.sawCR = p.line[:0], false
}

func (p *Parser) release(n int64) {
	if n > 0 {
		p.reserver.Release(Charge{Bytes: n})
		p.charge.Bytes -= n
	}
}

func (p *Parser) startLine() (Progress, bool) {
	line := p.takeLine()
	ok := false
	switch p.kind {
	case Request:
		ok = p.message.readRequestLine(line)
	case Response:
		ok = p.message.readStatusLine(line)
	default:
		p.release(int64(len(line)))
		return p.refuse(DefectMalformed, "no kind of message was asked for")
	}
	if !ok {
		p.release(int64(len(line)))
		if p.kind == Request {
			return p.refuse(DefectMalformed, "the first line is not a request line")
		}
		return p.refuse(DefectMalformed, "the first line is not a status line")
	}
	p.phase = inFields
	return Progress{}, false
}

func (p *Parser) fieldLine() (Progress, bool) {
	line := p.takeLine()
	if line == "" {
		return p.fieldsEnded()
	}
	refuse := func(defect Defect, detail string) (Progress, bool) {
		p.release(int64(len(line)))
		return p.refuse(defect, detail)
	}
	if len(p.message.Headers) >= p.limits.MaxHeaders {
		return refuse(DefectLimit, fmt.Sprintf("more than %d field lines", p.limits.MaxHeaders))
	}
	p.headerBytes += len(line)
	if p.headerBytes > p.limits.MaxHeaderBytes {
		return refuse(DefectLimit, fmt.Sprintf("more than %d bytes of field lines", p.limits.MaxHeaderBytes))
	}
	header, ok := readHeader(line)
	if !ok {
		return refuse(DefectMalformed, "a field line no strict endpoint would accept")
	}
	p.message.Headers = append(p.message.Headers, header)
	return Progress{}, false
}

// fieldsEnded frames a request by its fields. A response waits on Answer,
// because what it answers decides whether it has a body.
func (p *Parser) fieldsEnded() (Progress, bool) {
	if p.kind == Response {
		p.phase = awaitingAnswer
		return p.head(), true
	}
	return p.frame(false)
}

// head is a copy of the message in progress as far as its field section.
func (p *Parser) head() Progress {
	m := *p.message
	return Progress{Result: Head, Message: &m}
}

// frame decides how the message's body ends, and returns Framed or a stop
// where that ends the message, Head for a request whose body follows, and
// NeedInput for a response whose body follows.
func (p *Parser) frame(noBody bool) (Progress, bool) {
	m := p.message
	framing, length, detail := m.frame(p.kind, noBody)
	m.Framing = framing

	switch framing {
	case FramingAmbiguous:
		// Two disagreeing framings put the next boundary in two places.
		return p.refuse(DefectAmbiguousFraming, detail)
	case FramingNone:
		if detail != "" {
			return p.refuse(DefectMalformed, detail)
		}
		m.Framed, m.Complete = true, true
		return p.handOver(Framed), true
	case FramingContentLength:
		m.BodyLength, p.remaining, p.phase = length, length, inDeclaredBody
		if length == 0 {
			return p.bodyStep()
		}
	case FramingChunked:
		if progress, event := p.chunkSizeNext(); event {
			return progress, event
		}
	case FramingUntilClose:
		// A reader of an open connection never sees that body end.
		m.Defect, m.Detail = DefectStreamEnded, "the body ends with the connection, and a fragment carries no close"
		p.stop = Unsupported
		return p.handOver(Unsupported), true
	}
	if p.kind == Response {
		return Progress{Result: NeedInput}, true
	}
	return p.head(), true
}

// chunkSizeNext moves to the next chunk size, refusing one past the bound
// before reading any of it, as Parse does.
func (p *Parser) chunkSizeNext() (Progress, bool) {
	if p.chunks >= p.limits.MaxChunks {
		return p.refuse(DefectLimit, fmt.Sprintf("more than %d chunks", p.limits.MaxChunks))
	}
	p.phase = inChunkSize
	return Progress{}, false
}

// body reads body bytes from in: a declared body, or the data of the chunk in
// progress. What fits under the bound is kept, the rest counted as elided.
func (p *Parser) body(in []byte) (Progress, bool) {
	m := p.message
	take := min(uint64(len(in)), p.remaining)
	keep := uint64(0)
	if room := p.limits.MaxBodyBytes - len(m.Body); room > 0 {
		keep = min(take, uint64(room))
	}
	if keep > 0 && !p.reserver.Reserve(Charge{Bytes: int64(keep)}) {
		return Progress{Result: Refused}, true
	}
	m.Body = append(m.Body, in[:keep]...)
	p.charge.Bytes += int64(keep)
	p.examined += take
	p.next += take
	p.remaining -= take
	if p.phase == inDeclaredBody {
		m.BodyElided += take - keep
	} else {
		p.chunkKept += keep
		p.chunkElided += take - keep
	}
	return p.bodyStep()
}

// bodyStep finishes a declared body or a chunk's data once nothing remains.
func (p *Parser) bodyStep() (Progress, bool) {
	if p.remaining != 0 {
		return Progress{}, false
	}
	m := p.message
	if p.phase == inChunkData {
		m.BodyLength += p.chunkSize
		m.BodyHoled += p.chunkHoled
		m.BodyElided += p.chunkElided
		p.phase, p.endSeen = inChunkEnd, 0
		return Progress{}, false
	}
	m.Framed = true
	if m.BodyHoled > 0 {
		// The declared length still says where this message ends: the body is lost,
		// not the structure.
		m.Defect, m.Detail = DefectHole, fmt.Sprintf("%d of the body's %d bytes were never captured", m.BodyHoled, m.BodyLength)
	} else {
		m.Complete = true
	}
	return p.handOver(Framed), true
}

func (p *Parser) trailerLine() (Progress, bool) {
	line := p.takeLine()
	m := p.message
	if line == "" {
		m.Framed = true
		if m.BodyHoled > 0 {
			m.Defect, m.Detail = DefectHole, fmt.Sprintf("%d of the body's %d bytes were never captured", m.BodyHoled, m.BodyLength)
		} else {
			m.Complete = true
		}
		return p.handOver(Framed), true
	}
	if len(m.Trailers) >= p.limits.MaxTrailers {
		p.release(int64(len(line)))
		return p.refuse(DefectLimit, fmt.Sprintf("more than %d trailer fields", p.limits.MaxTrailers))
	}
	trailer, ok := readHeader(line)
	if !ok {
		p.release(int64(len(line)))
		return p.refuse(DefectMalformed, "a trailer field no strict endpoint would accept")
	}
	m.Trailers = append(m.Trailers, trailer)
	return Progress{}, false
}

// refuse stops the direction at the message in progress, which ends where the
// parser stands, and hands it over.
func (p *Parser) refuse(defect Defect, detail string) (Progress, bool) {
	p.message.Defect, p.message.Detail = defect, detail
	p.stop = stopFor(defect)
	return p.handOver(p.stop), true
}

func stopFor(defect Defect) Result {
	switch defect {
	case DefectHole:
		return Cut
	case DefectLimit:
		return Limit
	default:
		return Malformed
	}
}

// handOver gives the message in progress, which ends where the parser stands,
// and its charge, to the caller.
func (p *Parser) handOver(result Result) Progress {
	m := p.message
	m.End = p.next
	progress := Progress{Result: result, Message: m, Charge: p.charge}
	p.message, p.charge, p.phase = nil, Charge{}, betweenMessages
	p.line, p.sawCR = p.line[:0], false
	p.settled = m.End
	return progress
}

// Answer gives a response parser the method of the request the response it is
// reading answers, once Feed has returned Head for that response. The body is
// then framed: none for HEAD (RFC 9112 section 6.3), otherwise by the
// response's own fields. An empty method frames it by its fields, as for a
// response no request is known for.
//
// It consumes nothing. Where the answer alone ends the message - no body, an
// empty one, framing no strict endpoint accepts, or a body only a close would
// end - it returns Framed or the stop, with the message handed over, so a
// response is never left waiting for input it does not need. Otherwise it
// returns NeedInput, and the body is fed next.
func (p *Parser) Answer(method string) (Progress, error) {
	if p.phase != awaitingAnswer || p.ended {
		return Progress{}, ErrAnswer
	}
	progress, _ := p.frame(strings.EqualFold(method, "HEAD"))
	return progress, nil
}

// End declares the input finished. A message in progress is handed over
// incomplete (DefectStreamEnded); a response still waiting on its answer is
// first framed as Answer with an empty method would frame it. A later End
// hands over nothing.
func (p *Parser) End() Progress {
	if p.ended {
		return Progress{Result: End}
	}
	if p.phase == awaitingAnswer {
		if answered, _ := p.Answer(""); answered.Message != nil {
			p.ended = true
			answered.Result = End
			return answered
		}
	}
	p.ended = true
	if p.message == nil {
		return Progress{Result: End}
	}

	m := p.message
	short := stream.ErrShort.Error()
	m.Defect, m.End = DefectStreamEnded, p.next
	switch p.phase {
	case inStartLine:
		p.dropLine()
		m.Detail = "reading the start line: " + short
	case inFields:
		p.dropLine()
		m.Detail = "reading a field line: " + short
	case inChunkSize:
		p.dropLine()
		m.Detail = "reading a chunk size: " + short
	case inTrailers:
		p.dropLine()
		m.Detail = "reading a trailer field: " + short
	case inDeclaredBody:
		m.Detail = fmt.Sprintf("the stream ends %d bytes into a body of %d", m.BodyLength-p.remaining, m.BodyLength)
	case inChunkData:
		// Parse never takes a chunk the stream ends inside.
		m.Body = m.Body[:uint64(len(m.Body))-p.chunkKept]
		p.release(int64(p.chunkKept))
		m.End = p.chunkStart
		m.Detail = fmt.Sprintf("the stream ends inside a chunk of %d bytes", p.chunkSize)
	case inChunkEnd:
		// Nor a lone byte of the pair after a chunk.
		m.End = p.next - uint64(p.endSeen)
		m.Detail = "reading the end of a chunk: " + short
	}
	progress := Progress{Result: End, Message: m, Charge: p.charge}
	p.message, p.charge, p.phase = nil, Charge{}, betweenMessages
	p.settled = m.End
	return progress
}

// Next is the offset the next part must begin at, and false before the first
// part, when any offset is accepted.
func (p *Parser) Next() (uint64, bool) {
	return p.next, p.started
}

// Retained is what the parser holds now and has not handed over.
func (p *Parser) Retained() Charge {
	return p.charge
}

// Unplaced is how many offsets after the point the direction stopped were never
// read as part of a message. It is zero while the direction is open.
func (p *Parser) Unplaced() uint64 {
	if p.stop == NeedInput && !p.ended {
		return 0
	}
	return p.next - p.settled
}
