// Package http1 reads HTTP/1.1 messages out of a plaintext stream that may
// have holes in it.
//
// It is strict: where two endpoints could read a byte differently (a bare line
// feed ending a header, both a length and chunked encoding, a space before a
// colon), an observer choosing one reading reports an exchange neither had -
// the request smuggling shape. It refuses the message, says why, and stops
// rather than guessing where the next one begins.
//
// Everything is bounded: start line, header lines, header count, body bytes
// kept, chunk count and messages per stream.
//
// A hole inside a body leaves the message framed (the declared length says
// where it ends), so the next message is still found. A hole anywhere else
// stops the parse; the rest is reported as unplaced rather than
// resynchronised on a guess.
//
// Parse reads a direction already whole. A Parser reads one as it arrives, a
// part at a time, by the same rules: Parse runs on it.
package http1

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/evandukss/edge-observer/stream"
)

// Kind is which side of an exchange a message is.
type Kind uint8

const (
	UnknownKind Kind = iota
	// Request is a message beginning with a request line.
	Request
	// Response is a message beginning with a status line.
	Response
)

func (k Kind) String() string {
	switch k {
	case Request:
		return "request"
	case Response:
		return "response"
	default:
		return "unknown"
	}
}

// Framing is how the end of a message's body is known.
type Framing uint8

const (
	// FramingNone is a message that carries no body.
	FramingNone Framing = iota
	// FramingContentLength is a body whose length the message declares.
	FramingContentLength
	// FramingChunked is a body whose end is the zero-sized chunk.
	FramingChunked
	// FramingUntilClose is a body ending with the connection. A fragment carries
	// no close, so such a body is never complete here.
	FramingUntilClose
	// FramingAmbiguous is a message that declares two framings which disagree.
	FramingAmbiguous
)

func (f Framing) String() string {
	switch f {
	case FramingNone:
		return "none"
	case FramingContentLength:
		return "content-length"
	case FramingChunked:
		return "chunked"
	case FramingUntilClose:
		return "until-close"
	case FramingAmbiguous:
		return "ambiguous"
	default:
		return fmt.Sprintf("framing(%d)", uint8(f))
	}
}

// Defect says what is missing from or wrong with a message.
type Defect uint8

const (
	// DefectNone is a message with every byte present and nothing refused.
	DefectNone Defect = iota
	// DefectStreamEnded is a message the stream ran out inside.
	DefectStreamEnded
	// DefectHole is a message a hole falls inside.
	DefectHole
	// DefectMalformed is a message no strict endpoint would accept.
	DefectMalformed
	// DefectAmbiguousFraming is a message declaring two framings at once.
	DefectAmbiguousFraming
	// DefectLimit is a message that reached one of the caller's bounds.
	DefectLimit
)

func (d Defect) String() string {
	switch d {
	case DefectNone:
		return "none"
	case DefectStreamEnded:
		return "stream-ended"
	case DefectHole:
		return "hole"
	case DefectMalformed:
		return "malformed"
	case DefectAmbiguousFraming:
		return "ambiguous-framing"
	case DefectLimit:
		return "limit"
	default:
		return fmt.Sprintf("defect(%d)", uint8(d))
	}
}

// Header is one field line, with its name as it was sent.
type Header struct{ Name, Value string }

// Message is one HTTP/1.1 message as far as it could be read. BodyLength is
// the body's extent in the stream and Body what was kept; BodyHoled and
// BodyElided say whether capture or the caller's bound cut it short.
type Message struct {
	Kind Kind

	Method   string
	Target   string
	Protocol string

	Status int
	Reason string

	Headers []Header

	Framing    Framing
	Body       []byte
	BodyLength uint64
	BodyHoled  uint64
	BodyElided uint64
	Trailers   []Header

	// Complete reports that every byte of this message was in the stream, not
	// that all were kept.
	Complete bool
	// Framed reports that the end of this message is known, so what follows
	// begins a new one.
	Framed bool

	Defect Defect
	// Detail is one line saying what went wrong, structurally. Never a body byte.
	Detail string

	// Offset is where the start line begins; End is one past the last offset this
	// message accounts for.
	Offset, End uint64
}

// Lookup is the value of the first field with this name, compared without
// regard to case.
func (m Message) Lookup(name string) (string, bool) {
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value, true
		}
	}
	return "", false
}

// StartLine is the message's first line as it was sent.
func (m Message) StartLine() string {
	switch m.Kind {
	case Request:
		return m.Method + " " + m.Target + " " + m.Protocol
	case Response:
		line := m.Protocol + " " + strconv.Itoa(m.Status)
		if m.Reason != "" {
			line += " " + m.Reason
		}
		return line
	default:
		return ""
	}
}

// Limits bounds everything one message can make this package hold or scan. A
// zero field takes its default, so a caller overrides one and keeps the rest.
// None counts a stream's messages: what a stream holds is bounded by whoever
// holds the stream, and a connection never stops being read at a total.
type Limits struct {
	MaxStartLine   int
	MaxHeaderLine  int
	MaxHeaders     int
	MaxHeaderBytes int
	MaxBodyBytes   int
	MaxChunks      int
	MaxTrailers    int
}

// DefaultLimits are bounds well-behaved traffic never reaches.
func DefaultLimits() Limits {
	return Limits{
		MaxStartLine:   8 << 10,
		MaxHeaderLine:  8 << 10,
		MaxHeaders:     128,
		MaxHeaderBytes: 64 << 10,
		MaxBodyBytes:   8 << 20,
		MaxChunks:      16384,
		MaxTrailers:    32,
	}
}

func (l Limits) orDefaults() Limits {
	d := DefaultLimits()
	if l.MaxStartLine <= 0 {
		l.MaxStartLine = d.MaxStartLine
	}
	if l.MaxHeaderLine <= 0 {
		l.MaxHeaderLine = d.MaxHeaderLine
	}
	if l.MaxHeaders <= 0 {
		l.MaxHeaders = d.MaxHeaders
	}
	if l.MaxHeaderBytes <= 0 {
		l.MaxHeaderBytes = d.MaxHeaderBytes
	}
	if l.MaxBodyBytes <= 0 {
		l.MaxBodyBytes = d.MaxBodyBytes
	}
	if l.MaxChunks <= 0 {
		l.MaxChunks = d.MaxChunks
	}
	if l.MaxTrailers <= 0 {
		l.MaxTrailers = d.MaxTrailers
	}
	return l
}

// Parsed is what one direction of one connection was read as.
type Parsed struct {
	Messages []Message
	// Unplaced is how many offsets after the last message were never read as part
	// of one: non-zero whenever the parse stopped early.
	Unplaced uint64
}

// Parse reads every message it can from one direction's plaintext.
func Parse(s stream.Stream, kind Kind, limits Limits) Parsed {
	return parse(s, kind, limits, nil)
}

// ParseResponses reads a response stream where some requests forbid a body in
// the response (HEAD, RFC 9112 section 6.3): bodiless[i] reports that of the
// i'th response. A nil or short slice frames every response by its headers.
func ParseResponses(s stream.Stream, limits Limits, bodiless []bool) Parsed {
	return parse(s, Response, limits, bodiless)
}

func parse(s stream.Stream, kind Kind, limits Limits, bodiless []bool) Parsed {
	p := newParser(kind, limits, unaccounted{})
	var parsed Parsed

	// take keeps a message handed over, and reports whether the parse is over.
	take := func(progress Progress) bool {
		if progress.Message == nil || progress.Result == Head {
			return false
		}
		m := *progress.Message
		if progress.Result == Unsupported && m.Framing == FramingUntilClose {
			// A reader of an open connection stops at this body; Parse has the whole
			// stream, so the body is the rest of it.
			cursor := stream.NewCursor(s)
			if _, _, err := cursor.Take(m.End-s.Start, 0); err == nil {
				m.readUntilClose(cursor, p.limits)
				m.End = cursor.Offset()
			}
			parsed.Messages = append(parsed.Messages, m)
			parsed.Unplaced = s.End - m.End
			return true
		}
		parsed.Messages = append(parsed.Messages, m)
		return false
	}

	for _, part := range s.Parts {
		for part.Length > 0 {
			progress, err := p.Feed(part)
			if err != nil {
				// Parts Assemble produced always pass; a hand-made stream that does not
				// is read as far as it was fed.
				return finish(parsed, s, p)
			}
			consumed := progress.Consumed
			if progress.Result == Head && kind == Response {
				method := ""
				if len(bodiless) > len(parsed.Messages) && bodiless[len(parsed.Messages)] {
					method = "HEAD"
				}
				progress, _ = p.Answer(method)
			}
			if take(progress) {
				return parsed
			}
			part.Offset, part.Length = part.Offset+consumed, part.Length-consumed
			if part.Gap == stream.GapNone {
				part.Bytes = part.Bytes[consumed:]
			}
		}
	}
	if take(p.End()) {
		return parsed
	}
	return finish(parsed, s, p)
}

// finish counts what follows the last message as unplaced.
func finish(parsed Parsed, s stream.Stream, p *Parser) Parsed {
	p.End()
	parsed.Unplaced = s.End - s.Start
	if n := len(parsed.Messages); n > 0 {
		parsed.Unplaced = s.End - parsed.Messages[n-1].End
	}
	return parsed
}

// unaccounted grants everything: Parse reads a stream already whole, and its
// holder bounds it.
type unaccounted struct{}

func (unaccounted) Reserve(Charge) bool { return true }
func (unaccounted) Release(Charge)      {}

// readUntilClose reads a body that ends with the connection. It is never
// complete: a fragment carries no close, so a closed connection and missing
// bytes look alike.
func (m *Message) readUntilClose(cursor *stream.Cursor, limits Limits) {
	reach := cursor.Remaining()
	// Take cannot fail asked for exactly the offsets that remain.
	body, holed, _ := cursor.Take(reach, limits.MaxBodyBytes)
	m.Body, m.BodyHoled, m.BodyLength = body, holed, reach
	m.BodyElided = reach - holed - uint64(len(body))
	m.Defect = DefectStreamEnded
	m.Detail = "the body ends with the connection, and a fragment carries no close"
}

// frame decides how the end of this message's body is known, from its fields
// alone. A non-empty detail with FramingNone is a refusal.
func (m *Message) frame(kind Kind, noBody bool) (Framing, uint64, string) {
	var lengths, codings []string
	declaresEncoding := false

	for _, h := range m.Headers {
		switch {
		case strings.EqualFold(h.Name, "content-length"):
			lengths = append(lengths, splitList(h.Value)...)
		case strings.EqualFold(h.Name, "transfer-encoding"):
			declaresEncoding = true
			for _, coding := range splitList(h.Value) {
				codings = append(codings, strings.ToLower(coding))
			}
		}
	}

	// The smuggling shape: one endpoint frames by the length, the other by the
	// chunks.
	if declaresEncoding && len(lengths) > 0 {
		return FramingAmbiguous, 0, "the message declares both a length and a transfer encoding"
	}

	// A response to HEAD, or with a bodiless status, carries none whatever it
	// declares.
	if kind == Response && (noBody || statusForbidsBody(m.Status)) {
		return FramingNone, 0, ""
	}

	if declaresEncoding {
		switch {
		case len(codings) == 0:
			return FramingNone, 0, "an empty transfer encoding"
		case codings[len(codings)-1] == "chunked":
			for _, coding := range codings[:len(codings)-1] {
				if coding == "chunked" {
					return FramingNone, 0, "chunked applied more than once"
				}
			}
			return FramingChunked, 0, ""
		default:
			for _, coding := range codings {
				if coding == "chunked" {
					return FramingNone, 0, "a transfer coding applied after chunked"
				}
			}
			if kind == Request {
				// A request whose body this observer cannot delimit is a
				// request the server must refuse (RFC 9112 section 6.1).
				return FramingNone, 0, "a request whose transfer encoding is not chunked"
			}
			return FramingUntilClose, 0, ""
		}
	}

	if len(lengths) > 0 {
		for _, value := range lengths[1:] {
			if value != lengths[0] {
				return FramingNone, 0, "two content lengths that disagree"
			}
		}
		length, err := strconv.ParseUint(lengths[0], 10, 63)
		if err != nil || !isDigits(lengths[0]) {
			return FramingNone, 0, "a content length that is not a decimal number"
		}
		return FramingContentLength, length, ""
	}

	if kind == Response {
		return FramingUntilClose, 0, ""
	}
	return FramingNone, 0, ""
}

// statusForbidsBody reports the codes whose responses never carry one,
// whatever they declare (RFC 9110 section 6.4.1).
func statusForbidsBody(status int) bool {
	return (status >= 100 && status < 200) || status == 204 || status == 304
}

func (m *Message) readRequestLine(line string) bool {
	parts := strings.Split(line, " ")
	if len(parts) != 3 {
		return false
	}
	if !isToken(parts[0]) || parts[1] == "" || !isVisibleText(parts[1]) || !isVersion(parts[2]) {
		return false
	}
	m.Method, m.Target, m.Protocol = parts[0], parts[1], parts[2]
	return true
}

func (m *Message) readStatusLine(line string) bool {
	// The shortest legal status line is a version, a space and three digits.
	if len(line) < 12 || !isVersion(line[:8]) || line[8] != ' ' || !isDigits(line[9:12]) {
		return false
	}
	reason := ""
	switch {
	case len(line) == 12:
	case line[12] == ' ':
		reason = line[13:]
	default:
		return false
	}
	if !isVisibleText(reason) {
		return false
	}
	status, err := strconv.Atoi(line[9:12])
	if err != nil {
		return false
	}
	m.Protocol, m.Status, m.Reason = line[:8], status, reason
	return true
}

// readHeader reads one field line. A name that is not a token catches a space
// before the colon and an obsolete line folding, both smuggling shapes.
func readHeader(line string) (Header, bool) {
	colon := strings.IndexByte(line, ':')
	if colon <= 0 {
		return Header{}, false
	}
	name := line[:colon]
	if !isToken(name) {
		return Header{}, false
	}
	value := strings.Trim(line[colon+1:], " \t")
	if !isVisibleText(value) {
		return Header{}, false
	}
	return Header{Name: name, Value: value}, true
}

// chunkSize reads a chunk size line. What follows its first semicolon is not
// interpreted.
func chunkSize(line string) (uint64, bool) {
	if semicolon := strings.IndexByte(line, ';'); semicolon >= 0 {
		line = line[:semicolon]
	}
	if line == "" || len(line) > 16 || !isHex(line) {
		return 0, false
	}
	size, err := strconv.ParseUint(line, 16, 63)
	if err != nil {
		return 0, false
	}
	return size, true
}

// splitList splits a comma-separated field value, which is how one field is
// sent as several values on one line.
func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		out = append(out, strings.Trim(part, " \t"))
	}
	return out
}

// isToken reports whether s is a field name or method: the visible ASCII that
// RFC 9110 section 5.6.2 permits unquoted, and nothing else.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// isVisibleText reports whether s holds only visible ASCII, spaces and tabs: a
// control character is a line ending one endpoint may honour and the other
// not.
func isVisibleText(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < ' ' && c != '\t' || c == 0x7f {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// isVersion reports whether s is an HTTP version this package reads.
func isVersion(s string) bool {
	return len(s) == 8 && s[:5] == "HTTP/" && s[5] >= '0' && s[5] <= '9' && s[6] == '.' && s[7] >= '0' && s[7] <= '9'
}
