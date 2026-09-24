package stream

import (
	"errors"
	"fmt"
)

var (
	// ErrGap is returned when a read would cross a hole: the bytes either side did
	// not touch.
	ErrGap = errors.New("the read crosses a hole in the stream")
	// ErrShort is returned when the stream ends before the read completes: no
	// more bytes yet, unlike ErrGap.
	ErrShort = errors.New("the stream ends inside the read")
	// ErrTooLong is returned when a read reaches its bound first.
	ErrTooLong = errors.New("the read reached its bound")
)

// Cursor reads a Stream's offsets in order. Methods returning bytes copy them.
type Cursor struct {
	stream Stream
	pos    uint64
	idx    int
}

// NewCursor returns a cursor at the first offset of the stream.
func NewCursor(s Stream) *Cursor {
	return &Cursor{stream: s, pos: s.Start}
}

// Offset is the offset the cursor will read next.
func (c *Cursor) Offset() uint64 { return c.pos }

// Remaining is how many offsets are left, gaps included.
func (c *Cursor) Remaining() uint64 {
	if c.pos >= c.stream.End {
		return 0
	}
	return c.stream.End - c.pos
}

// AtEnd reports whether every offset has been read.
func (c *Cursor) AtEnd() bool { return c.Remaining() == 0 }

// AtGap reports the hole the cursor is sitting in, if it is in one.
func (c *Cursor) AtGap() (GapReason, bool) {
	p, ok := c.part()
	if !ok || p.Gap == GapNone {
		return GapNone, false
	}
	return p.Gap, true
}

// part is the part holding the cursor's offset.
func (c *Cursor) part() (Part, bool) {
	for c.idx < len(c.stream.Parts) {
		p := c.stream.Parts[c.idx]
		if c.pos < p.Offset+p.Length {
			if c.pos < p.Offset {
				return Part{}, false
			}
			return p, true
		}
		c.idx++
	}
	return Part{}, false
}

// ReadLine reads up to and including the next CRLF and returns the bytes
// before it. Only CRLF ends a line: a terminator implementations disagree on is
// a smuggling vector (RFC 9112 section 2.2).
func (c *Cursor) ReadLine(max int) ([]byte, error) {
	line := make([]byte, 0, 64)
	sawCR := false

	for {
		if c.AtEnd() {
			return nil, ErrShort
		}
		p, ok := c.part()
		if !ok {
			return nil, ErrShort
		}
		if p.Gap != GapNone {
			return nil, fmt.Errorf("%w: %s at offset %d", ErrGap, p.Gap, c.pos)
		}

		within := c.pos - p.Offset
		for _, b := range p.Bytes[within:] {
			c.pos++
			switch {
			case sawCR && b == '\n':
				return line, nil
			case sawCR:
				// A CR without LF is an ordinary byte; the line stays open.
				sawCR = false
				line = append(line, '\r')
				if len(line) > max {
					return nil, ErrTooLong
				}
				fallthrough
			default:
				if b == '\r' {
					sawCR = true
					continue
				}
				line = append(line, b)
				if len(line) > max {
					return nil, ErrTooLong
				}
			}
		}
	}
}

// ReadN reads exactly n offsets and returns their bytes. A hole among them is
// an error.
func (c *Cursor) ReadN(n uint64) ([]byte, error) {
	if n > c.Remaining() {
		return nil, ErrShort
	}
	out := make([]byte, 0, n)
	for n > 0 {
		p, ok := c.part()
		if !ok {
			return nil, ErrShort
		}
		if p.Gap != GapNone {
			return nil, fmt.Errorf("%w: %s at offset %d", ErrGap, p.Gap, c.pos)
		}
		within := c.pos - p.Offset
		take := min(n, p.Length-within)
		out = append(out, p.Bytes[within:within+take]...)
		c.pos += take
		n -= take
	}
	return out, nil
}

// Take reads n offsets and returns the bytes present, keeping at most keep of
// them, and how many offsets were holes. Bodies are read with it: a hole inside
// a body of known length leaves an incomplete body, not an unknown end.
func (c *Cursor) Take(n uint64, keep int) (data []byte, holed uint64, err error) {
	if n > c.Remaining() {
		return nil, 0, ErrShort
	}
	for n > 0 {
		p, ok := c.part()
		if !ok {
			return nil, 0, ErrShort
		}
		within := c.pos - p.Offset
		take := min(n, p.Length-within)
		if p.Gap != GapNone {
			holed += take
		} else if room := keep - len(data); room > 0 {
			data = append(data, p.Bytes[within:within+min(take, uint64(room))]...)
		}
		c.pos += take
		n -= take
	}
	return data, holed, nil
}

// Peek reports up to n bytes at the cursor without moving it, stopping at a
// hole or the end.
func (c *Cursor) Peek(n int) []byte {
	saved, savedIdx := c.pos, c.idx
	defer func() { c.pos, c.idx = saved, savedIdx }()

	out := make([]byte, 0, n)
	for len(out) < n {
		p, ok := c.part()
		if !ok || p.Gap != GapNone {
			break
		}
		within := c.pos - p.Offset
		take := min(uint64(n-len(out)), p.Length-within)
		out = append(out, p.Bytes[within:within+take]...)
		c.pos += take
	}
	return out
}
