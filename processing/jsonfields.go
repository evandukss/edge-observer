package processing

import (
	"bytes"
	"errors"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/evandukss/edge-observer/contract/config"
)

// errUndecidable is every reason a JSON field operation cannot act on a body:
// not one strictly valid JSON value, or past a bound. The caller removes the
// whole body; which reason applied is never needed to decide that.
var errUndecidable = errors.New("body is not strictly valid JSON within the bounds")

// editJSON removes, or with replacement set replaces the value of, every member
// or element the pointers match, and returns the body with every other byte
// kept, and which pointers matched at least once. It fails rather than guess.
func editJSON(body []byte, pointers []string, replacement []byte) ([]byte, []bool, error) {
	if bytes.HasPrefix(body, []byte("\xef\xbb\xbf")) || !utf8.Valid(body) {
		return nil, nil, errUndecidable
	}
	j := &jsonEditor{body: body, replacement: replacement, matched: make([]bool, len(pointers))}
	for _, p := range pointers {
		j.pointers = append(j.pointers, config.PointerTokens(p))
	}
	j.space()
	var active []cursor
	for i := range j.pointers {
		active = append(active, cursor{pointer: i})
	}
	if _, err := j.value(1, active); err != nil {
		return nil, nil, err
	}
	j.space()
	if j.pos != len(body) {
		return nil, nil, errUndecidable
	}
	slices.SortFunc(j.edits, func(a, b jsonEdit) int { return a.start - b.start })
	out := make([]byte, 0, len(body))
	at := 0
	for _, e := range j.edits {
		out = append(out, body[at:e.start]...)
		out = append(out, e.with...)
		at = e.end
	}
	out = append(out, body[at:]...)
	return out, j.matched, nil
}

// cursor is one pointer part-way through its tokens: token is the next one to
// match against the children of the value it is attached to.
type cursor struct {
	pointer int
	token   int
}

// jsonEdit replaces body[start:end] with with; a nil with deletes.
type jsonEdit struct {
	start, end int
	with       []byte
}

type jsonEditor struct {
	body        []byte
	pos         int
	nodes       int
	pointers    [][]string
	replacement []byte
	matched     []bool
	edits       []jsonEdit
}

// child is one member or element of a container: its whole span, and the span
// of its value.
type child struct {
	start, valueStart, end int
	act                    bool
}

func (j *jsonEditor) space() {
	for j.pos < len(j.body) {
		switch j.body[j.pos] {
		case ' ', '\t', '\n', '\r':
			j.pos++
		default:
			return
		}
	}
}

// value reads one value. active holds the cursors attached to it.
func (j *jsonEditor) value(depth int, active []cursor) (int, error) {
	if depth > config.MaxJSONFieldDepth {
		return 0, errUndecidable
	}
	j.nodes++
	if j.nodes > config.MaxJSONFieldNodes || j.pos >= len(j.body) {
		return 0, errUndecidable
	}
	start := j.pos
	switch c := j.body[j.pos]; {
	case c == '{':
		return start, j.object(depth, active)
	case c == '[':
		return start, j.array(depth, active)
	case c == '"':
		_, err := j.text()
		return start, err
	case c == '-' || (c >= '0' && c <= '9'):
		return start, j.number()
	default:
		for _, literal := range []string{"true", "false", "null"} {
			if bytes.HasPrefix(j.body[j.pos:], []byte(literal)) {
				j.pos += len(literal)
				return start, nil
			}
		}
		return 0, errUndecidable
	}
}

// descend decides, for a child reached by key or index, whether a cursor ends
// on it (act) and which cursors continue beneath it.
func (j *jsonEditor) descend(active []cursor, matches func(token string) bool) (bool, []cursor) {
	act := false
	var next []cursor
	for _, c := range active {
		tokens := j.pointers[c.pointer]
		if !matches(tokens[c.token]) {
			continue
		}
		if c.token+1 == len(tokens) {
			act = true
			j.matched[c.pointer] = true
			continue
		}
		next = append(next, cursor{pointer: c.pointer, token: c.token + 1})
	}
	if act {
		// The outer match is acted on; nothing inside it is edited as well.
		return true, nil
	}
	return false, next
}

func (j *jsonEditor) object(depth int, active []cursor) error {
	j.pos++
	j.space()
	var children []child
	if j.pos < len(j.body) && j.body[j.pos] == '}' {
		j.pos++
		return nil
	}
	for {
		if j.pos >= len(j.body) || j.body[j.pos] != '"' {
			return errUndecidable
		}
		start := j.pos
		name, err := j.text()
		if err != nil {
			return err
		}
		j.space()
		if j.pos >= len(j.body) || j.body[j.pos] != ':' {
			return errUndecidable
		}
		j.pos++
		j.space()
		// * matches every member as it matches every element: PHP iterates
		// objects and arrays alike.
		act, next := j.descend(active, func(token string) bool { return token == "*" || name == token || strings.EqualFold(name, token) })
		valueStart, err := j.value(depth+1, next)
		if err != nil {
			return err
		}
		children = append(children, child{start: start, valueStart: valueStart, end: j.pos, act: act})
		j.space()
		if j.pos >= len(j.body) {
			return errUndecidable
		}
		if j.body[j.pos] == '}' {
			j.pos++
			j.edit(children)
			return nil
		}
		if j.body[j.pos] != ',' {
			return errUndecidable
		}
		j.pos++
		j.space()
	}
}

func (j *jsonEditor) array(depth int, active []cursor) error {
	j.pos++
	j.space()
	var children []child
	if j.pos < len(j.body) && j.body[j.pos] == ']' {
		j.pos++
		return nil
	}
	for index := 0; ; index++ {
		at := strconv.Itoa(index)
		act, next := j.descend(active, func(token string) bool { return token == "*" || token == at })
		start, err := j.value(depth+1, next)
		if err != nil {
			return err
		}
		children = append(children, child{start: start, valueStart: start, end: j.pos, act: act})
		j.space()
		if j.pos >= len(j.body) {
			return errUndecidable
		}
		if j.body[j.pos] == ']' {
			j.pos++
			j.edit(children)
			return nil
		}
		if j.body[j.pos] != ',' {
			return errUndecidable
		}
		j.pos++
		j.space()
	}
}

// edit records what happens to a container's acted-on children. A replaced
// value is its own span. A removed run of children goes with the separators
// after it where a kept child follows, and otherwise with the separator before
// it, so exactly one comma leaves with each removed child and nothing outside
// the removed members changes.
func (j *jsonEditor) edit(children []child) {
	if j.replacement != nil {
		for _, c := range children {
			if c.act {
				j.edits = append(j.edits, jsonEdit{start: c.valueStart, end: c.end, with: j.replacement})
			}
		}
		return
	}
	for i := 0; i < len(children); {
		if !children[i].act {
			i++
			continue
		}
		last := i
		for last+1 < len(children) && children[last+1].act {
			last++
		}
		switch {
		case last+1 < len(children):
			j.edits = append(j.edits, jsonEdit{start: children[i].start, end: children[last+1].start})
		case i > 0:
			j.edits = append(j.edits, jsonEdit{start: children[i-1].end, end: children[last].end})
		default:
			j.edits = append(j.edits, jsonEdit{start: children[i].start, end: children[last].end})
		}
		i = last + 1
	}
}

// text reads a string and returns it with its escapes decoded. An unescaped
// control byte, an unknown escape or an escape naming an unpaired surrogate
// is refused.
func (j *jsonEditor) text() (string, error) {
	j.pos++
	var out strings.Builder
	for j.pos < len(j.body) {
		c := j.body[j.pos]
		switch {
		case c == '"':
			j.pos++
			return out.String(), nil
		case c < 0x20:
			return "", errUndecidable
		case c == '\\':
			if j.pos+1 >= len(j.body) {
				return "", errUndecidable
			}
			escape := j.body[j.pos+1]
			j.pos += 2
			switch escape {
			case '"', '\\', '/':
				out.WriteByte(escape)
			case 'b':
				out.WriteByte('\b')
			case 'f':
				out.WriteByte('\f')
			case 'n':
				out.WriteByte('\n')
			case 'r':
				out.WriteByte('\r')
			case 't':
				out.WriteByte('\t')
			case 'u':
				r, ok := j.hex4()
				if !ok {
					return "", errUndecidable
				}
				if utf16.IsSurrogate(r) {
					if r >= 0xdc00 || j.pos+1 >= len(j.body) || j.body[j.pos] != '\\' || j.body[j.pos+1] != 'u' {
						return "", errUndecidable
					}
					j.pos += 2
					low, ok := j.hex4()
					if !ok || low < 0xdc00 || low > 0xdfff {
						return "", errUndecidable
					}
					r = utf16.DecodeRune(r, low)
				}
				out.WriteRune(r)
			default:
				return "", errUndecidable
			}
		default:
			out.WriteByte(c)
			j.pos++
		}
	}
	return "", errUndecidable
}

func (j *jsonEditor) hex4() (rune, bool) {
	if j.pos+4 > len(j.body) {
		return 0, false
	}
	v, err := strconv.ParseUint(string(j.body[j.pos:j.pos+4]), 16, 32)
	if err != nil {
		return 0, false
	}
	j.pos += 4
	return rune(v), true
}

// number reads -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?.
func (j *jsonEditor) number() error {
	digits := func() int {
		n := 0
		for j.pos < len(j.body) && j.body[j.pos] >= '0' && j.body[j.pos] <= '9' {
			j.pos++
			n++
		}
		return n
	}
	if j.body[j.pos] == '-' {
		j.pos++
	}
	if j.pos < len(j.body) && j.body[j.pos] == '0' {
		j.pos++
	} else if digits() == 0 {
		return errUndecidable
	}
	if j.pos < len(j.body) && j.body[j.pos] == '.' {
		j.pos++
		if digits() == 0 {
			return errUndecidable
		}
	}
	if j.pos < len(j.body) && (j.body[j.pos] == 'e' || j.body[j.pos] == 'E') {
		j.pos++
		if j.pos < len(j.body) && (j.body[j.pos] == '+' || j.body[j.pos] == '-') {
			j.pos++
		}
		if digits() == 0 {
			return errUndecidable
		}
	}
	return nil
}

// jsonString writes a printable ASCII value as a JSON string. Only the quote
// and the backslash need escaping in that range.
func jsonString(value string) []byte {
	var out bytes.Buffer
	out.WriteByte('"')
	for i := 0; i < len(value); i++ {
		if value[i] == '"' || value[i] == '\\' {
			out.WriteByte('\\')
		}
		out.WriteByte(value[i])
	}
	out.WriteByte('"')
	return out.Bytes()
}
