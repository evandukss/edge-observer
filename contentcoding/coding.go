package contentcoding

import (
	"strconv"
	"strings"
)

// Coding is one content coding this package undoes.
type Coding uint8

const (
	// Gzip is "gzip", and its alias "x-gzip": one or more gzip members
	// (RFC 1952), each checked against its CRC-32 and length.
	Gzip Coding = iota + 1
	// Deflate is "deflate": a zlib stream (RFC 1950) when the body's first two
	// bytes satisfy the zlib header check, and a raw deflate stream (RFC 1951)
	// otherwise. See Decode for the check.
	Deflate
	// Brotli is "br" (RFC 7932).
	Brotli
	// Zstd is "zstd": one or more Zstandard frames (RFC 8878).
	Zstd
)

// String is the coding's name as Content-Encoding spells it, lowercase; Gzip
// is "gzip" whichever of its two names the header used.
func (c Coding) String() string {
	switch c {
	case Gzip:
		return "gzip"
	case Deflate:
		return "deflate"
	case Brotli:
		return "br"
	case Zstd:
		return "zstd"
	}
	return "coding(" + strconv.Itoa(int(c)) + ")"
}

// MaxCodings is the most codings one message may carry: one. A list of more is
// Unsupported, however many of its codings are known, each duplicate and each
// alias counted: "gzip, gzip" and "gzip, x-gzip" are two.
const MaxCodings = 1

// List is a message's content coding, as ParseList read it: none or one. The
// zero List has none: the body is its own content.
type List struct {
	codings [MaxCodings]Coding
	n       uint8
}

// Len is how many codings the list holds.
func (l List) Len() int { return int(l.n) }

// At is the i-th coding, from 0. It panics outside [0, Len()).
func (l List) At(i int) Coding {
	if i < 0 || i >= int(l.n) {
		panic("contentcoding: List.At(" + strconv.Itoa(i) + ") outside a list of " + strconv.Itoa(int(l.n)))
	}
	return l.codings[i]
}

// Verdict is what ParseList found in a message's Content-Encoding fields.
type Verdict uint8

const (
	// Supported is a list of at most MaxCodings codings, each one this package
	// undoes: one coding, or none. An empty list is Supported, and its List
	// has length zero.
	Supported Verdict = iota + 1
	// Unsupported is a well-formed list naming a coding this package does not
	// undo, or more than MaxCodings codings. Nothing of the body is decoded.
	// Its exclusion reason is ReasonCodingUnsupported.
	Unsupported
	// Malformed is a field value that is not a comma-separated list of
	// tokens. It is a defect in the message, never an exclusion reason, and
	// takes precedence over Unsupported.
	Malformed
)

// Reason is the exclusion reason the verdict carries: ReasonCodingUnsupported
// for Unsupported, and "" for the other two.
func (v Verdict) Reason() string {
	if v == Unsupported {
		return ReasonCodingUnsupported
	}
	return ""
}

// ParseList reads the content codings from a message's Content-Encoding field
// values, given in the order they were captured. Repeated fields combine in
// that order, field by field and then within each list, and the whole list is
// read before anything is decided.
//
// Each value is a comma-separated list (RFC 9110 section 5.6.1). Whitespace
// around an element is ignored, and so is an empty element, so a value that
// is empty or holds only commas and whitespace adds nothing. Every other
// element must be a token (RFC 9110 section 5.6.2), compared without regard
// to case:
//   - "identity" is ignored wherever it appears;
//   - "gzip", "x-gzip", "deflate", "br" and "zstd" are the codings undone;
//   - any other token is a coding this package does not undo.
//
// An element that is not a token makes the list Malformed, wherever that
// element is. Otherwise a coding not undone, or more than MaxCodings codings
// once "identity" is set aside, each duplicate and alias counted, makes it
// Unsupported, and nothing of the body is decoded. Only a Supported list is
// returned with its coding; the other two return the zero List.
func ParseList(values []string) (List, Verdict) {
	var l List
	count := 0
	unknown := false
	for _, value := range values {
		for value != "" {
			element := value
			if i := strings.IndexByte(value, ','); i >= 0 {
				element, value = value[:i], value[i+1:]
			} else {
				value = ""
			}
			token := strings.Trim(element, " \t")
			if token == "" {
				continue
			}
			if !isToken(token) {
				return List{}, Malformed
			}
			c := named(token)
			if c == identity {
				continue
			}
			if c == 0 {
				unknown = true
			} else if count < MaxCodings {
				l.codings[count] = c
			}
			count++
		}
	}
	if unknown || count > MaxCodings {
		return List{}, Unsupported
	}
	l.n = uint8(count)
	return l, Supported
}

// identity stands for "identity" while a list is read; no List holds it.
const identity Coding = 255

// named is the coding a token names, identity, or 0 for one not undone.
func named(token string) Coding {
	for _, n := range [...]struct {
		name   string
		coding Coding
	}{{"identity", identity}, {"gzip", Gzip}, {"x-gzip", Gzip}, {"deflate", Deflate}, {"br", Brotli}, {"zstd", Zstd}} {
		if strings.EqualFold(token, n.name) {
			return n.coding
		}
	}
	return 0
}

// isToken reports whether s is one or more tchar (RFC 9110 section 5.6.2).
func isToken(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return s != ""
}
