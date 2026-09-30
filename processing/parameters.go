package processing

import (
	"slices"
	"strings"

	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/reconstruct"
)

// removeParameters removes from a query or an urlencoded body every parameter
// whose percent-decoded name equals a configured name exactly. Parameters are
// separated by & alone. It returns the text with every other byte kept and
// the configured names that removed something. A malformed escape anywhere in
// a name or a value leaves the text undecidable: undecidable is true and the
// caller removes the whole query or body.
func removeParameters(text string, names []string) (kept string, matched []string, undecidable bool) {
	if malformedEscape(text) {
		return "", nil, true
	}
	type parameter struct{ start, end int }
	var parameters []parameter
	start := 0
	for i := 0; i <= len(text); i++ {
		if i == len(text) || text[i] == '&' {
			parameters = append(parameters, parameter{start, i})
			start = i + 1
		}
	}
	removed := make([]bool, len(parameters))
	for i, p := range parameters {
		name, _, _ := strings.Cut(text[p.start:p.end], "=")
		decoded := percentDecode(name)
		for _, configured := range names {
			if decoded == configured {
				removed[i] = true
				if !slices.Contains(matched, configured) {
					matched = append(matched, configured)
				}
			}
		}
	}
	if len(matched) == 0 {
		return text, nil, false
	}
	// A removed run goes with the & after it, or the one before it where it
	// is last.
	var out strings.Builder
	at := 0
	for i := 0; i < len(parameters); {
		if !removed[i] {
			i++
			continue
		}
		last := i
		for last+1 < len(parameters) && removed[last+1] {
			last++
		}
		from, to := parameters[i].start, parameters[last].end
		switch {
		case last+1 < len(parameters):
			to = parameters[last+1].start
		case i > 0:
			from = parameters[i-1].end
		}
		out.WriteString(text[at:from])
		at = to
		i = last + 1
	}
	out.WriteString(text[at:])
	return out.String(), matched, false
}

// malformedEscape is a % not followed by two hexadecimal digits.
func malformedEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && (i+2 >= len(s) || !hexDigit(s[i+1]) || !hexDigit(s[i+2])) {
			return true
		}
	}
	return false
}

// percentDecode decodes a well-formed name as urlencoding defines it: + is a
// space and % with two hexadecimal digits is that byte.
func percentDecode(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '+':
			out = append(out, ' ')
		case '%':
			out = append(out, hexValue(s[i+1])<<4|hexValue(s[i+2]))
			i += 2
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}

func hexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexValue(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// admittedForm is whether a request, as parsed, declares exactly one
// Content-Type whose media type is application/x-www-form-urlencoded. It reads
// the parsed message so that no header operation can change what it admits.
func admittedForm(m *reconstruct.Message) bool {
	count := 0
	var value string
	for _, fields := range [][]http1.Header{m.Headers, m.Trailers} {
		for _, h := range fields {
			if strings.EqualFold(h.Name, "content-type") {
				count++
				value = h.Value
			}
		}
	}
	if count != 1 {
		return false
	}
	media, _, _ := strings.Cut(value, ";")
	return strings.EqualFold(strings.Trim(media, " \t"), "application/x-www-form-urlencoded")
}
