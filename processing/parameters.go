package processing

import (
	"slices"
	"strings"

	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/reconstruct"
)

// removeParameters removes from a query or an urlencoded body every byte a
// parameter selected under either separator reading holds, and returns the
// text with every other byte kept and the configured names that selected
// something. PHP splits on & alone, so a value may carry ; and all of it is
// filed under the name; splitting on ; as well finds a parameter an
// application splitting on both reads. The union of the two removes both.
func removeParameters(text string, names []string) (string, []string) {
	// The finest segmentation, on & and ;, is what the result is built from:
	// every parameter of either reading is a run of these segments.
	type segment struct{ start, end int }
	var segments []segment
	start := 0
	for i := 0; i <= len(text); i++ {
		if i == len(text) || text[i] == '&' || text[i] == ';' {
			segments = append(segments, segment{start, i})
			start = i + 1
		}
	}
	removed := make([]bool, len(segments))
	var matched []string
	selects := func(parameter string) bool {
		name, _, _ := strings.Cut(parameter, "=")
		hit := false
		for _, reading := range parameterReadings(name) {
			for _, configured := range names {
				if reading == configured {
					hit = true
					if !slices.Contains(matched, configured) {
						matched = append(matched, configured)
					}
				}
			}
		}
		return hit
	}
	// The ; reading: each segment is a parameter.
	for i, s := range segments {
		if selects(text[s.start:s.end]) {
			removed[i] = true
		}
	}
	// The & reading: a parameter runs from one & to the next, over any ;.
	for first := 0; first < len(segments); {
		last := first
		for last+1 < len(segments) && text[segments[last].end] == ';' {
			last++
		}
		if selects(text[segments[first].start:segments[last].end]) {
			for i := first; i <= last; i++ {
				removed[i] = true
			}
		}
		first = last + 1
	}
	if len(matched) == 0 {
		return text, nil
	}
	// A removed run goes with one adjacent separator. Where the two differ the
	// ; goes and the & stays, so every boundary PHP reads is kept; otherwise
	// the one after it, or the one before it where the run is last.
	var out strings.Builder
	at := 0
	for i := 0; i < len(segments); {
		if !removed[i] {
			i++
			continue
		}
		last := i
		for last+1 < len(segments) && removed[last+1] {
			last++
		}
		from, to := segments[i].start, segments[last].end
		switch {
		case last+1 < len(segments) && i > 0 && text[segments[i-1].end] == ';' && text[segments[last].end] == '&':
			from = segments[i-1].end
		case last+1 < len(segments):
			to = segments[last+1].start
		case i > 0:
			from = segments[i-1].end
		}
		out.WriteString(text[at:from])
		at = to
		i = last + 1
	}
	out.WriteString(text[at:])
	return out.String(), matched
}

// parameterReadings is every name a parameter could be filed under: its
// decoded name, and PHP's filing of it as CONFIG.md lists the readings. The
// differential test against PHP's own parse_str holds this set.
func parameterReadings(raw string) []string {
	decoded := phpDecode(raw)
	readings := []string{decoded}
	normalised := decoded
	if cut := strings.IndexByte(normalised, 0); cut >= 0 {
		normalised = normalised[:cut]
	}
	b := []byte(strings.TrimLeft(normalised, " "))
	for i, c := range b {
		if c == ' ' || c == '.' || c == '+' {
			b[i] = '_'
		}
	}
	normalised = string(b)
	open := strings.IndexByte(normalised, '[')
	if open < 0 {
		return append(readings, normalised)
	}
	readings = append(readings, normalised[:open])
	if !strings.Contains(normalised[open+1:], "]") {
		readings = append(readings, normalised[:open]+"_"+normalised[open+1:], strings.ReplaceAll(normalised, "[", "_"))
	}
	return readings
}

// phpDecode decodes a name as PHP's urldecode does: + is a space, % and two
// hexadecimal digits is that byte, and any other % is itself.
func phpDecode(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '+':
			out = append(out, ' ')
		case s[i] == '%' && i+2 < len(s) && hexDigit(s[i+1]) && hexDigit(s[i+2]):
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
