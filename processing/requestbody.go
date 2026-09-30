package processing

import (
	"strings"

	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/reconstruct"
)

// requestBody applies request-body-fields to one request body. The grammar is
// chosen from the bytes and from the message as parsed, so a header operation
// earlier in the route changes nothing here. A body goes to a grammar's rules
// only where that grammar's own operation would read it, and where the two
// could disagree it is removed whole, so this never decides less than either
// operation decides alone:
//
//	strictly valid JSON, no Content-Type naming a form media type -> the JSON rules
//	strictly valid JSON, some Content-Type naming one             -> removed whole
//	not strictly valid JSON, admitted as urlencoded               -> the form rules
//	anything else                                                 -> removed whole
func (r *slotRun) requestBody(m, parsed *reconstruct.Message, a *config.Arguments, where PolicyExclusion) {
	_, _, err := editJSON(m.Body, nil, nil)
	valid := err == nil
	switch {
	case valid && !namesFormMediaType(parsed):
		r.requestJSON(m, a, where)
	case !valid && admittedForm(parsed):
		body, matched, undecidable := removeParameters(string(m.Body), a.Names)
		if undecidable {
			r.removeBody(m, where, DispositionRemovedUndecidable)
			return
		}
		r.spliced(m, []byte(body), matched, config.FormFieldPrefix, where)
	default:
		r.removeBody(m, where, DispositionRemovedUndecidable)
	}
}

// requestJSON removes, then masks, on a body already known to be strictly
// valid JSON, recording each removal as remove-json-fields records it.
func (r *slotRun) requestJSON(m *reconstruct.Message, a *config.Arguments, where PolicyExclusion) {
	if len(a.Pointers) > 0 {
		body, hits, err := editJSON(m.Body, a.Pointers, nil)
		if err != nil {
			r.removeBody(m, where, DispositionRemovedUndecidable)
			return
		}
		var matched []string
		for i, hit := range hits {
			if hit {
				matched = append(matched, a.Pointers[i])
			}
		}
		r.spliced(m, body, matched, config.JSONFieldPrefix, where)
	}
	for _, mask := range a.Masks {
		body, _, err := editJSON(m.Body, []string{mask.Pointer}, jsonString(mask.Value))
		if err != nil {
			r.removeBody(m, where, DispositionRemovedUndecidable)
			return
		}
		// A replaced value is not a removal and records no entry.
		r.spliced(m, body, nil, config.JSONFieldPrefix, where)
	}
}

// namesFormMediaType is whether any Content-Type field of the message as
// parsed, in its headers or its trailers, mentions a form media type anywhere
// in its value. It is broad on purpose: a body under such a label is one an
// application may read as a form, whatever else the label says.
func namesFormMediaType(m *reconstruct.Message) bool {
	for _, fields := range [][]http1.Header{m.Headers, m.Trailers} {
		for _, h := range fields {
			if !strings.EqualFold(h.Name, "content-type") {
				continue
			}
			value := strings.ToLower(h.Value)
			if strings.Contains(value, "application/x-www-form-urlencoded") || strings.Contains(value, "multipart/form-data") {
				return true
			}
		}
	}
	return false
}
