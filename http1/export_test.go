package http1

import (
	"fmt"
	"strings"
)

// Examined is how many bytes p has looked at, counting a byte each time it is
// looked at: what a test reads to show that new input costs work in proportion
// to itself and never a rescan of what came before.
func Examined(p *Parser) uint64 { return p.examined }

// Snapshot renders everything p keeps between calls, so two snapshots of one
// parser are equal exactly when nothing it keeps has changed: what a test
// reads to show that a refused reservation left the parser as it was.
func Snapshot(p *Parser) string {
	var b strings.Builder
	fmt.Fprintf(&b, "kind=%s started=%t next=%d ended=%t stop=%s settled=%d phase=%d charge=%+v",
		p.kind, p.started, p.next, p.ended, p.stop, p.settled, p.phase, p.charge)
	fmt.Fprintf(&b, " line=%q sawCR=%t headerBytes=%d remaining=%d chunks=%d", p.line, p.sawCR, p.headerBytes, p.remaining, p.chunks)
	fmt.Fprintf(&b, " chunk=%d+%d kept=%d holed=%d elided=%d end=%d/%q",
		p.chunkStart, p.chunkSize, p.chunkKept, p.chunkHoled, p.chunkElided, p.endSeen, p.endFirst)
	if m := p.message; m != nil {
		fmt.Fprintf(&b, " message={%s %q %q %q %d %q %q", m.Kind, m.Method, m.Target, m.Protocol, m.Status, m.Reason, m.Headers)
		fmt.Fprintf(&b, " %s body=%q %d/%d/%d %q", m.Framing, m.Body, m.BodyLength, m.BodyHoled, m.BodyElided, m.Trailers)
		fmt.Fprintf(&b, " %t %t %s %q %d-%d}", m.Complete, m.Framed, m.Defect, m.Detail, m.Offset, m.End)
	}
	return b.String()
}
