package reconstruct

import (
	"fmt"
	"strings"

	"github.com/evandukss/edge-observer/fragment"
)

// Examined is how many bytes p has looked at, over both directions: the bytes
// it read to decide the side, and every byte its parsers consumed. What a test
// reads to show that new input costs work in proportion to itself.
func Examined(p *Pairing) uint64 { return p.examined }

// Snapshot renders everything p keeps between calls, so two snapshots of one
// pairing are equal exactly when nothing it keeps has changed: what a test
// reads to show that a refused reservation left the pairing as it was. Of each
// parser it renders what the parser reports of itself, its position and what
// it retains; the parser's own snapshot is http1's.
func Snapshot(p *Pairing) string {
	var b strings.Builder
	fmt.Fprintf(&b, "routed=%t decided=%t unread=%t role=%s base=%d methods=%q limit=%d why=%s stop=%s ending=%t ended=%t",
		p.routed, p.decided, p.unread, p.role, p.base, p.methods, p.limit, p.why, p.stop, p.ending, p.ended)
	for d := fragment.Sent; d <= fragment.Received; d++ {
		at := p.directions[d]
		// What is held renders from where the parser stands, which within a call
		// can be ahead of what the pairing has recorded of it.
		read := uint64(0)
		if s := p.sideOf(d); s != nil {
			read, _ = s.parser.Next()
		}
		fmt.Fprintf(&b, "\ndirection %d started=%t start=%d position=%d settled=%d beginning=%+v held=[", d, at.started, at.start, p.position(d), at.settled, at.beginning)
		for _, h := range at.held {
			part := h.part
			if read > part.Offset {
				if read >= part.Offset+part.Length {
					continue
				}
				part = tail(part, read-part.Offset)
			}
			fmt.Fprintf(&b, "{%d+%d %s %q charge=%d}", part.Offset, part.Length, part.Gap, part.Bytes, h.charge)
		}
		b.WriteString("]")
	}
	if p.routed {
		for _, s := range []*side{p.requests, p.responses} {
			next, started := s.parser.Next()
			fmt.Fprintf(&b, "\nside %d headSeen=%t waiting=%t stopped=%t ended=%t parser{next=%d %t retained=%+v unplaced=%d} done=[",
				s.direction, s.headSeen, s.waiting, s.stopped, s.ended, next, started, s.parser.Retained(), s.parser.Unplaced())
			for _, f := range s.done {
				m := f.message
				fmt.Fprintf(&b, "{%q %d-%d %s complete=%t charge=%+v}", m.StartLine(), m.Offset, m.End, m.Defect, m.Complete, f.charge)
			}
			b.WriteString("]")
		}
	}
	return b.String()
}
