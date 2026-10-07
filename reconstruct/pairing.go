package reconstruct

import (
	"errors"
	"fmt"
	"strings"

	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/http1"
	"github.com/evandukss/edge-observer/stream"
)

// ErrDirection is a part given for a direction that is neither sent nor
// received.
var ErrDirection = errors.New("a part is sent or received")

// Step is what one call to a Pairing did.
type Step struct {
	// Consumed is how many of the part's offsets the call accounted for, from
	// its first. It is less than the part's Length only at Refused; the rest is
	// fed again, from Next.
	Consumed uint64
	// Exchanges are those that became decidable in this call, in wire order, each
	// handed over with its Charge: the caller owns them, and the pairing never
	// touches them again.
	Exchanges []Exchange
	// Result is where the pairing stands after the call:
	//
	//   - NeedInput: the part was used up, and more exchanges may follow;
	//   - Refused: growth the Reserver refused, nothing of it retained, and the
	//     rest of the part is the caller's to feed again;
	//   - Malformed, Limit, Unsupported or Cut: the pairing has stopped, why it
	//     stopped, and the exchange that stopped it has been handed over, in this
	//     call or an earlier one. Nothing more is paired, and later parts are
	//     consumed as unplaced;
	//   - End: End was called, and whatever remained has been handed over.
	Result http1.Result
}

// Pairing reads one connection as its two directions arrive, one part at a
// time, and hands each response over with the request it answers once both are
// framed. It is what Run does for a connection already whole, done as the
// connection goes on.
//
// The side the observed process was on is decided as Run decides it, from what
// each direction begins with, and what arrives before anything can be read is
// held. Where one direction begins as a request or a response, reading starts
// on that basis; the other direction's beginning must then agree with it as
// Run would have it, or the connection is one neither direction of which is
// read (Unsupported, RoleUnknown) and nothing is handed over. An exchange needs
// both directions, so none is handed over before both have begun.
//
// Pairing:
//
//   - requests are kept in wire order, each with its method, and the i'th
//     response answers the i'th request. A response to HEAD carries no body
//     whatever it declares, so a response is framed only once the request it
//     answers is known;
//   - a response arriving before its request is held until the request comes,
//     with what it holds reserved like anything else it retains. A response
//     that is only delayed is never declared unpaired: an exchange is handed
//     over once both its messages are framed, or at End;
//   - each direction stops at its own defect (Malformed, Limit, Cut), at a body
//     only a close would end (Unsupported), and after an informational
//     response, a CONNECT request or a message carrying Upgrade (Unsupported).
//     The earliest exchange at which either direction stops is the last one:
//     each direction reads its message of that exchange as far as it can and
//     nothing after it, and that exchange is handed over with the stop as the
//     Result once both have. Nothing is read forward of a hole for a plausible
//     start line, and a body only a close would end is never framed.
//
// Input rules, each refused with an error and no change to the pairing: a part
// names a direction that is sent or received (ErrDirection), and within each
// direction the rules of http1.Parser hold (stream.ErrInvalidPart,
// http1.ErrOffset, http1.ErrEnded).
//
// A Pairing is not safe for concurrent use.
type Pairing struct {
	limits   Limits
	reserver http1.Reserver

	directions [3]direction

	// routed is whether a direction has begun as a request or a response, so the
	// parsers exist; decided whether the other direction's beginning has agreed,
	// and unread whether the connection is one neither direction of which is
	// read.
	routed, decided, unread bool
	role                    Role
	requests, responses     *side

	// base is the number of exchanges handed over, and methods the methods of the
	// requests from there on, as far as their heads have been read.
	base    int
	methods []string
	// limit is the earliest exchange at which either side stops, -1 while none
	// has, and why the stop's result. stop is that result once the exchange has
	// been handed over, NeedInput until then.
	limit int
	why   http1.Result
	stop  http1.Result

	ending, ended bool
	// examined counts the bytes looked at to decide the side, and the bytes the
	// parsers consumed.
	examined uint64
}

// direction is where one direction of the connection stands.
type direction struct {
	started     bool
	start, next uint64
	beginning   beginning
	// held is input that arrived before it could be read, in order: before the
	// side was decided, or while the response in progress waits on its request.
	held []held
	// settled is where the last message of this direction handed over ends.
	settled uint64
}

type held struct {
	part   stream.Part
	charge int64
}

// side is the requests or the responses of the connection.
type side struct {
	direction fragment.Direction
	parser    *http1.Parser
	// done is each message finished and not yet handed over, from base on.
	done []finished
	// headSeen is whether the request in progress has had its method recorded;
	// waiting whether the response in progress waits on the request it answers.
	headSeen, waiting bool
	// stopped is a side that reads nothing more; ended one whose input is over.
	stopped, ended bool
}

type finished struct {
	message *http1.Message
	charge  http1.Charge
}

// NewPairing returns a pairing for one connection, reading within these limits
// and asking reserver before it retains anything.
func NewPairing(limits Limits, reserver http1.Reserver) (*Pairing, error) {
	if reserver == nil {
		return nil, http1.ErrReserver
	}
	return &Pairing{limits: limits, reserver: reserver, limit: -1}, nil
}

// Feed reads the next part of one direction.
func (p *Pairing) Feed(d fragment.Direction, part stream.Part) (Step, error) {
	if err := p.admit(d, part); err != nil {
		return Step{}, err
	}
	at := &p.directions[d]
	if !at.started {
		at.started, at.start, at.next, at.settled = true, part.Offset, part.Offset, part.Offset
		at.beginning = beginning{prefix: true, space: -1, token: true}
	}
	if p.stopped() {
		at.next += part.Length
		return Step{Consumed: part.Length, Result: p.result()}, nil
	}

	// Earlier held input goes first; then this part; then whatever it unblocked.
	if p.pump() {
		return Step{Result: http1.Refused}, nil
	}
	consumed, refused := p.accept(d, part)
	if refused || p.pump() {
		return Step{Consumed: consumed, Result: http1.Refused}, nil
	}
	step := Step{Consumed: consumed}
	p.handOver(&step)
	step.Result = p.result()
	return step, nil
}

// admit checks a part against the input rules, changing nothing.
func (p *Pairing) admit(d fragment.Direction, part stream.Part) error {
	if d != fragment.Sent && d != fragment.Received {
		return fmt.Errorf("%w: %s", ErrDirection, d)
	}
	if p.ending {
		return http1.ErrEnded
	}
	if err := part.Validate(); err != nil {
		return err
	}
	if at := p.directions[d]; at.started && part.Offset != p.position(d) {
		return fmt.Errorf("%w: a %s part begins at %d and the direction stands at %d", http1.ErrOffset, d, part.Offset, p.position(d))
	}
	return nil
}

// position is where the next part of a direction begins. Within a call a
// parser can have consumed more than the pairing has recorded yet, so where
// its parser stands further on, that is the position.
func (p *Pairing) position(d fragment.Direction) uint64 {
	next := p.directions[d].next
	if s := p.sideOf(d); s != nil {
		if n, started := s.parser.Next(); started && n > next {
			next = n
		}
	}
	return next
}

func (p *Pairing) stopped() bool { return p.unread || p.stop != http1.NeedInput }

func (p *Pairing) result() http1.Result {
	if p.unread {
		return http1.Unsupported
	}
	return p.stop
}

func (p *Pairing) sideOf(d fragment.Direction) *side {
	switch {
	case !p.routed:
		return nil
	case p.requests.direction == d:
		return p.requests
	default:
		return p.responses
	}
}

// readable is a direction whose parser can be fed: the side is routed and the
// direction's own beginning is known, so what it is read as is settled.
func (p *Pairing) readable(d fragment.Direction) bool {
	return p.routed && !p.unread && p.directions[d].beginning.certain
}

// accept takes part, read or held, committing each byte it takes as it takes
// it, and reports how much it took and whether growth was refused.
func (p *Pairing) accept(d fragment.Direction, part stream.Part) (uint64, bool) {
	at := &p.directions[d]
	s := p.sideOf(d)
	if s != nil && s.stopped {
		at.next += part.Length
		return part.Length, false
	}
	if s == nil || !p.readable(d) || len(at.held) > 0 || s.waiting {
		if !p.hold(at, part) {
			return 0, true
		}
		at.next += part.Length
		if !at.beginning.certain {
			if part.Gap != stream.GapNone {
				at.beginning.close()
			} else {
				p.examined += uint64(at.beginning.take(part.Bytes))
			}
			p.decide()
		}
		return part.Length, false
	}

	rest, refused := p.read(s, part, func(n uint64) { at.next += n })
	if refused {
		return part.Length - rest.Length, true
	}
	if rest.Length > 0 {
		// The response in progress waits on its request: hold the rest.
		if !p.hold(at, rest) {
			return part.Length - rest.Length, true
		}
		at.next += rest.Length
	}
	return part.Length, false
}

// hold keeps a copy of part until it can be read, reserving its bytes first.
func (p *Pairing) hold(at *direction, part stream.Part) bool {
	charge := int64(len(part.Bytes))
	if charge > 0 && !p.reserver.Reserve(http1.Charge{Bytes: charge}) {
		return false
	}
	part.Bytes = append([]byte(nil), part.Bytes...)
	at.held = append(at.held, held{part: part, charge: charge})
	return true
}

// pump reads held input wherever it can now be read, until nothing more can
// be, and reports whether growth was refused.
func (p *Pairing) pump() bool {
	for moved := true; moved && p.routed && !p.stopped(); {
		moved = false
		p.answer()
		for _, s := range []*side{p.requests, p.responses} {
			at := &p.directions[s.direction]
			for len(at.held) > 0 && p.readable(s.direction) && !s.waiting && !s.stopped && !p.stopped() {
				moved = true
				_, refused := p.read(s, at.held[0].part, func(n uint64) {
					if len(at.held) > 0 {
						at.held[0].part = tail(at.held[0].part, n)
					}
				})
				if len(at.held) > 0 && at.held[0].part.Length == 0 {
					p.release(http1.Charge{Bytes: at.held[0].charge})
					at.held = at.held[1:]
				}
				if refused {
					return true
				}
				p.answer()
			}
		}
	}
	return false
}

// read feeds part to a side's parser until the part is used up, the side
// waits, the side stops, or growth is refused. advance commits what each call
// consumed as it is consumed. What is left is returned only where the side
// waits or growth was refused.
func (p *Pairing) read(s *side, part stream.Part, advance func(uint64)) (stream.Part, bool) {
	for part.Length > 0 && !s.waiting && !s.stopped {
		progress, err := s.parser.Feed(part)
		if err != nil {
			// The pairing feeds each parser contiguous parts that have passed the
			// input rules, so this is a defect in the pairing; stop the side rather
			// than read on a guess.
			p.finishSide(s, http1.Malformed)
			break
		}
		if part.Gap == stream.GapNone {
			p.examined += progress.Consumed
		}
		part = tail(part, progress.Consumed)
		advance(progress.Consumed)
		switch progress.Result {
		case http1.Refused:
			return part, true
		case http1.Head:
			p.head(s, progress.Message)
		case http1.Framed, http1.Malformed, http1.Limit, http1.Unsupported, http1.Cut:
			if progress.Message != nil {
				p.finish(s, progress)
			}
		case http1.NeedRequest:
			s.waiting = true
		}
	}
	if s.stopped && part.Length > 0 {
		// What follows the side's last message is unplaced.
		advance(part.Length)
		part = tail(part, part.Length)
	}
	return part, false
}

// head is a message whose field section has been read: a request's method is
// the context its response needs, and a response is answered once its request
// is known.
func (p *Pairing) head(s *side, m *http1.Message) {
	i := p.base + len(s.done)
	if s == p.requests {
		p.methods = append(p.methods, m.Method)
		s.headSeen = true
		p.boundary(i, m, true)
		return
	}
	p.boundary(i, m, false)
	s.waiting = true
	p.answer()
}

// answer frames the response in progress once the request it answers is
// known, or, once no request is to come, by its own fields.
func (p *Pairing) answer() {
	s := p.responses
	if s == nil || !s.waiting || s.stopped {
		return
	}
	// The response in progress answers the request at the same index; methods
	// begins at base, as done does.
	j := len(s.done)
	method := ""
	switch {
	case j < len(p.methods):
		method = p.methods[j]
	case !p.requests.ended:
		return
	}
	s.waiting = false
	progress, err := s.parser.Answer(method)
	if err == nil && progress.Message != nil {
		p.finish(s, progress)
	}
}

// boundary is where pairing stops at an informational response, a CONNECT
// request or a message carrying Upgrade: the message itself is read to its
// end, and nothing after its exchange.
func (p *Pairing) boundary(i int, m *http1.Message, request bool) {
	upgrade := false
	for _, h := range m.Headers {
		if strings.EqualFold(h.Name, "upgrade") {
			upgrade = true
		}
	}
	if upgrade || (request && strings.EqualFold(m.Method, "CONNECT")) || (!request && m.Status < 200) {
		p.setLimit(i, http1.Unsupported, request)
	}
}

// finish takes a message a side's parser handed over.
func (p *Pairing) finish(s *side, progress http1.Progress) {
	i := p.base + len(s.done)
	s.done = append(s.done, finished{message: progress.Message, charge: progress.Charge})
	if s == p.requests {
		if !s.headSeen {
			p.methods = append(p.methods, progress.Message.Method)
			p.boundary(i, progress.Message, true)
		}
		s.headSeen = false
	}
	if progress.Result.Stopped() {
		p.setLimit(i, progress.Result, s == p.requests)
	}
	if p.limit >= 0 && i >= p.limit {
		p.stopSide(s)
	}
}

// finishSide stops a side whose parser cannot go on.
func (p *Pairing) finishSide(s *side, why http1.Result) {
	p.setLimit(p.base+len(s.done), why, s == p.requests)
	p.stopSide(s)
}

// setLimit records a stop at exchange i. The earliest stop wins, and of two at
// one exchange the request's, so the outcome does not depend on which
// direction arrived first. What either side read past it is let go.
func (p *Pairing) setLimit(i int, why http1.Result, request bool) {
	if p.limit >= 0 && (i > p.limit || (i == p.limit && !request)) {
		return
	}
	p.limit, p.why = i, why
	keep := i - p.base + 1
	for _, s := range []*side{p.requests, p.responses} {
		if len(s.done) > keep {
			for _, f := range s.done[keep:] {
				p.release(f.charge)
			}
			s.done = s.done[:keep]
		}
		if p.base+len(s.done) > i {
			p.stopSide(s)
		}
	}
	if len(p.methods) > keep {
		p.methods = p.methods[:keep]
	}
}

// stopSide makes a side read nothing more, letting go of the message it had in
// progress and of its held input.
func (p *Pairing) stopSide(s *side) {
	if s.stopped {
		return
	}
	s.stopped, s.waiting = true, false
	p.release(s.parser.Retained())
	at := &p.directions[s.direction]
	for _, h := range at.held {
		p.release(http1.Charge{Bytes: h.charge})
	}
	at.held = nil
}

func (p *Pairing) release(c http1.Charge) {
	if !c.IsZero() {
		p.reserver.Release(c)
	}
}

// handOver hands over each exchange both of whose messages are finished, in
// wire order, and the exchange at the limit once both sides are done with it.
func (p *Pairing) handOver(step *Step) {
	if !p.decided || p.stopped() {
		return
	}
	for {
		requested, answered := len(p.requests.done) > 0, len(p.responses.done) > 0
		if p.limit >= 0 && p.base == p.limit {
			if (requested || p.requests.ended) && (answered || p.responses.ended) {
				step.Exchanges = append(step.Exchanges, p.pop())
				p.stopAll()
			}
			return
		}
		if !requested || !answered {
			return
		}
		step.Exchanges = append(step.Exchanges, p.pop())
	}
}

// pop hands over the exchange at base.
func (p *Pairing) pop() Exchange {
	var e Exchange
	for _, s := range []*side{p.requests, p.responses} {
		if len(s.done) == 0 {
			continue
		}
		f := s.done[0]
		s.done = s.done[1:]
		m := read(*f.message, p.limits.JSON)
		if s == p.requests {
			e.Request = m
		} else {
			e.Response = m
		}
		e.Charge = e.Charge.Add(f.charge)
		p.directions[s.direction].settled = f.message.End
	}
	if len(p.methods) > 0 {
		p.methods = p.methods[1:]
	}
	e.Complete = e.Request != nil && e.Request.Complete && e.Response != nil && e.Response.Complete
	p.base++
	return e
}

// stopAll ends the pairing after the exchange at the limit.
func (p *Pairing) stopAll() {
	p.stop = p.why
	p.stopSide(p.requests)
	p.stopSide(p.responses)
}

// decide reads the side off what the directions began with, as Run does.
func (p *Pairing) decide() {
	if p.decided {
		return
	}
	out, in := p.directions[fragment.Sent].beginning, p.directions[fragment.Received].beginning
	if !p.routed {
		switch {
		case out.certain && out.what == opensSomethingElse:
			// Run reads no connection whose process writes neither.
			p.markUnread()
			return
		case out.certain && out.what == opensRequest, in.certain && in.what == opensResponse:
			p.route(fragment.Sent)
		case out.certain && out.what == opensResponse, in.certain && in.what == opensRequest:
			p.route(fragment.Received)
		case out.certain && in.certain:
			p.markUnread()
			return
		default:
			return
		}
	}
	if out.certain && in.certain {
		if roleFrom(out.what, in.what) != p.role {
			p.markUnread()
			return
		}
		p.decided = true
	}
}

// route starts reading with requests on one direction.
func (p *Pairing) route(requests fragment.Direction) {
	responses := fragment.Sent
	p.role = Server
	if requests == fragment.Sent {
		responses, p.role = fragment.Received, Client
	}
	p.routed = true
	request, _ := http1.NewParser(http1.Request, p.limits.HTTP, p.reserver)
	response, _ := http1.NewParser(http1.Response, p.limits.HTTP, p.reserver)
	p.requests = &side{direction: requests, parser: request}
	p.responses = &side{direction: responses, parser: response}
}

// markUnread is a connection neither direction of which is read: everything
// held is let go, and every offset is unplaced.
func (p *Pairing) markUnread() {
	p.unread, p.decided, p.role = true, true, RoleUnknown
	if p.routed {
		for _, s := range []*side{p.requests, p.responses} {
			for _, f := range s.done {
				p.release(f.charge)
			}
			s.done = nil
			p.stopSide(s)
		}
		p.methods = nil
	}
	for d := range p.directions {
		at := &p.directions[d]
		for _, h := range at.held {
			p.release(http1.Charge{Bytes: h.charge})
		}
		at.held = nil
	}
}

// End declares the connection's input finished, both directions: what remains
// is handed over, an exchange missing a message or a byte as incomplete, and
// the Result is End. Finishing can need growth - a response held for a request
// that never came is framed by its own fields and read - and where the
// Reserver refuses it, End returns Refused, hands over nothing it has not
// finished, and can be called again. A later End hands over nothing.
func (p *Pairing) End() Step {
	if p.ended {
		return Step{Result: http1.End}
	}
	p.ending = true
	if p.stopped() {
		p.ended = true
		return Step{Result: http1.End}
	}
	for d := fragment.Sent; d <= fragment.Received; d++ {
		at := &p.directions[d]
		if !at.started {
			at.beginning = beginning{what: opensNothing, certain: true}
		}
		at.beginning.close()
	}
	p.decide()
	if p.unread {
		p.ended = true
		return Step{Result: http1.End}
	}

	if p.pump() {
		return Step{Result: http1.Refused}
	}
	if !p.requests.ended {
		p.requests.ended = true
		if !p.requests.stopped {
			if progress := p.requests.parser.End(); progress.Message != nil {
				p.finish(p.requests, progress)
			}
		}
	}
	// Responses no request is to come for are framed by their own fields.
	for {
		p.answer()
		if p.pump() {
			return Step{Result: http1.Refused}
		}
		if !p.responses.waiting || p.responses.stopped {
			break
		}
	}
	if !p.responses.ended {
		p.responses.ended = true
		if !p.responses.stopped {
			if progress := p.responses.parser.End(); progress.Message != nil {
				p.finish(p.responses, progress)
			}
		}
	}

	var step Step
	for !p.stopped() && (len(p.requests.done) > 0 || len(p.responses.done) > 0) {
		last := p.limit >= 0 && p.base == p.limit
		step.Exchanges = append(step.Exchanges, p.pop())
		if last {
			p.stopAll()
		}
	}
	p.ended = true
	step.Result = http1.End
	return step
}

// Role is the side the observed process was on once what the directions began
// with decides it as Run would, and RoleUnknown and false until then.
func (p *Pairing) Role() (Role, bool) {
	if !p.decided {
		return RoleUnknown, false
	}
	return p.role, true
}

// Next is the offset the next part of a direction must begin at, and false
// before its first part, when any offset is accepted.
func (p *Pairing) Next(d fragment.Direction) (uint64, bool) {
	if d != fragment.Sent && d != fragment.Received {
		return 0, false
	}
	return p.position(d), p.directions[d].started
}

// Retained is what the pairing holds now and has not handed over: both
// parsers' state, the requests waiting on their responses, and input held
// until it can be read.
func (p *Pairing) Retained() http1.Charge {
	var c http1.Charge
	for _, at := range p.directions {
		for _, h := range at.held {
			c.Bytes += h.charge
		}
	}
	if p.routed {
		for _, s := range []*side{p.requests, p.responses} {
			if !s.stopped {
				c = c.Add(s.parser.Retained())
			}
			for _, f := range s.done {
				c = c.Add(f.charge)
			}
		}
	}
	return c
}

// Unplaced is how many offsets of a direction were never read as part of a
// message handed over: after the point it stopped, or, for a connection
// neither direction of which is read, all of them.
func (p *Pairing) Unplaced(d fragment.Direction) uint64 {
	if (d != fragment.Sent && d != fragment.Received) || (!p.stopped() && !p.ended) {
		return 0
	}
	return p.position(d) - p.directions[d].settled
}

func tail(part stream.Part, n uint64) stream.Part {
	part.Offset, part.Length = part.Offset+n, part.Length-n
	if part.Gap == stream.GapNone {
		part.Bytes = part.Bytes[n:]
	}
	return part
}

// openingWindow is how many bytes of a direction Run looks at to see what it
// begins with.
const openingWindow = 32

// beginning is what a direction begins with, read as its bytes arrive by the
// rules opening applies to the first openingWindow of them: certain as soon
// as no later byte could change it, or once the window closes at its last
// byte, a hole or the end.
type beginning struct {
	n int
	// prefix is whether the bytes so far begin as "HTTP/" does; space is where
	// the first space is, -1 before one; token whether every byte before it is
	// a token byte.
	prefix  bool
	space   int
	token   bool
	what    opener
	certain bool
}

// take reads bytes into the window until what the direction begins with is
// certain, and reports how many it looked at.
func (b *beginning) take(in []byte) int {
	examined := 0
	for _, c := range in {
		if b.certain {
			break
		}
		i := b.n
		b.n++
		examined++
		if i < 5 {
			b.prefix = b.prefix && c == "HTTP/"[i]
		}
		if b.space < 0 {
			if c == ' ' {
				b.space = i
			} else if !isTokenByte(c) {
				b.token = false
			}
		}
		switch {
		case b.n >= 5 && b.prefix, b.space >= 0, !b.token && (b.n >= 5 || !b.prefix), b.n == openingWindow:
			b.close()
		}
	}
	return examined
}

// close decides what the direction begins with from the bytes seen.
func (b *beginning) close() {
	if b.certain {
		return
	}
	switch {
	case b.n >= 5 && b.prefix:
		b.what = opensResponse
	case b.space > 0 && b.token:
		b.what = opensRequest
	default:
		b.what = opensSomethingElse
	}
	b.certain = true
}
