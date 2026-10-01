// Package workload generates intake entries for tests and benchmarks: HTTP/1.1
// connections described by a few parameters and a seed, the same entries for
// the same parameters and seed.
//
// The entries are captured, not authored. A real capture session receives
// synthetic library events (one per transfer, and one ending per connection)
// and the fragments and connection records it writes are the workload, so
// identity, sequence, placement and connection numbering are capture's own.
// Nothing is attached and no kernel is involved.
package workload

import (
	"cmp"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/contract/config"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

// Defects a connection can carry, at most one each. A defect affects one
// exchange; the exchanges before it are untouched.
const (
	// DefectHole is a transfer capture kept only the first half of, so the
	// stream has a hole from there on.
	DefectHole = "hole"
	// DefectMalformed is a request whose start line is not HTTP.
	DefectMalformed = "malformed"
	// DefectUnsupported is a response with a content encoding processing does
	// not decode.
	DefectUnsupported = "unsupported"
	// DefectIncomplete is a connection that ends halfway through a response.
	// No exchange follows it.
	DefectIncomplete = "incomplete"
)

// Defects lists every defect, in the order a seed chooses among them.
var Defects = []string{DefectHole, DefectMalformed, DefectUnsupported, DefectIncomplete}

// Shape is what a workload holds. Zero values are the smallest workload of
// that kind: one process, connections one after another, no headers beyond
// Host and framing, no bodies, no JSON, no defects, no reordering.
type Shape struct {
	// Connections is how many connections there are, at least 1.
	Connections int
	// Exchanges is how many request and response pairs each connection
	// carries, at least 1. A defect can end a connection before its last one.
	Exchanges int
	// HeaderBytes is the size of the header lines each request and each
	// response carries beyond its start line, Host and framing headers.
	HeaderBytes int
	// RequestBodyBytes and ResponseBodyBytes are body sizes. A request
	// without a body is a GET, with one a POST.
	RequestBodyBytes  int
	ResponseBodyBytes int
	// JSONShare is the fraction of bodies, 0 to 1, that are JSON objects
	// labelled application/json; the others are text.
	JSONShare float64
	// DefectShare is the fraction of connections, 0 to 1, that carry one
	// defect, its kind and the exchange it hits chosen by the seed.
	DefectShare float64
	// DefectKinds are the defects the seed chooses among, each one of
	// Defects. Empty means all of Defects.
	DefectKinds []string
	// Processes is how many processes the connections are spread over, at
	// least 1 (0 means 1).
	Processes int
	// Concurrency is how many connections are in progress at once, their
	// transfers interleaved by the seed (0 means 1: one after another).
	Concurrency int
	// ReorderShare is the fraction of connections, 0 to 1, whose connection
	// record is delivered before their last fragment, as concurrent capture
	// callbacks can deliver them.
	ReorderShare float64
	// Seed chooses everything the parameters leave open.
	Seed uint64
}

// Entry is one intake entry: exactly one of Fragment and Connection is set.
type Entry struct {
	Fragment   *fragment.Record
	Connection *connection.Record
}

// Connection is what one generated connection holds.
type Connection struct {
	ID      fragment.ConnectionID
	Process fragment.Process
	// Exchanges is how many requests were sent on it, including the one a
	// defect hit.
	Exchanges int
	// Defect is one of Defects, or empty.
	Defect string
	// DefectAt is the index of the exchange the defect hit, where Defect is set.
	DefectAt int
}

// Workload is a generated set of intake entries in the order capture's
// callbacks delivered them.
type Workload struct {
	Shape       Shape
	Entries     []Entry
	Connections []Connection
	// Exchanges is the requests sent across all connections.
	Exchanges int
}

// Sink takes intake entries. *intake.Store is one.
type Sink interface {
	Write(fragment.Record) error
	Connection(connection.Record) error
}

// Write hands every entry to sink in order and returns how many it accepted
// before the first refusal, with that refusal.
func (w *Workload) Write(sink Sink) (int, error) {
	for n, e := range w.Entries {
		var err error
		if e.Fragment != nil {
			err = sink.Write(*e.Fragment)
		} else {
			err = sink.Connection(*e.Connection)
		}
		if err != nil {
			return n, err
		}
	}
	return len(w.Entries), nil
}

// Generate builds the workload of shape. The same shape, seed included,
// always yields the same entries.
func Generate(shape Shape) (*Workload, error) {
	if shape.Connections < 1 || shape.Exchanges < 1 {
		return nil, errors.New("workload needs at least one connection and one exchange")
	}
	if shape.HeaderBytes < 0 || shape.RequestBodyBytes < 0 || shape.ResponseBodyBytes < 0 || shape.Processes < 0 || shape.Concurrency < 0 {
		return nil, errors.New("workload sizes and counts cannot be negative")
	}
	for _, share := range []float64{shape.JSONShare, shape.DefectShare, shape.ReorderShare} {
		if !(share >= 0 && share <= 1) {
			return nil, errors.New("workload shares are between 0 and 1")
		}
	}
	for _, kind := range shape.DefectKinds {
		if !slices.Contains(Defects, kind) {
			return nil, fmt.Errorf("workload has no defect %q", kind)
		}
	}
	g := &generator{shape: shape, random: rand.New(rand.NewPCG(shape.Seed, 0x6f62736572766572))}
	g.session = capture.Recording(g, g)
	return g.run(), nil
}

type generator struct {
	shape   Shape
	random  *rand.Rand
	session *capture.Session
	stamp   uint64
	entries []Entry
}

func (g *generator) Write(r fragment.Record) error {
	r.Payload = slices.Clone(r.Payload)
	g.entries = append(g.entries, Entry{Fragment: &r})
	return nil
}

func (g *generator) Connection(r connection.Record) error {
	g.entries = append(g.entries, Entry{Connection: &r})
	return nil
}

// transfer is one library call of a script: length bytes in one direction, of
// which capture keeps payload.
type transfer struct {
	direction fragment.Direction
	payload   []byte
	length    int
}

type script struct {
	process   int
	endpoint  uint64
	transfers []transfer
	next      int
	plan      Connection
}

var base = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

func (g *generator) run() *Workload {
	processes := max(g.shape.Processes, 1)
	scripts := make([]*script, g.shape.Connections)
	for c := range scripts {
		scripts[c] = g.script(c, g.random.IntN(processes))
	}
	concurrency := max(g.shape.Concurrency, 1)
	var active []*script
	pending := scripts
	for len(active) > 0 || len(pending) > 0 {
		for len(active) < concurrency && len(pending) > 0 {
			active = append(active, pending[0])
			pending = pending[1:]
		}
		i := g.random.IntN(len(active))
		s := active[i]
		if s.next < len(s.transfers) {
			g.send(s, s.transfers[s.next])
			s.next++
			continue
		}
		g.stamp++
		p, instance := identity(s.process)
		g.session.Closed(probe.Connection{Process: p, Instance: instance, Stamp: g.stamp, Endpoint: s.endpoint, At: g.at()})
		active = slices.Delete(active, i, i+1)
	}
	w := &Workload{Shape: g.shape, Entries: g.entries}
	for _, s := range scripts {
		w.Exchanges += s.plan.Exchanges
	}
	// Capture numbers a connection at its first transfer, so the plans learn
	// their ids from the records it wrote.
	ids := map[uint64]fragment.ConnectionID{}
	for _, e := range g.entries {
		if r := e.Connection; r != nil {
			ids[r.Handle.Address] = r.ID
		}
	}
	for _, s := range scripts {
		s.plan.ID = ids[s.endpoint]
		w.Connections = append(w.Connections, s.plan)
	}
	slices.SortFunc(w.Connections, func(a, b Connection) int { return cmp.Compare(a.ID, b.ID) })
	g.reorder(w)
	return w
}

// reorder moves a connection's record before its last fragment for the share
// of connections the shape asks, chosen by the seed.
func (g *generator) reorder(w *Workload) {
	for _, c := range w.Connections {
		if g.random.Float64() >= g.shape.ReorderShare {
			continue
		}
		last, ending := -1, -1
		for n, e := range w.Entries {
			if e.Fragment != nil && e.Fragment.Connection == c.ID {
				last = n
			}
			if e.Connection != nil && e.Connection.ID == c.ID {
				ending = n
			}
		}
		if last < 0 || ending < last {
			continue
		}
		moved := w.Entries[ending]
		w.Entries = slices.Delete(w.Entries, ending, ending+1)
		w.Entries = slices.Insert(w.Entries, last, moved)
	}
}

func (g *generator) at() time.Time { return base.Add(time.Duration(g.stamp) * time.Microsecond) }

func (g *generator) send(s *script, t transfer) {
	g.stamp++
	p, instance := identity(s.process)
	g.session.Transfer(probe.Transfer{Process: p, Instance: instance, Endpoint: s.endpoint, Direction: t.direction,
		Measured: true, Length: uint32(t.length), Payload: t.payload, Stamp: g.stamp, At: g.at()})
}

func identity(process int) (fragment.Process, admission.Instance) {
	pid := int32(1000 + process)
	start := uint64(5000 + process)
	return fragment.Process{PID: pid, StartTime: start}, admission.Instance{
		Namespace: admission.Namespace{Device: 1, Inode: 4026531836}, PID: pid,
		Start: admission.Determinate(admission.BootTicks(start)), Generation: 1}
}

// script plans connection c: its exchanges, any defect, and the library calls
// that carry them, each at most capture's per-event payload ceiling.
func (g *generator) script(c, process int) *script {
	s := &script{process: process, endpoint: 0x10000 + uint64(c)*0x100}
	p, _ := identity(process)
	s.plan.Process = p
	defectAt := -1
	if g.random.Float64() < g.shape.DefectShare {
		kinds := Defects
		if len(g.shape.DefectKinds) != 0 {
			kinds = g.shape.DefectKinds
		}
		s.plan.Defect = kinds[g.random.IntN(len(kinds))]
		defectAt = g.random.IntN(g.shape.Exchanges)
		s.plan.DefectAt = defectAt
	}
	for n := range g.shape.Exchanges {
		s.plan.Exchanges++
		request := g.message(c, n, true, n == defectAt && s.plan.Defect == DefectMalformed, false)
		response := g.message(c, n, false, false, n == defectAt && s.plan.Defect == DefectUnsupported)
		g.split(s, fragment.Sent, request, n == defectAt && s.plan.Defect == DefectHole)
		if n == defectAt && s.plan.Defect == DefectIncomplete {
			g.split(s, fragment.Received, response[:len(response)/2], false)
			break
		}
		g.split(s, fragment.Received, response, false)
	}
	return s
}

func (g *generator) split(s *script, direction fragment.Direction, message []byte, hole bool) {
	ceiling := int(config.MaxEventPayloadBytes)
	for len(message) > 0 {
		n := min(len(message), ceiling)
		t := transfer{direction: direction, payload: message[:n], length: n}
		if hole {
			// Only the first transfer of the message loses its tail.
			t.payload = message[:n/2]
			hole = false
		}
		s.transfers = append(s.transfers, t)
		message = message[n:]
	}
}

// message is one request or response of exchange n on connection c.
func (g *generator) message(c, n int, request, malformed, encoded bool) []byte {
	size := g.shape.ResponseBodyBytes
	if request {
		size = g.shape.RequestBodyBytes
	}
	json := size >= 2 && g.random.Float64() < g.shape.JSONShare
	body := g.body(size, json)
	var b strings.Builder
	switch {
	case malformed:
		b.WriteString("\x01\x02 not a request line\r\n")
	case request && size == 0:
		fmt.Fprintf(&b, "GET /items/%d/%d HTTP/1.1\r\n", c, n)
	case request:
		fmt.Fprintf(&b, "POST /items/%d/%d HTTP/1.1\r\n", c, n)
	default:
		b.WriteString("HTTP/1.1 200 OK\r\n")
	}
	if request {
		b.WriteString("Host: service.example\r\n")
	}
	g.headers(&b)
	if size > 0 {
		if json {
			b.WriteString("Content-Type: application/json\r\n")
		} else {
			b.WriteString("Content-Type: text/plain\r\n")
		}
	}
	if encoded {
		b.WriteString("Content-Encoding: gzip\r\n")
	}
	if size > 0 || !request {
		b.WriteString("Content-Length: " + strconv.Itoa(size) + "\r\n")
	}
	b.WriteString("\r\n")
	b.Write(body)
	return []byte(b.String())
}

// headers writes header lines totalling HeaderBytes, line endings included, in
// lines of at most about 80 bytes. Where what is left cannot hold one more
// line, the total falls short by that remainder, under 16 bytes.
func (g *generator) headers(b *strings.Builder) {
	left := g.shape.HeaderBytes
	for i := 1; left > 0; i++ {
		name := fmt.Sprintf("X-Field-%d: ", i)
		overhead := len(name) + 2
		if left <= overhead {
			return
		}
		value := min(left-overhead, 64)
		b.WriteString(name)
		b.Write(g.text(value))
		b.WriteString("\r\n")
		left -= overhead + value
	}
}

func (g *generator) body(size int, json bool) []byte {
	if !json {
		return g.text(size)
	}
	id := strconv.Itoa(g.random.IntN(1_000_000))
	skeleton := `{"id":` + id + `,"text":""}`
	if len(skeleton) > size {
		// Too small for the object with text: an object padded with spaces.
		return append([]byte("{}"), []byte(strings.Repeat(" ", size-2))...)
	}
	return []byte(`{"id":` + id + `,"text":"` + string(g.text(size-len(skeleton))) + `"}`)
}

func (g *generator) text(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte('a' + g.random.IntN(26))
	}
	return out
}
