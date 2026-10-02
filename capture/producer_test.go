package capture_test

import (
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
)

// producer stands in for the kernel producer's numbering in front of a capture
// session: a transfer handed on with no sequence of its own is numbered in its
// handle's occupancy and direction, as the program numbers it, an ending carries
// the numbers taken, and once production stops the producer answers for the
// occupancies it still holds. A transfer that carries a sequence is handed on as
// it is, which is how a case builds a gap.
type producer struct {
	*capture.Session

	occupancies map[probe.Handle]uint64
	numbers     map[numbered]uint64
	next        uint64
}

type numbered struct {
	handle    probe.Handle
	direction fragment.Direction
}

// produced is a recording session behind a producer that settles it.
func produced(sink capture.Sink, records connection.Sink, options ...capture.Option) *producer {
	p := &producer{occupancies: make(map[probe.Handle]uint64), numbers: make(map[numbered]uint64)}
	p.Session = capture.Recording(sink, records, append(options, capture.Settles(p))...)
	return p
}

func handleOf(t probe.Transfer) probe.Handle {
	return probe.Handle{Instance: t.Instance.Key(), Endpoint: t.Endpoint}
}

// Transfer numbers a transfer that carries no sequence and hands it on. A call
// the program measured as moving nothing takes no number. A transfer carrying
// its own sequence is recorded as what the producer holds, so the producer
// settles it as it settles one it numbered.
func (p *producer) Transfer(t probe.Transfer) {
	if t.Sequence.Occupancy != 0 {
		handle := handleOf(t)
		p.occupancies[handle] = t.Sequence.Occupancy
		key := numbered{handle: handle, direction: t.Direction}
		p.numbers[key] = max(p.numbers[key], t.Sequence.Number)
	}
	if t.Sequence == (probe.Sequence{}) {
		handle := handleOf(t)
		id, held := p.occupancies[handle]
		if !held {
			p.next++
			id = p.next
			p.occupancies[handle] = id
		}
		t.Sequence = probe.Sequence{Occupancy: id, Born: true}
		if !t.Measured || t.Length != 0 {
			key := numbered{handle: handle, direction: t.Direction}
			p.numbers[key]++
			t.Sequence.Number = p.numbers[key]
		}
	}
	p.Session.Transfer(t)
}

// final is what the producer holds for a handle's occupancy.
func (p *producer) final(handle probe.Handle) probe.Final {
	return probe.Final{
		Known:    true,
		Sent:     probe.Terminal{Last: p.numbers[numbered{handle: handle, direction: fragment.Sent}]},
		Received: probe.Terminal{Last: p.numbers[numbered{handle: handle, direction: fragment.Received}]},
	}
}

// Closed hands on an ending carrying the numbers its occupancy took, which
// settles its tail, and ends the occupancy. An ending that carries its own
// sequence or final is handed on as it is.
func (p *producer) Closed(c probe.Connection) {
	if c.Sequence == (probe.Sequence{}) && !c.Final.Known {
		handle := probe.Handle{Instance: c.Instance.Key(), Endpoint: c.Endpoint}
		if id, held := p.occupancies[handle]; held {
			c.Sequence = probe.Sequence{Occupancy: id, Born: true}
			c.Final = p.final(handle)
			delete(p.occupancies, handle)
			delete(p.numbers, numbered{handle: handle, direction: fragment.Sent})
			delete(p.numbers, numbered{handle: handle, direction: fragment.Received})
		}
	}
	p.Session.Closed(c)
}

// Settled answers as a producer still holding the handle's occupancy would.
func (p *producer) Settled(handle probe.Handle) (probe.Settlement, error) {
	id, held := p.occupancies[handle]
	if !held {
		return probe.Settlement{}, nil
	}
	return probe.Settlement{Occupancy: id, Final: p.final(handle)}, nil
}

// Unlocated is zero: this producer places every loss.
func (p *producer) Unlocated() (uint64, error) { return 0, nil }
