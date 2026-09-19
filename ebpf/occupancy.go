package ebpf

import (
	"fmt"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/probe"
)

// Occupancy is one entry of what this session keeps about a descriptor: what
// the kernel cannot answer at the operation, namely one occupancy of a number
// from the next, and a call that made no syscall. Every entry names its owner:
// Instance carries the pid namespace, the number and the admission generation,
// which separates successive holders of a pid.
type Occupancy struct {
	// Instance is the execution the entry was written for.
	Instance admission.Instance

	// Descriptor is the number and Generation its occupancy: closed and reopened,
	// or replaced by dup2, is a different socket with the same number.
	Descriptor int32
	Generation uint64
}

// Binding is one TLS handle's descriptor and the occupancy it was made
// against, read back so a binding surviving into an execution it does not
// belong to can be seen.
type Binding struct {
	Instance admission.Instance

	// Handle is the library handle's address in the observed process. It is not an
	// identity: the allocator reuses addresses, which the generation survives.
	Handle uint64

	Descriptor int32
	Generation uint64

	// Socket is the socket's inode, the kernel's identity for it, meaningful only
	// with the generation.
	Socket uint64
}

// handleKey and bindingValue are the handle table as the program declares it
// (bpf/ssl.bpf.h, struct handle_key and struct binding).
type handleKey struct {
	NamespaceDevice uint64
	NamespaceInode  uint64
	PID             uint32
	Reserved        uint32
	SSL             uint64
}

type bindingValue struct {
	FD         int32
	Reserved   uint32
	Generation uint64

	// Inode is the socket's number, so a continuing call names the same socket.
	Inode uint64

	// Occupancy is what the run last saw behind the descriptor number when the
	// binding was made. It can only withdraw a continuity assertion (struct
	// binding, bpf/ssl.bpf.h).
	Occupancy uint64

	// The socket's endpoints as established, not re-derived. A v4 address arrives
	// v4-mapped.
	NetIno      uint64
	Opened      uint64
	Local       [16]byte
	Peer        [16]byte
	LPort       uint16
	DPort       uint16
	Ends        uint8
	EndsPadding [3]uint8
}

// Occupancies is every descriptor occupancy this session holds, with its
// owning execution, read straight from the loaded map.
func (s *Session) Occupancies() ([]Occupancy, error) {
	sockets := s.collection.Maps["sockets"]
	if sockets == nil {
		return nil, fmt.Errorf("%w: the program has no descriptor occupancy table", ErrUnavailable)
	}

	var (
		key   socketKey
		life  socketLife
		held  []Occupancy
		items = sockets.Iterate()
	)
	for items.Next(&key, &life) {
		held = append(held, Occupancy{
			Instance: admission.Instance{
				Namespace: admission.Namespace{
					Device: key.NamespaceDevice,
					Inode:  key.NamespaceInode,
				},
				PID: int32(key.PID),
			},
			Descriptor: key.FD,
			Generation: life.Generation,
		})
	}
	if err := items.Err(); err != nil {
		return nil, fmt.Errorf("%w: read the descriptor occupancies back: %v", ErrUnavailable, err)
	}
	return held, nil
}

// Bindings is every handle binding this session holds, with the execution that
// owns each.
func (s *Session) Bindings() ([]Binding, error) {
	handles := s.collection.Maps["handles"]
	if handles == nil {
		return nil, fmt.Errorf("%w: the program has no handle binding table", ErrUnavailable)
	}

	var (
		key   handleKey
		made  bindingValue
		held  []Binding
		items = handles.Iterate()
	)
	for items.Next(&key, &made) {
		held = append(held, Binding{
			Instance: admission.Instance{
				Namespace: admission.Namespace{
					Device: key.NamespaceDevice,
					Inode:  key.NamespaceInode,
				},
				PID: int32(key.PID),
			},
			Handle:     key.SSL,
			Descriptor: made.FD,
			Generation: made.Generation,
			Socket:     made.Inode,
		})
	}
	if err := items.Err(); err != nil {
		return nil, fmt.Errorf("%w: read the handle bindings back: %v", ErrUnavailable, err)
	}
	return held, nil
}

// unmatchedValue is the occasion record as the program declares it
// (bpf/ssl.bpf.h, struct unmatched).
type unmatchedValue struct {
	First uint64
	Last  uint64
	SSL   uint64
	PID   uint32
	TID   uint32
}

// UnmatchedAt is when this session saw a return whose entry was never
// recorded, or zero where it saw none. It comes from the program's map: the
// occasion is when the return fired, which userspace never sees.
func (s *Session) UnmatchedAt() (probe.Occasion, error) {
	seen := s.collection.Maps["unmatched_at"]
	if seen == nil {
		return probe.Occasion{}, fmt.Errorf("%w: the program records no occasion for a return "+
			"whose entry was never seen, so its count cannot be correlated with anything",
			ErrUnavailable)
	}
	var held unmatchedValue
	if err := seen.Lookup(uint32(0), &held); err != nil {
		return probe.Occasion{}, fmt.Errorf("%w: read when an unmatched return was seen: %v",
			ErrUnavailable, err)
	}
	return probe.Occasion{
		First:  int64(held.First),
		Last:   int64(held.Last),
		Handle: held.SSL,
		PID:    int32(held.PID),
		TID:    int32(held.TID),
	}, nil
}
