package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/evandukss/edge-observer/held"
)

// kernelStores is every table the program keeps entries in as it runs, by
// its name in the object. The arrays hold a fixed number of slots and the
// ring buffer a fixed number of bytes, so neither is listed.
var kernelStores = []string{
	"inflight", "allowed_processes", "reads", "sockets", "handles", "occupancies",
	"operations", "discovered", "holders",
}

// Retained is what this session holds now, store by store: every kernel table
// above, counted entry by entry, then what userspace keeps about admissions,
// placements and the processes it has named, and the events decoded and not
// yet taken, against the staging channel's capacity. A table the loaded
// program does not have (reads, in the metadata-only build) is not listed.
func (s *Session) Retained() ([]held.Occupancy, error) {
	var out []held.Occupancy
	for _, name := range kernelStores {
		table := s.collection.Maps[name]
		if table == nil {
			continue
		}
		count, err := entries(table)
		if err != nil {
			return nil, fmt.Errorf("%w: count the %s table: %v", ErrUnavailable, name, err)
		}
		out = append(out, held.Occupancy{Store: "bpf." + name, Held: count, Bound: int(table.MaxEntries())})
	}

	s.held.Lock()
	inventory, index := len(s.inventory), len(s.index)
	targets, identities := len(s.targets), len(s.identities)
	namedBy := len(s.namedBy)
	indexRebuilt, namedByRebuilt := s.indexChurn.Rebuilds(),
		s.namedByChurn.Rebuilds()
	s.held.Unlock()

	return append(out,
		held.Occupancy{Store: "ebpf.accepted", Held: len(s.accepted)},
		held.Occupancy{Store: "ebpf.declined", Held: len(s.declined)},
		held.Occupancy{Store: "ebpf.denied", Held: len(s.denied)},
		held.Occupancy{Store: "ebpf.excluded", Held: len(s.excluded)},
		held.Occupancy{Store: "ebpf.enumerated", Held: len(s.enumerated)},
		held.Occupancy{Store: "ebpf.named_by", Held: namedBy, Rebuilds: namedByRebuilt},
		held.Occupancy{Store: "ebpf.inventory", Held: inventory},
		held.Occupancy{Store: "ebpf.index", Held: index, Rebuilds: indexRebuilt},
		held.Occupancy{Store: "ebpf.targets", Held: targets},
		held.Occupancy{Store: "ebpf.identities", Held: identities},
		held.Occupancy{Store: "ebpf.placed", Held: len(s.placed)},
		held.Occupancy{Store: "ebpf.links", Held: len(s.links)},
		held.Occupancy{Store: "ebpf.events", Held: len(s.events), Bound: cap(s.events)},
	), nil
}

// entries counts a hash table's entries by walking its keys.
func entries(table *ebpf.Map) (int, error) {
	key := make([]byte, table.KeySize())
	value := make([]byte, table.ValueSize())
	count := 0
	walk := table.Iterate()
	for walk.Next(&key, &value) {
		count++
	}
	if err := walk.Err(); err != nil {
		return 0, err
	}
	return count, nil
}
