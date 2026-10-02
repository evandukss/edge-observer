// Package held names what the observer holds at once while a session runs.
//
// A continuous session keeps nothing that grows with what it has done in
// total: what it holds is bounded by what is live now. Two readings make that
// checkable. An Occupancy is one retained store's entries at the moment it is
// read, so a store can be read against the live population it serves. A Slot
// is the place one event takes under the delivery gate's bound on events held
// at once: the store retaining the event's input holds the slot, and it is
// returned once, along a Path, when that input is processed or discarded.
package held

// Occupancy is one retained store's entries at the moment it was read.
type Occupancy struct {
	// Store names the store by its component and its field or map, such as
	// "capture.streams" or "bpf.occupancies".
	Store string

	// Held is how many entries the store holds now.
	Held int

	// Bound is the most the store can hold, or zero where only the population it
	// serves bounds it.
	Bound int
}

// Reader is a component whose retained stores can be read. Retained lists
// every store the component keeps; a store it does not keep is not listed.
type Reader interface {
	Retained() ([]Occupancy, error)
}

// Path is why a slot was returned.
type Path string

const (
	// Unretained is an event whose input no store kept: an empty or refused
	// transfer, an unmatched ending, or input a full store refused.
	Unretained Path = "unretained"

	// Processed is input processing finished with: every line it produced was
	// offered to the sink queue, which holds its own charge for what it took, or
	// it produced none.
	Processed Path = "processed"

	// Discarded is input given up unprocessed.
	Discarded Path = "discarded"

	// Cut is input discarded because its connection reached the bound on what one
	// open connection may hold.
	Cut Path = "cut"
)

// Paths is every Path, once each.
func Paths() []Path { return []Path{Unretained, Processed, Discarded, Cut} }

// Slot is one admitted event's place under the delivery gate's bound on events
// held at once. Whatever retains the event's input holds the slot and returns
// it when that input is processed or discarded; the deliverer returns a slot
// nobody kept.
type Slot interface {
	// Keep records that a store retained the event's input, so the slot travels
	// with that input rather than being returned by the deliverer.
	Keep()

	// Kept reports whether a store retained the event's input.
	Kept() bool

	// Refund returns the slot along path. It reports true the first time. A
	// later call returns nothing, reports false and is counted as a double refund.
	Refund(Path) bool
}
