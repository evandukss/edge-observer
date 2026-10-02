package held

// Churn is what a long-lived map keyed by identities that never return - a
// connection's id, a handle's address, a process's number - needs so its
// allocation stays bounded by what it holds. The runtime keeps a deleted slot
// as a tombstone and, once a table's free slots are used up, grows or splits
// the table rather than reclaiming them in place, so such a map's allocation
// rises with every key it has ever held while its live size stays the same.
// Churn counts the deletions since the map was last copied, and Shed copies it
// into a fresh map once they exceed both its live size and churnFloor: at most
// as many slots are left by deletions as are live, so what the map allocates
// is bounded by its live size.
type Churn struct {
	deleted  int
	rebuilds int
}

// churnFloor keeps a small map from being copied every few deletions.
const churnFloor = 64

// Note records one deletion from the map.
func (c *Churn) Note() { c.deleted++ }

// Rebuilds is how many times the map was copied into a fresh one.
func (c *Churn) Rebuilds() int { return c.rebuilds }

// Shed returns m, or a fresh copy of it once the deletions noted since the
// last copy exceed both its live size and churnFloor. The caller stores what
// it returns, and calls it after a loop over m rather than inside one.
func Shed[K comparable, V any](m map[K]V, c *Churn) map[K]V {
	if c.deleted <= churnFloor || c.deleted <= len(m) {
		return m
	}
	fresh := make(map[K]V, len(m))
	for key, value := range m {
		fresh[key] = value
	}
	c.deleted = 0
	c.rebuilds++
	return fresh
}

// Deleted deletes key from m, notes it where it was there, and returns what
// Shed returns.
func Deleted[K comparable, V any](m map[K]V, key K, c *Churn) map[K]V {
	if _, present := m[key]; !present {
		return m
	}
	delete(m, key)
	c.Note()
	return Shed(m, c)
}
