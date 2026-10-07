//go:build attach

package ebpf

// Counter reads one of the program's counters by its index (package bpf,
// Stat*), for a case asserting that a refusal counter did not move.
func Counter(s *Session, index uint32) (int64, error) { return s.stat(index) }
