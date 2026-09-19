// Package spool holds captured records on local disk, under a required bound,
// so the observer cannot fill the host's disk. Nothing leaves the host.
package spool

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/fragment"
)

// The two files a session writes. Fragments are written as placed; a
// connection record when it stops changing.
const (
	Name            = "fragments.jsonl"
	ConnectionsName = "connections.jsonl"
)

// Stats is what a spool has done: whether an operator is seeing everything.
type Stats struct {
	// Written is the records on disk.
	Written int64 `json:"written"`

	// Dropped is the records refused at the bound. It is counted because a full
	// spool otherwise looks like a quiet host.
	Dropped int64 `json:"dropped"`

	// Refused is the records that could not be placed in a stream: a capture
	// defect, not the bound.
	Refused int64 `json:"refused"`

	// Connections is the connection records on disk; ConnectionsDropped and
	// ConnectionsRefused are those that did not reach it, for the same two
	// reasons. They are never folded into the fragment counters.
	Connections        int64 `json:"connections"`
	ConnectionsDropped int64 `json:"connections_dropped"`
	ConnectionsRefused int64 `json:"connections_refused"`

	// Bytes is what both files hold; Limit is the one bound over both.
	Bytes int64 `json:"bytes"`
	Limit int64 `json:"limit"`
}

// Spool is a bounded pair of files: the fragments, and the connections they
// belong to.
type Spool struct {
	limit int64

	// Kept because a closed file has no name, and callers report paths after close.
	path            string
	connectionsPath string

	mutex       sync.Mutex
	file        *os.File
	connections *os.File
	stats       Stats
}

// Open prepares a spool in dir under a bound of limit bytes. The bound is
// required and has no default.
func Open(dir string, limit int64) (*Spool, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("a spool is bounded, and %d is not a bound", limit)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("make the spool directory: %w", err)
	}

	// 0600: the files hold the observed processes' traffic.
	fragments, held, err := openBounded(filepath.Join(dir, Name))
	if err != nil {
		return nil, err
	}
	connections, alsoHeld, err := openBounded(filepath.Join(dir, ConnectionsName))
	if err != nil {
		_ = fragments.Close()
		return nil, err
	}

	return &Spool{
		limit:           limit,
		path:            fragments.Name(),
		connectionsPath: connections.Name(),
		file:            fragments,
		connections:     connections,
		stats:           Stats{Bytes: held + alsoHeld, Limit: limit},
	}, nil
}

// openBounded opens one of the spool's files and says how much of the bound it
// already holds.
func openBounded(path string) (*os.File, int64, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, 0, fmt.Errorf("open the spool: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, fmt.Errorf("read the spool: %w", err)
	}
	return file, info.Size(), nil
}

// Write puts a record in the spool. It refuses a record that cannot be placed
// and drops one that would pass the bound, counting each; neither is an error
// for the caller, so observation never blocks the observed process.
func (s *Spool) Write(record fragment.Record) error {
	if err := record.Validate(); err != nil {
		s.mutex.Lock()
		s.stats.Refused++
		s.mutex.Unlock()
		return err
	}

	line, err := json.Marshal(record)
	if err != nil {
		s.mutex.Lock()
		s.stats.Refused++
		s.mutex.Unlock()
		return err
	}
	line = append(line, '\n')

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.file == nil {
		s.stats.Refused++
		return fmt.Errorf("the spool is closed")
	}
	if s.stats.Bytes+int64(len(line)) > s.limit {
		// Dropped whole: half a record is unparseable.
		s.stats.Dropped++
		return nil
	}

	written, err := s.file.Write(line)
	s.stats.Bytes += int64(written)
	if err != nil {
		return fmt.Errorf("write to the spool: %w", err)
	}
	s.stats.Written++
	return nil
}

// Stats is what this spool has done.
func (s *Spool) Stats() Stats {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.stats
}

// Connection puts a connection record in the spool, refusing and dropping as
// Write does, on the connection counters.
func (s *Spool) Connection(record connection.Record) error {
	if err := record.Validate(); err != nil {
		s.mutex.Lock()
		s.stats.ConnectionsRefused++
		s.mutex.Unlock()
		return err
	}

	line, err := json.Marshal(record)
	if err != nil {
		s.mutex.Lock()
		s.stats.ConnectionsRefused++
		s.mutex.Unlock()
		return err
	}
	line = append(line, '\n')

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.connections == nil {
		s.stats.ConnectionsRefused++
		return fmt.Errorf("the spool is closed")
	}
	if s.stats.Bytes+int64(len(line)) > s.limit {
		s.stats.ConnectionsDropped++
		return nil
	}

	written, err := s.connections.Write(line)
	s.stats.Bytes += int64(written)
	if err != nil {
		return fmt.Errorf("write to the spool: %w", err)
	}
	s.stats.Connections++
	return nil
}

// Counted is this spool's part of the run's inventory: what reached the file,
// what the bound dropped, and what could not be placed.
func (s *Spool) Counted() connection.Counters {
	held := s.Stats()
	return connection.Counters{
		Persisted:        connection.Counted(held.Written),
		PersistedDropped: connection.Counted(held.Dropped),
		PersistedRefused: connection.Counted(held.Refused),
	}
}

// Path is the fragment file this spool writes.
func (s *Spool) Path() string { return s.path }

// ConnectionsPath is where this spool writes its connection records.
func (s *Spool) ConnectionsPath() string { return s.connectionsPath }

// Close closes both files. A spool that is closed twice is closed once.
func (s *Spool) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var first error
	for _, file := range []**os.File{&s.file, &s.connections} {
		if *file == nil {
			continue
		}
		open := *file
		*file = nil
		if err := open.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
