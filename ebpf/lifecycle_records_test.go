//go:build attach

package ebpf_test

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/spool"
)

func independentLifecycleConnections(t *testing.T, path string) []connection.Record {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(file)
	var records []connection.Record
	for {
		var record connection.Record
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			return records
		}
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
}

func waitIndependentLifecycleConnections(t *testing.T, disk *spool.Spool, want int64) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for disk.Stats().Connections < want {
		select {
		case <-deadline.C:
			t.Fatalf("only %d connections persisted, wanted %d", disk.Stats().Connections, want)
		case <-tick.C:
		}
	}
}
