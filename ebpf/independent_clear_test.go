//go:build attach

package ebpf_test

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
)

func TestIndependentClearSeparatesRealTLSConnections(t *testing.T) {
	r := proofFixture(t, nil)
	address, _ := r.open(t, 0)
	r.command(t, "W 0 1")
	r.consume()
	answer := r.command(t, "C 0")
	var index int
	var reused uint64
	if _, err := fmt.Sscanf(answer, "C %d %d", &index, &reused); err != nil || reused != address || index != 0 {
		t.Fatalf("wiring, not the property: SSL_clear did not recycle same object: %q", answer)
	}
	select {
	case <-r.peers:
	case <-time.After(time.Second):
		t.Fatal("wiring, not the property: second real TLS handshake absent")
	}
	r.command(t, "W 0 1")
	r.consume()
	r.command(t, "F 0")
	r.consume()
	r.finish(t)
	var ids, numbers []uint64
	for _, e := range r.events {
		if e.Kind == ebpf.Transfer && e.Direction == fragment.Sent && e.Length == 512 {
			ids = append(ids, e.Sequence.Occupancy)
			numbers = append(numbers, e.Sequence.Number)
		}
	}
	if len(ids) != 2 || len(r.collected.fragments) != 2 {
		t.Fatalf("wiring, not the property: two real TLS writes did not reach capture: ids=%v fragments%d", ids, len(r.collected.fragments))
	}
	t.Logf("PRECONDITIONS SSL_clear_calls=1 reused_object=%d real_TLS_connections=2 transfers=2 occupancies=%v numbers=%v records=%d", address, ids, numbers, len(r.collected.records))
	if ids[0] == 0 || ids[1] == 0 || ids[0] == ids[1] || numbers[0] != 1 || numbers[1] != 1 {
		t.Errorf("recycled SSL object continued a connection sequence: ids=%v numbers=%v", ids, numbers)
	}
	if len(r.collected.records) != 2 {
		t.Errorf("two actual connections produced%d records", len(r.collected.records))
	}
	for _, rec := range r.collected.records {
		if rec.Fragments.Known && rec.Fragments.Value > 1 {
			t.Errorf("connection record joins transfers across SSL_clear: %+v", rec)
		}
	}
}

func TestIndependentClearRefusalDisablesCapture(t *testing.T) {
	requested := 0
	r := proofConfigured(t, nil, func(o *ebpf.Options) {
		for i := range o.Points {
			if o.Points[i].Symbol == "SSL_clear" {
				o.Points[i].Path = "/independent-missing-clear"
				requested++
			}
		}
	})
	r.open(t, 0)
	r.command(t, "W 0 1")
	r.consume()
	r.command(t, "F 0")
	r.consume()
	r.finish(t)
	writes := 0
	for _, e := range r.events {
		if e.Length == 512 {
			writes++
			if e.Sequence.Occupancy != 0 {
				t.Errorf("capture live with clear unprobed: %+v", e.Sequence)
			}
		}
	}
	if writes != 1 {
		t.Fatal("wiring, not the property: byte movers did not deliver actual write")
	}
	if requested != 1 {
		t.Errorf("present SSL_clear not offered as a lifecycle probe: count%d", requested)
	}
	if !slices.Contains(r.session.Unprobed(), "SSL_clear") || !slices.Contains(r.session.Coverage().Unprobed, "SSL_clear") {
		t.Errorf("clear refusal absent from coverage: %+v", r.session.Coverage())
	}
	t.Logf("PRECONDITIONS requested_clear_refusals=%d actual_writes=%d", requested, writes)
}

func TestIndependentAbsentClearDoesNotDisableCapture(t *testing.T) {
	libs, err := filepath.Glob("/usr/lib/*-linux-gnu/libssl.so.3")
	if err != nil || len(libs) != 1 {
		t.Fatalf("wiring, not the property: libssl paths=%v err=%v", libs, err)
	}
	data, err := os.ReadFile(libs[0])
	if err != nil {
		t.Fatal(err)
	}
	old, next := []byte("SSL_clear\x00"), []byte("ZZZ_clear\x00")
	if bytes.Count(data, old) == 0 {
		t.Fatal("wiring, not the property: original clear symbol absent")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "libssl.so.3")
	if err := os.WriteFile(path, bytes.ReplaceAll(data, old, next), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := f.DynamicSymbols()
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	replacement := 0
	for _, s := range symbols {
		if s.Name == "SSL_clear" {
			t.Fatal("wiring, not the property: clear symbol still present")
		}
		if s.Name == "ZZZ_clear" {
			replacement++
		}
	}
	if replacement != 1 {
		t.Fatal("wiring, not the property: replacement export absent")
	}
	t.Setenv("LD_LIBRARY_PATH", dir)
	r := proofFixture(t, nil)
	for _, p := range r.points {
		if p.Symbol == "SSL_clear" || !strings.Contains(p.Path, dir) {
			t.Fatalf("wiring, not the property: wrong ELF resolved: %+v", p)
		}
	}
	r.open(t, 0)
	r.command(t, "W 0 1")
	r.consume()
	r.command(t, "F 0")
	r.consume()
	r.finish(t)
	writes, born := 0, 0
	for _, e := range r.events {
		if e.Length == 512 {
			writes++
			if e.Sequence.Born && e.Sequence.Number == 1 {
				born++
			}
		}
	}
	if writes != 1 {
		t.Fatal("wiring, not the property: absent-symbol library did not move bytes")
	}
	if born != 1 || len(r.session.Unprobed()) != 0 {
		t.Errorf("absent clear blocks capture: born%d unprobed%v", born, r.session.Unprobed())
	}
	t.Logf("PRECONDITIONS absent_clear=1 replacement_exports=%d actual_writes=%d", replacement, writes)
}
