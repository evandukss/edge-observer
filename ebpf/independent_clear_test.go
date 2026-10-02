//go:build attach

package ebpf_test

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
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
	old := []byte("SSL_clear\x00")
	renamed, changed := independentRenameClear(t, data)
	if bytes.Count(data, old) == 0 {
		t.Fatal("wiring, not the property: original clear symbol absent")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "libssl.so.3")
	if err := os.WriteFile(path, changed, 0600); err != nil {
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
		if s.Name == renamed {
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

// Internal libssl calls also resolve this export through the dynamic linker.
// Keep the renamed function in its original GNU-hash bucket, updating its hash
// and bloom bits, so the private library remains executable without SSL_clear.
func independentRenameClear(t *testing.T, data []byte) (string, []byte) {
	t.Helper()
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Section(".hash") != nil {
		t.Fatal("wiring, not the property: unsupported private ELF hash layout")
	}
	section := f.Section(".gnu.hash")
	if section == nil {
		t.Fatal("wiring, not the property: GNU hash absent")
	}
	symbols, err := f.DynamicSymbols()
	if err != nil {
		t.Fatal(err)
	}
	index := uint32(0)
	for i, s := range symbols {
		if s.Name == "SSL_clear" {
			index = uint32(i + 1)
		}
	}
	at := section.Offset
	order := binary.LittleEndian
	buckets := order.Uint32(data[at:])
	first := order.Uint32(data[at+4:])
	words := order.Uint32(data[at+8:])
	shift := order.Uint32(data[at+12:])
	if index < first || buckets == 0 || words == 0 {
		t.Fatal("wiring, not the property: clear export lacks a GNU hash chain")
	}
	hash := func(s string) uint32 {
		h := uint32(5381)
		for i := range len(s) {
			h = h*33 + uint32(s[i])
		}
		return h
	}
	var name string
	var h uint32
	for i := 0; i < 1000000; i++ {
		name = fmt.Sprintf("Z%08x", i)
		h = hash(name)
		if h%buckets == hash("SSL_clear")%buckets {
			break
		}
		name = ""
	}
	if name == "" {
		t.Fatal("wiring, not the property: no same-bucket export name")
	}
	changed := bytes.ReplaceAll(data, []byte("SSL_clear\x00"), append([]byte(name), 0))
	chain := at + 16 + uint64(words)*8 + uint64(buckets)*4 + uint64(index-first)*4
	terminal := order.Uint32(changed[chain:]) & 1
	order.PutUint32(changed[chain:], h&^uint32(1)|terminal)
	bloom := at + 16 + uint64((h/64)%words)*8
	mask := uint64(1)<<(h%64) | uint64(1)<<((h>>shift)%64)
	order.PutUint64(changed[bloom:], order.Uint64(changed[bloom:])|mask)
	return name, changed
}
