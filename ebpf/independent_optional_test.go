//go:build attach

package ebpf_test

import (
	"bytes"
	"debug/elf"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evandukss/edge-observer/fragment"
)

// A private ELF copy keeps the real TLS implementation but renames its optional
// sendfile export. No call in this workload uses that route. This tests an absent
// library symbol, rather than an intentionally omitted resolved Point.
func TestIndependentOptionalAbsentRouteKeepsCaptureLive(t *testing.T) {
	libs, err := filepath.Glob("/usr/lib/*-linux-gnu/libssl.so.3")
	if err != nil || len(libs) != 1 {
		t.Fatalf("UNPROVED: libssl candidates=%v err=%v", libs, err)
	}
	data, err := os.ReadFile(libs[0])
	if err != nil {
		t.Fatal(err)
	}
	old := []byte("SSL_sendfile\x00")
	newName := []byte("ZZZ_sendfile\x00")
	n := bytes.Count(data, old)
	if n == 0 {
		t.Fatal("UNPROVED: export string absent before fixture change")
	}
	dir := t.TempDir()
	copyPath := filepath.Join(dir, "libssl.so.3")
	if err := os.WriteFile(copyPath, bytes.ReplaceAll(data, old, newName), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := elf.Open(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := f.DynamicSymbols()
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	absent, replaced := true, 0
	for _, s := range symbols {
		if s.Name == "SSL_sendfile" {
			absent = false
		}
		if s.Name == "ZZZ_sendfile" {
			replaced++
		}
	}
	if !absent || replaced != 1 {
		t.Fatalf("UNPROVED: absent=%t replacement_symbols=%d", absent, replaced)
	}
	t.Setenv("LD_LIBRARY_PATH", dir)
	r := proofFixture(t, nil)
	for _, p := range r.points {
		if p.Symbol == "SSL_sendfile" || !strings.Contains(p.Path, dir) {
			t.Fatalf("UNPROVED: resolver selected wrong library/route: %+v", p)
		}
	}
	if len(r.session.Unprobed()) != 0 {
		t.Errorf("COUNTEREXAMPLE: absent optional route disables capture: %v", r.session.Unprobed())
	}
	r.open(t, 0)
	r.command(t, "W 0 1")
	r.consume()
	r.command(t, "F 0")
	r.consume()
	r.finish(t)
	born := 0
	for _, e := range r.events {
		if e.Length == 512 && e.Sequence.Born && e.Sequence.Number == 1 {
			born++
		}
	}
	if born != 1 {
		t.Errorf("COUNTEREXAMPLE: optional route absent and real write not live: born_first=%d", born)
	}
	if len(r.collected.records) != 1 {
		t.Fatalf("UNPROVED: records=%d", len(r.collected.records))
	}
	for _, rec := range r.collected.records {
		p, _ := rec.Placement(fragment.Sent)
		if !p.Whole() {
			t.Errorf("COUNTEREXAMPLE: optional absence cut observed write: %+v", p)
		}
	}
	t.Logf("PRECONDITIONS absent_optional_exports=1 replacement_symbols=%d actual_TLS_writes=1 born_first=%d resolved_points=%d", replaced, born, len(r.points))
}
