package contentcoding

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"runtime"
	"testing"
)

// These size-class ceilings are the published allocation units. The history
// capacities below come from the pinned decoder's low-memory frame contract,
// independently of the workspace planner that consumes these fixtures.
func decodingAllocated(n int64) int64 {
	if n == 0 {
		return 0
	}
	if n <= 32<<10 {
		return n + n/4 + 16
	}
	return (n + 8191) / 8192 * 8192
}

func decodingHistory(window int64) int64 {
	if window < (1<<21)-1 {
		return 2 * window
	}
	return window + ((1<<21)-1)/2
}

func decodingZstdFixedWorkspace() int64 {
	blocks := 3*decodingAllocated((128<<10)+17) + decodingAllocated((0x7f00+0xffff)*24)
	return (32 << 10) + 2*blocks + 1024
}

func TestZstdWorkspaceTracksRetainedHistory(t *testing.T) {
	const bound = 8 << 20
	for _, tc := range []struct {
		name        string
		descriptors []byte
		windows     []int64
	}{
		{"small", []byte{0}, []int64{1024}},
		{"below-threshold", []byte{86}, []int64{7 << 18}},
		{"nearest-below-threshold", []byte{87}, []int64{15 << 17}},
		{"at-threshold", []byte{88}, []int64{2 << 20}},
		{"growing-then-shrinking", []byte{86, 87, 88, 86, 0}, []int64{7 << 18, 15 << 17, 2 << 20, 7 << 18, 1024}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var encoded []byte
			for _, d := range tc.descriptors {
				encoded = append(encoded, decodingZstdRawFrame(d, []byte{'a'})...)
			}
			plain := bytes.Repeat([]byte{'a'}, len(tc.descriptors))
			if !bytes.Equal(decodingReference(t, "zstd", encoded), plain) {
				t.Fatal("wiring, not the property: workspace fixture does not decode")
			}
			var retained, peak int64
			for _, window := range tc.windows {
				capacity := decodingHistory(window)
				if capacity > retained {
					peak = max(peak, decodingAllocated(retained)+decodingAllocated(capacity))
					retained = capacity
				}
			}
			expected := decodingZstdFixedWorkspace() + peak
			t.Run("plan", func(t *testing.T) {
				got := Workspace(Zstd, encoded, bound)
				if got != expected {
					t.Errorf("workspace=%d, want independently derived retained-history plan %d", got, expected)
				}
				if got > WorkspaceCeiling(Zstd, bound) {
					t.Errorf("plan %d exceeds ceiling", got)
				}
			})
			t.Run("admission", func(t *testing.T) {
				observed := decodingRun(t, decodingList(Zstd), encoded, bound, Decoded, 0, plain)
				if observed[0].Workspace != expected || observed[0].Planned != int64(9*len(tc.descriptors)) {
					t.Errorf("observed plan=%+v, want workspace=%d planned=%d", observed[0], expected, 9*len(tc.descriptors))
				}
			})
		})
	}
}

func TestTinySingleSegmentUsesWindowFloor(t *testing.T) {
	// A single-segment frame has no window descriptor and a one-byte content
	// size here. The pinned decoder gives all three a 1024-byte window.
	for _, size := range []byte{0, 1, 255} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			plain := bytes.Repeat([]byte{'a'}, int(size))
			encoded := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x20, size}
			h := uint32(size)<<3 | 1
			encoded = append(encoded, byte(h), byte(h>>8), byte(h>>16))
			encoded = append(encoded, plain...)
			if !bytes.Equal(decodingReference(t, "zstd", encoded), plain) {
				t.Fatal("wiring, not the property: single-segment fixture invalid")
			}
			expected := decodingZstdFixedWorkspace() + decodingAllocated(2048)
			t.Run("plan", func(t *testing.T) {
				if got := Workspace(Zstd, encoded, 8<<20); got != expected {
					t.Errorf("tiny frame workspace %d, want floor plan %d", got, expected)
				}
			})
			t.Run("decode", func(t *testing.T) { decodingRun(t, decodingList(Zstd), encoded, 8<<20, Decoded, 0, plain) })
		})
	}
}

func TestSmallWindowWorkspaceDoesNotDependOnBodyBound(t *testing.T) {
	plain := []byte("small window")
	for _, tc := range []struct {
		name   string
		coding Coding
	}{{"gzip", Gzip}, {"deflate", Deflate}, {"br", Brotli}, {"zstd", Zstd}} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := decodingEncode(t, tc.name, plain)
			small, large := Workspace(tc.coding, encoded, 1024), Workspace(tc.coding, encoded, 8<<20)
			if small <= 0 {
				t.Fatal("wiring, not the property: fixture has no workspace plan")
			}
			if small != large {
				t.Errorf("fixed declared window charged by body bound: %d versus %d", small, large)
			}
			if tc.coding == Brotli || tc.coding == Zstd {
				if large >= WorkspaceCeiling(tc.coding, 8<<20) {
					t.Errorf("small declared window uses worst-case ceiling: %d", large)
				}
			}
			observed := decodingRun(t, decodingList(tc.coding), encoded, 8<<20, Decoded, 0, plain)
			planned := int64(0)
			if tc.coding == Brotli {
				planned = 1
			}
			if tc.coding == Zstd {
				planned = observed[0].Planned
				if planned < 9 {
					t.Error("zstd planner did not read frame/block headers")
				}
			}
			if observed[0].Planned != planned || observed[0].Workspace != small {
				t.Errorf("small window admission=%+v, expected workspace=%d planned=%d", observed[0], small, planned)
			}
		})
	}
}

func TestWorkspaceCeilingCoversHistoryBeforeThreshold(t *testing.T) {
	const bound = 2 << 20
	// Single-segment content sizes can approach the threshold byte by byte,
	// even though a regular frame's window descriptor has coarser steps.
	largestHistory := 2 * int64((1<<21)-2)
	expected := decodingZstdFixedWorkspace() + 2*decodingAllocated(largestHistory)
	if got := WorkspaceCeiling(Zstd, bound); got != expected {
		t.Errorf("ceiling=%d, want history envelope=%d", got, expected)
	}
	n := int64(bound + 1)
	if got := Charges(Zstd, bound); got != n+(n+1)/2+expected {
		t.Errorf("charge ceiling=%d, want new+old outputs plus workspace", got)
	}
	if got := Peak(Zstd, bound, 123); got != 123+n+(n+1)/2+expected {
		t.Errorf("owned peak did not include captured input and one stage: %d", got)
	}
}

type decodingGrowthAdmission struct {
	ledger             decodingLedger
	last               runtime.MemStats
	previousCapacity   int64
	refusalCapacity    int64
	delta              uint64
	allowance          uint64
	workspaceAllowance int64
	refused            bool
}

func (g *decodingGrowthAdmission) Reserve(c Charge) bool {
	if c.Kind == OutputCharge {
		var now runtime.MemStats
		runtime.ReadMemStats(&now)
		if c.Bytes >= 1<<20 {
			g.delta = now.TotalAlloc - g.last.TotalAlloc
			// Between two output reservations, the preceding output may be allocated
			// and a stored flate block may initialize decoder state. The next buffer
			// is not yet admitted, so none of its capacity belongs in this delta.
			g.allowance = uint64(decodingAllocated(g.previousCapacity) + g.workspaceAllowance + AdmissionAllocation)
			g.refusalCapacity = c.Bytes
			g.refused = true
			g.ledger.refuse = g.ledger.calls + 1
		} else {
			g.last = now
			g.previousCapacity = c.Bytes
		}
	}
	return g.ledger.Reserve(c)
}
func (g *decodingGrowthAdmission) Release(c Charge) { g.ledger.Release(c) }

func TestOutputGrowthRefusalPrecedesAllocation(t *testing.T) {
	const bound = 8 << 20
	plain := bytes.Repeat([]byte{'a'}, 2<<20)
	var encoded bytes.Buffer
	w, err := gzip.NewWriterLevel(&encoded, flate.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodingReference(t, "gzip", encoded.Bytes()), plain) {
		t.Fatal("wiring, not the property: stored-block fixture invalid")
	}
	list := decodingList(Gzip)
	charge := Workspace(Gzip, encoded.Bytes(), bound)
	admission := &decodingGrowthAdmission{ledger: decodingLedger{t: t, list: list, bound: bound, expectedFirst: charge}, workspaceAllowance: charge}
	runtime.GC()
	result := Decode(list, encoded.Bytes(), Options{Bound: bound, Reserver: admission})
	if !admission.refused || !admission.ledger.refused || admission.previousCapacity == 0 {
		t.Fatal("wiring, not the property: a populated output did not reach its refused growth")
	}
	if result.Outcome != Refused || result.Body != nil || result.Charge != 0 || admission.ledger.total() != 0 {
		t.Errorf("refused growth retained state: result=%+v held=%d", result, admission.ledger.total())
	}
	if admission.delta > admission.allowance {
		t.Errorf("allocation before refused output growth=%d, preceding admitted buffer plus decoder allowance=%d", admission.delta, admission.allowance)
	}
	if uint64(admission.refusalCapacity) <= admission.allowance {
		t.Fatal("wiring, not the property: next buffer cannot be distinguished from permitted allocation")
	}
	t.Logf("previous=%d refused=%d allocation=%d allowance=%d", admission.previousCapacity, admission.refusalCapacity, admission.delta, admission.allowance)
}
