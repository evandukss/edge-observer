package main

import (
	"bytes"
	"strings"
	"testing"
)

type stderrWitness struct {
	want    []byte
	lines   int
	bytes   int
	invalid bool
}

func (w *stderrWitness) Write(p []byte) (int, error) {
	w.lines++
	w.bytes += len(p)
	w.invalid = w.invalid || !bytes.Equal(p, w.want)
	return len(p), nil
}

func TestStderrFloodPreservesItsBytesWithoutAllocatingPerLine(t *testing.T) {
	want := []byte("stderr\x1b\t" + strings.Repeat("s", 4096) + "\n")
	var allocations []float64
	for _, count := range []int{2000, 20000} {
		w := &stderrWitness{want: want}
		allocs := testing.AllocsPerRun(3, func() {
			w.lines, w.bytes, w.invalid = 0, 0, false
			floodStderr(w, count)
		})
		if w.invalid || w.lines != count || w.bytes != count*4105 {
			t.Fatalf("wiring, not the property: count=%d lines=%d bytes=%d invalid=%v", count, w.lines, w.bytes, w.invalid)
		}
		t.Logf("count=%d witnessed_lines=%d witnessed_bytes=%d allocations=%g", count, w.lines, w.bytes, allocs)
		allocations = append(allocations, allocs)
	}
	if allocations[1] > allocations[0]+16 {
		t.Errorf("10x stderr workload grew generator allocations: %v", allocations)
	}
}
