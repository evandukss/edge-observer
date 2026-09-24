package ebpf_test

import (
	"testing"

	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/probe"
)

// resolved is what an adapter hands PointsFrom: one entry per catalogued entry
// point it found in the library, plaintext and lifecycle alike.
func resolved(symbols ...string) []probe.Probe {
	probes := make([]probe.Probe, len(symbols))
	for i, symbol := range symbols {
		probes[i] = probe.Probe{Symbol: symbol, Path: "/lib/libssl.so.3", Offset: uint64(0x1000 * (i + 1))}
	}
	return probes
}

// Every entry point the catalogue attaches to maps to a program, including the
// connection ending, whose absence nothing downstream reveals: a reused SSL
// address would continue the previous stream.
func TestEveryEntryPointTheCatalogueAttachesToIsMappedToAProgram(t *testing.T) {
	catalogued := append(probe.OpenSSL.Probed(), probe.OpenSSL.Lifecycle...)

	symbols := make([]string, 0, len(catalogued))
	for _, function := range catalogued {
		symbols = append(symbols, function.Symbol)
	}

	points, discarded := ebpf.PointsFrom(resolved(symbols...), probe.OpenSSL)
	for _, one := range discarded {
		t.Errorf("%s is attached to in the catalogue and was discarded: %s", one.Symbol, one.Reason)
	}
	placed := make(map[string]ebpf.Point, len(points))
	for _, point := range points {
		placed[point.Symbol] = point
	}

	for _, function := range catalogued {
		point, mapped := placed[function.Symbol]
		if !mapped {
			t.Errorf("%s is attached to in the catalogue and is mapped to no program", function.Symbol)
			continue
		}
		if point.Entry == "" {
			t.Errorf("%s is mapped to no entry program", function.Symbol)
		}
	}
	if len(catalogued) == 0 {
		t.Fatal("the catalogue names nothing to attach to, so nothing was measured")
	}
}

// A function moving no bytes has no return program: there is no count to read.
func TestAFunctionThatMovesNoBytesIsMappedToAnEntryProgramOnly(t *testing.T) {
	for _, function := range probe.OpenSSL.Lifecycle {
		if !function.Probed {
			continue
		}
		points, _ := ebpf.PointsFrom(resolved(function.Symbol), probe.OpenSSL)
		if len(points) != 1 {
			t.Fatalf("%s mapped to %d points, want 1", function.Symbol, len(points))
		}
		if points[0].Return != "" {
			t.Errorf("%s carries a return program, and it moves no bytes", function.Symbol)
		}
	}
}
