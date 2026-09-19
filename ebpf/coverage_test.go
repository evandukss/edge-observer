package ebpf_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/probe"
)

// asked is the whole point set an adapter places for one library object:
// catalogued entry points, the connection ending, the C library fork, and every
// socket entry point.
func asked(t *testing.T) []ebpf.Point {
	t.Helper()

	catalogued := append(probe.OpenSSL.Probed(), probe.OpenSSL.Lifecycle...)
	symbols := make([]string, 0, len(catalogued))
	for _, function := range catalogued {
		symbols = append(symbols, function.Symbol)
	}
	points, discarded := ebpf.PointsFrom(resolved(symbols...), probe.OpenSSL)
	if len(discarded) > 0 {
		t.Fatalf("the catalogue and the programs disagree about %d entry points", len(discarded))
	}
	points = append(points, ebpf.ForkPoint("fork", "/lib/libc.so.6", 0x2000))
	for i, symbol := range ebpf.SocketSymbols() {
		points = append(points, ebpf.SocketPoint(symbol, "/lib/libc.so.6", uint64(0x3000+0x10*i)))
	}
	return points
}

// confirming is what the kernel answered for each point: all held except the
// named symbols.
func confirming(points []ebpf.Point, refused ...string) []ebpf.Placed {
	answered := make([]ebpf.Placed, len(points))
	for i, point := range points {
		answered[i] = ebpf.Placed{Point: point, Confirmed: !slices.Contains(refused, point.Symbol)}
	}
	return answered
}

// The control: every probe held, so everything is observed and nothing named
// missing; otherwise a reduction always answering no would pass.
func TestASessionHoldingEveryProbeObservesEverythingItsProgramCan(t *testing.T) {
	coverage := ebpf.CoverageOf(confirming(asked(t)))

	if !coverage.Payload {
		t.Error("no plaintext transfer function is observed although the kernel holds every probe")
	}
	if !coverage.Lifecycle {
		t.Error("no connection ending is observed although the kernel holds every probe")
	}
	if !coverage.Binding {
		t.Error("no socket association is observed although the kernel holds every probe")
	}
	if len(coverage.Unobserved) != 0 {
		t.Errorf("the kernel holds every probe and %v are named unobserved", coverage.Unobserved)
	}
}

// One catalogued function is not held and the rest are: the plaintext claim
// stands for what placed, and the missing function is named, since its bytes
// are absent while everything captured looks right.
func TestOneUnheldTransferFunctionIsNamedAndDoesNotUnmakeTheRest(t *testing.T) {
	coverage := ebpf.CoverageOf(confirming(asked(t), "SSL_read"))

	if !coverage.Payload {
		t.Error("one unheld function took the plaintext capability from every function that placed")
	}
	if !slices.Contains(coverage.Unobserved, "SSL_read") {
		t.Errorf("SSL_read is not held and the coverage names %v as unobserved", coverage.Unobserved)
	}
	if len(coverage.Unobserved) != 1 {
		t.Errorf("one function is unheld and %v are named unobserved", coverage.Unobserved)
	}
	if !coverage.Lifecycle || !coverage.Binding {
		t.Errorf("an unheld transfer function cost this session %+v", coverage)
	}
}

// No transfer function is held, so this session copies no plaintext however
// well its other probes placed.
func TestASessionHoldingNoTransferFunctionCopiesNoPlaintext(t *testing.T) {
	points := asked(t)
	var transfers []string
	for _, function := range probe.OpenSSL.Probed() {
		transfers = append(transfers, function.Symbol)
	}

	coverage := ebpf.CoverageOf(confirming(points, transfers...))

	if coverage.Payload {
		t.Error("a session holding no transfer probe at all says it copies plaintext")
	}
	for _, symbol := range transfers {
		if !slices.Contains(coverage.Unobserved, symbol) {
			t.Errorf("%s is not held and is not named unobserved: %v", symbol, coverage.Unobserved)
		}
	}
	if !coverage.Lifecycle || !coverage.Binding {
		t.Errorf("the probes that are not transfer probes were held and the coverage says %+v", coverage)
	}
}

// The connection ending stops a reused address from continuing the previous
// stream, and nothing downstream reveals its absence, so a session without it
// says so.
func TestASessionThatCannotObserveAConnectionEndingSaysSo(t *testing.T) {
	coverage := ebpf.CoverageOf(confirming(asked(t), "SSL_free"))

	if coverage.Lifecycle {
		t.Error("the handle release is not held and this session says it observes a connection ending")
	}
	if !slices.Contains(coverage.Unobserved, "SSL_free") {
		t.Errorf("SSL_free is not held and the coverage names %v as unobserved", coverage.Unobserved)
	}
	if !coverage.Payload || !coverage.Binding {
		t.Errorf("an unheld connection ending cost this session %+v", coverage)
	}
}

// An unheld fork point costs nothing else: it only decides the window a call
// inside a fork is held through.
func TestAnUnheldForkPointCostsASessionNoOtherCoverage(t *testing.T) {
	coverage := ebpf.CoverageOf(confirming(asked(t), "fork"))

	if !coverage.Payload || !coverage.Lifecycle || !coverage.Binding {
		t.Errorf("an unheld fork point cost this session %+v", coverage)
	}
}

// Every socket entry point is unheld, so no binding source is left and every
// association this run reports is unknown for that reason.
func TestASessionWithNoSocketProbeAtAllEstablishesNoBinding(t *testing.T) {
	coverage := ebpf.CoverageOf(confirming(asked(t), ebpf.SocketSymbols()...))

	if coverage.Binding {
		t.Error("no socket entry point is held and this session says it establishes a binding")
	}
	if !coverage.Payload || !coverage.Lifecycle {
		t.Errorf("unheld socket points cost this session %+v", coverage)
	}
}

// The control: one surviving source can still bind. The survivor is named as a
// program that records a descriptor; taking the first by sort order would pick
// accept, which records none, and pass while measuring the opposite.
func TestOneSurvivingBindingSourceStillEstablishesABinding(t *testing.T) {
	for _, survivor := range []string{"read", "write", "sendto", "recvmsg"} {
		var refused []string
		for _, symbol := range ebpf.SocketSymbols() {
			if symbol != survivor {
				refused = append(refused, symbol)
			}
		}
		if got := len(refused); got != len(ebpf.SocketSymbols())-1 {
			t.Fatalf("%d symbols refused of %d, so this case is not the one it is named for",
				got, len(ebpf.SocketSymbols()))
		}
		if !ebpf.CoverageOf(confirming(asked(t), refused...)).Binding {
			t.Errorf("%s is held and this session says it establishes no binding", survivor)
		}
	}
}

// A session holding only the occupancy-table socket points (socket, accept,
// accept4, connect, close, dup2) establishes nothing and says so: none records
// a descriptor inside a call.
func TestASessionHoldingOnlyTheOccupancyPointsEstablishesNoBinding(t *testing.T) {
	recording := []string{"sendto", "recvfrom", "sendmsg", "recvmsg", "read", "write", "readv", "writev"}

	var occupancy []string
	for _, symbol := range ebpf.SocketSymbols() {
		if !slices.Contains(recording, symbol) {
			occupancy = append(occupancy, symbol)
		}
	}
	if len(occupancy) == 0 {
		t.Fatal("every socket entry point records a descriptor, so there is no such session to measure")
	}

	coverage := ebpf.CoverageOf(confirming(asked(t), recording...))
	if coverage.Binding {
		t.Errorf("a session holding only %v says it establishes a binding, and none of them "+
			"records a descriptor against a call", occupancy)
	}
	if !coverage.Payload || !coverage.Lifecycle {
		t.Errorf("unheld binding sources cost this session %+v", coverage)
	}
}

// The reduction a caller reads: the build's capability narrowed to what this
// session holds.
func TestTheBuildCapabilityIsNarrowedToWhatTheSessionHolds(t *testing.T) {
	built := probe.Capability{
		Backend: probe.BPF, Program: "full", Payload: true, Filtered: true,
		Descendants: true, Lifecycle: true, Binding: true, MinimumKernel: "5.15",
	}

	// Descendants comes back false: CoverageOf does not answer it, so narrowing by
	// CoverageOf clears it. Production narrows by Session.Coverage, measured in the
	// attach suite.
	kept := built
	kept.Descendants = false

	whole := ebpf.CoverageOf(confirming(asked(t))).Narrow(built)
	if !reflect.DeepEqual(whole, kept) {
		t.Errorf("a session holding every probe reports %+v, want the build's own %+v", whole, kept)
	}

	var transfers []string
	for _, function := range probe.OpenSSL.Probed() {
		transfers = append(transfers, function.Symbol)
	}
	blind := ebpf.CoverageOf(confirming(asked(t), transfers...)).Narrow(built)
	if blind.Payload {
		t.Error("a session holding no transfer probe at all is narrowed to a capability that " +
			"still copies plaintext, which is an empty reconstruction reported as a full one")
	}

	short := ebpf.CoverageOf(confirming(asked(t), "SSL_free", "fork")).Narrow(built)
	if short.Lifecycle {
		t.Error("the handle release is unheld and the narrowed capability still observes a connection ending")
	}
	if !short.Payload || !short.Binding {
		t.Errorf("the narrowing took what the session does hold: %+v", short)
	}
	if !slices.Contains(short.Unobserved, "SSL_free") {
		t.Errorf("the narrowed capability names %v as unobserved", short.Unobserved)
	}
	if short.Backend != probe.BPF || short.Program != "full" || short.MinimumKernel != "5.15" {
		t.Errorf("the narrowing changed how this session reached the kernel: %+v", short)
	}
}

// A narrowing never widens: a build copying no plaintext does not gain it by
// placing every probe.
func TestNarrowingNeverWidensWhatTheBuildCanDo(t *testing.T) {
	metadata := probe.Capability{Backend: probe.BPF, Program: "meta", Filtered: true}

	narrowed := ebpf.CoverageOf(confirming(asked(t))).Narrow(metadata)
	if narrowed.Payload {
		t.Error("a build carrying no plaintext program reports plaintext once its probes are held")
	}
	if narrowed.Lifecycle || narrowed.Binding {
		t.Errorf("a build that claims none of these acquired them from its placements: %+v", narrowed)
	}
}
