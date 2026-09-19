//go:build attach

package ebpf_test

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// sending is every catalogued function that moves bytes out; the fixture's
// runtime picks among them (CPython reaches SSL_write or SSL_write_ex depending
// on the buffer).
func sending() []string {
	var symbols []string
	for _, function := range probe.OpenSSL.Probed() {
		if function.Direction == fragment.Sent {
			symbols = append(symbols, function.Symbol)
		}
	}
	return symbols
}

// unheldAt is a point the kernel will not take: the same function at an offset
// past the end of any library, so neither probe is placed. The symbol is kept,
// because these cases read the account's naming of it.
func unheldAt(point ebpf.Point) ebpf.Point {
	point.Offset = 1 << 40
	return point
}

// returnless is a point whose entry probe places and whose return probe cannot,
// as when the kernel takes one of a point's probes and refuses the other,
// reached by naming a return program the object lacks. It leaves a live entry
// probe on a function whose calls never complete.
func returnless(point ebpf.Point) ebpf.Point {
	point.Return = "obs_no_such_return"
	return point
}

// spoiling rebuilds a point set with the named symbols passed through spoil.
func spoiling(points []ebpf.Point, spoil func(ebpf.Point) ebpf.Point, symbols ...string) []ebpf.Point {
	spoilt := make([]ebpf.Point, 0, len(points))
	for _, point := range points {
		if containsSubstringExact(symbols, point.Symbol) {
			spoilt = append(spoilt, spoil(point))
			continue
		}
		spoilt = append(spoilt, point)
	}
	return spoilt
}

func containsSubstringExact(symbols []string, want string) bool {
	for _, symbol := range symbols {
		if symbol == want {
			return true
		}
	}
	return false
}

// partial attaches a session over one process's points with the named symbols
// spoilt, and returns it with the traffic driver.
func partial(t *testing.T, spoil func(ebpf.Point) ebpf.Point, symbols ...string) (*ebpf.Session, client) {
	t.Helper()

	serverPID, port := serving(t)
	server := loaded(t, serverPID)
	moveToCgroup(t, "obs-partial", server.PID)

	asked := points(t, server)
	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  spoiling(asked, spoil, symbols...),
		Admit:   authorise(server),
	})
	if err != nil {
		t.Fatalf("attach a partially placed session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	return session, speaking(t, port)
}

// unconfirmed is what the kernel says it does not hold, by symbol, which every
// case asserts against.
func unconfirmed(session *ebpf.Session) map[string]string {
	refused := make(map[string]string)
	for _, placement := range session.Confirmed() {
		if !placement.Confirmed {
			refused[placement.Symbol] = placement.Refusal
		}
	}
	return refused
}

func countOf(t *testing.T, what string, read func() (int64, error)) int64 {
	t.Helper()
	value, err := read()
	if err != nil {
		t.Fatalf("read %s: %v", what, err)
	}
	return value
}

// The control: a session that placed everything captures both directions, so
// "the sent direction produced nothing" cannot be satisfied by a silent
// fixture.
func TestASessionThatPlacedEveryProbeCapturesBothDirections(t *testing.T) {
	session, talking := partial(t, unheldAt)
	if refused := unconfirmed(session); len(refused) != 0 {
		t.Fatalf("a session that spoilt nothing does not hold %v", refused)
	}

	talking.ask(t, "/?asked=whole-placement-control")
	taken := drain(session, 500*time.Millisecond)

	if !containsSubstring(taken.plaintext(fragment.Received), "whole-placement-control") {
		t.Error("the request is absent from a session holding every probe")
	}
	if len(taken.plaintext(fragment.Sent)) == 0 {
		t.Error("the response is absent from a session holding every probe")
	}
	if got := countOf(t, "unmeasurable calls", session.Unmeasurable); got != 0 {
		t.Errorf("a session holding every probe reports %d calls it could not measure", got)
	}
	if coverage := session.Coverage(); !coverage.Payload || !coverage.Lifecycle {
		t.Errorf("a session holding every probe reports %+v", coverage)
	}
}

// No probe on the handle's release is held, and the rest are. The cost (an
// established binding becomes invalidated, the ending unestablished) is in the
// connection record; asserted here is the state producing it, from the
// kernel's answer, and that transfers keep arriving.
func TestAnUnheldConnectionEndingLeavesTheTransfersArriving(t *testing.T) {
	session, talking := partial(t, unheldAt, "SSL_free")

	if _, named := unconfirmed(session)["SSL_free"]; !named {
		t.Fatal("the handle release was placed at an offset past the end of the library and the " +
			"kernel confirms it")
	}
	coverage := session.Coverage()
	if coverage.Lifecycle {
		t.Error("the handle release is not held and this session says it observes a connection ending")
	}
	if !containsSubstringExact(coverage.Unobserved, "SSL_free") {
		t.Errorf("SSL_free is not held and the coverage names %v", coverage.Unobserved)
	}
	if !coverage.Payload {
		t.Error("every transfer function is held and this session says it copies no plaintext")
	}

	talking.ask(t, "/?asked=ending-not-held")
	taken := drain(session, 500*time.Millisecond)
	if !containsSubstring(taken.plaintext(fragment.Received), "ending-not-held") {
		t.Error("an unheld connection ending cost this session the traffic it does hold probes for")
	}
}

// A function's entry point is not held, and the rest are: what crosses it is
// absent and nothing counts it, since the probe that would notice is missing.
func TestAFunctionWhoseEntryIsNotHeldIsUnobservedAndUncounted(t *testing.T) {
	session, talking := partial(t, unheldAt, sending()...)

	refused := unconfirmed(session)
	for _, symbol := range sending() {
		if _, named := refused[symbol]; !named {
			t.Errorf("%s was placed at an offset past the end of the library and the kernel confirms it", symbol)
		}
	}
	coverage := session.Coverage()
	for _, symbol := range sending() {
		if !containsSubstringExact(coverage.Unobserved, symbol) {
			t.Errorf("%s is not held and the coverage names %v", symbol, coverage.Unobserved)
		}
	}
	if !coverage.Payload {
		t.Error("the received direction is held and this session says it copies no plaintext")
	}

	talking.ask(t, "/?asked=entry-not-held")
	taken := drain(session, 500*time.Millisecond)

	if !containsSubstring(taken.plaintext(fragment.Received), "entry-not-held") {
		t.Error("the received direction is held and its request is absent")
	}
	if sent := taken.plaintext(fragment.Sent); len(sent) != 0 {
		t.Errorf("the sending functions are unheld and %d sent fragments arrived", len(sent))
	}
	if got := countOf(t, "unmeasurable calls", session.Unmeasurable); got != 0 {
		t.Errorf("no entry probe is placed on the sending functions and %d calls were counted "+
			"through them, which nothing could have seen", got)
	}
}

// A function's return point is not held and its entry is. All three must hold:
// what crosses it is unmeasurable and counted, not zero; a fully placed
// function on the same thread (the fixture's handler thread does both halves of
// each exchange) is still measured; and nothing is left in flight to make a
// later call read as a continuation.
func TestAFunctionWhoseReturnIsNotHeldIsCountedAndLeavesItsThreadCapturing(t *testing.T) {
	session, talking := partial(t, returnless, sending()...)

	refused := unconfirmed(session)
	for _, symbol := range sending() {
		reason, named := refused[symbol]
		if !named {
			t.Errorf("%s has no return program and the kernel confirms the point", symbol)
			continue
		}
		if !strings.Contains(reason, "obs_no_such_return") {
			t.Errorf("%s is unconfirmed and the reason does not name what was missing: %s", symbol, reason)
		}
	}

	talking.ask(t, "/?asked=return-not-held-first")
	first := countOf(t, "unmeasurable calls", session.Unmeasurable)
	if first < 1 {
		t.Fatalf("a response crossed a function with no return probe and %d calls were counted", first)
	}
	// The in-flight count is a baseline, not asserted zero: the keep-alive server
	// parks in a blocking read, one real call in flight. An abandoned entry would
	// show as growth, one live entry per unmeasurable send.
	inFlight := countOf(t, "calls still executing", session.Executing)

	// The same thread, three more exchanges, each a fully placed receive after an
	// unmeasurable send.
	for _, marker := range []string{"second", "third", "fourth"} {
		talking.ask(t, "/?asked=return-not-held-"+marker)
	}
	taken := drain(session, 500*time.Millisecond)

	for _, marker := range []string{"first", "second", "third", "fourth"} {
		if !containsSubstring(taken.plaintext(fragment.Received), "return-not-held-"+marker) {
			t.Errorf("the %s request on this thread is absent, so the thread stopped capturing", marker)
		}
	}
	if sent := taken.plaintext(fragment.Sent); len(sent) != 0 {
		t.Errorf("the sending functions cannot be completed and %d sent fragments arrived", len(sent))
	}

	// The count measures what went through those functions, so it moves with the
	// traffic.
	last := countOf(t, "unmeasurable calls", session.Unmeasurable)
	if last < first+3 {
		t.Errorf("three more exchanges crossed the unmeasurable functions and the count went from "+
			"%d to %d", first, last)
	}
	if grew := countOf(t, "calls still executing", session.Executing) - inFlight; grew >= 3 {
		t.Errorf("the in-flight count grew by %d over three more exchanges through a function that "+
			"cannot complete one; an entry abandoned by each unmeasurable send would grow it by "+
			"exactly that, and a thread parked in a keep-alive read would not grow it at all", grew)
	}
}

// A process with a child when the policy is resolved that forks another
// afterwards, both transferring, so a run says which it observed. The early
// child waits on a file: a forked child shares the parent's stdin, and two
// readers of one pipe race.
const forkingBeforeAndAfter = `
import http.client, os, ssl, sys, time

port, gate = int(sys.argv[1]), sys.argv[2]

def ask(path):
    context = ssl._create_unverified_context()
    connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=10)
    connection.request("GET", path)
    connection.getresponse().read()
    connection.close()

early = os.fork()
if early == 0:
    while not os.path.exists(gate):
        time.sleep(0.01)
    ask("/fork-early")
    os._exit(0)

print("ready", os.getpid(), flush=True)
sys.stdin.readline()
open(gate, "w").close()
ask("/fork-parent")
late = os.fork()
if late == 0:
    ask("/fork-late")
    os._exit(0)
os.waitpid(early, 0)
os.waitpid(late, 0)
print("done", flush=True)
sys.stdin.readline()
`

// forkingProcess starts the fixture above and returns its pid, its answer
// reader, and its release.
func forkingProcess(t *testing.T, port int) (int32, *bufio.Reader, func()) {
	t.Helper()

	directory := t.TempDir()
	script := filepath.Join(directory, "forking.py")
	if err := os.WriteFile(script, []byte(forkingBeforeAndAfter), 0o600); err != nil {
		t.Fatalf("write the forking fixture: %v", err)
	}

	command := exec.Command("python3", script, fmt.Sprint(port), filepath.Join(directory, "gate"))
	send, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start the forking fixture: %v", err)
	}
	t.Cleanup(func() {
		_ = send.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	said := bufio.NewReader(out)
	line, err := said.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "ready") {
		t.Fatalf("the forking fixture did not come up: %q %v", line, err)
	}
	return int32(command.Process.Pid), said, func() {
		if _, err := io.WriteString(send, "go\n"); err != nil {
			t.Fatalf("release the forking fixture: %v", err)
		}
		for {
			line, err := said.ReadString('\n')
			if err != nil {
				t.Fatalf("the forking fixture stopped before it finished: %v", err)
			}
			if strings.HasPrefix(line, "done") {
				return
			}
		}
	}
}

// A descendant present when the policy was resolved and one created afterwards,
// neither needing a fork point on the C library: the process-table walk finds
// the first and the kernel's fork event admits the second before it runs.
func TestADescendantCreatedAfterThePolicyIsObservedWithNoForkPointHeld(t *testing.T) {
	_, port := serving(t)
	pid, _, release := forkingProcess(t, port)
	parent := loaded(t, pid)
	moveToCgroup(t, "obs-partial-fork", parent.PID)

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  points(t, parent),
		Admit:   authorise(parent),
	})
	if err != nil {
		t.Fatalf("attach with no fork point: %v", err)
	}
	defer func() { _ = session.Close() }()

	// No fork point was asked for, and the session still reports what this process
	// creates as observed: the policy's answer, backed by the kernel fork event.
	if !session.Coverage().Descendants {
		t.Fatal("a session admitting under follow says what its approved process creates is " +
			"unobserved, so the answer is still resting on a placement")
	}

	release()
	taken := drain(session, 700*time.Millisecond)
	sent := taken.plaintext(fragment.Sent)

	// The control: the approved process itself is observed, or a missing child and
	// a failed attachment look alike.
	if !containsSubstring(sent, "/fork-parent") {
		t.Fatal("the approved process's own plaintext did not appear, so this run measures nothing " +
			"about what it forks")
	}
	if !containsSubstring(sent, "/fork-early") {
		t.Error("a descendant already running when the policy was resolved is unobserved, and the " +
			"walk that admits it does not need a fork point")
	}
	if !containsSubstring(sent, "/fork-late") {
		t.Error("a descendant created after the policy was resolved is unobserved with no fork " +
			"point held, so admission is resting on that point rather than on the kernel's own " +
			"fork event")
	}
}

// socketPointsFor is every socket entry point of the process's C library, built
// here so a session can be attached with and without them.
func socketPointsFor(t *testing.T, p process.Process) []ebpf.Point {
	t.Helper()

	mappings, err := process.Mappings(procfs, p.PID)
	if err != nil {
		t.Fatalf("read the process mappings: %v", err)
	}
	for _, mapping := range mappings {
		if !mapping.Executable || !strings.HasPrefix(filepath.Base(mapping.Path), "libc.so") {
			continue
		}
		path := filepath.Join(procfs, fmt.Sprint(p.PID), "root", mapping.Path)
		offsets, err := probe.SymbolOffsets(path, ebpf.SocketSymbols())
		if err != nil {
			t.Fatalf("resolve the socket entry points: %v", err)
		}
		var placed []ebpf.Point
		for _, symbol := range ebpf.SocketSymbols() {
			offset, resolved := offsets[symbol]
			if !resolved {
				continue
			}
			placed = append(placed, ebpf.SocketPoint(symbol, path, offset))
		}
		if len(placed) == 0 {
			t.Fatalf("the process's C library exports none of %v", ebpf.SocketSymbols())
		}
		return placed
	}
	t.Fatal("the process maps no executable C library")
	return nil
}

// bindings is what each transfer event says was established about its socket.
func bindings(taken captured) []probe.Bound {
	var states []probe.Bound
	for _, event := range taken.events {
		if event.Kind == ebpf.Transfer {
			states = append(states, event.Bound)
		}
	}
	return states
}

// The socket a call used comes from the kernel evidence group alone: with it
// placed a binding is established, and with it withheld none is, even with all
// fourteen C library socket points placed (those maintain the occupancy table
// and establish nothing; binding through them would be a second resolver). The
// control is a second session: bindings belong to the handle and the group
// attaches to the kernel, so only what a session was given can differ.
func TestOnlyTheKernelEvidenceEstablishesTheSocketACallUsed(t *testing.T) {
	serverPID, port := serving(t)
	server := loaded(t, serverPID)
	moveToCgroup(t, "obs-partial-bind", server.PID)

	// The control: the group is placed and a binding is established.
	held, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  append(points(t, server), socketPointsFor(t, server)...),
		Admit:   authorise(server),
	})
	if err != nil {
		t.Fatalf("attach with the kernel evidence group: %v", err)
	}
	if !held.Coverage().SocketEvidence {
		withheld := held.Withheld()
		_ = held.Close()
		t.Fatalf("this kernel does not hold the socket evidence group, so this run measures a "+
			"host rather than the mechanism: %v", withheld)
	}
	speaking(t, port).ask(t, "/?asked=binding-control")
	established := bindings(drain(held, 700*time.Millisecond))
	if err := held.Close(); err != nil {
		t.Fatalf("close the session that held the group: %v", err)
	}

	if len(established) == 0 {
		t.Fatal("no transfer arrived with the group placed, so this run measures nothing about " +
			"what its absence costs")
	}
	bound := 0
	for _, state := range established {
		if state == probe.BoundTo {
			bound++
		}
	}
	if bound == 0 {
		t.Fatalf("the group was placed and none of %d transfers established a binding, so the "+
			"producer is not working and nothing below is about a withheld claim",
			len(established))
	}

	// The group withheld and every C library socket point placed: no binding at
	// all, or there would be two competing resolvers.
	blind, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  append(points(t, server), socketPointsFor(t, server)...),
		Admit:   authorise(server),
		Kernel:  []ebpf.KernelPoint{},
	})
	if err != nil {
		t.Fatalf("attach with the group withheld: %v", err)
	}
	defer func() { _ = blind.Close() }()

	if blind.Coverage().SocketEvidence {
		t.Fatal("no member of the group was asked for and this session claims the socket evidence")
	}
	speaking(t, port).ask(t, "/?asked=binding-absent")
	unbound := bindings(drain(blind, 700*time.Millisecond))

	if len(unbound) == 0 {
		t.Fatal("no transfer arrived with the group withheld, so nothing here is about the association")
	}
	for i, state := range unbound {
		if state != probe.NotBound {
			t.Errorf("transfer %d reports %s through a session holding no kernel evidence at all, "+
				"which is a second resolver answering where the first was withheld", i, state)
		}
	}
}

// occupancyOnly is the socket points that maintain the occupancy table and
// record no descriptor: socket, accept, accept4, connect, close and dup2.
func occupancyOnly(points []ebpf.Point) []ebpf.Point {
	recording := []string{"sendto", "recvfrom", "sendmsg", "recvmsg", "read", "write", "readv", "writev"}
	var kept []ebpf.Point
	for _, point := range points {
		if !containsSubstringExact(recording, point.Symbol) {
			kept = append(kept, point)
		}
	}
	return kept
}

// The occupancy-table socket points establish no binding, on a real kernel.
// This session holds six of fourteen socket entry points, all placed, and
// Coverage.Binding is false; claiming otherwise would present session facts as
// facts about the observed process. The Coverage.Binding assertion tells these
// six from the recording family. The no-transfer-binds assertion guards that
// nothing but the kernel evidence establishes a socket: the row above proves
// the group binds, and this proves nothing else does.
func TestASessionHoldingOnlyTheOccupancyPointsBindsNothingOnAKernel(t *testing.T) {
	serverPID, port := serving(t)
	server := loaded(t, serverPID)
	moveToCgroup(t, "obs-partial-occupancy", server.PID)

	occupancy := occupancyOnly(socketPointsFor(t, server))
	if len(occupancy) == 0 {
		t.Fatal("the C library resolved none of the occupancy points, so this run stages nothing")
	}

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  append(points(t, server), occupancy...),
		Admit:   authorise(server),
		// Withheld as above: the group binds without any C library point, so holding
		// it would measure the group.
		Kernel: []ebpf.KernelPoint{},
	})
	if err != nil {
		t.Fatalf("attach with the occupancy points alone: %v", err)
	}
	defer func() { _ = session.Close() }()

	// The kernel holds every one of them, so what follows is about what they can
	// do.
	for _, placement := range session.Confirmed() {
		if !placement.Confirmed {
			t.Fatalf("%s did not place, so this run measures a refusal rather than a capability: %s",
				placement.Symbol, placement.Refusal)
		}
	}
	if session.Coverage().Binding {
		t.Errorf("this session holds %d occupancy points and none that records a descriptor, "+
			"and it says it establishes a binding", len(occupancy))
	}

	speaking(t, port).ask(t, "/?asked=occupancy-only")
	taken := bindings(drain(session, 700*time.Millisecond))
	if len(taken) == 0 {
		t.Fatal("no transfer arrived, so nothing here is about the association")
	}
	for i, state := range taken {
		if state != probe.NotBound {
			t.Errorf("transfer %d reports %s through a session that records no descriptor "+
				"against any call", i, state)
		}
	}
}

// The socket is established with no C library binding source placed at all:
// the counterpart of the rows above, so the pair locates which mechanism did
// the work. It is also a host missing an old C library binding symbol with all
// kernel members present, reached here by not asking for the symbol.
func TestTheKernelEvidenceBindsWithNoLibraryBindingSourcePlaced(t *testing.T) {
	serverPID, port := serving(t)
	server := loaded(t, serverPID)
	moveToCgroup(t, "obs-kernel-evidence", server.PID)

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  points(t, server),
		Admit:   authorise(server),
	})
	if err != nil {
		t.Fatalf("attach with the kernel evidence group and no socket entry point: %v", err)
	}
	defer func() { _ = session.Close() }()

	coverage := session.Coverage()
	if !coverage.SocketEvidence {
		t.Fatalf("this kernel does not hold the socket evidence group, so this run measures a "+
			"host rather than the mechanism: %v", session.Withheld())
	}
	if coverage.Binding {
		t.Fatal("no C library binding source was asked for and this session says it holds one, " +
			"so a binding below would not be the group's doing")
	}

	speaking(t, port).ask(t, "/?asked=kernel-evidence")
	taken := bindings(drain(session, 700*time.Millisecond))
	if len(taken) == 0 {
		t.Fatal("no transfer arrived, so nothing here is about the association")
	}

	bound := 0
	for _, state := range taken {
		if state == probe.BoundTo {
			bound++
		}
	}
	if bound == 0 {
		t.Errorf("none of %d transfers established a binding through the kernel evidence group, "+
			"with every member of it placed", len(taken))
	}
}

// The socket identity this run publishes is the kernel's: a reader outside the
// observer can ask the kernel which socket a process holds and compare.
// /proc/<pid>/fd/<n> reads socket:[N], the same N /proc/net/tcp carries
// against the connection's address pair.
func TestThePublishedSocketIsTheOneProcNames(t *testing.T) {
	serverPID, port := serving(t)
	server := loaded(t, serverPID)
	moveToCgroup(t, "obs-socket-identity", server.PID)

	session, err := ebpf.Attach(ebpf.Options{
		Program: bpf.Full(),
		Points:  points(t, server),
		Admit:   authorise(server),
	})
	if err != nil {
		t.Fatalf("attach with the kernel evidence group: %v", err)
	}
	defer func() { _ = session.Close() }()

	if !session.Coverage().SocketEvidence {
		t.Fatalf("this kernel does not hold the socket evidence group: %v", session.Withheld())
	}

	speaking(t, port).ask(t, "/?asked=socket-identity")
	taken := drain(session, 700*time.Millisecond)

	published := make(map[uint64]bool)
	for _, event := range taken.events {
		if event.Kind == ebpf.Transfer && event.Bound == probe.BoundTo && event.Socket != 0 {
			published[event.Socket] = true
		}
	}
	if len(published) == 0 {
		t.Fatal("no transfer arrived carrying a socket identity, so nothing here compares anything")
	}

	// What the kernel says the process holds, read as anyone outside would.
	held := socketsNamedByProc(t, serverPID)
	if len(held) == 0 {
		t.Fatalf("/proc/%d/fd names no socket at all, so this run measures nothing", serverPID)
	}

	for inode := range published {
		if !held[inode] {
			t.Errorf("this run published socket:[%d] and /proc/%d/fd names %v, so the number it "+
				"reports is not the one the kernel does", inode, serverPID, sorted(held))
		}
	}
}

// socketsNamedByProc is every socket inode the kernel says a process holds,
// from its descriptor links.
func socketsNamedByProc(t *testing.T, pid int32) map[uint64]bool {
	t.Helper()
	dir := filepath.Join("/proc", strconv.FormatInt(int64(pid), 10), "fd")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	held := make(map[uint64]bool, len(entries))
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(dir, entry.Name()))
		if err != nil {
			// A descriptor closed between the listing and the read.
			continue
		}
		rest, isSocket := strings.CutPrefix(target, "socket:[")
		if !isSocket {
			continue
		}
		number, err := strconv.ParseUint(strings.TrimSuffix(rest, "]"), 10, 64)
		if err != nil {
			continue
		}
		held[number] = true
	}
	return held
}

func sorted(held map[uint64]bool) []uint64 {
	numbers := make([]uint64, 0, len(held))
	for number := range held {
		numbers = append(numbers, number)
	}
	slices.Sort(numbers)
	return numbers
}
