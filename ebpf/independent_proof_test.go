//go:build attach

package ebpf_test

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/capture"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

type proofCollection struct {
	fragments []fragment.Record
	records   []connection.Record
}

func (p *proofCollection) Write(r fragment.Record) error {
	p.fragments = append(p.fragments, r)
	return nil
}
func (p *proofCollection) Connection(r connection.Record) error {
	p.records = append(p.records, r)
	return nil
}

type proofRun struct {
	actor     *armingProcess
	session   *ebpf.Session
	recording *capture.Session
	collected *proofCollection
	who       process.Process
	events    []ebpf.Event
	points    []ebpf.Point
	peers     chan *tls.Conn
	bytes     atomic.Int64
}

func proofFixture(t *testing.T, resize map[string]uint32) *proofRun {
	return proofConfigured(t, resize, nil)
}
func proofConfigured(t *testing.T, resize map[string]uint32, configure func(*ebpf.Options)) *proofRun {
	t.Helper()
	cert := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer cert.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: cert.TLS.Certificates})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	r := &proofRun{peers: make(chan *tls.Conn, 64), collected: &proofCollection{}}
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c *tls.Conn) {
				defer func() { _ = c.Close() }()
				if c.Handshake() != nil {
					return
				}
				r.peers <- c
				b := make([]byte, 4096)
				for {
					n, e := c.Read(b)
					r.bytes.Add(int64(n))
					if e != nil {
						return
					}
				}
			}(c.(*tls.Conn))
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	p, _ := strconv.Atoi(port)
	source, err := os.ReadFile("testdata/independent_proof.c")
	if err != nil {
		t.Fatal(err)
	}
	r.actor = independentActor(t, string(source), p)
	r.who = loaded(t, int32(r.actor.command.Process.Pid))
	r.points = points(t, r.who)
	options := ebpf.Options{Program: bpf.Full(), Points: append([]ebpf.Point(nil), r.points...), Admit: authorise(r.who), Resize: resize, Staging: 1}
	if configure != nil {
		configure(&options)
	}
	r.session, err = ebpf.Attach(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.session.Close() })
	r.recording = capture.Recording(r.collected, r.collected, capture.Settles(r.session))
	return r
}
func (r *proofRun) command(t *testing.T, line string) string {
	t.Helper()
	if _, err := fmt.Fprintln(r.actor.input, line); err != nil {
		t.Fatal(err)
	}
	out, err := r.actor.output.ReadString('\n')
	if err != nil {
		t.Fatalf("wiring, not property: command %s response %q: %v", line, out, err)
	}
	return strings.TrimSpace(out)
}
func (r *proofRun) open(t *testing.T, i int) (uint64, *tls.Conn) {
	t.Helper()
	out := r.command(t, fmt.Sprintf("N %d", i))
	var got int
	var addr uint64
	if _, e := fmt.Sscanf(out, "N %d %d", &got, &addr); e != nil || got != i || addr == 0 {
		t.Fatalf("wiring: open %q", out)
	}
	select {
	case c := <-r.peers:
		return addr, c
	case <-time.After(time.Second):
		t.Fatal("wiring: TLS peer absent")
	}
	return 0, nil
}
func (r *proofRun) consume() {
	for {
		select {
		case e := <-r.session.Events():
			r.events = append(r.events, e)
			instance := admission.Instance{Namespace: e.Namespace, PID: e.NamespacePID, Generation: e.Generation, Start: r.who.Start(), Executable: r.who.Executable}
			if e.Kind == ebpf.Closed {
				r.recording.Closed(probe.Connection{Instance: instance, Process: r.who.Identity(), Endpoint: e.SSL, Stamp: e.Stamp, Sequence: e.Sequence, Final: e.Final, At: e.At})
			} else {
				r.recording.Transfer(probe.Transfer{Instance: instance, Process: r.who.Identity(), Endpoint: e.SSL, Stamp: e.Stamp, Sequence: e.Sequence, At: e.At, Direction: e.Direction, Measured: e.Measured, Length: e.Length, Payload: e.Payload, Descriptor: e.Descriptor, Binding: e.Binding, Bound: e.Bound, Socket: e.Socket, Outcome: e.Outcome, Ends: e.Endpoints})
			}
		case <-time.After(20 * time.Millisecond):
			return
		}
	}
}
func (r *proofRun) finish(t *testing.T) {
	t.Helper()
	w, e := r.session.StopProducing()
	if e != nil || !w.Complete {
		t.Fatalf("wiring: withdrawal %+v %v", w, e)
	}
	r.consume()
	d, e := r.session.Drain(time.Second)
	if e != nil || !d.Complete {
		t.Fatalf("wiring: drain %+v %v", d, e)
	}
	r.consume()
	r.recording.Finish(time.Now())
}
func proofCounter(t *testing.T, f func() (int64, error)) int64 {
	t.Helper()
	n, e := f()
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func (r *proofRun) identity(e ebpf.Event) probe.Handle {
	return probe.Handle{Instance: admission.Instance{Namespace: e.Namespace, PID: e.NamespacePID, Generation: e.Generation, Start: r.who.Start(), Executable: r.who.Executable}.Key(), Endpoint: e.SSL}
}
func (r *proofRun) gaps(t *testing.T) (int64, int, int) {
	t.Helper()
	var total int64
	affected, whole := 0, 0
	for _, rec := range r.collected.records {
		var last, offset, cut uint64
		var missing int64
		cut = ^uint64(0)
		occ := uint64(0)
		for _, e := range r.events {
			if e.SSL != rec.Handle.Address || e.Kind != ebpf.Transfer || e.Direction != fragment.Sent || e.Length == 0 {
				continue
			}
			if occ == 0 {
				occ = e.Sequence.Occupancy
			}
			if e.Sequence.Number <= last {
				t.Fatalf("wiring: serial producer number %d after %d", e.Sequence.Number, last)
			}
			if e.Sequence.Number > last+1 {
				if cut == ^uint64(0) {
					cut = offset
				}
				missing += int64(e.Sequence.Number - last - 1)
			}
			last = e.Sequence.Number
			offset += uint64(e.Length)
		}
		if occ == 0 {
			t.Fatal("wiring: no numbered stream")
		}
		var final probe.Final
		for _, e := range r.events {
			if e.Kind == ebpf.Closed && e.Sequence.Occupancy == occ {
				final = e.Final
			}
		}
		if !final.Known {
			t.Fatal("wiring: missing close final")
		}
		if final.Sent.Last > last {
			missing += int64(final.Sent.Last - last)
			if cut == ^uint64(0) {
				cut = offset
			}
		}
		p, ok := rec.Placement(fragment.Sent)
		if !ok {
			t.Fatal("wiring: missing placement")
		}
		if missing > 0 {
			affected++
			if p.Whole() || p.Placeable(cut) || (cut > 0 && !p.Placeable(cut-1)) {
				t.Errorf("COUNTEREXAMPLE: %d missing producer numbers but offset %d placeable: %+v", missing, cut, p)
			}
		} else {
			whole++
			if !p.Whole() {
				t.Errorf("loss-free control cut: %+v", p)
			}
		}
		total += missing
	}
	return total, affected, whole
}
func TestIndependentProofRingAndConcurrentHandles(t *testing.T) {
	for _, handles := range []int{1, 19} {
		t.Run(fmt.Sprint(handles), func(t *testing.T) {
			r := proofFixture(t, map[string]uint32{"events": 32768})
			for i := 0; i < handles; i++ {
				r.open(t, i)
				r.command(t, fmt.Sprintf("W %d 1", i))
				r.consume()
			}
			if out := r.command(t, fmt.Sprintf("B %d 83", handles)); out != "B ok" {
				t.Fatal(out)
			}
			dropped := proofCounter(t, r.session.Dropped)
			if dropped == 0 {
				t.Fatalf("UNPROVED: attempts=%d ring failures=0", handles*83)
			}
			r.consume()
			for i := 0; i < handles; i++ {
				r.command(t, fmt.Sprintf("W %d 1", i))
				r.consume()
			}
			r.open(t, handles)
			r.command(t, fmt.Sprintf("E %d 1", handles))
			r.consume()
			for i := 0; i <= handles; i++ {
				r.command(t, fmt.Sprintf("F %d", i))
				r.consume()
			}
			r.finish(t)
			lost, affected, whole := r.gaps(t)
			if lost != dropped {
				t.Errorf("COUNTEREXAMPLE: raw numbers missing=%d ring failures=%d", lost, dropped)
			}
			if whole < 1 {
				t.Fatal("wiring: no intact fresh control")
			}
			t.Logf("PRECONDITIONS handles=%d byte_calls=%d ring_failures=%d missing=%d affected=%d whole=%d peer_bytes=%d", handles, handles*85+1, dropped, lost, affected, whole, r.bytes.Load())
		})
	}
}
func TestIndependentProofUnlocated(t *testing.T) {
	r := proofFixture(t, map[string]uint32{"occupancies": 2})
	for i := 0; i < 3; i++ {
		r.open(t, i)
		r.command(t, fmt.Sprintf("W %d 1", i))
		r.consume()
	}
	u, e := r.session.Unlocated()
	if e != nil || u == 0 {
		t.Fatalf("UNPROVED: unlocated=%d err=%v", u, e)
	}
	r.command(t, "W 0 1")
	r.consume()
	r.command(t, "F 1")
	r.consume()
	prior := make(map[uint64]bool)
	for _, event := range r.events {
		prior[event.Sequence.Occupancy] = true
	}
	r.open(t, 3)
	r.command(t, "W 3 1")
	r.consume()
	r.finish(t)
	unsequenced, bornAfter := 0, 0
	for _, e := range r.events {
		if e.Kind == ebpf.Transfer {
			if e.Sequence.Occupancy == 0 {
				unsequenced++
			}
			if e.Sequence.Born && !prior[e.Sequence.Occupancy] && e.Sequence.Number == 1 && e.Sequence.Unlocated >= u {
				bornAfter++
			}
		}
	}
	if unsequenced == 0 || bornAfter == 0 {
		t.Fatalf("UNPROVED: unsequenced=%d born_after=%d", unsequenced, bornAfter)
	}
	for _, rec := range r.collected.records {
		if p, ok := rec.Placement(fragment.Sent); ok && p.Whole() {
			t.Errorf("COUNTEREXAMPLE: conservative rule certified %+v", rec)
		}
	}
	t.Logf("PRECONDITIONS table_capacity=2 rejected=%d unlocated=%d unsequenced=%d born_after=%d", proofCounter(t, r.session.OccupanciesUnrecorded), u, unsequenced, bornAfter)
}
func TestIndependentProofLostFreeAndReuse(t *testing.T) {
	r := proofFixture(t, map[string]uint32{"events": 32768})
	old, _ := r.open(t, 0)
	r.command(t, "W 0 1")
	r.consume()
	first := r.events[len(r.events)-1]
	r.command(t, "W 0 97")
	before := proofCounter(t, r.session.Dropped)
	if before == 0 {
		t.Fatal("UNPROVED: no ring failures")
	}
	r.command(t, "F 0")
	after := proofCounter(t, r.session.Dropped)
	if after-before != 1 {
		t.Fatalf("UNPROVED: free reservation failures=%d", after-before)
	}
	r.consume()
	out := r.command(t, fmt.Sprintf("R 0 %d", old))
	var idx, tries int
	var addr uint64
	if _, e := fmt.Sscanf(out, "R %d %d %d", &idx, &addr, &tries); e != nil || addr != old {
		t.Fatalf("UNPROVED: same address not reused: %q", out)
	}
	r.command(t, "W 0 1")
	r.consume()
	latest := r.events[len(r.events)-1]
	if !latest.Sequence.Born || latest.Sequence.Occupancy == first.Sequence.Occupancy {
		t.Errorf("COUNTEREXAMPLE: successor not distinct born occupancy: %+v %+v", first.Sequence, latest.Sequence)
	}
	r.command(t, "F 0")
	r.consume()
	r.finish(t)
	if len(r.collected.records) != 2 {
		t.Fatalf("occupancies spliced: records=%d", len(r.collected.records))
	}
	p, _ := r.collected.records[1].Placement(fragment.Sent)
	if !p.Whole() {
		t.Errorf("fresh successor cut: %+v", p)
	}
	t.Logf("PRECONDITIONS lost_free=%d same_address=%d allocation_attempts=%d old_occupancy=%d new_occupancy=%d", after-before, addr, tries, first.Sequence.Occupancy, latest.Sequence.Occupancy)
}
func TestIndependentProofOverlapAndWrappers(t *testing.T) {
	r := proofFixture(t, nil)
	_, peer := r.open(t, 0)
	r.command(t, "E 0 3")
	r.consume()
	wrappers := proofCounter(t, r.session.NestedWrappers)
	if wrappers == 0 {
		t.Fatal("UNPROVED: wrapper occurrences=0")
	}
	r.command(t, "O")
	deadline := time.Now().Add(time.Second)
	seen := false
	for time.Now().Before(deadline) {
		st, e := r.session.Settled(r.identity(r.events[0]))
		if e != nil {
			t.Fatal(e)
		}
		if st.Final.Received.InFlight {
			seen = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !seen {
		t.Fatal("UNPROVED: first read not in flight")
	}
	r.command(t, "Z")
	over := proofCounter(t, r.session.Overlapped)
	deadline = time.Now().Add(time.Second)
	for over == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		over = proofCounter(t, r.session.Overlapped)
	}
	if over == 0 {
		t.Fatal("UNPROVED: overlap occurrences=0")
	}
	if _, e := peer.Write([]byte("x")); e != nil {
		t.Fatal(e)
	}
	time.Sleep(50 * time.Millisecond)
	_ = peer.Close()
	out := r.command(t, "J")
	var firstRead, secondRead int
	if _, err := fmt.Sscanf(out, "J %d %d", &firstRead, &secondRead); err != nil || (firstRead != 1 && secondRead != 1) {
		t.Fatalf("wiring: neither read completed: %s", out)
	}
	r.consume()
	r.command(t, "F 0")
	r.consume()
	r.finish(t)
	marked := 0
	for _, e := range r.events {
		if e.Sequence.Overlapped {
			marked++
		}
	}
	if marked == 0 {
		t.Fatal("COUNTEREXAMPLE: overlapping read emitted unmarked")
	}
	for _, rec := range r.collected.records {
		p, _ := rec.Placement(fragment.Received)
		if p.Whole() || p.Because != connection.OperationsOverlapped {
			t.Errorf("COUNTEREXAMPLE: overlap certified %+v", p)
		}
	}
	t.Logf("PRECONDITIONS overlapping_entries=%d marked_events=%d nested_wrappers=%d", over, marked, wrappers)
}
