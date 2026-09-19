package attach

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/ebpf"
	"github.com/evandukss/edge-observer/fragment"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl"
	"github.com/evandukss/edge-observer/process"
)

// EBPF is the OpenSSL adapter, attached through a BPF program that reads the
// caller's plaintext buffer. It is the only attaching adapter: a host that
// cannot load the program is refused, because every other way copies no
// plaintext (probe.Request.Unmet). Every build loads the full program
// (program.go, package bpf).
type EBPF struct {
	// Adapter answers whether a process can be observed and where its entry
	// points are; the catalogue it carries decides what this attaches to.
	Adapter openssl.Adapter

	// approval is the attach policy: which library builds and offsets a probe may
	// be placed on. An empty policy approves whatever a process maps.
	approval process.Approval
}

// NeweBPF builds the OpenSSL adapter against the running host. The approval
// carries the attach policy the adapter enforces before it places a probe.
func NeweBPF(approval process.Approval) EBPF {
	return EBPF{Adapter: openssl.New(), approval: approval}
}

func (a EBPF) Name() string { return a.Adapter.Name() }

// Loads loads this build's program into the running kernel and closes it, with
// no probe placed: whether this kernel takes the program a capture would load
// (preflight, ProgramLoad).
func Loads() error { return ebpf.Loads(defaultProgram()) }

func (a EBPF) Inspect(p process.Process) probe.Support { return a.Adapter.Inspect(p) }

// Built is what this build can do, read off the program it loads. A dry run
// and an account state it as the build's capability, and a run requires it of
// its attachment: a run that could only reach a backend copying no plaintext
// would reconstruct no bytes, which is also what a correctly attached observer
// on a silent host produces.
func Built() probe.Capability {
	program := defaultProgram()
	return probe.Capability{
		Backend: probe.BPF,
		Program: program.Name,
		Payload: program.ReadsPayload,
		// The allowlist is inside the program, ahead of every read: a call by an
		// unapproved process is refused in the kernel and nothing crosses to userspace.
		Filtered: true,
		// A child is admitted at the kernel's fork event, before it can run, so it is
		// observed from its first call (package ebpf, forkTracepoint).
		Descendants: true,
		// The lifecycle family carries a program, so a connection ending is observed
		// and a reused address does not continue the previous stream.
		Lifecycle: true,
		// The socket entry points carry programs, so a descriptor can be recorded
		// against a call. That does not establish the socket (below).
		Binding: true,
		// The kernel evidence group carries programs, so a call's socket can be taken
		// from the object the kernel acquired for its I/O, for both address families.
		// This is what the build can do; a session narrows it to what the kernel took
		// (package ebpf, Coverage.Narrow).
		SocketEvidence: true,
		IPv6:           true,
		MinimumKernel:  ebpf.MinimumKernel,
	}
}

func (a EBPF) Capability() probe.Capability { return Built() }

// Attach loads the program, authorises the requested processes, places the
// probes and delivers what they report to the sink: one placement per library
// file, covering every requested process running it. A host that will not run
// the program is refused the whole attachment.
func (a EBPF) Attach(request probe.Request, sink probe.Sink) (probe.Attachment, error) {
	if len(request.Processes) == 0 {
		return nil, errors.New("a request names the processes to observe, and this one names none")
	}

	// A build with no plaintext program can never satisfy a request, so it is
	// refused before any probe is placed.
	if err := request.Unmet(a.Capability()); err != nil {
		return nil, err
	}

	attached := newSet()
	attached.adapter = &a
	objects, unsupported := a.objects(request)
	for pid, err := range unsupported {
		attached.refuse(pid, err)
	}

	for _, one := range objects {
		live, declined, err := a.place(one, sink)
		if err == nil {
			for _, refused := range declined {
				attached.refuse(refused.Selection.ObserverPID, refused.Err)
			}
			// A placement covers only the processes it was authorised for. A declined
			// process is left out: the probes are on the file, but the allowlist refuses
			// its calls, so it is not observed and must not be reported as observed.
			attached.placeOn(one.file, live, observed(one.processes, declined)...)
			continue
		}
		if !errors.Is(err, ebpf.ErrUnavailable) && !errors.Is(err, ebpf.ErrRefused) {
			for _, p := range one.processes {
				attached.refuse(p.PID, err)
			}
			continue
		}

		// The host will not run the program and nothing else copies plaintext, so the
		// whole attachment is refused: continuing would look, for that process, like
		// watching a silent host.
		_ = attached.Close()
		return nil, fmt.Errorf("%w: this host will not run the %s program: %v", probe.ErrDegraded, Built().Program, err)
	}

	if attached.placed() == 0 {
		_ = attached.Close()
		return nil, errors.Join(noneAttached(request, attached)...)
	}

	// Checked again against what placed: placements that hold no probe on any
	// function plaintext crosses would run with an empty reconstruction. A
	// partial placement is kept: a set holding one transfer probe copies what
	// crosses it, and its capability names what did not place.
	if err := request.Unmet(attached.Capability()); err != nil {
		_ = attached.Close()
		return nil, err
	}
	return attached, nil
}

// object is one library file, every requested process running it, and why
// each is admitted.
type object struct {
	support   probe.Support
	processes []process.Process
	admit     []admission.Selection

	// file is the library file, by which a reload routes a new process.
	file fileID

	// deny is the whole exclusion set: a denial applies wherever the probes are,
	// because the subtree it denies can reach any of them.
	deny []admission.Denial
}

// objects groups the requested processes by the library file a probe would be
// placed on, and says why any cannot be observed. The key is the file's device
// and inode, never the path: paths are reached through each process's own
// root, so one file can have two strings, and grouping on the string would
// place the probes twice and report every call twice, doubling counts and
// offsets. A file that cannot be identified is not grouped and its processes
// are refused.
func (a EBPF) objects(request probe.Request) ([]object, map[int32]error) {
	processes := request.Processes
	unsupported := make(map[int32]error, len(processes))
	var found []object
	at := make(map[fileID]int, len(processes))

	admit := make(map[int32]admission.Selection, len(request.Admit))
	for _, one := range request.Admit {
		admit[one.ObserverPID] = one
	}

	for _, p := range processes {
		granted, named := admit[p.PID]
		if !named {
			// The two halves of the request came from different readings. Admitting on
			// one would allowlist a process with no target and no mode, which nothing
			// could later withdraw by name.
			unsupported[p.PID] = fmt.Errorf("pid %d is in the request and no admission says why, "+
				"so nothing here can say which target selected it", p.PID)
			continue
		}
		support, id, err := a.library(p, request)
		if err != nil {
			unsupported[p.PID] = err
			continue
		}
		if index, grouped := at[id]; grouped {
			found[index].processes = append(found[index].processes, p)
			found[index].admit = append(found[index].admit, granted)
			continue
		}
		at[id] = len(found)
		found = append(found, object{
			support:   support,
			processes: []process.Process{p},
			admit:     []admission.Selection{granted},
			deny:      request.Deny,
			file:      id,
		})
	}
	return found, unsupported
}

// fileID is the device and inode a probe is held against.
type fileID struct {
	device uint64
	inode  uint64
}

// library is which library p runs and what the adapter said of it: taken from
// the request where it carries its reading (probe.Request.Read), since a
// session reloading can no longer read /proc/<pid>/maps or root; read here
// otherwise.
func (a EBPF) library(p process.Process, request probe.Request) (probe.Support, fileID, error) {
	if read, given := request.Read[p.PID]; given {
		support := supportIn(read.Report)
		if !support.Supported {
			return support, fileID{}, fmt.Errorf("%w: pid %d: %s", probe.ErrUnsupported, p.PID, read.Report.Reason())
		}
		return support, fileID{device: read.Library.Device, inode: read.Library.Inode}, nil
	}
	support := a.Adapter.Inspect(p)
	if !support.Supported {
		return support, fileID{}, fmt.Errorf("%w: pid %d: %s", probe.ErrUnsupported, p.PID, support.Reason)
	}
	id, err := identify(openssl.Path(support))
	if err != nil {
		return support, fileID{}, fmt.Errorf("pid %d: %w", p.PID, err)
	}
	return support, id, nil
}

// supportIn is the answer of the adapter a report says will observe the
// process, or the zero value.
func supportIn(report probe.Report) probe.Support {
	for _, one := range report.Support {
		if one.Adapter == report.Adapter && one.Supported {
			return one
		}
	}
	return probe.Support{}
}

// Identify is which library file and C library file p runs, by which a
// running session routes a reload. The reload command calls it, holding the
// privilege the session gave up after attaching.
func (a EBPF) Identify(p process.Process, report probe.Report) (library, libc probe.FileID, err error) {
	support := supportIn(report)
	if !support.Supported {
		return probe.FileID{}, probe.FileID{}, fmt.Errorf("pid %d: %s", p.PID, report.Reason())
	}
	id, err := identify(openssl.Path(support))
	if err != nil {
		return probe.FileID{}, probe.FileID{}, fmt.Errorf("pid %d: %w", p.PID, err)
	}
	c, err := a.libcOf(p)
	if err != nil {
		return probe.FileID{}, probe.FileID{}, fmt.Errorf("pid %d: %w", p.PID, err)
	}
	return probe.FileID{Device: id.device, Inode: id.inode}, probe.FileID{Device: c.device, Inode: c.inode}, nil
}

func identify(path string) (fileID, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileID{}, fmt.Errorf("identify the library at %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, fmt.Errorf("this platform does not say which file %s is", path)
	}
	return fileID{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

// observed is the processes a placement watches: those asked for, less those
// the kernel was never given an authorisation for.
func observed(processes []process.Process, declined []ebpf.Declined) []int32 {
	refused := make(map[int32]bool, len(declined))
	for _, one := range declined {
		refused[one.Selection.ObserverPID] = true
	}

	found := make([]int32, 0, len(processes))
	for _, p := range processes {
		if !refused[p.PID] {
			found = append(found, p.PID)
		}
	}
	return found
}

// place attaches one library object's probes for its processes, and says
// which of them the kernel was never given an authorisation for.
func (a EBPF) place(one object, sink probe.Sink) (probe.Attachment, []ebpf.Declined, error) {
	points, discarded := ebpf.PointsFrom(one.support.Probes, a.Adapter.Runtime)
	if len(discarded) > 0 {
		// The resolver found symbols no program was chosen for: the catalogue and the
		// programs disagree. Attaching short would capture the rest and look correct.
		return nil, nil, unplaceable(discarded)
	}
	if len(points) == 0 {
		return nil, nil, fmt.Errorf("%w: %s: nothing resolved to attach to",
			probe.ErrUnsupported, openssl.Path(one.support))
	}

	// The attach policy, enforced before a probe is placed: the library's build id
	// and every entry-point offset must be approved, or nothing attaches.
	if err := a.approvePolicy(one.support); err != nil {
		return nil, nil, err
	}

	points = append(points, a.forkPoints(one.processes)...)
	points = append(points, a.socketPoints(one.processes)...)

	session, err := ebpf.Attach(ebpf.Options{
		Program: defaultProgram(),
		Points:  points,
		Admit:   one.admit,
		Deny:    one.deny,
	})
	if err != nil {
		return nil, nil, err
	}

	attached := &ebpfAttachment{
		networks: a.networks(one.processes),
		libcs:    a.libcs(one.processes),
		session:  session,
		procfs:   a.Adapter.ProcFS,
		// What the build can do, narrowed to what the kernel says it holds. Otherwise
		// a partial placement reports what it could have done, and bytes crossing an
		// unattached entry point are simply absent (package ebpf, Coverage).
		capability: session.Coverage().Narrow(a.Capability()),
		sink:       sink,
		known:      make(map[int32]identity),
		done:       make(chan struct{}),
	}
	// The sink is told what the program has taken out of the production order
	// before any event reaches it (delivery starts in deliver below). Set later,
	// the first gap of a run is confirmed for want of an answer, and a confirmed
	// gap retires every live stream.
	//
	// This assertion fails open: a sink that stops satisfying it (a wrapper, a
	// changed signature) installs nothing and the suites stay green, because they
	// build sessions with the reader directly. The counter "ordering ... confirmed
	// with nothing able to say" is what shows it; a required constructor argument
	// would make the case unreachable.
	if consumer, can := sink.(interface {
		Consuming(func() (probe.Consumed, error))
	}); can {
		consumer.Consuming(session.Consumed)
	}

	go attached.deliver()
	return attached, session.Declined(), nil
}

// forkPoints is where each process forks, one point per distinct C library
// file. A process whose fork cannot be resolved contributes no point and is
// not refused: its own transfers are still observed, and only what it forks
// is lost.
func (a EBPF) forkPoints(processes []process.Process) []ebpf.Point {
	var points []ebpf.Point
	seen := make(map[fileID]bool, len(processes))

	for _, p := range processes {
		root := filepath.Join(a.Adapter.ProcFS, strconv.FormatInt(int64(p.PID), 10), "root")
		path, offset, err := forkIn(root, p, a.Adapter.ProcFS)
		if err != nil {
			continue
		}
		id, err := identify(path)
		if err != nil || seen[id] {
			continue
		}
		seen[id] = true
		points = append(points, ebpf.ForkPoint(forked, path, offset))
	}
	return points
}

// networks is each process's network namespace, read here rather than when an
// event arrives: once capabilities are dropped after placement,
// /proc/<pid>/ns/net of another uid is refused. One that cannot be read stays
// unknown rather than taking the observer's own.
func (a EBPF) networks(processes []process.Process) map[int32]probe.Netns {
	held := make(map[int32]probe.Netns, len(processes))
	for _, p := range processes {
		device, inode, err := process.Network(a.Adapter.ProcFS, p.PID)
		if err != nil {
			continue
		}
		held[p.PID] = probe.Netns{Device: device, Inode: inode}
	}
	return held
}

// libcs is every C library file these processes run, where their fork and
// socket points go. A reload may add a process only where its C library is
// among them, or its forks and descriptors would go unobserved.
func (a EBPF) libcs(processes []process.Process) map[fileID]bool {
	held := make(map[fileID]bool, len(processes))
	for _, p := range processes {
		if id, err := a.libcOf(p); err == nil {
			held[id] = true
		}
	}
	return held
}

// libcOf is one process's C library file, as its fork point resolves it.
func (a EBPF) libcOf(p process.Process) (fileID, error) {
	root := filepath.Join(a.Adapter.ProcFS, strconv.FormatInt(int64(p.PID), 10), "root")
	path, _, err := forkIn(root, p, a.Adapter.ProcFS)
	if err != nil {
		return fileID{}, err
	}
	return identify(path)
}

// socketPoints is every socket entry point of each process's C library, one
// set per distinct file. A process whose library resolves none contributes no
// point and is not refused: its transfers are observed and the association is
// reported unknown with its reason. A symbol the library does not export is
// skipped on its own, since not every libc build has every family.
func (a EBPF) socketPoints(processes []process.Process) []ebpf.Point {
	var points []ebpf.Point
	seen := make(map[fileID]bool, len(processes))

	for _, p := range processes {
		root := filepath.Join(a.Adapter.ProcFS, strconv.FormatInt(int64(p.PID), 10), "root")
		path, err := libcIn(root, p, a.Adapter.ProcFS)
		if err != nil {
			continue
		}
		id, err := identify(path)
		if err != nil || seen[id] {
			continue
		}
		seen[id] = true

		offsets, err := probe.SymbolOffsets(path, ebpf.SocketSymbols())
		if err != nil {
			continue
		}
		for _, symbol := range ebpf.SocketSymbols() {
			offset, resolved := offsets[symbol]
			if !resolved {
				continue
			}
			points = append(points, ebpf.SocketPoint(symbol, path, offset))
		}
	}
	return points
}

// unplaceable names the resolved entry points no program observes.
func unplaceable(discarded []ebpf.Discard) error {
	reasons := make([]string, 0, len(discarded))
	for _, one := range discarded {
		reasons = append(reasons, one.Symbol+": "+one.Reason)
	}
	return fmt.Errorf("the library exports entry points this build resolved and cannot place: %s",
		strings.Join(reasons, "; "))
}

// approvePolicy checks a process's mapped library and its resolved entry-point
// offsets against the attach policy. openssl.Path is where the probes would
// go, under the process's own root.
func (a EBPF) approvePolicy(support probe.Support) error {
	if len(a.approval.Libraries) == 0 {
		return nil
	}
	path := openssl.Path(support)
	buildID, err := probe.BuildID(path)
	if err != nil {
		return err
	}
	offsets := make(map[string]uint64, len(support.Probes))
	for _, resolved := range support.Probes {
		offsets[resolved.Symbol] = resolved.Offset
	}
	return a.approval.ApproveLibrary(buildID, offsets)
}

// ebpfAttachment is one live BPF attachment. It turns the program's events
// into what the sink understands, naming the process each came from.
type ebpfAttachment struct {
	// networks is each observed process's namespace at placement, the last moment
	// it can be read. A reload adds to it while delivery reads it, so both hold
	// mutex (networkOf).
	networks map[int32]probe.Netns

	// libcs is the C library files this placement put fork and socket points on.
	libcs map[fileID]bool

	session    *ebpf.Session
	procfs     string
	capability probe.Capability
	sink       probe.Sink

	mutex sync.Mutex
	known map[int32]identity

	closed sync.Once
	done   chan struct{}
}

func (a *ebpfAttachment) deliver() {
	defer close(a.done)
	for event := range a.session.Events() {
		who := a.identify(event)
		switch event.Kind {
		case ebpf.Closed:
			a.sink.Closed(probe.Connection{
				Process:  who.process,
				Instance: who.instance,
				Network:  a.networkOf(event.PID),
				Stamp:    event.Stamp,
				Endpoint: event.SSL,
				At:       event.At,
			})
		case ebpf.Transfer:
			a.sink.Transfer(probe.Transfer{
				Process:    who.process,
				Instance:   who.instance,
				Network:    a.networkOf(event.PID),
				Stamp:      event.Stamp,
				Descriptor: event.Descriptor,
				Binding:    event.Binding,
				Bound:      event.Bound,
				Socket:     event.Socket,
				Ends:       event.Endpoints,
				Outcome:    event.Outcome,
				Endpoint:   event.SSL,
				Direction:  event.Direction,
				Length:     event.Length,
				Payload:    event.Payload,
				Early:      event.Early,
				Measured:   event.Measured,
				At:         event.At,
			})
		}
	}
}

// identity is who an event came from: the process a fragment is attributed to,
// and the admitted execution a connection is keyed by.
type identity struct {
	process  fragment.Process
	instance admission.Instance
}

// identify names the execution an event came from. The identity comes off the
// event (pid namespace, pid inside it, admission generation), never off /proc,
// which answers in the observer's own numbering. /proc supplies the start
// identity and executable, read the first time a pid is seen. A process that
// has exited leaves those indeterminate, and is still identified.
func (a *ebpfAttachment) identify(event ebpf.Event) identity {
	a.mutex.Lock()
	known, found := a.known[event.PID]
	a.mutex.Unlock()

	if !found {
		known = identity{process: fragment.Process{PID: event.PID}}
		if p, err := process.Identify(a.procfs, event.PID); err == nil {
			known.process = p.Identity()
			known.instance.Start = p.Start()
			known.instance.Executable = p.Executable
		}
		a.mutex.Lock()
		a.known[event.PID] = known
		a.mutex.Unlock()
	}

	known.instance.Namespace = event.Namespace
	known.instance.PID = event.NamespacePID
	known.instance.Generation = event.Generation
	return known
}

// Capability is what this attachment can report, read off the loaded program.
func (a *ebpfAttachment) Capability() probe.Capability { return a.capability }

// Placements is what the kernel says it holds, read back from the links.
func (a *ebpfAttachment) Placements(int32) ([]probe.Placement, error) {
	return a.session.Confirmed(), nil
}

// Close removes the probes and stops delivering.
func (a *ebpfAttachment) Close() error {
	var err error
	a.closed.Do(func() {
		err = a.session.Close()
		<-a.done
	})
	return err
}

// StopProducing withdraws this attachment's capture authority (package ebpf
// holds the allowlist it empties).
func (a *ebpfAttachment) StopProducing() (connection.Withdrawal, error) {
	return a.session.StopProducing()
}

// Drain empties the ring buffer, then stops and waits for delivery, so what is
// counted afterwards is what reached the sink. An event still in the channel
// or goroutine when the run is sealed would be missing with nothing to say so.
func (a *ebpfAttachment) Drain(within time.Duration) (connection.Drained, error) {
	started := time.Now()
	drained, err := a.session.Drain(within)
	if err != nil {
		return drained, err
	}
	if !drained.Complete {
		return drained, nil
	}

	// Nothing can submit any more: what the channel holds is handed to the sink as
	// the goroutine finishes.
	a.session.StopReading()
	left := within - time.Since(started)
	if left <= 0 {
		left = quiet
	}
	select {
	case <-a.done:
		return drained, nil
	case <-time.After(left):
		drained.Complete = false
		drained.Outstanding = connection.Uncounted(
			"delivery to the sink had not finished when the drain ran out of time, so what it " +
				"still held was never placed in a stream")
		drained.Because = "the delivery of drained events did not finish in " + within.String()
		return drained, nil
	}
}

// quiet is the least a drain waits for delivery once the ring buffer is empty,
// for when the caller's budget is already spent.
const quiet = 50 * time.Millisecond

// Account is this attachment's counters, read after the drain.
func (a *ebpfAttachment) Account() (connection.Counters, error) { return a.session.Account() }

// Withdrawals is every instance with a recorded grant the kernel no longer
// holds. A failed reading is an error, not an empty list.
func (a *ebpfAttachment) Withdrawals() ([]probe.Withdrawal, error) {
	gone, err := a.session.Withdrawn()
	if err != nil {
		return nil, err
	}
	out := make([]probe.Withdrawal, 0, len(gone))
	for _, one := range gone {
		out = append(out, probe.Withdrawal{
			PID:      one.Selection.ObserverPID,
			Instance: one.Selection.Instance.String(),
			State:    string(one.State),
			Evidence: one.Evidence,
			Limit:    one.State == ebpf.GrantEndedWhileRunning,
		})
	}
	return out, nil
}

// Grants is every admission this session recorded and its grant state. An
// unreadable allowlist makes each grant unknown, so the population is whole.
func (a *ebpfAttachment) Grants() ([]probe.Grant, error) { return a.session.Grants(), nil }

// networkOf is an observed process's network namespace at admission, or zero
// where it could not be read.
func (a *ebpfAttachment) networkOf(pid int32) probe.Netns {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return a.networks[pid]
}

// admit adds grants to this placement for processes running its library, and
// reads their network namespaces; without the capabilities held at attach, one
// that cannot be read stays unknown.
func (a *ebpfAttachment) admit(selections []admission.Selection, processes []process.Process,
	networks map[int32]probe.Netns) ([]admission.Selection, []probe.Skip, error) {
	granted, skipped, err := a.session.Admit(selections)
	if err != nil {
		return nil, skipped, err
	}
	a.mutex.Lock()
	for pid, netns := range networks {
		a.networks[pid] = netns
	}
	a.mutex.Unlock()
	return granted, skipped, nil
}

// retract takes back grants admit wrote, and their namespaces: one left under
// a pid would be handed to that pid's next process.
func (a *ebpfAttachment) retract(granted []admission.Selection) {
	a.session.Retract(granted)
	a.mutex.Lock()
	defer a.mutex.Unlock()
	for _, one := range granted {
		delete(a.networks, one.ObserverPID)
	}
}

// Losses is what this attachment discarded, read from the program's counters.
// An unreadable counter is an error, not a zero.
func (a *ebpfAttachment) Losses() (probe.Losses, error) {
	dropped, err := a.session.Dropped()
	if err != nil {
		return probe.Losses{}, err
	}
	unmatched, err := a.session.Unmatched()
	if err != nil {
		return probe.Losses{}, err
	}
	descendants, err := a.session.Descendants()
	if err != nil {
		return probe.Losses{}, err
	}
	when, err := a.session.UnmatchedAt()
	if err != nil {
		return probe.Losses{}, err
	}
	return probe.Losses{
		Dropped: dropped, Unmatched: unmatched, Descendants: descendants, When: when,
	}, nil
}

// Refusals is what this attachment's program refused, by reason, read from its
// counters. An unreadable counter fails the call.
func (a *ebpfAttachment) Refusals() (map[string]int64, error) {
	refused, err := a.session.Refusals()
	if err != nil {
		return nil, err
	}
	counted := make(map[string]int64, len(refused.Counted))
	for reason, value := range refused.Counted {
		counted[string(reason)] = value
	}
	return counted, nil
}
