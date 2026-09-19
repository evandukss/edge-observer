package attach

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/connection"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/probe/openssl"
)

// producing is an attachment whose production can be stopped and accounted
// for separately from being closed. It is declared here, not in package probe,
// because preflight builds on probe and is bounded by what it may reach
// (preflight/boundary_test.go). A backend that cannot withdraw its capture
// authority does not satisfy it, and the run reports it could not be sealed.
type producing interface {
	probe.Attachment
	connection.Producer
}

// set is one attachment over several placements. Probes go on files, so
// processes sharing a library build share a placement; the set makes them one
// attachment, so Close and Capability cover all of them. It must never hold
// one placement per process on one file: every call would be reported twice.
type set struct {
	mutex   sync.Mutex
	members []member

	// refusals is why nothing was placed for a requested process, kept so a
	// partial failure reports both halves.
	refusals map[int32]error

	// adapter is what attached this set, and what a reload asks for each new
	// process's library.
	adapter *EBPF

	// routed is which member the last Admit wrote each grant to, for Retract. Each
	// Admit replaces it.
	routed map[int32]int
}

// member is one placement and the processes it observes; file is the library
// file a reload routes new processes by.
type member struct {
	covers []int32
	live   probe.Attachment
	file   fileID
}

func newSet() *set { return &set{refusals: make(map[int32]error)} }

// place records one placement and the processes it observes.
func (s *set) place(live probe.Attachment, covers ...int32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.members = append(s.members, member{covers: covers, live: live})
}

// placeOn records one placement on a library file and its processes.
func (s *set) placeOn(file fileID, live probe.Attachment, covers ...int32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.members = append(s.members, member{covers: covers, live: live, file: file})
}

// refuse records that nothing was placed for a process, and why.
func (s *set) refuse(pid int32, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.refusals[pid] = err
}

// placed is how many placements this set holds. With none it observes nothing,
// and the caller returns an error.
func (s *set) placed() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return len(s.members)
}

// Capability is what the whole set can report: probe.Weakest over its members.
// A refused process has no member and cannot weaken the rest; Placements
// reports it with its reason instead.
func (s *set) Capability() probe.Capability {
	s.mutex.Lock()
	members := s.members
	s.mutex.Unlock()

	capabilities := make([]probe.Capability, len(members))
	for i, at := range members {
		capabilities[i] = at.live.Capability()
	}
	return probe.Weakest(capabilities...)
}

// Capable is what this set can report for one process, which may exceed what
// the whole set can report. An uncovered process is answered with the reason.
func (s *set) Capable(pid int32) (probe.Capability, error) {
	s.mutex.Lock()
	members, refusals := s.members, s.refusals
	s.mutex.Unlock()

	for _, at := range members {
		for _, covered := range at.covers {
			if covered == pid {
				return at.live.Capability(), nil
			}
		}
	}
	if err, refused := refusals[pid]; refused {
		return probe.Capability{}, err
	}
	return probe.Capability{}, fmt.Errorf(
		"pid %d is not in this attachment and no reason was recorded for it", pid)
}

// Close removes every probe in the set, closing every member even after one
// fails.
func (s *set) Close() error {
	s.mutex.Lock()
	members := s.members
	s.mutex.Unlock()

	var failures []error
	for _, at := range members {
		if err := at.live.Close(); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// Placements is what the kernel says it holds on behalf of one process.
func (s *set) Placements(pid int32) ([]probe.Placement, error) {
	s.mutex.Lock()
	members, refusals := s.members, s.refusals
	s.mutex.Unlock()

	for _, at := range members {
		for _, covered := range at.covers {
			if covered != pid {
				continue
			}
			attested, canAttest := at.live.(probe.Attested)
			if !canAttest {
				return nil, nil
			}
			return attested.Placements(pid)
		}
	}
	if err, refused := refusals[pid]; refused {
		return nil, err
	}
	return nil, fmt.Errorf("pid %d is not in this attachment and no reason was recorded for it", pid)
}

// Withdrawals is every recorded process across the set whose grant is gone.
// One member unable to answer makes the set unable to answer, rather than
// returning a short list that reads as complete.
func (s *set) Withdrawals() ([]probe.Withdrawal, error) {
	s.mutex.Lock()
	members := s.members
	s.mutex.Unlock()

	var all []probe.Withdrawal
	for _, at := range members {
		accounting, can := at.live.(probe.Accounting)
		if !can {
			return nil, fmt.Errorf("%s does not record what it admitted, so neither does this attachment",
				at.live.Capability().Backend)
		}
		gone, err := accounting.Withdrawals()
		if err != nil {
			return nil, err
		}
		all = append(all, gone...)
	}
	return all, nil
}

// Grants is every admission recorded across the set with its grant state. One
// member unable to answer makes the set unable to answer.
func (s *set) Grants() ([]probe.Grant, error) {
	s.mutex.Lock()
	members := s.members
	s.mutex.Unlock()

	var all []probe.Grant
	for _, at := range members {
		granting, can := at.live.(probe.Granting)
		if !can {
			return nil, fmt.Errorf("%s records no admissions, so this attachment cannot say whose grant it still holds",
				at.live.Capability().Backend)
		}
		grants, err := granting.Grants()
		if err != nil {
			return nil, err
		}
		all = append(all, grants...)
	}
	return all, nil
}

// Admit adds grants for a reload: processes whose library file and C library
// this set's placements already cover. Every process is routed before
// anything is written: one needing an unattached library refuses the whole
// request (placing a probe needs dropped privileges; that is a restart). A
// placement that refuses takes back what the earlier ones wrote.
func (s *set) Admit(request probe.Request) (probe.Added, error) {
	if s.adapter == nil {
		return probe.Added{}, errors.New("this attachment was not made by an adapter that can admit after attaching")
	}
	objects, unsupported := s.adapter.objects(request)
	if len(unsupported) > 0 {
		reasons := make([]error, 0, len(unsupported))
		for pid, err := range unsupported {
			reasons = append(reasons, fmt.Errorf("pid %d cannot be observed: %w", pid, err))
		}
		return probe.Added{}, errors.Join(reasons...)
	}

	s.mutex.Lock()
	members := s.members
	s.mutex.Unlock()

	type routed struct {
		index int
		live  *ebpfAttachment
		one   object
	}
	var routes []routed
	for _, one := range objects {
		index := slices.IndexFunc(members, func(at member) bool { return at.file == one.file && at.file != fileID{} })
		if index < 0 {
			return probe.Added{}, fmt.Errorf("needs a library nothing has attached yet: pid %d maps %s, which "+
				"no placement in this session covers, and placing a probe needs the privilege given up after "+
				"attaching, so a restart applies it", one.processes[0].PID, openssl.Path(one.support))
		}
		live, isBPF := members[index].live.(*ebpfAttachment)
		if !isBPF {
			return probe.Added{}, fmt.Errorf("pid %d runs a library this session placed without the BPF "+
				"program, which admits nothing after attaching, so a restart applies it", one.processes[0].PID)
		}
		for _, p := range one.processes {
			var (
				libc fileID
				err  error
			)
			if read, given := request.Read[p.PID]; given {
				libc = fileID{device: read.Libc.Device, inode: read.Libc.Inode}
			} else {
				libc, err = s.adapter.libcOf(p)
			}
			if err != nil || !live.libcs[libc] {
				return probe.Added{}, fmt.Errorf("needs a library nothing has attached yet: pid %d runs a C "+
					"library this session put no fork or socket point on, so what it forks and which socket "+
					"it uses would go unobserved; a restart applies it", p.PID)
			}
		}
		routes = append(routes, routed{index: index, live: live, one: one})
	}

	var (
		added probe.Added
		done  []struct {
			live    *ebpfAttachment
			granted []admission.Selection
		}
	)
	s.mutex.Lock()
	s.routed = make(map[int32]int)
	s.mutex.Unlock()
	for _, route := range routes {
		networks := make(map[int32]probe.Netns, len(route.one.processes))
		if request.Read == nil {
			networks = s.adapter.networks(route.one.processes)
		}
		for _, p := range route.one.processes {
			if read, given := request.Read[p.PID]; given {
				networks[p.PID] = read.Network
			}
		}
		granted, skipped, err := route.live.admit(route.one.admit, route.one.processes, networks)
		added.Skipped = append(added.Skipped, skipped...)
		if err != nil {
			for _, back := range done {
				back.live.retract(back.granted)
			}
			return probe.Added{Skipped: added.Skipped}, err
		}
		done = append(done, struct {
			live    *ebpfAttachment
			granted []admission.Selection
		}{route.live, granted})
		added.Selections = append(added.Selections, granted...)

		s.mutex.Lock()
		for _, one := range granted {
			s.members[route.index].covers = append(s.members[route.index].covers, one.ObserverPID)
			s.routed[one.ObserverPID] = route.index
		}
		s.mutex.Unlock()
	}
	return added, nil
}

// Retract takes back the last Admit's grants from the member that wrote each.
func (s *set) Retract(granted []admission.Selection) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	byMember := make(map[int][]admission.Selection)
	taken := make(map[int32]bool, len(granted))
	for _, one := range granted {
		index, wrote := s.routed[one.ObserverPID]
		if !wrote {
			continue
		}
		byMember[index] = append(byMember[index], one)
		taken[one.ObserverPID] = true
		delete(s.routed, one.ObserverPID)
	}
	for index, grants := range byMember {
		if live, isBPF := s.members[index].live.(*ebpfAttachment); isBPF {
			live.retract(grants)
		}
		// A new slice: a caller may still be reading the old one.
		kept := make([]int32, 0, len(s.members[index].covers))
		for _, pid := range s.members[index].covers {
			if !taken[pid] {
				kept = append(kept, pid)
			}
		}
		s.members[index].covers = kept
	}
}

// Losses is what the whole set discarded, summed. One member unable to say
// makes the set unable to say.
func (s *set) Losses() (probe.Losses, error) {
	s.mutex.Lock()
	members := s.members
	s.mutex.Unlock()

	var total probe.Losses
	for _, at := range members {
		counted, canCount := at.live.(probe.Counting)
		if !canCount {
			return probe.Losses{}, fmt.Errorf("%s cannot say what it lost, so neither can this attachment",
				at.live.Capability().Backend)
		}
		lost, err := counted.Losses()
		if err != nil {
			return probe.Losses{}, err
		}
		total.Dropped += lost.Dropped
		total.Unmatched += lost.Unmatched
		total.Descendants += lost.Descendants
		total.When = spanning(total.When, lost.When)
	}
	return total, nil
}

// spanning folds one member's occasion into the set's interval. A silent
// member's First is zero and must not pull the interval to zero. Handle, PID
// and TID move only with First, naming the first occasion.
func spanning(held, next probe.Occasion) probe.Occasion {
	if !next.Seen() {
		return held
	}
	if !held.Seen() {
		return next
	}
	if next.First < held.First {
		// The identity moves with the first occasion.
		next.Last = max(held.Last, next.Last)
		return next
	}
	held.Last = max(held.Last, next.Last)
	return held
}

// Refusals is what the whole set refused, summed by reason. One member unable
// to say makes the set unable to say; a reason one member does not count is
// still contributed by the others.
func (s *set) Refusals() (map[string]int64, error) {
	s.mutex.Lock()
	members := s.members
	s.mutex.Unlock()

	total := make(map[string]int64)
	for _, at := range members {
		refusing, can := at.live.(probe.Refusing)
		if !can {
			return nil, fmt.Errorf("%s cannot say what it refused, so neither can this attachment",
				at.live.Capability().Backend)
		}
		counted, err := refusing.Refusals()
		if err != nil {
			return nil, err
		}
		for reason, value := range counted {
			total[reason] += value
		}
	}
	return total, nil
}

// StopProducing withdraws capture authority from every member, stopping each
// even where one fails; the withdrawal is complete only when every member's
// is.
func (s *set) StopProducing() (connection.Withdrawal, error) {
	s.mutex.Lock()
	members := s.members
	s.mutex.Unlock()

	whole := connection.Withdrawal{At: time.Now(), Complete: true}
	var refused []string
	for _, at := range members {
		producing, canStop := at.live.(producing)
		if !canStop {
			whole.Complete = false
			refused = append(refused, string(at.live.Capability().Backend)+
				" cannot withdraw its own capture authority, so it is still producing")
			continue
		}
		one, err := producing.StopProducing()
		whole.Instances += one.Instances
		if err != nil {
			whole.Complete = false
			refused = append(refused, err.Error())
			continue
		}
		if !one.Complete {
			whole.Complete = false
			refused = append(refused, one.Because)
		}
	}
	whole.Because = strings.Join(refused, "; ")
	return whole, nil
}

// Drain drains every member with the whole budget each, so the last member is
// not left with what the others did not use.
func (s *set) Drain(within time.Duration) (connection.Drained, error) {
	s.mutex.Lock()
	members := s.members
	s.mutex.Unlock()

	whole := connection.Drained{Delivered: connection.Counted(0), Outstanding: connection.Counted(0), Complete: true}
	var refused []string
	for _, at := range members {
		producing, canDrain := at.live.(producing)
		if !canDrain {
			whole.Complete = false
			whole.Outstanding = connection.Uncounted(string(at.live.Capability().Backend) +
				" cannot drain what it had in flight, so what it still held was never counted")
			refused = append(refused, string(at.live.Capability().Backend)+" cannot be drained")
			continue
		}
		one, err := producing.Drain(within)
		whole.Delivered = whole.Delivered.Add(one.Delivered)
		whole.Outstanding = whole.Outstanding.Add(one.Outstanding)
		if err != nil {
			whole.Complete = false
			refused = append(refused, err.Error())
			continue
		}
		if !one.Complete {
			whole.Complete = false
			refused = append(refused, one.Because)
		}
	}
	whole.Because = strings.Join(refused, "; ")
	return whole, nil
}

// Account is the set's counters, summed per counter: an unknown term makes
// only its own stage unknown.
func (s *set) Account() (connection.Counters, error) {
	s.mutex.Lock()
	members := s.members
	s.mutex.Unlock()

	if len(members) == 0 {
		// No members accounts for nothing: an error, not eleven unknown stages
		// without reasons.
		return connection.Counters{}, fmt.Errorf(
			"this attachment holds no placement, so nothing here counted anything")
	}

	var whole connection.Counters
	for index, at := range members {
		producing, canAccount := at.live.(producing)
		if !canAccount {
			return connection.Counters{}, fmt.Errorf(
				"%s cannot say what it accounted for, so neither can this attachment",
				at.live.Capability().Backend)
		}
		one, err := producing.Account()
		if err != nil {
			return connection.Counters{}, err
		}
		if index == 0 {
			whole = one
			continue
		}
		whole = sum(whole, one)
	}
	return whole, nil
}

// sum adds two members' counters stage by stage, carrying unknowns
// (Count.Add).
func sum(whole, one connection.Counters) connection.Counters {
	whole.Ordered = whole.Ordered.Add(one.Ordered)
	whole.ReservationAttempts = whole.ReservationAttempts.Add(one.ReservationAttempts)
	whole.Reservations = whole.Reservations.Add(one.Reservations)
	whole.ReservationFailures = whole.ReservationFailures.Add(one.ReservationFailures)
	whole.Submitted = whole.Submitted.Add(one.Submitted)
	whole.Delivered = whole.Delivered.Add(one.Delivered)
	whole.Undecodable = whole.Undecodable.Add(one.Undecodable)
	whole.LostAfterSubmission = whole.LostAfterSubmission.Add(one.LostAfterSubmission)
	whole.Outstanding = whole.Outstanding.Add(one.Outstanding)
	whole.StillExecuting = whole.StillExecuting.Add(one.StillExecuting)
	whole.UnmatchedReturns = whole.UnmatchedReturns.Add(one.UnmatchedReturns)
	whole.UnmeasurableCalls = whole.UnmeasurableCalls.Add(one.UnmeasurableCalls)
	whole.RefusedInFlight = whole.RefusedInFlight.Add(one.RefusedInFlight)
	whole.SocketsUnrecorded = whole.SocketsUnrecorded.Add(one.SocketsUnrecorded)
	whole.BindingsUnrecorded = whole.BindingsUnrecorded.Add(one.BindingsUnrecorded)
	whole.DenialsUnrecorded = whole.DenialsUnrecorded.Add(one.DenialsUnrecorded)
	whole.DeferredDiscarded = whole.DeferredDiscarded.Add(one.DeferredDiscarded)
	return whole
}
