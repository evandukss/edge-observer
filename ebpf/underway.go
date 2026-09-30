package ebpf

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	obpf "github.com/evandukss/edge-observer/bpf"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

// A call that began before the probes were placed is invisible to them. A
// return probe is armed when a call passes the entry breakpoint, which did not
// exist yet, so its return fires nothing; no entry was recorded, so its system
// calls open no operation frame (obs_sys_enter). The bytes it moves are absent
// and no kernel site can count them. What can say where such a call is are the
// threads: one blocked inside the same socket system call before the probes
// were placed and after, never switched out in between, is inside a call that
// began before them (probe.UnderWay).

// threadsBefore is the first reading: the threads of every process about to be
// observed, taken before any probe is placed. It covers the admitted processes
// and every descendant they have now, which is a superset of what adopt may
// admit after placement.
type threadsBefore struct {
	threads map[int32][]process.Thread
	unread  map[int32]error
	failed  error
}

func (s *Session) readBefore() threadsBefore {
	before := threadsBefore{threads: make(map[int32][]process.Thread), unread: make(map[int32]error)}
	table, err := process.Read(defaultProcFS)
	if err != nil {
		before.failed = fmt.Errorf("the process table could not be read before the probes were placed: %w", err)
		return before
	}
	for _, one := range s.accepted {
		if one.ObserverPID <= 0 {
			continue
		}
		pids := []int32{one.ObserverPID}
		for _, below := range table.Descendants(one.ObserverPID) {
			pids = append(pids, below.PID)
		}
		for _, pid := range pids {
			if _, read := before.threads[pid]; read {
				continue
			}
			threads, err := process.Threads(defaultProcFS, pid)
			if err != nil {
				before.unread[pid] = err
				continue
			}
			before.threads[pid] = threads
		}
	}
	return before
}

// readAfter is the second reading, over every process admitted by the end of
// attach, and what the two readings say together.
func (s *Session) readAfter(before threadsBefore) probe.UnderWay {
	under := probe.UnderWay{Known: true}
	var unknown []string
	if before.failed != nil {
		unknown = append(unknown, before.failed.Error())
	}

	done := make(map[int32]bool)
	for _, one := range s.Inventory() {
		pid := one.ObserverPID
		if pid <= 0 || done[pid] || before.failed != nil {
			continue
		}
		done[pid] = true
		if err, unread := before.unread[pid]; unread {
			unknown = append(unknown, fmt.Sprintf("pid %d before the probes were placed: %v", pid, err))
			continue
		}
		now, err := process.Threads(defaultProcFS, pid)
		if errors.Is(err, fs.ErrNotExist) {
			// Gone: whatever call it was inside ended with it.
			continue
		}
		if err != nil {
			unknown = append(unknown, fmt.Sprintf("pid %d after the probes were placed: %v", pid, err))
			continue
		}
		unknown = append(unknown, tally(&under, pid, before.threads[pid], now, func(fd int64) (bool, error) {
			return process.IsSocket(defaultProcFS, pid, fd)
		})...)
	}
	if len(unknown) > 0 {
		under.Known = false
		under.Why = "a thread could not be read: " + strings.Join(unknown, "; ")
	}
	return under
}

// tally adds one process's threads to the reading: earlier is its first
// reading and now its second. A thread still in the same socket call on a
// socket is under way; one that ran, started, or was not read before is
// undetermined; one still in any other call is neither. What could not be read
// is returned.
func tally(under *probe.UnderWay, pid int32, earlier, now []process.Thread, socket func(fd int64) (bool, error)) []string {
	var unknown []string
	now = slices.Clone(now)
	slices.SortFunc(now, func(a, b process.Thread) int { return int(a.TID - b.TID) })
	for _, thread := range now {
		first := slices.IndexFunc(earlier, thread.Same)
		if first < 0 || !earlier[first].Still(thread) {
			under.Undetermined++
			continue
		}
		name, socketCall := obpf.SocketCalls[thread.Call]
		if !socketCall {
			continue
		}
		isSocket, err := socket(thread.FD)
		if err != nil {
			unknown = append(unknown, fmt.Sprintf("thread %d of pid %d is blocked in %s and %v", thread.TID, pid,
				name, err))
			continue
		}
		if !isSocket {
			continue
		}
		under.Threads++
		if under.First == nil {
			under.First = &probe.Blocked{PID: pid, TID: thread.TID, FD: thread.FD, Call: name}
		}
	}
	return unknown
}

// UnderWay is what the approved processes' threads said at attach about calls
// that began before the probes were placed (probe.UnderWay).
func (s *Session) UnderWay() probe.UnderWay { return s.underWay }
