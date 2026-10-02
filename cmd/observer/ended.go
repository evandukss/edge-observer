package main

import (
	"sync"
	"time"

	"github.com/evandukss/edge-observer/account"
	"github.com/evandukss/edge-observer/probe"
)

// endings is where an attachment tells of the admitted executions it has
// established as ended. It exists before the attachment does, and is given the
// session once there is one: an end told before that waits for it, and only
// what the attachment admitted can end.
type endings struct {
	mutex   sync.Mutex
	session *daemon
	early   []probe.Ended
}

// told is the attachment's callback (probe.Request.Ended).
func (e *endings) told(one probe.Ended) {
	e.mutex.Lock()
	d := e.session
	if d == nil {
		e.early = append(e.early, one)
	}
	e.mutex.Unlock()
	if d != nil {
		d.ended(one)
	}
}

// serve hands the session every end told so far, and every later one.
func (e *endings) serve(d *daemon) {
	if e == nil {
		return
	}
	e.mutex.Lock()
	early := e.early
	e.early, e.session = nil, d
	e.mutex.Unlock()
	for _, one := range early {
		d.ended(one)
	}
}

// endedLine is one admitted execution's end in the operational log: the only
// record of its identity, since the account counts it and keeps nothing else.
type endedLine struct {
	Record    string            `json:"record"`
	Version   int               `json:"version"`
	Session   string            `json:"session"`
	At        time.Time         `json:"at"`
	Admission account.Admission `json:"admission"`
}

// ended lets go of an attached process whose execution ended: it is dropped
// from the account's processes and counted, and its end is written once to the
// operational log. A failed write is counted with the log's other failures.
func (d *daemon) ended(one probe.Ended) {
	d.planMutex.Lock()
	kept := d.plan.Processes[:0]
	for _, placed := range d.plan.Processes {
		if placed.PID == one.Selection.ObserverPID && placed.Namespace == one.Selection.Instance.Namespace &&
			(!one.Selection.Instance.Start.Determined || placed.StartTime == 0 ||
				placed.StartTime == uint64(one.Selection.Instance.Start.Ticks)) {
			d.plan.ProcessesEnded++
			continue
		}
		kept = append(kept, placed)
	}
	clear(d.plan.Processes[len(kept):])
	d.plan.Processes = kept
	d.planMutex.Unlock()

	if d.log == nil {
		return
	}
	if err := d.log.write(endedLine{Record: "execution-ended", Version: recordVersion, Session: d.session,
		At: one.At, Admission: account.EndedAdmission(one)}); err != nil {
		d.endedLogFailures.Add(1)
	}
}
