package processing

import (
	"maps"
	"slices"
)

// FreezeSnapshot fixes Snapshot at the workers' last returned outcomes and
// current delivery/extension counts, without joining any worker or I/O owner.
// Call after closing authorization and freezing the writer. It does not itself
// stop processing or close authorization. Every returned value is detached.
func (r *Run) FreezeSnapshot() Outcome {
	r.snapshotMutex.Lock()
	defer r.snapshotMutex.Unlock()
	if r.frozenSnapshot == nil {
		o := cloneOutcome(r.snapshot())
		r.frozenSnapshot = &o
	}
	return cloneOutcome(*r.frozenSnapshot)
}

func cloneOutcome(o Outcome) Outcome {
	if o.StdoutDelivery != nil {
		s := *o.StdoutDelivery
		o.StdoutDelivery = &s
	}
	o.Extensions = slices.Clone(o.Extensions)
	for i := range o.Extensions {
		e := &o.Extensions[i]
		e.FailedBy = maps.Clone(e.FailedBy)
		e.RetiredBy = maps.Clone(e.RetiredBy)
		e.DerivedRefusedBy = maps.Clone(e.DerivedRefusedBy)
	}
	return o
}

// CloseAdmission orders the release cutoff with id issuance and the short
// enqueue callback. It never waits on BeforeAuthorize, a worker, an extension,
// or sink I/O. Output must obey its nonblocking contract. Already admitted
// lines can drain until the owner freezes the writer. It does not join workers.
func (r *Run) CloseAdmission() {
	if r == nil {
		return
	}
	r.release.admission.Lock()
	r.release.closed = true
	if w, ok := r.options.Output.(*Writer); ok {
		w.CloseAdmission()
	}
	r.release.admission.Unlock()
	r.cancel()
}

func (r *release) nextID() uint64 {
	r.admission.Lock()
	defer r.admission.Unlock()
	if r.closed {
		return 0
	}
	id := r.issued.Add(1)
	if r.extensions != nil {
		r.extensions.issue(1)
	}
	return id
}
