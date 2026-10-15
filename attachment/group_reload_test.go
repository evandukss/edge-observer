package attachment

import (
	"errors"
	"testing"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/probe"
	"github.com/evandukss/edge-observer/process"
)

type reloadAdapter struct {
	name  string
	live  *reloadOwner
	ended func(probe.Ended)
}

func (a *reloadAdapter) Name() string { return a.name }
func (a *reloadAdapter) Inspect(p process.Process) probe.Support {
	return probe.Support{Supported: p.Executable == a.name, Reason: a.name}
}
func (a *reloadAdapter) Attach(r probe.Request, _ probe.Sink) (probe.Attachment, error) {
	a.ended = r.Ended
	return a.live, nil
}

type reloadOwner struct {
	lifecycleOwner
	generation admission.Generation
	received   []probe.Request
	retracted  []admission.Selection
	fail       bool
	after      func(probe.Added)
	scope      *probe.AdmissionScope
	receipt    func(*probe.AdmissionScope, []admission.Selection)
	fixed      *admission.Instance
}

func (o *reloadOwner) Admit(r probe.Request) (probe.Added, error) {
	o.received = append(o.received, r)
	if o.fail {
		return probe.Added{}, errors.New("reload selected refusal")
	}
	var added probe.Added
	for _, one := range r.Admit {
		o.generation++
		one.Instance.Generation = o.generation
		added.Selections = append(added.Selections, one)
	}
	if o.fixed != nil {
		for i := range added.Selections {
			added.Selections[i].Instance = *o.fixed
		}
	}
	if o.scope != nil {
		added.Scopes = make(map[admission.Key]*probe.AdmissionScope)
		for _, one := range added.Selections {
			added.Scopes[one.Instance.Key()] = o.scope
		}
		scope := o.scope
		added.Retract = func(selections []admission.Selection) { o.receipt(scope, selections) }
	}
	if o.after != nil {
		o.after(added)
	}
	return added, nil
}

func TestNestedAllocatorCollisionPreservesSuccessorRoutesAndReceipts(t *testing.T) {
	for _, finish := range []string{"end", "retract"} {
		t.Run(finish, func(t *testing.T) {
			a := &reloadAdapter{name: "a", live: &reloadOwner{generation: 6}}
			c, err := probe.NewCatalog(a)
			if err != nil {
				t.Fatal(err)
			}
			g, err := Attach(c, requestFor(process.Process{PID: 1, Executable: "a"}), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = g.Close() }()
			oldScope, currentScope := probe.NewAdmissionScope(), probe.NewAdmissionScope()
			calls := make(map[*probe.AdmissionScope]int)
			a.live.receipt = func(scope *probe.AdmissionScope, selections []admission.Selection) {
				if len(selections) != 1 {
					t.Fatal("receipt lost selection")
				}
				calls[scope]++
			}
			a.live.scope = oldScope
			request := requestFor(process.Process{PID: 2, Executable: "a"})
			request.Admit[0].Instance.Start = admission.Determinate(100)
			old, err := g.Admit(request)
			if err != nil {
				t.Fatal(err)
			}
			if old.Retract == nil || len(old.Selections) != 1 {
				t.Fatal("wiring: old receipt absent")
			}
			a.live.scope = currentScope
			a.live.generation = 6
			a.live.after = func(probe.Added) { a.ended(probe.Ended{Scope: oldScope, Selection: old.Selections[0]}) }
			current, err := g.Admit(request)
			if err != nil {
				t.Fatal(err)
			}
			if current.Retract == nil || len(current.Selections) != 1 || !current.Selections[0].Instance.Same(old.Selections[0].Instance) || current.Selections[0].Instance.Start != old.Selections[0].Instance.Start {
				t.Fatal("wiring: admissions did not collide on exact key and birth")
			}
			if _, err := g.ForProcess(2); err != nil {
				t.Fatal("old retirement during Admit suppressed successor installation")
			}
			a.ended(probe.Ended{Scope: oldScope, Selection: old.Selections[0]})
			old.Retract(old.Selections)
			if _, err := g.ForProcess(2); err != nil || calls[oldScope] != 1 || calls[currentScope] != 0 || len(a.live.retracted) != 0 {
				t.Fatal("old receipt or nested retirement reached successor")
			}
			if finish == "end" {
				a.ended(probe.Ended{Scope: currentScope, Selection: current.Selections[0]})
			} else {
				current.Retract(current.Selections)
				if calls[currentScope] != 1 {
					t.Fatal("current receipt not reached")
				}
			}
			if _, err := g.ForProcess(2); err == nil {
				t.Fatal("successor's own completion retained route")
			}
		})
	}
}

func TestRetirementBeforeAdmitReturnsDoesNotResurrectRoute(t *testing.T) {
	a := &reloadAdapter{name: "a", live: &reloadOwner{generation: 1}}
	c, err := probe.NewCatalog(a)
	if err != nil {
		t.Fatal(err)
	}
	g, err := Attach(c, requestFor(process.Process{PID: 1, Executable: "a"}), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	ended := false
	a.live.after = func(added probe.Added) {
		if len(added.Selections) != 1 {
			t.Fatal("wiring: no returned admission")
		}
		a.ended(probe.Ended{Selection: added.Selections[0]})
		ended = true
	}
	if _, err := g.Admit(requestFor(process.Process{PID: 2, Executable: "a"})); err != nil {
		t.Fatal(err)
	}
	if !ended {
		t.Fatal("wiring: did not retire before Admit returned")
	}
	if _, err := g.ForProcess(2); err == nil {
		t.Fatal("retired admission resurrected routing")
	}
	if len(g.pending) != 0 {
		t.Fatal("completed admission retained retirement history")
	}
}
func (o *reloadOwner) Retract(selections []admission.Selection) {
	o.retracted = append(o.retracted, selections...)
}
func requestFor(ps ...process.Process) probe.Request {
	r := probe.Request{Processes: ps}
	for _, p := range ps {
		r.Admit = append(r.Admit, admission.Selection{ObserverPID: p.PID, Instance: admission.Instance{PID: p.PID, Generation: 1}})
	}
	return r
}

func TestReloadRoutesByOwnerAndRollsBackEarlierOwners(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		a := &reloadAdapter{name: "a", live: &reloadOwner{}}
		b := &reloadAdapter{name: "b", live: &reloadOwner{}}
		adapters := []probe.Inspector{a, b}
		if reverse {
			adapters = []probe.Inspector{b, a}
		}
		c, err := probe.NewCatalog(adapters...)
		if err != nil {
			t.Fatal(err)
		}
		g, err := Attach(c, requestFor(process.Process{PID: 1, Executable: "a"}, process.Process{PID: 2, Executable: "b"}), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		first, second := adapters[0].(*reloadAdapter), adapters[1].(*reloadAdapter)
		second.live.fail = true
		if _, err := g.Admit(requestFor(process.Process{PID: 3, Executable: "a"}, process.Process{PID: 4, Executable: "b"})); err == nil {
			t.Fatal("selected reload refusal was lost")
		}
		if len(first.live.retracted) != 1 || len(second.live.retracted) != 0 {
			t.Fatal("earlier reload grants were not retracted exactly once")
		}
		for _, at := range []*reloadAdapter{a, b} {
			if len(at.live.received) != 1 || len(at.live.received[0].Processes) != 1 || at.live.received[0].Processes[0].Executable != at.name {
				t.Fatal("reload crossed adapter owners")
			}
		}
		if err := g.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMultipleLegacyOwnersCannotAdvertiseAmbiguousRollback(t *testing.T) {
	a := &reloadAdapter{name: "a", live: &reloadOwner{}}
	b := &reloadAdapter{name: "b", live: &reloadOwner{}}
	c, err := probe.NewCatalog(a, b)
	if err != nil {
		t.Fatal(err)
	}
	g, err := Attach(c, requestFor(process.Process{PID: 1, Executable: "a"}, process.Process{PID: 2, Executable: "b"}), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if _, err := g.Admit(requestFor(process.Process{PID: 3, Executable: "a"}, process.Process{PID: 4, Executable: "b"})); err == nil {
		t.Fatal("compound legacy batch exposed ambiguous rollback")
	}
	if len(a.live.retracted) != 1 || len(b.live.retracted) != 1 {
		t.Fatal("refused compound batch retained grants")
	}
	if _, err := g.ForProcess(3); err == nil {
		t.Fatal("refused batch installed routing")
	}
}

func TestAggregateRejectsCollidingKeysWithinOneReturnedBatch(t *testing.T) {
	instance := admission.Instance{PID: 9, Generation: 7, Start: admission.Determinate(100)}
	a := &reloadAdapter{name: "a", live: &reloadOwner{scope: probe.NewAdmissionScope(), fixed: &instance}}
	b := &reloadAdapter{name: "b", live: &reloadOwner{scope: probe.NewAdmissionScope(), fixed: &instance}}
	calls := make(map[*probe.AdmissionScope]int)
	for _, at := range []*reloadAdapter{a, b} {
		at.live.receipt = func(scope *probe.AdmissionScope, take []admission.Selection) {
			if len(take) != 1 || !take[0].Instance.Same(instance) {
				t.Fatal("wiring: rollback changed returned key")
			}
			calls[scope]++
		}
	}
	c, err := probe.NewCatalog(a, b)
	if err != nil {
		t.Fatal(err)
	}
	g, err := Attach(c, requestFor(process.Process{PID: 1, Executable: "a"}, process.Process{PID: 2, Executable: "b"}), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if _, err := g.Admit(requestFor(process.Process{PID: 3, Executable: "a"}, process.Process{PID: 4, Executable: "b"})); err == nil {
		t.Fatal("aggregate overwrote colliding allocator ownership")
	}
	if calls[a.live.scope] != 1 || calls[b.live.scope] != 1 {
		t.Fatal("rejected collision did not retract both allocating owners")
	}
	for _, pid := range []int32{3, 4} {
		if _, err := g.ForProcess(pid); err == nil {
			t.Fatal("rejected collision installed a route")
		}
	}
}

func TestOldRetirementCannotRemoveSuccessorRouting(t *testing.T) {
	a := &reloadAdapter{name: "a", live: &reloadOwner{generation: 1}}
	c, err := probe.NewCatalog(a)
	if err != nil {
		t.Fatal(err)
	}
	g, err := Attach(c, requestFor(process.Process{PID: 1, Executable: "a"}), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	old := requestFor(process.Process{PID: 1}).Admit[0]
	added, err := g.Admit(requestFor(process.Process{PID: 1, Executable: "a"}))
	if err != nil || len(added.Selections) != 1 {
		t.Fatalf("wiring: successor not admitted %v %v", added, err)
	}
	successor := added.Selections[0]
	if successor.Instance.Generation == old.Instance.Generation {
		t.Fatal("wiring: generation did not change")
	}
	a.ended(probe.Ended{Selection: old})
	g.Retract([]admission.Selection{old})
	if _, err := g.ForProcess(1); err != nil || len(a.live.retracted) != 0 {
		t.Fatal("old end/retraction removed successor")
	}
	a.ended(probe.Ended{Selection: successor})
	if _, err := g.ForProcess(1); err == nil {
		t.Fatal("successor's own end did not retire routing")
	}
}
