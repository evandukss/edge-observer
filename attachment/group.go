package attachment

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/evandukss/edge-observer/admission"
	"github.com/evandukss/edge-observer/held"
	"github.com/evandukss/edge-observer/probe"
)

// Group owns one attachment per selected adapter. Membership is fixed at
// startup; reload can add grants only to adapters that already attached.
type Group struct {
	catalog     probe.Catalog
	owners      []*owner
	mutex       sync.Mutex
	routes      map[int32]ownedProcess
	routesChurn held.Churn
	pending     map[*pendingAdmission]struct{}
}

// Retirement records live only for the corresponding Admit call. Generations
// are assigned by the owner, so its returned key is not known before the call.
type pendingAdmission struct {
	owner *owner
	pids  map[int32]bool
	ended map[scopedKey]bool
}
type scopedKey struct {
	scope *probe.AdmissionScope
	key   admission.Key
}

type ownedProcess struct {
	instance  admission.Instance
	owner     *owner
	confirmed bool
	scope     *probe.AdmissionScope
}

type owner struct {
	name  string
	live  probe.Attachment
	close call[struct{}]
	stop  call[withdrawal]
	drain call[drained]
}

// Attach routes the complete request before placement, then follows
// PartialAttachmentPolicy. The caller leaves unsupported processes out of the
// request and retains their catalogue reports for the account.
func Attach(catalog probe.Catalog, request probe.Request, reports map[int32]probe.Report, sink probe.Sink) (*Group, error) {
	routes, err := catalog.Routes(request, reports)
	if err != nil {
		return nil, err
	}
	if len(routes) == 0 {
		return nil, ErrNothingAttached
	}
	g := &Group{catalog: catalog, routes: make(map[int32]ownedProcess)}
	for _, route := range routes {
		at := &owner{name: route.Adapter.Name()}
		g.mutex.Lock()
		for _, one := range route.Request.Admit {
			g.routes[one.ObserverPID] = ownedProcess{instance: one.Instance, owner: at}
		}
		g.mutex.Unlock()
		told := route.Request.Ended
		route.Request.Ended = func(one probe.Ended) {
			g.mutex.Lock()
			for pending := range g.pending {
				if pending.owner == at && pending.pids[one.Selection.ObserverPID] {
					pending.ended[scopedKey{one.Scope, one.Selection.Instance.Key()}] = true
				}
			}
			if current, found := g.routes[one.Selection.ObserverPID]; found && current.owner == at && ((current.scope == one.Scope && current.instance.Same(one.Selection.Instance) && current.instance.Start == one.Selection.Instance.Start) || (!current.confirmed && current.instance.Start.Determined && current.instance.Start == one.Selection.Instance.Start)) {
				g.routes = held.Deleted(g.routes, one.Selection.ObserverPID, &g.routesChurn)
			}
			g.mutex.Unlock()
			if told != nil {
				told(one)
			}
		}
		at.live, err = route.Adapter.Attach(route.Request, sink)
		if at.live != nil {
			g.owners = append(g.owners, at)
		}
		if err == nil && at.live == nil {
			err = errors.New("attachment returned no owner")
		}
		if err != nil {
			return nil, errors.Join(fmt.Errorf("adapter %s: %w", at.name, err), g.Close())
		}
		if granting, ok := at.live.(probe.Granting); ok {
			grants, readErr := granting.Grants()
			if readErr == nil {
				g.mutex.Lock()
				for _, grant := range grants {
					one := grant.Selection
					if route, found := g.routes[one.ObserverPID]; found && route.owner == at {
						g.routes[one.ObserverPID] = ownedProcess{instance: one.Instance, owner: at, confirmed: true, scope: grant.Scope}
					}
				}
				g.mutex.Unlock()
			}
		}
	}
	return g, nil
}

func (g *Group) Capability() probe.Capability {
	capabilities := make([]probe.Capability, 0, len(g.owners))
	for _, at := range g.owners {
		capabilities = append(capabilities, at.live.Capability())
	}
	return probe.Weakest(capabilities...)
}

func (g *Group) forPID(pid int32) (*owner, error) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if route, found := g.routes[pid]; found {
		return route.owner, nil
	}
	return nil, fmt.Errorf("pid %d has no selected attachment owner", pid)
}

func (g *Group) Capable(pid int32) (probe.Capability, error) {
	at, err := g.forPID(pid)
	if err != nil {
		return probe.Capability{}, err
	}
	if covering, ok := at.live.(probe.Covering); ok {
		return covering.Capable(pid)
	}
	return at.live.Capability(), nil
}

func (g *Group) Placements(pid int32) ([]probe.Placement, error) {
	at, err := g.forPID(pid)
	if err != nil {
		return nil, err
	}
	attested, ok := at.live.(probe.Attested)
	if !ok {
		return nil, fmt.Errorf("adapter %s cannot attest its placements", at.name)
	}
	return attested.Placements(pid)
}

// Admit preflights the adapter routes before any write and retracts successful
// writes on a later refusal. Retraction carries the exact admitted generations.
func (g *Group) Admit(request probe.Request) (probe.Added, error) {
	routes, err := g.catalog.Routes(request, nil)
	if err != nil {
		return probe.Added{}, err
	}
	type addition struct {
		at      *owner
		request probe.Request
		granted []admission.Selection
		added   probe.Added
	}
	work := make([]addition, 0, len(routes))
	for _, route := range routes {
		i := slices.IndexFunc(g.owners, func(at *owner) bool { return at.name == route.Adapter.Name() })
		if i < 0 {
			return probe.Added{}, fmt.Errorf("selected adapter %s has no attachment; a restart applies it", route.Adapter.Name())
		}
		at := g.owners[i]
		if _, ok := at.live.(probe.Admitting); !ok {
			return probe.Added{}, fmt.Errorf("selected adapter %s cannot admit after attaching; a restart applies it", at.name)
		}
		work = append(work, addition{at: at, request: route.Request})
	}
	all := probe.Added{Scopes: make(map[admission.Key]*probe.AdmissionScope)}
	durableReceipt := true
	pending := make([]*pendingAdmission, len(work))
	g.mutex.Lock()
	if g.pending == nil {
		g.pending = make(map[*pendingAdmission]struct{})
	}
	for i, one := range work {
		p := &pendingAdmission{owner: one.at, pids: make(map[int32]bool), ended: make(map[scopedKey]bool)}
		for _, selection := range one.request.Admit {
			p.pids[selection.ObserverPID] = true
		}
		pending[i] = p
		g.pending[p] = struct{}{}
	}
	g.mutex.Unlock()
	defer func() {
		g.mutex.Lock()
		for _, p := range pending {
			delete(g.pending, p)
		}
		if len(g.pending) == 0 {
			g.pending = nil
		}
		g.mutex.Unlock()
	}()
	for i := range work {
		one := &work[i]
		added, err := one.at.live.(probe.Admitting).Admit(one.request)
		one.granted = slices.Clone(added.Selections)
		for j := range one.granted {
			one.granted[j].AlsoNamedBy = slices.Clone(one.granted[j].AlsoNamedBy)
		}
		one.added = added
		one.added.Scopes = maps.Clone(added.Scopes)
		if len(added.Selections) > 0 && added.Retract == nil {
			durableReceipt = false
		}
		all.Skipped = append(all.Skipped, added.Skipped...)
		if err == nil {
			err = added.Validate()
		}
		if err != nil {
			for _, back := range work[:i+1] {
				if len(back.granted) > 0 {
					retractBatch(back.at, back.added, back.granted)
				}
			}
			return probe.Added{Skipped: all.Skipped}, fmt.Errorf("adapter %s: %w", one.at.name, err)
		}
		all.Selections = append(all.Selections, added.Selections...)
		for key, scope := range added.Scopes {
			all.Scopes[key] = scope
		}
	}
	if durableReceipt {
		all.Retract = probe.BindRetraction(all.Selections, func(requested []admission.Selection) {
			for _, batch := range work {
				var take []admission.Selection
				for _, original := range batch.granted {
					if slices.ContainsFunc(requested, func(one admission.Selection) bool {
						return one.ObserverPID == original.ObserverPID && one.Instance.Same(original.Instance) && one.Instance.Start == original.Instance.Start
					}) {
						take = append(take, original)
					}
				}
				g.mutex.Lock()
				for _, one := range take {
					if current, found := g.routes[one.ObserverPID]; found && current.owner == batch.at && current.scope == batch.added.Scopes[one.Instance.Key()] && current.instance.Same(one.Instance) && current.instance.Start == one.Instance.Start {
						g.routes = held.Deleted(g.routes, one.ObserverPID, &g.routesChurn)
					}
				}
				g.mutex.Unlock()
				if len(take) > 0 {
					retractBatch(batch.at, batch.added, take)
				}
			}
		})
	}
	validation := all.Validate()
	if !durableReceipt && len(g.owners) != 1 {
		validation = errors.Join(validation, errors.New("multiple attachment owners require batch-bound retraction receipts"))
	}
	if validation != nil {
		for _, back := range work {
			if len(back.granted) > 0 {
				retractBatch(back.at, back.added, back.granted)
			}
		}
		return probe.Added{Skipped: all.Skipped}, validation
	}
	g.mutex.Lock()
	for i, one := range work {
		for _, granted := range one.granted {
			scope := one.added.Scopes[granted.Instance.Key()]
			if !pending[i].ended[scopedKey{scope, granted.Instance.Key()}] {
				g.routes[granted.ObserverPID] = ownedProcess{instance: granted.Instance, owner: one.at, confirmed: true, scope: scope}
			}
		}
	}
	g.mutex.Unlock()
	return all, nil
}

func retractBatch(at *owner, batch probe.Added, selections []admission.Selection) {
	if batch.Retract != nil {
		batch.Retract(selections)
	} else {
		at.live.(probe.Admitting).Retract(selections)
	}
}

func (g *Group) Retract(granted []admission.Selection) {
	if len(g.owners) != 1 {
		return
	}
	byOwner := make(map[*owner][]admission.Selection)
	g.mutex.Lock()
	for _, one := range granted {
		if route, found := g.routes[one.ObserverPID]; found && route.scope == nil && route.instance.Same(one.Instance) && route.instance.Start == one.Instance.Start {
			byOwner[route.owner] = append(byOwner[route.owner], one)
			g.routes = held.Deleted(g.routes, one.ObserverPID, &g.routesChurn)
		}
	}
	g.mutex.Unlock()
	for at, selections := range byOwner {
		at.live.(probe.Admitting).Retract(selections)
	}
}

func (g *Group) Close() error { return g.CloseContext(context.Background()) }

func (g *Group) CloseContext(ctx context.Context) error {
	for _, at := range g.owners {
		at.close.start(func() (struct{}, error) { return struct{}{}, at.live.Close() })
	}
	var failures []error
	for _, at := range g.owners {
		if _, err := at.close.wait(ctx); err != nil {
			failures = append(failures, fmt.Errorf("adapter %s close: %w", at.name, err))
		}
	}
	return errors.Join(failures...)
}

// call invokes its owner once; timeout never leaves a sender waiting for a
// receiver, and waiting never holds an owner lock. Results become visible only
// when done closes, so late results cannot mutate a returned value.
type call[T any] struct {
	once  sync.Once
	done  chan struct{}
	value T
	err   error
}

func (c *call[T]) start(run func() (T, error)) {
	c.once.Do(func() {
		c.done = make(chan struct{})
		go func() { c.value, c.err = run(); close(c.done) }()
	})
}
func (c *call[T]) wait(ctx context.Context) (T, error) {
	select {
	case <-c.done:
		return c.value, c.err
	default:
	}
	select {
	case <-c.done:
		return c.value, c.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}
