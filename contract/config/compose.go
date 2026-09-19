package config

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/evandukss/edge-observer/contract/policy"
)

// enabled is one pack the configuration enables, with the name its manifest was
// supplied under.
type enabled struct {
	manifest Manifest
	document string
}

// composer holds what composition has resolved so far.
type composer struct {
	configuration Configuration
	available     Available
	packs         []enabled

	types      map[string][]string
	components map[string]Component
	// suppliedBy is the document of the pack that supplied a component, and
	// empty for a built-in.
	suppliedBy map[string]string
	sinks      map[string]Sink
	kinds      map[string]SinkKind

	pipelines []EffectivePipeline
	// documents is the document each effective pipeline was declared in.
	documents map[string]string
	// replaced is the replacement that selected a slot's implementation, by
	// "<pipeline>.<slot>".
	replaced map[string]replacement

	findings []Finding
}

type replacement struct {
	Replacement
	document string

	// original is the implementation the slot held before this replacement.
	original string
}

func (c *composer) add(document, subject string, reason Reason, detail string, arguments ...any) {
	c.findings = append(c.findings, Finding{Document: document, Subject: subject, Reason: reason, Detail: fmt.Sprintf(detail, arguments...)})
}

// compose checks that well-formed documents compose with each other and with
// what the runtime has, and resolves them where they do. manifests are every
// supplied manifest that read, in supplied order.
func compose(configuration Configuration, manifests []enabled, available Available) ([]Finding, *Resolved) {
	c := &composer{
		configuration: configuration, available: available,
		types: map[string][]string{}, components: map[string]Component{}, suppliedBy: map[string]string{},
		sinks: map[string]Sink{}, kinds: map[string]SinkKind{}, documents: map[string]string{},
		replaced: map[string]replacement{},
	}
	for _, t := range available.Types {
		c.types[t.Name] = t.Fields
	}
	for _, k := range available.SinkKinds {
		c.kinds[k.Name] = k
	}

	c.enable(manifests)
	c.resolveComponents()
	c.checkTargets()
	c.checkSinks()
	c.collectPipelines()
	c.applyReplacements()
	for _, p := range c.pipelines {
		c.checkPipeline(p)
	}
	c.checkSubscribers()

	if len(c.findings) > 0 {
		return c.findings, nil
	}
	return nil, c.resolve()
}

// enable finds the manifest of every pack the configuration names. Only an
// enabled pack takes part in composition: a manifest supplied and not named
// contributes nothing.
func (c *composer) enable(manifests []enabled) {
	byName := map[string]enabled{}
	for _, m := range manifests {
		if _, taken := byName[m.manifest.Name]; taken {
			c.add(m.document, "pack:"+m.manifest.Name, DuplicateName, "two supplied manifests declare the pack name %q", m.manifest.Name)
			continue
		}
		byName[m.manifest.Name] = m
	}
	for _, name := range c.configuration.Packs {
		m, found := byName[name]
		if !found {
			c.add("configuration", "pack:"+name, UnknownPack, "no supplied manifest declares the pack %q", name)
			continue
		}
		c.packs = append(c.packs, m)
	}
}

// resolveComponents builds the effective available component set: the
// runtime's built-ins and every enabled pack's components.
func (c *composer) resolveComponents() {
	for _, b := range c.available.Builtins {
		c.components[b.Name] = b
	}
	for _, p := range c.packs {
		for _, component := range p.manifest.Components {
			if _, taken := c.components[component.Name]; taken {
				c.add(p.document, "component:"+component.Name, ComponentNameTaken,
					"a built-in or another enabled pack already supplies a component named %q", component.Name)
				continue
			}
			c.components[component.Name] = component
			c.suppliedBy[component.Name] = p.document
		}
	}

	reachable := c.reachable()
	for _, p := range c.packs {
		for _, component := range p.manifest.Components {
			if c.suppliedBy[component.Name] != p.document {
				continue
			}
			subject := "component:" + component.Name
			declared := append(append(slices.Clone(component.Input.Types), component.Output.Records...), component.Output.Derived...)
			unknown := false
			for _, t := range declared {
				if _, known := c.types[t]; !known {
					c.add(p.document, subject, UnknownType, "%q is not a published record type", t)
					unknown = true
				}
			}
			if unknown {
				continue
			}
			for _, t := range component.Input.Types {
				switch {
				case !c.produced(t, component.Name):
					c.add(p.document, subject, InputTypeNotProduced,
						"it receives %q, which neither the core nor any other available component produces", t)
				case !reachable[t]:
					c.add(p.document, subject, InputTypeUnreachable,
						"it receives %q, and every component producing it can run only on types nothing the core emits leads to", t)
				}
			}
		}
	}
}

// produced is whether the core, or any available component other than the one
// asking, produces a type.
func (c *composer) produced(t, asking string) bool {
	if slices.Contains(c.available.CoreEmits, t) {
		return true
	}
	for name, component := range c.components {
		if name == asking {
			continue
		}
		if slices.Contains(component.Output.Records, t) || slices.Contains(component.Output.Derived, t) {
			return true
		}
	}
	return false
}

// reachable is every type the core emits, and every type an available component
// produces from a type that is itself reachable. One record or one batch of one
// type is delivered at a time, so one reachable input is enough for a component
// to run. A component producing a type
// only from types nothing the core emits leads to never receives a record, so
// what it produces is not reachable however many components produce it.
func (c *composer) reachable() map[string]bool {
	reached := map[string]bool{}
	for _, t := range c.available.CoreEmits {
		reached[t] = true
	}
	for grew := true; grew; {
		grew = false
		for _, component := range c.components {
			if !slices.ContainsFunc(component.Input.Types, func(t string) bool { return reached[t] }) {
				continue
			}
			for _, t := range append(slices.Clone(component.Output.Records), component.Output.Derived...) {
				if !reached[t] {
					reached[t] = true
					grew = true
				}
			}
		}
	}
	return reached
}

func (c *composer) checkTargets() {
	var names []string
	fixed := c.available.Descendants
	for _, t := range c.configuration.ObservationScope.Targets {
		names = append(names, t.Name)
		for member, pair := range [][2]string{
			{t.Descendants.Boundary, fixed.Boundary},
			{t.Descendants.RootExit, fixed.RootExit},
			{t.Descendants.Replacement, fixed.Replacement},
		} {
			if pair[0] != pair[1] {
				c.add("configuration", "target:"+t.Name, DescendantAnswerNotSupported,
					"%s is %q, and the runtime's only answer is %q", []string{"boundary", "root_exit", "replacement"}[member], pair[0], pair[1])
			}
		}
	}
	for i, rule := range c.configuration.TrafficScope.Rules {
		for _, name := range rule.Targets {
			if !slices.Contains(names, name) {
				c.add("configuration", fmt.Sprintf("traffic_scope.rules[%d]", i), UnknownTarget, "no target is named %q", name)
			}
		}
	}
}

func (c *composer) checkSinks() {
	for _, s := range c.configuration.Sinks {
		if _, known := c.kinds[s.Kind]; !known {
			c.add("configuration", "sink:"+s.Name, UnknownSinkKind, "the runtime has no sink kind %q", s.Kind)
			continue
		}
		c.sinks[s.Name] = s
	}
	for _, name := range c.configuration.RetentionExport.ExportSinks {
		if _, known := c.sinks[name]; !known {
			c.add("configuration", "sink:"+name, UnknownSink, "retention_and_export names a sink that is not configured")
		}
	}
}

func (c *composer) collectPipelines() {
	declare := func(p Pipeline, document, by string) {
		if _, taken := c.documents[p.Name]; taken {
			c.add(document, "pipeline:"+p.Name, DuplicateName, "a pipeline named %q is already declared", p.Name)
			return
		}
		effective := EffectivePipeline{Name: p.Name, Input: p.Input, Sinks: slices.Clone(p.Sinks), DeclaredBy: by}
		for _, s := range p.Slots {
			effective.Slots = append(effective.Slots, EffectiveSlot{Name: s.Name, Implementation: s.Implementation, SelectedBy: by})
		}
		if effective.Slots == nil {
			effective.Slots = []EffectiveSlot{}
		}
		c.pipelines = append(c.pipelines, effective)
		c.documents[p.Name] = document
	}
	for _, p := range c.configuration.Pipelines {
		declare(p, "configuration", "configuration")
	}
	for _, pack := range c.packs {
		for _, p := range pack.manifest.Pipelines {
			declare(p, pack.document, "pack:"+pack.manifest.Name)
		}
	}
}

// applyReplacements selects each replacement's implementation for its slot.
// Two replacements for one slot select neither.
func (c *composer) applyReplacements() {
	bySlot := map[string][]replacement{}
	var order []string
	for _, pack := range c.packs {
		for _, r := range pack.manifest.Replacements {
			key := r.Pipeline + "." + r.Slot
			if _, seen := bySlot[key]; !seen {
				order = append(order, key)
			}
			bySlot[key] = append(bySlot[key], replacement{Replacement: r, document: pack.document})
		}
	}
	for _, key := range order {
		list := bySlot[key]
		subject := "replacement:" + key
		if len(list) > 1 {
			for _, r := range list {
				c.add(r.document, subject, ReplacementConflict, "%d replacements select this slot, so none is selected", len(list))
			}
			continue
		}
		r := list[0]
		slot := c.slot(r.Pipeline, r.Slot)
		if slot == nil {
			c.add(r.document, subject, UnknownSlot, "no effective pipeline %q has a slot %q", r.Pipeline, r.Slot)
			continue
		}
		if _, available := c.components[r.Implementation]; !available {
			c.add(r.document, subject, ReplacementNotResolvable,
				"%q is not a built-in and no enabled pack supplies it", r.Implementation)
			continue
		}
		r.original = slot.Implementation
		slot.Implementation = r.Implementation
		slot.SelectedBy = "pack:" + strings.TrimPrefix(r.document, "manifest:")
		for _, pack := range c.packs {
			if pack.document == r.document {
				slot.SelectedBy = "pack:" + pack.manifest.Name
			}
		}
		c.replaced[key] = r
	}
}

func (c *composer) slot(pipeline, name string) *EffectiveSlot {
	for i := range c.pipelines {
		if c.pipelines[i].Name != pipeline {
			continue
		}
		for j := range c.pipelines[i].Slots {
			if c.pipelines[i].Slots[j].Name == name {
				return &c.pipelines[i].Slots[j]
			}
		}
	}
	return nil
}

// checkPipeline follows the record types through one pipeline, and checks its
// orderings and its sinks.
func (c *composer) checkPipeline(p EffectivePipeline) {
	document := c.documents[p.Name]
	subject := "pipeline:" + p.Name

	flowing := []string{p.Input}
	known := true
	if _, published := c.types[p.Input]; !published {
		c.add(document, subject, UnknownType, "its input %q is not a published record type", p.Input)
		known = false
	} else if !slices.Contains(c.available.CoreEmits, p.Input) {
		c.add(document, subject, PipelineInputNotEmitted, "the core does not produce %q", p.Input)
	}

	// previous is the replacement that selected the slot whose output is
	// flowing, so a type it produces and the next consumer refuses is charged
	// to it.
	var previous *replacement
	for _, s := range p.Slots {
		key := p.Name + "." + s.Name
		r, isReplaced := c.replaced[key]
		component, resolvable := c.components[s.Implementation]
		if !resolvable {
			c.add(document, "slot:"+key, UnknownComponent, "%q is not a built-in and no enabled pack supplies it", s.Implementation)
			known = false
			previous = nil
			continue
		}
		if component.Role != RoleProcessor {
			if isReplaced {
				c.add(r.document, "replacement:"+key, ReplacementIncompatible, "%q is a %s, and a slot holds a processor", s.Implementation, component.Role)
			} else {
				c.add(document, "slot:"+key, RoleMismatch, "%q is a %s, and a slot holds a processor", s.Implementation, component.Role)
			}
			known = false
			previous = nil
			continue
		}
		if known && len(flowing) == 0 {
			c.add(document, "slot:"+key, InputTypeMismatch, "no record reaches it: the slot before it passes nothing on")
		} else if known {
			if refused := missing(flowing, component.Input.Types); len(refused) > 0 {
				switch {
				case isReplaced:
					c.add(r.document, "replacement:"+key, ReplacementIncompatible,
						"%q does not accept %v, which reaches the slot", s.Implementation, refused)
				case previous != nil:
					c.add(previous.document, "replacement:"+previous.Pipeline+"."+previous.Slot, ReplacementIncompatible,
						"it produces %v, which the next slot %q does not accept", refused, s.Name)
				default:
					c.add(document, "slot:"+key, InputTypeMismatch, "%q does not accept %v, which reaches it", s.Implementation, refused)
				}
			}
		}
		flowing = outputs(flowing, component.Output)
		// A processor returning records or derived records states what flows on
		// whatever reached it; one returning only suppression decisions passes on
		// what reached it, which is still unknown if that was.
		if len(component.Output.Records) > 0 || len(component.Output.Derived) > 0 {
			known = true
		}
		if isReplaced {
			previous = &r
		} else {
			previous = nil
		}
	}

	retain := c.configuration.RetentionExport.RetainPlaintext != nil && *c.configuration.RetentionExport.RetainPlaintext
	for _, name := range p.Sinks {
		sink, configured := c.sinks[name]
		if !configured {
			c.add(document, "sink:"+name, UnknownSink, "pipeline %q dispatches through a sink that is not configured", p.Name)
			continue
		}
		kind := c.kinds[sink.Kind]
		if known && len(flowing) == 0 {
			c.add(document, "sink:"+name, InputTypeMismatch, "no record reaches it: pipeline %q passes nothing on", p.Name)
		} else if known {
			if refused := missing(flowing, kind.Accepts); len(refused) > 0 {
				if previous != nil {
					c.add(previous.document, "replacement:"+previous.Pipeline+"."+previous.Slot, ReplacementIncompatible,
						"it produces %v, which the sink %q does not accept", refused, name)
				} else {
					c.add(document, "sink:"+name, InputTypeMismatch, "pipeline %q delivers %v, which its kind %q does not accept", p.Name, refused, sink.Kind)
				}
			}
		}
		if kind.LeavesHost && !slices.Contains(c.configuration.RetentionExport.ExportSinks, name) {
			c.add(document, "sink:"+name, ExportNotPermitted, "its kind %q leaves the host and retention_and_export does not name it", sink.Kind)
		}
		if kind.RetainsPlaintext && !retain {
			c.add(document, "sink:"+name, RetentionNotPermitted, "its kind %q keeps plaintext on the host and retain_plaintext is false", sink.Kind)
		}
	}

	c.checkOrdering(p, document)
}

// outputs is the types that leave a processor. A processor that returns only
// suppression decisions passes on what reached it, less what it suppresses.
func outputs(flowing []string, o Output) []string {
	var out []string
	if len(o.Records) == 0 && o.Suppression {
		out = slices.Clone(flowing)
	} else {
		out = slices.Clone(o.Records)
	}
	for _, t := range o.Derived {
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

func missing(flowing, accepted []string) []string {
	var refused []string
	for _, t := range flowing {
		if !slices.Contains(accepted, t) {
			refused = append(refused, t)
		}
	}
	return refused
}

// checkOrdering holds a pipeline's slot order to the orderings declared on what
// fills its slots. An ordering names a component and stands for the slot that
// component fills, so where a pack replaced it the replacement inherits every
// ordering on the slot - those the replaced component declared and those naming
// it. A pack that could drop an ordering by replacing the component it names
// could remove a core-enforced guarantee by naming a replacement.
//
// Orderings no order satisfies are refused as unsatisfiable, and orderings
// this order does not satisfy as not met - unless an inherited ordering is
// among them, in which case the replacement that cannot honour it is refused.
func (c *composer) checkOrdering(p EffectivePipeline, document string) {
	type slot struct {
		name           string
		position       int
		implementation string
		replaced       *replacement
	}
	var slots []slot
	for i, s := range p.Slots {
		if _, resolvable := c.components[s.Implementation]; !resolvable {
			continue
		}
		one := slot{name: s.Name, position: i, implementation: s.Implementation}
		if r, found := c.replaced[p.Name+"."+s.Name]; found {
			one.replaced = &r
		}
		slots = append(slots, one)
	}

	// named is every slot a component name stands for, and whether it stands for
	// it only through the component that slot's replacement replaced.
	type match struct {
		index     int
		inherited bool
	}
	named := func(name string) []match {
		var found []match
		for i, s := range slots {
			switch {
			case s.implementation == name:
				found = append(found, match{i, false})
			case s.replaced != nil && s.replaced.original == name:
				found = append(found, match{i, true})
			}
		}
		return found
	}

	type edge struct {
		before, after int
		// charged are the replacements an ordering reaches this edge through.
		charged []*replacement
	}
	var edges []edge
	declare := func(from int, ordering Ordering, inheritedBy *replacement) {
		link := func(before, after int, through *replacement) {
			if before == after {
				return
			}
			e := edge{before: before, after: after}
			for _, r := range []*replacement{inheritedBy, through} {
				if r != nil {
					e.charged = append(e.charged, r)
				}
			}
			edges = append(edges, e)
		}
		through := func(m match) *replacement {
			if m.inherited {
				return slots[m.index].replaced
			}
			return nil
		}
		for _, other := range ordering.After {
			for _, m := range named(other) {
				link(m.index, from, through(m))
			}
		}
		for _, other := range ordering.Before {
			for _, m := range named(other) {
				link(from, m.index, through(m))
			}
		}
	}
	for i, s := range slots {
		declare(i, c.components[s.implementation].Ordering, nil)
		if s.replaced != nil {
			if original, resolvable := c.components[s.replaced.original]; resolvable {
				declare(i, original.Ordering, s.replaced)
			}
		}
	}

	refuseReplacements := func(charged []*replacement, detail string, arguments ...any) {
		seen := map[string]bool{}
		for _, r := range charged {
			key := r.Pipeline + "." + r.Slot
			if seen[key] {
				continue
			}
			seen[key] = true
			c.add(r.document, "replacement:"+key, ReplacementIncompatible, detail, arguments...)
		}
	}

	keys := make([]string, len(slots))
	for i, s := range slots {
		keys[i] = s.name
	}
	index := func(name string) int { return slices.Index(keys, name) }
	if cycle := findCycle(keys, func(from string) []string {
		var to []string
		for _, e := range edges {
			if keys[e.before] == from {
				to = append(to, keys[e.after])
			}
		}
		return to
	}); cycle != nil {
		var charged []*replacement
		var implementations []string
		for i, name := range cycle {
			implementations = append(implementations, slots[index(name)].implementation)
			next := cycle[(i+1)%len(cycle)]
			for _, e := range edges {
				if keys[e.before] == name && keys[e.after] == next {
					charged = append(charged, e.charged...)
				}
			}
		}
		if len(charged) > 0 {
			refuseReplacements(charged, "an ordering it inherits from its slot and the orderings on %s require each to precede the next and the last to precede the first, which no order satisfies",
				strings.Join(implementations, ", "))
			return
		}
		c.add(document, "pipeline:"+p.Name, OrderingUnsatisfiable,
			"the orderings declared by %s require each to precede the next and the last to precede the first, which no order satisfies",
			strings.Join(implementations, ", "))
		return
	}

	for _, e := range edges {
		before, after := slots[e.before], slots[e.after]
		if before.position < after.position {
			continue
		}
		if len(e.charged) > 0 {
			refuseReplacements(e.charged, "an ordering it inherits from its slot requires %q before %q, and this order does not satisfy it",
				before.implementation, after.implementation)
			continue
		}
		c.add(document, "pipeline:"+p.Name, OrderingNotMet, "%q must precede %q and does not", before.implementation, after.implementation)
	}
}

// findCycle returns the components of one cycle, in order, or nil.
func findCycle(names []string, next func(string) []string) []string {
	const (
		unvisited = iota
		open
		done
	)
	state := map[string]int{}
	var stack []string
	var found []string
	var visit func(string) bool
	visit = func(name string) bool {
		state[name] = open
		stack = append(stack, name)
		for _, to := range next(name) {
			switch state[to] {
			case open:
				start := slices.Index(stack, to)
				found = slices.Clone(stack[start:])
				return true
			case unvisited:
				if visit(to) {
					return true
				}
			}
		}
		stack = stack[:len(stack)-1]
		state[name] = done
		return false
	}
	for _, name := range names {
		if state[name] == unvisited && visit(name) {
			return found
		}
	}
	return nil
}

func (c *composer) checkSubscribers() {
	for _, s := range c.configuration.Subscribers {
		subject := "subscriber:" + s.Name
		var stream *EffectivePipeline
		for i := range c.pipelines {
			if c.pipelines[i].Name == s.Stream {
				stream = &c.pipelines[i]
			}
		}
		if stream == nil {
			c.add("configuration", subject, UnknownStream, "no pipeline is named %q", s.Stream)
		}
		component, resolvable := c.components[s.Implementation]
		if !resolvable {
			c.add("configuration", subject, UnknownComponent, "%q is not a built-in and no enabled pack supplies it", s.Implementation)
			continue
		}
		if component.Role != RoleSubscriber {
			c.add("configuration", subject, RoleMismatch, "%q is a %s, and a subscriber is a subscriber", s.Implementation, component.Role)
			continue
		}
		if stream != nil {
			if refused := missing(c.delivered(*stream), component.Input.Types); len(refused) > 0 {
				c.add("configuration", subject, InputTypeMismatch, "%q does not accept %v, which pipeline %q delivers", s.Implementation, refused, s.Stream)
			}
		}
	}
}

// delivered is the types a pipeline dispatches, where every slot resolves.
func (c *composer) delivered(p EffectivePipeline) []string {
	flowing := []string{p.Input}
	for _, s := range p.Slots {
		component, resolvable := c.components[s.Implementation]
		if !resolvable {
			return nil
		}
		flowing = outputs(flowing, component.Output)
	}
	return flowing
}

// resolve builds the resolved view of documents that composed.
func (c *composer) resolve() *Resolved {
	observer := c.configuration.Observer
	resolved := &Resolved{
		Observer: ResolvedObserver{
			Log: observer.Log, Directory: observer.Directory,
			SpoolBoundMiB: DefaultSpoolBoundMiB, StateEverySeconds: DefaultStateEverySeconds,
		},
		Pipelines:   c.pipelines,
		Descendants: map[string]FullAnswers{},
		Inventory: policy.Inventory{
			EnforcementPoints: c.available.EnforcementPoints,
			Pipelines:         map[string]policy.Pipeline{},
			Components:        map[string]policy.Component{},
			Transformations:   c.available.Transformations,
			Structures:        c.available.Structures,
			Slots:             map[string]policy.Slot{},
			Sinks:             map[string]policy.Sink{},
		},
	}
	if observer.SpoolBoundMiB != nil {
		resolved.Observer.SpoolBoundMiB = *observer.SpoolBoundMiB
	}
	if observer.StateEverySeconds != nil {
		resolved.Observer.StateEverySeconds = *observer.StateEverySeconds
	}
	for name, sink := range c.sinks {
		kind := c.kinds[sink.Kind]
		resolved.Inventory.Sinks[name] = policy.Sink{Kind: kind.Name, LeavesHost: kind.LeavesHost, RetainsPlaintext: kind.RetainsPlaintext}
	}
	for _, t := range c.configuration.ObservationScope.Targets {
		resolved.Descendants[t.Name] = FullAnswers{
			Existing: *t.Descendants.Existing, Future: *t.Descendants.Future,
			Boundary: t.Descendants.Boundary, RootExit: t.Descendants.RootExit, Replacement: t.Descendants.Replacement,
		}
	}
	for _, t := range c.available.Types {
		for _, field := range t.Fields {
			if !slices.Contains(resolved.Inventory.RecordFields, field) {
				resolved.Inventory.RecordFields = append(resolved.Inventory.RecordFields, field)
			}
		}
	}

	queues := map[string][]string{}
	for _, p := range c.configuration.Pipelines {
		for _, q := range p.Queues {
			queues[p.Name] = append(queues[p.Name], q.Name)
		}
	}
	for _, pack := range c.packs {
		for _, p := range pack.manifest.Pipelines {
			for _, q := range p.Queues {
				queues[p.Name] = append(queues[p.Name], q.Name)
			}
		}
	}
	for _, p := range c.pipelines {
		projected := policy.Pipeline{Components: []string{}, Sinks: slices.Clone(p.Sinks), Queues: queues[p.Name]}
		if projected.Queues == nil {
			projected.Queues = []string{}
		}
		for _, s := range p.Slots {
			resolved.Inventory.Slots[p.Name+"."+s.Name] = policy.Slot{Pipeline: p.Name, Component: s.Implementation}
			if !slices.Contains(projected.Components, s.Implementation) {
				projected.Components = append(projected.Components, s.Implementation)
			}
			component := c.components[s.Implementation]
			fields := []string{}
			for _, t := range component.Input.Types {
				for _, field := range c.types[t] {
					if !slices.Contains(fields, field) {
						fields = append(fields, field)
					}
				}
			}
			resolved.Inventory.Components[s.Implementation] = policy.Component{Execution: component.Execution, InputFields: fields}
		}
		resolved.Inventory.Pipelines[p.Name] = projected
	}

	load := func(source policy.Source, documents []json.RawMessage) {
		for _, raw := range documents {
			var document policy.Document
			// Already read structurally, so this cannot fail here.
			_ = decode(raw, &document)
			resolved.Policy = append(resolved.Policy, policy.Loaded{Source: source, Document: document})
		}
	}
	load(policy.Operator, c.configuration.Policy)
	for _, pack := range c.packs {
		load(policy.Pack, pack.manifest.Policy)
	}
	return resolved
}
