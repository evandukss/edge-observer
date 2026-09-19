package policy

import (
	"fmt"
	"math"
	"slices"
	"strings"
)

// Decide gives every declaration in the documents its disposition against the
// inventory, and says which pipelines activate. It follows the procedure in
// VOCABULARY.md step for step, and a declaration stops at the first step it
// fails, because each step presupposes the ones before it.
func Decide(documents []Loaded, inventory Inventory) Result {
	d := decider{inventory: inventory, requirements: map[string]bool{}, claims: map[string]bool{}, approved: map[string]bool{}}
	for name := range inventory.Pipelines {
		d.all = append(d.all, name)
	}
	slices.Sort(d.all)

	// Approvals are gathered before any claim is decided, because an operator
	// document may approve a claim a pack document declared before it.
	readable := d.readable(documents)
	for index, document := range documents {
		if readable[index] != "" || document.Source != Operator {
			continue
		}
		for _, approval := range document.Document.Approvals {
			if d.claims[approval.Claim] {
				d.approved[approval.Claim] = true
			}
		}
	}

	var findings []Finding
	for index, document := range documents {
		if reason := readable[index]; reason != "" {
			findings = append(findings, Finding{
				Declaration: fmt.Sprintf("document:%d", index),
				Disposition: RefuseActivation,
				Reason:      reason,
				Pipelines:   slices.Clone(d.all),
			})
			continue
		}
		for position, requirement := range document.Document.Requirements {
			findings = append(findings, d.requirement(requirement, named(requirement.ID, "requirement", index, position)))
		}
		for position, claim := range document.Document.Claims {
			findings = append(findings, d.claim(claim, named(claim.ID, "claim", index, position)))
		}
		for _, approval := range document.Document.Approvals {
			if finding, refused := d.approval(approval, document.Source); refused {
				findings = append(findings, finding)
			}
		}
	}

	result := Result{Findings: findings}
	for _, pipeline := range d.all {
		activation := Activation{Pipeline: pipeline}
		for _, finding := range findings {
			if !slices.Contains(finding.Pipelines, pipeline) {
				continue
			}
			switch finding.Disposition {
			case RefuseActivation, RefuseAssurance:
				activation.RefusedBy = append(activation.RefusedBy, finding.Declaration)
			case AllowTrusted:
				activation.Limitations = append(activation.Limitations, finding.Limitation)
			}
		}
		activation.Activates = len(activation.RefusedBy) == 0
		result.Activations = append(result.Activations, activation)
	}
	return result
}

type decider struct {
	inventory Inventory

	// all is every pipeline, in name order: what a refusal reaches when which
	// pipeline it reaches cannot be established.
	all []string

	requirements, claims, approved map[string]bool
}

// readable applies D1 and D2, returning the refusal reason for each document or
// an empty reason, and records the ids of the documents that are read.
func (d *decider) readable(documents []Loaded) []Reason {
	reasons := make([]Reason, len(documents))
	seen := map[string]bool{}
	for index, loaded := range documents {
		document := loaded.Document
		if document.Vocabulary != Vocabulary {
			reasons[index] = UnknownVersion
			continue
		}
		var ids []string
		for _, requirement := range document.Requirements {
			ids = append(ids, requirement.ID)
		}
		for _, claim := range document.Claims {
			ids = append(ids, claim.ID)
		}
		for position, id := range ids {
			if id != "" && (seen[id] || slices.Contains(ids[:position], id)) {
				reasons[index] = Malformed
			}
		}
		if reasons[index] != "" {
			continue
		}
		for _, requirement := range document.Requirements {
			seen[requirement.ID] = true
			d.requirements[requirement.ID] = true
		}
		for _, claim := range document.Claims {
			seen[claim.ID] = true
			d.claims[claim.ID] = true
		}
	}
	return reasons
}

// target resolves what a requirement names to the pipelines it belongs to.
// Resolved is false where the inventory has no such thing, which is not the
// same as it belonging to no pipeline.
func (d *decider) target(kind, name string) (pipelines []string, resolved bool) {
	for _, pipeline := range d.all {
		members := d.inventory.Pipelines[pipeline]
		var holds bool
		switch kind {
		case RefPipeline:
			holds = pipeline == name
		case RefComponent:
			holds = slices.Contains(members.Components, name)
		case RefSink:
			holds = slices.Contains(members.Sinks, name)
		case RefQueue:
			holds = slices.Contains(members.Queues, name)
		case RefSlot:
			slot, known := d.inventory.Slots[name]
			holds = known && slot.Pipeline == pipeline
		}
		if holds {
			pipelines = append(pipelines, pipeline)
		}
	}
	switch kind {
	case RefComponent:
		_, known := d.inventory.Components[name]
		return pipelines, known
	case RefSink:
		// A sink the runtime cannot say leaves the host or keeps plaintext is
		// not one a requirement can be decided about.
		_, known := d.inventory.Sinks[name]
		return pipelines, known && len(pipelines) > 0
	}
	return pipelines, len(pipelines) > 0
}

// processor resolves an ordering's processor, which names a component or a
// slot. A name that is both could mean either, so it resolves to neither and
// ambiguous is true.
func (d *decider) processor(name string) (pipelines []string, resolved, ambiguous bool) {
	slotPipelines, slot := d.target(RefSlot, name)
	componentPipelines, component := d.target(RefComponent, name)
	switch {
	case slot && component:
		return nil, true, true
	case slot:
		return slotPipelines, true, false
	case component:
		return componentPipelines, true, false
	}
	return nil, false, false
}

func (d *decider) requirement(r Requirement, declaration string) Finding {
	pipelines, resolved := d.target(r.Target.Kind, r.Target.Name)
	if !resolved {
		pipelines = slices.Clone(d.all)
	}
	refuse := func(reason Reason) Finding {
		return Finding{Declaration: declaration, Disposition: RefuseActivation, Reason: reason, Pipelines: pipelines}
	}

	// R1
	if r.ID == "" || r.Target.Kind == "" || r.Target.Name == "" || r.Operation == "" || r.FailureAction == "" {
		return refuse(Malformed)
	}
	// R2
	index := slices.IndexFunc(Operations, func(o Operation) bool { return o.Name == r.Operation })
	if index < 0 {
		return refuse(UnknownOperation)
	}
	operation := Operations[index]
	// R3
	point, accepted := operation.EnforcementPoints[r.Target.Kind]
	if !accepted {
		return refuse(IncompatibleInterface)
	}
	// R4
	var defined []Parameter
	for _, parameter := range operation.Parameters {
		if len(parameter.TargetKinds) == 0 || slices.Contains(parameter.TargetKinds, r.Target.Kind) {
			defined = append(defined, parameter)
		}
	}
	for name := range r.Parameters {
		if !slices.ContainsFunc(defined, func(p Parameter) bool { return p.Name == name }) {
			return refuse(UnknownParameter)
		}
	}
	// R5
	for _, parameter := range defined {
		value, present := r.Parameters[parameter.Name]
		if !present {
			if parameter.Optional {
				continue
			}
			return refuse(Malformed)
		}
		if !wellTyped(parameter.Type, value) {
			return refuse(Malformed)
		}
	}
	if !slices.Contains(operation.FailureActions, r.FailureAction) {
		return refuse(Malformed)
	}
	// R6
	for _, parameter := range defined {
		if count, present := r.Parameters[parameter.Name]; present && parameter.Type == TypeCount {
			if value, _ := integer(count); value < 1 {
				return refuse(ParameterOutOfRange)
			}
		}
	}
	// R7
	if !resolved {
		return refuse(MissingCapability)
	}
	for _, parameter := range defined {
		name, _ := r.Parameters[parameter.Name].(string)
		if parameter.References != "" && !d.exists(parameter.References, name) {
			return refuse(MissingCapability)
		}
	}
	// R8
	if !d.fits(r) {
		return refuse(IncompatibleInterface)
	}
	// R9
	limits, present := d.inventory.EnforcementPoints[point]
	if !present {
		return Finding{Declaration: declaration, Disposition: RefuseAssurance, Reason: NoEnforcementPoint, Pipelines: slices.Clone(d.all)}
	}
	// R10
	for _, parameter := range defined {
		if count, present := r.Parameters[parameter.Name]; present && parameter.Type == TypeCount {
			if value, _ := integer(count); !within(limits[parameter.Name], value) {
				return refuse(ParameterOutOfRange)
			}
		}
	}
	if arguments, present := r.Parameters["arguments"].(map[string]any); present {
		transformation := d.inventory.Transformations[r.Parameters["transformation"].(string)]
		for name, argument := range arguments {
			if value, _ := integer(argument); !within(transformation[name], value) {
				return refuse(ParameterOutOfRange)
			}
		}
	}
	// R11
	scope := &Scope{EnforcementPoint: point, Covers: operation.Covers, DoesNotCover: operation.DoesNotCover}
	if sink, through := r.Parameters["sink"].(string); through {
		facts := d.inventory.Sinks[sink]
		scope.Sink = &facts
	} else if r.Target.Kind == RefSink {
		facts := d.inventory.Sinks[r.Target.Name]
		scope.Sink = &facts
	}
	return Finding{
		Declaration: declaration,
		Disposition: Accept,
		Reason:      Enforced,
		Scope:       scope,
		Pipelines:   pipelines,
	}
}

// exists reports whether the inventory has the named entry of a referenced kind.
func (d *decider) exists(kind, name string) bool {
	switch kind {
	case RefComponent:
		_, known := d.inventory.Components[name]
		return known
	case RefSink:
		_, resolved := d.target(RefSink, name)
		return resolved
	case RefProcessor:
		_, resolved, _ := d.processor(name)
		return resolved
	case RefStructure:
		return slices.Contains(d.inventory.Structures, name)
	case RefTransformation:
		_, known := d.inventory.Transformations[name]
		return known
	}
	return false
}

// fits is R8: whether every name a requirement uses belongs where it is used.
func (d *decider) fits(r Requirement) bool {
	var fields []string
	if field, named := r.Parameters["field"].(string); named {
		fields = append(fields, field)
	}
	if listed, named := r.Parameters["fields"].([]any); named {
		for _, field := range listed {
			fields = append(fields, field.(string))
		}
	}
	if conditions, named := r.Parameters["all"].([]any); named {
		for _, condition := range conditions {
			fields = append(fields, condition.(map[string]any)["field"].(string))
		}
	}
	for _, field := range fields {
		if !slices.Contains(d.inventory.RecordFields, field) {
			return false
		}
	}

	switch r.Operation {
	case "project_fields":
		component := r.Target.Name
		if r.Target.Kind == RefSlot {
			component = d.inventory.Slots[r.Target.Name].Component
		}
		input := d.inventory.Components[component].InputFields
		for _, field := range fields {
			if !slices.Contains(input, field) {
				return false
			}
		}
	case "order_before":
		processor, _, ambiguous := d.processor(r.Parameters["processor"].(string))
		// Not redundant with the membership check below: if processor() ever returned
		// both resolutions for a name that is both a slot and a component, that check
		// would accept an ambiguous reference. A mutant removing this branch survives,
		// because the finding is identical either way.
		if ambiguous {
			return false
		}
		sink, _ := d.target(RefSink, r.Target.Name)
		if !slices.ContainsFunc(sink, func(pipeline string) bool { return slices.Contains(processor, pipeline) }) {
			return false
		}
	case "transform_field":
		defined := d.inventory.Transformations[r.Parameters["transformation"].(string)]
		given, _ := r.Parameters["arguments"].(map[string]any)
		if len(given) != len(defined) {
			return false
		}
		for name := range given {
			if _, known := defined[name]; !known {
				return false
			}
		}
	}
	return true
}

func (d *decider) claim(c Claim, declaration string) Finding {
	pipelines, resolved := d.target(RefComponent, c.Component)
	if !resolved {
		pipelines = slices.Clone(d.all)
	}
	refuse := func(reason Reason) Finding {
		return Finding{Declaration: declaration, Disposition: RefuseActivation, Reason: reason, Pipelines: pipelines}
	}

	// C1
	if c.ID == "" || c.Component == "" || strings.TrimSpace(c.Statement) == "" {
		return refuse(Malformed)
	}
	// C2
	if !resolved {
		return refuse(MissingCapability)
	}
	// C3
	if d.inventory.Components[c.Component].Execution != External {
		return refuse(IncompatibleInterface)
	}
	// C4
	if !d.approved[c.ID] {
		return refuse(TrustedBehaviourNotApproved)
	}
	// C5
	return Finding{
		Declaration: declaration,
		Disposition: AllowTrusted,
		Reason:      OperatorApproved,
		Limitation:  TrustedLabel + ": " + c.Statement,
		Pipelines:   pipelines,
	}
}

// approval is A1 to A3. An approval that passes all three carries no finding
// of its own: the claim it approves carries the result.
func (d *decider) approval(a Approval, source Source) (Finding, bool) {
	refuse := func(reason Reason) (Finding, bool) {
		return Finding{Declaration: "approval:" + a.Claim, Disposition: RefuseActivation, Reason: reason, Pipelines: slices.Clone(d.all)}, true
	}
	switch {
	case !d.claims[a.Claim] && !d.requirements[a.Claim]:
		return refuse(Malformed)
	case d.requirements[a.Claim]:
		return refuse(ApprovalNamesARequirement)
	case source != Operator:
		return refuse(ApprovalNotFromOperator)
	}
	return Finding{}, false
}

// named is the name a finding is reported under: the declaration's id, or where
// it has none, its kind and position. Two declarations without ids would
// otherwise be reported under one empty name, and an activation refused by both
// could not say which.
func named(id, kind string, document, position int) string {
	if id != "" {
		return id
	}
	return fmt.Sprintf("%s:%d.%d", kind, document, position)
}

// wellTyped is the type half of R5.
func wellTyped(kind string, value any) bool {
	switch kind {
	case TypeName:
		name, is := value.(string)
		return is && name != ""
	case TypeNames:
		names, is := value.([]any)
		if !is || len(names) == 0 {
			return false
		}
		for _, name := range names {
			if !wellTyped(TypeName, name) {
				return false
			}
		}
		return true
	case TypeCount:
		_, is := integer(value)
		return is
	case TypeArguments:
		arguments, is := value.(map[string]any)
		if !is {
			return false
		}
		for _, argument := range arguments {
			if _, is := integer(argument); !is {
				return false
			}
		}
		return true
	case TypeConditions:
		conditions, is := value.([]any)
		if !is || len(conditions) == 0 {
			return false
		}
		for _, entry := range conditions {
			if !wellFormedCondition(entry) {
				return false
			}
		}
		return true
	}
	return false
}

func wellFormedCondition(entry any) bool {
	condition, is := entry.(map[string]any)
	if !is || !wellTyped(TypeName, condition["field"]) {
		return false
	}
	test, _ := condition["test"].(string)
	value, valued := condition["value"]
	switch test {
	case TestEquals, TestHasPrefix:
		_, text := value.(string)
		return text && len(condition) == 3
	case TestPresent:
		return !valued && len(condition) == 2
	}
	return false
}

// integer reads a whole number however it was decoded. A JSON number arrives as
// a float64, so a fractional or out-of-range one is not an integer.
func integer(value any) (int64, bool) {
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int64:
		return number, true
	case float64:
		if number != math.Trunc(number) || number < math.MinInt64 || number >= math.MaxInt64 {
			return 0, false
		}
		return int64(number), true
	}
	return 0, false
}

func within(bounds Range, value int64) bool {
	return (bounds.Min == nil || value >= *bounds.Min) && (bounds.Max == nil || value <= *bounds.Max)
}
