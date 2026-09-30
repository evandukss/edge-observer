package config

import (
	"fmt"
	"slices"

	"github.com/evandukss/edge-observer/contract/policy"
)

// The bounded processing profile accepts only these compiled-in operations.
const (
	RemoveHeaders        = "remove-headers"
	ReplaceHeaderValues  = "replace-header-values"
	TruncateHeaderValues = "truncate-header-values"

	// Component operations never parse inside the component they act on, so
	// they have no input they cannot decide.
	RemoveBody            = "remove-body"
	ReduceBodyToStructure = "reduce-body-to-structure"
	RemoveQuery           = "remove-query"

	// Field operations parse. Where they cannot decide, they remove the whole
	// body rather than less.
	RemoveJSONFields      = "remove-json-fields"
	ReplaceJSONValues     = "replace-json-values"
	RemoveFormFields      = "remove-form-fields"
	RemoveQueryParameters = "remove-query-parameters"

	// RequestBodyFields is the one operation on request bodies when form rules
	// and JSON request rules both apply, since remove-form-fields and
	// remove-json-fields each remove the other's bodies whole. It reads a
	// request body by the grammar the body and every Content-Type field allow:
	// strictly valid JSON with no Content-Type naming a form media type goes to
	// the JSON rules; strictly valid JSON under a form media type is removed
	// whole as undecidable; a body that is not strictly valid JSON and is
	// admitted as urlencoded, as remove-form-fields admits it, goes to the form
	// rules; anything else is removed whole as undecidable. It never decides
	// less for a body than either grammar's operation decides alone. Response
	// bodies are not touched.
	RequestBodyFields = "request-body-fields"

	MaxProcessingBytes     = 256 * 1024
	MaxProcessingPacks     = 8
	MaxProcessingPipelines = 16
	MaxProcessingSlots     = 16
	MaxProcessingFanout    = 8
	MaxHeaderNames         = 32
	MaxHeaderValueBytes    = 4096

	// MaxFieldSelectors bounds the pointers or names of one field operation.
	MaxFieldSelectors     = 32
	MaxPointerBytes       = 1024
	MaxPointerTokens      = 32
	MaxParameterNameBytes = 128
	MaxJSONValueBytes     = 4096
	// A body a JSON field operation cannot read within these bounds is removed
	// whole as undecidable.
	MaxJSONFieldDepth = 32
	MaxJSONFieldNodes = 65536
)

// The messages a body operation selects.
const (
	MessageRequest  = "request"
	MessageResponse = "response"
)

// Exclusion field forms. A header field is HeaderFieldPrefix and a lowercase
// HTTP token; a query or form field is its prefix and a parameter name; a JSON
// field is JSONFieldPrefix and a pointer, written with no separator between
// them ("message.body.json/card/number").
const (
	HeaderFieldPrefix = "message.headers."
	BodyField         = "message.body"
	BodyValuesField   = "message.body.values"
	TargetQueryField  = "message.target.query"
	QueryFieldPrefix  = "message.query."
	FormFieldPrefix   = "message.form."
	JSONFieldPrefix   = "message.body.json"
)

const (
	ConfigurationTooLarge          Reason = "configuration_too_large"
	FanoutTooLarge                 Reason = "fanout_too_large"
	UnsupportedComponent           Reason = "unsupported_component"
	UnsupportedRole                Reason = "unsupported_role"
	UnsupportedForm                Reason = "unsupported_form"
	InvalidBuiltinArguments        Reason = "invalid_builtin_arguments"
	UnsupportedTransform           Reason = "unsupported_transform"
	InvalidTransformParameters     Reason = "invalid_transform_parameters"
	ExclusionNotEnforced           Reason = "exclusion_not_enforced"
	ExclusionFailureActionMismatch Reason = "exclusion_failure_action_mismatch"
	// BodyGrammarConflict refuses a pipeline holding both a JSON field
	// operation and a form field operation: each removes the other's bodies
	// whole, so an operator who needs both writes two pipelines.
	BodyGrammarConflict Reason = "body_grammar_conflict"
)

// Arguments is the executor's resolved input, never decoded again by a worker.
// Only the members of the slot's implementation are set.
//
// Headers are lowercase exact names. All matching occurrences in both headers
// and trailers of both exchange messages are affected; absent fields stay
// absent. Remove drops the fields, Replace writes Value, and Truncate keeps at
// most Length bytes of each value. No operation reads the original after an
// earlier step has changed it.
//
// Messages lists "request", "response" or both, in that order. Pointers are
// RFC 6901 JSON pointers as configured; a "*" token also matches every array
// element. Names are parameter names as configured. For replace-json-values,
// Value is the string written, as a JSON string, in place of each matched value.
//
// For request-body-fields, Names are the form names removed, Pointers the JSON
// members removed, and Masks the JSON members whose value is replaced, each
// with its own value. Removal is applied before masking.
type Arguments struct {
	Headers  []string   `json:"headers,omitempty"`
	Value    string     `json:"value,omitempty"`
	Length   int        `json:"length,omitempty"`
	Messages []string   `json:"messages,omitempty"`
	Pointers []string   `json:"pointers,omitempty"`
	Names    []string   `json:"names,omitempty"`
	Masks    []JSONMask `json:"masks,omitempty"`
}

// JSONMask replaces the value of every JSON member or element Pointer matches
// with Value, written as a JSON string.
type JSONMask struct {
	Pointer string `json:"pointer"`
	Value   string `json:"value"`
}

// ProcessingPlan is the sole execution form. A nil plan cannot activate.
// Pipelines run in order on independent copies of the input; their slots run
// in order. Every output goes through Routes, including the zero-slot path.
// Accessors return detached executor views; the compiled backing state is
// immutable. Take a view at worker setup, not once for every record.
type ProcessingPlan struct {
	resolved   Resolved
	routes     []DurableRoute
	exclusions []Exclusion
}

// DurableRoute identifies a final pipeline output and its configured sink.
// No output, logging, spool or diagnostic path may persist source plaintext
// outside this list. Connection records contain metadata only; observations
// containing raw payload are not a supported durable input.
type DurableRoute struct {
	Pipeline string `json:"pipeline"`
	Sink     string `json:"sink"`
	Kind     string `json:"kind"`
}

// Exclusion requires removal of Field on every reconstruction route, even when
// its declaration names only one sink. A truncation or replacement is not
// removal. Field is one of the exclusion field forms; Header is the lowercase
// name when Field is a header field, and empty otherwise. Header names include
// trailer occurrences, repeats and case variants. Every slot counted towards
// the removal must use the declared FailureAction.
type Exclusion struct {
	Declaration   string `json:"declaration"`
	Field         string `json:"field"`
	Header        string `json:"header,omitempty"`
	FailureAction string `json:"failure_action"`
}

// CompileProcessing resolves configuration-only packs and checks the bounded
// runtime profile before capture admission. It never attaches or executes.
// Findings identify every independently deciding rule reached at a stage;
// later stages requiring a valid earlier result are not claimed as reached.
func CompileProcessing(configuration []byte, manifests []Supplied) (*ProcessingPlan, []Finding) {
	f := &processingFindings{document: "configuration"}
	// Subtraction keeps the aggregate check safe even for enormous input slices.
	remaining := MaxProcessingBytes
	if len(configuration) > remaining {
		f.add("configuration", ConfigurationTooLarge, "configuration exceeds %d encoded bytes", MaxProcessingBytes)
		return nil, f.list
	}
	remaining -= len(configuration)
	if len(manifests) > MaxProcessingPacks {
		f.add("manifests", ConfigurationTooLarge, "more than %d manifests supplied", MaxProcessingPacks)
	}
	for _, m := range manifests {
		if len(m.Content) > remaining {
			f.add("manifests", ConfigurationTooLarge, "configuration and supplied manifests exceed %d encoded bytes", MaxProcessingBytes)
			break
		}
		remaining -= len(m.Content)
	}
	if len(f.list) > 0 {
		return nil, f.list
	}

	c, structural := readConfiguration(configuration)
	var supplied []enabled
	for _, raw := range manifests {
		m, failures := readManifest(raw)
		structural = append(structural, failures...)
		supplied = append(supplied, enabled{manifest: m, document: "manifest:" + raw.Name})
	}
	if len(structural) > 0 {
		return nil, structural
	}

	if len(c.Packs) > MaxProcessingPacks {
		f.add("packs", ConfigurationTooLarge, "more than %d packs enabled", MaxProcessingPacks)
	}
	for _, s := range c.Subscribers {
		f.add("subscriber:"+s.Name, UnsupportedRole, "the processing runtime has no subscriber role")
	}
	for i, r := range c.TrafficScope.Rules {
		if len(r.Targets) > 0 || r.Direction != DirectionAny || len(r.LocalPorts) > 0 || len(r.RemotePorts) > 0 {
			f.add(fmt.Sprintf("traffic_scope.rules[%d]", i), UnsupportedForm, "the processing runtime captures every connection of an approved instance")
		}
	}
	for _, t := range c.ObservationScope.Targets {
		if !*t.Descendants.Existing && *t.Descendants.Future {
			f.add("target:"+t.Name, DescendantAnswerNotSupported, "future descendants without existing descendants have no admission mode")
		}
	}
	pipelineCount := 0
	checkPipelines := func(pipelines []Pipeline, document string) {
		one := &processingFindings{document: document}
		pipelineCount += len(pipelines)
		for _, p := range pipelines {
			if p.Input == "observation" {
				one.add("pipeline:"+p.Name, UnsupportedForm, "raw observations cannot reach durable processing output")
			}
			if len(p.Queues) > 0 {
				one.add("pipeline:"+p.Name, UnsupportedForm, "the processing runtime has no configurable queue")
			}
			if len(p.Slots) > MaxProcessingSlots {
				one.add("pipeline:"+p.Name, ConfigurationTooLarge, "more than %d slots", MaxProcessingSlots)
			}
		}
		f.list = append(f.list, one.list...)
	}
	checkPipelines(c.Pipelines, "configuration")
	for _, p := range supplied {
		if !slices.Contains(c.Packs, p.manifest.Name) {
			continue
		}
		for _, component := range p.manifest.Components {
			f.list = append(f.list, Finding{Document: p.document, Subject: "component:" + component.Name, Reason: UnsupportedComponent, Detail: "only configuration-only packs are executable; external components are unsupported"})
		}
		checkPipelines(p.manifest.Pipelines, p.document)
	}
	if pipelineCount > MaxProcessingPipelines {
		f.add("pipelines", ConfigurationTooLarge, "more than %d effective pipelines", MaxProcessingPipelines)
	}
	if len(f.list) > 0 {
		return nil, f.list
	}

	composition, resolved := compose(c, supplied, processingAvailable())
	if len(composition) > 0 {
		return nil, composition
	}
	plan := &ProcessingPlan{resolved: *resolved}
	fanout := map[string]int{}
	for pi := range plan.resolved.Pipelines {
		p := &plan.resolved.Pipelines[pi]
		one := &processingFindings{document: p.DeclaredBy}
		for si := range p.Slots {
			s := &p.Slots[si]
			args, err := compileArguments(s.Implementation, s.Configuration)
			if err != nil {
				f.list = append(f.list, Finding{Document: s.SelectedBy, Subject: "slot:" + p.Name + "." + s.Name, Reason: InvalidBuiltinArguments, Detail: err.Error()})
			} else {
				s.Arguments = args
			}
		}
		if jsonSlot, formSlot := bodyGrammars(p.Slots); jsonSlot != "" && formSlot != "" {
			one.add("pipeline:"+p.Name, BodyGrammarConflict, "slot %s reads bodies as JSON and slot %s as urlencoded; each removes the other's bodies whole, so they need two pipelines", jsonSlot, formSlot)
		}
		for _, sink := range p.Sinks {
			fanout[p.Input]++
			plan.routes = append(plan.routes, DurableRoute{Pipeline: p.Name, Sink: sink, Kind: resolved.Inventory.Sinks[sink].Kind})
		}
		if fanout[p.Input] > MaxProcessingFanout {
			one.add("pipeline:"+p.Name, FanoutTooLarge, "input %s has %d durable routes, exceeding %d", p.Input, fanout[p.Input], MaxProcessingFanout)
		}
		f.list = append(f.list, one.list...)
	}
	if len(f.list) > 0 {
		return nil, f.list
	}
	if failures := compileExclusions(plan); len(failures) > 0 {
		return nil, failures
	}
	return plan, nil
}

func processingAvailable() Available {
	var builtins []Component
	for _, name := range []string{RemoveHeaders, ReplaceHeaderValues, TruncateHeaderValues, RemoveBody, ReduceBodyToStructure, RemoveQuery, RemoveJSONFields, ReplaceJSONValues, RemoveFormFields, RemoveQueryParameters, RequestBodyFields} {
		builtins = append(builtins, Component{
			Interface: ComponentVersion, Name: name, Version: "1", Role: RoleProcessor, Execution: ExecutionBuiltin,
			Input: Consumes{Types: []string{"reconstruction"}, Delivery: DeliveryRecord}, Output: Output{Records: []string{"reconstruction"}},
			State: StateNone, Ordering: Ordering{Records: RecordsNone},
			Lifecycle: Lifecycle{Startup: HookIgnored, ConfigurationChange: HookIgnored, StreamClosure: HookIgnored, Flush: HookIgnored, Shutdown: HookIgnored},
			Failures:  []string{FailureRecord, FailureFatal},
		})
	}
	return Available{
		Types:     []RecordType{{Name: "reconstruction", Fields: []string{"connection.id", "message.start_line", "message.headers", "message.body"}}, {Name: "connection", Fields: []string{"connection.id", "process.instance", "local.port", "remote.port"}}},
		CoreEmits: []string{"reconstruction", "connection"}, Builtins: builtins,
		SinkKinds:         []SinkKind{{Name: "local_account", Accepts: []string{"reconstruction", "connection"}, RetainsPlaintext: true}},
		Descendants:       FixedAnswers{Boundary: "exec_ends_the_grant", RootExit: "survivors_keep_their_grants", Replacement: "needs_restart"},
		EnforcementPoints: map[string]policy.Limits{"builtin_transformation": {}}, Transformations: map[string]policy.Limits{"remove": {}},
	}
}

// bodyGrammars names the first slot reading bodies as JSON and the first
// reading them as urlencoded, either empty where there is none.
func bodyGrammars(slots []EffectiveSlot) (jsonSlot, formSlot string) {
	for _, s := range slots {
		switch s.Implementation {
		case RemoveJSONFields, ReplaceJSONValues:
			if jsonSlot == "" {
				jsonSlot = s.Name
			}
		case RemoveFormFields:
			if formSlot == "" {
				formSlot = s.Name
			}
		}
	}
	return jsonSlot, formSlot
}

// processingFindings reports runtime-profile decisions over the composed
// documents. The structural findings collector remains specific to reading
// one configuration or manifest, independently of runtime capabilities.
type processingFindings struct {
	document string
	list     []Finding
}

func (f *processingFindings) add(subject string, reason Reason, detail string, arguments ...any) {
	f.list = append(f.list, Finding{Document: f.document, Subject: subject, Reason: reason, Detail: fmt.Sprintf(detail, arguments...)})
}

// Pipelines returns the ordered execution view of the compiled plan.
func (p *ProcessingPlan) Pipelines() []EffectivePipeline {
	pipelines := slices.Clone(p.resolved.Pipelines)
	for i := range pipelines {
		pipeline := &pipelines[i]
		pipeline.Sinks = slices.Clone(pipeline.Sinks)
		pipeline.Slots = slices.Clone(pipeline.Slots)
		for j := range pipeline.Slots {
			slot := &pipeline.Slots[j]
			slot.Configuration = slices.Clone(slot.Configuration)
			if slot.Arguments != nil {
				arguments := *slot.Arguments
				arguments.Headers = slices.Clone(arguments.Headers)
				arguments.Messages = slices.Clone(arguments.Messages)
				arguments.Pointers = slices.Clone(arguments.Pointers)
				arguments.Names = slices.Clone(arguments.Names)
				arguments.Masks = slices.Clone(arguments.Masks)
				slot.Arguments = &arguments
			}
		}
	}
	return pipelines
}

// Routes returns every durable destination in dispatch order.
func (p *ProcessingPlan) Routes() []DurableRoute { return slices.Clone(p.routes) }

// Exclusions returns the session-wide exclusions.
func (p *ProcessingPlan) Exclusions() []Exclusion { return slices.Clone(p.exclusions) }

// Observer returns the fully defaulted settings.
func (p *ProcessingPlan) Observer() ResolvedObserver { return p.resolved.Observer }
