package config

import (
	"fmt"
	"slices"

	"github.com/evandukss/edge-observer/contract/policy"
)

// The bounded processing profile accepts only these compiled-in operations.
const (
	RemoveHeaders          = "remove-headers"
	ReplaceHeaderValues    = "replace-header-values"
	TruncateHeaderValues   = "truncate-header-values"
	MaxProcessingBytes     = 256 * 1024
	MaxProcessingPacks     = 8
	MaxProcessingPipelines = 16
	MaxProcessingSlots     = 16
	MaxProcessingFanout    = 8
	MaxHeaderNames         = 32
	MaxHeaderValueBytes    = 4096
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
)

// HeaderArguments is the executor's resolved input, never decoded again by a
// worker. Headers are lowercase exact names. All matching occurrences in both
// headers and trailers of both exchange messages are affected; absent fields
// stay absent. Remove drops the fields, Replace writes Value, and Truncate
// keeps at most Length bytes of each value. No operation reads the original
// after an earlier step has changed it.
type HeaderArguments struct {
	Headers []string `json:"headers"`
	Value   string   `json:"value,omitempty"`
	Length  int      `json:"length,omitempty"`
}

// ProcessingPlan is the sole execution form. A nil plan cannot activate.
// Pipelines run in order on independent copies of the input; their slots run
// in order. Every output goes through Routes, including the zero-slot path.
// Accessors return detached executor views; the compiled backing state is
// immutable. Take a view at worker setup, not once for every record.
type ProcessingPlan struct {
	resolved   Resolved
	routes     []DurableRoute
	exclusions []HeaderExclusion
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

// HeaderExclusion requires removal on every reconstruction route, even when
// its declaration names only one sink. A truncation or replacement is not
// removal. Names include trailer occurrences, repeats and case variants.
// Every slot removing this header must use the declared FailureAction.
type HeaderExclusion struct {
	Declaration   string `json:"declaration"`
	Header        string `json:"header"`
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
			args, err := compileHeaderArguments(s.Implementation, s.Configuration)
			if err != nil {
				f.list = append(f.list, Finding{Document: s.SelectedBy, Subject: "slot:" + p.Name + "." + s.Name, Reason: InvalidBuiltinArguments, Detail: err.Error()})
			} else {
				s.Arguments = args
			}
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
	for _, name := range []string{RemoveHeaders, ReplaceHeaderValues, TruncateHeaderValues} {
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
				slot.Arguments = &arguments
			}
		}
	}
	return pipelines
}

// Routes returns every durable destination in dispatch order.
func (p *ProcessingPlan) Routes() []DurableRoute { return slices.Clone(p.routes) }

// Exclusions returns the session-wide header exclusions.
func (p *ProcessingPlan) Exclusions() []HeaderExclusion { return slices.Clone(p.exclusions) }

// Observer returns the fully defaulted settings.
func (p *ProcessingPlan) Observer() ResolvedObserver { return p.resolved.Observer }
