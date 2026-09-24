package config

import "github.com/evandukss/edge-observer/contract/policy"

// Supplied is one document as it was handed to the check: the bytes, and the
// name whoever loaded it gives it.
type Supplied struct {
	Name    string
	Content []byte
}

// Input is everything one check reads: the operator's configuration, the
// manifests of the packs available to it, and what the runtime has.
type Input struct {
	Configuration []byte
	Manifests     []Supplied
	Available     Available
}

// Available is what a runtime has, against which documents are resolved.
// Supplied by the runtime, never read from a document, so a pack cannot
// declare a type, sink kind or enforcement point into existence.
type Available struct {
	// Types are the published record types a component can receive or return.
	Types []RecordType `json:"types"`

	// CoreEmits are the types the core produces into pipelines.
	CoreEmits []string `json:"core_emits"`

	// Builtins are the components compiled into the runtime.
	Builtins []Component `json:"builtins"`

	SinkKinds []SinkKind `json:"sink_kinds"`

	// Descendants are the three answers admission fixes.
	Descendants FixedAnswers `json:"descendants"`

	// EnforcementPoints, Transformations and Structures are carried into the
	// resolved policy inventory unchanged.
	EnforcementPoints map[string]policy.Limits `json:"enforcement_points"`
	Transformations   map[string]policy.Limits `json:"transformations"`
	Structures        []string                 `json:"structures"`
}

// RecordType is one published record type and the fields a record of it can
// carry.
type RecordType struct {
	Name   string   `json:"name"`
	Fields []string `json:"fields"`
}

// SinkKind is one kind of sink the runtime can dispatch through.
type SinkKind struct {
	Name string `json:"name"`

	// Accepts are the record types the kind can take.
	Accepts []string `json:"accepts"`

	// LeavesHost is whether dispatch through the kind sends anything off the
	// host. RetainsPlaintext is whether it keeps plaintext on the host.
	LeavesHost       bool `json:"leaves_host"`
	RetainsPlaintext bool `json:"retains_plaintext"`
}

// FixedAnswers are the descendant answers admission gives every target.
type FixedAnswers struct {
	Boundary    string `json:"boundary"`
	RootExit    string `json:"root_exit"`
	Replacement string `json:"replacement"`
}

// Outcome is where a check ended. Structural refusal and composition refusal
// are different outcomes: the first says a document is not a well-formed
// document of its kind, the second that well-formed documents do not compose
// with each other and with what the runtime has.
type Outcome string

const (
	// StructurallyRefused is a document that is not well formed. Composition
	// was not checked, so the result says nothing about it.
	StructurallyRefused Outcome = "structurally_refused"
	// CompositionRefused is well-formed documents that do not compose.
	CompositionRefused Outcome = "composition_refused"
	// Accepted is well-formed documents that compose. It establishes
	// nothing about what any component's code does.
	Accepted Outcome = "accepted"
)

// Reason is why a finding was made.
type Reason string

// Structural reasons: decided on one document alone.
const (
	UnknownVersion Reason = "unknown_version"
	Malformed      Reason = "malformed"
	DuplicateName  Reason = "duplicate_name"
)

// Composition reasons: decided on the documents together and what the runtime
// has.
const (
	UnknownPack     Reason = "unknown_pack"
	UnknownType     Reason = "unknown_type"
	UnknownTarget   Reason = "unknown_target"
	UnknownSink     Reason = "unknown_sink"
	UnknownSinkKind Reason = "unknown_sink_kind"
	UnknownStream   Reason = "unknown_stream"
	UnknownSlot     Reason = "unknown_slot"

	// UnknownComponent is an implementation an operator or a pack pipeline
	// names that is not in the effective available component set.
	UnknownComponent Reason = "unknown_component"

	// ComponentNameTaken is a pack component whose name is already a built-in
	// or another enabled pack's component.
	ComponentNameTaken Reason = "component_name_taken"

	// RoleMismatch is a subscriber in a slot, or a processor as a subscriber.
	RoleMismatch Reason = "role_mismatch"

	// DescendantAnswerNotSupported is a fixed descendant answer stated as
	// something other than the runtime's answer.
	DescendantAnswerNotSupported Reason = "descendant_answer_not_supported"

	// InputTypeNotProduced is a pack component declaring an input type that
	// neither the core nor any other available component produces.
	InputTypeNotProduced Reason = "input_type_not_produced"

	// InputTypeUnreachable is a pack component whose input type is produced only
	// by components that can never run on anything reachable from the core's
	// emitted types (two components producing each other's input, say). Decided
	// statically. The repair is connecting to what the core seeds, not adding a
	// producer, hence distinct from InputTypeNotProduced.
	InputTypeUnreachable Reason = "input_type_unreachable"

	// PipelineInputNotEmitted is a pipeline whose input the core does not
	// produce.
	PipelineInputNotEmitted Reason = "pipeline_input_not_emitted"

	// InputTypeMismatch is a record type reaching a slot, or a sink, that does
	// not accept it.
	InputTypeMismatch Reason = "input_type_mismatch"

	// OrderingUnsatisfiable is components in one pipeline whose declared
	// orderings no order satisfies.
	OrderingUnsatisfiable Reason = "ordering_unsatisfiable"

	// OrderingNotMet is declared orderings some order satisfies and the
	// configured order does not.
	OrderingNotMet Reason = "ordering_not_met"

	// ReplacementNotResolvable is a replacement whose implementation is not in
	// the effective available component set.
	ReplacementNotResolvable Reason = "replacement_not_resolvable"

	// ReplacementIncompatible is a resolvable replacement that is incompatible
	// with its slot: the wrong role, a type reaching the slot it does not
	// accept, an output the slot's next consumer does not accept, or an ordering
	// it inherits from the slot that it cannot satisfy.
	ReplacementIncompatible Reason = "replacement_incompatible"

	// ReplacementConflict is two replacements selecting one slot.
	ReplacementConflict Reason = "replacement_conflict"

	// ExportNotPermitted is a pipeline dispatching through a sink that leaves
	// the host and is not an export sink.
	ExportNotPermitted Reason = "export_not_permitted"

	// RetentionNotPermitted is a pipeline dispatching through a sink that keeps
	// plaintext on the host where retention does not permit it.
	RetentionNotPermitted Reason = "retention_not_permitted"
)

// StructuralReasons and CompositionReasons are every reason each stage gives.
var (
	StructuralReasons  = []Reason{UnknownVersion, Malformed, DuplicateName}
	CompositionReasons = []Reason{
		UnknownPack, UnknownType, UnknownTarget, UnknownSink, UnknownSinkKind, UnknownStream, UnknownSlot,
		UnknownComponent, ComponentNameTaken, RoleMismatch, DescendantAnswerNotSupported,
		InputTypeNotProduced, InputTypeUnreachable, PipelineInputNotEmitted, InputTypeMismatch, OrderingUnsatisfiable,
		OrderingNotMet, ReplacementNotResolvable, ReplacementIncompatible, ReplacementConflict,
		ExportNotPermitted, RetentionNotPermitted,
	}
)

// Finding is one refusal.
type Finding struct {
	// Document is "configuration" or "manifest:<supplied name>".
	Document string `json:"document"`

	// Subject is what the finding is about: "component:<name>",
	// "pipeline:<name>", "slot:<pipeline>.<slot>", "sink:<name>",
	// "target:<name>", "pack:<name>", "subscriber:<name>" or
	// "replacement:<pipeline>.<slot>". A structural finding names the member
	// path instead.
	Subject string `json:"subject"`

	Reason Reason `json:"reason"`
	Detail string `json:"detail"`
}

// Result is one check's outcome. Composition is empty when the outcome is
// StructurallyRefused, because it was not checked; Resolved is set only when
// the outcome is Accepted.
type Result struct {
	Outcome     Outcome   `json:"outcome"`
	Structural  []Finding `json:"structural"`
	Composition []Finding `json:"composition"`
	Resolved    *Resolved `json:"resolved,omitempty"`
}

// Resolved is the effective configuration: every pipeline after replacements,
// the descendant answers per target, and the policy inventory and documents
// contract/policy decides.
type Resolved struct {
	Observer ResolvedObserver `json:"observer"`

	Pipelines   []EffectivePipeline    `json:"pipelines"`
	Descendants map[string]FullAnswers `json:"descendants"`
	Inventory   policy.Inventory       `json:"inventory"`
	Policy      []policy.Loaded        `json:"-"`
}

// ResolvedObserver is the observer settings with every optional one resolved.
type ResolvedObserver struct {
	Log               string `json:"log"`
	Directory         string `json:"directory"`
	SpoolBoundMiB     int64  `json:"spool_bound_mib"`
	StateEverySeconds int64  `json:"state_every_seconds"`
}

// EffectivePipeline is a pipeline as it will be composed.
type EffectivePipeline struct {
	Name  string          `json:"name"`
	Input string          `json:"input"`
	Slots []EffectiveSlot `json:"slots"`
	Sinks []string        `json:"sinks"`

	// DeclaredBy is "configuration" or "pack:<name>".
	DeclaredBy string `json:"declared_by"`
}

// EffectiveSlot is a slot and who selected what fills it.
type EffectiveSlot struct {
	Name           string `json:"name"`
	Implementation string `json:"implementation"`

	// SelectedBy is "configuration" or "pack:<name>".
	SelectedBy string `json:"selected_by"`
}

// FullAnswers is all five descendant answers for one target.
type FullAnswers struct {
	Existing    bool   `json:"existing"`
	Future      bool   `json:"future"`
	Boundary    string `json:"boundary"`
	RootExit    string `json:"root_exit"`
	Replacement string `json:"replacement"`
}

// Check reads the configuration and manifests structurally, and where every
// one is well formed, checks that they compose with each other and with what
// the runtime has. It is static: nothing is executed, no policy is decided,
// and an accepted result establishes nothing about any component's behaviour.
func Check(input Input) Result {
	configuration, structural := readConfiguration(input.Configuration)
	var manifests []enabled
	for _, supplied := range input.Manifests {
		manifest, found := readManifest(supplied)
		structural = append(structural, found...)
		manifests = append(manifests, enabled{manifest: manifest, document: "manifest:" + supplied.Name})
	}
	if len(structural) > 0 {
		return Result{Outcome: StructurallyRefused, Structural: structural}
	}

	composition, resolved := compose(configuration, manifests, input.Available)
	if len(composition) > 0 {
		return Result{Outcome: CompositionRefused, Composition: composition}
	}
	return Result{Outcome: Accepted, Resolved: resolved}
}
