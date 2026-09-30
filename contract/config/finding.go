package config

import "encoding/json"

// Supplied is one document as it was handed to the reader: the bytes, and the
// name whoever loaded it gives it.
type Supplied struct {
	Name    string
	Content []byte
}

// Outcome is where reading a document ended.
type Outcome string

// StructurallyRefused is a document that is not well formed.
const StructurallyRefused Outcome = "structurally_refused"

// Reason is why a finding was made.
type Reason string

// Reasons that decide on one document alone, and the one that decides on the
// configuration and the packs supplied beside it.
const (
	UnknownVersion Reason = "unknown_version"
	Malformed      Reason = "malformed"
	DuplicateName  Reason = "duplicate_name"
	UnknownPack    Reason = "unknown_pack"
)

// Finding is one refusal.
type Finding struct {
	// Document is "configuration" or "pack:<name>".
	Document string `json:"document"`

	// Subject is the key the finding is about, as a path: "remove.headers[2]",
	// "watch[0].children". Empty where the finding is about the document whole.
	Subject string `json:"subject"`

	Reason Reason `json:"reason"`
	Detail string `json:"detail"`
}

// Resolved is the compiled configuration: the observer settings with every
// optional one resolved, and the pipelines in order.
type Resolved struct {
	Observer  ResolvedObserver    `json:"observer"`
	Pipelines []EffectivePipeline `json:"pipelines"`
}

// ResolvedObserver is the observer settings with every optional one resolved.
type ResolvedObserver struct {
	Log                    string `json:"log"`
	Directory              string `json:"directory"`
	ApprovedOutputBoundMiB int64  `json:"approved_output_bound_mib"`
	StateEverySeconds      int64  `json:"state_every_seconds"`
	AdmittedEventLimit     int64  `json:"admitted_event_limit"`
}

// EffectivePipeline is a pipeline as it will be composed.
type EffectivePipeline struct {
	Name  string          `json:"name"`
	Input string          `json:"input"`
	Slots []EffectiveSlot `json:"slots"`
	Sinks []string        `json:"sinks"`
}

// EffectiveSlot is one operation and which documents' rules it carries.
type EffectiveSlot struct {
	Name           string          `json:"name"`
	Implementation string          `json:"implementation"`
	Configuration  json.RawMessage `json:"configuration,omitempty"`
	// Arguments is the configuration after validation.
	Arguments *Arguments `json:"arguments,omitempty"`

	// SelectedBy is the documents whose rules the operation carries,
	// "configuration" or "pack:<name>", joined by commas.
	SelectedBy string `json:"selected_by"`
}
