package config

import "slices"

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

	MaxProcessingBytes  = 256 * 1024
	MaxProcessingPacks  = 8
	MaxHeaderNames      = 32
	MaxHeaderValueBytes = 4096

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

const ConfigurationTooLarge Reason = "configuration_too_large"

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

// Exclusion requires removal of Field on every reconstruction route. A
// truncation or a replacement is not removal. Field is one of the exclusion
// field forms; Header is the lowercase name when Field is a header field, and
// empty otherwise. Header names include trailer occurrences, repeats and case
// variants. Every remove entry of the configuration and its packs is one.
type Exclusion struct {
	Declaration string `json:"declaration"`
	Field       string `json:"field"`
	Header      string `json:"header,omitempty"`
	// Messages are the messages the removal applies to: request, response or
	// both. A header, query or form field is counted as the request.
	Messages []string `json:"messages,omitempty"`
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
