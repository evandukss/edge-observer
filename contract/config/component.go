package config

import "encoding/json"

// Component is the typed processing-component interface: what an
// implementation declares about itself, whether it is compiled in or supplied
// by a pack. It receives records of published types and returns results of
// declared kinds. Nothing in it can name a core internal - every type it names
// is a published record type, resolved against the runtime's list of them.
type Component struct {
	Interface string `json:"interface"`
	Name      string `json:"name"`
	Version   string `json:"version"`

	// Role is processor or subscriber.
	Role string `json:"role"`

	// Execution is builtin or external. A pack supplies only external
	// components.
	Execution string `json:"execution"`

	// Input is the published record types the component accepts, one record or
	// one batch at a time.
	Input  Consumes `json:"input"`
	Output Output   `json:"output"`

	// State is what the component holds between records.
	State string `json:"state"`

	Ordering  Ordering  `json:"ordering"`
	Lifecycle Lifecycle `json:"lifecycle"`

	// Failures are the failure results the component can return.
	Failures []string `json:"failures"`

	// ConfigurationSchema is the schema the component's own configuration is
	// checked against. It is DECLARED: a configuration it admits is well formed,
	// which says nothing about whether the component obeys it. Its notation is
	// the open schema decision, so it is carried and not interpreted.
	ConfigurationSchema json.RawMessage `json:"configuration_schema,omitempty"`
}

// Roles.
const (
	RoleProcessor  = "processor"
	RoleSubscriber = "subscriber"
)

// Executions.
const (
	ExecutionBuiltin  = "builtin"
	ExecutionExternal = "external"
)

// Consumes is what a component receives. One record, or one batch of one type,
// is delivered at a time, so a component runs on whichever of its listed types
// arrives, and reachability asks whether any of them does. A component needing
// several records together declares batch delivery of the type they share; that
// is the only mechanism for it, and adding a correlated delivery form is a
// change to this interface rather than something a component works around.
type Consumes struct {
	Types []string `json:"types"`

	// Delivery is record or batch.
	Delivery string `json:"delivery"`
}

// Deliveries.
const (
	DeliveryRecord = "record"
	DeliveryBatch  = "batch"
)

// Output is what a component returns. Records are transformed records passed
// on in the pipeline; Derived are new records of the named types, linked to the
// observation ids they derive from; Suppression is whether it returns
// suppression decisions, which the core applies and accounts. A subscriber
// returns linked findings only, and never records.
type Output struct {
	Records     []string `json:"records"`
	Derived     []string `json:"derived"`
	Suppression bool     `json:"suppression"`
	Findings    bool     `json:"findings"`
}

// States.
const (
	StateNone          = "none"
	StatePerConnection = "per_connection"
	StatePerStream     = "per_stream"
	StatePipeline      = "pipeline"
)

// Ordering is what a component requires of the records it receives and of
// where it sits.
type Ordering struct {
	// Records is none, or in_order_per_connection.
	Records string `json:"records"`

	// After and Before name components that must precede or follow this one
	// wherever both are in one pipeline. A name stands for the slot the named
	// component fills: where a pack replaces that component, the ordering
	// applies to the replacement in the same slot, and a named component that
	// is absent rather than replaced constrains nothing.
	After  []string `json:"after"`
	Before []string `json:"before"`
}

// Record orderings.
const (
	RecordsNone                 = "none"
	RecordsInOrderPerConnection = "in_order_per_connection"
)

// Lifecycle is the supporting hooks the component handles. They carry no
// domain processing. Each is handled or ignored; stream_closure and flush are
// required of a component whose state is kept, because otherwise its state has
// no end.
type Lifecycle struct {
	Startup             string `json:"startup"`
	ConfigurationChange string `json:"configuration_change"`
	StreamClosure       string `json:"stream_closure"`
	Flush               string `json:"flush"`
	Shutdown            string `json:"shutdown"`
}

// Hook handling.
const (
	HookHandled = "handled"
	HookIgnored = "ignored"
)

// Failure results a component can return.
const (
	// FailureRecord is one record the component could not process. The slot's
	// on_failure decides what happens to it.
	FailureRecord = "record_error"
	// FailureFatal is a component that cannot continue. The pipeline stops.
	FailureFatal = "fatal"
	// FailureConfiguration is a configuration the component refuses at startup
	// or on change. The pipeline does not activate, or keeps its previous
	// configuration.
	FailureConfiguration = "configuration_refused"
)
