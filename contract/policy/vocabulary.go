// Package policy is the policy-declaration vocabulary operator configuration
// and pack-supplied policy are both written in, and the procedure that gives
// every declaration one of four dispositions against what a runtime actually
// has. VOCABULARY.md in this directory is the specification; this package is
// that specification executed.
//
// Nothing here enforces anything. Deciding that a declaration has an enforcement
// point is not enforcing it, and a schema that admits a declaration has
// validated its structure and not implemented its behaviour.
package policy

// Vocabulary is the one version this draft reads. It stays a draft until the
// schema language is chosen, so no document written against it is frozen.
const Vocabulary = "observer.policy/draft"

// Source is who declared a document. It is attached by whoever loaded the
// document and never read out of it, so a pack cannot declare itself the
// operator.
type Source string

const (
	Operator Source = "operator"
	Pack     Source = "pack"
)

// Loaded is one document and who declared it.
type Loaded struct {
	Source   Source
	Document Document
}

// Document is one declaration document in the vocabulary.
type Document struct {
	Vocabulary   string        `json:"vocabulary"`
	Requirements []Requirement `json:"requirements"`
	Claims       []Claim       `json:"claims"`
	Approvals    []Approval    `json:"approvals"`
}

// Target names what a requirement is about.
type Target struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Requirement is a mandatory declaration the core enforces or refuses. It
// carries no enforcement point: the operation fixes that, and a field in which a
// declarer could name one would let a plugin introduce a guarantee by naming it.
type Requirement struct {
	ID            string         `json:"id"`
	Target        Target         `json:"target"`
	Operation     string         `json:"operation"`
	Parameters    map[string]any `json:"parameters"`
	FailureAction string         `json:"failure_action"`
}

// Claim is custom behaviour supplied as trusted plugin functionality. It is
// never enforced.
type Claim struct {
	ID        string `json:"id"`
	Component string `json:"component"`
	Statement string `json:"statement"`
}

// Approval is an operator's acceptance of one claim without the assurance.
type Approval struct {
	Claim string `json:"claim"`
}

// Inventory is what a runtime actually has. The same document is decided
// differently against two inventories, which is why this is an input rather
// than a constant of the vocabulary.
type Inventory struct {
	// EnforcementPoints are the core-controlled boundaries present, each with
	// the limits it holds its parameters to.
	EnforcementPoints map[string]Limits `json:"enforcement_points"`

	Pipelines  map[string]Pipeline  `json:"pipelines"`
	Components map[string]Component `json:"components"`

	// RecordFields are the fields a record can carry.
	RecordFields []string `json:"record_fields"`

	// Transformations are the built-ins transform_field can name, each with
	// the integer arguments it defines and their limits.
	Transformations map[string]Limits `json:"transformations"`

	// Structures are what require_output_structure can validate against.
	Structures []string `json:"structures"`

	// Slots are the positions pipelines hold components in, keyed
	// "<pipeline>.<slot>", each with the component that fills it after every
	// replacement. A requirement targeting a slot follows whatever fills it.
	Slots map[string]Slot `json:"slots"`

	// Sinks are what the runtime knows about each sink a pipeline dispatches
	// through: its kind, and whether dispatch through it leaves the host or
	// keeps plaintext on it.
	Sinks map[string]Sink `json:"sinks"`
}

// Slot is one position in one pipeline and the component filling it.
type Slot struct {
	Pipeline  string `json:"pipeline"`
	Component string `json:"component"`
}

// Sink is what the runtime knows about one sink.
type Sink struct {
	Kind             string `json:"kind"`
	LeavesHost       bool   `json:"leaves_host"`
	RetainsPlaintext bool   `json:"retains_plaintext"`
}

// Limits holds each named integer parameter within a range.
type Limits map[string]Range

// Range is inclusive, and an absent end is unbounded on that side.
type Range struct {
	Min *int64 `json:"min"`
	Max *int64 `json:"max"`
}

// Pipeline is what one pipeline is made of.
type Pipeline struct {
	Components []string `json:"components"`
	Sinks      []string `json:"sinks"`
	Queues     []string `json:"queues"`
}

// Component is one processing component as the runtime knows it.
type Component struct {
	// Execution is builtin or external.
	Execution string `json:"execution"`

	// InputFields are the fields the core can construct this component's
	// input from.
	InputFields []string `json:"input_fields"`
}

const (
	Builtin  = "builtin"
	External = "external"
)

// Disposition is one of the four outcomes a declaration can have.
type Disposition string

const (
	// Accept is a supported requirement with its enforcement point present.
	Accept Disposition = "accept"
	// RefuseActivation refuses every pipeline the declaration affects.
	RefuseActivation Disposition = "refuse_activation"
	// AllowTrusted is an operator-approved claim, allowed with its limitation
	// labelled extension-declared and not core-enforced.
	AllowTrusted Disposition = "allow_trusted"
	// RefuseAssurance refuses the whole configuration: a mandatory requirement
	// is never downgraded.
	RefuseAssurance Disposition = "refuse_assurance"
)

// Reason is why a declaration has its disposition. Two results with one
// disposition and different reasons are different results.
type Reason string

const (
	Enforced                    Reason = "enforced"
	OperatorApproved            Reason = "operator_approved"
	UnknownVersion              Reason = "unknown_version"
	Malformed                   Reason = "malformed"
	UnknownOperation            Reason = "unknown_operation"
	UnknownParameter            Reason = "unknown_parameter"
	ParameterOutOfRange         Reason = "parameter_out_of_range"
	IncompatibleInterface       Reason = "incompatible_interface"
	MissingCapability           Reason = "missing_capability"
	TrustedBehaviourNotApproved Reason = "trusted_behaviour_not_approved"
	ApprovalNamesARequirement   Reason = "approval_names_a_requirement"
	ApprovalNotFromOperator     Reason = "approval_not_from_operator"
	NoEnforcementPoint          Reason = "no_enforcement_point"
)

// Reasons is every reason the procedure can give.
var Reasons = []Reason{
	Enforced, OperatorApproved, UnknownVersion, Malformed, UnknownOperation,
	UnknownParameter, ParameterOutOfRange, IncompatibleInterface, MissingCapability,
	TrustedBehaviourNotApproved, ApprovalNamesARequirement, ApprovalNotFromOperator,
	NoEnforcementPoint,
}

// TrustedLabel is what every allowed claim carries, before the plugin receives
// data and again in the account.
const TrustedLabel = "extension-declared, not core-enforced"

// Scope is what an acceptance covers, and what it does not.
type Scope struct {
	EnforcementPoint string
	Covers           string
	DoesNotCover     string

	// Sink is set where the requirement targets a sink or dispatches through
	// one: whether what it enforces leaves the host or is kept on it.
	Sink *Sink
}

// Finding is one declaration's disposition.
type Finding struct {
	// Declaration is a requirement's or claim's id, "requirement:<document>.<position>"
	// or "claim:<document>.<position>" for one with no id, "approval:<claim>" for
	// an approval, or "document:<index>" for a document.
	Declaration string
	Disposition Disposition
	Reason      Reason

	// Scope is set on an acceptance.
	Scope *Scope

	// Limitation is set on an allowed claim: the claim's statement under the
	// trusted label.
	Limitation string

	// Pipelines are the pipelines this finding reaches, in name order.
	Pipelines []string
}

// Activation is whether one pipeline activates, and with what.
type Activation struct {
	Pipeline  string
	Activates bool

	// RefusedBy are the declarations that refused it, in finding order.
	RefusedBy []string

	// Limitations are the allowed claims it activates carrying.
	Limitations []string
}

// Result is every finding and every pipeline's activation, in pipeline name
// order.
type Result struct {
	Findings    []Finding
	Activations []Activation
}
