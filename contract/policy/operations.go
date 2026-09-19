package policy

// Operation is one of the finite set of things a requirement can ask for.
type Operation struct {
	Name string

	// EnforcementPoints maps each target kind the operation accepts to the
	// core-controlled boundary that enforces it there.
	EnforcementPoints map[string]string

	Parameters     []Parameter
	FailureActions []string

	// Covers and DoesNotCover are the scope an acceptance names.
	Covers       string
	DoesNotCover string
}

// Parameter is one parameter an operation defines.
type Parameter struct {
	Name string

	// Type is one of the parameter types below.
	Type string

	// TargetKinds are the target kinds the parameter is defined and required
	// for. Empty means every kind the operation accepts.
	TargetKinds []string

	// References is the inventory the value names an entry of, if any.
	References string

	// Optional parameters may be absent.
	Optional bool
}

// Parameter types.
const (
	TypeName       = "name"
	TypeNames      = "names"
	TypeCount      = "count"
	TypeConditions = "conditions"
	TypeArguments  = "arguments"
)

// Inventories a parameter or a target can reference.
const (
	RefComponent      = "component"
	RefSink           = "sink"
	RefQueue          = "queue"
	RefPipeline       = "pipeline"
	RefStructure      = "structure"
	RefTransformation = "transformation"

	// RefSlot is a slot, named "<pipeline>.<slot>".
	RefSlot = "slot"

	// RefProcessor is a component or a slot.
	RefProcessor = "processor"
)

// Failure actions.
const (
	None           = "none"
	DropAndAccount = "drop_and_account"
	StopPipeline   = "stop_pipeline"
)

// Condition tests suppress_matching evaluates.
const (
	TestEquals    = "equals"
	TestHasPrefix = "has_prefix"
	TestPresent   = "present"
)

// Operations is the vocabulary. It is finite, and a declaration naming anything
// else is refused rather than read as a promise.
var Operations = []Operation{
	{
		Name:              "project_fields",
		EnforcementPoints: map[string]string{RefComponent: "component_input_construction", RefSlot: "component_input_construction"},
		Parameters:        []Parameter{{Name: "fields", Type: TypeNames}},
		FailureActions:    []string{None},
		Covers:            "the input the core constructs for the component holds only the listed fields",
		DoesNotCover:      "data the component obtains by any route other than its input",
	},
	{
		Name:              "transform_field",
		EnforcementPoints: map[string]string{RefComponent: "builtin_transformation", RefSlot: "builtin_transformation", RefSink: "builtin_transformation"},
		Parameters: []Parameter{
			{Name: "field", Type: TypeName},
			{Name: "transformation", Type: TypeName, References: RefTransformation},
			{Name: "arguments", Type: TypeArguments, Optional: true},
		},
		FailureActions: []string{DropAndAccount, StopPipeline},
		Covers:         "the core applies the built-in to the field before the target receives the record",
		DoesNotCover:   "copies of the field made before the target",
	},
	{
		Name:              "order_before",
		EnforcementPoints: map[string]string{RefSink: "pipeline_dispatch_order"},
		Parameters:        []Parameter{{Name: "processor", Type: TypeName, References: RefProcessor}},
		FailureActions:    []string{DropAndAccount, StopPipeline},
		Covers:            "no record reaches the sink unless the processor completed on it first",
		DoesNotCover:      "whether the processor did the right thing with it",
	},
	{
		Name:              "require_output_structure",
		EnforcementPoints: map[string]string{RefSink: "sink_admission"},
		Parameters:        []Parameter{{Name: "structure", Type: TypeName, References: RefStructure}},
		FailureActions:    []string{DropAndAccount, StopPipeline},
		Covers:            "the sink admits only records the core validated against the structure",
		DoesNotCover:      "whether the values in a valid record are correct",
	},
	{
		Name: "suppress_matching",
		EnforcementPoints: map[string]string{
			RefPipeline: "suppression_evaluation", RefComponent: "suppression_evaluation", RefSlot: "suppression_evaluation",
			RefSink: "suppression_evaluation",
		},
		Parameters:     []Parameter{{Name: "all", Type: TypeConditions}},
		FailureActions: []string{None},
		Covers:         "matching records do not reach the target, and each suppression is counted in the account",
		DoesNotCover:   "records that match only after a later transformation",
	},
	{
		Name:              "bound_size",
		EnforcementPoints: map[string]string{RefQueue: "queue_admission", RefPipeline: "record_admission"},
		Parameters: []Parameter{
			{Name: "max_records", Type: TypeCount, TargetKinds: []string{RefQueue}},
			{Name: "max_record_bytes", Type: TypeCount, TargetKinds: []string{RefPipeline}},
		},
		FailureActions: []string{DropAndAccount, StopPipeline},
		Covers:         "the core holds the queue, or the records entering the pipeline, within the bound",
		DoesNotCover:   "memory held by component code, which no core queue or record bound reaches",
	},
	{
		Name:              "dispatch_through",
		EnforcementPoints: map[string]string{RefPipeline: "sink_dispatch"},
		Parameters:        []Parameter{{Name: "sink", Type: TypeName, References: RefSink}},
		FailureActions:    []string{DropAndAccount, StopPipeline},
		Covers:            "the pipeline's output leaves by core dispatch through that sink alone",
		DoesNotCover:      "network actions taken by component code",
	},
}
