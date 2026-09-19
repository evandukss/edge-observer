# The policy-declaration vocabulary

Status: Live, draft vocabulary `observer.policy/draft`. The notation below is the one the worked cases
in `testdata/cases/` are written in. **It is not a frozen schema**: which schema language the contracts
are written in, and how a validator executes it, is an open decision, and the version identifier stays
`draft` until it is taken. What is specified here is the SEMANTICS, which no schema language supplies.

## The guarantee

The core enforces supported declarative requirements at identified core-controlled boundaries;
arbitrary extension behaviour remains operator-trusted unless a separate enforcement mechanism covers
it; unsupported mandatory requirements prevent activation; and accepted limitations are explicit and
recorded.

## One vocabulary, two declarers

**Operator configuration and pack-supplied policy are written in this one vocabulary.** A pack does
not get a more powerful declaration language because it ships code. There is a finite set of
operations and no general policy-programming language.

**Who declared a document is attached by whoever loaded it, never read out of the document.** A pack
that writes "operator" into its own file has said nothing, because the file has no field to say it
in.

**A schema validates configuration structure. It does not implement the declared behaviour.** A
declaration accepted here is a declaration the runtime has an enforcement point for; the enforcement
itself is the runtime's, and nothing in this directory performs it.

**Expressibility is necessary and not sufficient.** A declaration the vocabulary can express and the
runtime has no enforcement point for is refused, not accepted on its wording.

## A document

    {
      "vocabulary": "observer.policy/draft",
      "requirements": [ <requirement>, ... ],
      "claims":       [ <claim>, ... ],
      "approvals":    [ <approval>, ... ]
    }

Every member of every object is defined here. An undefined member is a malformed document.

### A requirement

    {
      "id": "queue-bound",
      "target": {"kind": "queue", "name": "capture-out"},
      "operation": "bound_size",
      "parameters": {"max_records": 10000},
      "failure_action": "drop_and_account"
    }

**Every requirement is mandatory.** There is no advisory requirement in this draft, so there is no
path by which one is downgraded: a requirement the runtime cannot enforce stops activation, and the
only way to run without that assurance is to withdraw the requirement and approve a claim instead.

**A requirement carries no enforcement point.** The operation fixes it. A plugin cannot introduce a
new enforcement guarantee by naming one, and a field in which a declarer could name one would be
exactly that.

### A claim, and an approval

    {"id": "classifier-redacts", "component": "classifier",
     "statement": "the classifier removes email addresses from message bodies"}

    {"claim": "classifier-redacts"}

A claim is custom behaviour supplied as trusted plugin functionality. **It is never enforced.** An
approval names a claim and is honoured only from an operator document. It names a CLAIM and never a
requirement: a requirement cannot be approved into trusted behaviour, only withdrawn.

"Run the classifier before output" is enforceable ordering and is a requirement (`order_before`).
"Reject output lacking classification" is enforceable presence and is a requirement
(`require_output_structure`). "The classification is correct" is neither and can only be a claim.

## The operations

Each operation fixes its target kinds, its parameters, its enforcement point, its permitted failure
actions, and the scope an acceptance names. **The scope always says what the enforcement does NOT
cover**, because that half is what a reader otherwise fills in for themselves.

Failure actions: `none` where nothing is detected at the enforcement point, `drop_and_account` where
the record is removed and the removal counted in the account, `stop_pipeline` where the pipeline
stops.

| operation | target kinds | parameters | enforcement point | failure actions |
|---|---|---|---|---|
| `project_fields` | `component`, `slot` | `fields`: non-empty list of field names | `component_input_construction` | `none` |
| `transform_field` | `component`, `slot`, `sink` | `field`: field name; `transformation`: a built-in's name; `arguments`: that built-in's own parameters | `builtin_transformation` | `drop_and_account`, `stop_pipeline` |
| `order_before` | `sink` | `processor`: a component or slot name | `pipeline_dispatch_order` | `drop_and_account`, `stop_pipeline` |
| `require_output_structure` | `sink` | `structure`: a structure name | `sink_admission` | `drop_and_account`, `stop_pipeline` |
| `suppress_matching` | `pipeline`, `component`, `slot`, `sink` | `all`: non-empty list of conditions | `suppression_evaluation` | `none` |
| `bound_size` | `queue`, `pipeline` | `max_records` (queue only) or `max_record_bytes` (pipeline only), an integer of at least 1 | `queue_admission` for a queue, `record_admission` for a pipeline | `drop_and_account`, `stop_pipeline` |
| `dispatch_through` | `pipeline` | `sink`: a sink name | `sink_dispatch` | `drop_and_account`, `stop_pipeline` |

A condition in `suppress_matching` is `{"field": <name>, "test": "equals" | "has_prefix", "value":
<string>}` or `{"field": <name>, "test": "present"}`.

What an acceptance covers, and what it does not:

| operation | covers | does not cover |
|---|---|---|
| `project_fields` | the input the core constructs for the component holds only the listed fields | data the component obtains by any route other than its input |
| `transform_field` | the core applies the built-in to the field before the target receives the record | copies of the field made before the target |
| `order_before` | no record reaches the sink unless the processor completed on it first | whether the processor did the right thing with it |
| `require_output_structure` | the sink admits only records the core validated against the structure | whether the values in a valid record are correct |
| `suppress_matching` | matching records do not reach the target, and each suppression is counted in the account | records that match only after a later transformation |
| `bound_size` | the core holds the queue, or the records entering the pipeline, within the bound | memory held by component code, which no core queue or record bound reaches |
| `dispatch_through` | the pipeline's output leaves by core dispatch through that sink alone | network actions taken by component code |

## The runtime inventory

The procedure is decided against what the runtime actually has, never against what a declaration
says it has: the enforcement points present, with any limits on their parameters; the pipelines with
their components, sinks and queues; the fields a record can carry; each component's execution
(`builtin` or `external`) and the fields its input can carry; the built-in transformations with the
integer arguments each defines and their limits; the structures a sink can validate against; the slots
pipelines hold components in, each with the component filling it; and each sink's kind and whether
dispatch through it leaves the host or keeps plaintext on it.
**A draft vocabulary accepted against one inventory is not accepted against another**, which is why the
inventory is an input and not a constant.

**A slot is named `<pipeline>.<slot>` and stands for whatever fills it.** A requirement targeting a
slot, or an ordering whose processor names one, is decided against the component filling the slot
after every replacement, so replacing that component does not make the requirement stop applying. A
requirement naming the replaced component by its own name names something the inventory no longer
has, and is refused rather than dropped. A processor name that is both a slot and a component could
mean either and is refused as `incompatible_interface`.

**A sink's kind is an OPEN string.** Nothing in the procedure reads the kind; what a decision reads is
`leaves_host` and `retains_plaintext`, and the kind names the sink for a reader and the account. A
runtime names its own kinds, and a kind in a worked case is illustrative rather than a list of the
kinds there are.

**A sink the inventory has no facts for is a missing capability**, whether a requirement targets it or
dispatches through it. An acceptance on a sink, or through one, names in its scope the sink's kind and
whether it leaves the host or keeps plaintext, so the account carries what the enforcement reaches.
No operation of this draft requires a sink not to leave the host; the configuration check refuses an
export or a retention the operator did not permit.

## The four dispositions

| disposition | when | what is refused or allowed |
|---|---|---|
| `accept` | supported, and its enforcement point exists | nothing refused; the result names the enforcement scope |
| `refuse_activation` | malformed, unknown operation, incompatible interface, missing mandatory capability | activation of every pipeline the declaration affects |
| `allow_trusted` | a claim the operator approved | nothing refused; the pipeline carries the limitation, labelled extension-declared and not core-enforced |
| `refuse_assurance` | a supported requirement the runtime has no enforcement point for | the whole configuration. A mandatory requirement is never downgraded |

**Two cases landing in one disposition with different reasons are two different results.** The reason
is part of the result, and a check that compares dispositions alone has compared half of it.

**The limitation an `allow_trusted` carries appears before the plugin receives data, and again in the
account.** An operator approving trusted behaviour without the assurance is making an explicit change
to the operating contract, not executing the original policy successfully.

## The procedure

Run over every document, then every requirement, claim and approval in order. Each declaration stops
at the FIRST check it fails, and the order is not arbitrary: each check presupposes the ones before
it, so a later reason is not established for a declaration that failed an earlier one.

    Document
    D1  vocabulary is observer.policy/draft                   else refuse_activation unknown_version
    D2  no requirement or claim reuses an id already seen,
        in this document or an earlier one                    else refuse_activation malformed

    Requirement
    R1  id, target kind, target name, operation and failure
        action are present                                    else refuse_activation malformed
    R2  the operation is one of the seven                     else refuse_activation unknown_operation
    R3  the target kind is one the operation accepts          else refuse_activation incompatible_interface
    R4  every parameter is one the operation defines for
        that target kind                                      else refuse_activation unknown_parameter
    R5  every parameter the operation requires is present
        and of its type, and the failure action is one the
        operation permits                                     else refuse_activation malformed
    R6  every parameter is within the vocabulary's own range  else refuse_activation parameter_out_of_range
    R7  the target and every name a parameter references
        exist in the inventory                                else refuse_activation missing_capability
    R8  they fit: every field named is one a record carries,
        a projected field is one the component's input
        carries, a processor ordered before a sink names one
        component or slot and is in a pipeline with it, and a
        transformation's arguments are exactly the ones
        that built-in defines                                 else refuse_activation incompatible_interface
    R9  the operation's enforcement point is in the inventory else refuse_assurance no_enforcement_point
    R10 every parameter is within the enforcement point's
        limits, and every transformation argument within
        its built-in's limits                                 else refuse_activation parameter_out_of_range
    R11                                                       accept enforced, naming the scope

    Claim
    C1  id, component and statement are present               else refuse_activation malformed
    C2  the component exists in the inventory                 else refuse_activation missing_capability
    C3  the component's execution is external                 else refuse_activation incompatible_interface
    C4  an operator document approves it                      else refuse_activation trusted_behaviour_not_approved
    C5                                                        allow_trusted operator_approved

    Approval
    A1  it names an id that exists                            else refuse_activation malformed
    A2  that id is a claim, not a requirement                 else refuse_activation approval_names_a_requirement
    A3  it comes from an operator document                    else refuse_activation approval_not_from_operator

**A document refused at D1 or D2 is not read further**, and its finding names `document:<index>`. A
requirement or claim with no id is refused at R1 or C1 under `requirement:<document>.<position>` or
`claim:<document>.<position>`, counting from zero, so two of them are never reported under one name.

**R4 precedes R5 on purpose.** A parameter an operation does not define is refused as unknown before
anything asks whether a defined one is missing, so a requirement smuggled onto an unrelated operation
as an extra parameter is named for what it is.

**R10 follows R9 because the limits belong to the enforcement point.** Without the point there is
nothing to hold the parameter against, and the binding reason is that the point is missing.

**Which pipelines a refusal affects.** A requirement affects the pipelines its target belongs to - a
pipeline itself, or every pipeline holding the component, slot, sink or queue. A claim affects every pipeline
holding its component. A refused document, a refused approval, and anything whose target cannot be
resolved affect EVERY pipeline: not knowing which pipeline a refusal reaches is not the same as it
reaching none. An approval that is not refused produces no finding of its own; the claim it approves
carries the result.

**A pipeline activates only when nothing refuses it**, and it activates carrying every limitation the
claims on its components were allowed with. Any `refuse_assurance` refuses every pipeline.

## Not in this vocabulary

**An execution memory budget is not an operation of this draft.** A processor's private allocations
grow independently of every core queue and record bound, so `bound_size` does not reach them and its
scope says so. A declaration naming such an operation is refused at R2, and one smuggling it onto
`bound_size` as a parameter is refused at R4. Supporting it is a change to this vocabulary, made by
adding a named operation with its own enforcement point, and never by widening an existing one.
