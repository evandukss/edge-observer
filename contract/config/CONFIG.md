# Operator configuration, pack manifest and component interface

Status: Live, draft contracts `observer.config/draft`, `observer.pack/draft` and
`observer.component/draft`. The notation below is the one the examples in `examples/` and the worked
cases in `testdata/cases/` are written in. **These remain draft contracts.** No machine-readable schema is published; example JSON files
show the document shapes, and the tool's Go validators enforce the contracts. What is specified here
is the semantics and the static check.

## Three documents and one inventory

| | written by | says |
|---|---|---|
| the configuration | the operator | what may be inspected, captured, kept and exported, which packs are enabled, and the pipelines |
| a manifest | a pack | the components it supplies, the pipelines it adds, the slots it selects implementations for, and its policy |
| a component declaration | whoever implements a component, inside a manifest or compiled into the runtime | what the component receives, returns, holds and requires |
| the runtime inventory (`Available`) | the runtime | the published record types, what the core emits, the built-ins, the sink kinds, the fixed descendant answers, and the enforcement points |

**The runtime inventory is supplied by the runtime and never read out of a document.** A pack cannot
declare a record type, a sink kind or an enforcement point into existence. `examples/runtime.json` is an
ILLUSTRATIVE inventory: its type names and fields are chosen for the examples and are not the published
record contract, which is `contract/record`'s.

Every member of every document is defined here. An undefined member, a key written twice, a value of the
wrong JSON type, and anything following the document are malformed. **No member has a default except the
two observer settings whose defaults are stated below as values**: a required scalar that is absent is
malformed. Some lists must be present even where they may be empty - `libraries`, `export_sinks` and a
pipeline's `slots` - and the rest may be absent, which means empty. "What the structural check refuses"
below lists every rule.

## The configuration

    {
      "version": "observer.config/draft",
      "observer": {"log": "stdout", "directory": "/var/lib/observer",
                   "spool_bound_mib": 64, "state_every_seconds": 30},
      "observation_scope": {"targets": [<target>, ...], "exclude": [<match>, ...],
                            "libraries": [{"build_id": "...", "symbols": {"SSL_read": 221920}}]},
      "traffic_scope": {"rules": [<rule>, ...]},
      "retention_and_export": {"retain_plaintext": false, "export_sinks": ["export"]},
      "packs": ["acme-classifier"],
      "sinks": [{"name": "account", "kind": "local_account"}],
      "pipelines": [<pipeline>, ...],
      "subscribers": [<subscriber>, ...],
      "policy": [<policy document>, ...]
    }

### Three controls, and none is expressed through another

    observation_scope      which instances may be inspected. Approval against it is decided BEFORE
                           plaintext is copied
    traffic_scope          which connections of those instances are captured, by direction and
                           port. Also decided before plaintext is copied
    retention_and_export   what may be kept on the host and what may leave it, checked against
                           the kind of every sink a pipeline dispatches through

**A condition that needs a reconstructed message is not a traffic scope condition.** It is a
post-capture suppression, written as `suppress_matching` in the policy vocabulary
(`contract/policy`), and it is evaluated on records of instances the observation scope already
approved. **A content filter is therefore never evidence that an unapproved process was not
inspected**: `examples/content-filter-is-not-approval.config.json` suppresses health checks, and a
process outside every target whose requests would match that suppression is not inspected because no
target selects it, not because anything filtered it.

`examples/scopes-inbound-retained.config.json` and `examples/scopes-outbound-exported.config.json` hold
the SAME target under different traffic and retention and export scopes.

A target is `{"name", "match", "descendants"}`. A match names at least one of `exe`, `args`, `cgroup`,
`pid` (`{"pid", "start", "boot"}`, an instance and not a number), `port` and `interface` - the
conditions the observer's admission reads. `libraries` names the library builds a probe may be placed
on, each by build id with the offsets its entry points are approved at; written empty it approves any
library, as an empty approval does in `process` `ApproveLibrary`. `spool_bound_mib`
and `state_every_seconds` are the observer's own settings and are OPTIONAL: absent, they are 64 and 30
(`DefaultSpoolBoundMiB`, `DefaultStateEverySeconds`), and the resolved view carries the value in force
either way. The observer (`policy`) reads its configuration through this check and turns the
resolved values into its own settings, and a test loads a file stating neither setting through it and
fails when its values and these disagree.
`observer.log` is `stdout` or an absolute path and `observer.directory` an absolute path: a relative path
would resolve against the observer process's working directory, which nothing configures, so one
configuration would write to different places depending on how the process was started.

A traffic rule is `{"targets", "direction", "local_ports", "remote_ports"}`: `targets` empty means every
target, `direction` is `inbound`, `outbound` or `any`, and an empty port list places no condition on that
side. At least one rule is written; `any` with no ports admits every connection of the selected
instances.

### Descendants: five answers, not one flag

    {"existing": true, "future": true,
     "boundary": "exec_ends_the_grant", "root_exit": "survivors_keep_their_grants",
     "replacement": "needs_restart"}

`existing` and `future` are the operator's to choose. **`boundary`, `root_exit` and `replacement` are
fixed by the runtime's admission** (`admission`, `Mode.Answers`) and are written out so a reader
of the configuration sees them. A configuration stating any other value is refused
(`descendant_answer_not_supported`); making one of them configurable is a change to admission first and
to this contract second. All five are required.

### Pipelines

    {"name": "exchanges", "input": "reconstruction",
     "slots": [{"name": "redact", "implementation": "http-redactor", "on_failure": "drop_and_account"}],
     "sinks": ["account"], "queues": [{"name": "exchanges-out"}]}

**Composition is an explicit pipeline.** Records of `input` enter, pass through the slots in order and
are dispatched through every sink. A slot holds exactly one implementation. **A replacement is a
different implementation in the same slot**, never a second component racing to intercept the first.

`on_failure` is what a record the implementation returns `record_error` for does: `drop_and_account`
or `stop_pipeline`. A `fatal` result always stops the pipeline.

**A pipeline with no slots is the no-extension path, and it is the same route through the core as any
other pipeline.** `slots` is required and written `[]` there. This contract defines no implicit
pipeline: a configuration names its pipelines. Whether a runtime supplies a configuration when an
operator gives none, and what it holds, is not decided here (`examples/no-extension.config.json` is one
such configuration written out, not a default).

A slot's `configuration` and a replacement's `configuration` are carried as supplied. They are checked
against nothing in this draft, because the component's `configuration_schema` is in the notation the
open schema decision chooses.

### Subscribers

    {"name": "notes", "stream": "exchanges", "implementation": "annotation-subscriber"}

A subscriber consumes one pipeline's output and emits linked findings that reference observation ids.
**It never rewrites a delivered record.** Reserved: nothing runs a subscriber in this draft, and the
check establishes only that the stream exists and the implementation is a subscriber accepting what
the stream delivers.

## The manifest

    {
      "version": "observer.pack/draft",
      "name": "acme-classifier",
      "pack_version": "2.3.0",
      "components": [<component>, ...],
      "pipelines": [<pipeline>, ...],
      "replacements": [{"pipeline": "exchanges", "slot": "redact", "implementation": "truncating-redactor"}],
      "policy": [<policy document>, ...]
    }

**A MANIFEST DECLARES AND DOES NOT ESTABLISH.** Everything in it is what the pack says about itself.
Accepting it establishes that the documents are well formed and compose with each other and with what
the runtime has. It establishes nothing about whether the pack's code does what its components declare:
a component declaring `state: none` may keep state, and a configuration a component's
`configuration_schema` admits is structurally valid and says nothing about whether the component obeys
it. What the core enforces is what the policy vocabulary accepts at an enforcement point, and nothing a
manifest says widens that.

**Only an enabled pack takes part in composition.** A manifest is enabled by the configuration naming
its `name` in `packs`; a supplied manifest nobody enables is read structurally and contributes nothing.
A pack supplies external components only.

**A replacement selects; it does not have to supply.** Its implementation is resolved in the effective
available component set - the runtime's built-ins and every enabled pack's components - so a
configuration-only pack selecting an available compatible built-in is a replacement
(`examples/configuration-only-pack.config.json`). A replacement is compatible with its slot when the
implementation is a processor, accepts every type reaching the slot, and produces only types the slot's
next consumer - the next slot, or every sink - accepts. Two replacements selecting one slot select
neither.

**An ordering names a component and stands for the slot it fills, so a replacement inherits every ordering
on its slot**: those the replaced component declares, and those other components declare naming it. A
pack that could drop an ordering by replacing the component it names could remove a core-enforced
guarantee, so the ordering is never dropped, and a replacement that cannot satisfy an inherited ordering
is refused (`replacement_incompatible`). A named component that is absent from a pipeline, rather than
replaced in it, constrains nothing there.

A pack's policy documents are loaded with the PACK as their source, and an operator's with the
operator as theirs. The source is attached by the check from which document carried them, never read
out of the policy document.

## The component interface

    {
      "interface": "observer.component/draft",
      "name": "acme-classifier", "version": "2.3.0",
      "role": "processor", "execution": "external",
      "input": {"types": ["reconstruction"], "delivery": "batch"},
      "output": {"records": ["reconstruction"], "derived": ["annotation"], "suppression": true, "findings": false},
      "state": "per_connection",
      "ordering": {"records": "in_order_per_connection", "after": ["http-redactor"], "before": []},
      "lifecycle": {"startup": "handled", "configuration_change": "handled", "stream_closure": "handled",
                    "flush": "handled", "shutdown": "handled"},
      "failures": ["record_error", "fatal", "configuration_refused"],
      "configuration_schema": <carried, not interpreted>
    }

**A component receives records or batches of published record types and returns transformed records,
derived records, suppression decisions or errors. It does not receive pointers into the core**: every
type it names is resolved against the runtime's published types, and nothing in a declaration can name
anything else.

| member | values | means |
|---|---|---|
| `role` | `processor`, `subscriber` | a processor fills a slot; a subscriber consumes a stream and returns linked findings only |
| `execution` | `builtin`, `external` | compiled into the runtime, or supplied by a pack |
| `input.types` | published type names | at least one. One record, or one batch of one type, is delivered at a time, so the component runs on whichever listed type arrives, and reachability asks whether any of them does. A component needing several records together declares batch delivery of the type they share: that is the ONLY mechanism for it, and a correlated delivery form would be a change to this interface |
| `input.delivery` | `record`, `batch` | one record at a time, or batches |
| `output.records` | published type names | the types of the records it passes on |
| `output.derived` | published type names | new records it creates, linked to the observation ids they derive from |
| `output.suppression` | boolean | it returns suppression decisions, which the core applies and accounts. A processor returning only these passes on what reached it |
| `output.findings` | boolean | linked findings; a subscriber's only output, and never a processor's |
| `state` | `none`, `per_connection`, `per_stream`, `pipeline` | what it holds between records. Any state but `none` handles `stream_closure` and `flush` |
| `ordering.records` | `none`, `in_order_per_connection` | what it requires of the order records reach it in |
| `ordering.after`, `ordering.before` | component names | components that must precede or follow it wherever both are in one pipeline |
| `lifecycle.*` | `handled`, `ignored` | the supporting hooks: startup, configuration change, stream closure, flush, shutdown. They carry no domain processing |
| `failures` | `record_error`, `fatal`, `configuration_refused` | the failure results it can return; `fatal` is always among them |
| `configuration_schema` | opaque | declared, carried, and not interpreted by this draft |

**What this interface FREEZES** once its version leaves draft: the members above and their meanings,
that inputs and outputs are published record types and never core internals, that a component occupies
a slot of an explicit pipeline, the three failure results and what the pipeline does with each, and
that lifecycle hooks are supporting and carry no processing.

**What the subprocess wire protocol still OWES**, none of which this interface decides: the framing and
encoding of records and batches on the wire; how a derived record's link to observation ids is carried;
how a suppression decision names the record it suppresses; how and when each lifecycle hook is
delivered and acknowledged; flow control, back-pressure and timeouts; how a `fatal` or a crash is
observed and how `configuration_refused` is reported; how `configuration_schema` is expressed; and
version negotiation between the core and a component. **No execution budget is part of this interface**
(`contract/policy`, VOCABULARY.md, "Not in this vocabulary").

## The check

`Check(Input) Result` reads the configuration and every supplied manifest, and has three outcomes:

    structurally_refused   a document is not a well-formed document of its kind. Composition was NOT
                           checked, so the result says nothing about it
    composition_refused    every document is well formed and they do not compose with each other or
                           with the runtime inventory
    accepted               they compose. The result carries the resolved view. It establishes
                           nothing about what any component's code does

**Structural acceptance is not composition acceptance**, and a result never reports both as checked
when only one was. A structural finding names the member path; a composition finding names its subject
(`component:`, `pipeline:`, `slot:`, `sink:`, `target:`, `pack:`, `subscriber:`, `replacement:`) and the
document it was declared in. Every finding carries a detail. Composition collects every finding rather
than stopping at the first.

It is static. It executes no component, decides no policy and enforces nothing - the policy vocabulary's
`Decide` is run over the resolved view by whoever needs a decision.

**A runtime that implements part of this contract refuses the rest BETWEEN the two stages.** The order
is: structural, then what the runtime does not implement, then composition against its inventory. A
document that is not well formed is refused as that first. A well-formed section the runtime implements
nothing of is refused next, naming the section and the capability it needs, because composition
against that runtime's inventory would refuse it for a reason answering a different question - `packs`
naming a pack is `unknown_pack` against an inventory that can load none, and the operator needs to hear
that no pack is loaded. **The decision is the inventory's count, not the section's name**: NONE of a
kind (no processor, no subscriber, no sink kind leaving the host) is a kind the runtime does not
implement; SOME of a kind without the one named is the operator's error and stays a composition
refusal. The observer's own subset and its refusals are `policy`'s (`Unimplemented`).

| reason | stage | when |
|---|---|---|
| `unknown_version` | structural | a document, or a component declaration, of a version this draft does not read |
| `malformed` | structural | an undefined member, a key written twice, a required member absent, a value outside its set, or a declaration contradicting itself |
| `duplicate_name` | structural | two members of one list with one name. Also given at composition for two pipelines or two supplied packs with one name |
| `unknown_pack` | composition | the configuration enables a pack no supplied manifest declares |
| `unknown_type` | composition | a type that is not a published record type |
| `unknown_target` | composition | a traffic rule names a target the observation scope does not have |
| `unknown_sink` | composition | a pipeline or the export list names a sink that is not configured |
| `unknown_sink_kind` | composition | a sink names a kind the runtime does not have |
| `unknown_stream` | composition | a subscriber consumes a pipeline that does not exist |
| `unknown_slot` | composition | a replacement names a slot no effective pipeline has |
| `unknown_component` | composition | a slot or subscriber names an implementation not in the effective available set |
| `component_name_taken` | composition | a pack component's name is already a built-in's or another enabled pack's |
| `role_mismatch` | composition | a subscriber in a slot, or a processor as a subscriber |
| `descendant_answer_not_supported` | composition | a fixed descendant answer stated as anything but the runtime's |
| `input_type_not_produced` | composition | a pack component receives a type that neither the core nor any other available component produces |
| `input_type_unreachable` | composition | a pack component receives a type other components produce, and none of them can run on anything reachable from the types the core emits |
| `pipeline_input_not_emitted` | composition | a pipeline's input is a type the core does not produce |
| `input_type_mismatch` | composition | a type reaches a slot, sink or subscriber that does not accept it |
| `ordering_unsatisfiable` | composition | components in one pipeline declare orderings that no order satisfies |
| `ordering_not_met` | composition | the declared orderings are satisfiable and the slot order does not satisfy them |
| `replacement_not_resolvable` | composition | a replacement's implementation is not in the effective available set |
| `replacement_incompatible` | composition | a resolvable replacement is not a processor, does not accept what reaches its slot, produces what the next consumer does not accept, or cannot satisfy an ordering it inherits from its slot |
| `replacement_conflict` | composition | two replacements select one slot |
| `export_not_permitted` | composition | a pipeline dispatches through a sink that leaves the host and is not an export sink |
| `retention_not_permitted` | composition | a pipeline dispatches through a sink that keeps plaintext where `retain_plaintext` is false |

**The three states a composition check exists to refuse are each structurally well formed**, and each is
refused with a reason naming which it is: a manifest declaring a component whose input type no producer
emits (`input_type_not_produced`), or whose input type is produced only by components that can never run
because nothing the core emits reaches them (`input_type_unreachable`); two components whose declared orderings cannot both be satisfied
(`ordering_unsatisfiable`); and a pack selecting a replacement that cannot be resolved in the effective
available set (`replacement_not_resolvable`) or is incompatible with its slot or type
(`replacement_incompatible`).

## What the structural check refuses

Every refusal the structural check can make, one line each: the member, the reason, and the condition.
A document refused as unreadable or at its version is not read further; otherwise every rule is applied
and every finding reported. `<target>`, `<rule>`, `<library>`, `<sink>`, `<pipeline>` and `<component>`
stand for one entry of that list, written out in full wherever a row names a member of another.

**The configuration** - document `configuration`:

    (document)                              malformed        not JSON, an undefined member, a key written twice,
                                                             a value of the wrong type, or anything after the document
    version                                 unknown_version  not observer.config/draft
    observer.log                            malformed        absent
    observer.log                            malformed        neither stdout nor an absolute path
    observer.directory                      malformed        absent
    observer.directory                      malformed        not an absolute path
    observer.spool_bound_mib                malformed        present and below 1
    observer.state_every_seconds            malformed        present and below 1
    observation_scope.targets               malformed        absent or empty: a configuration selecting no instance
                                                             observes nothing
    observation_scope.targets               duplicate_name   two targets with one name
    <target>.name                           malformed        absent
    <target>.match                          malformed        names none of exe, args, cgroup, pid, port, interface:
                                                             a match with no condition would select every instance
    observation_scope.exclude[i]            malformed        as for <target>.match
    <target>.match.port                     malformed        outside 1 to 65535
    observation_scope.exclude[i].port       malformed        outside 1 to 65535
    <target>.descendants.<each of five>     malformed        absent
    observation_scope.libraries             malformed        absent (written empty, it approves any library)
    <library>.build_id                      malformed        absent
    <library>.symbols                       malformed        absent or empty
    traffic_scope.rules                     malformed        absent or empty
    <rule>.direction                        malformed        absent, or not inbound, outbound or any
    <rule>                                  malformed        a local or remote port outside 1 to 65535
    retention_and_export.retain_plaintext   malformed        absent
    retention_and_export.export_sinks       malformed        absent (written empty, it exports nothing)
    packs                                   duplicate_name   one pack named twice
    <sink>.name, <sink>.kind                malformed        absent
    sinks                                   duplicate_name   two sinks with one name
    pipelines                               malformed        absent or empty: the no-extension path is written out
    subscribers[i].name, .stream,           malformed        absent
      .implementation
    subscribers                             duplicate_name   two subscribers with one name
    policy[i]                               malformed        not a policy document read strictly: an undefined member,
                                                             a key written twice, or a value of the wrong type

**Every pipeline**, in a configuration or a manifest - `pipelines` must be non-empty in a configuration
and may be absent in a manifest:

    <pipeline>.name, .input                 malformed        absent
    <pipeline>.slots                        malformed        absent (written empty for the no-extension path)
    <pipeline>.slots[j].name,               malformed        absent
      .implementation
    <pipeline>.slots[j].on_failure          malformed        absent, or not drop_and_account or stop_pipeline
    <pipeline>.slots                        duplicate_name   two slots with one name
    <pipeline>.sinks                        malformed        absent or empty: a pipeline dispatches through at least one sink
    <pipeline>.sinks                        duplicate_name   one sink named twice
    <pipeline>.queues[j].name               malformed        absent
    <pipeline>.queues                       duplicate_name   two queues with one name
    pipelines                               duplicate_name   two pipelines with one name

**A manifest** - document `manifest:<supplied name>`:

    (document)                              malformed        as for the configuration
    version                                 unknown_version  not observer.pack/draft
    name, pack_version                      malformed        absent
    components[i].execution                 malformed        not external: a built-in is the runtime's
    components                              duplicate_name   two components with one name
    replacements[i].pipeline, .slot,        malformed        absent
      .implementation
    policy[i]                               malformed        as for the configuration

**A component declaration in a manifest.** The runtime's built-ins are checked against the same rules
by a test, `TestEveryBuiltinSatisfiesTheComponentRules`, which runs these rules over the built-in set -
today the one in `examples/runtime.json`, the only built-in set in this tree - and fails on any
finding. Checking a configuration does not re-read them, because they are compiled in and cannot vary
between starts:

    <component>.interface                   unknown_version  not observer.component/draft; nothing else in it is read
    <component>.name, .version              malformed        absent
    <component>.role                        malformed        absent, or not processor or subscriber
    <component>.execution                   malformed        absent, or not builtin or external
    <component>.input.types                 malformed        absent or empty
    <component>.input.types                 duplicate_name   one type listed twice
    <component>.input.delivery              malformed        absent, or not record or batch
    <component>.state                       malformed        absent, or not none, per_connection, per_stream or pipeline
    <component>.ordering.records            malformed        absent, or not none or in_order_per_connection
    <component>.lifecycle.<each of five>    malformed        absent, or not handled or ignored
    <component>.lifecycle                   malformed        state is not none and stream_closure or flush is not
                                                             handled: kept state would have no end
    <component>.failures                    malformed        absent or empty
    <component>.failures                    malformed        a value that is not record_error, fatal or
                                                             configuration_refused
    <component>.failures                    malformed        fatal not among them, because every component can
                                                             fail fatally
    <component>.failures                    duplicate_name   one failure result listed twice
    <component>.output                      malformed        a subscriber returning records, derived records or
                                                             suppression decisions, or not returning findings
    <component>.output.findings             malformed        a processor returning findings, which are a subscriber's
    <component>.output                      malformed        a processor returning no records, no derived records and
                                                             no suppression decisions; a component that only observes
                                                             and reports is a subscriber returning findings
    <component>.ordering                    malformed        after or before names the component itself

## The resolved view, and what the policy inventory carries

An accepted result carries the observer settings with the optional ones resolved, every effective
pipeline after replacements, who selected each slot's implementation, the five descendant answers per
target, the policy documents with their sources, and the policy `Inventory` (`contract/policy`) projected from them: each pipeline's components, sinks
and queues; each used component's execution and the fields its input types carry; the fields every
published type carries; and the enforcement points, transformations and structures the runtime has.

The inventory also carries every SLOT, named `<pipeline>.<slot>` with the component filling it after
replacement, so a requirement can target the slot rather than the component and goes on applying when a
pack replaces it; and every configured SINK with its kind and whether it leaves the host or retains
plaintext, which an acceptance through that sink names in its scope.

**What the configuration says and the inventory does not carry**, so a policy declaration cannot name
it: a component's input TYPES, carried only as the union of their fields; record fields per type rather
than as one list; the order of slots; and the three scopes and the descendant answers.
