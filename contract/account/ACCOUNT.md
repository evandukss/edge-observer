# Observer account contract

Versions: account `observer.account/1-draft`, bundle `observer.bundle/1-draft`. **DRAFT and not frozen.**
No machine-readable schema is published; example JSON files show the document shapes, and the tool's
Go validators enforce the contracts. This document is the contract and the Go types in this directory
encode it. Where the two disagree this document is corrected first.

The account is what the observer says about ONE capture session: what was asked for and what it resolved
to, what was attached, what came through, what was lost, what could not be established, what processing
did, which requirements the core enforces and which it does not, and how the session ended. The records it
describes are the record contracts (`contract/record/record.md`). The bundle is a sealed account
and those records, copied together so they can be validated and inspected away from the host that wrote
them.

It is domain-neutral. Nothing here names a business operation or a privacy rule.

## Two things called the account, and the one relation between them

| Name here | What it is | Where | Version |
|---|---|---|---|
| **operational account** | the observer's own account of a session at three moments - planned, live, sealed - built by one set of functions and sealed beside the session's spool | `account`, `Account` | `Version` = 1 |
| **account** | this contract: the published form of a SEALED operational account, with the records it describes carried beside it in a bundle | `contract/account` | `observer.account/1-draft` |

**The relation is one-way and versioned on the operational account's number.** An account at
`observer.account/1-draft` is PROJECTED from an operational account of version 1 and nothing else; a
projection that is handed any other version refuses. Wherever this contract says account it means the
second row.

What a reconstruction carries per connection - reconstructed exchanges, discards, duplicates, unplaced bytes,
placement - is carried by the record contracts' `reconstruction`, `reassembly` and `connection` records,
which are bundle members.

## Encoding

JSON, as the record contracts. Every count is a DECIMAL STRING, so a reader whose numbers are doubles cannot
round it. Instants, births, namespaces and text-that-may-be-unread are the record contracts' primitives
(`record.md`, Primitives) and mean exactly what they mean there.

**Every member the contract names is REQUIRED wherever its block is `carried`, and a member that is not
there is refused.** Where a producer has nothing to say, the BLOCK is present and says which kind of nothing
it is (Block state, below). A list that is empty is `[]`, never absent.

## Block state

Every block carries `state`, and `why` where the state is `unavailable`.

| `state` | Means |
|---|---|
| `carried` | the block was read, and every member it names is present and holds what was read |
| `unavailable` | the producer tried to read it and could not; `why` says what failed |
| `not_reached` | the moment precedes it: a planned account has not captured, and only a sealed one has a seal |
| `not_carried` | this contract names it and this producer does not supply it at all; never a reading of the session |

A block that is not `carried` holds NO VALUES: beside `state`, `why` and a member naming which block of a list
it is - a control's `control` - a member is absent or empty (`""`,
`false`, `0`, `[]`, `{}`, or an object whose members are all empty). One that holds a value is refused with
`member_not_in_contract`, because a count beside `not_carried` is a count nobody can say was read.

**None of the three absences is zero, and a block missing from the document is none of them.** A reader
that cannot find a required block REFUSES with `required_block_absent`, naming the block's path. A missing
`capture.ordering` never reads as nothing disordered, nothing tolerated, nothing retired and nothing
unexplained: it is a document that does not say, and saying so is the whole of what a reader does with it.
Presence is checked first; no verdict is read off a block until every required block has been found.

Which states each moment permits:

| Block | `planned` | `live` | `sealed` |
|---|---|---|---|
| `provenance`, `scope` | carried | carried | carried |
| `capture` | not_reached | carried, unavailable | carried, unavailable |
| `reconstruction` | not_reached | carried, unavailable, not_carried | carried, unavailable, not_carried |
| `processing`, `requirements` | any but not_reached | any but not_reached | any but not_reached |
| `seal` | not_reached | not_reached | carried, unavailable |

A state a moment does not permit is refused with `block_state_not_permitted`.

**`reconstruction` permits `not_carried` and `capture` does not, and the asymmetry is the whole of what
separates them.** Capture happens while the session runs, so a producer that captured has a reading to
report and one that could not has a failure to report - `carried` or `unavailable`, and there is no third
answer. **RECONSTRUCTION RUNS AT READ TIME**, so a producer sealing
an account **does not supply it at all**, which is `not_carried` by this table's own definition above:
this contract names it and this producer does not supply it. It is NOT `unavailable`, which would say the
producer tried to read it and could not - false, because it never tried.

**And the rule that a block which is not `carried` holds no values does the rest.** A `not_carried`
reconstruction cannot carry the six totals, so "absent rather than a zero that reads as none happened" is
something the validator REFUSES rather than something two producers have to agree about.

**A reader that reconstructs supplies them and its own block is `carried`**, which this table already
permits at `live` and `sealed`. Nothing further is owed for that direction.

## The account

    account         "observer.account/1-draft"
    session         the session id
    moment          planned | live | sealed
    at              instant: wall, observer_wall_read - when the account was taken
    provenance      block
    scope           block
    capture         block
    reconstruction  block
    processing      block
    requirements    block
    seal            block
    extensions      object, possibly empty

### Required blocks

The dotted path of every block, and each is required wherever its parent block is `carried`:

    provenance
    provenance.observer
    provenance.configuration
    provenance.pipelines
    scope
    scope.requested
    scope.instances
    scope.overlap
    scope.placement
    scope.coverage
    scope.filters
    capture
    capture.capability
    capture.seen
    capture.loss
    capture.admitted
    capture.ordering
    capture.refused
    capture.spool
    reconstruction
    processing
    requirements
    seal
    seal.recorded

Beside the blocks, every other member named below is required where its block is `carried`, and one that is
absent is refused with `required_member_absent`; the only optional members are a block's `why` - required when
it is `unavailable` - and the reasons that exist only for some values: a placed process's `reason`, a probe's
`through` and `refusal`, an admission's `why`, an instance coverage's `why`, a cgroup's `why`, a withheld claim's `reason`, a declaration's `limitation`, an accepted requirement's `sink`, and a withdrawal's and a drain's
`because`. A list is `[]`, and `null` is
absent. A count is a decimal string, and a value outside its vocabulary, or a count that is not decimal, is
`value_not_in_contract`. A member the contract does not name, anywhere outside an extension's `content`, is
refused with `member_not_in_contract`.
**That is what stops a pack writing a second `capture` or a `loss` of its own at the top level.**

### provenance

| Member | Meaning |
|---|---|
| `observer` | block: the capability facts of the BUILD (below) and `floor` `{published, proved, established, would_establish}` - claims about the build and not about this session |
| `contracts[]` | the contract versions this account and its records are written at |
| `configuration` | block: `references[]` `{document, revision, generation}` - the configuration the session ran under BY REFERENCE: its content revision and the generation the session activated. **Never its content and never a credential** |
| `pipelines` | block: `pipelines[]` `{name, input, declared_by, slots[] {slot, implementation, version, selected_by}, sinks[]}` - the effective pipelines as the configuration check resolved them, with the version of each implementation |

### scope

What was asked for, what it resolved to, and what the session's coverage turned out to be.

| Member | Meaning |
|---|---|
| `requested` | block: `controls[]`, one per control - `observation_scope`, `traffic_scope`, `retention_and_export` - each its own block `{state, control, document, revision, member}`. Three separate controls, never one expressed through another. A control this producer does not read is `not_carried`, which is not a control that was empty |
| `targets[]` | `{number, name, mode, descendants, resolution, roots[], existing_descendants[], denied[], unsupported[], cgroups[], listeners[]}`. `descendants` is the five answers `{existing, future, boundary, root_exit, replacement}`. `resolution` is a block: `carried` where the target resolved, `unavailable` with `why` where it did not - an unresolved target selected nothing because nothing could be resolved, which is not a target that matched nothing. `cgroups[]` holds `{path, inode, why}` for a cgroup target as it was when resolved, `listeners[]` `{address, owners[]}` for a port target; each is empty for a target that selects another way |
| `exclusions[]` | `{number, roots[], denied[]}` |
| `overlap` | block: `instances[]` `{instance, targets[]}` - every instance more than one target selected |
| `instances` | block: `instances[]`, one per instance the scope named, `{instance, selected_by[], multiply_selected, excluded_by[], coverage, why, evidence[]}` (below) |
| `placement` | block: `processes[]` `{pid, birth, pid_namespace, namespace_pid, executable, runtime, mode, capability, outcome, reason, requested, confirmed, partial, probes[], unattempted[], uncatalogued[], absent[]}`. `capability` is the capability facts of that process's attachment; `partial` where fewer probes were confirmed than requested; `probes[]` is `{symbol, path, offset, confirmed, through, refusal}` per entry point asked for; `unattempted[]` is what the catalogue attaches to and this session did not ask for, `uncatalogued[]` what the library exports that the catalogue does not name, `absent[]` what the catalogue expects and the library lacks |
| `coverage` | block: `rule`, `covered`, `by_target[]` `{target, covered, ended, unknown}`, `coverage_ended[]` and `grant_unknown[]` `{instance, target, inherited, no_later_than, read_from, read_to, why}`; the three instants are undetermined where there is no reading |
| `filters` | block: `filters[]` `{name, stage}`, `stage` `pre_capture` or `post_capture`. **A filter that needs reconstruction is `post_capture`**, and it is never evidence that anything it removed was not read |
| `limits[]` | what this scope's coverage does not reach, one sentence each |

An `instance` is `{pid, pid_namespace, namespace_pid, birth, executable}`: the pid in the observer's own pid
namespace, the process's pid namespace read at resolution, its number there, its start identity and its
executable. Never its arguments. A determined pid namespace says what established it: `resolution_proc_read`
for one read from `/proc` when the policy was resolved, `admission_event` for a descendant whose admission the
kernel reported. **Approval is checked before plaintext is copied**; the scope is where a reader learns which
instances were eligible to be read, and nothing a later filter did narrows it.

#### Per-instance coverage

`scope.instances` answers, for each instance the scope named, whether it was covered - so a reader never
derives coverage from `targets` and `placement` and gets a different answer from the next reader.

| Member | Meaning |
|---|---|
| `selected_by[]` | every target that selected the instance |
| `multiply_selected` | whether more than one did |
| `excluded_by[]` | what removed it: `target:<name>` for a denial under a target, `exclusion:<number>` for an exclusion |
| `coverage` | one of the values below |
| `why` | required for every coverage but `covered` and `excluded` |
| `evidence[]` | the references (Evidence references, below) that establish the coverage; empty where it is `undetermined` |

| `coverage` | Means |
|---|---|
| `covered` | attached with every probe it was asked for |
| `partially_covered` | attached with fewer probes than it was asked for |
| `not_covered` | selected and not attached, or no adapter can observe it; `why` says which |
| `excluded` | an exclusion removed it |
| `undetermined` | nothing establishes its coverage: no placement names it, or more than one placement could. **It is never read as not covered** |

**Coverage is never inferred from ABSENCE.** An instance no placement names is `undetermined`, not
`not_covered`: nothing said anything about it, which is a different fact from something saying it was not
attached.

#### Placement identity, and what it does not establish

A placed process is identified by `pid`, `birth`, `pid_namespace`, `namespace_pid` and `executable`. **That is
NOT unique under pid reuse while `birth` is undetermined**: a reused pid in the same namespace running the same
executable matches every other member. So the join from a placement to the instance it attached is only as
strong as those members: `scope.instances` states a coverage where exactly one placement matches and
`undetermined` where more than one could, and **a coverage joined without a determined birth cannot tell the
instance from a later process that reused its pid**. **What removes that is the process's birth reaching the
event**, which the observer does not carry yet.
`namespace_pid` and `executable` are `not_carried` wherever the producer does not supply them; at operational
account version 1 it supplies neither for a placed process.

### capture

Every member is its own block, so one that could not be read is not read as the others.

| Member | Members of the block |
|---|---|
| `capability` | the capability facts of the ATTACHMENT, and `sentence`, the observer's own sentence saying what it can report |
| `seen` | `transfers`, `unmeasured`, `empty`, `records`, `connections`, `closed`, `early`, and what capture could not place: `rejected`, `unattributed`, `endings_unmatched`, `connections_unrecorded` |
| `loss` | `dropped`, `unmatched`, `occasion` `{first, last, handle, pid, tid}`: the first and last unmatched return on the monotonic clock, and the first one's handle, process and thread, each undetermined where no occasion was stated. Losses only |
| `admitted` | `descendants`. Not a loss |
| `ordering` | `disordered`, `unstamped`, `tolerated`, `lost`, `retired`, `unexplained`. Never folded into `loss`: a session that could not order its observations has not lost them |
| `refused` | `reasons` `{reason: count}` |
| `spool` | `written`, `dropped`, `refused`, `connections`, `connections_dropped`, `connections_refused`, `bytes`, `limit` |

The capability facts, in `provenance.observer` and `capture.capability` alike: `backend`, `program`,
`minimum_kernel`, `payload`, `filtered`, `descendants`, `lifecycle`, `binding`, `socket_evidence`, `ipv6`,
`unobserved[]`, and `withheld[]` `{claim, member, reason}`.

`retired` is the streams a located loss ended. The seal's `interrupted` is a different fact - transfers
refused at the read boundary - and the two never share a name here.

### reconstruction

Totals over the session: `connections`, `exchanges`, `complete`, `discards`, `duplicates`, `unplaced` bytes.
**Each connection's reconstruction status is in the `reconstruction` records**; the totals say how many there
are to find.

### processing

`pipelines[]` `{pipeline, activation, received, suppressed[], failed[], outputs[]}`. `suppressed` and
`failed` are `{by, reason, count}`; `outputs` are `{sink, disposition, count}`. `activation` is `active` or
`refused`; an output `disposition` is `dispatched`, `refused` or `dropped`. **A suppression is
accounted, not silent**: a record a predicate removed is counted under the component and reason that removed
it.

### requirements

The dispositions `contract/policy` decides, kept in three lists so the core's guarantee and an
extension's claim are never in one:

| Member | What | Disposition |
|---|---|---|
| `core_enforced[]` | `{declaration, operation, enforcement_point, covers, does_not_cover, sink, pipelines[]}` - the scope the vocabulary's acceptance names. `sink` `{kind, leaves_host, retains_plaintext}` is present exactly where the acceptance targets a sink or dispatches through one, and absent otherwise | `accept` |
| `extension_declared[]` | `{declaration, declared_by, disposition, reason, limitation, pipelines[]}` - operator-approved and NOT core-enforced, with the claim's statement under the trusted label in `limitation` | `allow_trusted` |
| `refused[]` | the same shape, without `limitation` | `refuse_activation`, `refuse_assurance` |

### seal

`stopped` and `sealed` instants; `complete` and `because[]`; `withdrawal` `{at, instances, complete, because}`;
`drain` `{delivered, outstanding, complete, because}`; `interrupted`, calls inside the library when authority
was withdrawn; `counters`, every counter the seal holds by the observer's own name for it, each a record
`count` because the seal can fail to read one, in the unit of what it counts as that counter's declaration in
the observer says - `places`, `events`, `calls`, `fragments`, `bytes`, `instances`, `descriptor_lifetimes` or
`bindings`; `conserved[]`, every conservation identity over those counters, each side in the unit of its left
term,
`{name, left, right, holds}` with `holds` `holds`, `does_not_hold` or `not_evaluated`; `recorded`, a block
saying whether every descriptor lifetime, binding and denial the session saw could be recorded - `complete`,
and `unavailable` where any of the three counts could not be read; then `members[]`.

**`members[]` binds the records to this session**: one `{role, sha256, records}` per record role
(`observations`, `connections`, `reconstructions`, `reassembly`), the SHA-256 of the member file and the
number of records in it, taken when the session's records stopped changing. A seal that could not be taken
is `unavailable` with `why`, and a bundle of it cannot be bound to its session.

### extensions

`{namespace: {schema, content}}`. A namespace is a lower-case dotted name of at least two parts
(`example.tally`), so it can never be a core block's name; any other form is refused with
`extension_namespace_invalid`. `schema` is a schema id. `content` is the extension's own and nothing in this
contract constrains it.

**Extension material is added, never substituted.** It lives only under `extensions`, a member the contract
does not name elsewhere is refused, and so an extension can say anything about the session except in the
core's voice: it cannot replace what the core said about capture loss or coverage.

## The bundle

A directory. Its root holds `bundle.json`:

    bundle      "observer.bundle/1-draft"
    session     the session id
    members[]   {role, path, contract, sha256}
    schemas[]   {id, path}

| `role` | `contract` | File |
|---|---|---|
| `account` | `observer.account/1-draft` | one account, JSON |
| `observations` | `observer.record/1-draft` | JSON Lines, one `observation` per line |
| `connections` | `observer.record/1-draft` | JSON Lines, one `connection` per line |
| `reconstructions` | `observer.record/1-draft` | JSON Lines, one `reconstruction` per line |
| `reassembly` | `observer.record/1-draft` | JSON Lines, exactly one `reassembly` |

Every role is required, once. `path` is relative to the bundle root, `sha256` is the lower-case hex digest of
the file's bytes. `schemas[]` are extension schemas the bundle carries; they are optional, and a bundle with
none is complete.

**A bundle is of a session that ended**: its account's `moment` is `sealed`.

### What validation checks, in order

Presence before verdicts, and each stage runs only if the one before it found nothing.

**A finding names a cause, and a consequence of a cause already reported is not a separate finding.** A
reference that fails for a reason independent of every reported cause is its own finding: a member genuinely
absent from the bundle is a defect of its own, and the same member unreachable only because a link above it was
refused is not. So one cause is one finding however many references it makes fail, and several independent
causes are several findings.

1. **The manifest.** `bundle.json` present, well formed, at a known version.
2. **Closure.** Every reference in the bundle resolves inside it (Closure, below); a member path naming no
   file is `member_missing`. No symbolic link anywhere in the bundle.
3. **The members.** Every role present once; no unknown role; each member's `contract` the one its role
   requires; each file's digest the manifest's.
4. **The account's presence.** Version known; every required member present; every block's state one of
   the four and permitted by the moment; nothing outside the contract; `moment` sealed.
5. **The records.** Every line a record of its member's kind, at a known record version.
6. **The session.** The manifest's `session` is the account's. The seal is `carried`. Every record member's
   digest is the one `seal.members` names for its role, and holds the number of records it names.
7. **Extensions.** Each namespace well formed. Each section's schema id executed where the validator has an
   executor for it.

### The result

| `outcome` | `validated` | Means |
|---|---|---|
| `refused` | `none` | not a conforming bundle, and nothing in it is vouched for; `findings[]` say why, each `{member, at, reason, detail}` |
| `core_validated_extension_not_checked` | `core_envelope` | the core envelope validated, and at least one extension section was not checked. **Nothing is said about the unchecked sections** |
| `validated` | `core_envelope_and_extensions` | the core envelope validated, and every extension section present was checked and conforms. A bundle with no extensions is this |

`extensions[]` has one `{namespace, schema, state, why}` per section: `conforms`, `nonconforming`, or
`not_checked` with `schema_unavailable` - neither the bundle nor the validator has that id - or
`schema_not_executable` - the bundle carries a schema file and the validator has no checker for its id.
A nonconforming section refuses the bundle with `extension_invalid`.

`examined` says how much was looked at - `members`, `records`, `blocks` - so a result can be told from one
that examined nothing.

### Refusal reasons

    bundle     manifest_absent, manifest_malformed, unknown_bundle_version, unknown_role,
               duplicate_member, member_missing, member_digest_mismatch, unknown_member_contract,
               reference_outside_bundle, link_not_permitted, reference_unresolved
    account    account_malformed, unknown_account_version, required_block_absent,
               required_member_absent, value_not_in_contract, unknown_block_state,
               block_state_not_permitted, member_not_in_contract, account_not_sealed,
               extension_namespace_invalid, extension_invalid
    records    record_malformed, unknown_record_version, record_kind_mismatch
    session    session_mismatch, session_binding_unavailable, member_not_of_session,
               member_count_disagrees

**A bundle assembled from two sessions refuses on the session stage**: a record member from another session
does not carry the digest this account's seal names for it (`member_not_of_session`), however carefully the
manifest was rewritten to match the files - the manifest is the assembler's and the seal is the session's.

**What the binding rests on, and what would strengthen it.** The observer's operational account at version 1
holds no digest of its spool, so `seal.members` is written when the bundle is assembled, from the records the
assembler was handed. Validation therefore refuses a member substituted AFTER assembly, and a member whose
record count disagrees with the observer's own `capture.spool` counts; it cannot refuse an assembler handed
another session's records whose counts happen to match. The binding becomes the session's own evidence when the
observer writes its members' digests into the account it seals, which is an observer change outside this
contract.

## Evidence references

An answer or a finding cites evidence by reference, and a reference names ONE member of a bundle. It resolves
within the bundle and nowhere else:

    account:<dotted path>                     a block or member of the account; a list element by its
                                              position, 0 first: account:scope.instances.instances[2].coverage
    connections:<pid>/<id>                    a connection record, by process.pid and id
    reconstructions:<pid>/<id>                a reconstruction record, by its connection
    reconstructions:<pid>/<id>/<index>/<half> one exchange's half, `request` or `response`, by the
                                              exchange's index
    observations:<index>                      an observation, by its position in the session's observation
                                              sequence, 0 first - the same index reassembly carries

`<pid>` is the pid in the observer's own pid namespace, as the records carry it; `<id>` and `<index>` are
decimal.

**A position indexes a list and never a block.** A block holds several members, often more than one list -
`scope` holds `targets`, `exclusions` and `limits` - so a position after a block name has no one list to mean. `scope.instances` is a block and `instances` is its list,
so an instance is `scope.instances.instances[<n>]`. **The doubled name is kept even where the list name is
unique within its block**: eliding it would make a reference valid only while no block gains a second list,
and when one did, a reference would resolve to the wrong list rather than fail. Naming the list keeps every
reference positionally explicit.

| Outcome | Means |
|---|---|
| `resolved` | exactly one member matches; `member` and `at` say where |
| `unresolved` | the reference is in the form and matches no member, or more than one; `matches` says how many |
| `not_a_reference` | not in the form: a path, a scheme, a member name the form does not have, or a malformed part |

**A reference that matches more than one record does not resolve**, and neither does anything reaching outside
the bundle: a reference carries no path, so there is nowhere outside for it to name.

## Closure

`CheckClosure` reads a tree - a copied bundle, or a contract directory - and refuses any reference that does
not resolve inside it. It reads nothing outside the tree and nothing over a network. The reference forms it
knows:

| Where | Form | Kind |
|---|---|---|
| `bundle.json` at the tree root | `members[].path`, `schemas[].path` | path, relative to the root |
| any `.json` or `.jsonl` file | the value of a member named `$ref`, with any `#fragment` removed | path, relative to the file's directory |
| any `.json` or `.jsonl` file | the value of a member named `$schema` or `$id`; `schemas[].id` in `bundle.json` | identifier |
| any `.md` file, outside code | a link target `[text](target)`, with any `#fragment` removed | path, relative to the file's directory |

A member name beginning `$` is never data in these contracts, which is why those are the generic forms: a
data member that happens to be called `path` - a cgroup's, say - is not a reference. A value that is only a
`#fragment` is not a reference.

A PATH is refused when it is absolute, carries a scheme (`https:`, `file:`, any `name:`), holds a backslash,
or leaves the root once its `..` elements are resolved - `reference_outside_bundle` - and when it names no file
in the tree - `reference_unresolved`. An IDENTIFIER is a name and not a location, so one carrying a scheme is
accepted; one written as a path - absolute, or relative and leaving the root - is refused the same way. A
symbolic link anywhere in the tree is `link_not_permitted`.

**A path that is a refused link, or lies under a linked directory, adds no finding of its own**: the link is
the cause, and the path's repair is the link's. Nothing is hidden by that, because a refused link blocks
inspection of everything beneath it, so no reference under it can carry a problem that could be detected
independently. **It is the corollary above - a reference failing for an independent reason is its own finding -
that protects any case where the cause does not block inspection, and not the cause's position above the
reference.** A refused link beside a member genuinely absent elsewhere is two findings.

The result says how many files it read and how many references it found, so a tree with none is told from a
check that read nothing. **This check does not execute carried schemas or fetch identifiers with a
scheme**; it refuses the reference forms described above that would reach outside by location.

## Writing an account and a bundle

`Project` writes an operational account in this contract. It refuses (`ErrUnrepresentable`) an operational
account at any version but 1, and a live or sealed one missing its capability, seen, loss, admitted or refused
block. What the operational account at version 1 does not hold is written `not_carried` and never filled: the
traffic-scope and retention controls, the traffic filters, the pipelines, processing and requirements. Where
it could not read a block it says why, and the block is `unavailable` with that reason.

The operational account does not hold the reconstruction either, and what `Project` writes for it is what its
CALLER states of the session's records - never what it infers from being handed none, because a caller that did
not seek them and one that could not read them both hand over nothing:

    not supplied        not_carried. How a session is sealed: reconstruction runs when a capture is read back
    could not be read   unavailable, with the caller's reason. A caller giving no reason is refused
    supplied            carried, the totals read off the records - zeros where the session had no traffic,
                        which is a reading and not an absence

A caller that states none of the three is refused.

`Bundle` writes a sealed account and its records as a bundle, naming each record member in the seal by digest
and count; `Assemble` is `Project` then `Bundle`. Both return files by bundle-relative path, so a bundle has no
location until somebody writes it somewhere.

`inventory_test.go` fills the operational account's TYPE - every field, both ways a reading can go - and
requires each fact to be listed with where the account carries it, and the projection to carry something there.
A field added to the operational account is unlisted until somebody says where it goes.

## Agreement across the contracts

`CheckAgreement` reads a conformance tree - `bundle/`, `configuration.json`, `runtime.json`, and
`acceptance/ACCEPTANCE.md`, `acceptance/ROWS.md` and `acceptance/QUESTIONS.md` - and checks that the contracts
line up across it. Every member is read from INSIDE the tree it is given, so the tree is self-contained: the
three acceptance documents in it are copies of those in `contract/acceptance/`. `runtime.json` is what the
runtime has, in the form the configuration contract reads it (`contract/config/CONFIG.md`), such as
`contract/config/examples/runtime.json`.

| Check | Refused with |
|---|---|
| the bundle validates | `bundle_not_validated` |
| the account references the configuration beside it as `configuration` at `sha256:` of its bytes | `configuration_not_referenced` |
| every contract version the account names is one in use, the account names the account and record versions its bundle is written at, and the configuration is at the configuration version | `version_disagrees` |
| the configuration check accepts `configuration.json` against `runtime.json` with no pack manifests: no structural finding and no composition finding. Each of its findings is carried with its own reason in the detail, and nothing below that reads what the check resolves is compared against a configuration it refused | `configuration_refused` |
| the account's `provenance.pipelines` is `carried` and holds exactly the effective pipelines the configuration check resolves, in their order. For each: `name`, `input`, `declared_by` and `sinks` are equal, and `slots` are equal in order, with `slot`, `implementation` and `selected_by` those of the resolved slot and `version` the version of the component declaration that implementation names among the runtime's builtins. A resolved pipeline the account does not list and a listed pipeline that was not resolved are each a finding | `pipelines_disagree` |
| the configuration's policy is decided against the policy inventory the configuration check RESOLVES from `runtime.json`, never against an inventory supplied beside it; every requirement the account lists has the disposition, reason, scope, pipelines and limitation decided for it, in the list that disposition belongs to, and no decided declaration is missing. An accepted requirement's `sink` is present exactly where the decided scope names a sink, with `kind`, `leaves_host` and `retains_plaintext` equal to it | `enforcement_claim_disagrees` |
| every connection an observation or a reconstruction names is a connection record in the bundle | `record_reference_unresolved` |
| every evidence reference the acceptance documents write resolves as described below | `acceptance_reference_unresolved` |

**What the acceptance-reference check reads.** Every code span in the three acceptance documents that begins
`account:`, `connections:`, `reconstructions:` or `observations:` is a reference. Each placeholder `<name>` in it
is replaced by `0`, and the result is given to `Resolve` over the conformance bundle.

- **An `account:` reference must be `resolved`.** The conformance account carries every block the
  specification names and at least one element of every list it indexes, so a reference that does not resolve
  is a spelling no account at this contract's version can satisfy. This is the check that refuses a
  block-indexed spelling such as `account:scope.instances[0]`.
- **A record reference must be in the form, and is not required to resolve here.** It names a record by the
  pid, id and exchange index a real run assigns, which a specification can write only as a template, so
  here it establishes the FORM - not `not_a_reference` - and nothing more. Whether such a reference resolves
  is decided where those ids exist: in the bundle of a run evaluated under the acceptance rows that cite
  it.
- **An acceptance document that cannot be read is a finding against it.**
- **The guard against reading nothing is over the three documents TOGETHER**: where they yield no reference
  between them it is a finding, never an agreement over nothing. One document that cites no reference, beside
  others that do, is not a finding. The result's `references` says how many each document yielded.

A resolved reference establishes that the path exists in an account written at this contract's version. It
says nothing about whether the value there answers the question that cites it.

| `outcome` | Means |
|---|---|
| `disagree` | a check found contracts that do not line up; `findings[]` say where |
| `agree` | every check ran and agreed |

**The agreement result has no way to report a check that did not run.** So a check that cannot run on its
input reports a finding against that input, and a check that skips silently must never be added: it would
leave the result `agree` over something nobody checked. A check that genuinely cannot run needs a third
outcome, which says the result is not agreement, and a list of what did not run - both added together, or
neither.

## What this contract does not carry

- The records themselves - the record contracts'.
- Why a declaration has its disposition beyond the policy vocabulary's own reason - `contract/policy`.
- The configuration's content: only references to it.
- Any argument of any process.
