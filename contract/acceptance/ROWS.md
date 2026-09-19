# standalone_inspection_v1: the rows

Specification version: `observer.acceptance/standalone_inspection_v1`, with `ACCEPTANCE.md` and `QUESTIONS.md`
in this directory. Terms, dispositions, the two kinds of unknown, evidence references, runs and normalization
are defined in `ACCEPTANCE.md` and mean exactly that here.

Every row has a DECISION RECORD in one shape:

    required inputs     what must exist for the row to be decided at all
    comparison          what is compared with what, by which rule
    threshold           the value that is MET
    missing evidence    the inputs whose absence leaves the elements that read them UNGRADED. It is
                        a RESULT, not a failure to grade, and it never overrides an element
                        established failing on the inputs that are present (`ACCEPTANCE.md`, the
                        precedence): the row is then UNMET, with its ungraded count beside it

A row reports every count its comparison takes, and each count names the set it is taken over.

## Shared rules

### Message equality

Two messages are equal when all of these are equal:

    start line     method, target and protocol of a request; protocol, status and reason of a response
    headers        an ORDERED list of (name, value), repetition preserved
    body           bytes
    framing        how the body's length was established
    completeness   whether every byte of the message is present

**The permitted normalizations, and there are no others**: header names folded to lower case, and line
endings read as CRLF. Headers are never reordered or de-duplicated, whitespace inside a value is never
trimmed, and a body is never normalized. **Both sides apply this same list.**

A request is associated with a response by their ORDER within one connection, never by content.

### The join

A witnessed connection and a captured connection record are the same connection when

    the socket's network namespace, as the realisation maps it + address family + local address + local port
                                                             + peer address + peer port

are equal, with local and peer taken from the approved instance's side, and their lifetimes overlap. The
capture's side is the record's `associations[].endpoints` with `endpoints.namespace`, and its lifetime is
`[first_seen, ending.at)`, with an undetermined `ending.at` open. **`opened` is never used here**: it is a
crossed reading and `first_seen` and `ending.at` are direct ones (`observer.record/1-draft`, Instant). The
lifetime comparison allows the declared value `T_join`, the realisation's measured bound on the difference
between its witnesses' clock readings and the observer's direct wall readings on the same host.

**The join is one to one.** Where two captured records satisfy it for one witnessed connection, or two
witnessed connections for one record, every connection involved is AMBIGUOUS; neither content nor the nearest
instant resolves it. Co-claimant records of one socket (`observer.record/1-draft`, One socket, more than one
claimant) join as ONE captured connection held by several instances, and each claimant's instance is graded
in R2.

### Evidence that a row read something

**Every row states how much it examined before it states a verdict**: the members, records and population
members it read, from the same expression the comparison consumed. A row whose required population is
non-empty and which examined none of it is MISSING_EVIDENCE when the realisation supplied nothing, and UNMET
when the product did.

### The remover test applied

`ACCEPTANCE.md`, Two kinds of unknown, states the test. **The limit is not on the correctness of the answer; it
is on what the answer establishes.** `unknown_throughout` is fully correct and establishes less than `unknown
from offset N` would, and marking it stops the count reading as more knowledge than was had. The product
already makes that distinction where it can: capture places a lost observation's streams `unknown_from` the
offset each had reached when it can order its observations, and `unknown_throughout` when it cannot, or when
the gap falls before a stream began and there is no offset in it to name. So "throughout" is what it says when
it could not locate a loss, not what it says when locating is impossible.

Every element in this version whose expected answer can be an unknown, and how the test classifies it. A
reader applying the test to an element not listed here has found an omission in this table.

| Where | Expected unknown | Remover | Classification |
|---|---|---|---|
| R2 (a), R2 (c), Q1 process, Q5 per instance | `instance.birth` or a placement's `birth` `undetermined`, and so every coverage joined without a determined birth | the kernel's thread-group birth carried on the event that admits the instance | STATED LIMIT |
| R2 (c), Q5 per instance | a placement's `namespace_pid` or `executable` `not_carried` | the producer supplying both for a placed process | STATED LIMIT |
| R2 (a), Q1 process, Q5 per instance | `instance.executable` `undetermined` | the executable read while the instance is known to be live, and carried with the instance | STATED LIMIT |
| Q2 bound | "not established" | a production instant reaching the event, carried as `observation.produced` | STATED LIMIT |
| R3 S13, a direction `unknown_throughout` | no offset in it established, where the loss was not located in production order or fell before the stream began | a recorded loss that carries the connection, direction and stream offset it was lost from | STATED LIMIT |
| R3 S13, a direction `unknown_from` | established below the offset, and not which stream the lost observation belonged to | the same recorded loss | STATED LIMIT |
| Q4 undecidable | WHERE the loss fell: whether this message's direction lost data | the same recorded loss | STATED LIMIT |
| Q4, any message capture lost bytes of | WHAT was in the lost bytes | none: bytes no observation delivered exist nowhere an observer could read them | COMPLETE |
| R3 S12 and Q4 evidential limit | whether the server sent more than the observed instance received | none on the observed host: bytes that never arrived were never there to read | COMPLETE |
| R3 whole-bundle rule, a count `undetermined` where the account could not read it | the count | the read succeeding | not expected in this version: the expected artifact holds every count as read, so an `undetermined` count is INCORRECT here |
| Q5, R2 (c) `coverage` `undetermined` | whether the instance was covered | a determined birth on the placement, which makes the join unique | not expected in this version: the realisation pins no pid reuse (`QUESTIONS.md`, Q5), so the answer is INCORRECT here |

**A rule containing any STATED LIMIT element that the expected artifact expects is `MET_WITH_STATED_LIMIT`
when every element is otherwise correct**, and its record names each limit by this table's row.

## R1. Capture and reconstruction fidelity

100% of the `graded` expected messages reproduced exactly once, with correct content and association, and no
invented message.

**Expected-value artifact: the expected message list.** One entry per message of every `graded` exchange:
the witnessed connection (endpoints, network namespace, open and close instants), the exchange's position in
that connection, the half (`request` or `response`), and the message's witnessed start line, headers, body,
framing and completeness. Entries of every other disposition are listed with their disposition and are not
in R1's population.

| | |
|---|---|
| required inputs | the graded bundle; the expected message list; `T_join`; the run's attach and stop mark pairs; the connection-completeness witness |
| comparison | join each expected connection to the bundle's connection records. For each joined connection and each half, take the expected messages in witnessed order, and the reconstructed messages of that half from every record joined to it in RECONSTRUCTED ORDER (Order and occurrence, below); apply Message equality, and match OCCURRENCES one to one by the three passes below. Count, over the `graded` expected messages: `matched_once`, consumed in pass 1; `misplaced`, consumed in pass 2; `content_differs`, not consumed while an unconsumed reconstructed message sits at its position; `missing`, not consumed with no reconstructed message at its position, or on a connection that did not join; `ambiguous`, on a connection the join left AMBIGUOUS. Over the joined connections, count `duplicated`: reconstructed messages left unconsumed after pass 2 that are equal to an expected message on that connection and half; and `invented`: every other reconstructed message left unconsumed after pass 2. Over the bundle, count `unaccounted`: connection records carrying at least one observation that join no witnessed connection, whose `first_seen` falls after the upper attach mark and before the lower stop mark |
| threshold | `matched_once` equals the number of `graded` expected messages, and `missing`, `content_differs`, `misplaced`, `duplicated`, `ambiguous`, `invented` and `unaccounted` are all zero |
| missing evidence | the expected message list, `T_join`, either mark pair, or the connection-completeness witness absent; a scripted slot unwitnessed or not exhibited (`ACCEPTANCE.md`, The denominator); a captured connection the completeness witness holds and no exchange witness recorded |

### Order and occurrence

**Reconstructed order is total.** A reconstructed message is placed by the session-sequence index of the first
observation holding its first byte (`observer.record/1-draft`, reassembly: `index`), and two messages beginning
in the same observation - which then belong to one record and one direction - by their `stream.offset`. No two
messages share both. The `seen` reading is never an ordering key: it is an observer wall read, and two
observations can share one.

**Occurrences are matched one to one, in three passes over one connection and half.** Each expected message and
each reconstructed message is consumed at most once.

    1  position     the k-th expected message and the k-th reconstructed message, in their orders, are
                    consumed together where they are equal and the reconstructed message sits in the
                    exchange the witness paired the expected one in
    2  elsewhere    each expected message left, in witnessed order, is consumed with the FIRST
                    reconstructed message left, in reconstructed order, that is equal to it
    3  leftovers    what is left is counted as the comparison cell says

So an expected `[A, A]` captured as `[A, A]` is two `matched_once` and nothing else, and captured as `[A, A, A]`
is two `matched_once` and one `duplicated`.

**Whether the captured corpus exhibits these cases.** Repeated identical messages on one connection and half
ARE live. In the reconstructions of the two graded runs the retained captures come from, 16 of the 244
connection halves carry more than one message, and every one of those 16 carries a byte-identical repeat: 32
repeated occurrences among 268 messages per run, on keep-alive connections carrying the same retrieval request
and the same response. Two messages beginning in one observation, and consecutive messages whose first
observations share a wall reading, are NOT exhibited: 0 among 268 messages in each of the three retained
capture sets. The occurrence rule is therefore exercised by that corpus. **The tie rule - two messages beginning
in one observation, ordered by `stream.offset` - has been exercised by no run in it.**

**`unaccounted` is not reduced by any disposition**, and a missing exchange witness is not a reason to set a
capture aside. What separates the observer holding traffic nothing accounts for from a realisation that did
not witness everything is the realisation's CONNECTION-COMPLETENESS WITNESS: a record of every connection the
observed host scope made during the run, taken independently of the exchange witnesses. A captured connection
it holds that no exchange witness recorded leaves that connection ungraded; one it does not hold is
`unaccounted`, an established failure.
It is a required input of R1.

## R2. Identity and placement

100% correct instance and connection association; overlap and partial placement reported; no plaintext from an
unapproved instance.

**Expected-value artifact: the identity and selection matrix.** Its POPULATION is every process instance the
realisation started, or that existed, inside the observed host scope between the lower attach mark and the
upper stop mark - approved roots, descendants of both kinds, S5, S7, S8, and every other process the
realisation's process record holds - and not only the instances that carried traffic. For each instance:

    identity        its pid namespace, its pid in that namespace, its start identity where the realisation
                    read it, and its executable
    selected by     the selection situations that match it: none, one, or two (S6)
    excluded        whether an exclusion removes it (S7)
    approved        selected and not excluded
    placement       for S8: which entry points are expected confirmed and which not
    allocator       `target` for an instance a selection named, `descent` for a child admitted after
                    selection (`observer.record/1-draft`, Instance key and allocator)
    connections     the witnessed connections it held, including every co-claimant window

| | |
|---|---|
| required inputs | the graded bundle; the identity and selection matrix; the join inputs of R1 |
| comparison | **(a) Connection association**: for every `graded` and `expected_incomplete` expected connection joined in R1, the connection record's `instance.key` pid namespace and pid equal the expected holder's, and `instance.executable`, where determined, equals it; for a co-claimed socket, the set of claimant records' instances equals the expected set. A `birth` that is determined must equal the realisation's where the realisation read one. **(b) Selection**: `account:scope.instances.instances` holds one entry for every approved root, existing descendant, S6's and S7's instance, each with `selected_by` equal to the expected targets; `multiply_selected` is true exactly for S6's instance, and `account:scope.overlap.instances` holds exactly that instance with both targets; S7's entry has a non-empty `excluded_by` and `coverage` `excluded`; `allocator` on every connection record equals the expected. **(c) Placement**: S8's `scope.instances` entry has `coverage` `partially_covered`, and the `account:scope.placement.processes` entry its `evidence[]` cites has `partial` true, `confirmed` below `requested`, and each probe's `confirmed` equal to the expected; every other approved instance `scope.instances` names has `coverage` `covered`, and no other placed process is `partial`. A placement is matched to an instance by `pid`, `birth`, `pid_namespace`, `namespace_pid` and `executable`, **which is not unique under pid reuse while `birth` is undetermined** (`contract/account/ACCOUNT.md`, Placement identity): an entry the account marks `undetermined` for that reason is UNGRADED where the realisation's process record shows the pid reused, and established failing where it shows no reuse. **(d) Unapproved**: no connection record's instance, and no observation's process, is S5's or S7's, and no connection record joins a connection S5 or S7 held |
| threshold | (a) all correct over the stated set; (b), (c) and (d) exact, with zero differences. `MET_WITH_STATED_LIMIT` where any record's `instance.birth` or `instance.executable` is `undetermined`, or any placement's `birth` is `undetermined` or its `namespace_pid` or `executable` `not_carried` (The remover test applied), with the count of each |
| missing evidence | the matrix absent, or an instance in it without a pid namespace and pid; the realisation's process record not covering the window. **Where two matrix instances share a pid namespace and pid inside the window and the realisation read no start identity to separate them, every item naming either is UNGRADED**: the scenario did not pin what it needed to |

**"Correct" is read from the product's own records, and a join that succeeds is not evidence that the instance
is right.** (a) is decided on the instance each record carries, after the join, and never inferred from the
join.

## R3. Failure and loss accounting

Every scripted fault accounted for; a deliberate gap never becomes a supposedly complete message; uncertainty
preserved.

**Expected-value artifact: the fault ledger.** One entry per induced fault, each naming the witnessed exchange
it applies to, the EVIDENCE the bundle must carry for it, and the expected DISPOSITION, including every place
where `unknown` or `undecidable` is the correct bounded answer. **A run-wide count does not locate a fault**,
and no entry is satisfied by one.

| Fault | Expected evidence in the bundle | Expected disposition |
|---|---|---|
| S9 delay | the exchange's request and response each present, `complete` true | an application property, not an observation failure: no loss on either direction of its connection |
| S10 500 | the response present, `status` 500, `complete` true, `defect` `none` | an application failure: no loss on either direction |
| S11 invalid JSON | the response present, `complete` true, `framed` true, `defect` `none`, `structure` `derived` with a top-level shape of kind `invalid` | an application failure, distinguished from S12 and S14 |
| S12 reset | the response present with `framed` true, `complete` false and `defect` `stream_ended`; the received direction's placement `established`; no `hole` in it; the connection's `ending.how` `socket_closed` or `handle_released` | interrupted by the connection ending: an application-side failure observed whole. **Not a capture loss**, and not evidence the server sent nothing further |
| S13 gap | at least one of `account:capture.loss.dropped`, `account:capture.loss.unmatched`, `account:capture.ordering.lost`, `account:capture.ordering.retired` above zero; for EVERY expected message of an `expected_affected` connection that the witness shows crossing the window, either the message is absent, or it is present with `complete` false, or its direction's placement is `unknown_from` at or before its offset or `unknown_throughout` | an observation failure. **Two facts are graded separately, and neither is inferred from the other.** LOCATION IN PRODUCTION ORDER: where the realisation declares the loss located in the session's production order, an `expected_affected` direction is `unknown_from` at an offset no later than the start of its first expected message crossing the window, or `unknown_throughout` where the gap falls before the direction's stream began; where it declares the loss not located, `unknown_throughout`. STREAM ATTRIBUTION: no placement state attributes a lost observation to a stream (`observer.record/1-draft`, placement), so neither `unknown_from` nor `unknown_throughout` is read as a claim about which stream lost data, and a direction is never required to be `unknown_throughout` because the loss is not attributed to a stream. An `established` placement on any `expected_affected` direction is UNMET. `unknown_from` and `unknown_throughout` are each a STATED LIMIT (The remover test applied) |
| S14 limit | the response present with `complete` true and `framed` true, and its structure `refused`, or `body.elided` above zero, or `defect` `limit` | an observer bound, not an application failure and not a capture loss |

| | |
|---|---|
| required inputs | the graded bundle; the fault ledger; the join inputs of R1; S13's window marks and its declared locatability |
| comparison | per ledger entry, every listed field of the joined connection's records and the account, read from the bundle. And over the whole bundle: **no message is `complete` true whose witnessed counterpart crossed S13's window with bytes the capture did not receive**, and **no field the record contracts give a `state` holds a value where the realisation's evidence cannot have supplied one** - in particular a loss count reads `undetermined` rather than zero wherever the account says it could not be read |
| threshold | every entry's evidence and disposition exact; zero violations of the two whole-bundle rules; and in a run with no S13 window, every loss and ordering count listed in the S13 row is zero. `MET_WITH_STATED_LIMIT` wherever an S13 direction is `unknown_from` or `unknown_throughout`, with each limit named |
| missing evidence | the ledger absent; an entry's exchange unwitnessed or not exhibited; S13's window marks or declared locatability absent |

## R4. Diagnostic usefulness

Five of five predefined operator questions answered from vanilla output alone, with supporting references.

| | |
|---|---|
| required inputs | the graded bundle; the product's documentation as released; the answer record for each question (`QUESTIONS.md`, The answer record); the expected answers (`QUESTIONS.md`); every expected-value artifact they cite; a REFERENCE RESOLVER executing the form `contract/account/ACCOUNT.md` defines in its section Evidence references |
| comparison | the scoring sheet in `QUESTIONS.md`, per question and per element |
| threshold | every element of every question correct. `MET` at five answered; `MET_WITH_STATED_LIMIT` at five correct with at least one answered with a stated limit, each limit named; `UNMET` at any question not answered, whatever else is missing; `MISSING_EVIDENCE` only where no question is not answered and one is missing evidence. Reported always as the four counts `QUESTIONS.md` gives, never as a bare five of five |
| missing evidence | an answer record absent; an expected answer absent; an artifact a question cites absent; no executable reference resolver. **A resolver that decides nothing is not a resolver**, and references it did not resolve are never passed |

**Writing analysis code is UNMET, not MISSING_EVIDENCE.** An answer record that holds anything but commands
the released documentation describes, with their arguments, fails the question: a pile of raw records is not
diagnostic functionality. A table printed by a documented command is enough.

## R5. Artifact portability

The bundle validates and inspects on a second machine.

| | |
|---|---|
| required inputs | a FAITHFUL COPY of the graded bundle in the second environment, which the realisation makes and the product does not, shown by two TREE RECORDS that are equal - one of the bundle as written on the source host and one of the copy - each holding every path relative to the bundle root, its file type (regular file, directory, symbolic link with its target, or other) and each regular file's sha256, equal meaning the same set of paths, the same type and link target for each, the same digest for each regular file, and nothing else present; a reference resolver as R4 names it, run in the second environment; a SECOND-ENVIRONMENT DECLARATION: a different host, the path the bundle was copied to, which differs from the source path, and the evidence that the source host, its `/proc`, its kernel type information, its session and any network service are unreachable from it; the validation outcome and the five answer records taken there; the same taken on the source host |
| comparison | the bundle's closure check reads the copied tree and finds every reference resolving inside it; validation's `outcome` is `validated`, and its `examined` counts equal the bundle's members and records; the normalized answers to the five questions equal the source host's, and every evidence reference in them resolves in the copy |
| threshold | all of the above exact. Each comparison is its own element: an absent input leaves the comparisons that read it ungraded and establishes nothing about the others |
| missing evidence | either tree record absent, or the two tree records differ: the copy is then not shown to be the bundle, and EVERY comparison taken on the copy is ungraded; the second-environment declaration absent or not showing the source unreachable; either set of answer records absent; a validator executing `observer.bundle/1-draft` not available to the realisation; no executable reference resolver, in which case no reference in either set of answer records is counted as resolving |

**The copy is the realisation's, and nothing in this row has the product make it**: portability is the product's
bundle validating and answering away from its host, not the product copying it. So a faithful copy is an input,
never a comparison, and a copy that differs from the bundle is missing evidence rather than a product failure.
Equal file digests do not show a faithful copy, because a refusal can turn on the tree as well as the bytes: a
symbolic link is refused as `link_not_permitted`, and `member_missing` and a member the contract does not name
turn on which files exist, so a copy that turns a file into a link or adds a stray file can match every file's
digest and still be refused. **A validation refusal is an established failure, whatever it names, wherever the
tree records are equal**: the refusal is then of the product's own bundle, and it stays UNMET when the
second-environment declaration is absent, because that absence ungrades only the comparisons needing the
declaration and does not reach the refusal.

## R6. Installation independence

The released archive completes the documented workflow in a declared clean environment, with no source
checkout, compiler or pack.

| | |
|---|---|
| required inputs | the release archive and its digest; the CLEAN-ENVIRONMENT DECLARATION: an operating system image by digest, a kernel version and its type-information availability, the complete list of installed packages, and the result of a search for any source checkout of the product, any Go toolchain, any C compiler and any pack, all taken before installation; the command record of the installation and of the documented workflow, in order, with each command's exit status |
| comparison | the installed bytes are the archive's, by digest; every command in the record is one the released documentation gives; every command exits as the documentation says it does; the workflow ends in a sealed bundle; and the run's R1 to R4 were graded on THAT installation |
| threshold | all of the above, with the search showing none of the four present. The search finding one of them present, or the environment not meeting the documented kernel floor, is the realisation's environment and not the product: every comparison taken in that environment is UNGRADED, so no command failing there is an established failure. That includes the installed-bytes digest: in an environment already holding a checkout, a toolchain, a pack or an earlier build, something other than the documented installation may have written the installed paths, so neither a match nor a mismatch there is established about the release; below the documented kernel floor the release promises nothing, so nothing taken there is established either |
| missing evidence | either declaration or the command record absent; the environment not meeting the kernel floor the product documents, which is the realisation's error and not the product's |

## R7. Non-interference

Starting, stopping and forcing the failure of the observer add no transaction failure in a
controlled comparison.

**The forced failure this version grades is OBSERVER TERMINATION**: the observer's process ends without being
asked, by a signal it cannot handle. Processor failure and sink failure are different boundaries and are not
graded by this version.

**Three interventions, each in its own runs:**

    N1 start       the observer is started while transaction T is in flight
    N2 stop        the observer is stopped in its documented way while T is in flight
    N3 terminate   the observer's process is terminated while T is in flight

**Each intervention is placed by a BARRIER, never by a sleep.** T's server holds T's response until the
realisation releases it. The realisation (1) witnesses that the server has received T's whole request and
has not begun its response, (2) triggers the intervention, (3) witnesses the intervention complete - for N1
the observer reporting itself attached, for N2 the observer process ended and its account sealed, for N3 the
process gone - and only then (4) releases T. The four are recorded with their instants, in that order.

**Step (3) has a COMPLETION BOUND**, a declared value in the intervention plan: the longest the realisation
waits for the completion witness after triggering. Two different things happen past it, and they are kept apart:

    the product demonstrably  the realisation recorded (1) and (2), and records at the bound the evidence
      did not complete        that the completion did not occur - for N1 no attached report from the
                              product, for N2 the process still running or ended with no sealed account,
                              for N3 the process still present. That intervention element is an
                              ESTABLISHED FAILURE and the row is UNMET, whatever else is ungraded
    the realisation did not   (1) or (2) is absent, or nothing was recorded at the bound saying whether the
      record it               completion occurred. The intervention element is UNGRADED

**In both cases T's transaction comparisons for that run are UNGRADED**: T was held at a barrier that the
intervention never let the realisation release in order, so its outcome and its deadline measure the barrier
rather than the observer. The realisation still releases T at the bound so the run can end, and records that it
did.

**The expected capture gap is declared before execution**, so testing a stop does not contradict a promise to
capture while stopped:

    N1   T's connection opened before the observer attached: every T message is `coverage_limit`, and T's
         capture, if any, is not graded by R1
    N2   nothing after the lower stop mark is promised; the account is sealed; a T message recorded
         `complete` true is UNMET unless its witnessed bytes all precede the lower stop mark
    N3   nothing after termination is promised and no sealed account is promised; whether one is
         written is recorded, not graded

**Expected-value artifact: the intervention plan.** For each intervention: T's identity; every other scripted
transaction in the run; the planned application faults, if any, listed so they are never counted as
observer-induced; and the DEADLINE, a declared value no larger than the client's own configured timeout for
T.

| | |
|---|---|
| required inputs | the intervention plan; for each intervention, its runs with the four barrier records; for each, a CONTROL run with no observer, driving the same script with the same barrier released at the same script position; client-side and server-side witness records of every transaction in both |
| comparison | per intervention run: the intervention's completion witnessed within its completion bound; and against its control: T's terminal outcome at the client (status line, headers, body, completeness, or the connection's failure) equals the control's; T's completion, from release to the client's witnessed terminal instant, is within the deadline; every other scripted transaction's terminal outcome equals the control's; the server-side count of requests received per transaction equals the control's, so nothing was duplicated; every response the server-side witness shows emitted is witnessed received by the client, so nothing was lost; planned faults are compared to the control's planned faults and never counted as added failures |
| threshold | zero differences and every deadline met, in each of THREE runs per intervention, each decided on its own evidence. A barrier record missing or out of order leaves THAT run's comparisons ungraded, and an established difference in any other run is still UNMET |
| missing evidence | the plan or a control run absent; a barrier record missing, out of order, or showing T released before the intervention completed; a deadline or completion bound undeclared; a completion not witnessed within the bound WITHOUT the realisation's record of what it observed at the bound |

## Conformance records: one per contract the rows read

These read the contracts through whatever executes them at the pinned versions. **A MET here says only what the
executing check checks, and each row names that**; accuracy is R1 to R3's. Where a published schema and the
check that enforces it later check more, these rows are revised with them, and they promise nothing now.

| Contract | required inputs | comparison | threshold | missing evidence |
|---|---|---|---|---|
| `observer.bundle/1-draft` and `observer.account/1-draft` | the graded bundle; a validator executing both | validation outcome, findings and `examined` | `outcome` `validated`, no findings, `examined` equal to the bundle's members, records and account blocks | no validator executing both is available. **A stub that decides nothing is not a validator**, and its outcome is not read |
| `observer.record/1-draft` | the same validator, at its records stage | CHECKED: every line of a record member decodes as one record; its `record` is the kind its member's role holds; its `version` is `observer.record/1-draft`; it decodes into that record's type with no member the type does not name; the reassembly member holds exactly one record; each member's record count and digest are the seal's. **NOT CHECKED: record semantics** - that a required member is present, that a value is in its named vocabulary (a `direction` other than `sent` or `received` is not refused), and the relations between members (an `undetermined` instant still carrying a `value` is not refused) | no finding. This row's MET does not establish that the records are well formed in the sense `record.md` defines | as above |
| `observer.config/draft` | the run's configuration document; a check executing the contract | the check's result | accepted, with every scope the situations need expressed | the configuration or an executing check absent |
| `observer.policy/draft` | the policy documents the configuration carries, possibly none; the procedure's result | each declaration's disposition and reason; `account:requirements` | every disposition the realisation declared, and the account's three lists holding exactly those | an executing procedure absent where the configuration carries a policy document |
