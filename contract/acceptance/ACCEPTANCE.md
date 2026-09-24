# standalone_inspection_v1

Specification version: `observer.acceptance/standalone_inspection_v1`.

**Frozen at the first graded run.** Until a run has been graded against it, a change is made in place; after
one has, any change to a situation, an expected disposition, a comparison, a threshold, a question, the
scoring sheet or the normalization is a new specification version, and runs graded against different versions
are never compared. A realisation names the version it realises; this document names no realisation.

This specification is read with `ROWS.md` (the seven rows, their decision records and the conformance
records) and `QUESTIONS.md` (the five operator questions and their scoring sheet), in this directory. It is
written against these contract versions, and a row that reads a member of one of them is re-checked when that
contract's version changes:

    observer.record/1-draft      the observation, connection, reconstruction and reassembly records
    observer.account/1-draft     the account
    observer.bundle/1-draft      the bundle
    observer.policy/draft        the policy-declaration vocabulary
    observer.config/draft        operator configuration

## What is graded

Using only the released archive, its documentation, its configuration and its own local output, an operator
inspects the supported interactions of approved processes and DISTINGUISHES OBSERVED APPLICATION FAILURES
FROM OBSERVATION FAILURES.

**The promise graded is narrow**: the observer explains what it observed on the supported interfaces, shows
the associated process, connection and failure evidence, and states where its own observation was incomplete.
Business semantics, root-cause diagnosis, throughput and privacy adequacy are not graded.

**Extension portability is a separate acceptance test and does not substitute for any row here.** This
version grades the observer with no pack and no extension.

## Terms

    realisation        whatever produces the situations below, witnesses them, and grades a run. It is
                       not the product and nothing it does may be credited to the product
    witness            a record of traffic or process state made OUTSIDE the observer, by the
                       realisation. The observer's own output is never a witness
    expected-value     a file the realisation writes from the situation list, its declared values and its
      artifact         witness records, BEFORE the run's bundle is opened. Never from observer output
    declared value     a number the realisation fixes before execution and hashes with itself: a
                       tolerance, a hold, a deadline. Every one this specification uses is named where it
                       is used, and a realisation that does not declare one cannot grade the rule
    run                one execution of the scenario, producing one sealed bundle and one set of
                       witness records
    graded bundle      the bundle the product wrote for that run, exactly as written

## Two kinds of unknown, kept apart

They read alike in a report and mean opposite things about the product.

| Where | Value | Means |
|---|---|---|
| a PRODUCT answer | `unknown`, `undetermined`, `undecidable` | the observer says it cannot establish something. **Correct only where the expected-value artifact expects that answer**, and wrong wherever the expected artifact holds a determined value |
| a GRADER outcome | `MISSING_EVIDENCE` | the realisation did not supply an input the rule needs. **A result about the realisation, never about the product**, and never counted as either MET or UNMET |

Every rule in `ROWS.md` and `QUESTIONS.md` is decided over its ELEMENTS - each comparison, count, entry or
answer part it reads - and each element is ESTABLISHED CORRECT, ESTABLISHED FAILING, or UNGRADED because an
input it needs is absent. The rule's outcome is then taken by ONE PRECEDENCE, a total order applied the same
way at every level - element, question, row and run:

    1  UNMET              at least one element is established failing, WHETHER OR NOT every input
                          was present
    2  MISSING_EVIDENCE   no element is established failing, and at least one is ungraded; the
                          record names which inputs were absent
    3  MET                every element is established correct

**Missing evidence cannot un-establish an established failure.** If it could, any failing rule could be made
non-failing by making one of its elements ungradeable. And the protection runs the other way unchanged: with
nothing established as failing, a rule is never UNMET, however much is absent.

**Stated limits travel ALONGSIDE the outcome and are never a rank of their own.** A rule that is MET with at
least one stated limit is written `MET_WITH_STATED_LIMIT`, so a bare MET never hides one; an UNMET or
MISSING_EVIDENCE rule lists its stated limits beside its outcome in the same way. The record names each limit.

**MISSING_EVIDENCE is a THIRD STATE, never a failure and never a pass.** It is the difference between NOT
GRADEABLE and FAILED. Whatever reports a rule, a row, a question or a run carries MET (with
MET_WITH_STATED_LIMIT), UNMET and MISSING_EVIDENCE as distinct states, and MISSING_EVIDENCE is never folded into
UNMET, into a failure, or into a pass. **Every count of rows or questions is reported per state**, in one line:
for example `5 met, 1 met with a stated limit, 0 unmet, 1 missing evidence, of 7`. **An UNMET rule prints its
count of ungraded elements beside the verdict**, so repairing its failure can never move it straight to MET
while an element is still ungraded.

**THE REMOVER TEST decides whether a correct `unknown` is a stated limit.** Every element whose expected
answer is `unknown`, `undetermined`, `not_carried`, `undecidable`, `not established` or a stream placement
that is not `established` is put one question: **does a remover exist** - a change to what the product
records, carries or reads, after which the same situation would have a determined answer?

    a remover exists       a STATED LIMIT. The element is correct, the rule reporting it is
                           MET_WITH_STATED_LIMIT and never MET, and the remover is named beside
                           the element where it is expected
    nothing would remove   a COMPLETE answer. The evidence never existed where any observer
      it                   could read it, so no product could answer. No limit, no annotation,
                           and the count is whole

**The limit is not on the CORRECTNESS of the answer. It is on WHAT THE ANSWER ESTABLISHES.** A stated limit is
fully correct and establishes less than the answer its remover would allow; marking it stops a count reading as
more knowledge than was had. **No report of this suite states a count of answered or met items without the
count of those answered with a stated limit beside it, in the same line**, so a limit can never be read out of
a bare "5 of 5". `ROWS.md`, The remover test applied, lists every such element in this version and its
classification.

**Product output is never a required input whose absence is MISSING_EVIDENCE.** A bundle the product did not
write, a record it did not emit, a block it left out or a command that failed is UNMET. A witness record, a
mark, a declared value, an expected-value artifact, a declared environment or an executable validator the
realisation did not supply is MISSING_EVIDENCE.

## The situations

**Each is an observable situation, never a configuration spelling.** How a selection rule is written is the
configuration contract's; what is graded is that two rules selected one instance, not how the file said so.

"Approved" means selected by the run's observation scope and not excluded. Every situation below except S5
and S7 is in approved instances. Each situation carries exchanges of both kinds wherever it carries more than
one: requests shaped like business operations and requests that are not. **Nothing is graded on telling them
apart.**

| Id | Situation |
|---|---|
| S1 | INBOUND HTTP/1.1 over TLS: a client outside the approved instances sends requests to an approved root, which answers normally |
| S2 | OUTBOUND HTTP/1.1 over TLS: an approved root sends requests to a peer, which answers normally |
| S3 | a FUTURE DESCENDANT: an approved root creates a child after selection, and the child carries S1 or S2 exchanges |
| S4 | an EXISTING DESCENDANT: a child of an approved root that existed when selection resolved, carrying S1 or S2 exchanges |
| S5 | an UNAPPROVED process on the same host, using the same TLS library, sending requests of the same methods and body shapes to the same peers as S2 |
| S6 | OVERLAPPING SELECTION: two selection rules both select one instance, which carries exchanges |
| S7 | an EXCLUDED instance: a selection rule matches it and an exclusion removes it; it carries exchanges |
| S8 | PARTIAL PLACEMENT: an instance for which the probe on its RECEIVE entry point is not placed while its SEND entry point is, carrying outbound exchanges |
| S9 | a DELAYED RESPONSE: an outbound exchange whose server holds its whole response for a scripted duration before sending it |
| S10 | a 500: an outbound exchange answered with status 500 and a complete response |
| S11 | COMPLETE FRAMING, INVALID JSON: an outbound exchange whose response declares `application/json`, carries a Content-Length equal to the body bytes sent, and whose body stops mid-object |
| S12 | RESET DURING A RESPONSE: an outbound exchange whose server sends a head promising N body bytes, sends fewer, and resets the connection |
| S13 | AN INDUCED CAPTURE GAP: for a declared window the observer is prevented from reading its capture while scripted outbound exchanges continue, so that capture loses data. The means is external to the observer and uses only the release; it is declared by the realisation with the loss it produces and whether that loss can be located to a stream |
| S14 | A PARSER LIMIT: an outbound exchange answered with a complete, VALID JSON response whose body exceeds the reconstruction's documented structure limit |

**Two constraints on how the situations share a run**, because a situation that damages another's evidence
makes that other row undecidable:

- **S13 is isolated in time.** No connection carrying an S1 to S12 or S14 exchange is open between the lower
  mark of S13's window and its upper mark. A connection open in that window is S13's.
- **S5, S7 and S8 are not the only traffic their peers receive**, so that a capture of theirs cannot be
  recognised by its peer alone.

**Unpinned background traffic** - anything the realisation cannot pin to a script position - is permitted,
is witnessed, and carries the disposition `background`. It is outside every expected population here and is
never evidence for a MET.

## The denominator is frozen before capture

The expected-value artifacts are written from the situation list, the declared values and the witness
records. **The observer's output decides no disposition, no population member and no expected answer.** A run
in which the observer reclassifies eligible traffic - calls a witnessed S1 or S2 exchange unsupported, partial
or out of scope - is graded against the frozen disposition and fails where it differs.

Every witnessed exchange receives exactly one disposition, by these rules in this order:

| Disposition | Assigned when |
|---|---|
| `background` | the realisation declares it unpinned |
| `attach_band` | its connection opened between the lower and upper attach marks: neither graded nor charged |
| `stop_band` | its connection closed between the lower and upper stop marks: neither graded nor charged |
| `coverage_limit` | its connection opened before the lower attach mark, or had not closed by the upper stop mark |
| `expected_absent` | it belongs to S5, S7, or the unplaced direction of S8 |
| `expected_affected` | its connection is open inside S13's window |
| `expected_incomplete` | it is S12's response |
| `graded` | everything else |

**The marks are the realisation's, taken in pairs.** Each run edge has a LOWER mark, an instant before which
the edge had certainly not happened, and an UPPER mark, an instant by which it certainly had: for attach, the
instant the realisation began starting the observer and the instant it observed the observer attached; for
stop, the instant it began stopping the observer and the instant it observed it stopped. A connection is
placed against the pair by the WITNESS's open and close instants, never by anything the observer recorded,
so a capture's own silence never classifies it. **A scripted exchange whose connection the witness did not
date cannot be placed**, and every rule reading it is MISSING_EVIDENCE rather than the exchange leaving the
population. Every count of `attach_band`, `stop_band` and `coverage_limit` is reported beside every figure
those exchanges are excluded from.

**The scripted population is compared against its script.** Every exchange slot the scenario script names
must be witnessed. A slot with no witness record makes every rule reading that slot MISSING_EVIDENCE; it is
never dropped from the population. **So does a scripted slot whose disposition comes out `attach_band`,
`stop_band` or `coverage_limit`**: the situation was not exhibited while the observer was certainly attached,
which says nothing about the product.

## Evidence references

An answer and a finding cite evidence by reference, in the form `contract/account/ACCOUNT.md` defines
in its section Evidence references, and in no other form. **A reference counts as evidence only where that
form's outcome is `resolved`**: `unresolved` and `not_a_reference` are a reference that does not resolve.

## Runs

**A run is CLEAN when every row applicable to it is MET or MET_WITH_STATED_LIMIT on that run's own raw
evidence**, before anything is normalized. By the same precedence: a run with any row UNMET is FAILED, whatever
else is missing; a run with no row UNMET and any row MISSING_EVIDENCE is NOT GRADEABLE, not clean and not
failed. The run report states which of the three the run is, beside its per-state row count.

**Stated limits are reported GROUPED BY REMOVER, not only counted.** A clean run's report and the suite's
result list each remover once, with the rows and elements whose limit it would remove - for example `2 rows
carry a stated limit, from 2 removers: the birth reaching the event (R2; R4 at Q1 and Q5); the producer
supplying namespace_pid and executable (R2)`. A qualifier that sits on the same rows every run trains a reader
to skip it; grouped by remover it says how many things would have to change to clear how many rows.

**The suite passes on THREE CONSECUTIVE CLEAN RUNS whose normalized outcome reports are identical.** It is a
regression gate. It is not a statistical claim about production reliability, and a pass is not evidence of
one.

- **Consecutive means every run executed.** Each run the realisation starts is recorded, with its outcome,
  whatever that outcome is. A run that is not clean ends the sequence; the next clean run starts a new one.
  No run is discarded, repeated in place, or left unrecorded.
- **Identical normalized reports that are not clean are not clean runs.** Three identical failures are three
  failures.
- **A non-clean run is diagnosed before the sequence restarts**, and the diagnosis is recorded beside it: which
  rule, on which evidence, and whether the cause is the product, the realisation or undetermined.

The non-interference row is graded on its own intervention runs (`ROWS.md`, R7), which are not among the three
and have their own count.

## Normalization

Frozen with this specification. It is applied only to compare outcome reports ACROSS runs, after each run has
been graded on its own raw evidence.

**Permitted: consistent renaming that preserves every relationship.** Within one run each of these is
replaced by a name assigned in order of first appearance in the outcome report, one value to one name, the
same value always receiving the same name:

    pid, pid in its own namespace, namespace device and inode, start identity (birth), session id,
    connection id, handle address, handle and binding generation, socket inode, descriptor number,
    ephemeral port, observation index, record file digest

An instant is replaced by its offset from the run's lower attach mark. A measured interval is kept as its
value and compared across runs by its CLASS against the threshold its rule states (within, below, above),
with the value itself carried unchanged beside the class.

**Not permitted, and a report normalized this way is not comparable:** deleting or merging an association, a
state, a reason, an uncertainty, a loss count, a fault entry, an interval, an evidence reference or a
disposition; renaming two distinct values to one name or one value to two; collapsing `undetermined` into a
value; reordering what a record orders.

**What the normalized report holds**: every rule's outcome as one of the four states, with its counts and its
stated limits by remover, every expected-population member's disposition and verdict, every question's
per-element verdict, and every finding. Counts over `background` traffic are reported per run and excluded
from the identity comparison, because their size is not pinned.

## What this version does not grade

- Unsupported protocols and transports. A later version that adds them adds their own situations and expected
  dispositions.
- Processor failure and sink failure as forced failures (`ROWS.md`, R7 says which forced failure is graded).
- The correctness of anything an extension claims.
