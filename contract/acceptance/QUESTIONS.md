# standalone_inspection_v1: the five questions and the scoring sheet

Specification version: `observer.acceptance/standalone_inspection_v1`, with `ACCEPTANCE.md` and `ROWS.md` in
this directory. Situations S1 to S14, dispositions, evidence references and the two kinds of unknown are
defined in `ACCEPTANCE.md`.

The questions are FIXED. A question is scored by ELEMENTS, each checked against an expected answer the
realisation writes from its expected-value artifacts before the bundle is opened. **Printing something is not
answering**: an element is correct only when its returned identifier, value or class equals the expected
one.

## The answer record

For each question the grader keeps:

    commands     every command run, verbatim, in order, each one given by the released documentation
    output       each command's printed output, whole
    answer       one value per element below, each with the evidence references it rests on

**Every element's value is read from the printed output of a documented command.** An element the operator
obtained by writing or running any program of their own, by arithmetic over printed values, or by reading the
bundle's files directly, is INCORRECT. Reading across two printed tables by an identifier both print is
reading.

**Every evidence reference must resolve** (`ACCEPTANCE.md`, Evidence references). An element whose references
do not resolve is incorrect whatever its value.

**A question has one of four outcomes**, taken by the precedence in `ACCEPTANCE.md`, Two kinds of unknown:

    NOT_ANSWERED                    any element established incorrect, whether or not every input was
                                    present; its ungraded elements are counted beside it
    MISSING_EVIDENCE                no element established incorrect, and at least one ungraded because
                                    an input it needs is absent (`ROWS.md`, R4)
    ANSWERED                        every element established correct, none of them by a stated limit
    ANSWERED_WITH_STATED_LIMIT      every element established correct, and at least one correct only
                                    because the product stated a limit the expected answer expects; the
                                    limit is named

**R4 is reported as four counts in one line, never as one**: answered, answered with a stated limit, not
answered, missing evidence, of five - for example `4 answered, 1 answered with a stated limit (Q2 bound), 0 not
answered, 0 missing evidence, of 5`. R4 is `UNMET` at any question not answered, whatever the other counts
are; `MISSING_EVIDENCE` only where no question is not answered and at least one is missing evidence; `MET` at
five answered; `MET_WITH_STATED_LIMIT` at five established correct with at least one answered with a stated
limit. An UNMET R4 still prints its missing-evidence count in that line.

## Q1. Which process and connection received the 500, and for which request?

| Element | Correct when |
|---|---|
| connection | the answer names exactly one connection record, by reference, and it is the record the R1 join assigns to S10's connection |
| process | the answer names the instance holding that connection - pid namespace, pid in it, and executable where the record determines it - and it equals S10's holder in the identity and selection matrix. An `undetermined` executable, stated as such, is a STATED LIMIT (`ROWS.md`, The remover test applied) and makes the question `ANSWERED_WITH_STATED_LIMIT` |
| request | the answer names, by reference, the request half of the same exchange as the 500, and that request is equal (`ROWS.md`, Message equality) to S10's expected request |
| response | the answer names the 500 response by reference, and its status is 500 |
| no other | no other response is named as a 500 unless the expected answer lists it |

## Q2. Which exchange had the scripted delay, and what interval did the observer actually measure?

The interval asked for is the one the observer measured on the approved instance's side: from the last request
byte the instance sent to the first response byte it received.

| Element | Correct when |
|---|---|
| exchange | the answer names exactly one exchange by reference, and it is S9's |
| interval | the answer gives a value, and BOTH hold: (a) the value EQUALS the `seen` value of the cited response observation minus the `seen` value of the cited request observation, exactly or to the precision of the unit the answer states; and (b) it lies within `[H - T_delay, H + T_delay]`, where `H` is the hold S9's server-side witness recorded, from the last request byte received to the first response byte sent, and `T_delay` is a declared value. (a) binds the number to what was measured, and (b) checks the measurement against the witness |
| clock | the answer names the clock domain and the reading the interval's two instants were taken on, and they are the ones the cited records carry (`observer.record/1-draft`, Instant) |
| bound | the answer states the bound on the interval and its source. **Where the cited readings are ones whose lag the records say nothing measures, "not established" with that reason is the correct bound, and it is a STATED LIMIT**: the question is then `ANSWERED_WITH_STATED_LIMIT`, never `ANSWERED`. A numeric bound the records cannot support is incorrect |
| references | the answer cites exactly two observations: the one holding the LAST byte of S9's request in the `sent` direction, and the one holding the FIRST byte of S9's response in the `received` direction, each established from the observation's `offset` and `length` against the message's `stream` offsets in its reconstruction record, and each on S9's connection |
| no other | no other exchange is named as delayed |

**What would remove Q2's limit.** At `observer.record/1-draft` a reconstructed message carries no instant,
every observation's `seen` is an observer wall read taken after the event by a lag nothing measures, and the
field that would carry the kernel's production instant, `observation.produced`, is reserved and `not_carried`.
The bound becomes establishable when a production instant reaches the event and that field is carried. Until a
record contract version carries it, the expected Q2 bound is "not established"; once one does, the expected
bound is derived from it, and "not established" is incorrect. **The question is not narrowed to what can be
answered today**: the bound element stays, and it is what records that the limit exists.

`T_delay` is not a licence to be vague. It is declared by the realisation from a measurement of the same two
readings on exchanges with no scripted hold, and it is smaller than half the scripted hold, or the realisation
has not pinned a delay the question can separate.

## Q3. Which response had complete HTTP framing and invalid JSON?

| Element | Correct when |
|---|---|
| response | the answer names exactly one response by reference, and it is S11's |
| framing | the answer says the response's framing was complete - its end known and every byte present - citing the record members that say so |
| content | the answer says the body is not valid JSON, citing the structure the reconstruction derived |
| not incomplete framing | S12's response is not named as invalid JSON, and is not described as completely framed |
| not a parser limit | S14's response is not named as invalid JSON; it is named, if at all, as not structured because of a limit |

## Q4. Which message was interrupted by the witnessed reset, as against which reconstruction was incomplete because capture lost data?

Each half is answered on its own positive evidence. **Where the evidence cannot separate the two, the answer is
`undecidable` with the reason**, and that is the correct answer wherever the expected answer says so.

| Element | Correct when |
|---|---|
| interrupted | the answer names S12's response by reference as INTERRUPTED: framed, incomplete, ended when its stream ended, with no capture loss on its direction, citing those members |
| capture-incomplete | for every S13 message the expected answer classes as CAPTURE-INCOMPLETE, the answer names it by reference as incomplete because capture lost data, citing the loss that locates it to that message or its direction |
| undecidable | for every S13 message the expected answer classes as UNDECIDABLE, the answer names it as undecidable and gives the reason - a loss the session recorded that nothing located to that stream. **This is a STATED LIMIT**: where any S13 message is expected UNDECIDABLE, the question is `ANSWERED_WITH_STATED_LIMIT`, never `ANSWERED` |
| not crossed | S12's response is not called a capture loss, and no S13 message is called interrupted by the peer |
| evidential limit | **no statement in the answer says that a server did not send a response, or did not send further bytes, on the ground that the observer did not capture them.** What the observer can say is what the observed instance received before its stream ended. Any such statement fails the whole question |
| wording | the answer does not name the interruption a reset unless a cited record carries that fact. The records at `observer.record/1-draft` do not |

**The expected class of each S13 message is written before the run from the realisation's DECLARED gap
mechanism**, never from what the observer reported. CAPTURE-INCOMPLETE is expected only for a message whose
lost data the mechanism is declared to ATTRIBUTE to that message's direction - a hole inside the message, for
example. A loss LOCATED only in the session's production order does not attribute it to any stream (`ROWS.md`,
R3), so every message whose loss is not attributed is expected UNDECIDABLE, whether or not the loss was located
in production order. **What would remove the UNDECIDABLE limit**: a recorded loss that carries the
connection, direction and stream offset it was lost from, so the account can locate it; the expected class of a
message whose mechanism then records that is CAPTURE-INCOMPLETE.

**Q4 carries both kinds of unknown, and an answer keeps them apart.** WHERE a loss fell - whether this
message's direction lost data - is the PRODUCT's limit: a stated limit, removed by that recorded loss, and
answerable by a product that carries it. WHAT was in the lost bytes is the EVIDENCE's: no observation
delivered them, so they exist nowhere an observer could read, no product will ever answer it, and saying so is a
COMPLETE answer with no limit. An answer that reports only "undecidable" without saying which of the two it
means is incorrect at the undecidable element.

## Q5. Which requested instances were covered, excluded, multiply selected, or only partially covered?

**The population is the REQUESTED instances**: every instance a selection situation matches when selection
resolves - the approved roots, the existing descendants, S6's instance, S7's instance and S8's instance. A
future descendant is not requested. S5 is not requested. **The account's `scope.instances` block names one
entry per instance the scope named** (`contract/account/ACCOUNT.md`, Per-instance coverage), and the
answer reads coverage from there and nowhere else.

Each instance's answer is its `coverage` - `covered`, `partially_covered`, `not_covered`, `excluded` or
`undetermined` - and whether it was `multiply_selected`.

| Element | Correct when |
|---|---|
| per instance | for every requested instance, the answer's coverage and multiply-selected flag equal the expected ones, and the instance is named by pid namespace, pid in it, and executable; an `undetermined` executable, stated as such, is a STATED LIMIT (`ROWS.md`, The remover test applied) |
| references | each answer cites the `account:scope.instances.instances[<n>]` entry it rests on - a list is indexed by the member that holds it, never by the block around it, and the entry's own `evidence[]` references resolve |
| no absence as coverage | no instance is answered `covered`, `partially_covered` or `not_covered` except from its own `scope.instances` entry saying so. An instance with no entry, or whose entry is `undetermined`, is never answered as covered or as not covered |
| nothing outside | no instance outside the population - S5, a future descendant - is answered with any coverage |

The expected answers hold no `undetermined` and no `not_covered`: the realisation pins every requested
instance as attachable and pins no pid reuse among them, so either answer is INCORRECT in this version.
