# Observer record contracts

Version: `observer.record/1-draft`. **DRAFT and not frozen.** No machine-readable schema is published;
example JSON files show the document shapes, and the tool's Go validators enforce the contract. This
document is the contract and the Go types in this directory encode it. Where the two disagree this
document is corrected first.

These are the records the observer PRODUCES about what it captured. They are domain-neutral: nothing here
names a business operation or a privacy rule, and a field that only a domain reader needs belongs to a pack.

| Record | One per | Built from |
|---|---|---|
| `observation` | plaintext fragment one library call transferred | `fragment.Record` |
| `connection` | occupancy of a TLS library handle by one admitted execution | `connection.Record` |
| `reconstruction` | connection's observations read as messages and exchanges | `reconstruct.Connection` |
| `reassembly` | session: the observations reassembly refused or did not need | `reconstruct.Reconstruction` |

Every record carries `record` (its kind) and `version`. A record set covers ONE capture session: connection
ids are unique within a session and mean nothing across sessions.

## Encoding

The tests use JSON. That is the encoding the observer already writes; it is not a choice of
schema notation.

- Every 64-bit identity, generation, offset and instant is a DECIMAL STRING, so a reader whose numbers are
  doubles cannot round it. Values that fit 32 bits are numbers.
- Every vocabulary is a lower-case name. A source value with no name is refused by the producer
  (`ErrUnrepresentable`), never mapped to the nearest name.
- A field whose value can be absent carries `state`, and no value stands for "could not find out". Zero is a
  value.

## Primitives

### State

| `state` | Means |
|---|---|
| `determined` | read or computed; the value is present |
| `undetermined` | this run could not establish it; no value is present, and it is not zero |
| `not_carried` | a RESERVED field this producer does not supply at all; never a reading of an event |

### Instant

`{state, domain, unit, reading, value}`. `value` is a decimal count of `unit` since the domain's origin.

| `domain` | Clock | Origin |
|---|---|---|
| `wall` | CLOCK_REALTIME | the Unix epoch |
| `monotonic` | CLOCK_MONOTONIC | this boot; does not advance across a suspend |
| `boottime` | CLOCK_BOOTTIME | this boot; advances across a suspend |

The three domains are never compared with each other.

| `reading` | How the value was obtained |
|---|---|
| `observer_wall_read` | the observer read its own wall clock in userspace, AFTER the moment the field dates, by a lag nothing measures |
| `crossed_from_monotonic` | a kernel CLOCK_MONOTONIC stamp moved onto the wall clock by ONE pairing of the two clocks per session |
| `kernel_stamp` | a kernel clock read at the event, on its own domain |

**A crossed instant and a direct wall instant are not interchangeable at millisecond granularity.** Measured
over two capture runs of one scenario, 76 dated connections each: `first_seen - opened`
diverged by about 5ms over 21 seconds within one run, with opposite sign in the two runs. No tolerance is
established. A comparison between the two readings either states a tolerance no smaller than that
measurement or is not made.

An undetermined instant carries no `value` and no `reading`. An absent kernel stamp is never crossed: a
crossing would turn an absence into the instant the session began.

### Birth

`{state, domain, unit, value}`, always `boottime` in `clock_ticks`. **A birth is a process IDENTITY, not a
timestamp**: it separates one occupant of a pid from the next and is compared only with another birth read
the same way. It is never converted to an instant. The length of a clock tick is the host's and is not
carried.

### Count

`{state, unit, value, why}`. `why` is the source's own reason where it gave one, on either state. A unit is
what one step of the value IS, and no unit bounds another:

| `unit` | One step is |
|---|---|
| `bytes` | a byte |
| `events` | an event the kernel program produced |
| `fragments` | a transfer placed in a stream |
| `calls` | a call into an observed library, whether or not its bytes reached a record |
| `instances` | an admitted execution or process |
| `places` | a place in the session's production order: an event produced or a call refused at the read boundary |
| `descriptor_lifetimes` | an occupancy of a descriptor by a socket |
| `bindings` | a binding of a library handle to a descriptor occupancy |

### Namespace

`{state, device, inode, established_by}`: a kernel namespace named by its nsfs device and inode.

| `established_by` | Evidence | About |
|---|---|---|
| `admission_event` | the pid namespace on the kernel event that admitted the instance | the instance |
| `process_proc_read` | `/proc/<pid>/ns/net` of the holding process, read while probes were placed | the PROCESS, never a socket |
| `resolution_proc_read` | `/proc/<pid>/ns/pid` of a process, read when the observer resolved its policy | the PROCESS, as it was at that read |
| `socket_evidence` | kernel socket evidence on the call | the SOCKET |

A process's network namespace and a socket's network namespace are different facts and one is never
substituted for the other: a socket inherited across a namespace transition belongs to the namespace it was
created in.

### Instance key and allocator

`{pid_namespace, pid, generation, allocator}` identifies one admitted execution. `pid` is the number inside
`pid_namespace`. `allocator` is `target` for a generation below 2^63, stamped when a selection named the
instance, and `descent` at or above it, stamped by the kernel for a child it admitted. It is read off the
generation's range and carries no other evidence.

### Descriptor, socket, address, generation

Each is `{state, ...}`. Descriptor `number` 0 and port 0 are ordinary values. `socket.inode` is the kernel's
own inode for the socket, the same number `/proc/<pid>/fd/<n>` names as `socket:[N]`; it is reused once the
socket is freed. A generation separates one occupancy of a reused name from the next and is a counter, not a
time.

## observation

| Field | Class | Meaning |
|---|---|---|
| `process.pid` | identity | the pid in the OBSERVER's pid namespace |
| `process.birth` | identity | start identity read from the observer's `/proc`; undetermined where it could not be read |
| `connection` | identity | the connection id within the session |
| `direction` | identity | `sent` (the process wrote) or `received` (it read) |
| `sequence` | identity | orders the connection's observations, both directions together |
| `offset` | identity | where the first byte sits in its direction's stream |
| `length` | loss | bytes the call transferred |
| `payload.kept` / `payload.truncated` | loss | bytes capture kept, and whether that is fewer than `length`; lost bytes are at the END of the fragment |
| `payload.data` | content | the kept bytes, `payload.encoding` = `base64` |
| `seen` | provenance | `wall`, `observer_wall_read`: when the observer DECODED the event |
| `produced` | reserved | `monotonic` nanoseconds: when the kernel produced the event. `not_carried` in this version |

`(process.pid, connection)` joins an observation to its connection record. A fragment boundary is a library
call, not a message boundary.

## connection

| Field | Class | Meaning |
|---|---|---|
| `id` | identity | stable for the record's life whatever its association says |
| `handle.instance`, `handle.address`, `handle.generation` | identity | the occupancy: an execution, a library handle address, and the generation separating this occupancy of the address from the next |
| `instance.key` | identity | the admitted execution that held the handle |
| `instance.birth` | identity | its start identity, with its state explicit; the thread group's kernel birth fills this where it reaches the record |
| `instance.executable` | identity | where `/proc/<pid>/exe` pointed, with its state explicit; undetermined where unread |
| `process` | identity | the same execution in the observer's pid numbering, as an observation carries it |
| `process_network` | provenance | the holding process's network namespace, `process_proc_read` |
| `first_seen` | provenance | `observer_wall_read`: when the observer decoded the handle's first transfer |
| `opened` | uncertainty | `crossed_from_monotonic`: when the socket beneath was created. Undetermined where the run did not see it created, which includes every descriptor inherited across a fork |
| `ending.how` | uncertainty | `still_open`, `handle_released`, `socket_closed`, `unobserved`, `unestablished` |
| `ending.at` | provenance | `observer_wall_read`: when the observer decoded the event that ended the record, for `handle_released` and `socket_closed`. ALWAYS undetermined for `unobserved`, `still_open` and `unestablished`, because none of them has an observed end |
| `ending.detected` | provenance | present ONLY for `unobserved`: `observer_wall_read`, when the observer DETECTED the loss that retired the record. It is not when the connection ended, and nothing records that |
| `associations[]` | see below | one per direction the run said anything about. A direction with no entry had nothing observed, which is not a direction observed to have no binding |
| `placements[]` | see below | one per direction that carried bytes |
| `fragments` | loss | fragments placed, both directions; bounds neither transfers nor bytes |
| `early[]`, `early_unmeasured` | loss | TLS 1.3 early-data ranges, and early transfers nothing could measure |

### association

| Field | Class | Meaning |
|---|---|---|
| `state` | uncertainty | `established`, `unknown`, `ambiguous`, `invalidated` |
| `reason` | uncertainty | required for every state but `established`, and only from that state's set |
| `binding` | identity | the descriptor occupancy's generation |
| `source` | provenance | `setter_argument`, `in_call_syscall`, `socket_lifetime` |
| `basis` | provenance | `confirmed_in_call` or `continuity`; only on `established`, and absent where the backend cannot say |
| `valid` | provenance | `from` and `until`, both `observer_wall_read`, and `open`, as the observer wrote them. What `open` establishes is UNESTABLISHED: see Known limits of this producer |
| `descriptor`, `contended[]` | identity, uncertainty | the descriptor, and for `ambiguous` the two or more candidates, never resolved to the first |
| `socket` | identity | the socket inode |
| `endpoints.local`, `endpoints.remote` | identity | addresses, each with its own state |
| `endpoints.namespace` | provenance | the SOCKET's network namespace, `socket_evidence` |
| `join`, `join_reason` | uncertainty | whether the tuple is complete enough to join an outside witness, and why not. A second axis, not derived from `state` |
| `wire` | loss | ciphertext bytes the kernel ACCEPTED on the syscall behind the binding; not peer receipt and not `length` |

Reasons by state:

    unknown       no_binding_observed, insertion_refused, observation_lost, transport_unsupported,
                  binding_unobservable, operation_was_not_a_socket, evidence_unreadable,
                  operation_unresolved, route_unsupported, operation_frame_broken,
                  socket_evidence_unavailable
    ambiguous     several_descriptors
    invalidated   descriptor_replaced, transport_replaced, lifetime_evidence_ended,
                  handle_released, handle_lifetime_unobservable

Join reasons: `no_binding_to_join`, `endpoint_unreadable`, `no_endpoint_producer`, `namespace_unestablished`.

### placement

| Field | Class | Meaning |
|---|---|---|
| `positions` | uncertainty | `established`, `unknown_from`, `unknown_throughout` |
| `from` | uncertainty | only on `unknown_from`: the first offset whose position is not established |
| `because` | uncertainty | a reason from the association vocabulary; required unless `established` |
| `lost` | loss | observations of this direction known to be missing, in `events`; undetermined where no count exists |

A gap located in the session's production order is `unknown_from`; one nothing located is
`unknown_throughout`. Neither says which stream the missing observation belonged to.

### One socket, more than one claimant

A socket can be held by more than one execution at once: a parent and the child it forked both hold an
accepted socket between the fork and the parent's close. **Each claimant is its own handle occupancy and so
its own connection record.** Two records are CO-CLAIMANTS of one socket when they carry the same determined
`socket.inode`, their `instance.key`s differ, and their lifetimes `[first_seen, ending.at)` overlap, an
undetermined `ending.at` counting as still open. A socket inode is reused only after the socket is freed, so
an overlap in time is one socket. A child the kernel admitted carries `allocator` `descent`.

**Two records of ONE instance on one socket are not co-claimants.** They are successive occupancies of the
handle - a record a located gap retired, ending `unobserved`, and the record that took over at the next
handle generation. `valid.open` does not separate the two cases: the observer leaves it true on records that
have ended, so an interval test over `valid` reads every such pair as overlapping.

## reconstruction

| Field | Class | Meaning |
|---|---|---|
| `connection` | identity | `{process, id}` as an observation names it |
| `protocol` | uncertainty | `http/1.1`, or `unknown` where neither direction began as a message |
| `role` | uncertainty | `server`, `client`, `unknown` |
| `unplaced` | loss | stream offsets that carried bytes and were read as no message |
| `note` | provenance | the reconstructor's own sentence, where it wrote one |
| `exchanges[]` | | in stream order |

`exchange`: `index`, `request` and `response` each `{state: present | absent, message}`, and `complete`
(both present and neither missing a byte). An absent response is not an empty one.

`message`:

| Field | Class | Meaning |
|---|---|---|
| `kind` | identity | `request`, `response`, `unknown` |
| `method`, `target`, `protocol`, `status`, `reason` | content | as sent; `status` only on a response |
| `headers[]`, `trailers[]` | content | `{name, value}` in order, names as sent |
| `framing` | uncertainty | `none`, `content_length`, `chunked`, `until_close`, `ambiguous` |
| `body.length` | loss | the body's extent in the stream |
| `body.kept` | content | the kept bytes, `base64` |
| `body.holed` / `body.elided` | loss | bytes capture never had / bytes a bound dropped. Different facts |
| `complete`, `framed` | uncertainty | every byte present / the end known |
| `defect`, `detail` | uncertainty | `none`, `stream_ended`, `hole`, `malformed`, `ambiguous_framing`, `limit`, and one line that never carries body bytes |
| `stream` | identity | `{direction, offset, end}`. `direction` is DERIVED from `role`: a server receives requests |
| `structure` | content, uncertainty | `derived` with a `shape`, `refused` with a reason, or `none` for no body |

A `shape` is `{kind, fields[], elems[], count, elided}` with kinds `invalid`, `object`, `array`, `integer`,
`fraction`, `boolean`, `null`, `short_string`, `long_string`, `decimal_string`, and fields
`{name, name_elided, shape}`. It carries structure and no values.

## reassembly

`discards[]` `{observation, because}` and `duplicates[]` `{observation, offset, length, agrees}`. An
observation is referenced by `index`, its position in the session's observation sequence - the one identity
a refused observation is guaranteed to have - with its pid, connection, direction and sequence beside it. A
refused observation's offsets are a gap. A duplicate changed no stream and is carried because a run that
delivered a fragment twice reconstructs identically to one that delivered it once; `agrees` false is a
capture contradicting itself.

## Known limits of this producer

True of the current observer, and to be re-measured when capture changes. A consumer relies on the state
each field carries, not on the declaration of the observer type it was projected from.

- **`valid.open` is true on every association**, including records whose handle was released and records
  that ended unobserved. **`open` is not evidence that a binding still held when the run was sealed.**
- **`instance.birth` and `instance.executable` are undetermined, and so is every observation's
  `process.birth`.** Each is carried as `undetermined`, never as zero or an empty string.
- **Every `unobserved` ending carries its only instant in `ending.detected`**; `ending.at` is undetermined.

## Reserved

| Field | Unit and domain | Fills when |
|---|---|---|
| `observation.produced` | `monotonic`, `nanoseconds`, `kernel_stamp` | the kernel event carries the production instant the kernel already holds |

The thread group's kernel birth needs no new field: it fills `instance.birth`, which already exists and is
undetermined wherever `/proc` could not be read.

## What these records do not carry

- The run's account - capture scope, selection, loss counters, ordering, the seal - which is the account
  contract's.
- Why an instance was admitted - target, rule, parent - which the observer's connection record does not
  hold. `allocator` says only which counter stamped the generation.
- Policy dispositions, processing results and extension output.

## Normalization

Permitted normalization, which changes representation and no fact:

- a Go RFC 3339 time becomes decimal nanoseconds of the same instant;
- a numeric vocabulary value becomes its name;
- a zero or a `Known` flag becomes an explicit `state`;
- a 64-bit number becomes a decimal string;
- the observer's field names become these.
