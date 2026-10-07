# The extension protocol

Status: Live, draft protocol `observer.extension/1`. **This remains a draft.** No machine-readable schema
is published; this document is the contract and the worked examples below show every message. Where the
observer and this document disagree this document is corrected first.

An **extension** is a user's own executable that the observer starts and feeds records to. It is
configured by one entry in the configuration's `extensions` section
([../config/CONFIG.md](../config/CONFIG.md), Extensions). This document is everything an extension's author
needs: how the observer runs it, every message both ways, what it may answer, every bound, and what happens
when it fails. It can be written in any language with no library from the observer: it reads lines of
JSON on standard input and writes lines of JSON on standard output.

What an extension receives is the observer's own records, as the approved output writes them
([../record/record.md](../record/record.md)), restricted to the fields its entry names, after the
built-in rules have run. An extension can leave an exchange unchanged, change it, or fail it, and it can
emit **derived records** - its own lines, in its own output file, about exchanges it was given. **What an
extension does is extension-declared and not observer-enforced**: the observer checks the shape and the
attribution of what an extension says, never its truth.

## The process

- **One process per extension sees every connection.** The observer starts it once per session and again
  after it fails; each start is a **generation**, numbered from 1 within the session.
- It is started **after the observer has given up its capabilities**, with no capability in any set, with
  `no_new_privs` set, and with none of the observer's capture, output or control descriptors: its standard
  input, output and error are pipes to the observer and it holds nothing else from it.
- It runs **as the observer's user** - root under the documented start - **without capabilities**. It can
  read and write what that user owns, including the session's output, account and configuration, and it
  can stop the observer. **It is trusted code and not sandboxed.** Anything it sends over the network is an
  export the observer does not control.
- It runs in **its own process group**. The observer stops a generation with `SIGTERM` to the group and
  `SIGKILL` to the group after the termination grace. The extension process is given a parent-death signal
  (`SIGKILL`), so **no extension process outlives the observer. A process the extension starts can**: the
  parent-death signal does not pass to a child, and only an orderly stop signals the group.
- Its **out-of-memory score is raised** (`oom_score_adj` 1000, the most the kernel allows) so the kernel
  prefers it to the observer as a victim, and its **core dump limit is set to 1 byte**, soft and hard,
  before it runs, which suppresses its core dumps where the kernel honours that limit. Where a dump does
  happen it holds what the extension received, and never anything `remove` took out. It shares the
  observer's memory and CPU; memory exhaustion may still end the observer.
- The command is run exactly as configured - an argument vector, no shell - with the observer's environment
  and the observer's working directory.

## Framing

- Standard input carries the observer's messages, standard output the extension's. **One message is one
  JSON object on one line**, UTF-8, ended by one line feed (`\n`). A line feed inside a string is escaped,
  as JSON requires. A carriage return before the line feed is not stripped.
- **Every message has a `type`.** A message the observer receives with a `type` it does not know is a
  protocol violation; a member a message does not define is ignored, so a later draft can add members.
- **A line is bounded**, line feed included: `frame_bytes_to_extension` for what the observer writes and
  `frame_bytes_from_extension` for what the extension writes (Bounds).
- **Standard error is drained, never read as protocol.** The observer reads it continuously, so an
  extension never blocks on writing it, and copies it into the observer's log within the stderr bounds,
  each line escaped and attributed to the extension and generation. Lines beyond the bounds are counted and
  dropped. A `failed` result's reason goes to the same log, escaped and cut at `reason_bytes`, and shares
  the stderr rate: beyond it a reason is not logged, and `failed_by.declined` still counts every declined
  exchange, so a missing log line is never a missing failure.
- **Counts and ids are decimal strings**, as in the records, so a reader whose numbers are doubles cannot
  round them. Bounds and `timeout_ms` are JSON numbers; each is far below 2^53.

## Ids

**Every exchange the observer sends has an `id`: a positive decimal string from
one sequence for the session, never reused.** Every extension sees the same id
for the same exchange. Each exchange also carries its connection's
`connection_id`, the connection record's `id`, and its zero-based `index` on that
connection, whatever fields the entry selects. The approved exchange line
carries the same `exchange_id`, `index` and connection `id`.

**Ids and indexes are issued as the observer reads a connection**: one per
exchange, in wire order, when its reading hands the exchange over. An exchange
whose copy the shared allowance has no room for takes none, and its connection
is cut. With extensions configured an exchange also needs the copy every
extension and every line reads: one that no pipeline still working on its
connection can copy and project takes none, and is neither sent nor written.
Without extensions a failed pipeline withholds only its own lines, and the
exchange still takes its id and index. Indexes and ids survive dropped lines and
excluded exchanges. **No message carries a range of a connection's ids**: a
connection that is still open does not know its last one. `connection_done`
carries how many were issued.
See [the line contract](../record/record.md#approved-line-envelope).
With `write_content` false no exchange is sent or written and no id is issued.

A result must name an id this generation was sent and has not answered. A derived record's source id is
valid when it is an id issued so far in the session. **That establishes that the exchange existed
in the session - not that this extension received it, and not that it was written.**

## Lifecycle

    observer                                   extension
    start  ------------------------------------>
           <------------------------------------ ready
    exchange (id 1, connection 7, index 0) ---->
           <------------------------------------ result (id 1)
    exchange (id 2, connection 7, index 1) ---->
           <------------------------------------ derived (any time, zero or more)
           <------------------------------------ result (id 2)
    connection_done (connection 7, count 2) --->
      ... more connections, interleaved ...
    session_ending ---------------------------->
           <------------------------------------ derived (the last summaries)
    shutdown, then standard input closed ------>
                                                exits

1. **`start`.** The first message of every generation. It names the protocol version, the extension, the
   session, the generation, the fields it receives and every bound. The extension answers **`ready`**
   naming the same protocol version. **The version is matched exactly**: a `ready` naming any other is a
   protocol violation. No `ready` within `startup_ms` of `start` being written retires the generation.
2. **`exchange`.** One exchange: its id, its connection's id, its index on the connection, whether the
   output will write it, and the fields the entry selects. Sent only to a generation that has answered
   `ready`.
3. **`result`.** The extension's answer for one id: `unchanged`, `changed` with replacement content, or
   `failed` with a reason. **Exactly one per exchange sent.**
4. **`connection_done`.** No more exchanges will be sent for that connection. It carries the connection's
   id, how many exchange ids were issued on it, and the record's own ending, which is `still_open` for a
   connection the session ended while it was open. With `connection` selected it carries the connection
   record too. When it is sent, and for which connections, is in [Connection done](#connection-done).
5. **`derived`.** A derived record, at any time after `ready`, zero or more.
6. **`session_ending`.** No more exchanges and no more `connection_done` will be sent in this session.
   The extension emits whatever it holds - a summary, a last batch - as derived records.
7. **`shutdown`.** Sent once every exchange of the generation is resolved, then standard input is closed.
   The extension exits. Derived records it writes before it exits are still taken.

**Order is guaranteed within a connection and nowhere else.** For one connection, exchanges are sent in
index order, **never two outstanding at once, at any extension**: an exchange goes through the extensions
in their configured order, the next exchange of the connection starts only once the previous one has been
answered or skipped at every extension, and `connection_done` comes only after the last one has. Exchanges
of different connections are interleaved, and their arrival order is not evidence of causation or of time.

**When exchanges are sent.** An exchange the output will write is sent once the observer releases it -
both its messages read, and every byte of them vouched for by capture - and the one before it on its
connection is done. That is while the connection is still open, or at the latest when the connection or
the session ends. A long-lived keep-alive connection is sent exchange by exchange. **Its line is written
once every extension has answered or skipped it.** Exchanges the output will not write are sent when that
becomes decidable ([Which exchanges](#which-exchanges)).

**A generation that becomes ready part way through a connection** receives that connection's later
exchanges and its `connection_done` without the earlier ones. Every new generation starts with no state:
**the observer does not replay exchanges and does not recover state**, and the account counts each reset.

## What an extension is sent

### The fields

An entry's `fields` select from seven. Each brings the parts of the record named here and nothing else:

| field | the record's parts |
|---|---|
| `request.line` | the request's `method`, `target` and `protocol` |
| `request.headers` | the request's `headers[]` and `trailers[]`, `{name, value}` in order, names as sent |
| `request.body` | the request's `body` (`length`, `kept` in base64, `holed`, `elided`, `encoding`), `framing` and `structure` |
| `response.line` | the response's `status`, `reason` and `protocol` |
| `response.headers` | the response's `headers[]` and `trailers[]` |
| `response.body` | the response's `body`, `framing` and `structure` |
| `connection` | the connection record, as the approved output writes it |

**Each selected field brings its structural companions**: for a field of a side, that side's `state`
(`present` or `absent`) and, where it is present, the message's `kind`, `complete`, `framed` and `defect`.
An exchange always carries `index` and `complete`. A side with no field selected is sent as `{}`; an
absent side as `{"state": "absent"}`.

**Read-only, never replaceable**: identity (`id`, `connection_id`, `index`, `kind`, the connection
record), completeness (`complete`, `framed`, `defect`, a side's `state`), loss (`length`, `holed`,
`elided`), `encoding`, `structure`, and the policy evidence in `removed[]`. The record carries no timing;
neither does an exchange.

**Never sent**: a field the entry does not select; a value `remove` took out; anything outside the
prefix of a connection that capture established; a parser's diagnostic text (`detail`).

### After the built-in rules

**An extension receives each field as the output would write it**: after `remove`, `mask`, `truncate` and
`body_values` - including for an exchange the output will not write - with the rules' conservative
handling of a body they cannot decide. A masked value arrives masked and a truncated one truncated.

**A removed field arrives marked removed.** `removed[]` lists the removals the rules made in this exchange
within the selected fields, as the approved output records them: `{message, field, disposition}`, with
`section` for a header. A header removed is absent from `headers[]` and listed; a body removed whole has an
empty `kept`, keeps its `length`, has `structure.state` `removed`, and is listed. The removed value itself
is never sent, in any form, in any exchange.

### Which exchanges

**Every exchange the observer's reading of a connection hands over is sent, in index order**, including
incomplete and one-sided ones. `output` says whether the approved output will write it:

- `{"state": "eligible"}`: the output will write it, unless processing refuses it for another reason;
- `{"state": "excluded", "reason": R}`: the output will not write it, for the truncation reason R the
  connection's line records (`capture_hole`, `positions_unknown`, `incomplete_message`, `malformed_message`,
  `ambiguous_framing`, `processing_limit`, `unsupported_message`, `unpaired_exchange`, `unparsed_suffix`,
  `connection_cut`).

**The output writes a connection's exchanges up to the first one it cannot write.** That one and every one
after it are excluded. **Each excluded exchange is sent as soon as its reason is decidable, and then let
go**, with the reason its connection line records. A reason is decidable once nothing later can change it:
once the connection has been read past where the first exchange the output cannot write stopped, in the
direction the reason comes from, with no stop of capture's there. At the latest it is decidable when the
connection ends or the session ends, or when the connection is cut, where the reason is `connection_cut`.
So a connection does not accumulate excluded exchanges: each waits only until its reason is decidable and
its extensions have answered.

**An excluded exchange can be read and never changed**: a `changed` answer for one fails.

**A connection is cut** when it cannot hold more unreleased work: at its own bound, or with the observer's
shared allowance full. What it had not released is discarded unread and never sent. The exchanges it had
released are still sent, in order, and their lines written; its held excluded exchanges are sent as above.

**A capture loss** on a connection withdraws what it has not yet sent: each exchange that has not reached an
extension skips it as `withdrawn`, and its line is withdrawn too. The connection's `connection_done` still
follows once it ends.

### Connection done

**Exactly one `connection_done` is sent for every connection that was issued an exchange id**, once the
connection has ended - its handle released, its socket closed, or the session ended with it open - and
its last exchange has been answered or skipped at every extension. That includes a connection cut after
some of its exchanges were sent, and one whose capture lost input after them.

- **`count` is the number of exchange ids issued on the connection**: every exchange sent, excluded ones
  included, and the ones that skipped an extension or whose line the output dropped. It is not the number
  this extension or this generation received, nor the number the output wrote; an extension compares the
  two to learn what it missed.
- **A connection that ends with no id issued, and was not refused whole**, is sent one with `count` `"0"`:
  no content of it arrived, or what arrived was read and paired nothing. With `write_content` false this
  metadata-only form is what every such connection is sent.
- **A connection refused whole is sent nothing**: one cut, lost to capture or refused before any id was
  issued on it, or one whose content arrived and none of it could be read. No exchange, no
  `connection_done`.
- **`ending` is absent** only where the observer holds no readable retirement record for a connection that
  was issued ids: the record never arrived before the session ended, or the observer refused it.

Like every control message, it is dropped where no generation is ready, and a generation retired before
it is sent never receives it. A session that stops without settling its connections - a terminal fault, or
an end without capture's final facts - sends none for the connections it did not settle.

## What an extension answers

    {"type": "result", "id": "17", "outcome": "unchanged"}
    {"type": "result", "id": "17", "outcome": "changed", "changes": {<field>: <replacement>, ...}}
    {"type": "result", "id": "17", "outcome": "failed", "reason": "<text>"}

**There is no empty answer**: `outcome` is one of the three, and anything else fails the exchange as
`malformed`.

**`changed` replaces whole components.** `changes` holds one or more of the content fields the entry
selects, each replaced whole - there is no patch language:

| field | replacement |
|---|---|
| `request.line` | `{"method", "target", "protocol"}`, all three: a method an HTTP token, a target of printable ASCII without space, a protocol `HTTP/` and a digit, a dot and a digit |
| `response.line` | `{"status", "reason", "protocol"}`, all three: a status a number from 100 to 999, a reason of printable ASCII, space and tab, a protocol as above |
| `request.headers`, `response.headers` | `{"headers": [...], "trailers": [...]}`, both lists, each item `{name, value}`: a name an HTTP token, a value with no CR, LF or NUL; at most 128 headers, 32 trailers and 65536 bytes of headers |
| `request.body`, `response.body` | `{"kept": "<base64>"}`: the replacement bytes, standard base64 with padding, at most 8388608 bytes decoded |

**An answer is validated whole.** Any failure below fails the exchange, and it keeps the form it had
before this extension - nothing of the answer is applied. Each reason is counted
([../account/ACCOUNT.md](../account/ACCOUNT.md), processing):

| reason | the answer |
|---|---|
| `malformed` | is not one of the three shapes, or a replacement breaks its rules above |
| `not_given` | changes a field the entry does not select, or a field of a side that is absent |
| `read_only` | changes `connection`, or names a member of a component that is not replaceable (`length`, `structure` ...) |
| `removed_content` | replaces a body `remove` took out whole (`structure.state` `removed`, or values removed): content that was removed was not given, and supplying it is refused |
| `excluded` | is `changed` for an excluded exchange |
| `declined` | is `failed`, with the extension's own reason |
| `no_room` | is `changed`, and the observer's shared allowance has no room to keep the replacement. The connection is then cut: this exchange goes on and is written, and what the connection had not released is discarded |

**An accepted change becomes a new representation of that component and goes through the whole built-in
chain once** - `remove`, `mask`, `truncate`, `body_values` - before the next extension sees the exchange.
A positional rule applies to a replacement body as to any body. **A removal the chain makes from
replacement content is recorded apart from removals of captured content**, attributed to the extension
that supplied it, so a header an extension adds back is removed again and the output says which extension
supplied it. A replacement never changes completeness, loss or identity: a body replaced keeps the
`length`, `holed` and `elided` capture gave it, so **an extension cannot make an incomplete capture
complete**.

**Extensions run in the order the configuration lists them, each after the one before** has answered or
failed. Each sees the exchange as the previous ones and the chain left it. The output records, per written
exchange, every extension's outcome and which of its changes survive, apart from changes a later extension
overwrote.

**A failure never stops an exchange.** It is written without that extension's changes - after the built-in
chain, never in a form that skipped it - and the failure is counted. **So an extension never protects
data; that belongs in `remove`**, which applies before any extension and always applies.

## Derived records

    {"type": "derived", "sources": ["17", "18"], "basis": "inferred", "record": {...}}

- `sources`: one to `derived_sources` ids, each an id issued so far in the session.
- `basis`: `observed` - read off the exchanges it names - or `inferred` - concluded from them, such as a
  path template like `/users/{id}`.
- `record`: a JSON object, the extension's own payload.

**Derived records go to the extension's own file and never into the observer's records, output or
account.** The file is `derived-<name>.jsonl` under the configured directory, opened in append mode with mode
0600 across sessions. Each line the observer writes is:

    {"version": "observer.derived/1", "extension": "<name>", "session": "<id>", "generation": "<n>",
     "processing_revision": "sha256:...", "effects": "extension_declared_not_observer_enforced",
     "sources": [...], "basis": "...", "record": {...}}

The observer stamps the extension, session, generation, processing revision and label; the extension
supplies the rest.

A derived record is refused - counted, never written, and never fatal to the session - for:

| reason | when |
|---|---|
| `malformed` | `sources`, `basis` or `record` breaks the rules above |
| `unknown_source` | a source id is not an id issued so far in the session |
| `rate` | the extension is over `derived_lines_per_second` |
| `queue_full` | `derived_queue_bytes` of its records are already waiting to be written |
| `stopped` | the session's output has stopped |
| `write_failed` | the write failed |

Derived output is best effort, with no cumulative byte budget. Approved and derived
lines share a bounded sink queue; queued and in-flight bytes count together. A
full queue drops immediately. Unavailable or failing files cost counted attempts,
never monitoring or extension activation. Delivery counts keep authorized,
written, failed, dropped and pending separate. A failed attempt is not retried
and does not prove the line absent from the file. A later write starts a new line.

**Reading results never waits behind derived output**: a derived record that cannot be queued is refused
at once. **An extension refused for rate in each of `derived_flood_seconds` consecutive seconds is
retired** as `flood`.

## Failure, retirement and restart

**A generation is retired** - stopped with `SIGTERM` to its group and `SIGKILL` after the termination grace,
and every exchange it has outstanding resolved once as failed under the cause - when:

| cause | what happened |
|---|---|
| `start_failed` | the process could not be started: running the command failed |
| `startup_timeout` | no `ready` within `startup_ms` |
| `timeout` | an exchange's deadline passed, or a message could not be written within the entry's `timeout_ms` |
| `crash` | standard output reached end of file, or the process exited or was killed |
| `protocol` | a line that is not valid UTF-8 JSON, not an object, has no known `type`, or a `ready` naming another version, or a `ready` after the first |
| `oversized_frame` | a line longer than `frame_bytes_from_extension`, or that many bytes with no line feed |
| `unknown_id` | a `result` for an id this generation was never sent and is not counted `duplicate` (below) |
| `flood` | derived records refused for rate in `derived_flood_seconds` consecutive seconds |

**The deadline starts when the exchange is queued for the extension**, before it is written, so a pipe the
extension stops reading expires too. **Each admitted call waits at most `timeout_ms`, its queueing and
writing included.**

**A result that arrives late or twice is discarded and counted on its own**: `late` for an answer from a
generation already being retired, `duplicate` for a second answer to an id this generation already
answered. Neither retires anything. **Each exchange has exactly one terminal outcome.**

**A second answer is told from an answer to an id never sent by a bounded record.** The observer keeps the
ids each generation has answered as at most 4096 spans of consecutive ids. Past that bound the oldest spans
fold into a floor, and an answer to an id at or below the floor is counted `duplicate` rather than retiring
the generation as `unknown_id`. So a generation is never retired for an answer to an id it was sent. An
answer to an id it was never sent that lies at or below the floor is counted `duplicate` and does not
retire it.

**Restart.** After a retirement the next generation starts after a backoff that doubles from
`backoff_min_ms` to `backoff_max_ms`, and returns to `backoff_min_ms` once a generation has stayed up
`healthy_ms`. A generation that answers `ready` after an earlier one did is a **state reset**, counted. No
generation is started once `session_ending` has been sent.

**An exchange skips an extension at once** - counted under the reason, never waited for - when:

| reason | when |
|---|---|
| `unavailable` | no generation is ready: one is starting, the extension is in backoff, or it could not be started |
| `busy` | the extension already has `in_flight` exchanges outstanding, or admitting this connection would take the charge of the connections waiting on it over `waiting_bytes` |
| `too_large` | the exchange's message would be longer than `frame_bytes_to_extension` |
| `withdrawn` | the connection's capture lost input before the exchange reached this extension: its content is withdrawn, as its approved line is, and it is never sent |

**So an extension slower than its load costs extension processing before it costs any connection.** A
connection keeps everything it holds in the observer's shared allowance while one of its exchanges waits
on an extension: its captured input, what its reading keeps, and the copies of its exchanges. That whole
charge, read when the call is made, is what the call is admitted at. The connections admitted to all
extensions together are charged at most half the allowance; a call that would pass its extension's share
skips it as `busy`, and the exchange goes on and is written.

**Shutdown never waits without bound.** `shutdown` is sent once every outstanding exchange has a result or
has passed its deadline; the extension then has the termination grace to exit before `SIGTERM`, and the
grace again before `SIGKILL`. No generation is restarted during shutdown.

## The delay an extension adds

**Exchanges reach an extension as they are released, while their connection is open, and their lines wait
for the extensions' answers. Each admitted call waits at most `timeout_ms`, its queueing and writing
included. An exchange's own extension waits total at most the sum of its extensions' `timeout_ms`. Earlier
exchanges of its connection still with an extension, processing and output can add delay.** While one
connection waits on an extension, other connections are processed and written; the application never waits
on an extension and capture never waits on one directly.

## Bounds

Every constant, in one place. `start` discloses each under the name in the first column.

| name | value | why |
|---|---|---|
| `startup_ms` | 5000 | from `start` written to `ready` read. Long enough for an interpreter or a virtual machine to start on a loaded host, short enough that a generation that will never answer is found within seconds; exchanges skip it as `unavailable` meanwhile |
| `frame_bytes_to_extension` | 33554432 | 32 MiB. Above any exchange the reconstructor produces under its default limits - two 8 MiB bodies in base64 with their headers - so `too_large` is a guard rather than an expected outcome |
| `frame_bytes_from_extension` | 4194304 | 4 MiB. The observer holds at most this much of one unfinished line per extension, so eight extensions cost at most 32 MiB of read buffers. A replacement body of up to 3 MiB fits |
| `in_flight` | 4096 | exchanges outstanding at one extension at once, one per connection; beyond it an exchange skips the extension as `busy`. What those connections hold is bounded by `waiting_bytes`, so this count bounds only the observer's record of what is outstanding, one entry an exchange. A lower count would make a healthy extension see less than the session held whenever many connections release together, as every open one does at session end |
| `waiting_bytes` | the shared allowance (`limits.events` times 4096 bytes) divided by twice the number of extensions | the charge in the shared allowance of the connections waiting on this extension - each connection's captured input, what its reading keeps and the copies of its exchanges - each read when its call is made. Together, half the allowance, so the other half is always free for capture |
| `healthy_ms` | 60000 | a generation up this long resets the backoff. Twelve times `backoff_max_ms`, so an extension failing every few seconds stays in backoff |
| `backoff_min_ms` | 100 | the first wait before a restart |
| `backoff_max_ms` | 5000 | the longest; the wait doubles from the first to this |
| `termination_grace_ms` | 2000 | from `shutdown` or `SIGTERM` to the next step. Long enough to flush a file, short enough that a stop is not held |
| `stderr_lines_per_second` | 10 | standard error lines and `failed` reasons, together, copied into the log per extension. Standard error lines beyond it are counted (`stderr_dropped`) and dropped; a reason beyond it is not logged, and the exchange is still counted under `declined` |
| `stderr_line_bytes` | 1024 | a longer standard error line is cut there and marked cut |
| `derived_lines_per_second` | 1000 | derived records accepted per extension, as a bucket that refills at this rate and holds one second's worth |
| `derived_flood_seconds` | 10 | consecutive seconds with a rate refusal before the generation is retired as `flood` |
| `derived_queue_bytes` | 1048576 | 1 MiB of an extension's derived records waiting to be written; beyond it a record is refused at once |
| `derived_sources` | 1024 | source ids one derived record may name |
| `reason_bytes` | 256 | a `failed` result's `reason`, kept escaped and cut there, in the observer's log |

`timeout_ms` is each entry's own, from 1 to 60000. There is no cumulative output budget.

## Messages

### Observer to extension

**`start`**

| member | value |
|---|---|
| `type` | `"start"` |
| `protocol` | `"observer.extension/1"` |
| `extension` | the entry's `name` |
| `session` | the session id |
| `generation` | this generation, a decimal string from `"1"` |
| `processing_revision` | the session's processing revision, which binds the extension entries |
| `write_content` | the configuration's `write_content` |
| `fields` | the fields the entry selects, in this document's order |
| `timeout_ms` | the entry's `timeout_ms` |
| `bounds` | every bound in the table above, by name, `waiting_bytes` as computed for this session |

**`exchange`**

| member | value |
|---|---|
| `type` | `"exchange"` |
| `id` | the exchange's id |
| `connection_id` | its connection's id, the connection record's `id`: a decimal string, unique within the session |
| `index` | the exchange's index in the connection |
| `output` | `{"state": "eligible"}` or `{"state": "excluded", "reason": R}` |
| `exchange` | `{index, complete, request, response, removed[]}` with the selected fields |
| `connection` | the connection record; only with `connection` selected |

**`connection_done`**

| member | value |
|---|---|
| `type` | `"connection_done"` |
| `connection_id` | the connection's id, as its exchanges carried it |
| `count` | the exchange ids issued on the connection, a decimal string; `"0"` where none was |
| `ending` | the connection record's `ending`: `{how, at}`, with `detected` for `unobserved`. Absent only where the observer holds no readable record for a connection that was issued ids ([Connection done](#connection-done)) |
| `connection` | the connection record; only with `connection` selected |

**`session_ending`** and **`shutdown`**: `{"type": "session_ending"}`, `{"type": "shutdown"}`.

### Extension to observer

**`ready`**: `{"type": "ready", "protocol": "observer.extension/1"}`.

**`result`**: `type`, `id`, `outcome`; `changes` with `changed`; `reason` with `failed`, a string the
observer cuts at `reason_bytes`.

**`derived`**: `type`, `sources`, `basis`, `record`.

## Worked examples

Each is one line on the wire, wrapped here to be read.

**`start`**, generation 1 of an extension selecting the two lines, in a session with the default
`limits.events` and one extension:

    {"type": "start", "protocol": "observer.extension/1", "extension": "inventory",
     "session": "20261001T120000Z-4f2a", "generation": "1",
     "processing_revision": "sha256:5b0e...", "write_content": true,
     "fields": ["request.line", "response.line"], "timeout_ms": 250,
     "bounds": {"startup_ms": 5000, "frame_bytes_to_extension": 33554432,
       "frame_bytes_from_extension": 4194304, "in_flight": 4096, "waiting_bytes": 33554432,
       "healthy_ms": 60000, "backoff_min_ms": 100, "backoff_max_ms": 5000,
       "termination_grace_ms": 2000, "stderr_lines_per_second": 10, "stderr_line_bytes": 1024,
       "derived_lines_per_second": 1000, "derived_flood_seconds": 10,
       "derived_queue_bytes": 1048576, "derived_sources": 1024, "reason_bytes": 256}}

**`ready`**:

    {"type": "ready", "protocol": "observer.extension/1"}

**`exchange`**, the first of a connection's three, eligible for output, with the two lines selected:

    {"type": "exchange", "id": "17", "connection_id": "7", "index": 0,
     "output": {"state": "eligible"},
     "exchange": {"index": 0, "complete": true,
       "request": {"state": "present", "message": {"kind": "request", "complete": true,
         "framed": true, "defect": "none", "method": "GET", "target": "/users/42",
         "protocol": "HTTP/1.1"}},
       "response": {"state": "present", "message": {"kind": "response", "complete": true,
         "framed": true, "defect": "none", "status": 200, "reason": "OK",
         "protocol": "HTTP/1.1"}},
       "removed": []}}

**`exchange`**, the last of that connection, one-sided and so excluded from output, sent when the
connection ended, with the request's headers selected and `authorization` removed by the configuration:

    {"type": "exchange", "id": "19", "connection_id": "7", "index": 2,
     "output": {"state": "excluded", "reason": "unpaired_exchange"},
     "exchange": {"index": 2, "complete": false,
       "request": {"state": "present", "message": {"kind": "request", "complete": true,
         "framed": true, "defect": "none",
         "headers": [{"name": "Host", "value": "api.internal"}], "trailers": []}},
       "response": {"state": "absent"},
       "removed": [{"message": "request", "field": "message.headers.authorization",
         "disposition": "removed", "section": "headers"}]}}

**`result`**, one of each:

    {"type": "result", "id": "17", "outcome": "unchanged"}

    {"type": "result", "id": "18", "outcome": "changed",
     "changes": {"response.headers": {"headers": [{"name": "Content-Type", "value": "application/json"},
       {"name": "X-Classified", "value": "internal"}], "trailers": []}}}

    {"type": "result", "id": "19", "outcome": "failed", "reason": "no request line selected"}

**`derived`**, an inferred endpoint summary citing three exchanges:

    {"type": "derived", "sources": ["17", "18", "23"], "basis": "inferred",
     "record": {"method": "GET", "path_template": "/users/{id}",
       "status_classes": {"2xx": 3}, "exchanges": 3, "one_sided": 0, "incomplete": 0}}

**`connection_done`**, for that connection, which ended with its socket closed after three ids were
issued on it:

    {"type": "connection_done", "connection_id": "7", "count": "3",
     "ending": {"how": "socket_closed", "at": {"state": "determined", "domain": "wall",
       "unit": "nanoseconds", "reading": "observer_wall_read", "value": "1759320000123456789"}}}

**`connection_done`** for a connection cut after its first two exchanges were sent, sent when it later
ended with its handle released. What it had not released was discarded, so no third id was issued:

    {"type": "connection_done", "connection_id": "9", "count": "2",
     "ending": {"how": "handle_released", "at": {"state": "determined", "domain": "wall",
       "unit": "nanoseconds", "reading": "observer_wall_read", "value": "1759320004000000000"}}}

**`connection_done`** at session end for a connection still open, with `connection` selected and
`write_content` false, so no id was issued:

    {"type": "connection_done", "connection_id": "8", "count": "0",
     "ending": {"how": "still_open", "at": {"state": "undetermined", "domain": "wall",
       "unit": "nanoseconds"}},
     "connection": {...the connection record...}}

**`session_ending`** and **`shutdown`**:

    {"type": "session_ending"}
    {"type": "shutdown"}

**A derived line as the observer writes it** to `derived-inventory.jsonl`:

    {"version": "observer.derived/1", "extension": "inventory", "session": "20261001T120000Z-4f2a",
     "generation": "1", "processing_revision": "sha256:5b0e...",
     "effects": "extension_declared_not_observer_enforced",
     "sources": ["17", "18", "23"], "basis": "inferred",
     "record": {"method": "GET", "path_template": "/users/{id}", "status_classes": {"2xx": 3},
       "exchanges": 3, "one_sided": 0, "incomplete": 0}}

## Compatibility

**What this protocol promises is narrow**: its version, the message shapes, the lifecycle, and the timeout
and failure behaviour. A later draft changes the version. **It is not a security, privacy or correctness
endorsement of any extension.**
