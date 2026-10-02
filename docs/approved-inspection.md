# Approved artifact inspection

The public entry point is:

```
observer inspect <copied-session-directory> --text
```

A copied session directory contains the sealed `account.json`. Pass each
approved output file explicitly with `--file <path>`; files may hold several
sessions, and `--session <id>` selects one. Without these options, inspection
selects the account's session and reads the stable `approved.jsonl` in the
configured output directory. Copied legacy session-local output remains readable.
The command reads the sealed account, then visits and renders approved artifacts.
It needs no capturing process, configuration, extensions or raw spool. Default
JSON account inspection remains account-only; `--text` exposes approved values.

The reader uses `processing.Artifact`. Each rendered record includes its session,
persisted policy revision, pipeline, sink, route, connection and exchange identity.
Header and trailer values are quoted; body bytes are decoded from base64 and
quoted. Message directions and offsets identify where retained values came
from. The persisted actual connection ending, unplaced count state and reason,
and all reconstruction truncation fields stay visible. An indeterminate suffix
does not become an empty suffix or an observed transport close.

Missing or empty approved output fails text inspection. Malformed or unsupported
records, incomplete final lines and output errors also fail. Earlier complete
records may have been printed before a later error; the command must still fail.
A sealed account alone is not evidence that approved values were displayed.
Legacy spool reconstruction is not a fallback for this path.

Independent acceptance authors can use the public binary or the existing
`run([]string{"inspect", directory, "--text"}, writer)` seam in package main.
Reader unit consumers use `ReadArtifacts(fs.FS, func(Artifact) error) error` and
`RenderArtifact(io.Writer, Artifact) error`. Output assertions must check actual
permitted values and their provenance, not merely a successful exit status.
After capture ends, changing local policy must leave those values and their
capture-time policy revision unchanged.

## Policy exclusion evidence

`policy_exclusions` records actual removals by processing policy from retained
messages, per pipeline. It never carries a removed value.

The worker writes `observer.approved/3`. Each entry names the exchange index,
`request` or `response`, the `field` removed and a `disposition`:

| field | disposition | written when |
|---|---|---|
| `message.headers.<name>` | `removed` | a header or trailer was removed; `section` is `headers` or `trailers` |
| `message.body` | `removed` | `remove-body`, or `reduce-body-to-structure` with no structure derived, removed a body with bytes |
| `message.body` | `removed_undecidable` | a field operation removed a body with bytes whole: not strictly valid JSON within the bounds, a request body not admitted as urlencoded, or an admitted body holding a malformed percent escape |
| `message.body.values` | `values_removed` | `reduce-body-to-structure` removed the bytes of a body whose structure was derived |
| `message.target.query` | `removed` | `remove-query` removed a query; the target had a `?` |
| `message.target.query` | `removed_undecidable` | `remove-query-parameters` removed a query whole because it held a malformed percent escape |
| `message.query.<name>` | `removed` | a query parameter matched a configured name |
| `message.form.<name>` | `removed` | an admitted urlencoded request body parameter matched a configured name |
| `message.body.json<pointer>` | `removed` | a JSON member or element matched the configured pointer, written as configured |

`section` is present only for a header field; `name` is absent. An entry exists
only where the component was present, which is what separates a field excluded
from a field never present. Each entry occurs once per exchange and message
however many occurrences or slots it covers. Replacement and truncation, of a
header or of a JSON value, add no entry.

A body removed whole keeps `body.length` and `framing`, has an empty
`body.kept` and has `structure.state` `removed`. A body whose values were
removed has an empty `body.kept` and keeps its derived `structure`. A body with
a JSON member removed or replaced keeps its other bytes exactly, and its
structure is derived again from them. A reader therefore tells apart no body
(length 0), a body removed by policy, a body with its values removed and a kept
body, and a request target whose query was removed from one that had none.

`observer.approved/1` artifacts are still read. Their entries carry `section`
and a lowercase header `name`, with no `field` or `disposition`, and record
`remove-headers` removals only.

In every version the reader distinguishes:

- A populated array: the named fields were excluded by policy.
- An empty array: no fields were excluded in the retained population. A field
  absent from both a retained message and this complete exclusion list was not
  present there; this says nothing about an indeterminate suffix.
- An absent key or explicit `null`: exclusion evidence is unavailable. Neither
  means none excluded. Re-encoding a legacy artifact through the public Go type
  emits `null` for an originally absent key.

Text inspection preserves the artifact as indented JSON, then prints the
exclusion disposition and quoted, decoded body bytes with the body's structure
state. The JSON retains every published metadata and reconstruction field,
including provenance and limits. It escapes header and trailer values; decoded
bodies use Go string quoting.

## Lines and exchange ids

The canonical envelope is in the [record contract](../contract/record/record.md#approved-line-envelope).

The writer emits `observer.approved/3`. Each line carries `session`,
`policy_revision`, `route`, and `connection` metadata. The metadata can be
provisional on an exchange released before retirement; its ending never asserts
an observed close without evidence.

- `record: "exchange"` is emitted only on the exchanges route and carries `exchange_id` (a positive decimal string),
  `index` (the zero-based index within the connection), and `reconstruction`
  containing exactly one complete request/response pair. Its exchange index
  equals the line's `index`. Only processed, policy-eligible content is present.
- `record: "connection"` is emitted once at retirement, on the connections route.
  It has final connection metadata, no exchange id, index or reconstruction.
  It carries any `reconstruction_truncation` describing the incomplete suffix;
  exchange lines do not carry that retirement evidence.
- Every line has present `policy_exclusions`, `extension_outcomes` and
  `replacement_exclusions` lists. On an exchange they refer only to that
  exchange's index; on a connection they are empty.

Ids are issued monotonically within the session before delivery, and never
reused. An id denotes the same connection and index on every route and in every
extension. Indexes continue across releases of a long connection. Dropping a
line cannot renumber any later exchange. With `write_content` false, no exchange
line is emitted and no exchange id is issued. Version 3 has no `exchange_ids`
range. Readers retain support for versions 1 and 2 under their historical rules;
a version 2 line has its connection's contiguous id range.

## Delivery and retained bytes

`approved.jsonl` and `derived-<extension>.jsonl` are stable paths under the
configured directory, opened in append mode across sessions. The session's own
directory retains its account and control state. Rotation and retention belong
to the operator; the account counts attempts and outcomes, never a sink inventory.

Enqueue is the release decision, ordered against invalidation. Only immutable,
fully processed lines enter the byte-bounded queue. A line enqueued before a
later invalidation may still be written. Full queues drop immediately. Counts
separate authorized, written, failed, dropped and pending lines. Failed means a
failed attempt, possibly after a partial write, never proven absence. It is not
retried; the next record starts on a new line and damaged records are malformed.
Unavailable destinations do not prevent monitoring and can recover by reopen.
Shutdown is bounded and counts remaining pending lines as discarded. An in-flight
write may still complete later; discard does not prove absence from the file.

The Go `sink.Sink` boundary supplies `Write`, `Reopen` and `Close`.
`sink.Queue.Enqueue` transfers the line's retained-byte charge before input
reservations are refunded. `Stats.PendingBytes` counts queued and in-flight
bytes together; `HighWaterBytes` records their maximum. `processing.OpenWriter`
accepts a `WriterOptions.OpenSink` factory for deterministic boundary tests.

`ReadArtifactFiles(fs.FS, []string, session, visitor)` reads explicit files and
filters by session. It claims nothing about missing lines between files.
Inspection accepts `--session <id>` and `--file <path>` repeated with `--text`;
without explicit files it reads the stable approved file beside the session
directory. Malformed records fail inspection without quoting their content.

## Extension outcomes

Every written exchange records what each configured extension did to it, in
`extension_outcomes`, one entry per exchange and extension, in the order the
extensions ran:

    "extension_outcomes": [
      {"exchange": 0, "extension": "classify", "outcome": "changed",
       "changed": ["response.headers"], "overwritten": []},
      {"exchange": 0, "extension": "inventory", "outcome": "unchanged"}
    ]

| member | value |
|---|---|
| `exchange` | the exchange's `index` in this line |
| `extension` | the configured name |
| `outcome` | `unchanged`, `changed` or `failed` |
| `changed` | with `changed`: the fields its accepted answer replaced |
| `overwritten` | with `changed`: those of them a later extension replaced again, so they are not what is written |
| `reason` | with `failed`: one of the protocol's reasons ([PROTOCOL.md](../contract/extension/PROTOCOL.md)) - `timeout`, `crash`, `protocol`, `oversized_frame`, `unknown_id`, `flood`, `malformed`, `not_given`, `read_only`, `removed_content`, `excluded`, `declined`, `unavailable`, `busy`, `too_large` |

A field in `changed` and not in `overwritten` is the extension's change as
written, after the configuration's rules ran over it again. With no extension
configured the list is empty. A connections-route line, which carries no
exchange, has an empty list.

**Removals from replacement content are recorded apart.** Each accepted change
goes through `remove`, `mask`, `truncate` and `body_values` again. What `remove`
takes out of a replacement is listed in `replacement_exclusions`, never in
`policy_exclusions`, with the extension that supplied it:

    "replacement_exclusions": [
      {"exchange": 0, "message": "request", "field": "message.headers.authorization",
       "section": "headers", "disposition": "removed", "extension": "classify"}
    ]

Its entries have the members, forms and dispositions of `policy_exclusions`,
and `extension`. `policy_exclusions` records only what was removed from captured
content, so a reader tells a header the application sent and the configuration
removed from one an extension added back and the configuration removed again.
The list is empty where nothing was removed from a replacement.

## Reader validation

`ReadArtifacts` reads `approved.jsonl`; `ReadArtifactFiles` reads each explicitly
named file in order and selects the requested session. Both visit LF-terminated records. It requires a non-nil filesystem and visitor. A missing file
preserves `fs.ErrNotExist`; an empty file returns `ErrNoArtifacts`. A visitor
error is returned unchanged and stops reading. Read failures, a malformed line
(including a blank line), an unsupported artifact version and an unterminated
final line fail with the record number. A close failure also fails inspection.
Diagnostics do not quote malformed record content.

Both reading and rendering validate these structural requirements:

- The artifact version is `observer.approved/3`, `observer.approved/2` or `observer.approved/1`;
  policy revision, pipeline, sink and route kind are nonempty. Connection
  record kind/version and identity are present.
- A reconstruction has the published record kind/version, names the same
  connection and process, and contains at least one exchange. Exchange indexes
  are unique and nonnegative. Each exchange is complete with present, complete,
  framed request and response messages of the corresponding kind and no defect.
  Body encoding is base64 and its retained bytes decode. Message directions are
  sent or received; stream offsets are unsigned decimal integers with end at
  least start.
- Truncation requires a reconstruction or a version 3 retirement line, state `truncated`, suffix
  `indeterminate`, and one or two stops ordered sent then received, without
  repetition. Offsets are unsigned decimal integers; evidence cannot precede
  the exclusion boundary. Reasons are the codes declared in `TruncationStop`.
  On historical reconstruction lines, unplaced must be undetermined bytes, without a numeric value, with reason
  `reconstruction_truncated`. That reason also requires truncation evidence.
- Each exclusion is a unique entry referring to an existing retained exchange
  and to request or response. Metadata-only records carry no populated
  exclusion evidence. Version 3 retirement lines can carry truncation evidence.
- In `observer.approved/1`, an entry names headers or trailers and a lowercase
  HTTP field token, and the named field cannot also be present in that message
  section. No structure state is `removed`.
- In `observer.approved/2` and `/3`, an entry's field is one of the forms above, with the
  disposition its row names, and `name` is absent. A header entry names headers
  or trailers and the header cannot also be present there; no other entry has a
  section. `message.target.query`, `message.query.<name>` and
  `message.form.<name>` entries are on a request, and after a
  `message.target.query` entry, `removed` or `removed_undecidable`, its target
  has no `?`. A `message.body` entry requires an empty `body.kept` and structure
  state `removed`, and a structure state `removed` requires such an entry. A
  `message.body.values` entry requires an empty `body.kept` and structure state
  `derived` or `removed`. Parameter names and pointers follow the
  configuration's name and pointer rules
  ([CONFIG.md](../contract/config/CONFIG.md)).
- In `observer.approved/2`, `exchange_ids` is present: `count` a decimal
  string, and `first` and `last` positive decimal strings with `count` equal to
  `last` - `first` + 1 where `count` is not `"0"`, and absent where it is. Every
  exchange index of the line is below `count`.
- `extension_outcomes` and `replacement_exclusions` are present lists. An
  outcome refers to a retained exchange, names a configured extension once per
  exchange, and carries `changed` and `overwritten` only for `changed`, with
  `overwritten` a subset of `changed`, and `reason` only for `failed`, from the
  protocol's reasons. A replacement exclusion follows the `policy_exclusions`
  rules and names an extension whose outcome for that exchange is `changed`.
- An entry's form, identity and disposition are always checked. **An entry's
  agreement with the written message** - the header absent, the body's kept
  bytes empty and its structure `removed`, the target without `?` - **is
  checked only where the entry's author owns the written component**:
  `policy_exclusions` where no extension's change of that component is
  written, a replacement exclusion where its extension's change is the one
  written. A component an extension replaced is not the captured one, and a
  component a later extension replaced again is not the earlier one's.


Unknown JSON members are ignored by the typed decoder. These are structural
readability checks, not a re-execution of capture policy. The text renderer
applies the same checks before printing a record and returns output failures,
including short writes. The sealed account's text output also propagates write
failures. Default JSON inspection remains account-only.


