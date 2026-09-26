# Approved artifact inspection

The public entry point is:

```
observer inspect <copied-session-directory> --text
```

The copied directory contains the sealed `account.json` and `approved.jsonl`
only. The command reads the sealed account, then visits and renders the approved
artifacts. It does not require the capturing process, original directory,
configuration, pack manifests or raw spool. The default JSON account inspection
retains its existing account-only meaning; `--text` exposes approved values.

The reader uses the existing `processing.Artifact` representation without
changing it. Each rendered record includes the persisted policy revision,
pipeline, sink and route kind, connection metadata, and any reconstruction.
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

The worker writes `observer.approved/2`. Each entry names the exchange index,
`request` or `response`, the `field` removed and a `disposition`:

| field | disposition | written when |
|---|---|---|
| `message.headers.<name>` | `removed` | a header or trailer was removed; `section` is `headers` or `trailers` |
| `message.body` | `removed` | `remove-body`, or `reduce-body-to-structure` with no structure derived, removed a body with bytes |
| `message.body` | `removed_undecidable` | a field operation removed a body with bytes whole: not strictly valid JSON within the bounds, or a request body not admitted as urlencoded |
| `message.body.values` | `values_removed` | `reduce-body-to-structure` removed the bytes of a body whose structure was derived |
| `message.target.query` | `removed` | `remove-query` removed a query; the target had a `?` |
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

In both versions the reader distinguishes:

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

## Reader validation

`ReadArtifacts` visits LF-terminated JSON records in file order and owns only
`approved.jsonl`. It requires a non-nil filesystem and visitor. A missing file
preserves `fs.ErrNotExist`; an empty file returns `ErrNoArtifacts`. A visitor
error is returned unchanged and stops reading. Read failures, a malformed line
(including a blank line), an unsupported artifact version and an unterminated
final line fail with the record number. A close failure also fails inspection.
Diagnostics do not quote malformed record content.

Both reading and rendering validate these structural requirements:

- The artifact version is `observer.approved/2` or `observer.approved/1`;
  policy revision, pipeline, sink and route kind are nonempty. Connection
  record kind/version and identity are present.
- A reconstruction has the published record kind/version, names the same
  connection and process, and contains at least one exchange. Exchange indexes
  are unique and nonnegative. Each exchange is complete with present, complete,
  framed request and response messages of the corresponding kind and no defect.
  Body encoding is base64 and its retained bytes decode. Message directions are
  sent or received; stream offsets are unsigned decimal integers with end at
  least start.
- Truncation requires a reconstruction, state `truncated`, suffix
  `indeterminate`, and one or two stops ordered sent then received, without
  repetition. Offsets are unsigned decimal integers; evidence cannot precede
  the exclusion boundary. Reasons are the codes declared in `TruncationStop`.
  Unplaced must be undetermined bytes, without a numeric value, with reason
  `reconstruction_truncated`. That reason also requires truncation evidence.
- Each exclusion is a unique entry referring to an existing retained exchange
  and to request or response. Metadata-only records carry no populated
  exclusion or truncation evidence.
- In `observer.approved/1`, an entry names headers or trailers and a lowercase
  HTTP field token, and the named field cannot also be present in that message
  section. No structure state is `removed`.
- In `observer.approved/2`, an entry's field is one of the forms above, with the
  disposition its row names, and `name` is absent. A header entry names headers
  or trailers and the header cannot also be present there; no other entry has a
  section. `message.target.query`, `message.query.<name>` and
  `message.form.<name>` entries are on a request, and after a
  `message.target.query` entry its target has no `?`. A `message.body` entry
  requires an empty `body.kept` and structure state `removed`, and a structure
  state `removed` requires such an entry. A `message.body.values` entry requires
  an empty `body.kept` and structure state `derived` or `removed`. Parameter
  names and pointers follow the configuration's name and pointer rules
  ([CONFIG.md](../contract/config/CONFIG.md)).

Unknown JSON members are ignored by the typed decoder. These are structural
readability checks, not a re-execution of capture policy. The text renderer
applies the same checks before printing a record and returns output failures,
including short writes. The sealed account's text output also propagates write
failures. Default JSON inspection remains account-only.

The reader's own tests cover readable output, failure paths, and all four wire
forms at the reader/renderer boundary, including literal null produced by
re-encoding a legacy artifact through the public type. The independent
condition-2 engagement covers the broader protected-value/suffix absence and
exclusion-evidence guarantee; task acceptance waits for that engagement.
