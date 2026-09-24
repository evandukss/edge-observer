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

`policy_exclusions` records actual `RemoveHeaders` removals from retained
messages, per pipeline. Each entry names the exchange index, request or
response, headers or trailers, and lowercase field name. It never carries the
removed value. Replacement and truncation leave a field present and do not add
entries. The reader distinguishes:

- A populated array: the named fields were excluded by policy.
- An empty array: no fields were excluded in the retained population. A field
  absent from both a retained message and this complete exclusion list was not
  present there; this says nothing about an indeterminate suffix.
- An absent key or explicit `null`: exclusion evidence is unavailable. Neither
  means none excluded. Re-encoding a legacy artifact through the public Go type
  emits `null` for an originally absent key.

Text inspection preserves the artifact as indented JSON, then prints the
exclusion disposition and quoted, decoded body bytes. The JSON retains every
published metadata and reconstruction field, including provenance and limits.
It escapes header and trailer values; decoded bodies use Go string quoting.

## Reader validation

`ReadArtifacts` visits LF-terminated JSON records in file order and owns only
`approved.jsonl`. It requires a non-nil filesystem and visitor. A missing file
preserves `fs.ErrNotExist`; an empty file returns `ErrNoArtifacts`. A visitor
error is returned unchanged and stops reading. Read failures, a malformed line
(including a blank line), an unsupported artifact version and an unterminated
final line fail with the record number. A close failure also fails inspection.
Diagnostics do not quote malformed record content.

Both reading and rendering validate these structural requirements:

- The artifact version is supported; policy revision, pipeline, sink and route
  kind are nonempty. Connection record kind/version and identity are present.
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
- Each exclusion is a unique tuple referring to an existing retained exchange,
  request or response, and headers or trailers. Names are lowercase HTTP field
  tokens. The named field cannot also be present in the same message section.
  Metadata-only records carry no populated exclusion or truncation evidence.

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
