# The configuration and the pack

Status: Live, draft contracts `observer.config/1` and `observer.pack/1`. **These remain draft
contracts.** No machine-readable schema is published; the examples, such as
[examples/observer.config.json](examples/observer.config.json), show the shapes, and the reader in this
directory ([read.go](read.go), [compile.go](compile.go)) enforces them. This document is the contract.
Where the two disagree this document is corrected first.

A user writes one configuration file: what to watch, where the output goes, and what to remove, mask and
truncate. A pack is a second file of rules, installed beside it. The observer compiles the two directly
into the plan it runs. **There are no pipelines, slots or components to write**: the observer runs the
rules in one fixed, published order.

## The configuration file

    {
      "version": "observer.config/1",
      "output": "/var/lib/observer",
      "log": "stdout",
      "watch": [
        {"name": "api", "exe": "/usr/bin/php", "args": ["/srv/api/main.php"], "children": "all"}
      ],
      "ignore": [{"exe": "/usr/bin/curl"}],
      "libraries": [],
      "write_content": true,
      "remove": {
        "headers": ["authorization", "cookie"],
        "query": ["token"],
        "query_string": false,
        "form": ["card_number"],
        "json": {"request": ["/card/number"], "response": ["/items/*/pan"]},
        "bodies": [],
        "body_values": []
      },
      "mask": {"headers": {"x-api-key": "withheld"}, "json": {"response": {"/email": "withheld"}}},
      "truncate": {"headers": {"x-trace-id": 8}},
      "limits": {"output_mib": 64, "events": 16384, "state_every_seconds": 30},
      "packs": ["credentials"]
    }

**Required:** `version`, `output` and `watch`. Every other key is optional; absent means the value shown
above for `log`, `write_content`, `limits` and each `children`, and empty for the rest.

**The reader is strict at every level.** An unknown key (`"remvoe"`), a key written in another case
(`"Remove"`), a key written twice, a value of the wrong type, a missing required key and anything after
the document are each refused, naming the key by its path (`remove.remvoe`, `watch[0].children`). A
document at another version is refused as `unknown_version`, naming the version this reader reads, and
a pack given as a configuration, or the reverse, is refused by its version.

### Keys

| key | value |
|---|---|
| `output` | an absolute path: where each session's directory is written |
| `log` | `stdout`, or an absolute path |
| `watch` | at least one entry, each a `name` and at least one of `exe`, `args`, `cgroup`, `pid` (`{pid, start, boot}`), `port`, `interface`, with `children` |
| `ignore` | matches never watched, in the conditions `watch` uses, without `name` or `children`. The account numbers them in their order: `ignore N` |
| `libraries` | approved TLS library builds, `{build_id, symbols: {SSL_read: <offset>}}`. Empty means any. The shape is stated; no tool prints it |
| `write_content` | `true` writes exchanges and connection records. `false` writes connection records only; **plaintext is still read into memory and processed, and never written** |
| `remove`, `mask`, `truncate` | the rules, below |
| `limits` | `output_mib`, the approved output's allowance; `events`, the events admitted to processing; `state_every_seconds`, how often the log restates the session's state |
| `packs` | pack names, each read from `packs/<name>.json` beside the configuration (below) |

**A watch entry's conditions are matched as the observer's admission reads them.** `exe` is an absolute
path. `args` are the arguments after `argv[0]`; an empty list means a process run with none, and absent
means any. `cgroup` is an absolute cgroup path. `pid` names one process instance by its pid, start time
and boot, never a pid number alone. `port` is a listening port, optionally with an `interface`. Every
condition an entry names must hold.

**`children` says which descendants of a watched process are watched too:**

| `children` | watched |
|---|---|
| `all` (the default) | the descendants running when the watch is resolved, and every one created afterwards |
| `existing` | the descendants running when the watch is resolved |
| `none` | no descendant |

The account states each target's answer as its mode: `follow`, `existing` or `none`.

## The rules

**`remove`: every entry is a guarantee.** It is recorded as a mandatory exclusion, and the observer
refuses to start when it cannot enforce one.

| key | removes |
|---|---|
| `headers` | the named headers, trailers included, in both messages |
| `query` | the named request query parameters |
| `query_string` | `true`: the request target from its first `?` |
| `form` | the named parameters of an urlencoded request body |
| `json` | the JSON members or elements the pointers match, keyed by message: `{"request": [...], "response": [...]}` |
| `bodies` | `request` and/or `response`: the whole body |
| `body_values` | `request` and/or `response`: every value of a JSON body, keeping its names and nesting. A body with no derived structure is removed whole |

**`mask`** replaces a value and keeps the field: `headers` `{name: value}` and `json`
`{message: {pointer: value}}`. **It never counts as removal.**

**`truncate`** keeps at most the given number of bytes of each named header's value: `headers`
`{name: length}`.

Header names are HTTP token names, compared ignoring case. Pointers, parameter names and values follow the
argument rules below.

### How rules combine

**Removal wins over every other rule and is never a conflict. Two rules that would keep different values
for one field are refused** (`rule_conflict`), naming both documents and keys. That covers two masks of
one field, two truncations of one header, a mask and a truncation of one header, and the same conflicts
between the configuration and a pack. The same value written twice is one rule. JSON pointers overlap
where they MAY match one field: one token list is a prefix of the other, and each pair of tokens is equal
under simple case folding or one of them is `*`.

**The rules run in one fixed order: remove, then mask, then truncate, then body_values.** Within
remove, the order is headers, the query string, query parameters, bodies, form, request JSON, response
JSON. A rule that runs later sees what earlier rules left. Nothing a user writes changes the order.

**Every rule applies to every `watch` entry.** Different rules for different watched programs are not in
this draft.

### JSON and form rules on the request together

When `form` and a request JSON rule (`remove.json.request` or `mask.json.request`) are both present, a
request body is dispatched by what it is:

| request body | goes to |
|---|---|
| strictly valid JSON, and no `Content-Type` field names a form media type | the JSON rules |
| strictly valid JSON, and some `Content-Type` field names a form media type | removed whole, `removed_undecidable` |
| not strictly valid JSON, and admitted as urlencoded (below) | the form rules |
| anything else with bytes | removed whole, `removed_undecidable` |

**"Names a form media type"** means the field's value contains `application/x-www-form-urlencoded` or
`multipart/form-data`, compared ignoring case, in ANY `Content-Type` field, headers or trailers. It is
broad on purpose: **the combined operation never decides less for a body than either grammar's rule
decides alone.** Form admission is positive, so a body it does not admit never reaches rules that keep
what they do not match. JSON under `application/json`, `text/plain` or no label is read by the JSON
rules. Where only one grammar has request rules, every other non-empty body in that message is removed
whole.

## What the rules compile to

The observer compiles the rules into one `exchanges` pipeline, written only when `write_content` is
`true`, and one `connections` pipeline, which carries connection metadata and never a message. Both
route to the sink `account`. Every approved line's `route` names one of these: they are published
constants, not names a user writes.

Each rule key compiles to one of the operations below, with its arguments; a mask or a truncation is one
operation per distinct value or length. A user never names an operation, and the observer checks every
operation's arguments again before it runs. A refusal from that check is an observer defect
(`internal_defect`), never the user's error.

### Header operations

Each acts on every matching field in both headers and trailers, in both messages of an exchange,
including repeated and differently cased names, and never adds an absent field:

| operation | compiled from | action |
|---|---|---|
| `remove-headers` | `remove.headers` | remove the named fields and their values |
| `replace-header-values` | `mask.headers` | replace each selected value with the value given |
| `truncate-header-values` | `truncate.headers` | keep at most the given number of bytes of each selected value |

A header name is an HTTP token, resolved to lowercase. A mask value is at most `MaxHeaderValueBytes`
printable ASCII bytes (empty is allowed); a length is between zero and `MaxHeaderValueBytes`.

### Body and query operations

**The guarantee is a pair.** The component operations - `remove-body`, `reduce-body-to-structure` and
`remove-query` - never parse inside what they remove, cannot fail to decide, and hold whatever the
application. The field operations parse, and they hold only for an application that reads the part as
they do: JSON members by the rules below, and parameters by their names exactly as sent, once
percent-decoded. An application that reads names differently needs the component operations for a
guarantee. Where a field operation cannot decide, it removes the whole body or query, never less.

| operation | compiled from | action |
|---|---|---|
| `remove-body` | `remove.bodies` | drop the body bytes of each selected message; its length and framing are kept and its structure becomes `removed` |
| `reduce-body-to-structure` | `remove.body_values` | drop the body bytes and keep the JSON structure already derived (member names, nesting, value kinds). Where none was derived the body is removed whole |
| `remove-query` | `remove.query_string` | drop the request target from its first `?`; the path is kept |
| `remove-json-fields` | `remove.json` | remove every member or element a pointer matches |
| `replace-json-values` | `mask.json` | replace the value of every member or element a pointer matches with the value given, written as a JSON string |
| `remove-form-fields` | `remove.form` | remove the named parameters from an admitted urlencoded request body |
| `remove-query-parameters` | `remove.query` | remove the named parameters from the request target's query |
| `request-body-fields` | `remove.form` with a request JSON rule | read each request body by the grammar it allows, as above; removal is applied before masking |

`reduce-body-to-structure` discloses value kinds, which are derived from the values: whether a string is
written as a decimal numeral, and whether it is short or long. **Member names are body content and this
operation keeps them**: an object keyed by a card number or an email address keeps the key.

Argument rules:

- A pointer is an RFC 6901 JSON pointer of at most `MaxPointerBytes` bytes of valid UTF-8 and at most
  `MaxPointerTokens` reference tokens. It begins with `/`; the empty pointer, which names the whole
  document, is refused, since `bodies` removes a whole body. In a token `~` is followed by `0` or `1`,
  read as `~` and `/`; any other `~` is refused.
- A parameter name is 1 to `MaxParameterNameBytes` bytes, each printable ASCII other than space (`!` to
  `~`). It is compared literally with the decoded name, so `card.number` and `items[]` name exactly
  those parameters.
- A JSON mask value is at most `MaxJSONValueBytes` printable ASCII bytes (space to `~`); empty is
  allowed. It is escaped as a JSON string where it is written.

**A JSON pointer matches more than RFC 6901 says.** A token applied to an object matches every member
whose name, with escapes decoded, equals the token exactly OR under Unicode simple case folding, and
every such member is acted on, duplicates included. A token applied to an array matches the element at
that index (`0`, or digits not starting with `0`). The token `*` matches every element of an array and
every member of an object. A pointer matching nothing changes nothing. Where one match lies inside
another, the outer one is acted on.

**A JSON body is acted on only when it is strictly valid**: one JSON value per RFC 8259 with only JSON
whitespace around it, valid UTF-8 throughout, no byte order mark, no escape naming an unpaired UTF-16
surrogate, nesting at most `MaxJSONFieldDepth` deep and at most `MaxJSONFieldNodes` values. Every other
non-empty body in a selected message - form, multipart, XML, text, a mislabelled body - is removed whole
as undecidable. Outside `request-body-fields` the `Content-Type` label is not consulted: a JSON body
labelled otherwise is still read, and a body labelled JSON that is not JSON is removed.

**The rest of the bytes are spliced, never re-serialised.** A removed member or element goes with
exactly one adjacent comma: the one after it, or the one before it where it was last. Whitespace, key
order, escapes and number spelling everywhere else are kept byte for byte. A replaced value is the only
span that changes. The structure is derived again from the retained bytes.

**A urlencoded body is admitted positively.** The form rules act on request bodies only. A request body
is admitted only when the request AS PARSED carries exactly one `Content-Type` field, counting headers
and trailers, whose media type - the value before any `;`, without surrounding spaces and tabs - is
`application/x-www-form-urlencoded`, compared ignoring case. Every other non-empty request body is
removed whole as undecidable, multipart included. Response bodies are not touched.

**Body operations read header facts from the message as parsed, never as processed.** A header rule
that ran earlier - removing or masking `content-type` - does not change what a body rule admits.

**Parameter names match exactly as sent.** A query, or an admitted body, is split into parameters on
`&` alone; `;` is an ordinary byte. A parameter's name is its text before the first `=`, or all of it.
The name is decoded once - `+` is a space and `%` followed by two hexadecimal digits is that byte - and
the parameter is removed when its decoded name equals a configured name exactly. Nothing else is read
into a name: `card.number`, `card_number[]` and ` card_number` are other names than `card_number`. **A
`%` not followed by two hexadecimal digits, anywhere in a name or a value, leaves the part
undecidable**: the whole query goes, as `query_string` removes it, or the whole body, and the evidence
says `removed_undecidable`.

A removed run of parameters goes with exactly one adjacent `&`: the one after it, or the one before it
where the run is last. Empty parameters and every other byte are kept.

**Not covered**, and no rule here reaches it:

- a value encapsulated inside another value: JSON in a JSON string, a form field such as `payload=`
  holding JSON, base64, a JWT. The application decodes it and no rule looks inside;
- a secret in the request PATH, such as `/reset/<token>`;
- a URL inside a header value, such as `location` or `referer`; `remove.headers` removes the header;
- an application that reads the query, the form body and top-level JSON members under one name: it
  needs one removal per grammar;
- an application that reads a parameter name other than exactly as sent - rewriting characters in it,
  reading brackets as nesting, or splitting on `;` - for which the parameter rules are not sound;
  `query_string` and `bodies` hold for it.

## Exclusions, and what the approved output says

Every `remove` entry, the configuration's or a pack's, is a mandatory exclusion of one field, named by
GRAMMAR, so its name promises nothing about a framework:

| field | written as | what is removed |
|---|---|---|
| `message.headers.<name>` | `remove.headers` | the header, trailers included |
| `message.target.query` | `remove.query_string` | the request target from its first `?` |
| `message.query.<name>` | `remove.query` | the query parameter |
| `message.form.<name>` | `remove.form` | the urlencoded request body parameter |
| `message.body.json<pointer>` | `remove.json` | the JSON member or element, in the message named |
| `message.body` | `remove.bodies` | the body of the message named |
| `message.body.values` | `remove.body_values` | every body value of the message named; names, nesting and value kinds may stay |

**The observer refuses to start unless the plan it compiled enforces every one.** It checks the plan
against the documents as it read them: every `remove` entry must have its exclusion AND an operation that
removes that field on the exchanges route. A plan that does not is refused as `internal_defect` - the
observer's defect, and it fails closed. A mask or a truncation satisfies no removal. Connection records
carry metadata only and cannot contain these fields.

**Every removal is recorded in the approved output**, `observer.approved/2`, as an entry naming the
exchange, the message, the field and a disposition - `removed`, `values_removed`, or
`removed_undecidable` for a whole body or query a field rule could not decide - and only where the
component was present, which is what separates excluded from never present. A mask and a truncation add
no entry.

## Limits

The reader checks every limit a user can reach, in the user's terms, naming the key and the index of the
entry past the limit (`limit_exceeded`). The limits count the configuration and its packs together, as
merged:

| what | at most |
|---|---|
| names in `remove.headers`, `mask.headers` and `truncate.headers`, each | `MaxHeaderNames` |
| names in `remove.query` and `remove.form`, each | `MaxFieldSelectors` |
| pointers in `remove.json` and `mask.json`, each per message | `MaxFieldSelectors` |
| enabled packs | `MaxProcessingPacks` |
| the configuration and its enabled packs, in bytes | `MaxProcessingBytes` |
| `limits.output_mib`, `limits.events`, `limits.state_every_seconds` | `MaxOutputMiB`, `MaxEvents`, `MaxStateEverySeconds`, and at least 1 |

The internal bounds are sized from what the reader can emit, so a configuration the reader accepts
compiles within them. `MaxJSONFieldDepth` and `MaxJSONFieldNodes` bound what a JSON rule reads at run
time; a body past either is removed whole as undecidable. The constants are defined once, in
[file.go](file.go) and [processing.go](processing.go).

## Refusals

Each refusal names its document - `configuration`, or `pack:<name>` - and the key it is about.

| reason | when |
|---|---|
| `unknown_version` | the document is at another version, or is a pack given as a configuration or the reverse |
| `malformed` | the document is not JSON |
| `unknown_key` | a key the format does not define, including a defined key written in another case |
| `duplicate_key` | a key written twice in one object |
| `wrong_type` | a value of the wrong JSON type |
| `trailing_content` | anything after the document |
| `missing_key` | a required key is absent |
| `invalid_value` | a value outside its rules: a relative path, a header name that is not a token, a pointer, a length, a limit below 1 |
| `limit_exceeded` | an entry past one of the limits above |
| `duplicate_name` | two watch entries with one name, or a pack enabled twice |
| `rule_conflict` | two rules that would keep different values for one field |
| `unknown_pack` | an enabled pack that was not supplied |
| `configuration_too_large` | the configuration and its enabled packs exceed `MaxProcessingBytes` |
| `pack_name_invalid` | a pack name that does not meet the name rule (below) |
| `pack_name_mismatch` | a pack that names itself other than the name it is enabled by |
| `internal_defect` | the observer's own check refused what it compiled, or the plan does not enforce a `remove` entry. Never the user's error |

## The pack

    {
      "version": "observer.pack/1",
      "name": "credentials",
      "remove": {"headers": ["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"]}
    }

A pack is `version`, `name` and any of `remove`, `mask` and `truncate`, in the configuration's shapes.
**A pack adds rules; it cannot weaken the configuration's.** Its rules combine with the configuration's
as above. The shipped example pack is `credentials`,
[examples/packs/credentials.json](examples/packs/credentials.json).

### Where the observer reads a pack

**A pack named N that the configuration enables is read from `packs/N.json` in the directory holding the
configuration file.** That directory is the lexical parent of the configuration's path, made absolute
once where the command receives it, so a relative path means the same thing to a detached session and to
a reload as to the command that named it. Only enabled packs are read, in the order `packs` lists them.
Nothing is found by listing the directory, by a search path or by fetching, and a file there that the
configuration does not enable is never opened. A configuration with no `packs` reads nothing there.

**Installing a pack is placing its file there; activating it is naming it in `packs` and starting a
session.** The pack's `name` must equal N. N must match `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`, checked
before any file is opened, so a name cannot reach outside that directory. The file is opened without
waiting for a writer and must be a regular file before a byte of it is read. The configuration and its
enabled packs together are held to `MaxProcessingBytes`, and no more than one byte past it is read. A
link is followed, as the configuration's own path is.

A pack that cannot be read as the one named is refused before capture, with a nonzero exit. The finding
names the `packs` entry that enabled it, and its detail names the path tried. It never means continuing
without the pack:

| reason | when |
|---|---|
| `unknown_pack` | no file exists at `packs/N.json`, including a link to nothing |
| `pack_unreadable` | the file exists and cannot be opened or read, including a loop of links |
| `pack_not_regular_file` | the path is a directory, a named pipe, a socket or a device |
| `configuration_too_large` | the configuration and the enabled packs read so far exceed `MaxProcessingBytes`; no pack after it is read |

A pack that is read is then refused by the reader, under document `pack:N`, as any document is.

**The observer does not authenticate packs.** The operator controls the integrity of the configuration,
the packs and the directories through which either can be replaced: an observed participant or any
other untrusted user must not be able to write them. There is no ownership, signature or link rule on
the pack file, because the configuration file is read without one and a rule on the pack alone would be
an assurance the rest of the path does not back. The pack's identity in a session is its exact bytes,
bound into the session's revisions; that is identity, not authentication.

## Reload and restart

**The processing revision covers `remove`, `mask`, `truncate`, `write_content`, `packs` and the packs'
bytes, and nothing else. Reload adds `watch` entries; every other change needs a restart,** including
reordering `ignore`.

A running session executes the plan it compiled when it started. `reload` rereads the configuration and
every enabled pack, in the command and again in the running session after it has given up its
capabilities, so both must be readable to the session then. Any change to the rules or to an enabled
pack's bytes - a value, a version, whitespace - changes the processing revision and is refused as a
processing change a restart applies, leaving the plan and generation in force. `restart` compiles the
new configuration before it stops the running session, so a pack that cannot be read leaves that session
running.

**`stop`, and `inspect` of a running session, read only where the session is** - the configuration's
`output`, read with the reader and nothing more - and never a pack. A pack that is broken, removed or
changed never prevents stopping or inspecting a session. `start`, `start --daemonize`, `restart`,
`dry-run`, `preflight` and `reload` compile everything, packs included. `inspect` of a finished
session's directory reads no configuration at all.

## Lost with the earlier format

These cannot be written in `observer.config/1`:

- `stop_pipeline`, which ended a pipeline's output for the session at its first undecidable exchange.
  Every failure now drops what it concerns and is counted;
- exchanges written without connection records. `write_content: true` writes both;
- `mask` and `truncate` on one header, which are two different values for one field and refused.
