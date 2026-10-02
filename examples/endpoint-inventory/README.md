# Endpoint inventory

This Python 3.10+ example groups the exchanges it receives by method and path
template. It uses only the standard library and answers every exchange unchanged.
It is source in this checkout, separate from the release archive.

Add this entry to your observer configuration, replacing both absolute paths with
the interpreter and source file on your host:

```json
"extensions": [{
  "name": "inventory",
  "command": ["/usr/bin/python3", "/opt/edge-observer/examples/endpoint-inventory/inventory.py"],
  "fields": ["request.line", "response.line"],
  "timeout_ms": 1000
}]
```

Keep `write_content` enabled. See [extensions](../../docs/extensions.md) for
configuration, trust and failure behavior, and the
[protocol](../../contract/extension/PROTOCOL.md) for the wire format.

Read `derived-inventory.jsonl` in the session directory. Each line's `record`
has `kind: endpoint_inventory`, `scope: exchanges this extension received`,
an `exchanges` count, and an `endpoints` list. Each endpoint has:

- `method`, `path_template` and `template_basis` (`observed` or `inferred`).
- `status_classes`: counts such as `2xx`, `4xx`, or `unknown` when no status is available.
- `exchanges`, `one_sided` (exactly one side present), and `incomplete` (the
  exchange's completeness flag is false). These last two counts may overlap.
- `sources`: the exact source exchange ids for that summary. The outer line's
  `sources` lists every id in the batch. Counts and ids are decimal strings.

Only whole decimal, UUID-shaped, or hexadecimal segments of at least 16 characters
become `{id}`. For example, `/users/42` and `/users/43` yield `/users/{id}`, labelled
`inferred`; `/users/alice` stays literal. This is a heuristic, not a discovered
route definition: numbers can be literal route segments too. Query strings and
absolute-target origins are omitted. Percent escapes, repeated slashes and letter
case stay as received. No hostname or connection direction is selected, so equal
method/path pairs across hosts and directions aggregate together.

An absent request, CONNECT authority target, unsupported target, or oversized line
has a null path and an explicit `endpoint_state` explaining why. Its
`template_basis` is `unavailable`. Methods over 64 characters or targets over 4096
characters use `line_too_long`, with both method and path null. Ordinary entries
have `endpoint_state: available`.

A batch holds at most 64 endpoint summaries and 256 source ids (or the observer's
`derived_sources` bound, if smaller). It flushes when another endpoint would exceed
the bound, when the source bound is reached, and at `session_ending`. Every batch
contains only its own counts; sum batches to get generation totals. A new process
generation starts empty. A crash loses the unflushed batch. The observer can refuse
derived output for rate or queue limits and failed delivery; inspect its account for those
refusals before treating the file as complete.

Totals always mean **exchanges this extension received**, including excluded,
incomplete and one-sided exchanges. They do not count traffic skipped while the
extension was unavailable or busy. Exchanges arrive when their connection ends
(or the session ends). There is no latency estimate: the protocol has no
per-request timing. Source ids resolve through the session's approved
[exchange ranges](../../docs/approved-inspection.md#exchange-ids).

## Checks

From this directory, `python3 -B -m unittest -v test_inventory` runs the Python
tests, and `python3 -B check_imports.py inventory.py` checks the executable's imports
against `sys.stdlib_module_names` and rejects local modules shadowing those names.
The Go test beside the example and the repository's example-coverage guard use
one runner, `checks.Run`, to run both commands in the observer's unit gate.
The import test also plants non-standard and source-tree imports and requires
the checker to reject them.

`testdata/session.jsonl` is the unchanged input captured from the real observer
by `TestEndpointInventoryEntryAndSourceProvenance` in `extension/attach`.
The capture contains three TLS requests (`/users/42`, `/users/43`, `/health`) and
the lifecycle messages from their session. The attach gate writes fresh input,
approved output and derived output beside its logs as `inventory-*.jsonl`.
Tests derive controlled presence, completeness, status and population variations
from that capture; they do not represent those variations as separately captured
traffic.
