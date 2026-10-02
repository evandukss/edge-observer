# Extensions

An **extension** is your own executable, which the observer starts and feeds its records to. It can read
the exchanges the observer captured, change them before they are written, and write records of its own -
an endpoint inventory, a classification, a count - for monitoring, discovery and troubleshooting. You add
one with one entry in the configuration file.

This page is for the person who configures one. The person who writes one reads the protocol,
[contract/extension/PROTOCOL.md](../contract/extension/PROTOCOL.md), which is everything needed to write
one in any language with no library from the observer.

The [endpoint inventory example](../examples/endpoint-inventory/README.md) is a
Python program using only the standard library. It answers exchanges unchanged
and emits bounded summaries of methods, path templates and status classes.

## Configuring one

    "extensions": [
      {"name": "inventory", "command": ["/usr/local/lib/observer/inventory", "--batch", "100"],
       "fields": ["request.line", "response.line"], "timeout_ms": 250}
    ]

| key | value |
|---|---|
| `name` | lowercase letters, digits, `_` and `-`, starting with a letter, at most 63 characters, unique. It names the extension's counts in the account and its output file |
| `command` | the executable and its arguments, as a list. Nothing is run through a shell. A relative executable is resolved against the directory holding the configuration file |
| `fields` | what it receives, at least one (below) |
| `timeout_ms` | how long the observer waits for its answer to one exchange, 1 to 60000 |

**Every command that compiles the configuration - `start`, `restart`, `dry-run`, `preflight`, `reload` -
refuses an entry whose command is not an executable regular file**, naming the entry and the path it
looked for, before anything attaches. The full rules of the entry are in
[contract/config/CONFIG.md](../contract/config/CONFIG.md), Extensions.

**Extensions run in the order you list them, after every `remove`, `mask` and `truncate` rule.** A
change to `extensions` takes a restart: `reload` refuses it.

### The fields

Each field is a part of the record the approved output writes for an exchange. Paths are within one
line of `approved.jsonl` ([approved-inspection.md](approved-inspection.md)):

| field | what the extension receives | where it is in the approved output |
|---|---|---|
| `request.line` | method, target, protocol | `reconstruction.exchanges[].request.message.method`, `.target`, `.protocol` |
| `request.headers` | headers and trailers, in order | `reconstruction.exchanges[].request.message.headers[]`, `.trailers[]` |
| `request.body` | the body, its framing and structure | `reconstruction.exchanges[].request.message.body`, `.framing`, `.structure` |
| `response.line` | status, reason, protocol | `reconstruction.exchanges[].response.message.status`, `.reason`, `.protocol` |
| `response.headers` | headers and trailers, in order | `reconstruction.exchanges[].response.message.headers[]`, `.trailers[]` |
| `response.body` | the body, its framing and structure | `reconstruction.exchanges[].response.message.body`, `.framing`, `.structure` |
| `connection` | the connection record | `connection` |

With any field of a side it also receives whether that side is present and complete. **It receives
nothing you did not select, and nothing `remove` took out**: a removed field arrives marked removed,
never with its value. With `write_content` false only `connection` can be selected, and the extension
receives connection records when each connection ends.

## What it does to the output

- **Changes.** For each exchange an extension answers unchanged, changed, or failed. A change replaces a
  selected part whole, and the replacement goes through your `remove`, `mask` and `truncate` rules again
  before the next extension sees it, so an extension cannot put back what `remove` took out. The approved
  output records each extension's outcome for each written exchange.
- **Its own records.** What an extension writes about exchanges goes to `derived-<name>.jsonl` in the
  session's directory, never into `approved.jsonl` or the account. Each line names the exchanges it is
  about by id - every line of `approved.jsonl` carries the ids of its connection's exchanges - and says
  whether it was observed or inferred. **Derived output uses at most half of `limits.output_mib`**, and
  running out of it never stops the observer's own output.
- **The account** counts, per extension, every exchange it was given and what became of it: changed,
  unchanged, failed by reason, or still pending; its restarts; and its derived lines written and refused.
  Every count is the observer's own; an extension cannot write into the account.

**In the observer's log** each extension adds two records, both escaped and attributed:
`extension-stderr`, a line the extension wrote to its standard error, and `extension-reason`, the reason an
extension gave for failing an exchange. Each carries `session`, `at`, `extension`, `generation`, `line`,
and `cut`, which says whether the line was cut at its bound (1024 bytes of standard error, 256 of a reason).
Together they are copied at most 10 a second per extension; beyond that a standard error line is counted as
dropped in the account and a reason is not logged, while the failure itself is always counted.

**Everything an extension does is labelled extension-declared and not observer-enforced** - in the
activation record written before any data reaches it, in the account, and in what `preflight` and
`dry-run` print. The observer checks the shape of what an extension says and which exchanges it cites,
never whether it is true.

## When it fails

**A failed extension writes the exchange without its changes, so protection belongs in `remove`.** When
an extension does not answer within `timeout_ms`, crashes, answers malformed, or is too busy to take
more, the exchange continues - through the rest of your extensions and into the output - exactly as it
was before that extension, and the account counts the failure under its reason. Nothing else waits on
it. An extension never protects data: `remove` applies before any extension sees anything and always
applies.

A crashed or stopped extension is started again after a pause that grows from 0.1 to 5 seconds. **It
starts with no state**: what it had gathered is gone, nothing is replayed to it, and the account counts
the reset. **Exchanges that arrive before an extension has said it is ready - at the start of a session
and after each restart - and while it is down skip it**, counted as `unavailable`: nothing waits for an
extension to start.

**An extension takes at most 4096 exchanges at once, one per connection, and a burst beyond that skips
it**, counted as `busy`. **When a session ends, every connection still open is sent to your extensions at
once**, so a session that ends with more open connections than that is such a burst.

## The delay it adds

**Exchanges reach an extension when their connection ends** - its handle released or its socket closed -
or when the session ends, the same moment they reach the output. A keep-alive connection is seen when it
closes. Each exchange waits at most `timeout_ms` at one extension, including the time to queue and write
it, and at most the sum of the `timeout_ms` of all your extensions in total. Earlier exchanges of its
connection, processing and output can add to that. While one connection waits on an extension, other
connections are processed and written; **the application you watch never waits on an extension.**

**Order is guaranteed within a connection only.** An extension receives one connection's exchanges in
order, one at a time. Exchanges of different connections are interleaved, and the order they arrive in
says nothing about which happened first.

## Processing capacity

`limits.workers` is a fixed count, **default 1**; it does not grow with load. For this generated
approximation of the reference traffic shape, one processing worker achieved about **26,700 requests/s
with file output** and **32,300 with an in-memory diagnostic sink**, without rules or extensions. File
throughput stayed near 27,000 at 1, 2 and 4 workers; the in-memory comparison reached about 61,900 at 4
workers. The cause of the file plateau was not isolated. This measures the **processing stage, not
capture**, and does not size workloads with extensions. It is a host-specific figure, not a sizing
guarantee.

Median [minimum, maximum] across five runs after warmup:

| output | workers | total requests/s | requests/s per worker |
|---|---:|---:|---:|
| file | 1 | 26,680 [25,965, 26,819] | 26,680 [25,965, 26,819] |
| file | 2 | 27,381 [27,240, 27,812] | 13,690 [13,620, 13,906] |
| file | 4 | 27,106 [26,192, 27,540] | 6,776 [6,548, 6,885] |
| memory | 1 | 32,296 [32,088, 32,532] | 32,296 [32,088, 32,532] |
| memory | 2 | 48,014 [47,864, 48,895] | 24,007 [23,932, 24,448] |
| memory | 4 | 61,878 [61,380, 64,012] | 15,469 [15,345, 16,003] |

The per-worker column divides total throughput by the worker count before rounding; it is not a promise
that each added worker adds that much. With file output, two workers gained about 2.6% over one while
median process CPU rose from 121% to 134% of one logical CPU. One worker is the default.

**Host and revision.** Apple M3, 8 logical CPUs, 16 GiB RAM, Darwin 24.1.0, under Docker Desktop 29.8.0;
the Linux/arm64 VM had 8 CPUs, 4.801 GiB RAM and kernel 7.0.12-linuxkit. Go 1.27.1, default
`GOMAXPROCS=8`, measured on the source revision that added this section; `git log -- docs/extensions.md`
finds it. File output used the container's overlay filesystem. **Writes went to the page cache without
fsync, so this is not durable-media throughput.** The container had a 2368 MiB memory limit with no swap or CPU quota, chosen
from a full-invocation calibration. Every run's `memory.events` counters `high`, `max`, `oom` and
`oom_kill` had zero increments; the largest cgroup memory peak was 1179 MiB. Process peak RSS ranged
from 61 to 76 MiB for file output and 186 to 206 MiB for memory output, including setup and warmup.

**Shape.** Reference traffic run `20260930-150423-33209` supplied 45 connections, each with one complete
exchange, no recorded defects, and JSON in all 68 nonempty bodies. The benchmark rounds its mean body
sizes to 105 request bytes and 138 response bytes, and its mean extra header size to 49 bytes per
message, beyond Host, Content-Type and framing. It uses JSON share 1, defect share 0, seed `20260930`,
one generated process and sequential connections. This approximates the shape: it does not preserve
the 22 empty requests, varying headers or JSON field counts. Both default output routes write about
**8,177 encoded bytes per request**. Only the numerical shape is reused, not the source payloads.

**Method.** [`BenchmarkCapacity`](../processing/capacity_linux_test.go) uses the real intake, workers,
release gate and writer, fully draining every session. Each operation contains 4500 connections to
amortize session startup and shutdown; their separately measured cost was below 0.013% of an operation
at every worker count. Each invocation measures 20 operations after ten untimed warmup sessions; Go's
preliminary one-operation invocation also warms. Generation, configuration compilation and file
creation are outside the timer. The memory comparison changes only the writer's file to a buffer,
reset between sessions. Intake, output, gate and processing refusals were zero. Benchmark allowances
are 1 GiB intake, 1 TiB output and default reconstruction bounds; they are not recommended settings.

**Rerunning requires a source checkout and Go 1.27.1 on Linux.** Build the test binary once, then run
each selected cell five times in separate invocations. For example, the one-worker file cell:

```sh
go test -c -o /tmp/observer-capacity.test ./processing
/tmp/observer-capacity.test -test.run='^$' \
  -test.bench='^BenchmarkCapacity$/^file$/^workers=1$' \
  -test.benchtime=20x -test.count=1 -test.v
```

Substitute `memory` and worker counts `2` or `4` for the other cells. Use an otherwise idle host and
the stated container envelope when comparing with this table; record load, CPU, peak memory and
`memory.events` before and after each invocation. Keep all samples. The benchmark's `-capacity-*`
flags set connections, exchanges per connection, header and body sizes, JSON/defect shares and seed;
use them to measure your traffic's shape. A same-host reproducibility check uses a tolerance of
**+/-10% of each table median**, declared before its single rerun of all six cells.

## What an extension can do: the trust model

**Extensions are trusted code and are not sandboxed.** Run only an extension you would run as the user
the observer runs as.

- **It runs as the observer's user - root under the documented start - without capabilities.** It can
  read and write what that user owns, including the session's output, account and configuration, and it
  can stop the observer. It cannot attach probes or change live traffic, and it holds none of the
  observer's capture, output or control descriptors.
- **Anything an extension sends over the network is an export the observer does not control.** What you
  select in `fields` is what it can send anywhere.
- **Extensions share the observer's memory and CPU.** The observer makes the kernel prefer an extension
  over itself when memory runs out, but **memory exhaustion may still end the observer**, for example where
  the cgroup kills every process in it at once. Running an extension adds CPU work for every exchange, in
  the observer and in the extension, so **on a host short of CPU it can slow the application you watch**.
- **A process an extension starts can outlive the observer.** The extension itself is stopped with the
  observer, by signal if it does not exit; what it starts in turn is stopped with it at an orderly stop and
  can survive when the observer is killed.
- **An extension's crash may leave a core dump holding what it received**, where the kernel does not honour
  the core dump limit the observer sets on it. That never includes anything `remove` took out.
- **The observer does not authenticate an extension.** You control the executable and every directory
  through which it could be replaced: an observed program or any other untrusted user must not be able to
  write them. An executable replaced behind the same path is run at its next start.
