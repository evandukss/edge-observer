# Architecture

How a capture moves through the code, and which package owns each part. Paths are relative to the
repository root; the program is `cmd/observer`, and every package it is built from sits beside it in
one Go module.

## The flow

    configuration file
      -> policy            compile it, check it against what this program has, refuse what it does not do
      -> process           read /proc, select the approved processes and their descendants
      -> probe             ask each adapter whether it can observe each process (the catalogue)
      -> probe/openssl/attach, ebpf, bpf
                           load the BPF program, place uprobes in libssl, keep the allowlist in the kernel
      -> privilege         drop every capability once the probes are placed
      -> capture           turn each library call into a fragment record
      -> intake            copy fragments and connection records into bounded volatile storage
      -> account           seal what the session attached, saw and lost, in its directory

    later, on any machine
      approved.jsonl -> processing.ReadArtifacts / RenderArtifact -> inspect --text

Two halves meet at one type. The kernel-facing half attaches and captures, and needs privilege. The
other half - `stream`, `http1`, `jsonshape` and `reconstruct` - turns captured fragments into exchanges
with no kernel and no privilege. The only thing they share is the fragment record (`fragment`).

## Selecting what to observe

**`cmd/observer`** reads the configuration file, and **`policy`** compiles it, resolving each
extension's command against the file's directory. The file is the operator configuration of
`contract/config/CONFIG.md`, checked by that contract's own code (`contract/config`) against what this
program has. Every section the contract accepts and this program does not implement is refused by
name, never read and ignored. `stop` and a running session's `inspect` read only where the session is.

**`process`** reads the processes on the host and decides which of them the configuration approves.
Nothing no rule names is observed, and an approval with no rules approves nothing. **`admission`**
defines what is published about an admitted process: the instance (pid namespace, pid, start identity,
admission generation, executable) and the selection (which target admitted it, and why).

**`preflight`** answers whether a capture can run on this host before anything attaches: the kernel,
the architecture, BTF, the capabilities, whether the kernel takes the program, each selected process's
TLS library, and the envelope it runs in, judged by the check `start` refuses on (`activation.Judge`),
which the command hands it as it hands it the program load. It captures nothing and opens no socket. A
test over the import graph (`preflight/boundary_test.go`) keeps the package from importing any capture,
spool or attaching code; it is still a mode of the one observer program, which holds all of that.

## Attaching

**`probe`** is the contract a TLS implementation is observed through: the `Adapter` interface and the
catalogue of adapters. `probe/catalog.go` lists the OpenSSL functions the observer attaches to, with the
release that introduced each. A runtime with no adapter is reported unsupported; the observer never
infers plaintext from socket traffic.

**`probe/openssl`** is the one adapter: it decides whether a process maps a `libssl.so` exporting the
catalogued functions. **`probe/openssl/attach`** places its probes. It is a package of its own so that
code which only asks whether a process can be observed, such as `preflight`, does not import it.

**`bpf`** embeds the two compiled BPF programs, built from one source (`bpf/ssl.bpf.h`): the full
program, which reads the plaintext buffer of each call, and a metadata-only program, which reads no
process memory. The observer loads the full one. `bpf/verify.go` decodes the kernel helpers each
compiled program calls and refuses any not on its list.

**`ebpf`** loads the program, attaches it, and reads what it reports through a ring buffer. The
allowlist of approved processes is a kernel map, checked inside the program before any read: a uprobe
fires for every process running the library, so an unapproved process is refused in the kernel. It is
keyed by process instance - pid namespace, the thread group's pid in it, and an admission generation -
rather than by a bare pid, which names different processes across namespaces and over time.

**`privilege`** drops the capabilities attaching needed, once the probes are placed, and reports
whether the process listens on anything. Both are readable from `/proc`, so an operator can check them.

## Capturing and keeping

**`capture`** turns what an adapter reports into fragment records: which connection a transfer belongs
to, where its bytes sit in that connection's stream, and in what order they were seen. **`fragment`**
is that record: one plaintext fragment as one library call transferred it. **`connection`** is the
record of a captured connection: its identity, lifetime, endpoints and where its bytes stop being
placeable, joined to fragments by connection id.

**`intake`** implements both capture sink interfaces with one bounded memory FIFO. Its byte allowance
charges the entry and record structs plus the lengths of owned slices and strings. Allocator and
runtime overhead are outside that accounting unit; it is not a heap limit. A record that exceeds the
remaining allowance is refused whole, and exhaustion stays set until the session ends. Both callbacks
only copy and account for storage: neither parses, admits an event, or authorizes a durable write.

The processing worker takes entries without retaining an intake lock. Taken entries remain charged
until it releases them. Callback arrival order does not establish completeness: an interruption can
retire a connection while its fragment callback is outstanding. The fragment callback runs outside the
capture mutex; interruption retirement runs under it. Normal close and ordinary finalization writes
run outside it.

**`processing`** publishes the worker and approved-output interfaces. Its worker consumes the
compiled `contract/config.ProcessingPlan` and leased intake entries. `processing.Artifact` defines
the versioned `approved.jsonl` representation for the public reader. Each exchange is one line,
with its session, connection, index and session-wide exchange id. One metadata line is emitted on
the connections route at retirement. Processing runs on `limits.workers` workers. One owner routes
leased intake entries by connection to its worker, preserving each connection's order. Entries stay
charged until processing transfers immutable, fully encoded output to the shared bounded sink queue.
The delivery gate orders authorization and enqueue against invalidation in one short step. A full
queue drops the line immediately; sink I/O runs outside the gate and release locks. Already enqueued
lines may be written after a later invalidation. Sink failures do not invalidate capture.

An approved prefix is not a whole stream. The retirement line's `reconstruction_truncation` marks
an incomplete suffix indeterminate and records its directions, excluded offsets, reasons and evidence
offsets. The exchange lines contain complete pairs only; the connection ending remains independent.
Still-open batches require withdrawal and callback-drain evidence at finalization, which never
substitutes for an observed transport close.

`policy_exclusions` records actual removals by policy in that pipeline's retained messages: the
exchange index, request or response, the field removed and a disposition (`removed`,
`values_removed`, or `removed_undecidable` for a body or query a field operation could not decide),
never its value. Each entry appears once; array order has no meaning. Configured-but-absent names,
replacement and truncation add no entry. Every new artifact carries an array, including `[]` for no
removals and for metadata routes. An older artifact with the member absent (or null) has unavailable
evidence, not known-empty evidence. Empty evidence says nothing about an unpublished or
indeterminate suffix. These encoded bytes are included in the queue charge with the rest of the line.

The command routes on one goroutine, separate from the controller that selects stop and gate
withdrawal. Routing takes queued intake on a 10 ms cadence; elapsed time never establishes batch
completeness. Accounts distinguish authorized, written, failed, dropped and pending output. A failed
write may have written a prefix and is never counted as written or retried. A later record begins on
a new line; inspection reports a damaged record as malformed. Snapshot counters can advance while
an account is rendered. At stop, producers withdraw and drain, workers release their remaining leases,
and sink shutdown waits only for its bounded deadline. Remaining pending lines are counted as
discarded. This deadline bounds sink shutdown, not every producer or extension's finalization.

**`sink`** owns the byte-bounded queue and per-file write/reopen boundaries. Queued and in-flight
lines both retain their charge. Stable files append across sessions; an unavailable file does not
prevent monitoring. `observer reopen` switches approved, derived and log files after external rotation.
A blocked old write prevents a successful reopen acknowledgement. Operators choose retention and
rotation; the account reports delivery outcomes rather than a retained-file inventory.

**`spool`** implements the legacy raw disk format. Production capture does not wire it into either
sink, and starting a new session does not open it. Legacy readers still recognize its filenames.
New operational accounts carry the minimum processing and output dispositions as session aggregates.
They do not substitute approved route counts for raw-fragment persistence counts. The contract
account marks the raw spool block `not_carried`, with a reason, rather than claiming an unreadable
spool or a determined zero for that legacy identity.

**`account`** is what the observer says about a session: the policy it resolved, what that selected,
what was attached, what came through, what was lost and how the session ended. One type serves a dry
run (planned), a running session (live) and an ended one (sealed). **`attachment`** is its record of
what was attached, built from what the kernel confirmed rather than from what was asked for. The
account carries no process's command-line arguments, because they can hold secrets.

## A session on disk

    <observer.directory>/
      observer.pid                    the running session's pid file
      last-sealed.json                the most recent session to seal
      approved.jsonl                  authorized exchange and retirement lines
      derived-<extension>.jsonl        extension records carrying their session
      sessions/<session>/
        control/                      requests and acknowledgements
        account.json                  the account, sealed when the session ended
        contract-account.json         the same account in the published account contract

A command to a running session is a request file in its directory and a signal to the pid its pid file
names. The observer listens on no socket.

## Reading a session back

**`internal/published`** writes the published account when a session seals, and reads a finished
session's legacy spool back in the published record contracts. New captures do not produce that raw
artifact. **`reconstruct`** turns the fragments into the exchanges the process had, with which side of each connection the process was on. **`stream`**
reassembles one direction of one connection and records every hole rather than closing it up;
**`http1`** reads HTTP/1.1 messages out of it, strictly, refusing a message two endpoints could read
differently; **`jsonshape`** records a JSON body's shape - names, nesting and kinds - and none of its
values. The public `inspect --text` command prints the sealed account, then reads approved
records through `processing.ReadArtifactFiles` and `processing.RenderArtifact`. Explicit files can
include rotated files, and a session filter selects their records. It retains their
capture-time provenance and exclusion/truncation evidence and displays permitted values. Missing
or empty approved output fails. It does not reconstruct a raw spool or execute current policy.

For legacy sessions reconstruction happens when a finished session is read. New captures reconstruct
and process before authorized output; capture callbacks themselves hold no reconstruction state.

## The contracts

`contract/` holds the published formats as documents, with Go code that encodes and checks each one.
Where a document and its code disagree, the document is corrected first.

    contract/config       the configuration a user writes, and the plan it compiles to
    contract/extension    the protocol between the observer and an extension
    contract/record       the records the observer produces: observation, connection, reconstruction,
                          reassembly
    contract/account      the account of a session, and the bundle that carries it with its records
    contract/acceptance   the acceptance specification, standalone_inspection_v1

## Boundaries the tests hold

- **The module reaches nothing outside itself** except what `go.mod` declares (`boundary_test.go`).
- **`preflight` imports no capture, spool or attaching code** (`preflight/boundary_test.go`). It runs
  inside the same program as everything else, so this separates packages, not processes.
- **Each BPF program calls only the helpers on its list** (`bpf/verify.go`), and the committed objects
  are what regenerating them produces ([CONTRIBUTING.md](../CONTRIBUTING.md)).
