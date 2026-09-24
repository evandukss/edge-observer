# Architecture

How a capture moves through the code, and which package owns each part. Paths are relative to the
repository root; the program is `cmd/observer`, and every package it is built from sits beside it in
one Go module.

## The flow

    configuration file
      -> policy            read it, check it against what this program has, refuse what it does not do
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

**`policy`** reads the configuration file. The file is the operator configuration of
`contract/config/CONFIG.md`, checked by that contract's own code (`contract/config`) against what this
program has. Every section the contract accepts and this program does not implement is refused by
name, never read and ignored.

**`process`** reads the processes on the host and decides which of them the configuration approves.
Nothing no rule names is observed, and an approval with no rules approves nothing. **`admission`**
defines what is published about an admitted process: the instance (pid namespace, pid, start identity,
admission generation, executable) and the selection (which target admitted it, and why).

**`preflight`** answers whether a capture can run on this host before anything attaches: the kernel,
the architecture, BTF, the capabilities, whether the kernel takes the program, and each selected
process's TLS library. It captures nothing and opens no socket. A test over the import graph
(`preflight/boundary_test.go`) keeps the package from importing any capture, spool or attaching code;
it is still a mode of the one observer program, which holds all of that.

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
the versioned `approved.jsonl` representation for the public reader; every durable route shares one
encoded-byte allowance in that file. The interface declarations state input validation, completion
evidence, authorization ordering and output refusal. The serial worker keeps intake leases through
processing and output, executes the compiled slots on separate pipeline copies, and authorizes each
encoded route result through the shared delivery gate immediately before writing. The writer refuses
a line that would exceed the remaining allowance without writing any of it; failure stops further
worker output. Connection routes carry metadata only. Still-open batches require explicit withdrawal
and callback-drain evidence at finalization, which never substitutes for a transport close.
An approved prefix is not a whole stream. `reconstruction_truncation` explicitly marks its suffix
indeterminate and records the affected directions, the first excluded offsets, the structural reasons,
and the evidence offsets (which can lie inside a withheld message). In the same artifact,
`reconstruction.unplaced` is undetermined with no numeric value and the reason
`reconstruction_truncated`; it must not assert a measured zero for that suffix. Unknown placement
at the observed boundary is reported even when no later fragment arrived. Connection routes omit
the reconstruction and its truncation, and the actual connection ending remains independent.

`policy_exclusions` records actual `RemoveHeaders` removals in that pipeline's retained messages:
the exchange index, request or response, headers or trailers, and lowercase field name, never its
value. Each tuple appears once; array order has no meaning. Configured-but-absent names, replacement
and truncation add no entry. Every new artifact carries an array, including `[]` for no removals and
for metadata routes. An older artifact with the member absent (or null) has unavailable evidence,
not known-empty evidence. Empty evidence says nothing about an unpublished or indeterminate suffix.
These encoded bytes share the approved-output allowance with the rest of the artifact.

The command runs the worker on one serial goroutine, separate from the controller that selects
stop, gate withdrawal and writer exhaustion. It takes queued intake on a 10 ms cadence; elapsed
time never establishes batch completeness. Live accounts carry only session aggregates: processing
failures, output failures, authorized and written route records, stopped-pipeline identities, and one
gate reason. The counts come from the last returned worker outcome and the gate is read later; these
are not an atomic reading and do not wait for a write to finish. At stop the producer withdraws and drains, capture
publishes its final records, and the worker receives the actual withdrawal and drain results. Both
must be complete to release a still-open batch. The worker releases all remaining leases and closes
approved output before the final account is written. This integration does not impose a whole-session
finalization deadline; the producer drain bound does not bound a held worker or writer.

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
      sessions/<session>/
        approved.jsonl                only authorized, processed route records
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
records through `processing.ReadArtifacts` and `processing.RenderArtifact`. It retains their
capture-time provenance and exclusion/truncation evidence and displays permitted values. Missing
or empty approved output fails. It does not reconstruct a raw spool or execute current policy.

For legacy sessions reconstruction happens when a finished session is read. New captures reconstruct
and process before authorized output; capture callbacks themselves hold no reconstruction state.

## The contracts

`contract/` holds the published formats as documents, with Go code that encodes and checks each one.
Where a document and its code disagree, the document is corrected first.

    contract/config       the operator configuration, pack manifest and component interface
    contract/policy       the policy-declaration vocabulary, and how a declaration is judged
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
