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
      -> spool             write fragments and connection records to local disk, under a bound
      -> account           seal what the session attached, saw and lost, beside the spool

    later, on any machine
      session directory -> internal/published -> reconstruct (http1, jsonshape) -> inspect --text

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

**`spool`** keeps both on local disk, in files only the user running the observer can read. It keeps
no more than the bound the configuration sets (`observer.spool_bound_mib`) and counts what it drops.

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
        fragments.jsonl               the spool: every fragment, payload base64-encoded
        connections.jsonl             the connection records
        account.json                  the account, sealed when the session ended
        contract-account.json         the same account in the published account contract

A command to a running session is a request file in its directory and a signal to the pid its pid file
names. The observer listens on no socket.

## Reading a session back

**`internal/published`** writes the published account when a session seals, and reads a finished
session's spool back in the published record contracts. **`reconstruct`** turns the fragments into the
exchanges the process had, with which side of each connection the process was on. **`stream`**
reassembles one direction of one connection and records every hole rather than closing it up;
**`http1`** reads HTTP/1.1 messages out of it, strictly, refusing a message two endpoints could read
differently; **`jsonshape`** records a JSON body's shape - names, nesting and kinds - and none of its
values. `inspect --text` prints the account, then that reconstruction.

Reconstruction happens only here, when a finished session is read. The capture holds no
reconstruction state.

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
