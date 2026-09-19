# Extending the observer

For somebody adding to the observer who has not worked on it before: a TLS library it does not read
yet, a protocol or body format it does not reconstruct yet, or an output it does not write to yet.
Each section says where the new code goes, what it implements, where it is registered, and which
other files still assume the one implementation that exists. Paths are relative to the repository root.

The three are not equally ready. A new TLS library compiles against an interface and is selected by
the catalogue, and is not yet the adapter that attaches. A new output compiles against an interface
and nothing routes a configuration to it. A new protocol has no interface to implement. Each section
says what would change that.

## A TLS library

The observer reads plaintext at the functions a TLS library moves it through, by placing uprobes on
them. One library is supported: OpenSSL 3.x, linked dynamically.

**What you write.** A package under `probe/`, beside `probe/openssl/`, with a type implementing
`probe.Adapter` from `probe/probe.go`:

    Name() string                           unique among registered adapters
    Inspect(process.Process) probe.Support  can this adapter observe this process, and why or why not
    Attach(probe.Request, probe.Sink)       place the probes and report what crosses them
        (probe.Attachment, error)

`Inspect` must not attach or read what the process holds, and fills `Support.Reason` whichever way it
answers. `Attach` reports each call into the library as a `probe.Transfer` and each connection ending
as a `probe.Connection` through the `probe.Sink` it is given. Capture, ordering and the spool take
transfers from any adapter and need no change. The optional interfaces in the same file
(`probe.Attested`, `probe.Covering`, `probe.Counting` and the rest) are how an attachment says what the
kernel confirmed, what it lost and what it refused. An attachment that does not implement
`probe.Counting`, for example, is reported as unable to count its losses, not as having lost nothing.

`probe/catalog.go` holds the list of OpenSSL functions the observer attaches to, with the release
that introduced each. A second library describes its own functions the same way, as a
`probe.Runtime`.

**Where it is registered.** The catalogue is built with `probe.NewCatalog(adapters...)`. Each command
that needs one builds its own: `preflight`, `dry-run` and `start` in `cmd/observer/main.go`, and
`reload` in `cmd/observer/reload.go`. A new adapter is added to each of those calls. The catalogue
asks adapters in the order given and selects the first that supports a process.

**What still assumes OpenSSL**, and has to change before a second adapter is the one that attaches:

    cmd/observer/main.go     observe() hands every supported process to the FIRST registered
                             adapter, whichever one the catalogue selected for it; catalogued()
                             names OpenSSL's functions for every process; the build capability
                             comes from the OpenSSL attachment package
    cmd/observer/reload.go   reads the libraries of every supported process through the OpenSSL
                             adapter, and admits new processes into the one running attachment
    preflight/readiness.go   the readiness verdict looks for libssl and reports any other process
                             as missing its TLS library

Until `observe()` attaches each process through the adapter the catalogue selected for it, a second
adapter registered after OpenSSL is selected and never attached: its processes are handed to the
OpenSSL adapter, which refuses them. Registered first, it is attached to every supported process,
including OpenSSL ones.

## A protocol or body format

HTTP/1.1 is parsed in `http1/` and JSON bodies are described by their shape in `jsonshape/`.
`reconstruct/reconstruct.go` pairs a connection's two directions into request and response
exchanges.

There is no interface for a second protocol. `reconstruct/reconstruct.go` calls the HTTP/1.1 parser
directly, its `Message` type is HTTP/1.1's, it decides which side of a connection a process was on by
looking for an HTTP method, and it hands every body to the JSON reader. A second protocol changes that
file, and `contract/record/project.go`, which turns a reconstruction into the published record, reads
HTTP fields from it. The record types the configuration can route (`Reconstruction` in
`policy/inventory.go`) name HTTP fields too.

The observer program reconstructs when a finished capture is read back, never while it captures: a
capture yields fragments and connection records and holds no reconstruction state, and `inspect`,
given a session's directory, runs `reconstruct.Run` over the fragments beside the account
(`internal/published/published.go`, `Reconstruct`) and prints what `reconstruct` renders. A second
protocol is reached from that read.

## An output

A capture writes through two interfaces: `capture.Sink` (`Write(fragment.Record) error`, in
`capture/capture.go`) for fragments and `connection.Sink` (`Connection(connection.Record) error`, in
`connection/record.go`) for connection records. The one implementation is the local spool in
`spool/spool.go`, which also bounds what it keeps and counts what it drops.

A second output compiles against those two interfaces without touching them. It is not reachable
without two further changes:

    policy/inventory.go      the sink kinds the program accepts in a configuration. A configuration
                             naming any other kind is refused, and the refusal says an output is added
                             to the program rather than configured into it
    cmd/observer/main.go     the session start hands the spool to capture as its only destination,
                             and reads the spool's own counts for the account

There is no step that routes a configured sink to an implementation, so the second of those is where
one would be built.

## Checking a change

    go vet ./... && go vet -tags attach ./...
    go test ./...
    go test -tags attach -p 1 ./probe/openssl/attach/... ./ebpf/...

Until they are repaired, `go vet -tags attach ./...` reports two findings: `possible misuse of
unsafe.Pointer` at `ebpf/arming_test.go:337` and `:338`, where a test fixture reads a supervised
process's path argument through the test's own address space. Any other finding from these commands
is new.

The attach-tagged tests place real probes, so they need the privilege to load BPF programs on a Linux
kernel that allows it (`HOST-REQUIREMENTS.md`). A change to `bpf/*.c` or `bpf/*.h` is followed by
`go generate ./bpf/`, which needs clang and the libbpf headers, and the regenerated objects and
bindings are committed with it; `go run ./bpf/cmd/verify` then checks the new objects' helper calls.
