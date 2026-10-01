# Adding support to the observer

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
as a `probe.Connection` through the `probe.Sink` it is given. Capture, ordering and the volatile intake take
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

The legacy spool reader reconstructs when a finished capture is read back: a
capture yields fragments and connection records and holds no reconstruction state, and `inspect`,
given a session's directory, runs `reconstruct.Run` over the fragments beside the account
(`internal/published/published.go`, `Reconstruct`) and prints what `reconstruct` renders. A second
protocol is reached from that read.

## An output

A capture hands records to two storage interfaces: `capture.Sink` (`Write(fragment.Record) error`,
in `capture/capture.go`) and `connection.Sink` (`Connection(connection.Record) error`, in
`connection/record.go`). Production supplies the same `intake.Store` to both. These are volatile
storage boundaries, not places to add durable output: neither may parse payload, grant
admission, decide completeness, or write raw records to disk.

A processing consumer calls `Take` and later `Release`. It keeps no intake lock while parsing or
writing, and the record remains charged until release. It must establish completeness separately and
obtain release authorization before durable output. Queue order alone is not lifecycle evidence.

`policy/inventory.go` declares which output kinds configuration accepts. Routing an approved result
to a durable output belongs downstream of processing and authorization. The legacy `spool` package
still defines the raw artifact format read by older-session inspection; it is not a production intake.

## Checking a change

[CONTRIBUTING.md](../CONTRIBUTING.md) has the commands that build and test a change, what they report
today, and how a change to `bpf/*.c` or `bpf/*.h` regenerates the compiled programs.
