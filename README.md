# Edge Observer

The observer shows what crossed the TLS boundary of processes you approve - the HTTP/1.1 requests and
responses they send and receive - without a proxy, a certificate, or any change to those processes. It
runs on Linux, places eBPF probes on the read and write functions of OpenSSL 3.x in the processes' own
`libssl`, and writes what it saw to files on the same host. The observer sends nothing off the host; an
extension you add can (Extensions, below). There is no registration, no account and no hosted service.

It is for somebody who administers a Linux host and wants to see what a service on it actually sends
and receives over TLS.

**It is early.** One pre-release, `v0.1.0-rc1`, has been published, from an earlier commit than this
document describes. The Status section below says what is built, what is built but not proven, and
what does not work. Read it before relying on anything here.

## Status

### Known not to work

- **A second TLS adapter is selected and never attached.** One registered after OpenSSL is chosen by
  the catalogue for its processes, which are then handed to the OpenSSL adapter, and it refuses them.
  Registered first, it is attached to every supported process, OpenSSL ones included.
  [docs/adding-support.md](docs/adding-support.md) names the code that still assumes OpenSSL.

### Built but not proven

- **The acceptance specification** (`contract/acceptance/`, `standalone_inspection_v1`) is built and has
  never been exercised end to end: no run has been graded against it.
- **Attaching is checked on pull requests on one runner only.** The tests that load the BPF programs and
  place probes (the `attach` build tag) need a privileged host, and the one authorised in
  [.github/gate/privileged-runners](.github/gate/privileged-runners) is a hosted x86-64 `ubuntu-24.04`
  runner. [CONTRIBUTING.md](CONTRIBUTING.md) says how to run them yourself.
- **Whether the observer needs the host's pid namespace when it runs in a container is not
  established.** Its tests do: in one container run without it, 27 of the 182 they then numbered failed.
- **x86-64 is the only architecture declared, and `observer preflight` refuses arm64 - the
  architecture the observer demonstrably runs on.** The x86-64 programs were first exercised on
  2026-09-22, on a hosted runner reporting `Linux 6.17.0-1022-azure x86_64`, where the attach suite
  ran all 182 of its tests with none skipped and none failed. Every run before that was on arm64,
  where preflight reports the architecture as missing and so returns NOT READY. Whether the
  declaration should change is open. [docs/compatibility.md](docs/compatibility.md) lists what has
  been observed and what that run does and does not establish.
- **The kernel floor, 5.15, has never been observed.** It is the oldest release declared; no run on it
  is recorded, and every account the observer writes says so.
- **On a real capture, the exchanges `inspect --text` prints are checked only by request path and
  session.** The rest of what it prints of them is checked on constructed input.
- **What the probes cost an observed process is not established.** No measurement of it stands.
- **Regenerating the BPF programs has only been done on arm64.** The generate directives name the arm64
  include directory ([CONTRIBUTING.md](CONTRIBUTING.md)).
- **This README shows no example output.** No capture has yet been made by following it, so there is
  no real output to show.

### Not implemented

- **One TLS library**: OpenSSL 3.x, loaded as a shared library. A process with no `libssl.so` mapped is
  reported unsupported and not observed. The major version is checked by `observer preflight`, not by
  the adapter.
- **One transport**: TLS over TCP, the only one tested. DTLS and QUIC, and so HTTP/3, run over UDP and
  are neither declared nor tested. TLS over a unix-domain socket is reported unsupported.
- **One protocol**: HTTP/1.1, with JSON bodies described by their shape. Other traffic, HTTP/2
  included, is captured and not reconstructed. Reconstruction runs while capturing, not when a session
  is read back.
- **No output while a connection is open.** A connection's exchanges are written when it ends - its TLS
  handle released or its socket closed - or when the session ends. A connection that reaches half of
  `limits.events` captured events before it ends is cut, and none of its exchanges is written; a long
  keep-alive connection reaches that in ordinary operation. [docs/extensions.md](docs/extensions.md)
  says when exchanges are written and what a cut costs.
- **Local output**: files on the host - each session's account, `approved.jsonl`, and one
  `derived-<name>.jsonl` per extension. Raw capture records stay in bounded volatile storage. Durable
  payload output requires processing and release authorization. The observer exports nothing; an
  extension can send what it receives anywhere.
- **One set of rules for every watched program.** The configuration
  ([contract/config/CONFIG.md](contract/config/CONFIG.md)) removes, masks and truncates headers, query
  parameters, form fields, JSON members and whole bodies, in one fixed order. Different rules for
  different watched programs are not in it. Three things the earlier format could write cannot be
  written: stopping a pipeline at its first undecidable exchange, exchanges written without connection
  records, and a mask with a truncation on one header.
- **A reload only adds `watch` entries.** It puts in force a new target that needs no probe beyond
  those already placed. Every other change - anything it would take away, a rule, an extension, a
  limit, and a library nothing has attached to - waits for a restart.
- **No stable release**: one pre-release, `v0.1.0-rc1`. The program reports no version; an archive
  names the commit it was built from in its `COMMIT` file.
- **Every published format is a draft and not frozen**: the record (`observer.record/1-draft`), the
  approved output (`observer.approved/3`), the account and bundle (`observer.account/2-draft`,
  `observer.bundle/1-draft`), the configuration (`observer.config/1`), and the extension protocol and
  its derived records (`observer.extension/1`, `observer.derived/1`).
- **The account format has one example bundle, and it is constructed**:
  [contract/examples/bundle](contract/examples/bundle) is a made-up session the account validator
  checks, not the output of a capture. [contract/account/ACCOUNT.md](contract/account/ACCOUNT.md)
  specifies the format.

## Installing

### From source

You need Go 1.27 or newer.

    git clone https://github.com/evandukss/edge-observer.git
    cd edge-observer
    CGO_ENABLED=0 go build -trimpath -o observer ./cmd/observer

On Linux, that builds `observer`, one static file for the machine you are on. It builds only for Linux,
so from any other system, or for an x86-64 host, build it as:

    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o observer ./cmd/observer

The BPF programs are compiled into it, so the host it runs on needs no compiler, headers or library
installed for the observer. [docs/compatibility.md](docs/compatibility.md) says what the host itself
must provide.

### Release archive

One pre-release has been published, `v0.1.0-rc1`, from an earlier commit; its archive holds fewer of
the files below. A release is an archive, `observer-linux-amd64.tar.gz`, built from one tagged commit.
It unpacks into one directory, `observer-linux-amd64`, holding exactly these files:

    observer                     the program: one static file, linux/amd64
    examples/systemd/observer.service  supervised deployment with its own memory envelope
    README.md                    this document
    docs/compatibility.md        what a host must provide, and what the observer has been seen to run on
    docs/extensions.md           how to configure an extension
    docs/observer.logrotate      external rotation with acknowledged reopen
    contract/config/CONFIG.md    the configuration contract
    contract/extension/PROTOCOL.md  the extension protocol
    observer.config.json         the simplest configuration the program runs, for you to edit
    LICENSE                      the Mozilla Public License 2.0
    LICENSES/GPL-2.0-only.txt    the GNU General Public License version 2, the BPF programs' other licence
    THIRD_PARTY_NOTICES          the third-party material in the program, with its licences and notices
    COMMIT                       the commit the archive was built from, one line

Beside the archive, and not inside it, is `observer-linux-amd64.sha256`: the digest of the program file.
Check it in the directory you unpacked the archive into, with `sha256sum -c observer-linux-amd64.sha256`.
The other documents this README links to are in the repository, not in the archive.

## Using it

Four steps: configure, check the host, run, inspect. Every command runs the program you built,
`./observer`, from the directory it is in.

### 1. Configure

The observer reads one JSON file, the configuration specified in
[contract/config/CONFIG.md](contract/config/CONFIG.md). Start from the simplest one the program runs:

    cp contract/config/examples/no-rules.config.json observer.config.json

In a release archive that file is already there, as `observer.config.json`. These are yours to set.

**Where it writes.** `output` holds the stable approved and derived files, the pid file, and
accounts under `sessions/<session>`; it is created if missing. `log` is `stdout`, or an absolute path for a log file.

**What it watches.** `watch` is the list of processes you approve, and no other process is observed. For
one process already running, find what identifies it:

    pgrep -a <program name>                 # its pid and command line (or find it with ps)
    readlink /proc/<pid>/exe                # the file the kernel runs: this is "exe"
    tr '\0' '\n' < /proc/<pid>/cmdline      # its command line, one entry per line

Then write the entry, with `args` being every command-line entry after the first:

    {"name": "api", "exe": "/usr/bin/python3.11", "args": ["/srv/api/server.py"], "children": "all"}

Leaving `args` out beside `exe` matches only a process run with no arguments.

Every condition in an entry must hold. Besides `exe` and `args` there are three more: `cgroup`, a path on
the unified cgroup hierarchy that the process must be in or below; `port`, a listening TCP port whose
holders are selected, with an optional `interface`; and `pid`, which names one process as
`{"pid": N, "start": S, "boot": B}`, where `start` is field 22 of `/proc/<pid>/stat` and `boot` is
`/proc/sys/kernel/random/boot_id`. `children` is `all` (the default), `existing` or `none`: which of
the matched process's descendants are watched too - those running when the watch is resolved and every
one created afterwards, only those running then, or none. `ignore` lists matches that are never
watched, whatever an entry says.

**What it removes.** Without rules nothing is taken out: the exchanges written are as they crossed the
TLS boundary. `remove` takes headers, query parameters, form fields, JSON members and whole
bodies out before anything is written, and the observer refuses to start when it cannot enforce
every one. `mask` replaces a value and `truncate` shortens a header's value. The example
`contract/config/examples/credentials.config.json` removes the usual credential headers: copy its
`remove` into your configuration. A misspelled key is refused by name, never ignored.

**Extensions.** `extensions` runs your own executables over the records, after every rule, to change
exchanges or write records of their own - an endpoint inventory, a classification.
[docs/extensions.md](docs/extensions.md) says how to configure one and what one can do: **extensions
are trusted code, not sandboxed, and run as the observer's user**.

**How much it holds.** `limits.events` is the most captured events held at once while they wait to be
processed, 16384 by default. A connection that reaches half of them before it ends is cut, and none of
its exchanges is written. `limits.workers` is the number of processing workers, 1 by default. Changing
a limit takes a restart. [contract/config/CONFIG.md](contract/config/CONFIG.md) has every key, and
[docs/extensions.md](docs/extensions.md) says what a cut costs and what processing capacity was measured.

Check what it would select, attaching nothing:

    ./observer dry-run observer.config.json --text

A target that selected nothing says why. Fix the target until yours shows the process you meant.

### 2. Check the host

Attaching needs root, or the capabilities [docs/compatibility.md](docs/compatibility.md) lists.

**The observer runs only inside an envelope of its own.** Its process must be in a cgroup (cgroup v2) of
its own that is a memory domain with a finite `memory.max` and no swap, and every process it watches
must be outside that cgroup. `start` refuses anywhere else and names the condition. A login shell's
cgroup has no memory limit and a service's own cgroup holds the service, so neither will do. Launch
`preflight` and `start` the same way, so that preflight judges the envelope start will run in.

On a host with systemd, a transient scope is one:

    sudo systemd-run --scope -p MemoryMax=512M -p MemorySwapMax=0 ./observer preflight observer.config.json --text

With containers, the observer runs in a container of its own whose `--memory` and `--memory-swap` are
equal, sharing the host's pid and cgroup namespaces, and the service it watches runs in another:

    docker run --rm --privileged --pid=host --cgroupns=host --memory=512m --memory-swap=512m \
        --volume "$PWD:/observer" --workdir /observer <an image with a shell> \
        ./observer preflight observer.config.json --text

The limit bounds what the observer and its extensions hold together; 512M is an example, not a measured
need.

Preflight answers `READY`, or `NOT READY` naming each requirement missing - each envelope condition
start would refuse on among them, in start's own words - or `INDETERMINATE` naming what it could not
read, and exits 0 only on `READY`. It attaches nothing. Do not start on anything but `READY`.

### 3. Run

Launched the way preflight was:

    sudo systemd-run --scope -p MemoryMax=512M -p MemorySwapMax=0 ./observer start observer.config.json

It runs in the foreground and prints one JSON record per line; the first says it activated and what it
attached to. Now use the service you approved so traffic crosses it - nothing is observed on a quiet
process. Its exchanges reach `approved.jsonl` when their connection ends, so those of a keep-alive
connection appear when it closes or when the session stops. From another terminal,
`sudo ./observer inspect observer.config.json --text` shows the running session's account as it stands;
add `--session <session>` to see its approved records too.

    sudo ./observer stop observer.config.json

(or Ctrl-C in the first terminal) ends the run. `stop` prints the session it ended, whether it sealed
completely, on the same line anything the account says was lost and why release was refused, and the
path of the account it sealed.

For supervised operation, adapt [examples/systemd/observer.service](examples/systemd/observer.service).
It runs the observer in its own finite memory domain with swap disabled and `Restart=on-failure`.
Keep watched processes outside that unit. The 512M limit is an example; use the same envelope for preflight.
The unit expects the binary in `/opt/observer` and the configuration in `/etc/observer`.

When the observer already holds `limits.events` captured events, or the memory set aside for them is
full, the next event is refused and counted (`input_limit`, `intake_exhausted`), and the connection it
belongs to is written as its connection line alone, with none of its exchanges. The session goes on,
and other connections are processed as usual. Where a connection's captured bytes have a gap, its
exchanges are written up to the gap and nothing after it. A loss the observer cannot place in any
connection (`unlocated` in the account) leaves the connections already open untouched; a connection
first seen after it has its exchanges written only if the observer saw its TLS handle created
(`SSL_new`).

Two reasons end the capture: `unknown_length` and `unknown_kind`. Either one refuses every line not yet
queued for writing, seals the account as it stands and exits with status 1. Startup errors, internal
processing errors and failures to write the sealed account also exit nonzero. A normal operator
stop exits zero after successful finalization. A supervisor restart starts a new session; its
activation records the gap since the prior seal only when that session's matching sealed account
is still readable. A missing or unreadable account does not imply a zero gap.

### 4. Inspect

Each session keeps its sealed account in `<output>/sessions/<session>`, the
session `stop` named. Approved output is appended across sessions to
`<output>/approved.jsonl`; extension output goes to `<output>/derived-<name>.jsonl`.

    sudo ./observer inspect /var/lib/observer/sessions/<session> --text

Text inspection reads the account and selects its session from the stable approved file.
To inspect a copy or rotated files, name each file and optionally select a session:

    ./observer inspect ./session --text --file ./approved.jsonl.1 --file ./approved.jsonl --session <session>

No running observer or configuration is needed. The files are readable only
by the user that ran the observer - root, above - so either inspect as that user, or copy the session
directory and the approved files somewhere you can read them and name the files with `--file`, as
above. Without `--text` it prints the account as JSON.

The account says what was attached, what was seen, and what was lost. **Read what it says was lost
before believing anything else in it**: a run that lost events is not evidence about what crossed the
host. And a run that saw nothing is only evidence of a quiet process if the account also says the
probes were attached.

**The account holds what may still run.** An attached process or an admission whose execution has ended
is counted, not listed: in the placement's `ended` and its target's coverage `ended`. Its identity is
written once, when its end is established, to the operational log as an `execution-ended` record, so the
record of which process it was is only as durable as that log, which is best effort (Rotation and
delivery, below).

`--text` prints the sealed account and the approved records from `approved.jsonl`, including
permitted header and trailer values, decoded body bytes, and their capture-time policy revision,
route, connection metadata and message positions. Inspection uses the persisted result; changing
local policy does not reinterpret it. Copy the account and explicitly name the output files you want to read. Inspection makes no claim about missing lines between files.

Named policy exclusions distinguish fields that were removed from fields absent in the retained
messages. An empty exclusion array means none were excluded there; an absent or null array in an
older artifact means that evidence is unavailable. Truncation evidence identifies an indeterminate
suffix independently of the connection's actual ending. Missing, empty or unreadable approved
output fails text inspection, even if the account was printed. A legacy raw spool is not used as a
fallback. See [approved inspection](docs/approved-inspection.md) for the reader contract.

**New capture sessions do not create raw spool files.** Both capture callbacks copy records into a
bounded volatile intake. Reaching its limit refuses the next record whole and cuts its connection;
releasing held records makes capacity available again. Intake records are not approved output.
The processing worker writes authorized, processed route records to `approved.jsonl`; it does not
write raw fragments or connection records to the legacy spool. The sealed account remains in the session directory.

Legacy `fragments.jsonl` files contain header values and body bytes base64-encoded, including any
credentials and personal data the traffic carried. Reading such a file does not sanitize it or remove
it from disk.

## Rotation and delivery

Rotation and retention are external. The [logrotate example](docs/observer.logrotate)
uses rename, `create 0600`, `sharedscripts`, and `observer reopen` in postrotate.
Reopen success acknowledges the switch: no old-descriptor write remains blocked
and subsequent writes go to the active paths. Run logrotate as the file owner,
and keep replacement ownership compatible with the observer's retained privileges.
`copytruncate` also works, with possible loss between copying and truncating.

Sink failures never stop monitoring. Fully processed lines enter a bounded queue;
a full queue drops at once. Authorized, written, failed, dropped and pending are
separate account counts. A failed attempt can leave part or all of a line, is
not retried, and the following record starts on a new line. Inspection stops at
the first damaged record and reports it as malformed. An unavailable file can
recover on reopen.
Shutdown is bounded and counts pending lines it discards. Enqueue is the release
decision: a line queued before a later invalidation can still be written.

## Documentation

    docs/compatibility.md       kernels, architectures, TLS libraries and protocols: declared and observed
    docs/architecture.md        how a capture flows through the packages, and what each one owns
    docs/extensions.md          configuring an extension, when exchanges are written, and processing capacity
    docs/approved-inspection.md reading the approved output, and what each of its lines records
    docs/adding-support.md      adding a TLS library, a protocol or an output, and what stops each today
    contract/                   the formats: configuration, extension protocol, record, account, acceptance

[CONTRIBUTING.md](CONTRIBUTING.md) says how to build, test and propose a change,
[GOVERNANCE.md](GOVERNANCE.md) who decides, [SECURITY.md](SECURITY.md) how to report a vulnerability
privately, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) what is expected of everyone taking part.

## Licence

The observer is licensed under the Mozilla Public License 2.0, in [LICENSE](LICENSE). **The BPF
component is the exception, and it is GPL-2.0-only**:

    bpf/ssl.bpf.h  bpf/sslfull.bpf.c  bpf/sslmeta.bpf.c
        the BPF program sources: the GNU General Public License version 2 only, as each file's
        licence header states
    bpf/full_arm64_bpfel.o  bpf/full_x86_bpfel.o  bpf/meta_arm64_bpfel.o  bpf/meta_x86_bpfel.o
        the compiled programs, built from those sources: the same
    bpf/full_arm64_bpfel.go  bpf/full_x86_bpfel.go  bpf/meta_arm64_bpfel.go  bpf/meta_x86_bpfel.go
        the Go bindings bpf2go generates for them, each embedding one of those objects: the same
        for what they describe of the programs, and the MIT licence for the code bpf2go's template
        supplies
    bpf/readbarrier.bpf.c  bpf/barrier_arm64_bpfel.o  bpf/barrier_x86_bpfel.o
    bpf/barrier_arm64_bpfel.go  bpf/barrier_x86_bpfel.go
        a program the attach tests use, never built into the observer, with its compiled objects and
        their Go bindings: each licensed as the source, objects and bindings above

The programs declare their licence to the kernel as "GPL". They need a GPL-compatible declaration,
because they call helpers the kernel offers only to GPL-compatible programs:
`bpf_probe_read_kernel`, `bpf_probe_read_user` and `bpf_get_current_task`.

**This arrangement is what Linux expressly permits**: a GPL BPF program runs alongside userspace
software under a separate licence, so the observer's own code stays MPL-2.0 and only the programs
the kernel loads are GPL.

[REUSE.toml](REUSE.toml) records every file's licence in a form tools can read. The licence texts it
names are in [LICENSES](LICENSES), each copied unchanged from release v3.29.0 of the SPDX License List
data, https://github.com/spdx/license-list-data:

    LICENSES/MPL-2.0.txt         text/MPL-2.0.txt, sha256 66a3107d5ad6a058aab753eaac2047ccb2ed0e39465dd0fe5844da3e300d5172
    LICENSES/GPL-2.0-only.txt    text/GPL-2.0-only.txt, sha256 aaf135472f81c5b4a0dca9367e5bb5e9750032b5bebe5442b36e4c0a47430df3
    LICENSES/MIT.txt             text/MIT.txt, sha256 b05785f9f18e6716bab63424b11454513b9943a222595b70411009202fc592b5

[THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES) lists the third-party material in the program and in the
compiled BPF programs, with each one's licence and notice.
