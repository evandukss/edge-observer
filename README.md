# Edge Observer

The observer shows what crossed the TLS boundary of processes you approve - the HTTP/1.1 requests and
responses they send and receive - without a proxy, a certificate, or any change to those processes. It
runs on Linux, places eBPF probes on the read and write functions of OpenSSL 3.x in the processes' own
`libssl`, and writes what it saw to files on the same host. Nothing leaves the host. There is no
registration, no account and no hosted service.

It is for somebody who administers a Linux host and wants to see what a service on it actually sends
and receives over TLS.

**It is early and unreleased.** The Status section below says what is built, what is built but not
proven, and what does not work. Read it before relying on anything here.

## Status

### Known not to work

- **A second TLS adapter is selected and never attached.** One registered after OpenSSL is chosen by
  the catalogue for its processes, which are then handed to the OpenSSL adapter, and it refuses them.
  Registered first, it is attached to every supported process, OpenSSL ones included.
  [docs/extension-guide.md](docs/extension-guide.md) names the code that still assumes OpenSSL.

### Built but not proven

- **The acceptance specification** (`contract/acceptance/`, `standalone_inspection_v1`) is built and has
  never been exercised end to end: no run has been graded against it.
- **Attaching is not checked on pull requests.** The tests that load the BPF programs and place probes
  (the `attach` build tag) need a privileged host, and no pull-request check runs them until the
  maintainer authorises one. [CONTRIBUTING.md](CONTRIBUTING.md) says how to run them yourself.
- **Whether the observer needs the host's pid namespace when it runs in a container is not
  established.** Its tests do: in one container run without it, 27 of their 182 failed.
- **x86-64 is the only architecture declared, and it has never been observed.** No recorded run has
  loaded the programs on an x86-64 host. Every recorded run was on arm64, where `observer preflight`
  reports the architecture as missing. [docs/compatibility.md](docs/compatibility.md) lists the kernels
  observed.
- **The kernel floor, 5.15, has never been observed.** It is the oldest release declared; no run on it
  is recorded, and every account the observer writes says so.
- **The exchanges `inspect --text` prints are checked on constructed input only.** The test that runs
  it on a real capture checks the account it prints, not the exchanges after it.
- **What the probes cost an observed process is not established.** No measurement of it stands.
- **Regenerating the BPF programs has only been done on arm64.** The generate directives name the arm64
  include directory ([CONTRIBUTING.md](CONTRIBUTING.md)).
- **This README shows no example output.** No capture has yet been made by following it, so there is
  no real output to show.

### Not implemented

- **One TLS library**: OpenSSL 3.x, loaded as a shared library. A process with no `libssl.so` mapped is
  reported unsupported and not observed. The major version is checked by `observer preflight`, not by
  the adapter.
- **One protocol**: HTTP/1.1, with JSON bodies described by their shape. Other traffic is captured and
  not reconstructed. Reconstruction runs when a finished session is read back, never while capturing.
- **One output**: the spool and the account, on the host. Nothing is exported.
- **Most of the configuration contract.** [contract/config/CONFIG.md](contract/config/CONFIG.md)
  specifies packs, processing pipelines, subscribers, policy documents, traffic filtering, turning
  plaintext retention off, export, and other kinds of sink. The program implements none of them, and
  refuses a configuration that asks for any of them, naming the section. Of a target's five
  `descendants` answers, three accept one value each.
- **A reload only adds.** It puts in force a new target that needs no probe beyond those already
  placed. Anything it would take away, and a library nothing has attached to, waits for a restart.
- **No release**: no archive, no tag, no version number.
- **Every published format is a draft and not frozen**: the record (`observer.record/1-draft`), the
  account and bundle (`observer.account/1-draft`, `observer.bundle/1-draft`), the configuration, pack
  manifest and component interface (`observer.config/draft`, `observer.pack/draft`,
  `observer.component/draft`) and the policy vocabulary (`observer.policy/draft`).
- **The account format has no worked example bundle** in this repository;
  [contract/account/ACCOUNT.md](contract/account/ACCOUNT.md) specifies it.

## Installing

### From source

You need Go 1.27 or newer.

    git clone https://github.com/evandukss/edge-observer.git
    cd edge-observer
    CGO_ENABLED=0 go build -trimpath -o observer ./cmd/observer

That builds `observer`, one static file for the machine you are on. For an x86-64 host, build it as:

    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o observer ./cmd/observer

The BPF programs are compiled into it, so the host it runs on needs no compiler, headers or library
installed for the observer. [docs/compatibility.md](docs/compatibility.md) says what the host itself
must provide.

### Release archive

No release has been published. A release is an archive, `observer-linux-amd64.tar.gz`, built from one
tagged commit. It unpacks into one directory, `observer-linux-amd64`, holding exactly these files:

    observer                 the program: one static file, linux/amd64
    README.md                this document
    docs/compatibility.md    what a host must provide, and what the observer has been seen to run on
    observer.config.json     the simplest configuration the program runs, for you to edit
    LICENSE                  the Mozilla Public License 2.0
    COMMIT                   the commit the archive was built from, one line

Beside the archive, and not inside it, is `observer-linux-amd64.sha256`: the digest of the program file.
The other documents this README links to are in the repository, not in the archive.

## Using it

Four steps: configure, check the host, run, inspect. Every command runs the program you built,
`./observer`, from the directory it is in.

### 1. Configure

The observer reads one JSON file, the operator configuration specified in
[contract/config/CONFIG.md](contract/config/CONFIG.md). Start from the simplest one the program runs:

    cp contract/config/examples/no-extension.config.json observer.config.json

In a release archive that file is already there, as `observer.config.json`. Four things in it are yours
to set.

**Where it writes.** `observer.directory` is where the observer keeps its pid file and one directory per
run under `sessions`; it is created if missing. `observer.log` is `stdout`, or an absolute path for a
log file.

**What it observes.** `observation_scope.targets` is the list of processes you approve, and no other
process is observed. For one process already running, find what identifies it:

    pgrep -a <program name>                 # its pid and command line (or find it with ps)
    readlink /proc/<pid>/exe                # the file the kernel runs: this is "exe"
    tr '\0' '\n' < /proc/<pid>/cmdline      # its command line, one entry per line

Then write the target, with `args` being every command-line entry after the first:

    {
      "name": "api",
      "match": {"exe": "/usr/bin/python3.11", "args": ["/srv/api/server.py"]},
      "descendants": {"existing": true, "future": true, "boundary": "exec_ends_the_grant",
                      "root_exit": "survivors_keep_their_grants", "replacement": "needs_restart"}
    }

Every condition in `match` must hold. Besides `exe` and `args` there are three more: `cgroup`, a path on
the unified cgroup hierarchy that the process must be in or below; `port`, a listening TCP port whose
holders are selected, with an optional `interface`; and `pid`, which names one process as
`{"pid": N, "start": S, "boot": B}`. `descendants.existing` and `descendants.future` choose whether the
matched process's children already running, and the ones it creates later, are observed too; the other
three answers are fixed and must be written exactly as above. `observation_scope.exclude` lists matches
that are never observed, whatever a target says.

**Leave every other section as it is in the file.** The program implements what that file asks for -
every connection of an approved process, kept on this host - and refuses any other value there with a
message naming the section, rather than ignoring it.

Check what it would select, attaching nothing:

    ./observer dry-run observer.config.json --text

A target that selected nothing says why. Fix the target until yours shows the process you meant.

### 2. Check the host

Attaching needs root, or the capabilities [docs/compatibility.md](docs/compatibility.md) lists. Ask
first whether this host can run it, as the user that will run it:

    sudo ./observer preflight observer.config.json --text

It answers `READY`, or `NOT READY` naming each requirement missing, or `INDETERMINATE` naming what it
could not read, and exits 0 only on `READY`. It attaches nothing. Do not start on anything but `READY`.

### 3. Run

    sudo ./observer start observer.config.json

It runs in the foreground and prints one JSON record per line; the first says it activated and what it
attached to. Now use the service you approved so traffic crosses it - nothing is observed on a quiet
process. From another terminal, `sudo ./observer inspect observer.config.json --text` shows the running
session's account as it stands.

    sudo ./observer stop observer.config.json

(or Ctrl-C in the first terminal) ends the run. `stop` prints the session it ended, whether it sealed
completely, and the path of the account it sealed.

### 4. Inspect

A finished run is a directory: `<observer.directory>/sessions/<session>`, the session `stop` named.

    sudo ./observer inspect /var/lib/observer/sessions/<session> --text

That reads the directory alone. No running observer and no configuration is needed, so the directory
can be copied to another machine and inspected there with the same program. Its files are readable only
by the user that ran the observer - root, above - so either inspect as that user or copy the directory
and give the copy to yourself. Without `--text` it prints the account as JSON.

The account says what was attached, what was seen, and what was lost. **Read what it says was lost
before believing anything else in it**: a run that lost events is not evidence about what crossed the
host. And a run that saw nothing is only evidence of a quiet process if the account also says the
probes were attached.

After the account, `--text` prints the exchanges reconstructed from the spool beside it: each connection
under its process, with whether that process was the server or the client, and under it each request's
method and path and the status of the response to it, every header by name, and each body by its size
and JSON shape. It prints no header value and no body byte. Reconstruction runs here, as the directory
is read, on the machine running `inspect`, and it reads the session's whole spool, every value
included, into memory to find that structure. Leaving the values out of what it prints removes nothing:
they were read to build the view, and the spool still holds them. A directory holding the account alone
says that nothing was reconstructed, rather than showing a session in which nothing crossed.

**The header values and body bytes are in the spool files beside the account, in full**: `.jsonl` files
of one JSON record per line, where each record of what crossed carries those bytes base64-encoded. That
is plaintext in all but spelling - whatever credentials and personal data the observed traffic carried
are in it, one decode away - and it stays on this host until you delete it.

## Documentation

    docs/compatibility.md       kernels, architectures, TLS libraries and protocols: declared and observed
    docs/architecture.md        how a capture flows through the packages, and what each one owns
    docs/extension-guide.md     adding a TLS library, a protocol or an output, and what stops each today
    contract/                   the formats: configuration, policy, record, account, acceptance

[CONTRIBUTING.md](CONTRIBUTING.md) says how to build, test and propose a change,
[GOVERNANCE.md](GOVERNANCE.md) who decides, [SECURITY.md](SECURITY.md) how to report a vulnerability
privately, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) what is expected of everyone taking part.

## Licence

The probes are licensed under GPL-2.0: the BPF program sources, `bpf/*.c` and `bpf/*.h`, as their
`SPDX-License-Identifier` headers state. Everything else is licensed under the Mozilla Public License
2.0, in [LICENSE](LICENSE).

The programs declare their licence to the kernel as GPL because they call helpers the kernel offers only
to GPL-compatible programs: `bpf_probe_read_kernel`, `bpf_probe_read_user` and `bpf_get_current_task`.
