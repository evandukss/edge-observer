# Compatibility

What a host must provide to run the observer, and what the project has actually seen it run on. Two
words keep those apart:

- **declared**: the code states the requirement, and `observer preflight` checks it before anything
  attaches;
- **observed**: a recorded run loaded the observer's programs and attached them on that host.

A kernel, architecture or library missing from the observed lists has not been tried. It is not known
to fail.

## At a glance

    operating system   Linux                                             declared
    architecture       x86-64                                            declared, observed
                       arm64                                             observed, NOT declared:
                                                                         preflight refuses it
    kernel             5.15 or newer, publishing its BTF                 declared
                       5.15 itself                                       never observed
                       6.11.11-linuxkit (arm64), 7.0.12-linuxkit (arm64) observed
                       6.17.0-1022-azure (x86-64)                        observed
    TLS library        OpenSSL 3.x, loaded as a shared library           declared
                       OpenSSL 3.5                                       observed
    protocol           HTTP/1.1, with JSON bodies described by shape     reconstructed
                       anything else                                     captured, not reconstructed

## Checking a host

    observer preflight <configuration> [--text]

It judges each requirement below against the host, and the TLS library of every process the
configuration selects. It answers READY only when every requirement is met, NOT READY naming each one
missing, or INDETERMINATE when nothing is missing and something could not be read. A requirement it
cannot establish never counts as met, and it exits 0 only on READY. It attaches nothing.

## Kernel

**Declared: Linux 5.15 or newer.** The binding constraint is the programs' atomic fetch-and-add
instructions, which three of their allocators need and which the kernel's verifier refuses before 5.12.
The ring buffer (5.8) and the helper that reads a pid inside a named pid namespace (5.7) are older. 5.15
is the published floor, above the 5.12 the compiled programs force.

**No run on 5.15 is recorded**, so the floor is the oldest kernel the observer is believed to run on,
not the oldest it is known to. Every account the observer writes says so. What would settle it is one
run on a 5.15 x86-64 host with no tracefs mounted: load the program and keep the verifier's answer,
place every probe before the capabilities are dropped, then put traffic through an approved process.

**Observed**, each on one host, both under Docker Desktop:

    6.11.11-linuxkit   arm64
    7.0.12-linuxkit    arm64

**The version is not the gate; the load is.** Vendor kernels backport features, so a kernel numbered
below 5.15 may hold everything needed and one above it may lack a build option. `observer preflight`
therefore both loads the program the way `start` does, and reports a release below 5.15 as missing.
`observer start` refuses, with the kernel's reason, when the kernel will not take the programs.

**Kernel BTF is required**: `/sys/kernel/btf/vmlinux`, present and readable. The programs read kernel
structures through CO-RE, relocated against that file when they load. It comes from the build option
`CONFIG_DEBUG_INFO_BTF`, not from a version, so a kernel well above 5.15 can still lack it. Without it
the load is refused rather than run degraded. To check:

    test -r /sys/kernel/btf/vmlinux && echo present

## Architecture

**Declared: x86-64 only.** `observer preflight` reports any other architecture as missing, so on arm64
its verdict is NOT READY. It also reports the architecture as missing when the program is running
emulated - the kernel's own architecture and the one `uname` reports disagree - because a probe on an
emulated process never fires.

**Observed: both.** The x86-64 programs were first run on 2026-09-22, on a hosted runner reporting
`Linux 6.17.0-1022-azure x86_64`: the attach suite collected 182 tests against its floor of 182, ran
182, skipped 0, failed 0, and exited 0. **Nothing opted out of the hardware** - a test here that needs
a kernel feature fails rather than skipping, so a skip count of zero means every one of those tests
met the machine.

**That those tests exercised the x86-64 objects follows by construction rather than from a line in
that run's output**: `full_x86_bpfel.go` is built `(386 || amd64) && linux` and `full_arm64_bpfel.go`
`arm64 && linux`, each embedding its own object, so a binary built and run on an x86-64 host can carry
no other. The run's detailed log stayed on the runner, so no recorded line says a probe was placed
there; what is recorded is the suite that places them passing on that machine.

Before that date every recorded load and attach was on arm64.

**AND THE INVERSION THAT REMAINS IS SHARPER NOW, NOT SOFTER: the observer refuses arm64, which is the
only architecture it had ever run on until that date, and which it demonstrably runs on.** `preflight`
returns NOT READY there because the declaration is x86-64 only. Whether that declaration should change
is a product decision with a shipping consequence - the release archive is `observer-linux-amd64` -
and this document records the fact rather than taking it.

The program builds for both: `GOOS=linux GOARCH=amd64` and `GOOS=linux GOARCH=arm64`, each embedding
that architecture's compiled programs.

## Privileges

Attaching needs root, or these capabilities:

    CAP_BPF  CAP_PERFMON  CAP_SYS_ADMIN  CAP_SYS_PTRACE  CAP_SYS_RESOURCE  CAP_DAC_READ_SEARCH

They are needed to load the programs and place the probes. The observer drops every capability once
the probes are placed.

**In a container**, whether the observer needs the host's pid namespace is not established. Its tests
need it: in one run without it, 27 of their 182 failed. Two of those failures name a cause, the tests
comparing the pids they see with the host pids the kernel reports; the cause of the other 25 is not
established.

## TLS libraries

**Declared: OpenSSL 3.x, loaded by the observed process as a shared library** (`libssl.so.3`).
`observer preflight` checks, for every process the configuration selects, that a `libssl.so` is mapped
and that its major version is 3.

**Observed: OpenSSL 3.5.**

The functions the observer attaches to are listed in `probe/catalog.go`, with the OpenSSL release that
introduced each: `SSL_read`, `SSL_write`, the `_ex` forms of both, `SSL_write_ex2`, the two TLS 1.3
early-data functions, and `SSL_free` to tell one connection from the next. `SSL_peek` and
`SSL_peek_ex` are catalogued and not attached, because the next read returns the same bytes again.

**A process with no `libssl.so` mapped is reported unsupported and is not observed**: OpenSSL linked
statically into the program, or any TLS implementation that is not a `libssl.so`. The observer does not
fall back to guessing plaintext from socket traffic.

**The major version is checked by `observer preflight` and not by the adapter.** Preflight reports a
`libssl.so` whose major version is not 3 as missing. The adapter attaches to any `libssl.so` that exports
the catalogued functions, so a start on such a process is outside what is declared, and it has not been
observed.

[extension-guide.md](extension-guide.md) says what adding another library takes, and what currently stops
a second one from attaching.

## Protocols

**HTTP/1.1** is reconstructed into requests and responses: start line, headers by name, and each body by
its size. A JSON body is also described by its shape - field names, nesting and each value's kind - and a
body that is not JSON is reported without a shape, with the reason. The parser is strict: where two
endpoints could read a message differently, it refuses the message and says why rather than choosing.

**There is no parser for any other protocol, HTTP/2 included.** Such traffic is still captured into the
spool, and is not reconstructed.

Reconstruction runs when a finished session is read back with `observer inspect`, never while it is
capturing.

## Not required

Each of these is a question operators ask, and the answer is what lets the observer run on a machine
nobody prepared:

- **No compiler and no kernel headers.** The programs ship compiled inside the observer, and the
  kernel's own BTF is what makes them portable.
- **No mounted tracefs.** Kernel probes attach through the performance-event interface. The observer
  never mounts tracefs and never falls back to it.
- **No cgroup attachment**, and no requirement on which cgroup an observed process is in.
- **No change to the observed application**: no library, no environment variable, no code change, no
  recompile.
- **No restart of the observed processes.** The observer attaches to processes that are already
  running.
