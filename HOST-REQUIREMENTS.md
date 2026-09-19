# What a host must provide to run the Edge Observer

For an operator deciding whether the observer can run on a machine, and for whoever supports them.
**Every requirement here is judged by `observer preflight` before anything attaches**
(package `preflight`), which answers READY, or NOT READY naming what is missing, or INDETERMINATE
naming what it could not read.

## Required

| | |
|---|---|
| **Linux** | The shipped build is `linux/amd64`. `arm64` is built and tested but not shipped. |
| **Linux 5.15 or newer** | Ring buffer maps, atomic add-and-fetch in BPF, iteration over map elements, uprobe and kernel-probe attachment through the performance-event interface. Measured running on 6.1, 6.11 and 6.12. **The version is what is published and tested against; the real gate is the load.** Vendor kernels backport, so a kernel numbered below this may hold everything needed and one numbered above may lack a configuration option - so `observer preflight` both loads the program the way start does and reports a release below this as missing, because below it nothing is declared. The observer refuses at start with the reason when the kernel will not take its programs. |
| **Kernel BTF** | `/sys/kernel/btf/vmlinux` present and readable. This is what the observer's programs are relocated against when they load, and it is what the endpoint mechanism reads a socket through. On by default in mainstream distribution kernels since 2020-21; absent on older long-term kernels and on minimal or custom builds. Check it with `test -r /sys/kernel/btf/vmlinux`. |
| **OpenSSL 3.x, dynamically linked** | The plaintext adapter attaches to `libssl.so` as a shared library. A statically linked TLS stack, or a different TLS library, is not covered by the probe catalogue (`probe/catalog.go`) - the observer reports the process as unsupported rather than observing it partially. |
| **Capabilities at start** | `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_RESOURCE`, `CAP_DAC_READ_SEARCH` (package `preflight`). They are needed to load programs and place probes, and the observer **drops them after attaching**. |

## Not required

Stated because each one is a question operators ask, and because the answer is what makes this
installable on a machine nobody prepared:

- **No compiler and no kernel headers.** The BPF objects ship compiled; the kernel's own BTF is what
  makes them portable.
- **No mounted tracefs.** Kernel probes attach through the performance-event interface, which needs
  no tracefs; the observer never mounts it and never silently falls back to it.
- **No cgroup attachment**, and no membership requirement on the observed processes.
- **No change to the observed application** - no library, no environment variable, no code change,
  no recompile.
- **No restart of the observed processes.** The observer attaches to processes that are already
  running.

## What the observer will not do on a host that qualifies

- It observes only the processes an approval names, and the check is in the kernel ahead of every
  read.
- It writes no process memory, and reads none outside an approved process's TLS calls - that is a
  property of the compiled object rather than a setting (`bpf/verify.go`).
- Nothing leaves the host: the one output this build has keeps what it writes on the host.

## Checking a host before a capture

    observer preflight <configuration> [--text]

It judges each requirement above against the host, and the TLS library of each process the
configuration selects, and gives a verdict: READY only when every requirement is met, NOT READY naming
each one missing, INDETERMINATE when nothing is missing and something could not be read. A requirement
it cannot establish is never counted as met. It exits 0 only on READY.
