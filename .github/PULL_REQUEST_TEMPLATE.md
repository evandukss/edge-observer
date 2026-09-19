<!-- What this changes and why. The diff shows what changed; say what a reviewer cannot see from it. -->

## How it was checked

<!--
The gate runs on this pull request. Each of its checks also runs locally with Docker:
.github/gate/run.sh static | unit | bpf | archive <commit> | attach

The attach tests load BPF programs and need a privileged container on a Linux kernel.
If this change touches probes, attachment or bpf/, say whether you ran them, and on
which kernel and architecture (uname -srm).

A change to bpf/*.c or bpf/*.h commits the objects and bindings `go generate ./bpf/`
produces from it.
-->
