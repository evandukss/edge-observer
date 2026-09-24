# Contributing

Anyone may open an issue or a pull request, and the maintainer reviews every one
([GOVERNANCE.md](GOVERNANCE.md)). This file says how to build and test a change and how to propose it.
[docs/architecture.md](docs/architecture.md) says what each package does, and
[docs/extension-guide.md](docs/extension-guide.md) says where a new TLS library, protocol or output
goes.

A security problem is reported privately, never in an issue or a pull request: see
[SECURITY.md](SECURITY.md).

## What you need

- **Linux.** The program is Linux only, and the tests read `/proc`.
- **Go 1.27 or newer**, the version `go.mod` names.
- **For the privileged tests**: root, a kernel with BTF (see
  [docs/compatibility.md](docs/compatibility.md)), a C compiler and the OpenSSL 3 development files,
  because the tests compile small C programs that link against `libssl`. On Debian:

      sudo apt-get update
      sudo apt-get install -y gcc libssl-dev

- **For changing the BPF programs**: clang and the libbpf headers. On Debian:

      sudo apt-get install -y clang libbpf-dev

- **For the linter**: golangci-lint, at the version the project uses:

      go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2

## Building

    go build ./...
    CGO_ENABLED=0 go build -trimpath -o observer ./cmd/observer

The second command builds the program as one static file. The compiled BPF programs are committed, so
building needs no BPF toolchain.

## Checking a change

    gofmt -l .
    go vet ./... && go vet -tags attach ./...
    "$(go env GOPATH)/bin/golangci-lint" run ./...
    "$(go env GOPATH)/bin/golangci-lint" run --build-tags attach ./...
    go test ./...
    sudo env "PATH=$PATH" go test -tags attach -p 1 ./probe/openssl/attach/... ./ebpf/...

`gofmt -l .` prints nothing when every file is formatted.

Run by a user who cannot act as another user, `go test ./...` fails three tests with `operation not
permitted`, because each starts a process as uid 65534:
`TestConfirmChecksTheStartAnyoneMayReadAndNamesAFailedReadForWhatItIs` in `ebpf`, and
`TestAListenerWhoseOwnerCannotBeReadIsUnresolvedRatherThanEmpty` and
`TestAProcessThisReaderMayNotReadIsNamedAsUnreadableRatherThanAbsent` in `process`. Run as root, they
pass. Any other finding from these commands is new.

The tests behind the `attach` build tag load the BPF programs and place real probes on processes the
tests start, so they run as root and only on a kernel that allows it. They take several minutes, and
`-p 1` runs the two packages one after the other.

Inside a container they also need the host's pid namespace: with Docker, `--privileged` and
`--pid=host`. In one run without `--pid=host`, 27 of the 182 tests failed. Two of those failures name
a cause: the tests compare the pids they see with the host pids the kernel reports. The cause of the
other 25 is not established, and neither is whether the observer itself needs the host's pid
namespace.

## Changing the BPF programs

The programs are C, in `bpf/ssl.bpf.h`, `bpf/sslfull.bpf.c` and `bpf/sslmeta.bpf.c`. A change to any of
them is followed by regenerating the compiled objects and their Go bindings, and checking the helpers
the new objects call:

    go generate ./bpf/
    go run ./bpf/cmd/verify

Commit the regenerated files with the change. On an unchanged tree, `go generate ./bpf/` reproduces the
committed files byte for byte with clang 19 on Debian 13. The generate directives in `bpf/gen.go` name
the arm64 include directory (`-I/usr/include/aarch64-linux-gnu`), and regenerating has only been done
on arm64.

`bpf/verify.go` holds the list of kernel helpers each program may call. A program that calls a helper
not on that list fails the check, so giving a program a new capability is a deliberate edit to that
list, reviewed with the change.

## Proposing a change

- **One change per pull request**, on a branch cut from the current `main` and named for what it does:
  `feat/`, `fix/`, `docs/` or `test/`, then a short description.
- **A pull request is squash-merged**, so it becomes one commit on `main`. Its title and description
  are that commit's message: say what the change does and why.
- **A change carries its tests**, and **a change that makes a document false corrects the document** in
  the same pull request.
- **For anything larger than a fix, open an issue first**, so the maintainer can say whether it fits
  before you build it.
