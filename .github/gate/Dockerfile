# The toolchains the gate runs in. The tree is mounted at run time, never copied
# in, so an image is reused across changes and every run measures the checkout it
# was started from.
#
# The base is pinned by digest, so every run builds with the same Go on the same
# Debian. The digest is a multi-platform index: amd64 and arm64 resolve from it.
ARG BASE=golang:1.27.1-trixie@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea

FROM ${BASE} AS go
# The attach tests compile small C programs against OpenSSL.
RUN apt-get update \
	&& apt-get install -y --no-install-recommends libssl-dev \
	&& rm -rf /var/lib/apt/lists/*
RUN go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
# A mounted checkout belongs to another user, so stamping a build with its
# version control state fails; the archive records its commit in a file instead.
ENV GOFLAGS=-buildvcs=false
WORKDIR /src

FROM ${BASE} AS bpf
# The committed BPF objects are what this clang produces from bpf/, byte for
# byte, so every package that decides the output is pinned. A different clang is
# a different object, and an image that cannot install these versions fails to
# build rather than comparing against a different compiler.
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		clang=1:19.0-63 clang-19=1:19.1.7-3+b1 libclang-cpp19=1:19.1.7-3+b1 \
		llvm=1:19.0-63 llvm-19=1:19.1.7-3+b1 libllvm19=1:19.1.7-3+b1 \
		libbpf-dev=1:1.5.0-3 libelf-dev=0.192-4 \
	&& rm -rf /var/lib/apt/lists/*
ENV GOFLAGS=-buildvcs=false
WORKDIR /src
