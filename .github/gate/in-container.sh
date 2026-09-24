#!/usr/bin/env bash
# Runs inside the gate image with the checkout mounted read-only at /src and an
# output directory at /out. Each subcommand writes its result to stdout; run.sh
# captures that to a file and reads the result from the file.
set -euo pipefail
cd /src

# The container's own high-water mark, so the memory cap run.sh sets can be
# re-measured from any run's log.
trap 'if [ -r /sys/fs/cgroup/memory.peak ]; then echo "memory peak $(cat /sys/fs/cgroup/memory.peak)"; fi' EXIT

# The attach-tagged tests live in these packages. They are named rather than
# matched with ./..., which under the tag would run every other package's tests a
# second time with privilege.
attach_packages=(./probe/openssl/attach/... ./ebpf/...)

refuse() {
	echo "refused: $*"
	exit 1
}

case "${1:?usage: in-container.sh <list-unit|unit|list-attach|attach|static|bpf|archive COMMIT>}" in

list-unit)
	go test -list '.*' ./...
	;;

unit)
	go test -count=1 -v ./...
	;;

list-attach)
	go test -tags attach -list '.*' "${attach_packages[@]}"
	;;

attach)
	# One package at a time: both attach probes to real processes on one kernel,
	# and side by side a short-lived child's traffic goes unreported.
	go test -count=1 -p 1 -tags attach -timeout 10m -v "${attach_packages[@]}"
	;;

static)
	status=0
	if unformatted="$(gofmt -l .)" && [ -z "$unformatted" ]; then
		echo "step gofmt ok"
	else
		printf 'gofmt: not formatted:\n%s\n' "$unformatted"
		echo "step gofmt FAILED"
		status=1
	fi
	# A static check examines only the files that compile under the tags it is
	# given, so it runs under every tag set the tests are built with.
	for tags in untagged attach; do
		vet=()
		lint=()
		if [ "$tags" = attach ]; then
			vet=(-tags=attach)
			lint=(--build-tags=attach)
		fi
		if go vet "${vet[@]}" ./...; then echo "step vet $tags ok"; else echo "step vet $tags FAILED"; status=1; fi
		if golangci-lint run "${lint[@]}" ./...; then echo "step lint $tags ok"; else echo "step lint $tags FAILED"; status=1; fi
	done
	# The shipped build, and the other architecture the tests run on.
	for arch in amd64 arm64; do
		if CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o /dev/null ./cmd/observer; then
			echo "step build linux/$arch ok"
		else
			echo "step build linux/$arch FAILED"
			status=1
		fi
	done
	exit "$status"
	;;

bpf)
	# Regenerate every object and binding from source in a copy with the
	# committed ones removed, then require the two sets to be the same files,
	# byte for byte. A committed file its source does not produce fails, and so
	# does a produced file nobody committed.
	generated() {
		(cd "$1/bpf" && find . -maxdepth 1 -type f \( -name '*_bpfel.o' -o -name '*_bpfel.go' \) -printf '%P\n' | sort)
	}
	work="$(mktemp -d)"
	tar -C /src --exclude=./.git --exclude=./.jj -cf - . | tar -C "$work" -xf -
	committed="$(generated /src)"
	committed_count="$(grep -c . <<<"$committed" || true)"
	[ "$committed_count" -gt 0 ] || refuse "bpf: no committed object or binding under bpf/"
	while IFS= read -r name; do rm -- "$work/bpf/$name"; done <<<"$committed"

	(cd "$work" && go generate ./bpf/)
	fresh="$(generated "$work")"
	fresh_count="$(grep -c . <<<"$fresh" || true)"
	echo "bpf committed $committed_count"
	echo "bpf generated $fresh_count"

	status=0
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		echo "missing $name: committed, and its source does not produce it"
		status=1
	done < <(comm -23 <(echo "$committed") <(echo "$fresh"))
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		echo "extra $name: produced from source, and not committed"
		status=1
	done < <(comm -13 <(echo "$committed") <(echo "$fresh"))
	while IFS= read -r name; do
		if [ ! -f "$work/bpf/$name" ]; then
			continue
		elif cmp -s "/src/bpf/$name" "$work/bpf/$name"; then
			echo "match $name"
		else
			echo "DIFFER $name: the committed file is not what its source produces"
			status=1
		fi
	done <<<"$committed"

	# The helpers each FRESH object calls, and the committed objects' own tests.
	if (cd "$work" && go run ./bpf/cmd/verify); then echo "step verify ok"; else echo "step verify FAILED"; status=1; fi
	if go test -count=1 ./bpf/; then echo "step test ok"; else echo "step test FAILED"; status=1; fi
	exit "$status"
	;;

archive)
	commit="${2:-}"
	[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || refuse "archive: '$commit' is not a full commit id"
	arch=amd64
	name="observer-linux-$arch"
	stage="$(mktemp -d)/$name"
	mkdir -p "$stage"

	# What the archive holds is stated once, in README.md: the first indented
	# block under its "### Release archive" heading, one member path per line
	# followed by two or more spaces and a description.
	[ -f README.md ] || refuse "archive: there is no README.md to state what the archive holds"
	block="$(awk '
		/^### Release archive[[:space:]]*$/ { on = 1; next }
		on && /^#/ { exit }
		on && /^    / { inside = 1; print; next }
		on && inside && /^[[:space:]]*$/ { next }
		on && inside { exit }
	' README.md)"
	stated=""
	while IFS= read -r line; do
		[ -n "${line// /}" ] || continue
		member="$(sed -nE 's/^    ([A-Za-z0-9._/-]+)  +[^ ].*$/\1/p' <<<"$line")"
		[ -n "$member" ] || refuse "archive: README.md's archive list holds a line that names no member: '$line'"
		case "/$member/" in
		*/../* | */./* | *//*) refuse "archive: '$member' is not a path inside the archive" ;;
		esac
		stated+="$member"$'\n'
	done <<<"$block"
	stated="$(sort <<<"$stated" | grep . || true)"
	stated_count="$(grep -c . <<<"$stated" || true)"
	[ "$stated_count" -gt 0 ] || refuse "archive: README.md states no members under '### Release archive'"
	grep -qx observer <<<"$stated" || refuse "archive: README.md's list does not include the program, observer"

	# Three members are made by the build; every other one is the file at the
	# same path in the repository.
	while IFS= read -r member; do
		mkdir -p "$(dirname "$stage/$member")"
		case "$member" in
		observer)
			CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$stage/observer" ./cmd/observer ||
				refuse "archive: the program did not build"
			;;
		observer.config.json)
			cp contract/config/examples/no-extension.config.json "$stage/$member"
			;;
		COMMIT)
			printf '%s\n' "$commit" >"$stage/COMMIT"
			;;
		*)
			[ -f "$member" ] || refuse "archive: README.md states $member, and there is no such file in the repository"
			cp "$member" "$stage/$member"
			;;
		esac
	done <<<"$stated"

	built="$(cd "$stage" && find . -type f -printf '%P\n' | sort)"
	[ "$built" = "$stated" ] ||
		refuse "$(printf 'archive: the build and README.md disagree\nstated:\n%s\nbuilt:\n%s' "$stated" "$built")"
	while IFS= read -r member; do
		[ -s "$stage/$member" ] || refuse "archive: $member is empty"
	done <<<"$built"

	# The program is a static linux/amd64 executable.
	info="$(go version -m "$stage/observer")"
	for setting in CGO_ENABLED=0 GOOS=linux "GOARCH=$arch" -trimpath=true; do
		grep -qxF "$(printf '\tbuild\t%s' "$setting")" <<<"$info" || refuse "archive: the program was not built with $setting"
	done
	headers="$(readelf -lW "$stage/observer")"
	grep -q 'LOAD' <<<"$headers" || refuse "archive: readelf reports no program headers for the program"
	if grep -q 'INTERP' <<<"$headers"; then
		refuse "archive: the program asks for a dynamic loader"
	fi

	chmod 0755 "$stage/observer"
	find "$stage" -type f ! -path "$stage/observer" -exec chmod 0644 {} +
	find "$stage" -type d -exec chmod 0755 {} +
	parent="$(dirname "$stage")"
	tar --sort=name --owner=0 --group=0 --numeric-owner -C "$parent" -cf - "$name" | gzip -n >"/out/$name.tar.gz"
	(cd "$parent" && sha256sum "$name/observer") >"/out/$name.sha256"

	# What was packed, against what README.md states, directories aside.
	listing="$(tar -tzf "/out/$name.tar.gz")" || refuse "archive: the packed archive cannot be listed"
	packed="$(grep -v '/$' <<<"$listing" | sed "s|^$name/||" | sort || true)"
	[ "$packed" = "$stated" ] ||
		refuse "$(printf 'archive: the packed archive and README.md disagree\nstated:\n%s\npacked:\n%s' "$stated" "$packed")"

	# The digest, checked against the program as a person gets it: unpacked from
	# the archive into an empty directory.
	check="$(mktemp -d)"
	cp "/out/$name.sha256" "$check/"
	tar -xzf "/out/$name.tar.gz" -C "$check"
	verdict="$(cd "$check" && sha256sum -c "$name.sha256" 2>&1)" || true
	[ "$verdict" = "$name/observer: OK" ] || refuse "archive: the digest does not match the packed program: $verdict"

	echo "archive $name.tar.gz holds the $stated_count members README.md states"
	while IFS= read -r member; do echo "archive member $member"; done <<<"$stated"
	echo "archive digest $verdict"
	echo "step archive ok"
	;;

*)
	refuse "in-container.sh: unknown subcommand '$1'"
	;;

esac
