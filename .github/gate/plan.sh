#!/usr/bin/env bash
# Decides which obligations a change is subject to, from the paths it touches,
# and which runners may run the privileged one.
#
# usage: plan.sh diff <base> <head>     the paths changed between two commits
#        plan.sh paths <basis>          the paths on standard input
#        plan.sh all <why>              every obligation applies
#
# A changed path is subject to EVERY obligation unless an entry below excuses it
# from some. The list is of exceptions, never of subjects: a path nobody listed is
# checked in full, so an omission costs a run rather than letting a change skip a
# check. Deleted and renamed paths count under their old names as well as their
# new ones.
#
# Prints one JSON document; under GitHub Actions it is also the step's outputs.
set -euo pipefail

obligations="static unit bpf artifact attach"
root="$(cd "$(dirname "$0")/../.." && pwd)"

# exception <path>: the obligations the path is excused from, a bar, and why.
# An entry holds only while nothing but the named reader reads the file; a test
# that starts reading one takes it off this list in the same change.
#
# LICENSES/, THIRD_PARTY_NOTICES and REUSE.toml are left off on purpose. A change
# to them runs every obligation, which costs a run and cannot skip a check, and
# two of them ship in the release archive, so the artifact check reads them anyway.
exception() {
	case "$1" in
	.github/CODEOWNERS | .github/PULL_REQUEST_TEMPLATE.md | .github/ISSUE_TEMPLATE/*)
		echo "static unit bpf artifact attach|read by GitHub alone; no build, test or archive reads it"
		;;
	CONTRIBUTING.md | GOVERNANCE.md | SECURITY.md | CODE_OF_CONDUCT.md | docs/architecture.md | docs/extension-guide.md)
		echo "static unit bpf artifact attach|prose that no build, test or archive reads"
		;;
	README.md | docs/compatibility.md | LICENSE)
		echo "static unit bpf attach|prose shipped in the release archive, so the artifact check still applies"
		;;
	esac
}

# A file that Go source names in a string literal is read by a build or a test,
# whatever the list says, so it is excused from nothing. This sees a file named
# in a string; a test that finds files by walking a directory it does not see.
named_by_go() {
	grep -rlF --include='*.go' -- "\"$1\"" "$root" 2>/dev/null | head -n 1 || true
}

authorised_runners() {
	local list="$root/.github/gate/privileged-runners"
	[ -f "$list" ] || return 0
	sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/^[[:space:]]*//' "$list" | grep . || true
}

usage="usage: plan.sh <diff BASE HEAD|paths BASIS|all WHY>"
mode="${1:?$usage}"
case "$mode:$#" in
diff:3 | paths:2 | all:2) ;;
*)
	echo "$usage" >&2
	exit 2
	;;
esac
all_reason=""
paths=""
case "$mode" in
diff)
	base="$2"
	head="$3"
	basis="the paths changed from $base to $head"
	errors="$(mktemp)"
	if ! paths="$(git -C "$root" diff --no-renames --name-only "$base" "$head" 2>"$errors")"; then
		all_reason="the change could not be computed ($(head -n 1 "$errors"))"
		paths=""
	fi
	rm -f "$errors"
	;;
paths)
	basis="$2"
	paths="$(cat)"
	;;
all)
	basis="$2"
	all_reason="$basis"
	;;
esac

paths="$(grep . <<<"$paths" | sort -u || true)"
count="$(grep -c . <<<"$paths" || true)"
if [ -z "$all_reason" ] && [ "$count" -eq 0 ]; then
	all_reason="no changed path was found, and an empty change excuses nothing"
fi

# Every obligation starts subject to nothing, and each path that is not excused
# from it makes it apply.
json_paths="[]"
for obligation in $obligations; do
	eval "reach_$obligation=0"
done
if [ -z "$all_reason" ]; then
	while IFS= read -r path; do
		entry="$(exception "$path")"
		excused="${entry%%|*}"
		why="${entry#*|}"
		if [ -n "$entry" ]; then
			reader="$(named_by_go "$path")"
			if [ -n "$reader" ]; then
				excused=""
				why="named in Go source (${reader#"$root"/}), so every obligation applies"
			fi
		else
			why="not on the exception list, so every obligation applies"
		fi
		for obligation in $obligations; do
			case " $excused " in
			*" $obligation "*) ;;
			*) eval "reach_$obligation=\$((reach_$obligation + 1))" ;;
			esac
		done
		json_paths="$(jq -c --arg path "$path" --arg excused "$excused" --arg why "$why" \
			'. + [{path: $path, excused: ($excused | split(" ") | map(select(. != ""))), why: $why}]' <<<"$json_paths")"
	done <<<"$paths"
fi

runners="$(authorised_runners | jq -Rsc 'split("\n") | map(select(. != ""))')"

plan="$(jq -n --arg basis "$basis" --arg all "$all_reason" --argjson paths "$json_paths" \
	--argjson count "$count" --argjson runners "$runners" '{basis: $basis, changed: $count, paths: $paths,
	all: (if $all == "" then null else $all end), runners: $runners, obligations: {}}')"
for obligation in $obligations; do
	reach="reach_$obligation"
	if [ -n "$all_reason" ]; then
		applies=true
		why="$all_reason"
	elif [ "${!reach}" -gt 0 ]; then
		applies=true
		why="${!reach} of $count changed paths reach it"
	else
		applies=false
		why="all $count changed paths are excused from it"
	fi
	plan="$(jq -c --arg o "$obligation" --argjson applies "$applies" --arg why "$why" \
		'.obligations[$o] = {applies: $applies, why: $why}' <<<"$plan")"
done

jq . <<<"$plan"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
	{
		echo "plan=$(jq -c . <<<"$plan")"
		for obligation in $obligations; do
			echo "$obligation=$(jq -r --arg o "$obligation" '.obligations[$o].applies' <<<"$plan")"
		done
		echo "runners=$(jq -c .runners <<<"$plan")"
	} >>"$GITHUB_OUTPUT"
fi
