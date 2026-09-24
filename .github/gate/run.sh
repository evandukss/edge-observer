#!/usr/bin/env bash
# Runs one obligation of the gate: builds the image it needs, runs it in a
# container with this checkout mounted read-only, captures the output to files
# and reads the result from the files - never from a pipeline's exit status.
#
# usage: .github/gate/run.sh <static|unit|attach|bpf>
#        .github/gate/run.sh archive <commit>
#
# The logs, and the archive, go under $GATE_OUT/<obligation>; without GATE_OUT a
# fresh temporary directory is used and named on the last line.
set -euo pipefail

usage="usage: run.sh <static|unit|attach|bpf> | run.sh archive <commit>"
obligation="${1:?$usage}"
commit="${2:-}"
if { [ "$obligation" = archive ] && [ $# -ne 2 ]; } || { [ "$obligation" != archive ] && [ $# -ne 1 ]; }; then
	echo "$usage" >&2
	exit 2
fi
root="$(cd "$(dirname "$0")/../.." && pwd)"

# Per obligation: the image stage, the memory cap on the container, and how the
# result is read. A cap is twice the container's measured peak (the "memory
# peak" line every run prints), rounded up to 64 MiB.
#
# A floor is the number of tests the selection collects on the tree that set it.
# It is raised when tests are added and never lowered to let a run pass: a
# collection below it means tests stopped being compiled or found.
privileged=()
case "$obligation" in
static)
	target=go memory=2304m result=steps steps=7
	;;
unit)
	target=go memory=1472m result=tests floor=522 list=list-unit
	;;
attach)
	# Loading BPF programs and placing uprobes needs a privileged container. Some
	# of these tests approve a process by the pid they see and match it against
	# the pid the kernel reports, which is the host's, so the container shares the
	# host's pid namespace.
	target=go memory=1280m result=tests floor=182 list=list-attach
	privileged=(--privileged --pid=host)
	;;
bpf)
	target=bpf memory=1152m result=bpf
	;;
archive)
	target=go memory=1664m result=steps steps=1
	;;
*)
	echo "run.sh: unknown obligation '$obligation'; $usage" >&2
	exit 2
	;;
esac

out="${GATE_OUT:-$(mktemp -d)}/$obligation"
mkdir -p "$out"

annotate() {
	if [ "${GITHUB_ACTIONS:-}" = true ]; then
		echo "::error title=$obligation::$*"
	fi
}

image="edge-observer-gate:$target"
if ! docker build --target "$target" --tag "$image" "$root/.github/gate" >"$out/build.log" 2>&1; then
	echo "$obligation: FAILED - the $target image did not build, see $out/build.log"
	annotate "the $target image did not build"
	exit 1
fi

run_in() {
	docker run --rm --memory="$memory" --memory-swap="$memory" ${privileged[@]+"${privileged[@]}"} \
		--volume "$root:/src:ro" --volume "$out:/out" \
		"$image" /src/.github/gate/in-container.sh "$@"
}

case "$result" in

tests)
	# THREE GUARDS, and each catches what the others cannot:
	#   collection  the count listed is at least the floor, so a narrowed pattern
	#               or a test file that stopped compiling fails
	#   ran         every listed test reached a result, so a run that died
	#               partway fails however few failures it printed
	#   skip        nothing skipped, since a skipped test is still listed and
	#               still counted as having run
	# Members are counted by what a member looks like, never by lines.
	set +e
	run_in "$list" >"$out/collect.log" 2>"$out/collect.stderr.log"
	list_code=$?
	run_in "$obligation" >"$out/run.log" 2>&1
	code=$?
	set -e

	collected="$(grep -Ec '^(Test|Fuzz|Example)' "$out/collect.log" || true)"
	ran="$(grep -Ec '^--- (PASS|FAIL|SKIP): ' "$out/run.log" || true)"
	failed="$(grep -Ec '^--- FAIL: ' "$out/run.log" || true)"
	skipped="$(grep -Ec '^--- SKIP: ' "$out/run.log" || true)"

	verdicts=()
	if [ "$list_code" -ne 0 ]; then
		verdicts+=("the listing exited $list_code (see collect.stderr.log)")
	fi
	if [ "$collected" -lt "$floor" ]; then
		verdicts+=("$collected tests collected, below the floor of $floor")
		echo "$obligation: guard collection: $collected collected, floor $floor: FAILED"
	else
		echo "$obligation: guard collection: $collected collected, floor $floor: ok"
	fi
	if [ "$ran" -ne "$collected" ]; then
		verdicts+=("$ran of $collected collected tests reached a result, so the run stopped partway")
		echo "$obligation: guard ran: $ran of $collected collected ran: FAILED"
	else
		echo "$obligation: guard ran: $ran of $collected collected ran: ok"
	fi
	if [ "$skipped" -ne 0 ]; then
		verdicts+=("$skipped tests skipped: $(grep -E '^--- SKIP: ' "$out/run.log" | sed -E 's/^--- SKIP: ([^ ]+).*/\1/' | paste -sd, -)")
		echo "$obligation: guard skip: $skipped skipped: FAILED"
	else
		echo "$obligation: guard skip: 0 skipped: ok"
	fi
	if [ "$failed" -ne 0 ]; then
		verdicts+=("$failed tests failed: $(grep -E '^--- FAIL: ' "$out/run.log" | sed -E 's/^--- FAIL: ([^ ]+).*/\1/' | paste -sd, -)")
	fi
	if [ "$code" -ne 0 ]; then
		verdicts+=("go test exited $code")
	fi
	summary="$collected collected (floor $floor), $ran ran, $skipped skipped, $failed failed, go test exit $code"
	;;

steps)
	set +e
	run_in "$obligation" "$commit" >"$out/run.log" 2>&1
	code=$?
	set -e
	ok="$(grep -Ec '^step .* ok$' "$out/run.log" || true)"
	verdicts=()
	while IFS= read -r line; do
		verdicts+=("$line")
	done < <(grep -E '^(step .* FAILED|refused: .*)$' "$out/run.log" || true)
	if [ "$ok" -ne "$steps" ]; then
		verdicts+=("$ok of $steps steps passed")
	fi
	if [ "$code" -ne 0 ]; then
		verdicts+=("exit $code")
	fi
	summary="$ok of $steps steps passed, exit $code"
	;;

bpf)
	set +e
	run_in bpf >"$out/run.log" 2>&1
	code=$?
	set -e
	committed="$(sed -nE 's/^bpf committed ([0-9]+)$/\1/p' "$out/run.log")"
	generated="$(sed -nE 's/^bpf generated ([0-9]+)$/\1/p' "$out/run.log")"
	matched="$(grep -Ec '^match ' "$out/run.log" || true)"
	ok="$(grep -Ec '^step (verify|test) ok$' "$out/run.log" || true)"
	verdicts=()
	if [ -z "$committed" ] || [ "$committed" -eq 0 ] || [ "$matched" -ne "$committed" ] || [ "${generated:-0}" -ne "$committed" ]; then
		verdicts+=("${matched} of ${committed:-no} committed objects and bindings match a fresh build of their source, ${generated:-none} generated")
	fi
	if [ "$ok" -ne 2 ]; then
		verdicts+=("$ok of 2 checks passed (verify, test)")
	fi
	if [ "$code" -ne 0 ]; then
		verdicts+=("exit $code")
	fi
	summary="${matched} of ${committed:-0} committed objects and bindings match a fresh build, $ok of 2 checks passed, exit $code"
	;;

esac

grep -E '^(memory peak|archive |step |bpf |match |DIFFER |missing |extra |refused: )' "$out/run.log" || true

if [ "${#verdicts[@]}" -eq 0 ]; then
	echo "$obligation: PASSED - $summary; logs $out"
	exit 0
fi
echo "$obligation: FAILED - $(printf '%s; ' "${verdicts[@]}")logs $out"
for verdict in "${verdicts[@]}"; do
	annotate "$verdict"
done
exit 1
