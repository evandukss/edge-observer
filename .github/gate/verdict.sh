#!/usr/bin/env bash
# The gate's verdict: every obligation by name, with what happened to it, and
# green only when every obligation the change is subject to ran and passed.
#
# Reads two JSON documents from the environment: NEEDS, the results of the jobs
# the verdict waits on, and PLAN, what plan.sh decided. An obligation the plan
# excused is named with its reason; one that applied and did not run is not
# green, whatever the reason it did not run.
set -euo pipefail

obligations="static unit bpf artifact attach"

describe() {
	case "$1" in
	static) echo "static: gofmt, vet and lint, untagged and under the attach tag; linux/amd64 and linux/arm64 builds" ;;
	unit) echo "unit: go test ./..., amd64 and arm64" ;;
	bpf) echo "bpf: every object and binding regenerated from source and compared byte for byte; verify" ;;
	artifact) echo "artifact: the release archive built, checked against README.md, and discarded" ;;
	attach) echo "attach: the attach-tagged tests, privileged" ;;
	esac
}

needs="${NEEDS:?NEEDS is not set}"
plan_result="$(jq -r '.plan.result // "absent"' <<<"$needs")"
plan="${PLAN:-}"
if [ "$plan_result" != success ] || [ -z "$plan" ]; then
	echo "verdict: NOT GREEN - the plan did not complete ($plan_result), so no obligation can be judged"
	exit 1
fi

lines=()
ran=0
excused=0
not_green=0
for obligation in $obligations; do
	applies="$(jq -r --arg o "$obligation" '.obligations[$o].applies' <<<"$plan")"
	why="$(jq -r --arg o "$obligation" '.obligations[$o].why' <<<"$plan")"
	result="$(jq -r --arg o "$obligation" '.[$o].result // "absent"' <<<"$needs")"
	runners="$(jq -r '.runners | join(", ")' <<<"$plan")"
	if [ "$applies" = false ]; then
		if [ "$result" = skipped ]; then
			state="not applicable: $why"
			excused=$((excused + 1))
		else
			state="$result, though excused: $why"
			not_green=$((not_green + 1))
		fi
	elif [ "$result" = success ]; then
		state="RAN, passed"
		if [ "$obligation" = attach ] && [ -n "$runners" ]; then
			state+=" on $runners"
		fi
		ran=$((ran + 1))
	elif [ "$result" = skipped ] && [ "$obligation" = attach ] && [ -z "$runners" ]; then
		state="PENDING AUTHORISATION: it applies ($why), and no runner is authorised for privileged execution in .github/gate/privileged-runners"
		not_green=$((not_green + 1))
	elif [ "$result" = failure ]; then
		state="RAN, FAILED"
		not_green=$((not_green + 1))
	else
		state="DID NOT RUN ($result), and it applies: $why"
		not_green=$((not_green + 1))
	fi
	lines+=("$(describe "$obligation")"$'\n'"    $state")
done

echo "change: $(jq -r '.basis' <<<"$plan"), $(jq -r '.changed' <<<"$plan") paths"
jq -r 'if .all then "every obligation applies: \(.all)" else (.paths[] | "  \(.path): \(if (.excused | length) > 0 then "excused from \(.excused | join(" ")): " else "" end)\(.why)") end' <<<"$plan"
printf '%s\n' "${lines[@]}"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	{
		echo "| obligation | verdict |"
		echo "|---|---|"
		for line in "${lines[@]}"; do
			state="${line#*$'\n'}"
			printf '| %s | %s |\n' "${line%%$'\n'*}" "${state#    }"
		done
	} >>"$GITHUB_STEP_SUMMARY"
fi

if [ "$not_green" -eq 0 ]; then
	echo "verdict: GREEN - every obligation this change is subject to ran and passed: $ran ran, $excused not applicable"
	exit 0
fi
echo "verdict: NOT GREEN - $not_green of the obligations this change is subject to did not run and pass"
exit 1
