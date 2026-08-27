#!/bin/bash -eu
#
# PR fuzz runner for native testing.F targets. The target registry remains
# build.sh, and check_targets.sh proves that registry exactly matches the
# Fuzz* functions under pkg/. Each target gets an equal share of the configured
# fuzz-time allotment and one fuzz worker; two single-worker target processes
# run concurrently.

set -o pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

fuzz_total_seconds="${FUZZ_TOTAL_SECONDS:-300}"
fuzz_max_parallel="${FUZZ_MAX_PARALLEL:-2}"
fuzz_wall_timeout_seconds="${FUZZ_WALL_TIMEOUT_SECONDS:-300}"
fuzz_target_grace_seconds="${FUZZ_TARGET_GRACE_SECONDS:-45}"
fuzz_log_dir="${FUZZ_LOG_DIR:-${TMPDIR:-/tmp}/keep-core-native-go-fuzz-logs}"

positive_integer() {
	[[ "$1" =~ ^[1-9][0-9]*$ ]]
}

for setting in \
	"FUZZ_TOTAL_SECONDS:$fuzz_total_seconds" \
	"FUZZ_MAX_PARALLEL:$fuzz_max_parallel" \
	"FUZZ_WALL_TIMEOUT_SECONDS:$fuzz_wall_timeout_seconds" \
	"FUZZ_TARGET_GRACE_SECONDS:$fuzz_target_grace_seconds"
do
	name="${setting%%:*}"
	value="${setting#*:}"
	if ! positive_integer "$value"; then
		echo "$name must be a positive integer, got: $value" >&2
		exit 1
	fi
done

if ! command -v setsid >/dev/null; then
	echo "setsid is required by the native Go fuzz runner" >&2
	exit 1
fi

# Refuse to schedule an incomplete, duplicate, or output-colliding registry.
./.clusterfuzzlite/check_targets.sh >/dev/null

mkdir -p "$fuzz_log_dir"

targets=()
representative_targets=()
declare -A seen_targets=()
declare -A seen_packages=()
while read -r package fuzz_function; do
	if [[ ! "$package" =~ ^github\.com/keep-network/keep-core/pkg/[A-Za-z0-9_./-]+$ ||
		! "$fuzz_function" =~ ^Fuzz[A-Za-z0-9_]+$ ]]; then
		echo "invalid native Go fuzz target: $package $fuzz_function" >&2
		exit 1
	fi

	target_key="$package $fuzz_function"
	if [[ -n "${seen_targets[$target_key]:-}" ]]; then
		echo "duplicate native Go fuzz target: $target_key" >&2
		exit 1
	fi
	seen_targets["$target_key"]=1
	targets+=("$package $fuzz_function")
	if [[ -z "${seen_packages[$package]:-}" ]]; then
		seen_packages["$package"]=1
		representative_targets+=("$package $fuzz_function")
	fi
done < <(
	awk '$1 == "compile_native_go_fuzzer" {print $2, $3}' \
		.clusterfuzzlite/build.sh
)

target_count="${#targets[@]}"
if [[ "$target_count" -eq 0 ]]; then
	echo "no native Go fuzz targets found in .clusterfuzzlite/build.sh" >&2
	exit 1
fi

if [[ "$fuzz_total_seconds" -lt "$target_count" ]]; then
	echo "FUZZ_TOTAL_SECONDS must provide at least one second per target" >&2
	exit 1
fi

# ClusterFuzzLite rounds the per-target max time up: the previous 300-second,
# 41-target PR run gave every target 8 seconds. Preserve that minimum rather
# than weakening any target to 7 seconds. FUZZ_WALL_TIMEOUT_SECONDS remains the
# hard aggregate wall cap while two single-worker targets run concurrently.
per_target_seconds="$(((fuzz_total_seconds + target_count - 1) / target_count))"
scheduled_fuzz_seconds="$((per_target_seconds * target_count))"
if [[ "$fuzz_target_grace_seconds" -lt "$((per_target_seconds + 5))" ]]; then
	echo "FUZZ_TARGET_GRACE_SECONDS must be at least one target interval plus 5 seconds" >&2
	echo "  target interval: ${per_target_seconds}s" >&2
	echo "  configured grace: ${fuzz_target_grace_seconds}s" >&2
	exit 1
fi
scheduled_targets=()
for target in "${targets[@]}"; do
	scheduled_targets+=("$target $per_target_seconds")
done

# A normal `go test -run=^$` build does not warm the separately instrumented
# build used by `go test -fuzz`. Compile one representative fuzz target from
# every package before the timed phase; target selection does not change the
# resulting test binary, so the remaining targets reuse the same build cache.
# This makes the per-target deadline measure fuzz execution rather than
# machine-dependent cold compilation.
preflight_binary="$(mktemp "$fuzz_log_dir/.preflight.test.XXXXXX")"
trap 'rm -f -- "$preflight_binary"' EXIT
echo "Precompiling ${#representative_targets[@]} fuzz-instrumented Go packages with ASAN."
for representative_target in "${representative_targets[@]}"; do
	read -r package fuzz_function <<<"$representative_target"
	echo "PRECOMPILE $package $fuzz_function"
	GOMAXPROCS="$fuzz_max_parallel" go test \
		-c \
		-asan \
		-fuzz="^${fuzz_function}$" \
		-o "$preflight_binary" \
		"$package"
done
rm -f -- "$preflight_binary"
trap - EXIT

run_go_fuzz_attempt() {
	local package="$1"
	local fuzz_function="$2"
	local target_seconds="$3"
	local go_timeout_seconds="$4"
	local log_path="$5"

	env GOMAXPROCS=1 \
		go test \
			-asan \
			-count=1 \
			-parallel=1 \
			-run='^$' \
			-fuzz="^${fuzz_function}$" \
			-fuzztime="${target_seconds}s" \
			-fuzzminimizetime=0 \
			-timeout="${go_timeout_seconds}s" \
			"$package" >"$log_path" 2>&1
}

# Go issue 75804 can leak the fuzz-time context deadline as exit 1 even after
# the requested fuzz duration completed without a target failure. The upstream
# fix (golang/go@5a957dc) is newer than the repository's pinned Go 1.25 line.
# Match its exact harness-only signature; any crash, failing corpus input,
# panic, sanitizer finding, generic error, or incomplete fuzz interval remains
# a hard failure.
is_go_fuzztime_deadline_race() {
	local log_path="$1"
	local package="$2"
	local fuzz_function="$3"
	local target_seconds="$4"

	awk \
		-v package_path="$package" \
		-v fuzz_function="$fuzz_function" \
		-v target_seconds="$target_seconds" '
		BEGIN {
			baseline_pattern = "^fuzz: elapsed: [0-9]+s, gathering baseline coverage: "
			baseline_pattern = baseline_pattern "[0-9]+/[0-9]+ completed"
			baseline_pattern = baseline_pattern "(, now fuzzing with 1 workers)?$"
			progress_pattern = "^fuzz: elapsed: [0-9]+s, execs: [0-9]+ "
			progress_pattern = progress_pattern "\\([0-9]+/sec\\), new interesting: "
			progress_pattern = progress_pattern "[0-9]+ \\(total: [0-9]+\\)$"
			completed_pattern = "^fuzz: elapsed: " target_seconds "s, execs: [1-9][0-9]* "
			completed_pattern = completed_pattern "\\([0-9]+/sec\\), new interesting: "
			completed_pattern = completed_pattern "[0-9]+ \\(total: [0-9]+\\)$"
			fail_pattern = "^--- FAIL: " fuzz_function " \\("
			fail_pattern = fail_pattern target_seconds "(\\.[0-9]+)?s\\)$"
			duration_pattern = "^[0-9]+(\\.[0-9]+)?s$"
		}

		{ lines[++line_count] = $0 }

		END {
			# The exact Go issue 75804 failure ends in six contiguous lines:
			# completed fuzz stats, target failure, sole deadline diagnostic,
			# FAIL, exit status 1, and the package FAIL trailer. Nothing may
			# follow the trailer or appear before it except normal fuzz stats.
			if (line_count < 7) {
				exit 1
			}

			terminal_start = line_count - 5
			for (i = 1; i < terminal_start; i++) {
				if (lines[i] ~ /, now fuzzing with 1 workers$/) {
					saw_fuzz_start = 1
				}
				if (lines[i] !~ baseline_pattern && lines[i] !~ progress_pattern) {
					exit 1
				}
			}

			if (!saw_fuzz_start || lines[terminal_start] !~ completed_pattern ||
				lines[terminal_start + 1] !~ fail_pattern ||
				lines[terminal_start + 2] != "    context deadline exceeded" ||
				lines[terminal_start + 3] != "FAIL" ||
				lines[terminal_start + 4] != "exit status 1") {
				exit 1
			}

			field_count = split(lines[terminal_start + 5], trailer, /[[:space:]]+/)
			if (field_count != 3 || trailer[1] != "FAIL" ||
				trailer[2] != package_path || trailer[3] !~ duration_pattern) {
				exit 1
			}
		}
	' "$log_path"
}

run_target() {
	local package="$1"
	local fuzz_function="$2"
	local target_seconds="$3"
	local package_suffix="${package#github.com/keep-network/keep-core/}"
	local log_name="${package_suffix//\//_}_${fuzz_function}.log"
	local log_path="$fuzz_log_dir/$log_name"
	local first_attempt_log="${log_path%.log}.fuzztime-deadline-race.log"
	local go_grace_seconds="$fuzz_target_grace_seconds"
	local go_timeout_seconds
	local status

	if [[ "$go_grace_seconds" -gt 5 ]]; then
		go_grace_seconds="$((go_grace_seconds - 5))"
	fi
	go_timeout_seconds="$((target_seconds + go_grace_seconds))"

	if run_go_fuzz_attempt \
		"$package" \
		"$fuzz_function" \
		"$target_seconds" \
		"$go_timeout_seconds" \
		"$log_path"
	then
		echo "PASS $package $fuzz_function (${target_seconds}s)"
		return 0
	else
		status=$?
	fi

	if [[ "$status" -eq 1 ]] && is_go_fuzztime_deadline_race \
		"$log_path" \
		"$package" \
		"$fuzz_function" \
		"$target_seconds"
	then
		if ! mv -- "$log_path" "$first_attempt_log"; then
			echo "FAIL $package $fuzz_function: could not preserve first attempt" >&2
			cat "$log_path" >&2
			return 1
		fi
		echo "RETRY $package $fuzz_function after Go fuzztime deadline race"
		cat "$first_attempt_log" >&2
		if run_go_fuzz_attempt \
			"$package" \
			"$fuzz_function" \
			"$target_seconds" \
			"$go_timeout_seconds" \
			"$log_path"
		then
			echo "PASS $package $fuzz_function (${target_seconds}s; one deadline-race retry)"
			return 0
		else
			status=$?
		fi
		echo "FAIL $package $fuzz_function after deadline-race retry (exit $status)" >&2
		echo "first attempt (matched Go issue 75804):" >&2
		cat "$first_attempt_log" >&2
		echo "retry:" >&2
		cat "$log_path" >&2
		return "$status"
	fi

	echo "FAIL $package $fuzz_function (exit $status)" >&2
	cat "$log_path" >&2
	return "$status"
}

export -f run_go_fuzz_attempt
export -f is_go_fuzztime_deadline_race
export -f run_target
export fuzz_log_dir fuzz_target_grace_seconds

printf 'Fuzzing %d targets: %ds scheduled fuzz time from a %ds allotment, %d concurrently, %ds wall cap.\n' \
	"$target_count" \
	"$scheduled_fuzz_seconds" \
	"$fuzz_total_seconds" \
	"$fuzz_max_parallel" \
	"$fuzz_wall_timeout_seconds"

# Every target runs in a separately tracked session/process group. On a target
# timeout, aggregate timeout, signal, or sibling failure, the EXIT trap sends
# TERM and then KILL to every still-active group and reaps its leader. This
# avoids the orphaning possible with nested timeout/xargs process groups.
active_target_pids=()
declare -A target_deadlines=()
declare -A target_labels=()

remove_active_target() {
	local removed_pid="$1"
	local active_pid
	local -a remaining_pids=()

	for active_pid in "${active_target_pids[@]}"; do
		if [[ "$active_pid" != "$removed_pid" ]]; then
			remaining_pids+=("$active_pid")
		fi
	done
	active_target_pids=("${remaining_pids[@]}")
	unset 'target_deadlines[$removed_pid]'
	unset 'target_labels[$removed_pid]'
}

target_is_running() {
	local target_pid="$1"
	local _process_pid _process_name process_state _remaining_fields

	if [[ ! -r "/proc/$target_pid/stat" ]]; then
		return 1
	fi

	read -r _process_pid _process_name process_state _remaining_fields \
		<"/proc/$target_pid/stat" || return 1
	[[ "$process_state" != Z && "$process_state" != X ]]
}

cleanup_active_targets() {
	local active_pid

	if [[ "${#active_target_pids[@]}" -eq 0 ]]; then
		return
	fi

	for active_pid in "${active_target_pids[@]}"; do
		kill -TERM -- "-$active_pid" 2>/dev/null || true
	done
	sleep 1
	for active_pid in "${active_target_pids[@]}"; do
		kill -KILL -- "-$active_pid" 2>/dev/null || true
	done
	for active_pid in "${active_target_pids[@]}"; do
		wait "$active_pid" 2>/dev/null || true
	done
	active_target_pids=()
}

cleanup_on_exit() {
	local exit_status=$?

	trap - EXIT
	trap '' HUP INT TERM
	cleanup_active_targets
	exit "$exit_status"
}

trap cleanup_on_exit EXIT
trap 'echo "native Go fuzz runner interrupted" >&2; exit 143' HUP INT TERM

phase_started_seconds="$SECONDS"
next_target_index=0
while [[ "$next_target_index" -lt "$target_count" ||
	"${#active_target_pids[@]}" -gt 0 ]]
do
	while [[ "$next_target_index" -lt "$target_count" &&
		"${#active_target_pids[@]}" -lt "$fuzz_max_parallel" ]]
	do
		if [[ "$((SECONDS - phase_started_seconds))" -ge "$fuzz_wall_timeout_seconds" ]]; then
			break
		fi

		read -r package fuzz_function target_seconds \
			<<<"${scheduled_targets[$next_target_index]}"
		# shellcheck disable=SC2016 # Positional args expand in the child shell.
		setsid /bin/bash -c \
			'run_target "$1" "$2" "$3"' \
			_ "$package" "$fuzz_function" "$target_seconds" &
		target_pid=$!
		active_target_pids+=("$target_pid")
		target_deadlines["$target_pid"]="$((SECONDS + target_seconds + fuzz_target_grace_seconds))"
		target_labels["$target_pid"]="$package $fuzz_function"
		next_target_index="$((next_target_index + 1))"
	done

	if [[ "$((SECONDS - phase_started_seconds))" -ge "$fuzz_wall_timeout_seconds" ]]; then
		echo "native Go fuzz phase exceeded ${fuzz_wall_timeout_seconds}s wall cap" >&2
		exit 124
	fi

	made_progress=0
	for target_pid in "${active_target_pids[@]}"; do
		if ! target_is_running "$target_pid"; then
			target_status=0
			wait "$target_pid" || target_status=$?
			# A completed leader must not leave an orphan in its process group.
			kill -KILL -- "-$target_pid" 2>/dev/null || true
			remove_active_target "$target_pid"
			made_progress=1
			if [[ "$target_status" -ne 0 ]]; then
				exit "$target_status"
			fi
		elif [[ "$SECONDS" -ge "${target_deadlines[$target_pid]}" ]]; then
			echo "TIMEOUT ${target_labels[$target_pid]}" >&2
			exit 124
		fi
	done

	if [[ "$made_progress" -eq 0 ]]; then
		sleep 0.2
	fi
done
