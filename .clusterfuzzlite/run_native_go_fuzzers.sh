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
packages=()
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
		packages+=("$package")
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
scheduled_targets=()
for target in "${targets[@]}"; do
	scheduled_targets+=("$target $per_target_seconds")
done

# Compile every package with the same ASAN setting before starting the bounded
# fuzz phase. This keeps dependency/toolchain setup out of the fuzz budget and
# makes a compile failure a direct, fail-closed result.
echo "Preflighting ${#packages[@]} native Go fuzz packages with ASAN."
GOMAXPROCS="$fuzz_max_parallel" go test \
	-asan \
	-count=1 \
	-run='^$' \
	"${packages[@]}"

run_target() {
	local package="$1"
	local fuzz_function="$2"
	local target_seconds="$3"
	local package_suffix="${package#github.com/keep-network/keep-core/}"
	local log_name="${package_suffix//\//_}_${fuzz_function}.log"
	local log_path="$fuzz_log_dir/$log_name"
	local go_grace_seconds="$fuzz_target_grace_seconds"
	local go_timeout_seconds
	local status

	if [[ "$go_grace_seconds" -gt 5 ]]; then
		go_grace_seconds="$((go_grace_seconds - 5))"
	fi
	go_timeout_seconds="$((target_seconds + go_grace_seconds))"

	if env GOMAXPROCS=1 \
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
	then
		echo "PASS $package $fuzz_function (${target_seconds}s)"
		return 0
	else
		status=$?
		echo "FAIL $package $fuzz_function (exit $status)" >&2
		cat "$log_path" >&2
		return "$status"
	fi
}

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
