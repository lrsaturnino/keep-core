#!/bin/bash -eu
#
# Linux contract tests for the native Go fuzz runner. The fake go command
# keeps these tests fast while exercising the real process-group scheduler,
# deadline-race classifier, retry bound, and exit propagation.

set -o pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! -r /proc/self/stat ]]; then
	echo "SKIP native Go runner contract tests: /proc is required"
	exit 0
fi

fixture_root="$(mktemp -d)"
trap 'rm -rf -- "$fixture_root"' EXIT

mkdir -p "$fixture_root/repo/.clusterfuzzlite" "$fixture_root/bin"
cp "$repo_root/.clusterfuzzlite/run_native_go_fuzzers.sh" \
	"$fixture_root/repo/.clusterfuzzlite/"

cat >"$fixture_root/repo/.clusterfuzzlite/build.sh" <<'EOF'
compile_native_go_fuzzer github.com/keep-network/keep-core/pkg/test FuzzTarget test_FuzzTarget
EOF

cat >"$fixture_root/repo/.clusterfuzzlite/check_targets.sh" <<'EOF'
#!/bin/bash -eu
exit 0
EOF
chmod +x "$fixture_root/repo/.clusterfuzzlite/check_targets.sh"

cat >"$fixture_root/bin/go" <<'EOF'
#!/bin/bash -eu

for argument in "$@"; do
	if [[ "$argument" == -c ]]; then
		exit 0
	fi
done

: "${FAKE_GO_MODE:?}"
: "${FAKE_GO_STATE:?}"

attempt=0
if [[ -s "$FAKE_GO_STATE" ]]; then
	read -r attempt <"$FAKE_GO_STATE"
fi
attempt="$((attempt + 1))"
printf '%s\n' "$attempt" >"$FAKE_GO_STATE"

deadline_race() {
	cat <<'LOG'
fuzz: elapsed: 0s, gathering baseline coverage: 0/1 completed
fuzz: elapsed: 0s, gathering baseline coverage: 1/1 completed, now fuzzing with 1 workers
fuzz: elapsed: 1s, execs: 123 (123/sec), new interesting: 1 (total: 2)
--- FAIL: FuzzTarget (1.01s)
    context deadline exceeded
FAIL
exit status 1
FAIL github.com/keep-network/keep-core/pkg/test 1.02s
LOG
	return 1
}

lookalike_finding() {
	cat <<'LOG'
fuzz: elapsed: 0s, gathering baseline coverage: 1/1 completed, now fuzzing with 1 workers
fuzz: elapsed: 1s, execs: 123 (123/sec), new interesting: 1 (total: 2)
--- FAIL: FuzzTarget (1.01s)
    context deadline exceeded
    --- FAIL: FuzzTarget/0123456789abcdef (0.00s)
        fuzz_test.go:10: context deadline exceeded
    Failing input written to testdata/fuzz/FuzzTarget/0123456789abcdef
FAIL
exit status 1
FAIL github.com/keep-network/keep-core/pkg/test 1.02s
LOG
	return 1
}

incomplete_deadline() {
	cat <<'LOG'
fuzz: elapsed: 0s, gathering baseline coverage: 1/1 completed, now fuzzing with 1 workers
fuzz: elapsed: 0s, execs: 0 (0/sec), new interesting: 0 (total: 1)
--- FAIL: FuzzTarget (1.01s)
    context deadline exceeded
FAIL
exit status 1
FAIL github.com/keep-network/keep-core/pkg/test 1.02s
LOG
	return 1
}

case "$FAKE_GO_MODE" in
success)
	echo PASS
	exit 0
	;;
deadline_once)
	if [[ "$attempt" -eq 1 ]]; then
		deadline_race
	fi
	echo PASS
	exit 0
	;;
deadline_once_timed)
	sleep 1
	if [[ "$attempt" -eq 1 ]]; then
		deadline_race
	fi
	echo PASS
	exit 0
	;;
deadline_always)
	deadline_race
	;;
deadline_then_crash)
	if [[ "$attempt" -eq 1 ]]; then
		deadline_race
	fi
	echo 'panic: synthetic retry crash'
	exit 1
	;;
deadline_then_hang)
	if [[ "$attempt" -eq 1 ]]; then
		deadline_race
	fi
	sleep 20
	echo PASS
	exit 0
	;;
deadline_exit_42)
	deadline_race || true
	exit 42
	;;
deadline_unclassified)
	deadline_race || true
	echo 'synthetic unclassified failure'
	exit 1
	;;
deadline_incomplete)
	incomplete_deadline
	;;
crash_with_deadline_text)
	deadline_race || true
	echo 'panic: synthetic fuzz crash'
	exit 1
	;;
lookalike_finding)
	lookalike_finding
	;;
generic_failure_one)
	echo 'synthetic generic exit-one failure'
	exit 1
	;;
generic_failure)
	echo 'synthetic generic failure'
	exit 42
	;;
*)
	echo "unknown FAKE_GO_MODE: $FAKE_GO_MODE" >&2
	exit 99
	;;
esac
EOF
chmod +x "$fixture_root/bin/go"

run_case() {
	local name="$1"
	local mode="$2"
	local expected_status="$3"
	local expected_attempts="$4"
	local case_root="$fixture_root/cases/$name"
	local status
	local attempts
	local started_seconds

	mkdir -p "$case_root/logs"
	: >"$case_root/state"

	started_seconds="$SECONDS"
	set +e
	env \
		PATH="$fixture_root/bin:$PATH" \
		FAKE_GO_MODE="$mode" \
		FAKE_GO_STATE="$case_root/state" \
		FUZZ_LOG_DIR="$case_root/logs" \
		FUZZ_MAX_PARALLEL=1 \
		FUZZ_TARGET_GRACE_SECONDS=6 \
		FUZZ_TOTAL_SECONDS=1 \
		FUZZ_WALL_TIMEOUT_SECONDS=10 \
		"$fixture_root/repo/.clusterfuzzlite/run_native_go_fuzzers.sh" \
		>"$case_root/transcript" 2>&1
	status=$?
	set -e
	last_case_elapsed="$((SECONDS - started_seconds))"

	if [[ "$status" -ne "$expected_status" ]]; then
		echo "$name: got status $status, want $expected_status" >&2
		cat "$case_root/transcript" >&2
		exit 1
	fi

	read -r attempts <"$case_root/state"
	if [[ "$attempts" -ne "$expected_attempts" ]]; then
		echo "$name: got $attempts target attempts, want $expected_attempts" >&2
		cat "$case_root/transcript" >&2
		exit 1
	fi

	last_case_root="$case_root"
}

run_case success success 0 1
if grep -Fq -- 'RETRY ' "$last_case_root/transcript"; then
	echo "success: unexpected retry" >&2
	exit 1
fi

run_case deadline-once deadline_once 0 2
grep -Fq -- \
	'RETRY github.com/keep-network/keep-core/pkg/test FuzzTarget after Go fuzztime deadline race' \
	"$last_case_root/transcript"
grep -Fq -- 'one deadline-race retry' "$last_case_root/transcript"
test -f "$last_case_root/logs/pkg_test_FuzzTarget.fuzztime-deadline-race.log"
grep -Fxq -- '    context deadline exceeded' \
	"$last_case_root/logs/pkg_test_FuzzTarget.fuzztime-deadline-race.log"
grep -Fxq -- PASS "$last_case_root/logs/pkg_test_FuzzTarget.log"

run_case deadline-once-timed deadline_once_timed 0 2
if [[ "$last_case_elapsed" -lt 2 ]]; then
	echo "deadline-once-timed: two full-duration attempts completed too quickly" >&2
	exit 1
fi
grep -Fq -- 'one deadline-race retry' "$last_case_root/transcript"

run_case deadline-always deadline_always 1 2
grep -Fq -- 'FAIL github.com/keep-network/keep-core/pkg/test FuzzTarget after deadline-race retry' \
	"$last_case_root/transcript"
test -f "$last_case_root/logs/pkg_test_FuzzTarget.fuzztime-deadline-race.log"
grep -Fxq -- '    context deadline exceeded' \
	"$last_case_root/logs/pkg_test_FuzzTarget.fuzztime-deadline-race.log"
grep -Fxq -- '    context deadline exceeded' \
	"$last_case_root/logs/pkg_test_FuzzTarget.log"

run_case retry-crash deadline_then_crash 1 2
grep -Fq -- 'panic: synthetic retry crash' "$last_case_root/transcript"
test -f "$last_case_root/logs/pkg_test_FuzzTarget.fuzztime-deadline-race.log"
test -f "$last_case_root/logs/pkg_test_FuzzTarget.log"
grep -Fxq -- '    context deadline exceeded' \
	"$last_case_root/logs/pkg_test_FuzzTarget.fuzztime-deadline-race.log"
grep -Fxq -- 'panic: synthetic retry crash' \
	"$last_case_root/logs/pkg_test_FuzzTarget.log"

run_case crash crash_with_deadline_text 1 1
grep -Fq -- 'panic: synthetic fuzz crash' "$last_case_root/transcript"
if grep -Fq -- 'RETRY ' "$last_case_root/transcript"; then
	echo "crash: unsafe retry" >&2
	exit 1
fi

run_case unclassified deadline_unclassified 1 1
grep -Fq -- 'synthetic unclassified failure' "$last_case_root/transcript"
if grep -Fq -- 'RETRY ' "$last_case_root/transcript"; then
	echo "unclassified: unsafe retry" >&2
	exit 1
fi

run_case incomplete deadline_incomplete 1 1
if grep -Fq -- 'RETRY ' "$last_case_root/transcript"; then
	echo "incomplete: unsafe retry" >&2
	exit 1
fi

run_case lookalike lookalike_finding 1 1
grep -Fq -- 'Failing input written to' "$last_case_root/transcript"
if grep -Fq -- 'RETRY ' "$last_case_root/transcript"; then
	echo "lookalike: unsafe retry" >&2
	exit 1
fi

run_case deadline-exit-42 deadline_exit_42 42 1
if grep -Fq -- 'RETRY ' "$last_case_root/transcript"; then
	echo "deadline-exit-42: non-1 exit was retried" >&2
	exit 1
fi

run_case generic-one generic_failure_one 1 1
if grep -Fq -- 'RETRY ' "$last_case_root/transcript"; then
	echo "generic-one: unexpected retry" >&2
	exit 1
fi

run_case generic generic_failure 42 1
grep -Fq -- 'synthetic generic failure' "$last_case_root/transcript"
if grep -Fq -- 'RETRY ' "$last_case_root/transcript"; then
	echo "generic: unexpected retry" >&2
	exit 1
fi

run_case retry-watchdog deadline_then_hang 124 2
grep -Fq -- \
	'TIMEOUT github.com/keep-network/keep-core/pkg/test FuzzTarget' \
	"$last_case_root/transcript"
test -f "$last_case_root/logs/pkg_test_FuzzTarget.fuzztime-deadline-race.log"
grep -Fxq -- '    context deadline exceeded' \
	"$last_case_root/logs/pkg_test_FuzzTarget.fuzztime-deadline-race.log"

echo "native Go runner contract tests passed"
