#!/usr/bin/env bash
#
# Self-test the container evidence-window capture. The fake Docker boundary
# exercises the successful two-service capture and the fail-closed cases for
# an ignored signal, failed delivery, a missing second periodic snapshot,
# periodic nonempty snapshots, and snapshots authored while the chain clock is
# unavailable.

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAPTURE="${TEST_DIR}/capture-cutover-evidence-window.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/cutover-evidence-window-test.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

FAKE_BIN="${WORK}/bin"
mkdir -p "${FAKE_BIN}"

cat >"${FAKE_BIN}/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

cat >"${FAKE_BIN}/docker" <<'EOF'
#!/usr/bin/env bash
set -u

scenario="${FAKE_DOCKER_SCENARIO:?}"
state="${FAKE_DOCKER_STATE:?}"
archive="${FAKE_EXPECTED_ARCHIVE:?}"
mkdir -p "${state}"

command_name="${1:-}"
shift || true

case "${command_name}" in
kill)
  signal=""
  container=""
  for argument in "$@"; do
    case "${argument}" in
    --signal=*) signal="${argument#*=}" ;;
    *) container="${argument}" ;;
    esac
  done

  case "${signal}" in
  SIGUSR1)
    if [[ "${scenario}" == "delivery_failure" &&
      "${container}" == "container-two" ]]; then
      exit 22
    fi
    if [[ "${scenario}" == "unsignaled" &&
      "${container}" == "container-two" ]]; then
      exit 0
    fi
    : >"${state}/${container}.open"
    ;;
  SIGUSR2)
    # Closing is allowed only after the capture has reached its final archive
    # path and recorded the pre-close account.
    [[ -f "${archive}/window-open.json" ]] || exit 23
    : >"${state}/${container}.closed"
    ;;
  *)
    exit 24
    ;;
  esac
  ;;
logs)
  container=""
  for argument in "$@"; do
    case "${argument}" in
    --timestamps | --since) ;;
    *) container="${argument}" ;;
    esac
  done

  [[ -f "${state}/${container}.open" ]] || exit 0
  printf '%s\n' \
    "2026-07-31T00:00:00.000000000Z protocol cutover evidence window changed [active=true] [signal=user defined signal 1]"

  case "${scenario}:${container}" in
  missing_periodic:container-two)
    printf '%s\n' \
      "2026-07-31T00:00:30.000000000Z protocol cutover peer roster snapshot [currentBlock=100] [clockAvailable=true] [legacyPeers=0] [oldestFirstSeenBlock=0] [rosterRevision=0]"
    ;;
  missing_empty:container-two)
    printf '%s\n' \
      "2026-07-31T00:00:30.000000000Z protocol cutover peer roster snapshot [currentBlock=100] [clockAvailable=true] [legacyPeers=1] [oldestFirstSeenBlock=99] [rosterRevision=1]" \
      "2026-07-31T00:05:30.000000000Z protocol cutover peer roster snapshot [currentBlock=125] [clockAvailable=true] [legacyPeers=1] [oldestFirstSeenBlock=99] [rosterRevision=1]"
    ;;
  clock_unavailable:container-two)
    printf '%s\n' \
      "2026-07-31T00:00:30.000000000Z protocol cutover peer roster snapshot [currentBlock=100] [clockAvailable=false] [legacyPeers=0] [oldestFirstSeenBlock=0] [rosterRevision=0]" \
      "2026-07-31T00:05:30.000000000Z protocol cutover peer roster snapshot [currentBlock=100] [clockAvailable=false] [legacyPeers=0] [oldestFirstSeenBlock=0] [rosterRevision=0]"
    ;;
  *)
    printf '%s\n' \
      "2026-07-31T00:00:30.000000000Z protocol cutover peer roster snapshot [currentBlock=100] [clockAvailable=true] [legacyPeers=0] [oldestFirstSeenBlock=0] [rosterRevision=0]" \
      "2026-07-31T00:05:30.000000000Z protocol cutover peer roster snapshot [currentBlock=125] [clockAvailable=true] [legacyPeers=0] [oldestFirstSeenBlock=0] [rosterRevision=0]"
    ;;
  esac

  if [[ -f "${state}/${container}.closed" ]]; then
    printf '%s\n' \
      "2026-07-31T00:05:31.000000000Z protocol cutover evidence window changed [active=false] [signal=user defined signal 2]"
  fi
  ;;
*)
  exit 25
  ;;
esac
EOF

chmod +x "${FAKE_BIN}/docker" "${FAKE_BIN}/sleep"

PASS=0
FAILED=0
CASE_RC=0
CASE_OUTPUT=""

run_case() {
  local scenario="$1"
  local archive="${WORK}/archive-${scenario}"
  local state="${WORK}/state-${scenario}"
  mkdir -p "${state}"

  set +e
  CASE_OUTPUT="$(
    PATH="${FAKE_BIN}:${PATH}" \
      FAKE_DOCKER_SCENARIO="${scenario}" \
      FAKE_DOCKER_STATE="${state}" \
      FAKE_EXPECTED_ARCHIVE="${archive}" \
      "${CAPTURE}" "${archive}" \
      r1-node-1=container-one r1-node-2=container-two 2>&1
  )"
  CASE_RC=$?
  set -e
}

pass_case() {
  printf 'ok   %s\n' "$1"
  PASS=$((PASS + 1))
}

fail_case() {
  printf 'FAIL %s\n' "$1"
  printf -- '--- detail ---\n%s\n--------------\n' "$2"
  FAILED=$((FAILED + 1))
}

expect_success() {
  local name="$1" scenario="$2"
  local archive="${WORK}/archive-${scenario}"
  run_case "${scenario}"

  if ((CASE_RC == 0)) &&
    node -e '
      const fs = require("fs");
      const result = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      if (!result.complete || result.services.length !== 2) process.exit(1);
      if (!result.services.every((service) =>
        service.signal_delivered &&
        service.activation_seen &&
        service.periodic_empty_snapshots_seen &&
        service.empty_snapshot_lines >= 2 &&
        service.close_delivered &&
        service.close_seen
      )) process.exit(1);
    ' "${archive}/result.json"; then
    pass_case "${name}"
  else
    fail_case "${name}" "exit ${CASE_RC}: ${CASE_OUTPUT}"
  fi
}

expect_failure() {
  local name="$1" scenario="$2" pattern="$3"
  local archive="${WORK}/archive-${scenario}"
  run_case "${scenario}"

  if ((CASE_RC == 1)) &&
    grep -Eq "${pattern}" <<<"${CASE_OUTPUT}" &&
    node -e '
      const fs = require("fs");
      const result = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      if (result.complete || result.failures.length === 0) process.exit(1);
    ' "${archive}/result.json"; then
    pass_case "${name}"
  else
    fail_case "${name}" "exit ${CASE_RC}: ${CASE_OUTPUT}"
  fi
}

expect_success \
  "every service opens, authors two empty periodic snapshots, archives, and closes" \
  success
expect_failure \
  "an unsignaled service cannot disappear from the fleet account" \
  unsignaled \
  "r1-node-2 did not author an evidence-window activation"
expect_failure \
  "failed signal delivery refuses the capture" \
  delivery_failure \
  "SIGUSR1 delivery failed for r1-node-2"
expect_failure \
  "one empty snapshot is not periodic evidence" \
  missing_periodic \
  "r1-node-2 did not author two clock-healthy empty roster snapshots"
expect_failure \
  "periodic nonempty snapshots cannot stand in for required empty evidence" \
  missing_empty \
  "r1-node-2 did not author two clock-healthy empty roster snapshots"
expect_failure \
  "clock-unavailable snapshots cannot stand in for fresh readiness evidence" \
  clock_unavailable \
  "r1-node-2 did not author two clock-healthy empty roster snapshots"

printf '%d passed, %d failed\n' "${PASS}" "${FAILED}"
if ((FAILED != 0)); then
  exit 1
fi
