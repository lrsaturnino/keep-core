#!/usr/bin/env bash
#
# Self-test the container evidence-window capture. The fake Docker boundary
# exercises the successful two-service capture and the fail-closed cases for
# an ignored signal, failed delivery, a missing second periodic snapshot,
# periodic nonempty snapshots, and snapshots authored while the chain clock is
# unavailable. It also proves a mismatched run/fleet context is rejected before
# any process receives the opening signal.

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
container_two="${FAKE_CONTAINER_TWO:?}"
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
      "${container}" == "${container_two}" ]]; then
      exit 22
    fi
    if [[ "${scenario}" == "unsignaled" &&
      "${container}" == "${container_two}" ]]; then
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

  if [[ "${container}" != "${container_two}" ]]; then
    printf '%s\n' \
      "2026-07-31T00:00:30.000000000Z protocol cutover peer roster snapshot [currentBlock=100] [clockAvailable=true] [legacyPeers=0] [oldestFirstSeenBlock=0] [rosterRevision=0]" \
      "2026-07-31T00:05:30.000000000Z protocol cutover peer roster snapshot [currentBlock=125] [clockAvailable=true] [legacyPeers=0] [oldestFirstSeenBlock=0] [rosterRevision=0]"
  elif [[ "${scenario}" == "missing_periodic" ]]; then
    printf '%s\n' \
      "2026-07-31T00:00:30.000000000Z protocol cutover peer roster snapshot [currentBlock=100] [clockAvailable=true] [legacyPeers=0] [oldestFirstSeenBlock=0] [rosterRevision=0]"
  elif [[ "${scenario}" == "missing_empty" ]]; then
    printf '%s\n' \
      "2026-07-31T00:00:30.000000000Z protocol cutover peer roster snapshot [currentBlock=100] [clockAvailable=true] [legacyPeers=1] [oldestFirstSeenBlock=99] [rosterRevision=1]" \
      "2026-07-31T00:05:30.000000000Z protocol cutover peer roster snapshot [currentBlock=125] [clockAvailable=true] [legacyPeers=1] [oldestFirstSeenBlock=99] [rosterRevision=1]"
  elif [[ "${scenario}" == "clock_unavailable" ]]; then
    printf '%s\n' \
      "2026-07-31T00:00:30.000000000Z protocol cutover peer roster snapshot [currentBlock=100] [clockAvailable=false] [legacyPeers=0] [oldestFirstSeenBlock=0] [rosterRevision=0]" \
      "2026-07-31T00:05:30.000000000Z protocol cutover peer roster snapshot [currentBlock=100] [clockAvailable=false] [legacyPeers=0] [oldestFirstSeenBlock=0] [rosterRevision=0]"
  else
    printf '%s\n' \
      "2026-07-31T00:00:30.000000000Z protocol cutover peer roster snapshot [currentBlock=100] [clockAvailable=true] [legacyPeers=0] [oldestFirstSeenBlock=0] [rosterRevision=0]" \
      "2026-07-31T00:05:30.000000000Z protocol cutover peer roster snapshot [currentBlock=125] [clockAvailable=true] [legacyPeers=0] [oldestFirstSeenBlock=0] [rosterRevision=0]"
  fi

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
CASE_ARCHIVE=""

CONTAINER_ONE="$(printf '1%.0s' {1..64})"
CONTAINER_TWO="$(printf '2%.0s' {1..64})"

run_case() {
  local scenario="$1"
  local capture_id
  capture_id="$(printf '%s' "${scenario}" | shasum -a 256 | awk '{print substr($1, 1, 32)}')"
  local archive="${WORK}/cutover-roster-window-${capture_id}"
  local state="${WORK}/state-${scenario}"
  local context
  context="$(node - "${scenario}" "${capture_id}" "${archive##*/}" \
    "${CONTAINER_ONE}" "${CONTAINER_TWO}" <<'NODE'
const crypto = require("crypto");
const [scenario, captureID, archiveID, containerOne, containerTwo] =
  process.argv.slice(2);
process.stdout.write(JSON.stringify({
  schema_version: 1,
  run_id: crypto.createHash("sha256")
    .update("run:" + scenario).digest("hex").slice(0, 32),
  capture_id: captureID,
  archive_id: archiveID,
  gate: "single_release",
  source_sha: "a".repeat(40),
  r1_image_digests: {
    amd64: "ghcr.io/keep-network/keep-client@sha256:" + "b".repeat(64),
  },
  revision: "a".repeat(40),
  protocol_epoch: "security_v2_cutover",
  chain_id: "11155111",
  cutover_block: 1000000,
  r1_fleet: [
    {
      service: "r1-node-1",
      container_id: containerOne,
      operator_address: "0x" + "1".repeat(40),
    },
    {
      service: "r1-node-2",
      container_id: containerTwo,
      operator_address: "0x" + "2".repeat(40),
    },
  ],
}));
NODE
  )"
  if [[ "${scenario}" == "context_fleet_mismatch" ]]; then
    context="$(node -e '
      const context = JSON.parse(process.argv[1]);
      context.r1_fleet[1].container_id = "3".repeat(64);
      process.stdout.write(JSON.stringify(context));
    ' "${context}")"
  elif [[ "${scenario}" == "context_archive_mismatch" ]]; then
    context="$(node -e '
      const context = JSON.parse(process.argv[1]);
      context.archive_id = "cutover-roster-window-" + "4".repeat(32);
      process.stdout.write(JSON.stringify(context));
    ' "${context}")"
  fi
  mkdir -p "${state}"
  CASE_ARCHIVE="${archive}"

  set +e
  CASE_OUTPUT="$(
    PATH="${FAKE_BIN}:${PATH}" \
      FAKE_DOCKER_SCENARIO="${scenario}" \
      FAKE_DOCKER_STATE="${state}" \
      FAKE_EXPECTED_ARCHIVE="${archive}" \
      FAKE_CONTAINER_TWO="${CONTAINER_TWO}" \
      "${CAPTURE}" "${archive}" "${context}" \
      "r1-node-1=${CONTAINER_ONE}" "r1-node-2=${CONTAINER_TWO}" 2>&1
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
  run_case "${scenario}"
  local archive="${CASE_ARCHIVE}"

  if ((CASE_RC == 0)) &&
    node -e '
      const crypto = require("crypto");
      const fs = require("fs");
      const path = require("path");
      const result = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      const checkpoint = fs.readFileSync(
        path.join(path.dirname(process.argv[1]), "window-open.json")
      );
      if (
        result.schema_version !== 2 ||
        result.capture_context.schema_version !== 1 ||
        !result.complete ||
        result.services.length !== 2 ||
        crypto.createHash("sha256").update(checkpoint).digest("hex") !==
          result.window_open_sha256 ||
        Date.parse(result.opened_at) >
          Date.parse(result.archived_before_close_at) ||
        Date.parse(result.archived_before_close_at) >
          Date.parse(result.closed_at)
      ) process.exit(1);
      if (!result.services.every((service) =>
        service.signal_delivered &&
        service.activation_seen &&
        service.periodic_empty_snapshots_seen &&
        service.empty_snapshot_lines >= 2 &&
        service.close_delivered &&
        service.close_seen &&
        crypto.createHash("sha256")
          .update(fs.readFileSync(
            path.join(path.dirname(process.argv[1]), service.service + ".log")
          ))
          .digest("hex") === service.relevant_log_sha256
      )) process.exit(1);
    ' "${archive}/result.json"; then
    pass_case "${name}"
  else
    fail_case "${name}" "exit ${CASE_RC}: ${CASE_OUTPUT}"
  fi
}

expect_failure() {
  local name="$1" scenario="$2" pattern="$3"
  run_case "${scenario}"
  local archive="${CASE_ARCHIVE}"

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

expect_context_failure() {
  local name="$1" scenario="$2" pattern="$3"
  run_case "${scenario}"
  local state="${WORK}/state-${scenario}"

  if ((CASE_RC == 1)) &&
    grep -Eq "${pattern}" <<<"${CASE_OUTPUT}" &&
    [[ ! -e "${CASE_ARCHIVE}" ]] &&
    ! compgen -G "${state}/*.open" >/dev/null; then
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
expect_context_failure \
  "a foreign container identity is refused before the evidence window opens" \
  context_fleet_mismatch \
  "R1 fleet differs from the signaled container set"
expect_context_failure \
  "an archive path not derived from the capture identity is refused before open" \
  context_archive_mismatch \
  "archive_id does not identify the archive directory"

printf '%d passed, %d failed\n' "${PASS}" "${FAILED}"
if ((FAILED != 0)); then
  exit 1
fi
