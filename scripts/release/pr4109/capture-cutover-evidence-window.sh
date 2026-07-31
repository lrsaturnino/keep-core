#!/usr/bin/env bash
#
# Open, capture, and close the node-local cutover roster evidence window for an
# exact set of running release-candidate containers.
#
# Each service is signaled with SIGUSR1. The capture is accepted only after
# every process logs that it opened the window and authors two clock-healthy
# empty roster snapshots with advancing blocks, separated by the production
# five-minute cadence. Relevant log lines are archived before SIGUSR2 is
# delivered; closing the window is then verified on every process. A delivery
# error, ignored signal, unreadable log, missing empty snapshot, stale clock,
# or missing cadence is a hard failure.

set -euo pipefail

readonly POLL_SECONDS=5
readonly ACTIVATION_POLL_ATTEMPTS=6
# A window opened just after a process's five-minute roster boundary may need
# almost ten minutes to produce two snapshots. Eleven minutes leaves one extra
# 30-second roster sweep plus scheduling margin.
readonly EVIDENCE_POLL_ATTEMPTS=132
readonly MIN_CADENCE_SECONDS=270
readonly MAX_CADENCE_SECONDS=360

usage() {
  printf 'usage: %s <archive-directory> <capture-context-json> <service=container> [...]\n' \
    "$(basename "$0")" >&2
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

if (($# < 3)); then
  usage
  exit 2
fi

command -v docker >/dev/null 2>&1 ||
  fail "docker is required to signal and read the candidate containers"
command -v node >/dev/null 2>&1 ||
  fail "Node.js is required to validate timestamped roster evidence"

ARCHIVE_DIR="$1"
shift
CAPTURE_CONTEXT="$1"
shift

if [[ -e "${ARCHIVE_DIR}" ]]; then
  fail "archive directory [${ARCHIVE_DIR}] already exists; refusing to overwrite evidence"
fi

declare -a SERVICES=()
declare -a CONTAINERS=()
declare -a SIGNAL_DELIVERED=()
declare -a ACTIVATION_SEEN=()
declare -a CADENCE_SEEN=()
declare -a CLOSE_DELIVERED=()
declare -a CLOSE_SEEN=()
declare -a FAILURES=()
FAILURE_COUNT=0
SEEN_SERVICES="|"
SEEN_CONTAINERS="|"

for binding in "$@"; do
  if [[ "${binding}" != *=* ]]; then
    fail "container binding [${binding}] must have the form service=container"
  fi

  service="${binding%%=*}"
  container="${binding#*=}"
  if [[ ! "${service}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    fail "service [${service}] is not a safe evidence identifier"
  fi
  if [[ ! "${container}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    fail "container [${container}] is not a safe Docker identifier"
  fi
  [[ "${SEEN_SERVICES}" != *"|${service}|"* ]] ||
    fail "service [${service}] appears more than once"
  [[ "${SEEN_CONTAINERS}" != *"|${container}|"* ]] ||
    fail "container [${container}] is bound to more than one service"
  SEEN_SERVICES="${SEEN_SERVICES}${service}|"
  SEEN_CONTAINERS="${SEEN_CONTAINERS}${container}|"

  SERVICES+=("${service}")
  CONTAINERS+=("${container}")
  SIGNAL_DELIVERED+=(0)
  ACTIVATION_SEEN+=(0)
  CADENCE_SEEN+=(0)
  CLOSE_DELIVERED+=(0)
  CLOSE_SEEN+=(0)
done

# The caller builds this context independently from the running fleet and
# later writes the same values into the rehearsal record. Validate it before
# delivering a signal: a malformed or differently bound capture must not open
# a logging window whose bytes could later be mistaken for release evidence.
CAPTURE_CONTEXT="$({
  node - "${CAPTURE_CONTEXT}" "${ARCHIVE_DIR##*/}" "$@" <<'NODE'
const [rawContext, archiveID, ...bindings] = process.argv.slice(2);
const fail = (message) => {
  console.error(message);
  process.exit(1);
};
const isObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const exactKeys = (value, expected) => {
  if (!isObject(value)) return false;
  const actual = Object.keys(value).sort();
  return actual.length === expected.length &&
    actual.every((key, index) => key === [...expected].sort()[index]);
};

let context;
try {
  context = JSON.parse(rawContext);
} catch (_) {
  fail("capture context is not valid JSON");
}

const contextKeys = [
  "schema_version",
  "run_id",
  "capture_id",
  "archive_id",
  "gate",
  "source_sha",
  "r1_image_digests",
  "revision",
  "protocol_epoch",
  "chain_id",
  "cutover_block",
  "r1_fleet",
];
if (!exactKeys(context, contextKeys) || context.schema_version !== 1) {
  fail("capture context has no supported exact shape");
}
if (!/^[0-9a-f]{32}$/.test(context.run_id || "")) {
  fail("capture context has no valid run_id");
}
if (!/^[0-9a-f]{32}$/.test(context.capture_id || "")) {
  fail("capture context has no valid capture_id");
}
const expectedArchiveID =
  "cutover-roster-window-" + context.capture_id;
if (
  context.archive_id !== archiveID ||
  context.archive_id !== expectedArchiveID
) {
  fail("capture context archive_id does not identify the archive directory");
}
if (context.gate !== "single_release") {
  fail("capture context gate is not single_release");
}
if (!/^[0-9a-f]{40}$/.test(context.source_sha || "")) {
  fail("capture context has no exact source revision");
}
if (context.revision !== context.source_sha) {
  fail("capture context runtime revision differs from its source revision");
}
if (context.protocol_epoch !== "security_v2_cutover") {
  fail("capture context has no security_v2_cutover epoch");
}
if (!/^[0-9]+$/.test(context.chain_id || "")) {
  fail("capture context has no numeric chain_id");
}
if (!Number.isSafeInteger(context.cutover_block) || context.cutover_block < 1) {
  fail("capture context has no positive safe cutover_block");
}
if (!isObject(context.r1_image_digests)) {
  fail("capture context has no executed R1 image map");
}
const imagePlatforms = Object.keys(context.r1_image_digests);
if (
  imagePlatforms.length !== 1 ||
  !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(imagePlatforms[0]) ||
  !/@sha256:[0-9a-f]{64}$/.test(
    String(context.r1_image_digests[imagePlatforms[0]] || "")
  )
) {
  fail("capture context does not name exactly one immutable executed R1 image");
}

const bindingMap = new Map();
for (const binding of bindings) {
  const separator = binding.indexOf("=");
  if (separator < 1) fail("capture context received a malformed fleet binding");
  const service = binding.slice(0, separator);
  const containerID = binding.slice(separator + 1);
  if (bindingMap.has(service)) {
    fail("capture context received a duplicate fleet service");
  }
  bindingMap.set(service, containerID);
}
if (!Array.isArray(context.r1_fleet) || context.r1_fleet.length < 1) {
  fail("capture context has no authoritative R1 fleet");
}
const fleetServices = new Set();
for (const instance of context.r1_fleet) {
  if (!exactKeys(instance, ["service", "container_id", "operator_address"])) {
    fail("capture context carries a malformed R1 fleet entry");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(instance.service || "")) {
    fail("capture context carries an unsafe R1 service identity");
  }
  if (!/^[0-9a-f]{64}$/.test(instance.container_id || "")) {
    fail("capture context carries no immutable R1 container identity");
  }
  if (!/^0x[0-9a-f]{40}$/.test(instance.operator_address || "")) {
    fail("capture context carries no normalized R1 operator identity");
  }
  if (fleetServices.has(instance.service)) {
    fail("capture context carries a duplicate R1 service identity");
  }
  fleetServices.add(instance.service);
  if (bindingMap.get(instance.service) !== instance.container_id) {
    fail("capture context R1 fleet differs from the signaled container set");
  }
}
if (
  fleetServices.size !== bindingMap.size ||
  Array.from(bindingMap.keys()).some((service) => !fleetServices.has(service))
) {
  fail("capture context R1 fleet differs from the signaled service set");
}

process.stdout.write(JSON.stringify(context));
NODE
} 2>&1)" || fail "invalid capture context: ${CAPTURE_CONTEXT}"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cutover-evidence-window.XXXXXX")" ||
  fail "cannot create a temporary evidence directory"
trap 'rm -rf "${WORK_DIR}"' EXIT

# Millisecond precision prevents an activation emitted just before this run in
# the same wall-clock second from being mistaken for this run's acknowledgement.
OPENED_AT="$(node -e 'process.stdout.write(new Date().toISOString())')"

relevant_log_path() {
  printf '%s/%s.log\n' "${WORK_DIR}" "$1"
}

refresh_relevant_log() {
  local index="$1"
  local service="${SERVICES[${index}]}"
  local container="${CONTAINERS[${index}]}"
  local raw="${WORK_DIR}/${service}.raw"
  local relevant
  relevant="$(relevant_log_path "${service}")"

  if ! docker logs --timestamps --since "${OPENED_AT}" \
    "${container}" >"${raw}" 2>"${WORK_DIR}/${service}.docker-error"; then
    return 1
  fi

  LC_ALL=C awk '
    index($0, "protocol cutover evidence window changed") ||
    index($0, "protocol cutover peer roster snapshot")
  ' "${raw}" >"${relevant}"
}

has_activation() {
  LC_ALL=C grep -Fq \
    'protocol cutover evidence window changed [active=true]' "$1"
}

has_close() {
  LC_ALL=C grep -Fq \
    'protocol cutover evidence window changed [active=false]' "$1"
}

has_periodic_empty_evidence() {
  local candidate_count
  candidate_count="$(
    LC_ALL=C awk '
      index($0, "protocol cutover peer roster snapshot") &&
      index($0, "[clockAvailable=true]") &&
      index($0, "[legacyPeers=0]") {
        count++
      }
      END {
        print count + 0
      }
    ' "$1"
  )"
  ((candidate_count >= 2)) || return 1

  node - "$1" "${MIN_CADENCE_SECONDS}" "${MAX_CADENCE_SECONDS}" <<'NODE'
const fs = require("fs");
const [path, minimumText, maximumText] = process.argv.slice(2);
const minimum = Number(minimumText) * 1000;
const maximum = Number(maximumText) * 1000;
const lines = fs.readFileSync(path, "utf8").split(/\r?\n/);

const snapshots = lines
  .filter((line) =>
    line.includes("protocol cutover peer roster snapshot") &&
    line.includes("[clockAvailable=true]") &&
    line.includes("[legacyPeers=0]")
  )
  .map((line) => {
    const token = (line.match(/^(\S+)\s/) || [])[1] || "";
    const currentBlock = Number(
      (line.match(/\[currentBlock=(\d+)\]/) || [])[1]
    );
    // Docker uses RFC3339Nano. Date.parse implementations commonly accept
    // milliseconds only, so truncate (never round) a longer fractional part.
    const normalized = token.replace(
      /(\.\d{3})\d+(Z|[+-]\d{2}:\d{2})$/,
      "$1$2"
    );
    return { timestamp: Date.parse(normalized), currentBlock };
  })
  .filter((snapshot) =>
    Number.isFinite(snapshot.timestamp) &&
    Number.isSafeInteger(snapshot.currentBlock)
  );

for (let index = 1; index < snapshots.length; index++) {
  const previous = snapshots[index - 1];
  const current = snapshots[index];
  const elapsed = current.timestamp - previous.timestamp;
  if (
    elapsed >= minimum &&
    elapsed <= maximum &&
    current.currentBlock > previous.currentBlock
  ) process.exit(0);
}
process.exit(1);
NODE
}

all_marked() {
  local mark
  for mark in "$@"; do
    [[ "${mark}" == "1" ]] || return 1
  done
}

add_failure() {
  FAILURES+=("$1")
  FAILURE_COUNT=$((FAILURE_COUNT + 1))
}

for index in "${!SERVICES[@]}"; do
  if docker kill --signal=SIGUSR1 "${CONTAINERS[${index}]}" >/dev/null; then
    SIGNAL_DELIVERED[index]=1
  else
    add_failure "SIGUSR1 delivery failed for ${SERVICES[${index}]}"
  fi
done

for ((attempt = 1; attempt <= ACTIVATION_POLL_ATTEMPTS; attempt++)); do
  for index in "${!SERVICES[@]}"; do
    if refresh_relevant_log "${index}" &&
      has_activation "$(relevant_log_path "${SERVICES[${index}]}")"; then
      ACTIVATION_SEEN[index]=1
    fi
  done

  all_marked "${ACTIVATION_SEEN[@]}" && break
  ((attempt == ACTIVATION_POLL_ATTEMPTS)) || sleep "${POLL_SECONDS}"
done

for index in "${!SERVICES[@]}"; do
  if [[ "${ACTIVATION_SEEN[${index}]}" != "1" ]]; then
    add_failure \
      "${SERVICES[${index}]} did not author an evidence-window activation"
  fi
done

if all_marked "${ACTIVATION_SEEN[@]}"; then
  for ((attempt = 1; attempt <= EVIDENCE_POLL_ATTEMPTS; attempt++)); do
    for index in "${!SERVICES[@]}"; do
      if refresh_relevant_log "${index}" &&
        has_periodic_empty_evidence \
          "$(relevant_log_path "${SERVICES[${index}]}")"; then
        CADENCE_SEEN[index]=1
      fi
    done

    all_marked "${CADENCE_SEEN[@]}" && break
    ((attempt == EVIDENCE_POLL_ATTEMPTS)) || sleep "${POLL_SECONDS}"
  done
fi

for index in "${!SERVICES[@]}"; do
  if [[ "${CADENCE_SEEN[${index}]}" != "1" ]]; then
    add_failure \
      "${SERVICES[${index}]} did not author two clock-healthy empty roster snapshots with advancing blocks at the five-minute cadence"
  fi
done

mkdir -p "$(dirname "${ARCHIVE_DIR}")" ||
  fail "cannot create the evidence archive parent"
mkdir "${ARCHIVE_DIR}" ||
  fail "cannot create evidence archive [${ARCHIVE_DIR}]"

STATUS_FILE="${WORK_DIR}/status.tsv"
: >"${STATUS_FILE}"
for index in "${!SERVICES[@]}"; do
  log="$(relevant_log_path "${SERVICES[${index}]}")"
  if [[ ! -f "${log}" ]]; then
    : >"${log}"
  fi
  cp "${log}" "${ARCHIVE_DIR}/${SERVICES[${index}]}.log" ||
    fail "cannot archive the log for ${SERVICES[${index}]}"
  printf '%s\t%s\t%s\t%s\n' \
    "${SERVICES[${index}]}" \
    "${SIGNAL_DELIVERED[${index}]}" \
    "${ACTIVATION_SEEN[${index}]}" \
    "${CADENCE_SEEN[${index}]}" >>"${STATUS_FILE}"
done

ARCHIVED_AT="$(node -e 'process.stdout.write(new Date().toISOString())')"
node - "${STATUS_FILE}" "${OPENED_AT}" "${ARCHIVED_AT}" \
  "${CAPTURE_CONTEXT}" <<'NODE' \
  >"${ARCHIVE_DIR}/window-open.json"
const fs = require("fs");
const [statusPath, openedAt, archivedAt, captureContextJSON] =
  process.argv.slice(2);
const services = fs.readFileSync(statusPath, "utf8").trim().split(/\r?\n/)
  .filter(Boolean)
  .map((line) => {
    const [service, signalDelivered, activationSeen, cadenceSeen] =
      line.split("\t");
    return {
      service,
      signal_delivered: signalDelivered === "1",
      activation_seen: activationSeen === "1",
      periodic_empty_snapshots_seen: cadenceSeen === "1",
    };
  });
process.stdout.write(JSON.stringify({
  schema_version: 2,
  capture_context: JSON.parse(captureContextJSON),
  opened_at: openedAt,
  archived_at: archivedAt,
  services,
  complete: services.length > 0 && services.every((service) =>
    service.signal_delivered &&
    service.activation_seen &&
    service.periodic_empty_snapshots_seen
  ),
}, null, 2) + "\n");
NODE

# The periodic evidence is now present in its final archive path. Only after
# that point may the operator signal close the window.
for index in "${!SERVICES[@]}"; do
  if docker kill --signal=SIGUSR2 "${CONTAINERS[${index}]}" >/dev/null; then
    CLOSE_DELIVERED[index]=1
  else
    add_failure "SIGUSR2 delivery failed for ${SERVICES[${index}]}"
  fi
done

for ((attempt = 1; attempt <= ACTIVATION_POLL_ATTEMPTS; attempt++)); do
  for index in "${!SERVICES[@]}"; do
    if refresh_relevant_log "${index}" &&
      has_close "$(relevant_log_path "${SERVICES[${index}]}")"; then
      CLOSE_SEEN[index]=1
    fi
  done

  all_marked "${CLOSE_SEEN[@]}" && break
  ((attempt == ACTIVATION_POLL_ATTEMPTS)) || sleep "${POLL_SECONDS}"
done

for index in "${!SERVICES[@]}"; do
  if [[ "${CLOSE_SEEN[${index}]}" != "1" ]]; then
    add_failure "${SERVICES[${index}]} did not author an evidence-window close"
  fi

  log="$(relevant_log_path "${SERVICES[${index}]}")"
  if [[ -f "${log}" ]]; then
    cp "${log}" "${ARCHIVE_DIR}/${SERVICES[${index}]}.log" ||
      fail "cannot finalize the archived log for ${SERVICES[${index}]}"
  fi
done

FAILURE_FILE="${WORK_DIR}/failures.txt"
: >"${FAILURE_FILE}"
if ((FAILURE_COUNT > 0)); then
  printf '%s\n' "${FAILURES[@]}" >"${FAILURE_FILE}"
fi
: >"${STATUS_FILE}"
for index in "${!SERVICES[@]}"; do
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${SERVICES[${index}]}" \
    "${SIGNAL_DELIVERED[${index}]}" \
    "${ACTIVATION_SEEN[${index}]}" \
    "${CADENCE_SEEN[${index}]}" \
    "${CLOSE_DELIVERED[${index}]}" \
    "${CLOSE_SEEN[${index}]}" >>"${STATUS_FILE}"
done

CLOSED_AT="$(node -e 'process.stdout.write(new Date().toISOString())')"
node - "${STATUS_FILE}" "${FAILURE_FILE}" "${ARCHIVE_DIR}" \
  "${OPENED_AT}" "${ARCHIVED_AT}" "${CLOSED_AT}" \
  "${CAPTURE_CONTEXT}" <<'NODE' \
  >"${ARCHIVE_DIR}/result.json"
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const [
  statusPath, failurePath, archivePath, openedAt, archivedAt, closedAt,
  captureContextJSON,
] = process.argv.slice(2);
const failures = fs.readFileSync(failurePath, "utf8").split(/\r?\n/)
  .filter(Boolean);
const services = fs.readFileSync(statusPath, "utf8").trim().split(/\r?\n/)
  .filter(Boolean)
  .map((line) => {
    const [
      service, signalDelivered, activationSeen, cadenceSeen,
      closeDelivered, closeSeen,
    ] = line.split("\t");
    const log = fs.readFileSync(path.join(archivePath, service + ".log"));
    const text = log.toString("utf8");
    return {
      service,
      signal_delivered: signalDelivered === "1",
      activation_seen: activationSeen === "1",
      periodic_empty_snapshots_seen: cadenceSeen === "1",
      close_delivered: closeDelivered === "1",
      close_seen: closeSeen === "1",
      empty_snapshot_lines: text.split(/\r?\n/).filter((line) =>
        line.includes("protocol cutover peer roster snapshot") &&
        line.includes("[legacyPeers=0]")
      ).length,
      relevant_log_sha256: crypto.createHash("sha256").update(log).digest("hex"),
    };
  });
const windowOpen = fs.readFileSync(path.join(archivePath, "window-open.json"));
process.stdout.write(JSON.stringify({
  schema_version: 2,
  capture_context: JSON.parse(captureContextJSON),
  opened_at: openedAt,
  archived_before_close_at: archivedAt,
  closed_at: closedAt,
  window_open_sha256:
    crypto.createHash("sha256").update(windowOpen).digest("hex"),
  complete: failures.length === 0,
  failures,
  services,
}, null, 2) + "\n");
NODE

if ((FAILURE_COUNT > 0)); then
  printf 'FAIL: cutover evidence window was not complete:\n' >&2
  printf '  - %s\n' "${FAILURES[@]}" >&2
  exit 1
fi

printf 'cutover roster evidence archived at %s\n' "${ARCHIVE_DIR}"
