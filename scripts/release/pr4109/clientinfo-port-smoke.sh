#!/usr/bin/env bash
#
# clientinfo-port-smoke.sh — container smoke matrix for the temporary
# clientInfo.port 9601 compatibility default.
#
# This harness proves, against an immutable runtime image, that:
#   - with no client-info setting the container listens on 9601 internally;
#   - an explicit 9601 (TOML or CLI) also listens;
#   - a custom port listens only on that port;
#   - explicit 0 (TOML or CLI) starts no client-info listener while the node
#     otherwise starts normally;
# and that every positive /metrics and /diagnostics response carries meaningful
# content (not just HTTP 200), including the stranded-peer observability signals
# added by this release.
#
# The unit/config half of the acceptance is proven by the Go tests and does
# NOT need this harness:
#   go test ./cmd/... ./config/... ./pkg/clientinfo/... -run \
#     'ClientInfoPort|TestReadConfig_ClientInfoPortZero'
#
# SCOPE NOTE: this build contains the block-height cutover gate, whose fixed
# gauges (performance_participation_gate_state, _cutover_block,
# _active_ceremonies, ...) are all registered at construction, so a positive
# /metrics response must carry them alongside the stranded-peer observability
# metrics. The one-value schedule exposes a single cutover height; there are
# no drain/stop metrics to assert.
#
# Two sub-steps CANNOT be exercised by this harness and are explicit manual /
# ops follow-up (do not fake them):
#   - a real testnet run scraped from the actual monitoring host for three
#     consecutive intervals with current revision/epoch;
#   - an external untrusted-network probe proving raw 9601 / /diagnostics are
#     unreachable unless an authenticated proxy is intentionally in front.
#
# Usage:
#   # Docker-only, no chain: confirm the image bakes the 9601 compatibility
#   # default into `keep-client start --help`.
#   IMAGE=keep-client@sha256:<candidate-digest> ./clientinfo-port-smoke.sh image-default-check
#
#   # Full listener matrix. Starts each of the six cases itself as a node
#   # container on a private network and probes the internal endpoints from a
#   # sibling container. A chain endpoint and an operator key are required
#   # because a node only brings up the client-info listener after it connects
#   # to Ethereum (cmd/start.go), so these are inherent inputs, not a scaffold.
#   IMAGE=keep-client@sha256:<candidate-digest> \
#   ETH_RPC=wss://... \
#   BTC_ELECTRUM_URL=tcp://electrum:50001 \
#   KEY_FILE=/abs/path/to/keyfile.json \
#   KEY_PASSWORD=... \
#     ./clientinfo-port-smoke.sh listener-matrix
#
set -euo pipefail

# Immutable-digest requirement: both the candidate and the probe image MUST be
# pinned by @sha256: digest, not a mutable tag, so a smoke run tests exactly the
# reviewed artifact and cannot be silently repointed between checks. Supply
# digest-pinned references via IMAGE / PROBE_IMAGE. The placeholders below are not
# valid digests and are rejected by require_digest until replaced; the live Docker
# run itself remains manual/ops follow-up (see the SCOPE NOTE above).
IMAGE="${IMAGE:-keep-client@sha256:REPLACE_WITH_CANDIDATE_IMAGE_DIGEST}"
PROBE_IMAGE="${PROBE_IMAGE:-curlimages/curl@sha256:REPLACE_WITH_CURL_IMAGE_DIGEST}"

# Network mode: start the node in an explicit non-mainnet network so the harness
# never resolves the mainnet default (config.go). Override to --developer if the
# candidate image is built for developer mode.
NETWORK_MODE="${NETWORK_MODE:---testnet}"

# Unique per-run suffix so a failed setup only ever force-removes THIS run's
# containers/network, never unrelated resources that happen to share a fixed name.
RUN_ID="${RUN_ID:-$$-${RANDOM}}"
NETWORK="cutover-port-smoke-net-${RUN_ID}"

# The six case container names, uniquely suffixed per run.
CASES=(default toml9601 cli9601 custom cli0 toml0)
cname() { printf 'case-%s-%s' "$1" "${RUN_ID}"; }

READY_TIMEOUT="${READY_TIMEOUT:-180}"
# The endpoint answering is the definitive readiness signal, so the positive
# probe retries with a bounded backoff instead of assuming the listener is up
# the instant a log line appears (which would race listener initialization).
PROBE_RETRIES="${PROBE_RETRIES:-20}"
PROBE_INTERVAL="${PROBE_INTERVAL:-3}"
# The negative (no-listener) probe re-checks over a short settling window so a
# listener that binds slightly after startup cannot false-pass a "disabled" case.
NEGATIVE_PROBE_ATTEMPTS="${NEGATIVE_PROBE_ATTEMPTS:-5}"
NEGATIVE_PROBE_INTERVAL="${NEGATIVE_PROBE_INTERVAL:-3}"
CUSTOM_PORT="${CUSTOM_PORT:-9137}"

WORKDIR=""

# require_digest fails unless ref is pinned by an immutable @sha256: digest.
require_digest() {
  local ref="$1" what="$2"
  case "${ref}" in
    *@sha256:REPLACE_*|*REPLACE_*)
      fail "${what} is a placeholder; set ${what} to an immutable @sha256: digest" ;;
    *@sha256:[0-9a-f]*)
      [[ "${#ref}" -ge 80 ]] || fail "${what} digest looks malformed: ${ref}" ;;
    *)
      fail "${what} must be pinned by an immutable @sha256: digest, not a mutable tag (${ref})" ;;
  esac
}

# Metric names every positive /metrics response must contain. The first six are
# backed by the current performance constants; the rest are the participation
# gate and stranded-peer / roster observability metrics added by this release
# (all registered at zero or their startup value, so they appear before any
# event).
REQUIRED_METRICS=(
  "client_info"
  "performance_signing_operations_total"
  "performance_signing_success_total"
  "performance_signing_failed_total"
  "performance_signing_timeouts_total"
  "performance_dkg_failed_total"
  "performance_participation_gate_state"
  "performance_participation_current_block"
  "performance_participation_cutover_block"
  "performance_participation_allowed"
  "performance_participation_active_ceremonies"
  "performance_announcer_session_id_mismatch_total"
  "performance_announcer_cross_format_peer_total"
  "performance_announcer_legacy_peers_current"
  "performance_announcer_legacy_peer_additions_total"
  "performance_announcer_legacy_peer_evictions_total"
)

# Substrings every positive /diagnostics response must contain.
REQUIRED_DIAGNOSTICS=(
  "client_info"
  "cutover_legacy_peers"
  "protocol_participation"
)

log()  { printf '[port-smoke] %s\n' "$*"; }
fail() { printf '[port-smoke][FAIL] %s\n' "$*" >&2; exit 1; }

# image-default-check: Docker-only, no chain. Proves the runtime image bakes the
# 9601 compatibility default and the trusted-network help text.
image_default_check() {
  require_digest "${IMAGE}" "IMAGE"
  log "checking that ${IMAGE} bakes the 9601 compatibility default"
  local help
  help="$(docker run --rm --entrypoint keep-client "${IMAGE}" start --help)"

  grep -Eq -- '--clientInfo\.port int .* \(default 9601\)' <<<"${help}" \
    || fail "start --help does not show '(default 9601)' for --clientInfo.port"
  grep -q -- 'Set to 0 to disable; expose only on a trusted network' <<<"${help}" \
    || fail "start --help is missing the trusted-network / zero-disable text"

  log "OK: image advertises the 9601 compatibility default with trusted-network guidance"
}

# write_config <file> <clientinfo-section> — render a minimal, valid start config
# with the operator-supplied chain/key/electrum values and the given client-info
# section (which may be empty to omit the section entirely).
write_config() {
  local file="$1" clientinfo="$2"
  cat >"${file}" <<EOF
[ethereum]
URL = "${ETH_RPC}"
KeyFile = "/keys/operator.json"

[bitcoin.electrum]
URL = "${BTC_ELECTRUM_URL}"

[network]
Port = 3919

[storage]
Dir = "/storage"

${clientinfo}
EOF
}

# start_node_case <name> <config-file> [extra cli args...] — start a node
# container on the private network with the rendered config and key mounted.
start_node_case() {
  local name="$1" config="$2"
  shift 2
  # NETWORK_MODE forces an explicit non-mainnet network so the node never
  # resolves mainnet defaults.
  docker run -d --name "${name}" --network "${NETWORK}" \
    -e KEEP_ETHEREUM_PASSWORD="${KEY_PASSWORD}" \
    -v "${config}:/config/config.toml:ro" \
    -v "${KEY_FILE}:/keys/operator.json:ro" \
    "${IMAGE}" start ${NETWORK_MODE} --config /config/config.toml "$@" >/dev/null \
    || fail "case ${name}: container failed to start"
}

# wait_ready <container> — block until the node logs that it has initialized the
# client info registry (or reached the point past which no listener will appear),
# bounded by READY_TIMEOUT.
wait_ready() {
  local container="$1" waited=0
  while (( waited < READY_TIMEOUT )); do
    if ! docker ps --filter "name=${container}" --filter "status=running" \
        --format '{{.Names}}' | grep -q "${container}"; then
      docker logs "${container}" 2>&1 | tail -40 >&2
      fail "case ${container}: node container exited before becoming ready"
    fi
    if docker logs "${container}" 2>&1 | grep -Eq \
        'clientinfo|client info|initialized tbtc|Bootstrapping|started tbtc'; then
      return 0
    fi
    sleep 3
    waited=$(( waited + 3 ))
  done
  docker logs "${container}" 2>&1 | tail -40 >&2
  fail "case ${container}: node did not reach readiness within ${READY_TIMEOUT}s"
}

# assert_listens <container> <port> — probe /metrics and /diagnostics from a
# sibling on the private network and require meaningful content on both.
assert_listens() {
  local container="$1" port="$2" body diag metric substr attempt=0
  # Retry the /metrics probe with a bounded backoff: wait_ready only proves the
  # process is up, so the listener may bind a moment later. The endpoint
  # answering is the real readiness signal.
  while :; do
    if body="$(docker run --rm --network "${NETWORK}" "${PROBE_IMAGE}" \
        -fsS --max-time 10 "http://${container}:${port}/metrics")"; then
      break
    fi
    attempt=$(( attempt + 1 ))
    if (( attempt >= PROBE_RETRIES )); then
      docker logs "${container}" 2>&1 | tail -40 >&2
      fail "case ${container}: expected a listener on ${port}, got none after ${attempt} attempts"
    fi
    sleep "${PROBE_INTERVAL}"
  done
  for metric in "${REQUIRED_METRICS[@]}"; do
    grep -q "${metric}" <<<"${body}" \
      || fail "case ${container}: /metrics missing required metric ${metric}"
  done

  diag="$(docker run --rm --network "${NETWORK}" "${PROBE_IMAGE}" \
    -fsS --max-time 10 "http://${container}:${port}/diagnostics")" \
    || fail "case ${container}: /diagnostics did not respond on ${port}"
  for substr in "${REQUIRED_DIAGNOSTICS[@]}"; do
    grep -q "${substr}" <<<"${diag}" \
      || fail "case ${container}: /diagnostics missing required content ${substr}"
  done
  log "OK: ${container} listens on ${port} with meaningful /metrics and /diagnostics content"
}

# assert_no_listener <container> <port> — require the port to STAY closed across a
# short settling window while the node process itself keeps running. A single
# immediate probe would false-pass if the listener binds slightly after startup,
# so re-probe NEGATIVE_PROBE_ATTEMPTS times: if a listener EVER answers, fail.
assert_no_listener() {
  local container="$1" port="$2" attempt
  for (( attempt = 1; attempt <= NEGATIVE_PROBE_ATTEMPTS; attempt++ )); do
    if docker run --rm --network "${NETWORK}" "${PROBE_IMAGE}" \
        -fsS --max-time 5 "http://${container}:${port}/metrics" >/dev/null 2>&1; then
      fail "case ${container}: expected NO listener on ${port}, but one answered on attempt ${attempt}"
    fi
    # The node must stay up throughout — a disabled listener must not mean a dead
    # node.
    docker ps --filter "name=${container}" --filter "status=running" \
      --format '{{.Names}}' | grep -q "${container}" \
      || fail "case ${container}: node container is not running"
    sleep "${NEGATIVE_PROBE_INTERVAL}"
  done
  log "OK: ${container} has no client-info listener across ${NEGATIVE_PROBE_ATTEMPTS} probes but the node is still running"
}

cleanup() {
  # Only this run's uniquely-named containers/network are ever removed.
  local base
  for base in "${CASES[@]}"; do
    docker rm -f "$(cname "${base}")" >/dev/null 2>&1 || true
  done
  docker network rm "${NETWORK}" >/dev/null 2>&1 || true
  [[ -n "${WORKDIR}" ]] && rm -rf "${WORKDIR}"
}

listener_matrix() {
  : "${ETH_RPC:?set ETH_RPC to a chain endpoint the node can start against}"
  : "${BTC_ELECTRUM_URL:?set BTC_ELECTRUM_URL to a reachable Electrum endpoint}"
  : "${KEY_FILE:?set KEY_FILE to an operator key file the node can start with}"
  : "${KEY_PASSWORD:?set KEY_PASSWORD for the operator key file}"

  # Enforce immutable digests before doing anything destructive.
  require_digest "${IMAGE}" "IMAGE"
  require_digest "${PROBE_IMAGE}" "PROBE_IMAGE"

  WORKDIR="$(mktemp -d)"
  docker network create "${NETWORK}" >/dev/null 2>&1 || true
  trap cleanup EXIT

  # Render one config per case. The disabled cases and the explicit cases differ
  # only in the [clientInfo] section / CLI flag; the compatibility-default case
  # omits the section entirely.
  write_config "${WORKDIR}/default.toml" ""
  write_config "${WORKDIR}/toml9601.toml" $'[clientInfo]\nPort = 9601'
  write_config "${WORKDIR}/cli.toml" ""
  write_config "${WORKDIR}/custom.toml" "[clientInfo]"$'\n'"Port = ${CUSTOM_PORT}"
  write_config "${WORKDIR}/toml0.toml" $'[clientInfo]\nPort = 0'

  log "starting the six client-info port cases (network mode: ${NETWORK_MODE})"
  start_node_case "$(cname default)"  "${WORKDIR}/default.toml"
  start_node_case "$(cname toml9601)" "${WORKDIR}/toml9601.toml"
  start_node_case "$(cname cli9601)"  "${WORKDIR}/cli.toml"    --clientInfo.port 9601
  start_node_case "$(cname custom)"   "${WORKDIR}/custom.toml"
  start_node_case "$(cname cli0)"     "${WORKDIR}/cli.toml"    --clientInfo.port 0
  start_node_case "$(cname toml0)"    "${WORKDIR}/toml0.toml"

  local base
  for base in "${CASES[@]}"; do
    wait_ready "$(cname "${base}")"
  done

  assert_listens     "$(cname default)"  9601
  assert_listens     "$(cname toml9601)" 9601
  assert_listens     "$(cname cli9601)"  9601
  assert_listens     "$(cname custom)"   "${CUSTOM_PORT}"
  # The custom-port case must NOT also answer on 9601.
  assert_no_listener "$(cname custom)"   9601
  assert_no_listener "$(cname cli0)"     9601
  assert_no_listener "$(cname toml0)"    9601

  log "OK: full client-info port listener matrix passed"
}

case "${1:-}" in
  image-default-check) image_default_check ;;
  listener-matrix)     listener_matrix ;;
  *)
    echo "usage: IMAGE=... $0 {image-default-check|listener-matrix}" >&2
    exit 2
    ;;
esac
