#!/usr/bin/env bash
#
# clientinfo-port-smoke.sh — Part B (section 14.2) container smoke matrix for the
# temporary clientInfo.port 9601 compatibility default.
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
# The unit/config half of the acceptance (section 14.1) is proven by the Go
# tests and does NOT need this harness:
#   go test ./cmd/... ./config/... ./pkg/clientinfo/... -run \
#     'ClientInfoPort|TestReadConfig_ClientInfoPortZero'
#
# SCOPE NOTE: this build does not contain the block-height cutover gate (Part A),
# so the gate-state metrics (performance_participation_gate_state, _drain_block,
# _stop_block, _active_ceremonies) are intentionally NOT asserted — they are not
# exposed. The stranded-peer observability metrics ARE exposed and are asserted.
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
#   IMAGE=keep-client:candidate ./clientinfo-port-smoke.sh image-default-check
#
#   # Full listener matrix. Starts each of the six cases itself as a node
#   # container on a private network and probes the internal endpoints from a
#   # sibling container. A chain endpoint and an operator key are required
#   # because a node only brings up the client-info listener after it connects
#   # to Ethereum (cmd/start.go), so these are inherent inputs, not a scaffold.
#   IMAGE=keep-client:candidate \
#   ETH_RPC=wss://... \
#   BTC_ELECTRUM_URL=tcp://electrum:50001 \
#   KEY_FILE=/abs/path/to/keyfile.json \
#   KEY_PASSWORD=... \
#     ./clientinfo-port-smoke.sh listener-matrix
#
set -euo pipefail

IMAGE="${IMAGE:-keep-client:candidate}"
NETWORK="cutover-port-smoke-net"
PROBE_IMAGE="curlimages/curl:8.10.1"
READY_TIMEOUT="${READY_TIMEOUT:-180}"
# The endpoint answering is the definitive readiness signal, so the positive
# probe retries with a bounded backoff instead of assuming the listener is up
# the instant a log line appears (which would race listener initialization).
PROBE_RETRIES="${PROBE_RETRIES:-20}"
PROBE_INTERVAL="${PROBE_INTERVAL:-3}"
CUSTOM_PORT="${CUSTOM_PORT:-9137}"

WORKDIR=""

# Metric names every positive /metrics response must contain. The first six are
# backed by the current performance constants; the rest are the stranded-peer /
# roster observability metrics added by this release (all registered at zero, so
# they appear before any event). Gate-state metrics are deliberately excluded —
# Part A is not built.
REQUIRED_METRICS=(
  "client_info"
  "performance_signing_operations_total"
  "performance_signing_success_total"
  "performance_signing_failed_total"
  "performance_signing_timeouts_total"
  "performance_dkg_failed_total"
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
)

log()  { printf '[port-smoke] %s\n' "$*"; }
fail() { printf '[port-smoke][FAIL] %s\n' "$*" >&2; exit 1; }

# image-default-check: Docker-only, no chain. Proves the runtime image bakes the
# 9601 compatibility default and the trusted-network help text.
image_default_check() {
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
  docker run -d --name "${name}" --network "${NETWORK}" \
    -e KEEP_ETHEREUM_PASSWORD="${KEY_PASSWORD}" \
    -v "${config}:/config/config.toml:ro" \
    -v "${KEY_FILE}:/keys/operator.json:ro" \
    "${IMAGE}" start --config /config/config.toml "$@" >/dev/null \
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

# assert_no_listener <container> <port> — require the port to be closed while the
# node process itself keeps running.
assert_no_listener() {
  local container="$1" port="$2"
  if docker run --rm --network "${NETWORK}" "${PROBE_IMAGE}" \
      -fsS --max-time 5 "http://${container}:${port}/metrics" >/dev/null 2>&1; then
    fail "case ${container}: expected NO listener on ${port}, but one answered"
  fi
  docker ps --filter "name=${container}" --filter "status=running" \
    --format '{{.Names}}' | grep -q "${container}" \
    || fail "case ${container}: node container is not running"
  log "OK: ${container} has no client-info listener but the node is still running"
}

cleanup() {
  docker rm -f case-default case-toml9601 case-cli9601 case-custom \
    case-cli0 case-toml0 >/dev/null 2>&1 || true
  docker network rm "${NETWORK}" >/dev/null 2>&1 || true
  [[ -n "${WORKDIR}" ]] && rm -rf "${WORKDIR}"
}

listener_matrix() {
  : "${ETH_RPC:?set ETH_RPC to a chain endpoint the node can start against}"
  : "${BTC_ELECTRUM_URL:?set BTC_ELECTRUM_URL to a reachable Electrum endpoint}"
  : "${KEY_FILE:?set KEY_FILE to an operator key file the node can start with}"
  : "${KEY_PASSWORD:?set KEY_PASSWORD for the operator key file}"

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

  log "starting the six client-info port cases"
  start_node_case case-default  "${WORKDIR}/default.toml"
  start_node_case case-toml9601 "${WORKDIR}/toml9601.toml"
  start_node_case case-cli9601  "${WORKDIR}/cli.toml"    --clientInfo.port 9601
  start_node_case case-custom   "${WORKDIR}/custom.toml"
  start_node_case case-cli0     "${WORKDIR}/cli.toml"    --clientInfo.port 0
  start_node_case case-toml0    "${WORKDIR}/toml0.toml"

  for c in case-default case-toml9601 case-cli9601 case-custom case-cli0 case-toml0; do
    wait_ready "${c}"
  done

  assert_listens     case-default  9601
  assert_listens     case-toml9601 9601
  assert_listens     case-cli9601  9601
  assert_listens     case-custom   "${CUSTOM_PORT}"
  # The custom-port case must NOT also answer on 9601.
  assert_no_listener case-custom   9601
  assert_no_listener case-cli0     9601
  assert_no_listener case-toml0    9601

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
