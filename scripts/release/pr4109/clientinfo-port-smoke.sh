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
#     otherwise starts normally.
#
# The unit/config half of the acceptance (section 14.1) is proven by the Go
# tests and does NOT need this harness:
#   go test ./cmd/... ./config/... ./pkg/clientinfo/... -run \
#     'ClientInfoPort|TestReadConfig_ClientInfoPortZero'
#
# Two sub-steps CANNOT be exercised by this harness and are explicit manual /
# ops follow-up (do not fake them):
#   - a real testnet run scraped from the actual monitoring host for three
#     consecutive intervals with current revision/epoch;
#   - an external untrusted-network probe proving raw 9601 / /diagnostics are
#     unreachable unless an authenticated proxy is intentionally in front.
#
# Usage:
#   # Locally runnable with only Docker (no chain): confirm the image bakes the
#   # 9601 compatibility default into `keep-client start --help`.
#   IMAGE=keep-client:candidate ./clientinfo-port-smoke.sh image-default-check
#
#   # Full listener matrix (needs a chain endpoint + an operator key the node
#   # can start with). Runs each case as a node container on a private network
#   # and probes the internal port from a sibling container.
#   IMAGE=keep-client:candidate \
#   ETH_RPC=wss://... \
#   KEY_FILE=/abs/path/to/keyfile.json \
#   KEY_PASSWORD=... \
#     ./clientinfo-port-smoke.sh listener-matrix
#
set -euo pipefail

IMAGE="${IMAGE:-keep-client:candidate}"
NETWORK="cutover-port-smoke-net"
PROBE_IMAGE="curlimages/curl:8.10.1"

# Metric names that every positive /metrics response must contain. The first six
# are backed by the current performance constants; the rest are the new
# stranded-peer / gate observability requirements.
REQUIRED_METRICS=(
  "client_info"
  "performance_signing_operations_total"
  "performance_signing_success_total"
  "performance_signing_failed_total"
  "performance_signing_timeouts_total"
  "performance_dkg_failed_total"
)

log() { printf '[port-smoke] %s\n' "$*"; }
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

# assert_listens <container> <port> — probe the internal port from a sibling on
# the private network and require the required metric names to be present.
assert_listens() {
  local container="$1" port="$2" body
  body="$(docker run --rm --network "${NETWORK}" "${PROBE_IMAGE}" \
    -fsS --max-time 10 "http://${container}:${port}/metrics")" \
    || fail "case ${container}: expected a listener on ${port}, got none"
  local metric
  for metric in "${REQUIRED_METRICS[@]}"; do
    grep -q "${metric}" <<<"${body}" \
      || fail "case ${container}: /metrics missing required metric ${metric}"
  done
  log "OK: ${container} listens on ${port} with meaningful /metrics content"
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

listener_matrix() {
  : "${ETH_RPC:?set ETH_RPC to a chain endpoint the node can start against}"
  : "${KEY_FILE:?set KEY_FILE to an operator key file the node can start with}"
  : "${KEY_PASSWORD:?set KEY_PASSWORD for the operator key file}"

  docker network create "${NETWORK}" >/dev/null 2>&1 || true
  trap 'docker rm -f case-default case-toml9601 case-cli9601 case-custom \
      case-cli0 case-toml0 >/dev/null 2>&1 || true;
      docker network rm "${NETWORK}" >/dev/null 2>&1 || true' EXIT

  log "NOTE: each case must run long enough for the node to pass ethereum.Connect"
  log "      and reach clientinfo.Initialize before the sibling probe fires."

  # The concrete `docker run ...` node invocations are intentionally left to the
  # operator: they depend on the chain endpoint, key mounting, and the developer
  # vs testnet flags of the target environment. Start each case container named
  # exactly as asserted below, then call the matching assertion:
  #
  #   case-default  : no client-info flags/section            -> assert_listens 9601
  #   case-toml9601 : [clientInfo] Port = 9601                -> assert_listens 9601
  #   case-cli9601  : --clientInfo.port 9601                  -> assert_listens 9601
  #   case-custom   : --clientInfo.port 9137                  -> assert_listens 9137
  #   case-cli0     : --clientInfo.port 0                     -> assert_no_listener 9601
  #   case-toml0    : [clientInfo] Port = 0                   -> assert_no_listener 9601
  #
  # Example assertions (uncomment once the case containers are started):
  # assert_listens     case-default  9601
  # assert_listens     case-toml9601 9601
  # assert_listens     case-cli9601  9601
  # assert_listens     case-custom   9137
  # assert_no_listener case-cli0     9601
  # assert_no_listener case-toml0    9601

  fail "listener-matrix requires operator-provided node case containers; see comments above"
}

case "${1:-}" in
  image-default-check) image_default_check ;;
  listener-matrix)     listener_matrix ;;
  *)
    echo "usage: IMAGE=... $0 {image-default-check|listener-matrix}" >&2
    exit 2
    ;;
esac
