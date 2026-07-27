#!/usr/bin/env bash
#
# PR #4109 Part A — single-release cutover rehearsal driver (sections 9.7, 9.8).
#
# This driver structures the two mandatory container rehearsals — the
# exact-image single-release rehearsal (smoke gate 6) and the homogeneous
# rollback rehearsal (smoke gate 7) — as explicit, individually reportable
# stages. Stages that are provable from this repository alone run real Go
# tests. Stages that require the immutable prior-production and R1 runtime
# images, a rehearsal chain, and persistent volumes refuse to run until those
# inputs are supplied: a rehearsal stage that cannot execute reports BLOCKED
# with its exact missing inputs instead of pretending to pass.
#
# Required environment for the container stages:
#
#   PRIOR_IMAGE_DIGEST   immutable prior-production runtime image digest
#                        (repo@sha256:...); a mutable tag is not evidence
#   R1_IMAGE_DIGEST      immutable R1 candidate runtime image digest
#   ETH_WS_URL           rehearsal chain websocket endpoint
#   CUTOVER_BLOCK        rehearsed cutover block C on that chain
#   KEYSTORE_DIR         operator key material for the rehearsal fleet
#
# Evidence is written under EVIDENCE_DIR (default: ./rehearsal-evidence) and
# must conform to rehearsal-evidence.schema.json before it is accepted.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
EVIDENCE_DIR="${EVIDENCE_DIR:-${SCRIPT_DIR}/rehearsal-evidence}"

usage() {
  cat <<'EOF'
usage: rehearse.sh <stage>

stages:
  local-proofs        run the repository-local Go proofs of the cutover gate:
                      boundary modes, pre-C permit surviving C, quiescence,
                      forced shutdown and clock-failure quarantine, penalty
                      suppression, forwarding lifecycle (runs today, no Docker)
  preflight           validate the container-rehearsal inputs and image digests
  single-release      smoke gate 6: prior+R1 mixed fleet before C, work across
                      C without restart, straggler negative control, clock
                      failure, quiesce with in-flight permits  [BLOCKED until
                      preflight passes]
  rollback            smoke gate 7: quiesce all R1, all-candidate-down barrier,
                      offline state audit, staged prior redeploy, forbidden
                      partial-rollback attempt  [BLOCKED until preflight passes]
EOF
}

note() { printf '>> %s\n' "$*"; }
blocked() {
  printf 'BLOCKED: %s\n' "$*" >&2
  exit 3
}

require_env() {
  local missing=()
  for name in "$@"; do
    [[ -n "${!name:-}" ]] || missing+=("${name}")
  done
  if ((${#missing[@]} > 0)); then
    blocked "missing required rehearsal inputs: ${missing[*]}"
  fi
}

require_immutable_digest() {
  local name="$1" value="$2"
  if [[ ! "${value}" =~ @sha256:[0-9a-f]{64}$ ]]; then
    blocked "${name} must be an immutable repo@sha256:... digest, got [${value}]"
  fi
}

stage_local_proofs() {
  note "running the repository-local cutover gate proofs"
  mkdir -p "${EVIDENCE_DIR}"
  local log="${EVIDENCE_DIR}/local-proofs.log"

  (
    cd "${REPO_ROOT}"
    go test -count=1 -v \
      -run 'TestJoinDKGIfEligible|TestMonitorRelayEntry|TestForwardSignatureShares' \
      ./pkg/beacon/
    go test -count=1 ./pkg/protocol/participation/... ./pkg/protocol/state/...
    go test -count=1 -race \
      ./pkg/protocol/participation/... ./pkg/protocol/state/...
    go test -count=1 \
      -run 'TestSubmitDKGResult|TestSyncExecute' \
      ./pkg/beacon/dkg/result/ ./pkg/protocol/state/
  ) 2>&1 | tee "${log}"

  note "local proofs recorded in ${log}"
}

stage_preflight() {
  require_env PRIOR_IMAGE_DIGEST R1_IMAGE_DIGEST ETH_WS_URL CUTOVER_BLOCK \
    KEYSTORE_DIR
  require_immutable_digest PRIOR_IMAGE_DIGEST "${PRIOR_IMAGE_DIGEST}"
  require_immutable_digest R1_IMAGE_DIGEST "${R1_IMAGE_DIGEST}"
  command -v docker >/dev/null 2>&1 || blocked "docker is required"
  [[ "${CUTOVER_BLOCK}" =~ ^[0-9]+$ && "${CUTOVER_BLOCK}" -gt 0 ]] ||
    blocked "CUTOVER_BLOCK must be a positive integer"
  [[ -d "${KEYSTORE_DIR}" ]] || blocked "KEYSTORE_DIR does not exist"

  note "pulling both immutable digests to verify availability"
  docker pull "${PRIOR_IMAGE_DIGEST}"
  docker pull "${R1_IMAGE_DIGEST}"

  note "preflight passed"
}

stage_single_release() {
  stage_preflight

  # The exact-image sequence of section 9.7 requires a rehearsal chain with
  # deployed contracts, a mixed prior/R1 fleet with persistent volumes, and a
  # controlled crossing of C. The compose shell is compose.rehearsal.yaml;
  # the orchestration of steps 1-8 (mixed pre-C controls, work started across
  # C, partition/restart, straggler negative control and quarantine,
  # homogeneous post-C controls, clock failure, quiescence with in-flight
  # permits) is deliberately not automated here yet: automating it without a
  # rehearsal chain to run against would produce untestable automation.
  blocked "the section 9.7 exact-image sequence needs a rehearsal chain with \
deployed beacon/tBTC contracts; supply one and extend this stage with the \
compose.rehearsal.yaml fleet before relying on it as release evidence"
}

stage_rollback() {
  stage_preflight

  # The section 9.8 rollback sequence additionally requires the offline state
  # audit tool run against every node's storage snapshot and an independent
  # network vantage point to prove the all-candidate-down barrier.
  blocked "the section 9.8 rollback sequence needs the section 9.7 fleet plus \
storage snapshots and an independent network probe; supply them and extend \
this stage before relying on it as release evidence"
}

case "${1:-}" in
local-proofs) stage_local_proofs ;;
preflight) stage_preflight ;;
single-release) stage_single_release ;;
rollback) stage_rollback ;;
*)
  usage
  exit 2
  ;;
esac
