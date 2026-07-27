#!/usr/bin/env bash
#
# Single-release cutover rehearsal driver.
#
# This driver structures the two mandatory container rehearsals — the
# exact-image single-release cutover rehearsal and the homogeneous rollback
# rehearsal — as explicit, individually reportable stages. Stages that are
# provable from this repository alone run real Go tests. Stages that require
# the immutable prior-production and R1 runtime images, a rehearsal chain, and
# persistent volumes refuse to run until those inputs are supplied: a
# rehearsal stage that cannot execute reports BLOCKED with its exact missing
# inputs instead of pretending to pass.
#
# Required environment for the container stages:
#
#   PRIOR_IMAGE_DIGEST   immutable prior-production runtime image digest
#                        (repo@sha256:...); a mutable tag is not evidence
#   R1_IMAGE_DIGEST      immutable R1 candidate runtime image digest
#   ETH_WS_URL           rehearsal chain websocket endpoint
#   CUTOVER_BLOCK        rehearsed cutover block C on that chain
#   KEYSTORE_DIR         per-node rehearsal inputs, one subdirectory per
#                        compose service holding that node's config.toml and
#                        operator key file
#   KEEP_ETHEREUM_PASSWORD  operator key file password for the fleet
#
# Fail-closed source binding (every proof stage):
#
#   PR4109_EXPECTED_SOURCE_COMMIT
#                        when set, a proof stage refuses to run unless the
#                        tree under test is exactly this commit: readable
#                        git metadata, HEAD equal to the value, and no
#                        divergence — untracked files included
#   PR4109_SOURCE_BINDING_MODE
#                        exact (default) tolerates no divergence at all;
#                        build-image additionally accepts only what the CI
#                        build image produces by design — .dockerignore'd
#                        paths absent from the image and the gen/ trees the
#                        image regenerates from published artifacts
#
# Evidence is written under EVIDENCE_DIR (default: ./rehearsal-evidence).
# Every accepted rehearsal run must produce a record conforming to
# rehearsal-evidence.schema.json; the validate-evidence stage enforces that.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
EVIDENCE_DIR="${EVIDENCE_DIR:-${SCRIPT_DIR}/rehearsal-evidence}"

usage() {
  cat <<'EOF'
usage: rehearse.sh <stage>

stages:
  local-proofs        run the repository-local Go proofs of the cutover gate:
                      boundary modes, pre-C permit surviving C, quiescence and
                      the signal lifecycle, forced shutdown and clock-failure
                      quarantine, penalty suppression, forwarding lifecycle,
                      held-wait cancellation, the offline state audit, and the
                      tBTC cutover ceremony suites — real security-v2
                      transcripts, the ten-misbehaved-seat real result, the
                      production-scale 90/10 split, heartbeat bands, and
                      roster wiring — under the race detector, plus the
                      integration-tag compile proof; ends with an explicit
                      report of every skipped case (runs today, no Docker)
  static-analysis     run the static analyzers CI enforces on the Go tree,
                      every tool at an immutable version: gofmt, go vet
                      over ./... (strictly wider than CI's root-only vet),
                      staticcheck 2025.1.1 (-SA1019), gosec v2.28.0 with
                      the CI flag set (G115/G118 and generated bindings
                      excluded; CI's own gosec action floats on master, the
                      pin keeps this evidence reproducible), and
                      golangci-lint v2.12.2 (network needed on first run to
                      fetch the pinned tools)
  solidity-proofs     build and test the changed ECDSA contracts surface
                      exactly as the contracts workflow does: Node 18.15.0,
                      the Corepack-managed yarn from packageManager, and a
                      never-skipped 'yarn install --immutable' before
                      yarn build and yarn test
  preflight           validate the container-rehearsal inputs and image digests
  single-release      exact-image cutover rehearsal: prior+R1 mixed fleet
                      before C, work across C without restart, straggler
                      negative control, clock failure, quiesce with in-flight
                      permits  [BLOCKED until preflight passes]
  rollback            homogeneous rollback rehearsal: quiesce all R1,
                      all-candidate-down barrier, offline state audit, staged
                      prior redeploy, forbidden partial-rollback attempt
                      [BLOCKED until preflight passes]
  validate-evidence   validate every evidence record under EVIDENCE_DIR
                      against rehearsal-evidence.schema.json

environment (every proof stage):
  PR4109_EXPECTED_SOURCE_COMMIT
                      fail closed: refuse to run unless the tree under test
                      is exactly this commit (clean, untracked included)
  PR4109_SOURCE_BINDING_MODE
                      exact (default) | build-image (accept only the CI
                      build image's .dockerignore/gen-rebuild divergence)
EOF
}

note() { printf '>> %s\n' "$*"; }
blocked() {
  printf 'BLOCKED: %s\n' "$*" >&2
  exit 3
}
fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

# Working-tree divergence from HEAD as porcelain lines, untracked files
# included: a file git does not track can still change what a go or yarn
# invocation tests, so only ignored paths (evidence logs, build output) are
# exempt. If git itself cannot answer, a sentinel line keeps every consumer
# fail-closed instead of mistaking an error for a clean tree.
source_divergence() {
  git -C "${REPO_ROOT}" status --porcelain 2>/dev/null ||
    printf '!! git status failed; divergence unknown\n'
}

# The exact source commit every stage stamps into its log. A working tree
# that differs from HEAD — untracked files included — is marked -dirty so a
# local log can never pass for evidence of the clean commit; outside a git
# checkout the stamp degrades to "unknown" instead of failing the stage.
# Refusing to run on divergence is verify_source_binding's job.
source_commit() {
  local commit
  if ! commit="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null)"; then
    printf 'unknown'
    return
  fi
  if [[ -n "$(source_divergence)" ]]; then
    commit="${commit}-dirty"
  fi
  printf '%s' "${commit}"
}

# Divergence the CI build image creates by design, and nothing else:
# .dockerignore keeps these paths out of the build context entirely, so
# against the mounted checkout metadata they surface as worktree deletions,
# and `make get_artifacts`/`make generate` rebuild the gen/ trees from the
# published contract artifacts, surfacing as modified, deleted, or
# untracked gen/ and node_modules/ paths. Reads porcelain lines on stdin
# and passes through every line neither family explains.
unexplained_build_image_divergence() {
  local regenerated='(^|/)(gen|node_modules)/'
  local dockerignored='^(\..+|docs[^/]*/.+|infrastructure/.+|scripts/.+'
  dockerignored+='|tmp/.+|CODEOWNERS|Dockerfile|[^/]+\.adoc|solidity/.+'
  dockerignored+='|token-stakedrop/.+|token-tracker/.+)$'
  local line status path
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    status="${line:0:2}"
    path="${line:3}"
    if [[ "${path}" =~ ${regenerated} ]]; then
      continue
    fi
    if [[ "${status}" == " D" && "${path}" =~ ${dockerignored} ]]; then
      continue
    fi
    printf '%s\n' "${line}"
  done
}

# Fail-closed source binding. When PR4109_EXPECTED_SOURCE_COMMIT is set —
# the workflow passes the dispatched SHA to every proof stage, mounting the
# checkout's .git and scripts/ read-only into the build image so even the
# container run can be held to it — the stage refuses to run unless the
# tree under test is exactly that commit. Without the variable the stage
# stamps its log via source_commit and runs anyway: a local iteration loop
# may test a dirty tree, it just can never produce evidence claiming to be
# a clean commit.
verify_source_binding() {
  local expected="${PR4109_EXPECTED_SOURCE_COMMIT:-}"
  if [[ -z "${expected}" ]]; then
    note "source commit: $(source_commit) (unbound run; set \
PR4109_EXPECTED_SOURCE_COMMIT to fail closed on divergence)"
    return
  fi

  local head
  if ! head="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null)"; then
    fail "source binding to ${expected} requested, but the tree under test \
has no readable git metadata; mount the dispatched checkout's .git \
(read-only) next to the source so the tested bytes can be verified"
  fi
  if [[ "${head}" != "${expected}" ]]; then
    fail "source binding mismatch: the tree under test is at ${head}, the \
dispatch expects ${expected}"
  fi

  local mode="${PR4109_SOURCE_BINDING_MODE:-exact}" divergence
  divergence="$(source_divergence)"
  case "${mode}" in
  exact)
    if [[ -n "${divergence}" ]]; then
      printf '%s\n' "${divergence}" >&2
      fail "source binding to ${expected} requested, but the tree diverges \
from that commit (listing above; untracked files count); refusing to \
produce evidence for bytes that are not the dispatched commit"
    fi
    note "source commit: ${expected} (verified against the dispatched SHA)"
    ;;
  build-image)
    local unexplained accepted=0
    unexplained="$(printf '%s\n' "${divergence}" |
      unexplained_build_image_divergence)"
    if [[ -n "${unexplained}" ]]; then
      printf '%s\n' "${unexplained}" >&2
      fail "source binding to ${expected} requested, but the build-image \
tree diverges from that commit beyond the .dockerignore'd and regenerated \
gen/ families (listing above); refusing to produce evidence"
    fi
    if [[ -n "${divergence}" ]]; then
      accepted="$(printf '%s\n' "${divergence}" | grep -c .)"
    fi
    note "source commit: ${expected} (verified against the dispatched SHA \
inside the build image; ${accepted} .dockerignore'd or regenerated path \
divergence(s) accepted by design)"
    ;;
  *)
    fail "unknown PR4109_SOURCE_BINDING_MODE [${mode}]; use exact or \
build-image"
    ;;
  esac
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
    verify_source_binding
    go test -count=1 -v \
      -run 'TestJoinDKGIfEligible|TestMonitorRelayEntry|TestForwardSignatureShares' \
      ./pkg/beacon/
    go test -count=1 ./pkg/protocol/participation/... ./pkg/protocol/state/...
    go test -count=1 -race \
      ./pkg/protocol/participation/... ./pkg/protocol/state/...
    go test -count=1 \
      -run 'TestSubmitDKGResult|TestSyncExecute' \
      ./pkg/beacon/dkg/result/ ./pkg/protocol/state/
    go test -count=1 -race \
      -run 'TestAwaitQuiesce|TestQuiesceBackstop|TestSignalLifecycle' \
      ./cmd/
    go test -count=1 -race ./cmd/participation-state-audit/
    go test -count=1 -run 'TestDecodeSignerAuditRecord' ./pkg/tbtc/
    go test -count=1 -race -timeout 900s -v \
      -run 'Cutover|HandleAnnouncerSessionMismatch' \
      ./pkg/tbtc/
    # The integration-tagged test files are not compiled by the ordinary
    # suite; type-check them so a signature drift cannot hide behind the
    # build tag. Their execution needs live Bitcoin/Ethereum endpoints and
    # stays with the CI integration job.
    go vet -tags=integration ./pkg/bitcoin/electrum/ ./pkg/chain/ethereum/
  ) 2>&1 | tee "${log}"

  # Skips are part of the evidence, not noise: every mandatory acceptance
  # case that cannot run yet must be visible in the proof output.
  local skips
  skips=$(grep -c '^--- SKIP' "${log}" || true)
  if [[ "${skips}" -gt 0 ]]; then
    note "ATTENTION: ${skips} skipped case(s) inside the local proofs:"
    grep '^--- SKIP' "${log}" | sed 's/^/>>   /'
    note "each skip above is a mandatory acceptance case still blocked on" \
      "an external dependency; see the hard-dependency record in README.md"
  else
    note "no skipped cases inside the local proofs"
  fi

  note "local proofs recorded in ${log}"
}

stage_static_analysis() {
  note "running the CI-enforced Go static analyzers at immutable versions"
  mkdir -p "${EVIDENCE_DIR}"
  local log="${EVIDENCE_DIR}/static-analysis.log"

  (
    cd "${REPO_ROOT}"
    verify_source_binding

    note "gofmt"
    if [[ "$(gofmt -l . | wc -l)" -gt 0 ]]; then
      gofmt -d -e .
      exit 1
    fi

    # CI's client-vet job vets the root package only; the rehearsal vets
    # the whole tree so a finding in any changed package blocks evidence.
    note "go vet ./..."
    go vet ./...

    note "staticcheck 2025.1.1 (checks: -SA1019)"
    go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 \
      -checks=-SA1019 ./...

    # CI's gosec job floats on securego/gosec@master; a rehearsal log must
    # be reproducible, so the same flag set runs at a pinned release.
    note "gosec v2.28.0 (CI flag set)"
    go run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 \
      -exclude=G115,G118 \
      -exclude-dir=pkg/chain/ethereum/beacon/gen \
      -exclude-dir=pkg/chain/ethereum/ecdsa/gen \
      -exclude-dir=pkg/chain/ethereum/threshold/gen \
      -exclude-dir=pkg/chain/ethereum/tbtc/gen \
      ./...

    note "golangci-lint v2.12.2"
    go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run
  ) 2>&1 | tee "${log}"

  note "static analysis recorded in ${log}"
}

stage_solidity_proofs() {
  note "building and testing the ECDSA contracts surface"
  mkdir -p "${EVIDENCE_DIR}"
  local log="${EVIDENCE_DIR}/solidity-ecdsa-proofs.log"

  command -v node >/dev/null 2>&1 || blocked "Node.js is required"
  command -v corepack >/dev/null 2>&1 ||
    blocked "corepack is required (bundled with Node >= 16.9)"

  # The contracts workflow runs on exactly Node 18.15.0 because newer
  # releases have produced broken hardhat compile artifacts; evidence from
  # any other version is not that workflow's evidence.
  local ci_node_version="18.15.0"
  local node_version
  node_version=$(node -p 'process.versions.node')
  if [[ "${node_version}" != "${ci_node_version}" ]]; then
    blocked "the contracts workflow runs on Node ${ci_node_version} (found \
$(node -v)); switch with 'nvm install ${ci_node_version} && nvm use \
${ci_node_version}' before running solidity-proofs"
  fi

  (
    cd "${REPO_ROOT}/solidity/ecdsa"
    verify_source_binding

    # Reproduce the contracts workflow's install exactly: the
    # Corepack-managed yarn release pinned in package.json's packageManager
    # field and an immutable install on every run — never skipped, so a
    # stale node_modules cannot masquerade as CI parity. Hardened mode is
    # opted out for the same reason CI opts out: the lockfile carries
    # legitimate npm-descriptor -> git-URL remaps that hardened mode
    # rejects, while lockfile checksums stay enforced either way.
    export YARN_ENABLE_HARDENED_MODE=0
    corepack enable
    note "yarn $(yarn --version)"
    yarn install --immutable
    yarn build
    yarn test
  ) 2>&1 | tee "${log}"

  note "solidity proofs recorded in ${log}"
}

stage_preflight() {
  require_env PRIOR_IMAGE_DIGEST R1_IMAGE_DIGEST ETH_WS_URL CUTOVER_BLOCK \
    KEYSTORE_DIR KEEP_ETHEREUM_PASSWORD
  require_immutable_digest PRIOR_IMAGE_DIGEST "${PRIOR_IMAGE_DIGEST}"
  require_immutable_digest R1_IMAGE_DIGEST "${R1_IMAGE_DIGEST}"
  command -v docker >/dev/null 2>&1 || blocked "docker is required"
  [[ "${CUTOVER_BLOCK}" =~ ^[0-9]+$ && "${CUTOVER_BLOCK}" -gt 0 ]] ||
    blocked "CUTOVER_BLOCK must be a positive integer"
  [[ -d "${KEYSTORE_DIR}" ]] || blocked "KEYSTORE_DIR does not exist"
  for service in prior-node r1-node-1 r1-node-2; do
    [[ -f "${KEYSTORE_DIR}/${service}/config.toml" ]] ||
      blocked "KEYSTORE_DIR/${service}/config.toml is missing; every node \
needs its per-node config with the rehearsal contract addresses, key file \
path, and storage directory"
  done

  note "pulling both immutable digests to verify availability"
  docker pull "${PRIOR_IMAGE_DIGEST}"
  docker pull "${R1_IMAGE_DIGEST}"

  note "preflight passed"
}

stage_single_release() {
  stage_preflight

  # The exact-image cutover sequence requires a rehearsal chain with deployed
  # contracts, a mixed prior/R1 fleet with persistent volumes, and a
  # controlled crossing of C. The compose shell is compose.rehearsal.yaml;
  # the orchestration of the rehearsal steps (mixed pre-C controls, work
  # started across C, partition/restart, straggler negative control and
  # quarantine, homogeneous post-C controls, clock failure, quiescence with
  # in-flight permits) is deliberately not automated here yet: automating it
  # without a rehearsal chain to run against would produce untestable
  # automation.
  blocked "the exact-image cutover sequence needs a rehearsal chain with \
deployed beacon/tBTC contracts; supply one and extend this stage with the \
compose.rehearsal.yaml fleet before relying on it as release evidence"
}

stage_rollback() {
  stage_preflight

  # The rollback sequence additionally requires the offline state audit tool
  # run against every node's storage snapshot and an independent network
  # vantage point to prove the all-candidate-down barrier.
  blocked "the rollback sequence needs the exact-image cutover fleet plus \
storage snapshots and an independent network probe; supply them and extend \
this stage before relying on it as release evidence"
}

stage_validate_evidence() {
  local schema="${SCRIPT_DIR}/rehearsal-evidence.schema.json"

  shopt -s nullglob
  local records=("${EVIDENCE_DIR}"/*.json)
  shopt -u nullglob
  if ((${#records[@]} == 0)); then
    blocked "no evidence records found under ${EVIDENCE_DIR}; a rehearsal \
run that produced no record cannot be accepted"
  fi

  command -v npx >/dev/null 2>&1 ||
    blocked "npx (Node.js) is required to validate evidence records"

  for record in "${records[@]}"; do
    note "validating ${record}"
    npx --yes ajv-cli@5 validate --spec=draft2020 \
      -s "${schema}" -d "${record}" ||
      blocked "evidence record ${record} does not conform to ${schema}"
  done

  note "all evidence records conform to the schema"
}

case "${1:-}" in
local-proofs) stage_local_proofs ;;
static-analysis) stage_static_analysis ;;
solidity-proofs) stage_solidity_proofs ;;
preflight) stage_preflight ;;
single-release) stage_single_release ;;
rollback) stage_rollback ;;
validate-evidence) stage_validate_evidence ;;
*)
  usage
  exit 2
  ;;
esac
