#!/usr/bin/env bash
#
# Self-test for rehearse.sh's evidence-record validation.
#
# Builds throwaway evidence records around the checked-in release manifest
# and proves stage_validate_evidence accepts exactly a record whose schema
# shape, manifest hash, and recorded termination grace are all correct —
# and rejects a wrong hash, a wrong grace, missing binding fields, a
# malformed timestamp, an empty record set, and a bad record hiding behind
# a good one. It also drives the manifest attestation the stage requires
# before it measures anything: absent, incomplete, taken over other manifest
# bytes, recording bounds the reviewed manifest contradicts, taken at
# another commit than the run is bound to, taken at no clean commit at all,
# or vouching for a record built from other bytes — plus the tree binding the
# stage verifies before it judges anything.
#
# The receipt lifecycle is proved through stage_local_proofs itself and not
# only through the invalidation function: the last cases give a reused
# evidence directory a valid inherited receipt, fail the stage's proof seam,
# and require that the receipt was already gone when the proofs started, that
# none survives the failure, and that the acceptance stage is blocked
# afterwards. Needs node/npx and git like the stage it tests; everything
# lives under mktemp and this repository is never touched.

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Guards the stage's self-test hook: the invocations below must run the
# validation itself, not recurse back into this script.
export PR4109_EVIDENCE_SELFTEST=1

# shellcheck source=/dev/null
source "${TEST_DIR}/rehearse.sh"

# The stage reads these from the environment; the container running the proof
# stages exports them, and every case below sets what it needs explicitly, so
# an ambient value must never decide a verdict here.
unset PR4109_EXPECTED_SOURCE_COMMIT PR4109_SOURCE_BINDING_MODE

command -v node >/dev/null 2>&1 ||
  blocked "node (Node.js) is required to self-test the evidence validator"
command -v npx >/dev/null 2>&1 ||
  blocked "npx (Node.js) is required to self-test the evidence validator"
command -v git >/dev/null 2>&1 ||
  blocked "git is required to self-test the evidence validator's source binding"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/pr4109-validate-evidence.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

PASS=0
FAILED=0
CASE_RC=0
CASE_OUT=""

# Every git invocation pins its identity and disables signing so the cases
# behave identically on a workstation and inside the CI build image.
git_q() {
  git -c user.name=rehearsal -c user.email=rehearsal@invalid \
    -c commit.gpgsign=false -c init.defaultBranch=main "$@"
}

# A throwaway checkout to bind the cases to. Running them against a
# repository whose HEAD this script chose — rather than against this
# worktree, whose HEAD and cleanliness vary — is what lets every case assert
# the same verdict on a workstation mid-edit and on a bound CI dispatch.
make_checkout() {
  local repo="$1"
  mkdir -p "${repo}"
  (
    cd "${repo}"
    git_q init -q
    echo 'rehearsal fixture checkout' >README
    git_q add -A
    git_q commit -qm 'fixture'
  )
}

make_checkout "${WORK}/repo"
FIXTURE_SHA="$(git -C "${WORK}/repo" rev-parse HEAD)"

# The same shape, plus one untracked file: the tree a bound stage must
# refuse to judge records from.
make_checkout "${WORK}/repo-divergent"
DIVERGENT_SHA="$(git -C "${WORK}/repo-divergent" rev-parse HEAD)"
echo 'injected' >"${WORK}/repo-divergent/untracked.go"

OTHER_SHA="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

# The bindings a correct record must carry: the checked-in manifest's exact
# bytes hash and its own termination grace. Reading them here rather than
# hard-coding them keeps the self-test valid across manifest regenerations.
MANIFEST_SHA="$(hash_stdin <"${TEST_DIR}/release-manifest.json")"
MANIFEST_GRACE="$(node -e '
  const fs = require("fs");
  const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  process.stdout.write(String(
    manifest.termination_grace.termination_grace_period_seconds));
' "${TEST_DIR}/release-manifest.json")"

# A schema-complete record bound to the given manifest hash, grace,
# generation timestamp, and source commit. The negative cases change exactly
# one argument each, so a rejection can only come from that change.
write_record() {
  local path="$1" sha="$2" grace="$3" generated_at="$4"
  local source_sha="${5:-${FIXTURE_SHA}}"
  cat >"${path}" <<EOF
{
  "schema_version": 1,
  "gate": "single_release",
  "generated_at": "${generated_at}",
  "source_sha": "${source_sha}",
  "artifacts": {
    "r1_image_digests": {
      "linux/amd64": "ghcr.io/keep-network/keep-client@sha256:1111111111111111111111111111111111111111111111111111111111111111"
    },
    "prior_image_digests": {
      "linux/amd64": "ghcr.io/keep-network/keep-client@sha256:2222222222222222222222222222222222222222222222222222222222222222"
    },
    "version": "v0.0.0-selftest",
    "revision": "aaaaaaa",
    "protocol_epoch": "security_v2_cutover"
  },
  "chain": { "chain_id": "11155111", "cutover_block": 1000000 },
  "release_manifest": {
    "sha256": "${sha}",
    "termination_grace_period_seconds": ${grace}
  },
  "stages": [ { "name": "preflight", "outcome": "pass" } ],
  "assertions": [ { "assertion": "self-test fixture", "holds": true } ]
}
EOF
}

# The attestation the stage demands before it measures any record against
# the reviewed manifest. The derived document defaults to the reviewed
# manifest's own bytes — the Go drift test pins those to the compiled bounds
# — so the fixtures stay correct across manifest regenerations and this
# script needs no Go toolchain. The negative cases override one argument
# each.
write_attestation() {
  local dir="$1/attestation"
  local sha="${2:-${MANIFEST_SHA}}"
  local derived="${3:-${TEST_DIR}/release-manifest.json}"
  local source_sha="${4:-${FIXTURE_SHA}}"
  mkdir -p "${dir}"
  printf '%s\n' "${sha}" >"${dir}/reviewed-manifest.sha256"
  cp "${derived}" "${dir}/derived-manifest.json"
  printf '%s\n' "${source_sha}" >"${dir}/source-commit.txt"
}

# Run stage_validate_evidence against a fixture directory in an isolated
# subshell so a blocked/fail exit inside the stage never kills the test
# run; capture rc and combined output. The stage now verifies its own source
# binding, so each case names the checkout it runs against and the commit it
# is bound to — by default the clean fixture checkout and its own HEAD.
run_validator() {
  local dir="$1"
  local expected="${2:-${FIXTURE_SHA}}"
  local repo="${3:-${WORK}/repo}"
  set +e
  CASE_OUT="$(
    (
      # The sourced stage reads these; shellcheck cannot see across the
      # source boundary, and the assignments stay in this subshell.
      # shellcheck disable=SC2030,SC2034
      EVIDENCE_DIR="${dir}"
      # shellcheck disable=SC2030,SC2034
      REPO_ROOT="${repo}"
      # shellcheck disable=SC2030,SC2034
      PR4109_EXPECTED_SOURCE_COMMIT="${expected}"
      # shellcheck disable=SC2030,SC2034
      PR4109_SOURCE_BINDING_MODE="exact"
      stage_validate_evidence
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

# Assert the captured rc and that the output matches every given pattern.
check() {
  local desc="$1" want_rc="$2"
  shift 2
  if [[ "${CASE_RC}" -ne "${want_rc}" ]]; then
    printf 'FAIL %s: rc %s, want %s\n--- output ---\n%s\n--------------\n' \
      "${desc}" "${CASE_RC}" "${want_rc}" "${CASE_OUT}"
    FAILED=$((FAILED + 1))
    return
  fi
  local pattern
  for pattern in "$@"; do
    if ! printf '%s\n' "${CASE_OUT}" | grep -Eq -- "${pattern}"; then
      printf 'FAIL %s: output missing /%s/\n--- output ---\n%s\n--------------\n' \
        "${desc}" "${pattern}" "${CASE_OUT}"
      FAILED=$((FAILED + 1))
      return
    fi
  done
  printf 'ok   %s\n' "${desc}"
  PASS=$((PASS + 1))
}

# ----------------------------------------------------------------------------

D="${WORK}/bound"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
run_validator "${D}"
check "a record bound to the manifest's hash, grace, and commit passes" 0 \
  "attestation binds" "were produced at ${FIXTURE_SHA}" \
  "hash and termination grace"

D="${WORK}/no-attestation"
mkdir -p "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
run_validator "${D}"
check "a correct record without a manifest attestation is not accepted" 3 \
  "no complete release-manifest attestation" "run the local-proofs stage"

# An attestation missing any one of its parts is a fragment, not a receipt —
# which is also what keeps a staging directory abandoned by an interrupted
# attestation from ever being read as one.
D="${WORK}/partial-attestation"
mkdir -p "${D}"
write_attestation "${D}"
rm "${D}/attestation/source-commit.txt"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
run_validator "${D}"
check "an attestation missing its source stamp is not a receipt" 3 \
  "no complete release-manifest attestation"

D="${WORK}/staging-leftover"
mkdir -p "${D}"
write_attestation "${D}"
mv "${D}/attestation" "${D}/attestation.staging.4242"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
run_validator "${D}"
check "a staging directory left by an interrupted attestation is not one" 3 \
  "no complete release-manifest attestation"

D="${WORK}/stale-attestation"
mkdir -p "${D}"
write_attestation "${D}" \
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
run_validator "${D}"
check "an attestation taken over other manifest bytes is rejected" 3 \
  "attestation was taken over a manifest" "re-run the local-proofs stage"

# The reviewed manifest and the attestation agree on the hash, but the
# attested compiled bounds carry a different grace: the case a hash-only
# check would wave through after both documents were regenerated together.
D="${WORK}/attested-bounds-differ"
mkdir -p "${D}"
node -e '
  const fs = require("fs");
  const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  manifest.termination_grace.termination_grace_period_seconds += 1;
  fs.writeFileSync(process.argv[2], JSON.stringify(manifest, null, 2));
' "${TEST_DIR}/release-manifest.json" "${WORK}/other-bounds.json"
write_attestation "${D}" "${MANIFEST_SHA}" "${WORK}/other-bounds.json"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
run_validator "${D}"
check "attested bounds contradicting the reviewed manifest are rejected" 3 \
  "disagrees with the compiled bounds"

# Reformatting and re-stamping a reviewed manifest must not read as drift:
# only the bounds are compared, canonically ordered.
D="${WORK}/reformatted-attestation"
mkdir -p "${D}"
node -e '
  const fs = require("fs");
  const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  manifest.generated_at = "2000-01-01T00:00:00Z";
  manifest.termination_grace.notes = "attestation-side note";
  const reordered = Object.keys(manifest).sort().reduce((o, k) => {
    o[k] = manifest[k];
    return o;
  }, {});
  fs.writeFileSync(process.argv[2], JSON.stringify(reordered));
' "${TEST_DIR}/release-manifest.json" "${WORK}/reformatted.json"
write_attestation "${D}" "${MANIFEST_SHA}" "${WORK}/reformatted.json"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
run_validator "${D}"
check "an attestation differing only in notes, stamp, and key order passes" 0 \
  "attestation binds"

# The manifest bytes are identical at both commits — every hash and bounds
# comparison in the stage agrees — so only the receipt's own source stamp can
# tell that these bounds were compiled somewhere else.
D="${WORK}/cross-commit-attestation"
mkdir -p "${D}"
write_attestation "${D}" "${MANIFEST_SHA}" "${TEST_DIR}/release-manifest.json" \
  "${OTHER_SHA}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z" "${OTHER_SHA}"
run_validator "${D}"
check "an attestation carried over from another commit is rejected" 3 \
  "attestation was taken at source \[${OTHER_SHA}\]" \
  "this run is bound to \[${FIXTURE_SHA}\]"

# What local-proofs stamps when the tree it proved diverges from any commit:
# bounds compiled from bytes no commit accounts for cannot carry provenance,
# so the receipt is refused even on an unbound run.
D="${WORK}/dirty-attestation"
mkdir -p "${D}"
write_attestation "${D}" "${MANIFEST_SHA}" "${TEST_DIR}/release-manifest.json" \
  "${FIXTURE_SHA}-dirty"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
run_validator "${D}" ""
check "an attestation taken on a divergent tree is rejected" 3 \
  "which is not a clean commit"

# The record copies the right manifest hash and grace but was built from
# other bytes: the binding the hash and grace checks cannot see.
D="${WORK}/record-other-commit"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z" "${OTHER_SHA}"
run_validator "${D}"
check "a record built from another commit than the attestation is rejected" 3 \
  "produced from source commit \[${OTHER_SHA}\]" \
  "attestation it is measured against was taken at \[${FIXTURE_SHA}\]"

# The stage judges records by the manifest, schema, and rules in its own
# tree, so a bound run must refuse to judge anything from a tree that is not
# the dispatched commit — before it reads a single record.
D="${WORK}/divergent-tree"
mkdir -p "${D}"
write_attestation "${D}" "${MANIFEST_SHA}" "${TEST_DIR}/release-manifest.json" \
  "${DIVERGENT_SHA}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z" "${DIVERGENT_SHA}"
run_validator "${D}" "${DIVERGENT_SHA}" "${WORK}/repo-divergent"
check "a bound run refuses to judge records from a divergent tree" 1 \
  "the tree diverges" "untracked files count"

D="${WORK}/wrong-sha"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" \
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
  "${MANIFEST_GRACE}" "2026-07-28T00:00:00Z"
run_validator "${D}"
check "a schema-valid record naming another manifest's hash is rejected" 3 \
  "binds release manifest sha256" "regenerate the record"

D="${WORK}/wrong-grace"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" 1 "2026-07-28T00:00:00Z"
run_validator "${D}"
check "the right hash with a false grace value is rejected" 3 \
  "termination grace of \[1\] seconds" \
  "manifest it binds grants \[${MANIFEST_GRACE}\]"

D="${WORK}/missing-grace"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
node -e '
  const fs = require("fs");
  const path = process.argv[1];
  const record = JSON.parse(fs.readFileSync(path, "utf8"));
  delete record.release_manifest.termination_grace_period_seconds;
  fs.writeFileSync(path, JSON.stringify(record, null, 2));
' "${D}/record.json"
run_validator "${D}"
check "a record missing the grace binding field fails the schema" 3 \
  "does not conform"

D="${WORK}/missing-binding"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
node -e '
  const fs = require("fs");
  const path = process.argv[1];
  const record = JSON.parse(fs.readFileSync(path, "utf8"));
  delete record.release_manifest;
  fs.writeFileSync(path, JSON.stringify(record, null, 2));
' "${D}/record.json"
run_validator "${D}"
check "a record missing the release-manifest binding fails the schema" 3 \
  "does not conform"

D="${WORK}/bad-timestamp"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "not-a-timestamp"
run_validator "${D}"
check "a malformed generation timestamp fails the schema" 3 \
  "does not conform"

D="${WORK}/empty"
mkdir -p "${D}"
run_validator "${D}"
check "an empty record set is rejected, never vacuously accepted" 3 \
  "no evidence records found"

D="${WORK}/one-bad-among-good"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/a-good.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
write_record "${D}/b-bad.json" "${MANIFEST_SHA}" 1 "2026-07-28T00:00:00Z"
run_validator "${D}"
check "one bad record is rejected even after a good one validated" 3 \
  "termination grace of \[1\] seconds"

# The lifecycle a reused evidence directory depends on. local-proofs runs
# invalidate_release_manifest_attestation before it proves anything, so a run
# that fails at any proof leaves no receipt behind: the acceptance stage then
# has nothing to measure against, rather than the receipt of whichever
# earlier run happened to succeed in the same directory.
D="${WORK}/invalidated"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
run_validator "${D}"
check "the inherited-receipt fixture is accepted before invalidation" 0 \
  "attestation binds"
(
  # shellcheck disable=SC2030,SC2031,SC2034
  EVIDENCE_DIR="${D}"
  invalidate_release_manifest_attestation
) >/dev/null
run_validator "${D}"
check "a receipt destroyed at proof-run start cannot be reused" 3 \
  "no complete release-manifest attestation"

# Invalidation must reach the staging directories too, or a fragment of an
# interrupted run could be renamed into place by a later one.
D="${WORK}/invalidated-staging"
mkdir -p "${D}/attestation.staging.777"
: >"${D}/attestation.staging.777/derived-manifest.json"
(
  # shellcheck disable=SC2031,SC2034
  EVIDENCE_DIR="${D}"
  invalidate_release_manifest_attestation
) >/dev/null
if [[ -e "${D}/attestation.staging.777" ]]; then
  printf 'FAIL invalidation leaves an interrupted staging directory behind\n'
  FAILED=$((FAILED + 1))
else
  printf 'ok   invalidation removes interrupted staging directories\n'
  PASS=$((PASS + 1))
fi

# The same lifecycle driven through stage_local_proofs itself rather than
# through the invalidation function alone. Calling that function directly
# proves only that it works when called; what a reused evidence directory
# actually depends on is the stage calling it before the first proof, so that
# a proof failing afterwards cannot leave its predecessor's receipt standing
# for the acceptance stage to find. Moving or dropping that call anywhere in
# the stage has to fail here.
D="${WORK}/orchestrated-invalidation"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
run_validator "${D}"
check "the inherited receipt is accepted before any proof run starts" 0 \
  "attestation binds"

# ----------------------------------------------------------------------------
#
# The other side of the same contract: the container rehearsals build the
# records this validator judges, so the builder is proved against the judge
# rather than against a restatement of the schema. Every case below drives the
# real ledger and the real emitter; only the two things that need a running
# fleet are replaced — the HTTP read of a node's client-info port and the
# registry lookup behind an immutable digest.
#
# The substitute is the transport and not the parser above it, so the real
# reader still has to find the identity where a node actually publishes it.
# The document below is the shape keep-common composes: one key per registered
# diagnostics source, each source's own JSON nested under it, with the client
# identity carrying the field names the Client struct's tags produce.
probe_diagnostics() {
  cat <<EOF
{
  "client_info": {
    "chain_address": "0x0000000000000000000000000000000000000001",
    "network_id": "16Uiu2HAm000000000000000000000000000000000000000",
    "version": "v2.0.0-rehearsal",
    "revision": "${FIXTURE_SHA}"
  },
  "cutover_legacy_peers": { "revision": 0, "peers": [] },
  "protocol_participation": {
    "protocol_epoch": "security_v2_cutover",
    "cutover_block": 9000000,
    "gate_state": "open_security_v2",
    "current_block": 9000001,
    "clock_available": true,
    "allowed": true,
    "quiescing": false,
    "active_ceremonies": 0
  }
}
EOF
}

image_digests_by_architecture() {
  printf '{"amd64":"%s","arm64":"%s"}' "$1" "$1"
}

# Drive a rehearsal to its conclusion in an isolated subshell: the ledger, the
# emitter, and the acceptance verdict conclude_rehearsal derives from the
# steps. The emitter validates its own output through the real
# stage_validate_evidence, so a record this returns 0 for is a record the
# release gate would accept.
run_rehearsal() {
  local dir="$1" gate="$2"
  shift 2
  set +e
  CASE_OUT="$(
    (
      # shellcheck disable=SC2030,SC2031,SC2034
      EVIDENCE_DIR="${dir}"
      # shellcheck disable=SC2030,SC2031,SC2034
      REPO_ROOT="${WORK}/repo"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_EXPECTED_SOURCE_COMMIT="${FIXTURE_SHA}"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_SOURCE_BINDING_MODE="exact"
      # shellcheck disable=SC2030,SC2031,SC2034
      R1_IMAGE_DIGEST="keep/keep-client@sha256:$(printf 'a%.0s' {1..64})"
      # shellcheck disable=SC2030,SC2031,SC2034
      PRIOR_IMAGE_DIGEST="keep/keep-client@sha256:$(printf 'b%.0s' {1..64})"
      # shellcheck disable=SC2030,SC2031,SC2034
      CHAIN_ID="11155111"
      # shellcheck disable=SC2030,SC2031,SC2034
      CUTOVER_BLOCK="9000000"
      # shellcheck disable=SC2030,SC2031,SC2034
      REHEARSAL_GATE="${gate}"
      "$@"
      conclude_rehearsal
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

# A rehearsal whose every mandatory step executed.
complete_run() {
  begin_step "cross C without restart"
  # The observation slots the real probes fill; record_step drains them.
  # shellcheck disable=SC2034
  STEP_CANONICAL_BLOCKS="8999999,9000001"
  # shellcheck disable=SC2034
  STEP_PERMIT_MODES='"security_v2"'
  # shellcheck disable=SC2034
  STEP_GAUGES='"r1-node-1.participation_gate_state":2'
  record_step "cross C without restart" pass "both gates crossed in process"
  record_assertion "the gate crosses C in-process" true \
    "cross C without restart"
}

# The same rehearsal with one step this release cannot execute.
blocked_run() {
  complete_run
  begin_step "quiescence with an in-flight legacy permit"
  block_step "quiescence with an in-flight legacy permit" \
    "the pinned tss-lib is hardened-only"
}

E="${WORK}/emitted"
mkdir -p "${E}"
write_attestation "${E}"
run_rehearsal "${E}" single_release complete_run
check "a rehearsal record the emitter builds is accepted by the acceptance stage" \
  0 "rehearsal evidence record written" "hash and termination grace" \
  "every mandatory step executed"

# The release identity in the record has to be the one the node published,
# read from where it publishes it. Asserting the values — not merely that the
# schema's required fields are populated — is what makes a rename or a wrong
# field name on the reader's side fail here instead of silently producing a
# record that binds the rehearsal to an empty version.
if grep -q '"version": "v2.0.0-rehearsal"' "${E}"/single_release-*.json &&
  grep -q "\"revision\": \"${FIXTURE_SHA}\"" "${E}"/single_release-*.json; then
  printf 'ok   the record carries the identity the node published\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the record does not carry the node-published identity\n'
  FAILED=$((FAILED + 1))
fi

# The same reader against the gate's own state object, which is what every
# step of both rehearsals decides its outcome from.
if [[ "$(participation_field r1-node-1 gate_state)" == "open_security_v2" &&
  "$(participation_field r1-node-1 current_block)" == "9000001" ]]; then
  printf 'ok   the gate-state reader finds the fields a node publishes\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the gate-state reader does not find the published fields\n'
  FAILED=$((FAILED + 1))
fi

# The property the whole per-step ledger exists for: a gate that cannot finish
# still writes a reviewable record, and still refuses to report success.
E="${WORK}/emitted-blocked"
mkdir -p "${E}"
write_attestation "${E}"
run_rehearsal "${E}" single_release blocked_run
check "a rehearsal with a blocked step still emits a record and still blocks" \
  3 "rehearsal evidence record written" \
  "1 mandatory step\(s\) of the single_release gate could not execute" \
  "quiescence with an in-flight legacy permit"

if ls "${E}"/single_release-*.json >/dev/null 2>&1; then
  printf 'ok   the blocked rehearsal left its record on disk for review\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the blocked rehearsal wrote no record\n'
  FAILED=$((FAILED + 1))
fi

# A blocked step is recorded as such rather than being smoothed into a pass:
# the record is the only place a reviewer can see which steps did not run.
if grep -q '"outcome": "blocked"' "${E}"/single_release-*.json; then
  printf 'ok   the record types the step that could not run as blocked\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the record does not type the unexecuted step as blocked\n'
  FAILED=$((FAILED + 1))
fi

# A rehearsal run from bytes no commit accounts for must not produce a record
# at all: the emitter is where that is caught, before anything is written.
E="${WORK}/emitted-dirty"
mkdir -p "${E}"
write_attestation "${E}"
echo 'divergence' >"${WORK}/repo/untracked-during-rehearsal"
run_rehearsal "${E}" single_release complete_run
check "a rehearsal on a divergent tree produces no record" 3 \
  "not a clean commit"
rm -f "${WORK}/repo/untracked-during-rehearsal"

# ----------------------------------------------------------------------------

# The seam the stage runs its proofs through, replaced by a stub that fails
# the way any proof failure does and reports what it found on the way in.
# Defined last in this file: everything above must run against the real one.
run_local_proof_suite() {
  if [[ -e "$(attestation_dir)" ]]; then
    printf 'fixture: the inherited receipt was still present at proof time\n'
  else
    printf 'fixture: the inherited receipt was already gone at proof time\n'
  fi
  return 1
}

set +e
CASE_OUT="$(
  (
    # The stage aborts on a failing proof through the shell options
    # rehearse.sh runs under, so the fixture has to restore them: the
    # capture below turns errexit off, and the whole point of this case is
    # what a proof failure does to the stage around it.
    set -eo pipefail
    # shellcheck disable=SC2030,SC2031,SC2034
    EVIDENCE_DIR="${D}"
    # shellcheck disable=SC2030,SC2031,SC2034
    REPO_ROOT="${WORK}/repo"
    stage_local_proofs
  ) 2>&1
)"
CASE_RC=$?
set -e
check "a proof run destroys the inherited receipt before it proves anything" \
  1 "the inherited receipt was already gone at proof time"

if grep -q 'already gone at proof time' "${D}/local-proofs.log"; then
  printf 'ok   the archived proof log records the receipt lifecycle\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the archived proof log does not record the receipt lifecycle\n'
  FAILED=$((FAILED + 1))
fi

if [[ -e "${D}/attestation" ]]; then
  printf 'FAIL a failed proof run left a release-manifest attestation behind\n'
  FAILED=$((FAILED + 1))
else
  printf 'ok   a failed proof run leaves no release-manifest attestation\n'
  PASS=$((PASS + 1))
fi

run_validator "${D}"
check "records are no longer acceptable after a failed proof run" 3 \
  "no complete release-manifest attestation"

# ----------------------------------------------------------------------------

printf '%d passed, %d failed\n' "${PASS}" "${FAILED}"
if [[ "${FAILED}" -ne 0 ]]; then
  exit 1
fi
