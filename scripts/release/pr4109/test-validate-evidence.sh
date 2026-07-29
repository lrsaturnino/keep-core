#!/usr/bin/env bash
#
# Self-test for rehearse.sh's evidence-record validation.
#
# Builds throwaway evidence records around the checked-in release manifest
# and proves stage_validate_evidence accepts exactly a record whose schema
# shape, manifest hash, recorded termination grace, complete gate roster,
# assertion-to-stage bindings, and reviewed instrument identities are all
# correct — and rejects a wrong hash, a wrong grace, missing binding fields,
# an incomplete or duplicated roster, a malformed timestamp, an empty record
# set, and a bad record hiding behind a good one. It also drives the manifest
# attestation the stage requires before it measures anything: absent,
# incomplete, taken over other manifest bytes, recording bounds the reviewed
# manifest contradicts, taken at another commit than the run is bound to,
# taken at no clean commit at all, or vouching for a record built from other
# bytes — plus the tree binding the stage verifies before it judges anything.
#
# Admissibility is not acceptance, and the cases keep the two apart. A
# separate set of records passes every binding check above and still denies
# the gate in its own outcomes — a failed step, a refused acceptance
# assertion with every step passing, a step that never executed, a failure
# beside an unexecuted step, and a failing record sitting beside a passing
# one — because a validator that only checked the shape of those records
# would hand a release a refuted gate as a satisfied one. The rehearsal
# ledger is driven to the same verdicts through the real emitter.
#
# One case is about the single-release stage's sequencing rather than its
# records: the legacy quiescence control drains a permit seeded before C, and
# three earlier controls in the same stage cancel every permit on the node they
# act on. That case walks the stage's own control order and requires the seeded
# permit to reach its drain, because a collision there produces a blocked step
# that reads like a broken work driver rather than the misallocation it is.
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
REVIEWED_WORK_DRIVER_DIGEST="$(reviewed_input_digest work-driver)"
REVIEWED_ROLLBACK_GENERATOR_DIGEST="$(
  reviewed_input_digest rollback-evidence-generator
)"
REVIEWED_TSSLIB_REVIEW_DIGEST="$(reviewed_input_digest tsslib-review)"

# A schema-complete record bound to the given manifest hash, grace,
# generation timestamp, and source commit. The negative cases change exactly
# one argument each, so a rejection can only come from that change.
#
# The last two arguments are the record's own stages and assertions. They
# default to the complete single-release gate contract. Acceptance negatives
# may replace them with a deliberately incomplete record, or mutate one
# canonical entry, to prove an arbitrary passing subset cannot stand in for
# the gate.
SINGLE_RELEASE_STAGES='
  { "name": "mixed prior/R1 pre-cutover compatibility controls", "outcome": "pass" },
  { "name": "representative pre-cutover work including the longest wallet action", "outcome": "pass" },
  { "name": "cross C without restart", "outcome": "pass" },
  { "name": "pre-cutover legacy work survives C and completes", "outcome": "pass" },
  { "name": "restart across C derives mode from the chain, not from process state", "outcome": "pass" },
  { "name": "post-cutover straggler fails closed and enters the roster", "outcome": "pass" },
  { "name": "90/10 DKG consequence is visible with the straggler eligible", "outcome": "pass" },
  { "name": "quarantine the straggler", "outcome": "pass" },
  { "name": "homogeneous security-v2 controls with no legacy sightings", "outcome": "pass" },
  { "name": "clock failure quarantines work rather than guessing a mode", "outcome": "pass" },
  { "name": "quiescence with an in-flight security-v2 permit", "outcome": "pass" },
  { "name": "quiescence with an in-flight legacy permit", "outcome": "pass" },
  { "name": "the cutover fleet leaves no release candidate running", "outcome": "pass" }'
SINGLE_RELEASE_ASSERTIONS='
  { "assertion": "the gate crosses C in-process, without a restart or a global toggle", "holds": true, "evidence_stage": "cross C without restart" },
  { "assertion": "a restarted node derives its mode from the canonical anchor and the current chain", "holds": true, "evidence_stage": "restart across C derives mode from the chain, not from process state" },
  { "assertion": "old post-C behavior fails closed and becomes operator-identified blocking evidence", "holds": true, "evidence_stage": "post-cutover straggler fails closed and enters the roster" },
  { "assertion": "post-C ceremonies run security-v2 with no legacy sightings", "holds": true, "evidence_stage": "homogeneous security-v2 controls with no legacy sightings" },
  { "assertion": "a failed chain-clock read refuses new work instead of assuming a side of C", "holds": true, "evidence_stage": "clock failure quarantines work rather than guessing a mode" },
  { "assertion": "graceful quiescence starts no new work and lets held permits finish", "holds": true, "evidence_stage": "quiescence with an in-flight security-v2 permit" },
  { "assertion": "a finished cutover rehearsal leaves no candidate able to act", "holds": true, "evidence_stage": "the cutover fleet leaves no release candidate running" }'
ROLLBACK_STAGES='
  { "name": "quiesce every R1 node with work represented", "outcome": "pass" },
  { "name": "no prior binary starts during quiescence", "outcome": "pass" },
  { "name": "a forced deadline quarantines rather than completing", "outcome": "pass" },
  { "name": "every release candidate is stopped or network-quarantined", "outcome": "pass" },
  { "name": "offline state audit produces a rollback-safe manifest", "outcome": "pass" },
  { "name": "every in-flight permit reconciles to completion or quarantine", "outcome": "pass" },
  { "name": "stage the prior digest behind the all-candidate-down barrier", "outcome": "pass" },
  { "name": "homogeneous legacy ceremonies work with no R1 traffic left", "outcome": "pass" },
  { "name": "a forbidden partial rollback is blocked", "outcome": "pass" },
  { "name": "the prior binary loads and signs with a wallet created after C", "outcome": "pass" }'
ROLLBACK_ASSERTIONS='
  { "assertion": "every R1 node drains to a stop within the reviewed termination grace", "holds": true, "evidence_stage": "quiesce every R1 node with work represented" },
  { "assertion": "no prior binary participates before every R1 node is down", "holds": true, "evidence_stage": "no prior binary starts during quiescence" },
  { "assertion": "all R1 is down or quarantined before any prior binary participates", "holds": true, "evidence_stage": "every release candidate is stopped or network-quarantined" },
  { "assertion": "the offline state audit passes before rollback", "holds": true, "evidence_stage": "offline state audit produces a rollback-safe manifest" },
  { "assertion": "every permit held at the stop completes or is audited into quarantine", "holds": true, "evidence_stage": "every in-flight permit reconciles to completion or quarantine" },
  { "assertion": "a partial rollback cannot be performed", "holds": true, "evidence_stage": "a forbidden partial rollback is blocked" }'
STAGE_PASSED="${SINGLE_RELEASE_STAGES}"
STAGE_FAILED='{ "name": "cross C without restart", "outcome": "fail" }'
STAGE_BLOCKED='{ "name": "quiescence with an in-flight legacy permit", "outcome": "blocked" }'
ASSERTION_HOLDS="${SINGLE_RELEASE_ASSERTIONS}"
ASSERTION_REFUSED='{
  "assertion": "the gate crosses C in-process, without a restart or a global toggle",
  "holds": false,
  "evidence_stage": "cross C without restart"
}'

write_record() {
  local path="$1" sha="$2" grace="$3" generated_at="$4"
  local source_sha="${5:-${FIXTURE_SHA}}"
  local stages="${6:-${STAGE_PASSED}}"
  local assertions="${7:-${ASSERTION_HOLDS}}"
  local gate="${8:-single_release}"
  cat >"${path}" <<EOF
{
  "schema_version": 1,
  "gate": "${gate}",
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
  "chain_inputs": {
    "work_driver_sha256": "${REVIEWED_WORK_DRIVER_DIGEST}",
    "tsslib_review_sha256": "${REVIEWED_TSSLIB_REVIEW_DIGEST}"
  },
  "stages": [ ${stages} ],
  "assertions": [ ${assertions} ]
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

# The instruments the record was produced with, held to the same standard as
# the bounds it is measured against. A record carrying chain transactions was
# produced by a work driver, and a record that cannot name which one attributes
# its terminal readings to a program nobody can identify.
STAGE_DROVE='{ "name": "post-C ceremony", "outcome": "pass",
  "transaction_hashes": [
    "0x9999999999999999999999999999999999999999999999999999999999999999" ] }'

D="${WORK}/undriven-record"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z" "${FIXTURE_SHA}" "${STAGE_DROVE}"
node -e '
  const fs = require("fs");
  const path = process.argv[1];
  const record = JSON.parse(fs.readFileSync(path, "utf8"));
  delete record.chain_inputs;
  fs.writeFileSync(path, JSON.stringify(record, null, 2));
' "${D}/record.json"
run_validator "${D}"
check "chain transactions with no named driver name no instrument" 3 \
  "carries chain transactions but names no work driver digest"

D="${WORK}/unreviewed-driver"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
node -e '
  const fs = require("fs");
  const record = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  record.chain_inputs = { work_driver_sha256: "a".repeat(64) };
  fs.writeFileSync(process.argv[1], JSON.stringify(record, null, 2));
' "${D}/record.json"
run_validator "${D}"
check "a record naming a driver the control does not pin is rejected" 3 \
  "work driver hashing to \[a{64}\], which .*chain-inputs.sha256 does not pin"

D="${WORK}/unreviewed-generator"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
node -e '
  const fs = require("fs");
  const record = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  record.chain_inputs = {
    rollback_evidence_generator_sha256: "b".repeat(64),
  };
  fs.writeFileSync(process.argv[1], JSON.stringify(record, null, 2));
' "${D}/record.json"
run_validator "${D}"
check "a record naming a generator the control does not pin is rejected" 3 \
  "evidence generator hashing to \[b{64}\]"

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

# ----------------------------------------------------------------------------
#
# Acceptance, which is a different question from admissibility. Every record
# below is schema-valid, produced at the attested commit, and bound to the
# reviewed manifest's exact hash and grace — so every check above it passes.
# What each one says, in the fields the schema exists to carry, is that the
# gate it evidences did not hold. A release that read only the checks above
# would take all of them for satisfied gates.

# The false-pass that prompted the gate-contract check: one arbitrary passing
# step and one true assertion used to satisfy both schema and acceptance.
D="${WORK}/accept-one-stage-subset"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z" "${FIXTURE_SHA}" \
  '{ "name": "cross C without restart", "outcome": "pass" }' \
  '{
    "assertion": "the gate crosses C in-process, without a restart or a global toggle",
    "holds": true,
    "evidence_stage": "cross C without restart"
  }'
run_validator "${D}"
check "one passing stage cannot stand in for the single-release gate" 3 \
  "required step.*mixed prior/R1 pre-cutover compatibility controls.*absent" \
  "required assertion.*restarted node derives its mode.*absent"

# A complete-looking record still names no instrument if it omits the driver
# digest. No transaction hash is needed to trigger this check: every accepted
# single-release gate uses the driver for its positive and negative controls.
D="${WORK}/accept-missing-required-driver"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
node -e '
  const fs = require("fs");
  const path = process.argv[1];
  const record = JSON.parse(fs.readFileSync(path, "utf8"));
  delete record.chain_inputs;
  fs.writeFileSync(path, JSON.stringify(record, null, 2));
' "${D}/record.json"
run_validator "${D}"
check "a complete single-release roster still requires its reviewed driver" 3 \
  "required reviewed release input.*work_driver_sha256.*absent"

# The decoupling this contract exists to express: whether the dependency has
# an archived independent review changes nothing about what the fleet can run,
# so a rehearsal without it executes and records every mandatory step. It is
# refused here, once, at acceptance — the record is complete and still not
# release-authoritative.
D="${WORK}/accept-missing-dependency-review"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
node -e '
  const fs = require("fs");
  const path = process.argv[1];
  const record = JSON.parse(fs.readFileSync(path, "utf8"));
  delete record.chain_inputs.tsslib_review_sha256;
  fs.writeFileSync(path, JSON.stringify(record, null, 2));
' "${D}/record.json"
run_validator "${D}"
check "every mandatory step passing does not accept an unreviewed dependency" \
  3 "required reviewed release input.*tsslib_review_sha256.*absent"

D="${WORK}/accept-unpinned-dependency-review"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
node -e '
  const fs = require("fs");
  const path = process.argv[1];
  const record = JSON.parse(fs.readFileSync(path, "utf8"));
  record.chain_inputs.tsslib_review_sha256 = "c".repeat(64);
  fs.writeFileSync(path, JSON.stringify(record, null, 2));
' "${D}/record.json"
run_validator "${D}"
check "a record naming a review the control does not pin is rejected" 3 \
  "review record hashing to \[c{64}\]"

# Repetition and invention cannot manufacture a complete gate. These records
# keep the canonical item count deliberately plausible so the decision cannot
# be reduced to a length check.
D="${WORK}/accept-duplicate-stage"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
node -e '
  const fs = require("fs");
  const path = process.argv[1];
  const record = JSON.parse(fs.readFileSync(path, "utf8"));
  record.stages[12] = { ...record.stages[2] };
  fs.writeFileSync(path, JSON.stringify(record, null, 2));
' "${D}/record.json"
run_validator "${D}"
check "a duplicated passing stage cannot replace another mandatory step" 3 \
  "step.*cross C without restart.*appears 2 times" \
  "required step.*cutover fleet leaves no release candidate running.*absent"

D="${WORK}/accept-unknown-assertion"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
node -e '
  const fs = require("fs");
  const path = process.argv[1];
  const record = JSON.parse(fs.readFileSync(path, "utf8"));
  record.assertions[6] = {
    assertion: "an invented release property",
    holds: true,
    evidence_stage: "the cutover fleet leaves no release candidate running",
  };
  fs.writeFileSync(path, JSON.stringify(record, null, 2));
' "${D}/record.json"
run_validator "${D}"
check "an unknown true assertion cannot replace a required one" 3 \
  "unknown assertion.*invented release property" \
  "required assertion.*finished cutover rehearsal.*absent"

# A true assertion must name its own designated passing step. Merely pointing
# at any other passing step is not a chain of evidence for the property.
D="${WORK}/accept-wrong-assertion-stage"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
node -e '
  const fs = require("fs");
  const path = process.argv[1];
  const record = JSON.parse(fs.readFileSync(path, "utf8"));
  record.assertions[0].evidence_stage =
    "homogeneous security-v2 controls with no legacy sightings";
  fs.writeFileSync(path, JSON.stringify(record, null, 2));
' "${D}/record.json"
run_validator "${D}"
check "an assertion cannot borrow an unrelated passing stage" 3 \
  "assertion.*gate crosses C.*cites.*homogeneous security-v2.*instead of.*cross C"

# Rollback consumes both external programs: the work driver identifies the
# permits being drained, and the evidence generator binds the offline audit
# to the state that drain left. A complete rollback roster needs both.
D="${WORK}/accept-rollback-missing-generator"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z" "${FIXTURE_SHA}" "${ROLLBACK_STAGES}" \
  "${ROLLBACK_ASSERTIONS}" rollback
run_validator "${D}"
check "rollback requires the reviewed evidence generator as well as the driver" \
  3 "required reviewed release input.*rollback_evidence_generator_sha256"

D="${WORK}/accept-complete-rollback"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z" "${FIXTURE_SHA}" "${ROLLBACK_STAGES}" \
  "${ROLLBACK_ASSERTIONS}" rollback
node -e '
  const fs = require("fs");
  const path = process.argv[1];
  const record = JSON.parse(fs.readFileSync(path, "utf8"));
  record.chain_inputs.rollback_evidence_generator_sha256 = process.argv[2];
  fs.writeFileSync(path, JSON.stringify(record, null, 2));
' "${D}/record.json" "${REVIEWED_ROLLBACK_GENERATOR_DIGEST}"
run_validator "${D}"
check "the complete rollback contract with both reviewed instruments passes" 0 \
  "every required step passed exactly once" \
  "every required reviewed release input is present"

D="${WORK}/accept-failed-step"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z" "${FIXTURE_SHA}" "${STAGE_FAILED}"
run_validator "${D}"
check "a correctly bound record whose mandatory step failed is not accepted" 1 \
  "the evidence refutes the gate it records" "cross C without restart"

D="${WORK}/accept-refused-assertion"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z" "${FIXTURE_SHA}" "${STAGE_PASSED}" \
  "${ASSERTION_REFUSED}"
run_validator "${D}"
check "every step passing does not accept a refused acceptance assertion" 1 \
  "the evidence refutes the gate it records" "the gate crosses C in-process"

D="${WORK}/accept-blocked-step"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z" "${FIXTURE_SHA}" \
  "${STAGE_PASSED}, ${STAGE_BLOCKED}"
run_validator "${D}"
check "a record with a step that never executed is not an accepted gate" 3 \
  "never executed" "quiescence with an in-flight legacy permit"

# A failure outranks a step that never ran: the rehearsal reached that
# property and watched it break, which is a refutation and not a gap.
D="${WORK}/accept-failed-and-blocked"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z" "${FIXTURE_SHA}" \
  "${STAGE_BLOCKED}, ${STAGE_FAILED}"
run_validator "${D}"
check "a failed step outranks a blocked one in the acceptance verdict" 1 \
  "the evidence refutes the gate it records"

# The gate a release actually reads is the whole directory, so a passing
# record must never cover for a failing one beside it.
D="${WORK}/accept-one-failed-among-good"
mkdir -p "${D}"
write_attestation "${D}"
write_record "${D}/a-good.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
write_record "${D}/b-failed.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z" "${FIXTURE_SHA}" "${STAGE_FAILED}"
run_validator "${D}"
check "a passing record does not cover for a failing one beside it" 1 \
  "the evidence refutes the gate it records" "b-failed.json"

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
diagnostics_document() {
  # Unset-only defaults: a case passing an explicit empty value is describing
  # a node that publishes nothing there, and a :- default would quietly hand
  # it the correct value instead.
  local revision="${1-${FIXTURE_SHA}}"
  local epoch="${2:-security_v2_cutover}"
  local cutover="${3:-9000000}"
  local version="${4:-v2.0.0-rehearsal}"
  local chain="${5-11155111}"
  cat <<EOF
{
  "client_info": {
    "chain_address": "0x0000000000000000000000000000000000000001",
    "network_id": "16Uiu2HAm000000000000000000000000000000000000000",
    "version": "${version}",
    "revision": "${revision}"
  },
  "cutover_legacy_peers": { "revision": 0, "peers": [] },
  "protocol_participation": {
    "protocol_epoch": "${epoch}",
    "ethereum_chain_id": "${chain}",
    "cutover_block": ${cutover},
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

probe_diagnostics() { diagnostics_document; }

image_digests_by_architecture() {
  printf '{"amd64":"%s","arm64":"%s"}' "$1" "$1"
}

# The exposition a node serves, in the shape keep-common's gauge writes it:
# a TYPE line, then the prefixed name, the value, and the trailing timestamp.
# Only the metrics under the application prefix are here, because the point of
# the cases below is that the probe reads the exposed names and not the
# internal ones the Go constants carry.
probe_metrics() {
  local metric
  for metric in "${PARTICIPATION_METRICS[@]}"; do
    printf '# TYPE %s_%s gauge\n' "${METRIC_APPLICATION_PREFIX}" "${metric}"
    printf '%s_%s 7 1769040000000\n' "${METRIC_APPLICATION_PREFIX}" "${metric}"
  done
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
      # The real preflight records the reviewed inputs it was handed before
      # the fleet starts. These emitter cases bypass preflight and install the
      # same proven identities directly.
      # shellcheck disable=SC2030,SC2031,SC2034
      WORK_DRIVER_DIGEST="${REVIEWED_WORK_DRIVER_DIGEST}"
      # shellcheck disable=SC2030,SC2031,SC2034
      TSSLIB_REVIEW_DIGEST="${REVIEWED_TSSLIB_REVIEW_DIGEST}"
      if [[ "${gate}" == "rollback" ]]; then
        # shellcheck disable=SC2030,SC2031,SC2034
        ROLLBACK_GENERATOR_DIGEST="${REVIEWED_ROLLBACK_GENERATOR_DIGEST}"
      fi
      # The real capture, against the fixture diagnostics: both gates read the
      # release identity off the running fleet before they touch it, and the
      # record is built from what was captured there.
      capture_r1_release_identity
      "$@"
      conclude_rehearsal
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

# A rehearsal whose every mandatory step executed.
complete_run() {
  local stages=(
    "mixed prior/R1 pre-cutover compatibility controls"
    "representative pre-cutover work including the longest wallet action"
    "cross C without restart"
    "pre-cutover legacy work survives C and completes"
    "restart across C derives mode from the chain, not from process state"
    "post-cutover straggler fails closed and enters the roster"
    "90/10 DKG consequence is visible with the straggler eligible"
    "quarantine the straggler"
    "homogeneous security-v2 controls with no legacy sightings"
    "clock failure quarantines work rather than guessing a mode"
    "quiescence with an in-flight security-v2 permit"
    "quiescence with an in-flight legacy permit"
    "the cutover fleet leaves no release candidate running"
  )
  local stage
  for stage in "${stages[@]}"; do
    begin_step "${stage}"
    if [[ "${stage}" == "cross C without restart" ]]; then
      # The observation slots the real probes fill; record_step drains them.
      # shellcheck disable=SC2034
      STEP_CANONICAL_BLOCKS="8999999,9000001"
      # shellcheck disable=SC2034
      STEP_PERMIT_MODES='"security_v2"'
      # shellcheck disable=SC2034
      STEP_GAUGES='"r1-node-1.participation_gate_state":2'
    fi
    record_step "${stage}" pass "self-test observed the mandatory property"
  done

  record_assertion \
    "the gate crosses C in-process, without a restart or a global toggle" \
    true "cross C without restart"
  record_assertion \
    "a restarted node derives its mode from the canonical anchor and the current chain" \
    true \
    "restart across C derives mode from the chain, not from process state"
  record_assertion \
    "old post-C behavior fails closed and becomes operator-identified blocking evidence" \
    true "post-cutover straggler fails closed and enters the roster"
  record_assertion \
    "post-C ceremonies run security-v2 with no legacy sightings" true \
    "homogeneous security-v2 controls with no legacy sightings"
  record_assertion \
    "a failed chain-clock read refuses new work instead of assuming a side of C" \
    true "clock failure quarantines work rather than guessing a mode"
  record_assertion \
    "graceful quiescence starts no new work and lets held permits finish" \
    true "quiescence with an in-flight security-v2 permit"
  record_assertion \
    "a finished cutover rehearsal leaves no candidate able to act" true \
    "the cutover fleet leaves no release candidate running"
}

# The old false-pass in the emitter itself: a hand-built run containing only
# the crossing used to reach conclude_verdict's success line.
one_stage_run() {
  begin_step "cross C without restart"
  record_step "cross C without restart" pass "only one property was observed"
  record_assertion \
    "the gate crosses C in-process, without a restart or a global toggle" \
    true "cross C without restart"
}

# The same rehearsal with one step this release cannot execute.
blocked_run() {
  complete_run
  begin_step "quiescence with an in-flight legacy permit"
  block_step "quiescence with an in-flight legacy permit" \
    "the pinned tss-lib is hardened-only"
}

# A rehearsal that reached every mandatory property and watched one break.
# Nothing here is missing: the steps all ran, the record is complete, and the
# only thing separating it from the accepted run above is what was observed.
failed_run() {
  complete_run
  begin_step "clock failure quarantines work rather than guessing a mode"
  record_step "clock failure quarantines work rather than guessing a mode" \
    fail "the gate reported open_security_v2 with its chain endpoint severed"
  record_assertion \
    "a failed chain-clock read refuses new work instead of assuming a side of C" \
    false "clock failure quarantines work rather than guessing a mode"
}

# Every step passed, and an acceptance assertion still does not hold. The
# assertions are only ever written true where the property was watched, so
# this is the gate's own contract being refused with no step to point at.
refused_assertion_run() {
  complete_run
  record_assertion "post-C ceremonies run security-v2 with no legacy sightings" \
    false "cross C without restart"
}

# One step failed and another never ran. A verdict that reported this as
# merely unrehearsed would lose the refutation entirely.
failed_and_blocked_run() {
  failed_run
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

E="${WORK}/emitted-one-stage"
mkdir -p "${E}"
write_attestation "${E}"
run_rehearsal "${E}" single_release one_stage_run
check "the emitter cannot report success for a one-stage rehearsal" 3 \
  "rehearsal evidence record written" \
  "required step.*mixed prior/R1 pre-cutover compatibility controls.*absent"

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

# The metric names the probe asks for must be the exposed ones. The client
# registers these through the "performance" application and that registration
# prefixes what it exposes, so a probe asking for the internal name reads
# nothing — silently, and in every step at once.
if [[ "$(metric_value r1-node-1 participation_gate_state)" == "7" ]]; then
  printf 'ok   the metric reader asks for the exposed, prefixed name\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the metric reader does not ask for the exposed name\n'
  FAILED=$((FAILED + 1))
fi

# The prefix the probe uses has to be the one the client actually registers
# under, so it is compared against the tree rather than trusted. This is the
# single restatement the probe cannot avoid — it reads a running container,
# not the source — which is exactly why it is pinned here.
if grep -q "ObserveApplicationSource(\"${METRIC_APPLICATION_PREFIX}\"" \
  "${TEST_DIR}/../../../pkg/clientinfo/performance.go"; then
  printf 'ok   the probe prefix is the application the client registers under\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the probe prefix is not the client'"'"'s registration application\n'
  FAILED=$((FAILED + 1))
fi

# Every internal name the probe snapshots must still be a metric the client
# defines, or the step recorded a gauge nobody publishes.
MISSING_METRICS=""
for METRIC in "${PARTICIPATION_METRICS[@]}" "${ANNOUNCER_CUTOVER_METRICS[@]}"; do
  grep -q "= \"${METRIC}\"" \
    "${TEST_DIR}/../../../pkg/clientinfo/performance.go" ||
    MISSING_METRICS="${MISSING_METRICS} ${METRIC}"
done
if [[ -z "${MISSING_METRICS}" ]]; then
  printf 'ok   every probed gate metric is one the client defines\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL probed metrics the client does not define:%s\n' \
    "${MISSING_METRICS}"
  FAILED=$((FAILED + 1))
fi

# Reading nothing is a broken instrument, not a fleet reporting zeros.
set +e
CASE_OUT="$(
  (
    # Serves only internal, unprefixed names — the exposition of a node the
    # probe is asking the wrong questions of. Invoked through the reader
    # under test, which shellcheck cannot see across.
    # shellcheck disable=SC2329
    probe_metrics() { printf 'participation_gate_state 7 1769040000000\n'; }
    observe_gate_gauges r1-node-1
  ) 2>&1
)"
CASE_RC=$?
set -e
check "a probe that reads no gate metric at all blocks instead of recording none" \
  3 "reading the wrong names"

# ----------------------------------------------------------------------------
# The node-authored account of permits a gate closed
#
# The controls that follow work across the cutover used to read the ending of
# each permit off the same driver that originated it. These cases are about the
# reading that replaces it: what a gate itself says became of the permits it
# closed, and the joins that hold a named permit to exactly one such record.
# ----------------------------------------------------------------------------

# One gate state document, with the closed-permit account substituted in.
gate_state_with_outcomes() {
  printf '{"protocol_participation":{"active_permits":[],%s}}' "$1"
}

# One closed-permit record as the gate serves it. The evidence defaults to the
# class a relay signing's result actually lives in, so a case that is about
# something else can vary one field and leave the rest a record the gate would
# really have written.
closed_permit() {
  local outcome="$1" work="$2" permit="$3" bound="${4:-true}"
  local evidence="${5-\"kind\":\"protocol_result\",\"reference\":\"0xentry\"}"
  local ceremony="${6-beacon_relay_signing}"
  local anchor="${7-10}"
  printf '{"recorded_at":"2026-07-28T00:00:00Z",'
  printf '"permit":{"ceremony":"%s","mode":"legacy",' "${ceremony}"
  printf '"canonical_start_block":%s,' "${anchor}"
  printf '"work_id":"%s","permit_id":"%s","identity_bound":%s},' \
    "${work}" "${permit}" "${bound}"
  printf '"outcome":"%s","evidence":{%s}}' "${outcome}" "${evidence}"
}

read_terminal_outcomes() {
  local state="$1"
  set +e
  CASE_OUT="$(
    (
      # Invoked through the reader under test, which shellcheck cannot see
      # across the source boundary into rehearse.sh.
      # shellcheck disable=SC2329
      probe_diagnostics() { printf '%s' "${state}"; }
      service_terminal_outcomes r1-node-1
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

read_terminal_outcomes "$(gate_state_with_outcomes \
  "\"recent_terminal_outcomes\":[$(closed_permit completed w-1 p-1)]")"
check "a closed permit is rendered with the identity the held list carries" 0 \
  "^r1-node-1@beacon_relay_signing@10@w-1#p-1=completed=protocol_result\
=0xentry=-=-=-=-$"

# The gate writes this itself when a permit is closed by an owner that recorded
# nothing. It has to arrive as a disposition rather than as an absence, because
# an absence reads exactly like a permit still in flight — and it is the one
# ending that names no evidence, because there was no owner to author any.
read_terminal_outcomes "$(gate_state_with_outcomes \
  "\"recent_terminal_outcomes\":[$(closed_permit unresolved w-1 p-1 true \
    '"kind":""')]")"
check "an owner that recorded nothing is read as a disposition, not a gap" 0 \
  "^r1-node-1@beacon_relay_signing@10@w-1#p-1=unresolved=-=-=-=-=-=-$"

# A release that stopped publishing the account would otherwise leave every
# control reading an empty list, which is what a fleet that closed nothing
# looks like.
read_terminal_outcomes '{"protocol_participation":{"active_permits":[]}}'
check "a gate publishing no closed-permit account cannot be read" 1 \
  "no recent_terminal_outcomes"

read_terminal_outcomes "$(gate_state_with_outcomes \
  "\"recent_terminal_outcomes\":[$(closed_permit completed w-1 p-1 false)]")"
check "an unbound closed permit names no work and is refused" 1 \
  "not identity-bound"

read_terminal_outcomes "$(gate_state_with_outcomes \
  "\"recent_terminal_outcomes\":[$(closed_permit finished w-1 p-1)]")"
check "an ending outside the gate's own vocabulary is refused" 1 \
  "not a terminal outcome"

# The ending is appended to the identity with "=", so a permit carrying one of
# its own would split into a different permit and a different ending than the
# node meant — and the joins decide which permit closed how by that split.
read_terminal_outcomes "$(gate_state_with_outcomes \
  "\"recent_terminal_outcomes\":[$(closed_permit completed w-1 'p=1')]")"
check "an identity that would split into another permit is refused" 1 \
  "names no work or permit identity"

# The ceremony and the anchor are inside the identity, so a record missing
# either names a permit no control can tell from another run of the same work.
read_terminal_outcomes "$(gate_state_with_outcomes \
  "\"recent_terminal_outcomes\":[$(closed_permit completed w-1 p-1 true \
    '"kind":"protocol_result","reference":"0xentry"' '')]")"
check "a closed permit naming no ceremony is refused" 1 \
  "names no gate ceremony"

read_terminal_outcomes "$(gate_state_with_outcomes \
  "\"recent_terminal_outcomes\":[$(closed_permit completed w-1 p-1 true \
    '"kind":"protocol_result","reference":"0xentry"' beacon_relay_signing \
    '"ten"')]")"
check "a closed permit naming no canonical start block is refused" 1 \
  "names no canonical start block"

# The evidence half. A completion is a category every finished ceremony writes,
# so a record whose evidence does not name what was produced leaves the control
# above it deciding on the word alone.
read_terminal_outcomes "$(gate_state_with_outcomes \
  "\"recent_terminal_outcomes\":[$(closed_permit completed w-1 p-1 true \
    '"kind":"protocol_result"')]")"
check "a completion naming no durable result is refused" 1 \
  "names no durable result"

read_terminal_outcomes "$(gate_state_with_outcomes \
  "\"recent_terminal_outcomes\":[$(closed_permit completed w-1 p-1 true \
    '"kind":"invented_evidence","reference":"0xentry"')]")"
check "evidence outside the gate's own classes is refused" 1 \
  "not a terminal evidence kind"

# The mirror: the classes that name no durable state must not carry one, or a
# quarantine could be dressed as a settlement by naming any identity beside it.
read_terminal_outcomes "$(gate_state_with_outcomes \
  "\"recent_terminal_outcomes\":[$(closed_permit quarantined w-1 p-1 true \
    '"kind":"quarantined_beacon_signer","reference":"0xentry"')]")"
check "unreferenced evidence carrying a result is refused" 1 \
  "must name no durable result"

read_terminal_outcomes "$(gate_state_with_outcomes \
  "\"recent_terminal_outcomes\":[$(closed_permit unresolved w-1 p-1 true \
    '"kind":"protocol_result","reference":"0xentry"')]")"
check "an unresolved permit that also names evidence is refused" 1 \
  "an unresolved permit names terminal evidence"

# A chain side effect the same permit dispatched, which travels beside the
# result rather than in place of it.
read_terminal_outcomes "$(gate_state_with_outcomes \
  "\"recent_terminal_outcomes\":[$(closed_permit completed w-1 p-1 true \
    '"kind":"protocol_result","reference":"0xentry",'\
'"chain_settlement":{"kind":"inactivity_claim","reference":"aabb:7"}')]")"
check "a dispatched chain settlement is carried with the ending" 0 \
  "=completed=protocol_result=0xentry=-=-=-=inactivity_claim:aabb:7$"

# The joins. Each is asked about a named population and an account that does or
# does not answer for it.
P1="r1-node-1@beacon_relay_signing@10@w-1#p-1"
P2="r1-node-1@beacon_relay_signing@11@w-2#p-2"
NAMED="${P1} ${P2}"
DONE1="${P1}=completed=protocol_result=0xr1=-=-=-=-"
DONE2="${P2}=completed=protocol_result=0xr2=-=-=-=-"
BOTH="${DONE1} ${DONE2}"

check_join() {
  local desc="$1" want="$2" got="$3"
  if [[ "${got}" == "${want}" ]]; then
    printf 'ok   %s\n' "${desc}"
    PASS=$((PASS + 1))
    return
  fi
  printf 'FAIL %s: got [%s], want [%s]\n' "${desc}" "${got}" "${want}"
  FAILED=$((FAILED + 1))
}

check_join "a permit no gate recorded an ending for is named" \
  "${P2}" \
  "$(unauthored_permits "${NAMED}" "${DONE1}")"
check_join "a fully answered population leaves nothing unauthored" "" \
  "$(unauthored_permits "${NAMED}" "${BOTH}")"
check_join "one permit ending twice is named with its count" \
  "${P1} (2 records)" \
  "$(duplicated_authored_permits "${NAMED}" \
    "${DONE1} ${P1}=exhausted=no_threshold=-=-=-=-=- ${DONE2}")"
check_join "an owner that recorded nothing is named with its ending" \
  "${P2}=unresolved" \
  "$(unresolved_authored_permits "${NAMED}" \
    "${DONE1} ${P2}=unresolved=-=-=-=-=-=-")"
check_join "a permit that ended some other way than required is named" \
  "${P2}=exhausted" \
  "$(misended_authored_permits "${NAMED}" \
    "${DONE1} ${P2}=exhausted=no_threshold=-=-=-=-=-" completed)"
# The unauthored and unresolved checks own those two cases; reporting them here
# as well would have one permit fail two controls with two different reasons.
check_join "a permit with no record is left to the unauthored check" "" \
  "$(misended_authored_permits "${NAMED}" "${DONE1}" completed)"
check_join "the endings a passing verdict quotes are the holders' own" \
  "${P1}=completed, ${P2}=completed" \
  "$(authored_endings "${NAMED}" "${BOTH}")"

# The collisions the whole identity exists for. A work id and a local permit id
# are unique only within one ceremony and one anchor — a member index is "1" in
# every group a node ever joins — so an account that reused them under a
# different ceremony or a different run would answer for the wrong permit.
check_join "a record for the same work under another ceremony answers for none" \
  "${P1}" \
  "$(unauthored_permits "${P1}" \
    "r1-node-1@tbtc_dkg@10@w-1#p-1=completed=persisted_tbtc_signer=0xr1=1=1=1\
=-")"
check_join "a record for the same work at another anchor answers for none" \
  "${P1}" \
  "$(unauthored_permits "${P1}" \
    "r1-node-1@beacon_relay_signing@99@w-1#p-1=completed=protocol_result=0xr1\
=-=-=-=-")"
check_join "a record from another holder answers for none" \
  "${P1}" \
  "$(unauthored_permits "${P1}" \
    "r1-node-2@beacon_relay_signing@10@w-1#p-1=completed=protocol_result=0xr1\
=-=-=-=-")"
# And the mirror, so the three above cannot pass by never matching anything.
check_join "the record naming the whole identity does answer for it" "" \
  "$(unauthored_permits "${P1}" "${DONE1}")"

# An account that stops at the category is what a release publishing the older
# shape serves, and every evidence check below would read its missing fields as
# whatever the truncation left in their place.
check_join "a record that stops at the disposition is unreadable" \
  "${P1}=completed" \
  "$(malformed_authored_records "${P1}" "${P1}=completed")"
check_join "a whole record reads as complete" "" \
  "$(malformed_authored_records "${NAMED}" "${BOTH}")"

# The evidence joins. Two holders of one ceremony write the same result because
# it is derived from the output; holders of different ones cannot.
S1="r1-node-1@beacon_relay_signing@10@w-1#1"
S2="r1-node-2@beacon_relay_signing@10@w-1#2"
SHARED="${S1}=completed=protocol_result=0xentry=-=-=-=- \
${S2}=completed=protocol_result=0xentry=-=-=-=-"
SPLIT="${S1}=completed=protocol_result=0xentry=-=-=-=- \
${S2}=completed=protocol_result=0xelsewhere=-=-=-=-"

check_join "holders that agree on one threshold output are not named" "" \
  "$(disagreeing_authored_results "${S1} ${S2}" "${SHARED}")"
check_join "holders naming different outputs for one ceremony are named" \
  "beacon_relay_signing@10@w-1 (0xentry/0xelsewhere)" \
  "$(disagreeing_authored_results "${S1} ${S2}" "${SPLIT}")"
check_join "a completion carrying another ceremony's evidence class is named" \
  "${S1} claims persisted_tbtc_signer where a protocol_result is the result of \
that ceremony" \
  "$(misevidenced_authored_permits "${S1}" \
    "${S1}=completed=persisted_tbtc_signer=0xentry=1=-=-=-")"
check_join "a completion carrying its own ceremony's class is not named" "" \
  "$(misevidenced_authored_permits "${S1} ${S2}" "${SHARED}")"

# The rehearsal's copy of the gate's one-to-one ceremony-to-evidence table is
# only worth applying if it is the gate's. A ceremony added to the gate without
# an entry here would be read by the rehearsal as having no declared result
# class, and one whose class changed would be refused for carrying the very
# evidence the gate requires — so the table is resolved out of the gate's own
# source and compared entry for entry.
GATE_SOURCE="${TEST_DIR}/../../../pkg/protocol/participation/quiescence.go"
GATE_CEREMONY_SOURCE="${TEST_DIR}/../../../pkg/protocol/participation/gate.go"
GATE_EVIDENCE_TABLE="$(
  awk '
    FILENAME == ARGV[1] && $2 == "Ceremony" && $3 == "=" {
      gsub(/"/, "", $4)
      ceremony[$1] = $4
      next
    }
    FILENAME == ARGV[2] && $2 == "TerminalEvidenceKind" && $3 == "=" {
      gsub(/"/, "", $4)
      evidence[$1] = $4
      next
    }
    FILENAME == ARGV[2] && /^var completedEvidenceKinds = map/ { inside = 1; next }
    inside && /^}/ { inside = 0; next }
    inside && $1 ~ /:$/ {
      name = substr($1, 1, length($1) - 1)
      kind = $2
      sub(/,$/, "", kind)
      print (ceremony[name] ? ceremony[name] : "?" name), \
        (evidence[kind] ? evidence[kind] : "?" kind)
    }
  ' "${GATE_CEREMONY_SOURCE}" "${GATE_SOURCE}"
)"

# The rehearsal's own arms, read out of its source rather than by asking the
# function. Asking it can only answer about ceremonies something already knows
# to ask about, so a ceremony the gate dropped while the rehearsal kept a class
# for it would never be reached — which is the drift in the direction a gate
# change makes likeliest.
REHEARSAL_EVIDENCE_TABLE="$(
  awk '
    /^expected_completed_evidence\(\) \{/ { inside = 1; next }
    inside && /^\}/ { inside = 0 }
    inside && $1 ~ /\)$/ && $2 == "printf" {
      name = substr($1, 1, length($1) - 1)
      if (name == "*") next
      kind = $3
      gsub(/'"'"'/, "", kind)
      print name, kind
    }
  ' "${TEST_DIR}/rehearse.sh"
)"

TABLE_LEFT="$(printf '%s\n' "${GATE_EVIDENCE_TABLE}" | sort)"
TABLE_RIGHT="$(printf '%s\n' "${REHEARSAL_EVIDENCE_TABLE}" | sort)"
if [[ -z "${GATE_EVIDENCE_TABLE//[[:space:]]/}" ]]; then
  printf 'FAIL the gate declares no completed-evidence table to mirror\n'
  FAILED=$((FAILED + 1))
elif [[ "${TABLE_LEFT}" != "${TABLE_RIGHT}" ]]; then
  printf 'FAIL the rehearsal result classes are not the gate%ss:\n' "'"
  diff <(printf '%s\n' "${TABLE_LEFT}") \
    <(printf '%s\n' "${TABLE_RIGHT}") || true
  FAILED=$((FAILED + 1))
else
  printf 'ok   every result class the rehearsal applies is one the gate pins\n'
  PASS=$((PASS + 1))
fi

# The seam between the two accounts: the driver names what the work settled as
# in its own vocabulary, the holders name what they produced, and the control
# is about the two being the same threshold output.
CLAIMED="beacon_signing@10@w-1=succeeded=0xtx=0xentry"
check_join "holders and driver naming one output reconcile" "" \
  "$(unclaimed_authored_results "${S1} ${S2}" "${SHARED}" "${CLAIMED}")"
check_join "a settlement the holders never produced is named" \
  "${S1} recorded 0xentry where the driver claims 0xsomethingelse, \
${S2} recorded 0xentry where the driver claims 0xsomethingelse" \
  "$(unclaimed_authored_results "${S1} ${S2}" "${SHARED}" \
    "beacon_signing@10@w-1=succeeded=0xtx=0xsomethingelse")"
check_join "a completion the driver never settled is named" \
  "${S1} recorded 0xentry where the driver claims no settlement at all" \
  "$(unclaimed_authored_results "${S1}" "${SHARED}" "")"

# A node that cannot be asked makes the whole reading unusable. A shorter list
# would be indistinguishable from a fleet whose permits all ended unrecorded.
SAVED_R1_SERVICES=("${REHEARSAL_R1_SERVICES[@]}")
REHEARSAL_R1_SERVICES=("r1-node-1")
set +e
CASE_OUT="$(
  (
    # shellcheck disable=SC2329
    probe_diagnostics() { return 1; }
    fleet_terminal_outcomes
  ) 2>&1
)"
CASE_RC=$?
set -e
REHEARSAL_R1_SERVICES=("${SAVED_R1_SERVICES[@]}")
check "a gate that cannot be asked leaves the fleet reading unusable" 0 \
  "^unreadable on r1-node-1$"

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

# The verdict a run reports when a mandatory property was watched and broke.
# This is the harness's most important negative outcome and the one a ledger
# read only for blocked steps reports as a success.
E="${WORK}/emitted-failed"
mkdir -p "${E}"
write_attestation "${E}"
run_rehearsal "${E}" single_release failed_run
check "a rehearsal whose mandatory step failed refuses the gate" 1 \
  "rehearsal evidence record written" \
  "1 mandatory step\(s\) of the single_release gate failed" \
  "clock failure quarantines work rather than guessing a mode"

if grep -q '"outcome": "fail"' "${E}"/single_release-*.json; then
  printf 'ok   the failed rehearsal left its record on disk for review\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the failed rehearsal wrote no record of what broke\n'
  FAILED=$((FAILED + 1))
fi

E="${WORK}/emitted-refused-assertion"
mkdir -p "${E}"
write_attestation "${E}"
run_rehearsal "${E}" single_release refused_assertion_run
check "every step passing does not carry a refused acceptance assertion" 1 \
  "1 acceptance assertion\(s\) of the single_release gate do not hold" \
  "post-C ceremonies run security-v2 with no legacy sightings"

E="${WORK}/emitted-failed-and-blocked"
mkdir -p "${E}"
write_attestation "${E}"
run_rehearsal "${E}" single_release failed_and_blocked_run
check "a failure outranks an unexecuted step in the run's own verdict" 1 \
  "of the single_release gate failed"

# ----------------------------------------------------------------------------
#
# What the record is allowed to say the fleet was. Every value below is read
# off the running nodes, from all of them, and compared against what this run
# is bound to — so the cases install fleets whose answers disagree and require
# the capture to refuse rather than record the first node's version of events.

run_capture() {
  set +e
  CASE_OUT="$(
    (
      # shellcheck disable=SC2030,SC2031,SC2034
      REPO_ROOT="${WORK}/repo"
      # shellcheck disable=SC2030,SC2031,SC2034
      CUTOVER_BLOCK="9000000"
      # shellcheck disable=SC2030,SC2031,SC2034
      CHAIN_ID="11155111"
      "$@"
      capture_r1_release_identity
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

homogeneous_fleet() { :; }

# The second node runs a different release of the same commit. Its revision
# still binds to this run, so only asking every node — rather than the first
# one — can see that the fleet is not one release under test.
mixed_release_fleet() {
  # Installed into the capture's subshell, which shellcheck cannot follow.
  # shellcheck disable=SC2329
  probe_diagnostics() {
    if [[ "$1" == "r1-node-2" ]]; then
      diagnostics_document "${FIXTURE_SHA}" security_v2_cutover 9000000 \
        v1.9.0-rehearsal
    else
      diagnostics_document
    fi
  }
}

# A homogeneous fleet built from bytes this run is not bound to.
foreign_revision_fleet() {
  # shellcheck disable=SC2329
  probe_diagnostics() { diagnostics_document "$(printf 'd%.0s' {1..40})"; }
}

# A homogeneous fleet armed with another schedule entirely: every crossing
# and refusal it produces is evidence about a cutover this record does not
# describe.
wrong_cutover_fleet() {
  # shellcheck disable=SC2329
  probe_diagnostics() {
    diagnostics_document "${FIXTURE_SHA}" security_v2_cutover 8000000
  }
}

run_capture homogeneous_fleet
check "a fleet agreeing on the bound revision and C is captured" 0 \
  "every R1 node reports" "matching the attested source"

run_capture mixed_release_fleet
check "one node running another release refuses the run" 3 \
  "the R1 fleet is not homogeneous" "r1-node-2"

run_capture foreign_revision_fleet
check "a fleet built from bytes this run is not bound to refuses the run" 3 \
  "does not name that commit exactly"

# An artifact naming the bound commit only as far as an abbreviation goes. It
# used to pass, because the comparison asked whether the attested SHA started
# with what the node reported — which the empty string also satisfies.
abbreviated_revision_fleet() {
  # shellcheck disable=SC2329
  probe_diagnostics() { diagnostics_document "${FIXTURE_SHA:0:7}"; }
}

run_capture abbreviated_revision_fleet
check "a fleet naming the bound commit only in abbreviation refuses the run" \
  3 "does not name that commit exactly"

silent_revision_fleet() {
  # shellcheck disable=SC2329
  probe_diagnostics() { diagnostics_document ""; }
}

run_capture silent_revision_fleet
check "a fleet reporting no revision at all refuses the run" 3 \
  "does not report the version, revision"

# The chain identity the record used to take from its own dispatch input,
# which agrees with itself whichever chain the fleet was pointed at. A cutover
# block is a count on one chain, so a fleet on another chain crossed a
# different schedule.
wrong_chain_fleet() {
  # shellcheck disable=SC2329
  probe_diagnostics() {
    diagnostics_document "${FIXTURE_SHA}" security_v2_cutover 9000000 \
      v2.0.0-rehearsal 1
  }
}

run_capture wrong_chain_fleet
check "a fleet connected to another chain refuses the run" 3 \
  "connected to Ethereum chain \[1\]"

silent_chain_fleet() {
  # shellcheck disable=SC2329
  probe_diagnostics() {
    diagnostics_document "${FIXTURE_SHA}" security_v2_cutover 9000000 \
      v2.0.0-rehearsal ""
  }
}

run_capture silent_chain_fleet
check "a fleet that will not name its chain cannot be evidenced" 3 \
  "protocol_participation.ethereum_chain_id"

run_capture wrong_cutover_fleet
check "a fleet armed with another cutover block refuses the run" 3 \
  "armed cutover block \[8000000\]" "bound to C=\[9000000\]"

# A release whose epoch is not the one the reviewed manifest was derived for:
# every bound this run measures it against was computed for something else.
wrong_epoch_fleet() {
  # shellcheck disable=SC2329
  probe_diagnostics() { diagnostics_document "${FIXTURE_SHA}" legacy_epoch; }
}

run_capture wrong_epoch_fleet
check "a fleet on another protocol epoch refuses the run" 3 \
  "reports protocol epoch \[legacy_epoch\]" "release manifest"

# ----------------------------------------------------------------------------
#
# The work driver is what makes the fleet do anything at all, and what it
# reports about the chain work it originated becomes part of the record. A
# report that cannot be read is a broken instrument, not an absence of
# transactions.

DRIVER_HASH_A="0x$(printf 'a%.0s' {1..64})"
DRIVER_HASH_B="0x$(printf 'b%.0s' {1..64})"

# The chain a driver's report is confirmed against. Every reading a phase takes
# off a report is only as good as the chain corroborating it, so the self-test
# answers the way a chain would rather than removing the check: a report that
# names transactions is confirmed here exactly as it would be in a rehearsal,
# and the cases below change what the chain says rather than whether it is
# asked.
# shellcheck disable=SC2034
ETH_RPC_URL="http://chain.rehearsal.invalid"
FIXTURE_CHAIN_ID="0xaa36a7"
FIXTURE_RECEIPT_STATUS="0x1"
FIXTURE_RECEIPT_BLOCK="0x1"
FIXTURE_RECEIPT_ABSENT=""
FIXTURE_RPC_BODY=""

# shellcheck disable=SC2329
chain_rpc() {
  if [[ -n "${FIXTURE_RPC_BODY}" ]]; then
    printf '%s' "${FIXTURE_RPC_BODY}"
    return 0
  fi
  case "$1" in
  eth_chainId)
    printf '{"jsonrpc":"2.0","id":1,"result":"%s","contributors":[{"service":"r1-node-1","permit_id":"1"}]}' "${FIXTURE_CHAIN_ID}"
    ;;
  eth_getTransactionReceipt)
    if [[ -n "${FIXTURE_RECEIPT_ABSENT}" ]]; then
      printf '{"jsonrpc":"2.0","id":1,"result":null}'
    else
      printf \
        '{"jsonrpc":"2.0","id":1,"result":{"status":"%s","blockNumber":"%s"}}' \
        "${FIXTURE_RECEIPT_STATUS}" "${FIXTURE_RECEIPT_BLOCK}"
    fi
    ;;
  *) printf '{"jsonrpc":"2.0","id":1,"result":null}' ;;
  esac
}

make_driver() {
  local path="$1" status="$2" report="$3"
  cat >"${path}" <<DRIVER
#!/usr/bin/env bash
printf '%s' '${report}'
exit ${status}
DRIVER
  chmod +x "${path}"
}

run_driver_case() {
  set +e
  CASE_OUT="$(
    (
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_WORK_DRIVER="$1"
      # shellcheck disable=SC2030,SC2031,SC2034
      STEP_TX_HASHES=""
      driver_rc=0
      run_work_driver homogeneous-security-v2 || driver_rc=$?
      printf 'driver_rc:%s hashes:[%s]\n' "${driver_rc}" "${STEP_TX_HASHES}"
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

make_driver "${WORK}/driver-reporting" 0 \
  "{\"transaction_hashes\":[\"${DRIVER_HASH_A}\",\"${DRIVER_HASH_B}\"]}"
run_driver_case "${WORK}/driver-reporting"
check "the transactions a driver reports enter the step being recorded" 0 \
  "driver_rc:0" "hashes:\[\"${DRIVER_HASH_A}\",\"${DRIVER_HASH_B}\"\]"

make_driver "${WORK}/driver-silent" 0 ""
run_driver_case "${WORK}/driver-silent"
check "a driver that reports nothing records no transactions" 0 \
  "driver_rc:0" "hashes:\[\]"

# The exit status has to survive the report parsing, or the steps that fail on
# a driver failure would stop seeing it.
make_driver "${WORK}/driver-failing" 4 \
  "{\"transaction_hashes\":[\"${DRIVER_HASH_A}\"]}"
run_driver_case "${WORK}/driver-failing"
check "a failing driver still reports its exit status to the step" 0 \
  "driver_rc:4" "hashes:\[\"${DRIVER_HASH_A}\"\]"

make_driver "${WORK}/driver-unreadable" 0 "{not json"
run_driver_case "${WORK}/driver-unreadable"
check "a report this rehearsal cannot read stops the step" 3 \
  "in a form this rehearsal cannot read"

make_driver "${WORK}/driver-bad-hash" 0 \
  '{"transaction_hashes":["0xnot-a-transaction-hash"]}'
run_driver_case "${WORK}/driver-bad-hash"
check "a reported value that is not a transaction hash stops the step" 3 \
  "in a form this rehearsal cannot read"

# ----------------------------------------------------------------------------
#
# What the rollback gate stages, and what it audits.
#
# Both are decided by what the container daemon reports, so the daemon is the
# seam: `compose` and `docker` are replaced by fixtures that answer the way one
# would for a described container, and the real staging, capture, and audit
# code runs over them. A case changes what the daemon says, never what the code
# under test does.

FIXTURE_PRIOR_ID="sha256:$(printf 'e%.0s' {1..64})"
FIXTURE_OTHER_ID="sha256:$(printf 'f%.0s' {1..64})"

# The container a fixture describes. Each case sets these before running the
# code under test; the two command fixtures answer from nothing else.
FIXTURE_CREATE_RC=0
FIXTURE_CONTAINER="c0ffee"
FIXTURE_RUNNING="false"
FIXTURE_CONTAINER_IMAGE="${FIXTURE_PRIOR_ID}"
FIXTURE_IMAGE_ID="${FIXTURE_PRIOR_ID}"
FIXTURE_VOLUMES="/mnt/storage"
FIXTURE_CP_RC=0
FIXTURE_STORAGE="${WORK}/fixture-storage"

# shellcheck disable=SC2329
compose() {
  case "$1" in
  create) return "${FIXTURE_CREATE_RC}" ;;
  ps) printf '%s\n' "${FIXTURE_CONTAINER}" ;;
  *) return 0 ;;
  esac
}

# The subset of the daemon the two functions under test speak to, dispatched
# on the same shapes they call it with.
# shellcheck disable=SC2329
docker() {
  case "$1" in
  image)
    # docker image inspect --format '{{.Id}}' <reference>
    [[ -n "${FIXTURE_IMAGE_ID}" ]] || return 1
    printf '%s\n' "${FIXTURE_IMAGE_ID}"
    ;;
  cp)
    [[ "${FIXTURE_CP_RC}" -eq 0 ]] || return "${FIXTURE_CP_RC}"
    # The real command copies the container path's contents into the
    # destination, so the fixture does exactly that from a directory standing
    # in for the volume.
    cp -R "${FIXTURE_STORAGE}/." "${3}"
    ;;
  inspect)
    case "$3" in
    '{{.State.Running}}')
      [[ -n "${FIXTURE_RUNNING}" ]] || return 1
      printf '%s\n' "${FIXTURE_RUNNING}"
      ;;
    '{{.Image}}') printf '%s\n' "${FIXTURE_CONTAINER_IMAGE}" ;;
    *Mounts*) printf '%s\n' "${FIXTURE_VOLUMES}" ;;
    *) return 1 ;;
    esac
    ;;
  *) return 1 ;;
  esac
}

run_fixture() {
  set +e
  CASE_OUT="$(
    (
      # shellcheck disable=SC2030,SC2031,SC2034
      PRIOR_IMAGE_DIGEST="keep/keep-client@sha256:$(printf 'b%.0s' {1..64})"
      "$@"
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

mkdir -p "${FIXTURE_STORAGE}"
printf 'drained state\n' >"${FIXTURE_STORAGE}/participation.json"

run_fixture stage_prior_container
check "the prior artifact is staged without being put on the network" 0 \
  "without starting it" "is not running"

FIXTURE_RUNNING="true"
run_fixture stage_prior_container
check "a staged prior container that came up refuses the rehearsal" 3 \
  "running immediately after being staged"
FIXTURE_RUNNING="false"

FIXTURE_CREATE_RC=1
run_fixture stage_prior_container
check "a prior container that cannot be created refuses the rehearsal" 3 \
  "would have nothing to start"
FIXTURE_CREATE_RC=0

FIXTURE_CONTAINER=""
run_fixture stage_prior_container
check "a create that produced no container refuses the rehearsal" 3 \
  "no staged prior artifact to release"
FIXTURE_CONTAINER="c0ffee"

FIXTURE_CONTAINER_IMAGE="${FIXTURE_OTHER_ID}"
run_fixture stage_prior_container
check "a prior container built from other bytes refuses the rehearsal" 3 \
  "the state audit never authorized"
FIXTURE_CONTAINER_IMAGE="${FIXTURE_PRIOR_ID}"

# The capture is what makes the audit below a statement about this rehearsal,
# so the cases are about which states it refuses to produce a snapshot from.
run_capture_snapshot() {
  set +e
  CASE_OUT="$(
    (
      # shellcheck disable=SC2030,SC2031,SC2034
      STORAGE_SNAPSHOT_DIR="${WORK}/snapshots"
      capture_rc=0
      capture_storage_snapshot r1-node-1 || capture_rc=$?
      printf 'capture_rc:%s reason:[%s]\n' "${capture_rc}" \
        "${SNAPSHOT_CAPTURE_REASON}"
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

SNAP="${WORK}/snapshots/r1-node-1"
mkdir -p "${WORK}/snapshots"

run_capture_snapshot
check "a drained node's state is captured from the container that stopped" 0 \
  "capture_rc:0" "state captured from the stopped container"
if [[ -f "${SNAP}/participation.json" ]]; then
  printf 'ok   the capture holds the stopped container'"'"'s own bytes\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the capture does not hold the stopped container bytes\n'
  FAILED=$((FAILED + 1))
fi

# An inherited capture is the whole failure mode a fixed per-service path
# invites: without removal the audit reads a previous run's state under this
# run's name and authorizes a rollback nobody rehearsed.
printf 'stale\n' >"${SNAP}/stale-from-an-earlier-run.json"
run_capture_snapshot
check "a capture replaces the one an earlier run left behind" 0 \
  "capture_rc:0" "state captured from the stopped container"
if [[ -f "${SNAP}/stale-from-an-earlier-run.json" ]]; then
  printf 'FAIL an earlier run'"'"'s capture survived into this one\n'
  FAILED=$((FAILED + 1))
else
  printf 'ok   an earlier run'"'"'s capture does not survive into this one\n'
  PASS=$((PASS + 1))
fi

FIXTURE_RUNNING="true"
run_capture_snapshot
check "a still-running node is not captured out from under itself" 0 \
  "capture_rc:1" "torn read"
FIXTURE_RUNNING="false"

FIXTURE_VOLUMES=""
run_capture_snapshot
check "a node with no persistent volume has no state to audit" 0 \
  "capture_rc:1" "0 persistent volume mount"
FIXTURE_VOLUMES="/mnt/storage
/mnt/other"
run_capture_snapshot
check "a node with two persistent volumes is refused rather than guessed at" \
  0 "capture_rc:1" "2 persistent volume mount"
FIXTURE_VOLUMES="/mnt/storage"

FIXTURE_CP_RC=1
run_capture_snapshot
check "a copy that failed leaves no snapshot to audit" 0 \
  "capture_rc:1" "no capture of the state the drain left"
if [[ -e "${SNAP}" ]]; then
  printf 'FAIL a failed capture left a partial snapshot behind\n'
  FAILED=$((FAILED + 1))
else
  printf 'ok   a failed capture leaves no partial snapshot behind\n'
  PASS=$((PASS + 1))
fi
FIXTURE_CP_RC=0

# ----------------------------------------------------------------------------
#
# The audit's own verdict, over the two passes it is made of. Every external
# record has to name the audited snapshot's aggregate checksum, and that
# checksum is a fact about state the drain has only just produced — so the
# first pass derives it, the generator is run against that manifest, and the
# second pass is the one that authorizes anything. The cases below drive both
# the order and the ways each pass can fail to establish what the next one
# needs, plus the two ways a stale or incomplete result can still be read as an
# authorization: a tool that refused this snapshot while an earlier ready
# manifest sat at its path, and one that never wrote a manifest at all.

AUDIT_INPUTS="${WORK}/audit-inputs"
mkdir -p "${AUDIT_INPUTS}"
GENERATOR="${AUDIT_INPUTS}/rollback-evidence-generator"
GENERATOR_ARGUMENTS="${AUDIT_INPUTS}/generator-arguments"

write_generator() {
  cat >"${GENERATOR}"
  chmod +x "${GENERATOR}"
}

# A generator that writes every record the audit reads back, and records the
# arguments it was handed so a case can assert which manifest this run bound
# its evidence to.
generator_complete() {
  write_generator <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >"${GENERATOR_ARGUMENTS}"
for record in chain-reconciliation bitcoin-reconciliation \\
  quiescence-report prior-reader-compatibility; do
  printf '{}\n' >"\$3/\${record}.json"
done
EOF
}

# The audit tool, replaced at the seam the stage runs it through. The subshell
# `go run` executes inherits this function, so the real invocation — its flags,
# its output path, and what the caller makes of its exit status — is what runs.
# Which pass it is answering is read off those flags, exactly as the tool
# itself would: an invocation carrying no evidence is the identity pass. The
# knobs are globals because a nested function reads its enclosing scope when it
# is called, not when it is defined, and by then the definer has long returned.
AUDIT_TOOL_STATUS=0
AUDIT_TOOL_MANIFEST=""
AUDIT_IDENTITY_STATUS=3
AUDIT_IDENTITY_MANIFEST='{"consistent":true,"snapshot":{"aggregate_sha256":"deadbeef"}}'
# shellcheck disable=SC2329
go() {
  local argument previous="" output="" authorizing=0
  for argument in "$@"; do
    [[ "${previous}" == "--output" ]] && output="${argument}"
    [[ "${argument}" == "--quiescence-report" ]] && authorizing=1
    previous="${argument}"
  done
  if ((authorizing == 0)); then
    [[ -n "${AUDIT_IDENTITY_MANIFEST}" ]] &&
      printf '%s\n' "${AUDIT_IDENTITY_MANIFEST}" >"${output}"
    return "${AUDIT_IDENTITY_STATUS}"
  fi
  [[ -n "${AUDIT_TOOL_MANIFEST}" ]] &&
    printf '%s\n' "${AUDIT_TOOL_MANIFEST}" >"${output}"
  return "${AUDIT_TOOL_STATUS}"
}
audit_tool() {
  AUDIT_TOOL_STATUS="$1"
  AUDIT_TOOL_MANIFEST="$2"
  AUDIT_IDENTITY_STATUS=3
  AUDIT_IDENTITY_MANIFEST='{"consistent":true,"snapshot":{"aggregate_sha256":"deadbeef"}}'
  generator_complete
}

run_audit_case() {
  set +e
  CASE_OUT="$(
    (
      # shellcheck disable=SC2030,SC2031,SC2034
      EVIDENCE_DIR="${WORK}/audit-evidence"
      # shellcheck disable=SC2030,SC2031,SC2034
      REPO_ROOT="${WORK}/repo"
      # shellcheck disable=SC2030,SC2031,SC2034
      CHAIN_ID="11155111"
      # shellcheck disable=SC2030,SC2031,SC2034
      PRIOR_IMAGE_DIGEST="keep/keep-client@sha256:$(printf 'b%.0s' {1..64})"
      # shellcheck disable=SC2030,SC2031,SC2034
      R1_IMAGE_DIGEST="keep/keep-client@sha256:$(printf 'a%.0s' {1..64})"
      # shellcheck disable=SC2030,SC2031,SC2034
      REHEARSAL_R1_IDENTITY='{"version":"v2.0.0-rehearsal","revision":"r"}'
      # shellcheck disable=SC2030,SC2031,SC2034
      REHEARSAL_R1_EPOCH="security_v2_cutover"
      # shellcheck disable=SC2030,SC2031,SC2034
      REHEARSAL_R1_CUTOVER_BLOCK="9000000"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_ROLLBACK_EVIDENCE_GENERATOR="${GENERATOR}"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_WALLET_REGISTRY_ADDRESS="0x1111111111111111111111111111111111111111"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_RANDOM_BEACON_ADDRESS="0x3333333333333333333333333333333333333333"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_FINALIZED_ETHEREUM_BLOCK_NUMBER="9001000"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_FINALIZED_ETHEREUM_BLOCK_HASH="0x$(printf 'c%.0s' {1..64})"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_CHAIN_EVIDENCE_PUBLIC_KEY="$(printf 'd%.0s' {1..64})"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_BITCOIN_NETWORK="testnet"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_PRIOR_VERSION="v1.9.0"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_PRIOR_REVISION="abc1234"
      "$1"
      audit_rc=0
      run_state_audit r1-node-1 "${SNAP}" || audit_rc=$?
      printf 'audit_rc:%s reason:[%s]\n' "${audit_rc}" "${STATE_AUDIT_REASON}"
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

mkdir -p "${WORK}/audit-evidence" "${SNAP}"

audit_ready() { audit_tool 0 '{"rollback_barrier_ready":true}'; }
run_audit_case audit_ready
check "an audit that completed and authorized the rollback is accepted" 0 \
  "audit_rc:0" "rollback_barrier_ready"

# The evidence has to be generated for the snapshot this run just derived, so
# the generator is handed that run's identity manifest and nothing else.
if grep -q 'r1-node-1 .*state-audit/r1-node-1-identity.json' \
  "${GENERATOR_ARGUMENTS}"; then
  printf 'ok   the generator is handed this run'"'"'s identity manifest\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the generator was not handed this run'"'"'s identity manifest: %s\n' \
    "$(cat "${GENERATOR_ARGUMENTS}")"
  FAILED=$((FAILED + 1))
fi

# The identity pass is what the evidence binds to, so a pass that establishes
# no snapshot leaves nothing for a record to speak for.
audit_no_identity() {
  audit_tool 0 '{"rollback_barrier_ready":true}'
  AUDIT_IDENTITY_MANIFEST=""
}
run_audit_case audit_no_identity
check "evidence cannot be generated for a snapshot never derived" 0 \
  "audit_rc:1" "without writing a manifest to"

audit_inconsistent_identity() {
  audit_tool 0 '{"rollback_barrier_ready":true}'
  AUDIT_IDENTITY_MANIFEST='{"consistent":false,"findings":["torn namespace"]}'
}
run_audit_case audit_inconsistent_identity
check "an inconsistent snapshot establishes no identity to bind to" 0 \
  "audit_rc:1" "torn namespace"

audit_unchecksummed_identity() {
  audit_tool 0 '{"rollback_barrier_ready":true}'
  AUDIT_IDENTITY_MANIFEST='{"consistent":true,"snapshot":{}}'
}
run_audit_case audit_unchecksummed_identity
check "a snapshot with no aggregate checksum binds no evidence" 0 \
  "audit_rc:1" "derived no snapshot aggregate checksum"

# A generator that failed leaves the rehearsal with no account of the drain it
# was asked to describe, which is not the same as an audit that refused.
audit_failing_generator() {
  audit_tool 0 '{"rollback_barrier_ready":true}'
  write_generator <<'EOF'
#!/usr/bin/env bash
exit 4
EOF
}
run_audit_case audit_failing_generator
check "a generator that failed authorizes nothing" 0 \
  "audit_rc:1" "evidence generator exited \[4\]"

audit_partial_generator() {
  audit_tool 0 '{"rollback_barrier_ready":true}'
  write_generator <<'EOF'
#!/usr/bin/env bash
printf '{}\n' >"$3/chain-reconciliation.json"
printf '{}\n' >"$3/bitcoin-reconciliation.json"
EOF
}
run_audit_case audit_partial_generator
check "a generator that wrote only some records authorizes nothing" 0 \
  "audit_rc:1" "wrote no quiescence-report.json prior-reader-compatibility.json"

audit_absent_generator() {
  audit_tool 0 '{"rollback_barrier_ready":true}'
  rm -f "${GENERATOR}"
}
run_audit_case audit_absent_generator
check "a generator that cannot be run authorizes nothing" 0 \
  "audit_rc:1" "which is not executable"

# The tool exits nonzero on an inconsistent namespace as well as on an unready
# barrier, so a run that reads only the ready flag accepts a snapshot the tool
# refused for a reason that flag does not carry.
audit_refused_but_ready() { audit_tool 3 '{"rollback_barrier_ready":true}'; }
run_audit_case audit_refused_but_ready
check "a nonzero audit is not authorized by its own ready flag" 0 \
  "audit_rc:1" "exited \[3\]"

# The stale case: this run's authorizing pass writes nothing, and an earlier
# run's ready manifest is sitting at the path it would have written.
printf '{"rollback_barrier_ready":true}\n' \
  >"${WORK}/audit-evidence/state-audit/r1-node-1.json"
audit_silent() { audit_tool 0 ""; }
run_audit_case audit_silent
check "an earlier run's manifest cannot authorize this run's rollback" 0 \
  "audit_rc:1" "without writing a manifest"

unset -f compose docker go

# ----------------------------------------------------------------------------
#
# The two step verdicts whose contracts have two halves each. Both used to
# pass on a proxy for the property — an unchanged permit counter nobody had
# challenged, a peak the gauge could not have risen above, a fallen active
# count that meant the owners noticed rather than the gate acted — so both are
# decided by functions that read only their observation slots and touch no
# fleet, and the cases drive them straight against constructed readings.

run_verdict() {
  set +e
  CASE_OUT="$(
    (
      set -o pipefail
      # shellcheck disable=SC2030,SC2031,SC2034
      REHEARSAL_GATE="single_release"
      # A ledger belonging to this case alone, so a verdict is read against
      # what it recorded and not against what an earlier case left behind.
      # shellcheck disable=SC2030,SC2031,SC2034
      REHEARSAL_STEPS=()
      # shellcheck disable=SC2030,SC2031,SC2034
      REHEARSAL_FAILED_STEPS=()
      # shellcheck disable=SC2030,SC2031,SC2034
      REHEARSAL_BLOCKED_STEPS=()
      # shellcheck disable=SC2030,SC2031,SC2034
      REHEARSAL_REFUTED_ASSERTIONS=()
      # shellcheck disable=SC2030,SC2031,SC2034
      REHEARSAL_ASSERTIONS=()
      "$@"
      # A passing step logs only its name, so the ledger itself is printed:
      # what a verdict wrote into the record is the thing under test, not the
      # console line it happened to emit on the way.
      printf 'ledger:%s\n' "${REHEARSAL_STEPS[*]}"
      conclude_verdict
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

# A clock failure that held work, canceled all of it, was offered new work
# while blind, and refused it. Each case below changes exactly one reading.
# The slots the verdict under test reads; shellcheck cannot follow them
# across the source boundary into rehearse.sh.
# shellcheck disable=SC2034
clock_readings() {
  CLOCK_STATE="clock_unavailable"
  CLOCK_HELD_BEFORE="3"
  CLOCK_HELD_AFTER="0"
  CLOCK_ABORTS_BEFORE="5"
  CLOCK_ABORTS_AFTER="8"
  CLOCK_PERMITS_BEFORE="42"
  CLOCK_PERMITS_AFTER="42"
  CLOCK_REFUSALS_BEFORE="7"
  CLOCK_REFUSALS_AFTER="9"
  CLOCK_REFUSAL_ATTEMPTED=1
  CLOCK_OFFER_FAILED=0
  CLOCK_OFFER_RC=""
}

clock_case() {
  clock_readings
  "$@"
  clock_failure_verdict
}

run_verdict clock_case :
check "a clock failure that canceled its work and refused new work holds" 0 \
  "canceled all 3 ceremonies it held" "2 refusal\(s\) and no new permit"

# The half that used to pass on silence: nothing was ever offered, so a permit
# counter standing still is what an unasked node looks like.
run_verdict clock_case eval 'CLOCK_REFUSAL_ATTEMPTED=0'
check "an unchallenged permit counter is not a refusal" 3 \
  "no work was offered to it while it was blind"

# Work was offered and the gate never saw it, so nothing was refused either.
run_verdict clock_case eval 'CLOCK_REFUSALS_AFTER="7"'
check "work that never reached the gate evidences no refusal" 3 \
  "nothing reached the gate to be refused"

run_verdict clock_case eval 'CLOCK_REFUSALS_AFTER="not-a-number"'
check "an unreadable refusal counter is not read as a refusal" 3 \
  "refusal counter did not move"

# The half that used to pass on the active count falling: permits stay counted
# until their owners close them, so a fall is the owners noticing rather than
# the gate canceling. Only the abort counter says the gate acted.
run_verdict clock_case eval 'CLOCK_ABORTS_AFTER="5"'
check "held work that was never canceled refutes the gate" 1 \
  "recorded only 0 clock cancellation\(s\)"

run_verdict clock_case eval 'CLOCK_ABORTS_AFTER="7"'
check "cancelling fewer permits than were held refutes the gate" 1 \
  "recorded only 2 clock cancellation\(s\)"

# The same partial cancellation, with the active count fallen to zero and then
# unreadable: neither may stand in for the cancellations that did not happen.
run_verdict clock_case eval 'CLOCK_ABORTS_AFTER="5"; CLOCK_HELD_AFTER="0"'
check "a drained active count does not excuse missing cancellations" 1 \
  "recorded only 0 clock cancellation\(s\)"

run_verdict clock_case eval 'CLOCK_ABORTS_AFTER="5"; CLOCK_HELD_AFTER=""'
check "an unreadable active count does not excuse missing cancellations" 1 \
  "recorded only 0 clock cancellation\(s\)"

run_verdict clock_case eval 'CLOCK_PERMITS_AFTER="43"'
check "a blind gate that issued a permit refutes the gate" 1 \
  "still issued 1 new permit"

run_verdict clock_case eval 'CLOCK_STATE="open_security_v2"'
check "a severed node that never reported clock_unavailable refutes it" 1 \
  "reported \[open_security_v2\] with its chain endpoint severed"

run_verdict clock_case eval 'CLOCK_HELD_BEFORE="0"'
check "a node holding nothing cannot evidence the cancel half" 3 \
  "cancel-what-is-held half of the contract was never exercised"

# The offer was made and the instrument broke, which the counters cannot tell
# apart from a gate nobody challenged — so the record has to.
run_verdict clock_case eval \
  'CLOCK_REFUSAL_ATTEMPTED=0; CLOCK_OFFER_FAILED=1; CLOCK_OFFER_RC="9"
   CLOCK_REFUSALS_AFTER="7"'
check "a driver that could not offer work is not a gate nobody asked" 3 \
  "work driver exited \[9\] without naming a transaction"

# A quiescence that held work, was offered more while quiescing, issued none,
# and was seen with its in-flight count at zero before it went away.
# The chain identifiers the held work is bound to. A held permit followed to an
# outcome needs the outcome to name the same piece of work the permit was
# issued for; without that the two are populations that happen to sit beside
# each other.
QUIESCE_TX1="0x3131313131313131313131313131313131313131313131313131313131313131"
QUIESCE_TX2="0x3232323232323232323232323232323232323232323232323232323232323232"
QUIESCE_TX3="0x3333333333333333333333333333333333333333333333333333333333333333"

# The slots the verdict under test reads; shellcheck cannot follow them
# across the source boundary into rehearse.sh.
# shellcheck disable=SC2034
quiesce_readings() {
  QUIESCE_STATE="quiescing"
  QUIESCE_HELD_BEFORE="2"
  QUIESCE_ISSUED_BEFORE="11"
  QUIESCE_ISSUED_AFTER="11"
  QUIESCE_FORCED_BEFORE="4"
  QUIESCE_FORCED_AFTER="4"
  QUIESCE_DRAINED=1
  QUIESCE_ATTEMPTED=1
  QUIESCE_OFFER_FAILED=0
  QUIESCE_OFFER_RC=""
  QUIESCE_GRACE="20160"
  # The node's own account of the refusal, total and per ceremony.
  QUIESCE_REFUSALS_BEFORE="7"
  QUIESCE_REFUSALS_AFTER="8"
  QUIESCE_CEREMONY_REFUSALS_BEFORE="tbtc_dkg=1
tbtc_signing=3
beacon_dkg=0"
  QUIESCE_CEREMONY_REFUSALS_AFTER="tbtc_dkg=1
tbtc_signing=4
beacon_dkg=0"
  # What this offer actually put on the chain, which is what the moved counter
  # has to belong to.
  QUIESCE_OFFERED="tbtc_signing"
  # The work the node was holding when the stop was issued, named rather than
  # counted, and what the driver saw become of each piece once the drain was
  # over. Two permits, two pieces of work, two outcomes.
  QUIESCE_INFLIGHT_WORK="\
tbtc_signing@840@wallet840=${QUIESCE_TX1}=r1-node-2~member-1 \
beacon_dkg@841@seed841=${QUIESCE_TX2}=r1-node-2~2"
  # The same two permits as the issuing gate itself named them, which is what
  # makes the driver's account checkable rather than merely the right length.
  QUIESCE_PERMITS_BEFORE="r1-node-2@tbtc_signing@840@wallet840#member-1 r1-node-2@beacon_dkg@841@seed841#2"
  QUIESCE_TERMINAL="\
tbtc_signing@840@wallet840=succeeded=${QUIESCE_TX1}=0xsigned840 \
beacon_dkg@841@seed841=succeeded=${QUIESCE_TX2}=0xgroup841"
  QUIESCE_TERMINAL_ASKED=1
  QUIESCE_TERMINAL_RC=0
  # And what the node itself recorded closing those two permits as, sampled
  # while it was still answering. The driver's account above is the account of
  # the party that also originated the work; this is the holder's.
  QUIESCE_AUTHORED_READ=1
  QUIESCE_AUTHORED_ENDINGS="\
r1-node-2@tbtc_signing@840@wallet840#member-1=completed=bitcoin_transaction\
=0xsigned840=-=1=1=- \
r1-node-2@beacon_dkg@841@seed841#2=completed=persisted_beacon_signer\
=0xgroup841=1=-=-=-"
  # The security-v2 half is not seeded and drains one population, so neither
  # the pre-C seeding rungs nor the co-live requirement apply to it.
  QUIESCE_FROM_SEED=0
  QUIESCE_COLIVE_REQUIRED=0
  QUIESCE_COLIVE_PERMITS=""
  QUIESCE_COLIVE_WORK=""
  QUIESCE_COLIVE_MODE=""
  QUIESCE_COLIVE_MISANCHORED=""
  QUIESCE_SEEDED_ASKED=0
  QUIESCE_SEEDED_RC=0
  QUIESCE_SEEDED_WORK=""
  QUIESCE_SEEDED_PERMITS_BEFORE_C=""
}

quiesce_case() {
  quiesce_readings
  "$@"
  quiescence_verdict r1-node-2 \
    "quiescence with an in-flight security-v2 permit" \
    "graceful quiescence starts no new work and lets held permits finish" \
    security-v2
}

run_verdict quiesce_case :
check "a quiescence that refused new work and drained its permits holds" 0 \
  "refused it on its own account \(tbtc_signing \+1" \
  "in-flight count observed at zero" \
  "closed with the ending its own holder recorded" \
  "r1-node-2@tbtc_signing@840@wallet840#member-1=completed" \
  "tbtc_signing@840@wallet840 \(${QUIESCE_TX1}, 0xsigned840\)"

# The seam these rungs close. Every rung above them reads the ending off the
# same driver that originated the work, so a drain that satisfied them all was
# reported rather than observed.
run_verdict quiesce_case eval 'QUIESCE_AUTHORED_READ=0'
check "a node that cannot say how it closed its permits observed no drain" 3 \
  "could not be asked what became of the permits it closed"

run_verdict quiesce_case eval \
  'QUIESCE_AUTHORED_ENDINGS="\
r1-node-2@tbtc_signing@840@wallet840#member-1=completed=bitcoin_transaction\
=0xsigned840=-=1=1=-"'
check "a drained permit only the driver vouches for is not accounted for" 3 \
  "recorded no ending for r1-node-2@beacon_dkg@841@seed841#2"

# Appends to the case's own reading, so it has to expand inside the case and
# not out here where the fixture has not been laid down yet.
# shellcheck disable=SC2016
run_verdict quiesce_case eval \
  'QUIESCE_AUTHORED_ENDINGS="${QUIESCE_AUTHORED_ENDINGS} \
r1-node-2@beacon_dkg@841@seed841#2=exhausted=no_threshold=-=-=-=-=-"'
check "one drained permit ending twice cannot be read as either ending" 3 \
  "more than one ending for r1-node-2@beacon_dkg@841@seed841#2 \(2 records\)"

# The permit-taken-with-the-process reading, seen from the node's side: the
# permit closed, and its own owner recorded nothing about where the ceremony
# went. The driver still reports both settling.
run_verdict quiesce_case eval \
  'QUIESCE_AUTHORED_ENDINGS="\
r1-node-2@tbtc_signing@840@wallet840#member-1\
=completed r1-node-2@beacon_dkg@841@seed841#2=unresolved=-=-=-=-=-=-"'
check "a drained permit whose owner recorded nothing refutes the gate" 1 \
  "without its ceremony owner recording any disposition"

# This gate asks that held work finish or enter audited quarantine, so the one
# is allowed where the other is not.
run_verdict quiesce_case eval \
  'QUIESCE_AUTHORED_ENDINGS="\
r1-node-2@tbtc_signing@840@wallet840#member-1\
=completed r1-node-2@beacon_dkg@841@seed841#2=quarantined=quarantined_beacon_signer=-=-=-=-=-"'
check "a drained permit whose key material was quarantined still holds" 0 \
  "r1-node-2@beacon_dkg@841@seed841#2=quarantined"

run_verdict quiesce_case eval \
  'QUIESCE_AUTHORED_ENDINGS="\
r1-node-2@tbtc_signing@840@wallet840#member-1\
=completed r1-node-2@beacon_dkg@841@seed841#2=exhausted=no_threshold=-=-=-=-=-"'
check "a drained permit the holder recorded as exhausted refutes the gate" 1 \
  "r1-node-2@beacon_dkg@841@seed841#2=exhausted"

# The reading a gauge cannot carry, and the one this step used to stop at. The
# permits are gone; a process that exited holding them produces exactly that.
run_verdict quiesce_case eval 'QUIESCE_INFLIGHT_WORK=""'
check "held permits nobody identified cannot be followed anywhere" 3 \
  "the driver named no identified work it was holding"

# A permit total and a list of work are two populations until they are the same
# size: an outcome for one piece of work reconciles no particular permit when
# the node was holding more permits than there was work to hold them for.
run_verdict quiesce_case eval 'QUIESCE_HELD_BEFORE="3"'
check "more held permits than identified work reconciles neither" 3 \
  "held 3 security-v2 permit\(s\) for 2 piece\(s\) of work"

run_verdict quiesce_case eval 'QUIESCE_TERMINAL_ASKED=0
   QUIESCE_TERMINAL=""'
check "a drain nobody asked the driver about is not work that finished" 3 \
  "never asked what became of the work behind them"

run_verdict quiesce_case eval 'QUIESCE_TERMINAL_RC=7'
check "a partial terminal report accounts for no held permit" 3 \
  "work driver exited \[7\] reporting what became of the work"

# A terminal phase must preserve the transaction that the in-flight phase
# recorded. The anchor and ceremony still match here; accepting them alone
# would let an unrelated successful transaction become the held permit's end.
run_verdict quiesce_case eval \
  "QUIESCE_TERMINAL=\"\
tbtc_signing@840@wallet840=succeeded=${QUIESCE_TX3}=0xunrelated \
beacon_dkg@841@seed841=succeeded=${QUIESCE_TX2}=0xgroup841\""
check "a terminal phase cannot replace the transaction that started work" 3 \
  "tbtc_signing@840@wallet840 .* originated as ${QUIESCE_TX1}" \
  "cannot replace the transaction that started held work"

# The regression the whole rung exists for: one of the two held permits has no
# outcome behind it at all, and the gauge fell to zero exactly the same way.
run_verdict quiesce_case eval \
  "QUIESCE_TERMINAL=\"\
tbtc_signing@840@wallet840=succeeded=${QUIESCE_TX1}=0xsigned840\""
check "a permit whose work never ended went down with the process" 3 \
  "no terminal outcome for beacon_dkg@841@seed841#2"

# An end, but not the end this step claims. Nothing in this gate audits what a
# ceremony that gave up left behind.
run_verdict quiesce_case eval \
  "QUIESCE_TERMINAL=\"\
tbtc_signing@840@wallet840=succeeded=${QUIESCE_TX1}=0xsigned840 \
beacon_dkg@841@seed841=failed=${QUIESCE_TX2}=retry_exhausted\""
check "work that gave up inside the grace is not work allowed to finish" 3 \
  "beacon_dkg@841@seed841#2=failed \(retry_exhausted\) came to nothing"

run_verdict quiesce_case eval 'QUIESCE_ATTEMPTED=0'
check "a quiescing node nobody asked evidences no refusal to start work" 3 \
  "no work was offered to it while it was quiescing"

# The regression this rung exists for: work went out and no permit came back,
# which is what a refusal looks like and equally what an offer that never
# arrived looks like. Only the node's own counter tells the two apart.
# The `before` value is the case's own, so it has to expand inside the case
# and not out here where the fixture has not been laid down yet.
# shellcheck disable=SC2016
run_verdict quiesce_case eval 'QUIESCE_CEREMONY_REFUSALS_AFTER="\
${QUIESCE_CEREMONY_REFUSALS_BEFORE}"
   QUIESCE_REFUSALS_AFTER="7"'
check "an offer the node never recorded refusing is not a refusal" 1 \
  "its own refusal counter never moved"

# A total that moved with no ceremony behind it names nothing a release could
# act on, and the total alone is satisfied by a refusal from any other cause.
# shellcheck disable=SC2016
run_verdict quiesce_case eval 'QUIESCE_CEREMONY_REFUSALS_AFTER="\
${QUIESCE_CEREMONY_REFUSALS_BEFORE}"'
check "a refusal no ceremony counter accounts for attributes nothing" 3 \
  "no per-ceremony refusal counter moved with the total"

# The regression this seam exists for: a per-ceremony counter did move, so the
# reading has the exact shape this step looks for — but it belongs to a
# ceremony this offer never originated. A rehearsal chain carries other
# traffic, and any ceremony refused for its own reasons moves the total and
# one per-ceremony counter together.
run_verdict quiesce_case eval 'QUIESCE_CEREMONY_REFUSALS_AFTER="tbtc_dkg=2
tbtc_signing=3
beacon_dkg=0"'
check "another ceremony's refusal is not this offer being refused" 3 \
  "this offer originated tbtc_signing and none of those counters moved"

# And the reading that cannot be attributed at all: the offer went out without
# saying what it put on the chain, so no counter can be tied back to it.
run_verdict quiesce_case eval 'QUIESCE_OFFERED=""'
check "an offer that named no ceremony attributes no refusal" 3 \
  "the offer named no ceremony it originated"

# The offer originated two ceremonies and one of them was refused, which is
# this offer being refused whatever the other one did.
run_verdict quiesce_case eval 'QUIESCE_OFFERED="beacon_dkg tbtc_signing"'
check "one refused ceremony among those offered holds the control" 0 \
  "refused it on its own account \(tbtc_signing \+1"

run_verdict quiesce_case eval 'QUIESCE_REFUSALS_AFTER=""'
check "an unreadable refusal counter observes no refusal at all" 3 \
  "refusal counter could not be read"

# A per-ceremony counter that could not be read must not subtract like a zero
# and turn an unobserved ceremony into an attributed one.
run_verdict quiesce_case eval 'QUIESCE_CEREMONY_REFUSALS_BEFORE="\
tbtc_signing=unreadable"
   QUIESCE_CEREMONY_REFUSALS_AFTER="tbtc_signing=4"'
check "an unreadable ceremony counter attributes no refusal" 3 \
  "no per-ceremony refusal counter moved with the total"

# The issuance counter and not the gauge peak: a permit taken and closed
# between two samples never raises the peak it would have been compared to.
run_verdict quiesce_case eval 'QUIESCE_ISSUED_AFTER="12"'
check "a permit issued and closed between samples still refutes the gate" 1 \
  "still issued 1 new permit"

run_verdict quiesce_case eval 'QUIESCE_ISSUED_AFTER=""'
check "an unreadable issuance counter is not read as no issuance" 3 \
  "issued-permit counter could not be read"

run_verdict quiesce_case eval 'QUIESCE_DRAINED=0'
check "permits unobserved at zero are not evidence they finished" 3 \
  "never seen without them"

run_verdict quiesce_case eval 'QUIESCE_FORCED_AFTER="5"'
check "a held permit cut short rather than finished refutes the gate" 1 \
  "force-aborted 1 held permit"

run_verdict quiesce_case eval 'QUIESCE_FORCED_AFTER=""'
check "an unreadable forced-abort counter is not read as none" 3 \
  "forced-abort counter could not be read"

run_verdict quiesce_case eval 'QUIESCE_STATE="open_security_v2"'
check "a draining node that never reported quiescing refutes the gate" 1 \
  "never reported quiescing"

run_verdict quiesce_case eval \
  'QUIESCE_ATTEMPTED=0; QUIESCE_OFFER_FAILED=1; QUIESCE_OFFER_RC="4"'
check "a driver that could not offer work is not a node nobody asked" 3 \
  "work driver exited \[4\] without naming a transaction"

# The straggler control, whose evidence used to be the gate's own refusal
# counter — a counter that moves when a node declines its own Begin, for
# reasons that need no legacy announcement behind them at all.
STRAGGLER_OPERATOR="0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"

# The chain identifiers a driven ceremony is bound to: the transaction that
# originated it, and — for the cases where one settles — the threshold output
# that settling produced. A control decided on outcomes alone accepts any of
# these detached from the work it claims to be about.
STRAGGLER_TX="0x1111111111111111111111111111111111111111111111111111111111111111"
STRAGGLER_TX2="0x2222222222222222222222222222222222222222222222222222222222222222"
STRAGGLER_SIG="0xabc123def456"

straggler_readings() {
  # shellcheck disable=SC2034
  STRAGGLER_BEFORE=("10" "4" "2")
  # shellcheck disable=SC2034
  STRAGGLER_AFTER=("11" "5" "3")
  # shellcheck disable=SC2034
  STRAGGLER_EXPECTED_OPERATOR="${STRAGGLER_OPERATOR}"
  # shellcheck disable=SC2034
  STRAGGLER_DRIVER_SUPPLIED=1
  # shellcheck disable=SC2034
  STRAGGLER_DRIVER_RC=0
  # shellcheck disable=SC2034
  STRAGGLER_DRIVER_TX=2
  # The driven ceremony came to nothing, which is the outcome "fails closed"
  # names. The fleet is sized so it needs the straggler to reach threshold.
  # Bound to the transaction that started it and to the termination that says
  # it stopped trying rather than is still trying.
  # shellcheck disable=SC2034
  STRAGGLER_BOUND="tbtc_signing=failed=${STRAGGLER_TX}=retry_exhausted"
}

straggler_case() {
  straggler_readings
  "$@"
}

# The same address as the fleet spells it back in lowercase, which is one of
# the two spellings a roster entry arrives in.
STRAGGLER_OPERATOR_LOWER="$(printf '%s' "${STRAGGLER_OPERATOR}" |
  tr '[:upper:]' '[:lower:]')"

run_verdict straggler_case eval \
  "straggler_control_verdict '${STRAGGLER_OPERATOR}'"
check "a straggler recognized, rostered, and named holds the control" 0 \
  "recognized 1 of them as cross-format" \
  "naming the straggler's own operator ${STRAGGLER_OPERATOR}"

# The regression the counters could not carry: the straggler was seen, named,
# and rostered — and the ceremony it joined settled anyway. Being named is not
# being refused, and this control is about post-C legacy work coming to
# nothing.
run_verdict straggler_case eval \
  "STRAGGLER_BOUND='tbtc_signing=succeeded=${STRAGGLER_TX}=${STRAGGLER_SIG}'
   straggler_control_verdict '${STRAGGLER_OPERATOR}'"
check "a rostered straggler whose ceremony settled has not failed closed" 1 \
  "produced a threshold output \(tbtc_signing \(${STRAGGLER_TX}, \
${STRAGGLER_SIG}\)\)"

# The same, with the settled ceremony sitting beside one that did not: a report
# is read whole here too.
run_verdict straggler_case eval \
  "STRAGGLER_BOUND='tbtc_signing=failed=${STRAGGLER_TX}=retry_exhausted \
beacon_dkg=succeeded=${STRAGGLER_TX2}=${STRAGGLER_SIG}'
   straggler_control_verdict '${STRAGGLER_OPERATOR}'"
check "one settled ceremony among the driven work refutes the control" 1 \
  "beacon_dkg \(${STRAGGLER_TX2}, ${STRAGGLER_SIG}\)"

# Retry exhaustion is what makes the outcome terminal. A ceremony still running
# has produced no threshold output yet, which is not the same as having failed
# to produce one, and the sightings would be read off a ceremony mid-flight.
run_verdict straggler_case eval \
  "STRAGGLER_BOUND=''
   straggler_control_verdict '${STRAGGLER_OPERATOR}'"
check "a ceremony with no terminal outcome cannot evidence failing closed" 3 \
  "exhausted its retries or is still running"

# The case the refusal counter could not tell apart from success: no legacy
# announcement ever arrived, so there was nothing to fail closed against.
run_verdict straggler_case eval \
  "STRAGGLER_AFTER=('10' '5' '3')
   straggler_control_verdict '${STRAGGLER_OPERATOR}'"
check "a roster entry with no session mismatch behind it is not the control" \
  3 "no session-ID mismatch"

run_verdict straggler_case eval \
  "STRAGGLER_AFTER=('11' '4' '3')
   straggler_control_verdict '${STRAGGLER_OPERATOR}'"
check "a mismatch never recognized as cross-format refutes the control" 1 \
  "recognized none of them as cross-format"

run_verdict straggler_case eval \
  "STRAGGLER_AFTER=('11' '5' '2')
   straggler_control_verdict '${STRAGGLER_OPERATOR}'"
check "a cross-format sighting that entered no roster refutes the control" 1 \
  "added none to its legacy roster"

run_verdict straggler_case eval 'straggler_control_verdict ""'
check "a roster addition naming no new operator refutes the control" 1 \
  "named no operator it had not already seen"

run_verdict straggler_case eval \
  "STRAGGLER_AFTER=('11' '' '3')
   straggler_control_verdict '${STRAGGLER_OPERATOR}'"
check "an unreadable cross-format counter observes no straggler at all" 3 \
  "announcer_cross_format_peer_total"

# The entry has to be the straggler's own. A roster that names some other peer
# is the release attributing a legacy sighting to the wrong node, and a release
# decision would act on the name.
run_verdict straggler_case eval \
  'straggler_control_verdict "0x1111111111111111111111111111111111111111"'
check "a roster naming an operator that is not the straggler refutes it" 1 \
  "none of them is the straggler's own operator"

# The same address in the two spellings it arrives in must not read as two
# operators: EIP-55 from one source, lowercase from another.
run_verdict straggler_case eval \
  "straggler_control_verdict '${STRAGGLER_OPERATOR_LOWER}'"
check "the straggler's operator in another spelling still holds the control" \
  0 "so the straggler failed closed and was named"

# Among several newly named operators, the straggler's presence is what the
# control is about.
run_verdict straggler_case eval \
  "straggler_control_verdict \
'0x2222222222222222222222222222222222222222 ${STRAGGLER_OPERATOR}'"
check "the straggler named alongside other operators holds the control" 0 \
  "so the straggler failed closed and was named"

run_verdict straggler_case eval \
  "STRAGGLER_EXPECTED_OPERATOR=''
   straggler_control_verdict '${STRAGGLER_OPERATOR}'"
check "a straggler whose own operator could not be read proves no naming" 3 \
  "straggler's own operator address could not be read"

# The driver accounting the counters used to be read without. A driver that
# failed, that named nothing, or that was never supplied leaves counter
# movement no one can attribute to this control.
run_verdict straggler_case eval \
  "STRAGGLER_DRIVER_SUPPLIED=0
   straggler_control_verdict '${STRAGGLER_OPERATOR}'"
check "counter movement with no driver behind it is not the control" 3 \
  "no PR4109_WORK_DRIVER was supplied"

run_verdict straggler_case eval \
  "STRAGGLER_DRIVER_RC=7
   straggler_control_verdict '${STRAGGLER_OPERATOR}'"
check "a failed driver leaves the sightings belonging to something else" 3 \
  "work driver exited \[7\] originating the post-C ceremony"

run_verdict straggler_case eval \
  "STRAGGLER_DRIVER_TX=0
   straggler_control_verdict '${STRAGGLER_OPERATOR}'"
check "a driver that named no transaction attributes no sighting" 3 \
  "named no transaction"

# The all-candidate-down barrier, whose evidence used to be one probe of the
# asking project's own two services. The readings below are the ones a passing
# rehearsal never produces and no fleet can be arranged to produce on demand:
# another gate's leftovers, a container the daemon cannot describe, and an
# enumeration that cannot even see the containers the asking stage created.
BARRIER_STEP="every release candidate is stopped or network-quarantined"
BARRIER_ASSERTION="all R1 is down or quarantined before any prior binary \
participates"

barrier_readings() {
  # shellcheck disable=SC2034
  CANDIDATE_INVENTORY=(
    "pr4109-rollback/r1-node-1 stopped -"
    "pr4109-rollback/r1-node-2 stopped -"
    "pr4109-single_release/r1-node-1 stopped -"
  )
  # shellcheck disable=SC2034
  CANDIDATE_EXPECTED=(
    "pr4109-rollback/r1-node-1"
    "pr4109-rollback/r1-node-2"
  )
  # shellcheck disable=SC2034
  CANDIDATE_INVENTORY_READ=1
}

barrier_case() {
  barrier_readings
  "$@"
  candidate_barrier_verdict "${BARRIER_STEP}" "${BARRIER_ASSERTION}"
  printf 'holds:%s\n' "${CANDIDATE_BARRIER_HOLDS}"
}

run_verdict barrier_case :
check "a daemon whose every candidate is stopped establishes the barrier" 0 \
  "3 container\(s\) across every rehearsal project" "holds:1"

# The regression this seam exists for: the asking project is quiet and another
# gate's fleet is not, and a distinct compose project is not a quarantine.
run_verdict barrier_case eval \
  'CANDIDATE_INVENTORY+=("pr4109-single_release/r1-node-2 running \
pr4109-single_release_rehearsal,pr4109-single_release_chain-egress")'
check "a candidate left running by another gate refutes the barrier" 1 \
  "pr4109-single_release/r1-node-2 on pr4109-single_release_rehearsal" \
  "separate compose project is not quarantine" "holds:0"

# A candidate started outside any rehearsal project, recognized by the image it
# was created from rather than by a label it need not carry.
run_verdict barrier_case eval \
  'CANDIDATE_INVENTORY+=("stray-candidate running bridge")'
check "an unlabelled candidate on a network refutes the barrier" 1 \
  "stray-candidate on bridge" "holds:0"

# Attached to nothing is the one quarantine this script can read rather than
# take on trust, so it holds — and the record names which container it was.
run_verdict barrier_case eval \
  'CANDIDATE_INVENTORY+=("pr4109-single_release/r1-node-2 running -")'
check "a running candidate attached to no network is quarantined" 0 \
  "attached to no network \(pr4109-single_release/r1-node-2\)" "holds:1"

# The candidate half of the shared-stack confusion: a release candidate holding
# another container's network stack owns no entry of its own, and the barrier
# that let it through would release the prior artifact while it still submits.
run_verdict barrier_case eval \
  'CANDIDATE_INVENTORY+=("pr4109-single_release/r1-node-2 running \
container:9fce2a1b7c4d")'
check "a candidate sharing another container's stack refutes the barrier" 1 \
  "pr4109-single_release/r1-node-2 on container:9fce2a1b7c4d" "holds:0"

run_verdict barrier_case eval \
  'CANDIDATE_INVENTORY+=("pr4109-single_release/r1-node-2 unreadable -")'
check "a candidate whose state cannot be read is not a candidate known down" \
  3 "run state of pr4109-single_release/r1-node-2" "holds:0"

# The vacuous pass: an enumeration returning nothing has an empty active set
# too, and an empty active set is what the barrier holding looks like.
run_verdict barrier_case eval 'CANDIDATE_INVENTORY=()'
check "an enumeration blind to this gate's own candidates blocks" 3 \
  "did not find this rehearsal's own candidate" "holds:0"

run_verdict barrier_case eval 'CANDIDATE_INVENTORY_READ=0'
check "a daemon that could not be enumerated establishes no barrier" 3 \
  "could not be enumerated" "holds:0"

# What both barriers rest on, before either of them classifies anything: the
# single token that says whether a running container can still reach the
# rehearsal chain and its peers. Every verdict below reads "-" as isolation, so
# what does and does not produce that token decides what the barriers accept.
check_attachment() {
  local desc="$1" networks="$2" mode="$3" want="$4" got
  got="$(container_attachment "${networks}" "${mode}")"
  if [[ "${got}" != "${want}" ]]; then
    printf 'FAIL %s: attachment "%s", want "%s"\n' "${desc}" "${got}" "${want}"
    FAILED=$((FAILED + 1))
    return
  fi
  printf 'ok   %s\n' "${desc}"
  PASS=$((PASS + 1))
}

check_attachment "a container on a compose network reaches it" \
  "pr4109-rollback_rehearsal," "pr4109-rollback_rehearsal" \
  "pr4109-rollback_rehearsal"

# The regression this rung exists for. A container run with `container:` or
# compose `service:` network mode holds the stack of the container it names and
# is on every network that one is on, while owning no `Networks` entry of its
# own. Read off the map alone it is indistinguishable from quarantine, and a
# prior or candidate left running that way would satisfy the barrier while
# still submitting against the rehearsal contracts.
check_attachment "a container sharing another's stack is not quarantined" \
  "" "container:9fce2a1b7c4d" "container:9fce2a1b7c4d"
check_attachment "a compose service-mode container is not quarantined" \
  "" "service:candidate-node" "service:candidate-node"

# The other half of the same confusion: Docker lists `none` in the map like any
# network, so genuine isolation does not present as an empty map and would be
# read as attachment.
check_attachment "the none network is the isolation it names" \
  "none," "none" "-"
check_attachment "a host-network container holds every route the host has" \
  "host," "host" "host"

check_attachment "a container attached to nothing at all is quarantined" \
  "" "bridge" "-"

# A mode that could not be read leaves reachability unknown, and an unknown
# must not spend the barrier's one passing reading.
check_attachment "an unreadable network mode is not proof of isolation" \
  "" "" "mode-unreadable"

# The other half of that barrier, and the half the candidate inventory skips by
# construction: no prior artifact executing anywhere while the fleet drains.
# The evidence for it used to be one HTTP probe of this project's own prior
# service, which is blind to precisely the container that breaks the barrier
# without breaking the probe — a prior started by another project, or started
# directly under no project at all, watching the same rehearsal chain.
#
# The readings below are sampled ones: the step's claim is about a window, so
# the cases fold several samples and the verdict is taken over all of them.
PRIOR_STEP="no prior binary starts during quiescence"
PRIOR_ASSERTION="no prior binary participates before every R1 node is down"

# The daemon as a held barrier shows it: this project's staged prior created
# and stopped, and an earlier gate's prior stopped beside it.
PRIOR_CLEAN_LISTING="pr4109-single_release/prior-node stopped -
pr4109-rollback/prior-node stopped -"

prior_readings() {
  reset_prior_drain_samples
  PRIOR_SAMPLE_LISTING="${PRIOR_CLEAN_LISTING}"
}

# Fold the current listing as many times as a drain would sample it, so a
# reading that only appears mid-window is what the verdict decides on.
prior_sample_window() {
  local count="${1:-3}" i
  for ((i = 0; i < count; i++)); do
    absorb_prior_inventory_sample <<<"${PRIOR_SAMPLE_LISTING}"
  done
}

prior_case() {
  prior_readings
  "$@"
  prior_absence_verdict "${PRIOR_STEP}" "${PRIOR_ASSERTION}"
}

run_verdict prior_case prior_sample_window
check "a daemon with every prior container stopped holds the barrier" 0 \
  "no container built from the prior image was running and network-attached"

# The regression this seam exists for: this project's own prior stays stopped
# for the whole window — so the probe keyed on it answers nothing — while
# another project's prior runs on a network throughout.
# Each of these appends to the listing the case itself laid down, so the
# expansion belongs to the case subshell and not to this line.
# shellcheck disable=SC2016
run_verdict prior_case eval \
  'PRIOR_SAMPLE_LISTING="${PRIOR_SAMPLE_LISTING}
pr4109-rollback/prior-node running pr4109-rollback_rehearsal"
   prior_sample_window'
check "another project's prior left running refutes the barrier" 1 \
  "pr4109-rollback/prior-node on pr4109-rollback_rehearsal" \
  "separate compose project is not quarantine"

# A prior started outside any rehearsal project, recognized by the image it was
# created from rather than by a label it need not carry.
# shellcheck disable=SC2016
run_verdict prior_case eval \
  'PRIOR_SAMPLE_LISTING="${PRIOR_SAMPLE_LISTING}
stray-prior running bridge"
   prior_sample_window'
check "an unlabelled prior on a network refutes the barrier" 1 \
  "stray-prior on bridge"

# The sequence a single post-drain probe cannot tell from a clean window: a
# prior that participated for part of quiescence and was gone before the last
# sample was taken.
# shellcheck disable=SC2016
run_verdict prior_case eval \
  'prior_sample_window 1
   PRIOR_SAMPLE_LISTING="${PRIOR_SAMPLE_LISTING}
pr4109-rollback/prior-node running pr4109-rollback_rehearsal"
   prior_sample_window 1
   PRIOR_SAMPLE_LISTING="${PRIOR_CLEAN_LISTING}"
   prior_sample_window 1'
check "a prior seen only mid-drain still refutes the barrier" 1 \
  "in 1 of 3 samples"

# Attached to nothing is the one quarantine this script can read rather than
# take on trust, and it is the same reading the candidate barrier takes.
# shellcheck disable=SC2016
run_verdict prior_case eval \
  'PRIOR_SAMPLE_LISTING="${PRIOR_SAMPLE_LISTING}
pr4109-rollback/prior-node running -"
   prior_sample_window'
check "a running prior attached to no network is quarantined" 0 \
  "no container built from the prior image was running and network-attached"

# And the reading that looks identical on the map alone: a prior holding
# another container's network stack owns no entry of its own, yet watches the
# same chain over the connections it borrowed.
# shellcheck disable=SC2016
run_verdict prior_case eval \
  'PRIOR_SAMPLE_LISTING="${PRIOR_SAMPLE_LISTING}
pr4109-rollback/prior-node running container:9fce2a1b7c4d"
   prior_sample_window'
check "a prior sharing another container's stack refutes the barrier" 1 \
  "pr4109-rollback/prior-node on container:9fce2a1b7c4d"

# shellcheck disable=SC2016
run_verdict prior_case eval \
  'PRIOR_SAMPLE_LISTING="${PRIOR_SAMPLE_LISTING}
stray-prior running host"
   prior_sample_window'
check "a prior on the host network refutes the barrier" 1 \
  "stray-prior on host"

# shellcheck disable=SC2016
run_verdict prior_case eval \
  'PRIOR_SAMPLE_LISTING="${PRIOR_SAMPLE_LISTING}
pr4109-rollback/prior-node unreadable -"
   prior_sample_window'
check "a prior whose state cannot be read is not a prior known down" 3 \
  "run state of pr4109-rollback/prior-node"

# This project's own prior service answering is still a refutation on its own,
# whatever the daemon believes about the container behind it.
run_verdict prior_case eval \
  'prior_sample_window
   PRIOR_DRAIN_SERVICE_SIGHTINGS=2'
check "this project's prior answering its port refutes the barrier" 1 \
  "answered on the rehearsal network in 2 of 3 samples"

# The vacuous pass: an enumeration returning nothing has an empty active set
# too, and an empty active set is what the barrier holding looks like.
run_verdict prior_case eval 'PRIOR_SAMPLE_LISTING=""
   prior_sample_window'
check "an enumeration blind to this project's staged prior blocks" 3 \
  "did not find this project's own staged prior container in 3 of 3 samples"

# shellcheck disable=SC2016
run_verdict prior_case eval \
  'prior_sample_window
   PRIOR_DRAIN_SAMPLES=$((PRIOR_DRAIN_SAMPLES + 1))
   PRIOR_DRAIN_UNREADABLE_SAMPLES=1'
check "a daemon that could not be enumerated proves no absence" 3 \
  "could not be enumerated in 1 of 4 samples"

run_verdict prior_case :
check "a window nothing sampled proves no absence" 3 \
  "no sample of the daemon was taken across the drain"

# The rollback drain, whose step is named "with work represented" and used to
# be decided by the stop command's exit status alone — a reading a fleet
# holding nothing produces just as readily as one draining real ceremonies.
drain_readings() {
  # shellcheck disable=SC2034
  ROLLBACK_DRIVER_SUPPLIED=1
  # shellcheck disable=SC2034
  ROLLBACK_DRIVER_RC=0
  # shellcheck disable=SC2034
  ROLLBACK_DRIVER_TX=3
  # Both classes of work in flight at once: a threshold round and a Bitcoin
  # wallet action, which fail differently when a shutdown interrupts them.
  # shellcheck disable=SC2034
  ROLLBACK_ORIGINATED="tbtc_signing tbtc_wallet_action"
  # shellcheck disable=SC2034
  ROLLBACK_INFLIGHT="2"
  # shellcheck disable=SC2034
  ROLLBACK_DRAIN_RC="0"
  # shellcheck disable=SC2034
  ROLLBACK_GRACE="20160"
}

drain_case() {
  drain_readings
  "$@"
  rollback_drain_verdict
}

run_verdict drain_case :
check "a drain over permits the driver originated and named holds" 0 \
  "while the fleet held 2 security-v2 permit\(s\)" \
  "threshold_ceremony and bitcoin_action both in flight"

# The reading the permit total could not carry: it counts ceremonies without
# distinguishing a threshold round from a wallet action, so a drain that only
# ever held one class reads identically to one that held both.
run_verdict drain_case eval 'ROLLBACK_ORIGINATED="tbtc_signing beacon_dkg"'
check "a drain holding no Bitcoin action authorizes no rollback over one" 3 \
  "nothing of class bitcoin_action"

run_verdict drain_case eval 'ROLLBACK_ORIGINATED="tbtc_wallet_action"'
check "a drain holding no threshold ceremony authorizes no rollback over one" \
  3 "nothing of class threshold_ceremony"

run_verdict drain_case eval 'ROLLBACK_ORIGINATED=""'
check "named transactions with no ceremony behind them say what drained" 3 \
  "no ceremony they originated"

# The reading the exit status could not tell apart from success: nothing was in
# flight, so a clean stop is a shutdown of idle processes.
run_verdict drain_case eval 'ROLLBACK_INFLIGHT="0"'
check "a clean stop of an idle fleet represents no work" 3 \
  "no R1 node held a security-v2 permit when the stop was issued"

run_verdict drain_case eval 'ROLLBACK_INFLIGHT="unreadable on r1-node-2"'
check "an unreadable in-flight count is not read as work in flight" 3 \
  "in-flight security-v2 permit count could not be read"

run_verdict drain_case eval 'ROLLBACK_DRIVER_SUPPLIED=0'
check "a drain with no driver behind it represents no originated work" 3 \
  "no PR4109_WORK_DRIVER was supplied"

run_verdict drain_case eval 'ROLLBACK_DRIVER_RC=5'
check "a failed driver leaves the fleet holding whatever it happened to" 3 \
  "work driver exited \[5\] originating the work this drain"

run_verdict drain_case eval 'ROLLBACK_DRIVER_TX=0'
check "a driver that named no transaction attributes no in-flight work" 3 \
  "named no transaction"

run_verdict drain_case eval 'ROLLBACK_DRAIN_RC="1"'
check "a drain that did not complete is not a quiescence" 1 \
  "termination grace exited \[1\] with 2 permit\(s\) in flight"

run_verdict drain_case eval 'ROLLBACK_DRAIN_RC="no exit status"'
check "a drain whose exit status was never observed is not a quiescence" 1 \
  "exited \[no exit status\]"

# Where the permits went, which neither the drain's exit status nor the audit's
# consistency verdict follows. An aggregate in-flight count describes the
# beginning of the drain; a fleet total of zero afterwards is equally produced
# by permits that finished and by processes that exited holding them, and the
# difference is exactly the state a rollback restores onto.
RECONCILE_STEP="every in-flight permit reconciles to completion or quarantine"
RECONCILE_ASSERTION="every permit held at the stop completes or is audited \
into quarantine"
RECONCILE_TX="0xdd44444444444444444444444444444444444444444444444444444444444444"
RECONCILE_TX2="0xee55555555555555555555555555555555555555555555555555555555555555"
RECONCILE_TX3="0xff66666666666666666666666666666666666666666666666666666666666666"
# The five permits, in the identity a gate scrape renders: the holder, the
# ceremony as the gate names it, the anchor the mode was pinned from, the chain
# work, and the local permit. Named once here because the per-node account and
# the expectations that quote it have to be the same five identities.
RECONCILE_SIGN1="r1-node-1@tbtc_signing@1000@sign1000#1"
RECONCILE_SIGN2="r1-node-2@tbtc_signing@1000@sign1000#2"
RECONCILE_ACTION1="r1-node-1@tbtc_signing@1001@action1001#wallet-a"
RECONCILE_ACTION2="r1-node-2@tbtc_signing@1001@action1001#wallet-b"
RECONCILE_SEED="r1-node-2@beacon_dkg@1002@seed1002#3"

# One node that drained everything it held, and one that also held a third
# piece of work and hit the deadline with its permit force-canceled and a
# quarantine record written for exactly that work.
#
# The unit throughout is the permit, not the ceremony: the signing and the
# wallet action each took a permit on both nodes, so five permits stand for
# three pieces of work, and it is the five that have to reconcile.
reconcile_readings() {
  # shellcheck disable=SC2034
  ROLLBACK_NODE_ACCOUNTS="r1-node-1 2 0 0
r1-node-2 3 1 0"
  # shellcheck disable=SC2034
  ROLLBACK_NODE_QUARANTINES="r1-node-1 none
r1-node-2 beacon_dkg@1002@seed1002#3"
  # What this gate put in flight, which node took a permit for each piece of
  # it, and what the driver saw become of it once the drain was over. A permit
  # that was not force-canceled is completed only if the work behind that
  # permit actually ended.
  # shellcheck disable=SC2034
  ROLLBACK_ORIGINATED="tbtc_signing tbtc_wallet_action beacon_dkg"
  # shellcheck disable=SC2034
  ROLLBACK_ORIGINATED_WORK="\
tbtc_signing@1000@sign1000=${RECONCILE_TX}=r1-node-1~1 \
tbtc_signing@1000@sign1000=${RECONCILE_TX}=r1-node-2~2 \
tbtc_wallet_action@1001@action1001=${RECONCILE_TX2}=r1-node-1~wallet-a \
tbtc_wallet_action@1001@action1001=${RECONCILE_TX2}=r1-node-2~wallet-b \
beacon_dkg@1002@seed1002=${RECONCILE_TX3}=r1-node-2~3"
  # shellcheck disable=SC2034
  ROLLBACK_TERMINAL_ASKED=1
  # shellcheck disable=SC2034
  ROLLBACK_TERMINAL_RC=0
  # shellcheck disable=SC2034
  ROLLBACK_TERMINAL="\
tbtc_signing@1000@sign1000=succeeded=${RECONCILE_TX}=0xsigned \
tbtc_wallet_action@1001@action1001=failed=${RECONCILE_TX2}=retry_exhausted"
  # What each node recorded about the permits it let go of, sampled inside the
  # drain window. The wallet action ran out of retries, which its holders
  # recorded as such; the beacon permit is the one force-canceled at the
  # deadline, and its holder recorded the quarantine the audit also wrote.
  # shellcheck disable=SC2034
  ROLLBACK_NODE_ENDINGS="r1-node-1 \
${RECONCILE_SIGN1}=completed=bitcoin_transaction=0xsigned=-=1=1=- \
${RECONCILE_ACTION1}=exhausted=no_threshold=-=-=-=-=-
r1-node-2 ${RECONCILE_SIGN2}=completed=bitcoin_transaction=0xsigned=-=1=1=- \
${RECONCILE_ACTION2}=exhausted=no_threshold=-=-=-=-=- \
${RECONCILE_SEED}=quarantined=quarantined_beacon_signer=-=-=-=-=-"
}

reconcile_case() {
  reconcile_readings
  "$@"
  rollback_reconciliation_verdict "${RECONCILE_STEP}" "${RECONCILE_ASSERTION}"
}

run_verdict reconcile_case :
check "permits that completed or were audited into quarantine reconcile" 0 \
  "4 completed with the holding node observed without them" \
  "tbtc_signing@1000@sign1000 \(${RECONCILE_TX}, 0xsigned\), \
tbtc_wallet_action@1001@action1001=failed" \
  "holding node recording an ending of its own for every permit it let go of" \
  "and 1 were force-canceled"

# The regression this whole accounting exists for: the permits outnumber the
# work behind them, so one reported outcome stands in for however many permits
# happen to be outstanding. Five permits over three pieces of work reconcile;
# seven do not, and no aggregate count can tell the two apart.
run_verdict reconcile_case eval 'ROLLBACK_NODE_ACCOUNTS="r1-node-1 2 0 0
r1-node-2 5 1 0"'
check "one outcome cannot stand in for permits nobody attributed work to" 3 \
  "r1-node-2 held 5 permit\(s\) for 3 piece\(s\) of work"

run_verdict reconcile_case eval 'ROLLBACK_NODE_ACCOUNTS="r1-node-1 1 0 0
r1-node-2 3 1 0"'
check "fewer permits than the work put on a node reconciles neither" 3 \
  "r1-node-1 held 1 permit\(s\) for 2 piece\(s\) of work"

# A quarantine record for work this drain never put on that node is state from
# somewhere else standing in for the permits being followed.
run_verdict reconcile_case eval 'ROLLBACK_NODE_QUARANTINES="r1-node-1 none
r1-node-2 beacon_relay_signing@77@other#9"'
check "a quarantine record for work the node never held accounts for none" 1 \
  "r1-node-2 quarantined beacon_relay_signing@77@other#9"

# And its mirror: an outcome for a ceremony this gate never originated.
run_verdict reconcile_case eval \
  "ROLLBACK_TERMINAL=\"\
tbtc_signing@1000@sign1000=succeeded=${RECONCILE_TX}=0xsigned \
tbtc_wallet_action@1001@action1001=failed=${RECONCILE_TX2}=retry_exhausted \
beacon_signing@9999@elsewhere=succeeded=${RECONCILE_TX3}=0xelsewhere\""
check "an outcome for work this drain never originated reconciles nothing" 3 \
  "terminal outcomes for beacon_signing@9999@elsewhere, which this drain never \
originated with those transactions"

# The same work identity on an unrelated transaction is somebody else's
# outcome even when the ceremony and anchor happen to line up.
run_verdict reconcile_case eval \
  "ROLLBACK_TERMINAL=\"\
tbtc_signing@1000@sign1000=succeeded=${RECONCILE_TX3}=0xother \
tbtc_wallet_action@1001@action1001=failed=${RECONCILE_TX2}=retry_exhausted\""
check "rollback preserves each originated transaction through settlement" 3 \
  "tbtc_signing@1000@sign1000 .* originated as ${RECONCILE_TX}" \
  "substituting a different transaction reconciles none"

# A driver that printed a readable report and then failed has looked at part of
# the chain; the permits it did not reach reconcile against nothing.
run_verdict reconcile_case eval 'ROLLBACK_TERMINAL_RC=3'
check "a terminal report from a driver that failed accounts for no permit" 3 \
  "work driver exited \[3\] reporting what became of the drained work"

run_verdict reconcile_case eval 'ROLLBACK_ORIGINATED_WORK=""'
check "permits nobody identified the work for reconcile nothing" 3 \
  "the driver named no identified work for the drain"

# The half of this reconciliation the driver cannot supply. Everything above
# decides on the driver's account of ceremonies it started, and a permit whose
# process went down holding it produces the same account as one that finished.
run_verdict reconcile_case eval \
  'ROLLBACK_NODE_ENDINGS="r1-node-1 unread
r1-node-2 unread"'
check "a node never asked about its own permits vouches for none of them" 3 \
  "never asked what became of the permits"

run_verdict reconcile_case eval \
  'ROLLBACK_NODE_ENDINGS="r1-node-1 none
r1-node-2 none"'
check "a node that recorded no ending at all vouches for none of them" 3 \
  "recorded no ending for r1-node-1@tbtc_signing@1000@sign1000#1"

# The partial population: a node accounts for one of the permits it held and
# never mentions the other, which is also what eviction from a bounded account
# looks like.
# shellcheck disable=SC2016
run_verdict reconcile_case eval \
  'ROLLBACK_NODE_ENDINGS="r1-node-1 ${RECONCILE_SIGN1}=completed\
=bitcoin_transaction=0xsigned=-=1=1=-
r1-node-2 ${RECONCILE_SIGN2}=completed=bitcoin_transaction=0xsigned=-=1=1=- \
${RECONCILE_ACTION2}=exhausted=no_threshold=-=-=-=-=- ${RECONCILE_SEED}\
=quarantined=quarantined_beacon_signer=-=-=-=-=-"'
check "a permit its holder never accounted for is not reconciled" 3 \
  "recorded no ending for r1-node-1@tbtc_signing@1001@action1001#wallet-a"

# shellcheck disable=SC2016
run_verdict reconcile_case eval \
  'ROLLBACK_NODE_ENDINGS="r1-node-1 ${RECONCILE_SIGN1}=completed\
=bitcoin_transaction=0xsigned=-=1=1=- \
${RECONCILE_ACTION1}=exhausted=no_threshold=-=-=-=-=- ${RECONCILE_SIGN1}\
=exhausted=no_threshold=-=-=-=-=-
r1-node-2 ${RECONCILE_SIGN2}=completed=bitcoin_transaction=0xsigned=-=1=1=- \
${RECONCILE_ACTION2}=exhausted=no_threshold=-=-=-=-=- ${RECONCILE_SEED}\
=quarantined=quarantined_beacon_signer=-=-=-=-=-"'
check "a drained permit ending twice cannot be read as either ending" 3 \
  "more than one ending for r1-node-1@tbtc_signing@1000@sign1000#1"

# The reading this whole rung exists for: the driver reports the ceremony
# ending, and the node that held the permit says its owner recorded nothing —
# which is what a process going down holding a permit writes.
# shellcheck disable=SC2016
run_verdict reconcile_case eval \
  'ROLLBACK_NODE_ENDINGS="r1-node-1 ${RECONCILE_SIGN1}=unresolved=-=-=-=-=-=- \
${RECONCILE_ACTION1}=exhausted=no_threshold=-=-=-=-=-
r1-node-2 ${RECONCILE_SIGN2}=completed=bitcoin_transaction=0xsigned=-=1=1=- \
${RECONCILE_ACTION2}=exhausted=no_threshold=-=-=-=-=- ${RECONCILE_SEED}\
=quarantined=quarantined_beacon_signer=-=-=-=-=-"'
check "a permit whose owner recorded nothing is not restorable state" 1 \
  "r1-node-1@tbtc_signing@1000@sign1000#1=unresolved"

# What the reconciliation reads a quarantine record off, and the reason it is
# read with an instant rather than counted. A quarantine namespace accumulates:
# the records an earlier interruption wrote are still in it, and a count of
# whatever it holds lets state from a run nobody is reconciling stand in for
# permits this drain abandoned.
QUARANTINE_MANIFEST="${WORK}/quarantine-manifest.json"
DRAIN_INSTANT="2026-07-28T12:00:00.000Z"

write_quarantine_manifest() {
  cat >"${QUARANTINE_MANIFEST}"
}

check_quarantine() {
  local name="$1" want="$2" got
  got="$(audit_quarantine_records "${QUARANTINE_MANIFEST}" "${DRAIN_INSTANT}")"
  if [[ "${got}" == "${want}" ]]; then
    printf 'ok   %s\n' "${name}"
    PASS=$((PASS + 1))
  else
    printf 'FAIL %s: got [%s], want [%s]\n' "${name}" "${got}" "${want}"
    FAILED=$((FAILED + 1))
  fi
}

write_quarantine_manifest <<'EOF'
{"beacon_quarantined_outputs":[
  {"ceremony":"beacon_dkg","canonical_start_block":1002,
   "seed_hash":"seed1002","member_index":3,
   "preserved_at":"2026-07-28T12:04:10.500Z"}],
 "tbtc_quarantined_outputs":[
  {"ceremony":"tbtc_signing","canonical_start_block":1000,
   "seed_hash":"sign1000","member_index":2,
   "preserved_at":"2026-07-28T12:04:11.000Z"}]}
EOF
check_quarantine "records this drain wrote are read with their work identity" \
  "beacon_dkg@1002@seed1002#3,tbtc_signing@1000@sign1000#2"

# The regression the instant exists for.
write_quarantine_manifest <<'EOF'
{"beacon_quarantined_outputs":[
  {"ceremony":"beacon_dkg","canonical_start_block":77,
   "seed_hash":"stale77","member_index":1,
   "preserved_at":"2026-07-27T09:00:00.000Z"}]}
EOF
check_quarantine "a record an earlier interruption left behind is not this \
drain's" "none"

write_quarantine_manifest <<'EOF'
{"beacon_quarantined_outputs":[
  {"ceremony":"beacon_dkg","canonical_start_block":77,
   "seed_hash":"stale77","member_index":1,
   "preserved_at":"2026-07-27T09:00:00.000Z"},
  {"ceremony":"beacon_dkg","canonical_start_block":1002,
   "seed_hash":"seed1002","member_index":3,
   "preserved_at":"2026-07-28T12:04:10.500Z"}]}
EOF
check_quarantine "a stale record beside a fresh one accounts only for the \
fresh one" "beacon_dkg@1002@seed1002#3"

# A record nobody could read authorizes nothing, and must not subtract like an
# absence: an unreadable manifest is not a manifest holding no records.
write_quarantine_manifest <<'EOF'
{"beacon_quarantined_outputs":[
  {"ceremony":"beacon_dkg","canonical_start_block":1002}]}
EOF
check_quarantine "a record with no preservation time is unreadable" \
  "unreadable"

write_quarantine_manifest <<'EOF'
{"beacon_quarantined_outputs":[
  {"canonical_start_block":1002,"seed_hash":"seed1002","member_index":3,
   "preserved_at":"2026-07-28T12:04:10.500Z"}]}
EOF
check_quarantine "a record naming no ceremony is unreadable" "unreadable"

write_quarantine_manifest <<'EOF'
{"beacon_quarantined_outputs":[
  {"ceremony":"beacon_dkg","seed_hash":"seed1002","member_index":3,
   "preserved_at":"2026-07-28T12:04:10.500Z"}]}
EOF
check_quarantine "a record naming no anchor is unreadable" "unreadable"

write_quarantine_manifest <<'EOF'
{not a manifest
EOF
check_quarantine "a manifest that cannot be parsed is unreadable" "unreadable"

write_quarantine_manifest <<'EOF'
{"schema_version":1}
EOF
check_quarantine "a manifest with no quarantine namespace holds no record" \
  "none"

rm -f "${QUARANTINE_MANIFEST}"
check_quarantine "a manifest that is not there is unreadable" "unreadable"

# The regression this step exists for: the fleet total went to zero because a
# node exited holding its permits, which no aggregate count distinguishes from
# a node that finished them.
run_verdict reconcile_case eval 'ROLLBACK_NODE_ACCOUNTS="r1-node-1 2 0 0
r1-node-2 3 0 2"'
check "a node that stopped holding permits reconciles nothing" 1 \
  "r1-node-2 stopped holding 2 of 3 permit\(s\)" \
  "went down with the process"

# A force-cancel the audit never wrote a record for is in-flight state the
# rollback would restore onto with nothing describing it. "none" is a manifest
# that was read and holds nothing this drain produced — a record an earlier
# interruption left behind is not this drain's force-cancel being accounted
# for, which is exactly what a bare count of the namespace would have taken it
# for.
run_verdict reconcile_case eval 'ROLLBACK_NODE_QUARANTINES="r1-node-1 none
r1-node-2 none"'
check "a force-canceled permit with no quarantine record refutes the step" 1 \
  "r1-node-2 \(1 force-canceled, no quarantine record\)"

run_verdict reconcile_case eval 'ROLLBACK_NODE_QUARANTINES="r1-node-1 none
r1-node-2 unreadable"'
check "an unreadable audit manifest audits no quarantine" 1 \
  "quarantine records unreadable"

# The regression this rung exists for: a record was present, so the step used
# to accept it however many permits the gate had abandoned. One record does not
# describe three permits, and the difference is in-flight state the rollback
# restores onto with nothing accounting for it.
run_verdict reconcile_case eval 'ROLLBACK_NODE_ACCOUNTS="r1-node-1 2 0 0
r1-node-2 3 2 0"'
check "one quarantine record does not account for two force-cancels" 1 \
  "r1-node-2 \(2 force-canceled, only 1 quarantine record"

# And the reading a gauge cannot carry: the permits are gone, but nothing says
# the work behind them ended rather than the process holding it exiting.
run_verdict reconcile_case eval 'ROLLBACK_TERMINAL_ASKED=0
   ROLLBACK_TERMINAL=""'
check "a gauge that fell with nothing asked of the driver is not completion" \
  3 "the driver was never asked what became of the work behind the permits"

# The regression this rung exists for. Three pieces of work were in flight and
# one outcome came back: the permits behind the other two used to be counted as
# completed because a ceremony *of that name* had ended somewhere.
run_verdict reconcile_case eval \
  "ROLLBACK_TERMINAL=\"\
tbtc_signing@1000@sign1000=succeeded=${RECONCILE_TX}=0xsigned\""
check "work the driver never accounted for reconciles nothing" 3 \
  "r1-node-1 held a permit for tbtc_wallet_action@1001@action1001#wallet-a" \
  "r1-node-2 held a permit for tbtc_wallet_action@1001@action1001#wallet-b"

# An unreadable counter must not subtract like a zero; that is how a permit
# nobody could account for disappears from a reconciliation.
run_verdict reconcile_case eval 'ROLLBACK_NODE_ACCOUNTS="r1-node-1 2 0 0
r1-node-2 unreadable 1 0"'
check "a permit count nobody could read reconciles nothing" 3 \
  "held unreadable"

run_verdict reconcile_case eval 'ROLLBACK_NODE_ACCOUNTS="r1-node-1 2 0 0
r1-node-2 3 unreadable 0"'
check "an unreadable forced-abort delta reconciles nothing" 3 \
  "forced unreadable"

# More force-cancels than permits held: the two counters describe different
# populations and nothing can be followed from one to the other.
run_verdict reconcile_case eval 'ROLLBACK_NODE_ACCOUNTS="r1-node-1 2 0 0
r1-node-2 1 3 0"'
check "more force-cancels than permits held closes no accounting" 3 \
  "force-canceled 3 of 1 held"

run_verdict reconcile_case eval 'ROLLBACK_NODE_ACCOUNTS=""'
check "a drain nobody accounted for reconciles nothing" 3 \
  "no R1 node's permit accounting was captured"

# The homogeneous positive control, which used to be decided by two permit
# counters — neither of which is either half of the property it names. A permit
# says a node was allowed to begin, not that a ceremony finished; and the
# legacy permit counter is about work this fleet took on, not about whether it
# saw a legacy peer.
# The chain identifiers this control's ceremonies are bound to. A control
# decided on a bare list of outcomes accepts them detached from the
# transactions that started them and from any threshold output at all.
HOM_TX1="0xaa11111111111111111111111111111111111111111111111111111111111111"
HOM_TX2="0xbb22222222222222222222222222222222222222222222222222222222222222"
HOM_TX3="0xcc33333333333333333333333333333333333333333333333333333333333333"
HOM_SIG1="0xsig1abc"
HOM_SIG2="0xsig2def"
# The work identities those ceremonies carry: ceremony, the block the permit
# pinned its mode from, and the chain-native identity of the request behind it.
# A bare ceremony name is not one — two runs of the same ceremony share it — and
# the driver report this control reads cannot produce one.
HOM_SIGNING="tbtc_signing@1200@sign1200"
HOM_BEACON="beacon_dkg@1201@bdkg1201"

homogeneous_readings() {
  # shellcheck disable=SC2034
  HOMOGENEOUS_DRIVER_SUPPLIED=1
  # shellcheck disable=SC2034
  HOMOGENEOUS_DRIVER_RC=0
  # shellcheck disable=SC2034
  HOMOGENEOUS_TX=2
  # shellcheck disable=SC2034
  HOMOGENEOUS_RESULTS="tbtc_signing=succeeded beacon_dkg=succeeded"
  # shellcheck disable=SC2034
  HOMOGENEOUS_BOUND="${HOM_SIGNING}=succeeded=${HOM_TX1}=${HOM_SIG1} \
${HOM_BEACON}=succeeded=${HOM_TX2}=${HOM_SIG2}"
  # The permits the fleet's gate issued for that work and what their holders
  # recorded when they closed. Without these the control decides entirely on
  # the report of the party that drove the ceremonies.
  # shellcheck disable=SC2034
  HOMOGENEOUS_ORIGINATED="${HOM_SIGNING}=${HOM_TX1}=r1-node-1~1 \
${HOM_BEACON}=${HOM_TX2}=r1-node-1~1"
  # shellcheck disable=SC2034
  HOMOGENEOUS_AUTHORED_ENDINGS="\
r1-node-1@tbtc_signing@1200@sign1200#1=completed=bitcoin_transaction\
=${HOM_SIG1}=-=1=1=- \
r1-node-1@beacon_dkg@1201@bdkg1201#1=completed=persisted_beacon_signer\
=${HOM_SIG2}=1=-=-=-"
  # shellcheck disable=SC2034
  HOMOGENEOUS_PERMITS_BEFORE="20"
  # shellcheck disable=SC2034
  HOMOGENEOUS_PERMITS_AFTER="24"
  # shellcheck disable=SC2034
  HOMOGENEOUS_LEGACY_BEFORE="3"
  # shellcheck disable=SC2034
  HOMOGENEOUS_LEGACY_AFTER="3"
  # shellcheck disable=SC2034
  HOMOGENEOUS_SIGHTINGS_BEFORE="5"
  # shellcheck disable=SC2034
  HOMOGENEOUS_SIGHTINGS_AFTER="5"
  # shellcheck disable=SC2034
  HOMOGENEOUS_NEW_OPERATORS=""
}

homogeneous_case() {
  homogeneous_readings
  "$@"
  homogeneous_control_verdict
}

run_verdict homogeneous_case :
check "post-C ceremonies that completed under security-v2 hold the control" 0 \
  "settled ${HOM_SIGNING} \(${HOM_TX1}, ${HOM_SIG1}\)" \
  "${HOM_BEACON} \(${HOM_TX2}, ${HOM_SIG2}\)" \
  "recorded r1-node-1@tbtc_signing@1200@sign1200#1=completed" \
  "recognized no cross-format peer"

# The half a permit counter cannot carry: work was allowed to start and
# nothing was observed finishing.
run_verdict homogeneous_case eval 'HOMOGENEOUS_RESULTS=""
   HOMOGENEOUS_BOUND=""'
check "permits without a completed ceremony are not a positive control" 3 \
  "named no ceremony that completed successfully"

# The regression this seam exists for: a report is taken whole. One half of the
# release failing outright used to be dropped on the way to the verdict, and
# the half that passed recorded the control on its own.
run_verdict homogeneous_case eval \
  "HOMOGENEOUS_RESULTS='tbtc_signing=succeeded beacon_dkg=failed'
   HOMOGENEOUS_BOUND='${HOM_SIGNING}=succeeded=${HOM_TX1}=${HOM_SIG1} \
${HOM_BEACON}=failed=${HOM_TX2}=no_threshold'"
check "a required ceremony failing beside a passing one refutes the control" \
  1 "reported beacon_dkg=failed" "cannot be read off the subset"

run_verdict homogeneous_case eval \
  "HOMOGENEOUS_RESULTS='tbtc_signing=succeeded beacon_dkg=succeeded \
tbtc_wallet_action=timed_out'
   HOMOGENEOUS_BOUND='${HOM_SIGNING}=succeeded=${HOM_TX1}=${HOM_SIG1} \
${HOM_BEACON}=succeeded=${HOM_TX2}=${HOM_SIG2} \
tbtc_wallet_action@1202@act1202=timed_out=${HOM_TX3}=retry_exhausted'"
check "a ceremony that timed out beside the controls refutes them" 1 \
  "tbtc_wallet_action=timed_out"

# Both halves of the release take their permits from the same gate through
# different call paths, so a driver that only ever drove one of them leaves the
# other unexercised however many times it succeeded.
run_verdict homogeneous_case eval \
  "HOMOGENEOUS_RESULTS='tbtc_signing=succeeded tbtc_dkg=succeeded'
   HOMOGENEOUS_BOUND='${HOM_SIGNING}=succeeded=${HOM_TX1}=${HOM_SIG1} \
tbtc_dkg@1201@dkg1201=succeeded=${HOM_TX2}=${HOM_SIG2}'"
check "a control that drove only tBTC says nothing about the beacon" 3 \
  "nothing from the beacon half of the release"

run_verdict homogeneous_case eval \
  "HOMOGENEOUS_RESULTS='beacon_dkg=succeeded beacon_signing=succeeded'
   HOMOGENEOUS_BOUND='beacon_dkg@1200@bdkg1200=succeeded=${HOM_TX1}=${HOM_SIG1} \
beacon_signing@1201@entry1201=succeeded=${HOM_TX2}=${HOM_SIG2}'"
check "a control that drove only the beacon says nothing about tBTC" 3 \
  "nothing from the tbtc half of the release"

# The half the legacy permit counter cannot carry: the fleet saw a legacy peer
# while claiming to be homogeneous.
run_verdict homogeneous_case eval 'HOMOGENEOUS_SIGHTINGS_AFTER="6"'
check "a cross-format sighting refutes a control that denies them" 1 \
  "recognized 1 cross-format peer\(s\)"

run_verdict homogeneous_case eval 'HOMOGENEOUS_SIGHTINGS_AFTER=""'
check "an unreadable sighting counter observes no absence of sightings" 3 \
  "cross-format sighting counter could not be read"

run_verdict homogeneous_case eval \
  'HOMOGENEOUS_NEW_OPERATORS="0x1111111111111111111111111111111111111111"'
check "a legacy roster entry refutes a control that denies them" 1 \
  "cannot produce a legacy roster entry"

run_verdict homogeneous_case eval 'HOMOGENEOUS_PERMITS_AFTER="20"'
check "ceremonies that took no permit from this fleet are not its ceremonies" \
  1 "issued no new security-v2 permit"

run_verdict homogeneous_case eval 'HOMOGENEOUS_LEGACY_AFTER="4"'
check "a legacy permit taken alongside refutes the control" 1 \
  "1 new legacy permit"

run_verdict homogeneous_case eval 'HOMOGENEOUS_TX=0'
check "a driver that named no transaction attributes no permit activity" 3 \
  "reported no transaction"

run_verdict homogeneous_case eval 'HOMOGENEOUS_DRIVER_RC=2'
check "a failed driver originates no post-C ceremony" 1 \
  "work driver exited \[2\] originating post-C ceremonies"

run_verdict homogeneous_case eval 'HOMOGENEOUS_DRIVER_SUPPLIED=0'
check "no driver leaves the positive control with nothing to observe" 3 \
  "no PR4109_WORK_DRIVER was supplied"

run_verdict homogeneous_case eval 'HOMOGENEOUS_PERMITS_AFTER="unreadable"'
check "unreadable permit counters observe no mode at all" 3 \
  "fleet permit counters could not be read"

# The half of this control that is not the driver's own account. A positive
# control's claim is that a fleet past C finishes work, and everything above
# reads that claim off the report of the party that drove it.
run_verdict homogeneous_case eval 'HOMOGENEOUS_ORIGINATED=""'
check "settled ceremonies naming no holder identify no security-v2 permit" 3 \
  "named no node holding a permit"

run_verdict homogeneous_case eval \
  'HOMOGENEOUS_AUTHORED_ENDINGS="unreadable on r1-node-2"'
check "a post-C fleet that cannot be asked has vouched for nothing" 3 \
  "could not be asked what became of the permits"

# shellcheck disable=SC2016
run_verdict homogeneous_case eval \
  'HOMOGENEOUS_AUTHORED_ENDINGS="\
r1-node-1@tbtc_signing@1200@sign1200#1=completed=bitcoin_transaction\
=${HOM_SIG1}=-=1=1=-"'
check "a post-C settlement no node vouched for is not finished work" 3 \
  "no node recorded an ending for r1-node-1@beacon_dkg@1201@bdkg1201#1"

# shellcheck disable=SC2016
run_verdict homogeneous_case eval \
  'HOMOGENEOUS_AUTHORED_ENDINGS="${HOMOGENEOUS_AUTHORED_ENDINGS} \
r1-node-1@beacon_dkg@1201@bdkg1201#1=exhausted"'
check "a post-C permit ending twice cannot be read as either ending" 3 \
  "more than one node-authored record"

run_verdict homogeneous_case eval \
  'HOMOGENEOUS_AUTHORED_ENDINGS="r1-node-1@tbtc_signing@1200@sign1200#1=completed \
r1-node-1@beacon_dkg@1201@bdkg1201#1=unresolved=-=-=-=-=-=-"'
check "a post-C settlement whose holder recorded nothing stands on nothing" 1 \
  "closed the permit without recording" "r1-node-1@beacon_dkg@1201@bdkg1201#1=unresolved"

# shellcheck disable=SC2016
run_verdict homogeneous_case eval \
  'HOMOGENEOUS_AUTHORED_ENDINGS="\
r1-node-1@tbtc_signing@1200@sign1200#1=completed=bitcoin_transaction\
=${HOM_SIG1}=-=1=1=- \
r1-node-1@beacon_dkg@1201@bdkg1201#1=exhausted=no_threshold=-=-=-=-=-"'
check "a post-C settlement the holder recorded as exhausted is refused" 1 \
  "r1-node-1@beacon_dkg@1201@bdkg1201#1=exhausted"

# Quarantine closes a permit too, and a control whose whole job is to show a
# post-C fleet finishing work cannot be satisfied by one that stopped.
run_verdict homogeneous_case eval \
  'HOMOGENEOUS_AUTHORED_ENDINGS="r1-node-1@tbtc_signing@1200@sign1200#1=completed \
r1-node-1@beacon_dkg@1201@bdkg1201#1=quarantined=quarantined_beacon_signer\
=-=-=-=-=-"'
check "a quarantined post-C permit is not a completed ceremony" 1 \
  "r1-node-1@beacon_dkg@1201@bdkg1201#1=quarantined"

# shellcheck disable=SC2016
run_verdict homogeneous_case eval \
  'HOMOGENEOUS_BOUND="${HOMOGENEOUS_BOUND} \
tbtc_heartbeat@1202@beat1202=succeeded=${HOM_TX3}=0xbeat1202"'
check "a post-C outcome for work never originated here is not evidence" 1 \
  "tbtc_heartbeat@1202@beat1202"

# shellcheck disable=SC2016
run_verdict homogeneous_case eval \
  'HOMOGENEOUS_ORIGINATED="${HOMOGENEOUS_ORIGINATED} \
tbtc_heartbeat@1202@beat1202=${HOM_TX3}=r1-node-1~2"
   HOMOGENEOUS_AUTHORED_ENDINGS="${HOMOGENEOUS_AUTHORED_ENDINGS} \
r1-node-1@tbtc_heartbeat@1202@beat1202#2=completed=protocol_result=0xbeat1202\
=-=1=1=-"'
check "post-C work the driver never reported on leaves a gap" 3 \
  "no outcome at all for tbtc_heartbeat@1202@beat1202#2"

# ----------------------------------------------------------------------------

# The pre-cutover mixed-fleet controls, which are the post-C control's claim
# inverted: legacy permits must be the ones issued, security-v2 must not
# appear, and the prior binary has to be on the network while it happens.
PRE_TX1="0xdd44444444444444444444444444444444444444444444444444444444444444"
PRE_TX2="0xee55555555555555555555555555555555555555555555555555555555555555"

precutover_readings() {
  # shellcheck disable=SC2034
  PRECUTOVER_DRIVER_SUPPLIED=1
  # shellcheck disable=SC2034
  PRECUTOVER_DRIVER_RC=0
  # shellcheck disable=SC2034
  PRECUTOVER_TX=2
  # shellcheck disable=SC2034
  PRECUTOVER_RESULTS="tbtc_dkg=succeeded tbtc_signing=succeeded \
tbtc_heartbeat=succeeded tbtc_wallet_action=succeeded beacon_dkg=succeeded \
beacon_signing=succeeded"
  # Every ceremony the pre-cutover mandate names, each settled on a transaction
  # the driver originated. A step that named only a family or a work class
  # would be satisfied by a subset of these.
  # shellcheck disable=SC2034
  PRECUTOVER_BOUND="tbtc_wallet_action@840@wallet840=succeeded=${PRE_TX1}=0xbtc840 \
beacon_signing@841@entry841=succeeded=${PRE_TX2}=0xentry841 \
tbtc_dkg@842@dkg842=succeeded=${PRE_TX1}=0xdkg842 \
tbtc_signing@843@sign843=succeeded=${PRE_TX1}=0xsign843 \
tbtc_heartbeat@844@beat844=succeeded=${PRE_TX1}=0xbeat844 \
beacon_dkg@845@bdkg845=succeeded=${PRE_TX2}=0xbdkg845"
  # Who each settled transcript incorporated. Both releases took part in every
  # required ceremony, which is the whole subject of a mixed prior/R1 control:
  # each ceremony is its own path into the gate, so interoperation on one of
  # them is not interoperation on the next.
  # shellcheck disable=SC2034
  PRECUTOVER_CONTRIBUTORS="\
tbtc_wallet_action@840@wallet840=r1-node-1~1 \
tbtc_wallet_action@840@wallet840=prior-node~7 \
beacon_signing@841@entry841=r1-node-1~1 \
beacon_signing@841@entry841=prior-node~7 \
tbtc_dkg@842@dkg842=r1-node-1~1 \
tbtc_dkg@842@dkg842=prior-node~7 \
tbtc_signing@843@sign843=r1-node-1~1 \
tbtc_signing@843@sign843=prior-node~7 \
tbtc_heartbeat@844@beat844=r1-node-1~1 \
tbtc_heartbeat@844@beat844=prior-node~7 \
beacon_dkg@845@bdkg845=r1-node-1~1 \
beacon_dkg@845@bdkg845=prior-node~7"
  # The permits this fleet's gate issued for that work, one record per local
  # permit, and what the node holding each one recorded when it closed. The
  # settlements above are the driver's account of its own ceremonies; these are
  # the gate's account of the permits they ran under and the holders' account
  # of how each ended.
  # shellcheck disable=SC2034
  PRECUTOVER_ORIGINATED="\
tbtc_wallet_action@840@wallet840=${PRE_TX1}=r1-node-1~1 \
beacon_signing@841@entry841=${PRE_TX2}=r1-node-1~1 \
tbtc_dkg@842@dkg842=${PRE_TX1}=r1-node-1~1 \
tbtc_signing@843@sign843=${PRE_TX1}=r1-node-1~1 \
tbtc_heartbeat@844@beat844=${PRE_TX1}=r1-node-1~1 \
beacon_dkg@845@bdkg845=${PRE_TX2}=r1-node-1~1"
  # shellcheck disable=SC2034
  PRECUTOVER_AUTHORED_ENDINGS="\
r1-node-1@tbtc_signing@840@wallet840#1=completed=bitcoin_transaction=0xbtc840\
=-=1,7=1=- \
r1-node-1@beacon_relay_signing@841@entry841#1=completed=protocol_result\
=0xentry841=-=-=-=- \
r1-node-1@tbtc_dkg@842@dkg842#1=completed=persisted_tbtc_signer=0xdkg842=1\
=1,7=1=- \
r1-node-1@tbtc_signing@843@sign843#1=completed=bitcoin_transaction=0xsign843\
=-=1,7=1=- \
r1-node-1@tbtc_heartbeat@844@beat844#1=completed=protocol_result=0xbeat844=-\
=1,7=1=- \
r1-node-1@beacon_dkg@845@bdkg845#1=completed=persisted_beacon_signer\
=0xbdkg845=1=-=-=-"
  # shellcheck disable=SC2034
  PRECUTOVER_PRIOR_RUNNING=1
  # shellcheck disable=SC2034
  PRECUTOVER_STATES=""
  # shellcheck disable=SC2034
  PRECUTOVER_LEGACY_BEFORE="2"
  # shellcheck disable=SC2034
  PRECUTOVER_LEGACY_AFTER="6"
  # shellcheck disable=SC2034
  PRECUTOVER_SECURITY_BEFORE="0"
  # shellcheck disable=SC2034
  PRECUTOVER_SECURITY_AFTER="0"
  # shellcheck disable=SC2034
  PRECUTOVER_SIGHTINGS_BEFORE="4"
  # shellcheck disable=SC2034
  PRECUTOVER_SIGHTINGS_AFTER="4"
  # shellcheck disable=SC2034
  CUTOVER_BLOCK="1000000"
}

precutover_case() {
  precutover_readings
  "$@"
  precutover_verdict \
    "representative pre-cutover work including the longest wallet action" \
    "" "${PRECUTOVER_REQUIRED_CEREMONIES} tbtc_wallet_action" \
    "representative pre-cutover work"
}

run_verdict precutover_case :
check "legacy-anchored work settling beside the prior binary holds" 0 \
  "issued 4 new legacy permits" \
  "no security-v2 permit" \
  "tbtc_wallet_action@840@wallet840 \(${PRE_TX1}, 0xbtc840\)" \
  "recognized no cross-format peer"

# The step is named for a mixed fleet, and a fleet with one release on it is
# not one however well its own work went.
run_verdict precutover_case eval 'PRECUTOVER_PRIOR_RUNNING=0'
check "R1 working alone is not a mixed prior/R1 control" 3 \
  "prior binary.*was not running"

# A running container is not a participating release. Unselected, partitioned,
# and cryptographically excluded all leave the prior node up beside ceremonies
# that settled without it, which is the reading interoperation produces too.
run_verdict precutover_case eval 'PRECUTOVER_CONTRIBUTORS=""'
check "a running prior binary that contributed nothing is not interop" 3 \
  "took no part in those results"

# Half the release interoperating is not the release interoperating: a prior
# binary in the tBTC transcripts says nothing about the beacon path into the
# gate, which is a separate call path with its own wire format.
run_verdict precutover_case eval '
  PRECUTOVER_CONTRIBUTORS="\
tbtc_wallet_action@840@wallet840=r1-node-1~1 \
tbtc_wallet_action@840@wallet840=prior-node~7 \
tbtc_dkg@842@dkg842=r1-node-1~1 \
tbtc_dkg@842@dkg842=prior-node~7 \
tbtc_signing@843@sign843=r1-node-1~1 \
tbtc_signing@843@sign843=prior-node~7 \
tbtc_heartbeat@844@beat844=r1-node-1~1 \
tbtc_heartbeat@844@beat844=prior-node~7 \
beacon_signing@841@entry841=r1-node-1~1 \
beacon_dkg@845@bdkg845=r1-node-1~1"'
check "a prior binary in one family alone does not cover the release" 3 \
  "no beacon_dkg beacon_signing transcript incorporated a share"

# The mirror on the other half, so neither family is covered by accident.
run_verdict precutover_case eval '
  PRECUTOVER_CONTRIBUTORS="\
tbtc_wallet_action@840@wallet840=r1-node-1~1 \
tbtc_dkg@842@dkg842=r1-node-1~1 \
tbtc_signing@843@sign843=r1-node-1~1 \
tbtc_heartbeat@844@beat844=r1-node-1~1 \
beacon_signing@841@entry841=r1-node-1~1 \
beacon_signing@841@entry841=prior-node~7 \
beacon_dkg@845@bdkg845=r1-node-1~1 \
beacon_dkg@845@bdkg845=prior-node~7"'
check "a prior binary absent from the tBTC transcripts is caught too" 3 \
  "no tbtc_dkg tbtc_signing tbtc_heartbeat tbtc_wallet_action transcript \
incorporated a share"

# The reading this check exists to refuse: a family is a set of separate call
# paths, not one. A prior binary that signed says nothing about whether it
# could have taken part in a key generation or a heartbeat, whose message sets,
# anchors, and refusals are all different — so a mixed signing beside an
# R1-only DKG and an R1-only heartbeat leaves most of the tBTC path never shown
# to interoperate, while every family total reads as covered.
run_verdict precutover_case eval '
  PRECUTOVER_CONTRIBUTORS="\
tbtc_wallet_action@840@wallet840=r1-node-1~1 \
tbtc_wallet_action@840@wallet840=prior-node~7 \
tbtc_dkg@842@dkg842=r1-node-1~1 \
tbtc_signing@843@sign843=r1-node-1~1 \
tbtc_signing@843@sign843=prior-node~7 \
tbtc_heartbeat@844@beat844=r1-node-1~1 \
beacon_signing@841@entry841=r1-node-1~1 \
beacon_signing@841@entry841=prior-node~7 \
beacon_dkg@845@bdkg845=r1-node-1~1 \
beacon_dkg@845@bdkg845=prior-node~7"'
check "a mixed signing does not cover the DKG and heartbeat beside it" 3 \
  "no tbtc_dkg tbtc_heartbeat transcript incorporated a share"

# The same one path down on the beacon side, where a mixed relay signing would
# otherwise carry an R1-only group creation.
run_verdict precutover_case eval '
  PRECUTOVER_CONTRIBUTORS="\
tbtc_wallet_action@840@wallet840=r1-node-1~1 \
tbtc_wallet_action@840@wallet840=prior-node~7 \
tbtc_dkg@842@dkg842=r1-node-1~1 \
tbtc_dkg@842@dkg842=prior-node~7 \
tbtc_signing@843@sign843=r1-node-1~1 \
tbtc_signing@843@sign843=prior-node~7 \
tbtc_heartbeat@844@beat844=r1-node-1~1 \
tbtc_heartbeat@844@beat844=prior-node~7 \
beacon_signing@841@entry841=r1-node-1~1 \
beacon_signing@841@entry841=prior-node~7 \
beacon_dkg@845@bdkg845=r1-node-1~1"'
check "a mixed beacon signing does not cover the beacon DKG" 3 \
  "no beacon_dkg transcript incorporated a share"

# An R1 node is not the prior binary however many transcripts it appears in.
run_verdict precutover_case eval '
  PRECUTOVER_CONTRIBUTORS="\
tbtc_wallet_action@840@wallet840=r1-node-1~1 \
tbtc_wallet_action@840@wallet840=r1-node-2~2 \
beacon_signing@841@entry841=r1-node-1~1 \
beacon_signing@841@entry841=r1-node-2~2"'
check "a homogeneous R1 transcript cannot stand for a mixed one" 3 \
  "took no part in those results"

# The case the whole control used to rest on the driver for. Here the driver
# names a prior contributor on every required ceremony, exactly as a genuine
# mixed run would, and the fleet's own transcripts say every seat that produced
# the tBTC results was one of its own. A report cannot add a party to a
# transcript, so the tBTC requirements stay uncovered whatever the list claims.
#
# The beacon requirements are covered here, and that is the standing limit rather
# than an oversight: those ceremonies publish no transcript, so their prior share
# is still read from the driver's list. The verdict below therefore names the
# tBTC ceremonies alone, which is exactly the set whose prior share this fleet
# authors.
run_verdict precutover_case eval '
  PRECUTOVER_AUTHORED_ENDINGS="${PRECUTOVER_AUTHORED_ENDINGS//1,7/1}"'
check "a driver-claimed prior party outside the transcript is refused" 3 \
  "no tbtc_dkg tbtc_signing tbtc_heartbeat tbtc_wallet_action transcript \
incorporated a share"

# And the reverse mutation on the same fixture: a seat the fleet does not claim
# is what makes the reading mixed, so moving that seat into a node's own
# memberships leaves a transcript this fleet produced alone.
run_verdict precutover_case eval '
  PRECUTOVER_AUTHORED_ENDINGS="${PRECUTOVER_AUTHORED_ENDINGS//=1,7=1=/=1,7=1,7=}"'
check "a fleet claiming every seat authored no mixed transcript" 3 \
  "no tbtc_dkg tbtc_signing tbtc_heartbeat tbtc_wallet_action transcript \
incorporated a share"

# The seat sets read the other way round: every seat that produced the signing
# result belongs to the prior binary and the R1 holder claims none of them.
#
# The gate permits exactly this record. A wallet action owns its permit and
# records the signature it saw settle even when the attempt that produced it
# selected none of the memberships it operates, so "completed, incorporating
# seats, none of them mine" is the honest ending of a permit whose ceremony ran
# without it. What it is not is a contribution: the transcript is prior-only,
# and an R1 node watching one finish supplies no R1 share to it. Read as a
# contribution — which is all a completion could ever say — this fixture is a
# homogeneous prior ceremony passing as interoperation, with the prior half of
# the claim genuinely present and the R1 half supplied by an observer.
run_verdict precutover_case eval '
  PRECUTOVER_AUTHORED_ENDINGS="${PRECUTOVER_AUTHORED_ENDINGS/\
0xsign843=-=1,7=1=-/0xsign843=-=7=-=-}"'
check "an R1 holder that only watched a result is not a party to it" 3 \
  "no tbtc_signing transcript incorporated a share"

# The same distinction where the driver's list is what reaches for it. Here the
# signing transcript is genuinely mixed — r1-node-1 holds a seat in it — and the
# driver additionally names r1-node-2, whose own record for that work claims no
# seat of its own. A contributor set has to be the parties whose shares combined
# into the result, so a holder that recorded watching it is refused the same way
# a party the fleet never mentioned is.
# shellcheck disable=SC2016
run_verdict precutover_case eval '
  PRECUTOVER_AUTHORED_ENDINGS="${PRECUTOVER_AUTHORED_ENDINGS} \
r1-node-2@tbtc_signing@843@sign843#4=completed=bitcoin_transaction=0xsign843\
=-=7=-=-"
  PRECUTOVER_CONTRIBUTORS="${PRECUTOVER_CONTRIBUTORS} \
tbtc_signing@843@sign843=r1-node-2~4"'
check "a claimed party that only watched the result is refused" 1 \
  "r1-node-2@tbtc_signing@843@sign843#4" "recorded no such contribution"

# The mirror on the other release. A prior binary settling a ceremony among
# its own kind is exactly as unmixed as an R1 fleet doing so, and a control
# that only ever looked for the prior share would call this interoperation.
run_verdict precutover_case eval '
  PRECUTOVER_CONTRIBUTORS="\
tbtc_wallet_action@840@wallet840=prior-node~7 \
beacon_signing@841@entry841=prior-node~7"'
check "a homogeneous prior transcript cannot stand for a mixed one" 3 \
  "took no part in those results"

# Two homogeneous ceremonies are not one mixed ceremony, and the same ceremony
# is not the same piece of work. The prior share here is claimed on the wallet
# action while the R1 completion this fleet published is on the signing beside
# it — one gate ceremony, two transcripts — so the signing requirement stays
# uncovered however the totals for that ceremony read.
#
# The wallet action is covered, and by the half of the reading the driver does
# not author: its own list credits no R1 party there at all, and r1-node-1's
# published record of having completed that work is what puts one in it. A
# contributor set that omits a holder no longer un-mixes a transcript the
# holder itself vouched for.
run_verdict precutover_case eval '
  PRECUTOVER_CONTRIBUTORS="\
tbtc_wallet_action@840@wallet840=prior-node~7 \
tbtc_signing@843@sign843=r1-node-1~1 \
beacon_signing@841@entry841=r1-node-1~1 \
beacon_signing@841@entry841=prior-node~7 \
beacon_dkg@845@bdkg845=r1-node-1~1 \
beacon_dkg@845@bdkg845=prior-node~7"'
check "shares in separate transcripts are not one mixed transcript" 3 \
  "no tbtc_dkg tbtc_signing tbtc_heartbeat transcript incorporated a share"

# A service the rehearsal does not run is neither half of the claim. Reading a
# third name as the R1 side would let a stray container supply a share no
# rehearsed release was shown to have contributed; reading it as the prior side
# would put the one unfalsifiable claim on a container that is not the prior
# binary.
run_verdict precutover_case eval '
  PRECUTOVER_CONTRIBUTORS="\
tbtc_wallet_action@840@wallet840=r1-node-1~1 \
tbtc_wallet_action@840@wallet840=prior-node~7 \
tbtc_dkg@842@dkg842=bystander-node~3 \
tbtc_dkg@842@dkg842=prior-node~7 \
tbtc_signing@843@sign843=r1-node-1~1 \
tbtc_signing@843@sign843=prior-node~7 \
tbtc_heartbeat@844@beat844=r1-node-1~1 \
tbtc_heartbeat@844@beat844=prior-node~7 \
beacon_signing@841@entry841=r1-node-1~1 \
beacon_signing@841@entry841=prior-node~7 \
beacon_dkg@845@bdkg845=r1-node-1~1 \
beacon_dkg@845@bdkg845=prior-node~7"'
check "an unrecognized service does not stand in for the R1 fleet" 3 \
  "bystander-node" "runs no such service"

# The fabrication the mixed-transcript reading rested on for as long as the
# contributor set was the driver's alone. r1-node-2 runs in this fleet and
# published no completion for the DKG, so a report naming it as a party to that
# transcript is the driver attesting to its own compatibility. It is caught at
# the whole permit identity, so a real holder under a permit it never took is
# caught with it.
# shellcheck disable=SC2016
run_verdict precutover_case eval '
  PRECUTOVER_CONTRIBUTORS="${PRECUTOVER_CONTRIBUTORS} \
tbtc_dkg@842@dkg842=r1-node-2~4"'
check "a claimed R1 party the fleet never vouched for is refused" 1 \
  "r1-node-2@tbtc_dkg@842@dkg842#4" "recorded no such contribution"

# The same node under a permit it did not hold. r1-node-1 published a completion
# for the DKG under permit 1; a second entry for the same node at permit 9 is
# one contribution reported twice, which is how a single share stands for the
# several a threshold needs.
# shellcheck disable=SC2016
run_verdict precutover_case eval '
  PRECUTOVER_CONTRIBUTORS="${PRECUTOVER_CONTRIBUTORS} \
tbtc_dkg@842@dkg842=r1-node-1~9"'
check "one contribution counted twice under a second permit is refused" 1 \
  "r1-node-1@tbtc_dkg@842@dkg842#9" "recorded no such contribution"

# The other direction. A driver that reports a subset of the population as the
# contributor set describes a smaller ceremony than the one the fleet published,
# and the mixed reading would then be about a transcript nobody claims.
run_verdict precutover_case eval '
  PRECUTOVER_CONTRIBUTORS="\
tbtc_wallet_action@840@wallet840=r1-node-1~1 \
tbtc_wallet_action@840@wallet840=prior-node~7 \
tbtc_dkg@842@dkg842=prior-node~7 \
tbtc_signing@843@sign843=r1-node-1~1 \
tbtc_signing@843@sign843=prior-node~7 \
tbtc_heartbeat@844@beat844=r1-node-1~1 \
tbtc_heartbeat@844@beat844=prior-node~7 \
beacon_signing@841@entry841=r1-node-1~1 \
beacon_signing@841@entry841=prior-node~7 \
beacon_dkg@845@bdkg845=r1-node-1~1 \
beacon_dkg@845@bdkg845=prior-node~7"'
check "a holder the contributor set omits is not left uncounted" 3 \
  "r1-node-1@tbtc_dkg@842@dkg842#1" "does not name them"

# A completion is what a contributor set is derived from, so a holder that
# closed its permit without producing anything is not a party to a transcript.
# The exhausted record makes the ending disagree with the driver's settlement
# first, which is the stronger refusal and the one that must come out.
# shellcheck disable=SC2016
run_verdict precutover_case eval '
  PRECUTOVER_AUTHORED_ENDINGS="${PRECUTOVER_AUTHORED_ENDINGS/\
r1-node-1@tbtc_dkg@842@dkg842#1=completed=persisted_tbtc_signer=0xdkg842=1\
=1,7=1=-/\
r1-node-1@tbtc_dkg@842@dkg842#1=exhausted=no_threshold=-=-=-=-=-}"'
check "a permit that produced nothing is not a party to a transcript" 1 \
  "tbtc_dkg@842@dkg842#1=exhausted"

# Work driven by a fleet already past C is not pre-cutover work, whatever
# mode counter moved.
run_verdict precutover_case eval \
  'PRECUTOVER_STATES="r1-node-1 reported [open_security_v2] at block [1000001]"'
check "a fleet past C drives no pre-cutover work" 3 \
  "not on the legacy side of C"

# The claim is that a pre-C anchor pins legacy. A security-v2 permit taken
# while driving work anchored below C refutes exactly that.
run_verdict precutover_case eval 'PRECUTOVER_SECURITY_AFTER="1"'
check "a security-v2 permit below C refutes the anchor rule" 1 \
  "pre-cutover anchor must pin the legacy mode"

# And its mirror: no legacy permit at all means the ceremonies the driver
# named were not run under this fleet's gate.
run_verdict precutover_case eval 'PRECUTOVER_LEGACY_AFTER="2"'
check "settled work with no legacy permit was not run under this gate" 1 \
  "issued no new legacy permit"

# Below C both releases speak one wire format, so a recognized cross-format
# peer is the compatibility claim failing.
run_verdict precutover_case eval 'PRECUTOVER_SIGHTINGS_AFTER="5"'
check "a cross-format peer below C refutes the compatibility claim" 1 \
  "below C the two releases must be one wire format"

# The coverage requirement is what makes the second pre-C step a different
# claim from the first rather than a repeat of it.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_BOUND="beacon_signing@841@entry841=succeeded=${PRE_TX2}=0xentry841
     tbtc_dkg@842@dkg842=succeeded=${PRE_TX1}=0xdkg842
     tbtc_signing@843@sign843=succeeded=${PRE_TX1}=0xsign843
     tbtc_heartbeat@844@beat844=succeeded=${PRE_TX1}=0xbeat844
     beacon_dkg@845@bdkg845=succeeded=${PRE_TX2}=0xbdkg845"'
check "pre-cutover work without a wallet action is not the longest action" 3 \
  "no tbtc_wallet_action"

# What a family-and-class requirement cannot state. This fixture covers both
# halves of the release and both work classes, and still leaves three mandated
# ceremonies undriven — which is the reading a broad requirement accepts.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_BOUND="tbtc_wallet_action@840@wallet840=succeeded=${PRE_TX1}=0xbtc840
     beacon_signing@841@entry841=succeeded=${PRE_TX2}=0xentry841
     tbtc_signing@843@sign843=succeeded=${PRE_TX1}=0xsign843"'
check "a covered family and work class is not the mandated ceremony set" 3 \
  "no tbtc_dkg tbtc_heartbeat beacon_dkg"

# The heartbeat is the mandated ceremony a threshold-class requirement is
# likeliest to skip: it settles like a signing, and it is the one carrying the
# inactivity penalty path the crossing has to keep quiet. A step that drove
# none of them says nothing about that path.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_BOUND="tbtc_wallet_action@840@wallet840=succeeded=${PRE_TX1}=0xbtc840
     beacon_signing@841@entry841=succeeded=${PRE_TX2}=0xentry841
     tbtc_dkg@842@dkg842=succeeded=${PRE_TX1}=0xdkg842
     tbtc_signing@843@sign843=succeeded=${PRE_TX1}=0xsign843
     beacon_dkg@845@bdkg845=succeeded=${PRE_TX2}=0xbdkg845"'
check "a pre-cutover step that drove no heartbeat is incomplete" 3 \
  "no tbtc_heartbeat"

# The beacon half is enumerated for the same reason the tBTC half is: its DKG
# and its signing are separate paths into the gate, and one beacon ceremony
# settling covers the family without covering the other path.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_BOUND="tbtc_wallet_action@840@wallet840=succeeded=${PRE_TX1}=0xbtc840
     tbtc_dkg@842@dkg842=succeeded=${PRE_TX1}=0xdkg842
     tbtc_signing@843@sign843=succeeded=${PRE_TX1}=0xsign843
     tbtc_heartbeat@844@beat844=succeeded=${PRE_TX1}=0xbeat844
     beacon_dkg@845@bdkg845=succeeded=${PRE_TX2}=0xbdkg845"'
check "one beacon ceremony does not cover the beacon controls" 3 \
  "no beacon_signing"

run_verdict precutover_case eval 'PRECUTOVER_DRIVER_SUPPLIED=0'
check "no driver originates no pre-cutover ceremony to observe" 3 \
  "no PR4109_WORK_DRIVER was supplied"

run_verdict precutover_case eval 'PRECUTOVER_TX=0'
check "a pre-cutover driver naming no transaction attributes nothing" 3 \
  "reported no transaction"

run_verdict precutover_case eval \
  'PRECUTOVER_RESULTS="tbtc_wallet_action=succeeded beacon_signing=timed_out"'
check "a compatibility control is not read off the work that survived" 1 \
  "beacon_signing=timed_out"

# The half of this control that is not the driver's own account. Everything
# above decides on what the driver said about ceremonies it ran; these decide
# on the permits this fleet's gate issued for them and on what the nodes
# holding those permits recorded when each one closed.
run_verdict precutover_case eval 'PRECUTOVER_ORIGINATED=""'
check "settled ceremonies naming no permit holder identify no gate permit" 3 \
  "named no node holding a permit"

run_verdict precutover_case eval \
  'PRECUTOVER_AUTHORED_ENDINGS="unreadable on r1-node-2"'
check "a fleet that cannot be asked has vouched for no settlement" 3 \
  "could not be asked what became of the permits"

# The partial population: five permits ended with a record and the sixth simply
# never mentioned, which is also what eviction from a bounded account looks
# like. Both are the same thing to a reader.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_AUTHORED_ENDINGS="${PRECUTOVER_AUTHORED_ENDINGS% *}"'
check "a settled ceremony no node vouched for is not completed work" 3 \
  "no node recorded an ending for r1-node-1@beacon_dkg@845@bdkg845#1"

# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_AUTHORED_ENDINGS="${PRECUTOVER_AUTHORED_ENDINGS} \
r1-node-1@beacon_dkg@845@bdkg845#1=exhausted=no_threshold=-=-=-=-=-"'
check "one permit ending twice cannot be read as either ending" 3 \
  "more than one node-authored record"

# A permit closed by an owner that recorded nothing. The gate writes that down
# as an ending rather than leaving it absent, so it arrives as a disposition a
# reader can refuse rather than as silence.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_AUTHORED_ENDINGS="\
${PRECUTOVER_AUTHORED_ENDINGS% *} r1-node-1@beacon_dkg@845@bdkg845#1\
=unresolved=-=-=-=-=-=-"'
check "a settled ceremony whose holder recorded nothing stands on nothing" 1 \
  "closed the permit without recording" "r1-node-1@beacon_dkg@845@bdkg845#1=unresolved"

# The disagreement this rung exists for: the driver reports a settlement and
# the node holding the permit says the ceremony ran out of retries.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_AUTHORED_ENDINGS="\
${PRECUTOVER_AUTHORED_ENDINGS% *} r1-node-1@beacon_dkg@845@bdkg845#1\
=exhausted=no_threshold=-=-=-=-=-"'
check "a driver settlement the holder recorded as exhausted is refused" 1 \
  "r1-node-1@beacon_dkg@845@bdkg845#1=exhausted"

# Quarantine is a closing too, and a pre-C compatibility claim is about work
# that finished rather than work whose key material was withdrawn.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_AUTHORED_ENDINGS="\
${PRECUTOVER_AUTHORED_ENDINGS% *} r1-node-1@beacon_dkg@845@bdkg845#1\
=quarantined=quarantined_beacon_signer=-=-=-=-=-"'
check "a quarantined permit is not a completed pre-cutover ceremony" 1 \
  "r1-node-1@beacon_dkg@845@bdkg845#1=quarantined"

# The collisions the permit identity exists for, driven through the whole
# ladder rather than through the join alone. A work id and a local permit id
# repeat across ceremonies and across runs of one ceremony, so an account that
# answered on those two alone would let the record of a different ceremony —
# or of the same one at a different anchor — stand for the permit under test.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_AUTHORED_ENDINGS="\
${PRECUTOVER_AUTHORED_ENDINGS% *} \
r1-node-1@tbtc_dkg@845@bdkg845#1=completed=persisted_tbtc_signer=0xbdkg845=1\
=1,7=1=-"'
check "an ending recorded under another ceremony answers for no permit" 3 \
  "no node recorded an ending for r1-node-1@beacon_dkg@845@bdkg845#1"

# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_AUTHORED_ENDINGS="\
${PRECUTOVER_AUTHORED_ENDINGS% *} \
r1-node-1@beacon_dkg@999@bdkg845#1=completed=persisted_beacon_signer\
=0xbdkg845=1=-=-=-"'
check "an ending recorded at another anchor answers for no permit" 3 \
  "no node recorded an ending for r1-node-1@beacon_dkg@845@bdkg845#1"

# A holder that recorded the category and nothing behind it, which is what a
# release publishing the older account serves. Every evidence rung below would
# otherwise read its missing fields as whatever the truncation left there.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_AUTHORED_ENDINGS="\
${PRECUTOVER_AUTHORED_ENDINGS% *} r1-node-1@beacon_dkg@845@bdkg845#1=completed"'
check "an ending that stops at the category cannot be reconciled" 3 \
  "stops short of what a permit"

# The evidence rungs themselves. A completion carrying the result class of a
# different ceremony is a categorical claim about an output nothing has seen.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_AUTHORED_ENDINGS="\
${PRECUTOVER_AUTHORED_ENDINGS% *} \
r1-node-1@beacon_dkg@845@bdkg845#1=completed=protocol_result=0xbdkg845=-=-=-\
=-"'
check "a completion carrying another ceremony's result class is refused" 1 \
  "claims protocol_result where a persisted_beacon_signer is the result"

# Two holders of one ceremony naming different outputs did not finish it
# together, however many completions are counted.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_ORIGINATED="${PRECUTOVER_ORIGINATED} \
beacon_dkg@845@bdkg845=${PRE_TX2}=r1-node-2~2"
   PRECUTOVER_AUTHORED_ENDINGS="${PRECUTOVER_AUTHORED_ENDINGS} \
r1-node-2@beacon_dkg@845@bdkg845#2=completed=persisted_beacon_signer\
=0xelsewhere=1=-=-=-"'
check "holders naming different outputs for one ceremony are refused" 1 \
  "beacon_dkg@845@bdkg845 \(0xbdkg845/0xelsewhere\)"

# The same disagreement from a holder the driver did not report. Its permit is
# absent from the originated records, so a reading whose population came from the
# driver's own account never looks at it — and that is the reading a node
# recording a different output for the ceremony would want. The record is checked
# because the node published it, not because the driver named it.
#
# One control covers both result rungs for an unreported holder. Any output it
# names other than the one the reported holder recorded disagrees with that
# holder first, so the disagreement rung is what an unreported record can be
# caught by; reaching the settlement rung instead would need the reported
# holder's own record to be missing, which blocks the control a rung earlier.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_AUTHORED_ENDINGS="${PRECUTOVER_AUTHORED_ENDINGS} \
r1-node-2@beacon_dkg@845@bdkg845#2=completed=persisted_beacon_signer\
=0xelsewhere=2=-=-=-"'
check "an unreported holder naming another output is refused too" 1 \
  "beacon_dkg@845@bdkg845 \(0xbdkg845/0xelsewhere\)"

# And the seam between the two accounts: the driver reports a settlement the
# holders never produced. Read separately both sides pass.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_AUTHORED_ENDINGS="\
${PRECUTOVER_AUTHORED_ENDINGS% *} \
r1-node-1@beacon_dkg@845@bdkg845#1=completed=persisted_beacon_signer\
=0xelsewhere=1=-=-=-"'
check "a completion naming an output the driver never settled is refused" 1 \
  "recorded 0xelsewhere where the driver claims 0xbdkg845"

# An outcome for a ceremony this phase did not put on the chain, and one whose
# transaction is not the transaction that originated it. Either is somebody
# else's ceremony arriving in this control's reckoning.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_BOUND="${PRECUTOVER_BOUND} \
tbtc_signing@846@sign846=succeeded=${PRE_TX1}=0xsign846"'
check "an outcome for work this phase never originated is not evidence" 1 \
  "tbtc_signing@846@sign846"

# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_ORIGINATED="${PRECUTOVER_ORIGINATED/@845@bdkg845=${PRE_TX2}/\
@845@bdkg845=${PRE_TX1}}"'
check "an outcome bound to a transaction that started nothing here is not \
evidence" 1 \
  "originated as ${PRE_TX1}"

# Originated work with no outcome at all, which is how a partial population
# passes: six ceremonies driven, five reported, and every requirement above
# satisfied by the five.
# shellcheck disable=SC2016
run_verdict precutover_case eval \
  'PRECUTOVER_ORIGINATED="${PRECUTOVER_ORIGINATED} \
tbtc_signing@846@sign846=${PRE_TX1}=r1-node-1~2"
   PRECUTOVER_AUTHORED_ENDINGS="${PRECUTOVER_AUTHORED_ENDINGS} \
r1-node-1@tbtc_signing@846@sign846#2=completed=bitcoin_transaction=0xsign846\
=-=1,7=1=-"'
check "originated work the driver never reported on leaves a gap" 3 \
  "no outcome at all for tbtc_signing@846@sign846#2"

# ----------------------------------------------------------------------------

# The in-flight half of the crossing: a permit taken below C that is still
# held when C passes and finishes afterwards.
SURVIVE_TX="0xff66666666666666666666666666666666666666666666666666666666666666"

surviving_readings() {
  # shellcheck disable=SC2034
  SURVIVING_DRIVER_SUPPLIED=1
  # shellcheck disable=SC2034
  SURVIVING_ORIGINATE_RC=0
  # shellcheck disable=SC2034
  SURVIVING_ORIGINATED="tbtc_signing@840@wallet840=${SURVIVE_TX}=r1-node-1~member-1"
  # shellcheck disable=SC2034
  SURVIVING_HELD_BEFORE="1"
  # What the gates themselves reported holding, before C and again once they
  # reported being past it. The identities are the driver's account rendered
  # the way a gate renders its own live permits, so the two can be compared
  # rather than counted against each other.
  # shellcheck disable=SC2034
  SURVIVING_PERMITS_BEFORE="r1-node-1@tbtc_signing@840@wallet840#member-1"
  # shellcheck disable=SC2034
  SURVIVING_PERMITS_AT_C="r1-node-1@tbtc_signing@840@wallet840#member-1"
  # shellcheck disable=SC2034
  SURVIVING_PERMITS_AT_C_READ=1
  # The quiescence control's seed goes on the chain between those two
  # readings, so it is the one legacy permit that legitimately appears at C
  # without having been named here — and only where the driver that seeded it
  # and the gate that issued it name the same identity. The base case seeds
  # nothing, so both readings are empty.
  # shellcheck disable=SC2034
  QUIESCE_SEEDED_WORK=""
  # shellcheck disable=SC2034
  QUIESCE_SEEDED_PERMITS_BEFORE_C=""
  # shellcheck disable=SC2034
  SURVIVING_LEGACY_COMPLETIONS_BEFORE="0"
  # shellcheck disable=SC2034
  SURVIVING_LEGACY_COMPLETIONS_AFTER="1"
  # shellcheck disable=SC2034
  SURVIVING_TERMINAL_ASKED=1
  # shellcheck disable=SC2034
  SURVIVING_TERMINAL_RC=0
  # shellcheck disable=SC2034
  SURVIVING_TERMINAL="tbtc_signing@840@wallet840=succeeded=${SURVIVE_TX}=0xsigned840"
  # What the gate that issued the permit says became of it. Everything above
  # is the account of the party that also originated the work; this is the
  # holder's own record of closing that very permit, and it is what the verdict
  # decides the ending on.
  # shellcheck disable=SC2034
  SURVIVING_AUTHORED_ENDINGS="\
r1-node-1@tbtc_signing@840@wallet840#member-1=completed=bitcoin_transaction\
=0xsigned840=-=1=1=-"
}

surviving_case() {
  surviving_readings
  "$@"
  surviving_legacy_verdict
}

run_verdict surviving_case :
check "a legacy permit held across C and finished holds the control" 0 \
  "tbtc_signing@840@wallet840 \(${SURVIVE_TX}, 0xsigned840\)" \
  "r1-node-1@tbtc_signing@840@wallet840#member-1=completed" \
  "recorded 1 legacy completion"

# The seam these readings exist to close. Every check above them is satisfied
# by an account the driver wrote about work the driver originated, so the
# crossing was reported rather than observed; the gate that issued the permit
# has to say the same thing about it.
run_verdict surviving_case eval \
  'SURVIVING_AUTHORED_ENDINGS="unreadable on r1-node-1"'
check "gates that cannot say how they closed a permit leave it unobserved" 3 \
  "could not be asked what became of"

run_verdict surviving_case eval 'SURVIVING_AUTHORED_ENDINGS=""'
check "a permit only the driver vouches for does not hold the control" 3 \
  "no R1 gate recorded an ending for r1-node-1@tbtc_signing@840@wallet840#member-1"

# A bounded account forgets its oldest first, and to a reader that is the same
# thing as an ending nobody recorded: some other permit's record is present
# and the named one's is not.
run_verdict surviving_case eval \
  'SURVIVING_AUTHORED_ENDINGS="\
r1-node-1@tbtc_signing@999@wallet999#member-9=completed=bitcoin_transaction\
=0xsigned999=-=1=1=-"'
check "a permit forgotten from the gate's own account is not vouched for" 3 \
  "no R1 gate recorded an ending for r1-node-1@tbtc_signing@840@wallet840#member-1"

run_verdict surviving_case eval \
  'SURVIVING_AUTHORED_ENDINGS="\
r1-node-1@tbtc_signing@840@wallet840#member-1=completed=bitcoin_transaction\
=0xsigned840=-=1=1=- \
r1-node-1@tbtc_signing@840@wallet840#member-1=exhausted=no_threshold=-=-=-=-\
=-"'
check "one permit ending twice cannot be read as either ending" 3 \
  "more than one ending for r1-node-1@tbtc_signing@840@wallet840#member-1 \(2 records\)"

# The gate writes this itself when the ceremony owner recorded nothing. The
# permit is gone and its holder cannot say where it went, which is not a permit
# that was allowed to finish.
run_verdict surviving_case eval \
  'SURVIVING_AUTHORED_ENDINGS="\
r1-node-1@tbtc_signing@840@wallet840#member-1=unresolved=-=-=-=-=-=-"'
check "a permit whose owner recorded nothing refutes the gate" 1 \
  "without their ceremony owners recording any disposition"

# The driver still reports a settlement here. A control that read the ending
# off the driver alone would pass this.
run_verdict surviving_case eval \
  'SURVIVING_AUTHORED_ENDINGS="\
r1-node-1@tbtc_signing@840@wallet840#member-1=exhausted=no_threshold=-=-=-=-\
=-"'
check "a holder recording an ending the driver contradicts refutes the gate" \
  1 "r1-node-1@tbtc_signing@840@wallet840#member-1=exhausted"

# The reading that separates surviving C from merely finishing before it.
run_verdict surviving_case eval 'SURVIVING_LEGACY_COMPLETIONS_AFTER="0"'
check "settled work with no post-C legacy completion did not survive C" 1 \
  "no gate recorded a legacy completion after C"

# A permit that had already ended when C approached never met the crossing.
run_verdict surviving_case eval 'SURVIVING_HELD_BEFORE="0"'
check "work that ended before C is not work held across it" 3 \
  "had already ended"

# A terminal phase must be about the work this step put on the chain.
# shellcheck disable=SC2016
run_verdict surviving_case eval \
  'SURVIVING_TERMINAL="beacon_dkg@900@seed900=succeeded=${SURVIVE_TX}=0xgroup900"'
check "an outcome for other work is not the held permit finishing" 3 \
  "did not originate before C"

# shellcheck disable=SC2016
run_verdict surviving_case eval \
  'SURVIVING_TERMINAL="tbtc_signing@840@wallet840=no_threshold=${SURVIVE_TX}=no_threshold"'
check "legacy work abandoned on the far side of C refutes the gate" 1 \
  "came to nothing"

run_verdict surviving_case eval 'SURVIVING_TERMINAL_ASKED=0'
check "a permit never followed up is not a permit that finished" 3 \
  "never asked what became of"

run_verdict surviving_case eval 'SURVIVING_ORIGINATED=""'
check "a driver naming no pre-C work identifies no surviving permit" 3 \
  "named no work it put on the chain before C"

run_verdict surviving_case eval 'SURVIVING_DRIVER_SUPPLIED=0'
check "no driver holds no legacy permit across C" 3 \
  "no PR4109_WORK_DRIVER was supplied"

# A control that only rejects extra terminal records reads a partial population
# as a whole one. These three mutations each leave a settlement and a moving
# counter in place, and each hides a permit the step claims to speak for.
SURVIVE_TX_SECOND="0xff77777777777777777777777777777777777777777777777777777777777777"

# Two permits held across C, one settled, the other simply unmentioned.
# shellcheck disable=SC2016
run_verdict surviving_case eval '
  SURVIVING_ORIGINATED="tbtc_signing@840@wallet840=${SURVIVE_TX}=r1-node-1~member-1 tbtc_signing@841@wallet841=${SURVIVE_TX_SECOND}=r1-node-1~member-2"
  SURVIVING_HELD_BEFORE="2"
  SURVIVING_PERMITS_BEFORE="r1-node-1@tbtc_signing@840@wallet840#member-1 r1-node-1@tbtc_signing@841@wallet841#member-2"
  SURVIVING_PERMITS_AT_C="r1-node-1@tbtc_signing@840@wallet840#member-1 r1-node-1@tbtc_signing@841@wallet841#member-2"
  SURVIVING_LEGACY_COMPLETIONS_AFTER="2"'
check "a held permit with no terminal outcome is not covered by another's" 3 \
  "reported no terminal outcome for it"

# The reading the permit identities exist for. A count of active legacy
# ceremonies moving in step with the driver's account is satisfied by any two
# unrelated permits; naming them is what ties the crossing to this step's work.
run_verdict surviving_case eval \
  'SURVIVING_PERMITS_BEFORE="r1-node-1@tbtc_signing@840@someoneelse#member-9"'
check "a gate holding some other permit is not holding this step's" 3 \
  "no R1 gate reported holding it"

# The mirror: the gates hold the named permit and another beside it, so the
# verdict would speak for a permit crossing C that this step never identified.
run_verdict surviving_case eval \
  'SURVIVING_PERMITS_BEFORE="r1-node-1@tbtc_signing@840@wallet840#member-1 r1-node-2@tbtc_signing@999@wallet999#member-3"'
check "an unnamed legacy permit crossing beside the named one is caught" 3 \
  "which this step did not originate"

# The crossing itself is where a permit would be dropped, so the survival has
# to be read there. A permit gone by the time the gates report open_security_v2
# was cut short at C however cleanly the driver later says it settled.
run_verdict surviving_case eval 'SURVIVING_PERMITS_AT_C=""'
check "a permit dropped at the crossing did not survive it" 1 \
  "no longer held.*when they reported open_security_v2"

# The other direction of the same reading, and the one every other rung here
# lets through. The completion fence at the bottom of this ladder is a
# fleet-wide counter, so a legacy permit appearing only at the crossing
# supplies an increment of its own: the driver's account of the named permit
# settling is unchanged, the delta still equals the one permit this step
# originated, and nothing below notices that the increment belongs to a permit
# nobody identified.
run_verdict surviving_case eval \
  'SURVIVING_PERMITS_AT_C="r1-node-1@tbtc_signing@840@wallet840#member-1 r1-node-2@tbtc_signing@999@latecomer#member-4"'
check "a legacy permit appearing only at the crossing is caught" 3 \
  "neither in flight when this step named what it originated nor seeded"

# The one permit that legitimately arrives between the two readings: the
# quiescence control's seed, put on the chain after this work was originated
# and observed in the gate that issued it while the fleet was still below C.
# Both readings of the seeding name it, which is what the exclusion rests on.
# shellcheck disable=SC2034
QUIESCE_SEED_TX="0xee66666666666666666666666666666666666666666666666666666666666666"
# shellcheck disable=SC2016
SEEDED_AT_C='SURVIVING_PERMITS_AT_C="r1-node-1@tbtc_signing@840@wallet840#member-1 r1-node-1@beacon_dkg@900@quiesce900#member-7"
  QUIESCE_SEEDED_WORK="beacon_dkg@900@quiesce900=${QUIESCE_SEED_TX}=r1-node-1~member-7"
  QUIESCE_SEEDED_PERMITS_BEFORE_C="r1-node-1@beacon_dkg@900@quiesce900#member-7"'

run_verdict surviving_case eval "${SEEDED_AT_C}"
check "the quiescence seed arriving before C is not an unaccounted permit" 0 \
  "recorded 1 legacy completion"

# A seed the issuing gate could not be asked about excludes nothing, so a
# permit that looks like it stays unaccounted for rather than being waved
# through on the strength of a reading that was never taken.
run_verdict surviving_case eval "${SEEDED_AT_C}"'
  QUIESCE_SEEDED_PERMITS_BEFORE_C="unreadable on r1-node-1"'
check "an unreadable seed reading accounts for no arrival at C" 3 \
  "neither in flight when this step named what it originated nor seeded"

# The gate's reading of the seed node is that node's whole legacy population,
# not the seeding's product. A permit that merely turned up there between the
# two samples is in it, and excusing the reading wholesale would wave that
# permit through C under the seed's name — where it can supply the fleet-wide
# completion increment the named permit is supposed to.
# shellcheck disable=SC2016
run_verdict surviving_case eval "${SEEDED_AT_C}"'
  SURVIVING_PERMITS_AT_C="${SURVIVING_PERMITS_AT_C} r1-node-1@tbtc_signing@900@bystander#member-8"
  QUIESCE_SEEDED_PERMITS_BEFORE_C="${QUIESCE_SEEDED_PERMITS_BEFORE_C} r1-node-1@tbtc_signing@900@bystander#member-8"'
check "a permit beside the seed on the seed node is not excused as one" 3 \
  "neither in flight when this step named what it originated nor seeded"

# The mirror reading: the driver names a seed the gate never reported holding
# below C. That is the driver's word for an anchor on the legacy side of the
# crossing, which is the one thing the seeding is checked for.
run_verdict surviving_case eval "${SEEDED_AT_C}"'
  QUIESCE_SEEDED_PERMITS_BEFORE_C="r1-node-1@tbtc_signing@840@somethingelse#member-9"'
check "a seed only the driver names accounts for no arrival at C" 3 \
  "neither in flight when this step named what it originated nor seeded"

# A crossing that never happened observed nothing, which is not the same as
# observing a permit survive one.
run_verdict surviving_case eval 'SURVIVING_PERMITS_AT_C_READ=0'
check "an unobserved crossing evidences no surviving permit" 3 \
  "never reached the point where the fleet reported open_security_v2"

# An unread fleet on either side leaves the survival unobserved rather than
# disproved, and a step that read a count alone would not notice.
run_verdict surviving_case eval \
  'SURVIVING_PERMITS_BEFORE="unreadable on r1-node-2"'
check "gates that cannot be asked what they hold identify no permit" 3 \
  "could not be asked which legacy permits they were holding"

run_verdict surviving_case eval \
  'SURVIVING_PERMITS_AT_C="unreadable on r1-node-2"'
check "gates unread at the crossing leave the survival unobserved" 3 \
  "could not be asked which legacy permits they still held"

# The counter moves, but by more than this step put across the crossing: an
# unrelated legacy ceremony finishing elsewhere in the fleet cannot stand in.
run_verdict surviving_case eval 'SURVIVING_LEGACY_COMPLETIONS_AFTER="2"'
check "an unrelated legacy completion cannot stand for the held permit" 3 \
  "counted completions this step did not originate"

# The fleet held more legacy permits than the driver named, so the verdict
# would speak for permits this step cannot identify.
run_verdict surviving_case eval 'SURVIVING_HELD_BEFORE="2"'
check "a held count above the named population leaves permits unidentified" 3 \
  "does not match the named population"

# ----------------------------------------------------------------------------

# The legacy half of quiescence decides the same ladder as the security-v2
# half over a different permit population, and records no assertion of its
# own: the contract names one graceful-quiescence assertion and binds it to
# the security-v2 step.
legacy_quiesce_case() {
  quiesce_readings
  # The stage seeds this half before C and drains it beside the other mode, so
  # the shared ladder is decided here with those rungs already satisfied rather
  # than absent — otherwise these cases would keep passing after the seeded
  # path stopped being taken.
  # shellcheck disable=SC2034
  QUIESCE_FROM_SEED=1
  # shellcheck disable=SC2034
  QUIESCE_SEEDED_ASKED=1
  # shellcheck disable=SC2034
  QUIESCE_SEEDED_WORK="${QUIESCE_INFLIGHT_WORK}"
  # shellcheck disable=SC2034
  QUIESCE_SEEDED_PERMITS_BEFORE_C="${QUIESCE_PERMITS_BEFORE}"
  # shellcheck disable=SC2034
  QUIESCE_COLIVE_REQUIRED=1
  # shellcheck disable=SC2034
  QUIESCE_COLIVE_MODE="security-v2"
  # shellcheck disable=SC2034
  QUIESCE_COLIVE_PERMITS="r1-node-1@tbtc_signing@1200@colive900#other-1"
  # The other mode's population is followed to an end on the same footing as
  # the seeded one, so the fixture names the work behind that permit and the
  # outcome the driver reported for it beside the seeded work's.
  # shellcheck disable=SC2034
  QUIESCE_COLIVE_WORK="tbtc_signing@1200@colive900=${QUIESCE_TX3}=r1-node-1~other-1"
  # shellcheck disable=SC2034
  QUIESCE_TERMINAL="${QUIESCE_TERMINAL} \
tbtc_signing@1200@colive900=succeeded=${QUIESCE_TX3}=0xsigned1200"
  # The holder's own record of that permit closing, on the same footing: the
  # co-live population is reconciled here exactly as the seeded one is, so a
  # permit of the other mode cannot end unaccounted while the step still
  # reports the gate let what it held finish.
  # shellcheck disable=SC2034
  QUIESCE_AUTHORED_ENDINGS="${QUIESCE_AUTHORED_ENDINGS} \
r1-node-1@tbtc_signing@1200@colive900#other-1=completed=bitcoin_transaction\
=0xsigned1200=-=1=1=-"
  "$@"
  quiescence_verdict r1-node-1 \
    "quiescence with an in-flight legacy permit" "" legacy
}

run_verdict legacy_quiesce_case :
check "a legacy quiescence that drained its permits holds the same ladder" 0 \
  "in-flight count observed at zero" \
  "quiescence with an in-flight legacy permit"

run_verdict legacy_quiesce_case eval 'QUIESCE_STATE=""'
check "a draining node that never quiesced refutes the legacy half too" 1 \
  "never reported quiescing" "legacy ceremonies in flight"

# The legacy half runs after the fleet has crossed C, so the work it originates
# when the control starts is fresh chain work — security-v2 unless the driver
# deliberately anchors it below the cutover block. The cases above inject the
# in-flight population directly and so cannot see that; these drive
# run_quiescence_control itself, which is where the population is collected.
QUIESCE_SEQ_TX="0xff88888888888888888888888888888888888888888888888888888888888888"
QUIESCE_SEQ_COLIVE_TX="0xff99999999999999999999999999999999999999999999999999999999999999"

# The endings the node under test recorded, which both the stubbed drain
# reading and the document the race case serves render from.
quiesce_seq_endings() {
  printf 'r1-node-1@tbtc_signing@%s@wallet%s#member-1' \
    "${QUIESCE_SEQ_ANCHOR}" "${QUIESCE_SEQ_ANCHOR}"
  printf '=completed=bitcoin_transaction=0xsigned=-=1,2=1=-'
  if ((QUIESCE_SEQ_SEEDED == 1)); then
    printf ' r1-node-1@tbtc_signing@1200@colive900#other-1'
    printf '=completed=bitcoin_transaction=0xsigned1200=-=1,2=1=-'
  fi
}

# Everything run_quiescence_control reaches outside its own logic. The drain is
# stubbed to succeed on its first sample so the ladder reaches the rung that
# reads the anchors rather than stopping at an earlier reading.
quiesce_sequencing_stubs() {
  QUIESCE_SEQ_ANCHOR="$1"
  # The reading taken before the stop is issued, which is the only one the
  # control still takes a field at a time: it needs a held permit there, or the
  # ladder stops at "nothing was in flight" before reaching the anchors.
  participation_field() {
    case "$2" in
    gate_state) printf 'quiescing' ;;
    *) printf '1' ;;
    esac
  }
  # A node that drained cleanly: it refused the work offered while quiescing,
  # issued no permit for it, and force-aborted nothing. The refusal is recorded
  # between the read taken before the stop and the reads taken during the
  # drain, so it needs the same marker treatment as the gauge.
  # Each reading gets its own marker: the total and the per-ceremony breakdown
  # are sampled one after the other, so a shared marker would have the second
  # read of the pair already reporting the refusal the first one had not yet
  # seen, and the two would never move together.
  QUIESCE_SEQ_REFUSED="${WORK}/quiesce-seq-refused"
  QUIESCE_SEQ_REFUSED_BY_CEREMONY="${WORK}/quiesce-seq-refused-ceremony"
  rm -f "${QUIESCE_SEQ_REFUSED}" "${QUIESCE_SEQ_REFUSED_BY_CEREMONY}"

  metric_value() {
    case "$2" in
    participation_refusals_total)
      if [[ -f "${QUIESCE_SEQ_REFUSED}" ]]; then
        printf '1'
      else
        : >"${QUIESCE_SEQ_REFUSED}"
        printf '0'
      fi
      ;;
    *) printf '0' ;;
    esac
  }
  ceremony_refusal_counters() {
    if [[ -f "${QUIESCE_SEQ_REFUSED_BY_CEREMONY}" ]]; then
      printf 'tbtc_signing=1'
    else
      : >"${QUIESCE_SEQ_REFUSED_BY_CEREMONY}"
      printf 'tbtc_signing=0'
    fi
  }
  manifest_termination_grace() { printf '4'; }
  compose() { return 0; }
  node_reachable() { return 1; }

  # The gate's own list of what it is holding, which the control reads beside
  # the count. The mode under test names the work the stubbed driver put on the
  # node; the other mode stands for a permit live beside it, which the seeded
  # control requires and a mutation can take away.
  QUIESCE_SEQ_COLIVE="r1-node-1@tbtc_signing@1200@colive900#other-1"
  node_mode_permits() {
    case "$2" in
    legacy)
      printf 'r1-node-1@tbtc_signing@%s@wallet%s#member-1' \
        "${QUIESCE_SEQ_ANCHOR}" "${QUIESCE_SEQ_ANCHOR}"
      ;;
    *) printf '%s' "${QUIESCE_SEQ_COLIVE}" ;;
    esac
  }

  # The other mode's work, which a seeded control puts in flight beside the
  # permit it drains. It is anchored past C so it really is the other mode,
  # and the control follows it to an outcome like any other held permit, so
  # the terminal phase reports it beside the drained population's.
  QUIESCE_SEQ_COLIVE_WORK="tbtc_signing@1200@colive900\
=${QUIESCE_SEQ_COLIVE_TX}=r1-node-1~other-1"
  QUIESCE_SEQ_COLIVE_TERMINAL="tbtc_signing@1200@colive900=succeeded\
=${QUIESCE_SEQ_COLIVE_TX}=0xsigned1200"
  # Empty for the unseeded control, whose in-flight phase originates the
  # population it goes on to drain rather than a second one beside it.
  QUIESCE_SEQ_SEEDED=0

  run_work_driver() {
    WORK_DRIVER_RC=0
    WORK_DRIVER_TX_COUNT=1
    WORK_DRIVER_ORIGINATED="tbtc_signing"
    if ((QUIESCE_SEQ_SEEDED == 1)) && [[ "$1" == *-inflight ]]; then
      WORK_DRIVER_ORIGINATED_WORK="${QUIESCE_SEQ_COLIVE_WORK}"
      WORK_DRIVER_BOUND_RESULTS="${QUIESCE_SEQ_COLIVE_TERMINAL}"
      return 0
    fi
    WORK_DRIVER_ORIGINATED_WORK="tbtc_signing@${QUIESCE_SEQ_ANCHOR}\
@wallet${QUIESCE_SEQ_ANCHOR}=${QUIESCE_SEQ_TX}=r1-node-1~member-1"
    WORK_DRIVER_BOUND_RESULTS="tbtc_signing@${QUIESCE_SEQ_ANCHOR}\
@wallet${QUIESCE_SEQ_ANCHOR}=succeeded=${QUIESCE_SEQ_TX}=0xsigned"
    if ((QUIESCE_SEQ_SEEDED == 1)) && [[ "$1" == *-terminal ]]; then
      WORK_DRIVER_BOUND_RESULTS="${WORK_DRIVER_BOUND_RESULTS} \
${QUIESCE_SEQ_COLIVE_TERMINAL}"
    fi
  }
}

# The one gate reading the drain window takes each pass: the state, what is
# still held, and what the node recorded about the permits it let go of. It
# answers for both populations — the co-live permit is reconciled on the same
# footing as the drained one, so a seeded control that could not read its
# ending would block exactly as one that could not read the drained permit's.
#
# Kept apart from the stub set above because the race case below has to let the
# real reader run against a served document, and a case cannot get that back by
# unsetting a stub: there is one function of this name, so overwriting it loses
# the definition rehearse.sh contributed.
#
# Invoked by the control under test, which shellcheck cannot see across the
# source boundary into rehearse.sh.
# shellcheck disable=SC2329
quiesce_stub_snapshot() {
  service_gate_snapshot() {
    printf 'state=quiescing\nactive=0\noutcomes=%s\n' "$(quiesce_seq_endings)"
  }
}

quiesce_sequencing_case() {
  # shellcheck disable=SC2034
  REHEARSAL_R1_CUTOVER_BLOCK="1000"
  # shellcheck disable=SC2034
  PR4109_WORK_DRIVER="/nonexistent/driver-is-stubbed"
  quiesce_sequencing_stubs "$1"
  quiesce_stub_snapshot
  run_quiescence_control r1-node-1 \
    "quiescence with an in-flight legacy permit" \
    "" legacy active_legacy_ceremonies participation_mode_legacy_total \
    quiesce-legacy
}

run_verdict quiesce_sequencing_case 1000
check "a legacy quiescence draining post-C work observed the other mode" 3 \
  "is not legacy-anchored work" "anchored at 1000, C is 1000"

run_verdict quiesce_sequencing_case 840
check "a legacy quiescence draining pre-C work is about a legacy permit" 0 \
  "quiescence with an in-flight legacy permit"

# The legacy half's real subject: a permit seeded before the fleet crossed C,
# observed in the gate that issued it while it was still on the legacy side,
# and drained beside a live permit of the other mode. Anything short of that is
# the driver's claimed anchor standing in for the crossing.
quiesce_seeded_case() {
  # shellcheck disable=SC2034
  REHEARSAL_R1_CUTOVER_BLOCK="1000"
  # shellcheck disable=SC2034
  PR4109_WORK_DRIVER="/nonexistent/driver-is-stubbed"
  quiesce_sequencing_stubs 840
  quiesce_stub_snapshot
  # shellcheck disable=SC2034
  QUIESCE_SEQ_SEEDED=1
  # shellcheck disable=SC2034
  QUIESCE_SEEDED_ASKED=1
  # shellcheck disable=SC2034
  QUIESCE_SEEDED_RC=0
  QUIESCE_SEEDED_WORK="tbtc_signing@840@wallet840=${QUIESCE_SEQ_TX}=r1-node-1~member-1"
  # shellcheck disable=SC2034
  QUIESCE_SEEDED_PERMITS_BEFORE_C="r1-node-1@tbtc_signing@840@wallet840#member-1"
  "$@"
  run_quiescence_control r1-node-1 \
    "quiescence with an in-flight legacy permit" \
    "" legacy active_legacy_ceremonies participation_mode_legacy_total \
    quiesce-legacy "${QUIESCE_SEEDED_WORK}"
}

run_verdict quiesce_seeded_case :
check "a legacy permit seeded before C and drained after it holds" 0 \
  "seeded before C and live beside r1-node-1@tbtc_signing@1200@colive900#other-1" \
  "quiescence with an in-flight legacy permit"

# Nothing was put on the legacy side of the crossing, so the permit drained
# here would be one the driver anchored below C on its own say-so.
run_verdict quiesce_seeded_case eval 'QUIESCE_SEEDED_ASKED=0'
check "an unseeded legacy quiescence drains no pre-C permit" 3 \
  "no legacy permit was seeded before the fleet crossed C"

run_verdict quiesce_seeded_case eval 'QUIESCE_SEEDED_RC=9'
check "a failed seeding puts nothing on the chain before C" 3 \
  "exited \[9\] seeding the legacy permit"

run_verdict quiesce_seeded_case eval 'QUIESCE_SEEDED_WORK=""'
check "a seeding that named no work identifies no pre-C permit" 3 \
  "named no legacy work it put on r1-node-1"

# A node that stops the instant it has answered once.
#
# This is what a correct drain looks like from outside: the last permit closes,
# the gate reports nothing held and the endings it recorded for what it let go
# of, and the process exits. Every reading after that is against a node that is
# gone. A watcher that asks for the state, then the count, then the endings
# gets one of the three, and the mandatory gate blocks on a fleet that did
# exactly what was asked of it — or, worse, records the drain beside an ending
# list read before the last permit closed. So the document is served once and
# every later fetch fails, which is the only stub in this file that lets the
# real snapshot reader run: what is under test is that the control needs one
# response, not three.
QUIESCE_RACE_FETCHES="${WORK}/quiesce-race-fetches"

# One membership set as the gate serves it: a JSON array of numbers, and the
# absent set as null so a record that names none reads as naming none rather
# than as an empty ceremony.
quiesce_race_members() {
  [[ "$1" == "-" ]] && {
    printf 'null'
    return 0
  }
  printf '[%s]' "${1//,/, }"
}

quiesce_race_document() {
  local outcomes="" token permit work
  for token in $(quiesce_seq_endings); do
    # Back to the fields the gate serves from the identity a reader renders:
    # every field of the ending comes off the end and the node's own name off
    # the front, because the reader is what joins them into one token.
    permit="$(authored_permit "${token}")"
    work="$(identity_work "${permit}")"
    outcomes="${outcomes}${outcomes:+,}
      {
        \"outcome\": \"$(authored_outcome "${token}")\",
        \"evidence\": {
          \"kind\": \"$(authored_evidence_kind "${token}")\",
          \"reference\": \"$(authored_result "${token}")\",
          \"contribution\": {
            \"incorporated_members\": $(quiesce_race_members \
              "$(authored_incorporated "${token}")"),
            \"local_members\": $(quiesce_race_members \
              "$(authored_local "${token}")")
          }
        },
        \"permit\": {
          \"identity_bound\": true,
          \"ceremony\": \"$(work_ceremony "${work}")\",
          \"canonical_start_block\": $(work_anchor "${work}"),
          \"work_id\": \"${work##*@}\",
          \"permit_id\": \"${permit##*#}\"
        }
      }"
  done
  cat <<EOF
{
  "protocol_participation": {
    "gate_state": "quiescing",
    "active_legacy_ceremonies": 0,
    "active_security_v2_ceremonies": 0,
    "recent_terminal_outcomes": [${outcomes}
    ]
  }
}
EOF
}

quiesce_race_case() {
  # shellcheck disable=SC2034
  REHEARSAL_R1_CUTOVER_BLOCK="1000"
  # shellcheck disable=SC2034
  PR4109_WORK_DRIVER="/nonexistent/driver-is-stubbed"
  quiesce_sequencing_stubs 840
  # shellcheck disable=SC2034
  QUIESCE_SEQ_SEEDED=1
  # shellcheck disable=SC2034
  QUIESCE_SEEDED_ASKED=1
  # shellcheck disable=SC2034
  QUIESCE_SEEDED_RC=0
  QUIESCE_SEEDED_WORK="tbtc_signing@840@wallet840=${QUIESCE_SEQ_TX}=r1-node-1~member-1"
  # shellcheck disable=SC2034
  QUIESCE_SEEDED_PERMITS_BEFORE_C="r1-node-1@tbtc_signing@840@wallet840#member-1"

  # The whole point of the case: the real reader — which is why no snapshot
  # stub is installed here — against a node that answers one request and is
  # then gone. The counter is a file because each fetch runs in its own command
  # substitution.
  : >"${QUIESCE_RACE_FETCHES}"
  # Invoked by the reader under test, which shellcheck cannot see across the
  # source boundary into rehearse.sh.
  # shellcheck disable=SC2329
  probe_diagnostics() {
    printf 'x' >>"${QUIESCE_RACE_FETCHES}"
    if (($(wc -c <"${QUIESCE_RACE_FETCHES}") > QUIESCE_RACE_ANSWERS)); then
      return 1
    fi
    quiesce_race_document
  }
  "$@"
  run_quiescence_control r1-node-1 \
    "quiescence with an in-flight legacy permit" \
    "" legacy active_legacy_ceremonies participation_mode_legacy_total \
    quiesce-legacy "${QUIESCE_SEEDED_WORK}"
}

QUIESCE_RACE_ANSWERS=1
run_verdict quiesce_race_case :
check "a node that answers once and exits still evidences its own drain" 0 \
  "seeded before C and live beside r1-node-1@tbtc_signing@1200@colive900#other-1" \
  "quiescence with an in-flight legacy permit"

# The mirror, which keeps the case above from passing for the wrong reason: a
# node that stops before it answers at all leaves nothing to read, and the
# control has to say so rather than treat an unanswered drain as a clean one.
run_verdict quiesce_race_case eval 'QUIESCE_RACE_ANSWERS=0'
check "a node that stops before answering evidences no drain at all" 1 \
  "never reported quiescing"

# The reading the whole seeding exists for: the driver says it anchored the
# work below C, and the gate that would have issued the permit never reported
# holding it there.
run_verdict quiesce_seeded_case eval \
  'QUIESCE_SEEDED_PERMITS_BEFORE_C="r1-node-1@tbtc_signing@840@somethingelse#member-9"'
check "a permit the gate never held below C is not pre-C legacy work" 3 \
  "was not holding r1-node-1@tbtc_signing@840@wallet840#member-1"

run_verdict quiesce_seeded_case eval \
  'QUIESCE_SEEDED_PERMITS_BEFORE_C="unreadable on r1-node-1"'
check "a gate unread below C cannot vouch for a seeded permit" 3 \
  "could not be asked which legacy permits it held before C"

# A gate draining one population never has to keep the two modes apart, which
# is the fence quiescence is supposed to hold.
run_verdict quiesce_seeded_case eval 'QUIESCE_SEQ_COLIVE=""'
check "a legacy drain with no security-v2 permit beside it exercises no fence" 3 \
  "held only legacy permits when the stop was issued"

run_verdict quiesce_seeded_case eval \
  'QUIESCE_SEQ_COLIVE="unreadable on r1-node-1"'
check "an unread other-mode population leaves the fence unexercised" 3 \
  "could not be asked whether it held a permit of the other mode"

# Both live modes have to finish or enter audited quarantine, so the other
# mode's permits are followed to an end on the same footing as the drained
# one's. These four take that half away in turn: a gate list nobody can match
# to work, a second population anchored on the same side of C as the first,
# the two disagreeing about which permits were live, and — the reading the
# whole half exists for — an other-mode permit the drain simply never accounts
# for.
run_verdict quiesce_seeded_case eval 'QUIESCE_SEQ_COLIVE_WORK=""'
check "an other-mode permit nothing identifies cannot be followed" 3 \
  "the driver named no work it put there"

# shellcheck disable=SC2016
run_verdict quiesce_seeded_case eval \
  'QUIESCE_SEQ_COLIVE_WORK="tbtc_signing@840@colive900=${QUIESCE_SEQ_COLIVE_TX}=r1-node-1~other-1"'
check "a second population on the same side of C exercises no fence" 3 \
  "is not security-v2-anchored work"

run_verdict quiesce_seeded_case eval \
  'QUIESCE_SEQ_COLIVE="r1-node-1@tbtc_signing@1200@somethingelse#other-9"'
check "an other-mode permit the gate never held is the driver's word" 3 \
  "does not include r1-node-1@tbtc_signing@1200@colive900#other-1"

run_verdict quiesce_seeded_case eval 'QUIESCE_SEQ_COLIVE_TERMINAL=""'
check "an other-mode permit with no terminal outcome is unaccounted for" 3 \
  "reported no terminal outcome for tbtc_signing@1200@colive900"

# The accounting every "was work offered here" rung above reads. It comes off a
# real driver invocation rather than a constructed reading, because what is
# being tested is that the driver's own exit status and report reach those
# rungs at all — which is exactly what `|| true` around the call used to
# discard.
DRIVER="${WORK}/work-driver"
HASH_A="0x$(printf 'a%.0s' {1..64})"
HASH_B="0x$(printf 'b%.0s' {1..64})"

write_driver() {
  cat >"${DRIVER}"
  chmod +x "${DRIVER}"
}

drive() {
  set +e
  CASE_OUT="$(
    (
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_WORK_DRIVER="${DRIVER}"
      # shellcheck disable=SC2030,SC2031,SC2034
      STEP_TX_HASHES=""
      run_work_driver "$1" || true
      printf 'results:%s\n' "${WORK_DRIVER_CEREMONY_RESULTS}"
      printf 'originated:%s\n' "${WORK_DRIVER_ORIGINATED}"
      printf 'bound:%s\n' "${WORK_DRIVER_BOUND_RESULTS}"
      printf 'work:%s\n' "${WORK_DRIVER_ORIGINATED_WORK}"
      if driver_offered_work; then
        printf 'offered:yes rc:%s tx:%s hashes:%s\n' \
          "${WORK_DRIVER_RC}" "${WORK_DRIVER_TX_COUNT}" "${STEP_TX_HASHES}"
      else
        printf 'offered:no rc:%s tx:%s\n' \
          "${WORK_DRIVER_RC}" "${WORK_DRIVER_TX_COUNT}"
      fi
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}","${HASH_B}"]}'
EOF
drive homogeneous-security-v2
check "a driver that succeeds and names its transactions has offered work" 0 \
  "offered:yes rc:0 tx:2" "${HASH_A}"

write_driver <<'EOF'
#!/usr/bin/env bash
printf '{"transaction_hashes":[]}'
EOF
drive homogeneous-security-v2
check "a driver that originated nothing has offered no work" 0 \
  "offered:no rc:0 tx:0"

write_driver <<'EOF'
#!/usr/bin/env bash
printf '{}'
EOF
drive homogeneous-security-v2
check "a driver reporting no transactions at all has offered no work" 0 \
  "offered:no rc:0 tx:0"

write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"]}'
exit 6
EOF
drive homogeneous-security-v2
check "a driver that failed has offered no work whatever it printed" 0 \
  "offered:no rc:6 tx:1"

write_driver <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
drive homogeneous-security-v2
check "a silent driver has offered no work" 0 "offered:no rc:0 tx:0"

write_driver <<'EOF'
#!/usr/bin/env bash
printf 'not json at all'
EOF
drive homogeneous-security-v2
check "a driver whose report cannot be read stops the step" 3 \
  "in a form this rehearsal cannot read"

# The terminal outcomes, which no fleet counter carries: a permit says a node
# was allowed to begin and a positive control is about a ceremony finishing.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}","${HASH_B}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"succeeded",'
printf '"canonical_start_block":500,"work_id":"sign500",'
printf '"transaction_hash":"${HASH_A}","result":"0xsigned","contributors":[{"service":"r1-node-1","permit_id":"1"}]},'
printf '{"ceremony":"beacon_dkg","outcome":"failed",'
printf '"canonical_start_block":501,"work_id":"seed501",'
printf '"transaction_hash":"${HASH_B}","termination":"no_threshold"}]}'
EOF
drive homogeneous-security-v2
check "a driver names the ceremonies it saw complete" 0 \
  "offered:yes rc:0 tx:2"

# The binding itself: each outcome carries the piece of work it belongs to,
# identified by the chain anchor its permit pinned from, the transaction that
# started it, and what it left behind — so a control cannot read an outcome
# against a hash that had nothing to do with it, nor take one outcome for as
# many runs of that ceremony as happen to be outstanding.
check "each outcome is bound to its transaction and what it produced" 0 \
  "bound:tbtc_signing@500@sign500=succeeded=${HASH_A}=0xsigned \
beacon_dkg@501@seed501=failed=${HASH_B}=no_threshold"
# The reading the controls actually decide on, taken over the same parse: only
# the ceremony that settled is a settlement, and it is named with the
# transaction and the threshold output rather than on its own.
SETTLED_OUT="$(bound_settlements \
  "tbtc_signing@500@sign500=succeeded=${HASH_A}=0xsigned \
beacon_dkg@501@seed501=failed=${HASH_B}=no_threshold")"
if [[ "${SETTLED_OUT}" == \
  "tbtc_signing@500@sign500 (${HASH_A}, 0xsigned)" ]]; then
  printf 'ok   only the ceremonies that settled are carried forward\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL a failed ceremony was carried forward as a settlement: %s\n' \
    "${SETTLED_OUT}"
  FAILED=$((FAILED + 1))
fi

# Its mirror, for the controls whose claim is that work came to nothing: the
# ceremony that did not settle is named with the termination that says it
# stopped trying.
TERMINATED_OUT="$(bound_terminations \
  "tbtc_signing@500@sign500=succeeded=${HASH_A}=0xsigned \
beacon_dkg@501@seed501=failed=${HASH_B}=no_threshold")"
if [[ "${TERMINATED_OUT}" == \
  "beacon_dkg@501@seed501=failed (${HASH_B}, no_threshold)" ]]; then
  printf 'ok   an unsettled ceremony is named with why it stopped\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL an unsettled ceremony lost its termination: %s\n' \
    "${TERMINATED_OUT}"
  FAILED=$((FAILED + 1))
fi
# And the one the successes alone could not carry: the failure is still there
# for a phase to read, rather than having been dropped at the parse.
if [[ "${CASE_OUT}" == *"results:tbtc_signing=succeeded beacon_dkg=failed"* ]]; then
  printf 'ok   an outcome that was not a success survives the parse\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL a failed outcome was discarded at the parse: %s\n' "${CASE_OUT}"
  FAILED=$((FAILED + 1))
fi

# What a phase over work still in flight reads instead of a terminal outcome:
# by the time one exists the work it was about is over. Each piece names the
# anchor that identifies it and the nodes that took a permit for it, because a
# drain reconciles per (node, work) and a ceremony name carries neither.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}","${HASH_B}"],'
printf '"originated_ceremonies":[{"ceremony":"tbtc_signing",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}","holders":['
printf '{"service":"r1-node-1","permit_id":"1"},'
printf '{"service":"r1-node-1","permit_id":"2"},'
printf '{"service":"r1-node-2","permit_id":"1"}]},'
printf '{"ceremony":"tbtc_wallet_action","canonical_start_block":601,'
printf '"work_id":"action601","transaction_hash":"${HASH_B}",'
printf '"holders":[{"service":"r1-node-2","permit_id":"wallet-a"}]}]}'
EOF
drive rollback-inflight
check "a driver names the work it put on the chain before it settles" 0 \
  "originated:tbtc_signing tbtc_wallet_action" "results:" \
  "work:tbtc_signing@600@sign600=${HASH_A}=r1-node-1~1 \
tbtc_signing@600@sign600=${HASH_A}=r1-node-1~2 \
tbtc_signing@600@sign600=${HASH_A}=r1-node-2~1 \
tbtc_wallet_action@601@action601=${HASH_B}=r1-node-2~wallet-a"

write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],'
printf '"originated_ceremonies":[{"ceremony":"a wallet action probably",'
printf '"canonical_start_block":600,"transaction_hash":"${HASH_A}",'
printf '"holders":["r1-node-1"]}]}'
EOF
drive rollback-inflight
check "originated work this rehearsal does not know stops the step" 3 \
  "not a ceremony"

# A ceremony name with no anchor behind it identifies nothing: two runs of one
# ceremony are the same word, and the permits behind them are what a drain has
# to follow separately.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],'
printf '"originated_ceremonies":["tbtc_signing"]}'
EOF
drive rollback-inflight
check "in-flight work named only by its ceremony stops the step" 3 \
  "originated work is not an object naming a ceremony, canonical start block"

# Work nobody holds is work no permit was issued for, and a permit is what the
# drain reconciles.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],'
printf '"originated_ceremonies":[{"ceremony":"tbtc_signing",'
printf '"canonical_start_block":600,"transaction_hash":"${HASH_A}"}]}'
EOF
drive rollback-inflight
check "in-flight work no node holds stops the step" 3 \
  "names no holding node"

# An anchor can contain several distinct chain events. Without the event,
# request, wallet action, group, or seed identity, the report still cannot say
# which work its local permits belong to.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],'
printf '"originated_ceremonies":[{"ceremony":"tbtc_signing",'
printf '"canonical_start_block":600,"transaction_hash":"${HASH_A}",'
printf '"holders":[{"service":"r1-node-1","permit_id":"1"}]}]}'
EOF
drive rollback-inflight
check "in-flight work naming no chain work identity stops the step" 3 \
  "names no chain work id"

# Holder names alone collapse two memberships on one node into one permit.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],'
printf '"originated_ceremonies":[{"ceremony":"tbtc_signing",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}","holders":["r1-node-1"]}]}'
EOF
drive rollback-inflight
check "a holder naming no local permit identity stops the step" 3 \
  "not a holding node"

# The same local membership cannot account for two permits. Distinct permit
# IDs on one holder are accepted by the positive fixture above.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],'
printf '"originated_ceremonies":[{"ceremony":"tbtc_signing",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}","holders":['
printf '{"service":"r1-node-1","permit_id":"1"},'
printf '{"service":"r1-node-1","permit_id":"1"}]}]}'
EOF
drive rollback-inflight
check "one local permit originated twice stops the step" 3 \
  "local permit originated twice"

# The same piece of work reported twice is either a duplicate or two permits
# claimed from one origination; both make a reconciliation count it twice.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}","${HASH_B}"],'
printf '"originated_ceremonies":[{"ceremony":"tbtc_signing",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}",'
printf '"holders":[{"service":"r1-node-1","permit_id":"1"}]},'
printf '{"ceremony":"tbtc_signing","canonical_start_block":600,'
printf '"work_id":"sign600","transaction_hash":"${HASH_B}",'
printf '"holders":[{"service":"r1-node-2","permit_id":"1"}]}]}'
EOF
drive rollback-inflight
check "one piece of work originated twice stops the step" 3 \
  "work originated twice"

# Two work classes claimed from one transaction. Read as parallel arrays this
# is a driver that drove both halves of the release; read as work it is one
# origination with two accounts of what it started.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],'
printf '"originated_ceremonies":[{"ceremony":"tbtc_signing",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}",'
printf '"holders":[{"service":"r1-node-1","permit_id":"1"}]},'
printf '{"ceremony":"beacon_dkg","canonical_start_block":601,'
printf '"work_id":"seed601","transaction_hash":"${HASH_A}",'
printf '"holders":[{"service":"r1-node-1","permit_id":"1"}]}]}'
EOF
drive rollback-inflight
check "one transaction claimed by two pieces of work stops the step" 3 \
  "transaction claimed by two pieces of work"

# And its mirror across the terminal half: one transaction reused between the
# tBTC and beacon outcomes.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"succeeded",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}","result":"0xs","contributors":[{"service":"r1-node-1","permit_id":"1"}]},'
printf '{"ceremony":"beacon_dkg","outcome":"succeeded",'
printf '"canonical_start_block":601,"work_id":"seed601",'
printf '"transaction_hash":"${HASH_A}","result":"0xg","contributors":[{"service":"r1-node-1","permit_id":"1"}]}]}'
EOF
drive homogeneous-security-v2
check "one transaction reused across both halves stops the step" 3 \
  "transaction claimed by two pieces of work"

# The inverse binding matters too. The ceremony and anchor identify the same
# piece of work in both halves of this report, so changing only its transaction
# must be refused rather than treated as an independent terminal observation.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}","${HASH_B}"],'
printf '"originated_ceremonies":[{"ceremony":"tbtc_signing",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}",'
printf '"holders":[{"service":"r1-node-1","permit_id":"1"}]}],'
printf '"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"succeeded",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_B}","result":"0xs","contributors":[{"service":"r1-node-1","permit_id":"1"}]}]}'
EOF
drive rollback-terminal
check "one piece of work cannot change transactions at its terminal result" 3 \
  "work claimed by two transactions"

# One piece of work ends once. A second terminal record for it is an outcome
# counted twice by everything downstream.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}","${HASH_B}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"succeeded",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}","result":"0xs","contributors":[{"service":"r1-node-1","permit_id":"1"}]},'
printf '{"ceremony":"tbtc_signing","outcome":"failed",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_B}","termination":"no_threshold"}]}'
EOF
drive homogeneous-security-v2
check "one piece of work reported terminal twice stops the step" 3 \
  "work reported terminal twice"

write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"probably fine"}]}'
EOF
drive homogeneous-security-v2
check "an outcome this rehearsal does not know stops the step" 3 \
  "not an outcome"

write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],"ceremony_results":['
printf '{"ceremony":"something_else","outcome":"succeeded"}]}'
EOF
drive homogeneous-security-v2
check "a ceremony this rehearsal does not know stops the step" 3 \
  "not a ceremony"

# An outcome that names no anchor names no particular ceremony run, and every
# control that follows a permit to it would be following a ceremony name.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"succeeded",'
printf '"transaction_hash":"${HASH_A}","result":"0xs","contributors":[{"service":"r1-node-1","permit_id":"1"}]}]}'
EOF
drive homogeneous-security-v2
check "an outcome naming no anchor identifies no piece of work" 3 \
  "names no canonical start block"

# The regression this binding exists for. An outcome with no transaction
# behind it is one population and the reported hashes are another: a stale or
# unrelated hash sitting beside an unrelated result satisfied every control
# that read the two as parallel arrays.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"succeeded",'
printf '"canonical_start_block":600,"work_id":"sign600","result":"0xs","contributors":[{"service":"r1-node-1","permit_id":"1"}]}]}'
EOF
drive homogeneous-security-v2
check "an outcome naming no transaction stops the step" 3 \
  "carries no transaction hash"

# And the same hole one step in: a transaction this report never claimed to
# have originated attributes the outcome to work done by somebody else.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"succeeded",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_B}","result":"0xs","contributors":[{"service":"r1-node-1","permit_id":"1"}]}]}'
EOF
drive homogeneous-security-v2
check "an outcome naming a transaction nobody originated stops the step" 3 \
  "did not originate"

# "succeeded" is a word; a threshold output is a thing the ceremony left
# behind. A positive control that cannot name one has not seen a ceremony
# settle, it has read a report that says so.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"succeeded",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}"}]}'
EOF
drive homogeneous-security-v2
check "a success with no threshold output behind it stops the step" 3 \
  "carries no threshold output identity"

# A threshold output says a ceremony settled; it does not say who settled it.
# Every mixed-fleet control asks which releases took part, and a result that
# named nobody would leave that question answerable only from which containers
# happened to be running.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"succeeded",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}","result":"0xs"}]}'
EOF
drive homogeneous-security-v2
check "a settled result naming no contributing party stops the step" 3 \
  "names no contributing party"

write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"succeeded",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}","result":"0xs",'
printf '"contributors":[{"service":"r1-node-1"}]}]}'
EOF
drive homogeneous-security-v2
check "a contributing party with no local permit identity stops the step" 3 \
  "names no local permit identity"

# One party contributes to one transcript once. Repeating it would let a
# single contribution be counted as the several a threshold needs, which is
# exactly how a homogeneous run could look like it met one.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"succeeded",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}","result":"0xs",'
printf '"contributors":[{"service":"r1-node-1","permit_id":"1"},'
printf '{"service":"r1-node-1","permit_id":"1"}]}]}'
EOF
drive homogeneous-security-v2
check "one party counted twice in a transcript stops the step" 3 \
  "party contributed twice to one result"

# The mirror, for the fails-closed controls: "failed" is equally what a
# ceremony still retrying looks like from outside, and a control about work
# that came to nothing cannot be read off work still in progress.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"failed",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}"}]}'
EOF
drive homogeneous-security-v2
check "an unsettled outcome with no termination behind it stops the step" 3 \
  "carries no termination evidence"

write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"timed_out",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}","termination":"gave up I think"}]}'
EOF
drive homogeneous-security-v2
check "a termination this rehearsal does not know stops the step" 3 \
  "carries no termination evidence"

# A driver that printed a readable report and then failed. The report parses,
# every field is bound, and the exit status still has to reach the step —
# which is what decides whether any of it counts as work having been driven.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"succeeded",'
printf '"canonical_start_block":600,"work_id":"sign600",'
printf '"transaction_hash":"${HASH_A}","result":"0xs","contributors":[{"service":"r1-node-1","permit_id":"1"}]}]}'
exit 9
EOF
drive rollback-terminal
check "a readable report from a driver that failed still reports failure" 0 \
  "offered:no rc:9" \
  "bound:tbtc_signing@600@sign600=succeeded=${HASH_A}=0xs"

# The chain itself, asked about what a report claims. Every other check on a
# driver report is a check of the report against itself: the hashes look like
# hashes, the outcomes name them, the anchors identify work. A report that is
# internally consistent and entirely invented passes all of it, and only the
# chain can tell the two apart.
CONFIRM_WORK="tbtc_signing@600@sign600=${HASH_A}=r1-node-1~1"
CONFIRM_BOUND="tbtc_signing@600@sign600=succeeded=${HASH_A}=0xsigned"

confirm_case() {
  set +e
  CASE_OUT="$(
    (
      "$@"
      confirm_reported_work rollback-inflight "\"${HASH_A}\"" \
        "${CONFIRM_WORK}" "${CONFIRM_BOUND}"
      printf 'confirmed\n'
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

confirm_case :
check "a report the chain corroborates is confirmed" 0 "confirmed"

# The regression this seam exists for: the transaction is on chain and it
# reverted, which from outside is the same shape as one that succeeded.
confirm_case eval 'FIXTURE_RECEIPT_STATUS="0x0"'
check "a reverted transaction started no work a control can rest on" 3 \
  "records as reverted"

confirm_case eval 'FIXTURE_RECEIPT_ABSENT=1
   WORK_DRIVER_CONFIRMATION_TIMEOUT=0'
check "a transaction the chain never mined started nothing" 3 \
  "still has no receipt for"

confirm_case eval 'FIXTURE_RPC_BODY="not json"'
check "an endpoint that cannot be read confirms nothing" 3 \
  "could not be asked what became of it"

confirm_case eval \
  'FIXTURE_RPC_BODY="{\"error\":{\"code\":-32000,\"message\":\"nope\"}}"'
check "an endpoint that answers with an error confirms nothing" 3 \
  "could not be asked what became of it"

# An anchor earlier than the block its own transaction landed in is a permit
# pinning its mode from a block at which the work did not exist — which is
# exactly what a report inventing anchors produces.
confirm_case eval 'FIXTURE_RECEIPT_BLOCK="0x300"'
check "work anchored before its own transaction is refused" 3 \
  "anchors tbtc_signing@600@sign600 at block 600, but the transaction it names \
landed \
in block 768"

# And a report naming nothing: there is nothing to confirm, and demanding an
# endpoint for it would block every phase that legitimately drove no work.
confirm_case eval 'CONFIRM_WORK=""; CONFIRM_BOUND=""'
check "a report naming transactions is confirmed whatever else it carries" 0 \
  "confirmed"

CONFIRM_NOTHING_OUT=""
set +e
CONFIRM_NOTHING_OUT="$(
  (
    # The stage under test reads this; shellcheck cannot follow it across the
    # source boundary into rehearse.sh.
    # shellcheck disable=SC2030,SC2034
    ETH_RPC_URL=""
    confirm_reported_work rollback-inflight "" "" ""
    printf 'confirmed\n'
  ) 2>&1
)"
CONFIRM_NOTHING_RC=$?
set -e
if [[ "${CONFIRM_NOTHING_RC}" -eq 0 && \
  "${CONFIRM_NOTHING_OUT}" == *"confirmed"* ]]; then
  printf 'ok   a report naming no transaction needs no chain to confirm it\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL an empty report demanded a chain endpoint: rc %s, %s\n' \
    "${CONFIRM_NOTHING_RC}" "${CONFIRM_NOTHING_OUT}"
  FAILED=$((FAILED + 1))
fi

# The endpoint has to be the chain the fleet ran on. One answering about some
# other chain confirms transactions that have nothing to do with this
# rehearsal, in exactly the same shape.
endpoint_case() {
  set +e
  CASE_OUT="$(
    (
      # shellcheck disable=SC2030,SC2034
      CHAIN_ID="11155111"
      "$@"
      verify_chain_endpoint
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

endpoint_case :
check "an endpoint on the rehearsed chain is accepted" 0 \
  "confirmed on chain id 11155111"

endpoint_case eval 'FIXTURE_CHAIN_ID="0x1"'
check "an endpoint answering about another chain confirms nothing" 3 \
  "reports chain id \[1\], but this rehearsal names \[11155111\]"

endpoint_case eval 'FIXTURE_RPC_BODY="{}"'
check "an endpoint with no readable chain id confirms nothing" 3 \
  "did not report a chain id this rehearsal can read"

# The two programs the rehearsal executes but does not contain. Both arrive
# from a mutable secret bundle, and both produce readings that become release
# evidence, so an executable bit is not enough: the bytes have to hash to a
# digest reviewed in a commit before the rehearsal will run them.
INPUT_CONTROL="${WORK}/chain-inputs.sha256"
INPUT_PROGRAM="${WORK}/work-driver-fixture"

printf '#!/usr/bin/env bash\nprintf "{}"\n' >"${INPUT_PROGRAM}"
chmod +x "${INPUT_PROGRAM}"
INPUT_DIGEST="$(hash_stdin <"${INPUT_PROGRAM}")"

input_case() {
  set +e
  CASE_OUT="$(
    (
      require_reviewed_input PR4109_WORK_DRIVER work-driver "$1" \
        "${INPUT_CONTROL}"
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

cat >"${INPUT_CONTROL}" <<EOF
# a reviewed control file
${INPUT_DIGEST}  work-driver
EOF
input_case "${INPUT_PROGRAM}"
check "a program hashing to its reviewed digest is recorded by that digest" \
  0 "${INPUT_DIGEST}"

input_case ""
check "a rehearsal handed no program has none to bind" 0 "^$"

input_case "${WORK}/no-such-program"
check "a program that is not executable drives nothing" 3 \
  "is not an executable program"

# The regression this control exists for: the bundle is mutable, so the bytes
# that arrive are not necessarily the bytes anybody read.
printf '#!/usr/bin/env bash\nprintf "{}"\nexit 0\n' >"${INPUT_PROGRAM}"
chmod +x "${INPUT_PROGRAM}"
input_case "${INPUT_PROGRAM}"
check "a program that is not the reviewed one stops the rehearsal" 3 \
  "hashes to" "pins work-driver at ${INPUT_DIGEST}"

cat >"${INPUT_CONTROL}" <<'EOF'
# a control file pinning something else entirely
0000000000000000000000000000000000000000000000000000000000000001  rollback-evidence-generator
EOF
input_case "${INPUT_PROGRAM}"
check "a program no reviewed digest names at all is unbound" 3 \
  "no reviewed SHA-256 for work-driver is recorded"

rm -f "${INPUT_CONTROL}"
input_case "${INPUT_PROGRAM}"
check "a missing control file pins nothing and binds nothing" 3 \
  "no reviewed SHA-256 for work-driver is recorded"

# The third external input, which the rehearsal never executes: the archived
# independent review of the dependency revision the build resolves. It is
# bound twice — to a digest reviewed in a commit, and to the commit go.mod
# resolves — because either binding alone admits a review of other code.
REVIEW_CONTROL="${WORK}/review-inputs.sha256"
REVIEW_RECORD="${WORK}/tsslib-review-fixture.md"
REVIEW_REPO="${WORK}/review-repo"
mkdir -p "${REVIEW_REPO}"
REVIEW_COMMIT="d847ce003019"
cat >"${REVIEW_REPO}/go.mod" <<EOF
module example

replace (
	github.com/bnb-chain/tss-lib => github.com/threshold-network/tss-lib v0.0.0-20260729021955-${REVIEW_COMMIT}
)
EOF

review_case() {
  set +e
  CASE_OUT="$(
    (
      # shellcheck disable=SC2030,SC2031,SC2034
      REPO_ROOT="${2:-${REVIEW_REPO}}"
      require_reviewed_record PR4109_TSSLIB_REVIEW tsslib-review "$1" \
        "${REVIEW_CONTROL}"
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

printf 'reviewed %s: no findings\n' "${REVIEW_COMMIT}" >"${REVIEW_RECORD}"
REVIEW_DIGEST="$(hash_stdin <"${REVIEW_RECORD}")"
cat >"${REVIEW_CONTROL}" <<EOF
# a reviewed control file
${REVIEW_DIGEST}  tsslib-review
EOF

review_case "${REVIEW_RECORD}"
check "a review record hashing to its reviewed digest and naming the pinned \
revision is accepted" 0 "${REVIEW_DIGEST}"

review_case ""
check "a rehearsal handed no review record has none to bind" 0 "^$"

review_case "${WORK}/no-such-review"
check "a review record that cannot be read is bound to nothing" 3 \
  "is not a readable file"

# The substitution the commit binding exists for: a real, reviewed-looking
# document about some other revision of the dependency.
printf 'reviewed 0000000000ff: no findings\n' >"${WORK}/other-review"
cat >"${REVIEW_CONTROL}" <<EOF
$(hash_stdin <"${WORK}/other-review")  tsslib-review
EOF
review_case "${WORK}/other-review"
check "a review of another revision is not a review of the pinned one" 3 \
  "does not name the dependency revision \[${REVIEW_COMMIT}\]"

# And the mutable-bundle regression, identical in shape to the driver one: a
# document naming the right revision is still not the reviewed document.
printf 'reviewed %s: findings withdrawn\n' "${REVIEW_COMMIT}" \
  >"${WORK}/edited-review"
cat >"${REVIEW_CONTROL}" <<EOF
${REVIEW_DIGEST}  tsslib-review
EOF
review_case "${WORK}/edited-review"
check "an edited review record stops the rehearsal" 3 \
  "hashes to" "pins tsslib-review at ${REVIEW_DIGEST}"

cat >"${REVIEW_CONTROL}" <<'EOF'
# a control file pinning something else entirely
0000000000000000000000000000000000000000000000000000000000000001  work-driver
EOF
review_case "${REVIEW_RECORD}"
check "a review record no reviewed digest names at all is unbound" 3 \
  "no reviewed SHA-256 for tsslib-review is recorded"

# A tree whose build resolves no replacement has no revision for a review to
# be about, so nothing can be bound and nothing is accepted.
cat >"${REVIEW_CONTROL}" <<EOF
${REVIEW_DIGEST}  tsslib-review
EOF
mkdir -p "${WORK}/no-replace-repo"
printf 'module example\n' >"${WORK}/no-replace-repo/go.mod"
review_case "${REVIEW_RECORD}" "${WORK}/no-replace-repo"
check "a tree resolving no dependency replacement binds no review" 3 \
  "resolves no github.com/bnb-chain/tss-lib replacement"

# The revision the binding is against is the one this tree actually builds,
# read where the build reads it.
CHECKED_IN_TSSLIB="$(pinned_tsslib_commit)"
if [[ "${CHECKED_IN_TSSLIB}" =~ ^[0-9a-f]{12}$ ]]; then
  printf 'ok   the pinned dependency revision is read out of go.mod\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL go.mod resolved the dependency revision as [%s]\n' \
    "${CHECKED_IN_TSSLIB}"
  FAILED=$((FAILED + 1))
fi

CHECKED_IN_REVIEW="$(reviewed_input_digest tsslib-review)"
if [[ "${CHECKED_IN_REVIEW}" == \
  "0000000000000000000000000000000000000000000000000000000000000000" ]]; then
  printf 'ok   the checked-in control pins no dependency review\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the checked-in tsslib-review digest is [%s]; if a review has \
been archived this expectation moves with it\n' "${CHECKED_IN_REVIEW}"
  FAILED=$((FAILED + 1))
fi

# And the checked-in control itself: the placeholder must match no program, so
# a rehearsal cannot be dispatched with an unreviewed driver until a reviewed
# digest is recorded in a reviewed commit.
CHECKED_IN_DRIVER="$(reviewed_input_digest work-driver)"
if [[ "${CHECKED_IN_DRIVER}" == \
  "0000000000000000000000000000000000000000000000000000000000000000" ]]; then
  printf 'ok   the checked-in control pins no driver a rehearsal could run\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the checked-in work-driver digest is [%s]; if a driver has \
been reviewed this expectation moves with it\n' "${CHECKED_IN_DRIVER}"
  FAILED=$((FAILED + 1))
fi

# Neither container stage can be executed anywhere but a real rehearsal — they
# need the immutable images, a chain, and persistent volumes — so a call site
# left pointing at a renamed helper survives every check in this file and
# every static analyzer, and surfaces in the most expensive place there is.
# Each helper those stages name in command position must therefore exist now.
# Only names carrying an underscore are examined: those are this driver's own
# helpers, and testing them says nothing about which external tools happen to
# be installed on the machine running the self-test.
UNDEFINED_HELPERS=""
while read -r HELPER; do
  [[ -n "${HELPER}" ]] || continue
  declare -F "${HELPER}" >/dev/null 2>&1 ||
    UNDEFINED_HELPERS="${UNDEFINED_HELPERS} ${HELPER}"
done < <(awk '
  /^(stage_single_release|stage_rollback|fleet_up|capture_r1_release_identity|run_state_audit|emit_evidence_record)\(\) \{/ { inside = 1 }
  inside {
    # A wrapped string continues the line before it, so its first word is
    # prose and not a command. Dropping those is what keeps this a scan of
    # call sites rather than of the refusal messages around them.
    if (!continuation) print
    continuation = (/\\$/) ? 1 : 0
  }
  inside && /^\}/ { inside = 0 }
' "${TEST_DIR}/rehearse.sh" |
  sed -E 's/^[[:space:]]*//; s/^(if|elif|until|while|then|else|do|!)[[:space:]]+//' |
  grep -oE '^[a-z_][a-z0-9_]*([[:space:]]|$)' |
  sed -E 's/[[:space:]]+$//' | sort -u | grep _)
if [[ -z "${UNDEFINED_HELPERS}" ]]; then
  printf 'ok   every helper the container stages call is defined\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the container stages call undefined helpers:%s\n' \
    "${UNDEFINED_HELPERS}"
  FAILED=$((FAILED + 1))
fi

# The per-ceremony refusal counters are what turn "the node refused something"
# into "the node refused this", and a ceremony the shell list omits is a
# refusal the rehearsal reads as unattributed — a quiescence that really did
# refuse would then block for naming nothing. So the list is held to the closed
# set the client publishes, which is the same set the gate's own drift test
# pins the metric names to.
GO_CEREMONIES="$(sed -n '/func GetAllParticipationCeremonies/,/^}/p' \
  "${TEST_DIR}/../../../pkg/clientinfo/performance.go" |
  grep -oE '"[a-z_]+"' | tr -d '"' | sort)"
SHELL_CEREMONIES="$(printf '%s\n' "${GATED_CEREMONIES[@]}" | sort)"
if [[ -n "${GO_CEREMONIES}" ]] &&
  [[ "${GO_CEREMONIES}" == "${SHELL_CEREMONIES}" ]]; then
  printf 'ok   the refusal-counter list matches the gated ceremony set\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the refusal-counter list drifted from the gated set: %s\n' \
    "$(diff <(printf '%s\n' "${GO_CEREMONIES}") \
      <(printf '%s\n' "${SHELL_CEREMONIES}") | tr '\n' ' ')"
  FAILED=$((FAILED + 1))
fi

# A rehearsal run from bytes no commit accounts for must not produce a record
# at all. The capture is the first refusal — no node can report a revision
# equal to a -dirty stamp — and the emitter carries its own guard for a
# divergence that appears after the capture, so both are driven here and the
# directory is required to stay empty either way.
E="${WORK}/emitted-dirty"
mkdir -p "${E}"
write_attestation "${E}"
echo 'divergence' >"${WORK}/repo/untracked-during-rehearsal"
run_rehearsal "${E}" single_release complete_run
check "a rehearsal on a divergent tree produces no record" 3 \
  "does not name that commit exactly"

# The emitter alone, with the identity the capture would have produced already
# in hand, so this case is about the guard the emitter carries and nothing
# before it.
run_emitter() {
  local dir="$1"
  set +e
  CASE_OUT="$(
    (
      # shellcheck disable=SC2030,SC2031,SC2034
      EVIDENCE_DIR="${dir}"
      # shellcheck disable=SC2030,SC2031,SC2034
      REPO_ROOT="${WORK}/repo"
      # shellcheck disable=SC2030,SC2031,SC2034
      R1_IMAGE_DIGEST="keep/keep-client@sha256:$(printf 'a%.0s' {1..64})"
      # shellcheck disable=SC2030,SC2031,SC2034
      PRIOR_IMAGE_DIGEST="keep/keep-client@sha256:$(printf 'b%.0s' {1..64})"
      # shellcheck disable=SC2030,SC2031,SC2034
      CHAIN_ID="11155111"
      # shellcheck disable=SC2030,SC2031,SC2034
      REHEARSAL_GATE="single_release"
      # shellcheck disable=SC2030,SC2031,SC2034
      WORK_DRIVER_DIGEST="${REVIEWED_WORK_DRIVER_DIGEST}"
      # shellcheck disable=SC2030,SC2031,SC2034
      REHEARSAL_R1_IDENTITY="$(diagnostics_document |
        node -e '
          let raw = "";
          process.stdin.on("data", (d) => (raw += d));
          process.stdin.on("end", () => {
            const doc = JSON.parse(raw);
            process.stdout.write(JSON.stringify(Object.assign(
              {}, doc.client_info, doc.protocol_participation)));
          });
        ')"
      complete_run
      emit_evidence_record
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

run_emitter "${E}"
check "the emitter refuses a record built from bytes no commit accounts for" \
  3 "not a clean commit"

if compgen -G "${E}/*.json" >/dev/null; then
  printf 'FAIL a divergent rehearsal left a record behind\n'
  FAILED=$((FAILED + 1))
else
  printf 'ok   a divergent rehearsal leaves no record behind\n'
  PASS=$((PASS + 1))
fi
rm -f "${WORK}/repo/untracked-during-rehearsal"

# ----------------------------------------------------------------------------
#
# The single-release stage's node allocation. This is a sequencing property
# rather than a validation one, and it is the kind that cannot be caught by
# reading any single step: the permit step 8's legacy half drains is put on the
# chain before C, and three earlier controls in the same stage — the restart,
# the severed chain endpoint, and the security-v2 stop — destroy every permit
# the node they act on is holding. Aiming any of them at the seeded node does
# not fail loudly. The drain simply finds nothing and blocks for a reason that
# reads like a broken work driver, so the whole gate reports an instrument
# problem instead of the collision that caused it.
#
# The order below is read out of the stage's own body rather than restated
# here, so a reallocation in the stage is what this case decides on.

single_release_control_order() {
  declare -f stage_single_release | awk '
    function role(  found) {
      found = match($0, /SINGLE_RELEASE_[A-Z_]+/)
      return found ? substr($0, RSTART, RLENGTH) : "UNRESOLVED"
    }
    /seed_legacy_quiescence_work "\$\{/          { print "seed " role(); next }
    /local restarted="\$\{/                      { print "destroy-restart " role(); next }
    /local clock_node="\$\{/                     { print "destroy-sever " role(); next }
    /run_quiescence_control "\$\{.*in-flight security-v2 permit"/ {
      print "destroy-stop " role(); next
    }
    /run_quiescence_control "\$\{.*in-flight legacy permit"/ {
      print "drain " role(); next
    }
  '
}

pass_case() {
  printf 'ok   %s\n' "$1"
  PASS=$((PASS + 1))
}

fail_case() {
  printf 'FAIL %s\n' "$1"
  [[ -n "${2:-}" ]] && printf -- '--- detail ---\n%s\n--------------\n' "$2"
  FAILED=$((FAILED + 1))
}

if assign_single_release_nodes; then
  pass_case "the rehearsal fleet can carry the single-release controls"
else
  fail_case "the rehearsal fleet can carry the single-release controls" \
    "roster [${REHEARSAL_R1_SERVICES[*]:-empty}]"
fi

# A fleet that cannot separate the two roles must block the stage rather than
# run it with both roles on one node, which is the collision itself.
SAVED_R1_SERVICES=("${REHEARSAL_R1_SERVICES[@]}")
REHEARSAL_R1_SERVICES=("r1-node-1")
if assign_single_release_nodes; then
  fail_case "a one-node fleet is refused the single-release controls"
else
  pass_case "a one-node fleet is refused the single-release controls"
fi
REHEARSAL_R1_SERVICES=("r1-node-1" "r1-node-1")
if assign_single_release_nodes; then
  fail_case "a fleet naming one node twice is refused the controls"
else
  pass_case "a fleet naming one node twice is refused the controls"
fi
REHEARSAL_R1_SERVICES=("${SAVED_R1_SERVICES[@]}")
assign_single_release_nodes

CONTROL_ORDER="$(single_release_control_order)"

# Every control the sequence turns on has to be present and resolved. A site
# that went back to naming a service directly drops out of the extraction
# entirely, which would otherwise read as a stage that never touches the node.
EXPECTED_CONTROLS="destroy-restart destroy-sever destroy-stop drain seed"
SEEN_CONTROLS="$(printf '%s\n' "${CONTROL_ORDER}" | awk 'NF {print $1}' |
  LC_ALL=C sort -u | tr '\n' ' ')"
SEEN_CONTROLS="${SEEN_CONTROLS% }"
if [[ "${SEEN_CONTROLS}" == "${EXPECTED_CONTROLS}" ]]; then
  pass_case "every single-release control names its node through a role"
else
  fail_case "every single-release control names its node through a role" \
    "found [${SEEN_CONTROLS}], want [${EXPECTED_CONTROLS}]"
fi
if printf '%s\n' "${CONTROL_ORDER}" | grep -q 'UNRESOLVED'; then
  fail_case "no single-release control names an unresolvable node" \
    "${CONTROL_ORDER}"
else
  pass_case "no single-release control names an unresolvable node"
fi

# The stage walked in the order it runs, carrying the one permit the sequence
# is about: seeded below C on one node, and required to still be there when
# that node is told to drain.
SEEDED_NODE=""
SEEDED_LOST_TO=""
DRAIN_REACHED=0
DRAIN_HELD_SEED=0
while read -r control role; do
  [[ -n "${control}" ]] || continue
  node="${!role:-}"
  case "${control}" in
  seed)
    SEEDED_NODE="${node}"
    ;;
  destroy-*)
    if [[ -n "${SEEDED_NODE}" && "${node}" == "${SEEDED_NODE}" ]]; then
      SEEDED_LOST_TO="${control} on ${node}"
    fi
    ;;
  drain)
    DRAIN_REACHED=1
    if [[ -n "${SEEDED_NODE}" && "${node}" == "${SEEDED_NODE}" &&
      -z "${SEEDED_LOST_TO}" ]]; then
      DRAIN_HELD_SEED=1
    fi
    ;;
  esac
done <<<"${CONTROL_ORDER}"

if [[ -z "${SEEDED_NODE}" ]]; then
  fail_case "the stage seeds a legacy permit before it crosses C" \
    "${CONTROL_ORDER}"
elif ((DRAIN_REACHED == 0)); then
  fail_case "the stage reaches the legacy drain" "${CONTROL_ORDER}"
elif [[ -n "${SEEDED_LOST_TO}" ]]; then
  fail_case "the seeded legacy permit survives every control before its drain" \
    "seeded on ${SEEDED_NODE}, canceled by ${SEEDED_LOST_TO}
${CONTROL_ORDER}"
elif ((DRAIN_HELD_SEED == 0)); then
  fail_case "the legacy drain runs on the node the permit was seeded on" \
    "seeded on ${SEEDED_NODE}
${CONTROL_ORDER}"
else
  pass_case "the seeded legacy permit reaches its drain on the node it was \
seeded on, through every intervening control"
fi

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
