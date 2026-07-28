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
# Admissibility is not acceptance, and the cases keep the two apart. A
# separate set of records passes every binding check above and still denies
# the gate in its own outcomes — a failed step, a refused acceptance
# assertion with every step passing, a step that never executed, a failure
# beside an unexecuted step, and a failing record sitting beside a passing
# one — because a validator that only checked the shape of those records
# would hand a release a refuted gate as a satisfied one. The rehearsal
# ledger is driven to the same verdicts through the real emitter.
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
#
# The last two arguments are the record's own stages and assertions. They
# default to a rehearsal that held, and the acceptance cases override them
# with the outcomes a record is allowed to carry and a release is not
# allowed to accept — every one of which is schema-valid and correctly
# bound, which is exactly why nothing before the acceptance check can see it.
STAGE_PASSED='{ "name": "preflight", "outcome": "pass" }'
STAGE_FAILED='{ "name": "cross C without restart", "outcome": "fail" }'
STAGE_BLOCKED='{ "name": "quiescence with a legacy permit", "outcome": "blocked" }'
ASSERTION_HOLDS='{ "assertion": "self-test fixture", "holds": true }'
ASSERTION_REFUSED='{ "assertion": "the gate crosses C in-process", "holds": false }'

write_record() {
  local path="$1" sha="$2" grace="$3" generated_at="$4"
  local source_sha="${5:-${FIXTURE_SHA}}"
  local stages="${6:-${STAGE_PASSED}}"
  local assertions="${7:-${ASSERTION_HOLDS}}"
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
  "never executed" "quiescence with a legacy permit"

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
}

quiesce_case() {
  quiesce_readings
  "$@"
  quiescence_verdict r1-node-2
}

run_verdict quiesce_case :
check "a quiescence that refused new work and drained its permits holds" 0 \
  "refused it on its own account \(tbtc_signing \+1" \
  "in-flight count observed at zero"

run_verdict quiesce_case eval 'QUIESCE_ATTEMPTED=0'
check "a quiescing node nobody asked evidences no refusal to start work" 3 \
  "no work was offered to it while it was quiescing"

# The regression this rung exists for: work went out and no permit came back,
# which is what a refusal looks like and equally what an offer that never
# arrived looks like. Only the node's own counter tells the two apart.
run_verdict quiesce_case eval 'QUIESCE_CEREMONY_REFUSALS_AFTER="\
${QUIESCE_CEREMONY_REFUSALS_BEFORE}"
   QUIESCE_REFUSALS_AFTER="7"'
check "an offer the node never recorded refusing is not a refusal" 1 \
  "its own refusal counter never moved"

# A total that moved with no ceremony behind it names nothing a release could
# act on, and the total alone is satisfied by a refusal from any other cause.
run_verdict quiesce_case eval 'QUIESCE_CEREMONY_REFUSALS_AFTER="\
${QUIESCE_CEREMONY_REFUSALS_BEFORE}"'
check "a refusal no ceremony counter accounts for attributes nothing" 3 \
  "no per-ceremony refusal counter moved with the total"

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
  # shellcheck disable=SC2034
  STRAGGLER_RESULTS="tbtc_signing=failed"
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
  "STRAGGLER_RESULTS='tbtc_signing=succeeded'
   straggler_control_verdict '${STRAGGLER_OPERATOR}'"
check "a rostered straggler whose ceremony settled has not failed closed" 1 \
  "produced a threshold output \(tbtc_signing=succeeded\)"

# The same, with the settled ceremony sitting beside one that did not: a report
# is read whole here too.
run_verdict straggler_case eval \
  "STRAGGLER_RESULTS='tbtc_signing=failed beacon_dkg=succeeded'
   straggler_control_verdict '${STRAGGLER_OPERATOR}'"
check "one settled ceremony among the driven work refutes the control" 1 \
  "beacon_dkg=succeeded"

# Retry exhaustion is what makes the outcome terminal. A ceremony still running
# has produced no threshold output yet, which is not the same as having failed
# to produce one, and the sightings would be read off a ceremony mid-flight.
run_verdict straggler_case eval \
  "STRAGGLER_RESULTS=''
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
run_verdict prior_case eval \
  'PRIOR_SAMPLE_LISTING="${PRIOR_SAMPLE_LISTING}
pr4109-rollback/prior-node running pr4109-rollback_rehearsal"
   prior_sample_window'
check "another project's prior left running refutes the barrier" 1 \
  "pr4109-rollback/prior-node on pr4109-rollback_rehearsal" \
  "separate compose project is not quarantine"

# A prior started outside any rehearsal project, recognized by the image it was
# created from rather than by a label it need not carry.
run_verdict prior_case eval \
  'PRIOR_SAMPLE_LISTING="${PRIOR_SAMPLE_LISTING}
stray-prior running bridge"
   prior_sample_window'
check "an unlabelled prior on a network refutes the barrier" 1 \
  "stray-prior on bridge"

# The sequence a single post-drain probe cannot tell from a clean window: a
# prior that participated for part of quiescence and was gone before the last
# sample was taken.
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
run_verdict prior_case eval \
  'PRIOR_SAMPLE_LISTING="${PRIOR_SAMPLE_LISTING}
pr4109-rollback/prior-node running -"
   prior_sample_window'
check "a running prior attached to no network is quarantined" 0 \
  "no container built from the prior image was running and network-attached"

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

# One node that drained everything it held, and one that hit the deadline with
# a permit the gate force-canceled and the audit wrote a quarantine record for.
reconcile_readings() {
  # shellcheck disable=SC2034
  ROLLBACK_NODE_ACCOUNTS="r1-node-1 2 0 0
r1-node-2 3 1 0"
  # shellcheck disable=SC2034
  ROLLBACK_NODE_QUARANTINES="r1-node-1 0
r1-node-2 1"
}

reconcile_case() {
  reconcile_readings
  "$@"
  rollback_reconciliation_verdict "${RECONCILE_STEP}" "${RECONCILE_ASSERTION}"
}

run_verdict reconcile_case :
check "permits that completed or were audited into quarantine reconcile" 0 \
  "4 completed with the holding node observed without them, and 1 were \
force-canceled"

# The regression this step exists for: the fleet total went to zero because a
# node exited holding its permits, which no aggregate count distinguishes from
# a node that finished them.
run_verdict reconcile_case eval 'ROLLBACK_NODE_ACCOUNTS="r1-node-1 2 0 0
r1-node-2 3 0 2"'
check "a node that stopped holding permits reconciles nothing" 1 \
  "r1-node-2 stopped holding 2 of 3 permit\(s\)" \
  "went down with the process"

# A force-cancel the audit never wrote a record for is in-flight state the
# rollback would restore onto with nothing describing it.
run_verdict reconcile_case eval 'ROLLBACK_NODE_QUARANTINES="r1-node-1 0
r1-node-2 0"'
check "a force-canceled permit with no quarantine record refutes the step" 1 \
  "r1-node-2 \(1 force-canceled, no quarantine record\)"

run_verdict reconcile_case eval 'ROLLBACK_NODE_QUARANTINES="r1-node-1 0
r1-node-2 unreadable"'
check "an unreadable audit manifest audits no quarantine" 1 \
  "quarantine records unreadable"

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
homogeneous_readings() {
  # shellcheck disable=SC2034
  HOMOGENEOUS_DRIVER_SUPPLIED=1
  # shellcheck disable=SC2034
  HOMOGENEOUS_DRIVER_RC=0
  # shellcheck disable=SC2034
  HOMOGENEOUS_TX=2
  # shellcheck disable=SC2034
  HOMOGENEOUS_CEREMONIES="tbtc_signing beacon_dkg"
  # shellcheck disable=SC2034
  HOMOGENEOUS_RESULTS="tbtc_signing=succeeded beacon_dkg=succeeded"
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
  "saw tbtc_signing beacon_dkg complete successfully" \
  "recognized no cross-format peer"

# The half a permit counter cannot carry: work was allowed to start and
# nothing was observed finishing.
run_verdict homogeneous_case eval 'HOMOGENEOUS_CEREMONIES=""
   HOMOGENEOUS_RESULTS=""'
check "permits without a completed ceremony are not a positive control" 3 \
  "named no ceremony that completed successfully"

# The regression this seam exists for: a report is taken whole. One half of the
# release failing outright used to be dropped on the way to the verdict, and
# the half that passed recorded the control on its own.
run_verdict homogeneous_case eval \
  'HOMOGENEOUS_CEREMONIES="tbtc_signing"
   HOMOGENEOUS_RESULTS="tbtc_signing=succeeded beacon_dkg=failed"'
check "a required ceremony failing beside a passing one refutes the control" \
  1 "reported beacon_dkg=failed" "cannot be read off the subset"

run_verdict homogeneous_case eval \
  'HOMOGENEOUS_CEREMONIES="tbtc_signing beacon_dkg"
   HOMOGENEOUS_RESULTS="tbtc_signing=succeeded beacon_dkg=succeeded \
tbtc_wallet_action=timed_out"'
check "a ceremony that timed out beside the controls refutes them" 1 \
  "tbtc_wallet_action=timed_out"

# Both halves of the release take their permits from the same gate through
# different call paths, so a driver that only ever drove one of them leaves the
# other unexercised however many times it succeeded.
run_verdict homogeneous_case eval \
  'HOMOGENEOUS_CEREMONIES="tbtc_signing tbtc_dkg"
   HOMOGENEOUS_RESULTS="tbtc_signing=succeeded tbtc_dkg=succeeded"'
check "a control that drove only tBTC says nothing about the beacon" 3 \
  "nothing from the beacon half of the release"

run_verdict homogeneous_case eval \
  'HOMOGENEOUS_CEREMONIES="beacon_dkg beacon_signing"
   HOMOGENEOUS_RESULTS="beacon_dkg=succeeded beacon_signing=succeeded"'
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
      printf 'ceremonies:%s\n' "${WORK_DRIVER_SUCCEEDED_CEREMONIES}"
      printf 'results:%s\n' "${WORK_DRIVER_CEREMONY_RESULTS}"
      printf 'originated:%s\n' "${WORK_DRIVER_ORIGINATED}"
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
printf '{"transaction_hashes":["${HASH_A}"],"ceremony_results":['
printf '{"ceremony":"tbtc_signing","outcome":"succeeded"},'
printf '{"ceremony":"beacon_dkg","outcome":"failed"}]}'
EOF
drive homogeneous-security-v2
check "a driver names the ceremonies it saw complete" 0 \
  "offered:yes rc:0 tx:1"
if [[ "${CASE_OUT}" == *$'ceremonies:tbtc_signing\n'* ]]; then
  printf 'ok   only the ceremonies that succeeded are carried forward\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL a failed ceremony was carried forward as a result: %s\n' \
    "${CASE_OUT}"
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
# by the time one exists the work it was about is over.
write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],'
printf '"originated_ceremonies":["tbtc_signing","tbtc_wallet_action"]}'
EOF
drive rollback-inflight
check "a driver names the work it put on the chain before it settles" 0 \
  "originated:tbtc_signing tbtc_wallet_action" "results:"

write_driver <<EOF
#!/usr/bin/env bash
printf '{"transaction_hashes":["${HASH_A}"],'
printf '"originated_ceremonies":["tbtc_signing","a wallet action probably"]}'
EOF
drive rollback-inflight
check "originated work this rehearsal does not know stops the step" 3 \
  "not a ceremony"

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
