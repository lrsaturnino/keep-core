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
# The audit's own verdict. It writes to one path per service, so the two ways
# a stale or incomplete result can be read as an authorization are what the
# cases below drive: a tool that refused this snapshot while an earlier ready
# manifest sat at that path, and a tool that never wrote one at all.

AUDIT_INPUTS="${WORK}/audit-inputs"
mkdir -p "${AUDIT_INPUTS}/quiescence"
printf '{}\n' >"${AUDIT_INPUTS}/chain.json"
printf '{}\n' >"${AUDIT_INPUTS}/bitcoin.json"
printf '{}\n' >"${AUDIT_INPUTS}/prior-reader.json"
printf '{}\n' >"${AUDIT_INPUTS}/quiescence/r1-node-1.json"

# The audit tool, replaced at the seam the stage runs it through. The subshell
# `go run` executes inherits this function, so the real invocation — its flags,
# its output path, and what the caller makes of its exit status — is what runs.
# The two knobs are globals because a nested function reads its enclosing
# scope when it is called, not when it is defined, and by then the definer has
# long returned.
AUDIT_TOOL_STATUS=0
AUDIT_TOOL_MANIFEST=""
# shellcheck disable=SC2329
go() {
  if [[ -n "${AUDIT_TOOL_MANIFEST}" ]]; then
    printf '%s\n' "${AUDIT_TOOL_MANIFEST}" \
      >"${WORK}/audit-evidence/state-audit-r1-node-1.json"
  fi
  return "${AUDIT_TOOL_STATUS}"
}
audit_tool() {
  AUDIT_TOOL_STATUS="$1"
  AUDIT_TOOL_MANIFEST="$2"
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
      PR4109_CHAIN_RECONCILIATION_EVIDENCE="${AUDIT_INPUTS}/chain.json"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_BITCOIN_RECONCILIATION_EVIDENCE="${AUDIT_INPUTS}/bitcoin.json"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_QUIESCENCE_REPORT_DIR="${AUDIT_INPUTS}/quiescence"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_PRIOR_READER_EVIDENCE="${AUDIT_INPUTS}/prior-reader.json"
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

# The tool exits nonzero on an inconsistent namespace as well as on an unready
# barrier, so a run that reads only the ready flag accepts a snapshot the tool
# refused for a reason that flag does not carry.
audit_refused_but_ready() { audit_tool 3 '{"rollback_barrier_ready":true}'; }
run_audit_case audit_refused_but_ready
check "a nonzero audit is not authorized by its own ready flag" 0 \
  "audit_rc:1" "exited \[3\]"

# The stale case: this run's tool writes nothing, and an earlier run's ready
# manifest is sitting at the path it would have written.
printf '{"rollback_barrier_ready":true}\n' \
  >"${WORK}/audit-evidence/state-audit-r1-node-1.json"
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
  QUIESCE_GRACE="20160"
}

quiesce_case() {
  quiesce_readings
  "$@"
  quiescence_verdict r1-node-2
}

run_verdict quiesce_case :
check "a quiescence that refused new work and drained its permits holds" 0 \
  "was offered new work while quiescing and issued no permit" \
  "in-flight count observed at zero"

run_verdict quiesce_case eval 'QUIESCE_ATTEMPTED=0'
check "a quiescing node nobody asked evidences no refusal to start work" 3 \
  "no work was offered to it while it was quiescing"

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

# The straggler control, whose evidence used to be the gate's own refusal
# counter — a counter that moves when a node declines its own Begin, for
# reasons that need no legacy announcement behind them at all.
straggler_readings() {
  # shellcheck disable=SC2034
  STRAGGLER_BEFORE=("10" "4" "2")
  # shellcheck disable=SC2034
  STRAGGLER_AFTER=("11" "5" "3")
}

straggler_case() {
  straggler_readings
  "$@"
}

run_verdict straggler_case eval \
  'straggler_control_verdict "0xabc"'
check "a straggler recognized, rostered, and named holds the control" 0 \
  "recognized 1 of them as cross-format" "naming operator\(s\) 0xabc"

# The case the refusal counter could not tell apart from success: no legacy
# announcement ever arrived, so there was nothing to fail closed against.
run_verdict straggler_case eval \
  'STRAGGLER_AFTER=("10" "5" "3"); straggler_control_verdict "0xabc"'
check "a roster entry with no session mismatch behind it is not the control" \
  3 "no session-ID mismatch"

run_verdict straggler_case eval \
  'STRAGGLER_AFTER=("11" "4" "3"); straggler_control_verdict "0xabc"'
check "a mismatch never recognized as cross-format refutes the control" 1 \
  "recognized none of them as cross-format"

run_verdict straggler_case eval \
  'STRAGGLER_AFTER=("11" "5" "2"); straggler_control_verdict "0xabc"'
check "a cross-format sighting that entered no roster refutes the control" 1 \
  "added none to its legacy roster"

run_verdict straggler_case eval 'straggler_control_verdict ""'
check "a roster addition naming no new operator refutes the control" 1 \
  "named no operator it had not already seen"

run_verdict straggler_case eval \
  'STRAGGLER_AFTER=("11" "" "3"); straggler_control_verdict "0xabc"'
check "an unreadable cross-format counter observes no straggler at all" 3 \
  "announcer_cross_format_peer_total"

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
