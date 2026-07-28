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
# before it measures anything: absent, taken over other manifest bytes, or
# recording bounds the reviewed manifest contradicts. Needs node/npx like
# the stage it tests; everything lives under mktemp and this repository is
# never touched.

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Guards the stage's self-test hook: the invocations below must run the
# validation itself, not recurse back into this script.
export PR4109_EVIDENCE_SELFTEST=1

# shellcheck source=/dev/null
source "${TEST_DIR}/rehearse.sh"

command -v node >/dev/null 2>&1 ||
  blocked "node (Node.js) is required to self-test the evidence validator"
command -v npx >/dev/null 2>&1 ||
  blocked "npx (Node.js) is required to self-test the evidence validator"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/pr4109-validate-evidence.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

PASS=0
FAILED=0
CASE_RC=0
CASE_OUT=""

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

# A schema-complete record bound to the given manifest hash, grace, and
# generation timestamp. The negative cases change exactly one argument each,
# so a rejection can only come from that change.
write_record() {
  local path="$1" sha="$2" grace="$3" generated_at="$4"
  cat >"${path}" <<EOF
{
  "schema_version": 1,
  "gate": "single_release",
  "generated_at": "${generated_at}",
  "source_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
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
  mkdir -p "${dir}"
  printf '%s\n' "${sha}" >"${dir}/reviewed-manifest.sha256"
  cp "${derived}" "${dir}/derived-manifest.json"
}

# Run stage_validate_evidence against a fixture directory in an isolated
# subshell so a blocked/fail exit inside the stage never kills the test
# run; capture rc and combined output.
run_validator() {
  local dir="$1"
  set +e
  CASE_OUT="$(
    (
      # The sourced stage reads EVIDENCE_DIR; shellcheck cannot see across
      # the source boundary, and the assignment stays in this subshell.
      # shellcheck disable=SC2030,SC2034
      EVIDENCE_DIR="${dir}"
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
check "a record bound to the manifest's hash and grace passes" 0 \
  "attestation binds" "bind the reviewed" "hash and termination grace"

D="${WORK}/no-attestation"
mkdir -p "${D}"
write_record "${D}/record.json" "${MANIFEST_SHA}" "${MANIFEST_GRACE}" \
  "2026-07-28T00:00:00Z"
run_validator "${D}"
check "a correct record without a manifest attestation is not accepted" 3 \
  "no release-manifest attestation" "run the local-proofs stage"

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

printf '%d passed, %d failed\n' "${PASS}" "${FAILED}"
if [[ "${FAILED}" -ne 0 ]]; then
  exit 1
fi
