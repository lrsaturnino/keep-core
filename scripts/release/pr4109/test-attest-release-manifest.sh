#!/usr/bin/env bash
#
# Self-test for the release-readiness seam between rehearse.sh's attestation
# producer and its acceptance consumer.
#
# The acceptance stage refuses evidence measured against a manifest that names
# no release, and it does so by reading one word out of the receipt the local
# proofs leave behind. Two functions decide that: attest_release_manifest asks
# the binary whether the reviewed manifest is release-ready and writes the
# answer down, and require_manifest_attestation refuses anything but "yes".
# The evidence-validator self-test drives the second one over a hand-authored
# verdict file, which proves the refusal but never runs the producer — so
# deleting the --release-ready invocation, or hard-coding the word it writes,
# leaves that whole suite green over a receipt nothing derived.
#
# This script runs the producer itself and holds it to the binary it is
# supposed to be quoting: the verdict in the receipt must equal the answer an
# independent --release-ready invocation gives, whatever that answer is. That
# is the assertion a hard-coded verdict cannot satisfy, and it stays correct
# through the release, when the reviewed cutover block lands and the answer
# flips from "no" to "yes".
#
# The receipt the producer wrote is then fed to the consumer unedited, and fed
# again with only the verdict flipped, so both directions of the seam are
# exercised end to end. Producing a "yes" receipt outright is not possible
# while the mainnet cutover block is the zero placeholder — validate requires
# the manifest to carry the compiled block and readiness requires that block to
# be nonzero, and no manifest satisfies both at once — which is why the
# agreement assertion, and not a fixture pinned to one verdict, is what covers
# this seam until the reviewed block is set.
#
# Needs the Go toolchain, which is why it runs from the local-proofs stage and
# not from the evidence-validator suite. Everything lives under mktemp and this
# repository is never written to.

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Guards rehearse.sh's own self-test hooks: sourcing it here must not recurse
# back into any suite that sources it in turn.
export PR4109_EVIDENCE_SELFTEST=1

# shellcheck source=/dev/null
source "${TEST_DIR}/rehearse.sh"

# Both functions read these from the environment. Every case below sets what it
# needs explicitly, so an ambient value must never decide a verdict here.
unset PR4109_EXPECTED_SOURCE_COMMIT PR4109_SOURCE_BINDING_MODE

command -v go >/dev/null 2>&1 ||
  blocked "go (the Go toolchain) is required to self-test the release-manifest \
attestation: the producer under test asks the binary for its readiness verdict"
command -v node >/dev/null 2>&1 ||
  blocked "node (Node.js) is required to self-test the release-manifest \
attestation"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/pr4109-attest-manifest.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

PASS=0
FAILED=0
CASE_RC=0
CASE_OUT=""

MANIFEST="${TEST_DIR}/release-manifest.json"

# The commit the produced receipts claim. The consumer refuses a receipt taken
# at anything but a clean commit id, and this worktree is routinely mid-edit,
# so the source identity is supplied rather than sampled: what these cases are
# about is the readiness verdict, and a -dirty stamp would block every one of
# them before the verdict was ever read.
FIXTURE_SHA="cccccccccccccccccccccccccccccccccccccccc"

# The reviewed manifest the consumer will recompute for itself, and a hash of
# something else. Detached provenance names the manifest it was taken over, so
# every case that supplies one needs both: the binding that agrees, and the
# binding that does not.
MANIFEST_SHA="$(hash_stdin <"${MANIFEST}")"
OTHER_MANIFEST_SHA="$(printf 'd%.0s' {1..64})"

# The binary's own answer, asked exactly the way the producer asks it and
# entirely outside the producer. This is the reference every assertion below
# compares against, so the suite tracks the release rather than pinning one
# verdict: today the reviewed manifest names no release and this is "no"; on the
# reviewed release commit it becomes "yes" and every case still holds.
expected_verdict() {
  if (cd "${REPO_ROOT}" && go run . release-manifest validate \
    --manifest "${MANIFEST}" --release-ready >/dev/null 2>&1); then
    printf 'yes'
  else
    printf 'no'
  fi
}

# Run the real producer against a fresh evidence directory, in a subshell so a
# blocked exit inside it never kills the test run.
run_producer() {
  local dir="$1"
  mkdir -p "${dir}"
  set +e
  CASE_OUT="$(
    (
      cd "${REPO_ROOT}" || exit 1
      # The producer reads these; the assignments stay in this subshell.
      # shellcheck disable=SC2030,SC2034
      EVIDENCE_DIR="${dir}"
      # shellcheck disable=SC2030,SC2034
      VERIFIED_SOURCE_COMMIT="${FIXTURE_SHA}"
      attest_release_manifest
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

# Run the real consumer over a receipt, in the same isolated way. A case may
# point it at a copied script directory so it judges a doctored manifest; the
# assignment stays in the subshell, and the real checked-in manifest is never
# written to.
run_consumer() {
  local dir="$1"
  local script_dir="${2:-${TEST_DIR}}"
  set +e
  CASE_OUT="$(
    (
      # shellcheck disable=SC2030,SC2034
      EVIDENCE_DIR="${dir}"
      # shellcheck disable=SC2030,SC2034
      SCRIPT_DIR="${script_dir}"
      require_manifest_attestation
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

# A copy of the produced receipt, forced to the ready verdict, so the cases
# about what a release-acceptance run requires can be reached while the
# reviewed manifest still names no release. Everything else in the receipt is
# the producer's own output.
#
# Forcing the verdict is exactly what the flipped-verdict case above does, and
# it is sound for the same reason: the verdict is one word the consumer reads,
# the suite proves separately that the producer writes the binary's own answer
# there, and no case here is about the verdict itself.
ready_receipt() {
  local name="$1"
  local dir="${WORK}/${name}"
  mkdir -p "${dir}"
  cp -R "${D}/attestation" "${dir}/attestation"
  printf 'yes\n' >"${dir}/attestation/release-ready.txt"
  printf '%s\n' "${dir}"
}

# A detached provenance document at the given path: written into a receipt
# copy for the consumer cases, and left standing alone for the ones that hand
# it to the producer.
#
# The producer builds its copy from a file the operator supplies and the binary
# has verified. The consumer cases write shapes a verified document cannot have
# — a different commit, a different reviewed manifest — because the consumer is
# the only thing standing between a receipt assembled by hand and acceptance.
write_provenance_file() {
  local path="$1" manifest_sha="$2" source_commit="$3"
  cat >"${path}" <<EOF
{
  "schema_version": 1,
  "generated_at": "2026-07-28T00:00:00Z",
  "manifest_sha256": "${manifest_sha}",
  "source_commit": "${source_commit}",
  "images": [
    {
      "platform": "amd64",
      "reference": "ghcr.io/keep-network/keep-client@sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    }
  ]
}
EOF
}

# The same document, written into a receipt copy where the consumer reads it.
write_case_provenance() {
  local dir="$1"
  shift
  write_provenance_file "${dir}/attestation/release-provenance.json" "$@"
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

# Assert two values are equal.
check_equal() {
  local desc="$1" got="$2" want="$3"
  if [[ "${got}" != "${want}" ]]; then
    printf 'FAIL %s: got [%s], want [%s]\n' "${desc}" "${got}" "${want}"
    FAILED=$((FAILED + 1))
    return
  fi
  printf 'ok   %s\n' "${desc}"
  PASS=$((PASS + 1))
}

# ----------------------------------------------------------------------------

EXPECTED="$(expected_verdict)"
printf '>> the binary reports the reviewed manifest release-ready: %s\n' \
  "${EXPECTED}"

D="${WORK}/produced"
run_producer "${D}"
check "the producer writes a receipt for the reviewed manifest" 0 \
  "release-manifest attestation written to"

# A receipt is all four documents or it is a fragment, and the consumer treats
# a fragment as no receipt at all. The producer is what has to write all four.
for part in derived-manifest.json reviewed-manifest.sha256 source-commit.txt \
  release-ready.txt; do
  if [[ -f "${D}/attestation/${part}" ]]; then
    printf 'ok   the produced receipt carries %s\n' "${part}"
    PASS=$((PASS + 1))
  else
    printf 'FAIL the produced receipt is missing %s\n' "${part}"
    FAILED=$((FAILED + 1))
  fi
done

# The assertion a hard-coded verdict cannot satisfy.
PRODUCED_VERDICT="$(tr -d '[:space:]' <"${D}/attestation/release-ready.txt")"
check_equal "the recorded verdict is the binary's own answer" \
  "${PRODUCED_VERDICT}" "${EXPECTED}"

# The log is the operator's account of what is still missing, and it is the
# only place the violations survive: the receipt records the word, not the
# reasons. A verdict written without running the check has nothing to log.
if [[ -s "${D}/attestation/release-ready.log" ]]; then
  printf 'ok   the produced receipt carries the readiness check output\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the produced receipt records a verdict with no check output\n'
  FAILED=$((FAILED + 1))
fi

# ----------------------------------------------------------------------------
# The seam itself: the receipt the producer wrote, read by the consumer that
# gates acceptance on it, with nothing hand-authored in between.

run_consumer "${D}"
if [[ "${EXPECTED}" == "yes" ]]; then
  check "the consumer accepts the produced receipt" 0 \
    "attestation binds .* to the compiled bounds of ${FIXTURE_SHA}"
else
  check "the consumer refuses the produced not-release-ready receipt" 3 \
    "records .* as not release-ready"
fi

# ----------------------------------------------------------------------------
# The same receipt with only the verdict flipped. Whichever answer the binary
# gives today, this covers the direction the case above could not reach, so the
# consumer is held to both outcomes rather than to whatever the placeholder
# manifest happens to produce.

FLIPPED="${WORK}/flipped"
mkdir -p "${FLIPPED}"
cp -R "${D}/attestation" "${FLIPPED}/attestation"
if [[ "${EXPECTED}" == "yes" ]]; then
  printf 'no\n' >"${FLIPPED}/attestation/release-ready.txt"
  run_consumer "${FLIPPED}"
  check "the consumer refuses a receipt recording no release" 3 \
    "records .* as not release-ready"
else
  printf 'yes\n' >"${FLIPPED}/attestation/release-ready.txt"
  # A ready receipt is a release-acceptance receipt, and one of those has to
  # say which artifact runs the cutover. Supplied here so this case stays
  # about the verdict; the receipt that omits it has its own case below.
  write_case_provenance "${FLIPPED}" "${MANIFEST_SHA}" "${FIXTURE_SHA}"
  run_consumer "${FLIPPED}"
  check "the consumer accepts a receipt recording a ready release" 0 \
    "attestation binds .* to the compiled bounds of ${FIXTURE_SHA}"
fi

# A verdict the producer never writes is not a verdict. Anything but "yes" has
# to refuse, or a truncated, empty, or garbled file would read as acceptance.
GARBLED="${WORK}/garbled"
mkdir -p "${GARBLED}"
cp -R "${D}/attestation" "${GARBLED}/attestation"
: >"${GARBLED}/attestation/release-ready.txt"
run_consumer "${GARBLED}"
check "the consumer refuses a receipt whose verdict is empty" 3 \
  "records .* as not release-ready"

# ----------------------------------------------------------------------------
# The commit the release was built from, against the commit the receipt was
# taken at.
#
# The manifest cannot make this statement about itself. It is part of the
# commit it would have to name, so writing the value changes the answer, and a
# check demanding the two agree can never be satisfied by any real checkout.
# The detached provenance is generated after that commit exists and lives
# outside the tree, so requiring it to name the commit under test asks for
# something a release flow can actually produce — and refuses the case the
# manifest never could: a release built from bytes no proof here measured.

OTHER_SHA="dddddddddddddddddddddddddddddddddddddddd"

CASE="$(ready_receipt "provenance-names-this-commit")"
write_case_provenance "${CASE}" "${MANIFEST_SHA}" "${FIXTURE_SHA}"
run_consumer "${CASE}"
check "the consumer accepts provenance naming the attested commit" 0 \
  "attestation binds .* to the compiled bounds of ${FIXTURE_SHA}" \
  "detached provenance binds that commit to the images"

CASE="$(ready_receipt "provenance-names-another-commit")"
write_case_provenance "${CASE}" "${MANIFEST_SHA}" "${OTHER_SHA}"
run_consumer "${CASE}"
check "the consumer refuses provenance naming another commit" 3 \
  "names source commit \[${OTHER_SHA}\]" \
  "built from bytes other than the ones under test"

# Provenance for a release reviewed under other bounds. Naming the right
# commit is not enough: the hash is what says these artifacts were built for
# the manifest these records are measured against.
CASE="$(ready_receipt "provenance-over-another-manifest")"
write_case_provenance "${CASE}" "${OTHER_MANIFEST_SHA}" "${FIXTURE_SHA}"
run_consumer "${CASE}"
check "the consumer refuses provenance taken over another manifest" 3 \
  "hashing to \[${OTHER_MANIFEST_SHA}\]" \
  "built under reviewed bounds other than the ones"

# A ready receipt carrying no provenance names a cutover and no artifact. The
# release-acceptance run is exactly where that absence stops being acceptable,
# so the refusal lives here rather than in the producer, which legitimately
# writes provenance-free receipts on every development run.
CASE="$(ready_receipt "ready-receipt-without-provenance")"
rm -f "${CASE}/attestation/release-provenance.json"
run_consumer "${CASE}"
check "the consumer refuses a ready receipt carrying no provenance" 3 \
  "carries no detached release provenance" \
  "outside the checkout"

# ----------------------------------------------------------------------------
# The producer's own handling of the document it is handed.

# The whole point of the split is that this document is not in the tree it
# describes. A tracked file would put the commit back inside the commit it
# names, and would do it quietly — every check downstream would still pass
# against whatever stale value the tree happened to carry.
run_producer_with_provenance() {
  local dir="$1" provenance="$2"
  mkdir -p "${dir}"
  set +e
  CASE_OUT="$(
    (
      cd "${REPO_ROOT}" || exit 1
      # shellcheck disable=SC2030,SC2031,SC2034
      EVIDENCE_DIR="${dir}"
      # shellcheck disable=SC2030,SC2031,SC2034
      VERIFIED_SOURCE_COMMIT="${FIXTURE_SHA}"
      # shellcheck disable=SC2030,SC2031,SC2034
      PR4109_RELEASE_PROVENANCE="${provenance}"
      attest_release_manifest
    ) 2>&1
  )"
  CASE_RC=$?
  set -e
}

run_producer_with_provenance "${WORK}/tracked-provenance" "${MANIFEST}"
check "the producer refuses provenance tracked in this repository" 1 \
  "is tracked in this repository" \
  "Generate it after the build, outside the checkout"

run_producer_with_provenance "${WORK}/absent-provenance" \
  "${WORK}/no-such-provenance.json"
check "the producer refuses provenance it cannot read" 1 \
  "which is not a readable file"

# The document the binary has to reject, handed to the producer untracked so
# the refusal can only come from the verification. While the reviewed manifest
# names no release there is nothing to have provenance for, and that is the
# answer; once the reviewed cutover block lands, the same case is refused for
# the mismatched hash it carries. Either way the producer must not record a
# document the binary did not accept.
UNVERIFIABLE="${WORK}/unverifiable-provenance.json"
write_provenance_file "${UNVERIFIABLE}" "${OTHER_MANIFEST_SHA}" \
  "${FIXTURE_SHA}"
run_producer_with_provenance "${WORK}/unverifiable" "${UNVERIFIABLE}"
check "the producer refuses provenance the binary does not verify" 1 \
  "does not verify against"
if [[ -f "${WORK}/unverifiable/attestation/release-provenance.json" ]]; then
  printf 'FAIL the producer recorded provenance the binary rejected\n'
  FAILED=$((FAILED + 1))
else
  printf 'ok   a rejected provenance is recorded in no receipt\n'
  PASS=$((PASS + 1))
fi

# A development run has no build to describe, and must still produce a
# receipt. The absence is the acceptance stage's refusal to make, not this
# one's.
if [[ -f "${D}/attestation/release-provenance.json" ]]; then
  printf 'FAIL the producer invented provenance nobody supplied\n'
  FAILED=$((FAILED + 1))
else
  printf 'ok   a run supplied no provenance records none\n'
  PASS=$((PASS + 1))
fi

# ----------------------------------------------------------------------------
# A second run must replace the receipt rather than leave the first one's
# verdict standing beside it, since the acceptance stage reads whatever is on
# disk and cannot tell which run wrote it.

run_producer "${D}"
check "the producer republishes over an inherited receipt" 0 \
  "release-manifest attestation written to"
REPUBLISHED_VERDICT="$(tr -d '[:space:]' <"${D}/attestation/release-ready.txt")"
check_equal "the republished verdict is still the binary's own answer" \
  "${REPUBLISHED_VERDICT}" "${EXPECTED}"

shopt -s nullglob
LEFTOVER=("${D}"/attestation.staging.*)
shopt -u nullglob
if [[ "${#LEFTOVER[@]}" -eq 0 ]]; then
  printf 'ok   the producer leaves no staging directory behind\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL the producer left %s behind\n' "${LEFTOVER[*]}"
  FAILED=$((FAILED + 1))
fi

# ----------------------------------------------------------------------------

printf '%d passed, %d failed\n' "${PASS}" "${FAILED}"
if [[ "${FAILED}" -ne 0 ]]; then
  exit 1
fi
