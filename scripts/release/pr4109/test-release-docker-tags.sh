#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELECTOR="${SCRIPT_DIR}/release-docker-tags.sh"
TRIGGER_TAG_RESOLVER="${SCRIPT_DIR}/release-trigger-tag.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/keep-release-tags.XXXXXX")"
trap 'rm -rf -- "${WORK}"' EXIT

passed=0
failed=0

assert_tags() {
  local name="$1"
  local expected="$2"
  shift 2

  local actual
  if ! actual="$("${SELECTOR}" "$@" 2>&1)"; then
    echo "FAIL ${name}: selector refused valid input: ${actual}" >&2
    failed=$((failed + 1))
    return
  fi

  if [[ "${actual}" != "${expected}" ]]; then
    echo "FAIL ${name}: unexpected tag set" >&2
    printf 'expected:\n%s\nactual:\n%s\n' "${expected}" "${actual}" >&2
    failed=$((failed + 1))
    return
  fi

  echo "ok   ${name}"
  passed=$((passed + 1))
}

assert_refused() {
  local name="$1"
  shift

  local output
  if output="$("${SELECTOR}" "$@" 2>&1)"; then
    echo "FAIL ${name}: selector unexpectedly accepted input: ${output}" >&2
    failed=$((failed + 1))
    return
  fi

  echo "ok   ${name}"
  passed=$((passed + 1))
}

assert_resolved_tag() {
  local name="$1"
  local expected="$2"
  shift 2

  local actual
  if ! actual="$("${TRIGGER_TAG_RESOLVER}" "$@" 2>&1)"; then
    echo "FAIL ${name}: trigger-tag resolver refused valid input: ${actual}" >&2
    failed=$((failed + 1))
    return
  fi

  if [[ "${actual}" != "${expected}" ]]; then
    echo "FAIL ${name}: resolved [${actual}], expected [${expected}]" >&2
    failed=$((failed + 1))
    return
  fi

  echo "ok   ${name}"
  passed=$((passed + 1))
}

assert_resolver_refused() {
  local name="$1"
  shift

  local output
  if output="$("${TRIGGER_TAG_RESOLVER}" "$@" 2>&1)"; then
    echo "FAIL ${name}: trigger-tag resolver unexpectedly accepted [${output}]" >&2
    failed=$((failed + 1))
    return
  fi

  echo "ok   ${name}"
  passed=$((passed + 1))
}

assert_tags \
  "stable release moves both production aliases" \
  $'thresholdnetwork/keep-client:v2.3.4\nthresholdnetwork/keep-client:latest\nthresholdnetwork/keep-client:mainnet' \
  thresholdnetwork v2.3.4

assert_tags \
  "release candidate remains version-only" \
  'thresholdnetwork/keep-client:v2.3.4-rc.1' \
  thresholdnetwork v2.3.4-rc.1

assert_tags \
  "prerelease remains version-only" \
  'thresholdnetwork/keep-client:v2.3.4-beta.2' \
  thresholdnetwork v2.3.4-beta.2

assert_tags \
  "unrecognized version shape fails closed to version-only" \
  'thresholdnetwork/keep-client:v2.3.4-1-g0123456' \
  thresholdnetwork v2.3.4-1-g0123456

assert_refused "invalid namespace is rejected" 'Threshold Network' v2.3.4
assert_refused "invalid Docker tag is rejected" thresholdnetwork 'v2.3.4+build'
assert_refused "missing arguments are rejected" thresholdnetwork

assert_resolved_tag \
  "exact triggering tag is the release identity" \
  v2.3.4 \
  refs/tags/v2.3.4 v2.3.4

assert_resolver_refused \
  "branch trigger is rejected" \
  refs/heads/main main

assert_resolver_refused \
  "mismatched trigger ref and name are rejected" \
  refs/tags/v2.3.4 v2.3.4-rc.1

assert_resolver_refused \
  "non-release tag is rejected" \
  refs/tags/release-2.3.4 release-2.3.4

assert_resolver_refused \
  "trigger tag outside Docker shape is rejected" \
  refs/tags/v2.3.4/candidate v2.3.4/candidate

# A stable tag and a release-candidate tag may point at the same commit. The
# triggering ref — not whichever tag repository discovery happens to choose —
# must remain the release identity and therefore keep the candidate
# version-only.
same_commit_repo="${WORK}/same-commit-stable-and-rc"
mkdir -p "${same_commit_repo}"
git -C "${same_commit_repo}" init -q
git -C "${same_commit_repo}" \
  -c user.name='Release fixture' \
  -c user.email='release-fixture@example.invalid' \
  commit --allow-empty -q -m 'same-commit tag fixture'
git -C "${same_commit_repo}" tag v2.3.4
git -C "${same_commit_repo}" tag v2.3.4-rc.1

stable_commit="$(git -C "${same_commit_repo}" rev-parse 'v2.3.4^{commit}')"
candidate_commit="$(git -C "${same_commit_repo}" rev-parse 'v2.3.4-rc.1^{commit}')"
resolved_candidate="$(
  "${TRIGGER_TAG_RESOLVER}" \
    refs/tags/v2.3.4-rc.1 v2.3.4-rc.1
)"
candidate_tags="$(
  "${SELECTOR}" thresholdnetwork "${resolved_candidate}"
)"

if [[ "${stable_commit}" != "${candidate_commit}" ]]; then
  echo "FAIL same-commit stable plus RC keeps triggering candidate identity: fixture tags do not share one commit" >&2
  failed=$((failed + 1))
elif [[ "${candidate_tags}" != 'thresholdnetwork/keep-client:v2.3.4-rc.1' ]]; then
  echo "FAIL same-commit stable plus RC keeps triggering candidate identity: unexpected tag set [${candidate_tags}]" >&2
  failed=$((failed + 1))
else
  echo "ok   same-commit stable plus RC keeps triggering candidate identity"
  passed=$((passed + 1))
fi

printf '%d passed, %d failed\n' "${passed}" "${failed}"
if ((failed != 0)); then
  exit 1
fi
