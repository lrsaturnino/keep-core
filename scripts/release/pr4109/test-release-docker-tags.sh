#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELECTOR="${SCRIPT_DIR}/release-docker-tags.sh"

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

printf '%d passed, %d failed\n' "${passed}" "${failed}"
if ((failed != 0)); then
  exit 1
fi
