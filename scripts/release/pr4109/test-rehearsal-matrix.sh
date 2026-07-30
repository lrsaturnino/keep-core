#!/usr/bin/env bash
#
# Self-test for the workflow-dispatch boundary that turns detached release
# provenance and the encoded per-platform chain document into native runner
# jobs. The test extracts and executes the workflow's own Node program rather
# than copying its validation rules, so a workflow edit changes the code under
# test immediately.
#
# The fixtures cover the accepted platform mappings and every fail-closed
# boundary the dispatch relies on: canonical base64 and UTF-8, unique JSON
# members, exact chain fields, endpoint schemes, integer forms, supported and
# unique provenance platforms, and a one-to-one provenance/input mapping.

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKFLOW="${TEST_DIR}/../../../.github/workflows/cutover-rehearsal.yml"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/cutover-rehearsal-matrix.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

command -v node >/dev/null 2>&1 ||
  {
    printf 'FAIL Node.js is required to test the native-runner matrix\n'
    exit 1
  }

VALIDATOR="${WORK}/build-rehearsal-matrix.js"
PROVENANCE="${WORK}/release-provenance.json"
MATRIX_OUTPUT="${WORK}/github-output"

# Locate the named workflow step, then remove the YAML block indentation from
# its quoted Node body. Refuse an absent or unterminated body: an empty test
# program would otherwise make every negative fixture look correctly refused.
awk '
  /- name: Build the native-runner matrix from release provenance/ {
    in_step = 1
  }
  in_step && /node - .*<<'\''NODE'\''/ {
    in_program = 1
    next
  }
  in_program && /^          NODE[[:space:]]*$/ {
    complete = 1
    exit
  }
  in_program {
    if ($0 != "" && substr($0, 1, 10) != "          ") {
      exit 2
    }
    print ($0 == "" ? "" : substr($0, 11))
  }
  END {
    if (!in_program || !complete) {
      exit 3
    }
  }
' "${WORKFLOW}" >"${VALIDATOR}" ||
  {
    printf 'FAIL cannot extract the native-runner matrix validator\n'
    exit 1
  }

if [[ ! -s "${VALIDATOR}" ]]; then
  printf 'FAIL the extracted native-runner matrix validator is empty\n'
  exit 1
fi

PASS=0
FAILED=0
CASE_RC=0
CASE_OUT=""

encode() {
  node -e '
    process.stdout.write(Buffer.from(process.argv[1], "utf8").toString("base64"));
  ' "$1"
}

run_case() {
  local encoded="$1" provenance="$2"
  printf '%s\n' "${provenance}" >"${PROVENANCE}"
  : >"${MATRIX_OUTPUT}"
  set +e
  CASE_OUT="$(
    REHEARSAL_CHAIN_INPUTS_B64="${encoded}" \
      node "${VALIDATOR}" "${PROVENANCE}" "${MATRIX_OUTPUT}" 2>&1
  )"
  CASE_RC=$?
  set -e
}

pass_case() {
  printf 'ok   %s\n' "$1"
  PASS=$((PASS + 1))
}

fail_case() {
  printf 'FAIL %s\n' "$1"
  if [[ -n "${2:-}" ]]; then
    printf -- '--- detail ---\n%s\n--------------\n' "$2"
  fi
  FAILED=$((FAILED + 1))
}

accept_document() {
  local name="$1" document="$2" provenance="$3" expected="$4"
  run_case "$(encode "${document}")" "${provenance}"
  if ((CASE_RC != 0)); then
    fail_case "${name}" "exit ${CASE_RC}: ${CASE_OUT}"
    return
  fi

  if node -e '
    const fs = require("fs");
    const line = fs.readFileSync(process.argv[1], "utf8").trim();
    if (!line.startsWith("matrix=")) process.exit(1);
    const actual = JSON.parse(line.slice("matrix=".length));
    const expected = JSON.parse(process.argv[2]);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) process.exit(1);
  ' "${MATRIX_OUTPUT}" "${expected}"; then
    pass_case "${name}"
  else
    fail_case "${name}" "$(cat "${MATRIX_OUTPUT}")"
  fi
}

reject_encoded() {
  local name="$1" encoded="$2" provenance="$3" pattern="$4"
  run_case "${encoded}" "${provenance}"
  if ((CASE_RC == 3)) && grep -Eq "${pattern}" <<<"${CASE_OUT}" &&
    [[ ! -s "${MATRIX_OUTPUT}" ]]; then
    pass_case "${name}"
  else
    fail_case "${name}" \
      "exit ${CASE_RC}, output [${CASE_OUT}], matrix [$(cat "${MATRIX_OUTPUT}")]"
  fi
}

reject_document() {
  reject_encoded "$1" "$(encode "$2")" "$3" "$4"
}

AMD64_PROVENANCE='{"images":[{"platform":"amd64"}]}'
AMD64_CHAIN='{"amd64":{"chain_id":"1337","cutover_block":100,"eth_rpc_url":"https://rpc.invalid/path","eth_ws_url":"wss://ws.invalid/path"}}'
AMD64_MATRIX='{"include":[{"platform":"amd64","runner":"ubuntu-latest","artifact_key":"amd64","eth_ws_url":"wss://ws.invalid/path","eth_rpc_url":"https://rpc.invalid/path","cutover_block":"100","chain_id":"1337"}]}'

accept_document \
  "one published amd64 image becomes one isolated native-runner job" \
  "${AMD64_CHAIN}" "${AMD64_PROVENANCE}" "${AMD64_MATRIX}"

ARM64_V8_PROVENANCE='{"images":[{"platform":"arm64/v8"}]}'
ARM64_V8_CHAIN='{"arm64/v8":{"chain_id":"1","cutover_block":1,"eth_rpc_url":"http://rpc.invalid","eth_ws_url":"ws://ws.invalid"}}'
ARM64_V8_MATRIX='{"include":[{"platform":"arm64/v8","runner":"ubuntu-24.04-arm","artifact_key":"arm64-v8","eth_ws_url":"ws://ws.invalid","eth_rpc_url":"http://rpc.invalid","cutover_block":"1","chain_id":"1"}]}'

accept_document \
  "the arm64/v8 artifact keeps its distinct platform and artifact key" \
  "${ARM64_V8_CHAIN}" "${ARM64_V8_PROVENANCE}" "${ARM64_V8_MATRIX}"

MULTI_PROVENANCE='{"images":[{"platform":"amd64"},{"platform":"arm64"}]}'
MULTI_CHAIN='{"amd64":{"chain_id":"11","cutover_block":101,"eth_rpc_url":"https://amd64-rpc.invalid","eth_ws_url":"wss://amd64-ws.invalid"},"arm64":{"chain_id":"12","cutover_block":202,"eth_rpc_url":"https://arm64-rpc.invalid","eth_ws_url":"wss://arm64-ws.invalid"}}'
MULTI_MATRIX='{"include":[{"platform":"amd64","runner":"ubuntu-latest","artifact_key":"amd64","eth_ws_url":"wss://amd64-ws.invalid","eth_rpc_url":"https://amd64-rpc.invalid","cutover_block":"101","chain_id":"11"},{"platform":"arm64","runner":"ubuntu-24.04-arm","artifact_key":"arm64","eth_ws_url":"wss://arm64-ws.invalid","eth_rpc_url":"https://arm64-rpc.invalid","cutover_block":"202","chain_id":"12"}]}'

accept_document \
  "each published platform receives its own chain and native job" \
  "${MULTI_CHAIN}" "${MULTI_PROVENANCE}" "${MULTI_MATRIX}"

reject_encoded \
  "an absent encoded chain document blocks the dispatch" \
  "" "${AMD64_PROVENANCE}" "chain_inputs_b64 is absent"
reject_encoded \
  "base64 containing whitespace is not canonical input" \
  "e30= " "${AMD64_PROVENANCE}" "not canonical base64"
reject_encoded \
  "unpadded base64 is not canonical input" \
  "e30" "${AMD64_PROVENANCE}" "not canonical base64"
reject_encoded \
  "decoded bytes must be valid UTF-8" \
  "$(node -e 'process.stdout.write(Buffer.from([255]).toString("base64"))')" \
  "${AMD64_PROVENANCE}" "not valid UTF-8"
reject_document \
  "decoded bytes must contain JSON" \
  "{" "${AMD64_PROVENANCE}" "does not decode to JSON"
reject_document \
  "the chain document root must be a platform object" \
  "[]" "${AMD64_PROVENANCE}" "must be an object keyed by published platform"

reject_document \
  "a repeated platform member cannot overwrite reviewed chain input" \
  '{"amd64":{"chain_id":"1","cutover_block":1,"eth_rpc_url":"https://one.invalid","eth_ws_url":"wss://one.invalid"},"amd64":{"chain_id":"2","cutover_block":2,"eth_rpc_url":"https://two.invalid","eth_ws_url":"wss://two.invalid"}}' \
  "${AMD64_PROVENANCE}" "repeats object member.*amd64"
reject_document \
  "a repeated chain field cannot overwrite a reviewed value" \
  '{"amd64":{"chain_id":"1","chain_id":"2","cutover_block":1,"eth_rpc_url":"https://rpc.invalid","eth_ws_url":"wss://ws.invalid"}}' \
  "${AMD64_PROVENANCE}" "repeats object member.*chain_id"
reject_document \
  "a platform chain input must itself be an object" \
  '{"amd64":[]}' "${AMD64_PROVENANCE}" \
  "chain input \\[amd64\\] must be an object"
reject_document \
  "a missing chain field blocks the platform" \
  '{"amd64":{"chain_id":"1","cutover_block":1,"eth_rpc_url":"https://rpc.invalid"}}' \
  "${AMD64_PROVENANCE}" "must contain exactly"
reject_document \
  "an extra chain field blocks the platform" \
  '{"amd64":{"chain_id":"1","cutover_block":1,"eth_rpc_url":"https://rpc.invalid","eth_ws_url":"wss://ws.invalid","label":"extra"}}' \
  "${AMD64_PROVENANCE}" "must contain exactly"

reject_document \
  "the HTTP endpoint must be a URL" \
  '{"amd64":{"chain_id":"1","cutover_block":1,"eth_rpc_url":"not a URL","eth_ws_url":"wss://ws.invalid"}}' \
  "${AMD64_PROVENANCE}" "eth_rpc_url is not a URL"
reject_document \
  "the RPC endpoint must use HTTP or HTTPS" \
  '{"amd64":{"chain_id":"1","cutover_block":1,"eth_rpc_url":"wss://rpc.invalid","eth_ws_url":"wss://ws.invalid"}}' \
  "${AMD64_PROVENANCE}" "eth_rpc_url uses protocol"
reject_document \
  "the websocket endpoint must use WS or WSS" \
  '{"amd64":{"chain_id":"1","cutover_block":1,"eth_rpc_url":"https://rpc.invalid","eth_ws_url":"https://ws.invalid"}}' \
  "${AMD64_PROVENANCE}" "eth_ws_url uses protocol"
reject_document \
  "an endpoint with surrounding whitespace is refused" \
  '{"amd64":{"chain_id":"1","cutover_block":1,"eth_rpc_url":" https://rpc.invalid","eth_ws_url":"wss://ws.invalid"}}' \
  "${AMD64_PROVENANCE}" "must be one nonempty endpoint string"

reject_document \
  "cutover block zero is not a positive integer" \
  '{"amd64":{"chain_id":"1","cutover_block":0,"eth_rpc_url":"https://rpc.invalid","eth_ws_url":"wss://ws.invalid"}}' \
  "${AMD64_PROVENANCE}" "cutover_block must be a positive safe integer"
reject_document \
  "a fractional cutover block is not an integer" \
  '{"amd64":{"chain_id":"1","cutover_block":1.5,"eth_rpc_url":"https://rpc.invalid","eth_ws_url":"wss://ws.invalid"}}' \
  "${AMD64_PROVENANCE}" "cutover_block must be a positive safe integer"
reject_document \
  "an unsafe cutover block is refused before string conversion" \
  '{"amd64":{"chain_id":"1","cutover_block":9007199254740992,"eth_rpc_url":"https://rpc.invalid","eth_ws_url":"wss://ws.invalid"}}' \
  "${AMD64_PROVENANCE}" "cutover_block must be a positive safe integer"
reject_document \
  "chain id is a decimal string rather than a JSON number" \
  '{"amd64":{"chain_id":1,"cutover_block":1,"eth_rpc_url":"https://rpc.invalid","eth_ws_url":"wss://ws.invalid"}}' \
  "${AMD64_PROVENANCE}" "chain_id must be a positive decimal string"
reject_document \
  "chain id cannot carry a leading zero" \
  '{"amd64":{"chain_id":"01","cutover_block":1,"eth_rpc_url":"https://rpc.invalid","eth_ws_url":"wss://ws.invalid"}}' \
  "${AMD64_PROVENANCE}" "chain_id must be a positive decimal string"

reject_document \
  "provenance cannot publish one platform twice" \
  "${AMD64_CHAIN}" \
  '{"images":[{"platform":"amd64"},{"platform":"amd64"}]}' \
  "publishes platform \\[amd64\\] more than once"
reject_document \
  "an unsupported published platform has no guessed runner" \
  '{"s390x":{"chain_id":"1","cutover_block":1,"eth_rpc_url":"https://rpc.invalid","eth_ws_url":"wss://ws.invalid"}}' \
  '{"images":[{"platform":"s390x"}]}' \
  "publishes platform \\[s390x\\].*no native runner"
reject_document \
  "every published platform needs its own chain input" \
  '{}' "${AMD64_PROVENANCE}" "has no entry for published platform \\[amd64\\]"
reject_document \
  "provenance with no runtime image cannot dispatch an empty matrix" \
  '{}' '{"images":[]}' "publishes no runtime platform"
reject_document \
  "chain input for an unpublished platform is refused" \
  '{"amd64":{"chain_id":"1","cutover_block":1,"eth_rpc_url":"https://rpc.invalid","eth_ws_url":"wss://ws.invalid"},"arm64":{"chain_id":"2","cutover_block":2,"eth_rpc_url":"https://rpc2.invalid","eth_ws_url":"wss://ws2.invalid"}}' \
  "${AMD64_PROVENANCE}" "contains unpublished platform.*arm64"

# Matrix values include chain endpoints, so letting GitHub synthesize the job
# label would copy those URLs into checks, statuses, and notifications. Hold
# the explicit label to the sole non-sensitive discriminator it needs.
CONTAINER_JOB_NAME="$(awk '
  /^  container-rehearsal:[[:space:]]*$/ {
    in_job = 1
    next
  }
  in_job && /^  [^[:space:]][^:]*:[[:space:]]*$/ {
    exit
  }
  in_job && /^    name:[[:space:]]*/ {
    sub(/^    name:[[:space:]]*/, "")
    print
    exit
  }
' "${WORKFLOW}")"
# The workflow expression is compared as literal source text.
# shellcheck disable=SC2016
if [[ "${CONTAINER_JOB_NAME}" == \
  'Container rehearsal (${{ matrix.platform }})' ]]; then
  pass_case "the container job label exposes only the platform"
else
  fail_case "the container job label exposes only the platform" \
    "found [${CONTAINER_JOB_NAME:-no explicit name}]"
fi

printf '%d passed, %d failed\n' "${PASS}" "${FAILED}"
if ((FAILED != 0)); then
  exit 1
fi
