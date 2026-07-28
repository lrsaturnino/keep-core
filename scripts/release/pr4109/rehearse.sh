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
#   PROBE_IMAGE_DIGEST   immutable digest of the image every evidence probe
#                        runs in; it reads the numbers that become the record,
#                        so a mutable tag would leave the reading instrument
#                        outside the record's own provenance
#   ETH_WS_URL           rehearsal chain websocket endpoint
#   CUTOVER_BLOCK        rehearsed cutover block C on that chain
#   CHAIN_ID             that chain's numeric id, recorded in the evidence
#   KEYSTORE_DIR         per-node rehearsal inputs, one subdirectory per
#                        compose service holding that node's config.toml and
#                        operator key file; each config must declare a nonzero
#                        clientInfo.port, which is the only surface the
#                        rehearsal can read that node's evidence from
#   KEEP_ETHEREUM_PASSWORD  operator key file password for the fleet
#   STORAGE_SNAPSHOT_DIR    rollback only: one storage snapshot per R1 service
#                        for the offline state audit
#   PR4109_WORK_DRIVER   executable that originates protocol work on the
#                        rehearsal chain, called with the phase name. The
#                        fleet only reacts to chain events, so without it no
#                        ceremony exists to observe and the steps that need
#                        one record themselves blocked
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
#                        build-image accepts only what the CI build image
#                        produces by design: context-excluded paths absent
#                        from the image, untracked files classified under
#                        the commit's own restored .gitignore rules, and
#                        the regenerated gen/ binding and _address families
#                        — never the committed protobuf code — restored
#                        byte-exact from the dispatched commit before any
#                        test compiles them, with a post-restore re-check
#                        that fails on anything left beyond the
#                        context-excluded absences
#
# Which absences build-image mode may explain away is decided by a
# classification written out in this script, so it is held to the commit's
# own .dockerignore rather than trusted: local-proofs and shell-analysis both
# compare the two over every tracked path and refuse to go on once they
# disagree in any direction the image build does not account for. Which
# ignore file that is comes out of the rehearsal workflow's build step, read
# from the commit rather than restated here, and the scaffold lint's path
# filters are held to the same resolution — otherwise a build moved onto
# another Dockerfile would take its ignore rules somewhere nothing checks.
#
# Evidence is written under EVIDENCE_DIR (default: ./rehearsal-evidence).
# Every accepted rehearsal run must produce a record conforming to
# rehearsal-evidence.schema.json and binding the checked-in release
# manifest — its exact hash and its termination grace; the validate-evidence
# stage enforces both, self-testing its own checker first. Those comparisons
# only speak for the release while that manifest still matches the compiled
# bounds, so local-proofs attests it under EVIDENCE_DIR/attestation and
# validate-evidence refuses to measure a record without that receipt. The
# receipt belongs to one run at one commit: local-proofs destroys the
# inherited one before it proves anything and publishes its own by atomic
# rename only after every proof passed, stamping the commit the binding
# check proved, and validate-evidence requires that stamp to equal both its
# own binding and every record's source_sha.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
EVIDENCE_DIR="${EVIDENCE_DIR:-${SCRIPT_DIR}/rehearsal-evidence}"

# Where this scaffold lives inside the repository, and what invokes it, both
# resolved from the paths above rather than restated. The gate below has to
# run on every change to the scaffold's own code and has to be checked for
# still invoking it, and naming either a second time is exactly the
# restatement that would go stale the first time the scaffold moved.
SCAFFOLD_DIR="${SCRIPT_DIR#"${REPO_ROOT}/"}"
SCAFFOLD_ENTRYPOINT="$(basename "${BASH_SOURCE[0]}")"

# The stage that gate exists to run — this script's own analysis verb, which
# is the one thing about the invocation it cannot read off its own identity.
SCAFFOLD_LINT_STAGE="shell-analysis"

# The environment names the invocation may carry, which is the one this
# entrypoint documents itself as reading (EVIDENCE_DIR, above). Everything
# else is refused rather than dropped, because what bash does with a script it
# is handed is decided in that environment and not in the command line the
# reading below can see: BASH_ENV names a file bash sources before the
# script's first line, and a file that exits there ends the run at status zero
# without a line of the analysis having run; SHELLOPTS carrying `noexec` has
# bash parse the whole script and execute none of it. An assignment silently
# dropped is a command word read out of a command that is not the one that
# would run.
SCAFFOLD_LINT_ENV_NAMES="EVIDENCE_DIR"

# The commit verify_source_binding proved the tree under test to be, empty
# until it has proved one. Only a caller-supplied binding can establish an
# identity a stage may stamp into evidence; an unbound run leaves this empty
# and falls back to the tree's own (possibly -dirty) stamp.
VERIFIED_SOURCE_COMMIT=""

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
                      integration-tag compile proof; self-tests the
                      source-binding and evidence-record validators first
                      (the latter needs node/npx), reports every skipped
                      case explicitly, holds the verifier's build-context
                      classification to the commit's own .dockerignore,
                      discards any inherited EVIDENCE_DIR/attestation before
                      proving anything, and
                      ends by attesting the checked-in release manifest
                      against the compiled bounds — stamped with the commit
                      the binding check proved — into that directory by
                      atomic rename (runs today, no Docker)
  static-analysis     run the static analyzers CI enforces on the Go tree,
                      every tool at an immutable version: gofmt, go vet
                      over ./... (strictly wider than CI's root-only vet),
                      staticcheck 2025.1.1 (-SA1019), gosec v2.28.0 with
                      the CI flag set (G115/G118 and generated bindings
                      excluded; CI's own gosec action floats on master, the
                      pin keeps this evidence reproducible), and
                      golangci-lint v2.12.2 (network needed on first run to
                      fetch the pinned tools)
  shell-analysis      analyze the rehearsal scaffold itself: bash -n and
                      ShellCheck over every script here, actionlint v1.7.12
                      over the scaffold's own workflows, the build-context
                      classification checked against the commit's own
                      .dockerignore over every tracked path — the file
                      selected by the Dockerfile the rehearsal workflow's
                      build step really compiles, with that workflow's own
                      path filters held to the same resolution — and both
                      validator self-tests: the gate the scaffold's CI job
                      runs on every change to these files and to the build
                      inputs they mirror, so the checkers that admit
                      rehearsal evidence are never proved only by a manual
                      dispatch
  solidity-proofs     build and test the changed ECDSA contracts surface
                      exactly as the contracts workflow's build-and-test job
                      does: the exact Node release that job pins — read out
                      of it, not restated here, so the stage blocks rather
                      than claims a parity CI has moved away from — the
                      Corepack-managed yarn from packageManager, and a
                      never-skipped 'yarn install --immutable' before
                      yarn build and yarn test
  preflight           validate the container-rehearsal inputs and image digests
  single-release      exact-image cutover rehearsal: prior+R1 mixed fleet
                      before C, work across C without restart, straggler
                      negative control, clock failure, quiesce with in-flight
                      permits. Runs every step this release can execute,
                      records each step's own outcome, and emits an evidence
                      record naming the steps that could not run and why;
                      exits BLOCKED unless every mandatory step executed
  rollback            homogeneous rollback rehearsal: quiesce all R1,
                      all-candidate-down barrier, offline state audit, staged
                      prior redeploy, forbidden partial-rollback attempt.
                      Same per-step ledger and verdict as single-release;
                      additionally needs STORAGE_SNAPSHOT_DIR
  verify-source-binding
                      run only the fail-closed source binding check on this
                      tree and record it; inside the CI build image set
                      PR4109_SOURCE_BINDING_MODE=build-image
  validate-evidence   validate every evidence record under EVIDENCE_DIR
                      against rehearsal-evidence.schema.json and require
                      each record's release-manifest binding — the exact
                      manifest hash and the termination grace the fleet ran
                      under — to match the checked-in reviewed manifest;
                      requires the local-proofs attestation proving that
                      manifest still matches the compiled bounds, requires
                      the attestation, every record, and this run's own
                      binding to name one commit, verifies its own source
                      binding like any proof stage, and self-tests its
                      checker first

environment (every proof stage):
  PR4109_EXPECTED_SOURCE_COMMIT
                      fail closed: refuse to run unless the tree under test
                      is exactly this commit (clean, untracked included)
  PR4109_SOURCE_BINDING_MODE
                      exact (default) | build-image (accept only the CI
                      build image's designed divergence: context-excluded
                      absences, with every regenerated gen/ file restored
                      byte-exact from the dispatched commit before testing)
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

# sha256 of stdin, portable across the CI build image (busybox sha256sum)
# and a macOS workstation (shasum).
hash_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

# The CI build image drops every root dotfile from its build context (the
# .dockerignore `.*` rule), so inside the image git sees a tree without the
# repository's own ignore rules and every gitignored build output — the
# keep-client binary, the tmp/contracts artifact trees — as untracked
# divergence. Restore the committed .gitignore files, and only where they
# are absent: the restored bytes come from the commit under verification
# itself, so restoration cannot mask anything, while a present-but-modified
# .gitignore keeps its modified status and still fails the stamp.
restore_committed_gitignores() {
  local path
  git -C "${REPO_ROOT}" ls-tree -r --name-only HEAD |
    { grep -E '(^|/)\.gitignore$' || true; } |
    while IFS= read -r path; do
      if [[ ! -e "${REPO_ROOT}/${path}" ]]; then
        mkdir -p "${REPO_ROOT}/$(dirname "${path}")"
        git -C "${REPO_ROOT}" show "HEAD:${path}" >"${REPO_ROOT}/${path}"
      fi
    done
}

# True when .dockerignore keeps this committed path out of the build context
# entirely, so its absence inside the image is the image's construction and
# not divergence. Mirrors .dockerignore rule by rule, negations included:
# .clusterfuzzlite MUST reach the context, so its absence is never explained
# away, and the regenerated gen/ families are deliberately not listed here —
# the image is supposed to recreate them, so their absence is drift.
dockerignore_excluded_path() {
  local path="$1"
  if [[ "${path}" =~ ^\.clusterfuzzlite(/|$) ]]; then
    return 1
  fi
  [[ "${path}" =~ ^\.[^/]*(/|$) ]] && return 0
  [[ "${path}" =~ ^docs[^/]*/ ]] && return 0
  [[ "${path}" =~ ^(infrastructure|scripts|tmp|solidity|token-stakedrop|token-tracker)/ ]] &&
    return 0
  [[ "${path}" =~ ^(CODEOWNERS|Dockerfile)$ ]] && return 0
  [[ "${path}" =~ ^[^/]+\.adoc$ ]] && return 0
  [[ "${path}" =~ (^|/)node_modules/ ]] && return 0
  [[ "${path}" =~ (^|/)gen/_contracts(/|$) ]] && return 0
  return 1
}

# True for the tracked files the image legitimately rewrites: .dockerignore
# keeps **/gen/**/*.go and **/gen/_address/* out of the context, and
# `make get_artifacts` + `make generate` recreate them from the published
# contract artifacts before the final COPY. The negated families —
# gen/pb/*.go, gen/gen.go, gen/cmd/cmd.go — DO reach the context and are
# overwritten with committed bytes by that COPY, so a difference there is
# tampering, never regeneration: the committed protobuf message code the
# tests compile stays byte-bound to the dispatched commit. A match here
# never accepts the found bytes — it only marks the path for byte-exact
# restoration from the dispatched commit before anything compiles it.
regenerated_by_design_path() {
  local path="$1"
  if [[ "${path}" =~ (^|/)gen/pb/[^/]+\.go$ ]] ||
    [[ "${path}" =~ (^|/)gen/gen\.go$ ]] ||
    [[ "${path}" =~ (^|/)gen/cmd/cmd\.go$ ]]; then
    return 1
  fi
  [[ "${path}" =~ (^|/)gen/.+\.go$ ]] && return 0
  [[ "${path}" =~ (^|/)gen/_address/[^/]+$ ]] && return 0
  return 1
}

# The workflow whose build step decides what the classification below has to
# be checked against, and the unconditional lint that has to run whenever any
# of those inputs changes. Both are paths inside the commit under test rather
# than on disk: the build context of a dispatched commit is that commit's tree.
REHEARSAL_WORKFLOW=".github/workflows/cutover-rehearsal.yml"
SCAFFOLD_LINT_WORKFLOW=".github/workflows/cutover-scaffold-lint.yml"

# The action that workflow builds the proof image with. Its `context` and
# `file` inputs are the whole of what selects the build's ignore rules.
BUILD_ACTION="docker/build-push-action"

# Read out of that step by resolve_build_step_identity: the build context root,
# and the Dockerfile the builder compiles relative to it. The Dockerfile name
# matters beyond the build itself, because it is what selects the ignore rules
# below — which is exactly why neither is restated here as a constant.
BUILD_CONTEXT=""
BUILD_DOCKERFILE=""

# The ignore rules the two classifications above mirror, compiled once per
# tree into one extended regular expression per pattern with a parallel flag
# marking the negations, alongside the context-relative path they were read
# from. They are read from the commit, not from disk: the build context of a
# dispatched commit is that commit's own tree, and inside the build image the
# file itself is one of the paths its own `.*` rule kept out.
DOCKERIGNORE_SOURCE=""
DOCKERIGNORE_REGEX=()
DOCKERIGNORE_NEGATED=()

# Go's path/filepath.Clean over a slash-separated path, which the builder
# applies to every ignore line before compiling it: a `.` segment drops out,
# a `..` pops the segment before it, repeated separators collapse, a rooted
# path keeps exactly one leading separator, and a relative path cleaned away
# to nothing becomes `.`.
#
# Without it, a rule written `./scripts` or `docs/../docs` would compile here
# into an expression matching nothing at all, and every path the build really
# removes under that rule would read as still in the build context — the
# dangerous direction, where an absence gets explained away.
dockerignore_clean_path() {
  local path="$1"
  if [[ -z "${path}" ]]; then
    printf '.'
    return
  fi

  local rooted=0
  [[ "${path}" == /* ]] && rooted=1

  local segments=() kept=() segment last cleaned="" i
  IFS='/' read -r -a segments <<<"${path}"
  for ((i = 0; i < ${#segments[@]}; i++)); do
    segment="${segments[i]}"
    case "${segment}" in
    '' | '.') ;;
    '..')
      if ((${#kept[@]} > 0)); then
        last="${kept[$((${#kept[@]} - 1))]}"
        if [[ "${last}" != '..' ]]; then
          unset "kept[$((${#kept[@]} - 1))]"
          continue
        fi
      fi
      # A rooted path has nothing above its root to climb to, so a `..` it
      # cannot pop is dropped rather than kept.
      ((rooted == 1)) || kept+=('..')
      ;;
    *) kept+=("${segment}") ;;
    esac
  done

  for ((i = 0; i < ${#kept[@]}; i++)); do
    [[ -n "${cleaned}" ]] && cleaned+='/'
    cleaned+="${kept[i]}"
  done

  if ((rooted == 1)); then
    printf '/%s' "${cleaned}"
  elif [[ -z "${cleaned}" ]]; then
    printf '.'
  else
    printf '%s' "${cleaned}"
  fi
}

# Translate one normalized ignore pattern into an extended regular expression
# over a whole context-relative path, following the build daemon's own
# compilation: `*` stops at a path separator, `?` is a single non-separator
# character, `**` spans any number of whole segments (`.*` when it ends the
# pattern), and every other character is literal.
#
# The daemon compiles to a regular expression too, and escapes exactly the
# five characters escaped below on the way — every other character reaches
# its expression engine carrying whatever meaning that engine gives it. So
# this translation is the daemon's only for patterns that carry none of the
# remaining metacharacters, and load_dockerignore_patterns refuses those,
# backslash escapes included, before this ever sees them: a refusal raised
# here would run inside a command substitution and exit nothing but its own
# subshell.
dockerignore_pattern_regex() {
  local pattern="$1" out="^" i ch
  for ((i = 0; i < ${#pattern}; i++)); do
    ch="${pattern:i:1}"
    if [[ "${ch}" == '*' ]]; then
      if [[ "${pattern:i+1:1}" == '*' ]]; then
        i=$((i + 1))
        # A `**/` prefix spans whole segments, so the separator belongs to it.
        [[ "${pattern:i+1:1}" == '/' ]] && i=$((i + 1))
        if ((i + 1 == ${#pattern})); then
          out+='.*'
        else
          out+='(.*/)?'
        fi
      else
        out+='[^/]*'
      fi
    elif [[ "${ch}" == '?' ]]; then
      out+='[^/]'
    elif [[ '.+()$' == *"${ch}"* ]]; then
      out+="\\${ch}"
    else
      out+="${ch}"
    fi
  done
  printf '%s$' "${out}"
}

# The characters the daemon hands to its expression engine unescaped and this
# script has no translation for: a character class (`[`…`]`, whose negation
# form the engine reads back to front from the glob grammar the rules are
# documented in), a repetition (`{`…`}`), an alternation (`|`), a class
# negation (`^`), and a backslash escape. Naming them one by one keeps the
# refusal specific enough to act on.
dockerignore_unmodelled_construct() {
  local pattern="$1" i ch
  for ((i = 0; i < ${#pattern}; i++)); do
    ch="${pattern:i:1}"
    if [[ '[]{}|^' == *"${ch}"* || "${ch}" == $'\\' ]]; then
      printf '%s' "${ch}"
      return 0
    fi
  done
  return 1
}

# The value a `key:` line carries, with one layer of matching quotes taken off
# and a trailing comment dropped the way the workflow parser drops it. Refuses
# — non-zero, no output — any quoting that would need escape processing to
# read, because a value carrying its own escapes is a value this parser and the
# workflow parser could disagree about.
yaml_scalar_value() {
  local raw="$1" quote body rest
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"
  case "${raw}" in
  '"'* | "'"*)
    quote="${raw:0:1}"
    body="${raw:1}"
    [[ "${body}" == *"${quote}"* ]] || return 1
    rest="${body#*"${quote}"}"
    body="${body%%"${quote}"*}"
    rest="${rest#"${rest%%[![:space:]]*}"}"
    [[ -z "${rest}" || "${rest}" == '#'* ]] || return 1
    [[ "${body}" == *$'\\'* ]] && return 1
    printf '%s' "${body}"
    ;;
  *)
    if [[ "${raw}" == *' #'* ]]; then
      raw="${raw%% #*}"
      raw="${raw%"${raw##*[![:space:]]}"}"
    fi
    printf '%s' "${raw}"
    ;;
  esac
}

# The raw spellings of a value this parser refuses rather than guesses at:
# every one of them means something to the workflow parser that reading the
# characters literally would get wrong. Returns the reason, like
# dockerignore_unmodelled_construct, so the refusal is raised by a caller that
# can still stop the run rather than inside a command substitution.
#
# The expression opener is matched as the literal characters the workflow
# parser reads there, so it is deliberately never expanded here.
# shellcheck disable=SC2016
yaml_unmodelled_value() {
  local raw="$1"
  case "${raw}" in
  '') printf 'no value at all' ;;
  '|'* | '>'*) printf 'a block scalar' ;;
  '&'*) printf 'an anchor' ;;
  '*'*) printf 'an alias' ;;
  '['* | '{'*) printf 'a flow collection' ;;
  *'${{'*) printf 'a workflow expression' ;;
  *) return 1 ;;
  esac
  return 0
}

# Split the workflow into per-line indentation widths and leading-whitespace-
# stripped bodies, with -1 marking a line a parser has nothing to place — a
# blank line, or a comment at any column. Populates YAML_INDENTS and
# YAML_BODIES because a command substitution could not raise the tab refusal.
YAML_INDENTS=()
YAML_BODIES=()
yaml_index_lines() {
  local source="$1" content="$2" line trimmed i
  YAML_INDENTS=()
  YAML_BODIES=()

  local -a lines=()
  while IFS= read -r line; do lines+=("${line}"); done <<<"${content}"

  for ((i = 0; i < ${#lines[@]}; i++)); do
    line="${lines[i]}"
    trimmed="${line#"${line%%[![:space:]]*}"}"
    if [[ -z "${trimmed}" || "${trimmed}" == '#'* ]]; then
      YAML_INDENTS+=(-1)
      YAML_BODIES+=("")
      continue
    fi
    # YAML forbids a tab in indentation outright, so a width measured over one
    # would not be the width the workflow parser sees.
    if [[ "${line%%[![:space:]]*}" == *$'\t'* ]]; then
      fail "${source} line $((i + 1)) indents with a tab, which YAML does not \
allow as indentation and this parser cannot place"
    fi
    YAML_INDENTS+=("$((${#line} - ${#trimmed}))")
    YAML_BODIES+=("${trimmed}")
  done
}

# The column a sequence item's own mapping keys sit at — past the dash and the
# whitespace after it — or nothing when the line does not open one.
yaml_item_key_indent() {
  local index="$1" body value stripped
  body="${YAML_BODIES[index]}"
  [[ "${body}" == '-'[[:space:]]* ]] || return 1
  value="${body#-}"
  stripped="${value#"${value%%[![:space:]]*}"}"
  printf '%s' "$((YAML_INDENTS[index] + 1 + ${#value} - ${#stripped}))"
}

# The index one past the last line belonging to a block whose content sits at
# `indent`, starting the scan at `from`. A block ends at the first line placed
# shallower than its own content, which is also how the next sequence item
# ends the one before it.
yaml_block_end() {
  local from="$1" indent="$2" i
  for ((i = from; i < ${#YAML_INDENTS[@]}; i++)); do
    ((YAML_INDENTS[i] < 0)) && continue
    if ((YAML_INDENTS[i] < indent)); then
      printf '%s' "${i}"
      return
    fi
  done
  printf '%s' "${#YAML_INDENTS[@]}"
}

# The inputs of the step yaml_locate_action_step last placed, split into keys
# and their still-raw values. Parallel arrays because the shapes below have to
# stay bash-3 portable, and globals because the placement refuses unmodelled
# shapes as it goes and a refusal inside a command substitution would exit
# nothing but its own subshell.
YAML_STEP_INPUT_KEYS=()
YAML_STEP_INPUT_VALUES=()

# Place the one step in [from, to) whose `uses:` names the given action and
# read its inputs. Placing a step is the same problem wherever the step lives,
# and every shape this parser does not read the way the workflow parser does is
# refused by name: a value resolved on a guess is worse than no value, because
# the guess is what every claim built on it would then be measured against.
yaml_locate_action_step() {
  local source="$1" action="$2" from="$3" to="$4"
  YAML_STEP_INPUT_KEYS=()
  YAML_STEP_INPUT_VALUES=()

  # Every step using the action, whichever of the two spellings its `uses:`
  # line takes — opening the sequence item or following one.
  local -a hits=()
  local i body value
  for ((i = from; i < to; i++)); do
    ((YAML_INDENTS[i] < 0)) && continue
    body="${YAML_BODIES[i]}"
    if [[ "${body}" == '-'[[:space:]]* ]]; then
      body="${body#-}"
      body="${body#"${body%%[![:space:]]*}"}"
    fi
    [[ "${body}" == 'uses:'* ]] || continue
    value="$(yaml_scalar_value "${body#uses:}")" || continue
    [[ "${value}" == "${action}@"* ]] || continue
    hits+=("${i}")
  done

  ((${#hits[@]} != 0)) ||
    fail "${source} has no ${action} step; the values this script would \
otherwise be restating are read out of that step, and there is nothing left \
to read them from"
  ((${#hits[@]} == 1)) ||
    fail "${source} has ${#hits[@]} ${action} steps; this script cannot tell \
which one the values it reads belong to"

  # The step's mapping keys sit at the sequence item's content column: on the
  # `uses:` line itself when that line opens the item, and otherwise at the
  # column the item's own dash line opened.
  local hit="${hits[0]}" start key_indent opened
  if key_indent="$(yaml_item_key_indent "${hit}")"; then
    start="${hit}"
  else
    key_indent="${YAML_INDENTS[hit]}"
    start=-1
    for ((i = hit - 1; i >= from; i--)); do
      ((YAML_INDENTS[i] < 0)) && continue
      ((YAML_INDENTS[i] < key_indent)) || continue
      start="${i}"
      break
    done
    ((start >= 0)) ||
      fail "${source}: the ${action} step on line $((hit + 1)) opens no \
sequence item this parser can place"
    opened="$(yaml_item_key_indent "${start}")" || opened=""
    [[ "${opened}" == "${key_indent}" ]] ||
      fail "${source} line $((start + 1)) is not the sequence item opening the \
${action} step; this parser cannot place that step's inputs"
  fi

  local end with_line=-1
  end="$(yaml_block_end "$((start + 1))" "${key_indent}")"
  ((end > to)) && end="${to}"

  # The `with:` mapping, and nothing else read as one: a key line this parser
  # cannot split is a step shape it is not reading the way the workflow parser
  # does, wherever in the step it sits.
  for ((i = start + 1; i < end; i++)); do
    ((YAML_INDENTS[i] == key_indent)) || continue
    body="${YAML_BODIES[i]}"
    [[ "${body}" == *:* && "${body%%:*}" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]] ||
      fail "${source} line $((i + 1)) is not a key this parser can read inside \
the ${action} step"
    [[ "${body%%:*}" == 'with' ]] || continue
    value="${body#with:}"
    value="${value#"${value%%[![:space:]]*}"}"
    [[ -z "${value}" || "${value}" == '#'* ]] ||
      fail "${source} line $((i + 1)) writes the ${action} step's inputs as \
[${value}]; this parser reads only a block mapping"
    with_line="${i}"
  done

  # A step passing no inputs at all is a legible shape. Whether it is an
  # acceptable one is the caller's question, not this parser's.
  ((with_line >= 0)) || return 0

  local input_indent=-1
  for ((i = with_line + 1; i < end; i++)); do
    ((YAML_INDENTS[i] < 0)) && continue
    # The step's own next key closes the mapping.
    ((YAML_INDENTS[i] <= key_indent)) && break
    if ((input_indent < 0)); then
      input_indent="${YAML_INDENTS[i]}"
    fi
    ((YAML_INDENTS[i] > input_indent)) && continue
    ((YAML_INDENTS[i] == input_indent)) ||
      fail "${source} line $((i + 1)) is indented under the ${action} step's \
inputs at a column this parser cannot place"
    body="${YAML_BODIES[i]}"
    [[ "${body}" == *:* && "${body%%:*}" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]] ||
      fail "${source} line $((i + 1)) is not an input this parser can read \
inside the ${action} step"
    YAML_STEP_INPUT_KEYS+=("${body%%:*}")
    YAML_STEP_INPUT_VALUES+=("${body#*:}")
  done
}

# The still-raw value the placed step passes for an input, or non-zero when it
# passes none — which is a different thing from passing an empty one, and the
# callers below tell the two apart.
yaml_step_input() {
  local key="$1" i
  for ((i = 0; i < ${#YAML_STEP_INPUT_KEYS[@]}; i++)); do
    [[ "${YAML_STEP_INPUT_KEYS[i]}" == "${key}" ]] || continue
    printf '%s' "${YAML_STEP_INPUT_VALUES[i]}"
    return 0
  done
  return 1
}

# The line range of one job in the workflow currently indexed, so a step search
# can be scoped to it: a workflow runs the same action in several jobs, and
# only one of them is the job a claim of parity names.
YAML_JOB_START=-1
YAML_JOB_END=-1
yaml_locate_job() {
  local source="$1" job="$2" i jobs_line=-1 jobs_end job_indent=-1
  YAML_JOB_START=-1
  YAML_JOB_END=-1

  for ((i = 0; i < ${#YAML_BODIES[@]}; i++)); do
    ((YAML_INDENTS[i] == 0)) || continue
    [[ "${YAML_BODIES[i]}" == 'jobs:' ]] || continue
    jobs_line="${i}"
    break
  done
  ((jobs_line >= 0)) ||
    fail "${source} declares no jobs this parser can read"

  jobs_end="$(yaml_block_end "$((jobs_line + 1))" 1)"
  for ((i = jobs_line + 1; i < jobs_end; i++)); do
    ((YAML_INDENTS[i] < 0)) && continue
    ((job_indent < 0)) && job_indent="${YAML_INDENTS[i]}"
    ((YAML_INDENTS[i] == job_indent)) || continue
    [[ "${YAML_BODIES[i]}" == "${job}:" ]] || continue
    YAML_JOB_START="${i}"
    YAML_JOB_END="$(yaml_block_end "$((i + 1))" "$((job_indent + 1))")"
    return 0
  done

  fail "${source} has no ${job} job; the values this script reads out of that \
job have nowhere left to come from"
}

# The CI job the contracts stage reproduces, and the rehearsal job that has to
# run it on the same toolchain. Naming a job is a claim about what a stage's
# evidence is evidence of, and the release is entitled to have that claim
# checked rather than restated.
CONTRACTS_WORKFLOW=".github/workflows/contracts-ecdsa.yml"
CONTRACTS_JOB="contracts-build-and-test"
SOLIDITY_PROOFS_JOB="solidity-proofs"
SETUP_NODE_ACTION="actions/setup-node"

# Read by resolve_setup_node_version: the exact Node release a job pins.
SETUP_NODE_VERSION=""

# The Node release one workflow job pins, read out of that job's setup-node
# step. The contracts stage claims to reproduce a named CI job, and a claim of
# parity restated as a constant beside the claim stops being a claim about
# anything the moment the job moves: the stage would go on producing green
# evidence whose log says it ran what CI runs while running something else.
resolve_setup_node_version() {
  local workflow="$1" job="$2" content raw unmodelled version
  SETUP_NODE_VERSION=""

  content="$(git -C "${REPO_ROOT}" show "HEAD:${workflow}" 2>/dev/null)" ||
    fail "the commit under test carries no ${workflow}; the toolchain this \
scaffold reproduces is pinned there, and this script has nothing left to read \
it from"

  yaml_index_lines "${workflow}" "${content}"
  yaml_locate_job "${workflow}" "${job}"
  yaml_locate_action_step "${workflow}" "${SETUP_NODE_ACTION}" \
    "${YAML_JOB_START}" "${YAML_JOB_END}"

  raw="$(yaml_step_input node-version)" ||
    fail "the ${SETUP_NODE_ACTION} step in ${workflow}'s ${job} job pins no \
node-version, so it takes whatever the runner image ships; evidence from a \
toolchain nobody named is not that job's evidence"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"

  if unmodelled="$(yaml_unmodelled_value "${raw}")"; then
    fail "the ${SETUP_NODE_ACTION} step in ${workflow}'s ${job} job writes its \
node-version as ${unmodelled}, which this parser does not resolve"
  fi
  version="$(yaml_scalar_value "${raw}")" ||
    fail "the ${SETUP_NODE_ACTION} step in ${workflow}'s ${job} job quotes its \
node-version in a form this parser does not read"

  # A range or a major line lets the runner choose the release, and the
  # contracts build is pinned precisely because one it chose broke compile
  # artifacts. Reproducing "whatever 18.x resolved to today" reproduces
  # nothing.
  [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    fail "the ${SETUP_NODE_ACTION} step in ${workflow}'s ${job} job pins \
node-version [${version}], which is not one exact release; the contracts \
build is pinned exactly because a release the runner chose broke its compile \
artifacts"

  SETUP_NODE_VERSION="${version}"
}

# Both halves of the contracts stage's parity claim held to the job it names:
# the dispatch that provisions the toolchain, and — through the stage itself —
# the interpreter the proofs actually run on. Checked here, in the gate that
# runs on every change to either workflow, so a bump in CI is caught by a lint
# rather than by a dispatch that blocks on the wrong version.
verify_contracts_toolchain_pin() {
  local ci_version
  resolve_setup_node_version "${CONTRACTS_WORKFLOW}" "${CONTRACTS_JOB}"
  ci_version="${SETUP_NODE_VERSION}"

  resolve_setup_node_version "${REHEARSAL_WORKFLOW}" "${SOLIDITY_PROOFS_JOB}"
  [[ "${SETUP_NODE_VERSION}" == "${ci_version}" ]] ||
    fail "${REHEARSAL_WORKFLOW}'s ${SOLIDITY_PROOFS_JOB} job provisions Node \
${SETUP_NODE_VERSION} while ${CONTRACTS_WORKFLOW}'s ${CONTRACTS_JOB} job pins \
${ci_version}; the contracts stage reproduces that job, and evidence produced \
on another toolchain is not its evidence"

  note "contracts toolchain: ${CONTRACTS_WORKFLOW}'s ${CONTRACTS_JOB} job and \
${REHEARSAL_WORKFLOW}'s ${SOLIDITY_PROOFS_JOB} job both pin Node ${ci_version}"
}

# The Dockerfile the rehearsal dispatch compiles and the context root it
# compiles from, read out of the workflow that does the building rather than
# restated here. The pair decides which ignore file the build applies, so a
# constant restating it goes stale the moment the build step changes —
# silently, and in the direction where this script keeps checking itself
# against rules the build has stopped reading.
#
# The workflow is read from the commit under test, like the ignore rules
# themselves. Every step shape this parser does not model is refused by name:
# resolving a real build's Dockerfile on a guess is how the whole classification
# below ends up measured against the wrong file.
resolve_build_step_identity() {
  BUILD_CONTEXT=""
  BUILD_DOCKERFILE=""

  local content
  content="$(git -C "${REPO_ROOT}" show "HEAD:${REHEARSAL_WORKFLOW}" \
    2>/dev/null)" ||
    fail "the commit under test carries no ${REHEARSAL_WORKFLOW}; that \
workflow's build step is what decides which Dockerfile the proof image is \
compiled from, and so which ignore rules the build-context classification in \
this script has to be checked against"

  yaml_index_lines "${REHEARSAL_WORKFLOW}" "${content}"
  yaml_locate_action_step "${REHEARSAL_WORKFLOW}" "${BUILD_ACTION}" 0 \
    "${#YAML_BODIES[@]}"

  local raw_context raw_file seen_context=1 seen_file=1 unmodelled
  raw_context="$(yaml_step_input context)" || seen_context=0
  raw_file="$(yaml_step_input file)" || seen_file=0

  # An unset `context` is the action's Git context — a build of the repository
  # URL, not of this checkout — under which nothing the classification below
  # says about a tracked path holds.
  ((seen_context == 1)) ||
    fail "the ${BUILD_ACTION} step in ${REHEARSAL_WORKFLOW} sets no context, \
so it builds the default Git context rather than the dispatched checkout; the \
build-context classification in this script describes the checkout's tree"

  raw_context="${raw_context#"${raw_context%%[![:space:]]*}"}"
  raw_context="${raw_context%"${raw_context##*[![:space:]]}"}"
  if unmodelled="$(yaml_unmodelled_value "${raw_context}")"; then
    fail "the ${BUILD_ACTION} step in ${REHEARSAL_WORKFLOW} writes its context \
as ${unmodelled}, which this parser does not resolve; the build-context \
classification below would be checked against a guess"
  fi
  local build_context
  build_context="$(yaml_scalar_value "${raw_context}")" ||
    fail "the ${BUILD_ACTION} step in ${REHEARSAL_WORKFLOW} quotes its context \
in a form this parser does not read"
  build_context="$(dockerignore_clean_path "${build_context}")"
  [[ "${build_context}" == '.' ]] ||
    fail "the ${BUILD_ACTION} step in ${REHEARSAL_WORKFLOW} builds from \
context [${build_context}], but the build-context classification in this \
script is written over repository-relative paths and holds only for a context \
rooted at the repository; re-derive it before this scaffold admits any \
further evidence"

  # buildx defaults `file` to <context>/Dockerfile, and resolves a given one
  # against the working directory — the same directory the context is rooted
  # at, which is what makes the two readings agree here at all.
  local build_dockerfile="Dockerfile"
  if ((seen_file == 1)); then
    raw_file="${raw_file#"${raw_file%%[![:space:]]*}"}"
    raw_file="${raw_file%"${raw_file##*[![:space:]]}"}"
    if unmodelled="$(yaml_unmodelled_value "${raw_file}")"; then
      fail "the ${BUILD_ACTION} step in ${REHEARSAL_WORKFLOW} writes its \
Dockerfile as ${unmodelled}, which this parser does not resolve; the ignore \
rules the classification below is checked against are selected by that name"
    fi
    build_dockerfile="$(yaml_scalar_value "${raw_file}")" ||
      fail "the ${BUILD_ACTION} step in ${REHEARSAL_WORKFLOW} quotes its \
Dockerfile in a form this parser does not read"
    build_dockerfile="$(dockerignore_clean_path "${build_dockerfile}")"
    [[ "${build_dockerfile}" == /* || "${build_dockerfile}" == '.' ||
      "${build_dockerfile}" == '..' || "${build_dockerfile}" == '../'* ]] &&
      fail "the ${BUILD_ACTION} step in ${REHEARSAL_WORKFLOW} builds \
Dockerfile [${build_dockerfile}], which does not resolve to a path inside the \
build context; this script cannot name the ignore file that selects"
  fi

  git -C "${REPO_ROOT}" cat-file -e "HEAD:${build_dockerfile}" 2>/dev/null ||
    fail "the ${BUILD_ACTION} step in ${REHEARSAL_WORKFLOW} builds Dockerfile \
[${build_dockerfile}], which the commit under test does not carry"

  BUILD_CONTEXT="${build_context}"
  BUILD_DOCKERFILE="${build_dockerfile}"
  note "build step: ${REHEARSAL_WORKFLOW} compiles ${BUILD_DOCKERFILE} from \
context ${BUILD_CONTEXT}"
}

# The build inputs the ignore-file selection above depends on decide what this
# scaffold accepts as evidence just as directly as its own code does, and the
# gate holding the two together only ever runs on the events and paths its own
# workflow names. So both are held to the resolved identity: a build step moved
# to another Dockerfile takes its ignore file with it, and a filter list left
# behind would leave every later change to that file ungated — the mirror check
# would keep passing, on a file nobody was told had changed.
#
# A trigger carrying no filter at all runs on every change and so covers
# everything; what this refuses is a gate that some class of change can get
# past — reachable only by remembering to dispatch it, restricted away from
# the merges it exists to hold, or listing an input it later negates again.
verify_scaffold_lint_path_filters() {
  local content
  content="$(git -C "${REPO_ROOT}" show "HEAD:${SCAFFOLD_LINT_WORKFLOW}" \
    2>/dev/null)" ||
    fail "the commit under test carries no ${SCAFFOLD_LINT_WORKFLOW}; nothing \
holds the build-context classification in this script to the build inputs it \
mirrors"

  yaml_index_lines "${SCAFFOLD_LINT_WORKFLOW}" "${content}"

  load_lint_required_inputs
  LINT_FILTER_MISSING=""

  local i on_line=-1
  for ((i = 0; i < ${#YAML_BODIES[@]}; i++)); do
    ((YAML_INDENTS[i] == 0)) || continue
    [[ "${YAML_BODIES[i]}" == 'on:' ]] || continue
    on_line="${i}"
    break
  done
  ((on_line >= 0)) ||
    fail "${SCAFFOLD_LINT_WORKFLOW} declares no triggers this parser can read, \
so nothing says when the gate holding this script to the build inputs runs"

  local on_end trigger_indent=-1 covered=0 merges=0
  on_end="$(yaml_block_end "$((on_line + 1))" 1)"
  for ((i = on_line + 1; i < on_end; i++)); do
    ((YAML_INDENTS[i] < 0)) && continue
    ((trigger_indent < 0)) && trigger_indent="${YAML_INDENTS[i]}"
    ((YAML_INDENTS[i] == trigger_indent)) || continue
    case "${YAML_BODIES[i]}" in
    'push:' | 'pull_request:')
      verify_lint_trigger_filters "${i}" "${trigger_indent}"
      covered=$((covered + 1))
      [[ "${YAML_BODIES[i]}" == 'pull_request:' ]] && merges=1
      ;;
    esac
  done

  # A push trigger is not the merge gate: it fires after the branch already
  # moved, and on a repository that merges by pull request it never fires on
  # the release branch at all. Only a pull_request trigger can stop a change
  # to these inputs from landing unchecked, so its absence is refused however
  # many other events the workflow names.
  ((merges > 0)) ||
    fail "${SCAFFOLD_LINT_WORKFLOW} runs on no pull request, so a change to \
the build inputs the classification in this script mirrors can merge without \
the gate that holds the two together ever having run"

  if [[ -n "${LINT_FILTER_MISSING}" ]]; then
    printf '%s' "${LINT_FILTER_MISSING}" >&2
    fail "${SCAFFOLD_LINT_WORKFLOW} no longer runs on every input this \
scaffold's trust model is derived from (listing above); a change to an \
uncovered one would retire rules this scaffold never rechecks"
  fi

  note "scaffold lint: ${SCAFFOLD_LINT_WORKFLOW} runs on every change to the \
${#LINT_REQUIRED_INPUTS[@]} tracked input(s) this scaffold's trust model is \
derived from, on all ${covered} push/pull-request trigger(s)"
}

# The inputs a filter list has to cover and the ones a run found uncovered.
# Globals rather than arguments because the check below appends to the second
# from inside a loop, and reports every uncovered input at once rather than
# failing on the first: a filter list left behind by a moved build step is
# usually missing more than one entry, and the listing is what the fix needs.
LINT_REQUIRED_INPUTS=()
LINT_FILTER_MISSING=""

# Every path a change to which can move what this scaffold accepts, read out
# of the commit under test rather than listed by hand — a hand-kept list is
# trusted by inspection, and the whole point of this gate is that nothing
# here is.
#
# Four classes, each one something this script really reads:
#
#   the three workflows      one names the build step every classification
#                            below is resolved from, one is this gate itself,
#                            and one pins the toolchain the contracts stage
#                            claims to reproduce
#   the build's ignore rules the resolved Dockerfile, the ignore file its name
#                            selects, and the root .dockerignore that applies
#                            only while no such file exists — the last two are
#                            required whether or not the commit carries them,
#                            because adding one retires the other's every rule
#   the scaffold itself      the checkers deciding what may be accepted as
#                            release evidence, all of them, not just the ones
#                            written in shell
#   ignore and build rules   every committed .gitignore, root and nested,
#                            because build-image mode classifies untracked
#                            paths under the restored ones; and every
#                            committed Makefile, because the regeneration the
#                            gen/ classification models is what they run
load_lint_required_inputs() {
  local path
  LINT_REQUIRED_INPUTS=()
  while IFS= read -r path; do
    [[ -n "${path}" ]] && LINT_REQUIRED_INPUTS+=("${path}")
  done < <(
    {
      printf '%s\n' \
        "${REHEARSAL_WORKFLOW}" \
        "${SCAFFOLD_LINT_WORKFLOW}" \
        "${CONTRACTS_WORKFLOW}" \
        "${BUILD_DOCKERFILE}" \
        "${BUILD_DOCKERFILE}.dockerignore" \
        '.dockerignore'
      git -C "${REPO_ROOT}" ls-tree -r --name-only HEAD |
        {
          grep -E "^${SCAFFOLD_DIR}/|(^|/)\.gitignore$|(^|/)Makefile$" || true
        }
    } | sort -u
  )
}

# GitHub's filter-pattern grammar, which is not the glob grammar the build's
# ignore rules are written in: `*` stops at a separator and `**` does not, and
# a leading `!` is handled by the caller because it negates the patterns
# before it rather than anything inside its own.
lint_pattern_regex() {
  local pattern="$1" out="^" i ch
  for ((i = 0; i < ${#pattern}; i++)); do
    ch="${pattern:i:1}"
    if [[ "${ch}" == '*' ]]; then
      if [[ "${pattern:i+1:1}" == '*' ]]; then
        i=$((i + 1))
        out+='.*'
      else
        out+='[^/]*'
      fi
    elif [[ '.(){}|^$' == *"${ch}"* ]]; then
      out+="\\${ch}"
    else
      out+="${ch}"
    fi
  done
  printf '%s$' "${out}"
}

# The characters this grammar gives a meaning that reading them literally
# would get wrong, and that this script has no translation for. `?` and `+`
# quantify the character before them here rather than standing for one of any
# character — the reading the build's ignore rules would give them — so a
# required path measured against either would be measured wrong.
lint_pattern_unmodelled_construct() {
  local pattern="$1" i ch
  for ((i = 0; i < ${#pattern}; i++)); do
    ch="${pattern:i:1}"
    if [[ '?+[]' == *"${ch}"* || "${ch}" == $'\\' ]]; then
      printf '%s' "${ch}"
      return 0
    fi
  done
  return 1
}

# One trigger's compiled filter list, in the order it was written: the verdict
# a pattern carries when it matches (0 covers, 1 excludes again) travels beside
# it because order is what decides, and a later negation of an earlier listing
# is exactly the shape a coverage check reading membership cannot see.
LINT_FILTER_REGEX=()
LINT_FILTER_VERDICT=()

# Whether the compiled list above runs on a change to one path. GitHub reads
# the whole list and lets the last matching entry decide, so this does too; a
# path no entry matches at all is not covered.
lint_filter_covers() {
  local path="$1" i verdict=1
  for ((i = 0; i < ${#LINT_FILTER_REGEX[@]}; i++)); do
    [[ "${path}" =~ ${LINT_FILTER_REGEX[i]} ]] || continue
    verdict="${LINT_FILTER_VERDICT[i]}"
  done
  return "${verdict}"
}

# One push or pull_request trigger: the events it really fires on, and the
# paths it really runs for.
verify_lint_trigger_filters() {
  local line="$1" trigger_indent="$2"
  local trigger="${YAML_BODIES[line]%:}" end key_indent=-1
  local i j body paths_line=-1 entry entries=0 bad negated

  end="$(yaml_block_end "$((line + 1))" "$((trigger_indent + 1))")"
  for ((i = line + 1; i < end; i++)); do
    ((YAML_INDENTS[i] < 0)) && continue
    ((key_indent < 0)) && key_indent="${YAML_INDENTS[i]}"
    ((YAML_INDENTS[i] == key_indent)) || continue
    body="${YAML_BODIES[i]}"
    # An exclusion list says which changes are exempt rather than which are
    # covered, so a trigger carrying one cannot be read as coverage at all.
    [[ "${body}" == 'paths-ignore:'* ]] &&
      fail "${SCAFFOLD_LINT_WORKFLOW} filters its ${trigger} trigger with \
paths-ignore, which this check cannot read as coverage of the build inputs the \
classification in this script mirrors"
    [[ "${body}" == 'paths:' ]] && paths_line="${i}"
    if [[ "${trigger}" == 'pull_request' ]]; then
      verify_lint_pull_request_reach "${i}" "${key_indent}" "${body}"
    fi
  done

  # No filter at all is the whole repository: every required input is covered.
  ((paths_line >= 0)) || return 0

  LINT_FILTER_REGEX=()
  LINT_FILTER_VERDICT=()
  end="$(yaml_block_end "$((paths_line + 1))" "$((key_indent + 1))")"
  for ((j = paths_line + 1; j < end; j++)); do
    ((YAML_INDENTS[j] < 0)) && continue
    body="${YAML_BODIES[j]}"
    [[ "${body}" == '-'[[:space:]]* ]] ||
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((j + 1)) is not a path filter \
entry this parser can read"
    entry="$(yaml_scalar_value "${body#-}")" ||
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((j + 1)) quotes its path filter \
in a form this parser does not read"
    negated=0
    if [[ "${entry}" == '!'* ]]; then
      negated=1
      entry="${entry#!}"
    fi
    if bad="$(lint_pattern_unmodelled_construct "${entry}")"; then
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((j + 1)) filters on [${entry}], \
whose [${bad}] this script has no reading for; a required input measured \
against a guess would be reported covered on a guess"
    fi
    LINT_FILTER_REGEX+=("$(lint_pattern_regex "${entry}")")
    LINT_FILTER_VERDICT+=("${negated}")
    entries=$((entries + 1))
  done

  ((entries > 0)) ||
    fail "${SCAFFOLD_LINT_WORKFLOW} filters its ${trigger} trigger to an empty \
path list, which no change matches; the gate holding this script to the build \
inputs would never run"

  for entry in "${LINT_REQUIRED_INPUTS[@]}"; do
    lint_filter_covers "${entry}" ||
      LINT_FILTER_MISSING+="${SCAFFOLD_LINT_WORKFLOW} line \
$((paths_line + 1)): the ${trigger} filter list does not cover ${entry}"$'\n'
  done
}

# The lines a `run:` key hands to the shell, and the workflow line each of them
# sits on, or nothing when the line opens no `run:` at all. Both spellings
# these workflows use are read — the key on a sequence item's own line and the
# key opening one — because a step runs what its `run:` carries and nothing
# else: the same text in a step name, an `env:` value or a `with:` input names
# something, and a step that only names a command runs none of it.
#
# A shape whose lines are not what the shell receives is reported in
# YAML_RUN_UNMODELLED rather than read, with the lines still returned, so a
# caller can tell whether the shape nothing here reads is the one it was
# looking for. Refusing every folded scalar in the file would refuse steps this
# gate has no interest in.
YAML_RUN_LINES=()
YAML_RUN_LINENOS=()
YAML_RUN_UNMODELLED=""
yaml_run_lines() {
  local index="$1" body key_indent raw value end i
  YAML_RUN_LINES=()
  YAML_RUN_LINENOS=()
  YAML_RUN_UNMODELLED=""

  body="${YAML_BODIES[index]}"
  if key_indent="$(yaml_item_key_indent "${index}")"; then
    body="${body#-}"
    body="${body#"${body%%[![:space:]]*}"}"
  else
    key_indent="${YAML_INDENTS[index]}"
  fi
  [[ "${body}" == 'run:'* ]] || return 1

  raw="${body#run:}"
  raw="${raw#"${raw%%[![:space:]]*}"}"
  raw="${raw%"${raw##*[![:space:]]}"}"

  case "${raw}" in
  '') return 1 ;;
  # The literal block scalar, whose lines are the shell's lines.
  '|' | '|-' | '|+') ;;
  # A folded scalar joins its lines before the shell ever sees them, and an
  # explicit indentation indicator moves where its content begins; either way
  # what runs is not what these lines say.
  '|'* | '>'*)
    YAML_RUN_UNMODELLED="the block scalar header [${raw}]"
    ;;
  *)
    # Kept as written when the quoting is one yaml_scalar_value refuses, so the
    # invocation is still found in it and refused for the reason it really has
    # rather than reported missing.
    if value="$(yaml_scalar_value "${raw}")"; then
      raw="${value}"
    else
      YAML_RUN_UNMODELLED="a quoted value needing escape processing to read"
    fi
    YAML_RUN_LINES=("${raw}")
    YAML_RUN_LINENOS=("${index}")
    return 0
    ;;
  esac

  end="$(yaml_block_end "$((index + 1))" "$((key_indent + 1))")"
  for ((i = index + 1; i < end; i++)); do
    ((YAML_INDENTS[i] < 0)) && continue
    YAML_RUN_LINES+=("${YAML_BODIES[i]}")
    YAML_RUN_LINENOS+=("${i}")
  done
}

# One entry per logical command in the lines above: a line ending in a
# backslash joins the one after it, which is the only shape here that spreads a
# command across lines. SHELL_COMMAND_LINES keeps the workflow line each
# command opened on, because that is the line a refusal has to name.
SHELL_COMMANDS=()
SHELL_COMMAND_LINES=()
shell_logical_commands() {
  local i line acc="" start=-1
  local join=$'\\' joined=$'\\\\'
  SHELL_COMMANDS=()
  SHELL_COMMAND_LINES=()
  for ((i = 0; i < ${#YAML_RUN_LINES[@]}; i++)); do
    line="${YAML_RUN_LINES[i]}"
    if ((start < 0)); then start="${YAML_RUN_LINENOS[i]}"; fi
    if [[ "${line}" == *"${join}" && "${line}" != *"${joined}" ]]; then
      acc+="${line%"${join}"} "
      continue
    fi
    SHELL_COMMANDS+=("${acc}${line}")
    SHELL_COMMAND_LINES+=("${start}")
    acc=""
    start=-1
  done
  if [[ -n "${acc}" ]]; then
    SHELL_COMMANDS+=("${acc}")
    SHELL_COMMAND_LINES+=("${start}")
  fi
}

# The runner substitutes a workflow expression into this shell before the shell
# parses it, so a value carrying an operator writes a command nothing here ever
# saw. The contexts below are the runner's own — none of them can carry text
# from a pull request — and every other one is refused by name rather than read
# through, the way every other value this scaffold cannot model is.
SHELL_RUNNER_CONTEXTS="github.workspace github.repository github.sha \
github.run_id github.run_number github.run_attempt runner.temp \
runner.workspace runner.os runner.arch"

SHELL_EXPANDED=""
SHELL_EXPRESSION_REFUSAL=""
# The expression opener and closer are the literal characters the workflow
# parser reads there, so they are deliberately never expanded here.
# shellcheck disable=SC2016
shell_expand_expressions() {
  local raw="$1" head rest context
  SHELL_EXPANDED=""
  SHELL_EXPRESSION_REFUSAL=""
  while [[ "${raw}" == *'${{'* ]]; do
    head="${raw%%'${{'*}"
    rest="${raw#*'${{'}"
    if [[ "${rest}" != *'}}'* ]]; then
      SHELL_EXPRESSION_REFUSAL="an unterminated workflow expression"
      return 1
    fi
    context="${rest%%'}}'*}"
    raw="${rest#*'}}'}"
    context="${context#"${context%%[![:space:]]*}"}"
    context="${context%"${context##*[![:space:]]}"}"
    case " ${SHELL_RUNNER_CONTEXTS} " in
    *" ${context} "*) ;;
    *)
      SHELL_EXPRESSION_REFUSAL="the workflow expression [${context}]"
      return 1
      ;;
    esac
    # A value with no operator in it, so the command around it reads the same
    # before and after the runner writes the real one in.
    SHELL_EXPANDED+="${head}RUNNER_VALUE"
  done
  SHELL_EXPANDED+="${raw}"
}

# The first thing in a command this parser has no reading for, named one by one
# the way dockerignore_unmodelled_construct names one. Every entry decides
# either whether the command runs or whose exit status the shell reports back,
# which are the only two questions asked of this body; reading past one of them
# would be answering both on a guess.
#
# Quoting is tracked because an operator inside quotes is not an operator, and
# a word-initial `#` outside them ends the command the way the shell ends it.
shell_unmodelled_construct() {
  local cmd="$1" quote="" i ch next prev=""
  for ((i = 0; i < ${#cmd}; i++)); do
    ch="${cmd:i:1}"
    next="${cmd:i+1:1}"
    if [[ "${quote}" == "'" ]]; then
      [[ "${ch}" == "'" ]] && quote=""
      prev="${ch}"
      continue
    fi
    if [[ "${ch}" == $'\\' ]]; then
      i=$((i + 1))
      prev=""
      continue
    fi
    if [[ "${ch}" == '`' ]] || [[ "${ch}" == '$' && "${next}" == '(' ]]; then
      printf 'a command substitution'
      return 0
    fi
    if [[ "${quote}" == '"' ]]; then
      [[ "${ch}" == '"' ]] && quote=""
      prev="${ch}"
      continue
    fi
    if [[ "${ch}" == '#' && -z "${prev}" ]]; then
      return 1
    fi
    case "${ch}" in
    "'" | '"') quote="${ch}" ;;
    '|')
      if [[ "${next}" == '|' ]]; then
        printf 'a conditional chain'
        return 0
      fi
      printf 'a pipeline'
      return 0
      ;;
    '&')
      if [[ "${next}" == '&' ]]; then
        printf 'a conditional chain'
        return 0
      fi
      printf 'a backgrounded command'
      return 0
      ;;
    ';')
      printf 'a command list'
      return 0
      ;;
    '<' | '>')
      printf 'a redirection'
      return 0
      ;;
    '(' | ')')
      printf 'a subshell'
      return 0
      ;;
    esac
    if [[ "${ch}" == [[:space:]] ]]; then prev=""; else prev="${ch}"; fi
  done
  if [[ -n "${quote}" ]]; then
    printf 'an unterminated quote'
    return 0
  fi
  return 1
}

# A command's words, with the leading `NAME=value` assignments taken off into
# SHELL_ASSIGNMENTS and anything from a word-initial `#` onwards dropped.
# Placing the command word is the same problem for the invocation and for
# everything beside it, and both readings below start from it. The assignments
# are kept rather than discarded because they are part of what would run: they
# name the environment the command word resolves and executes under.
SHELL_WORDS=()
SHELL_ASSIGNMENTS=()
shell_command_words() {
  local cmd="$1" word
  local -a raw=()
  SHELL_WORDS=()
  SHELL_ASSIGNMENTS=()
  read -ra raw <<<"${cmd}"
  local i=0
  while ((i < ${#raw[@]})); do
    [[ "${raw[i]}" =~ ^[A-Za-z_][A-Za-z_0-9]*= ]] || break
    SHELL_ASSIGNMENTS+=("${raw[i]}")
    i=$((i + 1))
  done
  for ((; i < ${#raw[@]}; i++)); do
    word="${raw[i]}"
    [[ "${word}" == '#'* ]] && break
    SHELL_WORDS+=("${word}")
  done
}

# The command words that decide something about the commands around them rather
# than doing work of their own: a compound statement's keywords, and the
# builtins that change what the shell does with the lines after them. One of
# these ahead of the invocation can stop it running — `set -n` reads the rest
# of the body without executing any of it — or replace the shell that would
# have run it, and neither leaves a mark on the step's exit status.
SHELL_COMPOUND_WORDS="if then elif else fi for while until do done case esac \
select function coproc time in { } ! ["
SHELL_EXECUTION_WORDS="set shopt eval exec exit return source . trap"
shell_unmodelled_word() {
  shell_command_words "$1"
  ((${#SHELL_WORDS[@]} > 0)) || return 1
  case " ${SHELL_COMPOUND_WORDS} " in
  *" ${SHELL_WORDS[0]} "*)
    printf 'the compound-statement word [%s]' "${SHELL_WORDS[0]}"
    return 0
    ;;
  esac
  case " ${SHELL_EXECUTION_WORDS} " in
  *" ${SHELL_WORDS[0]} "*)
    printf 'the shell builtin [%s]' "${SHELL_WORDS[0]}"
    return 0
    ;;
  esac
  return 1
}

# The one command shape read as running the analysis: the entrypoint, the
# stage, nothing after it, and no `NAME=value` assignment ahead of it beyond
# the one name this entrypoint reads. The invocation as an argument to
# something else — an `echo`, a runner, a command substitution's subject — is a
# mention of the analysis rather than a run of it, and the exit status the step
# reports is that other command's. An assignment is the same substitution made
# without touching a character of the command: the words read here stay exactly
# as they are while the environment they run under decides whether bash
# executes a line of the file they name.
shell_invocation_shape() {
  local entrypoint="${SCAFFOLD_DIR}/${SCAFFOLD_ENTRYPOINT}" word
  shell_command_words "$1"
  if ((${#SHELL_WORDS[@]} == 0)); then
    printf 'it carries no command word at all'
    return 0
  fi

  word="${SHELL_WORDS[0]//\"/}"
  word="${word//\'/}"
  case "${word}" in
  "${entrypoint}" | */"${entrypoint}") ;;
  *)
    printf 'its command word is [%s]' "${SHELL_WORDS[0]}"
    return 0
    ;;
  esac

  if ((${#SHELL_WORDS[@]} < 2)); then
    printf 'it names no stage to run'
    return 0
  fi
  word="${SHELL_WORDS[1]//\"/}"
  word="${word//\'/}"
  if [[ "${word}" != "${SCAFFOLD_LINT_STAGE}" ]]; then
    printf 'its argument is [%s] rather than %s' \
      "${SHELL_WORDS[1]}" "${SCAFFOLD_LINT_STAGE}"
    return 0
  fi

  if ((${#SHELL_WORDS[@]} > 2)); then
    printf 'it carries the further argument [%s]' "${SHELL_WORDS[2]}"
    return 0
  fi

  local name
  for word in ${SHELL_ASSIGNMENTS[@]+"${SHELL_ASSIGNMENTS[@]}"}; do
    name="${word%%=*}"
    case " ${SCAFFOLD_LINT_ENV_NAMES} " in
    *" ${name} "*) continue ;;
    esac
    printf 'it sets [%s] in the environment the entrypoint runs under' "${name}"
    return 0
  done
  return 1
}

# Triggers and filters say when the gate runs. They say nothing about what it
# runs, and a workflow firing on every change to every input while its job no
# longer invokes this script — or invokes it behind a condition, or with its
# failure declared survivable — is the same ungated state written a different
# way. So the invocation is placed and read.
#
# Placed in the only thing that runs anything, a step's `run:` body, and read
# there down to the shape of the command: exactly one of it, the last command
# of its body so that the step's exit status is the analysis's whatever the
# shell's error handling is set to, nothing around it that could condition it
# or swallow its status, and no condition on the step or the job holding it.
#
# What this cannot prove is that a run of that workflow happened, or that a run
# reporting success ran this file. Everything read here is the head commit's —
# the workflow, the steps around the invocation, the entrypoint itself — so a
# commit can drop the invocation along with this reading of it, and a commit
# whose job keeps the name a branch-protection rule requires can report success
# having run something else under it. A rule naming a job the head commit
# defines therefore holds the name, not the analysis. Nor is the reading below
# a closure within the one body it reads: the commands ahead of the invocation
# are read for the shell they open, so a `cp` over the entrypoint is accepted
# and the accepted final command runs the copy. What makes the absence of a run
# of *this* analysis block a merge is a ruleset requiring a workflow this
# repository does not supply: an entry naming the gate checked in here names a
# file every pull request here can rewrite, so the entry has to name an outside
# repository, pin it by commit SHA rather than by a branch or tag ref, and have
# that pinned source carry the analysis itself. That control and its current
# standing are recorded beside this scaffold rather than claimed here.
verify_scaffold_lint_runs_analysis() {
  local content
  content="$(git -C "${REPO_ROOT}" show "HEAD:${SCAFFOLD_LINT_WORKFLOW}" \
    2>/dev/null)" ||
    fail "the commit under test carries no ${SCAFFOLD_LINT_WORKFLOW}; nothing \
runs the analysis the evidence this scaffold admits rests on"

  yaml_index_lines "${SCAFFOLD_LINT_WORKFLOW}" "${content}"

  # The stage ends where a stage name can no longer continue, rather than at
  # whitespace: an invocation the shell has wrapped in something — a
  # substitution, a quote, a pipeline — is exactly the case the reading below
  # exists to refuse, and one that never matched here would be refused for the
  # wrong reason, as an invocation nobody could find.
  local invocation="${SCAFFOLD_DIR}/${SCAFFOLD_ENTRYPOINT//./\\.}"
  invocation+="[[:space:]]+${SCAFFOLD_LINT_STAGE}([^-.[:alnum:]_]|$)"

  # Every `run:` body in the file, searched over the logical commands it hands
  # the shell rather than over its raw lines, so an invocation continued across
  # two of them counts once and counts here. That there is exactly one of it is
  # this question; what shape it has is the next.
  local -a run_keys=() hit_lines=()
  local i j invocations=0 found
  for ((i = 0; i < ${#YAML_BODIES[@]}; i++)); do
    ((YAML_INDENTS[i] < 0)) && continue
    yaml_run_lines "${i}" || continue
    shell_logical_commands
    found=0
    for ((j = 0; j < ${#SHELL_COMMANDS[@]}; j++)); do
      [[ "${SHELL_COMMANDS[j]}" =~ ${invocation} ]] || continue
      found=$((found + 1))
      hit_lines+=("${SHELL_COMMAND_LINES[j]}")
    done
    if ((found > 0)); then
      invocations=$((invocations + found))
      run_keys+=("${i}")
    fi
  done

  ((invocations != 0)) ||
    fail "${SCAFFOLD_LINT_WORKFLOW} no longer runs ${SCAFFOLD_ENTRYPOINT} \
${SCAFFOLD_LINT_STAGE} from any step's run: body; it would go on firing on \
every change to the inputs this scaffold's trust model is derived from and \
checking none of them"
  ((invocations == 1)) ||
    fail "${SCAFFOLD_LINT_WORKFLOW} runs ${SCAFFOLD_ENTRYPOINT} \
${SCAFFOLD_LINT_STAGE} ${invocations} times; this parser cannot tell which of \
them the conditions it reads below belong to"

  # The shell that one body carries, read as the shell would take it: what the
  # runner writes into it, what the commands around the invocation could do to
  # it, and whether the status the step reports is the analysis's at all.
  local run_key="${run_keys[0]}" run_line="${hit_lines[0]}"
  yaml_run_lines "${run_key}"
  [[ -z "${YAML_RUN_UNMODELLED}" ]] ||
    fail "${SCAFFOLD_LINT_WORKFLOW} line $((run_key + 1)) hands the \
${SCAFFOLD_LINT_STAGE} run to the shell through ${YAML_RUN_UNMODELLED}, which \
this parser has no reading for; what would run there is not what these lines \
say, and a run nothing here can read is not one this scaffold has proved"
  shell_logical_commands

  local k reason invocation_at=-1
  for ((k = 0; k < ${#SHELL_COMMANDS[@]}; k++)); do
    if ! shell_expand_expressions "${SHELL_COMMANDS[k]}"; then
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((SHELL_COMMAND_LINES[k] + 1)) \
carries ${SHELL_EXPRESSION_REFUSAL} in the step running \
${SCAFFOLD_LINT_STAGE}; the runner writes that value into this shell before \
the shell parses it, so the command it would make is not one read here"
    fi
    SHELL_COMMANDS[k]="${SHELL_EXPANDED}"

    if reason="$(shell_unmodelled_construct "${SHELL_COMMANDS[k]}")"; then
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((SHELL_COMMAND_LINES[k] + 1)) \
runs ${SCAFFOLD_LINT_STAGE} in a body carrying ${reason}; the status the step \
reports would be decided by something other than the analysis, and a check \
nothing depends on gates nothing"
    fi
    if reason="$(shell_unmodelled_word "${SHELL_COMMANDS[k]}")"; then
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((SHELL_COMMAND_LINES[k] + 1)) \
opens ${reason} in the step running ${SCAFFOLD_LINT_STAGE}; whether the \
analysis runs at all then rests on shell this parser does not read"
    fi
    [[ "${SHELL_COMMANDS[k]}" =~ ${invocation} ]] && invocation_at="${k}"
  done

  ((invocation_at == ${#SHELL_COMMANDS[@]} - 1)) ||
    fail "${SCAFFOLD_LINT_WORKFLOW} line $((run_line + 1)) runs \
${SCAFFOLD_LINT_STAGE} with $((${#SHELL_COMMANDS[@]} - invocation_at - 1)) \
command(s) after it; a step reports its last command's exit status, so a \
failing analysis would be reported as whatever ran after it"

  if reason="$(shell_invocation_shape "${SHELL_COMMANDS[invocation_at]}")"; then
    fail "${SCAFFOLD_LINT_WORKFLOW} line $((run_line + 1)) does not run \
${SCAFFOLD_LINT_STAGE} as a command of its own: ${reason}; a mention of the \
analysis is not a run of it, and the step would report whatever did run"
  fi

  local step=-1 step_keys=""
  if step_keys="$(yaml_item_key_indent "${run_key}")"; then
    step="${run_key}"
  else
    # A `run:` key that did not open its own step belongs to the nearest
    # sequence item opened shallower than it.
    for ((i = run_key - 1; i >= 0; i--)); do
      ((YAML_INDENTS[i] < 0)) && continue
      ((YAML_INDENTS[i] < YAML_INDENTS[run_key])) || continue
      step_keys="$(yaml_item_key_indent "${i}")" || continue
      step="${i}"
      break
    done
  fi
  ((step >= 0)) ||
    fail "${SCAFFOLD_LINT_WORKFLOW} line $((run_key + 1)) runs \
${SCAFFOLD_LINT_STAGE} outside any step this parser can place, so nothing \
here can say whether that run is conditioned away"

  local step_end
  step_end="$(yaml_block_end "$((step + 1))" "${step_keys}")"
  verify_scaffold_lint_unconditional "${step}" "${step_end}" "${step_keys}" \
    "step"

  local jobs_line=-1 job_indent=-1 job=-1
  for ((i = 0; i < ${#YAML_BODIES[@]}; i++)); do
    ((YAML_INDENTS[i] == 0)) || continue
    [[ "${YAML_BODIES[i]}" == 'jobs:' ]] || continue
    jobs_line="${i}"
    break
  done
  ((jobs_line >= 0)) ||
    fail "${SCAFFOLD_LINT_WORKFLOW} declares no jobs this parser can read, so \
nothing here can say what surrounds the ${SCAFFOLD_LINT_STAGE} run"

  # The last job opened before the step is the one the step belongs to; a line
  # shallower than a job name means the step sits outside jobs: altogether.
  for ((i = jobs_line + 1; i <= step; i++)); do
    ((YAML_INDENTS[i] < 0)) && continue
    ((job_indent < 0)) && job_indent="${YAML_INDENTS[i]}"
    if ((YAML_INDENTS[i] < job_indent)); then
      job=-1
      break
    fi
    ((YAML_INDENTS[i] == job_indent)) && job="${i}"
  done
  ((job >= 0)) ||
    fail "${SCAFFOLD_LINT_WORKFLOW} line $((step + 1)) runs \
${SCAFFOLD_LINT_STAGE} in no job this parser can place, so nothing here can \
say whether that job is conditioned away"

  local job_end job_keys=-1
  job_end="$(yaml_block_end "$((job + 1))" "$((job_indent + 1))")"
  for ((i = job + 1; i < job_end; i++)); do
    ((YAML_INDENTS[i] < 0)) && continue
    job_keys="${YAML_INDENTS[i]}"
    break
  done
  ((job_keys >= 0)) ||
    fail "${SCAFFOLD_LINT_WORKFLOW} job [${YAML_BODIES[job]%:}] carries \
nothing this parser can read, so nothing here can say whether the \
${SCAFFOLD_LINT_STAGE} run inside it is conditioned away"
  verify_scaffold_lint_unconditional "${job}" "${job_end}" "${job_keys}" \
    "job [${YAML_BODIES[job]%:}]"

  verify_scaffold_lint_preceding_steps "${job}" "${step}" "${step_keys}"

  # The same two substitutions one level further out, where neither block above
  # would show them.
  for ((i = 0; i < ${#YAML_BODIES[@]}; i++)); do
    ((YAML_INDENTS[i] == 0)) || continue
    case "${YAML_BODIES[i]}" in
    'defaults:')
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((i + 1)) sets workflow-wide \
defaults; what runs the ${SCAFFOLD_LINT_STAGE} body is then decided somewhere \
this parser does not read, which is the same as not knowing"
      ;;
    'env:'*)
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((i + 1)) writes a workflow-wide \
environment; every step inherits it, so the shell running \
${SCAFFOLD_LINT_STAGE} would be handed names that decide what the entrypoint's \
own name resolves to before it parses the command read here"
      ;;
    esac
  done

  note "scaffold lint: ${SCAFFOLD_LINT_WORKFLOW} runs ${SCAFFOLD_ENTRYPOINT} \
${SCAFFOLD_LINT_STAGE} unconditionally, on line $((run_line + 1)), as its \
step's last command, under the runner's own shell, with no environment or \
working directory written around it and no earlier step in its job running a \
shell of its own; that this commit says so is the whole of what is proved here \
— a command ahead of the invocation in that same body is read for the shell it \
opens and not for what it writes, and that a run happened at all, and that the \
run reporting success ran this file, rests on a ruleset requiring a workflow \
this repository does not supply, SHA-pinned outside it and carrying this \
analysis itself, whose standing is recorded in ${SCAFFOLD_DIR}/README.md"
}

# The keys that turn a step or the job around it into something a change can
# get past without this analysis having judged it: one deciding whether it runs
# at all, one deciding that its failure does not fail the run, and the rest
# deciding what the accepted command word would actually reach. A condition is
# refused rather than evaluated — this parser cannot tell which runs it would
# hold for, and a gate whose reachability rests on a condition nothing here
# reads is not a gate this scaffold has proved reachable.
#
# `shell:` is the one that leaves no mark at all on the shell it retires: the
# body reads exactly as it did while an interpreter that never runs a line of
# it — or never reports what running it said — takes the step's place. Only the
# runner's own default is accepted, spelled out or left out. `defaults:` sets
# the same thing a level or two away, and is refused outright rather than
# followed, because a body run by something this parser never saw named is the
# same unread state either way.
#
# The three added beside them retire the invocation without touching the line
# that carries it, which is why reading the body alone was never enough:
#
#   `env:`               — the runner writes these names into the step's own
#                          shell before it parses a line, and a `BASH_ENV`
#                          there names a file that shell sources first. A
#                          function defined in it can carry the entrypoint's
#                          own name; the exact command word accepted above then
#                          runs that function and returns whatever it says.
#   `working-directory:` — the invocation is a relative path. Resolved from
#                          another directory it names another file, and the
#                          text proving the analysis runs proves it of
#                          something else entirely.
#   `container:`         — the job's steps run inside an image this parser
#                          never reads, which decides both what bash is and
#                          what stands at the entrypoint's path.
#
# All three are refused outright rather than followed: a value read here would
# have to be resolved against a filesystem and an environment that exist only
# on the runner, and a resolution guessed at is worse than a refusal.
verify_scaffold_lint_unconditional() {
  local from="$1" to="$2" key_indent="$3" where="$4" i body value
  for ((i = from + 1; i < to; i++)); do
    ((YAML_INDENTS[i] == key_indent)) || continue
    body="${YAML_BODIES[i]}"
    case "${body}" in
    'if:'*)
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((i + 1)) conditions the ${where} \
running ${SCAFFOLD_LINT_STAGE} on [${body#if:}]; a gate that runs only when a \
condition holds is not the unconditional one this scaffold's evidence rests on"
      ;;
    'continue-on-error:'*)
      value="$(yaml_scalar_value "${body#continue-on-error:}")" || value=""
      [[ "${value}" == 'false' ]] && continue
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((i + 1)) lets the ${where} \
running ${SCAFFOLD_LINT_STAGE} fail without failing the run; a check nothing \
depends on gates nothing"
      ;;
    'shell:'*)
      value="$(yaml_scalar_value "${body#shell:}")" || value=""
      [[ "${value}" == 'bash' ]] && continue
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((i + 1)) hands the ${where} \
running ${SCAFFOLD_LINT_STAGE} to [${value}]; the body would read the same \
while an interpreter this parser never saw decided whether any of it runs and \
what its failing said"
      ;;
    'defaults:')
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((i + 1)) sets defaults on the \
${where} running ${SCAFFOLD_LINT_STAGE}; what runs that body is then decided \
somewhere this parser does not read, which is the same as not knowing"
      ;;
    'env:'*)
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((i + 1)) writes an environment \
into the ${where} running ${SCAFFOLD_LINT_STAGE}; the runner sets those names \
before the shell parses a line, and one of them naming a file that shell \
sources first can define the entrypoint's own name as a function — the \
command read here would then be exactly as written and run none of the analysis"
      ;;
    'working-directory:'*)
      value="$(yaml_scalar_value "${body#working-directory:}")" || value=""
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((i + 1)) runs the ${where} \
carrying ${SCAFFOLD_LINT_STAGE} from [${value}]; the invocation is a relative \
path, so what it names is decided by a directory this parser cannot resolve, \
and the analysis proved to run there is an analysis in some other file"
      ;;
    'container:'*)
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((i + 1)) runs the ${where} \
carrying ${SCAFFOLD_LINT_STAGE} inside a container image; what bash is there \
and what stands at the entrypoint's path are decided by an image this parser \
never reads, which is the same as not knowing what ran"
      ;;
    esac
  done
}

# The steps the job runs before the analysis one.
#
# Everything above reads a single step, and a step's body is only as good as
# the tree and the environment it meets. A step ahead of it can write over the
# entrypoint in the checkout, or append a name to $GITHUB_ENV that every step
# after it inherits. Either one leaves each line read above exactly as it was
# while the run they describe becomes a different run entirely.
#
# So a preceding step carrying a `run:` body is refused rather than read: what
# that shell would do is the whole question, and answering it would mean
# modelling a filesystem and an environment that exist only on the runner.
#
# A preceding `uses:` step is not proved harmless by this — an action runs code
# out of another repository and reaches $GITHUB_ENV and the checkout just as
# directly. It is accepted because refusing it would refuse the checkout the
# analysis needs in order to read anything at all. What that leaves open is not
# closed here and is not claimed to be; it is recorded with the rest of this
# reading's boundary in ${SCAFFOLD_DIR}/README.md.
verify_scaffold_lint_preceding_steps() {
  local job="$1" step="$2" step_keys="$3"
  local i j item_end opened body first
  for ((i = job + 1; i < step; i++)); do
    ((YAML_INDENTS[i] < 0)) && continue
    opened="$(yaml_item_key_indent "${i}")" || continue
    [[ "${opened}" == "${step_keys}" ]] || continue

    # A sequence item's first key sits on the dash line itself; the rest sit at
    # the item's own key column, and the item ends where the next one opens.
    item_end="$(yaml_block_end "$((i + 1))" "${step_keys}")"
    first="${YAML_BODIES[i]#-}"
    first="${first#"${first%%[![:space:]]*}"}"
    for ((j = i; j < item_end; j++)); do
      if ((j == i)); then
        body="${first}"
      else
        ((YAML_INDENTS[j] == step_keys)) || continue
        body="${YAML_BODIES[j]}"
      fi
      [[ "${body}" == 'run:'* ]] || continue
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((j + 1)) runs shell in the job \
carrying ${SCAFFOLD_LINT_STAGE}, ahead of the step that carries it; what that \
shell leaves behind — the entrypoint's own file in the checkout, a name \
written into \$GITHUB_ENV for the steps after it — decides what the invocation \
read here would reach, and this parser reads none of it"
    done
  done
}

# The pull_request event states and base branches a run really covers.
#
# A restriction on either is invisible to a check that reads only paths, and
# both leave the same hole: a change to these inputs that merges without this
# gate having run on it. `branches` is refused outright rather than compared
# against a branch name — naming the branch here would be one more restated
# constant, and every restriction of it exempts some merge. `types` is read,
# because narrowing it is the subtler hole: a list without `synchronize` runs
# once when the pull request opens and never again on what is pushed into it
# afterwards, which is to say never on the change that actually merges.
verify_lint_pull_request_reach() {
  local line="$1" key_indent="$2" body="$3"
  local end j entry seen="" want required=""

  case "${body}" in
  'branches:' | 'branches-ignore:')
    fail "${SCAFFOLD_LINT_WORKFLOW} restricts its pull_request trigger with \
${body%:}, so a pull request into any branch that restriction leaves out \
merges a change to these inputs without this gate having run"
    ;;
  'types:') ;;
  *) return 0 ;;
  esac

  end="$(yaml_block_end "$((line + 1))" "$((key_indent + 1))")"
  for ((j = line + 1; j < end; j++)); do
    ((YAML_INDENTS[j] < 0)) && continue
    body="${YAML_BODIES[j]}"
    [[ "${body}" == '-'[[:space:]]* ]] ||
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((j + 1)) is not a pull_request \
activity type this parser can read"
    entry="$(yaml_scalar_value "${body#-}")" ||
      fail "${SCAFFOLD_LINT_WORKFLOW} line $((j + 1)) quotes its pull_request \
activity type in a form this parser does not read"
    seen+="${entry}"$'\n'
  done

  # The three the event carries when nothing narrows it. A list may widen past
  # them; dropping one is what leaves a pull request state this never runs in.
  for want in opened synchronize reopened; do
    grep -qxF -- "${want}" <<<"${seen}" || required+=" ${want}"
  done
  [[ -z "${required}" ]] ||
    fail "${SCAFFOLD_LINT_WORKFLOW} narrows its pull_request trigger to \
activity types missing${required}, leaving pull request states in which a \
change to these inputs is never rechecked"
}

# Compile the ignore rules the build itself reads, from the commit under
# test. Which file that is, the builder decides by Dockerfile:
# `<dockerfile>.dockerignore` beside the context root wins whenever the
# commit carries one, and the root `.dockerignore` applies only otherwise. So
# a commit adding the Dockerfile-specific file silently retires every rule in
# the root one, and a mirror that read the root file regardless would go on
# checking itself against rules the build has stopped applying.
#
# Each line is then normalized the way the builder normalizes it: a line
# opening with `#` is a comment before anything else touches it, surrounding
# whitespace is trimmed, a leading `!` splits off as a negation and what
# follows it is trimmed again, and the remainder is path-cleaned and stripped
# of a single leading separator.
load_dockerignore_patterns() {
  DOCKERIGNORE_SOURCE=""
  DOCKERIGNORE_REGEX=()
  DOCKERIGNORE_NEGATED=()

  local content
  if content="$(git -C "${REPO_ROOT}" show \
    "HEAD:${BUILD_DOCKERFILE}.dockerignore" 2>/dev/null)"; then
    DOCKERIGNORE_SOURCE="${BUILD_DOCKERFILE}.dockerignore"
  elif content="$(git -C "${REPO_ROOT}" show HEAD:.dockerignore 2>/dev/null)"; then
    DOCKERIGNORE_SOURCE=".dockerignore"
  else
    fail "the commit under test carries neither \
${BUILD_DOCKERFILE}.dockerignore nor .dockerignore; the build-context \
classification in this script has nothing left to be checked against"
  fi

  local line negated unmodelled
  while IFS= read -r line; do
    [[ "${line}" == '#'* ]] && continue
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -n "${line}" ]] || continue
    negated=0
    if [[ "${line}" == '!'* ]]; then
      negated=1
      line="${line#!}"
      line="${line#"${line%%[![:space:]]*}"}"
      line="${line%"${line##*[![:space:]]}"}"
      # The builder refuses a bare `!` as an illegal exclusion pattern and
      # fails the whole build with it, rather than carrying on with the
      # rules around it.
      [[ -n "${line}" ]] ||
        fail "${DOCKERIGNORE_SOURCE} carries a bare [!] line, which the build \
daemon refuses outright as an illegal exclusion pattern"
    fi
    line="$(dockerignore_clean_path "${line}")"
    ((${#line} > 1)) && line="${line#/}"
    # Checked here, in the shell that can still stop the run: the compiler
    # below runs inside a command substitution, where refusing would exit
    # only the subshell and leave the unmodelled pattern silently empty.
    if unmodelled="$(dockerignore_unmodelled_construct "${line}")"; then
      fail "the ${DOCKERIGNORE_SOURCE} pattern [${line}] carries \
[${unmodelled}], which the build daemon gives to its expression engine and \
the build-context classification in this script reads as a literal; extend \
dockerignore_pattern_regex before relying on it"
    fi
    DOCKERIGNORE_REGEX+=("$(dockerignore_pattern_regex "${line}")")
    DOCKERIGNORE_NEGATED+=("${negated}")
  done <<<"${content}"

  ((${#DOCKERIGNORE_REGEX[@]} > 0)) ||
    fail "${DOCKERIGNORE_SOURCE} carries no pattern at all; the \
build-context classification in this script has nothing to be checked against"
}

# True when the build daemon would keep this committed path out of the build
# context. Patterns apply in file order with the last one to match deciding,
# and a path matches when it or any of its ancestor directories does — the
# daemon's own rule, and the reason a bare directory pattern like `solidity`
# removes everything beneath it.
dockerignore_context_excluded() {
  local path="$1" excluded=1 i regex negated matched prefix rest
  for ((i = 0; i < ${#DOCKERIGNORE_REGEX[@]}; i++)); do
    negated="${DOCKERIGNORE_NEGATED[i]}"
    # A negation has nothing to re-include while the path is still in the
    # context, and an exclusion has nothing to add once it is already out.
    if [[ "${negated}" == 1 ]]; then
      [[ "${excluded}" == 0 ]] || continue
    else
      [[ "${excluded}" == 1 ]] || continue
    fi

    regex="${DOCKERIGNORE_REGEX[i]}"
    matched=1
    if [[ "${path}" =~ ${regex} ]]; then
      matched=0
    else
      prefix=""
      rest="${path}"
      while [[ "${rest}" == */* ]]; do
        prefix+="${rest%%/*}"
        rest="${rest#*/}"
        if [[ "${prefix}" =~ ${regex} ]]; then
          matched=0
          break
        fi
        prefix+="/"
      done
    fi

    if [[ "${matched}" == 0 ]]; then
      if [[ "${negated}" == 1 ]]; then excluded=1; else excluded=0; fi
    fi
  done
  return "${excluded}"
}

# The two classifications above are hand-written mirrors of build inputs that
# live elsewhere, and a mirror is only ever as good as its last
# synchronization. This walks every path the commit tracks and compares each
# mirror's verdict against the rules the build's own ignore file carries.
#
# A path the mirror calls context-excluded while the context in fact holds it
# is the dangerous direction: build-image mode would explain that file's
# absence from the image as the image's own construction and accept a tree
# missing it. The opposite direction is safe — the mirror would report a
# legitimate absence as unexplained divergence and refuse to produce evidence
# — but it is still drift, so it is tolerated only for the families the image
# regenerates by design, which verify_build_image_tree restores byte-exact
# rather than explains away.
verify_build_context_mirror() {
  # Which rules those are is itself a build input: the builder picks its
  # ignore file by Dockerfile, and which Dockerfile it compiles is written in
  # the workflow that does the building. So the identity is read from that
  # workflow, and the gate that reruns this check is held to it, before a
  # single pattern is compiled.
  resolve_build_step_identity
  verify_scaffold_lint_path_filters
  verify_scaffold_lint_runs_analysis
  load_dockerignore_patterns
  note "build-context mirror: checking this script's classification against \
the ${#DOCKERIGNORE_REGEX[@]} pattern(s) the build reads from \
${DOCKERIGNORE_SOURCE}"

  local path mirror context tracked=0 excluded=0 regenerated=0 drift=""
  while IFS= read -r -d '' path; do
    [[ -n "${path}" ]] || continue
    tracked=$((tracked + 1))
    if dockerignore_excluded_path "${path}"; then mirror=0; else mirror=1; fi
    if dockerignore_context_excluded "${path}"; then context=0; else context=1; fi

    if [[ "${mirror}" == 0 && "${context}" == 0 ]]; then
      excluded=$((excluded + 1))
    elif [[ "${mirror}" == 0 ]]; then
      drift+="${path}: this script explains an absence here as a \
context-excluded path, but ${DOCKERIGNORE_SOURCE} keeps it in the build \
context"$'\n'
    elif [[ "${context}" == 0 ]]; then
      if regenerated_by_design_path "${path}"; then
        regenerated=$((regenerated + 1))
      else
        drift+="${path}: ${DOCKERIGNORE_SOURCE} keeps this path out of the \
build context, but this script neither excludes it nor treats it as \
regenerated"$'\n'
      fi
    fi
  done < <(git -C "${REPO_ROOT}" ls-tree -r -z --name-only HEAD)

  if [[ -n "${drift}" ]]; then
    printf '%s' "${drift}" >&2
    fail "the build-context classification in this script no longer mirrors \
${DOCKERIGNORE_SOURCE} (listing above); re-derive dockerignore_excluded_path \
and regenerated_by_design_path from the current build inputs before this \
scaffold admits any further evidence"
  fi

  note "build-context mirror: ${tracked} tracked path(s) classified \
identically by ${DOCKERIGNORE_SOURCE} and this script (${excluded} kept out \
of the build context; ${regenerated} excluded from the context but \
regenerated into the image by design)"
}

# The artifact input identity behind the image build: get_artifacts leaves
# each resolved npm tarball — name and exact version — under tmp/contracts.
# The digests are forensic context, not trust: the bytes the proof stages
# compile are restored from the dispatched commit regardless of what these
# artifacts contained, but recording them lets an evidence consumer verify
# against the registry what the image build itself consumed.
record_artifact_identity() {
  local tarball
  if [[ ! -d "${REPO_ROOT}/tmp/contracts" ]]; then
    note "artifact identity: no tmp/contracts artifact tree in this image"
    return
  fi
  note "artifact identity: resolved contract artifact tarballs:"
  find "${REPO_ROOT}/tmp/contracts" -name '*.tgz' -type f |
    LC_ALL=C sort |
    while IFS= read -r tarball; do
      printf '>>   %s sha256 %s\n' "${tarball#"${REPO_ROOT}"/}" \
        "$(hash_stdin <"${tarball}")"
    done
}

# Restore one tracked path byte-exact from the commit under verification.
# `git show` only reads the object store, so it works against the read-only
# .git mount the workflow uses (a `git checkout` would have to write the
# index). HEAD equality with the dispatched SHA is proven before any
# restoration, so the restored bytes are the dispatched bytes by
# construction; a path that cannot be restored fails the stage.
restore_tracked_file_from_head() {
  local path="$1"
  mkdir -p "${REPO_ROOT}/$(dirname "${path}")" ||
    fail "could not create the directory to restore ${path}; the image \
tree cannot be bound to the dispatched commit"
  if ! git -C "${REPO_ROOT}" show "HEAD:${path}" >"${REPO_ROOT}/${path}"; then
    fail "could not restore ${path} byte-exact from the dispatched commit; \
the image tree cannot be bound to the dispatched SHA"
  fi
}

# Build-image verification: every porcelain line must be explained by the
# image's documented construction, and no regenerated byte is ever accepted
# into evidence. Deletions are accepted only for context-excluded paths —
# none of which holds Go code the proof stages compile. The families the
# image rewrites by design (the regenerated gen/ bindings and the
# gen/_address values, including placeholders the generator dropped) are
# never trusted as found: each one is restored byte-exact from the
# dispatched commit before any test compiles it, with the pre-restore image
# hash recorded for forensics, so whatever the generator — or anything
# else — put there can never become the tested bytes. Untracked files are
# always fatal once the committed ignore rules are restored; every other
# status — a modified or deleted committed file outside those families,
# index-side changes, renames, typechanges, an unreadable tree — is fatal.
# Restoration itself is not trusted either: the whole tree is re-checked
# afterwards and anything left beyond the context-excluded absences fails.
verify_build_image_tree() {
  local expected="$1"
  restore_committed_gitignores

  local divergence unexplained="" restorable="" absences=0 restores=0
  local line status path prior
  divergence="$(source_divergence)"
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    status="${line:0:2}"
    path="${line:3}"
    case "${status}" in
    " D")
      if dockerignore_excluded_path "${path}"; then
        absences=$((absences + 1))
      elif [[ "${path}" =~ (^|/)gen/_address/[^/]+$ ]]; then
        restorable+="${path}"$'\t'"absent from the image"$'\n'
      else
        unexplained+="${line}"$'\n'
      fi
      ;;
    " M")
      if regenerated_by_design_path "${path}"; then
        restorable+="${path}"$'\t'"pre-restore image sha256 \
$(hash_stdin <"${REPO_ROOT}/${path}")"$'\n'
      else
        unexplained+="${line}"$'\n'
      fi
      ;;
    *)
      unexplained+="${line}"$'\n'
      ;;
    esac
  done <<<"${divergence}"

  if [[ -n "${unexplained}" ]]; then
    printf '%s' "${unexplained}" >&2
    fail "source binding to ${expected} requested, but the build-image tree \
diverges from that commit beyond what the image build produces by design \
(listing above); refusing to produce evidence"
  fi

  if [[ -n "${restorable}" ]]; then
    note "regenerated tracked files restored byte-exact from the dispatched \
commit before testing:"
    while IFS=$'\t' read -r path prior; do
      [[ -n "${path}" ]] || continue
      restore_tracked_file_from_head "${path}"
      restores=$((restores + 1))
      printf '>>   %s committed sha256 %s (%s)\n' "${path}" \
        "$(hash_stdin <"${REPO_ROOT}/${path}")" "${prior}"
    done <<<"${restorable}"
  fi

  local residual=""
  absences=0
  divergence="$(source_divergence)"
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    status="${line:0:2}"
    path="${line:3}"
    if [[ "${status}" == " D" ]] && dockerignore_excluded_path "${path}"; then
      absences=$((absences + 1))
      continue
    fi
    residual+="${line}"$'\n'
  done <<<"${divergence}"
  if [[ -n "${residual}" ]]; then
    printf '%s' "${residual}" >&2
    fail "source binding to ${expected} requested, but restoration left the \
build-image tree diverging from that commit (listing above); refusing to \
produce evidence"
  fi

  record_artifact_identity

  note "source commit: ${expected} (verified against the dispatched SHA \
inside the build image; ${absences} context-excluded absence(s); \
${restores} regenerated tracked file(s) restored byte-exact from that \
commit before testing)"
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
  case "${mode}" in
  exact)
    divergence="$(source_divergence)"
    if [[ -n "${divergence}" ]]; then
      printf '%s\n' "${divergence}" >&2
      fail "source binding to ${expected} requested, but the tree diverges \
from that commit (listing above; untracked files count); refusing to \
produce evidence for bytes that are not the dispatched commit"
    fi
    note "source commit: ${expected} (verified against the dispatched SHA)"
    ;;
  build-image)
    verify_build_image_tree "${expected}"
    ;;
  *)
    fail "unknown PR4109_SOURCE_BINDING_MODE [${mode}]; use exact or \
build-image"
    ;;
  esac

  # Reaching here means the tested bytes were proved to be this commit's:
  # fail and blocked both exit. Later steps in the same stage stamp their
  # output with this identity rather than re-deriving it, because the raw
  # stamp cannot express what was proved — build-image mode verifies a tree
  # that legitimately diverges from HEAD, so source_commit would call the
  # very tree this function just accepted -dirty.
  VERIFIED_SOURCE_COMMIT="${expected}"
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

# Directory holding the release-manifest attestation: the receipt proving the
# checked-in manifest still matches the compiled bounds of the source under
# test. It is a subdirectory on purpose. Both the record glob below and the
# workflow's record probe look at EVIDENCE_DIR's top level only, so producing
# this receipt never makes a record-free dispatch look like it produced a
# rehearsal record.
attestation_dir() { printf '%s\n' "${EVIDENCE_DIR}/attestation"; }

# The source identity a receipt written now may claim: what the binding
# check proved, or — for an unbound run — the tree's own stamp, which carries
# its -dirty marker and its outside-a-checkout "unknown" with it. The
# acceptance stage refuses anything but a clean commit id, so an unbound or
# divergent run still produces a receipt; it just produces one that cannot
# launder bytes into release evidence.
attested_source_identity() {
  if [[ -n "${VERIFIED_SOURCE_COMMIT}" ]]; then
    printf '%s' "${VERIFIED_SOURCE_COMMIT}"
    return
  fi
  source_commit
}

# A receipt speaks for the run that wrote it and for no other, so every proof
# run destroys the receipt it inherits before it proves anything. Evidence
# directories get reused — a re-dispatch into the same workspace, a local
# iteration loop — and without this a run failing anywhere before the
# attestation step would leave its predecessor's receipt standing for the
# acceptance stage to find and accept. Interrupted staging directories go the
# same way, so no fragment of an older run survives into this one.
invalidate_release_manifest_attestation() {
  local dir
  dir="$(attestation_dir)"
  if [[ -e "${dir}" ]]; then
    note "discarding the release-manifest attestation inherited in ${dir}"
  fi
  rm -rf "${dir}" "${dir}".staging.*
}

# The acceptance stage judges a rehearsal record by comparing it against the
# checked-in release manifest, but that manifest only speaks for the release
# while it still matches this binary's compiled bounds. The Go proofs pin that
# identity inside their own log; this turns it into a machine-checkable
# receipt, produced here — inside the source-bound tree, where the Go
# toolchain is — so the acceptance stage can require the proof without
# carrying a toolchain of its own.
attest_release_manifest() {
  local manifest="${SCRIPT_DIR}/release-manifest.json"
  local dir staging
  dir="$(attestation_dir)"
  # Build the receipt beside its destination and publish it with a single
  # rename, so a reader sees this run's complete receipt or no receipt at
  # all. Writing the files straight into the destination would publish a
  # half-built receipt while it is being written, and would let files from
  # two different runs end up sitting in one directory.
  staging="${dir}.staging.$$"
  rm -rf "${staging}"
  mkdir -p "${staging}"

  note "attesting the release manifest against the compiled bounds"
  # validate is the binary's own reviewed check: it rejects a manifest whose
  # numbers differ from the compiled derivation in any field, the cleanup
  # allowance the runtime actually waits included.
  go run . release-manifest validate --manifest "${manifest}"

  # derive emits the manifest the compiled bounds produce, so the receipt
  # carries those bounds themselves rather than an assertion about them, and
  # the hash names the exact reviewed bytes validate just accepted.
  go run . release-manifest derive >"${staging}/derived-manifest.json"
  hash_stdin <"${manifest}" >"${staging}/reviewed-manifest.sha256"

  # The commit these bounds were compiled from. The acceptance stage requires
  # every record it measures to name this same commit, so a receipt can never
  # vouch for records built from other bytes — the case the manifest hash
  # alone misses entirely, since a manifest that did not change between two
  # commits hashes the same at both.
  attested_source_identity >"${staging}/source-commit.txt"
  printf '\n' >>"${staging}/source-commit.txt"

  rm -rf "${dir}"
  mv "${staging}" "${dir}"

  note "release-manifest attestation written to ${dir} for source \
$(tr -d '[:space:]' <"${dir}/source-commit.txt")"
}

# Everything stage_local_proofs proves, in one seam. The stage around it owns
# the receipt lifecycle — destroy the inherited one, prove, publish this run's
# — and that ordering is the whole reason a failed proof run cannot leave a
# usable receipt behind, so the self-test drives the stage with this function
# replaced by a failing stub to hold the ordering in place.
run_local_proof_suite() {
  # The verifier gates every piece of evidence below, so it proves itself
  # first: the self-test builds throwaway repositories shaped like the
  # dispatched checkout and like the build image's tree and checks the
  # verifier accepts exactly the image's documented construction.
  "${SCRIPT_DIR}/test-source-binding.sh"
  # The evidence-record validator gates the acceptance of every rehearsal
  # record the same way, so it proves itself on every proof run — not only
  # on the dispatches that happen to produce records for validate-evidence
  # — and its verdicts land in this stage's archived log.
  "${SCRIPT_DIR}/test-validate-evidence.sh"
  verify_source_binding
  # The verifier's own build-context classification is what the binding check
  # just used to explain away every absence from the image, so its agreement
  # with the committed build inputs is proved here, where evidence is
  # produced, and not only in the scaffold's static-analysis gate.
  verify_build_context_mirror
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
    -run 'TestAwaitQuiesce|TestQuiesceBackstop|TestSignalLifecycle|TestMaximumLegacyCompletionBlocks|TestReleaseManifest' \
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
}

stage_local_proofs() {
  note "running the repository-local cutover gate proofs"
  mkdir -p "${EVIDENCE_DIR}"
  local log="${EVIDENCE_DIR}/local-proofs.log"

  (
    # Before anything is proved, so no proof below can fail while an earlier
    # run's receipt stays behind to be accepted in this run's name. Runs
    # ahead of the cd because EVIDENCE_DIR may be relative to the caller's
    # directory.
    invalidate_release_manifest_attestation

    cd "${REPO_ROOT}"
    run_local_proof_suite

    # Last, so the receipt exists only for a tree whose proofs all passed.
    attest_release_manifest
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

# The scaffold's own workflow files. actionlint is deliberately not pointed
# at the whole workflow directory: the unrelated workflows carry pre-existing
# findings, and a gate that is red for reasons outside its scope stops being
# read.
cutover_workflow_files() {
  printf '%s\n' \
    "${REPO_ROOT}/.github/workflows/cutover-rehearsal.yml" \
    "${REPO_ROOT}/.github/workflows/cutover-scaffold-lint.yml"
}

stage_shell_analysis() {
  note "analyzing the rehearsal scaffold's shell scripts and workflows"
  mkdir -p "${EVIDENCE_DIR}"
  local log="${EVIDENCE_DIR}/shell-analysis.log"

  command -v shellcheck >/dev/null 2>&1 ||
    blocked "shellcheck is required to analyze the rehearsal scripts"
  command -v node >/dev/null 2>&1 ||
    blocked "node (Node.js) is required by the evidence-validator self-test"
  command -v npx >/dev/null 2>&1 ||
    blocked "npx (Node.js) is required by the evidence-validator self-test"
  command -v git >/dev/null 2>&1 ||
    blocked "git is required by both validator self-tests"

  (
    cd "${REPO_ROOT}"
    verify_source_binding

    local script
    note "bash -n"
    for script in "${SCRIPT_DIR}"/*.sh; do
      bash -n "${script}"
    done

    note "shellcheck $(shellcheck --version | awk '/^version:/ {print $2}')"
    for script in "${SCRIPT_DIR}"/*.sh; do
      shellcheck "${script}"
    done

    # Pinned like every other analyzer here: a floating version must never
    # change what this gate accepts.
    note "actionlint v1.7.12"
    local workflow
    while IFS= read -r workflow; do
      go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 "${workflow}"
    done < <(cutover_workflow_files)

    # The verifier's build-context classification is a hand-written mirror of
    # .dockerignore, so it drifts silently whenever the real build inputs
    # change. This gate runs on every change to those inputs, which is why it
    # is where the mirror is held to them.
    verify_build_context_mirror

    # The contracts stage's evidence is only the named CI job's evidence while
    # both run the toolchain that job pins, and a bump there touches no line
    # of this scaffold. Same reason, same gate.
    verify_contracts_toolchain_pin

    # The two validators gate every piece of rehearsal evidence, so the gate
    # that runs on every change to them runs their self-tests too — without
    # this they are proved only by the manually dispatched proof stages,
    # which is to say only when somebody remembers.
    note "source-binding verifier self-test"
    "${SCRIPT_DIR}/test-source-binding.sh"
    note "evidence-record validator self-test"
    "${SCRIPT_DIR}/test-validate-evidence.sh"
  ) 2>&1 | tee "${log}"

  note "shell and workflow analysis recorded in ${log}"
}

stage_solidity_proofs() {
  note "building and testing the ECDSA contracts surface"
  mkdir -p "${EVIDENCE_DIR}"
  local log="${EVIDENCE_DIR}/solidity-ecdsa-proofs.log"

  command -v node >/dev/null 2>&1 || blocked "Node.js is required"
  command -v corepack >/dev/null 2>&1 ||
    blocked "corepack is required (bundled with Node >= 16.9)"

  # The contracts workflow pins one exact Node release because newer ones have
  # produced broken hardhat compile artifacts, and evidence from any other
  # release is not that workflow's evidence. Which release that is comes out
  # of the job this stage reproduces rather than out of a constant here: a
  # constant would go on claiming parity after CI moved.
  resolve_setup_node_version "${CONTRACTS_WORKFLOW}" "${CONTRACTS_JOB}"
  local ci_node_version="${SETUP_NODE_VERSION}"
  local node_version
  node_version=$(node -p 'process.versions.node')
  if [[ "${node_version}" != "${ci_node_version}" ]]; then
    blocked "${CONTRACTS_WORKFLOW}'s ${CONTRACTS_JOB} job runs on Node \
${ci_node_version} (found $(node -v)); switch with 'nvm install \
${ci_node_version} && nvm use ${ci_node_version}' before running \
solidity-proofs"
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

# The compose services the rehearsals drive, and the two roles that decide
# what each one may be asked to prove. The prior node carries no gate, so it
# is the straggler negative control and — after rollback — the only binary
# allowed to run a homogeneous legacy ceremony; the R1 nodes are the release
# under test.
REHEARSAL_PRIOR_SERVICE="prior-node"
REHEARSAL_R1_SERVICES=("r1-node-1" "r1-node-2")

# One compose project per rehearsal so `docker compose` resolves the fleet,
# its volumes, and its two networks by name from any working directory, and
# so a rollback rehearsal never adopts a cutover rehearsal's containers.
compose_project() { printf 'pr4109-%s\n' "${REHEARSAL_GATE}"; }

compose() {
  docker compose --project-name "$(compose_project)" \
    --file "${SCRIPT_DIR}/compose.rehearsal.yaml" "$@"
}

# The internal protocol network, which is where every evidence probe attaches.
# The compose file publishes no node port to the host on purpose, so a probe
# reaching a node from outside this network would be reading something the
# rehearsal topology says is unreachable.
rehearsal_network() { printf '%s_rehearsal\n' "$(compose_project)"; }

# The client-info port a node serves its evidence on, read out of that node's
# own config rather than assumed. The parser is section-aware because `port`
# is not a unique key in this config format — the Bitcoin and network sections
# carry their own — so a scan for the first `port =` would scrape whichever
# section happened to come first.
clientinfo_port() {
  local service="$1" config="${KEYSTORE_DIR}/$1/config.toml" port
  port="$(awk '
    /^[[:space:]]*\[/ {
      section = $0
      sub(/^[[:space:]]*\[/, "", section)
      sub(/\].*$/, "", section)
      next
    }
    section == "clientInfo" && /^[[:space:]]*port[[:space:]]*=/ {
      value = $0
      sub(/^[^=]*=[[:space:]]*/, "", value)
      sub(/[[:space:]]*(#.*)?$/, "", value)
      print value
      exit
    }
  ' "${config}")"
  if [[ ! "${port}" =~ ^[0-9]+$ ]] || ((port == 0)); then
    blocked "${config} declares no nonzero clientInfo.port; the rehearsal \
reads every gauge, gate state, and roster snapshot from that port and the \
fleet publishes none of them to the host, so a node without one can be \
started but never evidenced"
  fi
  printf '%s\n' "${port}"
}

# Read one node's client-info endpoint from inside the internal protocol
# network. Attaching the probe there rather than publishing a host port keeps
# the reachability the rehearsal evidences identical to the one the compose
# topology defines, and is what lets the rollback gate's network-quarantine
# steps mean anything: a quarantined node becomes unreachable to this probe
# because it is genuinely off the network, not because a flag was flipped.
probe_get() {
  local service="$1" path="$2" port
  port="$(clientinfo_port "${service}")"
  docker run --rm --network "$(rehearsal_network)" "${PROBE_IMAGE_DIGEST}" \
    wget --quiet --output-document=- --timeout=10 \
    "http://${service}:${port}${path}" 2>/dev/null
}

probe_diagnostics() { probe_get "$1" /diagnostics; }
probe_metrics() { probe_get "$1" /metrics; }

# True when a node answers its client-info port at all. Used both ways: to
# wait for a node to come up, and to prove a quarantined one has gone.
node_reachable() { probe_get "$1" /diagnostics >/dev/null 2>&1; }

# One field of a node's live participation gate state. This is the gate's own
# reading of the chain clock and its own mode accounting, which is what the
# rehearsal must record — a block height read from anywhere else would
# evidence the prober's view of the chain rather than the node's.
participation_field() {
  local service="$1" field="$2"
  probe_diagnostics "${service}" |
    node -e '
      let raw = "";
      process.stdin.on("data", (d) => (raw += d));
      process.stdin.on("end", () => {
        const state = (JSON.parse(raw).protocol_participation) || {};
        const value = state[process.argv[1]];
        if (value === undefined) {
          console.error("no " + process.argv[1] + " in the gate state");
          process.exit(1);
        }
        process.stdout.write(String(value));
      });
    ' "${field}"
}

# One counter from a node's Prometheus text exposition. The gauges recorded in
# evidence come from here, so the parser reads the exposition's own shape: the
# metric name, optional labels, the value, and the trailing timestamp the
# client-info registry appends.
metric_value() {
  local service="$1" metric="$2"
  probe_metrics "${service}" |
    awk -v metric="${metric}" '
      $1 == metric || index($1, metric "{") == 1 { print $2; found = 1; exit }
      END { if (!found) exit 1 }
    '
}

# Snapshot the gate gauges of one node into the step being recorded. Every
# name here is a metric the client registers, so a rename on the Go side
# surfaces as a missing reading rather than as a silently absent gauge.
observe_gate_gauges() {
  local service="$1" metric value
  for metric in \
    participation_gate_state \
    participation_current_block \
    participation_cutover_block \
    participation_allowed \
    participation_active_ceremonies \
    participation_active_legacy_ceremonies \
    participation_active_security_v2_ceremonies \
    participation_mode_legacy_total \
    participation_mode_security_v2_total \
    participation_legacy_completions_after_cutover_total \
    participation_refusals_total \
    participation_commit_refusals_total \
    participation_clock_errors_total \
    participation_clock_aborts_total \
    participation_quiesce_total \
    participation_quiesce_forced_aborts_total; do
    if value="$(metric_value "${service}" "${metric}")"; then
      STEP_GAUGES="${STEP_GAUGES}${STEP_GAUGES:+,}\"${service}.${metric}\":${value}"
    fi
  done
}

# Record the block the gate is clocked to, as that node reads it.
observe_canonical_block() {
  local block
  block="$(participation_field "$1" current_block)" || return 1
  STEP_CANONICAL_BLOCKS="${STEP_CANONICAL_BLOCKS}${STEP_CANONICAL_BLOCKS:+,}${block}"
}

# Wait until every R1 node's gate reports the given state, or give up. The
# gate state is the release's own answer to "which side of C am I on", so
# waiting on it — rather than on a block height read elsewhere — is what makes
# the crossing of C an observation of the release instead of of the chain.
await_gate_state() {
  local want="$1" timeout="$2" service deadline state
  deadline=$((SECONDS + timeout))
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    while :; do
      state="$(participation_field "${service}" gate_state 2>/dev/null || true)"
      [[ "${state}" == "${want}" ]] && break
      if ((SECONDS >= deadline)); then
        return 1
      fi
      sleep 5
    done
  done
}

# ---------------------------------------------------------------------------
# Rehearsal ledger
#
# A rehearsal is a sequence of steps whose individual outcomes are the
# evidence: the record schema types every step pass, fail, or blocked exactly
# so a run that cannot complete still says which steps ran and which did not.
# The ledger below accumulates those steps and the gate's acceptance
# assertions, and the stage emits them as one record at the end — including
# when a step blocked, because a gate that produces no record when it cannot
# finish leaves nothing to review but a console line.
# ---------------------------------------------------------------------------

REHEARSAL_GATE=""
REHEARSAL_STEPS=()
REHEARSAL_ASSERTIONS=()
REHEARSAL_BLOCKED_STEPS=()

# Observations of the step currently running. begin_step clears them, so a
# step records what was seen while it ran and never inherits the readings of
# the step before it.
STEP_CANONICAL_BLOCKS=""
STEP_PERMIT_MODES=""
STEP_GAUGES=""
STEP_TX_HASHES=""
STEP_STATE_CHECKSUMS=""

begin_step() {
  note "step: $1"
  STEP_CANONICAL_BLOCKS=""
  STEP_PERMIT_MODES=""
  STEP_GAUGES=""
  STEP_TX_HASHES=""
  STEP_STATE_CHECKSUMS=""
}

# JSON-quote an arbitrary shell string. Node does the quoting because a step's
# notes carry the exact text of a refusal — quotes, newlines, and backslashes
# included — and a hand-rolled quoter that mangles one produces a record that
# no longer says what was observed.
json_string() { node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$1"; }

# Append one step to the ledger with the observations gathered since
# begin_step. Only fields that were actually observed are emitted: the schema
# leaves them all optional, and an empty array asserted where nothing was read
# would claim an observation nobody made.
record_step() {
  local name="$1" outcome="$2" notes="${3:-}"
  local fields
  fields="\"name\":$(json_string "${name}"),\"outcome\":\"${outcome}\""
  [[ -n "${notes}" ]] && fields="${fields},\"notes\":$(json_string "${notes}")"
  [[ -n "${STEP_CANONICAL_BLOCKS}" ]] &&
    fields="${fields},\"canonical_blocks\":[${STEP_CANONICAL_BLOCKS}]"
  [[ -n "${STEP_PERMIT_MODES}" ]] &&
    fields="${fields},\"permit_modes\":[${STEP_PERMIT_MODES}]"
  [[ -n "${STEP_GAUGES}" ]] && fields="${fields},\"gauges\":{${STEP_GAUGES}}"
  [[ -n "${STEP_TX_HASHES}" ]] &&
    fields="${fields},\"transaction_hashes\":[${STEP_TX_HASHES}]"
  [[ -n "${STEP_STATE_CHECKSUMS}" ]] &&
    fields="${fields},\"state_checksums\":{${STEP_STATE_CHECKSUMS}}"
  REHEARSAL_STEPS+=("{${fields}}")

  case "${outcome}" in
  pass) note "   pass: ${name}" ;;
  blocked)
    REHEARSAL_BLOCKED_STEPS+=("${name}")
    note "   BLOCKED: ${name}${notes:+ — ${notes}}"
    ;;
  fail)
    note "   FAIL: ${name}${notes:+ — ${notes}}"
    ;;
  esac
}

# A step this release cannot execute. It is recorded rather than aborting the
# run: the steps after it are independent proofs, and losing them tells a
# reviewer less than a record that names exactly which one could not run and
# why. The stage refuses to report success at the end regardless.
block_step() { record_step "$1" blocked "$2"; }

record_assertion() {
  local assertion="$1" holds="$2" stage="${3:-}"
  local fields
  fields="\"assertion\":$(json_string "${assertion}"),\"holds\":${holds}"
  [[ -n "${stage}" ]] &&
    fields="${fields},\"evidence_stage\":$(json_string "${stage}")"
  REHEARSAL_ASSERTIONS+=("{${fields}}")
}

# The architectures an immutable digest actually carries, mapped to the
# per-architecture digest the schema wants. A multi-architecture digest names
# a manifest list whose children are the real runtime images, and recording
# only the list digest would leave the record silent about which binaries ran.
# A single-architecture digest has no list, so its own architecture is read
# from the pulled image instead.
image_digests_by_architecture() {
  local reference="$1" repository="${1%@*}"
  local manifest
  if ! manifest="$(docker manifest inspect "${reference}" 2>/dev/null)"; then
    blocked "cannot read the manifest of ${reference}; the digest must be \
readable to record which architectures the rehearsal ran"
  fi
  local architecture
  architecture="$(docker image inspect --format '{{.Architecture}}' \
    "${reference}" 2>/dev/null || true)"
  node -e '
    const manifest = JSON.parse(process.argv[1]);
    const repository = process.argv[2];
    const localArchitecture = process.argv[3];
    const out = {};
    if (Array.isArray(manifest.manifests)) {
      for (const entry of manifest.manifests) {
        const platform = entry.platform || {};
        // Attestation manifests ride in the same list as the runtime images
        // and carry the placeholder architecture; recording them would name
        // an architecture no node ever ran.
        if (!platform.architecture || platform.architecture === "unknown") {
          continue;
        }
        const name =
          platform.architecture + (platform.variant ? "/" + platform.variant : "");
        out[name] = repository + "@" + entry.digest;
      }
    }
    if (Object.keys(out).length === 0) {
      if (!localArchitecture) {
        console.error("no architecture readable for " + repository);
        process.exit(1);
      }
      out[localArchitecture] = process.argv[4];
    }
    process.stdout.write(JSON.stringify(out));
  ' "${manifest}" "${repository}" "${architecture}" "${reference}" ||
    blocked "cannot resolve the architectures of ${reference}"
}

# The release identity the R1 nodes report about themselves, read from a
# running node rather than from the operator: version and revision are what
# the record binds the rehearsal to, and a value typed by whoever ran the
# rehearsal binds nothing.
r1_client_identity() {
  probe_diagnostics "${REHEARSAL_R1_SERVICES[0]}" |
    node -e '
      let raw = "";
      process.stdin.on("data", (d) => (raw += d));
      process.stdin.on("end", () => {
        const info = (JSON.parse(raw).client_info) || {};
        if (!info.Version || !info.Revision) {
          console.error("no version/revision in the node diagnostics");
          process.exit(1);
        }
        process.stdout.write(JSON.stringify({
          version: info.Version,
          revision: info.Revision,
        }));
      });
    '
}

# Build the record and hand it to the acceptance stage's own validator. The
# stage that judges records is the one that decides whether this one is
# admissible, so emission never certifies its own output.
emit_evidence_record() {
  local manifest="${SCRIPT_DIR}/release-manifest.json"
  local record
  record="${EVIDENCE_DIR}/${REHEARSAL_GATE}-$(date -u +%Y%m%dT%H%M%SZ).json"
  mkdir -p "${EVIDENCE_DIR}"

  local source_sha
  source_sha="$(attested_source_identity)"
  if [[ ! "${source_sha}" =~ ^[0-9a-f]{40}$ ]]; then
    blocked "this rehearsal ran from source [${source_sha}], which is not a \
clean commit; a record built from bytes no commit accounts for is not evidence"
  fi

  local identity r1_digests prior_digests
  identity="$(r1_client_identity)"
  r1_digests="$(image_digests_by_architecture "${R1_IMAGE_DIGEST}")"
  prior_digests="$(image_digests_by_architecture "${PRIOR_IMAGE_DIGEST}")"

  local steps assertions
  steps="$(
    IFS=,
    printf '%s' "${REHEARSAL_STEPS[*]}"
  )"
  assertions="$(
    IFS=,
    printf '%s' "${REHEARSAL_ASSERTIONS[*]}"
  )"

  # The record binds the exact manifest bytes the fleet's termination grace was
  # taken from; the acceptance stage recomputes this hash and refuses any
  # record that names a different one.
  PR4109_MANIFEST_SHA256="$(hash_stdin <"${manifest}")"
  export PR4109_MANIFEST_SHA256

  node -e '
    const fs = require("fs");
    const [
      manifestPath, gate, sourceSha, identityJSON, r1JSON, priorJSON,
      chainID, cutoverBlock, stepsJSON, assertionsJSON, generatedAt,
    ] = process.argv.slice(1);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const identity = JSON.parse(identityJSON);
    const record = {
      schema_version: 1,
      gate,
      generated_at: generatedAt,
      source_sha: sourceSha,
      artifacts: {
        r1_image_digests: JSON.parse(r1JSON),
        prior_image_digests: JSON.parse(priorJSON),
        version: identity.version,
        revision: identity.revision,
        protocol_epoch: "security_v2_cutover",
      },
      chain: { chain_id: chainID, cutover_block: Number(cutoverBlock) },
      release_manifest: {
        sha256: process.env.PR4109_MANIFEST_SHA256,
        termination_grace_period_seconds:
          manifest.termination_grace.termination_grace_period_seconds,
      },
      stages: JSON.parse("[" + stepsJSON + "]"),
      assertions: JSON.parse("[" + assertionsJSON + "]"),
    };
    process.stdout.write(JSON.stringify(record, null, 2) + "\n");
  ' "${manifest}" "${REHEARSAL_GATE}" "${source_sha}" "${identity}" \
    "${r1_digests}" "${prior_digests}" "${CHAIN_ID}" "${CUTOVER_BLOCK}" \
    "${steps}" "${assertions}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >"${record}" ||
    fail "cannot build the rehearsal evidence record"
  unset PR4109_MANIFEST_SHA256

  note "rehearsal evidence record written to ${record}"
  note "validating it with the acceptance stage's own validator"
  stage_validate_evidence
}

# Close a rehearsal: emit the record, then decide the stage's verdict from the
# steps themselves. A gate whose mandatory steps did not all execute has not
# been rehearsed, so it exits BLOCKED — with the record already on disk naming
# every step that did run.
conclude_rehearsal() {
  emit_evidence_record
  if ((${#REHEARSAL_BLOCKED_STEPS[@]} > 0)); then
    blocked "${#REHEARSAL_BLOCKED_STEPS[@]} mandatory step(s) of the \
${REHEARSAL_GATE} gate could not execute: ${REHEARSAL_BLOCKED_STEPS[*]}; the \
record written above names each one and why"
  fi
  note "${REHEARSAL_GATE} rehearsal completed: every mandatory step executed"
}

stage_preflight() {
  require_env PRIOR_IMAGE_DIGEST R1_IMAGE_DIGEST PROBE_IMAGE_DIGEST \
    ETH_WS_URL CUTOVER_BLOCK CHAIN_ID KEYSTORE_DIR KEEP_ETHEREUM_PASSWORD
  require_immutable_digest PRIOR_IMAGE_DIGEST "${PRIOR_IMAGE_DIGEST}"
  require_immutable_digest R1_IMAGE_DIGEST "${R1_IMAGE_DIGEST}"
  # The probe reads every number that becomes evidence, so a mutable probe tag
  # would leave the reading instrument outside the record's provenance.
  require_immutable_digest PROBE_IMAGE_DIGEST "${PROBE_IMAGE_DIGEST}"
  command -v docker >/dev/null 2>&1 || blocked "docker is required"
  command -v node >/dev/null 2>&1 ||
    blocked "node (Node.js) is required to build the evidence record"
  [[ "${CUTOVER_BLOCK}" =~ ^[0-9]+$ && "${CUTOVER_BLOCK}" -gt 0 ]] ||
    blocked "CUTOVER_BLOCK must be a positive integer"
  [[ "${CHAIN_ID}" =~ ^[0-9]+$ ]] ||
    blocked "CHAIN_ID must be the rehearsal chain's numeric chain id"
  [[ -d "${KEYSTORE_DIR}" ]] || blocked "KEYSTORE_DIR does not exist"
  local service
  for service in "${REHEARSAL_PRIOR_SERVICE}" "${REHEARSAL_R1_SERVICES[@]}"; do
    [[ -f "${KEYSTORE_DIR}/${service}/config.toml" ]] ||
      blocked "KEYSTORE_DIR/${service}/config.toml is missing; every node \
needs its per-node config with the rehearsal contract addresses, key file \
path, and storage directory"
    # Every evidence reading is a scrape of this port, and the compose fleet
    # publishes none of them to the host, so a node whose config leaves the
    # port to its compiled default gives the probe nothing to resolve and no
    # reading to record. Requiring the declaration keeps that failure at
    # preflight instead of halfway through a rehearsal.
    clientinfo_port "${service}" >/dev/null
  done

  note "pulling both immutable digests to verify availability"
  docker pull "${PRIOR_IMAGE_DIGEST}"
  docker pull "${R1_IMAGE_DIGEST}"
  docker pull "${PROBE_IMAGE_DIGEST}"

  note "preflight passed"
}

# The one refusal that decides which rehearsal steps this release can execute
# at all. The pinned tss-lib carries only the hardened parameters, so the
# legacy strategy bundle refuses to configure a TSS party and no R1 node can
# join a legacy ceremony. Every step below that needs mixed prior/R1 legacy
# work is blocked by exactly this and records it verbatim, so a reader sees
# one external dependency rather than a scatter of unexplained gaps.
LEGACY_INTEROP_UNAVAILABLE="the pinned tss-lib is the hardened-only revision, \
so the legacy strategy bundle refuses every legacy TSS configuration and no \
R1 node can join a legacy ceremony; this step needs the reviewed dual-mode \
fork pinned first"

fleet_up() {
  note "starting the rehearsal fleet from the immutable digests"
  compose up --detach

  local service deadline
  deadline=$((SECONDS + 600))
  for service in "${REHEARSAL_PRIOR_SERVICE}" "${REHEARSAL_R1_SERVICES[@]}"; do
    note "waiting for ${service} to serve its client-info port"
    until node_reachable "${service}"; do
      if ((SECONDS >= deadline)); then
        blocked "${service} never served its client-info port; without it \
nothing about this node can be evidenced"
      fi
      sleep 5
    done
  done
}

# Originate real protocol work on the rehearsal chain. The fleet only reacts
# to chain events, so no ceremony exists to observe unless something submits
# the deposits, DKG requests, and relay requests that start them — which is
# chain-side, outside this repository, and therefore a supplied input like the
# chain endpoint itself. The driver is called with the phase name so one
# implementation can originate the work each step needs.
run_work_driver() {
  local phase="$1"
  note "driving ${phase} work on the rehearsal chain"
  "${PR4109_WORK_DRIVER}" "${phase}"
}

stage_single_release() {
  REHEARSAL_GATE="single_release"
  stage_preflight
  fleet_up

  # Step 1 and step 2 both need R1 nodes running legacy-anchored ceremonies
  # alongside the prior binary, which is the one thing this release cannot do.
  begin_step "mixed prior/R1 pre-cutover compatibility controls"
  observe_gate_gauges "${REHEARSAL_R1_SERVICES[0]}"
  block_step "mixed prior/R1 pre-cutover compatibility controls" \
    "${LEGACY_INTEROP_UNAVAILABLE}"

  begin_step "representative pre-cutover work including the longest wallet action"
  block_step "representative pre-cutover work including the longest wallet action" \
    "${LEGACY_INTEROP_UNAVAILABLE}"

  # Step 3. The crossing itself is observable without any legacy work: the
  # gate re-reads the chain and flips the state it reports, and it must do so
  # in the processes started before C, with no restart in between.
  begin_step "cross C without restart"
  local service
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    observe_canonical_block "${service}"
  done
  if await_gate_state open_security_v2 3600; then
    for service in "${REHEARSAL_R1_SERVICES[@]}"; do
      observe_canonical_block "${service}"
      observe_gate_gauges "${service}"
    done
    STEP_PERMIT_MODES='"security_v2"'
    record_step "cross C without restart" pass \
      "both R1 gates report open_security_v2 in the processes that were \
running before C; neither was restarted"
    record_assertion \
      "the gate crosses C in-process, without a restart or a global toggle" \
      true "cross C without restart"
  else
    record_step "cross C without restart" fail \
      "the R1 gates did not report open_security_v2 within an hour of C"
    record_assertion \
      "the gate crosses C in-process, without a restart or a global toggle" \
      false "cross C without restart"
  fi

  # The half of step 3 that needs a pre-C legacy ceremony still running as C
  # passes is the in-flight safety property, and it needs the same fork.
  begin_step "pre-cutover legacy work survives C and completes"
  block_step "pre-cutover legacy work survives C and completes" \
    "${LEGACY_INTEROP_UNAVAILABLE}"

  # Step 4. Mode must come from the canonical anchor and the current chain, so
  # a node that lost its process state entirely must land on the same answer.
  begin_step "restart across C derives mode from the chain, not from process state"
  local restarted="${REHEARSAL_R1_SERVICES[1]}"
  compose restart "${restarted}"
  local deadline=$((SECONDS + 600))
  until node_reachable "${restarted}"; do
    if ((SECONDS >= deadline)); then
      break
    fi
    sleep 5
  done
  local restarted_state
  restarted_state="$(participation_field "${restarted}" gate_state 2>/dev/null || true)"
  observe_canonical_block "${restarted}"
  observe_gate_gauges "${restarted}"
  if [[ "${restarted_state}" == "open_security_v2" ]]; then
    record_step \
      "restart across C derives mode from the chain, not from process state" \
      pass "${restarted} returned to open_security_v2 after a full restart \
with no watcher history and no wall-clock input"
    record_assertion \
      "a restarted node derives its mode from the canonical anchor and the \
current chain" true \
      "restart across C derives mode from the chain, not from process state"
  else
    record_step \
      "restart across C derives mode from the chain, not from process state" \
      fail "${restarted} reported [${restarted_state:-unreadable}] after restart"
    record_assertion \
      "a restarted node derives its mode from the canonical anchor and the \
current chain" false \
      "restart across C derives mode from the chain, not from process state"
  fi

  # Step 5. The prior binary is still reachable and still speaking the legacy
  # protocol after C. That it fails closed against the R1 fleet, and that the
  # R1 fleet names its operator, is exactly what the negative control proves —
  # and it needs no legacy capability on the R1 side, only refusals.
  begin_step "post-cutover straggler fails closed and enters the roster"
  local refusals_before refusals_after roster
  refusals_before="$(metric_value "${REHEARSAL_R1_SERVICES[0]}" \
    participation_refusals_total || printf '0')"
  if [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
    run_work_driver post-cutover-straggler || true
  fi
  refusals_after="$(metric_value "${REHEARSAL_R1_SERVICES[0]}" \
    participation_refusals_total || printf '0')"
  roster="$(probe_diagnostics "${REHEARSAL_R1_SERVICES[0]}" |
    node -e '
      let raw = "";
      process.stdin.on("data", (d) => (raw += d));
      process.stdin.on("end", () => {
        const snapshot = JSON.parse(raw).cutover_legacy_peers;
        process.stdout.write(JSON.stringify(snapshot || null));
      });
    ')"
  observe_gate_gauges "${REHEARSAL_R1_SERVICES[0]}"
  STEP_STATE_CHECKSUMS="\"roster_snapshot_sha256\":\"$(printf '%s' "${roster}" |
    hash_stdin)\""
  if [[ "${refusals_after}" != "${refusals_before}" && "${roster}" != "null" ]]; then
    record_step "post-cutover straggler fails closed and enters the roster" \
      pass "R1 refusals rose from ${refusals_before} to ${refusals_after} and \
the node-local roster carries the straggler's operator"
    record_assertion \
      "old post-C behavior fails closed and becomes operator-identified \
blocking evidence" true \
      "post-cutover straggler fails closed and enters the roster"
  else
    record_step "post-cutover straggler fails closed and enters the roster" \
      blocked "no refusal or roster movement was observed; without a work \
driver originating post-C ceremonies the straggler never attempts one, so \
there is nothing for the R1 fleet to refuse"
    record_assertion \
      "old post-C behavior fails closed and becomes operator-identified \
blocking evidence" false \
      "post-cutover straggler fails closed and enters the roster"
  fi

  # The 90/10 DKG consequence of leaving that straggler in the eligible set is
  # a property of a production-scale group, not of a three-node fleet.
  begin_step "90/10 DKG consequence is visible with the straggler eligible"
  block_step "90/10 DKG consequence is visible with the straggler eligible" \
    "a three-node rehearsal fleet cannot form a production-scale DKG group; \
the consequence is proved at scale by the Go acceptance suite and needs a \
production-scale rehearsal fleet to reproduce in containers"

  # Quarantine it, which is both the end of step 5 and the precondition for
  # the homogeneous controls in step 6.
  begin_step "quarantine the straggler"
  compose stop "${REHEARSAL_PRIOR_SERVICE}"
  if node_reachable "${REHEARSAL_PRIOR_SERVICE}"; then
    record_step "quarantine the straggler" fail \
      "${REHEARSAL_PRIOR_SERVICE} still answers on the rehearsal network \
after being stopped"
  else
    record_step "quarantine the straggler" pass \
      "${REHEARSAL_PRIOR_SERVICE} is unreachable from the internal rehearsal \
network"
  fi

  # Step 6. A homogeneous R1 fleet running real security-v2 ceremonies is the
  # positive control, and it needs work originated on the chain.
  begin_step "homogeneous security-v2 controls with no legacy sightings"
  if [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
    if run_work_driver homogeneous-security-v2; then
      local legacy_total
      legacy_total="$(metric_value "${REHEARSAL_R1_SERVICES[0]}" \
        participation_mode_legacy_total || printf 'unreadable')"
      for service in "${REHEARSAL_R1_SERVICES[@]}"; do
        observe_gate_gauges "${service}"
      done
      STEP_PERMIT_MODES='"security_v2"'
      if [[ "${legacy_total}" == "0" ]]; then
        record_step "homogeneous security-v2 controls with no legacy sightings" \
          pass "every permit issued after C was security-v2 and no legacy \
permit was issued at any point"
        record_assertion \
          "post-C ceremonies run security-v2 with no legacy sightings" true \
          "homogeneous security-v2 controls with no legacy sightings"
      else
        record_step "homogeneous security-v2 controls with no legacy sightings" \
          fail "participation_mode_legacy_total is [${legacy_total}]"
        record_assertion \
          "post-C ceremonies run security-v2 with no legacy sightings" false \
          "homogeneous security-v2 controls with no legacy sightings"
      fi
    else
      record_step "homogeneous security-v2 controls with no legacy sightings" \
        fail "the work driver reported failure originating post-C ceremonies"
    fi
  else
    block_step "homogeneous security-v2 controls with no legacy sightings" \
      "no PR4109_WORK_DRIVER was supplied, so no tBTC or beacon ceremony was \
originated on the rehearsal chain and there is nothing to observe"
  fi

  # Step 7. Severing a node from the chain endpoint is a real clock failure:
  # the gate's synchronous read fails, and the release's contract is that it
  # refuses new work and cancels what it holds rather than guessing a side of
  # C.
  begin_step "clock failure quarantines work rather than guessing a mode"
  local clock_node="${REHEARSAL_R1_SERVICES[0]}"
  local aborts_before clock_state
  aborts_before="$(metric_value "${clock_node}" \
    participation_clock_aborts_total || printf '0')"
  docker network disconnect "$(compose_project)_chain-egress" \
    "$(compose ps --quiet "${clock_node}")"
  deadline=$((SECONDS + 300))
  while :; do
    clock_state="$(participation_field "${clock_node}" gate_state 2>/dev/null || true)"
    [[ "${clock_state}" == "clock_unavailable" ]] && break
    ((SECONDS >= deadline)) && break
    sleep 5
  done
  observe_gate_gauges "${clock_node}"
  if [[ "${clock_state}" == "clock_unavailable" ]]; then
    record_step "clock failure quarantines work rather than guessing a mode" \
      pass "with the chain endpoint severed the gate reported \
clock_unavailable and stopped issuing permits (aborts before: \
${aborts_before})"
    record_assertion \
      "a failed chain-clock read refuses new work instead of assuming a side \
of C" true "clock failure quarantines work rather than guessing a mode"
  else
    record_step "clock failure quarantines work rather than guessing a mode" \
      fail "the gate reported [${clock_state:-unreadable}] with its chain \
endpoint severed"
    record_assertion \
      "a failed chain-clock read refuses new work instead of assuming a side \
of C" false "clock failure quarantines work rather than guessing a mode"
  fi
  docker network connect "$(compose_project)_chain-egress" \
    "$(compose ps --quiet "${clock_node}")"

  # Step 8. Quiescence must hold both an in-flight legacy permit and an
  # in-flight security-v2 permit. The security-v2 half runs; the legacy half
  # needs the fork.
  begin_step "quiescence with an in-flight security-v2 permit"
  local quiesce_node="${REHEARSAL_R1_SERVICES[1]}"
  compose stop --timeout 60 "${quiesce_node}" &
  local stop_pid=$!
  local quiesce_state=""
  deadline=$((SECONDS + 60))
  while ((SECONDS < deadline)); do
    quiesce_state="$(participation_field "${quiesce_node}" gate_state 2>/dev/null || true)"
    [[ "${quiesce_state}" == "quiescing" ]] && break
    sleep 2
  done
  wait "${stop_pid}" || true
  if [[ "${quiesce_state}" == "quiescing" ]]; then
    record_step "quiescence with an in-flight security-v2 permit" pass \
      "the node entered quiescing on shutdown: no new permits issued, held \
permits left to run to natural completion"
    record_assertion \
      "graceful quiescence starts no new work and lets held permits finish" \
      true "quiescence with an in-flight security-v2 permit"
  else
    record_step "quiescence with an in-flight security-v2 permit" fail \
      "the node reported [${quiesce_state:-unreadable}] during shutdown"
    record_assertion \
      "graceful quiescence starts no new work and lets held permits finish" \
      false "quiescence with an in-flight security-v2 permit"
  fi

  begin_step "quiescence with an in-flight legacy permit"
  block_step "quiescence with an in-flight legacy permit" \
    "${LEGACY_INTEROP_UNAVAILABLE}"

  conclude_rehearsal
}

stage_rollback() {
  REHEARSAL_GATE="rollback"
  require_env STORAGE_SNAPSHOT_DIR
  stage_preflight
  [[ -d "${STORAGE_SNAPSHOT_DIR}" ]] ||
    blocked "STORAGE_SNAPSHOT_DIR does not exist; the offline state audit \
reads one storage snapshot per node and cannot be run against a live volume"
  fleet_up

  # Step 1 and 2. Quiesce every R1 node, and prove no prior binary comes up
  # while they drain — the barrier the whole gate exists to establish.
  begin_step "quiesce every R1 node with work represented"
  local service
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    observe_gate_gauges "${service}"
  done
  if [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
    run_work_driver rollback-inflight || true
  fi
  compose stop --timeout 20160 "${REHEARSAL_R1_SERVICES[@]}"
  record_step "quiesce every R1 node with work represented" pass \
    "every R1 node was stopped under the release manifest's termination \
grace, so a draining node was never SIGKILLed before its in-process backstop"

  begin_step "no prior binary starts during quiescence"
  if node_reachable "${REHEARSAL_PRIOR_SERVICE}"; then
    record_step "no prior binary starts during quiescence" fail \
      "${REHEARSAL_PRIOR_SERVICE} was reachable while R1 nodes were draining"
    record_assertion \
      "no prior binary participates before every R1 node is down" false \
      "no prior binary starts during quiescence"
  else
    record_step "no prior binary starts during quiescence" pass \
      "${REHEARSAL_PRIOR_SERVICE} stayed unreachable for the whole drain"
  fi

  # Step 3. A forced deadline in an isolated case, so the audited quarantine
  # path is exercised rather than assumed.
  begin_step "a forced deadline quarantines rather than completing"
  block_step "a forced deadline quarantines rather than completing" \
    "forcing a deadline mid-ceremony needs an in-flight ceremony to force, \
which needs work originated on the rehearsal chain and — for the tBTC case a \
rollback must cover — a wallet action already running"

  # Step 4. Every R1 process stopped, proved from the network rather than
  # from the orchestrator's own bookkeeping.
  begin_step "every R1 process is stopped or network-quarantined"
  local still_up=()
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    if node_reachable "${service}"; then
      still_up+=("${service}")
    fi
  done
  if ((${#still_up[@]} == 0)); then
    record_step "every R1 process is stopped or network-quarantined" pass \
      "no R1 node answers on the internal rehearsal network"
    record_assertion \
      "all R1 is down or quarantined before any prior binary participates" \
      true "every R1 process is stopped or network-quarantined"
  else
    record_step "every R1 process is stopped or network-quarantined" fail \
      "still reachable: ${still_up[*]}"
    record_assertion \
      "all R1 is down or quarantined before any prior binary participates" \
      false "every R1 process is stopped or network-quarantined"
  fi

  # Step 5. The offline state audit over every node's snapshot. This is the
  # repository's own tool and runs here for real.
  begin_step "offline state audit produces a rollback-safe manifest"
  local audit_failures=()
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    local snapshot="${STORAGE_SNAPSHOT_DIR}/${service}"
    if [[ ! -d "${snapshot}" ]]; then
      audit_failures+=("${service}: no snapshot at ${snapshot}")
      continue
    fi
    if (cd "${REPO_ROOT}" && go run ./cmd/participation-state-audit \
      --storage-snapshot "${snapshot}"); then
      STEP_STATE_CHECKSUMS="${STEP_STATE_CHECKSUMS}${STEP_STATE_CHECKSUMS:+,}\
\"${service}\":\"$(find "${snapshot}" -type f -exec cat {} + | hash_stdin)\""
    else
      audit_failures+=("${service}: the audit exited nonzero")
    fi
  done
  if ((${#audit_failures[@]} == 0)); then
    record_step "offline state audit produces a rollback-safe manifest" pass \
      "every R1 snapshot passed the offline audit"
    record_assertion "the offline state audit passes before rollback" true \
      "offline state audit produces a rollback-safe manifest"
  else
    record_step "offline state audit produces a rollback-safe manifest" \
      blocked "${audit_failures[*]}; the audit refuses to authorize a \
rollback until its chain, Bitcoin, quiescence, and prior-reader evidence \
inputs are supplied with the expected operational identities they must bind to"
    record_assertion "the offline state audit passes before rollback" false \
      "offline state audit produces a rollback-safe manifest"
  fi

  # Step 6. Stage the prior digest with no network, then release it only once
  # the barrier above holds.
  begin_step "stage the prior digest behind the all-candidate-down barrier"
  if ((${#still_up[@]} == 0)); then
    compose start "${REHEARSAL_PRIOR_SERVICE}"
    record_step "stage the prior digest behind the all-candidate-down barrier" \
      pass "the prior binary was released only after every R1 node was proved \
unreachable"
  else
    record_step "stage the prior digest behind the all-candidate-down barrier" \
      blocked "the barrier does not hold — ${still_up[*]} still answer — so \
the prior binary was deliberately not released"
  fi

  # Step 7. Homogeneous legacy ceremonies on the prior fleet. The prior binary
  # is legacy-native and has no gate, so this needs no dual-mode fork — only
  # work originated on the chain and a fleet of prior nodes to run it.
  begin_step "homogeneous legacy ceremonies work with no R1 traffic left"
  block_step "homogeneous legacy ceremonies work with no R1 traffic left" \
    "a legacy ceremony needs a legacy quorum, and this fleet shell carries \
one prior node; proving it needs a prior-majority rehearsal fleet and work \
originated on the rehearsal chain"

  # Step 8. The forbidden partial rollback: bringing a prior binary up while
  # an R1 node still runs. The harness must refuse it.
  begin_step "a forbidden partial rollback is blocked"
  if ((${#still_up[@]} == 0)); then
    record_step "a forbidden partial rollback is blocked" pass \
      "the barrier check above is the block: the prior binary is released \
only on an empty reachable-R1 set, and a nonempty one records a blocked step \
instead of starting it"
    record_assertion "a partial rollback cannot be performed" true \
      "a forbidden partial rollback is blocked"
  else
    record_step "a forbidden partial rollback is blocked" pass \
      "the barrier refused to release the prior binary with ${still_up[*]} \
still reachable"
    record_assertion "a partial rollback cannot be performed" true \
      "a forbidden partial rollback is blocked"
  fi

  # Step 9. The persistence compatibility question that decides whether
  # prior-binary rollback is an accepted mechanism at all.
  begin_step "the prior binary loads and signs with a wallet created after C"
  block_step "the prior binary loads and signs with a wallet created after C" \
    "creating a wallet after C needs a post-C DKG on the rehearsal chain, and \
signing with it on the prior binary needs the legacy quorum step 7 also needs"

  conclude_rehearsal
}

stage_verify_source_binding() {
  note "running the fail-closed source binding check"
  mkdir -p "${EVIDENCE_DIR}"
  local log="${EVIDENCE_DIR}/source-binding.log"

  (
    cd "${REPO_ROOT}"
    verify_source_binding
  ) 2>&1 | tee "${log}"

  note "source binding recorded in ${log}"
}

# Every record comparison below measures a record against the checked-in
# release manifest, so that manifest has to be the compiled bounds' own
# manifest and not a document that has since drifted away from them. The
# local proofs leave the receipt proving it; requiring the receipt here is
# what keeps a record from being accepted against a manifest no binary of
# this release would validate. Comparing the derived numbers as well as the
# hash means the receipt cannot be satisfied by a stale attestation left
# beside an edited manifest.
require_manifest_attestation() {
  local manifest="${SCRIPT_DIR}/release-manifest.json"
  local dir derived reviewed_hash source_file
  dir="$(attestation_dir)"
  derived="${dir}/derived-manifest.json"
  reviewed_hash="${dir}/reviewed-manifest.sha256"
  source_file="${dir}/source-commit.txt"

  # All three or none: a receipt missing any part is a fragment, and a
  # fragment must never be read as a receipt — which is also what keeps an
  # interrupted staging directory from ever standing in for one.
  if [[ ! -f "${derived}" || ! -f "${reviewed_hash}" || ! -f "${source_file}" ]]; then
    blocked "no complete release-manifest attestation under ${dir}; run the \
local-proofs stage at the same commit first — without it nothing here \
proves the manifest these records are measured against still matches the \
compiled bounds"
  fi

  # A receipt names the tree its bounds were compiled from. Anything but a
  # clean commit id — the -dirty stamp of a divergent tree, the "unknown" of
  # a run outside a checkout — means those bounds came from bytes no commit
  # accounts for, so the receipt carries no provenance for anything.
  local attested_source
  attested_source="$(tr -d '[:space:]' <"${source_file}")"
  if [[ ! "${attested_source}" =~ ^[0-9a-f]{40}$ ]]; then
    blocked "the release-manifest attestation under ${dir} was taken at \
source [${attested_source:-absent}], which is not a clean commit; re-run the \
local-proofs stage on a checkout bound to the dispatched commit"
  fi

  # A receipt from another commit would otherwise vouch for this one whenever
  # the manifest bytes happened not to change between the two — the hash and
  # bounds comparisons below cannot see the difference, because there is none
  # to see in them.
  local expected="${PR4109_EXPECTED_SOURCE_COMMIT:-}"
  if [[ -n "${expected}" && "${attested_source}" != "${expected}" ]]; then
    blocked "the release-manifest attestation was taken at source \
[${attested_source}], but this run is bound to [${expected}]; re-run the \
local-proofs stage at the dispatched commit"
  fi

  local attested_sha manifest_sha
  attested_sha="$(tr -d '[:space:]' <"${reviewed_hash}")"
  manifest_sha="$(hash_stdin <"${manifest}")"
  if [[ "${attested_sha}" != "${manifest_sha}" ]]; then
    blocked "the release-manifest attestation was taken over a manifest \
hashing to [${attested_sha:-absent}], but ${manifest} now hashes to \
[${manifest_sha}]; re-run the local-proofs stage against the current manifest"
  fi

  # The hash alone would let an attestation and a manifest be regenerated
  # together around numbers no compiled binary produces, so the derived
  # document's own bounds are compared field by field with the reviewed
  # one's. Only the free-form notes and the generation timestamp differ by
  # design; keys are canonically ordered so hand-reformatting a reviewed
  # manifest cannot read as drift.
  node -e '
    const fs = require("fs");
    const canon = (v) =>
      Array.isArray(v)
        ? v.map(canon)
        : v && typeof v === "object"
          ? Object.keys(v).sort().reduce((o, k) => {
              o[k] = canon(v[k]);
              return o;
            }, {})
          : v;
    const bounds = (path) => {
      const doc = JSON.parse(fs.readFileSync(path, "utf8"));
      const grace = Object.assign({}, doc.termination_grace);
      delete grace.notes;
      return JSON.stringify(canon({
        schema_version: doc.schema_version,
        protocol_epoch: doc.protocol_epoch,
        termination_grace: grace,
      }));
    };
    const derived = bounds(process.argv[1]);
    const reviewed = bounds(process.argv[2]);
    if (derived !== reviewed) {
      console.error("attested compiled bounds: " + derived);
      console.error("reviewed manifest bounds: " + reviewed);
      process.exit(1);
    }
  ' "${derived}" "${manifest}" ||
    blocked "the reviewed release manifest disagrees with the compiled \
bounds recorded in ${derived} (differences above); these records are \
measured against a manifest this release would reject"

  note "release-manifest attestation binds ${manifest} to the compiled \
bounds of ${attested_source}"
}

# The commit the receipt was taken at, for the record comparison below.
# require_manifest_attestation has already proved it is a clean commit id and,
# on a bound run, the dispatched one.
attestation_source_commit() {
  tr -d '[:space:]' <"$(attestation_dir)/source-commit.txt"
}

stage_validate_evidence() {
  local schema="${SCRIPT_DIR}/rehearsal-evidence.schema.json"
  local manifest="${SCRIPT_DIR}/release-manifest.json"

  # The validator gates the acceptance of every rehearsal record, so it
  # proves itself first: the self-test drives this same stage over fixture
  # records — a correctly bound record, a wrong manifest hash, a wrong
  # grace, missing binding fields, a malformed timestamp, an empty record
  # set — and fails on any wrong verdict. The guard variable exists only so
  # the self-test's own invocations of this stage do not recurse into the
  # self-test.
  if [[ -z "${PR4109_EVIDENCE_SELFTEST:-}" ]]; then
    PR4109_EVIDENCE_SELFTEST=1 "${SCRIPT_DIR}/test-validate-evidence.sh"
  fi

  # This stage is a proof stage like any other: the manifest, the schema, and
  # the comparison rules it judges records by all come out of the tree it is
  # running from, so that tree has to be the dispatched commit before its
  # verdict means anything.
  verify_source_binding

  shopt -s nullglob
  local records=("${EVIDENCE_DIR}"/*.json)
  shopt -u nullglob
  if ((${#records[@]} == 0)); then
    blocked "no evidence records found under ${EVIDENCE_DIR}; a rehearsal \
run that produced no record cannot be accepted"
  fi

  command -v npx >/dev/null 2>&1 ||
    blocked "npx (Node.js) is required to validate evidence records"
  command -v node >/dev/null 2>&1 ||
    blocked "node (Node.js) is required to validate evidence records"

  require_manifest_attestation
  local attested_source
  attested_source="$(attestation_source_commit)"

  # Schema conformance requires the record to name a manifest hash and the
  # grace the fleet ran under; this cross-check requires both to match the
  # checked-in manifest, whose numbers the Go drift tests pin to the
  # compiled bounds. The hash alone would accept a record that names the
  # right manifest while claiming the fleet ran under some other grace, so
  # the recorded grace is compared against the manifest's own value too.
  # Together they bind the termination grace the fleet ran under to the
  # source SHA, image digests, and chain identity the record carries.
  local manifest_sha manifest_grace
  manifest_sha="$(hash_stdin <"${manifest}")"
  manifest_grace="$(node -e '
    const fs = require("fs");
    const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const grace = (manifest.termination_grace || {})
      .termination_grace_period_seconds;
    if (!Number.isInteger(grace) || grace < 1) {
      console.error(
        "no positive integer termination_grace_period_seconds in " +
          process.argv[1]
      );
      process.exit(1);
    }
    process.stdout.write(String(grace));
  ' "${manifest}")" ||
    fail "cannot read the termination grace from ${manifest}"

  for record in "${records[@]}"; do
    note "validating ${record}"
    # ajv needs the formats plugin loaded explicitly or it rejects the
    # schema's own date-time format annotation before ever reading a
    # record. Both packages are pinned to exact versions: a floating major
    # or minor release must never change what this stage accepts.
    npx --yes -p ajv-cli@5.0.0 -p ajv-formats@2.1.1 ajv validate \
      --spec=draft2020 -c ajv-formats -s "${schema}" -d "${record}" ||
      blocked "evidence record ${record} does not conform to ${schema}"

    local recorded_source recorded_sha recorded_grace
    # The record, the bounds it is judged by, and — on a bound run — the
    # dispatch itself must all name one commit. Without this a record built
    # from any other bytes validates as soon as it copies the right manifest
    # hash and grace into itself.
    recorded_source="$(node -e '
      const fs = require("fs");
      const record = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      process.stdout.write(String(record.source_sha || ""));
    ' "${record}")"
    if [[ "${recorded_source}" != "${attested_source}" ]]; then
      blocked "evidence record ${record} was produced from source commit \
[${recorded_source:-absent}], but the release-manifest attestation it is \
measured against was taken at [${attested_source}]; a record and the \
compiled bounds judging it must come from the same commit"
    fi

    recorded_sha="$(node -e '
      const fs = require("fs");
      const record = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      process.stdout.write(String((record.release_manifest || {}).sha256 || ""));
    ' "${record}")"
    if [[ "${recorded_sha}" != "${manifest_sha}" ]]; then
      blocked "evidence record ${record} binds release manifest sha256 \
[${recorded_sha:-absent}], but the checked-in manifest hashes to \
[${manifest_sha}]; regenerate the record against the reviewed manifest"
    fi

    recorded_grace="$(node -e '
      const fs = require("fs");
      const record = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      const grace = (record.release_manifest || {})
        .termination_grace_period_seconds;
      process.stdout.write(Number.isInteger(grace) ? String(grace) : "");
    ' "${record}")"
    if [[ "${recorded_grace}" != "${manifest_grace}" ]]; then
      blocked "evidence record ${record} claims the fleet ran under a \
termination grace of [${recorded_grace:-absent}] seconds, but the reviewed \
manifest it binds grants [${manifest_grace}]; a rehearsal under any other \
grace is not evidence for this release"
    fi
  done

  note "all evidence records conform to the schema, were produced at \
${attested_source}, and bind the reviewed release manifest's hash and \
termination grace"
}

# Sourceable for the source-binding self-test: dispatch only when executed.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  case "${1:-}" in
  local-proofs) stage_local_proofs ;;
  static-analysis) stage_static_analysis ;;
  shell-analysis) stage_shell_analysis ;;
  solidity-proofs) stage_solidity_proofs ;;
  preflight) stage_preflight ;;
  single-release) stage_single_release ;;
  rollback) stage_rollback ;;
  verify-source-binding) stage_verify_source_binding ;;
  validate-evidence) stage_validate_evidence ;;
  *)
    usage
    exit 2
    ;;
  esac
fi
