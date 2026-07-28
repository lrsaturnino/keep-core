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
#
# Rollback only — the audit inputs no storage snapshot can supply. Every one
# is required before the offline state audit can authorize anything, and a
# missing one blocks the barrier that releases the prior binary rather than
# being skipped:
#
#   PR4109_CHAIN_RECONCILIATION_EVIDENCE
#                        Ethereum reconciliation record: wallet/group
#                        registration and DKG settlement for every group
#   PR4109_BITCOIN_RECONCILIATION_EVIDENCE
#                        Bitcoin reconciliation record: every pending
#                        transaction and whether it is signed, broadcast,
#                        mined, or absent
#   PR4109_QUIESCENCE_REPORT_DIR
#                        directory holding <service>.json per R1 service: the
#                        permits that node held at quiescence and how each
#                        one ended. Per node by nature — one shared report
#                        would bind every audit to one node's drain
#   PR4109_PRIOR_READER_EVIDENCE
#                        prior-release reader compatibility record: the
#                        tested prior version against every schema this
#                        release writes
#   PR4109_BITCOIN_NETWORK  the Bitcoin network the rollback targets
#   PR4109_PRIOR_VERSION    exact version of the prior release restored
#   PR4109_PRIOR_REVISION   exact revision of the prior release restored
#   PR4109_WORK_DRIVER   executable that originates protocol work on the
#                        rehearsal chain, called with the phase name. The
#                        fleet only reacts to chain events, so without it no
#                        ceremony exists to observe and the steps that need
#                        one record themselves blocked. On stdout it may
#                        report what it originated, as a JSON object whose
#                        optional transaction_hashes array carries
#                        0x-prefixed 32-byte hashes; those enter the step
#                        being recorded. A report that cannot be read stops
#                        the step rather than passing for no transactions
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
#
# All of that decides whether a record is admissible, which is not whether it
# accepts anything. A record is where a rehearsal says a mandatory step
# failed or an acceptance assertion does not hold, so a correctly bound,
# schema-valid record can be exactly the evidence that a gate must not be
# accepted. Both the rehearsal's own exit and validate-evidence therefore
# read the recorded outcomes as the verdict: a failed step or a refused
# assertion refuses the gate, a step that never executed leaves it
# unrehearsed, and only a run with none of the three reports success.

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
                      exits FAIL if any mandatory step failed or any
                      acceptance assertion does not hold, and BLOCKED if any
                      step could not execute
  rollback            homogeneous rollback rehearsal: quiesce all R1,
                      all-candidate-down barrier, offline state audit, staged
                      prior redeploy, forbidden partial-rollback attempt.
                      Same per-step ledger and verdict as single-release;
                      additionally needs STORAGE_SNAPSHOT_DIR — the directory
                      this stage captures each drained node's state into,
                      straight out of the container the drain stopped, so the
                      audit's verdict is over the state this fleet left and
                      not over a tree supplied under the same name
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
                      checker first. Then asks the separate question the
                      binding checks cannot: a correctly bound record still
                      says whether its gate held, so the stage exits FAIL on
                      any recorded failed step or refused acceptance
                      assertion and BLOCKED on any step that never executed

environment (every proof stage):
  PR4109_EXPECTED_SOURCE_COMMIT
                      fail closed: refuse to run unless the tree under test
                      is exactly this commit (clean, untracked included)
  PR4109_SOURCE_BINDING_MODE
                      exact (default) | build-image (accept only the CI
                      build image's designed divergence: context-excluded
                      absences, with every regenerated gen/ file restored
                      byte-exact from the dispatched commit before testing)

environment (preflight, single-release, rollback):
  PRIOR_IMAGE_DIGEST  immutable prior-production runtime digest
  R1_IMAGE_DIGEST     immutable R1 candidate runtime digest
  PROBE_IMAGE_DIGEST  immutable digest of the wget-carrying image every
                      evidence reading is scraped with
  ETH_WS_URL          rehearsal chain websocket endpoint
  CUTOVER_BLOCK       rehearsed cutover block C on that chain
  CHAIN_ID            that chain's numeric chain id
  KEYSTORE_DIR        per-node inputs, one <service>/ directory each holding
                      that node's config.toml and key material
  KEEP_ETHEREUM_PASSWORD
                      the key files' password
  PR4109_WORK_DRIVER  executable called with the phase name to originate
                      protocol work on the rehearsal chain; may report the
                      transactions it submitted as a JSON object with a
                      transaction_hashes array. The fleet only reacts to
                      chain events, so the steps that need a ceremony record
                      themselves blocked without one

environment (rollback, additionally):
  STORAGE_SNAPSHOT_DIR
                      where this stage captures each drained node's state
                      from the container it stopped, for the offline audit
  PR4109_CHAIN_RECONCILIATION_EVIDENCE
  PR4109_BITCOIN_RECONCILIATION_EVIDENCE
  PR4109_PRIOR_READER_EVIDENCE
                      the reconciliation and prior-reader results the audit
                      binds its verdict to; from a snapshot alone it reports
                      namespace consistency and nothing about rollback safety
  PR4109_QUIESCENCE_REPORT_DIR
                      one <service>.json per node: the permits it held when
                      it drained and how each one ended
  PR4109_BITCOIN_NETWORK
  PR4109_PRIOR_VERSION
  PR4109_PRIOR_REVISION
                      the operational identities the audit requires the
                      snapshot and the restored artifact to agree with
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

# The client registers every one of these through ObserveApplicationSource
# under the "performance" application, and that call prefixes the exposed name
# with the application. So the names below are the internal ones and the
# exposition carries performance_<name>; probing the internal name directly
# finds nothing at all. pkg/clientinfo/performance.go is where the application
# is chosen and pkg/clientinfo/metrics.go is where the prefix is applied.
METRIC_APPLICATION_PREFIX="performance"

# The termination grace the reviewed manifest grants, which is the ceiling the
# fleet's service manager and this driver must both stop nodes under.
manifest_termination_grace() {
  node -e '
    const fs = require("fs");
    const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const grace = (manifest.termination_grace || {})
      .termination_grace_period_seconds;
    if (!Number.isInteger(grace) || grace < 1) {
      console.error("no positive termination grace in " + process.argv[1]);
      process.exit(1);
    }
    process.stdout.write(String(grace));
  ' "${SCRIPT_DIR}/release-manifest.json"
}

# The release epoch the reviewed manifest is for. Every bound this run
# measures a fleet against comes out of that manifest, so a node running some
# other epoch is being judged by numbers that were never derived for it.
manifest_protocol_epoch() {
  node -e '
    const fs = require("fs");
    const manifest = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    if (!manifest.protocol_epoch) {
      console.error("no protocol_epoch in " + process.argv[1]);
      process.exit(1);
    }
    process.stdout.write(String(manifest.protocol_epoch));
  ' "${SCRIPT_DIR}/release-manifest.json"
}

# One counter from a node's Prometheus text exposition. The parser reads the
# exposition's own shape: the metric name, optional labels, the value, and the
# trailing timestamp the client-info registry appends.
metric_value() {
  local service="$1" metric="${METRIC_APPLICATION_PREFIX}_$2"
  probe_metrics "${service}" |
    awk -v metric="${metric}" '
      $1 == metric || index($1, metric "{") == 1 { print $2; found = 1; exit }
      END { if (!found) exit 1 }
    '
}

# The gate metrics an evidence step snapshots, by their internal names.
PARTICIPATION_METRICS=(
  participation_gate_state
  participation_current_block
  participation_cutover_block
  participation_allowed
  participation_active_ceremonies
  participation_active_legacy_ceremonies
  participation_active_security_v2_ceremonies
  participation_mode_legacy_total
  participation_mode_security_v2_total
  participation_legacy_completions_after_cutover_total
  participation_refusals_total
  participation_commit_refusals_total
  participation_clock_errors_total
  participation_clock_aborts_total
  participation_quiesce_total
  participation_quiesce_forced_aborts_total
)

# Snapshot the gate gauges of one node into the step being recorded. Reading
# none of them is a broken instrument rather than an absent value — a renamed
# application prefix or metric family would otherwise leave every step
# carrying an empty gauge object, which reads in the record exactly like a
# fleet that reported zeros.
observe_gate_gauges() {
  local service="$1" metric value read_count=0
  for metric in "${PARTICIPATION_METRICS[@]}"; do
    if value="$(metric_value "${service}" "${metric}")"; then
      read_count=$((read_count + 1))
      STEP_GAUGES="${STEP_GAUGES}${STEP_GAUGES:+,}\"${service}.${metric}\":${value}"
    fi
  done
  if ((read_count == 0)); then
    blocked "${service} exposed none of the ${#PARTICIPATION_METRICS[@]} \
participation gate metrics under the ${METRIC_APPLICATION_PREFIX} prefix; the \
probe is reading the wrong names and every gauge this rehearsal recorded \
would be empty"
  fi
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
# A step that ran and observed the property violated, and an acceptance
# assertion observed not to hold, are each on their own enough to deny the
# gate. They are tracked apart from the blocked steps because they mean
# something different — the rehearsal reached the property and the property
# was wrong, rather than the rehearsal never reaching it — and because a
# verdict drawn from the blocked list alone reports a gate whose steps all
# ran and one of which failed as a success.
REHEARSAL_FAILED_STEPS=()
REHEARSAL_REFUTED_ASSERTIONS=()

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
    REHEARSAL_FAILED_STEPS+=("${name}")
    note "   FAIL: ${name}${notes:+ — ${notes}}"
    ;;
  esac
}

# A step this release cannot execute. It is recorded rather than aborting the
# run: the steps after it are independent proofs, and losing them tells a
# reviewer less than a record that names exactly which one could not run and
# why. The stage refuses to report success at the end regardless.
block_step() { record_step "$1" blocked "$2"; }

# Record one of the gate's acceptance assertions with what was observed.
# Anything but a literal true is a refusal: an assertion is written true only
# where the run actually watched the property hold, so an unobserved one and
# a violated one both deny the gate rather than being waved through by a
# verdict that never reads them.
record_assertion() {
  local assertion="$1" holds="$2" stage="${3:-}"
  local fields
  fields="\"assertion\":$(json_string "${assertion}"),\"holds\":${holds}"
  [[ -n "${stage}" ]] &&
    fields="${fields},\"evidence_stage\":$(json_string "${stage}")"
  REHEARSAL_ASSERTIONS+=("{${fields}}")
  [[ "${holds}" == "true" ]] || REHEARSAL_REFUTED_ASSERTIONS+=("${assertion}")
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

# What one node says it is: the artifact it was built from, and the schedule
# its gate was compiled and armed with. All four come from the node's own
# diagnostics rather than from the operator, because a value typed by whoever
# ran the rehearsal binds nothing. Keys are emitted in a fixed order so two
# nodes' answers can be compared as strings.
node_release_identity() {
  probe_diagnostics "$1" |
    node -e '
      let raw = "";
      process.stdin.on("data", (d) => (raw += d));
      process.stdin.on("end", () => {
        const document = JSON.parse(raw);
        const info = document.client_info || {};
        const gate = document.protocol_participation || {};
        const missing = [];
        if (!info.version) missing.push("client_info.version");
        if (!info.revision) missing.push("client_info.revision");
        if (!gate.protocol_epoch) {
          missing.push("protocol_participation.protocol_epoch");
        }
        if (!Number.isInteger(gate.cutover_block)) {
          missing.push("protocol_participation.cutover_block");
        }
        if (missing.length > 0) {
          console.error("the node diagnostics carry no " + missing.join(", "));
          process.exit(1);
        }
        process.stdout.write(JSON.stringify({
          version: info.version,
          revision: info.revision,
          protocol_epoch: gate.protocol_epoch,
          cutover_block: gate.cutover_block,
        }));
      });
    '
}

# One counter summed across the whole R1 fleet. A control that watched a
# single node would pass on a fleet where every other node sat idle, and a
# node whose counter cannot be read makes the total unknown rather than
# smaller — so an unreadable one poisons the sum on purpose.
fleet_metric_total() {
  local metric="$1" service value total=0
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    value="$(metric_value "${service}" "${metric}" 2>/dev/null || printf '')"
    if [[ ! "${value}" =~ ^[0-9]+$ ]]; then
      printf 'unreadable on %s' "${service}"
      return 0
    fi
    total=$((total + value))
  done
  printf '%s' "${total}"
}

# One node's cutover peer roster snapshot, as it publishes it.
roster_snapshot() {
  probe_diagnostics "$1" |
    node -e '
      let raw = "";
      process.stdin.on("data", (d) => (raw += d));
      process.stdin.on("end", () => {
        const snapshot = JSON.parse(raw).cutover_legacy_peers;
        process.stdout.write(JSON.stringify(snapshot || null));
      });
    '
}

# The operator addresses one node has attributed legacy sightings to, sorted
# and one per line so two readings can be differenced. The roster object is
# present from startup with an empty peer list, so its existence says nothing
# and only the set of operators in it can be compared across an event.
roster_operators() {
  roster_snapshot "$1" |
    node -e '
      let raw = "";
      process.stdin.on("data", (d) => (raw += d));
      process.stdin.on("end", () => {
        const snapshot = JSON.parse(raw) || {};
        const operators = (snapshot.peers || [])
          .map((peer) => peer.operator_address)
          .filter(Boolean)
          .sort();
        process.stdout.write(
          operators.length > 0 ? operators.join("\n") + "\n" : ""
        );
      });
    '
}

# One field of a JSON document held in a shell variable.
json_field() {
  printf '%s' "$1" | node -e '
    let raw = "";
    process.stdin.on("data", (d) => (raw += d));
    process.stdin.on("end", () =>
      process.stdout.write(String(JSON.parse(raw)[process.argv[1]])));
  ' "$2"
}

# The release the whole R1 fleet says it is running, captured while the fleet
# is up and reused when the record is built.
#
# Everything here comes from the nodes rather than from the operator, and
# from every node rather than from the first one. A record built from the
# first node's answers is schema-valid evidence for a fleet whose other nodes
# ran something else entirely, so each value is compared across the fleet and
# any disagreement refuses the run. Two of them are compared against the run's
# own inputs as well: the revision must be the commit this run is bound to —
# the build stamps a short or a full SHA depending on how it was invoked, so a
# prefix match is the comparison that holds for both — and the cutover block
# the gates actually armed must be the C this rehearsal claims to be
# rehearsing, because copying that number out of the environment into the
# record would evidence what the operator typed rather than what ran.
#
# Capturing rather than reading on demand is also what lets the rollback gate
# emit a record at all: by the time it concludes, every R1 node has been
# stopped on purpose, and a reading taken then would be no reading at all.
REHEARSAL_R1_IDENTITY=""
REHEARSAL_R1_EPOCH=""
REHEARSAL_R1_CUTOVER_BLOCK=""

capture_r1_release_identity() {
  local attested manifest_epoch service reported revision epoch cutover
  local agreed=""
  attested="$(attested_source_identity)"
  manifest_epoch="$(manifest_protocol_epoch)"
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    reported="$(node_release_identity "${service}")" ||
      blocked "${service} does not report the version, revision, protocol \
epoch, and cutover block that identify what it is running; the record binds \
the rehearsal to what the running nodes say they are, and a node that will \
not say cannot be evidenced"

    revision="$(json_field "${reported}" revision)"
    if [[ "${attested}" != "${revision}"* ]]; then
      blocked "${service} reports revision [${revision}], which is not the \
commit this run is bound to [${attested}]; the running image was built from \
other bytes than the ones every proof here measures"
    fi

    cutover="$(json_field "${reported}" cutover_block)"
    if [[ "${cutover}" != "${CUTOVER_BLOCK}" ]]; then
      blocked "${service} armed cutover block [${cutover}], but this \
rehearsal is bound to C=[${CUTOVER_BLOCK}]; every crossing, refusal, and \
straggler observation below would be evidence about a different schedule"
    fi

    epoch="$(json_field "${reported}" protocol_epoch)"
    if [[ "${epoch}" != "${manifest_epoch}" ]]; then
      blocked "${service} reports protocol epoch [${epoch}], but the reviewed \
release manifest this run measures everything against is for \
[${manifest_epoch}]; the node is a different release than the one these \
bounds and this record describe"
    fi

    if [[ -z "${agreed}" ]]; then
      agreed="${reported}"
    elif [[ "${reported}" != "${agreed}" ]]; then
      blocked "the R1 fleet is not homogeneous: ${service} reports \
${reported} while ${REHEARSAL_R1_SERVICES[0]} reports ${agreed}; a mixed \
fleet is not one release under test and one record cannot speak for both"
    fi
  done

  REHEARSAL_R1_IDENTITY="${agreed}"
  REHEARSAL_R1_EPOCH="$(json_field "${agreed}" protocol_epoch)"
  REHEARSAL_R1_CUTOVER_BLOCK="$(json_field "${agreed}" cutover_block)"
  note "every R1 node reports ${agreed}, matching the attested source \
${attested} and the rehearsed C"
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
  identity="${REHEARSAL_R1_IDENTITY}"
  if [[ -z "${identity}" ]]; then
    blocked "no R1 release identity was captured while the fleet was up; the \
record binds the rehearsal to what the running nodes reported, and a gate \
that never captured it has nothing to bind"
  fi
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
      chainID, stepsJSON, assertionsJSON, generatedAt,
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
        // The epoch and C the nodes reported, not the ones this driver was
        // told. Restating them here would record what whoever ran the
        // rehearsal intended and leave the record silent about what the
        // fleet armed; the capture already refused the run on a disagreement.
        protocol_epoch: identity.protocol_epoch,
      },
      chain: { chain_id: chainID, cutover_block: identity.cutover_block },
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
    "${r1_digests}" "${prior_digests}" "${CHAIN_ID}" \
    "${steps}" "${assertions}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >"${record}" ||
    fail "cannot build the rehearsal evidence record"
  unset PR4109_MANIFEST_SHA256

  note "rehearsal evidence record written to ${record}"
  note "validating it with the acceptance stage's own validator"
  # Shape and binding only. This record is emitted by every rehearsal,
  # including one that just watched a mandatory step fail, and the point of
  # emitting it is that the refusal is reviewable — so the checks run here
  # are the ones that say the record is admissible. Whether its contents
  # accept the gate is conclude_verdict's decision on the way out, and the
  # acceptance stage's when a reviewer reads the directory later.
  validate_evidence_records
}

# The verdict a ledger implies, with no emission and no I/O of its own, so
# the decision can be exercised directly against a constructed ledger.
#
# The three outcomes are ordered by what they say about the release. A failed
# step is the strongest: the rehearsal reached the property, watched it, and
# watched it break — that is a refutation, and it outranks anything the run
# could not reach. A blocked step is next: the gate was not rehearsed, so it
# is unproved rather than disproved. A refused acceptance assertion with no
# step behind it is a refutation too, because the assertions are only ever
# written true where the property was observed. Only a ledger with none of
# the three is a rehearsed, satisfied gate.
conclude_verdict() {
  if ((${#REHEARSAL_FAILED_STEPS[@]} > 0)); then
    fail "${#REHEARSAL_FAILED_STEPS[@]} mandatory step(s) of the \
${REHEARSAL_GATE} gate failed: ${REHEARSAL_FAILED_STEPS[*]}; the gate is \
refused and the record written above names what each step observed"
  fi
  if ((${#REHEARSAL_BLOCKED_STEPS[@]} > 0)); then
    blocked "${#REHEARSAL_BLOCKED_STEPS[@]} mandatory step(s) of the \
${REHEARSAL_GATE} gate could not execute: ${REHEARSAL_BLOCKED_STEPS[*]}; the \
record written above names each one and why"
  fi
  if ((${#REHEARSAL_REFUTED_ASSERTIONS[@]} > 0)); then
    fail "${#REHEARSAL_REFUTED_ASSERTIONS[@]} acceptance assertion(s) of the \
${REHEARSAL_GATE} gate do not hold: ${REHEARSAL_REFUTED_ASSERTIONS[*]}; every \
mandatory step ran, so this is the property itself being refused"
  fi
  note "${REHEARSAL_GATE} rehearsal completed: every mandatory step executed \
and every acceptance assertion holds"
}

# Close a rehearsal: emit the record, then decide the stage's verdict from the
# steps themselves. The record is written first either way — a gate that is
# refused leaves the reviewable account of why, not just a console line.
conclude_rehearsal() {
  emit_evidence_record
  conclude_verdict
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

# Prove the named services are running the image the rehearsal was told to
# run.
#
# The record attributes everything it observed to the supplied digests, and
# nothing so far has checked that those digests are what the daemon actually
# created these containers from. compose resolves a service to an image
# through the compose file and the local image store, so a stale local tag, an
# edited compose file, or a service whose image was never refreshed all
# produce a fleet running other bytes under a record that names these ones.
#
# Image IDs are compared rather than references because the ID is the identity
# the container was created from; a reference can be re-pointed, and a
# container carries no memory of which name it was started by.
verify_running_images() {
  local reference="$1"
  shift
  local expected_id
  expected_id="$(docker image inspect --format '{{.Id}}' "${reference}" \
    2>/dev/null)" ||
    blocked "cannot resolve ${reference} in the local image store; the \
rehearsal cannot say what its containers were supposed to be running"

  local service container running_id
  for service in "$@"; do
    container="$(compose ps --quiet "${service}" 2>/dev/null || true)"
    if [[ -z "${container}" ]]; then
      blocked "${service} has no container, so nothing can be shown to be \
running ${reference}"
    fi
    running_id="$(docker inspect --format '{{.Image}}' "${container}" \
      2>/dev/null)" ||
      blocked "cannot read the image ${service} is running"
    if [[ "${running_id}" != "${expected_id}" ]]; then
      blocked "${service} is running image [${running_id}] but this \
rehearsal supplied [${reference}] ([${expected_id}]); every observation this \
fleet produces would be recorded against an artifact it did not run"
    fi
    note "${service} is running ${reference}"
  done
}

# Start exactly the named services from the immutable digests and wait for
# each to serve its evidence port.
#
# Which services a gate starts is part of what that gate proves, so the set is
# the caller's and never the whole compose file. The cutover rehearsal needs
# the prior binary on the network from the start — it is the straggler the
# negative control is about. The rollback rehearsal must not have it there at
# all: its entire subject is that no prior binary participates until every R1
# node is down and the state audit has authorized the rollback, and a fleet
# that started the prior service with everything else would have put the thing
# under test on the network before the first step ran.
fleet_up() {
  note "starting the rehearsal fleet from the immutable digests: $*"
  compose up --detach "$@"

  local service deadline
  deadline=$((SECONDS + 600))
  for service in "$@"; do
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

# Create the prior node's container without starting it.
#
# `compose start` can only start a container that already exists, and the
# rollback project deliberately never brings the prior service up — so on a
# clean run the step that releases the prior binary behind the barrier would
# have nothing to start, and would record a rollback that never happened. The
# gate needs two facts kept apart rather than one: the prior artifact is staged
# and ready to run, and it is not on the network. Creating the container
# establishes the first; the checks below are what make the second an
# observation instead of an assumption about what `compose create` does.
stage_prior_container() {
  note "staging ${REHEARSAL_PRIOR_SERVICE} from ${PRIOR_IMAGE_DIGEST} without \
starting it"
  compose create "${REHEARSAL_PRIOR_SERVICE}" ||
    blocked "cannot create ${REHEARSAL_PRIOR_SERVICE}'s container; the step \
that releases the prior binary behind the barrier would have nothing to start \
and would record a rollback that was never performed"

  local container
  container="$(compose ps --all --quiet "${REHEARSAL_PRIOR_SERVICE}" \
    2>/dev/null || true)"
  [[ -n "${container}" ]] ||
    blocked "${REHEARSAL_PRIOR_SERVICE} has no container after being created, \
so the rollback has no staged prior artifact to release"

  local running
  running="$(docker inspect --format '{{.State.Running}}' "${container}" \
    2>/dev/null)" ||
    blocked "cannot read whether ${REHEARSAL_PRIOR_SERVICE}'s staged \
container is running"
  [[ "${running}" == "false" ]] ||
    blocked "${REHEARSAL_PRIOR_SERVICE} is running immediately after being \
staged; the barrier this gate exists to prove would already be broken before \
its first step ran"

  # Checked here and not only at release, because a container created from
  # other bytes cannot be corrected once the barrier has authorized starting
  # it: by then the wrong artifact is the running fleet.
  local expected_id created_id
  expected_id="$(docker image inspect --format '{{.Id}}' \
    "${PRIOR_IMAGE_DIGEST}" 2>/dev/null)" ||
    blocked "cannot resolve ${PRIOR_IMAGE_DIGEST} in the local image store; \
the rehearsal cannot say what its staged prior container was supposed to be"
  created_id="$(docker inspect --format '{{.Image}}' "${container}" \
    2>/dev/null)" ||
    blocked "cannot read the image ${REHEARSAL_PRIOR_SERVICE} was created from"
  [[ "${created_id}" == "${expected_id}" ]] ||
    blocked "${REHEARSAL_PRIOR_SERVICE} was created from image \
[${created_id}] but this rehearsal supplied [${PRIOR_IMAGE_DIGEST}] \
([${expected_id}]); the rollback would restore an artifact the state audit \
never authorized"

  note "${REHEARSAL_PRIOR_SERVICE} is staged from ${PRIOR_IMAGE_DIGEST} and \
is not running"
}

# Why one node's state could not be captured, for the step that records it.
# Set by capture_storage_snapshot whenever it returns nonzero.
SNAPSHOT_CAPTURE_REASON=""

# Copy one drained node's persistent state out of the container that just
# stopped, into the directory the offline audit reads.
#
# The audit authorizes a rollback onto the state the fleet actually left
# behind, so the bytes it reads have to be those bytes. A snapshot handed in
# from outside is only a claim about them: an older capture, another node's, or
# a hand-edited tree all audit exactly as cleanly as the real thing and
# authorize the rollback just as readily. Taking the copy here — after the
# drain, from the stopped container, before the audit — is what makes the
# manifest the audit writes a statement about this rehearsal.
#
# Where a node's storage lives is read off the container rather than named
# here: the compose file owns that path, and a constant restating it would go
# on copying an empty directory the first time it moved. `docker cp` is the
# daemon's own copy, so it needs nothing installed inside an image whose only
# documented tool is the probe's wget, and it reads a stopped container as
# readily as a running one.
capture_storage_snapshot() {
  local service="$1"
  # Separate statements: bash expands every word of a `local` before it assigns
  # any of them, so a destination built from ${service} in the same statement
  # would read whatever the caller's scope happened to have under that name.
  local destination="${STORAGE_SNAPSHOT_DIR}/${service}"
  SNAPSHOT_CAPTURE_REASON=""

  local container
  container="$(compose ps --all --quiet "${service}" 2>/dev/null || true)"
  if [[ -z "${container}" ]]; then
    SNAPSHOT_CAPTURE_REASON="${service} has no container, so the state this \
rollback would be audited against does not exist to be read"
    return 1
  fi

  # A running node is still writing, so a copy taken from one is a torn read
  # of a moving target and says nothing about what the drain left behind.
  local running
  if ! running="$(docker inspect --format '{{.State.Running}}' "${container}" \
    2>/dev/null)"; then
    SNAPSHOT_CAPTURE_REASON="cannot read whether ${service} is still running, \
so nothing can say the state about to be copied is settled"
    return 1
  fi
  if [[ "${running}" != "false" ]]; then
    SNAPSHOT_CAPTURE_REASON="${service} is still running; a snapshot copied \
out from under a live node is a torn read and the audit's verdict over it \
would describe no moment the fleet was ever in"
    return 1
  fi

  # The keystore arrives as a read-only bind mount and the persistent state as
  # the service's named volume, so the volume mount is the one the audit reads.
  local volumes count storage
  if ! volumes="$(docker inspect --format \
    '{{range .Mounts}}{{if eq .Type "volume"}}{{.Destination}}{{"\n"}}{{end}}{{end}}' \
    "${container}" 2>/dev/null)"; then
    SNAPSHOT_CAPTURE_REASON="cannot read ${service}'s mounts, so this run \
cannot say where the state the audit reads lives"
    return 1
  fi
  count="$(printf '%s' "${volumes}" | grep -c . || true)"
  if [[ "${count}" != "1" ]]; then
    SNAPSHOT_CAPTURE_REASON="${service} carries ${count} persistent volume \
mount(s); the rehearsal fleet gives each node exactly one, so this run cannot \
tell which bytes the audit should read"
    return 1
  fi
  storage="$(printf '%s' "${volumes}" | grep . | head -1)"

  # Any inherited directory goes first: a capture that failed halfway while an
  # older one sat here would otherwise leave the audit reading a previous
  # run's state under this run's name.
  rm -rf "${destination}"
  if ! mkdir -p "${destination}"; then
    SNAPSHOT_CAPTURE_REASON="cannot create ${destination} to capture \
${service}'s state into"
    return 1
  fi

  note "capturing ${service}'s ${storage} into ${destination}"
  if ! docker cp "${container}:${storage}/." "${destination}"; then
    # Leave nothing behind: a partial copy is a snapshot of a state no node
    # was ever in, and auditing it cleanly would authorize a rollback onto
    # bytes that never existed.
    rm -rf "${destination}"
    SNAPSHOT_CAPTURE_REASON="copying ${service}'s ${storage} out of its \
stopped container failed, so there is no capture of the state the drain left"
    return 1
  fi

  note "${service}: state captured from the stopped container's ${storage}"
  return 0
}

# The rollback inputs the offline audit cannot derive from a storage
# snapshot. Everything the fleet can be asked for is read from the fleet; what
# remains is genuinely outside this repository — reconciliation against the
# live Ethereum and Bitcoin state, each node's own quiescence outcome record,
# the prior release's reader-compatibility result, and the identity of the
# prior artifact the rollback restores — so it arrives as supplied paths and
# values. A missing one blocks the barrier rather than being skipped: an audit
# run without them reports namespace consistency and nothing about whether
# rolling back onto this state is safe, and unbound evidence would approve a
# rollback of the wrong chain, network, or artifact just as readily.
ROLLBACK_AUDIT_INPUTS=(
  PR4109_CHAIN_RECONCILIATION_EVIDENCE
  PR4109_BITCOIN_RECONCILIATION_EVIDENCE
  PR4109_QUIESCENCE_REPORT_DIR
  PR4109_PRIOR_READER_EVIDENCE
  PR4109_BITCOIN_NETWORK
  PR4109_PRIOR_VERSION
  PR4109_PRIOR_REVISION
)

# Why the last audited snapshot is not rollback-safe, for the step that
# records it. Set by run_state_audit whenever it returns nonzero.
STATE_AUDIT_REASON=""

# Audit one node's storage snapshot for rollback safety. Returns 0 only when
# the tool itself reported rollback_barrier_ready over the full evidence set;
# the manifest it wrote is left beside the rehearsal record either way, because
# a refusal is the part of a rollback decision most worth reading.
#
# The identities the audit binds its evidence to are the ones already read off
# the running fleet — release version, revision, epoch, and armed C — so the
# rollback is authorized against what ran rather than against what the
# operator believed ran.
run_state_audit() {
  local service="$1" snapshot="$2"
  local output="${EVIDENCE_DIR}/state-audit-${service}.json"
  STATE_AUDIT_REASON=""

  # The path is fixed per service, so a re-run that never reaches the tool —
  # or one whose tool dies before writing — would otherwise be read through
  # the manifest an earlier run left at it. Removing it first makes the
  # presence of a manifest below evidence that this run produced one.
  rm -f "${output}"

  local missing=() name
  for name in "${ROLLBACK_AUDIT_INPUTS[@]}"; do
    if [[ -z "${!name:-}" ]]; then
      missing+=("${name}")
    fi
  done
  # One quiescence outcome record per node: the permits each node held when it
  # drained and how each one ended. It is per-node by nature, so a single
  # shared path would bind every node's audit to one node's drain.
  local quiescence=""
  if [[ -n "${PR4109_QUIESCENCE_REPORT_DIR:-}" ]]; then
    quiescence="${PR4109_QUIESCENCE_REPORT_DIR}/${service}.json"
    if [[ ! -f "${quiescence}" ]]; then
      missing+=("a quiescence outcome record for ${service} at ${quiescence}")
    fi
  fi
  if ((${#missing[@]} > 0)); then
    STATE_AUDIT_REASON="the audit cannot authorize a rollback without \
${missing[*]}; from a snapshot alone it reports namespace consistency and \
nothing about the live-chain reconciliation, this node's quiescence \
outcomes, or the prior release's ability to read what this one wrote"
    return 1
  fi

  note "auditing ${service}'s storage snapshot for rollback safety"
  local rc=0
  (
    cd "${REPO_ROOT}" && go run ./cmd/participation-state-audit \
      --storage-snapshot "${snapshot}" \
      --output "${output}" \
      --chain-reconciliation-evidence \
      "${PR4109_CHAIN_RECONCILIATION_EVIDENCE}" \
      --bitcoin-reconciliation-evidence \
      "${PR4109_BITCOIN_RECONCILIATION_EVIDENCE}" \
      --quiescence-report "${quiescence}" \
      --prior-reader-compatibility-evidence "${PR4109_PRIOR_READER_EVIDENCE}" \
      --expected-ethereum-chain-id "${CHAIN_ID}" \
      --expected-bitcoin-network "${PR4109_BITCOIN_NETWORK}" \
      --expected-prior-version "${PR4109_PRIOR_VERSION}" \
      --expected-prior-revision "${PR4109_PRIOR_REVISION}" \
      --expected-prior-image-digest "${PRIOR_IMAGE_DIGEST##*@}" \
      --expected-release-version \
      "$(json_field "${REHEARSAL_R1_IDENTITY}" version)" \
      --expected-release-revision \
      "$(json_field "${REHEARSAL_R1_IDENTITY}" revision)" \
      --expected-release-image-digest "${R1_IMAGE_DIGEST##*@}" \
      --expected-release-epoch "${REHEARSAL_R1_EPOCH}" \
      --expected-cutover-block "${REHEARSAL_R1_CUTOVER_BLOCK}"
  ) || rc=$?

  if [[ ! -f "${output}" ]]; then
    STATE_AUDIT_REASON="the audit exited [${rc}] without writing a manifest \
to ${output}, so it authorized nothing"
    return 1
  fi

  local verdict
  verdict="$(node -e '
    const fs = require("fs");
    const audit = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    if (audit.rollback_barrier_ready === true) {
      process.stdout.write("ready");
    } else {
      const reasons = (audit.rollback_blockers || [])
        .concat(audit.findings || []);
      process.stdout.write(
        reasons.length > 0
          ? reasons.join("; ")
          : "the manifest does not report rollback_barrier_ready"
      );
    }
  ' "${output}")" || {
    STATE_AUDIT_REASON="the audit manifest at ${output} could not be read"
    return 1
  }

  # Both halves, because they are not the same statement. The tool exits
  # nonzero on an inconsistent namespace as well as on an unready barrier, so
  # a manifest read alone would accept a snapshot the tool refused for a
  # reason its ready flag does not carry — and a tool that died after writing
  # a ready manifest would be read as having finished its checks.
  if [[ "${rc}" -ne 0 ]]; then
    STATE_AUDIT_REASON="the audit exited [${rc}] over ${service}'s snapshot \
(manifest in ${output}), so it completed no verdict this rollback can rely \
on: ${verdict}"
    return 1
  fi
  if [[ "${verdict}" == "ready" ]]; then
    note "${service}: rollback_barrier_ready, manifest in ${output}"
    return 0
  fi
  STATE_AUDIT_REASON="the audit refused to authorize a rollback (exit \
[${rc}], manifest in ${output}): ${verdict}"
  return 1
}

# Originate real protocol work on the rehearsal chain. The fleet only reacts
# to chain events, so no ceremony exists to observe unless something submits
# the deposits, DKG requests, and relay requests that start them — which is
# chain-side, outside this repository, and therefore a supplied input like the
# chain endpoint itself. The driver is called with the phase name so one
# implementation can originate the work each step needs.
#
# On stdout it may report what it originated, as a JSON object carrying a
# transaction_hashes array. Those hashes go into the step being recorded, so a
# reviewer can follow a step back to the chain transactions that caused it
# rather than taking the fleet counters as the only account of what happened.
# The output is either well formed or it is a broken instrument: a driver
# whose report cannot be read has left the step unable to say what it drove,
# and treating that as "no transactions" would record silence as evidence.
run_work_driver() {
  local phase="$1" report rc=0
  note "driving ${phase} work on the rehearsal chain"
  report="$("${PR4109_WORK_DRIVER}" "${phase}")" || rc=$?

  if [[ -n "${report//[[:space:]]/}" ]]; then
    local hashes
    hashes="$(printf '%s' "${report}" | node -e '
      let raw = "";
      process.stdin.on("data", (d) => (raw += d));
      process.stdin.on("end", () => {
        const report = JSON.parse(raw);
        const hashes = report.transaction_hashes;
        if (hashes === undefined) {
          process.stdout.write("");
          return;
        }
        if (!Array.isArray(hashes)) {
          console.error("transaction_hashes is not an array");
          process.exit(1);
        }
        for (const hash of hashes) {
          if (typeof hash !== "string" || !/^0x[0-9a-f]{64}$/.test(hash)) {
            console.error("not a transaction hash: " + JSON.stringify(hash));
            process.exit(1);
          }
        }
        process.stdout.write(hashes.map((h) => JSON.stringify(h)).join(","));
      });
    ')" ||
      blocked "the work driver reported the ${phase} phase in a form this \
rehearsal cannot read; its stdout must be a JSON object whose optional \
transaction_hashes array carries 0x-prefixed 32-byte hashes, and a report \
that cannot be read leaves the step with no account of what it drove"

    if [[ -n "${hashes}" ]]; then
      STEP_TX_HASHES="${STEP_TX_HASHES}${STEP_TX_HASHES:+,}${hashes}"
    fi
  fi

  return "${rc}"
}

# What the clock-failure step observed. The step fills these from the fleet;
# the verdict below reads nothing else.
CLOCK_STATE=""
CLOCK_HELD_BEFORE=""
CLOCK_HELD_AFTER=""
CLOCK_ABORTS_BEFORE=""
CLOCK_ABORTS_AFTER=""
CLOCK_PERMITS_BEFORE=""
CLOCK_PERMITS_AFTER=""
CLOCK_REFUSALS_BEFORE=""
CLOCK_REFUSALS_AFTER=""
CLOCK_REFUSAL_ATTEMPTED=0

# The verdict those observations imply, with no fleet interaction of its own,
# so the decision can be exercised directly against constructed readings.
# A ladder this layered is exactly the kind that passes on a proxy for the
# property rather than the property, and only a seam like this catches it.
#
# The contract has two halves and the ladder holds both. Cancellation is read
# from the abort counter and not from the active gauge, because the gate
# cancels every permit it finds and counts each one while the permits stay
# counted until their owners close them — so a falling active count is the
# owners noticing, not the gate acting. Refusal is read from a refusal
# recorded against work actually offered while the clock was down, because a
# permit counter that did not move is what a node nobody asked looks like too.
clock_failure_verdict() {
  local step="clock failure quarantines work rather than guessing a mode"
  local assertion="a failed chain-clock read refuses new work instead of \
assuming a side of C"

  if [[ "${CLOCK_STATE}" != "clock_unavailable" ]]; then
    record_step "${step}" fail "the gate reported \
[${CLOCK_STATE:-unreadable}] with its chain endpoint severed"
    record_assertion "${assertion}" false "${step}"
  elif [[ ! "${CLOCK_PERMITS_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${CLOCK_PERMITS_AFTER}" =~ ^[0-9]+$ ]] ||
    [[ ! "${CLOCK_ABORTS_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${CLOCK_ABORTS_AFTER}" =~ ^[0-9]+$ ]]; then
    record_step "${step}" blocked "the gate reported clock_unavailable, but \
its permit and abort counters could not be read (permits \
[${CLOCK_PERMITS_BEFORE:-unreadable}] to [${CLOCK_PERMITS_AFTER:-unreadable}], \
aborts [${CLOCK_ABORTS_BEFORE:-unreadable}] to \
[${CLOCK_ABORTS_AFTER:-unreadable}]), so nothing here observed what happened \
to the work it was holding"
    record_assertion "${assertion}" false "${step}"
  elif ((CLOCK_PERMITS_AFTER > CLOCK_PERMITS_BEFORE)); then
    record_step "${step}" fail "the gate reported clock_unavailable and still \
issued $((CLOCK_PERMITS_AFTER - CLOCK_PERMITS_BEFORE)) new permit(s); a gate \
that cannot read the chain picked a side of C anyway"
    record_assertion "${assertion}" false "${step}"
  elif [[ ! "${CLOCK_HELD_BEFORE}" =~ ^[0-9]+$ ]] ||
    ((CLOCK_HELD_BEFORE == 0)); then
    block_step "${step}" "the gate reported clock_unavailable and issued no \
new permit, but it held no ceremony when its clock failed (active_ceremonies \
[${CLOCK_HELD_BEFORE:-unreadable}]), so the cancel-what-is-held half of the \
contract was never exercised; it needs work originated on the rehearsal chain \
and still running when the endpoint is severed"
    record_assertion "${assertion}" false "${step}"
  elif ((CLOCK_ABORTS_AFTER - CLOCK_ABORTS_BEFORE < CLOCK_HELD_BEFORE)); then
    record_step "${step}" fail "the gate reported clock_unavailable holding \
${CLOCK_HELD_BEFORE} ceremonies but recorded only \
$((CLOCK_ABORTS_AFTER - CLOCK_ABORTS_BEFORE)) clock cancellation(s) \
(${CLOCK_ABORTS_BEFORE} to ${CLOCK_ABORTS_AFTER}); work it was holding was \
neither canceled nor accounted for, and ${CLOCK_HELD_AFTER:-an unreadable \
number of} ceremonies remain active"
    record_assertion "${assertion}" false "${step}"
  elif ((CLOCK_REFUSAL_ATTEMPTED == 0)); then
    block_step "${step}" "the gate reported clock_unavailable and canceled \
the $((CLOCK_ABORTS_AFTER - CLOCK_ABORTS_BEFORE)) permit(s) it held, but no \
work was offered to it while it was blind, so its permit counter standing \
still says only that nothing asked; proving the refusal half needs work \
originated on the rehearsal chain after the endpoint is severed"
    record_assertion "${assertion}" false "${step}"
  elif [[ ! "${CLOCK_REFUSALS_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${CLOCK_REFUSALS_AFTER}" =~ ^[0-9]+$ ]] ||
    ((CLOCK_REFUSALS_AFTER <= CLOCK_REFUSALS_BEFORE)); then
    block_step "${step}" "work was originated while the gate reported \
clock_unavailable, but its refusal counter did not move \
(${CLOCK_REFUSALS_BEFORE:-unreadable} to \
${CLOCK_REFUSALS_AFTER:-unreadable}), so nothing reached the gate to be \
refused and the unchanged permit counter evidences no refusal"
    record_assertion "${assertion}" false "${step}"
  else
    record_step "${step}" pass "with the chain endpoint severed the gate \
reported clock_unavailable, canceled all ${CLOCK_HELD_BEFORE} ceremonies it \
held (clock aborts ${CLOCK_ABORTS_BEFORE} to ${CLOCK_ABORTS_AFTER}), and \
refused the work originated while it was blind — \
$((CLOCK_REFUSALS_AFTER - CLOCK_REFUSALS_BEFORE)) refusal(s) and no new \
permit (${CLOCK_PERMITS_BEFORE} to ${CLOCK_PERMITS_AFTER})"
    record_assertion "${assertion}" true "${step}"
  fi
}

# What the quiescence step observed across the whole drain window, and the
# verdict they imply — same seam, same reason.
#
# Issuance is read from the permit counter rather than from a peak of the
# active gauge: a permit taken and closed between two samples never raises
# that peak. Completion is read from having seen the in-flight count at zero,
# because a node that stopped answering while still holding permits is
# indistinguishable, in its last reading, from one that finished them.
QUIESCE_STATE=""
QUIESCE_HELD_BEFORE=""
QUIESCE_ISSUED_BEFORE=""
QUIESCE_ISSUED_AFTER=""
QUIESCE_FORCED_BEFORE=""
QUIESCE_FORCED_AFTER=""
QUIESCE_DRAINED=0
QUIESCE_ATTEMPTED=0
QUIESCE_GRACE=""

quiescence_verdict() {
  local node="$1"
  local step="quiescence with an in-flight security-v2 permit"
  local assertion="graceful quiescence starts no new work and lets held \
permits finish"

  if [[ "${QUIESCE_STATE}" != "quiescing" ]]; then
    record_step "${step}" fail "${node} never reported quiescing while \
draining with ${QUIESCE_HELD_BEFORE} security-v2 ceremonies in flight"
    record_assertion "${assertion}" false "${step}"
  elif [[ ! "${QUIESCE_ISSUED_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${QUIESCE_ISSUED_AFTER}" =~ ^[0-9]+$ ]]; then
    block_step "${step}" "${node} entered quiescing, but its issued-permit \
counter could not be read (${QUIESCE_ISSUED_BEFORE:-unreadable} to \
${QUIESCE_ISSUED_AFTER:-unreadable}); the active gauge alone cannot say \
whether a permit was taken and closed between two samples"
    record_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_ISSUED_AFTER > QUIESCE_ISSUED_BEFORE)); then
    record_step "${step}" fail "${node} entered quiescing and still issued \
$((QUIESCE_ISSUED_AFTER - QUIESCE_ISSUED_BEFORE)) new permit(s) \
(${QUIESCE_ISSUED_BEFORE} to ${QUIESCE_ISSUED_AFTER}); a quiescing node \
started new work"
    record_assertion "${assertion}" false "${step}"
  elif [[ ! "${QUIESCE_FORCED_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${QUIESCE_FORCED_AFTER}" =~ ^[0-9]+$ ]]; then
    block_step "${step}" "${node} entered quiescing and issued no new permit, \
but its forced-abort counter could not be read \
(${QUIESCE_FORCED_BEFORE:-unreadable} to ${QUIESCE_FORCED_AFTER:-unreadable}), \
so nothing here observed whether the permits it held finished or were cut \
short"
    record_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_FORCED_AFTER > QUIESCE_FORCED_BEFORE)); then
    record_step "${step}" fail "${node} force-aborted \
$((QUIESCE_FORCED_AFTER - QUIESCE_FORCED_BEFORE)) held permit(s) rather than \
letting them finish inside the ${QUIESCE_GRACE}s grace"
    record_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_DRAINED == 0)); then
    block_step "${step}" "${node} entered quiescing holding \
${QUIESCE_HELD_BEFORE} security-v2 ceremonies and was never seen without \
them; the node stopped answering with its in-flight count unobserved at zero, \
so nothing here says those permits finished rather than went down with the \
process"
    record_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_ATTEMPTED == 0)); then
    block_step "${step}" "${node} entered quiescing, let all \
${QUIESCE_HELD_BEFORE} held permits finish, and issued none — but no work was \
offered to it while it was quiescing, so the starts-no-new-work half rests on \
nothing having asked; it needs work originated on the rehearsal chain after \
the node enters quiescence"
    record_assertion "${assertion}" false "${step}"
  else
    record_step "${step}" pass "${node} entered quiescing holding \
${QUIESCE_HELD_BEFORE} security-v2 ceremonies, was offered new work while \
quiescing and issued no permit for it (${QUIESCE_ISSUED_BEFORE} to \
${QUIESCE_ISSUED_AFTER}), and let every held permit finish inside the \
reviewed ${QUIESCE_GRACE}s grace — in-flight count observed at zero, no \
forced abort (${QUIESCE_FORCED_BEFORE} to ${QUIESCE_FORCED_AFTER})"
    record_assertion "${assertion}" true "${step}"
  fi
}

stage_single_release() {
  REHEARSAL_GATE="single_release"
  stage_preflight
  fleet_up "${REHEARSAL_PRIOR_SERVICE}" "${REHEARSAL_R1_SERVICES[@]}"
  verify_running_images "${R1_IMAGE_DIGEST}" "${REHEARSAL_R1_SERVICES[@]}"
  verify_running_images "${PRIOR_IMAGE_DIGEST}" "${REHEARSAL_PRIOR_SERVICE}"
  capture_r1_release_identity

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
  # A crossing has two sides, and only the second one is observable at the
  # end. A fleet started after C already reports open_security_v2 and would
  # satisfy every check below without ever having crossed anything, so the
  # pre-C side is established first: every node on the legacy side of its own
  # gate, at a block below the C it armed. Without that this step evidences a
  # state, not a transition.
  local before_c=()
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    observe_canonical_block "${service}"
    local pre_state pre_block
    pre_state="$(participation_field "${service}" gate_state 2>/dev/null || true)"
    pre_block="$(participation_field "${service}" current_block 2>/dev/null || true)"
    if [[ "${pre_state}" != "open_legacy" ]] ||
      [[ ! "${pre_block}" =~ ^[0-9]+$ ]] ||
      ((pre_block >= CUTOVER_BLOCK)); then
      before_c+=("${service} reported [${pre_state:-unreadable}] at block \
[${pre_block:-unreadable}]")
    fi
  done

  if ((${#before_c[@]} > 0)); then
    record_step "cross C without restart" blocked "the fleet was not on the \
legacy side of C when this step began — ${before_c[*]} — so nothing here \
could observe a crossing; the rehearsal chain must be below C=\
[${CUTOVER_BLOCK}] when the fleet starts"
    record_assertion \
      "the gate crosses C in-process, without a restart or a global toggle" \
      false "cross C without restart"
  elif await_gate_state open_security_v2 3600; then
    local permits_after=0 permits_read=1
    for service in "${REHEARSAL_R1_SERVICES[@]}"; do
      observe_canonical_block "${service}"
      observe_gate_gauges "${service}"
      local issued
      issued="$(metric_value "${service}" \
        participation_mode_security_v2_total || printf 'unreadable')"
      if [[ "${issued}" =~ ^[0-9]+$ ]]; then
        permits_after=$((permits_after + issued))
      else
        permits_read=0
      fi
    done
    # The record names a permit mode only where a permit was seen. Writing
    # security_v2 into every crossing record regardless would assert an
    # observation of the thing this whole release is about on the strength of
    # a state string.
    if ((permits_read == 1 && permits_after > 0)); then
      STEP_PERMIT_MODES='"security_v2"'
    fi
    record_step "cross C without restart" pass \
      "both R1 gates went from open_legacy below C to open_security_v2 in the \
processes that were running before C; neither was restarted (security-v2 \
permits issued fleet-wide so far: ${permits_after})"
    record_assertion \
      "the gate crosses C in-process, without a restart or a global toggle" \
      true "cross C without restart"
  else
    record_step "cross C without restart" fail \
      "the R1 gates were on the legacy side of C and did not report \
open_security_v2 within an hour of it"
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
  local observer="${REHEARSAL_R1_SERVICES[0]}"
  local refusals_before refusals_after operators_before operators_after roster
  refusals_before="$(metric_value "${observer}" \
    participation_refusals_total || printf '0')"
  operators_before="$(roster_operators "${observer}")"
  if [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
    run_work_driver post-cutover-straggler || true
  fi
  refusals_after="$(metric_value "${observer}" \
    participation_refusals_total || printf '0')"
  operators_after="$(roster_operators "${observer}")"
  roster="$(roster_snapshot "${observer}")"
  observe_gate_gauges "${observer}"
  STEP_STATE_CHECKSUMS="\"roster_snapshot_sha256\":\"$(printf '%s' "${roster}" |
    hash_stdin)\""

  # The roster object exists on every node from startup and is non-null with
  # an empty peer list, so its presence proves nothing. What the negative
  # control is about is a specific operator becoming named blocking evidence,
  # so the two readings are differenced: an operator this node had not seen
  # before the driven post-C ceremony, alongside the refusal that put it
  # there. A generic refusal counter moving on its own could be any refusal at
  # all, including one with no cross-format announcement behind it.
  local new_operators
  new_operators="$(comm -13 <(printf '%s' "${operators_before}") \
    <(printf '%s' "${operators_after}") | tr '\n' ' ')"
  new_operators="${new_operators% }"

  if [[ "${refusals_after}" != "${refusals_before}" && -n "${new_operators}" ]]; then
    record_step "post-cutover straggler fails closed and enters the roster" \
      pass "R1 refusals rose from ${refusals_before} to ${refusals_after} and \
the node-local roster gained operator(s) ${new_operators}, so the straggler \
was refused and named rather than merely refused"
    record_assertion \
      "old post-C behavior fails closed and becomes operator-identified \
blocking evidence" true \
      "post-cutover straggler fails closed and enters the roster"
  elif [[ "${refusals_after}" != "${refusals_before}" ]]; then
    record_step "post-cutover straggler fails closed and enters the roster" \
      fail "R1 refusals rose from ${refusals_before} to ${refusals_after}, but \
the node-local roster named no operator it had not already seen; a refusal \
that does not become operator-identified evidence is not what this control \
is about"
    record_assertion \
      "old post-C behavior fails closed and becomes operator-identified \
blocking evidence" false \
      "post-cutover straggler fails closed and enters the roster"
  else
    record_step "post-cutover straggler fails closed and enters the roster" \
      blocked "no refusal and no new roster operator was observed; without a \
work driver originating post-C ceremonies the straggler never attempts one, \
so there is nothing for the R1 fleet to refuse"
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
  if [[ -z "${PR4109_WORK_DRIVER:-}" ]]; then
    block_step "homogeneous security-v2 controls with no legacy sightings" \
      "no PR4109_WORK_DRIVER was supplied, so no tBTC or beacon ceremony was \
originated on the rehearsal chain and there is nothing to observe"
  else
    # A zero legacy counter is true of a fleet that ran nothing at all, so the
    # positive control has to be positive about something: permits actually
    # issued under security-v2 while the driver ran. The count is taken before
    # and after so it is this step's ceremonies being counted rather than the
    # crossing's, and it is summed across the fleet because a control that
    # only watched one node would pass on a fleet where the others sat idle.
    local permits_before permits_after legacy_after
    permits_before="$(fleet_metric_total participation_mode_security_v2_total)"
    local driver_rc=0
    run_work_driver homogeneous-security-v2 || driver_rc=$?
    permits_after="$(fleet_metric_total participation_mode_security_v2_total)"
    legacy_after="$(fleet_metric_total participation_mode_legacy_total)"
    for service in "${REHEARSAL_R1_SERVICES[@]}"; do
      observe_gate_gauges "${service}"
    done

    if ((driver_rc != 0)); then
      record_step "homogeneous security-v2 controls with no legacy sightings" \
        fail "the work driver exited [${driver_rc}] originating post-C \
ceremonies"
      record_assertion \
        "post-C ceremonies run security-v2 with no legacy sightings" false \
        "homogeneous security-v2 controls with no legacy sightings"
    elif [[ ! "${permits_before}" =~ ^[0-9]+$ ]] ||
      [[ ! "${permits_after}" =~ ^[0-9]+$ ]] ||
      [[ ! "${legacy_after}" =~ ^[0-9]+$ ]]; then
      record_step "homogeneous security-v2 controls with no legacy sightings" \
        blocked "the fleet permit counters could not be read \
(security-v2 [${permits_before}] to [${permits_after}], legacy \
[${legacy_after}]), so nothing here observed which mode the ceremonies ran in"
      record_assertion \
        "post-C ceremonies run security-v2 with no legacy sightings" false \
        "homogeneous security-v2 controls with no legacy sightings"
    elif ((permits_after <= permits_before)); then
      record_step "homogeneous security-v2 controls with no legacy sightings" \
        fail "the work driver reported success but the fleet issued no new \
security-v2 permit (still ${permits_after}); a control that observes no \
ceremony is not a positive control"
      record_assertion \
        "post-C ceremonies run security-v2 with no legacy sightings" false \
        "homogeneous security-v2 controls with no legacy sightings"
    elif ((legacy_after > 0)); then
      record_step "homogeneous security-v2 controls with no legacy sightings" \
        fail "the fleet issued $((permits_after - permits_before)) new \
security-v2 permits but participation_mode_legacy_total is [${legacy_after}]"
      record_assertion \
        "post-C ceremonies run security-v2 with no legacy sightings" false \
        "homogeneous security-v2 controls with no legacy sightings"
    else
      STEP_PERMIT_MODES='"security_v2"'
      record_step "homogeneous security-v2 controls with no legacy sightings" \
        pass "the fleet issued $((permits_after - permits_before)) new \
security-v2 permits driving post-C ceremonies and no legacy permit at any \
point"
      record_assertion \
        "post-C ceremonies run security-v2 with no legacy sightings" true \
        "homogeneous security-v2 controls with no legacy sightings"
    fi
  fi

  # Step 7. Severing a node from the chain endpoint is a real clock failure:
  # the gate's synchronous read fails, and the release's contract is that it
  # refuses new work and cancels what it holds rather than guessing a side of
  # C.
  begin_step "clock failure quarantines work rather than guessing a mode"
  local clock_node="${REHEARSAL_R1_SERVICES[0]}"

  # The contract has two halves — refuse new work, and cancel what is already
  # held — and the second one needs something held. A node that was idle when
  # its clock failed evidences only the first.
  if [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
    run_work_driver clock-failure-inflight || true
  fi
  CLOCK_HELD_BEFORE="$(participation_field "${clock_node}" active_ceremonies \
    2>/dev/null || printf '')"
  CLOCK_ABORTS_BEFORE="$(metric_value "${clock_node}" \
    participation_clock_aborts_total || printf '')"
  CLOCK_PERMITS_BEFORE="$(metric_value "${clock_node}" \
    participation_mode_security_v2_total || printf '')"
  CLOCK_REFUSALS_BEFORE="$(metric_value "${clock_node}" \
    participation_refusals_total || printf '')"

  docker network disconnect "$(compose_project)_chain-egress" \
    "$(compose ps --quiet "${clock_node}")"
  deadline=$((SECONDS + 300))
  while :; do
    CLOCK_STATE="$(participation_field "${clock_node}" gate_state 2>/dev/null || true)"
    [[ "${CLOCK_STATE}" == "clock_unavailable" ]] && break
    ((SECONDS >= deadline)) && break
    sleep 5
  done
  observe_gate_gauges "${clock_node}"

  # The refusal half of the contract, attempted rather than inferred. Until
  # something asks this gate to start work while it cannot read the chain, an
  # unchanged permit counter says only that nothing was offered — which is
  # what a node holding no work looks like too. The node is severed from the
  # chain but still on the protocol network, so work originated now reaches it
  # as peer traffic and the gate is what decides whether it joins.
  CLOCK_REFUSAL_ATTEMPTED=0
  if [[ -n "${PR4109_WORK_DRIVER:-}" && "${CLOCK_STATE}" == "clock_unavailable" ]]; then
    run_work_driver clock-failure-refusal || true
    CLOCK_REFUSAL_ATTEMPTED=1
    # The offer travels peer-to-peer and the gate answers it on its own
    # schedule, so the counters are read after a settling window rather than
    # immediately, and the state is re-read to be sure the window was spent
    # with the clock still down.
    sleep 30
    CLOCK_STATE="$(participation_field "${clock_node}" gate_state \
      2>/dev/null || true)"
  fi

  CLOCK_HELD_AFTER="$(participation_field "${clock_node}" active_ceremonies \
    2>/dev/null || printf '')"
  CLOCK_ABORTS_AFTER="$(metric_value "${clock_node}" \
    participation_clock_aborts_total || printf '')"
  CLOCK_PERMITS_AFTER="$(metric_value "${clock_node}" \
    participation_mode_security_v2_total || printf '')"
  CLOCK_REFUSALS_AFTER="$(metric_value "${clock_node}" \
    participation_refusals_total || printf '')"

  # Reconnect before recording, so the verdict is decided with the node back
  # on the chain rather than leaving it severed if the branch below exits.
  docker network connect "$(compose_project)_chain-egress" \
    "$(compose ps --quiet "${clock_node}")"

  clock_failure_verdict

  # Step 8. Quiescence must hold both an in-flight legacy permit and an
  # in-flight security-v2 permit. The security-v2 half runs; the legacy half
  # needs the fork.
  begin_step "quiescence with an in-flight security-v2 permit"
  local quiesce_node="${REHEARSAL_R1_SERVICES[1]}"

  # The property is about a permit the node is holding while it is told to
  # stop, so one has to be in flight before the stop is issued. A node with
  # nothing running quiesces trivially and evidences nothing.
  if [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
    run_work_driver quiesce-inflight || true
  fi
  QUIESCE_HELD_BEFORE="$(participation_field "${quiesce_node}" \
    active_security_v2_ceremonies 2>/dev/null || printf '')"
  QUIESCE_FORCED_BEFORE="$(metric_value "${quiesce_node}" \
    participation_quiesce_forced_aborts_total || printf '')"
  QUIESCE_ISSUED_BEFORE="$(metric_value "${quiesce_node}" \
    participation_mode_security_v2_total || printf '')"

  if [[ ! "${QUIESCE_HELD_BEFORE}" =~ ^[0-9]+$ ]] ||
    ((QUIESCE_HELD_BEFORE == 0)); then
    block_step "quiescence with an in-flight security-v2 permit" \
      "${quiesce_node} held no security-v2 ceremony when the stop was due to \
be issued (active_security_v2_ceremonies [${QUIESCE_HELD_BEFORE:-unreadable}]); \
a node with nothing in flight quiesces trivially, so this needs work \
originated on the rehearsal chain that is still running at shutdown"
    record_assertion \
      "graceful quiescence starts no new work and lets held permits finish" \
      false "quiescence with an in-flight security-v2 permit"
  else
    # The same grace the manifest grants and the compose file declares, so the
    # node is not SIGKILLed before its own in-process backstop can finish what
    # it holds. A number restated here would go on stopping nodes under the
    # old ceiling the first time the reviewed bounds moved.
    QUIESCE_GRACE="$(manifest_termination_grace)"
    compose stop --timeout "${QUIESCE_GRACE}" "${quiesce_node}" &
    local stop_pid=$!

    # Watch the drain rather than sample its end: the contract is that no new
    # permit is issued from the moment quiescing begins and that the held ones
    # are left to finish, and both are statements about the whole window.
    local held_now forced_now issued_now state_now
    QUIESCE_STATE=""
    QUIESCE_ISSUED_AFTER="${QUIESCE_ISSUED_BEFORE}"
    QUIESCE_FORCED_AFTER="${QUIESCE_FORCED_BEFORE}"
    QUIESCE_DRAINED=0
    QUIESCE_ATTEMPTED=0
    deadline=$((SECONDS + QUIESCE_GRACE))
    while ((SECONDS < deadline)); do
      state_now="$(participation_field "${quiesce_node}" gate_state \
        2>/dev/null || true)"
      if [[ "${state_now}" == "quiescing" ]]; then
        QUIESCE_STATE="quiescing"
        # Offered once the node has actually entered quiescence, because the
        # property is what a quiescing node does with new work — and a node
        # that was never asked answers exactly like one that refused.
        if ((QUIESCE_ATTEMPTED == 0)) &&
          [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
          run_work_driver quiesce-refusal || true
          QUIESCE_ATTEMPTED=1
        fi
      fi
      held_now="$(participation_field "${quiesce_node}" \
        active_security_v2_ceremonies 2>/dev/null || printf '')"
      if [[ "${held_now}" =~ ^[0-9]+$ ]] && ((held_now == 0)); then
        QUIESCE_DRAINED=1
      fi
      issued_now="$(metric_value "${quiesce_node}" \
        participation_mode_security_v2_total 2>/dev/null || printf '')"
      if [[ "${issued_now}" =~ ^[0-9]+$ ]]; then
        QUIESCE_ISSUED_AFTER="${issued_now}"
      fi
      forced_now="$(metric_value "${quiesce_node}" \
        participation_quiesce_forced_aborts_total 2>/dev/null || printf '')"
      if [[ "${forced_now}" =~ ^[0-9]+$ ]]; then
        QUIESCE_FORCED_AFTER="${forced_now}"
      fi
      # The node going unreachable is the drain finishing, not a failure.
      node_reachable "${quiesce_node}" || break
      sleep 2
    done
    wait "${stop_pid}" || true

    quiescence_verdict "${quiesce_node}"
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
  # Where this run writes each drained node's captured state, not where it
  # reads someone else's: the audit below is only about the state this fleet
  # left behind, so the snapshots are taken from the stopped containers rather
  # than supplied. The operator still chooses the location, because the
  # captures outlive the rehearsal as the evidence the audit's verdict is over.
  mkdir -p "${STORAGE_SNAPSHOT_DIR}" ||
    blocked "cannot create STORAGE_SNAPSHOT_DIR at ${STORAGE_SNAPSHOT_DIR}; \
the offline state audit reads one captured snapshot per node and this run has \
nowhere to capture them to"
  # Only the release under test comes up. The prior binary is what this gate
  # exists to keep off the network until the barrier holds, so it is staged
  # without being started and released by the one step allowed to release it.
  stage_prior_container
  fleet_up "${REHEARSAL_R1_SERVICES[@]}"
  verify_running_images "${R1_IMAGE_DIGEST}" "${REHEARSAL_R1_SERVICES[@]}"
  # While there is still a fleet to ask. Every step below stops these nodes.
  capture_r1_release_identity

  # Step 1 and 2. Quiesce every R1 node, and prove no prior binary comes up
  # while they drain — the barrier the whole gate exists to establish.
  #
  # The two are one operation, because absence has to be watched across the
  # whole drain. A single probe taken after the drain would be satisfied by a
  # prior binary that participated for all of quiescence and stopped a second
  # before the probe ran, which is exactly the sequence the barrier forbids.
  begin_step "quiesce every R1 node with work represented"
  local service
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    observe_gate_gauges "${service}"
  done
  if [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
    run_work_driver rollback-inflight || true
  fi
  # The grace comes out of the reviewed manifest, which the Go drift test
  # pins to the compiled bounds and the compose file's stop_grace_period to.
  # A number restated here would go on stopping nodes under the old ceiling
  # the first time those bounds moved, and a node SIGKILLed mid-drain cannot
  # evidence natural completion.
  local grace
  grace="$(manifest_termination_grace)"

  local prior_samples=0 prior_sightings=0
  if node_reachable "${REHEARSAL_PRIOR_SERVICE}"; then
    prior_sightings=$((prior_sightings + 1))
  fi
  prior_samples=$((prior_samples + 1))

  # The drain runs in the background so the prior service can be sampled
  # while it is happening. The marker carries the drain's own exit status out
  # of the subshell: a `wait` that raced the reaper would report nothing, and
  # a drain that failed must not read as a completed quiescence.
  local drain_marker drain_deadline
  drain_marker="$(mktemp "${TMPDIR:-/tmp}/pr4109-drain.XXXXXX")"
  (
    drain_status=0
    compose stop --timeout "${grace}" "${REHEARSAL_R1_SERVICES[@]}" ||
      drain_status=$?
    printf '%s' "${drain_status}" >"${drain_marker}"
  ) &
  # Twice the grace plus a minute: the drain is bounded by the grace itself,
  # so a marker that has still not appeared by then means the writer died
  # without writing one and the sampling loop would otherwise never end.
  drain_deadline=$((SECONDS + 2 * grace + 60))
  until [[ -s "${drain_marker}" ]]; do
    if ((SECONDS >= drain_deadline)); then
      break
    fi
    if node_reachable "${REHEARSAL_PRIOR_SERVICE}"; then
      prior_sightings=$((prior_sightings + 1))
    fi
    prior_samples=$((prior_samples + 1))
    sleep 2
  done
  wait
  local drain_rc="no exit status"
  if [[ -s "${drain_marker}" ]]; then
    drain_rc="$(cat "${drain_marker}")"
  fi
  rm -f "${drain_marker}"

  # One last sample once the drain is over, so the watched window ends where
  # the barrier's precondition is finally established rather than a probe
  # earlier.
  if node_reachable "${REHEARSAL_PRIOR_SERVICE}"; then
    prior_sightings=$((prior_sightings + 1))
  fi
  prior_samples=$((prior_samples + 1))

  if [[ "${drain_rc}" == "0" ]]; then
    record_step "quiesce every R1 node with work represented" pass \
      "every R1 node was stopped under the reviewed manifest's ${grace}s \
termination grace, so a draining node was never SIGKILLed before its \
in-process backstop"
  else
    record_step "quiesce every R1 node with work represented" fail \
      "stopping the R1 nodes under the reviewed manifest's ${grace}s \
termination grace exited [${drain_rc}]; a drain that did not complete is not \
a quiescence and the state it left is not what the audit below reads"
    record_assertion \
      "every R1 node drains to a stop within the reviewed termination grace" \
      false "quiesce every R1 node with work represented"
  fi

  begin_step "no prior binary starts during quiescence"
  if ((prior_sightings > 0)); then
    record_step "no prior binary starts during quiescence" fail \
      "${REHEARSAL_PRIOR_SERVICE} answered on the rehearsal network in \
${prior_sightings} of ${prior_samples} samples taken across the drain"
    record_assertion \
      "no prior binary participates before every R1 node is down" false \
      "no prior binary starts during quiescence"
  else
    record_step "no prior binary starts during quiescence" pass \
      "${REHEARSAL_PRIOR_SERVICE} was absent in all ${prior_samples} samples \
taken from before the drain started to after it finished"
    record_assertion \
      "no prior binary participates before every R1 node is down" true \
      "no prior binary starts during quiescence"
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
  # repository's own tool and runs here for real, with the external evidence
  # and the operational identities it binds that evidence to.
  begin_step "offline state audit produces a rollback-safe manifest"
  local audit_failures=() audit_ready=1
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    local snapshot="${STORAGE_SNAPSHOT_DIR}/${service}"
    # Captured here, from the container the drain above stopped, so the audit's
    # verdict is over the state this rehearsal produced rather than over a
    # tree that merely arrived under the right name.
    if ! capture_storage_snapshot "${service}"; then
      audit_failures+=("${service}: ${SNAPSHOT_CAPTURE_REASON}")
      audit_ready=0
      continue
    fi
    if run_state_audit "${service}" "${snapshot}"; then
      STEP_STATE_CHECKSUMS="${STEP_STATE_CHECKSUMS}${STEP_STATE_CHECKSUMS:+,}\
\"${service}\":\"$(find "${snapshot}" -type f -exec cat {} + | hash_stdin)\""
    else
      audit_ready=0
      audit_failures+=("${service}: ${STATE_AUDIT_REASON}")
    fi
  done
  if ((audit_ready == 1)); then
    record_step "offline state audit produces a rollback-safe manifest" pass \
      "every R1 node's state was captured from the container the drain \
stopped and audited to rollback_barrier_ready=true against the supplied \
reconciliation, quiescence, and prior-reader evidence"
    record_assertion "the offline state audit passes before rollback" true \
      "offline state audit produces a rollback-safe manifest"
  else
    record_step "offline state audit produces a rollback-safe manifest" \
      blocked "${audit_failures[*]}"
    record_assertion "the offline state audit passes before rollback" false \
      "offline state audit produces a rollback-safe manifest"
  fi

  # Step 6. Release the prior digest, and only behind the whole barrier.
  #
  # Both halves are load-bearing and neither substitutes for the other. Every
  # R1 node being unreachable stops two releases from writing the same state
  # at once; the audit reporting rollback_barrier_ready is what says the state
  # they left is state the prior binary can safely read. Starting the prior
  # binary on the first alone is a rollback performed without knowing whether
  # it is safe, which is the failure this gate exists to catch.
  begin_step "stage the prior digest behind the all-candidate-down barrier"
  if ((${#still_up[@]} == 0 && audit_ready == 1)); then
    compose start "${REHEARSAL_PRIOR_SERVICE}"
    # The binary that was released has to be the prior artifact the audit
    # authorized rolling back to, not whatever the compose file resolved.
    verify_running_images "${PRIOR_IMAGE_DIGEST}" "${REHEARSAL_PRIOR_SERVICE}"
    record_step "stage the prior digest behind the all-candidate-down barrier" \
      pass "the prior binary was released only after every R1 node was proved \
unreachable and every snapshot audited rollback-safe, and the container that \
came up is the audited prior digest"
  elif ((${#still_up[@]} > 0)); then
    record_step "stage the prior digest behind the all-candidate-down barrier" \
      blocked "the barrier does not hold — ${still_up[*]} still answer — so \
the prior binary was deliberately not released"
  else
    record_step "stage the prior digest behind the all-candidate-down barrier" \
      blocked "every R1 node is down, but the offline state audit did not \
report rollback_barrier_ready for every snapshot, so the prior binary was \
deliberately not released; an all-down fleet says two releases cannot write \
at once, not that the state left behind is safe to roll back onto"
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

# Every record in the evidence directory, as an array in the caller's
# EVIDENCE_RECORDS. A top-level glob rather than a walk, so the attestation
# receipt's own documents in the subdirectory are never mistaken for records.
collect_evidence_records() {
  shopt -s nullglob
  EVIDENCE_RECORDS=("${EVIDENCE_DIR}"/*.json)
  shopt -u nullglob
}

# Is each record admissible — well formed, produced at the attested commit,
# and measured against the reviewed manifest? This decides nothing about
# whether the gates the records evidence were satisfied; that is a separate
# question, asked by assess_evidence_acceptance. Keeping the two apart is
# what lets a refused rehearsal still write and shape-check the record that
# says why it was refused, without the shape check reading as acceptance.
validate_evidence_records() {
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

  collect_evidence_records
  if ((${#EVIDENCE_RECORDS[@]} == 0)); then
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

  for record in "${EVIDENCE_RECORDS[@]}"; do
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

# Do the records show the gates held?
#
# Admissibility is not acceptance. A record whose shape, commit, and manifest
# binding are all correct can still say, in the fields the schema exists to
# carry, that a mandatory step failed or an acceptance assertion does not
# hold — and a release that reads only the shape checks would take that
# record as a satisfied gate. So the outcomes themselves are the verdict
# here, by the same ordering conclude_verdict uses: a failed step or a
# refused assertion refutes the gate, a blocked step leaves it unrehearsed,
# and only a record with none of the three is evidence a gate was satisfied.
assess_evidence_acceptance() {
  collect_evidence_records
  if ((${#EVIDENCE_RECORDS[@]} == 0)); then
    blocked "no evidence records found under ${EVIDENCE_DIR}; a rehearsal \
run that produced no record cannot be accepted"
  fi

  local refutations=() unrehearsed=()
  local record outcomes kind what
  for record in "${EVIDENCE_RECORDS[@]}"; do
    # Every non-passing outcome the record carries, one per line, as the
    # kind that decides the verdict and the human-readable thing it names.
    outcomes="$(node -e '
      const fs = require("fs");
      const record = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      const lines = [];
      for (const stage of record.stages || []) {
        if (stage.outcome === "fail") {
          lines.push("refuted\tstep " + JSON.stringify(stage.name));
        } else if (stage.outcome === "blocked") {
          lines.push("unrehearsed\tstep " + JSON.stringify(stage.name));
        }
      }
      for (const entry of record.assertions || []) {
        if (entry.holds !== true) {
          lines.push("refuted\tassertion " + JSON.stringify(entry.assertion));
        }
      }
      process.stdout.write(lines.join("\n"));
    ' "${record}")" ||
      fail "cannot read the step and assertion outcomes of ${record}"

    [[ -n "${outcomes}" ]] || continue
    while IFS="$(printf '\t')" read -r kind what; do
      case "${kind}" in
      refuted) refutations+=("${record##*/}: ${what}") ;;
      unrehearsed) unrehearsed+=("${record##*/}: ${what}") ;;
      esac
    done <<<"${outcomes}"
  done

  if ((${#refutations[@]} > 0)); then
    fail "the evidence refutes the gate it records — ${#refutations[@]} \
failed step(s) or refused assertion(s): ${refutations[*]}; these records are \
admissible evidence that the rehearsal did not hold, not a passing gate"
  fi
  if ((${#unrehearsed[@]} > 0)); then
    blocked "${#unrehearsed[@]} mandatory step(s) across these records never \
executed: ${unrehearsed[*]}; a gate whose steps did not all run has not been \
rehearsed, whatever the records that do exist show"
  fi

  note "every recorded step passed and every acceptance assertion holds"
}

stage_validate_evidence() {
  validate_evidence_records
  assess_evidence_acceptance
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
