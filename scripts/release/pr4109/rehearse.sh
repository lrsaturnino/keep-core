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
#   ETH_WS_URL           rehearsal chain websocket endpoint
#   CUTOVER_BLOCK        rehearsed cutover block C on that chain
#   KEYSTORE_DIR         per-node rehearsal inputs, one subdirectory per
#                        compose service holding that node's config.toml and
#                        operator key file
#   KEEP_ETHEREUM_PASSWORD  operator key file password for the fleet
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
# disagree in any direction the image build does not account for.
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
                      .dockerignore over every tracked path, and both
                      validator self-tests — the gate the scaffold's CI job
                      runs on every change to these files and to the build
                      inputs they mirror, so the checkers that admit
                      rehearsal evidence are never proved only by a manual
                      dispatch
  solidity-proofs     build and test the changed ECDSA contracts surface
                      exactly as the contracts workflow does: Node 18.15.0,
                      the Corepack-managed yarn from packageManager, and a
                      never-skipped 'yarn install --immutable' before
                      yarn build and yarn test
  preflight           validate the container-rehearsal inputs and image digests
  single-release      exact-image cutover rehearsal: prior+R1 mixed fleet
                      before C, work across C without restart, straggler
                      negative control, clock failure, quiesce with in-flight
                      permits  [BLOCKED until preflight passes]
  rollback            homogeneous rollback rehearsal: quiesce all R1,
                      all-candidate-down barrier, offline state audit, staged
                      prior redeploy, forbidden partial-rollback attempt
                      [BLOCKED until preflight passes]
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

# The .dockerignore rules the two classifications above mirror, compiled once
# per tree into one extended regular expression per pattern with a parallel
# flag marking the negations. They are read from the commit, not from disk:
# the build context of a dispatched commit is that commit's own tree, and
# inside the build image the file itself is one of the paths its own `.*`
# rule kept out.
DOCKERIGNORE_REGEX=()
DOCKERIGNORE_NEGATED=()

# Translate one normalized .dockerignore pattern into an extended regular
# expression over a whole context-relative path, following the build daemon's
# own compilation: `*` stops at a path separator, `?` is a single
# non-separator character, `**` spans any number of whole segments (`.*` when
# it ends the pattern), and every other character is literal. Backslash
# escapes are the one construct not modelled; load_dockerignore_patterns
# rejects a pattern carrying one before this ever sees it, because a failure
# raised here would run inside a command substitution and exit nothing but
# its own subshell.
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
    elif [[ '.[](){}+|^$' == *"${ch}"* ]]; then
      out+="\\${ch}"
    else
      out+="${ch}"
    fi
  done
  printf '%s$' "${out}"
}

# Compile the committed .dockerignore the way the build daemon reads it:
# lines opening with `#` are comments, surrounding whitespace is trimmed, a
# leading `!` splits off as a negation, and the remainder is path-cleaned of
# its leading and trailing separators.
load_dockerignore_patterns() {
  DOCKERIGNORE_REGEX=()
  DOCKERIGNORE_NEGATED=()

  local content
  if ! content="$(git -C "${REPO_ROOT}" show HEAD:.dockerignore 2>/dev/null)"; then
    fail "the commit under test carries no .dockerignore; the build-context \
classification in this script has nothing left to be checked against"
  fi

  local line negated
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
    fi
    while [[ "${line}" == /* ]]; do line="${line#/}"; done
    while [[ "${line}" == */ ]]; do line="${line%/}"; done
    [[ -n "${line}" ]] || continue
    # Checked here, in the shell that can still stop the run: the compiler
    # below runs inside a command substitution, where refusing would exit
    # only the subshell and leave the unmodelled pattern silently empty.
    [[ "${line}" != *$'\\'* ]] ||
      fail "the committed .dockerignore pattern [${line}] uses a backslash \
escape, which the build-context classification in this script does not model; \
extend dockerignore_pattern_regex before relying on it"
    DOCKERIGNORE_REGEX+=("$(dockerignore_pattern_regex "${line}")")
    DOCKERIGNORE_NEGATED+=("${negated}")
  done <<<"${content}"

  ((${#DOCKERIGNORE_REGEX[@]} > 0)) ||
    fail "the committed .dockerignore carries no pattern at all; the \
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
# mirror's verdict against the rules .dockerignore itself carries.
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
  load_dockerignore_patterns
  note "build-context mirror: checking this script's classification against \
the ${#DOCKERIGNORE_REGEX[@]} committed .dockerignore pattern(s)"

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
context-excluded path, but .dockerignore keeps it in the build context"$'\n'
    elif [[ "${context}" == 0 ]]; then
      if regenerated_by_design_path "${path}"; then
        regenerated=$((regenerated + 1))
      else
        drift+="${path}: .dockerignore keeps this path out of the build \
context, but this script neither excludes it nor treats it as regenerated"$'\n'
      fi
    fi
  done < <(git -C "${REPO_ROOT}" ls-tree -r -z --name-only HEAD)

  if [[ -n "${drift}" ]]; then
    printf '%s' "${drift}" >&2
    fail "the build-context classification in this script no longer mirrors \
.dockerignore (listing above); re-derive dockerignore_excluded_path and \
regenerated_by_design_path from the current build inputs before this scaffold \
admits any further evidence"
  fi

  note "build-context mirror: ${tracked} tracked path(s) classified \
identically by .dockerignore and this script (${excluded} kept out of the \
build context; ${regenerated} excluded from the context but regenerated into \
the image by design)"
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

  # The contracts workflow runs on exactly Node 18.15.0 because newer
  # releases have produced broken hardhat compile artifacts; evidence from
  # any other version is not that workflow's evidence.
  local ci_node_version="18.15.0"
  local node_version
  node_version=$(node -p 'process.versions.node')
  if [[ "${node_version}" != "${ci_node_version}" ]]; then
    blocked "the contracts workflow runs on Node ${ci_node_version} (found \
$(node -v)); switch with 'nvm install ${ci_node_version} && nvm use \
${ci_node_version}' before running solidity-proofs"
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

stage_preflight() {
  require_env PRIOR_IMAGE_DIGEST R1_IMAGE_DIGEST ETH_WS_URL CUTOVER_BLOCK \
    KEYSTORE_DIR KEEP_ETHEREUM_PASSWORD
  require_immutable_digest PRIOR_IMAGE_DIGEST "${PRIOR_IMAGE_DIGEST}"
  require_immutable_digest R1_IMAGE_DIGEST "${R1_IMAGE_DIGEST}"
  command -v docker >/dev/null 2>&1 || blocked "docker is required"
  [[ "${CUTOVER_BLOCK}" =~ ^[0-9]+$ && "${CUTOVER_BLOCK}" -gt 0 ]] ||
    blocked "CUTOVER_BLOCK must be a positive integer"
  [[ -d "${KEYSTORE_DIR}" ]] || blocked "KEYSTORE_DIR does not exist"
  for service in prior-node r1-node-1 r1-node-2; do
    [[ -f "${KEYSTORE_DIR}/${service}/config.toml" ]] ||
      blocked "KEYSTORE_DIR/${service}/config.toml is missing; every node \
needs its per-node config with the rehearsal contract addresses, key file \
path, and storage directory"
  done

  note "pulling both immutable digests to verify availability"
  docker pull "${PRIOR_IMAGE_DIGEST}"
  docker pull "${R1_IMAGE_DIGEST}"

  note "preflight passed"
}

stage_single_release() {
  stage_preflight

  # The exact-image cutover sequence requires a rehearsal chain with deployed
  # contracts, a mixed prior/R1 fleet with persistent volumes, and a
  # controlled crossing of C. The compose shell is compose.rehearsal.yaml;
  # the orchestration of the rehearsal steps (mixed pre-C controls, work
  # started across C, partition/restart, straggler negative control and
  # quarantine, homogeneous post-C controls, clock failure, quiescence with
  # in-flight permits) is deliberately not automated here yet: automating it
  # without a rehearsal chain to run against would produce untestable
  # automation.
  blocked "the exact-image cutover sequence needs a rehearsal chain with \
deployed beacon/tBTC contracts; supply one and extend this stage with the \
compose.rehearsal.yaml fleet before relying on it as release evidence"
}

stage_rollback() {
  stage_preflight

  # The rollback sequence additionally requires the offline state audit tool
  # run against every node's storage snapshot and an independent network
  # vantage point to prove the all-candidate-down barrier.
  blocked "the rollback sequence needs the exact-image cutover fleet plus \
storage snapshots and an independent network probe; supply them and extend \
this stage before relying on it as release evidence"
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
