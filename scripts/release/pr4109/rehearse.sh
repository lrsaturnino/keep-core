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
#   ETH_RPC_URL          the same chain's JSON-RPC endpoint, questioned to
#                        confirm every transaction a work driver reports;
#                        an unconfirmed report is the driver's own account
#                        of itself
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
#   PR4109_EVIDENCE_RECORD_SUFFIX
#                        optional safe filename component identifying the
#                        native runner (for example amd64 or arm64-v8). The
#                        dispatched workflow sets it so records from separate
#                        platform jobs remain unique when they are aggregated
#
# Rollback only — the audit inputs no storage snapshot can supply. Every one
# is required before the offline state audit can authorize anything, and a
# missing one blocks the barrier that releases the prior binary rather than
# being skipped:
#
#   PR4109_ROLLBACK_EVIDENCE_GENERATOR
#                        executable called once per drained node as
#                        <service> <identity-manifest> <output-directory>,
#                        after that node's state has been captured and
#                        audited for identity. It must write
#                        chain-reconciliation.json,
#                        bitcoin-reconciliation.json, quiescence-report.json,
#                        and prior-reader-compatibility.json into the output
#                        directory, each naming the identity manifest's
#                        snapshot_aggregate_sha256. The chain record must also
#                        contain signed successful receipt/log projections
#                        from the independently trusted collector named below.
#                        It is run rather than supplied as files because every
#                        record has to speak for the exact snapshot this run
#                        captured, and that snapshot does not exist until the
#                        fleet has drained
#   PR4109_WALLET_REGISTRY_ADDRESS
#                        exact WalletRegistry address whose logs establish DKG
#                        settlement
#   PR4109_RANDOM_BEACON_ADDRESS
#                        exact RandomBeacon address whose logs establish relay
#                        entry request, delivery, and timeout settlement
#   PR4109_FINALIZED_ETHEREUM_BLOCK_NUMBER
#   PR4109_FINALIZED_ETHEREUM_BLOCK_HASH
#                        independently obtained finalized-chain anchor the
#                        collector's canonical block set must end at
#   PR4109_CHAIN_EVIDENCE_PUBLIC_KEY
#                        lowercase hexadecimal Ed25519 public key provisioned
#                        independently from the evidence generator; its
#                        signature authenticates the complete chain record
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
#                        0x-prefixed 32-byte hashes and whose optional
#                        ceremony_results array carries {ceremony, outcome}
#                        objects: the terminal result of each ceremony those
#                        transactions started, which no fleet counter can
#                        supply because a permit says a node was allowed to
#                        begin and a positive control is about one finishing.
#                        A report that cannot be read stops the step rather
#                        than passing for nothing having happened
#   PR4109_TSSLIB_REVIEW archived independent cryptographic review of the
#                        dual-mode dependency revision go.mod resolves. It is
#                        never executed and gates no step: a rehearsal runs
#                        every mixed prior/R1 stage without it and records
#                        what it observed. What it decides is acceptance —
#                        whether those transcripts are release-authoritative.
#                        Its bytes must hash to the reviewed tsslib-review
#                        digest and the document must name the exact revision
#                        go.mod resolves
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
# stage enforces both, self-testing its own checker first. It also requires
# exactly one record for each single_release/rollback and published-platform
# pair; per-run emission validates only its own record, because no native
# runner can see another runner's workspace. Those comparisons only speak for
# the release while that manifest still matches the compiled
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
                      integration-tag compile proof; self-tests source binding,
                      evidence acceptance, native-runner dispatch, and the
                      fleet evidence-window capture first (node/npx required),
                      reports every skipped case explicitly, holds the
                      verifier's build-context
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
                      inputs they mirror, so the checkers and fleet-window
                      capture that admit rehearsal evidence are never proved
                      only by a manual dispatch
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
                      checker first. Requires exactly one record for every
                      single_release/rollback and published-platform pair,
                      rejecting a wholly missing gate and duplicate accounts.
                      Then asks the separate question the binding checks
                      cannot: a correctly bound record still says whether its
                      gate held, so the stage exits FAIL on any recorded
                      failed step or refused acceptance assertion and BLOCKED
                      on any step that never executed

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
  ETH_RPC_URL         the same chain's JSON-RPC endpoint, questioned to
                      confirm every reported transaction
  CUTOVER_BLOCK       rehearsed cutover block C on that chain
  CHAIN_ID            that chain's numeric chain id
  KEYSTORE_DIR        per-node inputs, one <service>/ directory each holding
                      that node's config.toml and key material
  PR4109_EVIDENCE_RECORD_SUFFIX
                      optional safe filename component identifying this
                      native runner; the workflow sets one per platform
  KEEP_ETHEREUM_PASSWORD
                      the key files' password
  PR4109_WORK_DRIVER  executable called with the phase name to originate
                      protocol work on the rehearsal chain; may report the
                      transactions it submitted as a JSON object with a
                      transaction_hashes array. The fleet only reacts to
                      chain events, so the steps that need a ceremony record
                      themselves blocked without one
  PR4109_TSSLIB_REVIEW
                      archived independent cryptographic review of the
                      dual-mode dependency revision go.mod resolves. Gates
                      acceptance of the emitted record, not execution of any
                      step

environment (rollback, additionally):
  STORAGE_SNAPSHOT_DIR
                      where this stage captures each drained node's state
                      from the container it stopped, for the offline audit
  PR4109_ROLLBACK_EVIDENCE_GENERATOR
                      executable run once per drained node as <service>
                      <identity-manifest> <output-directory>, after that
                      node's state is captured and audited for identity. It
                      writes the reconciliation, quiescence, and prior-reader
                      records the audit binds its verdict to, each naming the
                      snapshot the manifest identifies. From a snapshot alone
                      the audit reports namespace consistency and nothing
                      about rollback safety, and a record produced before the
                      drain could not name the snapshot the drain left
  PR4109_WALLET_REGISTRY_ADDRESS
                      exact WalletRegistry whose raw logs establish DKG state
  PR4109_RANDOM_BEACON_ADDRESS
                      exact RandomBeacon whose raw logs establish relay entry
                      request, delivery, and timeout settlement
  PR4109_FINALIZED_ETHEREUM_BLOCK_NUMBER
  PR4109_FINALIZED_ETHEREUM_BLOCK_HASH
                      independently obtained finalized block anchoring the
                      authenticated canonical block set
  PR4109_CHAIN_EVIDENCE_PUBLIC_KEY
                      lowercase hexadecimal Ed25519 public key of the trusted
                      finalized-chain evidence collector
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
  # The files .dockerignore negates back out of docs/ and scripts/ for the
  # tests that open them, which run inside the image: an absence here is the
  # missing input those tests fail on, never the image's construction. Listed
  # one for one with the negations so the two can be read against each other.
  if [[ "${path}" =~ ^docs/performance-metrics\.adoc$ ]] ||
    [[ "${path}" =~ ^scripts/release/pr4109/(compose\.rehearsal\.yaml|rehearsal-evidence\.schema\.json|release-manifest\.json|release-manifest\.schema\.json|release-provenance\.schema\.json)$ ]] ||
    [[ "${path}" =~ ^scripts/release/pr4109/deploy/keep-client-termination-grace\.(k8s-patch\.yaml|systemd-dropin\.conf)$ ]]; then
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

# The workflow that builds the artifact a cutover record binds its identity to.
RELEASE_WORKFLOW=".github/workflows/release.yml"
RELEASE_BUILD_JOB="build-and-release"
RELEASE_PUBLISH_JOB="publish-docker-images"
RELEASE_GITHUB_RELEASE_ACTION="softprops/action-gh-release"
RELEASE_DOCKER_TAG_STEP="docker-tags"
RELEASE_DOCKER_TAG_SELECTOR="scripts/release/pr4109/release-docker-tags.sh"
RELEASE_TRIGGER_TAG_RESOLVER="scripts/release/pr4109/release-trigger-tag.sh"

# The released artifact must name its source commit exactly.
#
# capture_r1_release_identity requires every R1 node's reported revision to
# equal the commit this run is bound to, and that requirement is only
# satisfiable while the workflow that builds the artifact stamps the whole SHA
# into it. An abbreviation names a commit only as far as it goes, and the
# record would bind a rehearsal's every observation to a prefix. So the stamp
# is read out of the release workflow rather than assumed: a bump back to
# `--short` is caught by this lint, on the commit that makes it, instead of by
# a rehearsal that refuses every artifact the release pipeline can produce.
verify_release_revision_stamp() {
  local content stamps abbreviated
  content="$(git -C "${REPO_ROOT}" show "HEAD:${RELEASE_WORKFLOW}" \
    2>/dev/null)" ||
    fail "the commit under test carries no ${RELEASE_WORKFLOW}; the source \
stamp every cutover record binds its artifact identity to is written there, \
and this script has nothing left to read it from"

  # Every assignment of the revision the build is stamped with, whatever job
  # or step it sits in: a release building two images from two jobs stamps it
  # twice, and one of them reverting is the whole failure this catches.
  stamps="$(printf '%s\n' "${content}" |
    { grep -nE '(^|[^[:alnum:]_])revision=\$\(' || true; })"
  if [[ -z "${stamps}" ]]; then
    fail "${RELEASE_WORKFLOW} assigns no revision from a command; the \
artifact identity a cutover record is measured against comes from that \
assignment, and a release that stopped making it stamps nothing this scaffold \
can bind to"
  fi

  abbreviated="$(printf '%s\n' "${stamps}" |
    { grep -vE 'git rev-parse HEAD\)' || true; })"
  if [[ -n "${abbreviated}" ]]; then
    printf '%s\n' "${abbreviated}" >&2
    fail "${RELEASE_WORKFLOW} stamps the released artifact with a revision \
this scaffold cannot bind to (lines above); every assignment must be \
\$(git rev-parse HEAD), because a rehearsal record names one commit and an \
abbreviation is not that commit"
  fi

  note "release stamp: ${RELEASE_WORKFLOW} writes the full source SHA into \
every artifact it builds ($(printf '%s\n' "${stamps}" | wc -l | tr -d ' ') \
assignment(s))"
}

# Verify one release job derives its version only from the exact tag ref that
# triggered the workflow. A commit may carry both a stable tag and a release-
# candidate tag, so repository tag discovery cannot identify the release the
# runner is processing. Both jobs must resolve the same GitHub event fields
# through the fail-closed helper and publish that exact result as `version`.
verify_release_job_trigger_identity() {
  local content="$1" job="$2" i body
  local trigger_ref_bindings=0 trigger_tag_bindings=0
  local resolver_invocations=0 version_exports=0 version_env_writes=0
  local expected_ref_binding="RELEASE_TRIGGER_REF: \${{ github.ref }}"
  local expected_tag_binding="RELEASE_TRIGGER_TAG: \${{ github.ref_name }}"
  local expected_version_export="echo \"version=\${version}\" >> \"\${GITHUB_ENV}\""
  local expected_image_label="version=\${{ env.version }}"
  local resolver_assignment="version=\"\$("
  local trigger_ref_argument="\"\${RELEASE_TRIGGER_REF}\""
  local trigger_tag_argument="\"\${RELEASE_TRIGGER_TAG}\""

  yaml_index_lines "${RELEASE_WORKFLOW}" "${content}"
  yaml_locate_job "${RELEASE_WORKFLOW}" "${job}"

  for ((i = YAML_JOB_START; i < YAML_JOB_END; i++)); do
    body="${YAML_BODIES[i]}"

    [[ "${body}" == "${expected_ref_binding}" ]] &&
      trigger_ref_bindings=$((trigger_ref_bindings + 1))
    [[ "${body}" == "${expected_tag_binding}" ]] &&
      trigger_tag_bindings=$((trigger_tag_bindings + 1))

    if [[ "${body}" == *"version="* && "${body}" == *'git describe'* ]]; then
      fail "${RELEASE_WORKFLOW}'s ${job} job derives the release version with \
git describe on line $((i + 1)); a commit can carry stable and prerelease \
tags simultaneously, so the release identity must come from the exact \
triggering tag"
    fi

    if [[ "${body}" == *'version='* && "${body}" == *'GITHUB_ENV'* ]]; then
      version_env_writes=$((version_env_writes + 1))
      if [[ "${body}" == "${expected_version_export}" ]]; then
        version_exports=$((version_exports + 1))
      else
        fail "${RELEASE_WORKFLOW}'s ${job} job writes a release version to \
GITHUB_ENV outside the exact triggering-tag export on line $((i + 1)); a \
later write can replace the identity the resolver proved"
      fi
    fi

    if [[ "${body}" == version:* ]]; then
      fail "${RELEASE_WORKFLOW}'s ${job} job declares a separate version \
environment value on line $((i + 1)); the triggering-tag resolver must be the \
only release-identity source"
    fi
    if [[ "${body}" == version=* &&
      "${body}" != *"./${RELEASE_TRIGGER_TAG_RESOLVER}"* &&
      "${body}" != "${expected_image_label}" ]]; then
      fail "${RELEASE_WORKFLOW}'s ${job} job reassigns version outside the \
triggering-tag resolver on line $((i + 1)); the selector and release action \
must consume the identity the resolver returned"
    fi

    if [[ "${body}" == *"./${RELEASE_TRIGGER_TAG_RESOLVER}"* ]]; then
      resolver_invocations=$((resolver_invocations + 1))
      if [[ "${body}" != *"${resolver_assignment}"* ||
        "${body}" != *"${trigger_ref_argument}"* ||
        "${body}" != *"${trigger_tag_argument}"* ]]; then
        fail "${RELEASE_WORKFLOW}'s ${job} job does not assign version from \
${RELEASE_TRIGGER_TAG_RESOLVER} with both exact triggering-ref inputs on line \
$((i + 1))"
      fi
    fi
  done

  ((trigger_ref_bindings == 1)) ||
    fail "${RELEASE_WORKFLOW}'s ${job} job binds RELEASE_TRIGGER_REF to \
github.ref [${trigger_ref_bindings}] times; exactly one binding is required"
  ((trigger_tag_bindings == 1)) ||
    fail "${RELEASE_WORKFLOW}'s ${job} job binds RELEASE_TRIGGER_TAG to \
github.ref_name [${trigger_tag_bindings}] times; exactly one binding is \
required"
  ((resolver_invocations == 1)) ||
    fail "${RELEASE_WORKFLOW}'s ${job} job invokes \
${RELEASE_TRIGGER_TAG_RESOLVER} [${resolver_invocations}] times; exactly one \
invocation must derive its release identity"
  ((version_exports == 1)) ||
    fail "${RELEASE_WORKFLOW}'s ${job} job exports the resolved triggering tag \
as version [${version_exports}] times; exactly one GITHUB_ENV export is \
required"
  ((version_env_writes == 1)) ||
    fail "${RELEASE_WORKFLOW}'s ${job} job writes version to GITHUB_ENV \
[${version_env_writes}] times; exactly one triggering-tag export is required"
}

# A prerelease image must be available by its versioned tag without moving the
# mutable aliases operators use for stable production releases. The release
# workflow therefore derives one identity from the triggering tag in both
# release jobs and delegates its complete Docker tag set to one tested
# selector: exact vMAJOR.MINOR.PATCH tags receive the stable aliases and every
# other accepted Docker tag receives only its versioned name. The GitHub
# release prerelease decision must consume that same identity.
verify_release_candidate_tag_isolation() {
  local content i body selector_steps selector_invocations
  local raw_tags expected_tags raw_prerelease expected_prerelease
  local version_argument="\"\${version}\""
  content="$(git -C "${REPO_ROOT}" show "HEAD:${RELEASE_WORKFLOW}" \
    2>/dev/null)" ||
    fail "the commit under test carries no ${RELEASE_WORKFLOW}; there is no \
release publication path to verify for prerelease alias isolation"

  verify_release_job_trigger_identity "${content}" "${RELEASE_BUILD_JOB}"
  verify_release_job_trigger_identity "${content}" "${RELEASE_PUBLISH_JOB}"

  yaml_index_lines "${RELEASE_WORKFLOW}" "${content}"
  yaml_locate_job "${RELEASE_WORKFLOW}" "${RELEASE_PUBLISH_JOB}"

  selector_steps=0
  selector_invocations=0
  for ((i = YAML_JOB_START; i < YAML_JOB_END; i++)); do
    body="${YAML_BODIES[i]}"
    [[ "${body}" == "id: ${RELEASE_DOCKER_TAG_STEP}" ]] &&
      selector_steps=$((selector_steps + 1))

    if [[ "${body}" == *"./${RELEASE_DOCKER_TAG_SELECTOR}"* ]]; then
      selector_invocations=$((selector_invocations + 1))
      [[ "${body}" == *"${version_argument}"* ]] ||
        fail "${RELEASE_WORKFLOW}'s ${RELEASE_PUBLISH_JOB} job does not pass \
the exact triggering-tag version to ${RELEASE_DOCKER_TAG_SELECTOR} on line \
$((i + 1))"
    fi

    if [[ "${body}" == *':latest'* || "${body}" == *':mainnet'* ]]; then
      fail "${RELEASE_WORKFLOW}'s ${RELEASE_PUBLISH_JOB} job hard-codes a \
mutable Docker alias on line $((i + 1)); all tags must come from \
${RELEASE_DOCKER_TAG_SELECTOR}, whose stable-release test keeps prereleases \
off latest and mainnet"
    fi
  done

  ((selector_steps == 1)) ||
    fail "${RELEASE_WORKFLOW}'s ${RELEASE_PUBLISH_JOB} job has \
${selector_steps} steps with id ${RELEASE_DOCKER_TAG_STEP}; exactly one step \
must resolve the complete tag set"

  ((selector_invocations == 1)) ||
    fail "${RELEASE_WORKFLOW}'s ${RELEASE_PUBLISH_JOB} job invokes \
${RELEASE_DOCKER_TAG_SELECTOR} [${selector_invocations}] times; exactly one \
invocation must decide the complete published tag set"

  yaml_body_carries "${YAML_JOB_START}" "${YAML_JOB_END}" 'GITHUB_OUTPUT' ||
    fail "${RELEASE_WORKFLOW}'s ${RELEASE_PUBLISH_JOB} job does not write the \
selected Docker tags to GITHUB_OUTPUT"

  yaml_locate_action_step "${RELEASE_WORKFLOW}" "${BUILD_ACTION}" \
    "${YAML_JOB_START}" "${YAML_JOB_END}"
  raw_tags="$(yaml_step_input tags)" ||
    fail "the ${BUILD_ACTION} step in ${RELEASE_WORKFLOW}'s \
${RELEASE_PUBLISH_JOB} job publishes no tag set"
  raw_tags="${raw_tags#"${raw_tags%%[![:space:]]*}"}"
  raw_tags="${raw_tags%"${raw_tags##*[![:space:]]}"}"

  # The expression is workflow syntax, not a shell expansion.
  # shellcheck disable=SC2016
  expected_tags='${{ steps.docker-tags.outputs.tags }}'
  [[ "${raw_tags}" == "${expected_tags}" ]] ||
    fail "the ${BUILD_ACTION} step in ${RELEASE_WORKFLOW}'s \
${RELEASE_PUBLISH_JOB} job publishes [${raw_tags}] instead of the complete \
output of ${RELEASE_DOCKER_TAG_STEP}; another tag source could move stable \
aliases during a prerelease"

  yaml_index_lines "${RELEASE_WORKFLOW}" "${content}"
  yaml_locate_job "${RELEASE_WORKFLOW}" "${RELEASE_BUILD_JOB}"
  yaml_locate_action_step "${RELEASE_WORKFLOW}" \
    "${RELEASE_GITHUB_RELEASE_ACTION}" "${YAML_JOB_START}" "${YAML_JOB_END}"
  raw_prerelease="$(yaml_step_input prerelease)" ||
    fail "the ${RELEASE_GITHUB_RELEASE_ACTION} step in ${RELEASE_WORKFLOW}'s \
${RELEASE_BUILD_JOB} job makes no prerelease decision"
  raw_prerelease="${raw_prerelease#"${raw_prerelease%%[![:space:]]*}"}"
  raw_prerelease="${raw_prerelease%"${raw_prerelease##*[![:space:]]}"}"

  # The expression is workflow syntax, not a shell expansion.
  # shellcheck disable=SC2016
  expected_prerelease="\${{ contains(env.version, '-') }}"
  [[ "${raw_prerelease}" == "${expected_prerelease}" ]] ||
    fail "the ${RELEASE_GITHUB_RELEASE_ACTION} step in ${RELEASE_WORKFLOW}'s \
${RELEASE_BUILD_JOB} job derives prerelease from [${raw_prerelease}] instead \
of the exact triggering-tag identity [${expected_prerelease}]"

  note "release tags: both release jobs derive identity from the exact \
triggering tag; ${RELEASE_WORKFLOW} publishes exactly the tag set from \
${RELEASE_DOCKER_TAG_SELECTOR}, and prereleases remain version-only"
}

# The dispatch input a release run hands the detached provenance in, the
# variable attest_release_provenance reads it from, and the member it writes
# into the receipt. The producer and the acceptance consumer are what define
# these three; they are named here so the check below can hold the dispatched
# workflow to them.
RELEASE_PROVENANCE_INPUT="release_provenance_b64"
RELEASE_PROVENANCE_ENV="PR4109_RELEASE_PROVENANCE"
RELEASE_PROVENANCE_MEMBER="release-provenance.json"

# The job that produces the receipt, and the job that is judged by it.
REHEARSAL_PROOF_JOB="local-proofs"
REHEARSAL_CONTAINER_JOB="container-rehearsal"

# Does any content line in [from, to) carry the given text? Comments and blank
# lines are blanked by the indexer, so a check written on this can never be
# satisfied by a line the workflow parser does not read — which matters here,
# where every needle is a name a comment would naturally mention.
yaml_body_carries() {
  local from="$1" to="$2" needle="$3" i
  for ((i = from; i < to; i++)); do
    if [[ "${YAML_BODIES[i]}" == *"${needle}"* ]]; then
      return 0
    fi
  done
  return 1
}

# The dispatched rehearsal must be able to supply the half of the release
# identity the reviewed manifest cannot state about itself.
#
# A reviewed manifest names the cutover. It cannot name the commit finally
# built or the immutable image digests, because those are outputs of a build
# over its own bytes, so acceptance requires them from a detached document
# instead — and refuses, unconditionally, any release-ready receipt that
# carries none. Every one of those requirements lives in this script, and none
# of them is satisfiable by a dispatch with no way to hand the document in.
#
# That is a failure with no local symptom: every proof passes, the receipt is
# archived, and the refusal arrives only on the one dispatch that matters, at
# the end of a rehearsal that has already run every mandatory step. So the
# wiring is read out of the workflow here, on the commit that changes it,
# rather than discovered by the release it would block.
verify_release_provenance_wiring() {
  local content i
  content="$(git -C "${REPO_ROOT}" show "HEAD:${REHEARSAL_WORKFLOW}" \
    2>/dev/null)" ||
    fail "the commit under test carries no ${REHEARSAL_WORKFLOW}; the \
dispatch that supplies the detached release provenance is declared there, and \
this script has nothing left to read it from"

  yaml_index_lines "${REHEARSAL_WORKFLOW}" "${content}"
  local total="${#YAML_BODIES[@]}"

  # A mapping key of its own, matched whole: a step body mentioning the input
  # is a use of it and not a declaration, and only the declaration puts the
  # field in front of whoever dispatches the release.
  local declared=""
  for ((i = 0; i < total; i++)); do
    if [[ "${YAML_BODIES[i]}" == "${RELEASE_PROVENANCE_INPUT}:" ]]; then
      declared="yes"
      break
    fi
  done
  [[ -n "${declared}" ]] ||
    fail "${REHEARSAL_WORKFLOW} declares no ${RELEASE_PROVENANCE_INPUT} \
input; acceptance refuses every record measured against a release-ready \
manifest whose receipt names no artifact, so a dispatch with nowhere to put \
the detached provenance cannot produce admissible release evidence"

  yaml_locate_job "${REHEARSAL_WORKFLOW}" "${REHEARSAL_PROOF_JOB}"
  local proof_start="${YAML_JOB_START}" proof_end="${YAML_JOB_END}"

  yaml_body_carries "${proof_start}" "${proof_end}" \
    "inputs.${RELEASE_PROVENANCE_INPUT}" ||
    fail "${REHEARSAL_WORKFLOW}'s ${REHEARSAL_PROOF_JOB} job never reads the \
${RELEASE_PROVENANCE_INPUT} input; a declared input nothing consumes is a \
field an operator fills in and a release nobody can identify"

  yaml_body_carries "${proof_start}" "${proof_end}" \
    "${RELEASE_PROVENANCE_ENV}" ||
    fail "${REHEARSAL_WORKFLOW}'s ${REHEARSAL_PROOF_JOB} job never passes \
${RELEASE_PROVENANCE_ENV} to the stage that writes the receipt; the producer \
reads the document from that variable and records none without it, whatever \
the dispatch supplied"

  yaml_body_carries "${proof_start}" "${proof_end}" \
    "${RELEASE_PROVENANCE_MEMBER}" ||
    fail "${REHEARSAL_WORKFLOW}'s ${REHEARSAL_PROOF_JOB} job never requires \
${RELEASE_PROVENANCE_MEMBER} of the receipt it archives; a supplied document \
that did not reach the receipt leaves the archive unable to admit container \
evidence, and a green job saying otherwise"

  yaml_locate_job "${REHEARSAL_WORKFLOW}" "${REHEARSAL_CONTAINER_JOB}"
  yaml_body_carries "${YAML_JOB_START}" "${YAML_JOB_END}" \
    "${RELEASE_PROVENANCE_MEMBER}" ||
    fail "${REHEARSAL_WORKFLOW}'s ${REHEARSAL_CONTAINER_JOB} job never checks \
the receipt it downloads for ${RELEASE_PROVENANCE_MEMBER}; without it a \
rehearsal drives a fleet through every mandatory step before its own emitter \
refuses the run for an input the dispatch could have been given"

  note "release provenance: ${REHEARSAL_WORKFLOW} offers \
${RELEASE_PROVENANCE_INPUT}, hands it to the proof stage as \
${RELEASE_PROVENANCE_ENV}, and requires ${RELEASE_PROVENANCE_MEMBER} of the \
receipt in both the producing and the consuming job"
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
        "${RELEASE_WORKFLOW}" \
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

# The reviewed digests of the programs this rehearsal executes but does not
# contain, read out of the checked-in control file. Empty when the file names
# no digest for that program.
reviewed_input_digest() {
  local program="$1" file digest="" hash name
  file="${2:-${SCRIPT_DIR}/chain-inputs.sha256}"
  [[ -f "${file}" ]] || {
    printf ''
    return 0
  }
  while read -r hash name; do
    [[ -n "${hash}" && "${hash#\#}" == "${hash}" ]] || continue
    [[ "${name}" == "${program}" ]] || continue
    [[ "${hash}" =~ ^[0-9a-f]{64}$ ]] || continue
    digest="${hash}"
    break
  done <"${file}"
  printf '%s' "${digest}"
}

# The digests of the programs this run was actually handed, recorded so the
# evidence names the instruments it was produced with.
WORK_DRIVER_DIGEST=""
ROLLBACK_GENERATOR_DIGEST=""

# The digest of the archived independent cryptographic review of the pinned
# dual-mode dependency, when one was supplied. Unlike the two above this is not
# an instrument the rehearsal runs: it is a release input the recorded evidence
# is accepted against, so it may be absent from an execution that still runs
# every step.
TSSLIB_REVIEW_DIGEST=""

# The immutable dependency revision the build actually resolves.
#
# Read out of go.mod rather than restated, so a review record can only ever be
# bound to the revision this tree compiles against. Restating the commit here
# would let the pin move under a review record that still names the old one,
# which is the exact substitution the binding exists to prevent.
pinned_tsslib_commit() {
  local line commit=""
  while read -r line; do
    case "${line}" in
    *"github.com/bnb-chain/tss-lib =>"*)
      # The pseudo-version's trailing revision, e.g.
      # v0.0.0-20260729021955-d847ce003019 -> d847ce003019.
      commit="${line##*-}"
      break
      ;;
    esac
  done <"${REPO_ROOT}/go.mod"
  printf '%s' "${commit}"
}

# Bind one supplied review record to its reviewed digest and to the exact
# dependency revision it reviews, or refuse to accept it.
#
# A review record is an external document, and a document asserting that some
# revision was reviewed says nothing about the revision this tree builds. Two
# separate bindings are therefore required: the bytes must hash to a digest
# reviewed in a commit of this repository, and the document must name the
# commit go.mod resolves. Either alone admits a review of other code.
require_reviewed_record() {
  local variable="$1" program="$2" path="$3" control="${4:-}"
  local reviewed actual commit
  [[ -n "${path}" ]] || {
    printf ''
    return 0
  }
  [[ -f "${path}" && -r "${path}" ]] ||
    blocked "${variable} points at ${path}, which is not a readable file; a \
review record that cannot be read cannot be bound to anything"
  reviewed="$(reviewed_input_digest "${program}" "${control}")"
  [[ -n "${reviewed}" ]] ||
    blocked "no reviewed SHA-256 for ${program} is recorded in \
${SCAFFOLD_DIR}/chain-inputs.sha256, so the record supplied through \
${variable} is unbound; an unreviewed document asserting that the dependency \
was reviewed is the assertion this gate exists to check, not evidence for it"
  actual="$(hash_stdin <"${path}")"
  [[ "${actual}" == "${reviewed}" ]] ||
    blocked "the record supplied through ${variable} hashes to ${actual}, and \
${SCAFFOLD_DIR}/chain-inputs.sha256 pins ${program} at ${reviewed}; a \
rehearsal cannot accept a review record other than the reviewed one"
  commit="$(pinned_tsslib_commit)"
  [[ -n "${commit}" ]] ||
    blocked "go.mod resolves no github.com/bnb-chain/tss-lib replacement, so \
there is no dependency revision for the record supplied through ${variable} \
to be bound to"
  grep -qF "${commit}" "${path}" ||
    blocked "the record supplied through ${variable} does not name the \
dependency revision [${commit}] that go.mod resolves; a review of another \
revision is not a review of the code this rehearsal runs"
  printf '%s' "${actual}"
}

# Bind one supplied program to its reviewed digest, or refuse to run it.
#
# Both of these arrive from a mutable secret bundle, and both produce readings
# that become release evidence: the driver's account of what it originated and
# what became of it is the entire terminal half of every control that watches
# work settle. An executable bit is not provenance, and an internally
# consistent report from the wrong program passes every check in this
# repository. So the bytes are hashed here and compared against a digest
# reviewed in a commit, and a mismatch stops the rehearsal rather than
# producing a record naming an instrument nobody reviewed.
require_reviewed_input() {
  local variable="$1" program="$2" path="$3" control="${4:-}" reviewed actual
  [[ -n "${path}" ]] || {
    printf ''
    return 0
  }
  [[ -x "${path}" ]] ||
    blocked "${variable} points at ${path}, which is not an executable \
program; the rehearsal cannot drive work with it and cannot record what it did"
  reviewed="$(reviewed_input_digest "${program}" "${control}")"
  [[ -n "${reviewed}" ]] ||
    blocked "no reviewed SHA-256 for ${program} is recorded in \
${SCAFFOLD_DIR}/chain-inputs.sha256, so the program supplied through \
${variable} is unbound; its report is the terminal half of every control that \
watches work settle, and an unreviewed program produces an internally \
consistent passing account that every check in this repository accepts"
  actual="$(hash_stdin <"${path}")"
  [[ "${actual}" == "${reviewed}" ]] ||
    blocked "the program supplied through ${variable} hashes to ${actual}, \
and ${SCAFFOLD_DIR}/chain-inputs.sha256 pins ${program} at ${reviewed}; a \
rehearsal cannot record evidence produced by a program other than the \
reviewed one"
  printf '%s' "${actual}"
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

  # Validity is not readiness. A manifest is valid throughout development, but
  # it cannot anchor a release-acceptance decision until the values that do not
  # exist during development — the cutover block, the commit finally built, the
  # image digests acceptance ran against — have been reviewed and recorded. The
  # binary's own --release-ready mode is what answers that, and the answer is
  # recorded here, inside the source-bound tree where the toolchain is, so the
  # acceptance stage can refuse a placeholder without carrying one of its own.
  #
  # A manifest that is not ready does not fail this stage. Development runs
  # legitimately have one, and everything proved above is about the code rather
  # than about the release identity. The verdict is written down instead, and
  # refusing on it is the acceptance stage's decision to take.
  if go run . release-manifest validate --manifest "${manifest}" \
    --release-ready >"${staging}/release-ready.log" 2>&1; then
    printf 'yes\n' >"${staging}/release-ready.txt"
  else
    printf 'no\n' >"${staging}/release-ready.txt"
    note "ATTENTION: the reviewed release manifest is not release-ready;" \
      "no release-acceptance decision may be taken against it:"
    # Only the violations. The whole log stays in the receipt, but the
    # command-line usage the failing subcommand prints after them would
    # bury the lines an operator is reading this for.
    sed '/^Usage:/,$d' "${staging}/release-ready.log" |
      sed 's/^/>>   /'
  fi

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

  attest_release_provenance "${manifest}" "${staging}"

  rm -rf "${dir}"
  mv "${staging}" "${dir}"

  note "release-manifest attestation written to ${dir} for source \
$(tr -d '[:space:]' <"${dir}/source-commit.txt")"
}

# Take the detached provenance into the receipt, when the operator supplied
# one.
#
# The reviewed manifest names the cutover; it cannot name what was built to run
# it. Those values are outputs of a build over the manifest's own bytes, so
# recording them in the tree would require the tree to contain a hash of itself
# — write the commit and the commit changes. They live in a document generated
# after the build instead, and PR4109_RELEASE_PROVENANCE is where a release run
# points at it.
#
# Copied into the receipt rather than read from its original path at acceptance
# time: the receipt is the run's own sealed account, and a path re-read later
# is a file that may have been rewritten in between. The hash goes in beside it
# so the acceptance stage can say which document this was.
#
# A run without provenance writes none and is not refused here. Development
# runs legitimately have no build to describe, and the acceptance stage is
# where the absence becomes a refusal — for the same reason the readiness
# verdict is recorded rather than enforced here.
attest_release_provenance() {
  local manifest="$1" staging="$2"
  local provenance="${PR4109_RELEASE_PROVENANCE:-}"

  if [[ -z "${provenance}" ]]; then
    note "no detached release provenance supplied \
(PR4109_RELEASE_PROVENANCE); the receipt will carry none, and the acceptance \
stage refuses release evidence without it"
    return
  fi

  [[ -f "${provenance}" ]] ||
    fail "PR4109_RELEASE_PROVENANCE names [${provenance}], which is not a \
readable file"

  # The whole point of the document is that it is not in the tree it
  # describes. A tracked file would put the source commit back inside the
  # commit it names, which is the impossibility this split exists to remove —
  # and it would do it quietly, since every check downstream would still pass
  # against whatever stale hash the tree happened to carry.
  if git -C "${REPO_ROOT}" ls-files --error-unmatch "${provenance}" \
    >/dev/null 2>&1; then
    fail "the detached release provenance [${provenance}] is tracked in this \
repository; it records the commit built from this tree and the images built \
out of it, so committing it would require the tree to contain a hash of \
itself. Generate it after the build, outside the checkout"
  fi

  # The binary's own reviewed check: the manifest against the compiled bounds
  # and against readiness, the provenance against its shape, and the pair
  # against the manifest hash recorded inside the provenance.
  go run . release-manifest verify-provenance \
    --manifest "${manifest}" --provenance "${provenance}" ||
    fail "the detached release provenance [${provenance}] does not verify \
against ${manifest}"

  cp "${provenance}" "${staging}/release-provenance.json"
  hash_stdin <"${provenance}" >"${staging}/release-provenance.sha256"

  note "detached release provenance recorded in the receipt \
(sha256 $(tr -d '[:space:]' <"${staging}/release-provenance.sha256"))"
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
  # The workflow's own dispatch validator is extracted and driven over valid
  # and hostile provenance/chain mappings. This keeps an invalid dispatch from
  # reaching the expensive platform jobs merely because no container
  # rehearsal happened to exercise that input shape.
  "${SCRIPT_DIR}/test-rehearsal-matrix.sh"
  # The go/no-go roster path is process-signaled and log-authored rather than
  # exposed through the diagnostics API. Its capture helper is driven against
  # a fake two-node Docker boundary so an ignored signal, failed delivery, or
  # missing empty/cadenced evidence can never look like an empty ready fleet.
  "${SCRIPT_DIR}/test-cutover-evidence-window.sh"
  # The readiness verdict this stage is about to write is the one thing in the
  # receipt the validator suite cannot prove: that suite hand-authors the
  # verdict file, so it holds the refusal without ever running the producer.
  # This proves the seam instead — the recorded verdict against the binary's
  # own answer, and the produced receipt through the consumer that gates on it.
  # It runs here rather than in the shell-analysis gate because it needs the Go
  # toolchain to ask the binary, which is the whole point of the assertion.
  "${SCRIPT_DIR}/test-attest-release-manifest.sh"
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
  # The inactivity claim lifecycle publishes from one goroutine per controlled
  # member and shares a call-wide chain subscription and an atomic submission
  # record between them, so its tests only have teeth under the race detector.
  # The filter is deliberate rather than a whole-package run: pkg/tbtc carries
  # race warnings and a load-dependent block counter flake that reproduce at
  # this branch's merge base, and a gate that is red before the release changes
  # anything cannot report on them. Everything outside this filter is covered
  # by the ordinary suite and by CI's scheduled whole-tree race job.
  go test -count=1 -race -timeout 900s -v \
    -run 'Cutover|HandleAnnouncerSessionMismatch|InactivityClaim|SubmitClaim' \
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
    blocked "git is required by the source-binding and evidence-record \
validator self-tests"

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
    verify_release_revision_stamp
    verify_release_candidate_tag_isolation
    # And the one piece of the release path whose absence has no local
    # symptom: a dispatch that cannot hand in the detached provenance passes
    # every proof and produces evidence acceptance refuses.
    verify_release_provenance_wiring

    # The two validators gate every piece of rehearsal evidence, so the gate
    # that runs on every change to them runs their self-tests too — without
    # this they are proved only by the manually dispatched proof stages,
    # which is to say only when somebody remembers.
    note "source-binding verifier self-test"
    "${SCRIPT_DIR}/test-source-binding.sh"
    note "release Docker-tag selector self-test"
    "${SCRIPT_DIR}/test-release-docker-tags.sh"
    note "evidence-record validator self-test"
    "${SCRIPT_DIR}/test-validate-evidence.sh"
    note "native-runner matrix validator self-test"
    "${SCRIPT_DIR}/test-rehearsal-matrix.sh"
    note "cutover evidence-window capture self-test"
    "${SCRIPT_DIR}/test-cutover-evidence-window.sh"
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

# This bounds only the client-info readiness probe after Compose starts a
# process. It is not a service-manager termination grace: every R1 stop derives
# that independently reviewed bound from release-manifest.json.
NODE_REACHABILITY_TIMEOUT_SECONDS=600

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

# One JSON-RPC call against the rehearsal chain, from the egress network the
# fleet reaches the chain over — the same reachability the nodes have, so an
# endpoint this rehearsal can question is one they could act on.
chain_rpc() {
  local method="$1" params="$2"
  docker run --rm --network "$(compose_project)_chain-egress" \
    "${PROBE_IMAGE_DIGEST}" \
    wget --quiet --output-document=- --timeout=10 \
    --header='Content-Type: application/json' \
    --post-data="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\
\"params\":${params}}" \
    "${ETH_RPC_URL}" 2>/dev/null
}

# What the chain says became of one transaction: "succeeded <block>",
# "reverted <block>", "pending" while no receipt exists yet, or "unreadable"
# when the endpoint could not be questioned or did not answer in a form this
# rehearsal can read.
transaction_receipt() {
  local tx="$1" response
  response="$(chain_rpc eth_getTransactionReceipt "[\"${tx}\"]")" || {
    printf 'unreadable'
    return 0
  }
  printf '%s' "${response}" | node -e '
    let raw = "";
    process.stdin.on("data", (d) => (raw += d));
    process.stdin.on("end", () => {
      let body;
      try {
        body = JSON.parse(raw);
      } catch (e) {
        process.stdout.write("unreadable");
        return;
      }
      if (body === null || typeof body !== "object" || body.error) {
        process.stdout.write("unreadable");
        return;
      }
      const receipt = body.result;
      if (receipt === null || receipt === undefined) {
        process.stdout.write("pending");
        return;
      }
      const status = receipt.status;
      const block = receipt.blockNumber;
      if (typeof status !== "string" || typeof block !== "string" ||
        !/^0x[0-9a-f]+$/.test(block)) {
        process.stdout.write("unreadable");
        return;
      }
      process.stdout.write((status === "0x1" ? "succeeded" : "reverted") +
        " " + String(parseInt(block, 16)));
    });
  ' 2>/dev/null || printf 'unreadable'
}

# The chain id the questioned endpoint reports, or "unreadable".
endpoint_chain_id() {
  local response
  response="$(chain_rpc eth_chainId '[]')" || {
    printf 'unreadable'
    return 0
  }
  printf '%s' "${response}" | node -e '
    let raw = "";
    process.stdin.on("data", (d) => (raw += d));
    process.stdin.on("end", () => {
      let body;
      try {
        body = JSON.parse(raw);
      } catch (e) {
        process.stdout.write("unreadable");
        return;
      }
      const id = (body || {}).result;
      if (typeof id !== "string" || !/^0x[0-9a-f]+$/.test(id)) {
        process.stdout.write("unreadable");
        return;
      }
      process.stdout.write(String(parseInt(id, 16)));
    });
  ' 2>/dev/null || printf 'unreadable'
}

# True when a node answers its client-info port at all. Used both ways: to
# wait for a node to come up, and to prove a quarantined one has gone.
#
# This is one node's own HTTP surface and nothing more. It says a node answers
# or does not answer, which is weaker than the barrier below needs: a candidate
# whose client-info listener died while its protocol stack kept running answers
# nothing and is still on the network.
node_reachable() { probe_get "$1" /diagnostics >/dev/null 2>&1; }

# The compose project prefix every rehearsal gate of this scaffold runs under.
# A gate's own project name is compose_project; this is what makes another
# gate's leftovers recognizable as this scaffold's rather than as some
# unrelated container that happens to share the daemon.
REHEARSAL_PROJECT_PREFIX="pr4109-"

# Every container on this daemon that a rollback barrier has to account for,
# one per line as "<label> <state> <networks>".
#
# The barrier is about release candidates that could still act, and they are
# not all in the rehearsal project asking the question. A cutover rehearsal
# that ran before this one leaves its fleet behind under its own project name,
# and a distinct project name is not quarantine: two candidates on separate
# compose networks still watch the same rehearsal chain and still submit
# against the same contracts. So the inventory is taken daemon-wide and keyed
# on what makes a container a candidate — created from the candidate image, or
# belonging to a rehearsal project of any gate and not created from the prior
# image, which is the artifact a rollback restores rather than one it fences.
#
# State and network attachment both come from the daemon, which is the
# independent observation the per-node HTTP probe is not: a container that is
# running is participating unless the daemon shows it reaching nothing at all,
# and a container reaching nothing can reach neither its peers nor the chain.
# Anything else — a name, a project, a stopped sibling — is a claim about
# quarantine rather than a reading of it.
#
# Reaching nothing is not the same as owning no network, which is why the mode
# is read beside the map: a container run with `container:`/`service:` network
# mode has no entry of its own precisely because it holds another container's
# stack, and is on every network that container is on.
#
# Enumeration and inspection are factored out of the readings that filter them
# so that every barrier on this daemon describes the same instrument. Two
# independent enumerations taken moments apart could disagree about a fleet
# being torn down between them, and a candidate reading that disagreed with the
# prior reading about which containers exist would fence neither artifact.
#
# Emits one raw record per container as
# "<image>|<running>|<project>|<service>|<networks>|<mode>|<name>".
daemon_container_records() {
  local ids
  ids="$(docker ps --all --quiet --no-trunc 2>/dev/null)" || return 1
  [[ -n "${ids//[[:space:]]/}" ]] || return 0

  # One inspect over every container rather than one per container: a fleet
  # being torn down under the enumeration would otherwise turn a container that
  # vanished between the two calls into an inspect failure, and a failure to
  # read is exactly what this must not confuse with an absence.
  # shellcheck disable=SC2086
  docker inspect --format \
    '{{.Image}}|{{.State.Running}}|{{with index .Config.Labels "com.docker.compose.project"}}{{.}}{{end}}|{{with index .Config.Labels "com.docker.compose.service"}}{{.}}{{end}}|{{range $name, $_ := .NetworkSettings.Networks}}{{$name}},{{end}}|{{.HostConfig.NetworkMode}}|{{.Name}}' \
    ${ids} 2>/dev/null || return 1
}

# What a running container can still reach, as the single token the barriers
# classify. "-" is the one reading that means isolation.
#
# The network map alone cannot answer this. Docker lists `none` in the map like
# any other network, so genuine isolation does not present as an empty map; and
# a container sharing another's network stack presents as an empty map while
# holding every connection the container it shares with holds. Reading the map
# alone therefore refuses the one container that is quarantined and admits the
# ones that are not.
container_attachment() {
  local networks="${1%,}" mode="$2"
  case "${mode}" in
  # The stack belongs to another container. Compose resolves `service:` to a
  # `container:` mode before the daemon sees it; both are named here because
  # this reading is also taken against records a rehearsal supplies directly.
  container:* | service:*) printf '%s' "${mode}" ;;
  # The daemon's own stack: every route the host has, nothing to enumerate.
  host) printf '%s' 'host' ;;
  # The only mode that is isolation, whatever the map says.
  none) printf '%s' '-' ;;
  # A mode that could not be read leaves reachability unknown, and an unknown
  # must not spend the barrier's one passing reading. Naming it keeps it out
  # of the quarantined set and says why in the record.
  '') printf '%s' "${networks:-mode-unreadable}" ;;
  *) printf '%s' "${networks:--}" ;;
  esac
}

# The one place a raw record becomes the "<label> <state> <networks>" line a
# barrier classifies, so the candidate and prior readings cannot drift into
# describing running-ness or network attachment differently.
emit_container_record() {
  local running="$1" project="$2" service="$3" networks="$4" mode="$5" name="$6"
  local label state
  if [[ -n "${project}" && -n "${service}" ]]; then
    label="${project}/${service}"
  else
    label="${name#/}"
  fi
  case "${running}" in
  true) state="running" ;;
  false) state="stopped" ;;
  *) state="unreadable" ;;
  esac
  printf '%s %s %s\n' "${label}" "${state}" \
    "$(container_attachment "${networks}" "${mode}")"
}

candidate_container_inventory() {
  local candidate="$1" prior="$2" candidate_id prior_id raw
  candidate_id="$(docker image inspect --format '{{.Id}}' "${candidate}" \
    2>/dev/null)" || return 1
  prior_id="$(docker image inspect --format '{{.Id}}' "${prior}" \
    2>/dev/null)" || return 1
  raw="$(daemon_container_records)" || return 1
  [[ -n "${raw//[[:space:]]/}" ]] || return 0

  local image running project service networks mode name
  while IFS='|' read -r image running project service networks mode name; do
    [[ -n "${image}" ]] || continue
    if [[ "${image}" == "${prior_id}" ]]; then
      continue
    fi
    if [[ "${image}" != "${candidate_id}" ]] &&
      [[ "${project}" != "${REHEARSAL_PROJECT_PREFIX}"* ]]; then
      continue
    fi
    emit_container_record \
      "${running}" "${project}" "${service}" "${networks}" "${mode}" "${name}"
  done <<<"${raw}"
}

# Every container on this daemon created from the prior image, in the same
# "<label> <state> <networks>" shape.
#
# The candidate inventory above skips these by design — the prior artifact is
# what a rollback restores rather than one it fences — but "no prior binary
# participates before every R1 node is down" is a claim about this whole
# daemon, and asking this project's own prior service whether it answers cannot
# support it. A prior container left behind by an earlier rehearsal project, or
# started directly with no compose project at all, watches the same rehearsal
# chain and submits against the same contracts under a name this project never
# chose; a probe keyed on this project's service name is blind to exactly the
# container that would break the barrier without breaking the probe.
#
# So the prior reading is taken daemon-wide and keyed only on the image the
# container was created from, which is the one property a rollback's precondition
# is actually about: what artifact is executing.
prior_container_inventory() {
  local prior="$1" prior_id raw
  prior_id="$(docker image inspect --format '{{.Id}}' "${prior}" \
    2>/dev/null)" || return 1
  raw="$(daemon_container_records)" || return 1
  [[ -n "${raw//[[:space:]]/}" ]] || return 0

  local image running project service networks mode name
  while IFS='|' read -r image running project service networks mode name; do
    [[ -n "${image}" ]] || continue
    [[ "${image}" == "${prior_id}" ]] || continue
    emit_container_record \
      "${running}" "${project}" "${service}" "${networks}" "${mode}" "${name}"
  done <<<"${raw}"
}

# What the barrier saw, and the verdict it implies. Both are separated from the
# enumeration above for the same reason the clock and quiescence verdicts are:
# a barrier decision is only worth as much as its behavior on the readings it
# will never see in a passing rehearsal, and those readings cannot be produced
# by starting containers.
CANDIDATE_INVENTORY=()
# The labels this run knows the enumeration must contain — its own candidates.
# An enumeration that cannot see the containers this very stage created is an
# instrument failure, and an empty active set drawn from it is the barrier
# passing on nothing at all.
CANDIDATE_EXPECTED=()
# 1 when the daemon was enumerated at all; 0 when it could not be read.
CANDIDATE_INVENTORY_READ=1
# 1 once the barrier has been observed to hold, which is what the steps that
# release the prior artifact key off.
CANDIDATE_BARRIER_HOLDS=0

# Split CANDIDATE_INVENTORY into what it means for the barrier.
CANDIDATE_ACTIVE=()
CANDIDATE_QUARANTINED=()
CANDIDATE_UNREADABLE=()
CANDIDATE_MISSING=()

classify_candidate_inventory() {
  CANDIDATE_ACTIVE=()
  CANDIDATE_QUARANTINED=()
  CANDIDATE_UNREADABLE=()
  CANDIDATE_MISSING=()

  local line label state networks expected found
  for line in "${CANDIDATE_INVENTORY[@]+"${CANDIDATE_INVENTORY[@]}"}"; do
    read -r label state networks <<<"${line}"
    case "${state}" in
    running)
      if [[ "${networks}" == "-" ]]; then
        CANDIDATE_QUARANTINED+=("${label}")
      else
        CANDIDATE_ACTIVE+=("${label} on ${networks}")
      fi
      ;;
    stopped) ;;
    *) CANDIDATE_UNREADABLE+=("${label} [${state:-unreadable}]") ;;
    esac
  done

  for expected in "${CANDIDATE_EXPECTED[@]+"${CANDIDATE_EXPECTED[@]}"}"; do
    found=0
    for line in "${CANDIDATE_INVENTORY[@]+"${CANDIDATE_INVENTORY[@]}"}"; do
      read -r label state networks <<<"${line}"
      if [[ "${label}" == "${expected}" ]]; then
        found=1
        break
      fi
    done
    ((found == 1)) || CANDIDATE_MISSING+=("${expected}")
  done
}

# The barrier verdict over that classification, recorded as the named step.
# Sets CANDIDATE_BARRIER_HOLDS, which is the single fact every later step that
# would release or refuse the prior artifact reads.
candidate_barrier_verdict() {
  local step="$1" assertion="$2"
  CANDIDATE_BARRIER_HOLDS=0
  classify_candidate_inventory

  if ((CANDIDATE_INVENTORY_READ == 0)); then
    block_step "${step}" "the container daemon could not be enumerated, so \
nothing here knows which release candidates are still running; a barrier that \
cannot see the fleet it fences has not been established"
    record_assertion "${assertion}" false "${step}"
  elif ((${#CANDIDATE_MISSING[@]} > 0)); then
    block_step "${step}" "the enumeration did not find this rehearsal's own \
candidate(s) — ${CANDIDATE_MISSING[*]} — so it is not seeing the containers \
this stage created; an empty active set read from it is the instrument \
failing rather than the barrier holding"
    record_assertion "${assertion}" false "${step}"
  elif ((${#CANDIDATE_UNREADABLE[@]} > 0)); then
    block_step "${step}" "the run state of ${CANDIDATE_UNREADABLE[*]} could \
not be read; a candidate whose state is unknown is not a candidate known to \
be down"
    record_assertion "${assertion}" false "${step}"
  elif ((${#CANDIDATE_ACTIVE[@]} > 0)); then
    record_step "${step}" fail "still running and attached to a network: \
${CANDIDATE_ACTIVE[*]}; a separate compose project is not quarantine — a \
candidate left on any network still watches the same rehearsal chain and \
still acts on it"
    record_assertion "${assertion}" false "${step}"
  else
    local quarantined=""
    if ((${#CANDIDATE_QUARANTINED[@]} > 0)); then
      quarantined=" or attached to no network (${CANDIDATE_QUARANTINED[*]})"
    fi
    CANDIDATE_BARRIER_HOLDS=1
    record_step "${step}" pass "every release candidate on the daemon — \
${#CANDIDATE_INVENTORY[@]} container(s) across every rehearsal project, not \
only this gate's own — is stopped${quarantined}"
    record_assertion "${assertion}" true "${step}"
  fi
}

# Fill CANDIDATE_INVENTORY from the daemon, then correct it with what this
# gate's own nodes actually answer.
#
# The two readings are kept in this order on purpose. The daemon is the
# independent instrument — it sees candidates in projects this gate never
# started — but it reports the container's lifecycle, not the process's
# behavior. A node still answering its client-info port is participating
# whatever the daemon believes about it, so an answering service is promoted
# back to running here rather than being taken as down on the daemon's word.
read_candidate_inventory() {
  local inventory service label found line other

  CANDIDATE_INVENTORY=()
  CANDIDATE_EXPECTED=()
  CANDIDATE_INVENTORY_READ=1

  if ! inventory="$(candidate_container_inventory "${R1_IMAGE_DIGEST}" \
    "${PRIOR_IMAGE_DIGEST}")"; then
    CANDIDATE_INVENTORY_READ=0
    return 0
  fi
  while read -r line; do
    [[ -n "${line}" ]] || continue
    CANDIDATE_INVENTORY+=("${line}")
  done <<<"${inventory}"

  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    label="$(compose_project)/${service}"
    CANDIDATE_EXPECTED+=("${label}")
    node_reachable "${service}" || continue
    # Answering after the daemon called it stopped is the contradiction worth
    # keeping: the barrier must read it as an active candidate, and the
    # network it is answering on is the one thing observed about its reach.
    found=0
    other=()
    for line in "${CANDIDATE_INVENTORY[@]+"${CANDIDATE_INVENTORY[@]}"}"; do
      if [[ "${line}" == "${label} "* ]]; then
        found=1
        other+=("${label} running $(rehearsal_network)")
      else
        other+=("${line}")
      fi
    done
    ((found == 1)) || other+=("${label} running $(rehearsal_network)")
    CANDIDATE_INVENTORY=("${other[@]}")
  done
}

# What the daemon-wide prior reading saw across a drain, accumulated one sample
# at a time. Absence has to be watched for the whole window rather than probed
# once at its end, so these are counters over samples rather than a final
# state: a prior binary that participated for all of quiescence and stopped a
# second before the last probe is the sequence the barrier forbids, and only a
# sampled window can distinguish it from one that never ran.
PRIOR_DRAIN_SAMPLES=0
PRIOR_DRAIN_SERVICE_SIGHTINGS=0
PRIOR_DRAIN_ACTIVE_SIGHTINGS=0
PRIOR_DRAIN_UNREADABLE_SAMPLES=0
PRIOR_DRAIN_EXPECTED_MISSING=0
# Semicolon-joined listings rather than arrays: bash 3.2 has no name
# references, and every sample would otherwise re-list the same container once
# per sample taken.
PRIOR_DRAIN_ACTIVE_LABELS=""
PRIOR_DRAIN_UNREADABLE_LABELS=""

# Append a value to a semicolon-joined listing unless it is already there.
append_unique_listing() {
  local current="$1" value="$2"
  case ";${current};" in
  *";${value};"*) printf '%s' "${current}" ;;
  *) printf '%s' "${current}${current:+;}${value}" ;;
  esac
}

reset_prior_drain_samples() {
  PRIOR_DRAIN_SAMPLES=0
  PRIOR_DRAIN_SERVICE_SIGHTINGS=0
  PRIOR_DRAIN_ACTIVE_SIGHTINGS=0
  PRIOR_DRAIN_UNREADABLE_SAMPLES=0
  PRIOR_DRAIN_EXPECTED_MISSING=0
  PRIOR_DRAIN_ACTIVE_LABELS=""
  PRIOR_DRAIN_UNREADABLE_LABELS=""
}

# Fold one sample's worth of prior-image containers into the accumulators,
# reading the "<label> <state> <networks>" listing on stdin.
#
# Kept separate from the reading that produces the listing because the
# classification is the part that decides the barrier, and the readings it has
# to decide correctly — another project's prior left running while this
# project's own staged prior sits stopped — are exactly the ones no passing
# rehearsal produces and no fleet can be arranged to produce on demand.
absorb_prior_inventory_sample() {
  PRIOR_DRAIN_SAMPLES=$((PRIOR_DRAIN_SAMPLES + 1))

  local expected label state networks found_expected=0 active_this_sample=0
  expected="$(compose_project)/${REHEARSAL_PRIOR_SERVICE}"
  while read -r label state networks; do
    [[ -n "${label}" ]] || continue
    if [[ "${label}" == "${expected}" ]]; then
      found_expected=1
    fi
    case "${state}" in
    running)
      # Attached to no network at all, a container can reach neither its peers
      # nor the chain, which is the same reading the candidate barrier takes of
      # the same daemon fact.
      if [[ "${networks}" != "-" ]]; then
        active_this_sample=1
        PRIOR_DRAIN_ACTIVE_LABELS="$(append_unique_listing \
          "${PRIOR_DRAIN_ACTIVE_LABELS}" "${label} on ${networks}")"
      fi
      ;;
    stopped) ;;
    *)
      PRIOR_DRAIN_UNREADABLE_LABELS="$(append_unique_listing \
        "${PRIOR_DRAIN_UNREADABLE_LABELS}" "${label} [${state:-unreadable}]")"
      ;;
    esac
  done

  ((active_this_sample == 0)) ||
    PRIOR_DRAIN_ACTIVE_SIGHTINGS=$((PRIOR_DRAIN_ACTIVE_SIGHTINGS + 1))
  # This project staged its own prior container before the drain began, so an
  # enumeration that cannot see it is not seeing the containers this stage
  # created, and the empty active set drawn from it is the instrument failing
  # rather than the daemon being clear.
  ((found_expected == 1)) ||
    PRIOR_DRAIN_EXPECTED_MISSING=$((PRIOR_DRAIN_EXPECTED_MISSING + 1))
}

# One sample of "is any prior artifact executing anywhere on this daemon".
#
# Two independent readings, for the same reason the candidate barrier takes
# two. The node probe answers whether the process this project staged is
# serving; the daemon enumeration answers which containers built from the prior
# image exist at all, including the ones this project neither named nor
# started. Neither subsumes the other: a prior container in another project is
# invisible to the probe, and a process still answering its port after the
# daemon called its container stopped is invisible to the enumeration.
sample_prior_absence() {
  if node_reachable "${REHEARSAL_PRIOR_SERVICE}"; then
    PRIOR_DRAIN_SERVICE_SIGHTINGS=$((PRIOR_DRAIN_SERVICE_SIGHTINGS + 1))
  fi

  local inventory
  if ! inventory="$(prior_container_inventory "${PRIOR_IMAGE_DIGEST}")"; then
    # An enumeration that failed says nothing about absence, so the failure is
    # counted rather than being read as an empty daemon.
    PRIOR_DRAIN_SAMPLES=$((PRIOR_DRAIN_SAMPLES + 1))
    PRIOR_DRAIN_UNREADABLE_SAMPLES=$((PRIOR_DRAIN_UNREADABLE_SAMPLES + 1))
    return 0
  fi

  absorb_prior_inventory_sample <<<"${inventory}"
}

# The verdict over the sampled window, recorded as the named step.
prior_absence_verdict() {
  local step="$1" assertion="$2"

  if ((PRIOR_DRAIN_SAMPLES == 0)); then
    block_step "${step}" "no sample of the daemon was taken across the drain, \
so nothing here watched for a prior binary at all"
    record_assertion "${assertion}" false "${step}"
  elif ((PRIOR_DRAIN_UNREADABLE_SAMPLES > 0)); then
    block_step "${step}" "the container daemon could not be enumerated in \
${PRIOR_DRAIN_UNREADABLE_SAMPLES} of ${PRIOR_DRAIN_SAMPLES} samples taken \
across the drain; an absence read from an instrument that failed is not an \
absence"
    record_assertion "${assertion}" false "${step}"
  elif ((PRIOR_DRAIN_EXPECTED_MISSING > 0)); then
    block_step "${step}" "the enumeration did not find this project's own \
staged prior container in ${PRIOR_DRAIN_EXPECTED_MISSING} of \
${PRIOR_DRAIN_SAMPLES} samples, so it is not seeing the containers this stage \
created; an empty active set read from it is the instrument failing rather \
than the barrier holding"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${PRIOR_DRAIN_UNREADABLE_LABELS}" ]]; then
    block_step "${step}" "the run state of \
${PRIOR_DRAIN_UNREADABLE_LABELS//;/, } could not be read; a prior artifact \
whose state is unknown is not one known to be down"
    record_assertion "${assertion}" false "${step}"
  elif ((PRIOR_DRAIN_SERVICE_SIGHTINGS > 0 ||
    PRIOR_DRAIN_ACTIVE_SIGHTINGS > 0)); then
    local detail=""
    if ((PRIOR_DRAIN_SERVICE_SIGHTINGS > 0)); then
      detail="${REHEARSAL_PRIOR_SERVICE} answered on the rehearsal network in \
${PRIOR_DRAIN_SERVICE_SIGHTINGS} of ${PRIOR_DRAIN_SAMPLES} samples"
    fi
    if ((PRIOR_DRAIN_ACTIVE_SIGHTINGS > 0)); then
      detail="${detail}${detail:+; }a container built from the prior image was \
running and network-attached in ${PRIOR_DRAIN_ACTIVE_SIGHTINGS} of \
${PRIOR_DRAIN_SAMPLES} samples: ${PRIOR_DRAIN_ACTIVE_LABELS//;/, } — a \
separate compose project is not quarantine, and a prior binary on any network \
watches the same rehearsal chain"
    fi
    record_step "${step}" fail "${detail}"
    record_assertion "${assertion}" false "${step}"
  else
    record_step "${step}" pass "no container built from the prior image was \
running and network-attached anywhere on the daemon, and \
${REHEARSAL_PRIOR_SERVICE} did not answer, in any of ${PRIOR_DRAIN_SAMPLES} \
samples taken from before the drain started to after it finished"
    record_assertion "${assertion}" true "${step}"
  fi
}

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

# One value from an already-fetched Prometheus text exposition. Keeping the
# parser separate from the HTTP probe lets safety-sensitive multi-field
# accounts parse one node-authored response rather than assemble an apparent
# instant from several requests made while the process is stopping.
metric_value_from_exposition() {
  local metric="${METRIC_APPLICATION_PREFIX}_$1"
  awk -v metric="${metric}" '
    $1 == metric || index($1, metric "{") == 1 { print $2; found = 1; exit }
    END { if (!found) exit 1 }
  '
}

# One counter from a node's Prometheus text exposition. The parser reads the
# exposition's own shape: the metric name, optional labels, the value, and the
# trailing timestamp the client-info registry appends.
metric_value() {
  local service="$1"
  probe_metrics "${service}" | metric_value_from_exposition "$2"
}

# The four process-local signals that decide whether generated signer output
# made it fully into protected quarantine. This is the shell producer's one
# ordered definition: the general step snapshot, last-readable accumulator,
# evidence-gauge emitter, and rollback drain all consume this same list. The
# archive reader carries the corresponding JavaScript list below; the scaffold
# self-test binds the two so adding or renaming a signal cannot silently make
# one gate read a different preservation contract.
QUARANTINE_PRESERVATION_METRICS=(
  participation_tbtc_quarantine_preservation_failures_total
  participation_beacon_quarantine_preservation_failures_total
  participation_tbtc_quarantine_incomplete_outputs
  participation_beacon_quarantine_incomplete_outputs
)

# The restart evidence namespaces, pre-stop sampler freshness, watched-stop
# field provenance, and stopped process exit status are evidence, not
# Prometheus metrics or Compose command results. Keep their archive names once
# on the producer side; the scaffold self-test binds them to the JavaScript
# acceptance reader below.
RESTART_PRE_STOP_NAMESPACE="pre_stop"
RESTART_WATCHED_STOP_NAMESPACE="pre_restart"
RESTART_PRE_STOP_SAMPLE_READABLE_SUFFIX="sample_readable"
RESTART_WATCHED_FIELD_READABLE_SUFFIX="read_in_final_watched_sample"
RESTART_CONTAINER_EXIT_CODE_SUFFIX="container_exit_code"

# The participation metrics an evidence step snapshots, by their internal names.
#
# Every one of them is registered at zero with the rest of the fixed metric
# family, so a node with a client-info endpoint exposes all of them from startup
# whether or not it has anything to report — which is what makes a zero here a
# reading rather than an absence. The quarantined-signer count is the one whose
# value only tBTC can move: the protected namespace it counts and the wallet
# cache it compares against are both owned there, so it stays at zero on a
# service running none.
#
# A metric this list names and a node does not answer for is still skipped
# rather than treated as a fleet reporting zero — a service that publishes no
# participation family at all is not a fleet member reporting nothing — and only
# reading none of them at all is read as a broken instrument.
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
  "${QUARANTINE_PRESERVATION_METRICS[@]}"
  participation_quarantined_tbtc_signers
)

# The announcer's own account of a cross-format sighting, which is a different
# thing from the gate's refusal counter and the only thing that speaks to the
# straggler control. The gate counts a node refusing its own Begin; these count
# this node receiving a legacy session announcement where it expected a
# hardened one, recognizing it as cross-format, and recording the operator
# behind it. A refusal counter can move for reasons with no announcement behind
# them at all, and a correct cross-format sighting need never touch it.
ANNOUNCER_CUTOVER_METRICS=(
  announcer_session_id_mismatch_total
  announcer_cross_format_peer_total
  announcer_legacy_peer_additions_total
)

# The gated ceremonies, whose per-ceremony refusal counters name what a node
# refused rather than only that it refused something. A ceremony missing here
# is a refusal this rehearsal would read as unattributed, so the self-test
# holds this list to the closed set the Go tree publishes.
GATED_CEREMONIES=(
  tbtc_dkg
  tbtc_wallet_coordination
  tbtc_signing
  tbtc_heartbeat
  tbtc_inactivity_claim
  beacon_dkg
  beacon_relay_signing
  beacon_relay_forwarding
  beacon_timeout_report
)

# Every per-ceremony refusal counter on one node, as "<ceremony>=<count>"
# lines. A counter that cannot be read is emitted as "unreadable" rather than
# as zero, because a reading that failed must not subtract like an absence.
ceremony_refusal_counters() {
  local service="$1" ceremony value
  for ceremony in "${GATED_CEREMONIES[@]}"; do
    value="$(metric_value "${service}" \
      "participation_refusals_${ceremony}_total" 2>/dev/null || printf '')"
    [[ "${value}" =~ ^[0-9]+$ ]] || value="unreadable"
    printf '%s=%s\n' "${ceremony}" "${value}"
  done
}

# The ceremonies whose refusal counter moved between two such readings,
# comma-joined with their deltas. This is what turns "the node refused
# something" into "the node refused this", which is the only form a release
# decision can act on.
refused_ceremony_delta() {
  local before="$1" after="$2" line ceremony from to out=""
  while IFS='=' read -r ceremony from; do
    [[ -n "${ceremony}" ]] || continue
    to="$(printf '%s\n' "${after}" | sed -n "s/^${ceremony}=//p")"
    [[ "${from}" =~ ^[0-9]+$ && "${to}" =~ ^[0-9]+$ ]] || continue
    ((to > from)) || continue
    out="${out}${out:+, }${ceremony} +$((to - from))"
  done <<<"${before}"
  printf '%s' "${out}"
}

# The same delta restricted to the ceremonies an offer actually put on the
# chain.
#
# The unrestricted reading answers "the node refused something". A control
# whose claim is that the node refused *this* offer needs the ceremony the
# driver originated to be the one whose counter moved: a rehearsal chain
# carries other traffic, and any other ceremony being refused for its own
# reasons moves both the total and a per-ceremony counter, which is exactly
# the shape of the reading this step is looking for.
refused_offered_delta() {
  local before="$1" after="$2" offered="$3" ceremony from to out=""
  local wanted=" ${offered} "
  while IFS='=' read -r ceremony from; do
    [[ -n "${ceremony}" ]] || continue
    [[ "${wanted}" == *" ${ceremony} "* ]] || continue
    to="$(printf '%s\n' "${after}" | sed -n "s/^${ceremony}=//p")"
    [[ "${from}" =~ ^[0-9]+$ && "${to}" =~ ^[0-9]+$ ]] || continue
    ((to > from)) || continue
    out="${out}${out:+, }${ceremony} +$((to - from))"
  done <<<"${before}"
  printf '%s' "${out}"
}

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

# The identity every gate reading renders a permit under, shared by the live
# and the closed halves so one permit reads the same in both:
#
#   <service>@<ceremony>@<canonical start block>@<chain work>#<permit>
#
# The gate's own uniqueness key is the whole of it. Work IDs and local permit
# IDs are only unique within a ceremony and an anchor — a beacon member index
# is "1" for every group that node ever joins, and a wallet action's work ID
# repeats at every window — so a reading that named the last two alone lets a
# permit from one ceremony be answered by a record from another. The service
# is inside the identity rather than beside it because two nodes legitimately
# hold the same local permit id for the same chain work.
#
# This JS fragment is the one definition of that rendering and of what makes a
# permit readable at all. It is shared rather than repeated so the live list,
# the closed account, and the single-response drain snapshot cannot drift into
# accepting different things.
PERMIT_IDENTITY_JS='
      // The gate emits only nonsecret identity tokens, whose charset excludes
      // every separator this rendering uses. Checking it here is what keeps a
      // permit from splitting into a different permit than the node meant.
      const TOKEN = /^[A-Za-z0-9][A-Za-z0-9_.:-]*$/;
      const permitIdentity = (service, permit, what) => {
        if (permit === null || typeof permit !== "object" ||
          Array.isArray(permit)) {
          console.error("not a permit: " + JSON.stringify(permit));
          process.exit(1);
        }
        if (permit.identity_bound !== true) {
          console.error(what + " is not identity-bound: " +
            JSON.stringify(permit));
          process.exit(1);
        }
        if (typeof permit.ceremony !== "string" ||
          !TOKEN.test(permit.ceremony)) {
          console.error(what + " names no gate ceremony: " +
            JSON.stringify(permit));
          process.exit(1);
        }
        // The anchor the permit pinned its mode from. Two runs of one ceremony
        // are told apart by this and nothing else, so a reading that dropped
        // it would let a pre-cutover permit be answered by a post-cutover one.
        if (!Number.isInteger(permit.canonical_start_block) ||
          permit.canonical_start_block < 0) {
          console.error(what + " names no canonical start block: " +
            JSON.stringify(permit));
          process.exit(1);
        }
        if (typeof permit.work_id !== "string" ||
          !TOKEN.test(permit.work_id) ||
          typeof permit.permit_id !== "string" ||
          !TOKEN.test(permit.permit_id)) {
          console.error(what + " names no work or permit identity: " +
            JSON.stringify(permit));
          process.exit(1);
        }
        return service + "@" + permit.ceremony + "@" +
          permit.canonical_start_block + "@" + permit.work_id + "#" +
          permit.permit_id;
      };
'

# The permits of one mode that one node's gate reports live at this instant,
# rendered as permit identity tokens.
#
# A count of active ceremonies answers "this node is holding two" and nothing
# further, so a control watching work cross C or drain out of a quiescing node
# can only compare totals — and any two unrelated ceremonies moving in step
# satisfy that. The gate publishes the permits themselves; naming them is what
# lets a control say the permit that was in flight before the event is the one
# that was still there after it.
#
# Only identity-bound permits are usable. An unbound permit names no chain
# work, so nothing can match it to work a driver put on the chain, and reading
# it as a match would be reading the count again under another name.
service_mode_permits() {
  local service="$1" mode="$2"
  probe_diagnostics "${service}" |
    node -e "
      ${PERMIT_IDENTITY_JS}"'
      let raw = "";
      process.stdin.on("data", (d) => (raw += d));
      process.stdin.on("end", () => {
        const state = (JSON.parse(raw).protocol_participation) || {};
        const permits = state.active_permits;
        if (!Array.isArray(permits)) {
          console.error("no active_permits in the gate state");
          process.exit(1);
        }
        const service = process.argv[1];
        const mode = process.argv[2];
        const out = [];
        for (const permit of permits) {
          if (permit === null || typeof permit !== "object" ||
            Array.isArray(permit)) {
            console.error("not a permit: " + JSON.stringify(permit));
            process.exit(1);
          }
          if (permit.mode !== mode) {
            continue;
          }
          out.push(permitIdentity(service, permit, "a permit"));
        }
        process.stdout.write(out.join(" "));
      });
    ' "${service}" "${mode}"
}

# What one node's gate says became of the permits it has closed, rendered as
# "<service>=<chain work>#<permit>=<outcome>" tokens in the order they closed.
#
# This is the other half of the live permit list, and the half the controls
# were missing. The held list names work a node has; the moment that work ends
# the permit leaves the list and nothing further is said about it, so a control
# following work across the cutover saw a permit and then saw it gone, and had
# to take the word of whatever drove the work for which of those two endings it
# was. A report about a ceremony is not evidence about a ceremony. These
# records are written by each ceremony's own owner at the moment it closed its
# permit, under the same identities the held list carries, so a permit seen
# held joins to the disposition its holder recorded for it.
#
# A record that names no work or permit identity is refused rather than
# skipped. It would otherwise read exactly like a permit whose disposition the
# node never recorded, which is the case the joins below have to block on.
TERMINAL_OUTCOME_JS='
      // "unresolved" is in this list deliberately. It is what a permit closed
      // by an owner that recorded nothing is written as, and it has to arrive
      // as a disposition a reader can see and refuse rather than as an absence
      // indistinguishable from a permit still in flight.
      const OUTCOMES = [
        "completed", "quarantined", "exhausted", "unresolved",
      ];
      // The dispositions whose evidence names durable state the node produced,
      // and the ones whose evidence is the explicit absence of any. A record
      // carrying the wrong half for its ending is refused: the whole point of
      // reading evidence is that "completed" alone is a word, and the identity
      // of what was left behind is the thing that distinguishes a ceremony
      // that produced a result from a record that says it did.
      const REFERENCED_EVIDENCE = [
        "persisted_tbtc_signer", "persisted_beacon_signer",
        "bitcoin_transaction", "ethereum_transaction", "protocol_result",
      ];
      const UNREFERENCED_EVIDENCE = [
        "quarantined_tbtc_signer", "quarantined_beacon_signer",
        "no_threshold", "forwarder_closed",
      ];
      // A reference the gate never carries, so an absent one reads as absent
      // rather than as an empty field a later split could swallow. The gate
      // token charset opens on an alphanumeric, so this can never collide with
      // a real reference.
      const NONE = "-";
      // The ceremonies whose owners authenticate the parties behind their
      // result and therefore publish the transcript. The list mirrors the one
      // the gate keeps, and it is here rather than implied because a completed
      // record for one of these ceremonies without a transcript is the case
      // this reader has to refuse: it reads exactly like a ceremony that
      // authored one and leaves the population to whoever wrote the report.
      //
      // Both halves of the mirror matter, which is why a self-test holds this
      // list to the one the gate keeps. A ceremony missing here is read the
      // wrong way twice over: the record it publishes is refused as a
      // transcript it cannot observe, taking the whole snapshot with it, and
      // the record it omits passes as a completion nothing asked a population
      // of.
      const TRANSCRIPT_CEREMONIES = [
        "tbtc_dkg", "tbtc_signing", "tbtc_heartbeat",
        "beacon_dkg", "beacon_relay_signing",
      ];
      // The ceremonies whose record speaks in a different membership index space
      // than the permits issued for the same work, and whose transcript
      // therefore carries the seat each of its own seats was rebuilt from. The
      // list mirrors the one the gate keeps, and a self-test holds it there.
      //
      // Nothing else lets an ownership map span such a ceremony. A tBTC DKG
      // group is rebuilt from the members a node saw operating, so every seat
      // above a removed one shifts down; the permits name ceremony seats and the
      // transcripts name final seats, and a reader joining the two by number
      // attributes a final seat to whichever party holds that number in the
      // other space. A missing list entry is read the wrong way twice over: the
      // mapping the ceremony publishes is refused as one it cannot have, taking
      // the whole snapshot with it, and the ceremony that omits one passes as a
      // transcript nothing asked to be joinable.
      const REMAPPED_CEREMONIES = [
        "tbtc_dkg",
      ];
      // The evidence kinds that name a persisted DKG membership. The gate
      // requires the membership index on exactly these and forbids it
      // elsewhere, so a reader that dropped it would lose the field that ties a
      // persisted signer to the transcript that produced it.
      const MEMBERSHIP_EVIDENCE = [
        "persisted_tbtc_signer", "persisted_beacon_signer",
      ];
      // The chain side effects a ceremony dispatches outside its own protocol
      // result, each with the one rendering its resolved identity takes. A kind
      // outside this set is a side effect no ceremony in this release has a
      // code path to dispatch, so a record naming one is describing chain state
      // it could not have created.
      //
      // The rendering is held exactly rather than loosely because the whole
      // purpose of a resolved reference is to be joined to a single
      // authenticated log. An inactivity claim is named by the wallet it was
      // filed against and the nonce it settled at, which identifies one claim
      // for all time since the registry accepts a claim only at the current
      // nonce and increments it in the same call. An uppercase, 0x-prefixed,
      // padded, or truncated spelling of that pair names the same claim on
      // chain while failing every comparison an audit makes against the log,
      // and a reader accepting it hands the audit a settlement it will not find
      // — which reads afterwards as a penalty that never happened rather than
      // as the misrendering it was.
      const SETTLEMENT_REFERENCES = {
        tbtc_inactivity_claim: /^[0-9a-f]{64}:(0|[1-9][0-9]*)$/,
      };
      // A membership index as the journal renders it: 1 through 255, no leading
      // zeros, nothing else. Anything outside that is not a seat in a group.
      const memberIndexOf = (value, what) => {
        if (typeof value !== "number" || !Number.isInteger(value) ||
          value < 1 || value > 255) {
          console.error(what + " is not a membership index: " +
            JSON.stringify(value));
          process.exit(1);
        }
        return value;
      };
      // An ascending, duplicate-free membership set, rendered comma-joined.
      // The ordering is a rule the gate enforces and is checked rather than
      // normalized here: two records of one transcript have to compare equal as
      // text, and a set that arrived out of order or with a repeat is a record
      // no gate wrote.
      const memberSetOf = (value, what) => {
        if (!Array.isArray(value)) {
          console.error(what + " is not a membership set: " +
            JSON.stringify(value));
          process.exit(1);
        }
        let previous = 0;
        const members = [];
        for (const member of value) {
          const index = memberIndexOf(member, what);
          if (index <= previous) {
            console.error(what + " is not ascending and distinct: " +
              JSON.stringify(value));
            process.exit(1);
          }
          previous = index;
          members.push(index);
        }
        return members;
      };
      // Who the holder says produced the result, and which of those
      // memberships it operated itself.
      //
      // This is the field the mixed-release reading rests on. A completion says
      // a threshold result exists; every member of every finished ceremony
      // writes the same one, so a fleet whose shares combined from two releases
      // and a fleet where one release recovered the common result alone are the
      // same record without it. The two sets are kept apart because only their
      // difference can be attributed elsewhere: memberships the whole fleet
      // says it did not operate are memberships some node outside the fleet
      // supplied.
      const contributionOf = (record, kind, membership) => {
        const ceremony = (record.permit || {}).ceremony;
        const authored = TRANSCRIPT_CEREMONIES.includes(ceremony);
        const contribution = record.evidence.contribution;
        if (contribution === undefined || contribution === null) {
          if (authored) {
            console.error("a completed " + JSON.stringify(ceremony) +
              " permit names nobody who produced its result: " +
              JSON.stringify(record));
            process.exit(1);
          }
          return NONE + "=" + NONE;
        }
        if (!authored) {
          console.error("a " + JSON.stringify(ceremony) +
            " permit named a transcript it cannot observe: " +
            JSON.stringify(record));
          process.exit(1);
        }
        if (typeof contribution !== "object" || Array.isArray(contribution)) {
          console.error("not a transcript contribution: " +
            JSON.stringify(contribution));
          process.exit(1);
        }
        const incorporated = memberSetOf(
          contribution.incorporated_members,
          "the memberships that produced the result",
        );
        if (incorporated.length === 0) {
          console.error("a completed permit names no membership that " +
            "produced its result: " + JSON.stringify(record));
          process.exit(1);
        }
        // An empty local half is legitimate: a wallet action records the
        // signature it observed even when the attempt that produced it
        // selected none of its own memberships. A local membership outside the
        // produced population is not, because the record would then be an
        // account of other parties rather than of a ceremony this node was in.
        const local = memberSetOf(
          contribution.local_members === undefined ?
            [] : contribution.local_members,
          "the memberships this node operated",
        );
        for (const member of local) {
          if (!incorporated.includes(member)) {
            console.error("a node claims membership " + member +
              " outside the memberships that produced the result: " +
              JSON.stringify(record));
            process.exit(1);
          }
        }
        // The persisted membership and the transcript are two statements about
        // one ceremony, and the gate refuses a record whose seat is not among
        // the ones it says it operated. A reader that skipped it would carry a
        // persisted signer out to the joins under a seat its own transcript
        // places elsewhere: the audit then looks the key material up against
        // one seat while the population that produced it names another, and
        // both accounts are internally consistent.
        const seat = membership === NONE ? 0 : Number(membership);
        if (seat !== 0 && !local.includes(seat)) {
          console.error("a node persisted membership " + seat +
            " outside the memberships it operated in the transcript: " +
            JSON.stringify(record));
          process.exit(1);
        }
        // The seat behind each seat above, in the index space the permits for
        // this work were issued in. It is what lets an ownership map built from
        // permits be read against a transcript at all where the two spaces
        // differ.
        //
        // It rides on the incorporated field, after a "|", rather than as a
        // field of its own. The alignment is position for position and is the
        // whole encoding: a mapping read apart from the list it lines up with
        // says which ceremony seats survived and not which seat each of them
        // became, so keeping the two in one field is what makes losing the
        // pairing impossible. A mapping of a different length is refused rather
        // than truncated for the same reason — it would leave the seats past the
        // shorter list unjoinable and the ones before it unverifiable.
        let permitSpace = "";
        const mapped = REMAPPED_CEREMONIES.includes(ceremony);
        const declared = contribution.permit_space_members;
        if (declared === undefined || declared === null ||
          (Array.isArray(declared) && declared.length === 0)) {
          if (mapped) {
            console.error("a completed " + JSON.stringify(ceremony) +
              " permit publishes a transcript in another index space than " +
              "its own permits without saying how the two line up: " +
              JSON.stringify(record));
            process.exit(1);
          }
        } else if (!mapped) {
          console.error("a " + JSON.stringify(ceremony) +
            " permit maps between index spaces its record and its permits " +
            "share: " + JSON.stringify(record));
          process.exit(1);
        } else {
          const space = memberSetOf(
            declared,
            "the memberships behind the seats that produced the result",
          );
          if (space.length !== incorporated.length) {
            console.error("a transcript names " + incorporated.length +
              " memberships and maps " + space.length +
              " of them back to its permits: " + JSON.stringify(record));
            process.exit(1);
          }
          permitSpace = "|" + space.join(",");
        }
        return (incorporated.join(",") || NONE) + permitSpace + "=" +
          (local.join(",") || NONE);
      };
      const evidenceOf = (record) => {
        const evidence = record.evidence;
        if (evidence === null || typeof evidence !== "object" ||
          Array.isArray(evidence)) {
          console.error("a closed permit names no terminal evidence: " +
            JSON.stringify(record));
          process.exit(1);
        }
        // The one ending with no evidence of its own. The gate writes it for a
        // permit whose owner recorded nothing, so its record carries the empty
        // evidence and reading it is how a control sees the disposition it has
        // to refuse. An unresolved record that did name evidence would be some
        // other party writing into the gate account.
        if (record.outcome === "unresolved") {
          if (evidence.kind !== undefined && evidence.kind !== "") {
            console.error("an unresolved permit names terminal evidence: " +
              JSON.stringify(record));
            process.exit(1);
          }
          return NONE + "=" + NONE + "=" + NONE + "=" + NONE + "=" + NONE +
            "=" + NONE;
        }
        const kind = evidence.kind;
        const referenced = REFERENCED_EVIDENCE.includes(kind);
        if (!referenced && !UNREFERENCED_EVIDENCE.includes(kind)) {
          console.error("not a terminal evidence kind: " +
            JSON.stringify(kind));
          process.exit(1);
        }
        let reference = NONE;
        if (referenced) {
          if (typeof evidence.reference !== "string" ||
            !TOKEN.test(evidence.reference)) {
            console.error("terminal evidence of kind " + JSON.stringify(kind) +
              " names no durable result: " + JSON.stringify(evidence));
            process.exit(1);
          }
          reference = evidence.reference;
        } else if (evidence.reference !== undefined &&
          evidence.reference !== "") {
          console.error("terminal evidence of kind " + JSON.stringify(kind) +
            " must name no durable result: " + JSON.stringify(evidence));
          process.exit(1);
        }
        // The membership a completed DKG permit persisted. It is load-bearing
        // rather than decorative: the final signing group index can differ from
        // the DKG index the permit was issued under, so this is what joins a
        // persisted signer to the wallet seat the chain knows it by, and a
        // reader that dropped it could not tell one member record from
        // another beyond the seats they claim.
        let membership = NONE;
        if (MEMBERSHIP_EVIDENCE.includes(kind)) {
          membership = String(memberIndexOf(
            evidence.membership_index,
            "the membership a persisted DKG signer names",
          ));
        } else if (evidence.membership_index !== undefined &&
          evidence.membership_index !== 0) {
          console.error("terminal evidence of kind " + JSON.stringify(kind) +
            " must name no persisted membership: " + JSON.stringify(evidence));
          process.exit(1);
        }
        // A chain side effect the same permit dispatched beyond its own
        // protocol result — an inactivity claim filed alongside a heartbeat,
        // say. It is optional because most ceremonies dispatch none, and it
        // travels separately from the result identity because it is chain
        // state the audit reconciles rather than something the node computed.
        let settlement = NONE;
        const chain = evidence.chain_settlement;
        if (chain !== undefined && chain !== null) {
          if (typeof chain !== "object" || Array.isArray(chain) ||
            typeof chain.kind !== "string" || !TOKEN.test(chain.kind)) {
            console.error("not a chain settlement: " + JSON.stringify(chain));
            process.exit(1);
          }
          const rendering = SETTLEMENT_REFERENCES[chain.kind];
          if (rendering === undefined) {
            console.error("no ceremony dispatches the chain settlement " +
              JSON.stringify(chain.kind));
            process.exit(1);
          }
          // An unresolved settlement carries no reference; the kind alone is
          // the node saying it dispatched something it could not resolve, and
          // that has to stay visible rather than read as no settlement at all.
          if (chain.reference === undefined || chain.reference === "") {
            settlement = chain.kind;
          } else if (typeof chain.reference !== "string" ||
            !TOKEN.test(chain.reference) || !rendering.test(chain.reference)) {
            console.error("a chain settlement names no canonical identity: " +
              JSON.stringify(chain));
            process.exit(1);
          } else {
            settlement = chain.kind + ":" + chain.reference;
          }
        }
        return kind + "=" + reference + "=" + membership + "=" +
          contributionOf(record, kind, membership) + "=" + settlement;
      };
      // The ceremonies that operate no seat of their own. A forwarder relays
      // shares belonging to other members and computes nothing; a timeout
      // monitor files a penalty. The gate refuses a seat claimed under either,
      // so the reading here is the mirror of that refusal: a seat arriving on
      // one of them is a record no gate wrote.
      const SEATLESS_CEREMONIES = [
        "beacon_relay_forwarding", "beacon_timeout_report",
      ];
      // The ceremonies that run exactly one seat per permit, and name that seat
      // in the permit ID. The gate refuses any other operated set on them at
      // issuance, for the reason it states there: the permit ID and the operated
      // set are two node-authored statements about one permit, and a reader
      // shown disagreeing ones has to choose between them.
      const SINGLE_SEAT_CEREMONIES = [
        "tbtc_dkg", "beacon_dkg", "beacon_relay_signing",
      ];
      // The seats the holder of a permit says it operates, comma-joined, as
      // published when the permit was issued.
      //
      // This is the half of an ownership map that a transcript cannot supply. A
      // transcript exists only where a ceremony produced a result, so an
      // ownership map assembled from transcripts covers the nodes that finished
      // and silently omits the ones that contributed and then crashed, timed
      // out, or ended with nothing — and a seat omitted from the ownership map
      // of a fleet is a seat attributed to whoever else was on the network.
      // Reading it off the permit covers every holder whatever became of it.
      //
      // Which is why the shape rules are mirrored here rather than left to the
      // gate that enforces them. Holding a transcript to the operated set of its
      // own permit only constrains the permits that published a transcript, and
      // the records this reading exists to cover are the ones that did not: an
      // unresolved DKG permit supplying no transcript is checked against nothing
      // at all, so a record claiming a seat its permit was never issued for
      // enters the map unopposed. It takes that seat away from the R1 node whose
      // permit really held it, and the seat then reads as supplied from outside
      // the fleet — which turns a homogeneous run into the mixed one. A rule
      // that only binds the records that came with their own evidence is not a
      // rule about the records that did not.
      const operatedOf = (permit) => {
        const ceremony = permit.ceremony;
        const operated = memberSetOf(
          permit.operated_members === undefined ?
            [] : permit.operated_members,
          "the memberships a permit holder operates",
        );
        if (SEATLESS_CEREMONIES.includes(ceremony) && operated.length > 0) {
          console.error("a " + JSON.stringify(ceremony) +
            " permit claims seats it operates none of: " +
            JSON.stringify(permit));
          process.exit(1);
        }
        if (SINGLE_SEAT_CEREMONIES.includes(ceremony) &&
          (operated.length !== 1 ||
            String(operated[0]) !== permit.permit_id)) {
          console.error("a " + JSON.stringify(ceremony) +
            " permit runs one seat and must operate its permit ID alone: " +
            JSON.stringify(permit));
          process.exit(1);
        }
        return operated.join(",") || NONE;
      };
      const terminalOutcome = (service, record) => {
        if (record === null || typeof record !== "object" ||
          Array.isArray(record)) {
          console.error("not a terminal outcome record: " +
            JSON.stringify(record));
          process.exit(1);
        }
        if (record.permit === null || record.permit === undefined) {
          console.error("a terminal outcome names no permit: " +
            JSON.stringify(record));
          process.exit(1);
        }
        if (!OUTCOMES.includes(record.outcome)) {
          console.error("not a terminal outcome: " +
            JSON.stringify(record.outcome));
          process.exit(1);
        }
        return permitIdentity(service, record.permit, "a closed permit") +
          "=" + record.outcome + "=" + evidenceOf(record) +
          "=" + operatedOf(record.permit);
      };
'

# What one node's gate says became of the permits it has closed, rendered as
# "<permit identity>=<outcome>=<evidence kind>=<result>=<membership>=
# <incorporated>=<local>=<settlement>" tokens in the order they closed.
#
# This is the other half of the live permit list, and the half the controls
# were missing. The held list names work a node has; the moment that work ends
# the permit leaves the list and nothing further is said about it, so a control
# following work across the cutover saw a permit and then saw it gone, and had
# to take the word of whatever drove the work for which of those two endings it
# was. A report about a ceremony is not evidence about a ceremony. These
# records are written by each ceremony's own owner at the moment it closed its
# permit, under the same identities the held list carries, so a permit seen
# held joins to the disposition its holder recorded for it.
#
# The evidence travels with the ending rather than being summarized away by it.
# "completed" is a category, and every node that finished the same piece of
# work writes the same category however little it agrees with the others about
# what was produced; the result identity is what lets a control ask whether
# they finished the same ceremony and whether it is the one the driver claims.
#
# A record that names no work or permit identity is refused rather than
# skipped. It would otherwise read exactly like a permit whose disposition the
# node never recorded, which is the case the joins below have to block on.
service_terminal_outcomes() {
  local service="$1"
  probe_diagnostics "${service}" |
    node -e "
      ${PERMIT_IDENTITY_JS}
      ${TERMINAL_OUTCOME_JS}"'
      let raw = "";
      process.stdin.on("data", (d) => (raw += d));
      process.stdin.on("end", () => {
        const state = (JSON.parse(raw).protocol_participation) || {};
        const outcomes = state.recent_terminal_outcomes;
        if (!Array.isArray(outcomes)) {
          console.error("no recent_terminal_outcomes in the gate state");
          process.exit(1);
        }
        const service = process.argv[1];
        const out = [];
        for (const record of outcomes) {
          out.push(terminalOutcome(service, record));
        }
        process.stdout.write(out.join(" "));
      });
    ' "${service}"
}

# The readings a drain watcher decides on, all taken out of one gate response:
# the state the node reports, how many ceremonies of one mode it still holds,
# and the endings it has recorded so far. Rendered as "state=", "active=" and
# "outcomes=" lines.
#
# Asked one at a time these are three requests against a node that is in the
# middle of stopping, and the answers need not describe the same instant. The
# case that matters is the ordinary one: a node answers "quiescing", answers
# "nothing in flight", and exits before the third request — so the watcher
# records a drain beside whatever ending list some earlier pass happened to
# hold, which is the list from before the last permit closed. The permits this
# control exists to follow are exactly the ones that close last, so the reading
# is wrong precisely where it is load-bearing.
#
# One response cannot do that. The gate composes the whole object from a single
# state snapshot, so the three readings here are of one instant by
# construction, and a node that stops mid-drain fails the fetch outright rather
# than answering part of it.
service_gate_snapshot() {
  local service="$1" field="$2"
  probe_diagnostics "${service}" |
    node -e "
      ${PERMIT_IDENTITY_JS}
      ${TERMINAL_OUTCOME_JS}"'
      let raw = "";
      process.stdin.on("data", (d) => (raw += d));
      process.stdin.on("end", () => {
        const state = (JSON.parse(raw).protocol_participation) || {};
        const service = process.argv[1];
        const field = process.argv[2];
        const gateState = state.gate_state;
        if (typeof gateState !== "string" || !/^\S+$/.test(gateState)) {
          console.error("no gate_state in the gate state");
          process.exit(1);
        }
        const active = state[field];
        if (!Number.isInteger(active) || active < 0) {
          console.error("no " + field + " count in the gate state");
          process.exit(1);
        }
        const outcomes = state.recent_terminal_outcomes;
        if (!Array.isArray(outcomes)) {
          console.error("no recent_terminal_outcomes in the gate state");
          process.exit(1);
        }
        // The same reading of a closed permit the standalone account applies,
        // and the same refusal to skip an unreadable record. A snapshot that
        // dropped a malformed record would present a shorter ending list as a
        // whole one, and this reading is the one a drain verdict treats as
        // complete.
        const out = [];
        for (const record of outcomes) {
          out.push(terminalOutcome(service, record));
        }
        process.stdout.write("state=" + gateState + "\n" +
          "active=" + String(active) + "\n" +
          "outcomes=" + out.join(" ") + "\n");
      });
    ' "${service}" "${field}"
}

# One field out of such a snapshot. The value may be empty — an ending list is
# empty until the first permit closes — so this says nothing about whether the
# snapshot was taken; that is the fetch's own exit status.
snapshot_field() {
  printf '%s\n' "$1" | sed -n "s/^$2=//p"
}

# The same across the R1 fleet, with the unreadable-is-unusable convention the
# held-permit readings use: a node that cannot be asked leaves the whole
# reading unusable rather than a shorter list, which would otherwise be
# indistinguishable from a node whose permits all ended without a record.
fleet_terminal_outcomes() {
  local service outcomes out=""
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    if ! outcomes="$(service_terminal_outcomes "${service}" 2>/dev/null)"; then
      printf 'unreadable on %s' "${service}"
      return 0
    fi
    [[ -z "${outcomes}" ]] || out="${out}${out:+ }${outcomes}"
  done
  printf '%s' "${out}"
}

# Everything one node's gate says about the permits it has been issued, out of a
# single response: which process is answering, how much that account has already
# forgotten, the permits it is still holding, and the endings it recorded for the
# ones it is not. Rendered as "provenance=", "held=" and "outcomes=" lines.
#
# The four readings have to describe one instant because they are joined to each
# other. A permit is in the held list or in the closed account and never in both,
# so asked one at a time a permit that closes between the two requests appears in
# neither — and a permit in neither is a seat missing from the fleet's ownership
# map, which is the seat that reads as supplied by the other release. The
# provenance is on the same response for the same reason: it is what says whether
# the account those two lists came out of is the one that held the work, and read
# from a different instant it vouches for lists it never saw.
#
# The gate composes the whole object from one state snapshot, so this is one
# instant by construction. A node that stops mid-read fails the fetch outright
# rather than answering part of it.
service_account_snapshot() {
  local service="$1"
  probe_diagnostics "${service}" |
    node -e "
      ${PERMIT_IDENTITY_JS}
      ${TERMINAL_OUTCOME_JS}"'
      let raw = "";
      process.stdin.on("data", (d) => (raw += d));
      process.stdin.on("end", () => {
        const state = (JSON.parse(raw).protocol_participation) || {};
        const service = process.argv[1];
        const permits = state.active_permits;
        if (!Array.isArray(permits)) {
          console.error("no active_permits in the gate state");
          process.exit(1);
        }
        const outcomes = state.recent_terminal_outcomes;
        if (!Array.isArray(outcomes)) {
          console.error("no recent_terminal_outcomes in the gate state");
          process.exit(1);
        }
        // A held permit is rendered out of the same fields a closed one is, so
        // the two lists enter the ownership map on identical terms: each names
        // seats of its own holder, published at issuance, and what became of
        // the permit afterwards is a question the map does not ask.
        const held = [];
        for (const permit of permits) {
          held.push(permitIdentity(service, permit, "a held permit") +
            "=" + operatedOf(permit));
        }
        const ended = [];
        for (const record of outcomes) {
          ended.push(terminalOutcome(service, record));
        }
        // An identity a gate could not compose, and a count that is not one,
        // are rendered as the one token that can be neither. Carried through
        // verbatim they compare equal to themselves, and the reading that has to
        // be unfollowable comes out as the followable one.
        const instance = state.gate_instance;
        const forgotten = state.forgotten_terminal_outcomes;
        process.stdout.write("provenance=" + service + "=" +
          (/^[0-9a-f]{32}$/.test(instance) ? instance : "-") + "=" +
          (Number.isInteger(forgotten) && forgotten >= 0 ?
            String(forgotten) : "-") + "\n" +
          "held=" + held.join(" ") + "\n" +
          "outcomes=" + ended.join(" ") + "\n");
      });
    ' "${service}"
}

# The same across the R1 fleet, on the unreadable-is-unusable convention every
# reading above uses. A node that cannot be asked takes all three lines rather
# than shortening one: a fleet short one member's held permits is exactly what a
# fleet that released them looks like, and a fleet short one member's endings is
# what one whose permits all closed unrecorded looks like.
fleet_account_snapshot() {
  local service snapshot part provenance="" held="" outcomes=""
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    if ! snapshot="$(service_account_snapshot "${service}" 2>/dev/null)"; then
      printf 'provenance=unreadable on %s\nheld=unreadable on %s\n' \
        "${service}" "${service}"
      printf 'outcomes=unreadable on %s\n' "${service}"
      return 0
    fi
    part="$(snapshot_field "${snapshot}" provenance)"
    provenance="${provenance}${provenance:+ }${part}"
    part="$(snapshot_field "${snapshot}" held)"
    [[ -z "${part}" ]] || held="${held}${held:+ }${part}"
    part="$(snapshot_field "${snapshot}" outcomes)"
    [[ -z "${part}" ]] || outcomes="${outcomes}${outcomes:+ }${part}"
  done
  printf 'provenance=%s\nheld=%s\noutcomes=%s\n' \
    "${provenance}" "${held}" "${outcomes}"
}

# Whether each R1 node's account of closed permits can be followed at all,
# rendered as "<service>=<gate instance>=<forgotten count>" tokens.
#
# The account lives in memory. Read once, an empty one is a node that closed no
# permit and a node that closed one and lost the record — opposite answers about
# whether that node did the work, and reading the second as the first attributes
# its seats to whoever else was on the network. Two things make the difference
# readable: the process the account belongs to, and how many records the account
# has dropped to its own bound. Both are taken either side of a drive, because
# what matters is whether the account that answers afterwards is the same one
# that was there while the work ran.
#
# A node that cannot be read leaves the whole reading unusable rather than a
# shorter list, exactly as the outcomes above: a fleet with one member missing
# from the account is indistinguishable from a fleet whose permits all ended
# unrecorded.
#
# A node that answers with provenance it cannot stand behind is rendered "-" in
# that half rather than verbatim. The gate composes its identity from the
# system entropy source and says the identity is unknown when that source fails;
# the diagnostics layer publishes the word "unknown" for it. Carried through as
# text, two such nodes — or one node twice — compare equal, and an equality test
# then reads the case that was meant to be unfollowable as the followable one.
# The sentinel cannot be an instance, so it can only ever compare unequal.
#
# Rendering anything off-shape the same way is what keeps the token parse honest
# besides: an instance carrying a separator would otherwise split into a
# different node than the one that answered.
#
# It is taken out of the whole-account reading rather than asked for on its own,
# so the reading before a drive and the reading after it are produced by one
# renderer. Two renderers of one token shape is one chance for the two halves of
# an equality test to disagree about what an identity even is, and that test
# decides whether every join below it can be believed.
fleet_account_provenance() {
  snapshot_field "$(fleet_account_snapshot)" provenance
}

# How long a reading waits for the permits its driver named to close before
# reporting whatever is still open. The driver returns when its own side of a
# ceremony settled, and the holder's close follows within a coordination window
# or two; this is several of those, so a permit still open at the end of it is
# one that stopped closing rather than one that had not got there yet.
ACCOUNT_SETTLE_TIMEOUT=300

# One atomic fleet account in which no permit the driver named is still open,
# or the last one taken before waiting stopped being honest.
#
# The driver reports when its own side of a ceremony settled; the holder closes
# the permit it ran under some time after that. A reading taken at the instant
# the driver returns therefore catches permits mid-close, and a permit still
# open is in the held list and in no ending — which the ownership joins read as
# a holder that would not vouch for how its permit ended. That is a real
# finding about a different fleet: one that authored nothing. Here it is a race
# with a ceremony that is still running, and a control that cannot tell them
# apart fails every run of a fleet that is working.
#
# So the account is retaken until those permits are gone. Retaking is only
# sound while it stays the same account: a node that restarts between two reads
# answers from a process holding none of the old permits, which is a permit
# closed by being forgotten rather than by ending. The provenance taken before
# the drive is carried into every round, and the first reading that no longer
# follows it is returned unchanged for the verdict's own rung to refuse —
# waiting past that point would be waiting for an account that cannot answer
# for the work.
#
# What is still held when the wait ends is returned as it was read. A ceremony
# that never ends is a finding this rehearsal exists to surface, and it has to
# reach the verdict as one rather than as a reading that ran out of time.
settled_account_snapshot() {
  local originated="$1" before="$2" deadline account named held
  named="$(held_permit_identities "${originated}")"
  deadline=$((SECONDS + ACCOUNT_SETTLE_TIMEOUT))
  while :; do
    account="$(fleet_account_snapshot)"
    held="$(snapshot_field "${account}" held)"
    if [[ "${held}" == "unreadable on "* ]]; then
      break
    fi
    if [[ -z "$(held_open_permits "${named}" "${held}")" ]]; then
      break
    fi
    if [[ -n "$(unfollowable_account_nodes "${before}" \
      "$(snapshot_field "${account}" provenance)")" ]]; then
      break
    fi
    if ((SECONDS >= deadline)); then
      break
    fi
    sleep 5
  done
  printf '%s' "${account}"
}

# Of the fleet, the nodes whose account of closed permits cannot be followed
# across a drive, rendered as "<service> (<what changed>)".
#
# Either reading being unreadable takes the whole fleet, for the reason above. A
# node answering from a different process than the one that ran the work has lost
# every record the earlier one held; a node whose account dropped records while
# the work ran has lost some of them and cannot say which. Both are the same thing
# to a reader joining permits to endings, which is that this node's part in the
# work is unknown — and an unknown must not be read as a node that took no part.
#
# So is provenance the node declined to state. "-" is what the reading above puts
# in place of an identity a gate could not compose or a count that arrived
# off-shape, and it is unfollowable on sight rather than compared: the question
# an equality test answers is whether two readings came from the same process,
# and neither of two blanks answers it. A count that went backwards is the same
# refusal — the account only ever forgets — and it must not be subtracted into a
# negative number of dropped permits and reported as a drop of some kind.
#
# A node that answers afterwards with no reading of it beforehand is unfollowable
# too. Both readings are taken over one fixed service list, so the only way to
# lose the earlier one is for the pair to describe different fleets, and a node
# whose account was never sampled while the work ran cannot be held to it.
unfollowable_account_nodes() {
  local before="$1" after="$2"
  local token service instance forgotten earlier was was_forgotten out=""
  local matched
  case "${before}" in
    unreadable*)
      printf '%s' "${before}"
      return 0
      ;;
  esac
  case "${after}" in
    unreadable*)
      printf '%s' "${after}"
      return 0
      ;;
  esac
  for token in ${after}; do
    service="${token%%=*}"
    instance="${token#*=}"
    forgotten="${instance##*=}"
    instance="${instance%%=*}"
    matched=0
    for earlier in ${before}; do
      [[ "${earlier%%=*}" == "${service}" ]] || continue
      matched=1
      was="${earlier#*=}"
      was_forgotten="${was##*=}"
      was="${was%%=*}"
      if [[ "${instance}" == "-" || "${was}" == "-" ]]; then
        out="${out}${out:+, }${service} (does not say which process its \
account of closed permits belongs to)"
      elif [[ "${was}" != "${instance}" ]]; then
        out="${out}${out:+, }${service} (answered from a different process \
than the one the work ran on)"
      elif [[ "${forgotten}" == "-" || "${was_forgotten}" == "-" ]]; then
        out="${out}${out:+, }${service} (does not say how many closed permits \
its account has dropped)"
      elif ((forgotten < was_forgotten)); then
        out="${out}${out:+, }${service} (its account reports having dropped \
fewer closed permits than it had already dropped before the work ran)"
      elif [[ "${forgotten}" != "${was_forgotten}" ]]; then
        out="${out}${out:+, }${service} (its account dropped \
$((forgotten - was_forgotten)) closed permits while the work ran)"
      fi
      break
    done
    if ((matched == 0)); then
      out="${out}${out:+, }${service} (its account was not read before the \
work ran)"
    fi
  done
  printf '%s' "${out}"
}

# The gate's own spelling of the two permit modes, which is what a scrape
# filters on. The rehearsal writes the security-v2 half with a hyphen in step
# names and metric suffixes; the gate does not.
gate_mode_name() {
  case "$1" in
  security-v2 | security_v2) printf 'security_v2' ;;
  *) printf 'legacy' ;;
  esac
}

# Every legacy permit the R1 fleet holds right now, in the form the originated
# records render to. A node that cannot be read leaves the whole reading
# unusable rather than a shorter list, which would otherwise be indistinguishable
# from a node that had released its permits.
fleet_legacy_permits() {
  local service permits out=""
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    if ! permits="$(service_mode_permits "${service}" legacy 2>/dev/null)"; then
      printf 'unreadable on %s' "${service}"
      return 0
    fi
    [[ -z "${permits}" ]] || out="${out}${out:+ }${permits}"
  done
  printf '%s' "${out}"
}

# The same for one node and one mode, with the same unreadable-is-unusable
# convention so a control can tell "held nothing" from "could not be asked".
node_mode_permits() {
  local node="$1" permits
  if ! permits="$(service_mode_permits "${node}" \
    "$(gate_mode_name "$2")" 2>/dev/null)"; then
    printf 'unreadable on %s' "${node}"
    return 0
  fi
  printf '%s' "${permits}"
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
REHEARSAL_RUN_ID=""
REHEARSAL_R1_FLEET=""
REHEARSAL_R1_EXECUTED_IMAGES=""
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
# The record emitted by the current run. conclude_rehearsal checks this exact
# record against the gate contract before it may report success; using the
# whole evidence directory there would let an older record decide the current
# run's verdict.
EMITTED_EVIDENCE_RECORD=""

# Observations of the step currently running. begin_step clears them, so a
# step records what was seen while it ran and never inherits the readings of
# the step before it.
STEP_CANONICAL_BLOCKS=""
STEP_PERMIT_MODES=""
STEP_GAUGES=""
STEP_TX_HASHES=""
STEP_STATE_CHECKSUMS=""
STEP_EVIDENCE_REFS=""

# One unpredictable identity is created before a rehearsal observes the fleet.
# It is copied into the top-level record and every supporting capture, making
# a valid archive from another run detectably foreign even when the two runs
# used the same services, chain, and release artifact.
initialize_rehearsal_run_identity() {
  REHEARSAL_RUN_ID="$(node -e '
    const crypto = require("crypto");
    process.stdout.write(crypto.randomBytes(16).toString("hex"));
  ')" || blocked "cannot generate the rehearsal run identity"
  [[ "${REHEARSAL_RUN_ID}" =~ ^[0-9a-f]{32}$ ]] ||
    blocked "the generated rehearsal run identity is malformed"
}

begin_step() {
  note "step: $1"
  STEP_CANONICAL_BLOCKS=""
  STEP_PERMIT_MODES=""
  STEP_GAUGES=""
  STEP_TX_HASHES=""
  STEP_STATE_CHECKSUMS=""
  STEP_EVIDENCE_REFS=""
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
  [[ -n "${STEP_EVIDENCE_REFS}" ]] &&
    fields="${fields},\"evidence_refs\":{${STEP_EVIDENCE_REFS}}"
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

# The one published image a rehearsal actually ran, as the platform map the
# schema wants.
#
# A multi-architecture digest names a manifest list whose children are the real
# runtime images, and exactly one of them is on this daemon: the pull resolved
# the child matching the runner's own platform, and every container the fleet
# started came from that child. Naming the whole list would put architectures
# this run never executed into a record that speaks only for what it observed
# — and the acceptance comparison downstream would then read an amd64
# rehearsal as evidence for the arm64 artifact too. A release publishing
# several platforms is evidenced by rehearsing on each of them, which
# acceptance checks across the record set rather than inside any one record.
#
# A single-architecture digest has no list, so the reference is the image.
executed_image_digest() {
  local reference="$1" repository="${1%@*}"
  local manifest platform
  if ! manifest="$(docker manifest inspect "${reference}" 2>/dev/null)"; then
    blocked "cannot read the manifest of ${reference}; the digest must be \
readable to record which published image the rehearsal ran"
  fi
  # Asked of the local image rather than of the runner: what a record names has
  # to be what the containers were created from, and the daemon is the only
  # party that knows which child that pull resolved to.
  platform="$(docker image inspect \
    --format '{{.Os}}|{{.Architecture}}|{{.Variant}}' "${reference}" \
    2>/dev/null)" ||
    blocked "cannot read the platform ${reference} resolved to on this \
daemon; without it a record cannot say which of the release's images ran"
  node -e '
    const manifest = JSON.parse(process.argv[1]);
    const repository = process.argv[2];
    const parts = String(process.argv[3]).split("|");
    const os = parts[0] || "";
    const architecture = parts[1] || "";
    // An engine too old to report one renders the field as the template
    // placeholder rather than as an empty string.
    const variant =
      !parts[2] || parts[2] === "<no value>" ? "" : parts[2];
    const reference = process.argv[4];
    if (!architecture) {
      console.error("no architecture readable for " + reference);
      process.exit(1);
    }
    const name = architecture + (variant ? "/" + variant : "");
    const out = {};
    if (Array.isArray(manifest.manifests)) {
      const children = manifest.manifests.filter((entry) => {
        const platform = entry.platform || {};
        // Attestation manifests ride in the same list as the runtime images
        // and carry the placeholder architecture; one of those is never what
        // a container was created from.
        if (!platform.architecture || platform.architecture === "unknown") {
          return false;
        }
        if (platform.architecture !== architecture) return false;
        if ((platform.variant || "") !== variant) return false;
        return !os || !platform.os || platform.os === os;
      });
      if (children.length !== 1) {
        console.error(
          "the manifest of " + reference + " carries " + children.length +
            " runtime child(ren) for " + name + ", the platform this daemon " +
            "resolved it to; a record names the one image that ran"
        );
        process.exit(1);
      }
      out[name] = repository + "@" + children[0].digest;
    } else {
      out[name] = reference;
    }
    process.stdout.write(JSON.stringify(out));
  ' "${manifest}" "${repository}" "${platform}" "${reference}" ||
    blocked "cannot resolve which child of ${reference} this rehearsal ran"
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
        if (!gate.ethereum_chain_id) {
          missing.push("protocol_participation.ethereum_chain_id");
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
          ethereum_chain_id: gate.ethereum_chain_id,
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

# The operator chain address a node signs as, as it publishes it. This is the
# identity a roster entry has to match for a legacy sighting to be attributed
# to a specific node rather than to an unnamed peer.
node_operator_address() {
  probe_diagnostics "$1" |
    node -e '
      let raw = "";
      process.stdin.on("data", (d) => (raw += d));
      process.stdin.on("end", () => {
        const address = (JSON.parse(raw).client_info || {}).chain_address;
        if (!address) {
          console.error("the node diagnostics carry no client_info.chain_address");
          process.exit(1);
        }
        process.stdout.write(String(address));
      });
    '
}

# One live participation gauge summed across the whole R1 fleet, under the
# same poisoning rule: a node whose gauge cannot be read leaves the total
# unknown rather than smaller, because a step that treats an unreadable node as
# a zero is reading a fleet it cannot see.
fleet_gauge_total() {
  local field="$1" service value total=0
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    value="$(participation_field "${service}" "${field}" 2>/dev/null ||
      printf '')"
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

# Every operator any R1 node has attributed a legacy sighting to, sorted and
# deduplicated so two readings can be differenced. A control that watched one
# node's roster would miss a sighting the other node made, and one sighting
# anywhere in the fleet is what "no legacy sightings" denies.
fleet_roster_operators() {
  local service
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    roster_operators "${service}" 2>/dev/null || true
  done | sort -u
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
  local reported_chain
  local agreed=""
  attested="$(attested_source_identity)"
  manifest_epoch="$(manifest_protocol_epoch)"
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    reported="$(node_release_identity "${service}")" ||
      blocked "${service} does not report the version, revision, protocol \
epoch, and cutover block that identify what it is running; the record binds \
the rehearsal to what the running nodes say they are, and a node that will \
not say cannot be evidenced"

    # The exact commit, not an abbreviation of it. A prefix comparison
    # accepted a node reporting nothing at all — every string is a prefix of
    # the attested SHA when the empty one is — and, short of that, accepted an
    # abbreviation that names a commit only as far as it goes. The release
    # workflow stamps the full SHA into the artifact for exactly this reason,
    # and shell-analysis holds it to that.
    revision="$(json_field "${reported}" revision)"
    if [[ "${revision}" != "${attested}" ]]; then
      blocked "${service} reports revision [${revision:-absent}], but this run \
is bound to [${attested}]; the record binds every observation to one commit, \
and an artifact that does not name that commit exactly was built from bytes \
no proof here measured"
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

    # The chain the node actually reached, as it read it back from its own
    # endpoint at startup. Until this comparison the record's chain identity
    # was the dispatch input copied into it, which agrees with itself no
    # matter which chain the fleet was pointed at — and a cutover block is a
    # count on one chain, so a C observed on another chain is an observation
    # about a different schedule entirely.
    reported_chain="$(json_field "${reported}" ethereum_chain_id)"
    if [[ "${reported_chain}" != "${CHAIN_ID}" ]]; then
      blocked "${service} is connected to Ethereum chain [${reported_chain}], but \
this rehearsal records its evidence against chain [${CHAIN_ID}]; every block, \
crossing, and reconciliation below would be attributed to a chain the fleet \
was never on"
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
${attested}, the rehearsed C, and the chain the record is written against"
}

# Capture the concrete R1 processes behind the authoritative service roster.
# Service names alone repeat on every runner; full container IDs distinguish
# one process population from another, and normalized operator addresses bind
# each process to the chain identity it acts for. The image map is resolved at
# the same point and reused by both the supporting archive and final record.
capture_r1_fleet_identity() {
  [[ "${REHEARSAL_RUN_ID}" =~ ^[0-9a-f]{32}$ ]] ||
    blocked "no rehearsal run identity exists before fleet capture"

  REHEARSAL_R1_EXECUTED_IMAGES="$(
    executed_image_digest "${R1_IMAGE_DIGEST}"
  )" || blocked "cannot resolve the executed R1 image before fleet capture"

  local entries=()
  local service container container_id operator entry
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    container="$(compose ps --quiet "${service}" 2>/dev/null)" ||
      blocked "cannot resolve the running container for ${service} while \
capturing the authoritative R1 fleet"
    [[ -n "${container}" ]] ||
      blocked "${service} has no running container while capturing the \
authoritative R1 fleet"
    container_id="$(docker inspect --format '{{.Id}}' "${container}" \
      2>/dev/null)" ||
      blocked "cannot read the immutable container identity for ${service}"
    [[ "${container_id}" =~ ^[0-9a-f]{64}$ ]] ||
      blocked "${service} reports malformed container identity \
[${container_id:-absent}]"

    operator="$(node_operator_address "${service}" 2>/dev/null)" ||
      blocked "cannot read the chain operator identity for ${service}"
    operator="$(node -e '
      const value = String(process.argv[1] || "").toLowerCase();
      if (!/^0x[0-9a-f]{40}$/.test(value)) process.exit(1);
      process.stdout.write(value);
    ' "${operator}")" ||
      blocked "${service} reports a malformed chain operator identity"

    entry="$(node -e '
      process.stdout.write(JSON.stringify({
        service: process.argv[1],
        container_id: process.argv[2],
        operator_address: process.argv[3],
      }));
    ' "${service}" "${container_id}" "${operator}")" ||
      blocked "cannot encode the authoritative R1 identity for ${service}"
    entries+=("${entry}")
  done

  REHEARSAL_R1_FLEET="$(
    IFS=,
    printf '[%s]' "${entries[*]}"
  )"
  node -e '
    const fleet = JSON.parse(process.argv[1]);
    const services = fleet.map((instance) => instance.service);
    if (
      fleet.length === 0 ||
      new Set(services).size !== services.length
    ) process.exit(1);
  ' "${REHEARSAL_R1_FLEET}" ||
    blocked "the authoritative R1 fleet is empty or contains duplicate services"

  note "captured ${#entries[@]} authoritative R1 process identities for run \
${REHEARSAL_RUN_ID}"
}

r1_fleet_container_id() {
  node -e '
    const fleet = JSON.parse(process.argv[1]);
    const instance = fleet.find((entry) => entry.service === process.argv[2]);
    if (!instance) process.exit(1);
    process.stdout.write(instance.container_id);
  ' "${REHEARSAL_R1_FLEET}" "$1"
}

# Open the logging-only roster evidence window on every authoritative R1
# service, retain it until each process has authored two clock-healthy empty
# snapshots with advancing blocks at the five-minute production cadence,
# archive those exact timestamped lines, and close it only after the archive
# exists. The helper treats the supplied service list as an exact denominator:
# an ignored signal or unreadable node is a failure, never an implicit empty
# roster.
capture_cutover_roster_evidence_window() {
  local step="every R1 node authors periodic empty roster evidence"
  local assertion="every R1 node authors periodic empty roster evidence during the go/no-go window"
  local capture_id archive_id archive capture_context source_sha revision
  capture_id="$(node -e '
    const crypto = require("crypto");
    process.stdout.write(crypto.randomBytes(16).toString("hex"));
  ')" || blocked "cannot generate the fleet evidence-window capture identity"
  [[ "${capture_id}" =~ ^[0-9a-f]{32}$ ]] ||
    blocked "the generated fleet evidence-window capture identity is malformed"
  archive_id="cutover-roster-window-${capture_id}"
  archive="${EVIDENCE_DIR}/${archive_id}"
  source_sha="$(attested_source_identity)"
  revision="$(json_field "${REHEARSAL_R1_IDENTITY}" revision)"
  capture_context="$(node -e '
    const [
      runID, captureID, archiveID, sourceSha, imagesJSON, revision,
      epoch, chainID, cutoverBlock, fleetJSON,
    ] = process.argv.slice(1);
    process.stdout.write(JSON.stringify({
      schema_version: 1,
      run_id: runID,
      capture_id: captureID,
      archive_id: archiveID,
      gate: "single_release",
      source_sha: sourceSha,
      r1_image_digests: JSON.parse(imagesJSON),
      revision,
      protocol_epoch: epoch,
      chain_id: chainID,
      cutover_block: Number(cutoverBlock),
      r1_fleet: JSON.parse(fleetJSON),
    }));
  ' "${REHEARSAL_RUN_ID}" "${capture_id}" "${archive_id}" "${source_sha}" \
    "${REHEARSAL_R1_EXECUTED_IMAGES}" "${revision}" \
    "${REHEARSAL_R1_EPOCH}" "${CHAIN_ID}" \
    "${REHEARSAL_R1_CUTOVER_BLOCK}" "${REHEARSAL_R1_FLEET}")" ||
    blocked "cannot build the fleet evidence-window capture context"
  local service container container_id expected_container_id
  local bindings=()

  begin_step "${step}"

  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    if ! container="$(compose ps --quiet "${service}" 2>/dev/null)" ||
      [[ -z "${container}" ]]; then
      block_step "${step}" "${service} has no inspectable running container; \
the evidence window must be delivered to and acknowledged by every R1 service"
      record_assertion "${assertion}" false "${step}"
      return
    fi
    if ! container_id="$(docker inspect --format '{{.Id}}' "${container}" \
      2>/dev/null)" ||
      ! expected_container_id="$(r1_fleet_container_id "${service}")"; then
      block_step "${step}" "${service} has no readable immutable container \
identity at evidence-window open"
      record_assertion "${assertion}" false "${step}"
      return
    fi
    if [[ "${container_id}" != "${expected_container_id}" ]]; then
      block_step "${step}" "${service} changed from captured container \
[${expected_container_id}] to [${container_id}] before evidence-window open"
      record_assertion "${assertion}" false "${step}"
      return
    fi
    bindings+=("${service}=${container_id}")
  done

  local capture_rc=0
  "${SCRIPT_DIR}/capture-cutover-evidence-window.sh" \
    "${archive}" "${capture_context}" "${bindings[@]}" || capture_rc=$?

  if [[ -f "${archive}/result.json" ]]; then
    STEP_STATE_CHECKSUMS="\"cutover_evidence_window_summary_sha256\":\"$(
      hash_stdin <"${archive}/result.json"
    )\""
    STEP_EVIDENCE_REFS="\"cutover_evidence_window_archive\":$(
      json_string "${archive_id}"
    ),\"cutover_evidence_window_capture_id\":$(
      json_string "${capture_id}"
    )"
  fi

  if ((capture_rc == 0)); then
    record_step "${step}" pass "every R1 process acknowledged SIGUSR1, authored \
two clock-healthy empty roster snapshots with advancing blocks at the \
five-minute cadence, archived them, and acknowledged SIGUSR2 only after \
archival"
    record_assertion "${assertion}" true "${step}"
  else
    record_step "${step}" fail "the fleet evidence-window capture exited \
[${capture_rc}]; its archived result identifies the unsignaled, unreadable, \
uncadenced, nonempty-only, or unclosed service"
    record_assertion "${assertion}" false "${step}"
  fi
}

# Build the record and hand it to the acceptance stage's own validator. The
# stage that judges records is the one that decides whether this one is
# admissible, so emission never certifies its own output.
emit_evidence_record() {
  local manifest="${SCRIPT_DIR}/release-manifest.json"
  local record_suffix="${PR4109_EVIDENCE_RECORD_SUFFIX:-}"
  if [[ -n "${record_suffix}" ]] &&
    [[ ! "${record_suffix}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    blocked "PR4109_EVIDENCE_RECORD_SUFFIX [${record_suffix}] is not a safe \
record-name component; use only letters, digits, dots, underscores, and \
hyphens, beginning with a letter or digit"
  fi

  local record_name="${REHEARSAL_GATE}"
  if [[ -n "${record_suffix}" ]]; then
    record_name="${record_name}-${record_suffix}"
  fi

  local record
  record="${EVIDENCE_DIR}/${record_name}-$(date -u +%Y%m%dT%H%M%SZ).json"
  mkdir -p "${EVIDENCE_DIR}"
  [[ ! -e "${record}" ]] ||
    blocked "evidence record ${record} already exists; refusing to overwrite \
another account of this gate and platform"

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
  [[ "${REHEARSAL_RUN_ID}" =~ ^[0-9a-f]{32}$ ]] ||
    blocked "no valid run identity was created before this rehearsal began"
  [[ -n "${REHEARSAL_R1_FLEET}" ]] ||
    blocked "no authoritative R1 process identity was captured while the \
fleet was running"
  [[ -n "${REHEARSAL_R1_EXECUTED_IMAGES}" ]] ||
    blocked "no executed R1 image/platform identity was captured while the \
fleet was running"
  r1_digests="${REHEARSAL_R1_EXECUTED_IMAGES}"
  prior_digests="$(executed_image_digest "${PRIOR_IMAGE_DIGEST}")"

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
  PR4109_WORK_DRIVER_SHA256="${WORK_DRIVER_DIGEST}"
  PR4109_ROLLBACK_GENERATOR_SHA256="${ROLLBACK_GENERATOR_DIGEST}"
  PR4109_TSSLIB_REVIEW_SHA256="${TSSLIB_REVIEW_DIGEST}"
  export PR4109_WORK_DRIVER_SHA256 PR4109_ROLLBACK_GENERATOR_SHA256 \
    PR4109_TSSLIB_REVIEW_SHA256

  node -e '
    const fs = require("fs");
    const [
      manifestPath, runID, gate, sourceSha, identityJSON, r1JSON, priorJSON,
      fleetJSON, chainID, stepsJSON, assertionsJSON, generatedAt,
    ] = process.argv.slice(1);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    const identity = JSON.parse(identityJSON);
    const record = {
      schema_version: 1,
      run_id: runID,
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
      r1_fleet: JSON.parse(fleetJSON),
      chain: { chain_id: chainID, cutover_block: identity.cutover_block },
      release_manifest: {
        sha256: process.env.PR4109_MANIFEST_SHA256,
        termination_grace_period_seconds:
          manifest.termination_grace.termination_grace_period_seconds,
      },
      // The programs this rehearsal executed but does not contain. Preflight
      // has already refused any that did not hash to the reviewed digest, so
      // what is recorded here is a name for the instrument the readings below
      // were produced with rather than a claim the record makes about it.
      // The review record is named here for the same reason and with the same
      // meaning, except that preflight refused nothing by its absence: an
      // execution without it is a complete rehearsal whose record simply
      // cannot be accepted.
      chain_inputs: {
        work_driver_sha256: process.env.PR4109_WORK_DRIVER_SHA256 || undefined,
        rollback_evidence_generator_sha256:
          process.env.PR4109_ROLLBACK_GENERATOR_SHA256 || undefined,
        tsslib_review_sha256:
          process.env.PR4109_TSSLIB_REVIEW_SHA256 || undefined,
      },
      stages: JSON.parse("[" + stepsJSON + "]"),
      assertions: JSON.parse("[" + assertionsJSON + "]"),
    };
    process.stdout.write(JSON.stringify(record, null, 2) + "\n");
  ' "${manifest}" "${REHEARSAL_RUN_ID}" "${REHEARSAL_GATE}" \
    "${source_sha}" "${identity}" "${r1_digests}" "${prior_digests}" \
    "${REHEARSAL_R1_FLEET}" "${CHAIN_ID}" "${steps}" "${assertions}" \
    "$(node -e 'process.stdout.write(new Date().toISOString())')" \
    >"${record}" ||
    fail "cannot build the rehearsal evidence record"
  EMITTED_EVIDENCE_RECORD="${record}"
  unset PR4109_MANIFEST_SHA256 PR4109_WORK_DRIVER_SHA256 \
    PR4109_ROLLBACK_GENERATOR_SHA256 PR4109_TSSLIB_REVIEW_SHA256

  note "rehearsal evidence record written to ${record}"
  note "validating it with the acceptance stage's own validator"
  # Shape and binding only. This record is emitted by every rehearsal,
  # including one that just watched a mandatory step fail, and the point of
  # emitting it is that the refusal is reviewable — so the checks run here
  # are the ones that say the record is admissible. Whether its contents
  # accept the gate is conclude_verdict's decision on the way out, and the
  # acceptance stage's when a reviewer reads the directory later.
  validate_evidence_record_set "${record}"
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

  # Preserve the rehearsal's strongest first-hand verdict. A failed or
  # blocked step, or a refused assertion, already tells us more than a
  # secondary roster defect and conclude_verdict reports it with the exact
  # observations the run made.
  if ((${#REHEARSAL_FAILED_STEPS[@]} > 0 ||
    ${#REHEARSAL_BLOCKED_STEPS[@]} > 0 ||
    ${#REHEARSAL_REFUTED_ASSERTIONS[@]} > 0)); then
    conclude_verdict
  fi

  # A ledger containing an arbitrary passing subset used to reach the success
  # line below. Check the just-emitted record against the complete gate
  # contract first, through the same acceptance code used for archived
  # evidence.
  assess_evidence_record_set "${EMITTED_EVIDENCE_RECORD}"
  conclude_verdict
}

stage_preflight() {
  require_env PRIOR_IMAGE_DIGEST R1_IMAGE_DIGEST PROBE_IMAGE_DIGEST \
    ETH_WS_URL ETH_RPC_URL CUTOVER_BLOCK CHAIN_ID KEYSTORE_DIR \
    KEEP_ETHEREUM_PASSWORD
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

  # Before anything is started, because a fleet driven by an unreviewed
  # program has already produced the state every later reading is taken over.
  WORK_DRIVER_DIGEST="$(require_reviewed_input PR4109_WORK_DRIVER \
    work-driver "${PR4109_WORK_DRIVER:-}")"
  ROLLBACK_GENERATOR_DIGEST="$(require_reviewed_input \
    PR4109_ROLLBACK_EVIDENCE_GENERATOR rollback-evidence-generator \
    "${PR4109_ROLLBACK_EVIDENCE_GENERATOR:-}")"

  # Bound here rather than gating any step. Whether the dependency's
  # cryptographic review exists changes nothing about what a rehearsal can
  # execute or observe — the immutable images and the driver decide that — so
  # a missing review leaves every step runnable and is settled once, against
  # the emitted record, by the acceptance contract.
  TSSLIB_REVIEW_DIGEST="$(require_reviewed_record PR4109_TSSLIB_REVIEW \
    tsslib-review "${PR4109_TSSLIB_REVIEW:-}")"

  note "pulling both immutable digests to verify availability"
  docker pull "${PRIOR_IMAGE_DIGEST}"
  docker pull "${R1_IMAGE_DIGEST}"
  docker pull "${PROBE_IMAGE_DIGEST}"

  verify_chain_endpoint

  note "preflight passed"
}

# The endpoint every reported transaction is confirmed against has to be the
# chain the fleet ran on. An endpoint that answers about some other chain
# confirms transactions that have nothing to do with this rehearsal, and it
# answers in exactly the same shape — a receipt, a status, a block — so
# nothing downstream could tell the difference. The chain id is asked of the
# endpoint rather than restated from the dispatch input, because a configured
# value only ever agrees with itself.
verify_chain_endpoint() {
  local reported
  reported="$(endpoint_chain_id)"
  if [[ "${reported}" == "unreadable" ]]; then
    blocked "the ETH_RPC_URL endpoint did not report a chain id this \
rehearsal can read; every transaction a driver names is confirmed against \
this endpoint, and one that cannot be questioned confirms nothing"
  fi
  if [[ "${reported}" != "${CHAIN_ID}" ]]; then
    blocked "the ETH_RPC_URL endpoint reports chain id [${reported}], but \
this rehearsal names [${CHAIN_ID}]; transactions confirmed against another \
chain say nothing about the work this fleet did"
  fi
  note "chain endpoint confirmed on chain id ${reported}"
}

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
  deadline=$((SECONDS + NODE_REACHABILITY_TIMEOUT_SECONDS))
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

# The rollback inputs the offline audit cannot derive from a storage snapshot.
# Everything the fleet can be asked for is read from the fleet; what remains is
# genuinely outside this repository — reconciliation against the live Ethereum
# and Bitcoin state, each node's own quiescence outcome record, the prior
# release's reader-compatibility result, and the identity of the prior artifact
# the rollback restores — so it arrives as a generator this run executes and a
# handful of values. A missing one blocks the barrier rather than being
# skipped: an audit run without them reports namespace consistency and nothing
# about whether rolling back onto this state is safe, and unbound evidence
# would approve a rollback of the wrong chain, network, or artifact just as
# readily.
#
# The evidence is generated here rather than supplied because every record has
# to name the exact snapshot it speaks for — the audit rejects a record whose
# snapshot_aggregate_sha256 is anything but the audited snapshot's — and that
# checksum does not exist until this run has drained the fleet and copied the
# state out. A record handed in before the rehearsal started cannot know it,
# and one that carried it anyway would be describing a drain that had not
# happened yet.
ROLLBACK_AUDIT_INPUTS=(
  PR4109_ROLLBACK_EVIDENCE_GENERATOR
  PR4109_WALLET_REGISTRY_ADDRESS
  PR4109_RANDOM_BEACON_ADDRESS
  PR4109_FINALIZED_ETHEREUM_BLOCK_NUMBER
  PR4109_FINALIZED_ETHEREUM_BLOCK_HASH
  PR4109_CHAIN_EVIDENCE_PUBLIC_KEY
  PR4109_BITCOIN_NETWORK
  PR4109_PRIOR_VERSION
  PR4109_PRIOR_REVISION
)

# The records the generator must produce for one audited snapshot, named
# exactly as the audit reads them back.
ROLLBACK_EVIDENCE_RECORDS=(
  chain-reconciliation.json
  bitcoin-reconciliation.json
  quiescence-report.json
  prior-reader-compatibility.json
)

# Why the last audited snapshot is not rollback-safe, for the step that
# records it. Set by run_state_audit whenever it returns nonzero.
STATE_AUDIT_REASON=""

# One invocation of the offline audit over one snapshot. With an evidence
# directory it is the authorizing pass; without one it is the identity pass,
# which reports every external input missing on purpose — that run exists to
# derive the snapshot's checksum and interpreted inventory, which is what the
# evidence must then be generated against.
#
# The identities the audit binds its evidence to are the ones already read off
# the running fleet — release version, revision, epoch, and armed C — so the
# rollback is authorized against what ran rather than against what the operator
# believed ran.
audit_snapshot() {
  local snapshot="$1" output="$2" evidence="$3"
  local arguments=(
    --storage-snapshot "${snapshot}"
    --output "${output}"
    --expected-ethereum-chain-id "${CHAIN_ID}"
    --expected-wallet-registry-address
    "${PR4109_WALLET_REGISTRY_ADDRESS}"
    --expected-random-beacon-address
    "${PR4109_RANDOM_BEACON_ADDRESS}"
    --expected-finalized-ethereum-block-number
    "${PR4109_FINALIZED_ETHEREUM_BLOCK_NUMBER}"
    --expected-finalized-ethereum-block-hash
    "${PR4109_FINALIZED_ETHEREUM_BLOCK_HASH}"
    --expected-chain-evidence-public-key
    "${PR4109_CHAIN_EVIDENCE_PUBLIC_KEY}"
    --expected-bitcoin-network "${PR4109_BITCOIN_NETWORK}"
    --expected-prior-version "${PR4109_PRIOR_VERSION}"
    --expected-prior-revision "${PR4109_PRIOR_REVISION}"
    --expected-prior-image-digest "${PRIOR_IMAGE_DIGEST##*@}"
    --expected-release-version
    "$(json_field "${REHEARSAL_R1_IDENTITY}" version)"
    --expected-release-revision
    "$(json_field "${REHEARSAL_R1_IDENTITY}" revision)"
    --expected-release-image-digest "${R1_IMAGE_DIGEST##*@}"
    --expected-release-epoch "${REHEARSAL_R1_EPOCH}"
    --expected-cutover-block "${REHEARSAL_R1_CUTOVER_BLOCK}"
  )
  if [[ -n "${evidence}" ]]; then
    arguments+=(
      --chain-reconciliation-evidence "${evidence}/chain-reconciliation.json"
      --bitcoin-reconciliation-evidence
      "${evidence}/bitcoin-reconciliation.json"
      --quiescence-report "${evidence}/quiescence-report.json"
      --prior-reader-compatibility-evidence
      "${evidence}/prior-reader-compatibility.json"
    )
  fi
  (cd "${REPO_ROOT}" && go run ./cmd/participation-state-audit "${arguments[@]}")
}

# The snapshot identity an identity pass derived, or empty when that pass
# derived none. Every generated record has to name this exact value, and the
# audit refuses any that names another.
snapshot_identity() {
  node -e '
    const fs = require("fs");
    const audit = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    if (audit.consistent !== true) {
      console.error(
        "the snapshot is not internally consistent: " +
          (audit.findings || []).join("; ")
      );
      process.exit(1);
    }
    const aggregate = (audit.snapshot || {}).aggregate_sha256;
    if (!aggregate) {
      console.error("the manifest derived no snapshot aggregate checksum");
      process.exit(1);
    }
    process.stdout.write(String(aggregate));
  ' "$1"
}

# Audit one node's storage snapshot for rollback safety. Returns 0 only when
# the tool itself reported rollback_barrier_ready over the full evidence set;
# the manifest it wrote is left beside the rehearsal record either way, because
# a refusal is the part of a rollback decision most worth reading.
#
# The audit runs twice over the same snapshot, and the order is the whole
# point. Every external record must carry the audited snapshot's aggregate
# checksum, and that checksum is a fact about state this rehearsal has only
# just produced — so the first pass derives it from the captured bytes, the
# generator is then run against that manifest to produce records for this
# snapshot and no other, and the second pass is the one that authorizes
# anything. Evidence handed in before the fleet drained could not have named
# this snapshot, and evidence that named it anyway would be describing a drain
# that had not happened.
run_state_audit() {
  local service="$1" snapshot="$2"
  # Both manifests and the generated records live one level down, beside the
  # rehearsal record rather than among them: the acceptance stage validates
  # every JSON at the top of the evidence directory against the rehearsal
  # record schema, and an audit manifest is a different document that would
  # fail that check for saying what it is rather than for anything wrong.
  local audits="${EVIDENCE_DIR}/state-audit"
  local identity="${audits}/${service}-identity.json"
  local output="${audits}/${service}.json"
  local evidence="${audits}/${service}-evidence"
  STATE_AUDIT_REASON=""

  if ! mkdir -p "${audits}"; then
    STATE_AUDIT_REASON="cannot create ${audits} for ${service}'s audit \
manifests"
    return 1
  fi

  # The paths are fixed per service, so a re-run that never reaches the tool —
  # or one whose tool dies before writing — would otherwise be read through
  # the manifest an earlier run left at them. Removing them first makes the
  # presence of a manifest below evidence that this run produced one, and the
  # same holds for every record the generator is about to be asked for.
  rm -f "${identity}" "${output}"
  rm -rf "${evidence}"

  local missing=() name
  for name in "${ROLLBACK_AUDIT_INPUTS[@]}"; do
    if [[ -z "${!name:-}" ]]; then
      missing+=("${name}")
    fi
  done
  if ((${#missing[@]} > 0)); then
    STATE_AUDIT_REASON="the audit cannot authorize a rollback without \
${missing[*]}; from a snapshot alone it reports namespace consistency and \
nothing about the live-chain reconciliation, this node's quiescence \
outcomes, or the prior release's ability to read what this one wrote"
    return 1
  fi
  if [[ ! -x "${PR4109_ROLLBACK_EVIDENCE_GENERATOR}" ]]; then
    STATE_AUDIT_REASON="PR4109_ROLLBACK_EVIDENCE_GENERATOR names \
[${PR4109_ROLLBACK_EVIDENCE_GENERATOR}], which is not executable; the records \
that authorize a rollback are produced for the snapshot this run captured and \
cannot be produced by anything else"
    return 1
  fi

  note "deriving ${service}'s snapshot identity for the evidence to bind to"
  local rc=0
  audit_snapshot "${snapshot}" "${identity}" "" || rc=$?
  if [[ ! -f "${identity}" ]]; then
    STATE_AUDIT_REASON="the identity pass over ${service}'s snapshot exited \
[${rc}] without writing a manifest to ${identity}, so this run derived no \
snapshot for evidence to be generated against"
    return 1
  fi
  # A nonzero exit is expected here and carries no information: the identity
  # pass is deliberately run with no evidence at all, and every missing record
  # is a rollback blocker. What must hold is that the snapshot read cleanly and
  # produced a checksum, which is what the pass exists to establish.
  local aggregate
  if ! aggregate="$(snapshot_identity "${identity}" 2>&1)"; then
    STATE_AUDIT_REASON="the identity pass over ${service}'s snapshot did not \
establish one (manifest in ${identity}): ${aggregate}"
    return 1
  fi

  note "${service}: generating rollback evidence for snapshot ${aggregate}"
  if ! mkdir -p "${evidence}"; then
    STATE_AUDIT_REASON="cannot create ${evidence} for ${service}'s generated \
rollback evidence"
    return 1
  fi
  rc=0
  "${PR4109_ROLLBACK_EVIDENCE_GENERATOR}" "${service}" "${identity}" \
    "${evidence}" || rc=$?
  if ((rc != 0)); then
    STATE_AUDIT_REASON="the rollback evidence generator exited [${rc}] for \
${service}'s snapshot ${aggregate}, so this rehearsal has no reconciliation, \
quiescence, or prior-reader result for the state the drain actually left"
    return 1
  fi
  local absent=() record
  for record in "${ROLLBACK_EVIDENCE_RECORDS[@]}"; do
    [[ -f "${evidence}/${record}" ]] || absent+=("${record}")
  done
  if ((${#absent[@]} > 0)); then
    STATE_AUDIT_REASON="the rollback evidence generator exited cleanly but \
wrote no ${absent[*]} for ${service} into ${evidence}; every one of them is a \
rollback blocker the audit cannot decide without"
    return 1
  fi

  note "auditing ${service}'s storage snapshot for rollback safety"
  rc=0
  audit_snapshot "${snapshot}" "${output}" "${evidence}" || rc=$?

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
# transaction_hashes array and a ceremony_results array. The hashes go into the
# step being recorded, so a reviewer can follow a step back to the chain
# transactions that caused it rather than taking the fleet counters as the only
# account of what happened. The results are the terminal outcome of each
# ceremony those transactions started, which is the one thing no fleet counter
# can supply: a permit says a node was allowed to begin, and a positive control
# is about a ceremony that finished. The output is either well formed or it is
# a broken instrument: a driver whose report cannot be read has left the step
# unable to say what it drove, and treating that as "nothing happened" would
# record silence as evidence.

# What the last run_work_driver call reported: its exit status, how many chain
# transactions it accounted for, and which ceremonies it saw complete.
#
# The first two are needed before a step may say work was offered. `|| true`
# around a driver call turns a driver that failed, that was never installed, or
# that originated nothing at all into "attempted", and every one of those
# leaves the node in exactly the state a node nobody asked is in. A step whose
# contract is that the gate refused something has to know something was
# actually put on the chain for it to refuse.
WORK_DRIVER_RC=0
WORK_DRIVER_TX_COUNT=0
# Every terminal outcome the driver reported, space-joined as
# "<ceremony>=<outcome>". This is what a phase reads when the outcomes it must
# not see are as load-bearing as the ones it must. What a phase decides a
# control on is the bound form below: this one names what happened without
# naming what it happened to.
WORK_DRIVER_CEREMONY_RESULTS=""
# The ceremonies the driver put on the chain, whatever became of them. A phase
# whose subject is work still in flight — a drain, a forced deadline — has no
# terminal outcome to read: by the time one exists the work it was about is
# over. This is what such a phase reads to know what kind of work it drained.
WORK_DRIVER_ORIGINATED=""
# The same outcomes with what ties each one to the chain and to what it left
# behind, space-joined as "<ceremony>=<outcome>=<transaction>=<identity>".
#
# The projections above are populations that happen to sit beside each other:
# read from them, a control cannot tell a ceremony this driver originated from
# one that was already running, nor a ceremony that produced a threshold
# output from a report that merely says "succeeded". The identity is the
# threshold output for a ceremony that settled and the termination — retries
# exhausted, or no threshold reached — for one that did not, which is the
# distinction between work that came to nothing and work still trying.
WORK_DRIVER_BOUND_RESULTS=""
# The same in-flight permits with the identity that survives to their outcome,
# space joined as "<ceremony>@<canonical start block>@<chain-work-id>=\
# <transaction>=<holder>~<local-permit-id>".
#
# The ceremony list above says what kind of work drained; it cannot say how
# much. Two runs of one ceremony are the same word and two permits on every
# node that joined them, so a reconciliation reading ceremony names counts a
# population it never established the size of — which is how permits with no
# outcome behind them reconcile against an outcome belonging to something else.
# The chain work ID distinguishes work items sharing an anchor; the holder and
# local permit ID distinguish several permits one node took for that work.
WORK_DRIVER_ORIGINATED_WORK=""
# Every party whose share the settled result actually incorporated, space
# joined as "<ceremony>@<canonical start block>@<chain-work-id>=\
# <service>~<local-permit-id>".
#
# A mixed-fleet control needs this and cannot get it anywhere else. That a
# container is running says nothing about whether the release inside it took
# part: an unselected, disconnected, or cryptographically excluded party leaves
# a running container beside a ceremony that settled without it, which reads
# from outside exactly like interoperation. Only the transcript names who
# contributed to the result, so the driver has to carry it out.
WORK_DRIVER_RESULT_CONTRIBUTORS=""

# How long a reported transaction may still be unmined before the rehearsal
# stops waiting for it. A transaction that started work the fleet is holding
# has already been mined — the event that anchors a ceremony comes out of a
# mined transaction — so this covers submission latency rather than a wait for
# something to happen.
WORK_DRIVER_CONFIRMATION_TIMEOUT=180

# Confirm on the chain the fleet ran on that every transaction the last report
# named is really there, succeeded, and landed no later than the anchor the
# report claims for the work it started.
#
# Without this the whole account is the driver's own. Every field is checked
# for shape and cross-referenced against the other fields of the same report,
# and a report that is internally consistent and entirely invented passes all
# of it: the hashes look like hashes, the outcomes name them, and nothing has
# asked the chain whether any of it happened. A reverted transaction is the
# same shape as a successful one from outside, and an anchor earlier than the
# block its own transaction landed in is work attributed to a ceremony that
# had not started yet.
confirm_reported_work() {
  local phase="$1" hashes="$2" records="$3" bound="$4"
  local tx list pending reading status block deadline record anchor

  [[ -n "${hashes//[[:space:]]/}" ]] || return 0
  [[ -n "${ETH_RPC_URL:-}" ]] ||
    blocked "the ${phase} phase reported transactions, but no ETH_RPC_URL was \
supplied to confirm them on the chain the fleet ran on; a report nobody \
questioned is the driver's own account of itself"

  list="${hashes//\"/}"
  list="${list//,/ }"

  # Every hash, waited on together rather than one at a time, so a report
  # naming several does not spend the timeout on each in turn.
  deadline=$((SECONDS + WORK_DRIVER_CONFIRMATION_TIMEOUT))
  while :; do
    pending=""
    for tx in ${list}; do
      reading="$(transaction_receipt "${tx}")"
      status="${reading%% *}"
      case "${status}" in
      succeeded) ;;
      pending) pending="${pending}${pending:+, }${tx}" ;;
      reverted)
        blocked "the ${phase} phase reported transaction ${tx}, which the \
rehearsal chain records as reverted; work that never happened cannot be the \
work a control was decided on"
        ;;
      *)
        blocked "the ${phase} phase reported transaction ${tx}, and the \
rehearsal chain endpoint could not be asked what became of it; an \
unconfirmed transaction leaves the report as the driver's own account of \
itself"
        ;;
      esac
    done
    [[ -n "${pending}" ]] || break
    if ((SECONDS >= deadline)); then
      blocked "the ${phase} phase reported ${pending}, which the rehearsal \
chain still has no receipt for after \
${WORK_DRIVER_CONFIRMATION_TIMEOUT}s; a transaction that never landed started \
no ceremony for this fleet to have participated in"
    fi
    sleep 5
  done

  # And the anchors, against the blocks those transactions landed in. The
  # anchor is what pins a permit's mode, so an anchor before its own
  # transaction is a mode selected from a block at which the work did not
  # exist — and it is exactly what a report inventing anchors produces.
  # The two record shapes carry the transaction in different positions, so
  # each is read through its own accessor rather than through whichever one
  # happens to be in scope.
  for record in ${records}; do
    confirm_record_anchor "${phase}" "$(work_id "${record}")" \
      "$(work_transaction "${record}")"
  done
  for record in ${bound}; do
    confirm_record_anchor "${phase}" "$(bound_work "${record}")" \
      "$(bound_transaction "${record}")"
  done
}

# One work identity against the block its transaction landed in.
confirm_record_anchor() {
  local phase="$1" work="$2" tx="$3" anchor block reading remainder
  remainder="${work#*@}"
  anchor="${remainder%%@*}"
  [[ "${anchor}" =~ ^[0-9]+$ ]] || return 0
  [[ "${tx}" =~ ^0x[0-9a-f]{64}$ ]] || return 0
  reading="$(transaction_receipt "${tx}")"
  block="${reading##* }"
  [[ "${block}" =~ ^[0-9]+$ ]] || return 0
  if ((anchor < block)); then
    blocked "the ${phase} phase anchors ${work} at block ${anchor}, but the \
transaction it names landed in block ${block}; a permit cannot pin its mode \
from a block at which the work it is for did not exist"
  fi
}

# True when the last driver call both exited cleanly and named what it put on
# the chain, which is the whole of "work was offered here".
driver_offered_work() {
  ((WORK_DRIVER_RC == 0)) && ((WORK_DRIVER_TX_COUNT > 0))
}

# The release half a ceremony belongs to. tBTC and the beacon take their
# permits from the same gate through different call paths, so a control that
# only ever ran one of them says nothing about the other: a cutover that broke
# the beacon path would still produce a clean report from a driver that drove
# tBTC alone.
ceremony_family() {
  case "$1" in
  tbtc_*) printf 'tbtc' ;;
  beacon_*) printf 'beacon' ;;
  *) printf 'unknown' ;;
  esac
}

# Every result the driver reported that did not succeed, comma-joined for the
# record. A phase reads this so that one required ceremony failing beside a
# passing one cannot be dropped on the way to a verdict.
unsuccessful_results() {
  local results="$1" result out=""
  for result in ${results}; do
    [[ "${result#*=}" == "succeeded" ]] && continue
    out="${out}${out:+, }${result}"
  done
  printf '%s' "${out}"
}

# The kind of work a ceremony is, for the phases that must drain more than one
# kind at once. The two fail differently under an interrupted shutdown: a
# threshold ceremony cut off mid-round loses a share and can be re-run, while a
# wallet action cut off mid-flight can leave a Bitcoin transaction this fleet
# has already signed for and cannot unsign.
ceremony_class() {
  case "$1" in
  *_wallet_action) printf 'bitcoin_action' ;;
  *_dkg | *_signing | *_heartbeat) printf 'threshold_ceremony' ;;
  *) printf 'unknown' ;;
  esac
}

# Of the required work classes, the ones no originated ceremony represents.
# Space-joined, empty when every required class is in flight.
missing_work_classes() {
  local originated="$1" required="$2" class ceremony uncovered="" covered
  for class in ${required}; do
    covered=0
    for ceremony in ${originated}; do
      [[ "$(ceremony_class "${ceremony}")" == "${class}" ]] || continue
      covered=1
      break
    done
    ((covered == 1)) || uncovered="${uncovered}${uncovered:+ }${class}"
  done
  printf '%s' "${uncovered}"
}

# The fields of one bound result,
# "<work>=<outcome>=<transaction>=<identity>", where <work> is the work
# identity "<ceremony>@<canonical start block>@<chain-work-id>". Split here
# rather than at each reader so no control invents its own reading of a record
# whose whole purpose is that every control reads it the same way.
bound_work() {
  printf '%s' "${1%%=*}"
}

bound_outcome() {
  local rest
  rest="${1#*=}"
  printf '%s' "${rest%%=*}"
}

bound_transaction() {
  local rest
  rest="${1#*=}"
  rest="${rest#*=}"
  printf '%s' "${rest%%=*}"
}

bound_identity() {
  printf '%s' "${1##*=}"
}

# The ceremony half of a work identity. The anchor half is what distinguishes
# two runs of the same ceremony from each other; the ceremony half is what the
# class and family readers are about, and reading a whole identity as a
# ceremony name would put every one of them in the "unknown" bucket.
work_ceremony() {
  printf '%s' "${1%%@*}"
}

# The fields of one originated-permit record,
# "<work>=<transaction>=<holder>~<permit-id>". Work is
# "<ceremony>@<canonical start block>@<chain-work-id>". There is one record per
# local permit, rather than one record per ceremony or holder name: one node
# can control several memberships in the same chain work and therefore hold
# several permits with the same ceremony, anchor, transaction, and holder.
work_id() {
  printf '%s' "${1%%=*}"
}

work_transaction() {
  local rest
  rest="${1#*=}"
  printf '%s' "${rest%%=*}"
}

# The canonical start block a work identity is anchored at. The gate pins a
# permit's mode from this block and not from the current height, so it is the
# only field that says which side of C a permit belongs to.
work_anchor() {
  local remainder
  remainder="${1#*@}"
  printf '%s' "${remainder%%@*}"
}

# Of a set of originated records, the ones whose anchor puts them on the wrong
# side of C for the mode named. A control that drains "legacy" permits is about
# work anchored below the cutover block; work anchored at or above it takes a
# security-v2 permit however the control is labelled, and an unreadable anchor
# says nothing either way.
misanchored_for_mode() {
  local records="$1" mode="$2" cutover="$3" record anchor out=""
  [[ "${cutover}" =~ ^[0-9]+$ ]] || {
    printf '%s' "${records}"
    return 0
  }
  for record in ${records}; do
    anchor="$(work_anchor "$(work_id "${record}")")"
    if [[ ! "${anchor}" =~ ^[0-9]+$ ]]; then
      out="${out}${out:+, }$(permit_identity "${record}") (anchor unreadable)"
      continue
    fi
    case "${mode}" in
    legacy) ((anchor < cutover)) && continue ;;
    security-v2) ((anchor >= cutover)) && continue ;;
    *) continue ;;
    esac
    out="${out}${out:+, }$(permit_identity "${record}") (anchored at \
${anchor}, C is ${cutover})"
  done
  printf '%s' "${out}"
}

work_permit() {
  printf '%s' "${1##*=}"
}

permit_holder() {
  printf '%s' "${1%%~*}"
}

permit_local_id() {
  printf '%s' "${1#*~}"
}

# Whether a space-joined list contains an exact token, preserving
# multiplicity. Substring tests are what make "r1-node-1" match "r1-node-10",
# and set projection is what makes two local memberships look like one.
contains_token() {
  local list="$1" token="$2" item
  for item in ${list}; do
    [[ "${item}" == "${token}" ]] && return 0
  done
  return 1
}

# The originated-permit records one node took a permit for, space-joined.
work_records_held_by() {
  local records="$1" holder="$2" record permit out=""
  for record in ${records}; do
    permit="$(work_permit "${record}")"
    [[ "$(permit_holder "${permit}")" == "${holder}" ]] || continue
    out="${out}${out:+ }${record}"
  done
  printf '%s' "${out}"
}

# One permit record's identity, which retains the local permit after the chain
# work it belongs to. This is the unit counted and matched to quarantine.
permit_identity() {
  printf '%s#%s' "$(work_id "$1")" \
    "$(permit_local_id "$(work_permit "$1")")"
}

# The same identity rendered the way a gate scrape renders its own permits:
# "<holder>@<gate ceremony>@<canonical start block>@<chain work>#<permit>".
#
# Every component is load-bearing. Two nodes can issue permits with the same
# local id for the same chain work, so the holder belongs inside the identity
# rather than beside it. Work ids and local permit ids repeat across ceremonies
# and across runs of one ceremony — a beacon member index is "1" in every group
# that node ever joins — so an identity that named only those two lets a permit
# from one ceremony be answered by the record of another, and a pre-cutover
# permit be answered by a post-cutover one at the same work id. The ceremony is
# in the gate's own vocabulary rather than the driver's, because the record
# this identity has to join to is the one the gate wrote.
held_permit_identity() {
  local permit
  permit="$(work_permit "$1")"
  printf '%s@%s#%s' "$(permit_holder "${permit}")" \
    "$(audited_work_id "$(work_id "$1")")" "$(permit_local_id "${permit}")"
}

held_permit_identities() {
  local records="$1" record out=""
  for record in ${records}; do
    out="${out}${out:+ }$(held_permit_identity "${record}")"
  done
  printf '%s' "${out}"
}

# The tokens of the first list the second does not contain, comma-joined. The
# asymmetry is the point: asked one way it names what went missing, asked the
# other way it names what turned up unaccounted for, and a control that has to
# say "these exact permits" needs both directions rather than a total.
absent_tokens() {
  local wanted="$1" have="$2" token out=""
  for token in ${wanted}; do
    contains_token "${have}" "${token}" && continue
    out="${out}${out:+, }${token}"
  done
  printf '%s' "${out}"
}

# The tokens of the first list the second also contains, space-joined for use
# as a list rather than as prose. Where absent_tokens names a disagreement
# between two readings, this names what both of them account for — which is
# what a control needs when it may excuse only the identities two independent
# readings agree on, and neither reading alone is allowed to decide.
present_tokens() {
  local wanted="$1" have="$2" token out=""
  for token in ${wanted}; do
    contains_token "${have}" "${token}" || continue
    out="${out}${out:+ }${token}"
  done
  printf '%s' "${out}"
}

# ---------------------------------------------------------------------------
# Joining an originated permit to the ending its own holder recorded
#
# The driver originates work and the driver reports what became of it, which
# makes the whole account one party's. These helpers put the node between the
# two: every permit a control names has to be found, exactly once, in the
# node-authored record of permits that node closed, and the disposition read
# there is the node's own rather than the driver's.
#
# The tokens on both sides open with the permit identity a gate scrape renders,
# "<service>@<gate ceremony>@<anchor>@<chain work>#<permit>", which carries no
# "=" of its own. The node-authored side appends what its holder recorded:
# "=<outcome>=<evidence kind>=<result>=<membership>=<incorporated>=<local>=
# <settlement>=<operated>", with "-" wherever the gate carries no value. The
# three membership sets are comma-joined ascending, and the incorporated one
# carries the mapping back to its permits' index space after a "|" where the two
# spaces differ.
#
# The last field is the permit's rather than the ending's: it is the seats the
# holder said it was operating when the permit was issued, so it is there on
# every record whatever the ending, including the ones that produced nothing to
# write a transcript about.
# ---------------------------------------------------------------------------

# The permit identity a node-authored outcome token names, without its ending.
authored_permit() {
  printf '%s' "${1%%=*}"
}

# The ending it names.
authored_outcome() {
  local rest
  rest="${1#*=}"
  printf '%s' "${rest%%=*}"
}

# The kind of durable state the holder says the ending left behind.
authored_evidence_kind() {
  local rest
  rest="${1#*=}"
  rest="${rest#*=}"
  printf '%s' "${rest%%=*}"
}

# The identity of that state — the wallet storage key, group public key, or
# protocol result digest the ceremony produced — or "-" for the endings that
# leave none.
#
# This is the field a categorical ending cannot substitute for. Every node that
# finished the same piece of work writes "completed" whatever it actually
# produced, so the word alone cannot distinguish a fleet that agreed on one
# threshold output from one whose members each finished something else. The
# result identity is node-authored and shared: it is derived from the durable
# output itself, so two holders of the same ceremony write the same value and a
# holder of a different one cannot.
authored_result() {
  local rest
  rest="${1#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  printf '%s' "${rest%%=*}"
}

# The membership a completed DKG permit persisted, or "-" for the endings that
# persist none.
#
# The final signing group index can differ from the DKG index the permit was
# issued under, so this is the field that joins a holder to the wallet seat the
# chain knows it by rather than to the seat it started the ceremony in.
authored_membership() {
  local rest
  rest="${1#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  printf '%s' "${rest%%=*}"
}

# The memberships the holder says produced the result, comma-joined ascending,
# or "-" for the endings that name none.
#
# This is the half of a transcript no completion can substitute for. Every
# member of a finished ceremony writes "completed" and names the same result, so
# a reader holding only those cannot tell shares that combined from several
# parties from one party that arrived at the common result alone.
authored_incorporated() {
  local field
  field="$(authored_incorporated_field "$1")"
  printf '%s' "${field%%|*}"
}

# The whole field those memberships share with the mapping back to the permits'
# index space, "<memberships>" or "<memberships>|<mapping>". The two accessors
# above split it; nothing else should read it directly.
authored_incorporated_field() {
  local rest
  rest="${1#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  printf '%s' "${rest%%=*}"
}

# Of those memberships, the ones the holder says it operated itself,
# comma-joined ascending, or "-" when none of them were its own.
#
# Held against the incorporated set across the whole fleet, this is what makes a
# mixed reading node-authored: memberships the fleet says it produced but nobody
# in the fleet claims to have operated are memberships supplied from outside it.
authored_local() {
  local rest
  rest="${1#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  printf '%s' "${rest%%=*}"
}

# The seat in the index space this work's permits were issued in behind each of
# the incorporated memberships above, comma-joined and aligned with them position
# for position, or "-" for the records whose transcript already speaks in that
# space.
#
# This is what makes an ownership map readable against a transcript at all where
# the two index spaces differ. A tBTC DKG group is rebuilt from the members the
# recording node saw operating, so every seat above a removed one shifts down:
# the permits on that work name ceremony seats, the transcript names final seats,
# and joining the two by number attributes a final seat to whichever party holds
# that number in the other space. The mapping is the accepted result's own, and
# the gate has already held it to the recording permit's own seat.
#
# It rides on the incorporated field after a "|" rather than occupying a field of
# its own, because the two are one aligned pair: read apart from the list it
# lines up with, a mapping says which ceremony seats survived and not which seat
# each of them became. Keeping them together is what makes losing the pairing
# impossible.
authored_permit_space() {
  local field
  field="$(authored_incorporated_field "$1")"
  case "${field}" in
    *'|'*) printf '%s' "${field##*|}" ;;
    *) printf '%s' '-' ;;
  esac
}

# The chain side effect the same permit dispatched beyond its own protocol
# result, "<kind>" or "<kind>:<canonical identity>", or "-" for the permits
# that dispatched none.
authored_settlement() {
  local rest
  rest="${1#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  rest="${rest#*=}"
  printf '%s' "${rest%%=*}"
}

# The memberships the permit's holder said it was operating when the permit was
# issued, comma-joined ascending, or "-" for the permits that operate none.
#
# This is the field an ownership map is built from, and it is a different
# statement from the transcript's local half above. The transcript exists only
# where a ceremony reached a result, so a map assembled from transcripts covers
# the holders that finished and omits the ones that contributed and then crashed,
# timed out, or ended with nothing to record. Every one of those still operated
# its seats, and a seat missing from the fleet's map is a seat attributed to
# whichever other release was on the network — which is the whole mixed-release
# claim, decided by an omission.
authored_operated() {
  printf '%s' "${1##*=}"
}

# Of the permits a control named, the ones a node still reports holding open,
# comma-joined.
#
# A permit is held or closed and never both, so a named permit in the held list
# has no ending anywhere for a reader to find. Read by the check below it comes
# out as a permit whose holder would not say how it ended, which is a finding
# about a fleet that authored nothing — the opposite of a fleet whose ceremony
# is still running. The two have to be told apart before either is reported.
held_open_permits() {
  local wanted="$1" held="$2" permit token out=""
  for permit in ${wanted}; do
    for token in ${held}; do
      [[ "${token%%=*}" == "${permit}" ]] || continue
      out="${out}${out:+, }${permit}"
      break
    done
  done
  printf '%s' "${out}"
}

# Of the permits a control named, the ones no node recorded an ending for,
# comma-joined.
#
# This is the case that lets a partial population pass: two permits held across
# the crossing, one of them closed with a record, the other simply never
# mentioned by any node. It is also how eviction surfaces — the gate's account
# is bounded and forgets its oldest first — and both endings are the same thing
# to a reader, which is that no node will vouch for how this permit ended.
#
# A permit still open is not one of them, and the check above names it first:
# asked of a held permit this would report exactly what it reports of a
# forgotten one.
unauthored_permits() {
  local wanted="$1" authored="$2" token permits=""
  for token in ${authored}; do
    permits="${permits}${permits:+ }$(authored_permit "${token}")"
  done
  absent_tokens "${wanted}" "${permits}"
}

# Of the permits a control named, the ones more than one node-authored record
# claims to be the ending of, comma-joined.
#
# One permit ends once. A second record for the same identity is either a
# duplicate or two dispositions for one ceremony, and a control reading the
# first match it finds would take whichever came first as the answer.
duplicated_authored_permits() {
  local wanted="$1" authored="$2" token permit seen count out=""
  for permit in ${wanted}; do
    count=0
    for token in ${authored}; do
      seen="$(authored_permit "${token}")"
      [[ "${seen}" == "${permit}" ]] && count=$((count + 1))
    done
    ((count > 1)) || continue
    out="${out}${out:+, }${permit} (${count} records)"
  done
  printf '%s' "${out}"
}

# The ending one named permit's holder recorded for it, empty when none did.
# Reads the last record rather than the first: the account is in closing order,
# so where a duplicate slipped past the check above the later disposition is
# the one that stands.
authored_ending() {
  local permit="$1" authored="$2" token out=""
  for token in ${authored}; do
    [[ "$(authored_permit "${token}")" == "${permit}" ]] || continue
    out="$(authored_outcome "${token}")"
  done
  printf '%s' "${out}"
}

# Of the permits a control named, the ones whose own holder recorded no
# disposition, rendered with the ending, comma-joined.
#
# "unresolved" is what the gate writes when a permit is closed by an owner that
# recorded nothing. It is a real ending and it is the one a reader must refuse:
# the ceremony went somewhere the node cannot say, so nothing about it can be
# read off the fact that its permit is gone.
unresolved_authored_permits() {
  local wanted="$1" authored="$2" permit ending out=""
  for permit in ${wanted}; do
    ending="$(authored_ending "${permit}" "${authored}")"
    [[ "${ending}" == "unresolved" ]] || continue
    out="${out}${out:+, }${permit}=${ending}"
  done
  printf '%s' "${out}"
}

# The named permits and the endings their holders recorded, comma-joined for
# prose. This is what a passing verdict quotes instead of the driver's account
# of the same permits.
authored_endings() {
  local wanted="$1" authored="$2" permit ending out=""
  for permit in ${wanted}; do
    ending="$(authored_ending "${permit}" "${authored}")"
    out="${out}${out:+, }${permit}=${ending:-unrecorded}"
  done
  printf '%s' "${out}"
}

# Of the named permits, the ones whose holder recorded an ending outside the
# allowed set, rendered with what was recorded instead, comma-joined.
#
# A control whose claim is that held work finished cannot read that off the
# permit having closed: exhausted and quarantined are closings too. Which of
# them a control allows is the control's own question — the crossing requires
# work to complete, while a drain is satisfied by completion or audited
# quarantine — so the set is the caller's rather than fixed here.
misended_authored_permits() {
  local wanted="$1" authored="$2" allowed="$3" permit ending out=""
  for permit in ${wanted}; do
    ending="$(authored_ending "${permit}" "${authored}")"
    [[ -z "${ending}" || "${ending}" == "unresolved" ]] && continue
    contains_token "${allowed}" "${ending}" && continue
    out="${out}${out:+, }${permit}=${ending}"
  done
  printf '%s' "${out}"
}

# ---------------------------------------------------------------------------
# Reconciling a categorical ending to what it actually left behind
#
# The joins above answer "did this permit's own holder say how it ended". They
# stop at the word. Every holder of every ceremony that finished writes
# "completed", so the word alone cannot separate a fleet that agreed on one
# threshold output from one whose members each finished something else, nor
# either of those from a driver claiming a settlement the nodes never produced.
#
# What separates them is the identity of the durable result. It is derived from
# the output itself, so it is the same for every holder of one ceremony and
# different for holders of different ones — which makes it the one field a
# categorical ending cannot stand in for.
# ---------------------------------------------------------------------------

# The chain work a permit identity belongs to, "<gate ceremony>@<anchor>@<chain
# work>", with the holder in front of it dropped. Two
# holders of one ceremony share this; holders of different ceremonies, of
# different runs of one ceremony, and of one work id under two anchors do not.
identity_work() {
  local rest
  rest="${1#*@}"
  printf '%s' "${rest%%#*}"
}

# The gate ceremony a permit identity was issued for. It is read out of the
# identity rather than out of the driver's vocabulary because the two spell
# different things: the driver names the work it originated, and the gate names
# the ceremony class whose rules the permit was issued under.
identity_ceremony() {
  local rest
  rest="${1#*@}"
  printf '%s' "${rest%%@*}"
}

# The whole node-authored record for one named permit, empty when none names
# it. Like authored_ending it reads the last match, so where a duplicate slips
# past the check above the later record is the one that stands.
authored_record() {
  local permit="$1" authored="$2" token out=""
  for token in ${authored}; do
    [[ "$(authored_permit "${token}")" == "${permit}" ]] || continue
    out="${token}"
  done
  printf '%s' "${out}"
}

# Whether one node-authored token carries the whole ending shape: an identity,
# the disposition, the six evidence fields behind it — kind, result, persisted
# membership, the memberships that produced the result, the ones the holder named
# in the transcript, and the chain settlement — and the seats the permit was
# issued to operate.
#
# The count is exact rather than a floor. A token with fewer fields comes from a
# release publishing a narrower account, and every reader below would take the
# truncation for whatever field happened to land in that position; a token with
# more comes from a release this rehearsal was not built to read.
authored_record_complete() {
  local rest="$1" count=0
  while [[ "${rest}" == *=* ]]; do
    rest="${rest#*=}"
    count=$((count + 1))
  done
  ((count == 8))
}

# Of the named permits, the ones whose node-authored record stops short of the
# whole ending shape, comma-joined.
#
# A record that names a disposition and nothing else is what a release
# publishing the older, categorical account produces, and every evidence check
# below reads its missing fields as whatever the truncation happens to leave in
# their place. It has to be refused as unreadable rather than filled in.
malformed_authored_records() {
  local wanted="$1" authored="$2" permit record out=""
  for permit in ${wanted}; do
    record="$(authored_record "${permit}" "${authored}")"
    [[ -n "${record}" ]] || continue
    authored_record_complete "${record}" && continue
    out="${out}${out:+, }${record}"
  done
  printf '%s' "${out}"
}

# The single evidence kind the gate permits a ceremony to claim a durable
# result with. This mirrors the gate's own table, which is deliberately
# one-to-one: a ceremony whose real result is an external transaction must not
# settle on a digest it authored entirely by itself. A rehearsal reading an
# ending has to apply the same mapping, or a node serving a fabricated account
# could claim any ceremony completed by naming the evidence class of another.
#
# The self-test holds this table to the gate's, so a ceremony added there
# without one here is caught before a rehearsal decides anything on it.
expected_completed_evidence() {
  case "$1" in
  tbtc_dkg) printf 'persisted_tbtc_signer' ;;
  tbtc_wallet_coordination) printf 'protocol_result' ;;
  tbtc_signing) printf 'bitcoin_transaction' ;;
  tbtc_heartbeat) printf 'protocol_result' ;;
  tbtc_inactivity_claim) printf 'ethereum_transaction' ;;
  beacon_dkg) printf 'persisted_beacon_signer' ;;
  beacon_relay_signing) printf 'protocol_result' ;;
  beacon_relay_forwarding) printf 'forwarder_closed' ;;
  beacon_timeout_report) printf 'ethereum_transaction' ;;
  *) printf '' ;;
  esac
}

# Of the named permits whose holder recorded a completion, the ones whose
# evidence is not the class that ceremony's result actually lives in, rendered
# with what was recorded instead, comma-joined.
#
# The forwarding ceremony is the one that legitimately completes with no result
# identity: it relays other members' shares and produces nothing of its own, so
# reaching its close is the whole of its disposition. Every other completion
# names durable state, and one that does not is a categorical claim with
# nothing behind it.
misevidenced_authored_permits() {
  local wanted="$1" authored="$2" permit record kind want out=""
  for permit in ${wanted}; do
    record="$(authored_record "${permit}" "${authored}")"
    [[ -n "${record}" ]] || continue
    [[ "$(authored_outcome "${record}")" == "completed" ]] || continue
    want="$(expected_completed_evidence \
      "$(work_ceremony "$(identity_work "${permit}")")")"
    kind="$(authored_evidence_kind "${record}")"
    [[ -n "${want}" ]] || {
      out="${out}${out:+, }${permit} completed a ceremony with no declared \
result class, claiming ${kind}"
      continue
    }
    [[ "${kind}" == "${want}" ]] && continue
    out="${out}${out:+, }${permit} claims ${kind} where a ${want} is the \
result of that ceremony"
  done
  printf '%s' "${out}"
}

# Of the named permits, the ones whose holder dispatched a chain side effect it
# could not resolve, rendered with the kind it dispatched, comma-joined.
#
# The gate lets a settlement be recorded without its canonical identity because
# the alternative is worse: a node that submitted a transaction and could not
# learn what became of it must say so rather than record a settlement it cannot
# name, or record nothing and leave the side effect invisible. What must not
# happen is a verdict reading past it. An unresolved settlement is chain state
# this fleet may have created and cannot account for — a filed inactivity claim,
# a submitted penalty report — and every rung that reads a terminal record is
# about work whose ending is known. It blocks rather than fails: nothing here
# says the ceremony went wrong, only that its chain side effect is unaccounted
# for, and the offline audit is where that is resolved.
#
# What a resolved identity has to look like is settled before this runs. The
# reader that scrapes these records holds a settlement to the one kind its
# ceremony can dispatch and to the exact rendering that kind names on chain, and
# it refuses the snapshot rather than the permit when either is wrong — so every
# step blocks on a misrendered settlement, not only the two that read this rung.
# What is left here is the distinction that rung is about: a reference or no
# reference.
unresolved_authored_settlements() {
  local wanted="$1" authored="$2" permit record settlement out=""
  for permit in ${wanted}; do
    record="$(authored_record "${permit}" "${authored}")"
    [[ -n "${record}" ]] || continue
    settlement="$(authored_settlement "${record}")"
    [[ "${settlement}" == "-" ]] && continue
    # A resolved settlement carries its canonical identity after the kind; a
    # bare kind is the node saying it dispatched something it could not name.
    [[ "${settlement}" == *:* ]] && continue
    out="${out}${out:+, }${permit} dispatched a chain side effect it could not \
resolve (${settlement})"
  done
  printf '%s' "${out}"
}

# Of the chain work the named permits belong to, the pieces whose holders
# recorded completions naming different results, rendered with the results,
# comma-joined.
#
# Two members of one ceremony hold separate permits and write separate records,
# but a threshold ceremony has one output. Holders naming different ones did
# not finish the same ceremony together however many completions are counted,
# and a control reading only the count would record that as agreement.
disagreeing_authored_results() {
  local wanted="$1" authored="$2"
  local permit record work result seen works="" out=""
  for permit in ${wanted}; do
    record="$(authored_record "${permit}" "${authored}")"
    [[ -n "${record}" ]] || continue
    [[ "$(authored_outcome "${record}")" == "completed" ]] || continue
    result="$(authored_result "${record}")"
    [[ "${result}" == "-" ]] && continue
    work="$(identity_work "${permit}")"
    seen="$(authored_work_result "${work}" "${wanted}" "${authored}")"
    [[ "${seen}" == "${result}" ]] && continue
    contains_token "${works}" "${work}" && continue
    works="${works}${works:+ }${work}"
    out="${out}${out:+, }${work} (${seen})"
  done
  printf '%s' "${out}"
}

# Every permit some node authored an ending for on one of the given pieces of
# chain work, less the ones already named, space-joined.
#
# The result checks below run over a population the driver supplied: the permits
# it reported holders for. A holder it did not report is invisible to them, and
# invisibility is the whole evasion — that node can record a different result for
# the same ceremony, or one the driver never settled, and answer to nothing,
# because the population being checked came from the account its record would
# contradict. Widening the population to every record on the same work closes it:
# a holder is checked because it published a record, not because someone chose to
# name it.
authored_work_permits() {
  local works="$1" named="$2" authored="$3" token permit out=""
  for token in ${authored}; do
    authored_record_complete "${token}" || continue
    permit="$(authored_permit "${token}")"
    contains_token "${works}" "$(identity_work "${permit}")" || continue
    contains_token "${named}" "${permit}" && continue
    contains_token "${out}" "${permit}" && continue
    out="${out}${out:+ }${permit}"
  done
  printf '%s' "${out}"
}

# The results the holders of one piece of chain work recorded, "/"-joined and
# deduplicated, so a single value means they agreed and anything else does not
# compare equal to any one holder's record.
authored_work_result() {
  local work="$1" wanted="$2" authored="$3"
  local permit record result out=""
  for permit in ${wanted}; do
    [[ "$(identity_work "${permit}")" == "${work}" ]] || continue
    record="$(authored_record "${permit}" "${authored}")"
    [[ -n "${record}" ]] || continue
    [[ "$(authored_outcome "${record}")" == "completed" ]] || continue
    result="$(authored_result "${record}")"
    [[ "${result}" == "-" ]] && continue
    contains_token "${out//\// }" "${result}" && continue
    out="${out}${out:+/}${result}"
  done
  printf '%s' "${out}"
}

# What the driver claims one piece of chain work settled as, looked up in the
# gate's vocabulary so a holder's own record of the same work can be compared
# with it. Several claims for one piece of work are "/"-joined rather than
# resolved, so an ambiguous account compares equal to no holder's record.
claimed_work_result() {
  local bound="$1" work="$2" record identity out=""
  for record in ${bound}; do
    [[ "$(bound_outcome "${record}")" == "succeeded" ]] || continue
    [[ "$(audited_work_id "$(bound_work "${record}")")" == "${work}" ]] ||
      continue
    identity="$(bound_identity "${record}")"
    contains_token "${out//\// }" "${identity}" && continue
    out="${out}${out:+/}${identity}"
  done
  printf '%s' "${out}"
}

# Of the named permits whose holder recorded a completion naming a result, the
# ones whose result is not the one the driver claims for the same chain work,
# comma-joined.
#
# This is the seam the two accounts were never held across. The driver says a
# ceremony settled and names what it produced; the holders say their permits
# completed and name what they produced. Read separately, a driver reporting a
# settlement the fleet never reached and a fleet completing work the driver
# never originated both pass. Only comparing the two identities refuses them.
unclaimed_authored_results() {
  local wanted="$1" authored="$2" bound="$3"
  local permit record result work claimed out=""
  for permit in ${wanted}; do
    record="$(authored_record "${permit}" "${authored}")"
    [[ -n "${record}" ]] || continue
    [[ "$(authored_outcome "${record}")" == "completed" ]] || continue
    result="$(authored_result "${record}")"
    [[ "${result}" == "-" ]] && continue
    work="$(identity_work "${permit}")"
    claimed="$(claimed_work_result "${bound}" "${work}")"
    [[ "${claimed}" == "${result}" ]] && continue
    out="${out}${out:+, }${permit} recorded ${result} where the driver claims \
${claimed:-no settlement at all}"
  done
  printf '%s' "${out}"
}

# ---------------------------------------------------------------------------
# Deriving who took part in a transcript from the holders rather than the driver
#
# The joins above hold the driver's account of a permit's ending against the
# holder's own. Who contributed to a transcript was never held against anything:
# the driver named the parties, and a control whose whole claim is that two
# releases combined into one threshold output decided it on a list the party
# under test wrote. A driver reporting a homogeneous run as mixed satisfies it,
# because nothing else in the rehearsal ever asks a node whether it was there.
#
# The half that can be node-authored is authored here instead. Every R1 node
# publishes the permits it closed, what each one produced, and — where its
# ceremony authenticates the population behind a result — which of the seats that
# produced it were its own, so the R1 contributors to a piece of chain work are
# derivable from the fleet without the driver's participation, at the full permit
# identity rather than at a service name. The driver's list is then a claim to
# reconcile against that derivation in both directions — a claimed R1 party with
# no contribution of its own behind it is invented, and a holder's contribution
# the list omits is a party the driver chose not to count.
#
# The prior release publishes no gate account at all, so its share cannot be
# authored the same way. That is a standing limit of this rehearsal rather than
# something these helpers close, and it is recorded as one.
# ---------------------------------------------------------------------------

# The permit identity a driver-claimed contributor names, rendered in the gate's
# own vocabulary so the claim can be looked up in the node-authored account. The
# claim arrives as "<ceremony>@<anchor>@<chain work>=<service>~<permit>", which
# is the same identity the holders publish with its fields in another order and
# the driver's ceremony spelling.
contributor_permit_identity() {
  local record="$1" party
  party="${record##*=}"
  printf '%s@%s#%s' "$(permit_holder "${party}")" \
    "$(audited_work_id "$(work_id "${record}")")" \
    "$(permit_local_id "${party}")"
}

# The permits on one piece of chain work whose own holders recorded contributing
# to it and named what it produced, space-joined. Derived from the node-authored
# account alone: this is the R1 half of a contributor set, and the driver has no
# part in producing it.
#
# A completion naming no result is not counted. The forwarding ceremony
# legitimately reaches its close having produced nothing of its own, so it is a
# party to a relay rather than to a transcript, and a contributor set is about
# the parties whose shares combined into one output.
#
# Neither is a completion whose own transcript places this holder outside the
# result. Observing a threshold output and producing one are different facts,
# and a permit is entitled to record the first: a wallet action owns its permit
# and writes down the signature it saw settle even when the attempt that
# produced it selected none of the memberships this node operates, which the
# gate spells as a transcript naming incorporated seats and no local ones.
# Reading that record as a contribution is the whole gap a contributor set is
# supposed to close — an R1 observer of a prior-only transcript would supply the
# R1 half of a mixed claim while no R1 share ever entered the ceremony. Where
# the holder publishes a transcript, it is counted as a contributor exactly when
# it says one of the seats that produced the result was its own.
#
# A holder whose ceremony publishes no transcript at all is still counted on its
# completion. Every ceremony that reaches a threshold result publishes one and is
# refused without it, so what is left are the ceremonies that produce no
# transcript to publish — a coordination proposal from one leader, a forwarder
# relaying other members' shares, a penalty filing — and for those a completion
# naming a result is the whole of what a holder can vouch for. None of them is a
# ceremony a mixed-release claim is made about.
authored_work_contributors() {
  local work="$1" authored="$2" token permit out=""
  for token in ${authored}; do
    authored_record_complete "${token}" || continue
    [[ "$(authored_outcome "${token}")" == "completed" ]] || continue
    [[ "$(authored_result "${token}")" == "-" ]] && continue
    if [[ "$(authored_incorporated "${token}")" != "-" ]] &&
      [[ "$(authored_local "${token}")" == "-" ]]; then
      continue
    fi
    permit="$(authored_permit "${token}")"
    [[ "$(identity_work "${permit}")" == "${work}" ]] || continue
    contains_token "${out}" "${permit}" && continue
    out="${out}${out:+ }${permit}"
  done
  printf '%s' "${out}"
}

# The distinct pieces of chain work a set of permit identities belongs to,
# space-joined.
identity_works() {
  local permits="$1" permit work out=""
  for permit in ${permits}; do
    work="$(identity_work "${permit}")"
    contains_token "${out}" "${work}" && continue
    out="${out}${out:+ }${work}"
  done
  printf '%s' "${out}"
}

# Of the contributors the driver claims, the ones naming a node in the R1 fleet
# that never recorded contributing to that exact permit, comma-joined.
#
# This is the fabrication the mixed-transcript control rested on. A driver can
# write any party into its report, and a claim naming an R1 node is checkable
# against that node's own account: the permit identity either appears among the
# contributions its holder published or the contribution did not happen. A
# claimed party whose service is right and whose permit is not is caught here
# too, which is what keeps one real contribution from standing for the several a
# threshold needs.
#
# The population a claim is held to is the one the holders authored, so a driver
# naming a holder that merely observed the result — a permit whose transcript
# names incorporated seats and no local ones — is naming a party to that
# transcript that its own record does not claim to have been.
invented_contributors() {
  local claimed="$1" authored="$2" r1="$3"
  local record permit holder out=""
  for record in ${claimed}; do
    holder="$(permit_holder "${record##*=}")"
    contains_token "${r1}" "${holder}" || continue
    permit="$(contributor_permit_identity "${record}")"
    contains_token "$(authored_work_contributors \
      "$(identity_work "${permit}")" "${authored}")" "${permit}" && continue
    out="${out}${out:+, }${permit}"
  done
  printf '%s' "${out}"
}

# Of the contributors the driver claims, the ones naming a service this
# rehearsal does not run, comma-joined.
#
# Neither half of the fleet can account for these. A holder that is not the
# prior binary is checked against its own published record, and a holder that is
# the prior binary is the one claim nothing here can check — so a third name is
# a party whose release is unknown, and reading it as either half would let a
# stray container supply the side of the claim it was never shown to be on.
unrecognized_contributors() {
  local claimed="$1" prior="$2" r1="$3" record holder out=""
  for record in ${claimed}; do
    holder="$(permit_holder "${record##*=}")"
    [[ "${holder}" == "${prior}" ]] && continue
    contains_token "${r1}" "${holder}" && continue
    contains_token "${out//, / }" "${holder}" && continue
    out="${out}${out:+, }${holder}"
  done
  printf '%s' "${out}"
}

# The mirror: of the completions the holders authored on work this phase
# originated, the ones the driver's contributor set does not name, comma-joined.
#
# Refusing only invented parties leaves the other direction open. A driver that
# reports a subset of the fleet as the contributor set describes a smaller
# ceremony than the one that ran, and the mixed reading is then about a
# transcript nobody claims. Holding both directions makes the two accounts the
# same population or no verdict at all.
uncredited_contributors() {
  local claimed="$1" authored="$2" works="$3"
  local record work permit named="" out=""
  for record in ${claimed}; do
    named="${named}${named:+ }$(contributor_permit_identity "${record}")"
  done
  for work in ${works}; do
    for permit in $(authored_work_contributors "${work}" "${authored}"); do
      contains_token "${named}" "${permit}" && continue
      out="${out}${out:+, }${permit}"
    done
  done
  printf '%s' "${out}"
}

# Every seat on one piece of chain work that some holder of it says it operated
# itself, space-joined. Repeats are left in: this is read as an ownership map
# rather than as a population.
#
# A seat in the map is a seat a node under test was sitting in. A seat outside it
# is one no node in this fleet claims, and since the rehearsal runs exactly two
# releases and the container set is the harness's own rather than any report's,
# the only party left to have supplied it is the prior binary.
#
# The map spans the fleet because a seat's operator is whichever node operated
# it, not whichever node published the transcript naming it. Nothing in it is the
# driver's word: each holder names only memberships of its own, and no report can
# add one.
#
# Every ending counts toward it, and that is what makes the map a map. The seats
# are read from the permit rather than from the transcript, so they are there for
# a holder that contributed and then crashed, timed out, exhausted its retries,
# or closed without recording anything at all — and the "outside the map"
# reading below is what the fleet actually did not operate rather than what the
# subset of it that reached a result happened to write down. A map built from
# completions alone gets exactly one case wrong, and it is the case that decides
# the mixed-release claim: an R1 node whose seat went into another R1 node's
# result while its own permit ended with nothing to record leaves that seat
# outside the map, and the reading below then calls an all-R1 transcript mixed.
#
# Where the transcripts on this work speak in a different index space than its
# permits, the seats are placed in the transcripts' space before they enter the
# map, through the mapping those transcripts publish. A map left in the permits'
# space would read against the transcripts by number, which is the same false
# attribution in a quieter form: with a middle ceremony member removed every
# final seat shifts down, so the map's own seats land on the wrong side of the
# reading and a homogeneous run presents a seat as outside the fleet.
#
# A permit still held when the reading was taken counts toward it too, and that
# is the other half of the same rule. An ending is the only thing that puts a
# permit in the closed account, so a contributor whose permit was still open when
# the driver reported settlement — the ordinary case, since a driver watches the
# chain and a holder closes on its own schedule — is in neither the endings nor
# anywhere else, and its seat leaves the map without any counter moving. Read on
# its own the fleet looks like one that never operated that seat, which is the
# mixed verdict again, off a run where nothing went wrong at all.
#
# A seat that cannot be placed is left out of the map rather than guessed at, and
# untranslatable_ownership_permits below is what stops the reading from treating
# its absence as the fleet not having operated it.
authored_work_local_members() {
  local work="$1" authored="$2" held="$3"
  local token permit spaces transcript permits placed out=""
  spaces="$(authored_work_seat_spaces "${work}" "${authored}")"
  transcript="$(seat_spaces_transcript "${spaces}")"
  permits="$(seat_spaces_permits "${spaces}")"
  for token in ${authored}; do
    authored_record_complete "${token}" || continue
    permit="$(authored_permit "${token}")"
    [[ "$(identity_work "${permit}")" == "${work}" ]] || continue
    placed="$(placed_permit_seats "${permit}" "$(authored_operated "${token}")" \
      "${transcript}" "${permits}")"
    [[ -n "${placed}" ]] || continue
    out="${out}${out:+ }${placed}"
  done
  for token in ${held}; do
    held_record_complete "${token}" || continue
    permit="$(authored_permit "${token}")"
    [[ "$(identity_work "${permit}")" == "${work}" ]] || continue
    placed="$(placed_permit_seats "${permit}" "$(authored_operated "${token}")" \
      "${transcript}" "${permits}")"
    [[ -n "${placed}" ]] || continue
    out="${out}${out:+ }${placed}"
  done
  printf '%s' "${out}"
}

# The seats one permit contributes to its work's ownership map, space-joined, in
# the index space that work's transcripts speak in. Empty where the permit
# operates none, or where a remapping ceremony's seats cannot be placed.
#
# The permit identity is what says which space its seats are in, so the same
# rendering serves a permit read out of the closed account and one read off the
# live list — the two differ in what became of the permit, which the map does not
# ask about.
placed_permit_seats() {
  local permit="$1" members="$2" transcript="$3" permits="$4"
  local member seat out=""
  # "-" is how the gate renders an absent set, and it must not survive into a
  # membership map: read as a token it would make an absent "-" look like an
  # operated seat.
  [[ "${members}" == "-" ]] && return 0
  if ! ceremony_remaps_permit_space "$(identity_ceremony "${permit}")"; then
    printf '%s' "${members//,/ }"
    return 0
  fi
  for member in ${members//,/ }; do
    seat="$(aligned_membership "${transcript}" "${permits}" "${member}")"
    [[ -n "${seat}" ]] || continue
    out="${out}${out:+ }${seat}"
  done
  printf '%s' "${out}"
}

# Whether one live-permit token carries the whole shape a held reading has: the
# permit identity and the seats it was issued to operate, and nothing else.
#
# The count is exact for the reason the ending shape's is. A held token and an
# ending token are read out of the same fields by the same accessors, so a
# truncated ending arriving in the held list would be read as a permit still open
# — putting a permit that has already closed back into the live account — and a
# held token carrying extra fields comes from a release this rehearsal cannot
# read.
held_record_complete() {
  local rest="$1" count=0
  while [[ "${rest}" == *=* ]]; do
    rest="${rest#*=}"
    count=$((count + 1))
  done
  ((count == 1))
}

# Whether a ceremony records its result in a different membership index space
# than the permits issued for the same work, and so publishes the mapping between
# them. The list mirrors the gate's and the snapshot reader's, and a self-test
# holds all three together.
ceremony_remaps_permit_space() {
  case "$1" in
    tbtc_dkg) return 0 ;;
  esac
  return 1
}

# The one pair of index spaces the completions on a piece of chain work agree on,
# as "<transcript seats> <permit-space seats>" with each half comma-joined and
# the two aligned position for position. "-" when no completion on this work
# published a mapping at all, and "!" when two of them published different ones.
#
# One piece of DKG work has one final group, so its completions publish one
# mapping. Two that disagree describe two different rebuildings of it, and there
# is no rule for choosing between them that is not a guess — so the disagreement
# is rendered rather than resolved, and the readings below refuse rather than pick
# a side. The transcript half travels with the mapping because the alignment is
# what carries the meaning: the mapping alone says which ceremony seats survived,
# not which final seat each of them became.
authored_work_seat_spaces() {
  local work="$1" authored="$2" token permit mapping pair out=""
  for token in ${authored}; do
    authored_record_complete "${token}" || continue
    [[ "$(authored_outcome "${token}")" == "completed" ]] || continue
    permit="$(authored_permit "${token}")"
    [[ "$(identity_work "${permit}")" == "${work}" ]] || continue
    mapping="$(authored_permit_space "${token}")"
    [[ "${mapping}" == "-" ]] && continue
    pair="$(authored_incorporated "${token}") ${mapping}"
    if [[ -z "${out}" ]]; then
      out="${pair}"
    elif [[ "${out}" != "${pair}" ]]; then
      printf '!'
      return 0
    fi
  done
  printf '%s' "${out:--}"
}

# The membership one index space carries opposite a membership of another, given
# the two as comma-joined lists aligned position for position: aligned_membership
# "<wanted space>" "<given space>" "<membership of the given space>".
#
# Empty when the given space does not carry that membership at all, which is not
# a fault on its own: a ceremony member the recording node did not see operating
# is absent from the group that was rebuilt, so its seat has no place in the
# transcript and never enters an ownership map. Empty also for the renderings that
# say there is no usable mapping — none published, or two that disagreed — so a
# caller that reads this as "no seat" gets the unknown rather than a guess.
aligned_membership() {
  local wanted="$1" given="$2" seat="$3" wanted_seats given_seats index
  case "${wanted}" in
    -|'!'|'') return 0 ;;
  esac
  case "${given}" in
    -|'!'|'') return 0 ;;
  esac
  IFS=',' read -r -a wanted_seats <<<"${wanted}"
  IFS=',' read -r -a given_seats <<<"${given}"
  for ((index = 0; index < ${#given_seats[@]}; index++)); do
    [[ "${given_seats[index]}" == "${seat}" ]] || continue
    ((index < ${#wanted_seats[@]})) || return 0
    printf '%s' "${wanted_seats[index]}"
    return 0
  done
}

# The transcript half of a pair authored_work_seat_spaces rendered, and its
# permit-space half. Both are "-" when the pair says there is no usable mapping,
# which every reader of them treats as an unknown rather than as an empty space.
seat_spaces_transcript() {
  case "$1" in
    -|'!'|'') printf '%s' '-' ;;
    *) printf '%s' "${1%% *}" ;;
  esac
}

seat_spaces_permits() {
  case "$1" in
    -|'!'|'') printf '%s' '-' ;;
    *) printf '%s' "${1##* }" ;;
  esac
}

# Of the permits on one piece of chain work, the ones whose operated seats could
# not be placed in the index space its transcripts speak in, rendered as
# "<permit> (operated <seats>)".
#
# This is the gap the mixed reading must not read past. The ownership map is what
# says which seats of a transcript the fleet was sitting in, and a seat missing
# from it reads as a seat some other release supplied. Where this work published
# no usable mapping at all — none of its completions carried one, or two of them
# carried different ones — the honest answer is that the fleet's ownership of its
# transcripts is unknown, and an unknown must not be spent as evidence that two
# releases combined into one output.
#
# A holder whose own seat is simply absent from a mapping the work did publish is
# not named here, and the difference is the whole point. That seat belongs to a
# ceremony member the recording node did not see operating, so it was left out of
# the group that was rebuilt and holds no final seat at all — which is a definite
# answer rather than a missing one, and a normal outcome of every ceremony that
# removed a member.
untranslatable_ownership_permits() {
  local work="$1" authored="$2" held="$3" token permit members spaces out=""
  spaces="$(authored_work_seat_spaces "${work}" "${authored}")"
  case "${spaces}" in
    -|'!') ;;
    *) return 0 ;;
  esac
  for token in ${authored}; do
    authored_record_complete "${token}" || continue
    permit="$(authored_permit "${token}")"
    [[ "$(identity_work "${permit}")" == "${work}" ]] || continue
    ceremony_remaps_permit_space "$(identity_ceremony "${permit}")" || continue
    members="$(authored_operated "${token}")"
    [[ "${members}" == "-" ]] && continue
    out="${out}${out:+, }${permit} (operated ${members})"
  done
  # A permit still open is in the map on the same terms as a closed one, so its
  # seats go unplaced on the same terms too. Left out here, a work whose only
  # remapping holder had not yet closed would read as one with nothing to place.
  for token in ${held}; do
    held_record_complete "${token}" || continue
    permit="$(authored_permit "${token}")"
    [[ "$(identity_work "${permit}")" == "${work}" ]] || continue
    ceremony_remaps_permit_space "$(identity_ceremony "${permit}")" || continue
    members="$(authored_operated "${token}")"
    [[ "${members}" == "-" ]] && continue
    out="${out}${out:+, }${permit} (operated ${members})"
  done
  printf '%s' "${out}"
}

# The same across every piece of work a control covers, so a verdict can say the
# fleet's ownership of a transcript was unreadable rather than reporting the
# homogeneous reading that silence produces.
unplaceable_authored_ownership() {
  local authored="$1" works="$2" held="$3" work found out=""
  for work in ${works}; do
    found="$(untranslatable_ownership_permits "${work}" "${authored}" \
      "${held}")"
    [[ -n "${found}" ]] || continue
    out="${out}${out:+, }${found}"
  done
  printf '%s' "${out}"
}

# Of the records on one piece of chain work, the ones whose transcript claims a
# seat their own permit was not issued to operate, rendered as
# "<permit> (transcript <seats>, operated <seats>)".
#
# A holder makes two statements about one permit: the seats it announced it was
# operating, before the ceremony ran, and the seats it says produced the result,
# after. The ownership map above rests entirely on the first, so the second has to
# be held to it — otherwise a holder could announce one seat, record a result
# produced with another, and leave a reader with two node-authored answers and no
# rule for choosing between them.
#
# The gate refuses such a record at the moment it is written, so anything found
# here reached a gate scrape by some other route. Either way it is a reason to
# refuse the reading rather than to pick a side.
#
# A record whose transcript is in another index space than its own permit is
# compared through the mapping that record publishes, not exempted. Exempting it
# left the comparison undone for the one ceremony that remaps, which is the one
# whose two statements a reader most needs held together; comparing the raw
# numbers instead would refuse every correct record. The seat named here is
# always the permit's own, so a translation that fails to place it is itself the
# contradiction: the holder published a mapping its own seat is not in.
disowned_transcript_permits() {
  local work="$1" authored="$2"
  local token permit operated local_members member seat out=""
  for token in ${authored}; do
    authored_record_complete "${token}" || continue
    permit="$(authored_permit "${token}")"
    [[ "$(identity_work "${permit}")" == "${work}" ]] || continue
    local_members="$(authored_local "${token}")"
    [[ "${local_members}" == "-" ]] && continue
    operated="$(authored_operated "${token}")"
    for member in ${local_members//,/ }; do
      seat="${member}"
      if ceremony_remaps_permit_space "$(identity_ceremony "${permit}")"; then
        # The record's own mapping, read the other way about: the operated set is
        # in the permits' space, so the transcript seat is translated back into
        # it. It is this record's mapping rather than the one the work's
        # completions agree on, because what is being checked is whether one
        # holder contradicted itself and only its own account may answer that.
        seat="$(aligned_membership \
          "$(authored_permit_space "${token}")" \
          "$(authored_incorporated "${token}")" \
          "${member}")"
      fi
      [[ -n "${seat}" ]] &&
        contains_token "${operated//,/ }" "${seat}" && continue
      out="${out}${out:+, }${permit} (transcript ${local_members}, \
operated ${operated})"
      break
    done
  done
  printf '%s' "${out}"
}

# The same across every piece of work a control covers, so a verdict can name the
# record that contradicted itself rather than reporting only the coverage gap it
# leaves behind. A step that blocked with "no transcript incorporated a share"
# would send a reader looking for a homogeneous fleet when what actually happened
# is that a holder published two irreconcilable accounts of one permit.
disowned_authored_transcripts() {
  local authored="$1" works="$2" work found out=""
  for work in ${works}; do
    found="$(disowned_transcript_permits "${work}" "${authored}")"
    [[ -n "${found}" ]] || continue
    out="${out}${out:+, }${found}"
  done
  printf '%s' "${out}"
}

# Of the completions on one piece of chain work, the ones whose own transcript
# names both a seat this fleet operated and a seat it did not, rendered as
# "<permit> (fleet <seats>, outside <seats>)".
#
# This is the mixed-release claim reduced to something the fleet authors by
# itself, and it is asked of one transcript at a time. Every R1 holder publishes
# the memberships whose authenticated contributions it combined into the result
# and, separately, the memberships it operated; a single record naming a seat in
# the fleet's ownership map and a seat outside it is one threshold output that
# both releases went into.
#
# Populations from different records are never unioned, and that is the whole
# point of reading them one at a time. Two holders of one piece of work can
# recover the same threshold output from different subsets of the same ceremony,
# so records agreeing on a result do not imply records agreeing on a population:
# an R1-only transcript beside a prior-only observer's transcript is two
# homogeneous readings of the same work, and a union of the two would manufacture
# a mixed population that no node ever recorded and no ceremony ever had.
#
# Nothing here is the driver's word. A run this fleet performed alone leaves no
# record with a seat outside the map, a run it only watched leaves no record with
# a seat inside it, and a driver naming a party the fleet never authenticated
# cannot add either half.
#
# The map the seats are read against spans every ending rather than only the
# completions, so a holder that contributed and then ended with nothing to record
# still puts its seats in it. Without that the reading has a false positive in
# exactly the direction it is used: an all-R1 ceremony one of whose contributors
# never published an ending would present its seat as outside the fleet, and a
# homogeneous run would satisfy a control whose whole claim is that two releases
# combined into one output.
#
# A record whose transcript claims a seat its own permit never operated is not
# read at all. The two statements would have to be reconciled before either could
# be believed, and there is no rule for doing that which is not a guess.
#
# Nor is a work whose ownership map could not be placed in the index space its
# transcripts speak in. The map is what says which seats of a transcript the
# fleet was sitting in, and every seat missing from it reads as a seat some other
# release supplied — so an unreadable map produces the mixed verdict rather than
# no verdict, which is the one direction this reading must never fail in.
#
# An unplaceable map comes out empty, and the "some seat of this fleet" half below
# already declines to read a transcript against an empty one. The refusal is
# stated here anyway because it is the rule rather than a consequence: a later
# reading that filled an unplaceable seat in from somewhere would satisfy that
# half and arrive at exactly the verdict this must never produce.
mixed_transcript_permits() {
  local work="$1" authored="$2" held="$3"
  local owned token permit incorporated member fleet outside out=""
  [[ -z "$(disowned_transcript_permits "${work}" "${authored}")" ]] || return 0
  [[ -z "$(untranslatable_ownership_permits "${work}" "${authored}" \
    "${held}")" ]] || return 0
  owned="$(authored_work_local_members "${work}" "${authored}" "${held}")"
  for token in ${authored}; do
    authored_record_complete "${token}" || continue
    [[ "$(authored_outcome "${token}")" == "completed" ]] || continue
    permit="$(authored_permit "${token}")"
    [[ "$(identity_work "${permit}")" == "${work}" ]] || continue
    incorporated="$(authored_incorporated "${token}")"
    [[ "${incorporated}" == "-" ]] && continue
    fleet=""
    outside=""
    for member in ${incorporated//,/ }; do
      if contains_token "${owned}" "${member}"; then
        fleet="${fleet}${fleet:+,}${member}"
      else
        outside="${outside}${outside:+,}${member}"
      fi
    done
    [[ -n "${fleet}" ]] || continue
    [[ -n "${outside}" ]] || continue
    out="${out}${out:+, }${permit} (fleet ${fleet}, outside ${outside})"
  done
  printf '%s' "${out}"
}

# The memberships the fleet says produced one piece of chain work, comma-joined,
# or empty when no holder of it published a transcript at all.
#
# Emptiness is structural rather than a fault. The ceremonies whose owners
# authenticate their peers publish the population behind their result and their
# records are refused without it; the ones that do not publish one leave this
# empty for every holder, and a reader has to be able to tell "this fleet says
# nobody produced it" from "this release does not answer the question".
authored_work_transcript() {
  local work="$1" authored="$2" token permit members out=""
  for token in ${authored}; do
    authored_record_complete "${token}" || continue
    [[ "$(authored_outcome "${token}")" == "completed" ]] || continue
    permit="$(authored_permit "${token}")"
    [[ "$(identity_work "${permit}")" == "${work}" ]] || continue
    members="$(authored_incorporated "${token}")"
    [[ "${members}" == "-" ]] && continue
    out="${out}${out:+,}${members}"
  done
  printf '%s' "${out}"
}

# Every permit identity a set of originated records names, space-joined. Work
# may repeat here: two local permits for one chain work are two tokens.
permit_identities() {
  local records="$1" record out=""
  for record in ${records}; do
    out="${out}${out:+ }$(permit_identity "${record}")"
  done
  printf '%s' "${out}"
}

# The originated record for one work identity, empty when this phase did not
# originate it. The parser rejects a second record for an identity, so at most
# one can match.
originated_record() {
  local records="$1" work="$2" record
  for record in ${records}; do
    [[ "$(work_id "${record}")" == "${work}" ]] || continue
    printf '%s' "${record}"
    return 0
  done
  printf ''
}

# The bound record for one originated record, empty when nothing terminal was
# reported for the same work and transaction. The transaction is part of the
# binding even though the work identity also carries an anchor: separate
# driver phases must not replace the transaction that originated a permit with
# an unrelated successful transaction when they later report its outcome.
terminal_record() {
  local records="$1" originated="$2" record work transaction
  work="$(work_id "${originated}")"
  transaction="$(work_transaction "${originated}")"
  for record in ${records}; do
    [[ "$(bound_work "${record}")" == "${work}" ]] || continue
    [[ "$(bound_transaction "${record}")" == "${transaction}" ]] || continue
    printf '%s' "${record}"
    return 0
  done
  printf ''
}

# Of the work a gate originated, the identities the driver reported no terminal
# outcome for and no node quarantined. Space-joined, empty when every piece of
# work ended somewhere a later reader can see.
unended_work() {
  local records="$1" bound="$2" quarantined="$3" record permit uncovered=""
  for record in ${records}; do
    [[ -n "$(terminal_record "${bound}" "${record}")" ]] && continue
    permit="$(audited_permit_id "${record}")"
    contains_token "${quarantined}" "${permit}" && continue
    uncovered="${uncovered}${uncovered:+ }$(permit_identity "${record}")"
  done
  printf '%s' "${uncovered}"
}

# Of that same work, the pieces whose terminal record says they came to
# nothing, rendered with the termination. A control whose claim is that held
# work was allowed to finish reads this: retries exhausted is an end, but it is
# not the end that claim is about, and without an audited quarantine record
# beside it nothing distinguishes work that gave up from work that was dropped.
unsettled_work() {
  local records="$1" bound="$2" record terminal out=""
  for record in ${records}; do
    terminal="$(terminal_record "${bound}" "${record}")"
    [[ -n "${terminal}" ]] || continue
    [[ "$(bound_outcome "${terminal}")" == "succeeded" ]] && continue
    out="${out}${out:+, }$(permit_identity "${record}")=\
$(bound_outcome "${terminal}") \
($(bound_identity "${terminal}"))"
  done
  printf '%s' "${out}"
}

# Of the terminal records the driver reported, the ones naming work this gate
# did not originate with the transaction the terminal record claims. An
# outcome belonging to somebody else's ceremony or transaction is not a permit
# of this fleet's reconciling.
unoriginated_terminals() {
  local bound="$1" records="$2" record work originated expected actual stray=""
  for record in ${bound}; do
    work="$(bound_work "${record}")"
    originated="$(originated_record "${records}" "${work}")"
    if [[ -z "${originated}" ]]; then
      stray="${stray}${stray:+, }${work}"
      continue
    fi
    expected="$(work_transaction "${originated}")"
    actual="$(bound_transaction "${record}")"
    [[ "${actual}" == "${expected}" ]] && continue
    stray="${stray}${stray:+, }${work} (${actual}, originated as ${expected})"
  done
  printf '%s' "${stray}"
}

# Of the required families, the ones no bound successful result covers.
#
# The unbound mirror of this reads a population of outcomes that need not have
# anything to do with the transactions reported beside them. A control whose
# claim is that this driver's ceremonies ran under this fleet's gate has to
# decide on records that name both.
missing_bound_families() {
  local records="$1" required="$2" family record uncovered="" covered
  for family in ${required}; do
    covered=0
    for record in ${records}; do
      [[ "$(bound_outcome "${record}")" == "succeeded" ]] || continue
      [[ "$(ceremony_family \
        "$(work_ceremony "$(bound_work "${record}")")")" == "${family}" ]] ||
        continue
      covered=1
      break
    done
    ((covered == 1)) || uncovered="${uncovered}${uncovered:+ }${family}"
  done
  printf '%s' "${uncovered}"
}

# Of the required ceremonies, the ones where no one settled transcript
# incorporated both the prior release and one of the named R1 services.
#
# A mixed-fleet claim needs this and cannot be read off a running container.
# Either release can be up and never selected, up and partitioned, or up and
# cryptographically excluded, and every one of those produces a settled
# ceremony beside a running container — the same reading interoperation
# produces. Asking which parties the transcript itself incorporated is the only
# question that separates them.
#
# It is asked once per required ceremony rather than once per family. A family
# is a set of separate call paths into the gate — tBTC DKG, signing, and the
# heartbeat each anchor differently, refuse differently, and carry a different
# message set — so a prior binary that contributed to a signing says nothing
# about whether it could have contributed to a DKG. Counted per family, one
# mixed signing beside an R1-only DKG and an R1-only heartbeat reads as the
# whole tBTC path interoperating, when two of its three ceremonies were never
# shown to.
#
# The two shares have to be in the same transcript. A prior share in one
# ceremony and an R1 share in another is two homogeneous ceremonies however the
# totals read, and what a compatibility control claims is that the two releases
# combined into a single threshold output — which only a transcript naming both
# of them ever witnesses.
#
# Both sides of each transcript are read off the fleet rather than out of the
# driver's report.
#
# The R1 side was always answerable that way: a node that took part published the
# permit it closed and the result it produced. The prior side used to be the
# driver's word, and that was the whole weakness — a driver reporting a
# homogeneous run as mixed satisfied a control whose entire claim is that two
# releases combined into one threshold output, because nothing else ever asked a
# node who was there.
#
# Both are now read from the seats, and out of one record at a time. Each R1
# holder publishes the memberships whose authenticated contributions it combined
# into the result and, separately, the memberships it operated itself. One
# published transcript naming a seat some node in the fleet operated and a seat
# no node in it claims is a single threshold output both releases went into, and
# the only other release on this network is the prior binary.
#
# The seats of separate records are never added together to reach that reading.
# A threshold output can be recovered from different subsets of the same
# ceremony, so two holders agreeing on a result need not agree on who produced
# it: an R1-only transcript beside a prior-only observer's transcript of the same
# work would satisfy an aggregate reading with neither transcript mixed.
#
# The driver's contributor list is still reconciled in both directions before
# this runs, but it supplies neither half of the claim: a run this fleet
# performed alone leaves no record with a seat outside its own, and a run it only
# watched leaves no record with a seat of its own, whatever the report says about
# either.
ceremonies_without_mixed_transcript() {
  local claimed="$1" authored="$2" required="$3" prior="$4" held="$5"
  local ceremony record work audited covered uncovered=""
  for ceremony in ${required}; do
    covered=0
    for record in ${claimed}; do
      [[ "$(permit_holder "${record##*=}")" == "${prior}" ]] || continue
      # The requirement list is in the driver's vocabulary and the ceremony is
      # matched in it, not in the gate's. The gate spells a wallet action and a
      # signing the same way, so matching there would let a mixed wallet action
      # satisfy the signing requirement and the reverse — collapsing two of the
      # separate paths this control exists to cover one at a time.
      work="$(work_id "${record}")"
      [[ "$(work_ceremony "${work}")" == "${ceremony}" ]] || continue
      audited="$(audited_work_id "${work}")"
      # The same piece of work, not merely the same ceremony. A prior share on
      # one work and an R1 share on another are two homogeneous transcripts
      # however the totals read, so the reading below is joined to exactly the
      # work the prior claim is about.
      #
      # And it is one transcript's own population, not the fleet's aggregate
      # view of the work: a record naming a seat the fleet operated beside a seat
      # it did not. Both halves come off the seats rather than out of the report,
      # with no fallback to the driver's word — every gated ceremony that reaches
      # a threshold result publishes the population behind it (the tBTC signing
      # families from their authenticated done checks, tBTC DKG from its final
      # signing group, beacon DKG from the operating members of the accepted
      # result, beacon relay signing from the authenticated entry shares it
      # combined) and the gate refuses a completed record for any of them that
      # names none. A work whose holders publish no transcript therefore has no
      # reading here at all, which is the honest outcome: the driver cannot
      # describe a population the fleet never authored.
      #
      # An R1 node that merely observed a prior-only result completes its permit
      # honestly, claims no seat of its own in it, and so supplies neither half —
      # its transcript is prior-only, and the R1-only transcript of an actual
      # contributor beside it is still prior-free.
      [[ -n "$(mixed_transcript_permits "${audited}" "${authored}" \
        "${held}")" ]] || continue
      covered=1
      break
    done
    ((covered == 1)) || uncovered="${uncovered}${uncovered:+ }${ceremony}"
  done
  printf '%s' "${uncovered}"
}

# The bound records that settled, rendered as "<ceremony> (<transaction>,
# <identity>)" so a verdict names what it decided on rather than asserting it.
bound_settlements() {
  local records="$1" record out=""
  for record in ${records}; do
    [[ "$(bound_outcome "${record}")" == "succeeded" ]] || continue
    out="${out}${out:+, }$(bound_work "${record}") \
($(bound_transaction "${record}"), $(bound_identity "${record}"))"
  done
  printf '%s' "${out}"
}

# The mirror, for the controls whose claim is that work came to nothing: each
# unsettled record with the termination that says it stopped trying.
bound_terminations() {
  local records="$1" record out=""
  for record in ${records}; do
    [[ "$(bound_outcome "${record}")" == "succeeded" ]] && continue
    out="${out}${out:+, }$(bound_work "${record}")=\
$(bound_outcome "${record}") ($(bound_transaction "${record}"), \
$(bound_identity "${record}"))"
  done
  printf '%s' "${out}"
}

run_work_driver() {
  local phase="$1" report rc=0
  note "driving ${phase} work on the rehearsal chain"
  WORK_DRIVER_RC=0
  WORK_DRIVER_TX_COUNT=0
  WORK_DRIVER_CEREMONY_RESULTS=""
  WORK_DRIVER_ORIGINATED=""
  WORK_DRIVER_BOUND_RESULTS=""
  WORK_DRIVER_ORIGINATED_WORK=""
  WORK_DRIVER_RESULT_CONTRIBUTORS=""
  report="$("${PR4109_WORK_DRIVER}" "${phase}")" || rc=$?
  WORK_DRIVER_RC="${rc}"

  if [[ -n "${report//[[:space:]]/}" ]]; then
    # Six lines out of one parse: the hashes, the outcomes, the ceremonies
    # still in flight, the outcomes bound to what started them, the in-flight
    # work bound to the nodes holding a permit for it, and the parties each
    # settled transcript incorporated. Parsing six times would report a
    # malformed object six times and, worse, could accept one part of a report
    # whose other parts are unreadable.
    local parsed hashes
    parsed="$(printf '%s' "${report}" | node -e '
      const CEREMONIES = ["beacon_dkg", "beacon_signing", "tbtc_dkg",
        "tbtc_heartbeat", "tbtc_signing", "tbtc_wallet_action"];
      const OUTCOMES = ["succeeded", "failed", "timed_out"];
      // The two ways work legitimately comes to nothing, as opposed to work
      // that has simply not finished yet.
      const TERMINATIONS = ["retry_exhausted", "no_threshold"];
      let raw = "";
      process.stdin.on("data", (d) => (raw += d));
      process.stdin.on("end", () => {
        const report = JSON.parse(raw);
        const hashes = report.transaction_hashes;
        const encoded = [];
        if (hashes !== undefined) {
          if (!Array.isArray(hashes)) {
            console.error("transaction_hashes is not an array");
            process.exit(1);
          }
          for (const hash of hashes) {
            if (typeof hash !== "string" || !/^0x[0-9a-f]{64}$/.test(hash)) {
              console.error("not a transaction hash: " + JSON.stringify(hash));
              process.exit(1);
            }
            encoded.push(JSON.stringify(hash));
          }
        }
        // The chain anchor a permit pins its mode from and the chain-native
        // identity of the request, group, wallet action, or DKG seed behind
        // the work. Several events can share a block, so ceremony plus anchor
        // is not an identity.
        const anchorOf = (entry, what) => {
          const block = (entry || {}).canonical_start_block;
          if (!Number.isInteger(block) || block < 1) {
            console.error(what + " names no canonical start block: " +
              JSON.stringify((entry || {}).ceremony));
            process.exit(1);
          }
          return block;
        };
        const workIDOf = (entry, what) => {
          const id = (entry || {}).work_id;
          if (typeof id !== "string" ||
            !/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(id)) {
            console.error(what + " names no chain work id: " +
              JSON.stringify((entry || {}).ceremony));
            process.exit(1);
          }
          return id;
        };
        // One transaction starts one piece of work, and one piece of work
        // retains that transaction when the report also carries its terminal
        // outcome. Without both directions a report can name several
        // ceremonies against one hash or replace an origination hash with an
        // unrelated successful hash at the terminal boundary.
        const owners = new Map();
        const transactions = new Map();
        const claim = (work, tx) => {
          const owner = owners.get(tx);
          if (owner !== undefined && owner !== work) {
            console.error("transaction claimed by two pieces of work: " +
              JSON.stringify(tx));
            process.exit(1);
          }
          const transaction = transactions.get(work);
          if (transaction !== undefined && transaction !== tx) {
            console.error("work claimed by two transactions: " +
              JSON.stringify(work));
            process.exit(1);
          }
          owners.set(tx, work);
          transactions.set(work, tx);
        };
        // What the driver put on the chain, whatever became of it, and which
        // nodes took a permit for it. A phase whose subject is work still in
        // flight cannot read the terminal outcomes: by the time one exists the
        // work it was about is over.
        const originated = report.originated_ceremonies;
        const started = [];
        const inflight = [];
        const startedWork = new Set();
        const startedPermits = new Set();
        if (originated !== undefined) {
          if (!Array.isArray(originated)) {
            console.error("originated_ceremonies is not an array");
            process.exit(1);
          }
          for (const entry of originated) {
            // A bare ceremony name is the shape this report used to take, and
            // it identifies nothing: the drain that reads it has to follow
            // permits, and a name says neither which run of the ceremony nor
            // which nodes took one. Refusing it by name rather than by field
            // keeps a driver still emitting the old form from reporting as a
            // run that originated nothing.
            if (entry === null || typeof entry !== "object" ||
              Array.isArray(entry)) {
              console.error("originated work is not an object naming a " +
                "ceremony, canonical start block, transaction and holders: " +
                JSON.stringify(entry));
              process.exit(1);
            }
            const ceremony = entry.ceremony;
            if (!CEREMONIES.includes(ceremony)) {
              console.error("not a ceremony: " + JSON.stringify(ceremony));
              process.exit(1);
            }
            const block = anchorOf(entry, "originated work");
            const tx = (entry || {}).transaction_hash;
            if (typeof tx !== "string" ||
              !encoded.includes(JSON.stringify(tx))) {
              console.error("originated work names no transaction the report " +
                "originated: " + JSON.stringify(ceremony));
              process.exit(1);
            }
            // The local permits this work produced. A node controlling two
            // memberships takes two permits, so holders are records rather
            // than a set of service names. permit_id is the stable local
            // membership/member index or wallet/action identity by which a
            // quarantine record can be matched one-to-one.
            const holders = (entry || {}).holders;
            if (!Array.isArray(holders) || holders.length === 0) {
              console.error("originated work names no holding node: " +
                JSON.stringify(ceremony));
              process.exit(1);
            }
            for (const holder of holders) {
              if (holder === null || typeof holder !== "object" ||
                Array.isArray(holder) ||
                typeof holder.service !== "string" ||
                !/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(holder.service)) {
                console.error("not a holding node: " + JSON.stringify(holder));
                process.exit(1);
              }
              if (typeof holder.permit_id !== "string" ||
                !/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(holder.permit_id)) {
                console.error("holding node names no local permit identity: " +
                  JSON.stringify(holder.service));
                process.exit(1);
              }
            }
            const work = ceremony + "@" + block + "@" +
              workIDOf(entry, "originated work");
            if (startedWork.has(work)) {
              console.error("work originated twice: " + JSON.stringify(work));
              process.exit(1);
            }
            startedWork.add(work);
            claim(work, tx);
            started.push(ceremony);
            for (const holder of holders) {
              const localPermit = holder.service + "~" + holder.permit_id;
              const permit = work + "#" + localPermit;
              if (startedPermits.has(permit)) {
                console.error("local permit originated twice: " +
                  JSON.stringify(permit));
                process.exit(1);
              }
              startedPermits.add(permit);
              inflight.push(work + "=" + tx + "=" + localPermit);
            }
          }
        }
        const results = report.ceremony_results;
        const all = [];
        const bound = [];
        const contributors = [];
        const endedWork = new Set();
        if (results !== undefined) {
          if (!Array.isArray(results)) {
            console.error("ceremony_results is not an array");
            process.exit(1);
          }
          for (const result of results) {
            const ceremony = (result || {}).ceremony;
            const outcome = (result || {}).outcome;
            if (!CEREMONIES.includes(ceremony)) {
              console.error("not a ceremony: " + JSON.stringify(ceremony));
              process.exit(1);
            }
            if (!OUTCOMES.includes(outcome)) {
              console.error("not an outcome: " + JSON.stringify(outcome));
              process.exit(1);
            }
            // The same identity the in-flight half carries, so a phase can
            // follow one piece of work from the permit it took to what became
            // of it. One piece of work ends once: a second record for the same
            // identity is either a duplicate or two outcomes for one ceremony,
            // and both make the reconciliation below count an outcome twice.
            const block = anchorOf(result, "result");
            const work = ceremony + "@" + block + "@" +
              workIDOf(result, "result");
            if (endedWork.has(work)) {
              console.error("work reported terminal twice: " +
                JSON.stringify(work));
              process.exit(1);
            }
            endedWork.add(work);
            // The transaction this outcome belongs to, and it has to be one
            // the same report accounted for putting on the chain. Without it
            // the hashes and the outcomes are two independent populations,
            // and a stale hash beside an unrelated result satisfies every
            // control that reads them as parallel arrays.
            const tx = (result || {}).transaction_hash;
            if (typeof tx !== "string" || !/^0x[0-9a-f]{64}$/.test(tx)) {
              console.error("result carries no transaction hash: " +
                JSON.stringify(ceremony));
              process.exit(1);
            }
            if (!encoded.includes(JSON.stringify(tx))) {
              console.error("result names a transaction the report did not " +
                "originate: " + JSON.stringify(tx));
              process.exit(1);
            }
            claim(work, tx);
            // What the ceremony actually left behind. A control that asks
            // whether a ceremony settled cannot read that off the word
            // "succeeded": the identity of the threshold output is the thing
            // that distinguishes a ceremony that produced one from a report
            // that says it did.
            const identity = (result || {}).result;
            const termination = (result || {}).termination;
            if (outcome === "succeeded") {
              if (typeof identity !== "string" || !/^\S+$/.test(identity)) {
                console.error("successful result carries no threshold " +
                  "output identity: " + JSON.stringify(ceremony));
                process.exit(1);
              }
              // Who the settled transcript actually incorporated. Required on
              // every success, because the control that reads it is about
              // which releases took part and a result that named nobody would
              // let a homogeneous run stand for a mixed one.
              const parties = (result || {}).contributors;
              if (!Array.isArray(parties) || parties.length === 0) {
                console.error("successful result names no contributing " +
                  "party: " + JSON.stringify(ceremony));
                process.exit(1);
              }
              const seenParties = new Set();
              for (const party of parties) {
                if (party === null || typeof party !== "object" ||
                  Array.isArray(party) ||
                  typeof party.service !== "string" ||
                  !/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(party.service)) {
                  console.error("not a contributing party: " +
                    JSON.stringify(party));
                  process.exit(1);
                }
                if (typeof party.permit_id !== "string" ||
                  !/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(party.permit_id)) {
                  console.error("contributing party names no local permit " +
                    "identity: " + JSON.stringify(party.service));
                  process.exit(1);
                }
                const localParty = party.service + "~" + party.permit_id;
                // One party contributes to one transcript once. A repeated
                // entry would let a single contribution be counted as the
                // several a threshold needs.
                if (seenParties.has(localParty)) {
                  console.error("party contributed twice to one result: " +
                    JSON.stringify(work + "#" + localParty));
                  process.exit(1);
                }
                seenParties.add(localParty);
                contributors.push(work + "=" + localParty);
              }
            } else if (!TERMINATIONS.includes(termination)) {
              // The mirror of the above for the outcomes a fails-closed
              // control is about. "failed" alone is equally what a ceremony
              // still retrying looks like from outside, and a control about
              // work coming to nothing cannot be read off one in progress.
              console.error("unsettled result carries no termination " +
                "evidence: " + JSON.stringify(ceremony));
              process.exit(1);
            }
            // Every outcome is carried out, not only the successes. A phase
            // that kept the successes alone could not tell a clean run from
            // one where a required ceremony failed beside a passing one, and
            // could not see a ceremony succeeding where the property under
            // test is that it must not.
            all.push(ceremony + "=" + outcome);
            bound.push(work + "=" + outcome + "=" + tx + "=" +
              (outcome === "succeeded" ? identity : termination));
          }
        }
        process.stdout.write(encoded.join(",") + "\n" +
          all.join(" ") + "\n" + started.join(" ") + "\n" + bound.join(" ") +
          "\n" + inflight.join(" ") + "\n" + contributors.join(" "));
      });
    ')" ||
      blocked "the work driver reported the ${phase} phase in a form this \
rehearsal cannot read; its stdout must be a JSON object whose optional \
transaction_hashes array carries 0x-prefixed 32-byte hashes, whose optional \
originated_ceremonies array carries {ceremony, canonical_start_block, work_id, \
transaction_hash, holders} objects naming work put on the chain, with holders \
as {service, permit_id} objects naming every local permit separately, and \
whose optional ceremony_results array carries {ceremony, \
canonical_start_block, work_id, outcome, transaction_hash} objects over the \
known ceremonies and outcomes — each naming a transaction the same report \
originated and no other piece of work claims, each retaining the same \
transaction wherever the same work appears, each identifying one chain work \
item and local permit exactly once, and each carrying either a result identity \
and a contributors array of {service, permit_id} objects naming every party the \
settled transcript incorporated, no party twice, when it succeeded or a \
termination of retry_exhausted or no_threshold when it did not — and a report \
that cannot be read leaves the step with no account of what it drove"

    hashes="$(printf '%s\n' "${parsed}" | sed -n '1p')"
    WORK_DRIVER_CEREMONY_RESULTS="$(printf '%s\n' "${parsed}" | sed -n '2p')"
    WORK_DRIVER_ORIGINATED="$(printf '%s\n' "${parsed}" | sed -n '3p')"
    WORK_DRIVER_BOUND_RESULTS="$(printf '%s\n' "${parsed}" | sed -n '4p')"
    WORK_DRIVER_ORIGINATED_WORK="$(printf '%s\n' "${parsed}" | sed -n '5p')"
    WORK_DRIVER_RESULT_CONTRIBUTORS="$(printf '%s\n' "${parsed}" | sed -n '6p')"

    # Before any of it enters a step's record. A reading taken from a report
    # the chain does not corroborate is not a weaker reading, it is a
    # different kind of thing, and nothing downstream could tell them apart.
    confirm_reported_work "${phase}" "${hashes}" \
      "${WORK_DRIVER_ORIGINATED_WORK}" "${WORK_DRIVER_BOUND_RESULTS}"

    if [[ -n "${hashes}" ]]; then
      STEP_TX_HASHES="${STEP_TX_HASHES}${STEP_TX_HASHES:+,}${hashes}"
      # A transaction hash cannot contain the separator, so the separators are
      # the count. The number is what a step reads to know the driver named
      # something rather than reported an empty run.
      WORK_DRIVER_TX_COUNT=$(($(printf '%s' "${hashes}" | tr -cd ',' |
        wc -c | tr -d '[:space:]') + 1))
    fi
  fi

  return "${rc}"
}

# What the straggler control observed, in ANNOUNCER_CUTOVER_METRICS order:
# the mismatch, the cross-format recognition, and the roster addition, each
# before and after the driven post-C ceremony.
STRAGGLER_BEFORE=()
STRAGGLER_AFTER=()

# The operator address the straggler publishes as its own, and the accounting
# of the driver call that was supposed to make it announce.
#
# The expected operator is what turns "some operator entered the roster" into
# the control's actual claim. The R1 fleet is on a network with exactly one
# legacy peer, and the roster entry that matters is that peer's: an entry
# naming anything else is the release attributing a legacy sighting to the
# wrong node, which is worse evidence than no entry at all.
STRAGGLER_EXPECTED_OPERATOR=""
STRAGGLER_DRIVER_SUPPLIED=0
STRAGGLER_DRIVER_RC=0
STRAGGLER_DRIVER_TX=0
# The terminal outcomes of the ceremony this control drove.
#
# "Fails closed" is a claim about what the ceremony produced, and the counters
# below cannot carry it: a roster entry says the straggler was seen and named,
# not that its participation came to nothing. The rehearsal fleet is sized so
# the driven post-C ceremony needs the straggler to reach threshold, so a
# result that settled means either the straggler was not refused after all or
# the ceremony never depended on it — and a control that did not need the
# node it is about has not exercised the failure path it claims to.
#
# Each outcome is bound to the transaction that started it and to the
# termination that says the ceremony stopped trying. A bare "failed" is
# equally what a ceremony still retrying looks like from outside this fleet:
# only retries exhausted, or a round that reached no threshold, tells the two
# apart, and a control about work that came to nothing cannot be read off work
# still in progress.
STRAGGLER_BOUND=""

# One operator address in the form two spellings of the same address share.
# Chain addresses arrive EIP-55 checksummed from one source and lowercase from
# another, and a comparison that reads those as different operators would
# refuse the control for a difference in capitalization.
normalize_operator() {
  local address="${1#0x}"
  address="${address#0X}"
  printf '%s' "${address}" | tr '[:upper:]' '[:lower:]'
}

# The verdict those observations imply, over the same seam as the two below.
#
# The chain here is what the control is about and every link is required. A
# session-ID mismatch alone is any two peers disagreeing on a session. A
# mismatch this node did not recognize as cross-format is a straggler it
# failed to identify — the release's whole premise is that it does. A
# recognized cross-format peer that never entered the roster is a sighting
# that produced no evidence. A roster whose revision moved without naming an
# operator this node had not already seen is not the specific operator
# becoming blocking evidence. And an operator that is not the straggler's own
# is the release naming the wrong node.
straggler_control_verdict() {
  local new_operators="$1"
  local step="post-cutover straggler fails closed and enters the roster"
  local assertion="old post-C behavior fails closed and becomes \
operator-identified blocking evidence"

  if ((STRAGGLER_DRIVER_SUPPLIED == 0)); then
    block_step "${step}" "no PR4109_WORK_DRIVER was supplied, so no post-C \
ceremony was originated for the straggler to announce into; whatever the \
counters below hold was not produced by this control"
    record_assertion "${assertion}" false "${step}"
    return
  fi
  if ((STRAGGLER_DRIVER_RC != 0)); then
    block_step "${step}" "the work driver exited [${STRAGGLER_DRIVER_RC}] \
originating the post-C ceremony this control observes, so the announcement it \
was meant to provoke was never provoked and any counter movement below \
belongs to something else"
    record_assertion "${assertion}" false "${step}"
    return
  fi
  if ((STRAGGLER_DRIVER_TX == 0)); then
    block_step "${step}" "the work driver exited cleanly but named no \
transaction, so nothing attributes the sightings below to the post-C ceremony \
this control claims to have originated"
    record_assertion "${assertion}" false "${step}"
    return
  fi
  if [[ -z "${STRAGGLER_BOUND}" ]]; then
    block_step "${step}" "the work driver named no terminal outcome for the \
post-C ceremony it originated, so nothing says whether that ceremony \
exhausted its retries or is still running; a ceremony that has not finished \
cannot evidence failing closed, and the sightings below would be read off one \
still in progress"
    record_assertion "${assertion}" false "${step}"
    return
  fi
  local settled terminations
  settled="$(bound_settlements "${STRAGGLER_BOUND}")"
  terminations="$(bound_terminations "${STRAGGLER_BOUND}")"
  if [[ -n "${settled}" ]]; then
    record_step "${step}" fail "the post-C ceremony this control drove \
produced a threshold output (${settled}); the straggler entering the roster \
alongside a ceremony that settled is a node that was named but not refused, \
and this control is about a legacy participant whose post-C work comes to \
nothing"
    record_assertion "${assertion}" false "${step}"
    return
  fi
  # Recorded rather than merely required: the claim this control carries out
  # is that a named ceremony stopped trying, so the record names which
  # transaction it was and how it ended.
  note "the post-C ceremony came to nothing: ${terminations}"

  local i deltas=() unreadable=()
  for i in 0 1 2; do
    local before="${STRAGGLER_BEFORE[${i}]:-}" after="${STRAGGLER_AFTER[${i}]:-}"
    if [[ ! "${before}" =~ ^[0-9]+$ || ! "${after}" =~ ^[0-9]+$ ]]; then
      unreadable+=("${ANNOUNCER_CUTOVER_METRICS[${i}]}")
      deltas+=("unreadable")
    else
      deltas+=("$((after - before))")
    fi
  done

  if ((${#unreadable[@]} > 0)); then
    block_step "${step}" "the announcer's cross-format counters could not be \
read on the observing node (${unreadable[*]}); the gate's own refusal counter \
says nothing about whether a legacy announcement arrived, so nothing here \
observed the straggler at all"
    record_assertion "${assertion}" false "${step}"
  elif ((deltas[0] == 0)); then
    block_step "${step}" "the observing node saw no session-ID mismatch while \
the post-C ceremony ran, so no legacy announcement reached it; without a work \
driver originating post-C ceremonies the straggler never announces, and there \
is nothing for the R1 fleet to fail closed against"
    record_assertion "${assertion}" false "${step}"
  elif ((deltas[1] == 0)); then
    record_step "${step}" fail "the observing node saw ${deltas[0]} session-ID \
mismatch(es) and recognized none of them as cross-format; a legacy \
announcement the release cannot tell apart from an ordinary disagreement is a \
straggler it never identified"
    record_assertion "${assertion}" false "${step}"
  elif ((deltas[2] == 0)); then
    record_step "${step}" fail "the observing node recognized ${deltas[1]} \
cross-format peer(s) and added none to its legacy roster; a sighting that \
produces no roster entry produces no evidence"
    record_assertion "${assertion}" false "${step}"
  elif [[ -z "${new_operators}" ]]; then
    record_step "${step}" fail "the observing node recorded ${deltas[2]} \
legacy roster addition(s) from ${deltas[1]} cross-format sighting(s), but its \
roster named no operator it had not already seen; a refusal that does not \
become operator-identified evidence is not what this control is about"
    record_assertion "${assertion}" false "${step}"
  elif [[ -z "${STRAGGLER_EXPECTED_OPERATOR}" ]]; then
    block_step "${step}" "the observing node's roster newly named operator(s) \
${new_operators}, but the straggler's own operator address could not be read \
off the prior node, so nothing here can say the roster named the straggler \
rather than some other peer"
    record_assertion "${assertion}" false "${step}"
  elif ! straggler_operator_named "${new_operators}"; then
    record_step "${step}" fail "the observing node newly named operator(s) \
${new_operators} in its legacy roster, and none of them is the straggler's own \
operator ${STRAGGLER_EXPECTED_OPERATOR}; a sighting attributed to the wrong \
node is worse evidence than none, because the operator the roster names is \
what a release decision would act on"
    record_assertion "${assertion}" false "${step}"
  else
    record_step "${step}" pass "the observing node saw ${deltas[0]} \
session-ID mismatch(es), recognized ${deltas[1]} of them as cross-format, and \
turned them into ${deltas[2]} legacy roster addition(s) naming the straggler's \
own operator ${STRAGGLER_EXPECTED_OPERATOR} (newly named: ${new_operators}), \
so the straggler failed closed and was named rather than merely refused"
    record_assertion "${assertion}" true "${step}"
  fi
}

# True when the straggler's own operator is among the ones the roster newly
# named. Kept apart from the ladder so the comparison — which is where two
# spellings of one address decide a release gate — is one readable statement.
straggler_operator_named() {
  local expected operator
  expected="$(normalize_operator "${STRAGGLER_EXPECTED_OPERATOR}")"
  for operator in $1; do
    if [[ "$(normalize_operator "${operator}")" == "${expected}" ]]; then
      return 0
    fi
  done
  return 1
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
# The offer was made and the driver could not carry it out — a broken
# instrument, not a gate nobody challenged. Both leave the permit counter
# standing still, so the record has to tell them apart.
CLOCK_OFFER_FAILED=0
CLOCK_OFFER_RC=""
# What the gate reported once its chain endpoint came back. The clock-failure
# node is also the one the security-v2 quiescence half drains, so whether the
# gate recovered decides whether that step has a subject at all; it is observed
# here rather than inferred there from an empty drain.
CLOCK_RECOVERED_STATE=""

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
  elif ((CLOCK_OFFER_FAILED == 1)); then
    block_step "${step}" "the gate reported clock_unavailable and canceled the \
$((CLOCK_ABORTS_AFTER - CLOCK_ABORTS_BEFORE)) permit(s) it held, but the work \
driver exited [${CLOCK_OFFER_RC:-unreadable}] without naming a transaction \
when it was asked to originate work against the blind gate; nothing was put on \
the chain for the gate to refuse, so its permit counter standing still \
evidences no refusal"
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
# Set when the offer was made and the driver could not carry it out, which is a
# broken instrument rather than a node that was never asked. The two produce
# the same unchanged counters and must not produce the same account of why.
QUIESCE_OFFER_FAILED=0
QUIESCE_OFFER_RC=""
QUIESCE_GRACE=""
# The node's own account of having refused the offer, and of what it refused.
#
# An unchanged issued-permit counter is the shape of a refusal and also the
# shape of an offer that never arrived — a driver that submitted while the node
# was already gone, an event the node never saw, a ceremony that started
# somewhere else entirely. The gate counts every refusal it makes and counts it
# per ceremony, so requiring that counter to move on this node is what puts the
# refusal on the node rather than on the prober's inference, and the
# per-ceremony delta names what was refused.
QUIESCE_REFUSALS_BEFORE=""
QUIESCE_REFUSALS_AFTER=""
QUIESCE_CEREMONY_REFUSALS_BEFORE=""
QUIESCE_CEREMONY_REFUSALS_AFTER=""
# The ceremonies the offer itself put on the chain, retained so the counter
# that moved can be compared against the work that was actually offered. A
# per-ceremony delta on its own says the node refused something; the rehearsal
# chain carries other traffic, and any unrelated ceremony refused for its own
# reasons moves the total and one per-ceremony counter together, which is
# indistinguishable from this offer being refused.
QUIESCE_OFFERED=""
# The work this node was actually holding when the stop was issued, and what
# became of it, asked of the driver once the drain is over.
#
# "Lets held permits finish" is a claim about the work, and the node's own
# gauge cannot carry it: a process that exits holding a permit stops reporting
# the permit exactly as one that completed it does, and a gauge seen at zero is
# the same reading either way. Nor can a forced-abort counter that did not move
# stand in for it — a permit dropped when the process went is not a permit the
# gate force-canceled, and neither is it one that finished.
QUIESCE_INFLIGHT_WORK=""
QUIESCE_MISANCHORED=""
QUIESCE_TERMINAL=""
QUIESCE_TERMINAL_ASKED=0
QUIESCE_TERMINAL_RC=0
# The draining node's own account of the permits it closed, sampled inside the
# drain window because it goes away with the node. This is what the terminal
# rungs decide on; the driver's account above supplies the settlement
# identities and transactions the chain corroborates, which a gate scrape
# cannot know.
QUIESCE_AUTHORED_ENDINGS=""
QUIESCE_AUTHORED_READ=0
QUIESCE_PERMITS_BEFORE=""
QUIESCE_COLIVE_PERMITS=""
QUIESCE_COLIVE_REQUIRED=0
# The other mode's population, beside the one the control is named for. The
# fence a quiescing gate has to hold is the one where both modes are live at
# once, and the gate's promise is about every permit it was holding — so the
# other mode's permits are followed to a terminal outcome on the same footing
# as the named mode's. A gate list that is merely non-empty says the fence was
# exercised and nothing at all about what the far side of it ended up doing.
QUIESCE_COLIVE_WORK=""
QUIESCE_COLIVE_MODE=""
QUIESCE_COLIVE_MISANCHORED=""
QUIESCE_FROM_SEED=0

# The legacy permit the quiescence control drains, put on the chain before the
# fleet crossed C and observed in the gate that issued it while it was still on
# the legacy side.
#
# The legacy half of quiescence runs after the crossing, so work originated
# there is security-v2 work unless the driver deliberately anchors it below C —
# and a driver-supplied anchor is the driver's word for the one thing the
# control is about. A permit the gate itself reported holding before C is not.
QUIESCE_SEEDED_WORK=""
QUIESCE_SEEDED_ASKED=0
QUIESCE_SEEDED_RC=0
QUIESCE_SEEDED_PERMITS_BEFORE_C=""

# Put the legacy quiescence control's subject on the chain while the fleet is
# still below C, and record the permits the target node's own gate reported
# holding for it.
seed_legacy_quiescence_work() {
  local node="$1"

  QUIESCE_SEEDED_WORK=""
  QUIESCE_SEEDED_ASKED=0
  QUIESCE_SEEDED_RC=0
  QUIESCE_SEEDED_PERMITS_BEFORE_C=""

  [[ -n "${PR4109_WORK_DRIVER:-}" ]] || return 0
  QUIESCE_SEEDED_ASKED=1
  run_work_driver quiesce-legacy-seed || true
  QUIESCE_SEEDED_RC="${WORK_DRIVER_RC}"
  if driver_offered_work; then
    QUIESCE_SEEDED_WORK="$(work_records_held_by \
      "${WORK_DRIVER_ORIGINATED_WORK}" "${node}")"
  fi
  QUIESCE_SEEDED_PERMITS_BEFORE_C="$(node_mode_permits "${node}" legacy)"
}

# record_assertion, for the quiescence steps the gate contract records one
# for. The contract names a single graceful-quiescence assertion and binds it
# to the security-v2 step, so the legacy step decides the same ladder and
# reports no assertion of its own; writing one anyway would put a second entry
# under a name the contract expects exactly once.
quiescence_assertion() {
  [[ -n "$1" ]] || return 0
  record_assertion "$1" "$2" "$3"
}

# The verdict one quiescence control reached, for whichever permit mode was in
# flight.
#
# Both modes are the same property observed over a different permit
# population, so the ladder is shared and the mode is the caller's. Two copies
# would let the statement of what a quiescing node may do drift between the
# side of C the release is leaving and the side it is going to.
quiescence_verdict() {
  local node="$1" step="$2" assertion="$3" mode="$4"

  # Every permit the node was holding when it was told to stop, both modes
  # together. Smoke gate 6 asks that both live modes finish or enter audited
  # quarantine, so the terminal rungs below decide over the union rather than
  # over the mode the control happens to be named for; reconciling one half
  # would let the other end unaccounted while the step still reported that the
  # gate let what it held finish.
  local reconciled_work="${QUIESCE_INFLIGHT_WORK}"
  if ((QUIESCE_COLIVE_REQUIRED == 1)); then
    reconciled_work="${reconciled_work}${QUIESCE_COLIVE_WORK:+ ${QUIESCE_COLIVE_WORK}}"
  fi

  # A seeded control's subject was put on the chain before C and has to be
  # shown to have been there. Everything below decides on the permits the node
  # drained; these rungs decide whether those permits are the ones the crossing
  # left behind or ones the driver merely says were anchored below it.
  if ((QUIESCE_FROM_SEED == 1)) && ((QUIESCE_SEEDED_ASKED == 0)); then
    block_step "${step}" "no ${mode} permit was seeded before the fleet \
crossed C, so this step has no permit taken on the legacy side of the crossing \
to drain; work originated here takes a security-v2 permit unless a driver \
claims otherwise, and a claimed anchor is the driver's word for the one thing \
this control is about"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_FROM_SEED == 1)) && ((QUIESCE_SEEDED_RC != 0)); then
    block_step "${step}" "the work driver exited [${QUIESCE_SEEDED_RC}] \
seeding the ${mode} permit this step was to drain, so nothing was put on the \
chain before C for it to be about"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_FROM_SEED == 1)) &&
    [[ -z "${QUIESCE_SEEDED_WORK//[[:space:]]/}" ]]; then
    block_step "${step}" "the work driver exited cleanly before C but named no \
${mode} work it put on ${node}, so this step has nothing it can follow from \
the legacy side of the crossing into the drain"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_FROM_SEED == 1)) &&
    [[ "${QUIESCE_SEEDED_PERMITS_BEFORE_C}" == "unreadable on "* ]]; then
    block_step "${step}" "${node} could not be asked which ${mode} permits it \
held before C (${QUIESCE_SEEDED_PERMITS_BEFORE_C}); without that reading the \
permit drained below rests on the driver's claimed anchor rather than on the \
gate having issued it on the legacy side of the crossing"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_FROM_SEED == 1)) &&
    [[ -n "$(absent_tokens \
      "$(held_permit_identities "${QUIESCE_SEEDED_WORK}")" \
      "${QUIESCE_SEEDED_PERMITS_BEFORE_C}")" ]]; then
    block_step "${step}" "${node} was not holding \
$(absent_tokens "$(held_permit_identities "${QUIESCE_SEEDED_WORK}")" \
      "${QUIESCE_SEEDED_PERMITS_BEFORE_C}") while the fleet was still below C, \
though the driver named it as seeded there; a permit the gate did not report \
issuing on the legacy side of the crossing is not one this control can drain \
as legacy work"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ "${QUIESCE_STATE}" != "quiescing" ]]; then
    record_step "${step}" fail "${node} never reported quiescing while \
draining with ${QUIESCE_HELD_BEFORE} ${mode} ceremonies in flight"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ ! "${QUIESCE_ISSUED_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${QUIESCE_ISSUED_AFTER}" =~ ^[0-9]+$ ]]; then
    block_step "${step}" "${node} entered quiescing, but its issued-permit \
counter could not be read (${QUIESCE_ISSUED_BEFORE:-unreadable} to \
${QUIESCE_ISSUED_AFTER:-unreadable}); the active gauge alone cannot say \
whether a permit was taken and closed between two samples"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_ISSUED_AFTER > QUIESCE_ISSUED_BEFORE)); then
    record_step "${step}" fail "${node} entered quiescing and still issued \
$((QUIESCE_ISSUED_AFTER - QUIESCE_ISSUED_BEFORE)) new permit(s) \
(${QUIESCE_ISSUED_BEFORE} to ${QUIESCE_ISSUED_AFTER}); a quiescing node \
started new work"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ ! "${QUIESCE_FORCED_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${QUIESCE_FORCED_AFTER}" =~ ^[0-9]+$ ]]; then
    block_step "${step}" "${node} entered quiescing and issued no new permit, \
but its forced-abort counter could not be read \
(${QUIESCE_FORCED_BEFORE:-unreadable} to ${QUIESCE_FORCED_AFTER:-unreadable}), \
so nothing here observed whether the permits it held finished or were cut \
short"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_FORCED_AFTER > QUIESCE_FORCED_BEFORE)); then
    record_step "${step}" fail "${node} force-aborted \
$((QUIESCE_FORCED_AFTER - QUIESCE_FORCED_BEFORE)) held permit(s) rather than \
letting them finish inside the ${QUIESCE_GRACE}s grace"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_DRAINED == 0)); then
    block_step "${step}" "${node} entered quiescing holding \
${QUIESCE_HELD_BEFORE} ${mode} ceremonies and was never seen without \
them; the node stopped answering with its in-flight count unobserved at zero, \
so nothing here says those permits finished rather than went down with the \
process"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ -z "${QUIESCE_INFLIGHT_WORK//[[:space:]]/}" ]]; then
    # The gauge fell, and a gauge falling is where this step used to stop. It
    # is the same reading a process that exited holding its permits produces,
    # so the permits have to be named before anything can be said about them.
    block_step "${step}" "${node} was seen without the \
${QUIESCE_HELD_BEFORE} ${mode} ceremonies it held, but the driver named no \
identified work it was holding; an in-flight count says how many permits there \
were and not which work each one was issued for, and a count that fell to zero \
cannot be followed to anything"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ -n "${QUIESCE_MISANCHORED}" ]]; then
    block_step "${step}" "${node} drained ${QUIESCE_MISANCHORED}, which is not \
${mode}-anchored work; the gate pins a permit's mode from the work's canonical \
start block, so a control labelled ${mode} that drained work anchored on the \
other side of C observed a permit of the other mode and says nothing about \
this one"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_HELD_BEFORE != $(count_tokens \
    "$(permit_identities "${QUIESCE_INFLIGHT_WORK}")"))); then
    block_step "${step}" "${node} held ${QUIESCE_HELD_BEFORE} ${mode} \
permit(s) for $(count_tokens "$(permit_identities \
      "${QUIESCE_INFLIGHT_WORK}")") piece(s) of work the driver put on it \
($(permit_identities "${QUIESCE_INFLIGHT_WORK}")); the permit counter and the \
driver's account describe different populations, so an outcome for one piece \
of work cannot be said to be the outcome of any particular held permit"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ "${QUIESCE_PERMITS_BEFORE}" == "unreadable on "* ]]; then
    block_step "${step}" "${node} could not be asked which ${mode} permits it \
was holding when the stop was issued (${QUIESCE_PERMITS_BEFORE}); the count it \
did report says how many permits drained and never which, so the outcomes \
below would be reconciled against the driver's account alone"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ -n "$(absent_tokens \
    "$(held_permit_identities "${QUIESCE_INFLIGHT_WORK}")" \
    "${QUIESCE_PERMITS_BEFORE}")" ]]; then
    block_step "${step}" "${node} was drained holding \
${QUIESCE_PERMITS_BEFORE:-nothing it named}, which does not include \
$(absent_tokens "$(held_permit_identities "${QUIESCE_INFLIGHT_WORK}")" \
      "${QUIESCE_PERMITS_BEFORE}") from the driver's account of the work it \
put there; a permit the issuing gate never reported holding is one the driver \
alone vouches for"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ -n "$(absent_tokens "${QUIESCE_PERMITS_BEFORE}" \
    "$(held_permit_identities "${QUIESCE_INFLIGHT_WORK}")")" ]]; then
    block_step "${step}" "${node} was drained holding \
$(absent_tokens "${QUIESCE_PERMITS_BEFORE}" \
      "$(held_permit_identities "${QUIESCE_INFLIGHT_WORK}")") beside the work \
the driver named; an unidentified permit draining alongside the named ones is \
one this step would speak for without ever having followed it"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_COLIVE_REQUIRED == 1)) &&
    [[ "${QUIESCE_COLIVE_PERMITS}" == "unreadable on "* ]]; then
    block_step "${step}" "${node} could not be asked whether it held a permit \
of the other mode when the stop was issued (${QUIESCE_COLIVE_PERMITS}); the \
fence a quiescing gate has to hold is the one where both modes are live at \
once, and an unread node there leaves it unexercised"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_COLIVE_REQUIRED == 1)) &&
    [[ -z "${QUIESCE_COLIVE_PERMITS}" ]]; then
    block_step "${step}" "${node} held only ${mode} permits when the stop was \
issued; a gate draining one population never has to keep the two modes apart, \
so this needs a permit of the other mode live beside the ${mode} one it is \
about"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_COLIVE_REQUIRED == 1)) &&
    [[ -z "${QUIESCE_COLIVE_WORK//[[:space:]]/}" ]]; then
    # The gate list is non-empty, which is where this rung used to stop. It
    # names permits and not the work behind them, so nothing here could be
    # followed to an outcome — and the gate's promise covers these permits too.
    block_step "${step}" "${node} held ${QUIESCE_COLIVE_PERMITS} of the \
${QUIESCE_COLIVE_MODE} mode beside the ${mode} permits it was drained for, but \
the driver named no work it put there; a permit nothing identifies cannot be \
followed to an end, so half the population this drain covers would go \
unaccounted for"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_COLIVE_REQUIRED == 1)) &&
    [[ -n "${QUIESCE_COLIVE_MISANCHORED}" ]]; then
    block_step "${step}" "${node} held ${QUIESCE_COLIVE_MISANCHORED} beside \
the ${mode} permits it was drained for, which is not \
${QUIESCE_COLIVE_MODE}-anchored work; the fence this control is about is the \
one where both modes are live at once, and a second population anchored on the \
same side of C as the first leaves it unexercised"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_COLIVE_REQUIRED == 1)) &&
    [[ -n "$(absent_tokens \
      "$(held_permit_identities "${QUIESCE_COLIVE_WORK}")" \
      "${QUIESCE_COLIVE_PERMITS}")" ]]; then
    block_step "${step}" "${node} reported holding ${QUIESCE_COLIVE_PERMITS} \
of the ${QUIESCE_COLIVE_MODE} mode, which does not include \
$(absent_tokens "$(held_permit_identities "${QUIESCE_COLIVE_WORK}")" \
      "${QUIESCE_COLIVE_PERMITS}") from the driver's account of the work it \
put there; a permit the issuing gate never reported holding is one the driver \
alone vouches for"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_COLIVE_REQUIRED == 1)) &&
    [[ -n "$(absent_tokens "${QUIESCE_COLIVE_PERMITS}" \
      "$(held_permit_identities "${QUIESCE_COLIVE_WORK}")")" ]]; then
    block_step "${step}" "${node} was drained holding \
$(absent_tokens "${QUIESCE_COLIVE_PERMITS}" \
      "$(held_permit_identities "${QUIESCE_COLIVE_WORK}")") of the \
${QUIESCE_COLIVE_MODE} mode beside the work the driver named; an unidentified \
permit draining alongside the named ones is one this step would speak for \
without ever having followed it"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_TERMINAL_ASKED == 0)); then
    block_step "${step}" "${node} let all ${QUIESCE_HELD_BEFORE} held permits \
go without being force-aborted, but the driver was never asked what became of \
the work behind them; a gauge that fell to zero is equally a ceremony that \
finished and a process that exited holding it, and only one of those is a \
permit that was allowed to finish"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_TERMINAL_RC != 0)); then
    block_step "${step}" "the work driver exited [${QUIESCE_TERMINAL_RC}] \
reporting what became of the work ${node} held, so its account of the chain \
stops wherever it failed; held permits reconciled against a partial report \
take the outcomes it happened to reach for all there were"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ -n "$(unoriginated_terminals "${QUIESCE_TERMINAL}" \
    "${reconciled_work}")" ]]; then
    block_step "${step}" "the driver reported terminal outcomes for \
$(unoriginated_terminals "${QUIESCE_TERMINAL}" \
      "${reconciled_work}"), which ${node} did not originate with those \
transactions; a later phase cannot replace the transaction that started held \
work with an unrelated transaction and call its outcome the held permit's end"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ -n "$(unended_work "${reconciled_work}" \
    "${QUIESCE_TERMINAL}" "")" ]]; then
    block_step "${step}" "${node} was seen without the permits it held, but \
the driver reported no terminal outcome for $(unended_work \
      "${reconciled_work}" "${QUIESCE_TERMINAL}" ""); a permit that \
stopped being counted while the work behind it never ended is a permit the \
process took with it, which is the one reading this step exists to refuse"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ -n "$(unsettled_work "${reconciled_work}" \
    "${QUIESCE_TERMINAL}")" ]]; then
    # An end, but not the end this step's assertion is about. Nothing in this
    # gate audits the state a ceremony that gave up left behind — that is the
    # rollback gate's quarantine reconciliation — so a quiescence that produced
    # one is recorded as unproven rather than as work allowed to finish.
    block_step "${step}" "${node} let its held permits go and the driver \
followed them to an end, but $(unsettled_work "${reconciled_work}" \
      "${QUIESCE_TERMINAL}") came to nothing rather than settling on chain; \
this gate audits no quarantined state, so work that gave up inside the grace \
evidences neither that it was allowed to finish nor that what it left behind \
is accounted for"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_AUTHORED_READ == 0)); then
    block_step "${step}" "${node} could not be asked what became of the \
permits it closed while it drained; every rung above this one reads the \
ending off the same driver that originated the work, so without the node's \
own record the drain is reported rather than observed"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ -n "$(unauthored_permits \
    "$(held_permit_identities "${reconciled_work}")" \
    "${QUIESCE_AUTHORED_ENDINGS}")" ]]; then
    block_step "${step}" "${node} recorded no ending for \
$(unauthored_permits "$(held_permit_identities "${reconciled_work}")" \
      "${QUIESCE_AUTHORED_ENDINGS}") while it drained, though the driver \
reported an outcome for it; a permit whose own holder will not say how it \
closed is one only the driver vouches for, and that is the reading this step \
exists to refuse"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ -n "$(duplicated_authored_permits \
    "$(held_permit_identities "${reconciled_work}")" \
    "${QUIESCE_AUTHORED_ENDINGS}")" ]]; then
    block_step "${step}" "${node} recorded more than one ending for \
$(duplicated_authored_permits \
      "$(held_permit_identities "${reconciled_work}")" \
      "${QUIESCE_AUTHORED_ENDINGS}"); one permit ends once, so neither record \
can be read as what became of it"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ -n "$(unresolved_authored_permits \
    "$(held_permit_identities "${reconciled_work}")" \
    "${QUIESCE_AUTHORED_ENDINGS}")" ]]; then
    # The gate writes this itself when a permit is closed by an owner that
    # recorded nothing. It is exactly the permit-taken-with-the-process reading
    # the rung above refuses, seen from the node's side rather than the
    # driver's.
    record_step "${step}" fail "${node} closed \
$(unresolved_authored_permits \
      "$(held_permit_identities "${reconciled_work}")" \
      "${QUIESCE_AUTHORED_ENDINGS}") without its ceremony owner recording any \
disposition; a permit whose holder cannot say where its ceremony went was not \
let finish inside the grace"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ -n "$(misended_authored_permits \
    "$(held_permit_identities "${reconciled_work}")" \
    "${QUIESCE_AUTHORED_ENDINGS}" "completed quarantined")" ]]; then
    record_step "${step}" fail "${node} recorded \
$(misended_authored_permits \
      "$(held_permit_identities "${reconciled_work}")" \
      "${QUIESCE_AUTHORED_ENDINGS}" "completed quarantined") for permits it \
was draining; this gate asks that held work finish or enter audited \
quarantine, and an ending that is neither is work the grace did not carry"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_OFFER_FAILED == 1)); then
    block_step "${step}" "${node} entered quiescing and let all \
${QUIESCE_HELD_BEFORE} held permits finish, but the work driver exited \
[${QUIESCE_OFFER_RC:-unreadable}] without naming a transaction when it was \
asked to originate work against the quiescing node, so nothing was put on the \
chain for it to refuse and the unchanged permit counter records only that"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_ATTEMPTED == 0)); then
    block_step "${step}" "${node} entered quiescing, let all \
${QUIESCE_HELD_BEFORE} held permits finish, and issued none — but no work was \
offered to it while it was quiescing, so the starts-no-new-work half rests on \
nothing having asked; it needs work originated on the rehearsal chain after \
the node enters quiescence"
    quiescence_assertion "${assertion}" false "${step}"
  elif [[ ! "${QUIESCE_REFUSALS_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${QUIESCE_REFUSALS_AFTER}" =~ ^[0-9]+$ ]]; then
    block_step "${step}" "${node} entered quiescing and was offered work, but \
its refusal counter could not be read \
(${QUIESCE_REFUSALS_BEFORE:-unreadable} to \
${QUIESCE_REFUSALS_AFTER:-unreadable}); without it the node's own account of \
having refused the offer is missing, and an unchanged permit counter is all \
that is left"
    quiescence_assertion "${assertion}" false "${step}"
  elif ((QUIESCE_REFUSALS_AFTER <= QUIESCE_REFUSALS_BEFORE)); then
    # The reading this rung exists for. Work was submitted and no permit was
    # issued, which is what a refusal looks like — and also what an offer that
    # never reached this node looks like. The gate counts every refusal it
    # makes, so a node that refused says so itself.
    record_step "${step}" fail "${node} entered quiescing, was offered work, \
and issued no permit — but its own refusal counter never moved (still \
${QUIESCE_REFUSALS_AFTER}); nothing here says the offer reached this node \
before it stopped, and an unchanged permit counter is equally the shape of \
work that was never presented to it"
    quiescence_assertion "${assertion}" false "${step}"
  else
    local refused refused_offered
    refused="$(refused_ceremony_delta "${QUIESCE_CEREMONY_REFUSALS_BEFORE}" \
      "${QUIESCE_CEREMONY_REFUSALS_AFTER}")"
    if [[ -z "${refused}" ]]; then
      block_step "${step}" "${node} refused \
$((QUIESCE_REFUSALS_AFTER - QUIESCE_REFUSALS_BEFORE)) offer(s) while \
quiescing, but no per-ceremony refusal counter moved with the total, so \
nothing here says which ceremony it refused; a refusal a release cannot \
attribute to a ceremony is not evidence about that ceremony"
      quiescence_assertion "${assertion}" false "${step}"
      return
    fi
    if [[ -z "${QUIESCE_OFFERED}" ]]; then
      block_step "${step}" "${node} refused ${refused} while quiescing, but \
the offer named no ceremony it originated, so nothing says the counter that \
moved belongs to the work this step put in front of it; a refusal of \
something else is not this offer being refused"
      quiescence_assertion "${assertion}" false "${step}"
      return
    fi
    refused_offered="$(refused_offered_delta \
      "${QUIESCE_CEREMONY_REFUSALS_BEFORE}" \
      "${QUIESCE_CEREMONY_REFUSALS_AFTER}" "${QUIESCE_OFFERED}")"
    if [[ -z "${refused_offered}" ]]; then
      block_step "${step}" "${node} refused ${refused} while quiescing, but \
this offer originated ${QUIESCE_OFFERED} and none of those counters moved; \
the rehearsal chain carries other traffic, and a ceremony refused for its own \
reasons moves the total and a per-ceremony counter together exactly as this \
offer being refused would"
      quiescence_assertion "${assertion}" false "${step}"
      return
    fi
    record_step "${step}" pass "${node} entered quiescing holding \
${QUIESCE_HELD_BEFORE} ${mode} ceremonies its own gate named \
(${QUIESCE_PERMITS_BEFORE})$( ((QUIESCE_COLIVE_REQUIRED == 1)) &&
      printf ', seeded before C and live beside %s of the %s mode' \
        "${QUIESCE_COLIVE_PERMITS}" "${QUIESCE_COLIVE_MODE}"), was offered \
${QUIESCE_OFFERED} while quiescing and refused it on its own account \
(${refused_offered}; refusals \
${QUIESCE_REFUSALS_BEFORE} to ${QUIESCE_REFUSALS_AFTER}) while issuing no \
permit (${QUIESCE_ISSUED_BEFORE} to ${QUIESCE_ISSUED_AFTER}), and let every \
held permit finish inside the reviewed ${QUIESCE_GRACE}s grace — in-flight \
count observed at zero, no forced abort (${QUIESCE_FORCED_BEFORE} to \
${QUIESCE_FORCED_AFTER}), and every piece of work it was holding across \
$( ((QUIESCE_COLIVE_REQUIRED == 1)) && printf 'both modes' ||
      printf 'the %s mode' "${mode}") closed with the ending its own holder \
recorded ($(authored_endings \
      "$(held_permit_identities "${reconciled_work}")" \
      "${QUIESCE_AUTHORED_ENDINGS}")) and settled on chain \
($(bound_settlements "${QUIESCE_TERMINAL}"))"
    quiescence_assertion "${assertion}" true "${step}"
  fi
}

# Drain one node holding permits of one mode, and record what that observed.
#
# Everything the ladder above decides on is collected here, so both quiescence
# controls watch the same window in the same way and differ only in which
# permit population they are about: the gauge that counts the held permits, the
# counter that would show a new one being issued, and the driver phases that
# put work of that mode in flight. The observation is a window rather than a
# pair of samples because the contract — no new permit from the moment
# quiescing begins, held permits left to finish — is a statement about the
# whole drain.
run_quiescence_control() {
  local node="$1" step="$2" assertion="$3" mode="$4"
  local active_field="$5" issued_metric="$6" phase="$7" seeded="${8:-}"
  # Supplied-but-empty is the seeding having failed, which is a different
  # reading from a control that was never seeded at all; the ladder has to be
  # able to say which.
  QUIESCE_FROM_SEED=0
  (($# >= 8)) && QUIESCE_FROM_SEED=1

  # The property is about a permit the node is holding while it is told to
  # stop, so one has to be in flight before the stop is issued. A node with
  # nothing running quiesces trivially and evidences nothing.
  #
  # The work it puts in flight is retained, not only the fact that it ran: the
  # permits this node is about to be told to drain have to be followed to an
  # outcome afterwards, and only the driver's account names which piece of work
  # each one was issued for.
  #
  # A control handed seeded work drains that instead. Its subject was put on
  # the chain earlier — before C, where a legacy permit is the only kind a gate
  # will issue — so originating more here would replace the permit under
  # examination with one taken on the far side of the crossing.
  QUIESCE_COLIVE_REQUIRED="${QUIESCE_FROM_SEED}"
  QUIESCE_COLIVE_PERMITS=""
  QUIESCE_COLIVE_WORK=""
  QUIESCE_COLIVE_MISANCHORED=""
  QUIESCE_COLIVE_MODE=""
  QUIESCE_INFLIGHT_WORK="${seeded}"
  if ((QUIESCE_FROM_SEED == 1)); then
    case "${mode}" in
    legacy) QUIESCE_COLIVE_MODE="security-v2" ;;
    *) QUIESCE_COLIVE_MODE="legacy" ;;
    esac
    # The other mode is put in flight beside it deliberately. The fence a
    # quiescing gate has to hold is the one where both modes are live at once,
    # and a node draining a single population never exercises it.
    #
    # What that run originated is kept, not discarded: the gate's promise
    # covers every permit it was holding, so these permits are reconciled to
    # terminal outcomes exactly as the seeded ones are.
    if [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
      run_work_driver "${phase}-inflight" || true
      if driver_offered_work; then
        QUIESCE_COLIVE_WORK="$(work_records_held_by \
          "${WORK_DRIVER_ORIGINATED_WORK}" "${node}")"
      fi
    fi
  elif [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
    run_work_driver "${phase}-inflight" || true
    if driver_offered_work; then
      QUIESCE_INFLIGHT_WORK="$(work_records_held_by \
        "${WORK_DRIVER_ORIGINATED_WORK}" "${node}")"
    fi
  fi
  # This work is originated when the control starts, which for the legacy half
  # is after the fleet has already crossed C. The gate pins a permit's mode
  # from the work's anchor rather than the current height, so a driver can
  # still put a legacy-anchored permit in flight here — but nothing in the
  # readings above says it did, and fresh chain work at this point is
  # security-v2. Naming the population's anchors is what tells the two apart.
  QUIESCE_MISANCHORED="$(misanchored_for_mode "${QUIESCE_INFLIGHT_WORK}" \
    "${mode}" "${REHEARSAL_R1_CUTOVER_BLOCK}")"
  QUIESCE_HELD_BEFORE="$(participation_field "${node}" \
    "${active_field}" 2>/dev/null || printf '')"
  # What the node itself says it is holding, taken beside the count that says
  # how much. The outcomes below are reconciled against the driver's account of
  # the work; naming the permits is what makes that account checkable against
  # the gate that issued them rather than merely consistent with a gauge.
  QUIESCE_PERMITS_BEFORE="$(node_mode_permits "${node}" "${mode}")"
  if ((QUIESCE_COLIVE_REQUIRED == 1)); then
    QUIESCE_COLIVE_PERMITS="$(node_mode_permits "${node}" \
      "${QUIESCE_COLIVE_MODE}")"
    QUIESCE_COLIVE_MISANCHORED="$(misanchored_for_mode \
      "${QUIESCE_COLIVE_WORK}" "${QUIESCE_COLIVE_MODE}" \
      "${REHEARSAL_R1_CUTOVER_BLOCK}")"
  fi
  QUIESCE_FORCED_BEFORE="$(metric_value "${node}" \
    participation_quiesce_forced_aborts_total || printf '')"
  QUIESCE_ISSUED_BEFORE="$(metric_value "${node}" \
    "${issued_metric}" || printf '')"
  QUIESCE_REFUSALS_BEFORE="$(metric_value "${node}" \
    participation_refusals_total || printf '')"
  QUIESCE_CEREMONY_REFUSALS_BEFORE="$(ceremony_refusal_counters "${node}")"

  if [[ ! "${QUIESCE_HELD_BEFORE}" =~ ^[0-9]+$ ]] ||
    ((QUIESCE_HELD_BEFORE == 0)); then
    block_step "${step}" "${node} held no ${mode} ceremony when the stop was \
due to be issued (${active_field} [${QUIESCE_HELD_BEFORE:-unreadable}]); a \
node with nothing in flight quiesces trivially, so this needs work originated \
on the rehearsal chain that is still running at shutdown"
    quiescence_assertion "${assertion}" false "${step}"
    return
  fi

  # The same grace the manifest grants and the compose file declares, so the
  # node is not SIGKILLed before its own in-process backstop can finish what
  # it holds. A number restated here would go on stopping nodes under the
  # old ceiling the first time the reviewed bounds moved.
  QUIESCE_GRACE="$(manifest_termination_grace)"
  if ((SINGLE_RELEASE_QUARANTINE_PRESERVATION_SAMPLING == 1)); then
    sample_quarantine_preservation_signals "${node}"
  fi
  compose stop --timeout "${QUIESCE_GRACE}" "${node}" &
  local stop_pid=$!

  local held_now forced_now issued_now state_now refusals_now deadline
  local snapshot_now
  QUIESCE_STATE=""
  QUIESCE_ISSUED_AFTER="${QUIESCE_ISSUED_BEFORE}"
  QUIESCE_FORCED_AFTER="${QUIESCE_FORCED_BEFORE}"
  QUIESCE_DRAINED=0
  QUIESCE_ATTEMPTED=0
  QUIESCE_OFFER_FAILED=0
  QUIESCE_OFFER_RC=""
  QUIESCE_REFUSALS_AFTER="${QUIESCE_REFUSALS_BEFORE}"
  QUIESCE_CEREMONY_REFUSALS_AFTER="${QUIESCE_CEREMONY_REFUSALS_BEFORE}"
  QUIESCE_AUTHORED_ENDINGS=""
  QUIESCE_AUTHORED_READ=0
  QUIESCE_OFFERED=""
  deadline=$((SECONDS + QUIESCE_GRACE))
  while ((SECONDS < deadline)); do
    # The three readings this control decides on, taken together or not at all.
    # Whether the node was quiescing, whether it had let go of everything, and
    # what it recorded about the permits it let go of are one claim about one
    # instant; read one request apart they can describe a node before and after
    # the last permit it will ever close. Committed together, a snapshot either
    # names the drain and the endings that produced it or is discarded whole
    # and the previous one — which described some earlier consistent instant —
    # stands.
    if snapshot_now="$(service_gate_snapshot "${node}" "${active_field}" \
      2>/dev/null)"; then
      state_now="$(snapshot_field "${snapshot_now}" state)"
      held_now="$(snapshot_field "${snapshot_now}" active)"
      # The node's own account of what became of the permits it is draining,
      # which goes away with the node. The account only grows as permits close,
      # so the last snapshot taken before the node stops answering is the one
      # that has every permit that ended in this window — which is why it is
      # overwritten each pass rather than accumulated.
      QUIESCE_AUTHORED_READ=1
      QUIESCE_AUTHORED_ENDINGS="$(snapshot_field "${snapshot_now}" outcomes)"
      if [[ "${state_now}" == "quiescing" ]]; then
        QUIESCE_STATE="quiescing"
      fi
      if [[ "${held_now}" =~ ^[0-9]+$ ]] && ((held_now == 0)); then
        QUIESCE_DRAINED=1
      fi
    fi
    if [[ "${QUIESCE_STATE}" == "quiescing" ]]; then
      # Offered once the node has actually entered quiescence, because the
      # property is what a quiescing node does with new work — and a node
      # that was never asked answers exactly like one that refused. Only a
      # clean driver run that named its transactions counts as having asked;
      # a failed or empty one leaves nothing for the node to have refused,
      # and QUIESCE_OFFER_FAILED carries that apart from never having tried.
      if ((QUIESCE_ATTEMPTED == 0 && QUIESCE_OFFER_FAILED == 0)) &&
        [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
        run_work_driver "${phase}-refusal" || true
        if driver_offered_work; then
          QUIESCE_ATTEMPTED=1
          QUIESCE_OFFERED="${WORK_DRIVER_ORIGINATED}"
        else
          QUIESCE_OFFER_FAILED=1
          QUIESCE_OFFER_RC="${WORK_DRIVER_RC}"
        fi
      fi
    fi
    issued_now="$(metric_value "${node}" "${issued_metric}" \
      2>/dev/null || printf '')"
    if [[ "${issued_now}" =~ ^[0-9]+$ ]]; then
      QUIESCE_ISSUED_AFTER="${issued_now}"
    fi
    forced_now="$(metric_value "${node}" \
      participation_quiesce_forced_aborts_total 2>/dev/null || printf '')"
    if [[ "${forced_now}" =~ ^[0-9]+$ ]]; then
      QUIESCE_FORCED_AFTER="${forced_now}"
    fi
    # Sampled inside the window rather than after it, for the same reason the
    # issued counter is: the node stops answering when the drain finishes, and
    # a refusal it recorded is only readable while it is still serving.
    refusals_now="$(metric_value "${node}" \
      participation_refusals_total 2>/dev/null || printf '')"
    if [[ "${refusals_now}" =~ ^[0-9]+$ ]]; then
      QUIESCE_REFUSALS_AFTER="${refusals_now}"
      QUIESCE_CEREMONY_REFUSALS_AFTER="$(ceremony_refusal_counters "${node}")"
    fi
    if ((SINGLE_RELEASE_QUARANTINE_PRESERVATION_SAMPLING == 1)); then
      sample_quarantine_preservation_signals "${node}"
    fi
    # The node going unreachable is the drain finishing, not a failure.
    node_reachable "${node}" || break
    sleep 2
  done
  wait "${stop_pid}" || true

  # What became of the work the node was holding, asked once the drain is
  # over and the outcomes exist to be read. The window above cannot ask: its
  # subject is work still running, and by the time an outcome exists the work
  # it was about is finished.
  QUIESCE_TERMINAL=""
  QUIESCE_TERMINAL_ASKED=0
  QUIESCE_TERMINAL_RC=0
  if [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
    QUIESCE_TERMINAL_ASKED=1
    run_work_driver "${phase}-terminal" || true
    QUIESCE_TERMINAL="${WORK_DRIVER_BOUND_RESULTS}"
    QUIESCE_TERMINAL_RC="${WORK_DRIVER_RC}"
  fi

  quiescence_verdict "${node}" "${step}" "${assertion}" "${mode}"
}

# What the homogeneous positive control observed.
#
# The step is named "security-v2 controls with no legacy sightings" and used to
# be decided by two permit counters. Neither half of that name was actually
# read: a permit says a node was allowed to begin, not that a ceremony
# finished, and the legacy permit counter is about work this fleet took on, not
# about whether it saw a legacy peer. So the terminal outcome comes from the
# driver — the only party that can watch a DKG or a signing settle on chain —
# and the no-sightings half is read from the announcer's own cross-format
# counter and the roster, which is where a sighting would appear.
HOMOGENEOUS_DRIVER_SUPPLIED=0
HOMOGENEOUS_DRIVER_RC=0
HOMOGENEOUS_TX=0
HOMOGENEOUS_RESULTS=""
# The same outcomes bound to the transactions that started them and to the
# threshold output each left behind, which is what this control decides on.
# A bare list of ceremonies that succeeded is not enough to decide it: read
# from that alone, a ceremony this driver originated is indistinguishable from
# one that was already running, and a ceremony that produced a threshold
# output from a report that merely says it did.
HOMOGENEOUS_BOUND=""
# The permits this fleet's gate issued for that same work, and what the node
# holding each one recorded when it closed.
#
# The bound outcomes above are still one party's account of its own ceremonies:
# the driver both starts the work and says how it went, and a positive control
# that reads only that passes on a report which simply says so. These name the
# permits the ceremonies ran under and join each to its holder's own ending.
HOMOGENEOUS_ORIGINATED=""
HOMOGENEOUS_AUTHORED_ENDINGS=""
HOMOGENEOUS_PERMITS_BEFORE=""
HOMOGENEOUS_PERMITS_AFTER=""
HOMOGENEOUS_LEGACY_BEFORE=""
HOMOGENEOUS_LEGACY_AFTER=""
HOMOGENEOUS_SIGHTINGS_BEFORE=""
HOMOGENEOUS_SIGHTINGS_AFTER=""
HOMOGENEOUS_NEW_OPERATORS=""
# Both halves of the release must be represented by a ceremony that settled.
# One driver call that only ever drove tBTC leaves the beacon's path into the
# gate unexercised, and a control that covers half the release cannot support
# a claim made about all of it.
HOMOGENEOUS_REQUIRED_FAMILIES="tbtc beacon"

homogeneous_control_verdict() {
  local step="homogeneous security-v2 controls with no legacy sightings"
  local assertion="post-C ceremonies run security-v2 with no legacy sightings"

  # The required set is both halves of the release, because that is what
  # "controls" in the step's name means. Read before the ladder so the two
  # readings it adds are stated once.
  local failed_results missing_families settlements stray unended
  local named_permits unauthored duplicated unresolved misended authored
  local malformed misevidenced disagreeing unclaimed result_population
  local unresolved_settlements
  failed_results="$(unsuccessful_results "${HOMOGENEOUS_RESULTS}")"
  missing_families="$(missing_bound_families \
    "${HOMOGENEOUS_BOUND}" "${HOMOGENEOUS_REQUIRED_FAMILIES}")"
  settlements="$(bound_settlements "${HOMOGENEOUS_BOUND}")"
  stray="$(unoriginated_terminals "${HOMOGENEOUS_BOUND}" \
    "${HOMOGENEOUS_ORIGINATED}")"
  unended="$(unended_work "${HOMOGENEOUS_ORIGINATED}" \
    "${HOMOGENEOUS_BOUND}" "")"
  # The population read off the nodes rather than off the driver: the permits
  # the gate issued for this work, and the ending each holder recorded. A
  # positive control's claim is that a fleet past C finishes work, and only
  # this half of the reading is not the report of the party that drove it.
  named_permits="$(held_permit_identities "${HOMOGENEOUS_ORIGINATED}")"
  unauthored="$(unauthored_permits "${named_permits}" \
    "${HOMOGENEOUS_AUTHORED_ENDINGS}")"
  duplicated="$(duplicated_authored_permits "${named_permits}" \
    "${HOMOGENEOUS_AUTHORED_ENDINGS}")"
  unresolved="$(unresolved_authored_permits "${named_permits}" \
    "${HOMOGENEOUS_AUTHORED_ENDINGS}")"
  # Completion only, as for the crossing. Exhausted and quarantined are
  # closings, and a control whose whole job is to show that work finishes
  # cannot be satisfied by a permit that stopped.
  misended="$(misended_authored_permits "${named_permits}" \
    "${HOMOGENEOUS_AUTHORED_ENDINGS}" completed)"
  # And what those completions produced, which is the half a category cannot
  # carry: a positive control that reads only the word is equally satisfied by
  # a fleet whose members each finished something else.
  malformed="$(malformed_authored_records "${named_permits}" \
    "${HOMOGENEOUS_AUTHORED_ENDINGS}")"
  misevidenced="$(misevidenced_authored_permits "${named_permits}" \
    "${HOMOGENEOUS_AUTHORED_ENDINGS}")"
  # And what those completions dispatched beyond themselves. A side effect the
  # holder could not resolve is chain state this fleet may have created and
  # cannot account for, which every rung below would otherwise read past.
  unresolved_settlements="$(unresolved_authored_settlements \
    "${named_permits}" "${HOMOGENEOUS_AUTHORED_ENDINGS}")"
  # Every holder of this work, not only the ones the driver named. A holder it
  # omitted still published a record, and a result it recorded that disagrees
  # with the rest — or that no settlement claims — is exactly what a population
  # drawn from the driver's own report cannot see.
  result_population="${named_permits} $(authored_work_permits \
    "$(identity_works "${named_permits}")" "${named_permits}" \
    "${HOMOGENEOUS_AUTHORED_ENDINGS}")"
  disagreeing="$(disagreeing_authored_results "${result_population}" \
    "${HOMOGENEOUS_AUTHORED_ENDINGS}")"
  unclaimed="$(unclaimed_authored_results "${result_population}" \
    "${HOMOGENEOUS_AUTHORED_ENDINGS}" "${HOMOGENEOUS_BOUND}")"
  authored="$(authored_endings "${named_permits}" \
    "${HOMOGENEOUS_AUTHORED_ENDINGS}")"

  if ((HOMOGENEOUS_DRIVER_SUPPLIED == 0)); then
    block_step "${step}" "no PR4109_WORK_DRIVER was supplied, so no tBTC or \
beacon ceremony was originated on the rehearsal chain and there is nothing to \
observe"
    record_assertion "${assertion}" false "${step}"
  elif ((HOMOGENEOUS_DRIVER_RC != 0)); then
    record_step "${step}" fail "the work driver exited \
[${HOMOGENEOUS_DRIVER_RC}] originating post-C ceremonies"
    record_assertion "${assertion}" false "${step}"
  elif [[ ! "${HOMOGENEOUS_PERMITS_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${HOMOGENEOUS_PERMITS_AFTER}" =~ ^[0-9]+$ ]] ||
    [[ ! "${HOMOGENEOUS_LEGACY_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${HOMOGENEOUS_LEGACY_AFTER}" =~ ^[0-9]+$ ]]; then
    block_step "${step}" "the fleet permit counters could not be read \
(security-v2 [${HOMOGENEOUS_PERMITS_BEFORE}] to \
[${HOMOGENEOUS_PERMITS_AFTER}], legacy [${HOMOGENEOUS_LEGACY_BEFORE}] to \
[${HOMOGENEOUS_LEGACY_AFTER}]), so nothing here observed which mode the \
ceremonies ran in"
    record_assertion "${assertion}" false "${step}"
  elif ((HOMOGENEOUS_TX == 0)); then
    # The permits below are credited to this driver, and the only account of
    # what it put on the chain is the account it gives. Without one, a counter
    # that moved for some unrelated reason reads exactly like a driver that
    # originated the ceremonies this control is about.
    block_step "${step}" "the work driver exited cleanly but reported no \
transaction, so nothing attributes the fleet's permit activity to the \
ceremonies this control claims to have originated"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${failed_results}" ]]; then
    # A report is taken whole. Keeping the successes and discarding the rest
    # would let a run where one half of the release failed outright be
    # recorded by the half that happened to pass, which is the reading a
    # positive control exists to make impossible.
    record_step "${step}" fail "the work driver reported ${failed_results} \
driving post-C ceremonies; a control over ceremonies that ran security-v2 \
cannot be read off the subset of them that survived"
    record_assertion "${assertion}" false "${step}"
  elif [[ -z "${settlements}" ]]; then
    block_step "${step}" "the work driver named no ceremony that completed \
successfully on a transaction it originated, so this control observed work \
being allowed to start and nothing about it finishing; a permit is not a \
result, and a positive control that never sees one is not positive about \
anything"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${missing_families}" ]]; then
    block_step "${step}" "the work driver settled ${settlements} but nothing \
from the ${missing_families} half of the release, so this control covers one \
call path into the gate and says nothing about the other; a post-C control \
has to succeed on ${HOMOGENEOUS_REQUIRED_FAMILIES}"
    record_assertion "${assertion}" false "${step}"
  elif [[ -z "${named_permits//[[:space:]]/}" ]]; then
    block_step "${step}" "the work driver settled ${settlements} but named no \
node holding a permit for any of it, so nothing here identifies a permit this \
fleet's gate issued; the settlements are the driver's account of its own work \
and the counters below only say the fleet took some security-v2 permit while \
it ran"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${stray}" ]]; then
    record_step "${step}" fail "the work driver reported an outcome for \
${stray}, which it did not originate here on that transaction; an outcome \
belonging to another ceremony or another transaction is not this control's to \
be positive about"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${unended}" ]]; then
    block_step "${step}" "the work driver settled ${settlements} but reported \
no outcome at all for ${unended}; a positive control that reads only the work \
its driver chose to report on is satisfied by the subset that went well"
    record_assertion "${assertion}" false "${step}"
  elif [[ "${HOMOGENEOUS_AUTHORED_ENDINGS}" == "unreadable on "* ]]; then
    block_step "${step}" "the R1 fleet could not be asked what became of the \
permits it took for these ceremonies (${HOMOGENEOUS_AUTHORED_ENDINGS}); \
without that reading the settlements above are the driver's account of its \
own work and no node has vouched for one of them"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${unauthored}" ]]; then
    block_step "${step}" "no node recorded an ending for ${unauthored}, \
though the driver named ${named_permits} as the permits issued for the \
ceremonies it settled; a permit whose own holder will not say how it ended is \
not work this fleet was observed finishing"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${duplicated}" ]]; then
    block_step "${step}" "more than one node-authored record claims to be the \
ending of ${duplicated}; one permit ends once, and a reader taking the first \
match would decide this control on whichever record happened to come first"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${unresolved}" ]]; then
    record_step "${step}" fail "${unresolved} — the holder closed the permit \
without recording what became of it, so the ceremony went somewhere the node \
cannot say and the driver's settlement for it stands on nothing"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${misended}" ]]; then
    record_step "${step}" fail "the work driver settled ${settlements}, but \
the nodes holding the permits recorded ${misended}; a closing is not a \
completion, and where the two accounts disagree it is the driver's that is \
about its own work"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${malformed}" ]]; then
    block_step "${step}" "the node-authored account of these post-C ceremonies stops \
short of what a permit's holder records — ${malformed} — so the reading \
names a disposition and nothing about what it left behind; a release \
publishing only the category cannot be reconciled against what the driver \
says settled"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${misevidenced}" ]]; then
    record_step "${step}" fail "${misevidenced}; the gate pins each ceremony \
to the evidence class its result actually lives in, and a completion carrying \
another class is a categorical claim about a ceremony whose real output \
nothing here has seen"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${unresolved_settlements}" ]]; then
    block_step "${step}" "${unresolved_settlements}; the fleet may have left \
chain state behind that no node can name, and every reading below this is \
about work whose ending is accounted for — an unresolved side effect is for the \
offline audit to settle rather than for a step to read past"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${disagreeing}" ]]; then
    record_step "${step}" fail "the holders of ${disagreeing} each recorded a \
completion naming a different result; a threshold ceremony has one output, so \
this is separate work finishing separately on the same chain item rather than \
the fleet completing it together"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${unclaimed}" ]]; then
    record_step "${step}" fail "${unclaimed}; the driver's account of what \
these ceremonies settled as and the holders' own records of what they produced \
have to name the same threshold output, and where they do not, one of the two \
is describing work the other never did"
    record_assertion "${assertion}" false "${step}"
  elif ((HOMOGENEOUS_PERMITS_AFTER <= HOMOGENEOUS_PERMITS_BEFORE)); then
    record_step "${step}" fail "the work driver settled ${settlements}, but \
the fleet issued no new security-v2 permit (still \
${HOMOGENEOUS_PERMITS_AFTER}); the ceremonies it named were not run under \
this fleet's gate"
    record_assertion "${assertion}" false "${step}"
  elif ((HOMOGENEOUS_LEGACY_AFTER > HOMOGENEOUS_LEGACY_BEFORE)); then
    record_step "${step}" fail "the fleet issued \
$((HOMOGENEOUS_PERMITS_AFTER - HOMOGENEOUS_PERMITS_BEFORE)) new security-v2 \
permits and also $((HOMOGENEOUS_LEGACY_AFTER - HOMOGENEOUS_LEGACY_BEFORE)) \
new legacy permit(s) (participation_mode_legacy_total \
[${HOMOGENEOUS_LEGACY_BEFORE}] to [${HOMOGENEOUS_LEGACY_AFTER}]) driving \
post-C work"
    record_assertion "${assertion}" false "${step}"
  elif [[ ! "${HOMOGENEOUS_SIGHTINGS_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${HOMOGENEOUS_SIGHTINGS_AFTER}" =~ ^[0-9]+$ ]]; then
    block_step "${step}" "the fleet's cross-format sighting counter could not \
be read (${HOMOGENEOUS_SIGHTINGS_BEFORE:-unreadable} to \
${HOMOGENEOUS_SIGHTINGS_AFTER:-unreadable}), so the no-legacy-sightings half \
of this control was never observed; an unchanged legacy permit counter is \
about work this fleet took on, not about what it saw"
    record_assertion "${assertion}" false "${step}"
  elif ((HOMOGENEOUS_SIGHTINGS_AFTER > HOMOGENEOUS_SIGHTINGS_BEFORE)); then
    record_step "${step}" fail "the fleet recognized \
$((HOMOGENEOUS_SIGHTINGS_AFTER - HOMOGENEOUS_SIGHTINGS_BEFORE)) cross-format \
peer(s) while the homogeneous ceremonies ran (announcer cross-format total \
[${HOMOGENEOUS_SIGHTINGS_BEFORE}] to [${HOMOGENEOUS_SIGHTINGS_AFTER}]); the \
straggler was quarantined before this step, so the fleet was not homogeneous"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${HOMOGENEOUS_NEW_OPERATORS}" ]]; then
    record_step "${step}" fail "the fleet's legacy roster newly named \
operator(s) ${HOMOGENEOUS_NEW_OPERATORS} while the homogeneous ceremonies \
ran; a control with no legacy sightings cannot produce a legacy roster entry"
    record_assertion "${assertion}" false "${step}"
  else
    STEP_PERMIT_MODES='"security_v2"'
    record_step "${step}" pass "the fleet issued \
$((HOMOGENEOUS_PERMITS_AFTER - HOMOGENEOUS_PERMITS_BEFORE)) new security-v2 \
permits driving the post-C ceremonies the driver originated, the driver \
settled ${settlements} with nothing failing beside \
them and both ${HOMOGENEOUS_REQUIRED_FAMILIES} represented, the nodes holding \
the permits issued for that work recorded ${authored}, and the fleet took no legacy \
permit (participation_mode_legacy_total unchanged at \
[${HOMOGENEOUS_LEGACY_AFTER}]), recognized no cross-format peer (unchanged at \
[${HOMOGENEOUS_SIGHTINGS_AFTER}]), and added no operator to its legacy roster"
    record_assertion "${assertion}" true "${step}"
  fi
}

# What the rollback gate's drain observed, and the verdict they imply.
#
# The step is named "with work represented" and used to record a pass on the
# drain's exit status alone. A `compose stop` that returns zero over a fleet
# holding nothing is a clean shutdown of idle processes: it evidences that
# stopping works, not that a node holding protocol work drains rather than
# dropping it, which is the property a rollback decision rests on. So the
# permits have to be observed in flight at the moment the stop is issued, and
# the driver that put them there has to have said what it put on the chain.
ROLLBACK_DRIVER_SUPPLIED=0
ROLLBACK_DRIVER_RC=0
ROLLBACK_DRIVER_TX=0
ROLLBACK_ORIGINATED=""
ROLLBACK_INFLIGHT=""
ROLLBACK_DRAIN_RC=""
ROLLBACK_GRACE=""
# The kinds of work a rollback has to be authorized over, both in flight at
# once. A rollback decision is taken over a fleet that was holding whatever it
# was holding, and the two classes fail differently under an interrupted
# shutdown — a threshold ceremony loses a share and can be re-run, a wallet
# action can leave a Bitcoin transaction this fleet already signed for. A drain
# that only ever held one class evidences the rollback path for that class and
# says nothing about the other, and a permit total cannot tell them apart.
ROLLBACK_REQUIRED_CLASSES="threshold_ceremony bitcoin_action"

# The last readable quarantine-preservation account from every R1 service.
#
# Both exact-image gates can manufacture a quarantine: rollback does so while
# draining the whole fleet, and single_release does so when it severs a node's
# chain clock or forces either quiescence control. The nodes stop answering at
# the end of those controls, so each gate retains the newest numeric reading
# while the endpoint is still live and records the shared verdict afterwards.
# Every service line also retains the field mask from that service's final
# useful attempt. Keeping the mask beside the values is what prevents a later
# service sample — or an information-free post-exit scrape — from supplying
# provenance for a different node's carried incomplete-output zero.
QUARANTINE_PRESERVATION_READINGS=""
# Whether the most recent sampler call read all four signals in that call.
# The accumulator deliberately retains older numeric values across a transient
# probe failure, so a destructive pre-stop guard must consult this bit rather
# than mistaking retained history for a fresh reading.
QUARANTINE_PRESERVATION_SAMPLE_READABLE=0
# One bit per QUARANTINE_PRESERVATION_METRICS entry, set only when the most
# recent sampler call read that field. The watched-stop account retains the
# last attempt that read at least one field (or ran while the endpoint was
# still reachable), so a partially stale incomplete-output value cannot borrow
# freshness from another field or from an earlier all-readable sample.
QUARANTINE_PRESERVATION_SAMPLE_READ_MASK=0
# run_quiescence_control is shared, but only the single-release stage uses it
# inside the gate's process-local preservation window. Rollback samples the
# same signals directly in its fleet-drain loop.
SINGLE_RELEASE_QUARANTINE_PRESERVATION_SAMPLING=0

# reset_existing=1 is used only after a process restart. It preserves every
# other service's account but makes this service prove all four new-process
# readings instead of inheriting the stopped process's values.
sample_quarantine_preservation_signals() {
  local service="$1" reset_existing="${2:-0}"
  local listed_service listed_tbtc_failures listed_beacon_failures
  local listed_tbtc_incomplete listed_beacon_incomplete listed_sample_read_mask
  local retained="" metrics_body="" reading metric index=0
  local values=("unreadable" "unreadable" "unreadable" "unreadable")
  local sample_readable=1 sample_read_mask=0
  local retained_sample_read_mask=0

  while read -r listed_service listed_tbtc_failures listed_beacon_failures \
    listed_tbtc_incomplete listed_beacon_incomplete \
    listed_sample_read_mask; do
    [[ -n "${listed_service}" ]] || continue
    [[ -n "${listed_sample_read_mask}" ]] ||
      listed_sample_read_mask="unreadable"
    if [[ "${listed_service}" == "${service}" ]]; then
      if ((reset_existing == 0)); then
        values[0]="${listed_tbtc_failures}"
        values[1]="${listed_beacon_failures}"
        values[2]="${listed_tbtc_incomplete}"
        values[3]="${listed_beacon_incomplete}"
        retained_sample_read_mask="${listed_sample_read_mask}"
      fi
      continue
    fi
    retained="${retained}${retained:+$'\n'}${listed_service} \
${listed_tbtc_failures} ${listed_beacon_failures} \
${listed_tbtc_incomplete} ${listed_beacon_incomplete} \
${listed_sample_read_mask}"
  done <<<"${QUARANTINE_PRESERVATION_READINGS}"

  # One sampler attempt is exactly one /metrics response. Four independent
  # HTTP requests can straddle process shutdown and manufacture a partial
  # account whose fields never coexisted. A readable exposition may still
  # genuinely omit a metric; that field keeps its retained value and its mask
  # bit stays clear, making the node-authored absence explicit to acceptance.
  if metrics_body="$(probe_metrics "${service}" 2>/dev/null)"; then
    for metric in "${QUARANTINE_PRESERVATION_METRICS[@]}"; do
      reading="$(
        printf '%s\n' "${metrics_body}" |
          metric_value_from_exposition "${metric}" 2>/dev/null ||
          printf ''
      )"
      if [[ "${reading}" =~ ^[0-9]+$ ]]; then
        values[index]="${reading}"
        sample_read_mask=$((sample_read_mask | (1 << index)))
      else
        sample_readable=0
      fi
      index=$((index + 1))
    done
  else
    sample_readable=0
  fi

  # Replace a service's provenance only with an attempt that read at least one
  # field. Once the endpoint has disappeared, an information-free scrape has
  # no node-authored fact with which to erase the final useful attempt.
  if ((sample_read_mask > 0)); then
    retained_sample_read_mask="${sample_read_mask}"
  fi

  QUARANTINE_PRESERVATION_READINGS="\
${retained}${retained:+$'\n'}${service} ${values[0]} ${values[1]} \
${values[2]} ${values[3]} ${retained_sample_read_mask}"
  QUARANTINE_PRESERVATION_SAMPLE_READABLE="${sample_readable}"
  QUARANTINE_PRESERVATION_SAMPLE_READ_MASK="${sample_read_mask}"
}

initialize_quarantine_preservation_readings() {
  QUARANTINE_PRESERVATION_READINGS=""
  local service
  for service in "$@"; do
    sample_quarantine_preservation_signals "${service}"
  done
}

# Return one service's retained account exactly as the accumulator stores it.
# An absent service is different from an unreadable service: the latter has a
# line containing `unreadable`, while the former proves the expected fleet was
# never sampled at all.
quarantine_preservation_reading_for() {
  local wanted="$1"
  local service tbtc_failures beacon_failures tbtc_incomplete beacon_incomplete
  local sample_read_mask

  while read -r service tbtc_failures beacon_failures tbtc_incomplete \
    beacon_incomplete sample_read_mask; do
    [[ -n "${service}" ]] || continue
    if [[ "${service}" == "${wanted}" ]]; then
      printf '%s %s %s %s %s %s' \
        "${service}" "${tbtc_failures}" "${beacon_failures}" \
        "${tbtc_incomplete}" "${beacon_incomplete}" "${sample_read_mask}"
      return 0
    fi
  done <<<"${QUARANTINE_PRESERVATION_READINGS}"

  return 1
}

# Attach one retained account to the current evidence step. A namespace keeps
# a reading from a process that is about to disappear distinct from the same
# metric name published by the replacement process. Only numeric signal fields
# are emitted; the archive reader treats an absent key as an unread instrument
# and therefore cannot mistake `unreadable` for a node-authored zero. When the
# caller supplies sample_readable, archive that bit beside the retained values
# so a failed current scrape cannot pass off older numeric history as a fresh
# pre-stop reading. When it supplies sample_read_mask, archive one provenance
# bit beside every field so the watched-stop reader can distinguish values
# actually re-read during the stop from values carried over by the accumulator.
append_quarantine_preservation_gauges() {
  local service="$1" namespace="${2:-}" sample_readable="${3:-}"
  local sample_read_mask="${4:-}" account
  local listed_service tbtc_failures beacon_failures
  local tbtc_incomplete beacon_incomplete retained_sample_read_mask
  local metric value field_readable index=0
  local key_prefix="${service}."
  local complete=1 sample_read_mask_valid=0
  local max_read_mask=$(((1 << ${#QUARANTINE_PRESERVATION_METRICS[@]}) - 1))

  [[ -n "${namespace}" ]] && key_prefix="${service}.${namespace}."
  if [[ -n "${sample_read_mask}" ]]; then
    if [[ "${sample_read_mask}" =~ ^[0-9]+$ ]] &&
      ((sample_read_mask <= max_read_mask)); then
      sample_read_mask_valid=1
    else
      complete=0
    fi
  fi
  account="$(quarantine_preservation_reading_for "${service}")" || return 1
  read -r listed_service tbtc_failures beacon_failures tbtc_incomplete \
    beacon_incomplete retained_sample_read_mask <<<"${account}"
  local values=(
    "${tbtc_failures}"
    "${beacon_failures}"
    "${tbtc_incomplete}"
    "${beacon_incomplete}"
  )

  for metric in "${QUARANTINE_PRESERVATION_METRICS[@]}"; do
    value="${values[${index}]}"
    if [[ "${value}" =~ ^[0-9]+$ ]]; then
      STEP_GAUGES="${STEP_GAUGES}${STEP_GAUGES:+,}\
\"${key_prefix}${metric}\":${value}"
    else
      complete=0
    fi
    if ((sample_read_mask_valid == 1)); then
      field_readable=$(((sample_read_mask >> index) & 1))
      STEP_GAUGES="${STEP_GAUGES}${STEP_GAUGES:+,}\
\"${key_prefix}${metric}.${RESTART_WATCHED_FIELD_READABLE_SUFFIX}\":\
${field_readable}"
    fi
    index=$((index + 1))
  done

  if [[ -n "${sample_readable}" ]]; then
    if [[ "${sample_readable}" =~ ^[01]$ ]]; then
      STEP_GAUGES="${STEP_GAUGES}${STEP_GAUGES:+,}\
\"${key_prefix}${RESTART_PRE_STOP_SAMPLE_READABLE_SUFFIX}\":${sample_readable}"
    else
      complete=0
    fi
  fi

  ((complete == 1))
}

# The two live incomplete-output gauges are the safety statement in a watched
# stop account. Historical write-grace counters may be carried forward as
# advisories, but neither incomplete-output zero may be carried into the final
# useful watched sample from an earlier attempt.
quarantine_preservation_incomplete_fields_read() {
  local sample_read_mask="$1" metric index=0
  local max_read_mask=$(((1 << ${#QUARANTINE_PRESERVATION_METRICS[@]}) - 1))

  [[ "${sample_read_mask}" =~ ^[0-9]+$ ]] ||
    return 1
  ((sample_read_mask <= max_read_mask)) ||
    return 1

  for metric in "${QUARANTINE_PRESERVATION_METRICS[@]}"; do
    if [[ "${metric}" == *_quarantine_incomplete_outputs ]]; then
      if ((((sample_read_mask >> index) & 1) == 0)); then
        return 1
      fi
    fi
    index=$((index + 1))
  done

  return 0
}

# A watched stop can itself refute the restart control: the process may exit
# uncleanly, or preservation may become incomplete after the pre-stop guard
# passed. At that point the old process is already gone. Start the same
# container again only to keep the later, independent clock and quiescence
# controls interpretable; this never changes the restart step's failed/blocked
# outcome or authorizes its evidence.
RESTART_RECOVERY_NOTE=""
RESTART_RECOVERY_SAFE=0

recover_stopped_restart_subject() {
  local service="$1"
  local start_rc=0 deadline

  RESTART_RECOVERY_NOTE=""
  RESTART_RECOVERY_SAFE=0

  if compose start "${service}"; then
    start_rc=0
  else
    start_rc=$?
  fi

  if ((start_rc != 0)); then
    RESTART_RECOVERY_NOTE=" The same stopped container could not be \
recovery-started (Compose exited [${start_rc}]), so the remaining \
single-release controls were not evaluated against an unavailable node."
    return 1
  fi

  deadline=$((SECONDS + NODE_REACHABILITY_TIMEOUT_SECONDS))
  until node_reachable "${service}"; do
    if ((SECONDS >= deadline)); then
      break
    fi
    sleep 5
  done

  if ! node_reachable "${service}"; then
    RESTART_RECOVERY_NOTE=" The same stopped container was recovery-started, \
but its client-info endpoint did not become reachable within \
${NODE_REACHABILITY_TIMEOUT_SECONDS} seconds, so the remaining single-release \
controls were not evaluated against an unavailable node."
    return 1
  fi

  # This is a new process-local account. The old account already lives under
  # the restart step's pre_restart namespace and must not stand in for it. This
  # reset is safe only because every caller is already on an irrevocable
  # fail/blocked restart path; a future caller MUST establish that refusal
  # before invoking this helper, so replacement-process zeros can never turn
  # the restart step into a pass.
  sample_quarantine_preservation_signals "${service}" 1
  RESTART_RECOVERY_SAFE=1
  RESTART_RECOVERY_NOTE=" The same container was recovery-started only so the \
remaining independent controls retain a live subject; the restart step remains \
refused and its old-process account remains archived."
  return 0
}

quarantine_preservation_verdict() {
  local assertion="$1"
  local step="quarantine preservation is complete through quiescence"
  local service tbtc_failures beacon_failures tbtc_incomplete beacon_incomplete
  local sample_read_mask
  local nodes=0
  local unread="" still_incomplete="" recovered=""
  local unread_provenance="" carried_incomplete=""
  local unexpected_services="" duplicate_services="" missing_services=""
  local gauge_errors=""
  local expected seen
  local seen_services=()

  while read -r service tbtc_failures beacon_failures tbtc_incomplete \
    beacon_incomplete sample_read_mask; do
    [[ -n "${service}" ]] || continue
    nodes=$((nodes + 1))

    local already_seen=0 expected_service=0
    for seen in "${seen_services[@]+"${seen_services[@]}"}"; do
      [[ "${seen}" == "${service}" ]] && already_seen=1
    done
    if ((already_seen == 1)); then
      duplicate_services="${duplicate_services}\
${duplicate_services:+, }${service}"
    else
      seen_services+=("${service}")
    fi
    for expected in "${REHEARSAL_R1_SERVICES[@]+"${REHEARSAL_R1_SERVICES[@]}"}"; do
      [[ "${expected}" == "${service}" ]] && expected_service=1
    done
    if ((expected_service == 0)); then
      unexpected_services="${unexpected_services}\
${unexpected_services:+, }${service}"
    fi

    if [[ ! "${tbtc_failures}" =~ ^[0-9]+$ ]] ||
      [[ ! "${beacon_failures}" =~ ^[0-9]+$ ]] ||
      [[ ! "${tbtc_incomplete}" =~ ^[0-9]+$ ]] ||
      [[ ! "${beacon_incomplete}" =~ ^[0-9]+$ ]]; then
      unread="${unread}${unread:+, }${service} (tBTC \
failures ${tbtc_failures}, beacon failures ${beacon_failures}, tBTC incomplete \
${tbtc_incomplete}, beacon incomplete ${beacon_incomplete})"
      continue
    fi

    if [[ ! "${sample_read_mask}" =~ ^[0-9]+$ ]]; then
      unread_provenance="${unread_provenance}\
${unread_provenance:+, }${service} (final useful sample mask \
${sample_read_mask:-absent})"
    elif ! quarantine_preservation_incomplete_fields_read \
      "${sample_read_mask}"; then
      carried_incomplete="${carried_incomplete}\
${carried_incomplete:+, }${service} (final useful sample mask \
${sample_read_mask})"
    fi

    if ((tbtc_incomplete > 0)); then
      still_incomplete="${still_incomplete}${still_incomplete:+, }${service} \
(tBTC incomplete ${tbtc_incomplete}, grace-exhaustion history \
${tbtc_failures})"
    elif ((tbtc_failures > 0)); then
      recovered="${recovered}${recovered:+, }${service} (tBTC \
grace-exhaustion episodes ${tbtc_failures}, live incomplete 0)"
    fi

    if ((beacon_incomplete > 0)); then
      still_incomplete="${still_incomplete}${still_incomplete:+, }${service} \
(beacon incomplete ${beacon_incomplete}, grace-exhaustion history \
${beacon_failures})"
    elif ((beacon_failures > 0)); then
      recovered="${recovered}${recovered:+, }${service} (beacon \
grace-exhaustion episodes ${beacon_failures}, live incomplete 0)"
    fi
  done <<<"${QUARANTINE_PRESERVATION_READINGS}"

  for expected in "${REHEARSAL_R1_SERVICES[@]+"${REHEARSAL_R1_SERVICES[@]}"}"; do
    local found=0
    for seen in "${seen_services[@]+"${seen_services[@]}"}"; do
      [[ "${seen}" == "${expected}" ]] && found=1
    done
    if ((found == 0)); then
      missing_services="${missing_services}${missing_services:+, }${expected}"
    fi
  done

  # Emit only after the accumulator has proved it covers the authoritative
  # roster exactly once. Walking the roster, rather than the untrusted reading
  # lines, prevents a duplicated line from producing duplicate JSON keys.
  # Guard the designed-to-fail emitter so a future mismatch blocks this stage
  # instead of aborting the entire set -e rehearsal.
  if [[ -z "${missing_services}${unexpected_services}${duplicate_services}${unread}" ]] &&
    ((${#REHEARSAL_R1_SERVICES[@]} > 0)); then
    for expected in "${REHEARSAL_R1_SERVICES[@]}"; do
      local expected_account expected_sample_read_mask
      expected_account="$(
        quarantine_preservation_reading_for "${expected}"
      )" || {
        gauge_errors="${gauge_errors}${gauge_errors:+, }${expected}"
        continue
      }
      read -r _ _ _ _ _ expected_sample_read_mask <<<"${expected_account}"
      if ! append_quarantine_preservation_gauges \
        "${expected}" "" "" "${expected_sample_read_mask}"; then
        gauge_errors="${gauge_errors}${gauge_errors:+, }${expected}"
      fi
    done
  fi

  if ((${#REHEARSAL_R1_SERVICES[@]} == 0)); then
    block_step "${step}" "the expected R1 service roster is empty; no fleet \
reading can authorize quarantine preservation"
    record_assertion "${assertion}" false "${step}"
  elif ((nodes == 0)); then
    block_step "${step}" "no R1 node's quarantine-preservation counters were \
captured before the fleet stopped; an absent reading cannot say that no \
generated share was lost"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${missing_services}${unexpected_services}${duplicate_services}" ]]; then
    block_step "${step}" "the quarantine-preservation readings do not cover \
the authoritative R1 service roster exactly (missing \
[${missing_services:-none}], unexpected [${unexpected_services:-none}], \
duplicate [${duplicate_services:-none}]); one healthy \
node cannot stand in for a fleet member that was never sampled"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${unread}${unread_provenance}${gauge_errors}" ]]; then
    block_step "${step}" "the quarantine-preservation counters or live \
incomplete-output gauges, or their final useful sample provenance, were \
unreadable on ${unread:-${unread_provenance:-${gauge_errors} (evidence gauge \
emission failed)}}; zero must be a node-authored reading, not the value \
assigned to a node that stopped answering"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${carried_incomplete}" ]]; then
    block_step "${step}" "the final useful quarantine-preservation sample did \
not re-read both live incomplete-output fields on ${carried_incomplete}; a \
zero carried from an earlier attempt cannot prove preservation completed \
through quiescence"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${still_incomplete}" ]]; then
    record_step "${step}" fail "an R1 node is still holding generated signer \
output whose protected quarantine lacks key material or its audit record on \
${still_incomplete}; the gate remains refused until every output becomes \
fully durable and its live incomplete-output gauge clears"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${recovered}" ]]; then
    record_step "${step}" pass "preservation exhausted its write-grace rounds \
and later completed on ${recovered}; the cumulative counters retain those \
recovered episodes, every live incomplete-output gauge is zero, and the \
offline state audit remains required before any prior release starts"
    record_assertion "${assertion}" true "${step}"
  else
    record_step "${step}" pass "every R1 node reported zero tBTC and beacon \
write-grace exhaustion episodes and zero live incomplete outputs in its last \
readable cutover/quiescence sample"
    record_assertion "${assertion}" true "${step}"
  fi
}

rollback_drain_verdict() {
  local step="quiesce every R1 node with work represented"
  local assertion="every R1 node drains to a stop within the reviewed \
termination grace"

  if ((ROLLBACK_DRIVER_SUPPLIED == 0)); then
    block_step "${step}" "no PR4109_WORK_DRIVER was supplied, so the fleet \
held no originated work when it was told to stop; a drain of idle processes \
says stopping works and nothing about what happens to work in flight"
    record_assertion "${assertion}" false "${step}"
  elif ((ROLLBACK_DRIVER_RC != 0)); then
    block_step "${step}" "the work driver exited [${ROLLBACK_DRIVER_RC}] \
originating the work this drain was to be performed over, so the fleet was \
stopped holding whatever it happened to hold"
    record_assertion "${assertion}" false "${step}"
  elif ((ROLLBACK_DRIVER_TX == 0)); then
    block_step "${step}" "the work driver exited cleanly but named no \
transaction, so nothing attributes the fleet's in-flight work to this gate"
    record_assertion "${assertion}" false "${step}"
  elif [[ -z "${ROLLBACK_ORIGINATED}" ]]; then
    block_step "${step}" "the work driver named transactions but no ceremony \
they originated, so nothing here says what kind of work the fleet was holding \
when it was told to stop; a permit total counts ceremonies without \
distinguishing a threshold round from a Bitcoin wallet action, and a rollback \
is authorized over what was actually in flight"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "$(missing_work_classes "${ROLLBACK_ORIGINATED}" \
    "${ROLLBACK_REQUIRED_CLASSES}")" ]]; then
    block_step "${step}" "the work driver originated \
${ROLLBACK_ORIGINATED// /, } but nothing of class \
$(missing_work_classes "${ROLLBACK_ORIGINATED}" \
      "${ROLLBACK_REQUIRED_CLASSES}"), so this drain was performed over one \
kind of in-flight work; the two fail differently when a shutdown interrupts \
them, and a rollback authorized over ${ROLLBACK_REQUIRED_CLASSES// / and } \
needs both represented at once"
    record_assertion "${assertion}" false "${step}"
  elif [[ ! "${ROLLBACK_INFLIGHT}" =~ ^[0-9]+$ ]]; then
    block_step "${step}" "the fleet's in-flight security-v2 permit count could \
not be read (${ROLLBACK_INFLIGHT:-unreadable}) when the stop was issued, so \
nothing here observed whether the drain had any work to represent"
    record_assertion "${assertion}" false "${step}"
  elif ((ROLLBACK_INFLIGHT == 0)); then
    block_step "${step}" "the driver originated work and named its \
transactions, but no R1 node held a security-v2 permit when the stop was \
issued; the drain below is a shutdown of idle processes and evidences nothing \
about work in flight"
    record_assertion "${assertion}" false "${step}"
  elif [[ "${ROLLBACK_DRAIN_RC}" != "0" ]]; then
    record_step "${step}" fail "stopping the R1 nodes under the reviewed \
manifest's ${ROLLBACK_GRACE}s termination grace exited \
[${ROLLBACK_DRAIN_RC}] with ${ROLLBACK_INFLIGHT} permit(s) in flight; a drain \
that did not complete is not a quiescence and the state it left is not what \
the audit below reads"
    record_assertion "${assertion}" false "${step}"
  else
    record_step "${step}" pass "every R1 node was stopped under the reviewed \
manifest's ${ROLLBACK_GRACE}s termination grace while the fleet held \
${ROLLBACK_INFLIGHT} security-v2 permit(s) the driver had originated and named \
on chain, covering ${ROLLBACK_ORIGINATED// /, } — \
${ROLLBACK_REQUIRED_CLASSES// / and } both in flight — so a draining node \
holding work was never SIGKILLed before its in-process backstop"
    record_assertion "${assertion}" true "${step}"
  fi
}

# Per-node rollback accounting, one line per R1 service, as
# "<service> <held> <forced> <final_active>". An unreadable value is carried as
# "unreadable" rather than as zero: a read that failed must not subtract like an
# absence, which is exactly how a permit nobody could account for would
# disappear from the reconciliation.
ROLLBACK_NODE_ACCOUNTS=""
# The audited quarantine records, "<service> <id>[,<id>...]", read from each
# node's audit manifest after the audit has run and restricted to records this
# drain produced. "none" when the manifest holds no such record, "unreadable"
# when it could not be read.
ROLLBACK_NODE_QUARANTINES=""
# What each node recorded about the permits it closed while draining,
# "<service> <ending token>...", sampled inside the drain window because the
# account goes away with the node. "unread" when that node could never be
# asked, "none" when it answered having closed nothing.
#
# This is the half the driver cannot supply. A terminal outcome the driver
# reports is its account of a ceremony it originated, and read alone it makes
# the same claim whether the permit behind it completed or the process went
# down holding it — which is the very distinction a rollback reconciliation
# exists to draw.
ROLLBACK_NODE_ENDINGS=""
# What became of the work this gate originated, asked of the driver once the
# drain is over. A permit that was not force-canceled is only "completed" if
# the ceremony behind it actually reached an outcome; the fleet's own gauge
# falling to zero is equally what a process exiting while holding it looks
# like, and the driver is the only party that can watch a ceremony settle on
# chain.
ROLLBACK_TERMINAL=""
# 1 when the driver was asked for those outcomes at all, and the status it
# exited with when it was. A terminal report from a driver that failed is a
# partial account of an interrupted look at the chain, and reconciling permits
# against it would take the ceremonies it happened to reach for all there were.
ROLLBACK_TERMINAL_ASKED=0
ROLLBACK_TERMINAL_RC=0
# The identified work the drain was performed over, and the instant the stop
# was issued. The first is what each permit is followed to an outcome through;
# the second is what keeps the audit's quarantine records about this drain.
ROLLBACK_ORIGINATED_WORK=""
ROLLBACK_DRAIN_SINCE=""

# The verdict over that accounting.
#
# The drain step above establishes that the fleet held work and that stopping
# it returned cleanly. Neither says where the permits went. An aggregate
# in-flight count read at the moment of the stop is a statement about the
# beginning of the drain, and a fleet total of zero afterwards is equally
# produced by permits that finished and by processes that exited holding them —
# the state a rollback then restores onto is the difference between those two.
#
# So every permit a node held when the stop was issued has to land somewhere:
# completed, which the node evidences by being seen without it and the driver
# by an outcome for the work behind it, or force-canceled at the quiesce
# deadline, which the gate counts and the offline audit must have written a
# quarantine record for. A permit that reconciles to neither went down with its
# process, and nothing in the state left behind says so.
#
# The unit is the permit, not the ceremony. A count of ceremony names cannot
# close over a population of permits: a threshold ceremony takes one permit on
# every node that joins it, and two runs of one ceremony are the same name.
# Reconciled by name, one outcome covers as many permits as happen to be
# outstanding, which is the reading this exists to refuse rather than a weaker
# version of following each one.
rollback_reconciliation_verdict() {
  local step="$1" assertion="$2"
  local line service held forced final quarantined
  local unread="" unreconciled="" unaudited="" impossible="" miscounted=""
  local strayed="" orphaned="" unvouched="" misvouched=""
  local completed_total=0 quarantined_total=0 nodes=0
  local node_records node_permits expected quarantine_ids quarantine_count
  local record permit audited
  local endings node_held unauthored duplicated misended unresolved

  if [[ -z "${ROLLBACK_NODE_ACCOUNTS//[[:space:]]/}" ]]; then
    block_step "${step}" "no R1 node's permit accounting was captured across \
the drain, so nothing here followed a single permit from the stop to an \
outcome"
    record_assertion "${assertion}" false "${step}"
    return
  fi

  if [[ -z "${ROLLBACK_ORIGINATED_WORK//[[:space:]]/}" ]]; then
    block_step "${step}" "the driver named no identified work for the drain, \
so the permits the fleet held cannot be followed to anything; a ceremony name \
says what kind of work was in flight and a permit count says how much, and \
neither says which permit belongs to which piece of work"
    record_assertion "${assertion}" false "${step}"
    return
  fi

  if ((ROLLBACK_TERMINAL_ASKED == 0)); then
    # The reading this rung exists for. A permit that was not force-canceled
    # used to be counted as completed because the node was later seen without
    # it — and a node that exited holding one is also a node later seen without
    # it. Being gone is not an outcome.
    block_step "${step}" "the driver was never asked what became of the work \
behind the permits the fleet held; a gauge that fell to zero is equally a \
ceremony that finished and a process that exited holding it, and only one of \
those is a permit that completed"
    record_assertion "${assertion}" false "${step}"
    return
  fi

  if ((ROLLBACK_TERMINAL_RC != 0)); then
    block_step "${step}" "the work driver exited [${ROLLBACK_TERMINAL_RC}] \
reporting what became of the drained work, so its account of the chain stops \
wherever it failed; permits reconciled against a partial report take the \
outcomes it happened to reach for all there were"
    record_assertion "${assertion}" false "${step}"
    return
  fi

  strayed="$(unoriginated_terminals "${ROLLBACK_TERMINAL}" \
    "${ROLLBACK_ORIGINATED_WORK}")"
  if [[ -n "${strayed}" ]]; then
    block_step "${step}" "the driver reported terminal outcomes for \
${strayed}, which this drain never originated with those transactions; an \
outcome belonging to somebody else's ceremony or substituting a different \
transaction reconciles none of this fleet's permits"
    record_assertion "${assertion}" false "${step}"
    return
  fi

  while read -r service held forced final; do
    [[ -n "${service}" ]] || continue
    nodes=$((nodes + 1))
    if [[ ! "${held}" =~ ^[0-9]+$ ]] || [[ ! "${forced}" =~ ^[0-9]+$ ]] ||
      [[ ! "${final}" =~ ^[0-9]+$ ]]; then
      unread="${unread}${unread:+, }${service} (held \
${held}, forced ${forced}, final ${final})"
      continue
    fi
    if ((forced > held)); then
      # More permits force-canceled than were ever held: the two counters
      # describe different populations and the reconciliation cannot close
      # over them at all.
      impossible="${impossible}${impossible:+, }${service} force-canceled \
${forced} of ${held} held"
      continue
    fi
    if ((final > 0)); then
      unreconciled="${unreconciled}${unreconciled:+, }${service} stopped \
holding ${final} of ${held} permit(s)"
      continue
    fi

    # What this node was actually holding, named rather than counted. A permit
    # total that does not match the work the driver put on this node is an
    # accounting over two different populations: either the node joined work
    # nobody attributed to it, or work attributed to it never reached it, and
    # in both readings the outcomes below belong to a different set of permits.
    node_records="$(work_records_held_by \
      "${ROLLBACK_ORIGINATED_WORK}" "${service}")"
    node_permits="$(permit_identities "${node_records}")"
    expected="$(count_tokens "${node_permits}")"
    if ((held != expected)); then
      miscounted="${miscounted}${miscounted:+, }${service} held ${held} \
permit(s) for ${expected} piece(s) of work the driver put on it \
(${node_permits:-none})"
      continue
    fi

    quarantined="$(listing_value "${ROLLBACK_NODE_QUARANTINES}" "${service}")"
    quarantine_ids=""
    quarantine_count=0
    if [[ "${quarantined}" != "none" ]]; then
      if [[ -z "${quarantined}" || "${quarantined}" == "unreadable" ]]; then
        unaudited="${unaudited}${unaudited:+, }${service} (${forced} \
force-canceled, quarantine records unreadable)"
        continue
      fi
      quarantine_ids="${quarantined//,/ }"
      quarantine_count="$(count_tokens "${quarantine_ids}")"
    fi

    # A record has to be about work this node held. The namespace is written by
    # whatever the node was doing, and a record for a ceremony nobody
    # attributed to this drain accounts for none of the permits being followed
    # — it is state from somewhere else standing in for them.
    audited=""
    for record in ${node_records}; do
      audited="${audited}${audited:+ }$(audited_permit_id "${record}")"
    done
    for permit in ${quarantine_ids}; do
      contains_token "${audited}" "${permit}" && continue
      strayed="${strayed}${strayed:+, }${service} quarantined ${permit}"
    done
    [[ -n "${strayed}" ]] && continue

    if ((forced > 0)); then
      if ((quarantine_count == 0)); then
        unaudited="${unaudited}${unaudited:+, }${service} (${forced} \
force-canceled, no quarantine record)"
        continue
      fi
      # One record cannot account for many abandoned permits. The audit writes
      # a quarantine record per output it could not release, so a count short
      # of the force-cancels leaves the difference as in-flight state the
      # rollback restores onto with nothing describing it — which is the
      # reading this reconciliation exists to refuse, not a weaker version of
      # a record being present at all.
      if ((quarantine_count < forced)); then
        unaudited="${unaudited}${unaudited:+, }${service} (${forced} \
force-canceled, only ${quarantine_count} quarantine record(s))"
        continue
      fi
      quarantined_total=$((quarantined_total + forced))
    fi

    # And the permits that were not force-canceled: each one belongs to a piece
    # of work, and that work has to have ended somewhere the driver watched
    # rather than merely stopped being counted here.
    for record in ${node_records}; do
      contains_token "${quarantine_ids}" "$(audited_permit_id "${record}")" &&
        continue
      [[ -n "$(terminal_record "${ROLLBACK_TERMINAL}" \
        "${record}")" ]] &&
        continue
      orphaned="${orphaned}${orphaned:+, }${service} held a permit for \
$(permit_identity "${record}")"
    done

    # The same permits again, asked of the node that held them. Everything
    # above this point is the driver's account of ceremonies it originated, and
    # a permit whose owner recorded nothing is exactly the one whose process
    # went down holding it — which reads identically in a report that says the
    # ceremony settled. The endings are the node's own, sampled while it was
    # still draining.
    endings="$(listing_value "${ROLLBACK_NODE_ENDINGS}" "${service}")"
    if [[ -z "${endings}" || "${endings}" == "unread" ]]; then
      unvouched="${unvouched}${unvouched:+, }${service} (never asked what \
became of the permits it was draining)"
      continue
    fi
    [[ "${endings}" == "none" ]] && endings=""
    node_held="$(held_permit_identities "${node_records}")"
    unauthored="$(unauthored_permits "${node_held}" "${endings}")"
    if [[ -n "${unauthored}" ]]; then
      unvouched="${unvouched}${unvouched:+, }${service} recorded no ending \
for ${unauthored}"
      continue
    fi
    duplicated="$(duplicated_authored_permits "${node_held}" "${endings}")"
    if [[ -n "${duplicated}" ]]; then
      unvouched="${unvouched}${unvouched:+, }${service} recorded more than \
one ending for ${duplicated}"
      continue
    fi
    # The endings a rollback can restore onto: the ceremony finished, its
    # retries ran out, or its output was withdrawn into an audited quarantine
    # record. Each is a permit the node let go of and can describe, which is
    # what the restored fleet needs — the driver's side of this reconciliation
    # accepts a ceremony that gave up for the same reason.
    #
    # `unresolved` is the one ending that cannot be here, and it is checked
    # below rather than through this set: it is what the gate writes for a
    # permit closed by an owner that recorded nothing, which is exactly the
    # process that went down holding it.
    misended="$(misended_authored_permits "${node_held}" "${endings}" \
      "completed quarantined exhausted")"
    if [[ -n "${misended}" ]]; then
      misvouched="${misvouched}${misvouched:+, }${service} recorded \
${misended}"
      continue
    fi
    unresolved="$(unresolved_authored_permits "${node_held}" "${endings}")"
    if [[ -n "${unresolved}" ]]; then
      misvouched="${misvouched}${misvouched:+, }${service} recorded \
${unresolved}"
      continue
    fi

    completed_total=$((completed_total + held - forced))
  done <<<"${ROLLBACK_NODE_ACCOUNTS}"

  if [[ -n "${unread}" ]]; then
    block_step "${step}" "the permit accounting could not be read on \
${unread}; a permit whose fate is unknown is not a permit known to have \
completed, and treating an unreadable counter as zero is how one disappears \
from this reconciliation"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${impossible}" ]]; then
    block_step "${step}" "${impossible}, so the held and force-canceled counts \
describe different populations and no permit can be followed from one to the \
other"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${unreconciled}" ]]; then
    record_step "${step}" fail "${unreconciled}; those permits reconcile to \
neither completion nor quarantine — they went down with the process, and the \
state a rollback would restore onto carries no account of them"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${miscounted}" ]]; then
    block_step "${step}" "${miscounted}; the permit counters and the driver's \
account of what it put on each node describe different populations, so an \
outcome for one piece of work cannot be said to reconcile any particular \
permit"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${strayed}" ]]; then
    record_step "${step}" fail "${strayed}, which this drain never put on that \
node; a quarantine record for work nobody attributed to this drain is state \
from somewhere else standing in for the permits being followed"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${unaudited}" ]]; then
    record_step "${step}" fail "${unaudited}; a permit the gate force-canceled \
at the quiesce deadline that left no audited quarantine record behind is \
in-flight state the rollback would restore onto with nothing describing it"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${orphaned}" ]]; then
    block_step "${step}" "${orphaned} that neither ended in a terminal outcome \
the driver watched nor was written into a quarantine record; that permit \
reconciles to a gauge that fell rather than to work that ended, and the state \
a rollback restores onto carries no account of it"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${unvouched}" ]]; then
    block_step "${step}" "${unvouched}; the driver's terminal outcome is its \
account of a ceremony it started, and read alone it says the same thing about \
a permit that completed and one whose process went down holding it — only the \
node that held it can tell those apart"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "${misvouched}" ]]; then
    record_step "${step}" fail "${misvouched}, though the driver reported the \
work behind those permits ending; a rollback is authorized over permits their \
own holders let go of and can describe, and an ending outside that is \
in-flight state the restored fleet carries no account of"
    record_assertion "${assertion}" false "${step}"
  elif [[ -n "$(unended_work "${ROLLBACK_ORIGINATED_WORK}" \
    "${ROLLBACK_TERMINAL}" "$(quarantined_identities)")" ]]; then
    block_step "${step}" "the driver reported no terminal outcome and no node \
quarantined $(unended_work "${ROLLBACK_ORIGINATED_WORK}" \
      "${ROLLBACK_TERMINAL}" "$(quarantined_identities)"); work this gate put \
on the chain and never followed to an end is work the rollback restores onto \
with nothing describing it"
    record_assertion "${assertion}" false "${step}"
  else
    local settled terminated accounted
    settled="$(bound_settlements "${ROLLBACK_TERMINAL}")"
    terminated="$(bound_terminations "${ROLLBACK_TERMINAL}")"
    accounted="${settled}"
    if [[ -n "${terminated}" ]]; then
      accounted="${accounted}${accounted:+, }${terminated}"
    fi
    record_step "${step}" pass "every permit the ${nodes} R1 node(s) held when \
the stop was issued reconciles to the piece of work it was issued for: \
${completed_total} completed with the holding node observed without them, the \
driver reporting an outcome for each one (${accounted}), and the holding node \
recording an ending of its own for every permit it let go of; and \
${quarantined_total} were force-canceled at the quiesce deadline and written \
into the audit's quarantine records for the work they held"
    record_assertion "${assertion}" true "${step}"
  fi
}

# Every audited quarantine identity this drain produced, across the fleet.
quarantined_identities() {
  local k v out=""
  while read -r k v; do
    [[ -n "${k}" ]] || continue
    [[ "${v}" == "none" || "${v}" == "unreadable" || -z "${v}" ]] && continue
    out="${out}${out:+ }${v//,/ }"
  done <<<"${ROLLBACK_NODE_QUARANTINES}"
  printf '%s' "${out}"
}

# One value out of a "<key> <value>" listing, empty when the key is absent.
listing_value() {
  local listing="$1" key="$2" k v
  while read -r k v; do
    if [[ "${k}" == "${key}" ]]; then
      printf '%s' "${v}"
      return 0
    fi
  done <<<"${listing}"
  printf ''
}

# The quarantined outputs an audit manifest records for work interrupted after
# a given instant, one comma-joined
# "<ceremony>@<canonical start block>@<chain-work-id>#<member-index>" per
# record across both protocols. The DKG seed hash is the chain-work identity;
# the member index is the local permit identity. Keeping both is what lets two
# memberships on one node at one anchor remain two quarantined permits.
# Emitted as "unreadable" when the manifest or any record in it cannot be read,
# since a manifest nobody could read authorizes nothing, and as "none" when
# the manifest is readable and holds no record newer than the instant.
#
# The instant is what keeps the reading about this drain. A quarantine
# namespace accumulates: records an earlier interruption wrote are still there,
# and counting whatever the namespace holds lets state from a run nobody is
# reconciling stand in for permits this drain abandoned.
audit_quarantine_records() {
  local manifest="$1" since="$2"
  [[ -f "${manifest}" ]] || {
    printf 'unreadable'
    return 0
  }
  node -e '
    const fs = require("fs");
    const render = () => {
      const m = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      const since = Date.parse(process.argv[2]);
      const beacon = m.beacon_quarantined_outputs || [];
      const tbtc = m.tbtc_quarantined_outputs || [];
      if (!Array.isArray(beacon) || !Array.isArray(tbtc) ||
        !Number.isFinite(since)) {
        return "unreadable";
      }
      const ids = [];
      for (const record of beacon.concat(tbtc)) {
        const ceremony = (record || {}).ceremony;
        const block = (record || {}).canonical_start_block;
        const workID = (record || {}).seed_hash;
        const memberIndex = (record || {}).member_index;
        const preserved = Date.parse((record || {}).preserved_at);
        if (typeof ceremony !== "string" || !/^[a-z0-9_]+$/.test(ceremony) ||
          !Number.isInteger(block) ||
          typeof workID !== "string" ||
          !/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(workID) ||
          !Number.isInteger(memberIndex) || memberIndex < 1 ||
          !Number.isFinite(preserved)) {
          return "unreadable";
        }
        if (preserved < since) {
          continue;
        }
        ids.push(ceremony + "@" + block + "@" + workID + "#" + memberIndex);
      }
      return ids.length === 0 ? "none" : ids.join(",");
    };
    try {
      process.stdout.write(render());
    } catch (e) {
      process.stdout.write("unreadable");
    }
  ' "${manifest}" "${since}" 2>/dev/null || printf 'unreadable'
}

# The gate ceremony a driven work class takes its permit under, which is what
# the quarantine record the audit writes carries. The driver names work the way
# an operator drives it; the gate names it the way it is gated, and the two
# vocabularies differ where one gate class covers several driven ones: every
# non-heartbeat wallet action is a signing ceremony, and the beacon's signing
# class is its relay signing. Comparing the driver's word with the audit's
# without this mapping would find no quarantine record for work that has one.
gate_ceremony() {
  case "$1" in
  tbtc_wallet_action | tbtc_signing) printf 'tbtc_signing' ;;
  beacon_signing) printf 'beacon_relay_signing' ;;
  *) printf '%s' "$1" ;;
  esac
}

# One work identity in the audit's vocabulary rather than the driver's.
audited_work_id() {
  local ceremony remainder
  ceremony="$(work_ceremony "$1")"
  remainder="${1#*@}"
  printf '%s@%s' "$(gate_ceremony "${ceremony}")" "${remainder}"
}

# One originated permit in the audit manifest's vocabulary.
audited_permit_id() {
  printf '%s#%s' "$(audited_work_id "$(work_id "$1")")" \
    "$(permit_local_id "$(work_permit "$1")")"
}

# How many tokens a space-joined list holds.
count_tokens() {
  local item count=0
  for item in $1; do
    count=$((count + 1))
  done
  printf '%s' "${count}"
}

# Whether a compose service's container is running right now.
#
# Preflight already proved which image each service was created from, but that
# is a statement about the past. A mixed-fleet control's whole subject is the
# prior binary being on the network while R1 works, and a prior container that
# exited between then and now leaves a homogeneous R1 fleet producing readings
# a mixed-fleet claim would be recorded over.
service_container_running() {
  local service="$1" container state
  container="$(compose ps --quiet "${service}" 2>/dev/null || true)"
  [[ -n "${container}" ]] || return 1
  state="$(docker inspect --format '{{.State.Running}}' "${container}" \
    2>/dev/null || true)"
  [[ "${state}" == "true" ]]
}

# Of the required ceremonies, the ones no bound successful result covers. The
# mirror of missing_bound_families one level down, for the control whose claim
# names the ceremonies it drove rather than the half of the release or the kind
# of work they belong to.
missing_bound_ceremonies() {
  local records="$1" required="$2" ceremony record uncovered="" covered
  for ceremony in ${required}; do
    covered=0
    for record in ${records}; do
      [[ "$(bound_outcome "${record}")" == "succeeded" ]] || continue
      [[ "$(work_ceremony "$(bound_work "${record}")")" == "${ceremony}" ]] ||
        continue
      covered=1
      break
    done
    ((covered == 1)) || uncovered="${uncovered}${uncovered:+ }${ceremony}"
  done
  printf '%s' "${uncovered}"
}

# What one pre-cutover driver phase observed on a fleet that still has the
# prior binary on its network.
#
# Both halves of every counter are taken around the driver call rather than
# compared against zero: these steps run first, but the gauges are cumulative
# and a later re-read of this scaffold's own state must not make "the fleet
# took a legacy permit" true of something the crossing did.
PRECUTOVER_DRIVER_SUPPLIED=0
PRECUTOVER_DRIVER_RC=0
PRECUTOVER_TX=0
PRECUTOVER_RESULTS=""
PRECUTOVER_BOUND=""
PRECUTOVER_PRIOR_RUNNING=0
PRECUTOVER_STATES=""
PRECUTOVER_LEGACY_BEFORE=""
PRECUTOVER_LEGACY_AFTER=""
PRECUTOVER_SECURITY_BEFORE=""
PRECUTOVER_SECURITY_AFTER=""
PRECUTOVER_SIGHTINGS_BEFORE=""
PRECUTOVER_SIGHTINGS_AFTER=""
# The permits the driven work was actually issued, and what the nodes holding
# them recorded about how each one ended.
#
# Everything above this pair is the driver's account of its own work: which
# ceremonies it started, which it says settled, and which parties it says
# contributed. A control whose claim is that a mixed fleet completed work below
# C cannot rest on that alone — the same report is produced by a driver whose
# ceremonies were refused and by one whose ceremonies never ran. These two name
# the permits this fleet's gate issued for that work and join each of them to
# the disposition its own holder wrote down.
PRECUTOVER_ORIGINATED=""
PRECUTOVER_AUTHORED_ENDINGS=""
# And the permits still open when that reading was taken. A driver reports when
# the chain settles and a holder closes on its own schedule, so a contributor
# whose permit outlives the report is in neither the endings nor anywhere else —
# and a seat in neither is one the fleet reads as never having operated.
PRECUTOVER_HELD_AFTER=""
# Which process each node answered the readings above from, and how much
# its account had already forgotten, taken either side of the drive. An
# account read from a new process is missing every record the old one held.
PRECUTOVER_ACCOUNTS_BEFORE=""
PRECUTOVER_ACCOUNTS_AFTER=""

# The ceremonies a pre-cutover step must see settle, named one by one.
#
# The mandate is that mixed prior/R1 tBTC signing, DKG and heartbeat and the
# beacon controls all succeed below C. Neither a family nor a work-class
# requirement can state that: "a tBTC threshold ceremony settled" is satisfied
# by a signing alone, leaving the DKG and heartbeat paths into the gate
# undriven, and those anchor differently and refuse separately. A step that
# named a broad class would report on whichever ceremony the driver happened to
# pick.
PRECUTOVER_REQUIRED_CEREMONIES="tbtc_dkg tbtc_signing tbtc_heartbeat \
beacon_dkg beacon_signing"

collect_precutover_work() {
  local phase="$1" service state block account

  PRECUTOVER_DRIVER_SUPPLIED=0
  PRECUTOVER_DRIVER_RC=0
  PRECUTOVER_TX=0
  PRECUTOVER_RESULTS=""
  PRECUTOVER_BOUND=""
  PRECUTOVER_CONTRIBUTORS=""
  PRECUTOVER_STATES=""
  PRECUTOVER_ORIGINATED=""
  PRECUTOVER_AUTHORED_ENDINGS=""
  PRECUTOVER_HELD_AFTER=""
  PRECUTOVER_ACCOUNTS_BEFORE=""
  PRECUTOVER_ACCOUNTS_AFTER=""

  # Every R1 node has to be on the legacy side of its own gate before the work
  # starts. A node already past C would run this work under security-v2 and
  # produce a settled ceremony a pre-cutover control would record as
  # compatibility evidence.
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    observe_canonical_block "${service}"
    state="$(participation_field "${service}" gate_state 2>/dev/null || true)"
    block="$(participation_field "${service}" current_block 2>/dev/null || true)"
    if [[ "${state}" != "open_legacy" ]] ||
      [[ ! "${block}" =~ ^[0-9]+$ ]] ||
      ((block >= CUTOVER_BLOCK)); then
      PRECUTOVER_STATES="${PRECUTOVER_STATES}${PRECUTOVER_STATES:+, }\
${service} reported [${state:-unreadable}] at block [${block:-unreadable}]"
    fi
  done

  PRECUTOVER_PRIOR_RUNNING=0
  if service_container_running "${REHEARSAL_PRIOR_SERVICE}"; then
    PRECUTOVER_PRIOR_RUNNING=1
  fi

  PRECUTOVER_LEGACY_BEFORE="$(fleet_metric_total \
    participation_mode_legacy_total)"
  PRECUTOVER_SECURITY_BEFORE="$(fleet_metric_total \
    participation_mode_security_v2_total)"
  # Pre-C the prior binary and R1 speak the same wire format, so a recognized
  # cross-format peer here is the compatibility claim failing rather than a
  # straggler being found. It is read where a mismatch would appear rather
  # than inferred from the mode a permit pinned.
  PRECUTOVER_SIGHTINGS_BEFORE="$(fleet_metric_total \
    announcer_cross_format_peer_total)"
  # Which process each node's account of closed permits belongs to, and how much
  # that account has already forgotten, taken before the work starts so the
  # reading afterwards can be held to it. Without the pair, a node that restarted
  # mid-drive answers with an empty account and reads as a node that took no part
  # in the work — which puts its seats outside the fleet and turns a homogeneous
  # run into the mixed reading.
  PRECUTOVER_ACCOUNTS_BEFORE="$(fleet_account_provenance)"

  if [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
    PRECUTOVER_DRIVER_SUPPLIED=1
    run_work_driver "${phase}" || true
    PRECUTOVER_DRIVER_RC="${WORK_DRIVER_RC}"
    PRECUTOVER_TX="${WORK_DRIVER_TX_COUNT}"
    PRECUTOVER_RESULTS="${WORK_DRIVER_CEREMONY_RESULTS}"
    PRECUTOVER_BOUND="${WORK_DRIVER_BOUND_RESULTS}"
    PRECUTOVER_CONTRIBUTORS="${WORK_DRIVER_RESULT_CONTRIBUTORS}"
    PRECUTOVER_ORIGINATED="${WORK_DRIVER_ORIGINATED_WORK}"
    # Taken after the driver has reported, so every permit it says was issued
    # for this work has had its holder's own record written before the reading.
    # The driver's account is kept beside it rather than replaced: it carries
    # the settlement identities and transactions the chain corroborates, which
    # a gate scrape does not know.
    #
    # One reading per node, carrying the endings, the permits still open, and the
    # provenance of the account all three are read out of. They answer each other
    # — a permit is held or closed and never both, and the provenance says whether
    # either list can be believed — so taken at three instants a permit closing
    # between two of them is in none of them, which is a seat missing from the
    # fleet with nothing anywhere saying it went missing.
    #
    # Retaken until the permits this work was driven under have closed. The
    # driver settling its own side is not the holder closing the permit it ran
    # under, so the first reading after the driver returns catches permits
    # mid-close — and every ownership join below reads a still-open permit as
    # one whose holder refused to say how it ended.
    account="$(settled_account_snapshot "${PRECUTOVER_ORIGINATED}" \
      "${PRECUTOVER_ACCOUNTS_BEFORE}")"
    PRECUTOVER_AUTHORED_ENDINGS="$(snapshot_field "${account}" outcomes)"
    PRECUTOVER_HELD_AFTER="$(snapshot_field "${account}" held)"
    PRECUTOVER_ACCOUNTS_AFTER="$(snapshot_field "${account}" provenance)"
  fi

  PRECUTOVER_LEGACY_AFTER="$(fleet_metric_total \
    participation_mode_legacy_total)"
  PRECUTOVER_SECURITY_AFTER="$(fleet_metric_total \
    participation_mode_security_v2_total)"
  PRECUTOVER_SIGHTINGS_AFTER="$(fleet_metric_total \
    announcer_cross_format_peer_total)"
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    observe_gate_gauges "${service}"
  done
}

# The verdict the readings above imply, for whichever pre-cutover step
# collected them.
#
# The two pre-C steps decide on the same fleet observations and differ only in
# what the driven work must cover, so the ladder is shared and the coverage
# requirement is the caller's. Duplicating it per step would let the two
# statements of "the fleet took no security-v2 permit" drift apart.
precutover_verdict() {
  local step="$1" assertion="$2" required_ceremonies="$3" what="$4"

  local failed_results missing_ceremonies settlements
  local uninteroperated stray unended invented uncredited unrecognized
  local disowned unplaceable unfollowable
  local named_permits unauthored duplicated unresolved misended authored
  local malformed misevidenced disagreeing unclaimed result_population
  local unresolved_settlements stillheld
  failed_results="$(unsuccessful_results "${PRECUTOVER_RESULTS}")"
  missing_ceremonies="$(missing_bound_ceremonies \
    "${PRECUTOVER_BOUND}" "${required_ceremonies}")"
  settlements="$(bound_settlements "${PRECUTOVER_BOUND}")"
  # An outcome for work this phase did not originate on the transaction that
  # originated it is somebody else's ceremony, and originated work with no
  # outcome at all is how a partial population passes: five ceremonies driven,
  # one reported.
  stray="$(unoriginated_terminals "${PRECUTOVER_BOUND}" \
    "${PRECUTOVER_ORIGINATED}")"
  unended="$(unended_work "${PRECUTOVER_ORIGINATED}" "${PRECUTOVER_BOUND}" "")"
  # The same population read off the nodes rather than off the driver. Every
  # check above this line decides on an account the driver gave of its own
  # work; these are the holders' own records of closing the very permits this
  # fleet's gate issued for it.
  named_permits="$(held_permit_identities "${PRECUTOVER_ORIGINATED}")"
  # Whether the account those records came out of is the one that was there
  # while the work ran. Every join below reads it, so it is asked before any of
  # them: a node that restarted mid-drive answers with an account missing every
  # permit the old process held, which reads as a node that took no part.
  unfollowable="$(unfollowable_account_nodes \
    "${PRECUTOVER_ACCOUNTS_BEFORE}" "${PRECUTOVER_ACCOUNTS_AFTER}")"
  # And whether the reading caught this work still running. The reading above
  # waits for the driver's permits to close, so one still open here stayed open;
  # asked of the check below it would come out as a permit nobody would vouch
  # for, which is a different fleet's finding reported against this one.
  stillheld="$(held_open_permits "${named_permits}" "${PRECUTOVER_HELD_AFTER}")"
  unauthored="$(unauthored_permits "${named_permits}" \
    "${PRECUTOVER_AUTHORED_ENDINGS}")"
  duplicated="$(duplicated_authored_permits "${named_permits}" \
    "${PRECUTOVER_AUTHORED_ENDINGS}")"
  unresolved="$(unresolved_authored_permits "${named_permits}" \
    "${PRECUTOVER_AUTHORED_ENDINGS}")"
  # Completion only. A pre-C compatibility claim is that the mixed fleet
  # finished this work; a permit that ran out of retries or had its key
  # material quarantined is a closing, not a settlement, and the driver's
  # report of a successful ceremony beside it is exactly the disagreement this
  # rung exists to surface.
  misended="$(misended_authored_permits "${named_permits}" \
    "${PRECUTOVER_AUTHORED_ENDINGS}" completed)"
  # What those completions actually left behind. "completed" is what every
  # holder of every finished ceremony writes, so the rungs above it are
  # satisfied by a fleet whose members each finished something different and by
  # a driver claiming a settlement none of them produced.
  malformed="$(malformed_authored_records "${named_permits}" \
    "${PRECUTOVER_AUTHORED_ENDINGS}")"
  misevidenced="$(misevidenced_authored_permits "${named_permits}" \
    "${PRECUTOVER_AUTHORED_ENDINGS}")"
  # And what those completions dispatched beyond themselves. A side effect the
  # holder could not resolve is chain state this fleet may have created and
  # cannot account for, which every rung below would otherwise read past.
  unresolved_settlements="$(unresolved_authored_settlements \
    "${named_permits}" "${PRECUTOVER_AUTHORED_ENDINGS}")"
  # Every holder of this work, not only the ones the driver named. A holder it
  # omitted still published a record, and a result it recorded that disagrees
  # with the rest — or that no settlement claims — is exactly what a population
  # drawn from the driver's own report cannot see.
  result_population="${named_permits} $(authored_work_permits \
    "$(identity_works "${named_permits}")" "${named_permits}" \
    "${PRECUTOVER_AUTHORED_ENDINGS}")"
  disagreeing="$(disagreeing_authored_results "${result_population}" \
    "${PRECUTOVER_AUTHORED_ENDINGS}")"
  unclaimed="$(unclaimed_authored_results "${result_population}" \
    "${PRECUTOVER_AUTHORED_ENDINGS}" "${PRECUTOVER_BOUND}")"
  authored="$(authored_endings "${named_permits}" \
    "${PRECUTOVER_AUTHORED_ENDINGS}")"
  # Who took part, reconciled before it decides anything. The driver names the
  # contributors and the mixed-transcript rung below reads that list, so an
  # unreconciled list makes the whole compatibility claim the driver's own
  # account of itself. Both directions are held: a claimed R1 party the fleet
  # never recorded is invented, and a completion the fleet did record but the
  # list omits is a party the driver chose not to count.
  invented="$(invented_contributors "${PRECUTOVER_CONTRIBUTORS}" \
    "${PRECUTOVER_AUTHORED_ENDINGS}" "${REHEARSAL_R1_SERVICES[*]}")"
  unrecognized="$(unrecognized_contributors "${PRECUTOVER_CONTRIBUTORS}" \
    "${REHEARSAL_PRIOR_SERVICE}" "${REHEARSAL_R1_SERVICES[*]}")"
  uncredited="$(uncredited_contributors "${PRECUTOVER_CONTRIBUTORS}" \
    "${PRECUTOVER_AUTHORED_ENDINGS}" "$(identity_works "${named_permits}")")"
  disowned="$(disowned_authored_transcripts \
    "${PRECUTOVER_AUTHORED_ENDINGS}" \
    "$(identity_works "${named_permits}")")"
  # And whether the ownership map the mixed reading is decided against could be
  # placed in the index space the transcripts speak in at all. Where it could
  # not, the reading below has no map to subtract and every seat reads as
  # somebody else's — so the gap is named here rather than spent as evidence.
  unplaceable="$(unplaceable_authored_ownership \
    "${PRECUTOVER_AUTHORED_ENDINGS}" \
    "$(identity_works "${named_permits}")" "${PRECUTOVER_HELD_AFTER}")"
  # The permits still open enter the map beside the closed ones. A holder that
  # was contributing when the reading was taken operated its seats exactly as one
  # that had already closed did; what separates them is only whether the driver
  # or the holder finished first, and a map that turned on that reads a race as
  # the other release having supplied the seat.
  uninteroperated="$(ceremonies_without_mixed_transcript \
    "${PRECUTOVER_CONTRIBUTORS}" "${PRECUTOVER_AUTHORED_ENDINGS}" \
    "${required_ceremonies}" "${REHEARSAL_PRIOR_SERVICE}" \
    "${PRECUTOVER_HELD_AFTER}")"

  if ((PRECUTOVER_DRIVER_SUPPLIED == 0)); then
    block_step "${step}" "no PR4109_WORK_DRIVER was supplied, so no \
legacy-anchored ceremony was originated on the rehearsal chain and there is \
nothing to observe; the fleet only reacts to chain events"
  elif ((PRECUTOVER_PRIOR_RUNNING == 0)); then
    block_step "${step}" "the prior binary's container was not running when \
this step drove ${what}, so whatever the R1 fleet did it did alone; a mixed \
prior/R1 claim cannot be read off a fleet with one release on it"
  elif [[ -n "${PRECUTOVER_STATES}" ]]; then
    block_step "${step}" "the R1 fleet was not on the legacy side of C when \
this step began — ${PRECUTOVER_STATES} — so the work it drove was not \
pre-cutover work; the rehearsal chain must be below C=[${CUTOVER_BLOCK}] for \
this step"
  elif ((PRECUTOVER_DRIVER_RC != 0)); then
    record_step "${step}" fail "the work driver exited \
[${PRECUTOVER_DRIVER_RC}] originating ${what}"
  elif [[ ! "${PRECUTOVER_LEGACY_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${PRECUTOVER_LEGACY_AFTER}" =~ ^[0-9]+$ ]] ||
    [[ ! "${PRECUTOVER_SECURITY_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${PRECUTOVER_SECURITY_AFTER}" =~ ^[0-9]+$ ]]; then
    block_step "${step}" "the fleet permit counters could not be read (legacy \
[${PRECUTOVER_LEGACY_BEFORE}] to [${PRECUTOVER_LEGACY_AFTER}], security-v2 \
[${PRECUTOVER_SECURITY_BEFORE}] to [${PRECUTOVER_SECURITY_AFTER}]), so \
nothing here observed which mode the ceremonies ran in"
  elif ((PRECUTOVER_TX == 0)); then
    block_step "${step}" "the work driver exited cleanly but reported no \
transaction, so nothing attributes the fleet's permit activity to the \
ceremonies this control claims to have originated"
  elif [[ -n "${failed_results}" ]]; then
    record_step "${step}" fail "the work driver reported ${failed_results} \
driving ${what}; a compatibility control cannot be read off the subset of a \
mixed fleet's work that survived"
  elif [[ -z "${settlements}" ]]; then
    block_step "${step}" "the work driver named no ceremony that completed \
successfully on a transaction it originated, so this control observed work \
being allowed to start and nothing about it finishing"
  elif [[ -z "${named_permits//[[:space:]]/}" ]]; then
    block_step "${step}" "the work driver settled ${settlements} but named no \
node holding a permit for any of it, so nothing here identifies a permit this \
fleet's gate issued; the settlements are the driver's account of its own work \
and the gauges below only say the fleet took some legacy permit while it ran"
  elif [[ -n "${stray}" ]]; then
    record_step "${step}" fail "the work driver reported an outcome for \
${stray}, which it did not originate here on that transaction; an outcome \
belonging to another ceremony or another transaction is not evidence about \
${what}"
  elif [[ -n "${missing_ceremonies}" ]]; then
    block_step "${step}" "the work driver settled ${settlements} but no \
${missing_ceremonies}; this step's claim is about ${what}, and each ceremony \
it names is a separate path into the gate with its own anchor and its own \
refusal — one of them settling says nothing about the rest, so the step has \
to cover ${required_ceremonies}"
  elif [[ -n "${unended}" ]]; then
    block_step "${step}" "the work driver settled ${settlements} but reported \
no outcome at all for ${unended}; a control that reads only the work its \
driver chose to report on is satisfied by the subset that went well, which is \
the reading a mixed-fleet claim must not be decided by"
  elif [[ "${PRECUTOVER_AUTHORED_ENDINGS}" == "unreadable on "* ]]; then
    block_step "${step}" "the R1 fleet could not be asked what became of the \
permits it took for ${what} (${PRECUTOVER_AUTHORED_ENDINGS}); without that \
reading the settlements above are the driver's account of its own ceremonies \
and no node has vouched for one of them"
  elif [[ "${PRECUTOVER_HELD_AFTER}" == "unreadable on "* ]]; then
    block_step "${step}" "the R1 fleet could not be asked which permits it was \
still holding for ${what} (${PRECUTOVER_HELD_AFTER}); a permit open when the \
driver reported is in neither account, and its seats then read as operated by \
whatever else was on the network"
  elif [[ -n "${unfollowable}" ]]; then
    block_step "${step}" "${unfollowable}; the account of closed permits every \
reading below rests on lives in memory, so a node answering from a new process \
or dropping records while the work ran has published an account that is \
missing permits rather than one that never held them — and a missing permit \
reads as a node that took no part in work it may well have done"
  elif [[ -n "${stillheld}" ]]; then
    block_step "${step}" "the R1 fleet was still holding ${stillheld} \
${ACCOUNT_SETTLE_TIMEOUT}s after the work driver reported ${what} settled; a \
permit that never closed has no ending for the readings below to join to, and \
waiting past that is waiting for a ceremony that stopped finishing"
  elif [[ -n "${unauthored}" ]]; then
    block_step "${step}" "no node recorded an ending for ${unauthored}, \
though the driver named ${named_permits} as the permits issued for ${what}; a \
permit whose own holder will not say how it ended cannot be counted as work a \
mixed fleet completed"
  elif [[ -n "${duplicated}" ]]; then
    block_step "${step}" "more than one node-authored record claims to be the \
ending of ${duplicated}; one permit ends once, and a reader taking the first \
match would decide this control on whichever record happened to come first"
  elif [[ -n "${unresolved}" ]]; then
    record_step "${step}" fail "${unresolved} — the holder closed the permit \
without recording what became of it, so the ceremony went somewhere the node \
cannot say and the driver's settlement for it stands on nothing"
  elif [[ -n "${misended}" ]]; then
    record_step "${step}" fail "the work driver settled ${settlements}, but \
the nodes holding the permits recorded ${misended}; a closing is not a \
completion, and where the two accounts disagree it is the driver's that is \
about its own work"
  elif [[ -n "${malformed}" ]]; then
    block_step "${step}" "the node-authored account of ${what} stops \
short of what a permit's holder records — ${malformed} — so the reading \
names a disposition and nothing about what it left behind; a release \
publishing only the category cannot be reconciled against what the driver \
says settled"
  elif [[ -n "${misevidenced}" ]]; then
    record_step "${step}" fail "${misevidenced}; the gate pins each ceremony \
to the evidence class its result actually lives in, and a completion carrying \
another class is a categorical claim about a ceremony whose real output \
nothing here has seen"
  elif [[ -n "${unresolved_settlements}" ]]; then
    block_step "${step}" "${unresolved_settlements}; the fleet may have left \
chain state behind that no node can name, and every reading below this is \
about work whose ending is accounted for — an unresolved side effect is for the \
offline audit to settle rather than for a step to read past"
  elif [[ -n "${disagreeing}" ]]; then
    record_step "${step}" fail "the holders of ${disagreeing} each recorded a \
completion naming a different result; a threshold ceremony has one output, so \
this is separate work finishing separately on the same chain item rather than \
a mixed fleet completing it together"
  elif [[ -n "${unclaimed}" ]]; then
    record_step "${step}" fail "${unclaimed}; the driver's account of what \
${what} settled as and the holders' own records of what they produced have to \
name the same threshold output, and where they do not, one of the two is \
describing work the other never did"
  elif [[ -n "${unrecognized}" ]]; then
    block_step "${step}" "the work driver names ${unrecognized} among the \
parties to the transcripts it settled, and this rehearsal runs no such \
service; a holder whose release is unknown is neither half of a mixed \
prior/R1 claim, and counting it as either would let a stray container supply \
the side it was never shown to be on"
  elif [[ -n "${disowned}" ]]; then
    block_step "${step}" "${disowned}; a holder said which seats it was \
operating when its permit was issued and then published a result produced with \
a seat it never claimed, and the two accounts of one permit cannot both be \
true; the fleet ownership map every mixed reading is decided against is built \
from the first of them, so a record contradicting it settles nothing either way"
  elif [[ -n "${unplaceable}" ]]; then
    block_step "${step}" "${unplaceable}; the transcripts on that work are in a \
different membership index space than its permits and no usable mapping between \
the two was published, so which seats of those transcripts this fleet was \
sitting in is unknown; an unknown ownership map cannot be read as the fleet \
having operated none of them"
  elif [[ -n "${uninteroperated}" ]]; then
    block_step "${step}" "the work driver settled ${settlements}, but no \
${uninteroperated} transcript incorporated a share from both \
${REHEARSAL_PRIOR_SERVICE} and an R1 holder whose own record puts a share of \
its own in that result; one release was running beside the other and took no \
part in those results, which is what an unselected, partitioned, or excluded \
party looks like from outside — a ceremony the two releases did interoperate on \
cannot stand for one they did not, two homogeneous ceremonies cannot stand for \
either, and an R1 node that only watched a prior-only result finish is not a \
party to it"
  elif [[ -n "${invented}" ]]; then
    record_step "${step}" fail "the work driver claims ${invented} took part \
in the transcripts it settled, and those nodes recorded no such contribution; a \
party the fleet never vouched for is the driver attesting to its own \
compatibility, one real contribution reported under several identities is how a \
single share stands for the many a threshold needs, and a holder that recorded \
watching a result it had no seat in never claimed to be a party to it"
  elif [[ -n "${uncredited}" ]]; then
    block_step "${step}" "the holders of ${uncredited} recorded contributing \
to work the driver settled, and its contributor set does not name them; the set \
has to be the population that ran rather than a subset of it, or the account \
of who interoperated is about a smaller transcript than the one this fleet \
produced"
  elif ((PRECUTOVER_LEGACY_AFTER <= PRECUTOVER_LEGACY_BEFORE)); then
    record_step "${step}" fail "the work driver settled ${settlements}, but \
the fleet issued no new legacy permit (participation_mode_legacy_total still \
[${PRECUTOVER_LEGACY_AFTER}]); the ceremonies it named were not run under \
this fleet's gate on the legacy side of C"
  elif ((PRECUTOVER_SECURITY_AFTER > PRECUTOVER_SECURITY_BEFORE)); then
    record_step "${step}" fail "the fleet issued \
$((PRECUTOVER_SECURITY_AFTER - PRECUTOVER_SECURITY_BEFORE)) security-v2 \
permit(s) (participation_mode_security_v2_total \
[${PRECUTOVER_SECURITY_BEFORE}] to [${PRECUTOVER_SECURITY_AFTER}]) driving \
work anchored below C; a pre-cutover anchor must pin the legacy mode"
  elif [[ ! "${PRECUTOVER_SIGHTINGS_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${PRECUTOVER_SIGHTINGS_AFTER}" =~ ^[0-9]+$ ]]; then
    block_step "${step}" "the fleet's cross-format sighting counter could not \
be read (${PRECUTOVER_SIGHTINGS_BEFORE:-unreadable} to \
${PRECUTOVER_SIGHTINGS_AFTER:-unreadable}), so the half of this control that \
is about the prior binary being interoperable was never observed"
  elif ((PRECUTOVER_SIGHTINGS_AFTER > PRECUTOVER_SIGHTINGS_BEFORE)); then
    record_step "${step}" fail "the R1 fleet recognized \
$((PRECUTOVER_SIGHTINGS_AFTER - PRECUTOVER_SIGHTINGS_BEFORE)) cross-format \
peer(s) (announcer cross-format total [${PRECUTOVER_SIGHTINGS_BEFORE}] to \
[${PRECUTOVER_SIGHTINGS_AFTER}]) while running legacy-anchored work beside \
the prior binary; below C the two releases must be one wire format"
  else
    STEP_PERMIT_MODES='"legacy"'
    record_step "${step}" pass "the fleet issued \
$((PRECUTOVER_LEGACY_AFTER - PRECUTOVER_LEGACY_BEFORE)) new legacy permits \
and no security-v2 permit (unchanged at [${PRECUTOVER_SECURITY_AFTER}]) \
driving ${what} beside the running prior binary, the driver settled \
${settlements} with nothing failing beside them, the nodes holding the permits \
issued for that work recorded ${authored}, its contributor set named every \
contribution those holders recorded and no party they did not, each of \
${required_ceremonies} joined a claimed ${REHEARSAL_PRIOR_SERVICE} share to \
work an R1 holder's own record puts a share of its own in, and the fleet \
recognized no cross-format peer (unchanged at \
[${PRECUTOVER_SIGHTINGS_AFTER}])"
    [[ -z "${assertion}" ]] || record_assertion "${assertion}" true "${step}"
    return
  fi

  [[ -z "${assertion}" ]] || record_assertion "${assertion}" false "${step}"
}

# What the in-flight half of the crossing observed: work anchored below C that
# was still running when C passed.
#
# This one cannot be collected in the step that decides it. Its subject is a
# permit that outlives the crossing, so the work has to be put on the chain
# before the crossing step runs and asked about afterwards; a phase that
# originated and settled its work on one side of C would evidence a ceremony
# completing, not a ceremony surviving.
SURVIVING_DRIVER_SUPPLIED=0
SURVIVING_ORIGINATE_RC=0
SURVIVING_ORIGINATED=""
SURVIVING_HELD_BEFORE=""
SURVIVING_PERMITS_BEFORE=""
SURVIVING_PERMITS_AT_C=""
SURVIVING_PERMITS_AT_C_READ=0
SURVIVING_LEGACY_COMPLETIONS_BEFORE=""
SURVIVING_LEGACY_COMPLETIONS_AFTER=""
SURVIVING_TERMINAL_ASKED=0
SURVIVING_TERMINAL_RC=0
SURVIVING_TERMINAL=""
SURVIVING_AUTHORED_ENDINGS=""

originate_surviving_legacy_work() {
  SURVIVING_DRIVER_SUPPLIED=0
  SURVIVING_ORIGINATE_RC=0
  SURVIVING_ORIGINATED=""
  SURVIVING_PERMITS_BEFORE=""
  SURVIVING_PERMITS_AT_C=""
  SURVIVING_PERMITS_AT_C_READ=0
  SURVIVING_TERMINAL_ASKED=0
  SURVIVING_TERMINAL_RC=0
  SURVIVING_TERMINAL=""
  SURVIVING_AUTHORED_ENDINGS=""

  SURVIVING_LEGACY_COMPLETIONS_BEFORE="$(fleet_metric_total \
    participation_legacy_completions_after_cutover_total)"
  SURVIVING_HELD_BEFORE="$(fleet_metric_total \
    participation_active_legacy_ceremonies)"

  [[ -n "${PR4109_WORK_DRIVER:-}" ]] || return 0
  SURVIVING_DRIVER_SUPPLIED=1
  run_work_driver precutover-inflight || true
  SURVIVING_ORIGINATE_RC="${WORK_DRIVER_RC}"
  SURVIVING_ORIGINATED="${WORK_DRIVER_ORIGINATED_WORK}"
  SURVIVING_HELD_BEFORE="$(fleet_metric_total \
    participation_active_legacy_ceremonies)"
  # The gates' own list of what they are holding, taken beside the count. The
  # count says how many permits met C; only the list says which, and the whole
  # claim of this control is about particular permits.
  SURVIVING_PERMITS_BEFORE="$(fleet_legacy_permits)"
}

# The same list read at the instant the fleet reports it is past C. Taken from
# the crossing step rather than from the resolution that follows it: a permit
# read after the work settled is a permit that is gone whether it survived the
# crossing or was cut short at it, and the two readings have to be separable.
observe_surviving_permits_at_cutover() {
  SURVIVING_PERMITS_AT_C_READ=1
  SURVIVING_PERMITS_AT_C="$(fleet_legacy_permits)"
}

# What became of it, asked after the crossing step has established that C
# passed in the same processes.
resolve_surviving_legacy_work() {
  SURVIVING_LEGACY_COMPLETIONS_AFTER="$(fleet_metric_total \
    participation_legacy_completions_after_cutover_total)"

  [[ -n "${PR4109_WORK_DRIVER:-}" ]] || return 0
  SURVIVING_TERMINAL_ASKED=1
  run_work_driver precutover-inflight-terminal || true
  SURVIVING_TERMINAL_RC="${WORK_DRIVER_RC}"
  SURVIVING_TERMINAL="${WORK_DRIVER_BOUND_RESULTS}"
  # Taken after the driver has reported, so every permit it says ended has had
  # its holder's own record written before this reading is taken. This is the
  # reading the verdict decides on; the driver's is kept beside it because it
  # carries the settlement identities and transactions the chain corroborates,
  # neither of which a gate scrape knows.
  SURVIVING_AUTHORED_ENDINGS="$(fleet_terminal_outcomes)"
  SURVIVING_LEGACY_COMPLETIONS_AFTER="$(fleet_metric_total \
    participation_legacy_completions_after_cutover_total)"
}

surviving_legacy_verdict() {
  local step="pre-cutover legacy work survives C and completes"

  local stray settlements failed unended originated_permits held_delta
  local named_permits unheld_before unnamed_before lost_at_c arrived_at_c
  local unauthored duplicated unresolved misended authored
  local malformed misevidenced disagreeing unclaimed result_population
  local unresolved_settlements
  named_permits="$(held_permit_identities "${SURVIVING_ORIGINATED}")"
  unheld_before="$(absent_tokens "${named_permits}" \
    "${SURVIVING_PERMITS_BEFORE}")"
  unnamed_before="$(absent_tokens "${SURVIVING_PERMITS_BEFORE}" \
    "${named_permits}")"
  lost_at_c="$(absent_tokens "${named_permits}" "${SURVIVING_PERMITS_AT_C}")"
  # The comparison at C runs both ways. A named permit missing at C is one
  # that did not cross; a legacy permit present at C that was not there before
  # it is one this step never identified, and the completion fence at the
  # bottom of this ladder is a fleet-wide counter. An unaccounted legacy permit
  # completing after C supplies an increment of its own, which is exactly what
  # would let a named permit bypass its completion fence and still leave the
  # totals matching.
  #
  # One legacy permit is deliberately added between the two samples: the
  # quiescence control's seed, put on the chain after this work was originated
  # and before the crossing. It is named here rather than left to look like a
  # stray, but only by the identities two independent readings of the seeding
  # agree on: the ones the seeding driver said it originated on that node, and
  # the ones that node's own gate reported holding below C.
  #
  # Neither reading may excuse a permit alone. The gate's is the whole legacy
  # population of the seed node, so any permit that merely turned up there
  # between the two samples would be waved through under the seed's name — and
  # the completion fence at the bottom of this ladder is a fleet-wide counter,
  # so an excused arrival can supply the very increment the named permit is
  # meant to. The driver's is the driver's word for an anchor below C, which is
  # the one thing the seeding control exists to check. An unreadable gate
  # reading agrees with nothing and so excuses nothing.
  local accounted_at_c="${SURVIVING_PERMITS_BEFORE}"
  local seeded_before_c=""
  if [[ -n "${QUIESCE_SEEDED_PERMITS_BEFORE_C}" &&
    "${QUIESCE_SEEDED_PERMITS_BEFORE_C}" != "unreadable on "* ]]; then
    seeded_before_c="$(present_tokens \
      "$(held_permit_identities "${QUIESCE_SEEDED_WORK}")" \
      "${QUIESCE_SEEDED_PERMITS_BEFORE_C}")"
  fi
  accounted_at_c="${accounted_at_c}${seeded_before_c:+ ${seeded_before_c}}"
  arrived_at_c="$(absent_tokens "${SURVIVING_PERMITS_AT_C}" \
    "${accounted_at_c}")"
  stray="$(unoriginated_terminals "${SURVIVING_TERMINAL}" \
    "${SURVIVING_ORIGINATED}")"
  settlements="$(bound_settlements "${SURVIVING_TERMINAL}")"
  failed="$(bound_terminations "${SURVIVING_TERMINAL}")"
  # The stray check above rejects a terminal record for work this control did
  # not originate. Its mirror — originated work with no terminal record at all
  # — is what lets a partial population pass: two permits held across C, one
  # settled, and the unsettled one simply unmentioned.
  unended="$(unended_work "${SURVIVING_ORIGINATED}" "${SURVIVING_TERMINAL}" "")"
  # The same population read off the nodes rather than off the driver. Every
  # check above this line is about work the driver both originated and reported
  # on, which leaves the ending of each permit as one party's account of its
  # own work; these are the holders' own records of closing those very permits.
  unauthored="$(unauthored_permits "${named_permits}" \
    "${SURVIVING_AUTHORED_ENDINGS}")"
  duplicated="$(duplicated_authored_permits "${named_permits}" \
    "${SURVIVING_AUTHORED_ENDINGS}")"
  unresolved="$(unresolved_authored_permits "${named_permits}" \
    "${SURVIVING_AUTHORED_ENDINGS}")"
  misended="$(misended_authored_permits "${named_permits}" \
    "${SURVIVING_AUTHORED_ENDINGS}" completed)"
  # And what each completion left behind, which is the claim this control is
  # really making: that the work in flight at C finished, producing the very
  # threshold output the driver reports it settled as.
  malformed="$(malformed_authored_records "${named_permits}" \
    "${SURVIVING_AUTHORED_ENDINGS}")"
  misevidenced="$(misevidenced_authored_permits "${named_permits}" \
    "${SURVIVING_AUTHORED_ENDINGS}")"
  # And what those completions dispatched beyond themselves. A side effect the
  # holder could not resolve is chain state this fleet may have created and
  # cannot account for, which every rung below would otherwise read past.
  unresolved_settlements="$(unresolved_authored_settlements \
    "${named_permits}" "${SURVIVING_AUTHORED_ENDINGS}")"
  # Every holder of this work, not only the ones the driver named. A holder it
  # omitted still published a record, and a result it recorded that disagrees
  # with the rest — or that no settlement claims — is exactly what a population
  # drawn from the driver's own report cannot see.
  result_population="${named_permits} $(authored_work_permits \
    "$(identity_works "${named_permits}")" "${named_permits}" \
    "${SURVIVING_AUTHORED_ENDINGS}")"
  disagreeing="$(disagreeing_authored_results "${result_population}" \
    "${SURVIVING_AUTHORED_ENDINGS}")"
  unclaimed="$(unclaimed_authored_results "${result_population}" \
    "${SURVIVING_AUTHORED_ENDINGS}" "${SURVIVING_TERMINAL}")"
  authored="$(authored_endings "${named_permits}" \
    "${SURVIVING_AUTHORED_ENDINGS}")"
  originated_permits="$(count_tokens \
    "$(permit_identities "${SURVIVING_ORIGINATED}")")"
  held_delta=""
  if [[ "${SURVIVING_LEGACY_COMPLETIONS_BEFORE}" =~ ^[0-9]+$ ]] &&
    [[ "${SURVIVING_LEGACY_COMPLETIONS_AFTER}" =~ ^[0-9]+$ ]] &&
    ((SURVIVING_LEGACY_COMPLETIONS_AFTER >=
      SURVIVING_LEGACY_COMPLETIONS_BEFORE)); then
    held_delta=$((SURVIVING_LEGACY_COMPLETIONS_AFTER -
      SURVIVING_LEGACY_COMPLETIONS_BEFORE))
  fi

  if ((SURVIVING_DRIVER_SUPPLIED == 0)); then
    block_step "${step}" "no PR4109_WORK_DRIVER was supplied, so no \
legacy-anchored ceremony was in flight when C passed and there is nothing to \
observe surviving it"
  elif ((SURVIVING_ORIGINATE_RC != 0)); then
    record_step "${step}" fail "the work driver exited \
[${SURVIVING_ORIGINATE_RC}] originating the legacy-anchored work that was to \
be held across C"
  elif [[ -z "${SURVIVING_ORIGINATED//[[:space:]]/}" ]]; then
    block_step "${step}" "the work driver exited cleanly but named no work it \
put on the chain before C, so nothing here identifies a permit that could \
have survived the crossing; an in-flight count says how many permits there \
were and not which work each one was issued for"
  elif [[ ! "${SURVIVING_HELD_BEFORE}" =~ ^[0-9]+$ ]] ||
    ((SURVIVING_HELD_BEFORE == 0)); then
    block_step "${step}" "the fleet held \
[${SURVIVING_HELD_BEFORE:-unreadable}] legacy ceremonies when C approached, \
so the work the driver named had already ended and this step would be about a \
ceremony that never met the crossing"
  elif ((SURVIVING_HELD_BEFORE != originated_permits)); then
    block_step "${step}" "the fleet held ${SURVIVING_HELD_BEFORE} legacy \
ceremonies when C approached, but the driver named ${originated_permits} \
permit(s) it put there ($(permit_identities "${SURVIVING_ORIGINATED}")); a \
count that does not match the named population leaves permits this step \
cannot identify crossing C beside the ones it can, and the verdict below \
would speak for those too"
  elif [[ "${SURVIVING_PERMITS_BEFORE}" == "unreadable on "* ]]; then
    block_step "${step}" "the fleet gates could not be asked which legacy \
permits they were holding when C approached (${SURVIVING_PERMITS_BEFORE}); a \
count of active legacy ceremonies says how many permits met the crossing and \
never which, so nothing here could follow one across it"
  elif [[ -n "${unheld_before}" ]]; then
    block_step "${step}" "the driver named ${unheld_before} as put on the \
chain before C, but no R1 gate reported holding it; a permit this step cannot \
find in the gate that issued it is one the driver's account alone vouches for"
  elif [[ -n "${unnamed_before}" ]]; then
    block_step "${step}" "the R1 gates held ${unnamed_before} when C \
approached, which this step did not originate; an unnamed legacy permit \
crossing beside the named ones is one the verdict below would speak for \
without ever having identified it"
  elif ((SURVIVING_PERMITS_AT_C_READ == 0)); then
    block_step "${step}" "the crossing step never reached the point where the \
fleet reported open_security_v2, so nothing observed whether the legacy \
permits named before C were still held once it passed"
  elif [[ "${SURVIVING_PERMITS_AT_C}" == "unreadable on "* ]]; then
    block_step "${step}" "the fleet gates could not be asked which legacy \
permits they still held once C passed (${SURVIVING_PERMITS_AT_C}); the \
crossing is exactly where a permit would be dropped, so an unread fleet there \
leaves the survival unobserved"
  elif [[ -n "${lost_at_c}" ]]; then
    record_step "${step}" fail "the R1 gates no longer held ${lost_at_c} when \
they reported open_security_v2, though this step put it on the chain before C \
and no terminal outcome had been asked for yet; a legacy permit must keep its \
mode across the crossing, not be dropped at it"
  elif [[ -n "${arrived_at_c}" ]]; then
    block_step "${step}" "the R1 gates held ${arrived_at_c} when they \
reported open_security_v2, which was neither in flight when this step named \
what it originated nor seeded for the quiescence control; the completion \
count below is fleet-wide, so a legacy permit that appeared only at the \
crossing can supply an increment no named permit earned"
  elif ((SURVIVING_TERMINAL_ASKED == 0)); then
    block_step "${step}" "the driver was never asked what became of the \
legacy work it held across C; a permit observed in flight before the crossing \
and never followed up is equally one that completed and one that was cut short"
  elif ((SURVIVING_TERMINAL_RC != 0)); then
    block_step "${step}" "the work driver exited [${SURVIVING_TERMINAL_RC}] \
reporting what became of the legacy work held across C, so its account stops \
wherever it failed"
  elif [[ -n "${stray}" ]]; then
    block_step "${step}" "the driver reported terminal outcomes for ${stray}, \
which this step did not originate before C with those transactions; an \
outcome for other work cannot stand for the work that was held"
  elif [[ -n "${failed}" ]]; then
    record_step "${step}" fail "the legacy work held across C came to nothing: \
${failed}; a legacy permit taken before C must be allowed to finish on the \
far side of it, not abandoned there"
  elif [[ -n "${unended}" ]]; then
    block_step "${step}" "the driver originated ${unended} before C and \
reported no terminal outcome for it; work held across the crossing and left \
unmentioned is equally work that finished and work that was cut short, and \
the settlements it did report cannot answer for it"
  elif [[ -z "${settlements}" ]]; then
    block_step "${step}" "the driver named no terminal outcome at all for the \
legacy work it originated before C, so nothing here says those permits \
finished rather than went unreported"
  elif [[ "${SURVIVING_AUTHORED_ENDINGS}" == "unreadable on "* ]]; then
    block_step "${step}" "the fleet gates could not be asked what became of \
the legacy permits they closed (${SURVIVING_AUTHORED_ENDINGS}); everything \
above this line is the account of the party that also originated the work, and \
without the holders' own records the crossing is reported rather than observed"
  elif [[ -n "${unauthored}" ]]; then
    block_step "${step}" "no R1 gate recorded an ending for ${unauthored}, \
though the driver named it as put on the chain before C and reported an \
outcome for it; a permit whose own holder will not say how it closed — never \
recorded, or forgotten from a bounded account — is one only the driver \
vouches for"
  elif [[ -n "${duplicated}" ]]; then
    block_step "${step}" "the R1 gates recorded more than one ending for \
${duplicated}; one permit ends once, so a second record is either a duplicate \
or two dispositions for one ceremony and neither can be read as the answer"
  elif [[ -n "${unresolved}" ]]; then
    record_step "${step}" fail "the R1 gates closed ${unresolved} without \
their ceremony owners recording any disposition; a legacy permit taken before \
C must be allowed to finish on the far side of it, and one whose holder cannot \
say where it went did not"
  elif [[ -n "${misended}" ]]; then
    record_step "${step}" fail "the R1 gates recorded ${misended} for permits \
this step held across C; a legacy permit taken before the crossing must be \
allowed to complete on the far side of it, not end quarantined or exhausted \
there"
  elif [[ -n "${malformed}" ]]; then
    block_step "${step}" "the node-authored account of the permits held across C stops \
short of what a permit's holder records — ${malformed} — so the reading \
names a disposition and nothing about what it left behind; a release \
publishing only the category cannot be reconciled against what the driver \
says settled"
  elif [[ -n "${misevidenced}" ]]; then
    record_step "${step}" fail "${misevidenced}; the gate pins each ceremony \
to the evidence class its result actually lives in, and a permit that crossed \
C and then claimed another class produced nothing this control can show for \
the crossing"
  elif [[ -n "${unresolved_settlements}" ]]; then
    block_step "${step}" "${unresolved_settlements}; the fleet may have left \
chain state behind that no node can name, and every reading below this is \
about work whose ending is accounted for — an unresolved side effect is for the \
offline audit to settle rather than for a step to read past"
  elif [[ -n "${disagreeing}" ]]; then
    record_step "${step}" fail "the holders of ${disagreeing} each recorded a \
completion naming a different result after C; a threshold ceremony has one \
output, so the work that crossed the cutover did not finish as one ceremony"
  elif [[ -n "${unclaimed}" ]]; then
    record_step "${step}" fail "${unclaimed}; work that survived C has to \
finish as the same threshold output on both accounts, and where the driver's \
settlement and the holder's own record name different ones, neither is \
evidence that the permit in flight at C is the one that completed"
  elif [[ ! "${SURVIVING_LEGACY_COMPLETIONS_BEFORE}" =~ ^[0-9]+$ ]] ||
    [[ ! "${SURVIVING_LEGACY_COMPLETIONS_AFTER}" =~ ^[0-9]+$ ]]; then
    block_step "${step}" "the fleet post-cutover legacy completion counter \
could not be read (${SURVIVING_LEGACY_COMPLETIONS_BEFORE:-unreadable} to \
${SURVIVING_LEGACY_COMPLETIONS_AFTER:-unreadable}); the driver account alone \
cannot say the completion happened under this fleet gate after C"
  elif ((SURVIVING_LEGACY_COMPLETIONS_AFTER <=
    SURVIVING_LEGACY_COMPLETIONS_BEFORE)); then
    record_step "${step}" fail "the driver settled ${settlements}, but no \
gate recorded a legacy completion after C \
(participation_legacy_completions_after_cutover_total still \
[${SURVIVING_LEGACY_COMPLETIONS_AFTER}]); work that settled without one did \
not finish on the far side of the crossing"
  elif ((held_delta != originated_permits)); then
    # A delta merely greater than zero lets one settlement plus any unrelated
    # legacy completion elsewhere in the fleet stand for the whole held
    # population. The counter has to move by exactly the permits this step put
    # there, or the increments it counted belong to ceremonies it never named.
    block_step "${step}" "the fleet gates recorded ${held_delta} legacy \
completion(s) at or after C, but this step held ${originated_permits} permit(s) \
across it ($(permit_identities "${SURVIVING_ORIGINATED}")); a counter that \
moved by a different amount counted completions this step did not originate, \
or missed ones it did"
  else
    STEP_PERMIT_MODES='"legacy"'
    record_step "${step}" pass "the R1 gates held exactly the legacy permits \
this step originated before C (${named_permits}), still held those same \
permits when they reported open_security_v2, and each holder then recorded \
closing its own permit completed (${authored}); the driver's account of the \
same permits settles them at ${settlements}, and the fleet gates recorded \
${held_delta} legacy completion(s) at or after the cutover block — one for \
each permit held across the crossing. A permit taken on the legacy side of C \
kept its identity and its mode across the crossing and was allowed to finish"
  fi
}

# Which R1 node plays which part in the single-release stage.
#
# Three of this stage's controls destroy every permit the node they act on is
# holding: the restart in step 4, the severed chain endpoint in step 7, and the
# stop in step 8's security-v2 half. Step 8's legacy half is the one control
# whose subject is a permit put on the chain before C and required to still be
# held when its node is told to stop, so it has to run on a node none of those
# three touched. That is the whole allocation: one node stays untouched from
# before the crossing until its drain, and the other absorbs everything
# destructive, in the order the steps run.
#
# The collision does not fail loudly if it is reintroduced — the seeded permit
# is simply gone by the time the drain looks for it and the step blocks with a
# reason that reads like a broken work driver — so the allocation is derived in
# one place and checked rather than repeated at four call sites.
SINGLE_RELEASE_LEGACY_NODE=""
SINGLE_RELEASE_VOLATILE_NODE=""

assign_single_release_nodes() {
  SINGLE_RELEASE_LEGACY_NODE="${REHEARSAL_R1_SERVICES[0]:-}"
  SINGLE_RELEASE_VOLATILE_NODE="${REHEARSAL_R1_SERVICES[1]:-}"

  [[ -n "${SINGLE_RELEASE_LEGACY_NODE}" ]] || return 1
  [[ -n "${SINGLE_RELEASE_VOLATILE_NODE}" ]] || return 1
  [[ "${SINGLE_RELEASE_LEGACY_NODE}" != "${SINGLE_RELEASE_VOLATILE_NODE}" ]]
}

stage_single_release() {
  REHEARSAL_GATE="single_release"
  stage_preflight
  initialize_rehearsal_run_identity

  if ! assign_single_release_nodes; then
    begin_step "the fleet can carry the single-release controls"
    block_step "the fleet can carry the single-release controls" "the R1 \
fleet is [${REHEARSAL_R1_SERVICES[*]:-empty}]; this stage needs one node it \
never restarts, severs, or stops before the legacy drain and a second one to \
absorb those controls, so it cannot be run as configured"
    return 0
  fi
  fleet_up "${REHEARSAL_PRIOR_SERVICE}" "${REHEARSAL_R1_SERVICES[@]}"
  verify_running_images "${R1_IMAGE_DIGEST}" "${REHEARSAL_R1_SERVICES[@]}"
  verify_running_images "${PRIOR_IMAGE_DIGEST}" "${REHEARSAL_PRIOR_SERVICE}"
  capture_r1_release_identity
  capture_r1_fleet_identity
  capture_cutover_roster_evidence_window

  # Step 1 and step 2 both run R1 nodes on legacy-anchored ceremonies beside
  # the prior binary. Whether the dependency's dual-mode transcripts have an
  # archived independent review decides whether the resulting record is
  # release-authoritative, and that is settled once by the acceptance
  # contract; it is not a reason for the fleet to refuse to run.
  begin_step "mixed prior/R1 pre-cutover compatibility controls"
  collect_precutover_work precutover-compatibility
  precutover_verdict "mixed prior/R1 pre-cutover compatibility controls" \
    "" "${PRECUTOVER_REQUIRED_CEREMONIES}" \
    "legacy-anchored ceremonies beside the prior binary"

  # The second step is the first one's claim carried to the work that takes
  # longest to finish: a wallet action holds its permit across signing and a
  # Bitcoin broadcast, so it is the case where a legacy anchor has to survive
  # the most.
  begin_step "representative pre-cutover work including the longest wallet action"
  collect_precutover_work precutover-representative
  precutover_verdict \
    "representative pre-cutover work including the longest wallet action" \
    "" "${PRECUTOVER_REQUIRED_CEREMONIES} tbtc_wallet_action" \
    "representative pre-cutover work including the longest wallet action"

  # The in-flight half of step 3 needs its subject on the chain while the
  # fleet is still below C, so the work is originated here and asked about
  # once the crossing step has established that C passed in-process.
  originate_surviving_legacy_work

  # So does step 8's legacy half, for the same reason and one step further on:
  # its subject has to still be held when the node is told to stop, long after
  # the crossing. Seeding it here is what makes it a permit the gate issued on
  # the legacy side of C rather than one a driver says it anchored there.
  seed_legacy_quiescence_work "${SINGLE_RELEASE_LEGACY_NODE}"

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
    # Read before anything else in this branch: the legacy permits held across
    # the crossing are what the next step decides on, and every reading taken
    # here costs the fleet blocks in which one of them could finish.
    observe_surviving_permits_at_cutover
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
  # passes: the in-flight safety property. Its work was put on the chain
  # before the crossing above; what became of it is asked here.
  begin_step "pre-cutover legacy work survives C and completes"
  resolve_surviving_legacy_work
  surviving_legacy_verdict

  # Open the last-readable preservation window before the first control that
  # destroys a process. All four signals are process-local: once the volatile
  # node restarts, no reading from the new process can say what the old one was
  # holding. Seed the whole fleet now, retain separately named pre-stop guard
  # and watched-stop readings in step 4, and then re-seed the replacement
  # process once it answers.
  initialize_quarantine_preservation_readings \
    "${REHEARSAL_R1_SERVICES[@]}"
  SINGLE_RELEASE_QUARANTINE_PRESERVATION_SAMPLING=1

  # Step 4. Mode must come from the canonical anchor and the current chain, so
  # a node that lost its process state entirely must land on the same answer.
  begin_step "restart across C derives mode from the chain, not from process state"
  local restarted="${SINGLE_RELEASE_VOLATILE_NODE}"
  local restart_step="restart across C derives mode from the chain, not from process state"
  local restart_assertion="a restarted node derives its mode from the canonical anchor and the current chain"
  local restart_grace=""
  local restarted_container=""
  local restart_followups_safe=1
  local restart_step_outcome=""
  local restart_stop_authorized=0
  if ! restart_grace="$(manifest_termination_grace)"; then
    restart_step_outcome="blocked"
    block_step "${restart_step}" "the reviewed release manifest did not provide \
a positive termination grace, so ${restarted} was not stopped under an \
auditable bound; the node remains running and the later independent controls \
may still be evaluated"
    record_assertion "${restart_assertion}" false "${restart_step}"
  elif ! restarted_container="$(
    compose ps --all --quiet "${restarted}" 2>/dev/null
  )" || [[ -z "${restarted_container}" ]]; then
    restart_step_outcome="blocked"
    block_step "${restart_step}" "${restarted} has no inspectable container; \
the control cannot prove which old process it stopped or how that process \
exited, so it issued no stop and left the node available to the later \
independent controls"
    record_assertion "${restart_assertion}" false "${restart_step}"
  else
    # The first sample is a guard, not merely the beginning of the watched
    # account. Read and archive it before issuing any signal: an unreadable
    # account or a live incomplete output leaves the old process running.
    sample_quarantine_preservation_signals "${restarted}"
    local pre_stop_account=""
    local pre_stop_tbtc_failures="unreadable"
    local pre_stop_beacon_failures="unreadable"
    local pre_stop_tbtc_incomplete="unreadable"
    local pre_stop_beacon_incomplete="unreadable"
    local pre_stop_sample_readable="${QUARANTINE_PRESERVATION_SAMPLE_READABLE}"
    local pre_stop_readable="${pre_stop_sample_readable}"
    if pre_stop_account="$(
      quarantine_preservation_reading_for "${restarted}"
    )"; then
      read -r _ pre_stop_tbtc_failures pre_stop_beacon_failures \
        pre_stop_tbtc_incomplete pre_stop_beacon_incomplete \
        _ \
        <<<"${pre_stop_account}"
    else
      pre_stop_readable=0
    fi
    if ! append_quarantine_preservation_gauges \
      "${restarted}" "${RESTART_PRE_STOP_NAMESPACE}" \
      "${pre_stop_sample_readable}"; then
      pre_stop_readable=0
    fi

    if ((pre_stop_readable == 0)); then
      restart_step_outcome="blocked"
      block_step "${restart_step}" "${restarted} did not publish all four \
numeric quarantine-preservation signals at the pre-stop guard (tBTC failures \
${pre_stop_tbtc_failures}, beacon failures ${pre_stop_beacon_failures}, tBTC \
incomplete ${pre_stop_tbtc_incomplete}, beacon incomplete \
${pre_stop_beacon_incomplete}); no stop was issued, the old process remains \
the source of truth, and the later independent controls may still be evaluated \
against it"
      record_assertion "${restart_assertion}" false "${restart_step}"
    elif ((pre_stop_tbtc_incomplete > 0 || \
      pre_stop_beacon_incomplete > 0)); then
      restart_step_outcome="fail"
      record_step "${restart_step}" fail "${restarted} reported live incomplete \
quarantine output at the pre-stop guard (tBTC \
${pre_stop_tbtc_incomplete}, beacon ${pre_stop_beacon_incomplete}; \
write-grace histories ${pre_stop_tbtc_failures}/\
${pre_stop_beacon_failures}); no stop was issued, so the process that may still \
complete preservation remains live for the later independent controls"
      record_assertion "${restart_assertion}" false "${restart_step}"
    else
      restart_stop_authorized=1
    fi

    if ((restart_stop_authorized == 1)); then
      # `compose restart` blocks across the entire stop and erases the only
      # process that can report a preservation failure during its drain. Split
      # the operation: watch the old process while Compose stops it under the
      # manifest's reviewed service-manager grace, inspect that exact stopped
      # container, and only then allow the replacement process to start.
      compose stop --timeout "${restart_grace}" "${restarted}" &
      local restart_stop_pid=$!
      local restart_watched_sample_read_mask=0
      while kill -0 "${restart_stop_pid}" 2>/dev/null; do
        sample_quarantine_preservation_signals "${restarted}"
        # Retain this exact response whenever it carried at least one signal,
        # including a node-authored missing field, rather than OR-ing
        # freshness from an earlier response. A failed /metrics fetch carries
        # no information and cannot erase an earlier complete account merely
        # because the separate diagnostics endpoint still answers.
        if ((QUARANTINE_PRESERVATION_SAMPLE_READ_MASK > 0)); then
          restart_watched_sample_read_mask="\
${QUARANTINE_PRESERVATION_SAMPLE_READ_MASK}"
        fi
        if ! node_reachable "${restarted}"; then
          # Diagnostics disappearance ends the watched window. An
          # all-unreadable post-exit metrics fetch has already been ignored,
          # so the last response that actually carried a signal stands.
          break
        fi
        sleep 2
      done

      local restart_stop_rc=0
      if wait "${restart_stop_pid}"; then
        restart_stop_rc=0
      else
        restart_stop_rc=$?
      fi
      # End the watched window at the stop itself. If the endpoint has already
      # disappeared the sampler retains its last numeric, node-authored values;
      # it never substitutes replacement-process zeros.
      sample_quarantine_preservation_signals "${restarted}"
      if ((QUARANTINE_PRESERVATION_SAMPLE_READ_MASK > 0)); then
        restart_watched_sample_read_mask="\
${QUARANTINE_PRESERVATION_SAMPLE_READ_MASK}"
      fi

      local pre_restart_account=""
      local pre_restart_tbtc_failures="unreadable"
      local pre_restart_beacon_failures="unreadable"
      local pre_restart_tbtc_incomplete="unreadable"
      local pre_restart_beacon_incomplete="unreadable"
      local pre_restart_readable=1
      if pre_restart_account="$(
        quarantine_preservation_reading_for "${restarted}"
      )"; then
        read -r _ pre_restart_tbtc_failures \
          pre_restart_beacon_failures pre_restart_tbtc_incomplete \
          pre_restart_beacon_incomplete _ \
          <<<"${pre_restart_account}"
      else
        pre_restart_readable=0
      fi
      if ! append_quarantine_preservation_gauges \
        "${restarted}" "${RESTART_WATCHED_STOP_NAMESPACE}" "" \
        "${restart_watched_sample_read_mask}"; then
        pre_restart_readable=0
      fi
      if ! quarantine_preservation_incomplete_fields_read \
        "${restart_watched_sample_read_mask}"; then
        pre_restart_readable=0
      fi

      # Compose can report a successful stop after Docker exhausted the timeout
      # and killed the process. Read the old container itself before `start`
      # resets its state, and archive the code beside that process's last
      # preservation readings. Only exit zero is a natural, auditable stop.
      local restart_container_exit_code=""
      local restart_container_running=""
      restart_container_exit_code="$(
        docker inspect --format '{{.State.ExitCode}}' \
          "${restarted_container}" 2>/dev/null || true
      )"
      restart_container_running="$(
        docker inspect --format '{{.State.Running}}' \
          "${restarted_container}" 2>/dev/null || true
      )"
      if [[ "${restart_container_exit_code}" =~ ^[0-9]+$ ]]; then
        STEP_GAUGES="${STEP_GAUGES}${STEP_GAUGES:+,}\
\"${restarted}.${RESTART_WATCHED_STOP_NAMESPACE}.\
${RESTART_CONTAINER_EXIT_CODE_SUFFIX}\":\
${restart_container_exit_code}"
      fi

      local restart_start_rc=0
      local restarted_state="" restarted_reachable=0
      if ((restart_stop_rc != 0)); then
        if [[ "${restart_container_running}" == "false" ]]; then
          recover_stopped_restart_subject "${restarted}" || true
          restart_followups_safe="${RESTART_RECOVERY_SAFE}"
        else
          RESTART_RECOVERY_NOTE=" The container was not confirmed stopped \
(running [${restart_container_running:-unreadable}]); no recovery start was \
attempted."
        fi
        restart_step_outcome="fail"
        record_step "${restart_step}" fail "the watched stop of ${restarted} \
exited [${restart_stop_rc}] under the reviewed ${restart_grace}-second \
termination grace.${RESTART_RECOVERY_NOTE}"
        record_assertion "${restart_assertion}" false "${restart_step}"
      elif [[ "${restart_container_running}" != "false" ]]; then
        restart_step_outcome="blocked"
        block_step "${restart_step}" "the old ${restarted} container did not \
report a stopped state after Compose returned (running \
[${restart_container_running:-unreadable}]); starting a replacement would \
overlap an unaccounted-for candidate process, so no recovery start was \
attempted"
        record_assertion "${restart_assertion}" false "${restart_step}"
      elif [[ ! "${restart_container_exit_code}" =~ ^[0-9]+$ ]]; then
        recover_stopped_restart_subject "${restarted}" || true
        restart_followups_safe="${RESTART_RECOVERY_SAFE}"
        restart_step_outcome="blocked"
        block_step "${restart_step}" "the old ${restarted} container published \
no numeric exit status after its watched stop; a truncated stop is a refusal, \
not evidence of a clean process restart.${RESTART_RECOVERY_NOTE}"
        record_assertion "${restart_assertion}" false "${restart_step}"
      elif ((restart_container_exit_code != 0)); then
        recover_stopped_restart_subject "${restarted}" || true
        restart_followups_safe="${RESTART_RECOVERY_SAFE}"
        restart_step_outcome="fail"
        record_step "${restart_step}" fail "the old ${restarted} process exited \
[${restart_container_exit_code}] under the reviewed ${restart_grace}-second \
termination grace; the replacement was refused because a killed or otherwise \
unclean stop cannot prove preservation completed naturally (last watched tBTC \
and beacon incomplete-output readings ${pre_restart_tbtc_incomplete}/\
${pre_restart_beacon_incomplete}).\
${RESTART_RECOVERY_NOTE}"
        record_assertion "${restart_assertion}" false "${restart_step}"
      elif ((pre_restart_readable == 0)); then
        recover_stopped_restart_subject "${restarted}" || true
        restart_followups_safe="${RESTART_RECOVERY_SAFE}"
        restart_step_outcome="blocked"
        block_step "${restart_step}" "${restarted} did not provide a complete \
watched-stop quarantine-preservation account: all four retained values must be \
numeric and both incomplete-output fields must have been re-read in the final \
sample that obtained any watched-stop field (read mask \
${restart_watched_sample_read_mask}); the old process was the last source that \
could say whether it was holding generated output, so the restart control was \
refused rather than treating carried values as fresh.\
${RESTART_RECOVERY_NOTE}"
        record_assertion "${restart_assertion}" false "${restart_step}"
      elif ((pre_restart_tbtc_incomplete > 0 || pre_restart_beacon_incomplete > 0)); then
        recover_stopped_restart_subject "${restarted}" || true
        restart_followups_safe="${RESTART_RECOVERY_SAFE}"
        restart_step_outcome="fail"
        record_step "${restart_step}" fail "${restarted} reported live \
incomplete quarantine output during its watched stop (tBTC \
${pre_restart_tbtc_incomplete}, beacon ${pre_restart_beacon_incomplete}); the \
restart control was refused because the generated output was not yet fully \
durable when the old process disappeared.${RESTART_RECOVERY_NOTE}"
        record_assertion "${restart_assertion}" false "${restart_step}"
      else
        compose start "${restarted}" || restart_start_rc=$?

        local deadline
        deadline=$((SECONDS + NODE_REACHABILITY_TIMEOUT_SECONDS))
        if ((restart_start_rc == 0)); then
          until node_reachable "${restarted}"; do
            if ((SECONDS >= deadline)); then
              break
            fi
            sleep 5
          done
        fi

        if ((restart_start_rc == 0)) && node_reachable "${restarted}"; then
          restarted_reachable=1
          # This is a new process-local account. Re-seed it rather than letting
          # the old process's retained values stand for a process that did not
          # publish them; the separately namespaced pre-restart gauges preserve
          # the old process's watched drain account.
          sample_quarantine_preservation_signals "${restarted}" 1
          restarted_state="$(
            participation_field "${restarted}" gate_state 2>/dev/null || true
          )"
          observe_canonical_block "${restarted}"
          observe_gate_gauges "${restarted}"
        fi

        if ((restart_start_rc != 0)); then
          restart_followups_safe=0
          restart_step_outcome="fail"
          record_step "${restart_step}" fail "the cleanly stopped ${restarted} \
container could not be started again (Compose exited \
[${restart_start_rc}]); the remaining single-release controls were not \
evaluated against an unavailable node"
          record_assertion "${restart_assertion}" false "${restart_step}"
        elif ((restarted_reachable == 0)); then
          restart_followups_safe=0
          restart_step_outcome="fail"
          record_step "${restart_step}" fail "${restarted} did not become \
reachable within ${NODE_REACHABILITY_TIMEOUT_SECONDS} seconds after its clean \
watched stop and start; the remaining single-release controls were not \
evaluated against an unavailable node"
          record_assertion "${restart_assertion}" false "${restart_step}"
        elif [[ "${restarted_state}" == "open_security_v2" ]]; then
          restart_step_outcome="pass"
          record_step "${restart_step}" pass "${restarted} returned to \
open_security_v2 after a full restart with no watcher history and no wall-clock \
input; its old process exited zero under the reviewed ${restart_grace}-second \
termination grace and reported zero live incomplete outputs throughout the \
watched stop (prior tBTC/beacon write-grace exhaustion counters \
${pre_restart_tbtc_failures}/${pre_restart_beacon_failures})"
          record_assertion "${restart_assertion}" true "${restart_step}"
        else
          restart_step_outcome="fail"
          record_step "${restart_step}" fail "${restarted} reported \
[${restarted_state:-unreadable}] after restart"
          record_assertion "${restart_assertion}" false "${restart_step}"
        fi
      fi
    fi
  fi

  # A stop-authorized non-passing path is allowed to coexist with later
  # independent evidence only while the node those controls target is actually
  # available. Give that post-step check the same bounded readiness window as a
  # normal start. The passing path already proved bounded reachability, and the
  # four pre-stop refusal paths issued no stop, so neither is probed here.
  if ((restart_stop_authorized == 1)) &&
    [[ "${restart_step_outcome}" != "pass" ]] &&
    ((restart_followups_safe == 1)); then
    local restart_followup_probe_deadline
    restart_followup_probe_deadline=$((SECONDS +
      NODE_REACHABILITY_TIMEOUT_SECONDS))
    until node_reachable "${restarted}"; do
      if ((SECONDS >= restart_followup_probe_deadline)); then
        break
      fi
      sleep 5
    done
    if ! node_reachable "${restarted}"; then
      restart_followups_safe=0
    fi
  fi
  if ((restart_stop_authorized == 1 && restart_followups_safe == 0)); then
    note "the remaining single-release controls were not evaluated because \
${restarted} was unavailable after the control issued its watched stop and \
recorded outcome [${restart_step_outcome:-unrecorded}]"
    conclude_rehearsal
  fi

  # Step 5. The prior binary is still reachable and still speaking the legacy
  # protocol after C. That it fails closed against the R1 fleet, and that the
  # R1 fleet names its operator, is exactly what the negative control proves —
  # and it needs no legacy capability on the R1 side, only refusals.
  begin_step "post-cutover straggler fails closed and enters the roster"
  local observer="${REHEARSAL_R1_SERVICES[0]}"
  local operators_before operators_after roster metric
  STRAGGLER_BEFORE=()
  STRAGGLER_AFTER=()
  for metric in "${ANNOUNCER_CUTOVER_METRICS[@]}"; do
    STRAGGLER_BEFORE+=("$(metric_value "${observer}" "${metric}" ||
      printf '')")
  done
  operators_before="$(roster_operators "${observer}")"
  # Read from the straggler itself while it is still on the network, because
  # the operator this control is about is the one the prior node signs as —
  # not one named in a configuration file the roster was never compared to.
  STRAGGLER_EXPECTED_OPERATOR="$(node_operator_address \
    "${REHEARSAL_PRIOR_SERVICE}" 2>/dev/null || printf '')"
  STRAGGLER_DRIVER_SUPPLIED=0
  STRAGGLER_DRIVER_RC=0
  STRAGGLER_DRIVER_TX=0
  STRAGGLER_BOUND=""
  if [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
    STRAGGLER_DRIVER_SUPPLIED=1
    run_work_driver post-cutover-straggler || true
    STRAGGLER_DRIVER_RC="${WORK_DRIVER_RC}"
    STRAGGLER_DRIVER_TX="${WORK_DRIVER_TX_COUNT}"
    STRAGGLER_BOUND="${WORK_DRIVER_BOUND_RESULTS}"
  fi
  for metric in "${ANNOUNCER_CUTOVER_METRICS[@]}"; do
    STRAGGLER_AFTER+=("$(metric_value "${observer}" "${metric}" || printf '')")
  done
  operators_after="$(roster_operators "${observer}")"
  roster="$(roster_snapshot "${observer}")"
  observe_gate_gauges "${observer}"
  STEP_STATE_CHECKSUMS="\"roster_snapshot_sha256\":\"$(printf '%s' "${roster}" |
    hash_stdin)\""

  # The roster object exists on every node from startup and is non-null with
  # an empty peer list, so its presence proves nothing. What the negative
  # control is about is a specific operator becoming named blocking evidence,
  # so the two readings are differenced: an operator this node had not seen
  # before the driven post-C ceremony.
  local new_operators
  new_operators="$(comm -13 <(printf '%s' "${operators_before}") \
    <(printf '%s' "${operators_after}") | tr '\n' ' ')"
  new_operators="${new_operators% }"

  straggler_control_verdict "${new_operators}"

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
  HOMOGENEOUS_DRIVER_SUPPLIED=0
  HOMOGENEOUS_DRIVER_RC=0
  HOMOGENEOUS_TX=0
  HOMOGENEOUS_RESULTS=""
  HOMOGENEOUS_BOUND=""
  HOMOGENEOUS_ORIGINATED=""
  HOMOGENEOUS_AUTHORED_ENDINGS=""
  HOMOGENEOUS_NEW_OPERATORS=""

  # A zero legacy counter is true of a fleet that ran nothing at all, so the
  # positive control has to be positive about something: permits actually
  # issued under security-v2 while the driver ran, and a ceremony the driver
  # watched finish. Every count is taken before and after so it is this step's
  # ceremonies being counted rather than the crossing's, and summed across the
  # fleet because a control that only watched one node would pass on a fleet
  # where the others sat idle.
  #
  # Both permit counters are cumulative and both are read before as well as
  # after. A legacy count compared against zero would be a statement about
  # everything the fleet ever did, so the pre-C legacy controls this gate also
  # requires would make this step fail the moment they start working — on
  # their permits, taken before C, not on any sighting after it.
  HOMOGENEOUS_PERMITS_BEFORE="$(fleet_metric_total \
    participation_mode_security_v2_total)"
  HOMOGENEOUS_LEGACY_BEFORE="$(fleet_metric_total \
    participation_mode_legacy_total)"
  # The sighting half of the step's own name, read where a sighting would
  # appear rather than inferred from a permit counter that is about what this
  # fleet took on. The straggler was quarantined by the step above, so any
  # recognition here is a legacy peer the control claims is not there.
  HOMOGENEOUS_SIGHTINGS_BEFORE="$(fleet_metric_total \
    announcer_cross_format_peer_total)"
  local operators_before_homogeneous operators_after_homogeneous
  operators_before_homogeneous="$(fleet_roster_operators)"

  if [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
    HOMOGENEOUS_DRIVER_SUPPLIED=1
    run_work_driver homogeneous-security-v2 || true
    HOMOGENEOUS_DRIVER_RC="${WORK_DRIVER_RC}"
    HOMOGENEOUS_TX="${WORK_DRIVER_TX_COUNT}"
    HOMOGENEOUS_RESULTS="${WORK_DRIVER_CEREMONY_RESULTS}"
    HOMOGENEOUS_BOUND="${WORK_DRIVER_BOUND_RESULTS}"
    HOMOGENEOUS_ORIGINATED="${WORK_DRIVER_ORIGINATED_WORK}"
    # Asked after the driver has reported, so every permit it says was issued
    # for this work has had its holder's own record written before the reading.
    HOMOGENEOUS_AUTHORED_ENDINGS="$(fleet_terminal_outcomes)"
  fi

  HOMOGENEOUS_PERMITS_AFTER="$(fleet_metric_total \
    participation_mode_security_v2_total)"
  HOMOGENEOUS_LEGACY_AFTER="$(fleet_metric_total \
    participation_mode_legacy_total)"
  HOMOGENEOUS_SIGHTINGS_AFTER="$(fleet_metric_total \
    announcer_cross_format_peer_total)"
  operators_after_homogeneous="$(fleet_roster_operators)"
  HOMOGENEOUS_NEW_OPERATORS="$(comm -13 \
    <(printf '%s' "${operators_before_homogeneous}") \
    <(printf '%s' "${operators_after_homogeneous}") | tr '\n' ' ')"
  HOMOGENEOUS_NEW_OPERATORS="${HOMOGENEOUS_NEW_OPERATORS% }"
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    observe_gate_gauges "${service}"
  done

  homogeneous_control_verdict

  # Refresh the window opened before the restart while both current processes
  # answer. The clock-failure control cancels every held permit on its node,
  # and each quiescence control may reach its forced deadline, so their affected
  # nodes continue to be sampled throughout those destructive windows. The
  # verdict is emitted only after both quiescence controls, but before the
  # fleet-stop barrier makes any remaining endpoint unreadable.
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    sample_quarantine_preservation_signals "${service}"
  done

  # Step 7. Severing a node from the chain endpoint is a real clock failure:
  # the gate's synchronous read fails, and the release's contract is that it
  # refuses new work and cancels what it holds rather than guessing a side of
  # C.
  begin_step "clock failure quarantines work rather than guessing a mode"
  local clock_node="${SINGLE_RELEASE_VOLATILE_NODE}"

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
  sample_quarantine_preservation_signals "${clock_node}"

  # The refusal half of the contract, attempted rather than inferred. Until
  # something asks this gate to start work while it cannot read the chain, an
  # unchanged permit counter says only that nothing was offered — which is
  # what a node holding no work looks like too. The node is severed from the
  # chain but still on the protocol network, so work originated now reaches it
  # as peer traffic and the gate is what decides whether it joins.
  CLOCK_REFUSAL_ATTEMPTED=0
  CLOCK_OFFER_FAILED=0
  CLOCK_OFFER_RC=""
  if [[ -n "${PR4109_WORK_DRIVER:-}" && "${CLOCK_STATE}" == "clock_unavailable" ]]; then
    run_work_driver clock-failure-refusal || true
    # Only a driver that exited cleanly and named the transactions it submitted
    # has offered this gate anything. A driver that failed, or one that
    # originated nothing, leaves the node in the state a node nobody asked is
    # in — and that state is what the rest of this ladder must not read as a
    # refusal.
    if driver_offered_work; then
      CLOCK_REFUSAL_ATTEMPTED=1
    else
      CLOCK_OFFER_FAILED=1
      CLOCK_OFFER_RC="${WORK_DRIVER_RC}"
    fi
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

  # A clock failure has to be recoverable, not merely survivable, and this
  # stage depends on that concretely: the security-v2 quiescence half below
  # drains this same node. Waiting for its gate to name a side of C again is
  # what makes that next step's subject a working gate instead of a hopeful
  # one, and the reading is kept so the step can say so rather than blame the
  # drain for a node that never came back.
  CLOCK_RECOVERED_STATE=""
  deadline=$((SECONDS + 300))
  while :; do
    CLOCK_RECOVERED_STATE="$(participation_field "${clock_node}" gate_state \
      2>/dev/null || true)"
    [[ "${CLOCK_RECOVERED_STATE}" == "open_security_v2" ]] && break
    ((SECONDS >= deadline)) && break
    sleep 5
  done
  observe_gate_gauges "${clock_node}"
  sample_quarantine_preservation_signals "${clock_node}"

  clock_failure_verdict

  # Step 8. Quiescence must hold both an in-flight legacy permit and an
  # in-flight security-v2 permit. Both halves run the same control over a
  # different permit population, on a different node: the security-v2 half
  # stops the node it drains, so the legacy half cannot be asked of it.
  begin_step "quiescence with an in-flight security-v2 permit"
  if [[ "${CLOCK_RECOVERED_STATE}" != "open_security_v2" ]]; then
    # The node this half drains is the one the clock-failure step severed. A
    # gate still reporting clock_unavailable refuses everything, so a drain
    # observed on it would show an empty node and read as a clean quiescence.
    block_step "quiescence with an in-flight security-v2 permit" \
      "${SINGLE_RELEASE_VOLATILE_NODE} reported \
[${CLOCK_RECOVERED_STATE:-unreadable}] rather than open_security_v2 after its \
chain endpoint was restored; a gate that has not recovered refuses work for \
that reason and its drain says nothing about quiescence"
    record_assertion \
      "graceful quiescence starts no new work and lets held permits finish" \
      false "quiescence with an in-flight security-v2 permit"
  else
    run_quiescence_control "${SINGLE_RELEASE_VOLATILE_NODE}" \
      "quiescence with an in-flight security-v2 permit" \
      "graceful quiescence starts no new work and lets held permits finish" \
      security-v2 active_security_v2_ceremonies \
      participation_mode_security_v2_total quiesce
  fi

  # The legacy half needs a permit anchored below C still in flight after it,
  # which the gate issues on the anchor rather than on the current height. This
  # step runs after the crossing, so its subject is the permit seeded before it
  # and observed in the issuing gate while the fleet was still on the legacy
  # side; the control reads the anchors it was handed and refuses to decide
  # when they are not legacy-anchored, rather than taking the phase name for
  # the permit's mode. The node is the one nothing in this stage has restarted,
  # severed, or stopped, which is why the seeded permit is still there to drain.
  begin_step "quiescence with an in-flight legacy permit"
  run_quiescence_control "${SINGLE_RELEASE_LEGACY_NODE}" \
    "quiescence with an in-flight legacy permit" \
    "" legacy active_legacy_ceremonies \
    participation_mode_legacy_total quiesce-legacy "${QUIESCE_SEEDED_WORK}"

  # Take one final pass over nodes that remain live because a control blocked
  # before issuing its stop. For nodes that already drained, the sampler keeps
  # their last numeric values rather than replacing them with an invented zero.
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    sample_quarantine_preservation_signals "${service}"
  done
  SINGLE_RELEASE_QUARANTINE_PRESERVATION_SAMPLING=0

  begin_step "quarantine preservation is complete through quiescence"
  quarantine_preservation_verdict \
    "single-release quiescence loses no generated signer output to an \
unwritable quarantine namespace"

  # This gate ends where the next one begins. A rollback rehearsal's whole
  # subject is that no prior binary participates while a release candidate can
  # still act, and a cutover fleet left running is a release candidate that can
  # still act — on the same rehearsal chain, whatever compose project it
  # belongs to. Stopping it is part of this gate rather than of the orchestrator
  # around it, because a stage that failed halfway must not leave the next one
  # measuring a barrier against a fleet nobody accounted for.
  begin_step "the cutover fleet leaves no release candidate running"
  compose stop --timeout "$(manifest_termination_grace)" \
    "${REHEARSAL_PRIOR_SERVICE}" "${REHEARSAL_R1_SERVICES[@]}" || true
  read_candidate_inventory
  candidate_barrier_verdict \
    "the cutover fleet leaves no release candidate running" \
    "a finished cutover rehearsal leaves no candidate able to act"

  conclude_rehearsal
}

stage_rollback() {
  REHEARSAL_GATE="rollback"
  require_env STORAGE_SNAPSHOT_DIR
  stage_preflight
  initialize_rehearsal_run_identity
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
  capture_r1_fleet_identity

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
  ROLLBACK_DRIVER_SUPPLIED=0
  ROLLBACK_DRIVER_RC=0
  ROLLBACK_DRIVER_TX=0
  ROLLBACK_ORIGINATED=""
  ROLLBACK_ORIGINATED_WORK=""
  if [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
    ROLLBACK_DRIVER_SUPPLIED=1
    run_work_driver rollback-inflight || true
    ROLLBACK_DRIVER_RC="${WORK_DRIVER_RC}"
    ROLLBACK_DRIVER_TX="${WORK_DRIVER_TX_COUNT}"
    ROLLBACK_ORIGINATED="${WORK_DRIVER_ORIGINATED}"
    ROLLBACK_ORIGINATED_WORK="${WORK_DRIVER_ORIGINATED_WORK}"
  fi

  # The permits the fleet is actually holding as the stop is issued. This is
  # what makes the drain below a statement about work in flight rather than
  # about idle processes exiting, and it is read after the driver has run and
  # before anything is stopped, because that is the only moment it describes.
  ROLLBACK_INFLIGHT="$(fleet_gauge_total active_security_v2_ceremonies)"
  STEP_GAUGES="${STEP_GAUGES}${STEP_GAUGES:+,}\
\"fleet_active_security_v2_ceremonies\":\"${ROLLBACK_INFLIGHT}\""

  # The same moment, read per node rather than summed. A fleet total says how
  # much work was in flight; only a per-node reading can follow the permits one
  # node held to what became of them, and the reconciliation below is about
  # each permit rather than about the size of the population.
  local held_at_stop=() forced_before=() forced_after=() final_active=()
  local authored_endings=()
  local svc reading
  initialize_quarantine_preservation_readings \
    "${REHEARSAL_R1_SERVICES[@]}"
  for svc in "${REHEARSAL_R1_SERVICES[@]}"; do
    # "unread" rather than empty, because a node that answered with nothing yet
    # closed also has an empty list; the reconciliation has to tell a node it
    # could not ask from one that ended nothing.
    authored_endings+=("unread")
    reading="$(participation_field "${svc}" active_security_v2_ceremonies \
      2>/dev/null || printf 'unreadable')"
    [[ "${reading}" =~ ^[0-9]+$ ]] || reading="unreadable"
    held_at_stop+=("${reading}")
    # Seeded with the reading at the stop so a node that never answers again
    # reconciles against what it was holding rather than against a zero nobody
    # observed.
    final_active+=("${reading}")

    reading="$(metric_value "${svc}" \
      participation_quiesce_forced_aborts_total 2>/dev/null ||
      printf 'unreadable')"
    [[ "${reading}" =~ ^[0-9]+$ ]] || reading="unreadable"
    forced_before+=("${reading}")
    forced_after+=("${reading}")
  done

  # The grace comes out of the reviewed manifest, which the Go drift test
  # pins to the compiled bounds and the compose file's stop_grace_period to.
  # A number restated here would go on stopping nodes under the old ceiling
  # the first time those bounds moved, and a node SIGKILLed mid-drain cannot
  # evidence natural completion.
  local grace
  grace="$(manifest_termination_grace)"
  ROLLBACK_GRACE="${grace}"

  reset_prior_drain_samples
  sample_prior_absence

  # The instant the stop is issued, so the audit's quarantine records can be
  # read as this drain's rather than as whatever the namespace has accumulated.
  # Taken from the same runtime the manifest is parsed with, at millisecond
  # resolution, because a record written in the same second as a whole-second
  # stamp would otherwise be indistinguishable from one written before it.
  ROLLBACK_DRAIN_SINCE="$(node -e \
    'process.stdout.write(new Date().toISOString())')"

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
    sample_prior_absence
    # Each node's own drain, sampled while it can still be asked. The last
    # readable value stands: a node that has stopped answering cannot report
    # that it finished, and its last reading is what it was holding when it
    # went.
    #
    # What it was holding and what it recorded about the permits it let go of
    # come out of one response, because the interesting node is the one that
    # closes its last permit and exits: asked separately it answers the count
    # and not the endings, and the reconciliation would then read a drained
    # node beside the ending list from before that permit closed.
    local idx=0 snapshot_now active_now forced_now
    for svc in "${REHEARSAL_R1_SERVICES[@]}"; do
      if snapshot_now="$(service_gate_snapshot "${svc}" \
        active_security_v2_ceremonies 2>/dev/null)"; then
        active_now="$(snapshot_field "${snapshot_now}" active)"
        if [[ "${active_now}" =~ ^[0-9]+$ ]]; then
          final_active[idx]="${active_now}"
        fi
        # Overwritten rather than accumulated: the account only grows as
        # permits close, so the last whole reading has every permit that ended
        # in this window.
        snapshot_now="$(snapshot_field "${snapshot_now}" outcomes)"
        authored_endings[idx]="${snapshot_now:-none}"
      fi
      forced_now="$(metric_value "${svc}" \
        participation_quiesce_forced_aborts_total 2>/dev/null || printf '')"
      if [[ "${forced_now}" =~ ^[0-9]+$ ]]; then
        forced_after[idx]="${forced_now}"
      fi
      sample_quarantine_preservation_signals "${svc}"
      idx=$((idx + 1))
    done
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
  # earlier. Endpoints that already stopped keep their last numeric node-
  # authored values rather than becoming invented zeros.
  sample_prior_absence
  for svc in "${REHEARSAL_R1_SERVICES[@]}"; do
    sample_quarantine_preservation_signals "${svc}"
  done

  # The accounting the reconciliation step reads, assembled once the drain is
  # over. The forced-abort figure is the delta across the drain rather than the
  # node's lifetime total: aborts this rehearsal's earlier steps provoked are
  # not permits this drain force-canceled.
  ROLLBACK_NODE_ACCOUNTS=""
  ROLLBACK_NODE_ENDINGS=""
  local pos=0 forced_delta
  for svc in "${REHEARSAL_R1_SERVICES[@]}"; do
    if [[ "${forced_before[${pos}]}" =~ ^[0-9]+$ ]] &&
      [[ "${forced_after[${pos}]}" =~ ^[0-9]+$ ]] &&
      ((forced_after[pos] >= forced_before[pos])); then
      forced_delta=$((forced_after[pos] - forced_before[pos]))
    else
      forced_delta="unreadable"
    fi
    ROLLBACK_NODE_ACCOUNTS="${ROLLBACK_NODE_ACCOUNTS}\
${ROLLBACK_NODE_ACCOUNTS:+$'\n'}${svc} ${held_at_stop[${pos}]} \
${forced_delta} ${final_active[${pos}]}"
    # Kept as its own listing rather than appended to the accounting line: the
    # endings carry spaces, and the accounting is read field by field.
    ROLLBACK_NODE_ENDINGS="${ROLLBACK_NODE_ENDINGS}\
${ROLLBACK_NODE_ENDINGS:+$'\n'}${svc} ${authored_endings[${pos}]}"
    pos=$((pos + 1))
  done

  ROLLBACK_DRAIN_RC="${drain_rc}"
  rollback_drain_verdict

  begin_step "quarantine preservation is complete through quiescence"
  quarantine_preservation_verdict \
    "rollback quiescence loses no generated signer output to an unwritable \
quarantine namespace"

  begin_step "no prior binary starts during quiescence"
  prior_absence_verdict "no prior binary starts during quiescence" \
    "no prior binary participates before every R1 node is down"

  # Step 3. A forced deadline in an isolated case, so the audited quarantine
  # path is exercised rather than assumed.
  begin_step "a forced deadline quarantines rather than completing"
  block_step "a forced deadline quarantines rather than completing" \
    "forcing a deadline mid-ceremony needs an in-flight ceremony to force, \
which needs work originated on the rehearsal chain and — for the tBTC case a \
rollback must cover — a wallet action already running"

  # Step 4. Every release candidate stopped — every one on the daemon, not
  # only the two this project started.
  #
  # A rollback rehearsal runs after a cutover rehearsal, and the cutover fleet
  # is a fleet of the same candidate artifact watching the same chain. Asking
  # only this project's services whether they answer would authorize releasing
  # the prior binary alongside a candidate that a previous gate left running,
  # which is precisely the concurrent-write hazard the barrier exists to
  # forbid. Separate compose projects are separate namespaces, not separate
  # chains.
  begin_step "every release candidate is stopped or network-quarantined"
  read_candidate_inventory
  candidate_barrier_verdict \
    "every release candidate is stopped or network-quarantined" \
    "all R1 is down or quarantined before any prior binary participates"

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

  # Step 5b. Every permit the fleet held at the stop, followed to an outcome.
  #
  # The drain step says the fleet held work and that stopping it returned
  # cleanly; the audit says the state left behind is internally consistent.
  # Neither follows a permit. A rollback restores onto whatever the drain left,
  # so each permit has to land somewhere a later reader can see — completed, or
  # force-canceled into a quarantine record the audit wrote — and the audit's
  # manifests are read here because that is where the quarantine records are.
  begin_step "every in-flight permit reconciles to completion or quarantine"
  # What became of the work this gate put in flight, asked once the drain is
  # over and the outcomes exist to be read. The drain phase itself cannot ask:
  # its subject is work still running, and by the time an outcome exists the
  # work it was about is finished.
  ROLLBACK_TERMINAL=""
  ROLLBACK_TERMINAL_ASKED=0
  ROLLBACK_TERMINAL_RC=0
  if [[ -n "${PR4109_WORK_DRIVER:-}" ]]; then
    ROLLBACK_TERMINAL_ASKED=1
    run_work_driver rollback-terminal || true
    ROLLBACK_TERMINAL="${WORK_DRIVER_BOUND_RESULTS}"
    ROLLBACK_TERMINAL_RC="${WORK_DRIVER_RC}"
  fi
  ROLLBACK_NODE_QUARANTINES=""
  for service in "${REHEARSAL_R1_SERVICES[@]}"; do
    ROLLBACK_NODE_QUARANTINES="${ROLLBACK_NODE_QUARANTINES}\
${ROLLBACK_NODE_QUARANTINES:+$'\n'}${service} \
$(audit_quarantine_records "${EVIDENCE_DIR}/state-audit/${service}.json" \
      "${ROLLBACK_DRAIN_SINCE}")"
  done
  rollback_reconciliation_verdict \
    "every in-flight permit reconciles to completion or quarantine" \
    "every permit held at the stop completes or is audited into quarantine"

  # Step 6. Release the prior digest, and only behind the whole barrier.
  #
  # Both halves are load-bearing and neither substitutes for the other. Every
  # R1 node being unreachable stops two releases from writing the same state
  # at once; the audit reporting rollback_barrier_ready is what says the state
  # they left is state the prior binary can safely read. Starting the prior
  # binary on the first alone is a rollback performed without knowing whether
  # it is safe, which is the failure this gate exists to catch.
  begin_step "stage the prior digest behind the all-candidate-down barrier"
  if ((CANDIDATE_BARRIER_HOLDS == 1 && audit_ready == 1)); then
    compose start "${REHEARSAL_PRIOR_SERVICE}"
    # The binary that was released has to be the prior artifact the audit
    # authorized rolling back to, not whatever the compose file resolved.
    verify_running_images "${PRIOR_IMAGE_DIGEST}" "${REHEARSAL_PRIOR_SERVICE}"
    record_step "stage the prior digest behind the all-candidate-down barrier" \
      pass "the prior binary was released only after every release candidate \
on the daemon was proved stopped or attached to no network and every snapshot \
audited rollback-safe, and the container that came up is the audited prior \
digest"
  elif ((CANDIDATE_BARRIER_HOLDS == 0)); then
    record_step "stage the prior digest behind the all-candidate-down barrier" \
      blocked "the all-candidate-down barrier does not hold, so the prior \
binary was deliberately not released"
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
  if ((CANDIDATE_BARRIER_HOLDS == 1)); then
    record_step "a forbidden partial rollback is blocked" pass \
      "the barrier check above is the block: the prior binary is released only \
on a daemon-wide candidate set that is entirely stopped or attached to no \
network, and any other reading records a blocked step instead of starting it"
    record_assertion "a partial rollback cannot be performed" true \
      "a forbidden partial rollback is blocked"
  else
    record_step "a forbidden partial rollback is blocked" pass \
      "the barrier refused to release the prior binary with \
${CANDIDATE_ACTIVE[*]:-an unestablished candidate inventory} outstanding"
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

# The image set the receipt's detached provenance records, as a JSON object
# from platform to pinned reference. Published by require_manifest_attestation
# and read by the record comparison, so both speak from the receipt's own
# sealed copy of that document rather than re-reading a path that may have
# been rewritten between them. Empty until an attestation carrying provenance
# has been required, which is exactly the runs where no record may be accepted.
ATTESTED_PROVENANCE_IMAGES=""

# The [gate, platform] pairs the record loop observed, one JSON array per line
# per entry, for the archive-wide coverage question the loop cannot answer.
EVIDENCED_GATE_PLATFORMS=()

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
  local dir derived reviewed_hash source_file ready_file
  dir="$(attestation_dir)"
  derived="${dir}/derived-manifest.json"
  reviewed_hash="${dir}/reviewed-manifest.sha256"
  source_file="${dir}/source-commit.txt"
  ready_file="${dir}/release-ready.txt"

  # All four or none: a receipt missing any part is a fragment, and a
  # fragment must never be read as a receipt — which is also what keeps an
  # interrupted staging directory from ever standing in for one.
  if [[ ! -f "${derived}" || ! -f "${reviewed_hash}" ||
    ! -f "${source_file}" || ! -f "${ready_file}" ]]; then
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
      // Only the half of the identity the binary derives. The source commit
      // and the image digests are outputs of a build that happens after this
      // document is reviewed, so derive cannot produce them and a comparison
      // demanding they match would fail on every manifest that records them.
      // The manifest hash covers those two; what belongs here is what the
      // compiled binary itself claims — the chain the cutover block is for,
      // and the block.
      const identity = doc.release_identity || {};
      return JSON.stringify(canon({
        schema_version: doc.schema_version,
        protocol_epoch: doc.protocol_epoch,
        chain_id: identity.chain_id,
        cutover_block: identity.cutover_block,
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

  # The manifest may be internally valid and still name no release. Records
  # measured against one of those describe a rehearsal of the code, not a
  # release these bytes could be accepted as: nothing in them names the block
  # the cutover happens at, the commit built, or the images acceptance ran
  # against. Accepting them would put a receipt over a document that identifies
  # no artifact — which is exactly what the acceptance stage exists to refuse.
  local attested_ready
  attested_ready="$(tr -d '[:space:]' <"${ready_file}")"
  if [[ "${attested_ready}" != "yes" ]]; then
    blocked "the release-manifest attestation records ${manifest} as not \
release-ready; a reviewed release commit must set the mainnet cutover block \
and record the built commit and the immutable image digests before evidence \
measured against this manifest can be accepted — run \
\`keep-client release-manifest validate --release-ready\` for what is missing"
  fi

  # Readiness says the reviewed manifest names a real cutover. It says nothing
  # about which artifact runs it, and it cannot: the commit built and the
  # images are outputs of a build over the manifest's own bytes, so a manifest
  # naming them would have to contain a hash of the tree containing it.
  #
  # The detached provenance is that half, and this is where it becomes
  # mandatory. Past this point the run is a release-acceptance run, so a
  # receipt carrying no provenance is a rehearsal of code that names no
  # artifact — and every record below would be measured against a release
  # nobody can identify.
  local provenance="${dir}/release-provenance.json"
  if [[ ! -f "${provenance}" ]]; then
    blocked "the release-manifest attestation under ${dir} carries no \
detached release provenance, but ${manifest} is release-ready: acceptance \
needs the commit built and the immutable image digests, which cannot live in \
the reviewed manifest because they are outputs of a build over its own bytes. \
Generate the provenance after the build, outside the checkout, and re-run the \
local-proofs stage with PR4109_RELEASE_PROVENANCE pointing at it"
  fi

  # Two bindings, and the pair is what closes the loop the manifest could not
  # close alone. The provenance names the manifest it was taken over, so it
  # cannot be provenance for a release reviewed under other bounds; and it
  # names the commit built, which is required to be the commit this receipt
  # was taken at — already proved a clean id and, on a bound run, the
  # dispatched one. Neither statement is self-referential, because neither
  # document is inside the other's bytes.
  local provenance_manifest_sha provenance_source
  provenance_manifest_sha="$(node -e '
    const fs = require("fs");
    const doc = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    process.stdout.write(String(doc.manifest_sha256 || ""));
  ' "${provenance}")" ||
    blocked "cannot read the detached release provenance under ${dir}"
  if [[ "${provenance_manifest_sha}" != "${manifest_sha}" ]]; then
    blocked "the detached release provenance was taken over a manifest \
hashing to [${provenance_manifest_sha:-absent}], but ${manifest} hashes to \
[${manifest_sha}]; the artifact it names was built under reviewed bounds \
other than the ones these records are measured against"
  fi

  provenance_source="$(node -e '
    const fs = require("fs");
    const doc = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    process.stdout.write(String(doc.source_commit || ""));
  ' "${provenance}")" ||
    blocked "cannot read the detached release provenance under ${dir}"
  if [[ "${provenance_source}" != "${attested_source}" ]]; then
    blocked "the detached release provenance names source commit \
[${provenance_source:-absent}], but the attestation measuring these records \
was taken at [${attested_source}]; the release was built from bytes other \
than the ones under test, so re-generate the provenance for the commit \
actually built or re-run the local-proofs stage at the commit it names"
  fi

  # The reviewed image set, published for the record comparison. Read once
  # here, from the receipt's own sealed copy, so every record below is held to
  # one answer rather than to whatever the file says at the moment it is read.
  ATTESTED_PROVENANCE_IMAGES="$(node -e '
    const fs = require("fs");
    const doc = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    if (!Array.isArray(doc.images) || doc.images.length === 0) {
      console.error(
        "the detached release provenance publishes no runtime image"
      );
      process.exit(1);
    }
    const images = {};
    for (const image of doc.images) {
      images[String(image.platform)] = String(image.reference);
    }
    process.stdout.write(JSON.stringify(images));
  ' "${provenance}")" ||
    blocked "cannot read the image set from the detached release provenance \
under ${dir}"

  note "release-manifest attestation binds ${manifest} to the compiled \
bounds of ${attested_source}, and the detached provenance binds that commit \
to the images ${ATTESTED_PROVENANCE_IMAGES}"
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

# Is each caller-selected record admissible — well formed, produced at the
# attested commit, and measured against the reviewed manifest? This decides
# nothing about whether the gates the records evidence were satisfied, or
# whether the archive contains every required gate and platform. Those are
# separate questions, asked by assess_evidence_acceptance and
# require_evidenced_platform_coverage respectively. Keeping all three apart
# lets one platform runner validate the record it actually produced without
# pretending it can see the records other runners have not uploaded yet.
validate_evidence_record_set() {
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

  (($# > 0)) ||
    blocked "no evidence records were supplied for admissibility validation"

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

  # Filled in per record and settled once, after the loop, because the question
  # it answers is not one any single record can be asked.
  EVIDENCED_GATE_PLATFORMS=()

  for record in "$@"; do
    note "validating ${record}"
    # ajv needs the formats plugin loaded explicitly or it rejects the
    # schema's own date-time format annotation before ever reading a
    # record. Both packages are pinned to exact versions: a floating major
    # or minor release must never change what this stage accepts.
    npx --yes -p ajv-cli@5.0.0 -p ajv-formats@2.1.1 ajv validate \
      --spec=draft2020 -c ajv-formats -s "${schema}" -d "${record}" ||
      blocked "evidence record ${record} does not conform to ${schema}"

    local recorded_source recorded_revision recorded_sha recorded_grace
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
    recorded_revision="$(node -e '
      const fs = require("fs");
      const record = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      process.stdout.write(String((record.artifacts || {}).revision || ""));
    ' "${record}")"
    if [[ "${recorded_revision}" != "${recorded_source}" ]]; then
      blocked "evidence record ${record} says its R1 runtime revision is \
[${recorded_revision:-absent}], but its exact source commit is \
[${recorded_source}]; an artifact identity abbreviated from or unrelated to \
the source cannot bind supporting evidence to one build"
    fi

    # The images the record says the fleet ran, against the ones the release
    # published. A record naming some other build's digest is a rehearsal of an
    # artifact this release does not ship, and one naming a platform the
    # release does not publish is a fleet that ran something no reviewer ever
    # saw. Both are refused here.
    #
    # What the record does not name is not asked of it. One runner executes one
    # platform, so a record honestly speaks for that platform alone; whether
    # the published set was covered is a property of the whole archive, and it
    # is asked once below, over every record. Demanding it of each record would
    # make every rehearsal that could actually be run refuse itself.
    #
    # Comparing references rather than bare digests also refuses the same
    # digest pulled from another repository, which is a different supply chain
    # reaching the same content only for as long as nobody repoints it.
    local image_disagreement recorded_platforms
    image_disagreement="$(node -e '
      const fs = require("fs");
      const record = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      const reviewed = JSON.parse(process.argv[2]);
      const ran = (record.artifacts || {}).r1_image_digests || {};
      const differences = [];
      const platforms = Object.keys(ran);
      if (platforms.length === 0) {
        differences.push("it names no image at all");
      } else if (platforms.length > 1) {
        differences.push(
          "it names " + platforms.length + " platforms [" +
            platforms.sort().join(", ") + "], but one runner executes one " +
            "published image and one record can evidence only that image"
        );
      }
      for (const platform of Object.keys(ran).sort()) {
        if (!(platform in reviewed)) {
          differences.push(
            "this record evidences [" + platform + "] as " + ran[platform] +
              ", which the release does not publish"
          );
        } else if (ran[platform] !== reviewed[platform]) {
          differences.push(
            "[" + platform + "] ran " + ran[platform] +
              ", but the release publishes " + reviewed[platform]
          );
        }
      }
      process.stdout.write(differences.join("; "));
    ' "${record}" "${ATTESTED_PROVENANCE_IMAGES}")" ||
      blocked "cannot compare the images in evidence record ${record} against \
the reviewed release provenance"
    if [[ -n "${image_disagreement}" ]]; then
      blocked "evidence record ${record} was not produced against the images \
this release publishes: ${image_disagreement}"
    fi

    # What this record covers, for the archive-wide question below. Collected
    # as the gate it evidences paired with each platform it ran, because
    # coverage is owed per gate: a release rehearsed on two architectures with
    # the rollback gate run on only one has an artifact nobody rolled back.
    recorded_platforms="$(node -e '
      const fs = require("fs");
      const record = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      const gate = String(record.gate || "");
      const ran = (record.artifacts || {}).r1_image_digests || {};
      const lines = Object.keys(ran)
        .sort()
        .map((platform) => JSON.stringify([gate, platform]));
      process.stdout.write(lines.join("\n"));
    ' "${record}")" ||
      blocked "cannot read the platforms evidence record ${record} covers"
    # An `if` and not a `&&`: a false test as a loop body's last statement
    # carries its status out under errexit.
    if [[ -n "${recorded_platforms}" ]]; then
      EVIDENCED_GATE_PLATFORMS+=("${recorded_platforms}")
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

    # The instruments, held to the same standard as the bounds. A record's
    # terminal readings are the driver's account of the chain, so a record
    # that carries chain evidence and names no reviewed driver is a reading
    # taken with an instrument nobody can identify; and one naming a digest
    # the reviewed control does not pin is a program that was reviewed
    # somewhere other than in this repository.
    local recorded_driver recorded_generator recorded_review drove
    recorded_driver="$(node -e '
      const fs = require("fs");
      const record = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      process.stdout.write(
        String((record.chain_inputs || {}).work_driver_sha256 || "")
      );
    ' "${record}")"
    recorded_generator="$(node -e '
      const fs = require("fs");
      const record = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      process.stdout.write(String(
        (record.chain_inputs || {}).rollback_evidence_generator_sha256 || ""
      ));
    ' "${record}")"
    recorded_review="$(node -e '
      const fs = require("fs");
      const record = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      process.stdout.write(
        String((record.chain_inputs || {}).tsslib_review_sha256 || "")
      );
    ' "${record}")"
    drove="$(node -e '
      const fs = require("fs");
      const record = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      const drove = (record.stages || []).some(
        (stage) => (stage.transaction_hashes || []).length > 0
      );
      process.stdout.write(drove ? "yes" : "no");
    ' "${record}")"
    if [[ "${drove}" == "yes" && -z "${recorded_driver}" ]]; then
      blocked "evidence record ${record} carries chain transactions but names \
no work driver digest; the readings a driver produces are the terminal half \
of every control that watches work settle, and a record cannot attribute them \
to an instrument it does not identify"
    fi
    if [[ -n "${recorded_driver}" ]] &&
      [[ "${recorded_driver}" != "$(reviewed_input_digest work-driver)" ]]; then
      blocked "evidence record ${record} was produced with a work driver \
hashing to [${recorded_driver}], which \
${SCAFFOLD_DIR}/chain-inputs.sha256 does not pin"
    fi
    if [[ -n "${recorded_generator}" ]] &&
      [[ "${recorded_generator}" != \
      "$(reviewed_input_digest rollback-evidence-generator)" ]]; then
      blocked "evidence record ${record} was produced with a rollback \
evidence generator hashing to [${recorded_generator}], which \
${SCAFFOLD_DIR}/chain-inputs.sha256 does not pin"
    fi
    if [[ -n "${recorded_review}" ]] &&
      [[ "${recorded_review}" != "$(reviewed_input_digest tsslib-review)" ]]; then
      blocked "evidence record ${record} names a dependency review record \
hashing to [${recorded_review}], which ${SCAFFOLD_DIR}/chain-inputs.sha256 \
does not pin; a record naming an unpinned review asserts an approval this \
repository never took"
    fi
  done

  note "the supplied evidence records conform to the schema, were produced at \
${attested_source}, ran only images the release publishes, and bind the \
reviewed release manifest's hash and termination grace"
}

# Validate the complete archive. Per-record admissibility deliberately cannot
# answer whether another platform runner or the other mandatory gate produced
# its record, so only this whole-directory entry point asks that question.
validate_evidence_records() {
  collect_evidence_records
  if ((${#EVIDENCE_RECORDS[@]} == 0)); then
    blocked "no evidence records found under ${EVIDENCE_DIR}; a rehearsal \
run that produced no record cannot be accepted"
  fi

  validate_evidence_record_set "${EVIDENCE_RECORDS[@]}"
  require_evidenced_platform_coverage

  note "the evidence archive contains exactly one admissible record for every \
required gate and published platform"
}

# Was every published image rehearsed by every mandatory gate, exactly once?
#
# Each record names the one platform its runner executed, which is the only
# honest thing a record can say and is exactly why no record can answer this.
# A release publishing two architectures and rehearsed on one has a shipped
# artifact that no gate ever ran, and every record in that archive is
# individually correct. So the question is asked here, over the record set,
# once per gate: a rollback rehearsal that covered one architecture leaves the
# other with no evidence that it can be rolled back, however thoroughly the
# cutover gate covered both.
#
# Both mandatory gates are named here because archive completeness is a
# property of their gate/platform product. Inferring the gates from the
# records makes a wholly absent rollback record disappear from the question.
# Counting instead of taking a set matters too: two records for the same
# gate/platform are two competing accounts of one mandatory run, not stronger
# evidence for it.
require_evidenced_platform_coverage() {
  local pairs="" archive_problem
  # bash 3.2 refuses to expand an empty array under `set -u`, and the per-record
  # check has already blocked every record that named no image, so an empty set
  # here means no record at all — which the caller refused before this ran.
  if ((${#EVIDENCED_GATE_PLATFORMS[@]} > 0)); then
    pairs="$(
      IFS=$'\n'
      printf '%s' "${EVIDENCED_GATE_PLATFORMS[*]}"
    )"
  fi

  archive_problem="$(printf '%s' "${pairs}" | node -e '
    const reviewed = Object.keys(JSON.parse(process.argv[1])).sort();
    const requiredGates = ["single_release", "rollback"];
    let raw = "";
    process.stdin.on("data", (d) => (raw += d));
    process.stdin.on("end", () => {
      const covered = new Map();
      for (const line of raw.split("\n")) {
        if (!line) continue;
        const [gate, platform] = JSON.parse(line);
        if (!covered.has(gate)) covered.set(gate, new Map());
        const counts = covered.get(gate);
        counts.set(platform, (counts.get(platform) || 0) + 1);
      }
      const problems = [];
      for (const gate of requiredGates) {
        const ran = covered.get(gate) || new Map();
        const absent = reviewed.filter((platform) => !ran.has(platform));
        if (absent.length > 0) {
          problems.push(
            "the " + gate + " gate evidences [" +
              Array.from(ran.keys()).sort().join(", ") + "] and not [" +
              absent.join(", ") + "]"
          );
        }
        for (const platform of Array.from(ran.keys()).sort()) {
          const count = ran.get(platform);
          if (count > 1) {
            problems.push(
              "the " + gate + " gate has " + count +
                " records for [" + platform + "]"
            );
          }
        }
      }
      process.stdout.write(problems.join("; "));
    });
  ' "${ATTESTED_PROVENANCE_IMAGES}")" ||
    blocked "cannot determine whether the evidence archive contains every \
required gate and platform exactly once"

  if [[ -n "${archive_problem}" ]]; then
    blocked "the evidence archive does not contain exactly one record for \
every required gate and published platform: ${archive_problem}; a missing \
record leaves a mandatory release property unproved, while duplicate records \
leave competing accounts of which run is authoritative — rehearse each gate \
once on every platform and validate the records together"
  fi

  note "single_release and rollback each evidence every platform the release \
publishes exactly once"
}

# Inspect the supporting roster-window archive named by one single-release
# record. The reader binds the bytes to that record and run, verifies the
# pre-close checkpoint, and reconstructs the event chronology from each log.
cutover_evidence_window_findings() {
  local record="$1"
  node -e '
    const crypto = require("crypto");
    const fs = require("fs");
    const path = require("path");
    const [recordPath, evidenceRootInput, ...expectedServices] =
      process.argv.slice(1);
    const findings = [];
    const add = (kind, what) => findings.push(kind + "\t" + what);
    const isObject = (value) =>
      value !== null && typeof value === "object" && !Array.isArray(value);
    const safeIdentifier = (value) =>
      typeof value === "string" &&
      /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value);
    const sameArray = (left, right) =>
      left.length === right.length &&
      left.every((value, index) => value === right[index]);
    const sha256 = (value) =>
      crypto.createHash("sha256").update(value).digest("hex");
    const canonical = (value) => {
      if (Array.isArray(value)) return value.map(canonical);
      if (!isObject(value)) return value;
      return Object.fromEntries(
        Object.keys(value).sort().map((key) => [key, canonical(value[key])])
      );
    };
    const sameValue = (left, right) =>
      JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));

    // Producer and Docker timestamps are UTC RFC3339/RFC3339Nano. Parsing an
    // intentionally narrow form avoids Date.parse accepting normalized invalid
    // dates or implementation-specific strings as release chronology.
    const parseTimestamp = (value) => {
      if (typeof value !== "string") return undefined;
      const match = value.match(
        /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/
      );
      if (!match) return undefined;
      const year = Number(match[1]);
      const month = Number(match[2]);
      const day = Number(match[3]);
      const hour = Number(match[4]);
      const minute = Number(match[5]);
      const second = Number(match[6]);
      const fraction = match[7] || "";
      if (
        year < 1970 || month < 1 || month > 12 || day < 1 ||
        day > new Date(Date.UTC(year, month, 0)).getUTCDate() ||
        hour > 23 || minute > 59 || second > 59
      ) return undefined;
      const milliseconds = Date.UTC(year, month - 1, day, hour, minute, second);
      const date = new Date(milliseconds);
      if (
        date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 ||
        date.getUTCDate() !== day || date.getUTCHours() !== hour ||
        date.getUTCMinutes() !== minute || date.getUTCSeconds() !== second
      ) return undefined;
      return {
        seconds: Math.floor(milliseconds / 1000),
        nanos: Number((fraction + "000000000").slice(0, 9)),
      };
    };
    const compareTime = (left, right) =>
      left.seconds === right.seconds
        ? left.nanos - right.nanos
        : left.seconds - right.seconds;
    const elapsedMilliseconds = (left, right) =>
      (right.seconds - left.seconds) * 1000 +
      (right.nanos - left.nanos) / 1000000;

    const inspect = () => {
      let record;
      try {
        record = JSON.parse(fs.readFileSync(recordPath, "utf8"));
      } catch (_) {
        add("unrehearsed", "single_release record cannot be read while " +
          "resolving its fleet evidence-window archive");
        return;
      }
      if (record.gate !== "single_release") return;

      const evidenceWindow = (Array.isArray(record.stages) ? record.stages : [])
        .find((stage) => isObject(stage) && stage.name ===
          "every R1 node authors periodic empty roster evidence");
      if (!evidenceWindow) return;
      const checksums = isObject(evidenceWindow.state_checksums)
        ? evidenceWindow.state_checksums : {};
      const refs = isObject(evidenceWindow.evidence_refs)
        ? evidenceWindow.evidence_refs : {};
      const summaryDigest =
        checksums.cutover_evidence_window_summary_sha256;
      const archiveID = refs.cutover_evidence_window_archive;
      const captureID = refs.cutover_evidence_window_capture_id;
      const summaryDigestValid = typeof summaryDigest === "string" &&
        /^[0-9a-f]{64}$/.test(summaryDigest);
      if (!summaryDigestValid) {
        add("unrehearsed", "single_release fleet evidence-window step " +
          "carries no archived summary SHA-256");
      }
      if (!safeIdentifier(archiveID)) {
        add("unrehearsed", "single_release fleet evidence-window step " +
          "carries no safe relative archive identifier");
        return;
      }
      if (typeof captureID !== "string" || !/^[0-9a-f]{32}$/.test(captureID)) {
        add("unrehearsed", "single_release fleet evidence-window step " +
          "carries no valid capture identity");
      }
      if (
        typeof captureID === "string" &&
        archiveID !== "cutover-roster-window-" + captureID
      ) {
        add("unrehearsed", "single_release fleet evidence-window archive " +
          "identifier is not derived from its capture identity");
      }

      const expectedCounts = new Map();
      for (const service of expectedServices) {
        expectedCounts.set(service, (expectedCounts.get(service) || 0) + 1);
      }
      if (
        expectedServices.length === 0 ||
        expectedServices.some((service) => !safeIdentifier(service)) ||
        Array.from(expectedCounts.values()).some((count) => count !== 1)
      ) {
        add("unrehearsed", "single_release fleet evidence-window reader " +
          "received no exact authoritative R1 service set");
        return;
      }
      const expectedSorted = [...expectedServices].sort();

      let evidenceRoot;
      let archivePath;
      try {
        evidenceRoot = fs.realpathSync(evidenceRootInput);
        const rootStat = fs.lstatSync(evidenceRoot);
        if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
          throw new Error("evidence root is not a directory");
        }
        const lexicalArchive = path.resolve(evidenceRoot, archiveID);
        if (path.dirname(lexicalArchive) !== evidenceRoot) {
          throw new Error("archive is not a direct evidence child");
        }
        const archiveStat = fs.lstatSync(lexicalArchive);
        if (!archiveStat.isDirectory() || archiveStat.isSymbolicLink()) {
          throw new Error("archive is not a real directory");
        }
        archivePath = fs.realpathSync(lexicalArchive);
        if (path.dirname(archivePath) !== evidenceRoot) {
          throw new Error("archive resolves outside evidence root");
        }
      } catch (_) {
        add("unrehearsed", "single_release fleet evidence-window archive " +
          JSON.stringify(archiveID) + " is absent or does not resolve " +
          "safely beneath EVIDENCE_DIR");
        return;
      }

      const readRegularArchiveFile = (name, description) => {
        const candidate = path.join(archivePath, name);
        try {
          const stat = fs.lstatSync(candidate);
          if (!stat.isFile() || stat.isSymbolicLink()) {
            throw new Error("not a regular file");
          }
          const resolved = fs.realpathSync(candidate);
          if (path.dirname(resolved) !== archivePath) {
            throw new Error("file resolves outside archive");
          }
          return fs.readFileSync(resolved);
        } catch (_) {
          add("unrehearsed", "single_release fleet evidence-window archive " +
            JSON.stringify(archiveID) + " has no safe archived " + description);
          return undefined;
        }
      };

      const resultBytes = readRegularArchiveFile("result.json", "result.json");
      const checkpointBytes = readRegularArchiveFile(
        "window-open.json", "window-open.json"
      );
      if (resultBytes === undefined || checkpointBytes === undefined) return;
      if (summaryDigestValid && sha256(resultBytes) !== summaryDigest) {
        add("unrehearsed", "single_release fleet evidence-window summary " +
          "SHA-256 does not match the archived result.json named by the record");
      }

      let result;
      let checkpoint;
      try {
        result = JSON.parse(resultBytes.toString("utf8"));
      } catch (_) {
        add("unrehearsed", "single_release fleet evidence-window result.json " +
          "is malformed");
        return;
      }
      try {
        checkpoint = JSON.parse(checkpointBytes.toString("utf8"));
      } catch (_) {
        add("unrehearsed", "single_release fleet evidence-window " +
          "window-open.json is malformed");
        return;
      }
      if (!isObject(result) || result.schema_version !== 2) {
        add("unrehearsed", "single_release fleet evidence-window result.json " +
          "has no supported schema_version");
        return;
      }
      if (!isObject(checkpoint) || checkpoint.schema_version !== 2) {
        add("unrehearsed", "single_release fleet evidence-window " +
          "window-open.json has no supported schema_version");
        return;
      }
      if (
        typeof result.window_open_sha256 !== "string" ||
        !/^[0-9a-f]{64}$/.test(result.window_open_sha256) ||
        sha256(checkpointBytes) !== result.window_open_sha256
      ) {
        add("unrehearsed", "single_release fleet evidence-window pre-close " +
          "checkpoint does not match result.window_open_sha256");
      }

      const artifacts = isObject(record.artifacts) ? record.artifacts : {};
      const chain = isObject(record.chain) ? record.chain : {};
      const expectedContext = {
        schema_version: 1,
        run_id: record.run_id,
        capture_id: captureID,
        archive_id: archiveID,
        gate: record.gate,
        source_sha: record.source_sha,
        r1_image_digests: artifacts.r1_image_digests,
        revision: artifacts.revision,
        protocol_epoch: artifacts.protocol_epoch,
        chain_id: chain.chain_id,
        cutover_block: chain.cutover_block,
        r1_fleet: record.r1_fleet,
      };
      const contextFields = Object.keys(expectedContext);
      for (const [name, context] of [
        ["result.json", result.capture_context],
        ["window-open.json", checkpoint.capture_context],
      ]) {
        if (!isObject(context)) {
          add("unrehearsed", "single_release fleet evidence-window " + name +
            " carries no capture context");
          continue;
        }
        for (const field of contextFields) {
          if (!sameValue(context[field], expectedContext[field])) {
            add("unrehearsed", "single_release fleet evidence-window " + name +
              " capture context " + JSON.stringify(field) +
              " does not match its rehearsal record");
          }
        }
        const extras = Object.keys(context)
          .filter((field) => !contextFields.includes(field));
        if (extras.length > 0) {
          add("unrehearsed", "single_release fleet evidence-window " + name +
            " capture context carries unexpected fields [" +
            extras.sort().join(", ") + "]");
        }
      }
      if (!sameValue(result.capture_context, checkpoint.capture_context)) {
        add("unrehearsed", "single_release fleet evidence-window capture " +
          "context changed between open checkpoint and close result");
      }

      const timelineValues = {
        "result.opened_at": result.opened_at,
        "result.archived_before_close_at": result.archived_before_close_at,
        "result.closed_at": result.closed_at,
        "record.generated_at": record.generated_at,
        "checkpoint.opened_at": checkpoint.opened_at,
        "checkpoint.archived_at": checkpoint.archived_at,
      };
      const timeline = {};
      for (const [name, value] of Object.entries(timelineValues)) {
        timeline[name] = parseTimestamp(value);
        if (!timeline[name]) {
          add("unrehearsed", "single_release fleet evidence-window timestamp " +
            JSON.stringify(name) + " is not supported valid UTC RFC3339");
        }
      }
      if (
        checkpoint.opened_at !== result.opened_at ||
        checkpoint.archived_at !== result.archived_before_close_at
      ) {
        add("unrehearsed", "single_release fleet evidence-window pre-close " +
          "checkpoint timestamps do not match the close result");
      }
      const opened = timeline["result.opened_at"];
      const archived = timeline["result.archived_before_close_at"];
      const closed = timeline["result.closed_at"];
      const generated = timeline["record.generated_at"];
      if (
        opened && archived && closed && generated &&
        (
          compareTime(opened, archived) > 0 ||
          compareTime(archived, closed) > 0 ||
          compareTime(closed, generated) > 0
        )
      ) {
        add("unrehearsed", "single_release fleet evidence-window timeline is " +
          "not opened_at <= archived_before_close_at <= closed_at <= " +
          "record.generated_at");
      }

      if (result.complete !== true) {
        add("refuted", "single_release fleet evidence-window archive reports " +
          "complete=false");
      }
      if (!Array.isArray(result.failures)) {
        add("unrehearsed", "single_release fleet evidence-window result.json " +
          "has no failure account");
      } else if (result.failures.length !== 0) {
        add("refuted", "single_release fleet evidence-window archive records " +
          "capture failures");
      }
      if (checkpoint.complete !== true) {
        add("refuted", "single_release fleet evidence-window pre-close " +
          "checkpoint reports complete=false");
      }
      if (!Array.isArray(result.services) || !Array.isArray(checkpoint.services)) {
        add("unrehearsed", "single_release fleet evidence-window archive has " +
          "no complete result/checkpoint service account");
        return;
      }

      const indexServices = (entries) => {
        const map = new Map();
        const names = [];
        let valid = true;
        for (const entry of entries) {
          if (!isObject(entry) || !safeIdentifier(entry.service)) {
            valid = false;
            continue;
          }
          names.push(entry.service);
          if (map.has(entry.service)) valid = false;
          else map.set(entry.service, entry);
        }
        return { map, names: names.sort(), valid };
      };
      const resultIndex = indexServices(result.services);
      const checkpointIndex = indexServices(checkpoint.services);
      for (const [name, index] of [
        ["result", resultIndex], ["pre-close checkpoint", checkpointIndex],
      ]) {
        if (!index.valid || !sameArray(index.names, expectedSorted)) {
          add("unrehearsed", "single_release fleet evidence-window " + name +
            " service set [" + index.names.join(", ") +
            "] does not match the authoritative R1 service set [" +
            expectedSorted.join(", ") + "]");
        }
      }

      const expectedFiles = ["result.json", "window-open.json", ...expectedSorted
        .map((service) => service + ".log")].sort();
      try {
        const actualFiles = fs.readdirSync(archivePath).sort();
        if (!sameArray(actualFiles, expectedFiles)) {
          add("unrehearsed", "single_release fleet evidence-window archive " +
            "file set [" + actualFiles.join(", ") +
            "] does not match its exact evidence file set [" +
            expectedFiles.join(", ") + "]");
        }
      } catch (_) {
        add("unrehearsed", "single_release fleet evidence-window archive " +
          "cannot enumerate its evidence files");
      }

      const resultFlags = [
        "signal_delivered", "activation_seen",
        "periodic_empty_snapshots_seen", "close_delivered", "close_seen",
      ];
      const checkpointFlags = [
        "signal_delivered", "activation_seen", "periodic_empty_snapshots_seen",
      ];
      for (const service of expectedSorted) {
        const entry = resultIndex.map.get(service);
        const checkpointEntry = checkpointIndex.map.get(service);
        if (entry) {
          for (const flag of resultFlags) {
            if (entry[flag] !== true) {
              add("refuted", "single_release fleet evidence-window service " +
                JSON.stringify(service) + " does not record " +
                JSON.stringify(flag) + " as true");
            }
          }
        }
        if (checkpointEntry) {
          for (const flag of checkpointFlags) {
            if (checkpointEntry[flag] !== true) {
              add("refuted", "single_release fleet evidence-window pre-close " +
                "service " + JSON.stringify(service) + " does not record " +
                JSON.stringify(flag) + " as true");
            }
          }
        }
        if (!entry) continue;

        const logBytes = readRegularArchiveFile(
          service + ".log", "log for service " + JSON.stringify(service)
        );
        if (logBytes === undefined) continue;
        const recordedLogDigest = entry.relevant_log_sha256;
        if (
          typeof recordedLogDigest !== "string" ||
          !/^[0-9a-f]{64}$/.test(recordedLogDigest)
        ) {
          add("unrehearsed", "single_release fleet evidence-window service " +
            JSON.stringify(service) + " carries no relevant-log SHA-256");
        } else if (sha256(logBytes) !== recordedLogDigest) {
          add("unrehearsed", "single_release fleet evidence-window archived " +
            "log for service " + JSON.stringify(service) +
            " does not match its relevant_log_sha256");
        }

        const rawLines = logBytes.toString("utf8").split(/\r?\n/)
          .filter((line) => line.length > 0);
        const lines = rawLines.map((line, index) => {
          const timestampToken = (line.match(/^(\S+)\s/) || [])[1] || "";
          return { line, index, time: parseTimestamp(timestampToken) };
        });
        if (lines.some((line) => !line.time)) {
          add("unrehearsed", "single_release fleet evidence-window archived " +
            "log for service " + JSON.stringify(service) +
            " carries a line without supported valid UTC RFC3339Nano time");
        }
        for (let index = 1; index < lines.length; index++) {
          if (
            lines[index - 1].time && lines[index].time &&
            compareTime(lines[index - 1].time, lines[index].time) > 0
          ) {
            add("unrehearsed", "single_release fleet evidence-window archived " +
              "log for service " + JSON.stringify(service) +
              " is not in timestamp order");
            break;
          }
        }
        const activations = lines.filter((entry) =>
          entry.line.includes("protocol cutover evidence window changed") &&
          entry.line.includes("[active=true]"));
        const closes = lines.filter((entry) =>
          entry.line.includes("protocol cutover evidence window changed") &&
          entry.line.includes("[active=false]"));
        if (activations.length === 0) {
          add("unrehearsed", "single_release fleet evidence-window archived " +
            "log for service " + JSON.stringify(service) +
            " has no activation line");
        } else if (activations.length !== 1) {
          add("unrehearsed", "single_release fleet evidence-window archived " +
            "log for service " + JSON.stringify(service) +
            " has more than one activation line");
        }
        if (closes.length === 0) {
          add("unrehearsed", "single_release fleet evidence-window archived " +
            "log for service " + JSON.stringify(service) + " has no close line");
        } else if (closes.length !== 1) {
          add("unrehearsed", "single_release fleet evidence-window archived " +
            "log for service " + JSON.stringify(service) +
            " has more than one close line");
        }
        const activation = activations.length === 1 ? activations[0] : undefined;
        const close = closes.length === 1 ? closes[0] : undefined;
        if (
          activation && activation.time && opened && archived &&
          (
            compareTime(activation.time, opened) < 0 ||
            compareTime(activation.time, archived) > 0
          )
        ) {
          add("unrehearsed", "single_release fleet evidence-window activation " +
            "for service " + JSON.stringify(service) +
            " falls outside its open-to-archive interval");
        }
        if (
          close && close.time && archived && closed &&
          (
            compareTime(close.time, archived) < 0 ||
            compareTime(close.time, closed) > 0
          )
        ) {
          add("unrehearsed", "single_release fleet evidence-window close for " +
            "service " + JSON.stringify(service) +
            " does not occur after the archive checkpoint and by closed_at");
        }
        if (activation && close && activation.index >= close.index) {
          add("unrehearsed", "single_release fleet evidence-window close for " +
            "service " + JSON.stringify(service) +
            " is not ordered after activation");
        }

        const emptySnapshotLines = lines.filter((entry) =>
          entry.line.includes("protocol cutover peer roster snapshot") &&
          entry.line.includes("[legacyPeers=0]")).length;
        if (
          !Number.isSafeInteger(entry.empty_snapshot_lines) ||
          entry.empty_snapshot_lines !== emptySnapshotLines
        ) {
          add("unrehearsed", "single_release fleet evidence-window service " +
            JSON.stringify(service) +
            " empty_snapshot_lines does not match its archived log");
        }
        const eligibleSnapshots = lines.filter((entry) =>
          entry.line.includes("protocol cutover peer roster snapshot") &&
          entry.line.includes("[clockAvailable=true]") &&
          entry.line.includes("[legacyPeers=0]"))
          .map((entry) => ({
            ...entry,
            currentBlock: Number(
              (entry.line.match(/\[currentBlock=(\d+)\]/) || [])[1] || ""
            ),
          }))
          .filter((entry) => entry.time && Number.isSafeInteger(entry.currentBlock));
        let cadenceSeen = false;
        for (let index = 1; index < eligibleSnapshots.length; index++) {
          const previous = eligibleSnapshots[index - 1];
          const current = eligibleSnapshots[index];
          const elapsed = elapsedMilliseconds(previous.time, current.time);
          if (
            elapsed >= 270000 && elapsed <= 360000 &&
            current.currentBlock > previous.currentBlock &&
            activation && close && activation.time && close.time && archived &&
            activation.index < previous.index && previous.index < current.index &&
            current.index < close.index &&
            compareTime(activation.time, previous.time) <= 0 &&
            compareTime(previous.time, current.time) <= 0 &&
            compareTime(current.time, archived) <= 0 &&
            compareTime(archived, close.time) <= 0
          ) {
            cadenceSeen = true;
            break;
          }
        }
        if (!cadenceSeen) {
          add("unrehearsed", "single_release fleet evidence-window archived " +
            "log for service " + JSON.stringify(service) +
            " has no two clock-healthy empty snapshots 270-360 seconds apart " +
            "with advancing blocks between activation and the pre-close archive");
        }
      }
    };

    inspect();
    process.stdout.write(findings.join("\n"));
  ' "${record}" "${EVIDENCE_DIR}" \
    "${REHEARSAL_R1_SERVICES[@]+"${REHEARSAL_R1_SERVICES[@]}"}"
}

# Identities are also an archive-set property. A per-record comparison can
# prove that a capture matches one record, but only the set can prove that two
# platform records did not claim the same run or capture independently.
cutover_evidence_window_set_findings() {
  node -e '
    const fs = require("fs");
    const records = process.argv.slice(1).map((recordPath) => ({
      recordPath,
      record: JSON.parse(fs.readFileSync(recordPath, "utf8")),
    }));
    const findings = [];
    const add = (what) => findings.push("unrehearsed\t" + what);
    const ownersBy = (label, values) => {
      const owners = new Map();
      for (const { recordPath, value } of values) {
        if (typeof value !== "string" || value.length === 0) continue;
        if (!owners.has(value)) owners.set(value, []);
        owners.get(value).push(recordPath.split("/").pop());
      }
      for (const [value, paths] of owners) {
        if (paths.length > 1) {
          add("evidence records [" + paths.sort().join(", ") + "] reuse " +
            label + " " + JSON.stringify(value));
        }
      }
    };

    ownersBy("rehearsal run identity", records.map(({ recordPath, record }) => ({
      recordPath,
      value: record.run_id,
    })));
    const captures = [];
    const archives = [];
    const summaries = [];
    for (const { recordPath, record } of records) {
      if (record.gate !== "single_release") continue;
      const stage = (Array.isArray(record.stages) ? record.stages : []).find(
        (entry) => entry && entry.name ===
          "every R1 node authors periodic empty roster evidence"
      ) || {};
      const refs = stage.evidence_refs || {};
      const checksums = stage.state_checksums || {};
      captures.push({
        recordPath,
        value: refs.cutover_evidence_window_capture_id,
      });
      archives.push({
        recordPath,
        value: refs.cutover_evidence_window_archive,
      });
      summaries.push({
        recordPath,
        value: checksums.cutover_evidence_window_summary_sha256,
      });
    }
    ownersBy("fleet evidence-window capture identity", captures);
    ownersBy("fleet evidence-window archive identity", archives);
    ownersBy("fleet evidence-window summary bytes", summaries);
    process.stdout.write(findings.join("\n"));
  ' "$@"
}

# Render every acceptance-relevant finding in one record. The gate contracts
# here are the authoritative rosters for evidence acceptance: each mandatory
# stage and assertion must occur exactly once and in execution order, every
# assertion must point to its designated passing stage, and each gate must
# identify every externally supplied program whose readings it uses.
#
# This is deliberately stricter than JSON shape validation. JSON Schema can
# type an array entry, but a typed entry named "preflight" is not a substitute
# for the fifteen steps of the single-release gate, and a true assertion
# linked to some other passing step proves neither property.
evidence_acceptance_findings() {
  local record="$1"
  node -e '
    const fs = require("fs");
    const [recordPath, ...expectedServices] = process.argv.slice(1);
    const record = JSON.parse(fs.readFileSync(recordPath, "utf8"));

    const contracts = {
      single_release: {
        stages: [
          "every R1 node authors periodic empty roster evidence",
          "mixed prior/R1 pre-cutover compatibility controls",
          "representative pre-cutover work including the longest wallet action",
          "cross C without restart",
          "pre-cutover legacy work survives C and completes",
          "restart across C derives mode from the chain, not from process state",
          "post-cutover straggler fails closed and enters the roster",
          "90/10 DKG consequence is visible with the straggler eligible",
          "quarantine the straggler",
          "homogeneous security-v2 controls with no legacy sightings",
          "clock failure quarantines work rather than guessing a mode",
          "quiescence with an in-flight security-v2 permit",
          "quiescence with an in-flight legacy permit",
          "quarantine preservation is complete through quiescence",
          "the cutover fleet leaves no release candidate running",
        ],
        assertions: [
          {
            name:
              "every R1 node authors periodic empty roster evidence during the go/no-go window",
            stage: "every R1 node authors periodic empty roster evidence",
          },
          {
            name:
              "the gate crosses C in-process, without a restart or a global toggle",
            stage: "cross C without restart",
          },
          {
            name:
              "a restarted node derives its mode from the canonical anchor and the current chain",
            stage:
              "restart across C derives mode from the chain, not from process state",
          },
          {
            name:
              "old post-C behavior fails closed and becomes operator-identified blocking evidence",
            stage:
              "post-cutover straggler fails closed and enters the roster",
          },
          {
            name:
              "post-C ceremonies run security-v2 with no legacy sightings",
            stage:
              "homogeneous security-v2 controls with no legacy sightings",
          },
          {
            name:
              "a failed chain-clock read refuses new work instead of assuming a side of C",
            stage:
              "clock failure quarantines work rather than guessing a mode",
          },
          {
            name:
              "graceful quiescence starts no new work and lets held permits finish",
            stage:
              "quiescence with an in-flight security-v2 permit",
          },
          {
            name:
              "single-release quiescence loses no generated signer output to an unwritable quarantine namespace",
            stage:
              "quarantine preservation is complete through quiescence",
          },
          {
            name:
              "a finished cutover rehearsal leaves no candidate able to act",
            stage:
              "the cutover fleet leaves no release candidate running",
          },
        ],
        // The dependency review is an acceptance input, not an execution
        // one. Every step above can run, pass, and be recorded without it;
        // what it decides is whether the mixed prior/R1 legacy transcripts
        // those steps exercised are release-authoritative, which is a
        // question about the dependency rather than about the run.
        inputs: ["work_driver_sha256", "tsslib_review_sha256"],
      },
      rollback: {
        stages: [
          "quiesce every R1 node with work represented",
          "quarantine preservation is complete through quiescence",
          "no prior binary starts during quiescence",
          "a forced deadline quarantines rather than completing",
          "every release candidate is stopped or network-quarantined",
          "offline state audit produces a rollback-safe manifest",
          "every in-flight permit reconciles to completion or quarantine",
          "stage the prior digest behind the all-candidate-down barrier",
          "homogeneous legacy ceremonies work with no R1 traffic left",
          "a forbidden partial rollback is blocked",
          "the prior binary loads and signs with a wallet created after C",
        ],
        assertions: [
          {
            name:
              "every R1 node drains to a stop within the reviewed termination grace",
            stage: "quiesce every R1 node with work represented",
          },
          {
            name:
              "rollback quiescence loses no generated signer output to an unwritable quarantine namespace",
            stage:
              "quarantine preservation is complete through quiescence",
          },
          {
            name:
              "no prior binary participates before every R1 node is down",
            stage: "no prior binary starts during quiescence",
          },
          {
            name:
              "all R1 is down or quarantined before any prior binary participates",
            stage:
              "every release candidate is stopped or network-quarantined",
          },
          {
            name: "the offline state audit passes before rollback",
            stage:
              "offline state audit produces a rollback-safe manifest",
          },
          {
            name:
              "every permit held at the stop completes or is audited into quarantine",
            stage:
              "every in-flight permit reconciles to completion or quarantine",
          },
          {
            name: "a partial rollback cannot be performed",
            stage: "a forbidden partial rollback is blocked",
          },
        ],
        inputs: [
          "work_driver_sha256",
          "rollback_evidence_generator_sha256",
        ],
      },
    };

    const contract = contracts[record.gate];
    if (!contract) {
      process.stdout.write(
        "unrehearsed\tunknown gate " + JSON.stringify(record.gate) + "\n"
      );
      process.exit(0);
    }

    const findings = [];
    const add = (kind, what) => findings.push(kind + "\t" + what);
    const stages = Array.isArray(record.stages) ? record.stages : [];
    const assertions = Array.isArray(record.assertions)
      ? record.assertions
      : [];

    const fleet = Array.isArray(record.r1_fleet) ? record.r1_fleet : [];
    const fleetServices = fleet
      .map((instance) => String((instance || {}).service || ""))
      .sort();
    const authoritativeServices = [...expectedServices].sort();
    if (
      fleetServices.length !== authoritativeServices.length ||
      fleetServices.some(
        (service, index) => service !== authoritativeServices[index]
      )
    ) {
      add("unrehearsed", "recorded R1 fleet service set [" +
        fleetServices.join(", ") +
        "] does not match the authoritative R1 service set [" +
        authoritativeServices.join(", ") + "]");
    }
    if (new Set(fleetServices).size !== fleetServices.length) {
      add("unrehearsed", "recorded R1 fleet contains duplicate services");
    }
    const containerIDs = fleet.map(
      (instance) => String((instance || {}).container_id || "")
    );
    if (new Set(containerIDs).size !== containerIDs.length) {
      add("unrehearsed", "recorded R1 fleet reuses one container identity");
    }

    const checkRoster = (kind, entries, required, key) => {
      const actual = entries.map((entry) => String((entry || {})[key] || ""));
      const requiredSet = new Set(required);
      const counts = new Map();
      for (const name of actual) {
        counts.set(name, (counts.get(name) || 0) + 1);
      }
      for (const name of required) {
        const count = counts.get(name) || 0;
        if (count === 0) {
          add("unrehearsed", "required " + kind + " " +
            JSON.stringify(name) + " is absent");
        } else if (count > 1) {
          add("unrehearsed", kind + " " + JSON.stringify(name) +
            " appears " + count + " times");
        }
      }
      for (const [name, count] of counts) {
        if (!requiredSet.has(name)) {
          add("unrehearsed", "unknown " + kind + " " +
            JSON.stringify(name) + " appears " + count + " time(s)");
        }
      }
      if (
        actual.length === required.length &&
        actual.some((name, index) => name !== required[index])
      ) {
        add("unrehearsed", kind + " roster is not in execution order");
      }
    };

    checkRoster("step", stages, contract.stages, "name");
    checkRoster(
      "assertion",
      assertions,
      contract.assertions.map((entry) => entry.name),
      "assertion"
    );

    const stageByName = new Map();
    for (const stage of stages) {
      const name = String((stage || {}).name || "");
      if (!stageByName.has(name)) {
        stageByName.set(name, stage);
      }
      if (stage.outcome === "fail") {
        add("refuted", "step " + JSON.stringify(name));
      } else if (stage.outcome === "blocked") {
        add("unrehearsed", "step " + JSON.stringify(name));
      }
    }

    if (record.gate === "single_release" || record.gate === "rollback") {
      // This is the JavaScript consumer-side mirror of the shell producer-side
      // QUARANTINE_PRESERVATION_METRICS list. The scaffold self-test compares
      // the two exact sets so the archive cannot silently decide on fewer
      // signals than the running rehearsal sampled and emitted.
      const quarantineSignals = [
        {
          protocol: "tBTC",
          counter:
            "participation_tbtc_quarantine_preservation_failures_total",
          incomplete:
            "participation_tbtc_quarantine_incomplete_outputs",
        },
        {
          protocol: "beacon",
          counter:
            "participation_beacon_quarantine_preservation_failures_total",
          incomplete:
            "participation_beacon_quarantine_incomplete_outputs",
        },
      ];
      const stageGauges = (stage) =>
        stage.gauges &&
        typeof stage.gauges === "object" &&
        !Array.isArray(stage.gauges)
          ? stage.gauges
          : {};
      const readGauge = (stageName, gauges, name, readingKind) => {
        if (!Object.prototype.hasOwnProperty.call(gauges, name)) {
          add(
            "unrehearsed",
            record.gate + " step " + JSON.stringify(stageName) +
              " carries no " + readingKind + " reading of " +
              JSON.stringify(name)
          );
          return undefined;
        }
        const value = gauges[name];
        if (!Number.isFinite(value)) {
          add(
            "unrehearsed",
            record.gate + " quarantine-preservation reading " +
              JSON.stringify(name) + " is not numeric"
          );
          return undefined;
        }
        return value;
      };
      // Fleet and rollback verdicts use the same per-field provenance suffix
      // as the watched-stop restart account. The shell emitter archives one
      // bit from the final useful attempt for each service; a process-global
      // "last sample" value cannot stand in for another service.
      const fleetFieldReadableSuffix =
        "read_in_final_watched_sample";

      if (record.gate === "single_release") {
        const restartStageName =
          "restart across C derives mode from the chain, not from process state";
        const restartStage = stageByName.get(restartStageName) || {};
        const restartGauges = stageGauges(restartStage);
        // assign_single_release_nodes gives the destructive controls the
        // second R1 service. The source/compose roster test holds this array to
        // that allocation, so the archive asks the process that actually
        // disappeared rather than accepting a clean reading from its peer.
        const restartService = expectedServices[1];
        if (!restartService) {
          add(
            "unrehearsed",
            "single_release restart has no volatile R1 service in the " +
              "expected fleet roster"
          );
        } else {
          const readPreservationAccount = (
            namespace,
            readingKind,
            incompleteDescription,
            recoveryDescription,
            evaluateValues = true
          ) => {
            const prefix = restartService + "." + namespace + ".";
            let readable = true;
            let incompleteOutput = false;
            for (const signal of quarantineSignals) {
              const counterName = prefix + signal.counter;
              const incompleteName = prefix + signal.incomplete;
              const counter = readGauge(
                restartStageName,
                restartGauges,
                counterName,
                readingKind
              );
              const incomplete = readGauge(
                restartStageName,
                restartGauges,
                incompleteName,
                readingKind
              );
              if (counter === undefined || incomplete === undefined) {
                readable = false;
              }
              if (incomplete !== undefined && incomplete !== 0) {
                incompleteOutput = true;
                if (evaluateValues) {
                  add(
                    "refuted",
                    "single_release restart node " +
                      JSON.stringify(restartService) +
                      " reported live incomplete " + signal.protocol +
                      " quarantine output " + incompleteDescription + ": " +
                      JSON.stringify(incompleteName) + " is " + incomplete
                  );
                } else {
                  add(
                    "advisory",
                    "single_release restart node " +
                      JSON.stringify(restartService) + " retained a nonzero " +
                      signal.protocol + " incomplete-output observation in " +
                      "its stale " + readingKind + " account: " +
                      JSON.stringify(incompleteName) + " is " + incomplete +
                      "; the freshness failure prevented that account from " +
                      "authorizing a stop, but does not erase what it retained"
                  );
                }
              } else if (
                evaluateValues &&
                counter !== undefined &&
                incomplete === 0 &&
                counter !== 0
              ) {
                add(
                  "advisory",
                  "single_release restart node " +
                    JSON.stringify(restartService) + " recorded " +
                    signal.protocol + " preservation whose write-grace " +
                    "exhausted and later completed " + recoveryDescription +
                    ": " + JSON.stringify(counterName) + " is " + counter +
                    " and " + JSON.stringify(incompleteName) + " is zero"
                );
              }
            }
            return { readable, incompleteOutput };
          };

          // This account was read before any stop signal. An unreadable or
          // live-incomplete account does not authorize the watched stop, so in
          // that case post-stop readings are neither required nor expected.
          const preStopNamespace = "pre_stop";
          const watchedStopNamespace = "pre_restart";
          const preStopSampleReadableSuffix = "sample_readable";
          const preStopSampleReadableName =
            restartService + "." + preStopNamespace + "." +
            preStopSampleReadableSuffix;
          const preStopSampleReadable = readGauge(
            restartStageName,
            restartGauges,
            preStopSampleReadableName,
            "pre-stop freshness"
          );
          let preStopFresh = preStopSampleReadable === 1;
          if (
            preStopSampleReadable !== undefined &&
            (!Number.isInteger(preStopSampleReadable) ||
              (preStopSampleReadable !== 0 && preStopSampleReadable !== 1))
          ) {
            add(
              "unrehearsed",
              "single_release restart node " +
                JSON.stringify(restartService) +
                " carries an invalid pre-stop sample freshness: " +
                JSON.stringify(preStopSampleReadableName) + " is " +
                preStopSampleReadable
            );
            preStopFresh = false;
          } else if (preStopSampleReadable === 0) {
            add(
              "unrehearsed",
              "single_release restart node " +
                JSON.stringify(restartService) +
                " did not provide a fresh pre-stop preservation sample: " +
                JSON.stringify(preStopSampleReadableName) +
                " is zero; the archived signal values are retained history"
            );
          }
          const preStop = readPreservationAccount(
            preStopNamespace,
            "pre-stop",
            "at the pre-stop guard; the stop was not authorized",
            "before the pre-stop guard",
            preStopFresh
          );
          const exitCodeSuffix = "container_exit_code";
          const exitCodeName =
            restartService + "." + watchedStopNamespace + "." +
            exitCodeSuffix;
          const watchedFieldReadableSuffix =
            "read_in_final_watched_sample";
          const watchedNames = [exitCodeName];
          for (const signal of quarantineSignals) {
            watchedNames.push(
              restartService + "." + watchedStopNamespace + "." +
                signal.counter,
              restartService + "." + watchedStopNamespace + "." +
                signal.incomplete,
              restartService + "." + watchedStopNamespace + "." +
                signal.counter + "." + watchedFieldReadableSuffix,
              restartService + "." + watchedStopNamespace + "." +
                signal.incomplete + "." + watchedFieldReadableSuffix
            );
          }
          const carriesWatchedEvidence = watchedNames.some((name) =>
            Object.prototype.hasOwnProperty.call(restartGauges, name)
          );

          if (
            !preStopFresh ||
            !preStop.readable ||
            preStop.incompleteOutput
          ) {
            if (carriesWatchedEvidence) {
              add(
                "refuted",
                "single_release restart node " +
                  JSON.stringify(restartService) +
                  " carries watched-stop evidence even though its pre-stop " +
                  "preservation guard did not authorize issuing the stop"
              );
            }
          } else {
            const exitCode = readGauge(
              restartStageName,
              restartGauges,
              exitCodeName,
              "watched-stop container exit-status"
            );
            if (
              exitCode !== undefined &&
              (!Number.isInteger(exitCode) || exitCode < 0)
            ) {
              add(
                "unrehearsed",
                "single_release restart node " +
                  JSON.stringify(restartService) +
                  " carries an invalid old-process exit status: " +
                  JSON.stringify(exitCodeName) + " is " + exitCode
              );
            } else if (exitCode !== undefined && exitCode !== 0) {
              add(
                "refuted",
                "single_release restart node " +
                  JSON.stringify(restartService) +
                  " did not stop naturally: old process exit status " +
                  JSON.stringify(exitCodeName) + " is " + exitCode +
                  "; a killed or otherwise truncated stop cannot authorize " +
                  "starting the replacement process"
              );
            }
            readPreservationAccount(
              watchedStopNamespace,
              "watched-stop",
              "during the watched stop after the pre-stop guard passed",
              "before restart reset its process-local counters"
            );
            for (const signal of quarantineSignals) {
              const watchedPrefix =
                restartService + "." + watchedStopNamespace + ".";
              for (const field of [
                { name: signal.counter, kind: "counter" },
                { name: signal.incomplete, kind: "incomplete-output" },
              ]) {
                const fieldName = watchedPrefix + field.name;
                const readableName =
                  fieldName + "." + watchedFieldReadableSuffix;
                const fieldReadable = readGauge(
                  restartStageName,
                  restartGauges,
                  readableName,
                  "watched-stop field provenance"
                );
                if (
                  fieldReadable !== undefined &&
                  (!Number.isInteger(fieldReadable) ||
                    (fieldReadable !== 0 && fieldReadable !== 1))
                ) {
                  add(
                    "unrehearsed",
                    "single_release restart node " +
                      JSON.stringify(restartService) +
                      " carries an invalid watched-stop field provenance: " +
                      JSON.stringify(readableName) + " is " + fieldReadable
                  );
                } else if (
                  fieldReadable === 0 &&
                  field.kind === "incomplete-output"
                ) {
                  add(
                    "unrehearsed",
                    "single_release restart node " +
                      JSON.stringify(restartService) + " did not re-read the " +
                      signal.protocol + " incomplete-output field in the " +
                      "final watched-stop sample: " +
                      JSON.stringify(readableName) +
                      " is zero; archived value " +
                      JSON.stringify(fieldName) + " was carried from an " +
                      "earlier sample"
                  );
                } else if (
                  fieldReadable === 0 &&
                  field.kind === "counter"
                ) {
                  add(
                    "advisory",
                    "single_release restart node " +
                      JSON.stringify(restartService) + " retained the " +
                      signal.protocol + " preservation counter from an " +
                      "earlier sample in its final watched-stop account: " +
                      JSON.stringify(readableName) + " is zero"
                  );
                }
              }
            }
          }
        }
      }

      const preservationStageName =
        "quarantine preservation is complete through quiescence";
      const preservationStage = stageByName.get(preservationStageName) || {};
      const gauges = stageGauges(preservationStage);
      // The shell roster drives the fleet and is held to the compose file by
      // the validator self-test. Requiring every service in that same roster
      // prevents one healthy node from standing in for another node that
      // stopped answering before it published whether preservation failed.
      if (expectedServices.length === 0) {
        add(
          "unrehearsed",
          record.gate +
            " acceptance received an empty expected R1 service roster; " +
            "no fleet reading can authorize the gate"
        );
      }

      const readMetric = (service, metric) => {
        const name = service + "." + metric;
        return readGauge(preservationStageName, gauges, name, "fleet");
      };

      for (const service of expectedServices) {
        for (const signal of quarantineSignals) {
          const counterName = service + "." + signal.counter;
          const incompleteName = service + "." + signal.incomplete;
          const counter = readMetric(service, signal.counter);
          const incomplete = readMetric(service, signal.incomplete);
          const counterReadableName =
            counterName + "." + fleetFieldReadableSuffix;
          const incompleteReadableName =
            incompleteName + "." + fleetFieldReadableSuffix;
          const counterReadable = readGauge(
            preservationStageName,
            gauges,
            counterReadableName,
            "fleet field provenance"
          );
          const incompleteReadable = readGauge(
            preservationStageName,
            gauges,
            incompleteReadableName,
            "fleet field provenance"
          );
          let counterProvenanceValid = counterReadable !== undefined;
          let incompleteFresh = incompleteReadable === 1;
          if (
            counterReadable !== undefined &&
            (!Number.isInteger(counterReadable) ||
              (counterReadable !== 0 && counterReadable !== 1))
          ) {
            counterProvenanceValid = false;
            add(
              "unrehearsed",
              record.gate + " node " + JSON.stringify(service) +
                " carries invalid " + signal.protocol +
                " preservation-counter provenance: " +
                JSON.stringify(counterReadableName) + " is " +
                counterReadable
            );
          } else if (counterReadable === 0) {
            add(
              "advisory",
              record.gate + " node " + JSON.stringify(service) +
                " retained the " + signal.protocol +
                " preservation counter from an earlier sample in its final " +
                "fleet account: " + JSON.stringify(counterReadableName) +
                " is zero"
            );
          }
          if (
            incompleteReadable !== undefined &&
            (!Number.isInteger(incompleteReadable) ||
              (incompleteReadable !== 0 && incompleteReadable !== 1))
          ) {
            incompleteFresh = false;
            add(
              "unrehearsed",
              record.gate + " node " + JSON.stringify(service) +
                " carries invalid " + signal.protocol +
                " incomplete-output provenance: " +
                JSON.stringify(incompleteReadableName) + " is " +
                incompleteReadable
            );
          } else if (incompleteReadable === 0) {
            incompleteFresh = false;
            add(
              "unrehearsed",
              record.gate + " node " + JSON.stringify(service) +
                " did not re-read the " + signal.protocol +
                " incomplete-output field in its final useful fleet sample: " +
                JSON.stringify(incompleteReadableName) +
                " is zero; archived value " +
                JSON.stringify(incompleteName) +
                " was carried from an earlier sample"
            );
          }
          if (incompleteFresh && incomplete !== undefined && incomplete !== 0) {
            add(
              "refuted",
              record.gate + " node " + JSON.stringify(service) +
                " is still holding " + signal.protocol +
                " output whose protected quarantine is incomplete: " +
                JSON.stringify(incompleteName) + " is " + incomplete
            );
          } else if (
            counterProvenanceValid &&
            counter !== undefined &&
            incompleteFresh &&
            incomplete === 0 &&
            counter !== 0
          ) {
            add(
              "advisory",
              record.gate + " node " + JSON.stringify(service) +
                " recorded " +
                signal.protocol + " preservation whose write-grace " +
                "exhausted and later completed: " +
                JSON.stringify(counterName) + " is " + counter + " and " +
                JSON.stringify(incompleteName) + " is zero"
            );
          }
        }
      }
    }

    const expectedAssertion = new Map(
      contract.assertions.map((entry) => [entry.name, entry.stage])
    );
    for (const entry of assertions) {
      const name = String((entry || {}).assertion || "");
      if (entry.holds !== true) {
        add("refuted", "assertion " + JSON.stringify(name));
      }

      const expectedStage = expectedAssertion.get(name);
      if (!expectedStage) {
        continue;
      }
      if (entry.evidence_stage !== expectedStage) {
        add(
          "unrehearsed",
          "assertion " + JSON.stringify(name) + " cites " +
            JSON.stringify(entry.evidence_stage || "") + " instead of " +
            JSON.stringify(expectedStage)
        );
        continue;
      }
      const stage = stageByName.get(expectedStage);
      if (entry.holds === true && (!stage || stage.outcome !== "pass")) {
        add(
          "unrehearsed",
          "assertion " + JSON.stringify(name) +
            " claims to hold against non-passing step " +
            JSON.stringify(expectedStage)
        );
      }
    }

    // Both the instruments a gate took its readings with and the external
    // approvals that evidence is accepted under. A record missing either is
    // incomplete in the same way: it reports observations nobody can attribute
    // to a reviewed input.
    const inputs = record.chain_inputs || {};
    for (const input of contract.inputs) {
      if (typeof inputs[input] !== "string" || inputs[input].length === 0) {
        add(
          "unrehearsed",
          "required reviewed release input " + JSON.stringify(input) +
            " is absent"
        );
      }
    }

    process.stdout.write(findings.join("\n"));
  ' "${record}" \
    "${REHEARSAL_R1_SERVICES[@]+"${REHEARSAL_R1_SERVICES[@]}"}"
}

# Apply the acceptance contract to a caller-selected record set. The
# in-process rehearsal passes only the record it just emitted; the archive
# validator passes every top-level record it found.
assess_evidence_record_set() {
  (($# > 0)) ||
    blocked "no evidence records were supplied for acceptance"

  local refutations=() unrehearsed=() advisories=()
  local record outcomes archive_outcomes set_outcomes kind what
  set_outcomes="$(cutover_evidence_window_set_findings "$@")" ||
    fail "cannot inspect rehearsal/capture identity ownership across the \
evidence record set"
  if [[ -n "${set_outcomes}" ]]; then
    while IFS="$(printf '\t')" read -r kind what; do
      case "${kind}" in
      refuted) refutations+=("archive set: ${what}") ;;
      unrehearsed) unrehearsed+=("archive set: ${what}") ;;
      advisory) advisories+=("archive set: ${what}") ;;
      esac
    done <<<"${set_outcomes}"
  fi
  for record in "$@"; do
    outcomes="$(evidence_acceptance_findings "${record}")" ||
      fail "cannot assess the gate contract recorded in ${record}"
    archive_outcomes="$(cutover_evidence_window_findings "${record}")" ||
      fail "cannot inspect the fleet evidence-window archive recorded in \
${record}"
    if [[ -n "${archive_outcomes}" ]]; then
      outcomes="${outcomes}${outcomes:+$'\n'}${archive_outcomes}"
    fi

    [[ -n "${outcomes}" ]] || continue
    while IFS="$(printf '\t')" read -r kind what; do
      case "${kind}" in
      refuted) refutations+=("${record##*/}: ${what}") ;;
      unrehearsed) unrehearsed+=("${record##*/}: ${what}") ;;
      advisory) advisories+=("${record##*/}: ${what}") ;;
      esac
    done <<<"${outcomes}"
  done

  local advisory
  for advisory in "${advisories[@]+"${advisories[@]}"}"; do
    note "non-fatal recovered quarantine evidence: ${advisory}"
  done

  if ((${#refutations[@]} > 0)); then
    fail "the evidence refutes the gate it records — ${#refutations[@]} \
failed step(s) or refused assertion(s): ${refutations[*]}; these records are \
admissible evidence that the rehearsal did not hold, not a passing gate"
  fi
  if ((${#unrehearsed[@]} > 0)); then
    blocked "${#unrehearsed[@]} acceptance requirement(s) across these \
records were missing, duplicated, misbound, or never executed: \
${unrehearsed[*]}; an incomplete gate contract has not been rehearsed, \
whatever the records that do exist show"
  fi

  note "every required step passed exactly once, every required assertion \
holds against its designated passing step, every required reviewed release \
input is present, every run and capture identity has one owner, and every \
named supporting archive matches its record, digest, checkpoint, and \
independently re-derived chronology"
}

# Do the records show the gates held?
#
# Admissibility is not acceptance. A record whose shape, commit, and manifest
# binding are all correct can still omit most of a gate, duplicate one passing
# step in place of another, cite an unrelated passing step for an assertion,
# omit the reviewed instrument that produced its readings, or state outright
# that a mandatory property failed. Only the exact gate contract above can be
# accepted.
assess_evidence_acceptance() {
  collect_evidence_records
  if ((${#EVIDENCE_RECORDS[@]} == 0)); then
    blocked "no evidence records found under ${EVIDENCE_DIR}; a rehearsal \
run that produced no record cannot be accepted"
  fi

  assess_evidence_record_set "${EVIDENCE_RECORDS[@]}"
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
