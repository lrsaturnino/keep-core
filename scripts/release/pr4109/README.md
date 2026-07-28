# Release rehearsal and smoke harnesses

This directory holds the release-engineering scaffolding for the coordinated
security release:

1. the container smoke matrix for the temporary `clientInfo.port` **9601
   compatibility default** — `clientinfo-port-smoke.sh` and `compose.yaml`;
2. the single-release **cutover rehearsal** scaffold — `rehearse.sh`,
   `compose.rehearsal.yaml`, and `rehearsal-evidence.schema.json`, driven
   manually or through the `cutover-rehearsal` workflow; and
3. the **release manifest** binding the service-manager termination grace to
   the client's compiled protocol bounds — `release-manifest.json`,
   `release-manifest.schema.json`, and the deployment scaffold under
   `deploy/`.

## Cutover rehearsal scaffold

The chain-clocked cutover machinery — the participation gate, per-ceremony
permits, commit fences, quiescence and the signal lifecycle controller, and
the signer quarantine namespace — is implemented in this tree and proven by
repository-local Go tests, together with the tBTC cutover ceremony
acceptance suites under the race detector: real security-v2 key-generation
transcripts — including the ten-misbehaved-seat real result — the
production-scale 90/10 split exclusion, heartbeat inactivity bands, and
cutover roster wiring, ending with an explicit report of every skipped case.
Run those proofs, which need no Docker or chain, with:

```
./rehearse.sh local-proofs
```

Three sibling stages cover the rest of the changed risk surface locally:
`./rehearse.sh static-analysis` runs the CI-enforced Go analyzers with
every tool at an immutable version — gofmt, `go vet ./...` (strictly wider
than CI's root-only vet), staticcheck 2025.1.1, gosec v2.28.0 (CI's own
gosec action floats on `master`; the pin keeps the evidence reproducible),
and golangci-lint v2.12.2 — `./rehearse.sh solidity-proofs` builds and
tests the ECDSA contracts exactly as the contracts workflow's
`contracts-build-and-test` job does: the exact Node release that job pins,
read out of it rather than restated here, plus the Corepack-managed yarn
from `packageManager` and a never-skipped `yarn install --immutable` before
`yarn build` and `yarn test` — and `./rehearse.sh shell-analysis` analyzes this scaffold
itself: `bash -n` and ShellCheck over every script here, actionlint v1.7.12
over the scaffold's own workflows (scoped to them on purpose; the unrelated
workflows carry pre-existing findings, and a gate that is red for reasons
outside its scope stops being read), and both validator self-tests. That
last stage is the one CI runs unconditionally — see
`.github/workflows/cutover-scaffold-lint.yml` below — because the checkers
that admit rehearsal evidence must never be proved only by a manual
dispatch. Every stage stamps the exact source commit into its log,
marking any divergence from `HEAD` — untracked files included — as
`-dirty`. Setting `PR4109_EXPECTED_SOURCE_COMMIT` makes the stamp a
fail-closed binding instead: the stage refuses to run at all unless the
tree under test is exactly that commit, so a log carrying a verified stamp
is proof the stamped bytes were the tested bytes.

The offline state classification the rollback barrier requires runs with
`go run ./cmd/participation-state-audit --storage-snapshot <copy>`: it
records the snapshot identity (aggregate checksum and access mode), flags any
entry outside the expected storage layout, and — when the storage password is
supplied — interprets the beacon active, beacon quarantine, and tBTC active
namespaces with the same decode paths the client's own loaders use,
cross-validating quarantine metadata against its schema, epoch, mode/anchor
arithmetic, storage location, and decrypted membership. Namespace consistency
alone is never rollback-ready: the audit exits nonzero until references to
the chain reconciliation, Bitcoin reconciliation, quiescence outcome, and
prior-reader compatibility evidence are supplied via its
`--*-evidence`/`--quiescence-report` flags **and** the expected operational
identities the evidence must bind to are supplied via its `--expected-*`
flags — Ethereum chain ID, Bitcoin network, the exact prior and current
release versions, revisions, and immutable image digests, the release epoch,
the armed cutover block, and the evidence freshness bound. Its output never
authorizes activating quarantined material by itself.

The two **container** rehearsals are mandatory release gates that cannot run
from this repository alone: they need the immutable prior-production and R1
runtime image digests, an equally immutable probe image digest, a rehearsal
chain with deployed beacon/tBTC contracts and its chain id, per-node operator
keys and configs each declaring a nonzero `clientInfo.port`, a work driver
that originates protocol work on that chain, and (for rollback) one storage
snapshot per R1 service. `rehearse.sh preflight` validates those inputs and
reports `BLOCKED` with the exact missing one.

Once preflight passes, `single-release` and `rollback` **run**: each drives
its gate as an explicit sequence of steps, starting the fleet from the
immutable digests, reading every number it records from the nodes' own
client-info ports over the internal rehearsal network, and recording each
step's own outcome. A step this release cannot execute is recorded `blocked`
with the reason rather than aborting the run, because the steps after it are
independent proofs and losing them tells a reviewer less than a record naming
exactly which step could not run. Every run therefore ends with an evidence
record on disk — validated by the acceptance stage's own validator — and the
stage exits `BLOCKED` unless every mandatory step executed. A partial
rehearsal can never read as a passed gate, and a blocked gate is never
silent about what it did prove.

`compose.rehearsal.yaml` is the fleet shell: one prior node (no gate — the
deliberate straggler) and two R1 nodes with the non-mainnet
`--protocolParticipation.cutoverBlock` override and persistent volumes. Each
service mounts `KEYSTORE_DIR/<service>/` read-only at `/mnt/keystore` and
starts with `--config /mnt/keystore/config.toml`; that per-node config must
carry the rehearsal contract addresses, the key file path under
`/mnt/keystore`, and storage directory `/mnt/storage` (the persistent
volume). The fleet spans two networks: the internal `rehearsal` network
carries inter-node protocol traffic and evidence probes with no host
publication of any port, while `chain-egress` exists only so nodes can reach
the external `ETH_WS_URL` endpoint.

Every accepted rehearsal run must produce an evidence record conforming to
`rehearsal-evidence.schema.json`: exact source SHA, per-architecture image
digests, chain ID and C, the sha256 of the reviewed `release-manifest.json`
the fleet's termination grace was taken from and the grace value itself,
per-stage canonical/callback blocks, permit modes, gauge snapshots,
transaction hashes, and non-secret state checksums. Screenshots alone are
insufficient. `./rehearse.sh validate-evidence` checks every record under
`EVIDENCE_DIR` against the schema (ajv pinned to exact versions) and
requires the recorded manifest hash *and* the recorded termination grace to
equal the checked-in manifest's — the hash alone would accept a record that
names the right manifest while claiming the fleet ran under some other
grace — so an accepted record links the termination-grace record to the
exact artifact and chain identity it carries.

Those comparisons only mean something while the checked-in manifest is
still the compiled bounds' own manifest, so the stage refuses to measure
anything until it holds the receipt proving that. `local-proofs` writes it
under `EVIDENCE_DIR/attestation` as its last step, after every proof has
passed: `release-manifest validate` accepts the reviewed file against the
compiled bounds, `release-manifest derive` records the bounds themselves in
`derived-manifest.json`, `reviewed-manifest.sha256` names the exact bytes
that were validated, and `source-commit.txt` names the commit those bounds
were compiled from. `validate-evidence` requires all three files, the hash
to match the manifest as it stands now, and the derived bounds to match the
reviewed ones field by field — hash-matching alone would accept an
attestation and a manifest regenerated together around numbers no compiled
binary produces. Only the free-form notes and the generation stamp may
differ, and keys are canonically ordered so reformatting a reviewed
manifest cannot read as drift. The attestation lives in a subdirectory
because the record glob and the workflow's record probe both look at the
top level of `EVIDENCE_DIR` only: writing the receipt never makes a
dispatch that produced no rehearsal record look like it produced one.
Running `validate-evidence` without a matching attestation is BLOCKED, not
accepted — regenerate it by re-running `local-proofs` at the same commit.

A receipt belongs to one run at one commit, and three rules keep it that
way. `local-proofs` destroys the receipt it inherits — interrupted staging
directories included — *before* it proves anything, so a run failing at any
proof leaves nothing behind; without that, a reused evidence directory kept
whichever earlier run happened to succeed in it and the acceptance stage
read that as this run's receipt. The new receipt is built beside its
destination and published by a single rename, so a reader sees a complete
receipt or none, never a half-written one or parts from two runs. And the
receipt carries the commit the binding check *proved* rather than the raw
stamp — `build-image` mode verifies a tree that legitimately diverges from
`HEAD`, so the raw stamp would call the very tree it just accepted `-dirty`
— which `validate-evidence` then requires to equal both its own
`PR4109_EXPECTED_SOURCE_COMMIT` and every record's `source_sha`. A receipt
taken at one commit can otherwise admit records from another whenever the
manifest bytes did not change between them, since the hash and bounds
comparisons have nothing to see in that case. Anything but a clean 40-hex
commit — a `-dirty` stamp, the `unknown` of a run outside a checkout — is
refused outright, and `validate-evidence` verifies its own source binding
like any other proof stage, because the manifest, schema, and comparison
rules it judges by all come out of the tree it runs from.

The validator proves itself before validating anything:
`test-validate-evidence.sh` drives the stage over fixture records — correct
binding, wrong hash, wrong grace, wrong source commit, missing binding
fields, malformed timestamp, empty record set — over fixture attestations —
absent, incomplete, a leftover staging directory, taken over other manifest
bytes, contradicting the reviewed bounds, taken at another commit than the
run is bound to, taken on a divergent tree, and one differing only in
notes, stamp, and key order — and over a divergent tree the stage must
refuse to judge from, and the stage runs that self-test first on every
invocation. The receipt lifecycle is proved through `stage_local_proofs`
itself rather than through the invalidation function alone: a reused
evidence directory is given a valid inherited receipt, the stage's proof
seam is failed the way any proof failure fails it, and the case requires
that the receipt was already gone when the proofs started, that none
survives the failure, and that the acceptance stage is blocked afterwards.
Moving the invalidation anywhere later in the stage, or dropping it, fails
those cases. Its cases run against throwaway git checkouts it creates, not
against the working tree, so every verdict is the same mid-edit on a
workstation and on a bound CI dispatch. The
`cutover-rehearsal` workflow (manually dispatched, in
`.github/workflows/cutover-rehearsal.yml`) runs the local proofs, the
static analyzers, and the contracts build/test on every dispatch — and the
container preflight when the image digests and chain inputs are supplied.
Each stage's log is archived in a per-SHA artifact whether the stage
passes or fails, and the per-SHA name is backed by an in-stage proof, not
just labeling: the workflow hands every proof stage the dispatched SHA via
`PR4109_EXPECTED_SOURCE_COMMIT`, and for the build-image stage it mounts
the checkout's `.git` and `scripts/` read-only into the container
(`.dockerignore` keeps both out of the build context) and sets
`PR4109_SOURCE_BINDING_MODE=build-image`. Under that mode `rehearse.sh`
accepts exactly the image's documented construction and nothing else.
First it restores the commit's own `.gitignore` files — only where absent,
byte-exact from the commit under verification, so restoration can mask
nothing while a tampered ignore file keeps its modified status — because
the image drops every root dotfile and would otherwise report its own
gitignored build outputs (the `keep-client` binary, the `tmp/contracts`
artifact trees) as untracked noise. Then every remaining status line must
be explained: a deletion only for a path `.dockerignore` keeps out of the
context (honoring the `.clusterfuzzlite` negations — those files must be
present; no context-excluded path holds Go code the proof stages compile),
and the families the image regenerates from published artifacts
(`**/gen/**/*.go` and `**/gen/_address/*`, minus the negated `gen/pb/*.go`,
`gen/gen.go`, and `gen/cmd/cmd.go`, which the final `COPY` overwrites with
committed bytes — the committed protobuf code the tests compile can never
differ) are never accepted as found: each one is restored byte-exact from
the dispatched commit — `git show` against the read-only-mounted `.git`,
whose `HEAD` was already proven equal to the dispatched SHA — before any
test compiles it, with the pre-restore image hash recorded for forensics.
Untracked files and any other status are always fatal, a path that cannot
be restored is fatal, and the whole tree is re-checked after restoration:
anything left beyond the context-excluded absences fails the stage. The
resolved contract artifact tarballs under `tmp/contracts` — name, exact
version, sha256 — are still recorded as the image build's input identity
(the workflow pins the `ENVIRONMENT` build-arg from its
`artifact_environment` input instead of riding the Makefile's implicit
default), but they are forensic context only: whatever npm tag or version
the image was built from, the bytes the proof stages compile are the
dispatched commit's bytes by construction. The verifier is itself under
test: `test-source-binding.sh` drives it through checkout- and
image-shaped throwaway repositories — clean image, expected absences
alone, arbitrary bytes in every regenerated family proven replaced on disk
by the committed bytes, an unrestorable path, injected or deleted source,
tampered committed generated code, missing metadata, SHA mismatch — and
runs both as an early workflow step on the runner and inside
`local-proofs`, so its verdicts land in the archived evidence.
`./rehearse.sh verify-source-binding` runs the binding check alone and
records it under `EVIDENCE_DIR`.

Which absences that verifier may explain away is decided by a
classification of the build context written out in `rehearse.sh`, and a
hand-written mirror drifts silently whenever the thing it mirrors changes.
Both `local-proofs` and `shell-analysis` therefore hold it to the commit's
own `.dockerignore`, compiled the way the build daemon reads it — comments
and blanks dropped, negations split off, patterns path-cleaned, `*` stopping
at a separator, `**` spanning whole segments, last match winning, a path
excluded when it or any ancestor matches — and compared against the script's
verdict for every tracked path. The rules are read from the commit rather
than from disk, because inside the build image the file is one of the paths
its own `.*` rule kept out. A path the script calls context-excluded while
`.dockerignore` keeps it in the context is the dangerous direction and
always fails: build-image mode would otherwise explain that file's absence
as the image's construction and accept a tree missing it. The opposite
direction is safe but still drift, and is tolerated only for the families
the image regenerates by design — the ones the verifier restores byte-exact
rather than explains away. A pattern construct the compilation does not
model, an absent `.dockerignore`, and one carrying no rule at all each fail
closed. `test-source-binding.sh` proves all of it against throwaway trees
carrying the checked-in rules and deliberate drifts of them, and refuses to
build a drift case out of a filter that removes no line, so a case cannot
pass because the rule it targets was renamed.

Which ignore file the build reads is itself decided elsewhere: the builder
selects `<dockerfile>.dockerignore` when the commit carries one and the root
`.dockerignore` only otherwise, and which Dockerfile that is comes out of the
rehearsal workflow's build step, not out of this scaffold. So the identity is
read from that step rather than restated beside the classification — the
single `docker/build-push-action` step's `context` and `file` inputs, taken
from the commit under test. A constant restating them would go stale the
moment the build step moved, silently and in the direction where the mirror
keeps checking itself against rules the build has stopped applying. Every
step shape the resolution cannot read the way the workflow parser does is
refused by name rather than guessed at: a context that is not the repository
root (the classification is written over repository-relative paths), an unset
context (the action's default is the Git context, not this checkout), a
Dockerfile named by a workflow expression or resolving outside the context or
absent from the commit, inputs written as a flow mapping, and more or fewer
than one build step.

The rehearsal workflow writes its evidence into the workspace root rather
than the script's own default, and every proof stage refuses to run on a
tree that diverges from the dispatched commit — untracked files included —
so `/rehearsal-evidence/` is an ignore rule the repository's root
`.gitignore` carries alongside the script-local one. Without it a stage's
own log would count as divergence and fail the stage that wrote it.

Everything above runs only when somebody dispatches it, which is the wrong
gate for the checkers that decide what may become release evidence. The
`cutover-scaffold-lint` workflow
(`.github/workflows/cutover-scaffold-lint.yml`) is what runs without being
asked: on every push and pull request touching the scaffold it runs
`./rehearse.sh shell-analysis`, which puts shell syntax, ShellCheck,
actionlint, the build-context mirror check, and both validator self-tests over
every change to `rehearse.sh`, to either self-test, and to the workflows
themselves. Whether failing it also *blocks a merge* is a setting outside this
repository, and one whose standing is recorded — not assumed — under "An
enforcing ruleset behind the scaffold gate" in **Hard external dependencies**.
Its path filters cover the build inputs the trust model is derived
from as well as the scaffold's own files — `.dockerignore`, both ignore files
the build could select, the root and nested `.gitignore` rules, `Dockerfile`,
and the root and per-package `Makefile`s — because each of them decides what
the verifier accepts just as directly as its own code does, and a change to
any of them can widen what an image tree is allowed to be missing without
touching a line under `scripts/`. It builds no image and runs no Go suite, so
it is cheap enough to require.

Those filters decide when this gate runs at all, so neither they nor the list
they are measured against is maintained by hand: a build moved onto another
Dockerfile takes its ignore file with it, and a filter list left behind would
leave every later change to that file ungated while the mirror check went on
passing, on a file nobody was told had changed. `shell-analysis` therefore
enumerates the required inputs out of the commit under test — the three
workflows, the resolved Dockerfile, the ignore file that Dockerfile selects,
the root `.dockerignore`, every file under this directory, and every committed
`.gitignore` and `Makefile` — and requires each `push` and `pull_request`
trigger to run on all of them, or to carry no filter at all, which runs on
everything and covers everything. Adding a `gen/Makefile` or a nested
`.gitignore` therefore extends what the gate must cover without anyone
remembering to say so.

The list is read the way the workflow parser reads it, in order with the last
matching entry deciding, so an entry listed and then negated further down is
not coverage; a pattern construct this scaffold has no reading for is refused
rather than guessed at. A `paths-ignore` list, an empty filter list, and a
workflow reachable only by dispatch each fail closed.

Trigger shape is held to the same standard, because a restriction there is
invisible to a check that reads only paths and leaves the same hole. A `push`
trigger fires only after a branch has already moved, so a `pull_request`
trigger is required outright and refused if it carries `branches` or
`branches-ignore` — every restriction of it exempts some merge — or if its
`types` list drops one of `opened`, `synchronize`, `reopened`: without
`synchronize` the gate runs when a pull request opens and never again on what
is pushed into it afterwards. The `push` trigger's own `branches: [main]` is
accepted, since the `pull_request` trigger beside it is what holds the merge.

All of that says when the gate runs and none of it says that reaching it runs
anything, so the invocation is placed too: a workflow firing on every change
to every input while its job no longer calls `rehearse.sh shell-analysis` is
the same ungated state spelled differently, and it satisfies every rule above.
`shell-analysis` requires exactly one such invocation — two would leave it
unable to say which placement the rest of the reading belongs to — and refuses
an `if:` on either that step or the job around it, along with a
`continue-on-error` on either that is not spelled `false`. A condition is
refused rather than evaluated: nothing here can tell which runs it would hold
for, and a gate whose reachability rests on a condition nothing reads is not
one this scaffold has proved reachable. A condition on some *other* step is
untouched — the evidence upload runs under `if: always()` precisely so a
failing analyzer's log survives.

Matching text is not a run, so the invocation is read rather than found. It is
looked for only in a step's `run:` body, because that is the only key that
runs anything: the same text in a step name, an `env:` value or an action's
inputs labels a step that can do nothing at all. Inside that body the shell is
read as the shell takes it — lines joined across a trailing backslash, so an
invocation continued over two of them is one command — and the command has to
be the analysis itself and the *last* thing the body does, since a step reports
its last command's exit status. Around it, the shapes that would leave the text
running while the result went nowhere are refused by name: a pipeline, a `&&`
or `||` chain, a `;` list, a background `&`, a redirection, a command
substitution, a subshell, a compound-statement keyword, and the builtins that
decide what the shell does with the lines after them — `set -n` reads a body
without executing a line of it. Anything after the invocation is refused for
the same reason: a trailing `echo` is what a failing analysis would then be
reported as.

The two ways a body runs under something other than the shell it was written
for are held the same way. A step-level `shell:` is accepted only spelled
`bash`, the runner's own default: `shell: cat {0}` leaves every line exactly
as it was and executes none of them. `defaults:` — on the job or on the
workflow — sets that same thing further out and is refused outright rather
than followed. Workflow expressions inside the body are read too, because the
runner substitutes their values before the shell parses the line: only the
runner's own contexts (`github.workspace`, `runner.temp` and their siblings)
are accepted, and an expression carrying pull-request text is refused, since
its value is what would decide the command.

Reading the command is still not reading the run. The same invocation, spelled
character for character as the checked-in one, reaches something else entirely
when the environment or the tree around it changes, and none of that touches a
line the paragraphs above read. So four more shapes are refused:

- **`env:`**, on the step, the job or the workflow. The runner writes those
  names into the step's shell before it parses anything, and a `BASH_ENV`
  there names a file that shell sources first — where a function can be
  defined under the entrypoint's own name. The accepted command word then
  resolves to that function and returns whatever it says. An assignment
  written onto the invocation itself (`BASH_ENV=… ./rehearse.sh
  shell-analysis`) is the same interception with no key to hold it, so the
  assignments ahead of the command are read rather than skipped: only
  `EVIDENCE_DIR`, the one environment name this entrypoint documents itself as
  reading, is accepted there.
- **`working-directory:`**. The invocation is a relative path; resolved from
  another directory it names another file, and what was proved to run is an
  analysis somewhere else.
- **`container:`** on the job. The image decides both what `bash` is and what
  stands at the entrypoint's path, and nothing here reads images.
- **a preceding `run:` step in the same job.** It needs no key on the analysis
  step at all: it can write another file over the entrypoint in the checkout,
  or append `BASH_ENV` to `$GITHUB_ENV` for every step after it.

What none of that proves is that a run happened, or that a run reporting
success ran this file. Everything `shell-analysis` reads is the head commit's —
the workflow, the steps around the invocation, the entrypoint itself — and the
check that would notice the invocation being deleted lives *behind* that
invocation: a commit that removes the step also removes the run that would have
objected.

**A branch-protection rule requiring the `scaffold-lint` check does not close
this**, and this scaffold does not claim it does. That rule requires a
conclusion under a job name, and the job producing it is defined by the same
head commit under test: a commit keeping the name while its job runs something
else reports success and merges. The four refusals above narrow that to shapes
this parser reads; they are a narrowing and not a closure, and shapes outside
them remain. A preceding `uses:` step runs code from another repository and
reaches `$GITHUB_ENV` and the checkout just as directly, and it is accepted
here only because refusing it would refuse the checkout the analysis needs to
read anything at all. An ordinary command ahead of the invocation in the
analysis step's own body is accepted for a narrower reason: the words ahead of
the invocation are read for the shell they open and nothing else, and a `cp`
over the entrypoint opens none — after which the accepted final command runs
whatever the copy left at that path. Both are pinned as accepted cases in
`test-source-binding.sh`, because a boundary a reader has to infer from the
absence of a case is one the next rewording moves.

The control that does close it has to be defined where the pull request cannot
edit it, which is why it cannot be **this workflow under a rule**: a
`workflows` ruleset entry names one source repository and one path, and an
entry naming this file names something every pull request here can rewrite.
What closes the boundary is a **separate workflow, sourced from a repository no
pull request into `keep-core` can write to, pinned by commit SHA, and carrying
its own copy of the analysis** rather than calling back into the commit under
test for it. This file stays advisory however that is configured. The
requirement is tracked as an outstanding external dependency, with what was and
was not checkable from here, under "An enforcing ruleset behind the scaffold
gate" in **Hard external dependencies**.
`shell-analysis`'s own log says exactly that rather than claiming otherwise: it
reports what the commit under test says, and names this file for the rest.

The same reasoning covers the other claim this scaffold makes about work it
did not do itself. `solidity-proofs` says its evidence is
`contracts-ecdsa.yml`'s `contracts-build-and-test` job's evidence, and that
holds only while the stage and the dispatch that provisions it run the Node
release that job pins — a release picked precisely because another one broke
hardhat's compile artifacts. So it is read out of that job rather than
restated beside the claim: `shell-analysis` resolves it from the named job
(not from the workflow around it, whose other jobs pin other releases) and
requires the rehearsal workflow's own `solidity-proofs` setup-node to match,
while the stage itself blocks on any other interpreter. A pin loose enough
for the runner to choose, one decided by a workflow expression, a job that
sets up Node twice or not at all, and a renamed or absent job each fail
closed. That is why `contracts-ecdsa.yml` is one of the lint's path filters:
a bump there touches no line under `scripts/`.

On a hosted runner the per-node keystore comes from the
`REHEARSAL_KEYSTORE_BUNDLE_B64` repository secret: a base64-encoded tar.gz
whose top level holds one `<service>/` directory per rehearsal node, each
with its `config.toml` and rehearsal-only key material. Generate it from a
prepared `KEYSTORE_DIR` with `tar -cz -C "$KEYSTORE_DIR" . | base64`. The
bundle MUST contain throwaway rehearsal keys only — never production
operator keys — and the dispatch reports `BLOCKED` when the secret is not
provisioned. The companion `REHEARSAL_KEEP_ETHEREUM_PASSWORD` secret carries
the key files' password.

## Release manifest: service-manager termination grace

A terminating node drains instead of dying: the first SIGTERM quiesces the
participation gate, already-started ceremonies run to natural completion, and
only the in-process backstop — `(maximum legacy completion bound + reviewed
margin) × upper block interval + RPC/processing allowance`, armed by
`quiesceBackstopDeadline` in `cmd/start.go` — forces the remainder through the
audited forced-cancellation path. All of that is useless if the external
service manager SIGKILLs the process first: the Kubernetes default grace is
30 s and systemd's is typically 90 s, both hours short of the drain a node may
legitimately need. The release manifest exists to close that gap fail-closed
rather than by hand-tuned deployment values.

`release-manifest.json` records every input of the external grace — the tBTC
and beacon completion bounds with the beacon chain configuration they came
from, the reviewed quiesce margin, the upper block interval, the
RPC/processing allowance, and the resulting in-process backstop — plus the
forced-cancellation allowance between the backstop firing and SIGKILL,
itself a compiled constant: after the forced cancellation the lifecycle
controller keeps the run context alive until every canceled permit owner
finishes its quarantine/audit cleanup and releases its permit, waiting at
most exactly that constant. Validation checks the recorded allowance against
the compiled value like every other number — never re-deriving around the
manifest's own field — so a manifest whose allowance, grace, and scaffold
values were all recomputed coherently around a different allowance is still
rejected, and a `cmd` test additionally pins the runtime wait to the
checked-in manifest's recorded allowance. The service manager counts its grace from SIGTERM delivery, but the
backstop timer arms only after the controller has been scheduled and has
quiesced the gate, the allowance timer only after the gate has closed, and
the logging and teardown run after both — so the manifest adds the compiled
process-exit headroom (`processExitHeadroomSeconds`) on top of the two timed
waits, and the external grace strictly outlasts the complete internal
shutdown sequence rather than merely equaling the sum of its timers. The
authoritative external grace is the checked sum
`in_process_backstop_seconds + forced_cancellation_allowance_seconds +
process_exit_headroom_seconds` (currently `19800 + 300 + 60 = 20160`
seconds); a lifecycle test walks a forced shutdown from the termination
instant to exit readiness and requires the controller's overhead to fit
inside that headroom. The client never reads the manifest at runtime; its
bounds are compiled in, and the manifest exists so the SIGKILL deadline is
derived from those same bounds.

The chain is enforced at three layers, each fail-closed:

- `keep-client release-manifest derive` prints the manifest derived from the
  binary's compiled bounds, and `keep-client release-manifest validate
  --manifest <path>` re-derives every number and rejects the manifest on any
  mismatch, reporting every violation at once. Because the subcommand ships in
  the client binary, the exact-image rehearsal can validate the manifest with
  the very artifact under test.
- `go test ./cmd/ -run TestReleaseManifest` pins the checked-in manifest to
  the compiled bounds and the deployment scaffold to the manifest, so a
  changed protocol constant, a stale manifest, and a drifted scaffold value
  all fail the ordinary test suite; the strict loader additionally rejects
  unknown fields, trailing content, and non-integer numbers. The
  `local-proofs` stage runs these checks under the race detector.
- `release-manifest.schema.json` describes the document shape for external
  tooling; schema validity alone is never authority — only the compiled-bound
  validation is.

`deploy/` carries the two scaffold fragments operators apply, each holding
exactly the manifest's grace: `keep-client-termination-grace.k8s-patch.yaml`
(`spec.template.spec.terminationGracePeriodSeconds`, applied with `kubectl
patch --patch-file`) and `keep-client-termination-grace.systemd-dropin.conf`
(`TimeoutStopSec` plus an explicit `KillSignal=SIGTERM`, installed as a
`<unit>.service.d/` drop-in). The rehearsal fleet carries the same contract:
both R1 services in `compose.rehearsal.yaml` set the manifest's grace as
their `stop_grace_period`, because Docker's 10-second default would SIGKILL
a draining node long before its backstop and no rollback rehearsal could
ever evidence natural completion — the prior node deliberately keeps the
default, having no drain semantics to protect. The grace is a ceiling, not a
wait — a node whose drain completes exits immediately. Changing any compiled
bound — the cleanup allowance included — requires regenerating the manifest
with `derive`, re-reviewing it, and updating every scaffold site; the `cmd`
tests refuse any shortcut through that sequence.

## Hard external dependencies

### An enforcing ruleset behind the scaffold gate

`shell-analysis` proves what the commit under test *says* about
`cutover-scaffold-lint.yml`, and it cannot prove that a run of that workflow
happened or that a run reporting success ran this analyzer — the check lives
behind the invocation it checks, and the job producing the check is defined by
the same head commit. The reading detailed under "Cutover rehearsal scaffold"
narrows the shapes a green conclusion can hide (an `env:` at any level, an
assignment on the invocation, a `working-directory:`, a job `container:`, a
preceding `run:` step); it does not close the boundary. A preceding `uses:`
step is accepted while reaching `$GITHUB_ENV` and the checkout just as
directly, and so is an ordinary command ahead of the invocation inside the
analysis step's own body: a `cp` over the entrypoint is neither a shell
construct nor a builtin, and that is all the words ahead of the invocation are
read for. Both shapes are pinned as accepted in `test-source-binding.sh`, so a
later reading of the refusals cannot quietly grow into a claim of closure.

Only a control defined where the pull request cannot edit it closes this.
GitHub's is a **ruleset rule requiring a workflow** — "Require workflows to
pass before merging", spelled `"type": "workflows"` in the API, settable at
the organisation or enterprise level. Its `parameters.workflows` is a list of
entries, each requiring a `repository_id` and a `path`, and each carrying two
optional pin fields: `ref`, documented as "the ref (branch or tag) of the
workflow file to use", and `sha`, "the commit SHA of the workflow file to
use". It replaced Actions Required Workflows, which stopped being configurable
on 2023-09-20 and became unreachable on 2023-10-18:
`/orgs/{org}/actions/required_workflows` is not the control to look for, and
whatever it answers settles nothing about the present
one. A branch-protection rule requiring the `scaffold-lint` check is not a
substitute either — it requires a conclusion under a job name that the commit
under test defines.

Because an entry names one repository and one path, the rule cannot be pointed
at `cutover-scaffold-lint.yml` and be beyond this repository's reach at the
same time: requiring that path requires a file every pull request here can
rewrite, and the run it demands is the run the commit under test defines. **The
required workflow is a different file from the gate checked in here**, and the
gate checked in here stays advisory however the ruleset is configured.

Three properties of that entry are what close the boundary, and any one
missing reopens it:

- **The source repository is not this one.** `repository_id` must resolve to a
  repository no pull request into `keep-core` can write to. The integer alone
  settles nothing a reader can check, so the record names the repository it
  resolves to.
- **The pin is immutable.** `ref` names a branch or a tag and both move — a
  push to the branch, or a tag re-pointed at another commit, changes what runs
  without changing the rule, so a `ref`-only entry pins a name and not the
  bytes behind it. `sha` is what binds bytes, and is what the record carries. A
  tag is admissible only with evidence that it cannot move: an `active` ruleset
  on the source repository whose `target` is `tag`, whose conditions select
  that tag rather than some other one, whose `bypass_actors` do not hand it
  back to the maintainers the pin exists to bind, and whose rules include
  `deletion`, `update` and `non_fast_forward`, recorded the way this one is —
  the same exact-condition reading the ruleset behind the gate gets below,
  because a tag ruleset aimed elsewhere holds nothing here either.
- **The analysis is carried by that pinned source.** A pinned workflow that
  merely invokes the head commit's `scripts/release/pr4109/rehearse.sh`
  re-inherits everything above: the analyzer it runs is still the one the
  commit under test supplies. The SHA has to bind the checker implementation
  too, and the record names the analyzer that SHA binds.

Enforcement state belongs in the record rather than being assumed from the
ruleset's existence: `enforcement` is one of `disabled`, `active` and
`evaluate`, and `evaluate` is a dry run that reports without blocking a merge.
Only `active` gates anything. The carve-out that can leave an `active` ruleset
gating nothing for the merge that matters is recorded with it:
`bypass_actors` names actors holding permission to set the ruleset's rules
aside, each under a `bypass_mode` of `always`, `exempt` or `pull_request` that
governs when that permission is available and whether the actor has to reach
for it, and `pull_request` is not the narrow one it reads as. It confines that
actor's bypass to pull requests, and a merge into `main` goes through one, so
an actor listed that way can choose to bypass on exactly the event this gate
exists for. What the record carries is that capability, not a prediction it
gets exercised: a bypass declined on one merge is still available on the next,
so each actor's type, identity and mode belong in the record whether or not
one has ever been taken. `exempt` is the mode to read hardest — the rules are
not run for that actor and no bypass audit entry is written, so it is the
carve-out that leaves no trace on the merge it lets through. `pull_request` is
applicable only to branch rulesets, which is why it cannot appear on the `tag`
ruleset the pin above leans on: a bypass actor there holds `always` or
`exempt`, and both are unconditional.
The `workflows` rule's own `do_not_enforce_on_create` is recorded beside it
but is not a second such carve-out, and reading it as one waives a gate that
is in fact still standing: it is documented as allowing repositories and
branches to be *created* when a check would otherwise prohibit it, so it
waives the rule for the creation of a ref and not for an update to one that
exists. A merge into an existing `main` is an update, and this field leaves it
gated. What it does reach is a `main` deleted and created again, which is why
the record carries it rather than dropping it.

`enforcement`, `target` and the entry's own three properties still say nothing
about *what* the ruleset is aimed at. `target` is one of `branch`, `tag`,
`push` and `repository`: it names a kind of ref, not an instance, and the
instances come from `conditions`. An organisation-level branch ruleset pairs
`ref_name` with exactly one repository selector — `repository_name`,
`repository_id` or `repository_property` — and those three do not read alike,
so a record resolving "the conditions" generically resolves nothing:

- `ref_name` is an `include`/`exclude` pair of ref names or patterns, on all
  three variants. `include` accepts `~ALL` and `~DEFAULT_BRANCH` alongside an
  explicit `refs/heads/main` and one entry matching is enough; `exclude` fails
  the condition when any entry matches, so it takes back what `include`
  matched.
- `repository_name` is that same shape over repository names and patterns,
  `~ALL` accepted, plus a `protected` flag that governs renaming the targets
  and says nothing about what the ruleset is aimed at.
- `repository_id` is not that shape at all. It carries a `repository_ids`
  array of integers and one of them matching is the entire test: there is no
  repository-level `exclude` to take that back, and no `~ALL`. What it needs
  is the resolution the integer withholds — the ID read back as
  `threshold-network/keep-core`.
- `repository_property` is an `include`/`exclude` pair over `name` /
  `property_values` / `source` objects rather than strings, and its `include`
  is conjunctive where the others are disjunctive: *all* listed properties
  must match, while `exclude` still fails on any. It therefore aims at
  whatever set of repositories currently carries those values — a set this
  one can enter or leave without the ruleset changing — so the record has to
  name the properties and values, not merely which selector was used.

So an `active`, unbypassed, externally SHA-pinned entry carrying its own
analyzer can hold every property above and gate nothing here, by being aimed
at another repository or at every branch except this one — and it reads, in a
record naming only the target, as though it closed the boundary. The record
therefore resolves the conditions instead of reproducing them: the exact
`conditions` object, the repository selector in use carrying the evidence that
resolves it to `threshold-network/keep-core` — the ID read back to a
repository, or the property names and values read back to this repository's —
and that `ref_name` matches `refs/heads/main`, by pattern, by `~ALL`, or by
`~DEFAULT_BRANCH` while `main` is the default branch, with `ref_name.exclude`
not removing it again.

Standing, checked empirically on 2026-07-28:
`GET /repos/threshold-network/keep-core/rulesets?includes_parents=true`
returns an empty list. That is the informative probe — `includes_parents`
defaults to `true` and pulls in rulesets configured at higher levels that
apply to this repository, and GitHub filters only `bypass_actors` by the
caller's permission — so from outside the organisation this is the strongest
available signal, and it is a negative one: no ruleset, repository-level or
inherited, applies here. `GET /orgs/threshold-network/rulesets` returns 404
without `admin:org`, and GitHub answers 404 rather than 403 for organisation
resources a caller cannot see, so on its own it distinguishes an absent
ruleset from an invisible one not at all.
`GET /repos/threshold-network/keep-core/branches/main/protection` returns 404,
which for that endpoint likewise means either no protection or no admin rights
and so settles nothing either way.

Until an organisation admin configures such a ruleset, **the gate is
advisory**: a commit deleting `cutover-scaffold-lint.yml` deletes its own
enforcement silently, and a green `scaffold-lint` conclusion is evidence that
something under that name succeeded, not that this analyzer ran. Evidence that
rests on the scaffold's own checkers having judged a change should be read
with that in mind. Unblocking is a configuration change plus the record, not a
code change here, and the record has to name the ruleset's id and name, its
target, its exact `conditions` object together with the evidence resolving
that object's repository selector to this repository and its `ref_name` to
`refs/heads/main`, its `enforcement` — which must read `active` — its
`bypass_actors` with each actor's type, identity and `bypass_mode`, and the
rule's `do_not_enforce_on_create`, and, for the `workflows` entry, the
`repository_id` together with the repository it resolves to, the `path`, the
`sha` pinning it — or, for a tag, the tag together with the ruleset holding
that tag immutable — and the analyzer that pin binds. A record naming this
repository as the source, carrying a `ref` where the `sha` belongs, or leaving
the conditions unresolved, records something that does not close the boundary.

### Reviewed tss-lib fork with an immutable per-party legacy mode

R1's per-ceremony compatibility bundle covers all four wire- and
transcript-sensitive decisions (`pkg/protocol/compatibility`): the
announcement session-ID formats, the ECDH symmetric-key derivation, the G1
hash-to-point mapping, and the tECDSA proof-transcript configuration. The
bundle travels from the participation permit into every tECDSA DKG and
signing party (`pkg/tecdsa/dkg`, `pkg/tecdsa/signing` take the bundle
explicitly — there is no default), and a repository check
(`pkg/protocol/compatibility/transcript_ownership_test.go`) fails the build
tests if a call site bypasses it.

The legacy arm of the transcript decision has no implementation to select: a
Go build resolves exactly one `github.com/bnb-chain/tss-lib` replacement
(currently the hardened `threshold-network/tss-lib` revision `86bd1a375cc0`
in `go.mod`), and that revision exposes no per-party protocol mode.
Reproducing the legacy transcript requires extending that fork so each local
party is constructed with an immutable legacy/security-v2 setting: legacy
reproduces the prior-production proof transcript byte for byte — including
the prior wire message formats, whose protobuf schema the hardened revision
changed — security-v2 requires the session nonce, and every mode-independent
memory-safety fix stays active in both modes.

That extension is reviewed cryptographic work outside this repository, and an
unreviewed in-tree fork is not an accepted substitute. The dependency was
re-verified empirically on 2026-07-27: `git ls-remote --heads --tags
https://github.com/threshold-network/tss-lib` showed `master` at exactly the
pinned `86bd1a375cc0` revision and no tags; the remote carries development
branches (`advisory-fix`, `codex/*`, `constant-time-hardening`,
`integrate-bnb-hardening`, `resharing-fix-upstream`), and a shallow clone of
every branch tip grepped for any per-party legacy/transcript-mode API surface
found zero hits on all of them — the reviewed dual-mode revision does not
exist anywhere on the fork remote yet, so the dependency is outstanding
upstream, not merely unpinned here. Until the reviewed fork commit is pinned in `go.mod`:

- tBTC ceremonies **fail closed on legacy permits** — deliberately, at two
  layers. The authoritative fence is the legacy bundle itself: its TSS
  configuration returns `ErrLegacyTSSTranscriptUnavailable`
  (`pkg/protocol/compatibility`), so no tECDSA party can be constructed in
  legacy mode anywhere in the tree. The tECDSA executors additionally refuse
  legacy permits up front (`pkg/tbtc/dkg.go`, `pkg/tbtc/signing.go`,
  `pkg/tbtc/node.go`) so a refused ceremony never announces itself to peers.
- The pre-cutover interop acceptance cases of smoke gates 1 and 2 — mixed
  prior/R1 legacy signing and DKG succeeding before the cutover block, and a
  legacy-anchored ceremony completing with legacy peers — cannot produce
  evidence. They are recorded as explicit skips in
  `pkg/tbtc/signing_cutover_integration_test.go` and
  `pkg/tbtc/dkg_cutover_integration_test.go`.
- The `single-release` container rehearsal still exits `BLOCKED` with every
  image/chain input supplied, because its mixed prior/R1 pre-cutover steps
  cannot execute. It no longer refuses the whole sequence to say so: the run
  starts the fleet, executes the steps that need no legacy capability —
  crossing C in-process, restart-derives-mode-from-anchor, the straggler
  negative control and its quarantine, clock failure, quiescence with a
  security-v2 permit — and records the four legacy-dependent steps as
  `blocked` against this same dependency. The emitted record is what shows
  which half of the gate this release already satisfies.

Unblocking requires the reviewed fork commit, its review record, transcript
fixtures proving both modes reproduce their exact expected bytes, and the
`go.mod` pin. The keep-core changes are then confined to: pinning the fork,
replacing the legacy bundle's `ConfigureTSSParameters` refusal with the
fork's legacy-mode configuration, deleting the three executor-level early
refusals, and turning the skip-marked cases into runnable acceptance tests.
Every other integration point already receives its mode from the permit.

## clientInfo.port 9601 compatibility smoke matrix

### What is proven where

| Layer | Proof | Runnable |
|---|---|---|
| Port resolution (flag/TOML precedence, both explicit-zero paths, custom port) | Go unit/config tests | ✅ locally, no Docker/chain |
| Port → listener decision (`0` disables, nonzero enables) | `pkg/clientinfo` unit tests | ✅ locally, no Docker/chain |
| Runtime image bakes the 9601 default | `clientinfo-port-smoke.sh image-default-check` | ✅ Docker only, no chain |
| Container listens on 9601 / custom, serves meaningful `/metrics` | `clientinfo-port-smoke.sh listener-matrix` | ⚙️ needs Docker **and** a chain endpoint + operator key |
| Testnet scrape from the real monitoring host, 3 consecutive intervals, current revision/epoch | — | 🔲 **manual / ops follow-up** |
| External untrusted-network probe: raw `9601` / `/diagnostics` unreachable unless an authenticated proxy is in front | — | 🔲 **manual / ops follow-up** |

### Unit/config acceptance (fully runnable locally)

```
go test ./cmd/... ./config/... ./pkg/clientinfo/... \
  -run 'ClientInfoPort|TestReadConfig_ClientInfoPortZero|Initialize_'
```

Proves: no flag/TOML resolves to 9601 by default binding while an explicit
`--clientInfo.port 0` (CLI) and `[clientInfo] Port = 0` (TOML) both resolve to
zero; an explicit 9601 and a custom port enable; and `clientinfo.Initialize`
returns `(nil, false)` for port 0 and a registry for a nonzero port.

### Container matrix (this harness)

| Case | Configuration | Expected result |
|---|---|---|
| compatibility default | omit all client-info settings | TCP 9601 listens internally; `GET /metrics` succeeds |
| explicit compatibility | TOML `Port = 9601` | same |
| CLI compatibility | `--clientInfo.port 9601` | same |
| custom | `--clientInfo.port 9137` | only 9137 responds |
| CLI disabled | `--clientInfo.port 0` | no listener; node still starts |
| TOML disabled | `[clientInfo] Port = 0` | no listener; node still starts |

`clientinfo.Initialize` runs only after `ethereum.Connect`, so the listener
cases require a node that can actually start against a chain (developer network
or a testnet RPC + operator key). Provide those and run:

```
IMAGE=keep-client@sha256:<candidate-image-digest> ETH_RPC=... KEY_FILE=... KEY_PASSWORD=... \
  ./clientinfo-port-smoke.sh listener-matrix
```

The harness's `require_digest` rejects a mutable tag: `IMAGE` (and `PROBE_IMAGE`)
MUST be pinned by an immutable `@sha256:` digest so a smoke run tests exactly the
bytes operators will deploy.

The harness runs each case as a node container on a **private user-defined
bridge network** and probes the client-info port from a sibling `curl` container
— never via a published host port. The network is not made Docker `--internal`
because the node must still reach its Ethereum/Electrum backends to start; the
security property this harness proves is container-to-container reachability with
**no host publication of 9601**. Proving that raw `9601`/`/diagnostics` are
unreachable from a genuinely untrusted external network is a separate manual /
ops follow-up (see the matrix above). `compose.yaml` shows the same
private-network topology for the compatibility-default case.

## Guardrails

- 9601 is a **temporary** compatibility default; the follow-up R2 release flips
  it back to `0` after the monitoring migration. Do not treat this harness as
  permission to publish raw `9601`/`/diagnostics` publicly — always reach it over
  a trusted path (firewall/VPN or an authenticated proxy).
- Do not add an unconditional `-p 9601:9601` to any operator-facing Docker
  sample; the listener stays internal to the container unless explicitly
  disabled with `--clientInfo.port 0`.
