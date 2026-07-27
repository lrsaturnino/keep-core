# Release rehearsal and smoke harnesses

This directory holds two harnesses for the coordinated security release:

1. the container smoke matrix for the temporary `clientInfo.port` **9601
   compatibility default** — `clientinfo-port-smoke.sh` and `compose.yaml`;
   and
2. the single-release **cutover rehearsal** scaffold — `rehearse.sh`,
   `compose.rehearsal.yaml`, and `rehearsal-evidence.schema.json`, driven
   manually or through the `cutover-rehearsal` workflow.

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

Two sibling stages cover the rest of the changed risk surface locally:
`./rehearse.sh static-analysis` runs the CI-enforced Go analyzers with
every tool at an immutable version — gofmt, `go vet ./...` (strictly wider
than CI's root-only vet), staticcheck 2025.1.1, gosec v2.28.0 (CI's own
gosec action floats on `master`; the pin keeps the evidence reproducible),
and golangci-lint v2.12.2 — and `./rehearse.sh solidity-proofs` builds and
tests the ECDSA contracts exactly as the contracts workflow does: Node
18.15.0, the Corepack-managed yarn from `packageManager`, and a
never-skipped `yarn install --immutable` before `yarn build` and
`yarn test`. Every stage stamps the exact source commit into its log,
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
runtime image digests, a rehearsal chain with deployed beacon/tBTC contracts,
per-node operator keys and configs, and (for rollback) storage snapshots plus
an independent network vantage point. `rehearse.sh preflight` validates those
inputs; `single-release` and `rollback` refuse to run — reporting `BLOCKED`
with the exact missing input — until they are supplied and the stages are
extended against the real fleet.

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
digests, chain ID and C, per-stage canonical/callback blocks, permit modes,
gauge snapshots, transaction hashes, and non-secret state checksums.
Screenshots alone are insufficient. `./rehearse.sh validate-evidence` checks
every record under `EVIDENCE_DIR` against the schema, and the
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

On a hosted runner the per-node keystore comes from the
`REHEARSAL_KEYSTORE_BUNDLE_B64` repository secret: a base64-encoded tar.gz
whose top level holds one `<service>/` directory per rehearsal node, each
with its `config.toml` and rehearsal-only key material. Generate it from a
prepared `KEYSTORE_DIR` with `tar -cz -C "$KEYSTORE_DIR" . | base64`. The
bundle MUST contain throwaway rehearsal keys only — never production
operator keys — and the dispatch reports `BLOCKED` when the secret is not
provisioned. The companion `REHEARSAL_KEEP_ETHEREUM_PASSWORD` secret carries
the key files' password.

## Hard external dependencies

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
- The `single-release` container rehearsal stays `BLOCKED` even with all
  image/chain inputs supplied, because a mixed prior/R1 fleet cannot pass its
  pre-cutover compatibility stages.

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
