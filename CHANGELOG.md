# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0/).

## [Unreleased]

### Added
- Added a `golangci-lint` (gocritic/ruleguard) rule and `client-golangci` CI job that bans variable-indexed `tx.Outputs[i]`/`tx.Inputs[i]` access in non-test production code, steering callers to the bounds-checked `OutputAt`/`InputAt` accessors (#36)
- Added native Go fuzz targets across the beacon, network/security handshake, protocol, tBTC, tECDSA (DKG and signing), and bitcoin packages, asserting panic-free unmarshaling/deserialization of arbitrary untrusted input (#36)
- Added a non-blocking `client-race-test` CI job (race detector, scheduled and manual-dispatch only) (#36)
- Added the dev-only `github.com/quasilyte/go-ruleguard/dsl v0.3.23` tooling dependency (pinned via `tools.go`) used by the new lint rule (#36)
- ClusterFuzzLite CI integration: a per-PR fuzzing workflow (`code-change` mode, 300s, address sanitizer) and a scheduled nightly batch fuzzing workflow (`batch` mode, 1800s, daily cron + manual dispatch), backed by `.clusterfuzzlite/` build infra (Dockerfile, `project.yaml`, `build.sh` compiling 42 `Fuzz*` targets, plus a `check_targets.sh` drift guard). The per-PR workflow triggers on changes to `pkg/**`, `.clusterfuzzlite/**`, `go.mod`, `go.sum`, `.dockerignore`, `.github/workflows/cflite_pr.yml`, and `.github/workflows/cflite_batch.yml` (i.e. fuzzed code, fuzz build infra, dependencies, and the workflows themselves) (#37)
- New `target-sync` PR check that runs `.clusterfuzzlite/check_targets.sh` on every qualifying PR and fails the PR when a `Fuzz*` target under `pkg/` is not registered in `build.sh`; an unregistered target would otherwise silently get zero ClusterFuzzLite coverage (#37)
- `rapid` model-based property tests for retry participant selection (F-009): sub-multiset / all-or-nothing operator inclusion, minimum-seat retention, determinism, and operator-exclusion invariants for key generation and signing (#37)
- `rapid` property test for Ethereum redemption event conversion (F-014) asserting `convertRedemptionRequestedEvent` maps `TxMaxFee` from the event's `TxMaxFee` (not `TreasuryFee`) and reproduces all scalar fields (#37)
- `FuzzIdentityUnmarshal` fuzz target asserting the libp2p `identity.Unmarshal` never panics on arbitrary input (#37)
- Bitcoin transaction fuzzing improvements: a serialize/re-parse fixed-point property in `FuzzTransactionDeserialize` plus two pinned seed-corpus entries capturing parser quirks (trailing bytes accepted; witness-encoded zero-input txs colliding with the segwit marker on re-encode) (#37)
- Test-only dependency `pgregory.net/rapid v1.3.0` for property-based tests (#37)
- `.clusterfuzzlite/README.md` documenting the fuzz build setup; `.dockerignore` adjustments so the fuzz build context includes `.clusterfuzzlite/**` and committed protobuf code (`**/gen/pb/*.go`); and a `.gitignore` entry for `rapid` failure artifacts (`testdata/rapid/`) (#37)
- DKG test interceptor `Strategy` action API (`Strategy`, `Outbound`, `PassThrough`, `FromRules`, `NewNetworkWithStrategy`) supporting drop/mutate/duplicate/inject of messages, targetable per-sender and per-message-type; the prior `Rules` modify-or-drop API is retained via a `FromRules` back-compat adapter (#34)
- `dkgtest.RunTestWithStrategy` to run full DKG tests with a `Strategy`; existing `RunTest` is unchanged and now delegates through it (#34)
- `byzantine` test-harness package with predicate-based strategy constructors `Inactive`, `Withhold`, `Flood`, `Corrupt`, and `MatchAll` (#34)
- Unit tests for the new Strategy API and the `byzantine` constructors, full-DKG integration demos (Withhold/Flood/Corrupt), and an env-gated (`DETERMINISM_PROBE`) determinism probe (#34)
- CI job "Run Go race tests (Tier-2 interceptor)" running `go test -race` over `./pkg/internal/interception/...` and `./pkg/internal/byzantine/...` (#34)
- Test-only `pkg/internal/signingtest` harness (`RunTest`/`RunTestWithTimeout`) that runs the whole tECDSA signing protocol across a group of members over a local broadcast channel, with optional Byzantine interception, plus assertion helpers (`AssertSignatureGenerated`, `AssertMemberFailuresCount`, `AssertSameSignature`, `AssertNoDivergentSignatures`, `AssertValidSignature`) (#38)
- First whole-protocol signing integration tests in `pkg/tecdsa/signing/integration_test.go`: a happy-path case (5 members agree on one valid signature) and a Byzantine withhold case (member 2 inactive yields 0 signatures and 5 member failures), verifying that a malicious participant stalls signing (0 signatures, 5 member failures), and guarding against divergent or invalid signatures should a future change ever let members complete under this scenario (#38)
- Test-only Byzantine coordination harness for the tBTC wallet-coordination layer (`pkg/tbtc/coordination_byzantine_test.go`), injecting adversarial behavior by wrapping a specific operator's outbound channel with an `interception.Strategy`; includes an honest baseline scenario proving the interception seam does not perturb the protocol (#39)
- Withholding-leader test scenario asserting the safety invariant that a silent coordination leader (one that generates a proposal but never broadcasts it) can at worst cause denial of service (followers coordinate no action) but can never make followers act on an unreceived proposal or diverge onto split outcomes (#39)
- Byzantine integration test `TestByzantine_F008_ReconstructionPathExecutes` driving an honest quorum (groupSize 5, threshold 3) down the phase-12 reconstructed-share else-branch — the F-008 crash site — to corroborate that the contested beacon-DKG reconstruction nil-deref is a false positive (the missing-share branch does not form under real adversarial execution) (#40)
- `dkgtest` log-capture harness: thread-safe `capturingLogger` (records `Errorf` output that `MockLogger` discards), `(*dkgtest.Result).LoggedErrors()` accessor, and `dkgtest.AssertNoReconstructionGap` assertion that fails the test if the guard's "missing revealed share" error ever fires, making the absence of the F-008 gap observable (#40)
- Unit test `TestCapturingLoggerAndGapDetection` verifying the capture/detection logic (positive and negative cases) so the new assertion cannot be vacuously green (#40)
- `security/` directory with white-box pentest deliverables: architecture, attack surface, critical paths, crypto review, threat model, and smart-contracts analysis, plus 17 verified findings (F-01 through F-17) each with a code reference and status (#2)
- `SECURITY-BREAKING-CHANGES.md` documenting the F-02/F-03 wire-breaking changes, the BC-1..BC-10 / OV-1..OV-3 operator reference table, and the required coordinated-upgrade path (#2)
- Domain-separation info labels for ECDH key derivation: `gjkrEcdhInfo`, `dkgEcdhInfo` (`tecdsa-dkg`), and `signingEcdhInfo` (`tecdsa-sign`), plus a compile-time assertion that `MemberIndex` is 1 byte (#2)
- Tests for ECDH domain separation, `G1HashToPoint` determinism/wire-format, deduplicator concurrency, and Solidity reentrancy + storage layout (#2)
- Per-PR breaking-change, redeploy, and risk analysis notes under `keep-core-release/<org>/<repo>/<pr>.md`, covering this repo's PRs (#2, #8, #9, #10, #11, #13) and upstream Threshold repos keep-core (#3945, #3948, #3952), keep-common (#16, #17), and tss-lib (#4, #5, #6) (#14)
- `keep-core-release/<org>/<repo>/<pr>.md` directory convention for tracking post-merge release analysis going forward (#14)

### Release scope (non-security)

The following changes are included in this PR for convenience but are **not** part of the coordinated cryptographic flag-day (BC-1..BC-10). They do not affect DKG/signing wire compatibility and should be treated as independently reviewable operational/CI scope when bisecting or rolling back:

- ClusterFuzzLite continuous fuzzing (`.clusterfuzzlite/`, `.github/workflows/cflite_pr.yml`, `.github/workflows/cflite_batch.yml`) (#37)
- `.github/workflows/client.yml` rewrite and contract-docs workflow updates (#8, #37)
- Kubernetes dev Ropsten statefulset/service edits and `eth-tx-rpc-ws-networkpolicy.yaml` (#8)
- Deletion of `infrastructure/kube/keep-prd/monitoring/monitoring-ingress.yaml` (#8)
- Private-testnet bundle guide update under `infrastructure/eth-networks/` (#8)

### Changed
- Re-landed the Tier 0 (lint rule, race-detector CI job, bounds-checked accessors) and Tier 1 (native fuzz targets) portions of the previously reverted #33 testing/correctness hardening work as a single consolidated changeset, corresponding to the original PRs #29 and #30; the ClusterFuzzLite continuous fuzzing (#31) and rapid property tests (#32) are NOT included in this PR (#36)
- Nightly scheduled `-race` CI job: timeout raised from 30m to 60m, and on scheduled-run failure it now upserts a labeled GitHub issue (`race-detector-failure`); behavior is CI-only and gated to scheduled runs (#37)
- Narrowed the ruleguard lint rule for raw `Outputs[$i]`/`Inputs[$i]` indexing to fire only on `bitcoin.Transaction` / `*bitcoin.Transaction`, reducing false positives on unrelated and generated types (#37)
- `dkgtest` DKG test runs now share a single `capturingLogger` across member goroutines instead of constructing a per-call `MockLogger`, adding mutex-synchronized error capture during test execution; only `Errorf` behavior changes (capture vs discard), all other log levels are unchanged and no production protocol behavior is affected (#40)
- **BREAKING (wire):** Changed DKG session-ID format to `dkg-<seedHex>-<attempt:016x>` (typed prefix and fixed-width attempt number) and signing session-ID format to `signing-<messageHex>-<startBlock:016x>-<attempt:016x>`. The fixed-width formats guarantee every session ID clears tss-lib's 16-byte minimum-length floor, but are incompatible with the pre-hardening `<x>-<y>` form, so un-upgraded peers compute mismatched session IDs (#8)
- **BREAKING (behavioral):** Made the signing session ID depend on the attempt start block (`announcementEndBlock`) in addition to message digest and attempt number, introducing a new cross-node agreement requirement: even same-version peers that disagree on the attempt start block compute different session IDs and fail to interoperate (#8)
- Computed the session ID once per attempt and threaded it through attempt parameters so the announcer and the protocol cannot drift apart on the GG20 session binding (#8)
- `signing.NewLocalParty(...)` is now called with an additional `fullBytesLen` argument (`(Curve.Params().N.BitLen()+7)/8`). In the hardened tss-lib this parameter is variadic, so existing 5-argument callers still compile; omitting it, however, changes signing message byte-width / leading-zero handling, so this is a behavioral (not compile-breaking) change (#8)
- Added `pull-requests: read` (and job-level `contents: read`) permissions to path-filter jobs in CI workflows so PR change detection runs under `GITHUB_TOKEN` (#8)
- Added tests covering the new session-ID formats, the minimum entropy width, and the session-nonce derivation (`SHA512_256` of the session ID) for DKG and signing (#8)
- `ephemeral.PrivateKey.Ecdh` now takes an `info []byte` parameter and derives the symmetric key with HKDF-SHA256 instead of SHA-256; this changes the exported signature (compile break for external callers) and the derived session key (wire-incompatible with older nodes) (#2)
- `altbn128.G1HashToPoint` reimplemented from try-and-increment to a bounded counter-based `SHA-256(m || ctr)` (max 64 attempts); it produces a different G1 point for the same input (consensus-incompatible) and now panics if no valid point is found within the bound (#2)
- `RandomBeacon` relay-entry gas offset `_relayEntrySubmissionGasOffset` raised from 11250 to 13450 to account for the reentrancy-guard SSTOREs (mirrored in the test fixture) (#2)
- Enabled `storageLayout` output selection in the random-beacon Hardhat config, removed `scryptsy` from `yarn.lock`, and added `.envrc*`, `strix_runs/`, and `.claude/` to `.gitignore` (#2)
- **Operator action (temporary compatibility):** the `clientInfo.port` default is retained at `9601` for this coordinated security release so the client-info HTTP server (`/metrics` and `/diagnostics`) stays reachable through the cutover — the primary evidence channel for a node's exact revision and stranded-peer state must not go dark during deployment. Explicit `clientInfo.port = 0` still disables the server; the endpoint is unauthenticated and must be reached only over a trusted network path. Operators must commit an explicit `clientInfo.port` value and migrate every scrape target onto its trusted path; the follow-up R2 release flips the default back to `0` only after the tracked monitoring-migration exit criteria are met (see the monitoring-migration tracking issue for owner and dated expiry — **TODO: file the tracking issue and link it here before merge**; proposed title/body drafted for review in `.ralph/spec/draft-migration-issue.md`) (#2)
- **Operator action required:** renamed the libp2p peer-count metric from `connected_bootstrap_count` to `connected_wellknown_peers_count` to match bootstrap removal (#3909); update dashboards and alerts that query the old name (#3909)

### Fixed
- Test interceptor invoked the interception rule twice per `Send`; it is now invoked exactly once per send under a mutex (#34)
- Test interceptor silently dropped the `retransmissionStrategy` vararg; it is now forwarded to the underlying delegate (#34)
- Data race in `dkgtest` where member goroutines appended to `memberFailures` without synchronization; the append is now guarded by the existing mutex (#34)
- `tbtc` deduplicator notify methods (`notifyDKGStarted`, `notifyDKGResultSubmitted`, `notifyWalletClosed`) now use a single atomic `cache.Add` instead of non-atomic check-then-act, fixing a TOCTOU race (#2)

### Security
- Hardened transaction parsing against out-of-bounds crashes on untrusted/malformed Bitcoin-node responses: the SPV redemption and moved-funds-sweep paths now use bounds-checked `OutputAt` accessors and return a wrapped error instead of panicking when a node-supplied transaction has insufficient outputs (#36)
- **BREAKING (protocol fork):** Bound tECDSA DKG and signing session IDs into the TSS layer via `SetSessionNonceBytes`, deriving a fail-closed, session-specific GG20 proof nonce (`SHA512_256` of the session ID) for every ceremony. Combined with the changed session-ID formats and the hardened tss-lib pin, mixed-version peers in the same DKG or signing ceremony now derive different session IDs and fail proof verification. Upgrade the whole network at once; do not roll out partially (#8)
- **BREAKING (runtime contract):** `signing.Execute` and the tECDSA DKG `Execute` now thread the caller-supplied session ID into tss-lib's fail-closed minimum-length check. The hardened tss-lib (`tss/params.go`) panics if a session ID is shorter than 16 bytes; keep-core's own callers clear this via the new fixed-width formats, but an external Go caller passing a short or custom session ID will now panic at runtime even though the exported function signatures are unchanged (#8)
- Pinned the `threshold-network/tss-lib` replacement to commit `86bd1a375cc0` (`v0.0.0-20260615180949-86bd1a375cc0`), integrating the upstream hardening branch (threshold-network/tss-lib#2 through #7): GG20 proof transcript tagging/session binding, fail-closed positive `SessionNonce` enforcement, a 16-byte `SetSessionNonceBytes` minimum-length floor, ECDSA `fullBytesLen` signing validation, MtA/range/Paillier proof hardening, and non-canonical EC point rejection (#8)
- Lengthened signing session IDs to include a typed prefix and the attempt start block so repeated same-digest ceremonies no longer reuse the GG20 proof context (#8)
- Added an inline reentrancy guard (`nonReentrant` modifier, `_reentrancyStatus` storage slot, `ReentrantCall` error) to both `RandomBeacon.submitRelayEntry` entrypoints (#2)
