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
- DKG test interceptor `Strategy` action API (`Strategy`, `Outbound`, `PassThrough`, `FromRules`, `NewNetworkWithStrategy`) supporting drop/mutate/duplicate/inject of messages, targetable per-sender and per-message-type; the prior `Rules` modify-or-drop API is retained via a `FromRules` back-compat adapter (#34)
- `dkgtest.RunTestWithStrategy` to run full DKG tests with a `Strategy`; existing `RunTest` is unchanged and now delegates through it (#34)
- `byzantine` test-harness package with predicate-based strategy constructors `Inactive`, `Withhold`, `Flood`, `Corrupt`, and `MatchAll` (#34)
- Unit tests for the new Strategy API and the `byzantine` constructors, full-DKG integration demos (Withhold/Flood/Corrupt), and an env-gated (`DETERMINISM_PROBE`) determinism probe (#34)
- CI job "Run Go race tests (Tier-2 interceptor)" running `go test -race` over `./pkg/internal/interception/...` and `./pkg/internal/byzantine/...` (#34)

### Changed
- Re-landed the Tier 0 (lint rule, race-detector CI job, bounds-checked accessors) and Tier 1 (native fuzz targets) portions of the previously reverted #33 testing/correctness hardening work as a single consolidated changeset, corresponding to the original PRs #29 and #30; the ClusterFuzzLite continuous fuzzing (#31) and rapid property tests (#32) are NOT included in this PR (#36)

### Fixed
- Test interceptor invoked the interception rule twice per `Send`; it is now invoked exactly once per send under a mutex (#34)
- Test interceptor silently dropped the `retransmissionStrategy` vararg; it is now forwarded to the underlying delegate (#34)
- Data race in `dkgtest` where member goroutines appended to `memberFailures` without synchronization; the append is now guarded by the existing mutex (#34)

### Security
- Hardened transaction parsing against out-of-bounds crashes on untrusted/malformed Bitcoin-node responses: the SPV redemption and moved-funds-sweep paths now use bounds-checked `OutputAt` accessors and return a wrapped error instead of panicking when a node-supplied transaction has insufficient outputs (#36)
