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

### Changed
- Re-landed the Tier 0 (lint rule, race-detector CI job, bounds-checked accessors) and Tier 1 (native fuzz targets) portions of the previously reverted #33 testing/correctness hardening work as a single consolidated changeset, corresponding to the original PRs #29 and #30; the ClusterFuzzLite continuous fuzzing (#31) and rapid property tests (#32) are NOT included in this PR (#36)

### Security
- Hardened transaction parsing against out-of-bounds crashes on untrusted/malformed Bitcoin-node responses: the SPV redemption and moved-funds-sweep paths now use bounds-checked `OutputAt` accessors and return a wrapped error instead of panicking when a node-supplied transaction has insufficient outputs (#36)
