# Security Analysis - keep-core

Structured whitebox material for external security testers. Each file is self-contained and cross-references source locations.

## Scope

This directory covers the **keep-core** repository:

- Go client (`cmd/`, `pkg/`, `internal/`) -- threshold cryptography node
- Solidity v2 contracts (`solidity/random-beacon/`, `solidity/ecdsa/`) -- Random Beacon and ECDSA Wallet Registry
- Solidity v1 legacy (`solidity-v1/`) -- Keep v1 staking/beacon (legacy; lower priority)

Out of scope per the bug bounty program (see `SECURITY.adoc`):
- Attacks requiring leaked keys/credentials
- Basic economic governance attacks (51% attacks)
- Lack of liquidity
- Sybil attacks
- DoS attacks against infrastructure

## Findings Summary

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| [F-01](findings/F-01.md) | tECDSA key shares stored without encryption | High | Invalid -- encryption confirmed at rest |
| [F-02](findings/F-02.md) | Non-standard hash-to-curve (timing side channel) | ~~High~~ Low | Remediated -- counter-based applied; timing channel non-exploitable (public inputs only) |
| [F-03](findings/F-03.md) | Weak KDF for ECDH-derived session keys | High | Remediated -- HKDF-SHA256 with domain labels |
| [F-04](findings/F-04.md) | tss-lib fork contains unreviewed custom patches | Medium | Invalid -- known internal fork |
| [F-05](findings/F-05.md) | Non-atomic WalletRegistry upgrade is front-runnable | Medium | Mitigated by Design -- tracked in GH issue |
| [F-06](findings/F-06.md) | Recovered BLS group signature not re-verified | Medium | Low / Mitigated On-Chain |
| [F-07](findings/F-07.md) | `approveDkgResult()` does not re-validate the result | Medium | Mitigated by Design -- challenger incentive |
| [F-08](findings/F-08.md) | Post-TIP-092 slashing is symbolic | Medium | Accepted -- intentional post-TIP-092 design |
| [F-09](findings/F-09.md) | RandomBeacon callback has no reentrancy guard | Medium | Remediated -- inline nonReentrant guard |
| [F-10](findings/F-10.md) | `encryption.Box` implementation is opaque | Medium | No Action -- NaCl XSalsa20-Poly1305 confirmed |
| [F-11](findings/F-11.md) | Firewall positive-cache 12-hour post-deregistration window | Low | No Action Required |
| [F-12](findings/F-12.md) | Metrics endpoint unauthenticated (topology exposed) | Low | Accepted -- document in operator runbooks |
| [F-13](findings/F-13.md) | tBTC event deduplication TOCTOU race | Medium | Remediated -- atomic AddIfAbsent |
| [F-14](findings/F-14.md) | Legacy beacon reward withdrawal burns failed claims | Low | Won't Fix -- v1 contracts are immutable |
| [F-15](findings/F-15.md) | G2 square root exponent not cross-checked | Low | Remediated -- exponent verified, test added |
| [F-16](findings/F-16.md) | BLS aggregation does not enforce distinct signers | Low | Informational / No Action Required |
| [F-17](findings/F-17.md) | Single Ethereum RPC endpoint with no failover | Low | Accepted -- architectural constraint |

**Remediations shipped (PR #5):** F-02, F-03, F-09, F-13, F-15  
**Open follow-up:** F-02 RFC 9380 SWU hygiene ([issue #4](https://github.com/tlabs-xyz/keep-core-security/issues/4), optional -- no security impact), F-05 upgrade sequencing ([issue #6](https://github.com/tlabs-xyz/keep-core-security/issues/6))

## Files

| File | Contents |
|------|----------|
| [findings/](findings/) | Individual finding files F-01 through F-17 with severity ratings and verification status |
| [architecture.md](architecture.md) | System components, trust boundaries, actor roles, Go-to-chain boundary |
| [attack-surface.md](attack-surface.md) | All external entry points: P2P, chain events, RPC, config/key ingestion, CLI flags |
| [critical-paths.md](critical-paths.md) | End-to-end flows where subversion causes fund loss or protocol failure |
| [crypto-review.md](crypto-review.md) | Cryptographic primitives and custom constructions |
| [smart-contracts.md](smart-contracts.md) | Contract inventory, proxy/upgrade patterns, privilege functions, reentrancy surface |
| [threat-model.md](threat-model.md) | Assets at risk, threat actors, bug-bounty exclusions, STRIDE mapping |

## Quick Orientation

The system has two on-chain protocols sharing a Go client binary:

1. **Random Beacon** -- threshold BLS signature producing on-chain randomness (groups of 64, threshold 33)
2. **ECDSA Wallet Registry / tBTC** -- threshold ECDSA wallets holding Bitcoin (groups of 100, threshold 51)

Both use the same DKG, P2P, sortition, and inactivity-claim infrastructure. Operators run a single binary (`./keep-core start`) that participates in both protocols.

The highest-value targets are the tECDSA wallet key shares (control of a threshold means control of the Bitcoin wallet) and the Random Beacon output (biasing it affects wallet group selection).

## Contacts

Bug reports: `security@threshold.network` (see `SECURITY.adoc` for embargo and bounty details).
