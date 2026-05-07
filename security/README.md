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

## Files

| File | Contents |
|------|----------|
| [architecture.md](architecture.md) | System components, trust boundaries, actor roles, Go-to-chain boundary |
| [attack-surface.md](attack-surface.md) | All external entry points: P2P, chain events, RPC, config/key ingestion, CLI flags |
| [critical-paths.md](critical-paths.md) | End-to-end flows where subversion causes fund loss or protocol failure |
| [crypto-review.md](crypto-review.md) | Cryptographic primitives, custom constructions, flagged issues |
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
