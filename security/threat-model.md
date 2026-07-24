# Threat Model

## Assets at Risk

| Asset | Value | Location |
|-------|-------|----------|
| Bitcoin held in tBTC wallets | Highest -- directly redeemable BTC | tECDSA wallet key shares distributed across operators |
| tBTC token supply integrity | High -- overbacking or underbacking breaks peg | Bridge contract mint/burn accounting |
| T token stake (v1) | High -- operator collateral | `TokenStaking.sol` (v1) |
| Operator tECDSA key shares | High -- threshold reconstruction reveals wallet private key | `pkg/tecdsa/` work directory (encrypted at rest via `persistence.NewEncryptedProtectedPersistence`, XSalsa20-Poly1305 keyed by sha256-of-password); see F-01.md |
| Operator Ethereum private key | High -- used to authorise all on-chain transactions | Keystore file (password-encrypted) |
| Random Beacon output | Medium -- controls group selection | `RandomBeacon.sol` relay entry storage |
| Beacon DKG group key material | Medium -- used to sign relay entries | `pkg/beacon/gjkr/` per-operator shares |
| Operator identity | Low-medium -- loss breaks P2P participation | `pkg/operator/key.go` |
| Sortition pool weights | Low-medium -- controls selection probability | Allowlist contract (v2) |

---

## Threat Actors

### 1. External Attacker (No Stake, Network Access)

**Capabilities:**
- Can connect to P2P port 3919 of any node
- Can observe broadcast protocol messages (pubsub is broadcast)
- Cannot initially participate in groups (requires on-chain operator registration)

**Goals:** DoS protocol, extract key material, forge proofs

**Realistic attacks:**
- Malformed P2P message to crash or exhaust memory of a node
- Information disclosure via metrics endpoint (port 9601, no auth)
- Bitcoin Electrum MITM if the attacker is on the same network path

---

### 2. Malicious Operator (Staked, In Group)

**Capabilities:**
- Valid group member; can send all protocol messages
- Knows session ID and group membership
- Can deviate from protocol at any step

**Goals:** Recover wallet private key, bias beacon output, extract other members' key shares

**Realistic attacks:**
- Send malformed TSS round messages to force disqualification of honest members (griefing)
- Attempt to extract others' Paillier-encrypted shares (requires breaking Paillier encryption -- computationally infeasible with 2048-bit modulus)
- Withhold participation to prevent DKG completion (DoS); acceptable if below threshold
- Submit malicious DKG result on-chain; economically rational only if slashing cost < wallet value

---

### 3. Threshold Coalition (>= t Colluding Operators in Same Group)

**Capabilities:**
- Hold >= threshold key shares
- Can reconstruct the wallet private key
- Can sign arbitrary Bitcoin transactions

**Goals:** Steal all BTC held by any wallet where they hold threshold shares

**Attack:**
1. Colluding operators wait to be selected into the same wallet group
2. After DKG, they combine their `xi` shares (stored in plaintext in each operator's work directory)
3. Reconstruct full ECDSA private key
4. Sign Bitcoin transactions without using the on-chain protocol

**Likelihood:** Requires attacker to control >= 51 out of 100 selected operators. With honest majority of staked T tokens and random selection, probability is low per group but non-negligible at scale.

**Mitigation:** Random selection by beacon; stake-weighted probability; economic penalty (reputation, future selection probability). No cryptographic prevention -- threshold ECDSA is fundamentally vulnerable to threshold collusion.

---

### 4. Compromised RPC Provider

**Capabilities:**
- Serve false Ethereum chain state (block numbers, events, contract reads)
- Withhold or delay events
- Front-run operator transactions

**Goals:** Cause operators to act on false state (e.g., skip DKG rounds, sign wrong message)

**Realistic attacks:**
- Withhold `DkgStarted` event -- operator misses DKG, becomes inactive, is penalised
- Serve false `DkgResultApproved` -- operator believes DKG succeeded when it did not
- Delay relay entry events -- cause operators to time out and be slashed

**Note:** Only one RPC endpoint is supported (`config.go:201`). No failover or consistency check against multiple providers.

---

### 5. Compromised Electrum Server

**Capabilities:**
- Serve false Bitcoin transaction data
- Lie about confirmation counts
- Withhold specific transactions

**Goals:** Cause SPV proofs to be submitted for non-existent or unconfirmed transactions

**Realistic attacks:**
- Return false confirmation count → premature SPV proof submission → Bridge rejects, operator wastes gas
- Return malformed transaction bytes → Go client panic or incorrect proof assembly
- Withhold deposit transaction → operator misses sweep deadline

**Mitigation:** On-chain Bridge validates SPV proof cryptographically; false data fails on-chain. However, operator behavior can be disrupted.

---

### 6. Governance Attacker

**Capabilities:**
- If governance key is compromised or DAO vote is manipulated: can call all governance functions

**Goals:** Drain funds, brick protocol, steal stake

**Realistic attacks via governance:**
- Set `maliciousDkgResultSlashingAmount` to 0 -- removes economic deterrent for invalid DKG results
- Set `relayEntrySubmissionFailureSlashingAmount` to very high -- mass slashing
- Add attacker-controlled contract as authorised relay requestor -- can spam relay entries
- Replace `reimbursementPool` with attacker contract -- drain next refund
- `updateReimbursementPool` + `withdraw()` -- drain ETH from pool
- `authorizeRequester(attacker)` + spam requests -- exhaust operator capacity
- WalletRegistry: `upgradeRandomBeacon(attackerBeacon)` -- arbitrary beacon output
- Allowlist: `addStakingProvider(attacker, maxWeight)` -- guarantee attacker's selection

**Mitigation:** `RandomBeaconGovernance` enforces time-locks on parameter changes. Multi-sig / DAO governance requires social-layer attack. `Ownable2StepUpgradeable` on Allowlist prevents accidental key loss.

---

## Bug Bounty Exclusions (from SECURITY.adoc)

The following are explicitly excluded from the Threshold Network bug bounty:

- Attacks the reporter has already exploited (causing damage)
- Attacks requiring access to leaked keys or credentials
- Basic economic governance attacks (e.g., 51% attack on stake)
- Lack of liquidity
- Sybil attacks
- Any testing on mainnet or public testnet contracts (prohibited)
- DoS attacks against infrastructure
- Phishing or social engineering

---

## STRIDE Mapping (Highest-Severity Classes)

### S -- Spoofing

| Attack | Component | Notes |
|--------|-----------|-------|
| Spoof group member identity | P2P protocol | Mitigated by secp256k1 handshake + membership validator; requires key theft |
| Spoof DKG result submitter | On-chain | ECDSA signature recovery in validator; requires valid group member key |
| Spoof relay entry | On-chain | BLS threshold signature; requires threshold collusion |

### T -- Tampering

| Attack | Component | Notes |
|--------|-----------|-------|
| Tamper with in-transit P2P message | libp2p channel | TLS transport + sender signature on every message |
| Tamper with tECDSA key shares at rest | Operator filesystem | No at-rest encryption; mitigated only by filesystem ACLs |
| Tamper with DKG result on-chain | WalletRegistry | Signature validation + challenge period; requires valid member sigs |
| Tamper with SPV proof | Bridge contract | Cryptographic SPV validation; Bitcoin immutability |

### R -- Repudiation

| Attack | Component | Notes |
|--------|-----------|-------|
| Deny DKG result signature | WalletRegistry | On-chain signatures are non-repudiable |
| Deny signing session participation | Inactivity claim | Nonce-protected inactivity claim records non-participation |

### I -- Information Disclosure

| Attack | Component | Notes |
|--------|-----------|-------|
| Enumerate connected peers | Metrics endpoint (port 9601) | No authentication; returns peer identity and addresses |
| Extract tECDSA key share from disk | Work directory | Stored as plaintext protobuf; requires filesystem access |
| Timing attack on hash-to-curve | `altbn128.go:120` | Try-and-increment leaks iteration count |
| Observe P2P messages | Pubsub channel | Messages are signed but broadcast; payload visible to all subscribers |

**Metrics endpoint (port 9601) — temporary compatibility acceptance.** The
`clientInfo.port` default is retained at `9601` for the coordinated security
release so a node's exact revision and stranded-peer evidence stay visible
through the cutover (the compiled epoch and active-mode signals belong to the
not-yet-landed cutover gate and are not exposed by this build). There is still
**no authentication** on the endpoint;
mitigation is entirely by network posture. Required compensating controls: bind
the endpoint to a trusted/private path only (firewall/VPN or an authenticated
proxy), never publish it on a public interface, and set `clientInfo.port = 0`
where monitoring is intentionally retired. This acceptance is time-bounded: the
follow-up R2 release flips the default back to `0` (disabled) once the
monitoring migration exit criteria are signed off, and the Security owner
revalidates the exposure inventory before expiry.

### D -- Denial of Service

| Attack | Component | Notes |
|--------|-----------|-------|
| Flood P2P handshake | Port 3919 | Connection limits (900 high water); no rate limiting on inbound connections |
| Exhaust P2P message queue | libp2p pubsub | Queue depth 4096; beyond that, messages dropped (could stall protocol) |
| Withhold DKG/signing messages | Protocol | If < threshold respond, session fails; member slashed after timeout |
| Block operator Ethereum transactions | Gas price manipulation | `maxGasFeeCap` limits overpaying but high base fee can delay submissions |
| Drain ReimbursementPool | Governance attack (owner) | `withdraw()` callable by owner |

### E -- Elevation of Privilege

| Attack | Component | Notes |
|--------|-----------|-------|
| Compromise governance key | Smart contracts | Full protocol control; all privilege functions accessible |
| Compromise threshold of operator keys | tECDSA wallets | Reconstruct Bitcoin wallet private key |
| Compromise Ethereum keystore | Go client | Gain operator's on-chain identity; can submit transactions as operator |
| Exploit WalletRegistry upgrade | Proxy admin | Atomic upgrade required; non-atomic leaves initializer front-running window |

---

## Highest-Severity Attack Paths (Summary)

1. **Threshold coalition stealing Bitcoin wallet:** Requires compromising >= 51 operator machines within the same wallet group. Each machine stores plaintext tECDSA key shares. No cryptographic barrier after threshold shares are combined.

2. **Beacon output bias via threshold beacon group collusion:** Requires controlling >= 33 of 64 beacon group operators. Biased beacon output affects all subsequent tBTC wallet group selections.

3. **Governance compromise:** Compromising the governance multisig or manipulating a DAO vote unlocks full protocol control including upgrades, parameter changes, and contract replacement.

4. **Malicious DKG result with no challenger:** Submitting a crafted DKG result where the group public key corresponds to keys known to the attacker. If no one challenges during the challenge window, the result is approved and future signing sessions use attacker-controlled key shares.
