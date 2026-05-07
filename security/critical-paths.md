# Critical Paths

End-to-end flows where subversion causes fund loss or protocol failure. Each section states the triggering event, the sequence of steps, the security invariants that must hold, and the highest-risk code locations.

---

## 1. tECDSA DKG (Wallet Key Generation)

**Trigger:** `DkgStarted` event from WalletRegistry on-chain, carrying a `seed`.

**Risk:** If subverted, an attacker could recover a wallet's private key (threshold ECDSA shares), granting full control of all Bitcoin held by the wallet.

### Round Sequence

| Round | State | Messages exchanged | Core file |
|-------|-------|-------------------|-----------|
| 1 | `ephemeralKeyPairGenerationState` | Broadcast ephemeral secp256k1 pubkeys (N-1 receivers) | `pkg/tecdsa/dkg/states.go:14` |
| 2 | `symmetricKeyGenerationState` | Local ECDH -- no messages | `pkg/tecdsa/dkg/states.go:73` |
| 3 | `tssRoundOneState` | Broadcast: Paillier pubkey + commitments | `pkg/tecdsa/dkg/states.go:126` |
| 4 | `tssRoundTwoState` | Broadcast + P2P: shares and de-commitments | `pkg/tecdsa/dkg/states.go:188` |
| 5 | `tssRoundThreeState` | Broadcast: Paillier proofs | `pkg/tecdsa/dkg/states.go:250` |
| 6 | `finalizationState` | tss-lib finalization | `pkg/tecdsa/dkg/states.go:309` |
| 7 | `resultSigningState` | Members sign preferred result hash | `pkg/tecdsa/dkg/states.go:373` |
| 8 | `signaturesVerificationState` | Verify received signatures | `pkg/tecdsa/dkg/states.go` |
| 9 | `resultSubmissionState` | One member submits result + sigs on-chain | `pkg/tecdsa/dkg/states.go:519` |

### Security Invariants

1. **Membership validation on every message** -- `protocol/group/membership_validator.go:67`: sender public key checked against pinned network identity.
2. **Session isolation** -- `sessionID` field checked on every incoming message; cross-session replay rejected.
3. **One message per sender per round** -- deduplication in `states.go:561` prevents double-voting.
4. **Honest threshold required for result** -- `resultSigningState` collects signatures; only results with honest-threshold agreement are submitted.
5. **P2P share encryption** -- shares in round 4 are encrypted with the symmetric key derived from the ephemeral ECDH exchange; only the intended recipient can decrypt.

### Failure / Attack Scenarios

| Scenario | Outcome | Mitigation |
|----------|---------|-----------|
| Member sends malformed TSS message | tss-lib returns error; member marked disqualified (`protocol/group/message_filter.go`) | DQ tracking in `Result.DisqualifiedMemberIndexes` |
| Member sends wrong `sessionID` | Message rejected at state entry | Check in every `Receive()` method |
| Member impersonates another | Rejected by membership validator (network key mismatch) | `membership_validator.go:67` |
| < threshold members active after DQ/IA | DKG fails; result not produced | Result signing requires honest threshold |
| Member submits malicious result on-chain | Challenge period allows others to slash submitter (`challengeDkgResult()`) | `EcdsaDkgValidator.sol` on-chain |
| Member signs one result then broadcasts support for another | Protocol filters: only one signature per member per result hash accepted | `protocol.go:423` |

---

## 2. tECDSA Threshold Signing

**Trigger:** Wallet coordination proposal (heartbeat, deposit sweep, redemption, or moving funds) observed on-chain and accepted by the wallet leader.

**Risk:** If threshold shares are produced for an attacker-supplied message, the attacker can redirect Bitcoin payments.

### Round Sequence

The signing protocol (`pkg/tecdsa/signing/states.go`) mirrors the DKG pattern: ephemeral key exchange, symmetric key derivation, then 5 TSS signing rounds using GG18/GG20.

Round message counts:
- Round 1: 1 broadcast + N-1 P2P
- Round 2: N-1 P2P only
- Round 3: 1 broadcast + N-1 P2P
- Round 4: completes signature

### Security Invariants

1. **Message to be signed is determined by wallet coordination proposal** -- proposal must be validated by `WalletProposalValidator` on-chain before off-chain signing begins (`pkg/tbtc/coordination.go`).
2. **Honest-threshold participation required** -- fewer than threshold valid shares cannot reconstruct a signature.
3. **Share validity enforced by tss-lib** -- GG20 includes range proofs and Paillier encryption; an invalid share causes the protocol to abort for that member.
4. **Rogue-key prevention** -- Paillier proofs in round 3 prevent malicious members from biasing the output key.

### Failure / Attack Scenarios

| Scenario | Outcome |
|----------|---------|
| Member signs wrong message | Other members' proofs will be inconsistent; tss-lib round fails for dishonest member |
| Member withholds shares (DoS) | If < threshold members respond within block timeout, signing session fails; wallet coordination retries |
| Coordinating member proposes invalid action | Proposal validator on-chain rejects; off-chain nodes should also call `validateProposal()` before accepting |

---

## 3. Random Beacon Entry Generation

**Trigger:** `requestRelayEntry()` called on RandomBeacon (by authorised requestor).

**Risk:** If the beacon output is biased or withheld, operator selection for the next tBTC wallet group is corrupted, potentially concentrating wallet control.

### Flow

1. On-chain: previous entry stored; DKG seed published
2. Off-chain: each selected group member signs the previous BN256 G1 point using their BLS key share
3. Shares are broadcast on the P2P channel with `sessionID = hex(previousEntryBytes)`
4. Each share is validated: `bls.VerifyG1(groupPublicKeyShares[senderID], previousEntry, share)` (`entry.go:208`)
5. Once `honestThreshold` valid shares collected, Lagrange interpolation recovers full group signature (`bls.go:80`)
6. Signature submitted on-chain as new relay entry

**Key files:**
- `pkg/beacon/entry/entry.go:62` -- share collection and validation
- `pkg/bls/bls.go:80` -- Lagrange recovery
- `pkg/beacon/entry/entry.go:186` -- per-share BLS pairing check

### Security Invariants

1. **No single member can predict or bias the output** -- Lagrange interpolation ensures the final signature is fully determined by the group public key and previous entry; any threshold subset of honest members produces the same result.
2. **Invalid shares are rejected** -- BLS pairing check (`VerifyG1`) rejects wrong shares before they influence recovery.
3. **Timeout enforced** -- if fewer than `honestThreshold` shares arrive within `RelayEntryTimeout` blocks, the entry generation fails and slashing is triggered for inactive members.

### Attack Scenarios

| Scenario | Impact | Mitigation |
|----------|--------|-----------|
| Member broadcasts invalid share | Rejected by BLS check; ignored in recovery | `entry.go:208` |
| Member withholds share (DoS) | If < threshold respond, entry fails; member slashed after hard timeout | Relay entry timeout / slashing in `RandomBeacon.sol` |
| Attacker controls >= threshold members | Can produce valid but attacker-chosen entry (biased beacon) | Prevented by stake weight distribution and selection randomness |
| Previous entry forged | G1 unmarshal validation (`entry.go:63`) | BN256 point format validation |

---

## 4. tBTC Deposit (BTC Minting)

**Trigger:** User creates Bitcoin P2WSH UTXO matching a deposit script, then calls on-chain deposit request.

**Risk:** Failure causes user's BTC to be locked with no tBTC minted.

### Flow

1. User constructs deposit script including: depositor address, 8-byte blinding factor, wallet pubkey hash, refund pubkey hash, refund locktime (`pkg/tbtc/deposit.go:49`)
2. User sends BTC to P2WSH address derived from this script
3. After Bitcoin confirmations, SPV proof assembled by maintainer (`pkg/maintainer/spv/deposit_sweep.go:17`)
4. SPV proof submitted to Bridge contract (`Bridge.submitDepositSweepProof`)
5. Bridge validates: SPV inclusion proof, correct output script, wallet exists, deposit script format
6. tBTC minted to depositor

**Key security check:** The deposit script format is validated by the Go client at `deposit.go:16` (`depositScriptFormat` or `depositWithExtraDataScriptFormat`). The on-chain Bridge performs the authoritative validation.

### Attack Scenarios

| Scenario | Impact |
|----------|--------|
| False SPV proof submitted | Bridge rejects; no minting |
| Maintainer submits proof to wrong wallet | Bridge checks wallet address in proof; rejects |
| Wallet keys compromised before sweep | Attacker can spend the deposit UTXO before sweep; user loses BTC |

---

## 5. tBTC Redemption (tBTC Burning)

**Trigger:** User calls `requestRedemption()` on Bridge contract specifying a Bitcoin output script and amount.

**Risk:** If signing is subverted, user's tBTC is burned but BTC is not delivered; or BTC is sent to wrong address.

### Flow

1. Bridge records redemption request: redeemer address, requested amount, timeout (600 blocks ~2 h)
2. Wallet coordinator selects wallet with suitable UTXO (`pkg/tbtc/redemption.go:194`)
3. Coordinator proposes redemption: `ValidateRedemptionProposal()` checks output scripts and fee (`redemption.go:130`)
4. `assembleRedemptionTransaction()` builds unsigned Bitcoin tx (`redemption.go:235`)
5. Threshold signing session produces Bitcoin signature
6. Transaction broadcast to Bitcoin; SPV proof submitted on-chain
7. Bridge marks redemption complete; tBTC burned

**Key invariant:** The output scripts in the assembled transaction must match those in the on-chain redemption requests. The `assembleRedemptionTransaction()` function reads these from chain state, not from peer messages.

### Attack Scenarios

| Scenario | Impact | Mitigation |
|----------|--------|-----------|
| Wallet coordinator substitutes different output script | Signs wrong transaction | `assembleRedemptionTransaction()` reads scripts from chain, not peers |
| Signing session produces signature over wrong tx | Redemption sends BTC to wrong address | Proposal validation in `ValidateRedemptionProposal()` |
| Redemption timeout not acted on | User loses tBTC (burned) with no BTC delivered | Bridge enforces timeout; wallet is penalised |

---

## 6. Sortition (Operator Selection)

**Trigger:** Periodic check by operator (`pkg/sortition/sortition.go:22`); group selection called when DKG starts.

**Risk:** If selection is biased, an attacker controls enough wallet shares to reconstruct private keys.

### Flow

1. Operator registers with staking provider on-chain
2. Operator monitors pool status: `IsOperatorInPool()`, `IsOperatorUpToDate()` (every 6 h by default)
3. If eligible: `JoinSortitionPool()` or `UpdateOperatorStatus()`
4. On-chain selection uses beacon output as seed: `sortitionPool.selectGroup(groupSize, bytes32(seed))`
5. Selection is weighted by authorised stake (v1) or Allowlist weight (v2)

**Randomness source for selection:** Beacon relay entry hash (`uint256(keccak256(AltBn128.g1Marshal(relay.previousEntry)))` in `RandomBeacon.sol`). Biasing the beacon output directly biases group selection.

### Attack Scenarios

| Scenario | Impact |
|----------|--------|
| Attacker controls beacon output | Chooses selected group; if controls >= threshold positions, owns wallet key |
| Attacker stakes large amount just before selection | Increases probability of selection; economic attack |
| Sybil: many operators with small stake | Each contributes fractional probability; below threshold individually |

---

## 7. DKG Result Challenge

**Trigger:** A group member submits a DKG result on-chain; any party can challenge within the challenge period.

**Risk:** An unchallenged invalid result could produce a wallet whose key shares are known to the attacker (if they manufactured the result).

### Flow

1. `submitDkgResult()` stores result hash in `DkgState`
2. Challenge period: `dkg.parameters.resultChallengePeriodLength` blocks
3. Anyone calls `challengeDkgResult()`: `EcdsaDkgValidator.validate()` runs full re-check
4. If challenge succeeds: submitter slashed, result discarded, DKG can restart
5. After period, `approveDkgResult()` finalises -- **no re-validation occurs at approval time**

**High-risk gap:** `approveDkgResult()` in `WalletRegistry.sol` does not call the validator again. If no one challenges during the challenge period, an invalid result is approved. This is mitigated by the economic incentive to challenge (challenger reward) and by the fact that all operators independently run the validator before approving.

---

## 8. Inactivity Claim

**Trigger:** Group members observe that some members have not participated in heartbeat or signing sessions.

**Risk:** False inactivity claims could ban honest operators from rewards; missed claims allow inactive operators to continue receiving rewards while degrading liveness.

### Flow

1. Members sign an `InactivityClaim` struct: nonce, walletPubKey, inactiveMemberIndices
2. Claim submitted on-chain if majority signature collected (`notifyOperatorInactivity()` in `WalletRegistry.sol:1288`)
3. On-chain nonce checked to prevent replay (`nonce == inactivityClaimNonce[walletID]`)
4. Inactive members banned from rewards in sortition pool; no token slashing

**Key file:** `pkg/protocol/inactivity/` (Go side); `WalletRegistry.sol:1288` (chain side).
