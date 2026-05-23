# Smart Contracts

Coverage of both `solidity/` (v2, current) and `solidity-v1/` (legacy).

---

## Contract Inventory

### solidity/random-beacon/ (Current)

| Contract | Purpose |
|----------|---------|
| `RandomBeacon.sol` | Core orchestration: relay entry, DKG lifecycle, group management, slashing |
| `RandomBeaconGovernance.sol` | Ownable governance with time-locked parameter updates |
| `BeaconDkgValidator.sol` | Read-only DKG result validation (group size 64, active threshold 58/90%) |
| `ReimbursementPool.sol` | ETH gas reimbursement; `nonReentrant` guarded |
| `Governable.sol` | Abstract base: governance address + transfer function |
| `Reimbursable.sol` | Abstract base: `refundable` modifier; includes storage gap |
| `RandomBeaconChaosnet.sol` | Legacy chaosnet variant (lower priority) |
| **Libraries** | `BeaconDkg`, `BeaconAuthorization`, `BeaconInactivity`, `Relay`, `Groups`, `BLS`, `AltBn128`, `Callback`, `BytesLib`, `ModUtils` |

### solidity/ecdsa/ (Current)

| Contract | Purpose |
|----------|---------|
| `WalletRegistry.sol` | Upgradeable; ECDSA wallet management, DKG lifecycle, operator registration |
| `WalletRegistryGovernance.sol` | Ownable; owns WalletRegistry, controls all parameter updates |
| `EcdsaDkgValidator.sol` | Read-only DKG result validation (group size 100, active threshold 90/90%) |
| `Allowlist.sol` | Post-TIP-092; replaces token staking; Ownable2StepUpgradeable |
| **Libraries** | `EcdsaDkg`, `EcdsaAuthorization`, `EcdsaInactivity`, `Wallets` |

### solidity-v1/ (Legacy -- lower priority)

| Contract | Purpose |
|----------|---------|
| `TokenStaking.sol` | V1 staking with real token slashing |
| `KeepRandomBeaconOperator.sol` | V1 beacon operator contract |
| `KeepRandomBeaconService.sol` | V1 service with relay request fee model |
| `TokenGrant.sol` | Token grant distribution |
| `BeaconRewards.sol`, `Rewards.sol` | Staking rewards |
| `KeepToken.sol` | ERC20 KEEP token |
| Various staking policies | `AdaptiveStakingPolicy`, `PermissiveStakingPolicy`, `GuaranteedMinimumStakingPolicy` |

---

## Upgrade / Proxy Patterns

### WalletRegistry -- Initializable Proxy (UPGRADEABLE)

- **Pattern:** OpenZeppelin `Initializable` with external proxy (transparent or UUPS proxy deployed separately, not in this repo)
- `WalletRegistry.sol:36`: `@custom:oz-upgrades-unsafe-allow constructor` -- uses immutable variables alongside proxy pattern
- `initialize()` (`WalletRegistry.sol:349`): standard initializer; callable only once
- `initializeV2()` (`WalletRegistry.sol:447`): `reinitializer(2)` for post-TIP-092 allowlist upgrade

Storage gaps are included in all libraries (e.g., `EcdsaDkg`, `Wallets`) and abstract contracts to preserve upgrade slots.

### Allowlist -- Ownable2StepUpgradeable (UPGRADEABLE)

- `Allowlist.sol:30`: extends `Ownable2StepUpgradeable`
- Two-step ownership transfer prevents accidental ownership loss
- `initialize(walletRegistryAddress)` (`Allowlist.sol:72`): sets WalletRegistry reference
- Constructor calls `_disableInitializers()` (`Allowlist.sol:69`) to prevent direct deployment attacks

### RandomBeacon -- NOT Upgradeable

Non-upgradeable. Governance address transferred at construction: `_transferGovernance(msg.sender)` (`RandomBeacon.sol:381`).

---

## Privilege Functions

### RandomBeacon -- `onlyGovernance`

Governance is `RandomBeaconGovernance.sol` (Ownable). All parameter changes go through this contract, which enforces a time-lock via timestamp tracking (`governanceDelayChangeInitiated`).

| Function | Effect |
|----------|--------|
| `updateAuthorizationParameters()` | Minimum authorisation, decrease delay |
| `updateRelayEntryParameters()` | Soft/hard timeouts, callback gas limit |
| `updateGroupCreationParameters()` | Group lifetime, DKG timeout, result challenge period |
| `updateRewardParameters()` | Slash amounts, ban durations, notification reward multipliers |
| `updateGasParameters()` | DKG gas refund values |
| `authorizeRequester(address, bool)` | Add/remove authorised relay requestors |
| `updateReimbursementPool(address)` | Replace ETH reimbursement pool |

### WalletRegistry -- `onlyOwner` (via WalletRegistryGovernance)

| Function | Effect |
|----------|--------|
| `upgradeRandomBeacon(address)` | Replace RandomBeacon reference |
| `initializeWalletOwner(address)` | Set wallet owner (Bridge contract); callable only once |
| All DKG/authorization parameter updates | via `WalletRegistryGovernance` |

### Allowlist -- `onlyOwner`

**Warning from comment at `Allowlist.sol:119`:**
> "BE EXTREMELY CAREFUL MAKING CHANGES TO THE BETA STAKER SET. The wallet liveness depends on having a sufficient number of operators with weight > 0."

| Function | Effect |
|----------|--------|
| `addStakingProvider(address, weight)` | Add operator with initial weight |
| `requestWeightDecrease(address, newWeight)` | Begin weight decrease (requires wait period) |

### ReimbursementPool -- `onlyOwner`

| Function | Effect |
|----------|--------|
| `authorize(address)` | Allow contract to call `refund()` |
| `unauthorize(address)` | Revoke authorization |
| `updateStaticGas(uint256)` | Adjust base gas cost |
| `updateMaxGasPrice(uint256)` | Cap reimbursable gas price |
| `withdraw(uint256, address)` | Drain pool ETH |

### Sortition Pool (external dependency)

The sortition pool is a dependency (not in this repo). `RandomBeacon.sol` calls `sortitionPool.setRewardIneligibility()` and `sortitionPool.selectGroup()`. Trust assumptions about the sortition pool contract are inherited.

---

## Reentrancy Surface

### ReimbursementPool -- PROTECTED

`refund()` has `nonReentrant` modifier (`ReimbursementPool.sol:64`).

Low-level call at `ReimbursementPool.sol:79`:
```solidity
(bool success, ) = receiver.call{value: refundAmount}("");
```
Failure is ignored intentionally (smart-contract receivers may reject ETH). The `nonReentrant` guard prevents reentrant calls regardless.

### RandomBeacon -- PROTECTED (post-F-09)

Relay entry submission (`RandomBeacon.sol:1057`):
```solidity
callback.executeCallback(uint256(keccak256(entry)), _callbackGasLimit);
```
- Callback to arbitrary `IRandomBeaconConsumer` contract
- Gas-limited by `_callbackGasLimit` (governance-controlled parameter)
- Reentrancy is blocked by the inline `nonReentrant` modifier on the two callback-bearing entry points: `submitRelayEntry(bytes)` (`RandomBeacon.sol:1054`) and `submitRelayEntry(bytes, uint32[])` (`RandomBeacon.sol:1083`). OpenZeppelin's `ReentrancyGuard` is not inherited (EIP-170 bytecode budget); the guard is instead a single uint256 storage slot `_reentrancyStatus` initialized to 1 in the constructor and toggled to 2 around any function carrying the modifier. See F-09.md.

Slashing calls are wrapped in try-catch (`RandomBeacon.sol:1099`, `1157`, `1250`):
```solidity
try staking.slash(amount, providers) {
} catch {
    // emit event, continue
}
```
This pattern is safe for reentrancy (exception stops re-entry) but means slashing failures are silent.

### WalletRegistry

`__ecdsaWalletCreatedCallback()` called on `walletOwner` (`WalletRegistry.sol:895`):
```solidity
walletOwner.__ecdsaWalletCreatedCallback(publicKey, stakingProviders);
```
- `walletOwner` is the Bridge contract (set once by governance)
- No reentrancy guard on WalletRegistry

---

## Oracle / Sortition Trust Assumptions

### Randomness Source

The Random Beacon entry is the entropy source for group selection. Genesis seed:

```solidity
// RandomBeacon.sol:56
uint256 internal constant genesisSeed =
    31415926535897932384626433832795028841971693993751058209749445923078164062862;
```

Subsequent entries: `uint256(keccak256(AltBn128.g1Marshal(relay.previousEntry)))`.

Group selection seed used in `sortitionPool.selectGroup(groupSize, bytes32(seed))`. A successful attack on the beacon output directly controls operator selection.

### Chain ID in DKG Signatures

`EcdsaDkgValidator.sol:223` and `BeaconDkgValidator.sol:219` include `block.chainid` in the signed message:
```solidity
bytes32 signedMsgHash = keccak256(abi.encodePacked(
    block.chainid, result.groupPubKey, result.misbehavedMembersIndices, startBlock
)).toEthSignedMessageHash();
```
This prevents cross-chain DKG signature replay (e.g., testnet signatures replayed to mainnet).

---

## DKG Result Submission and Validation

### Validation Flow

1. `submitDkgResult()` -- checks pubkey uniqueness, calls `dkg.submitResult()`; stores result hash
2. Challenge period (`dkg.parameters.resultChallengePeriodLength` blocks)
3. `challengeDkgResult()` -- runs full `EcdsaDkgValidator.validate()`:
   - Field check: pubkey length, misbehaved count, signature count
   - Signature check: ECDSA recovery; signers match expected selected members
   - Members hash check: recalculate and compare
   - Group members check: verify against sortition pool selection with seed
4. `approveDkgResult()` -- does **not** re-run validation; relies on challenge period being sufficient

### EIP-150 Gas Manipulation Protection

`WalletRegistry.sol:1035`:
```solidity
if (gasleft() < dkg.parameters.resultChallengeExtraGas) revert();
```
This prevents an attacker from supplying exactly enough gas to pass the try-catch while leaving only 1/64 of gas for remaining operations.

---

## TIP-092 Symbolic Slashing (v2 Current State)

Post-TIP-092, `staking.seize()` calls are effectively no-ops in the Allowlist model:

```solidity
// solidity/ecdsa/contracts/Allowlist.sol:200-207
/// @notice No-op stake seize operation. After TIP-092 tokens are not staked
///         so there is nothing to seize from.
function seize(
    uint96,
    uint256,
    address notifier,
    address[] memory _stakingProviders
) external {
    emit MaliciousBehaviorIdentified(notifier, _stakingProviders);
}
```

Economic enforcement is entirely via governance weight reduction (`requestWeightDecrease()`). There are no immediate on-chain token penalties for misbehaviour in v2. Pentesters should note that slash-based attack cost models from v1 documentation do not apply.

---

## solidity-v1 Legacy -- Key Differences

| Aspect | v1 (solidity-v1) | v2 (solidity/) |
|--------|-----------------|----------------|
| Token staking | Real ERC20 stake required | Allowlist weight (no tokens locked) |
| Slashing | `slash()` burns tokens; `seize()` transfers to notifier | Events only (symbolic) |
| Group size | Variable | Fixed: 64 (beacon), 100 (ECDSA) |
| Upgradeability | Not upgradeable | WalletRegistry is upgradeable |
| Beacon contract | `KeepRandomBeaconOperator` | `RandomBeacon` |

The v1 contracts remain deployed and hold legacy staked tokens. The `TokenStaking.sol` escrow system and `TokenGrant.sol` grant schedules are active; reentrancy and authorization bugs in v1 staking are still in-scope for the bug bounty.
