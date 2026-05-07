# Architecture

## Binary Entry Points

A single Go binary (`main.go:20`) exposes these sub-commands via `cmd/cmd.go:24`:

| Command | Purpose |
|---------|---------|
| `start` | Run a full node (beacon + tBTC, or bootstrap-only with `--bootstrap`) |
| `ethereum` | Ethereum key and utility operations |
| `maintainer` | Bitcoin difficulty relay and SPV proof submission |
| `maintainerCli` | CLI wrapper for maintainer ops |
| `ping` | Network connectivity test |

The `start` command (`cmd/start.go:65`) sequentially: connects to Ethereum, initialises libp2p with a firewall, connects to Bitcoin Electrum, initialises encrypted local storage, then starts the Beacon and tBTC protocol loops.

## Major Packages

```
pkg/
  altbn128/      BN256 curve helpers (hash-to-curve, compress/decompress)
  beacon/        Random Beacon protocol (GJKR DKG + BLS entry signing)
    gjkr/        GJKR distributed key generation rounds
    entry/       BLS relay-entry signing (threshold collection)
    dkg/         DKG orchestration and result submission
  bls/           BLS threshold signature (Lagrange interpolation)
  chain/         Blockchain abstraction layer
    ethereum/    go-ethereum client, contract bindings (gen/)
  crypto/        Ephemeral ECDH key pairs; symmetric key derivation
  firewall/      P2P application-level access control
  generator/     Pre-parameter generation scheduler (tss-lib Paillier)
  maintainer/    Bitcoin difficulty relay; SPV proof assembly
  net/           libp2p P2P layer (channel, handshake, retransmission)
  operator/      Operator secp256k1 key identity
  protocol/      Generic state machine, group membership, inactivity protocol
  sortition/     Sortition pool monitoring and join/update logic
  storage/       Encrypted local persistence for key shares and work state
  tbtc/          tBTC wallet coordination (DKG loop, signing loop, sweeps)
  tbtcpg/        tBTC proposal generator
  tecdsa/        Threshold ECDSA (GG18/GG20 via tss-lib fork)
    dkg/         tECDSA distributed key generation
    signing/     tECDSA threshold signing
```

## Actor Roles

### Operator (node runner)
- Generates a secp256k1 identity key (`pkg/operator/key.go:50`)
- Must register with a staking provider on-chain via TokenStaking (v1) or Allowlist weight (v2)
- Joins the sortition pool for Beacon and/or ECDSA (`pkg/sortition/sortition.go:29`)
- When selected: participates in DKG (produces key shares) and in signing sessions
- Submits transactions (DKG result, inactivity claim, relay entry) to Ethereum -- requires ETH for gas

### Staker
- Holds T tokens and authorises an operator on specific applications
- Enforced entirely by on-chain TokenStaking / Allowlist contracts
- No direct interaction with the Go client

### Relay Requestor
- Smart contract allowed by governance to call `requestRelayEntry()` (`RandomBeacon.sol:1014`)
- Receives a randomness callback via `IRandomBeaconConsumer`
- No trusted role in the off-chain client; treated as untrusted stimulus

### Governance (DAO / multisig)
- Controls all protocol parameters through `RandomBeaconGovernance` (Ownable) and `WalletRegistryGovernance` (Ownable)
- Can update group size, thresholds, slash amounts, authorised requesters, and upgrade proxies
- Time-lock on parameter changes in `RandomBeaconGovernance`

## Trust Boundaries

### Trusted
| Source | Trust Basis |
|--------|-------------|
| On-chain Ethereum state | Chain finality; used as authoritative source for group membership and DKG results |
| Local keystore (encrypted) | Operator-controlled; password required to decrypt |
| Local config file | Operator-controlled; mis-configuration is operator's problem |
| Configured bootstrap peers | Explicitly listed in config; treated as firewall allowlist exceptions |

### Untrusted
| Source | Validation Applied |
|--------|-------------------|
| P2P peer messages | TLS + 3-act secp256k1 handshake; firewall check against on-chain operator registry; group membership validation on every protocol message |
| Ethereum RPC provider | Chain ID check on connect (`ethereum.go:221`); single endpoint with no fallover -- provider compromise is a risk |
| Electrum (Bitcoin) | No authentication; transaction data parsed but not cryptographically verified by the Go client -- SPV proof validation is on-chain |
| DKG messages from peers | Membership validator (`protocol/group/membership_validator.go:67`); session ID gating; type-checked protobuf deserialization |

### Key Observation
The firewall (`pkg/firewall/firewall.go`) caches chain lookups (12 h positive, 1 h negative). A peer that was recently deregistered on-chain can still connect until the negative cache expires.

## Go-to-Chain Interaction

All Ethereum interaction flows through `pkg/chain/ethereum/`. The client:

1. Connects via `ethclient.Dial(config.URL)` (`ethereum.go:74`) to a single JSON-RPC endpoint
2. Wraps the client with nonce management and per-second rate limiting (`ethereum.go:42`)
3. Serialises all transaction submissions behind a mutex (`ethereum.go:57`) to prevent nonce collisions
4. Subscribes to contract events as log filters (not websocket pushes unless the RPC supports `eth_subscribe`)

Key contracts interacted with:
- `RandomBeacon` (relay entry, DKG start/submit/approve/challenge)
- `WalletRegistry` (ECDSA DKG start/submit/approve, inactivity claim)
- `Bridge` (deposit sweeps, redemptions, moving funds -- tBTC)
- `TokenStaking` / Allowlist (operator and staking provider lookup)
- `SortitionPool` (join, update status, select group)

Contract addresses are resolved from npm package defaults at build time and can be overridden by CLI flags (`cmd/flags.go:368`).

## Component Interaction Diagram

```
             Ethereum chain
                  |
         +--------+--------+
         |                 |
  BeaconChain events    TbtcChain events
         |                 |
  +------+------+   +------+------+
  | Beacon      |   | tBTC        |
  | (GJKR DKG   |   | (tECDSA DKG |
  |  BLS entry) |   |  signing    |
  +------+------+   |  sweeps)    |
         |          +------+------+
         |                 |
  +------+-----------------+------+
  |         Protocol layer        |
  |  state machine / group mgmt   |
  |  inactivity claims            |
  +------+------------------------+
         |
  +------+------+
  |  libp2p P2P |   <-- untrusted peers
  |  net layer  |
  +------+------+
         |
  +------+------+
  |  Firewall   |   <-- validates against on-chain operator registry
  +-------------+
```

Beacon output (BLS threshold signature) is consumed by `WalletRegistry` as the seed for tECDSA group selection, creating a dependency: if the Beacon is disrupted, new ECDSA wallet groups cannot be formed.
