# Attack Surface

All external entry points where attacker-controlled data enters the system.

## 1. P2P Network (libp2p, port 3919)

Default port: `pkg/net/libp2p/libp2p.go:44` (`DefaultPort = 3919`). Configurable via `--network.port`.

### 1.1 Handshake (stream-based, inbound connections)

**Files:** `pkg/net/libp2p/authenticated_connection.go`

Every inbound TCP connection triggers a 3-act handshake:

| Act | Data received from peer | Deserialization | Location |
|-----|------------------------|-----------------|----------|
| Act 1 (responder receives) | `HandshakeEnvelope{message, signature, peerID}` | `proto.Unmarshal` | `authenticated_connection.go:400,424` |
| Act 2 (initiator receives) | `HandshakeEnvelope` with `Act2Message{nonce, challenge, protocol}` | `proto.Unmarshal` | `authenticated_connection.go:306,319` |
| Act 3 (responder receives) | `HandshakeEnvelope` with `Act3Message{challenge}` | `proto.Unmarshal` | `authenticated_connection.go:379` |

Frame size capped at 1024 bytes (`authenticated_connection.go:27`).

Firewall check applied after handshake (`authenticated_connection.go:223`): the operator public key recovered from the handshake is validated against the on-chain operator registry. The registry lookup is cached (12 h positive, 1 h negative -- `firewall.go:54`).

**Risk areas:**
- Malformed protobuf before signature verification (DoS via panic/allocation)
- Firewall bypass window during negative-cache period (up to 1 h after on-chain deregistration)

### 1.2 Pubsub Channel Messages (broadcast)

**File:** `pkg/net/libp2p/channel.go:313`

After a connection is established, broadcast messages are received via libp2p gossipsub:

```
BroadcastNetworkMessage {
  bytes sender         // secp256k1 public key
  bytes payload        // protocol-specific protobuf
  bytes type           // message type string
  uint64 sequenceNumber
}
```

Deserialization chain:
1. `proto.Unmarshal(pubsubMessage.Data, &messageProto)` -- outer envelope (`channel.go:315`)
2. Dynamic type lookup by `type` field
3. `unmarshaled.Unmarshal(message.GetPayload())` -- inner protocol message (`channel.go:333`)
4. `senderIdentifier.Unmarshal(message.Sender)` -- sender public key (`channel.go:339`)

Inbound queue depth: 4096 (`channel.go:289`). Messages beyond that are dropped.

**Risk:** Any peer can send messages to any pubsub topic before the type-based routing filters them. Message type strings are looked up in a registry -- an unknown type causes a silent drop, not a crash. However, the outer protobuf is always deserialized before the type check.

### 1.3 Protocol-Specific Message Types

All protocol messages arrive through the pubsub path above. Each has its own protobuf definition:

| Protocol | Message types | Proto definition |
|----------|--------------|-----------------|
| Beacon GJKR DKG | EphemeralPublicKey, MemberCommitments, PeerShares, etc. | `pkg/beacon/gjkr/gen/pb/message.proto` |
| Beacon entry signing | SignatureShareMessage | `pkg/beacon/entry/gen/pb/message.proto` |
| tECDSA DKG | EphemeralPublicKeyMessage, TSSRoundOne/Two/Three, tssFinalization | `pkg/tecdsa/dkg/gen/pb/message.proto` |
| tECDSA signing | TSSRoundOne through TSSRoundFive | `pkg/tecdsa/signing/gen/pb/` |
| tBTC coordination | CoordinationMessage, signingDoneMessage | `pkg/tbtc/gen/pb/message.proto` |
| Inactivity claim | InactivityClaimMessage | `pkg/protocol/inactivity/gen/pb/` |
| Announcer | AnnounceMessage | `pkg/protocol/announcer/gen/pb/` |

All inner messages include `sender_id` (member index) validated against group membership before processing.

---

## 2. Ethereum Chain Event Listeners

The client subscribes to Ethereum log events and processes them as triggers. Any attacker able to influence emitted events (e.g., by interacting with contracts) controls these inputs.

| Event | Contract | Data consumed | Handler location |
|-------|----------|---------------|-----------------|
| `DkgStarted` | WalletRegistry | `seed *big.Int`, `blockNumber` | `pkg/chain/ethereum/tbtc.go:470` |
| `DkgResultSubmitted` | WalletRegistry | `EcdsaDkgResult` struct (member indices, signatures, pubkey, membersHash) | `pkg/chain/ethereum/tbtc.go:523` |
| `DkgResultChallenged` | WalletRegistry | `resultHash`, `challenger`, `reason`, `blockNumber` | `pkg/chain/ethereum/tbtc.go:622` |
| `DkgResultApproved` | WalletRegistry | `resultHash`, `approver`, `blockNumber` | `pkg/chain/ethereum/tbtc.go:644` |
| `RelayEntrySubmitted` | RandomBeacon | entry bytes | `pkg/beacon/entry/entry.go:46` |
| `InactivityClaimed` | WalletRegistry | claim nonce, wallet pubkey, inactiveMemberIndices | `pkg/chain/ethereum/tbtc.go:145` |
| `DepositSweepStarted`, `RedemptionRequested`, `MovingFundsInitiated` | Bridge | deposit/redemption parameters | `pkg/chain/ethereum/tbtc.go` |

**Conversion risk:** `convertDkgResultFromAbiType()` (`tbtc.go:532`) translates raw ABI bytes into Go structs. A malicious DKG result on-chain (e.g., submitted by a dishonest operator) feeds directly into the Go state machine.

---

## 3. Ethereum RPC Endpoint

Configured via `--ethereum.url`. Single endpoint; no failover.

**Risk areas:**
- Compromised or malicious RPC provider can serve false chain state (wrong block numbers, fake events, wrong contract state)
- Chain ID is validated once on connect (`ethereum.go:221`) but not per-call
- Rate limited (`--ethereum.requestsPerSecondLimit`, `--ethereum.concurrencyLimit`)

---

## 4. Bitcoin Electrum RPC

Configured via `--bitcoin.electrum.url`. No authentication.

**Files:** `pkg/bitcoin/electrum/electrum.go`

| Operation | Risk |
|-----------|------|
| `GetTransaction()` (`electrum.go:77`) | Raw Bitcoin transaction bytes from server, parsed and deserialized locally |
| `GetTransactionConfirmations()` (`electrum.go:129`) | Block height arithmetic based on server-provided data |
| Block header retrieval (`block.go`) | Block headers used to construct SPV proofs |

A compromised Electrum server can withhold transactions, return false confirmation counts, or serve malformed transaction bytes. SPV proof validation happens on-chain at the Bridge contract, not in the Go client -- so false data may pass the Go layer and fail on-chain, but could also cause incorrect operator behavior (e.g., premature proof submission).

---

## 5. Operator CLI Flags and Config File

**Files:** `cmd/flags.go`, `config/config.go`

Config is read via Viper from a YAML/TOML/JSON file (`config.go:238`). No schema validation before `viper.Unmarshal()` (`config.go:257`).

### Security-Sensitive Flags

| Flag | Impact if Misconfigured |
|------|------------------------|
| `--ethereum.url` | Points to malicious RPC; false chain state |
| `--ethereum.keyFile` | Wrong/malformed file; node fails to start or loads wrong identity |
| `--ethereum.maxGasFeeCap` | Very high cap could drain operator's ETH in gas during attack scenarios |
| `--network.peers` | Specifying attacker nodes as bootstrap peers partitions operator |
| `--tbtc.preParamsPoolSize` | Very low value reduces signing participation reliability |
| `--bitcoin.electrum.url` | Points to attacker-controlled Electrum server |
| Contract address override flags (`cmd/flags.go:368`) | Can redirect all contract calls to attacker contracts |

### Developer Contract Address Overrides
`cmd/flags.go:368` exposes flags for every major contract address (RandomBeacon, WalletRegistry, Bridge, TokenStaking, etc.). If set, these override npm defaults. No on-chain consistency check is performed.

---

## 6. Operator Key File and Password

**Key file loading:** `pkg/chain/ethereum/ethereum.go:525`
- `ethutil.DecryptKeyFile(config.Account.KeyFile, config.Account.KeyFilePassword)`
- Path configured via `--ethereum.keyFile`
- Malformed keystore file can cause DoS; incorrect password silently produces wrong key material

**Password sources** (`config/config.go:166`):
1. Environment variable `KEEP_ETHEREUM_PASSWORD`
2. Interactive terminal prompt via `term.ReadPassword()`

Password is held in memory in plaintext for the lifetime of the process. No zeroing-on-exit observed.

---

## 7. Metrics / Diagnostics HTTP Server

**File:** `pkg/clientinfo/clientinfo.go:33`

An HTTP server listens on port 9601 by default (`--clientInfo.port`). No authentication.

Exposed information:
- Connected peer addresses and identities
- Ethereum and Bitcoin RPC health metrics
- Performance metrics (network layer)

**Risk:** Information disclosure. An attacker on the same network segment can enumerate connected peers, operator identity, and RPC endpoint health without any credentials. This can assist in targeted P2P attacks or identify isolated nodes.

---

## 8. Local Persistence (Storage)

**File:** `pkg/storage/storage.go`

Two storage areas:
- **Keystore directory** -- encrypted with the Ethereum keystore password
- **Work directory** -- persistent state for in-progress DKG and signing sessions; not separately encrypted

Work directory content includes tECDSA pre-parameters (Paillier key material) and in-progress DKG shares. If an attacker gains filesystem read access, they can extract:
- Pre-parameters (reveals Paillier private keys used in tECDSA)
- In-progress signing data

**Note:** tECDSA private key shares are stored as raw protobuf bytes with no additional encryption layer (`pkg/tecdsa/marshaling.go:24`); only the Ethereum keystore receives password-based encryption.
