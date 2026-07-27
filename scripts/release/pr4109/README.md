# Release rehearsal and smoke harnesses

This directory holds two harnesses for the coordinated security release:

1. the container smoke matrix for the temporary `clientInfo.port` **9601
   compatibility default** — `clientinfo-port-smoke.sh` and `compose.yaml`;
   and
2. the single-release **cutover rehearsal** scaffold — `rehearse.sh`,
   `compose.rehearsal.yaml`, and `rehearsal-evidence.schema.json`, driven
   manually or through the `cutover-rehearsal` workflow.

## Cutover rehearsal scaffold

The chain-clocked cutover machinery — the participation gate, per-ceremony
permits, commit fences, quiescence and the signal lifecycle controller, and
the signer quarantine namespace — is implemented in this tree and proven by
repository-local Go tests. Run those proofs, which need no Docker or chain,
with:

```
./rehearse.sh local-proofs
```

The offline state classification the rollback barrier requires runs with
`go run ./cmd/participation-state-audit --storage-snapshot <copy>`: it
records the snapshot identity (aggregate checksum and access mode), flags any
entry outside the expected storage layout, and — when the storage password is
supplied — interprets the beacon active, beacon quarantine, and tBTC active
namespaces with the same decode paths the client's own loaders use,
cross-validating quarantine metadata against its schema, epoch, mode/anchor
arithmetic, storage location, and decrypted membership. Namespace consistency
alone is never rollback-ready: the audit exits nonzero until references to
the chain reconciliation, Bitcoin reconciliation, quiescence outcome, and
prior-reader compatibility evidence are supplied via its
`--*-evidence`/`--quiescence-report` flags, and its output never authorizes
activating quarantined material by itself.

The two **container** rehearsals are mandatory release gates that cannot run
from this repository alone: they need the immutable prior-production and R1
runtime image digests, a rehearsal chain with deployed beacon/tBTC contracts,
per-node operator keys and configs, and (for rollback) storage snapshots plus
an independent network vantage point. `rehearse.sh preflight` validates those
inputs; `single-release` and `rollback` refuse to run — reporting `BLOCKED`
with the exact missing input — until they are supplied and the stages are
extended against the real fleet.

`compose.rehearsal.yaml` is the fleet shell: one prior node (no gate — the
deliberate straggler) and two R1 nodes with the non-mainnet
`--protocolParticipation.cutoverBlock` override and persistent volumes. Each
service mounts `KEYSTORE_DIR/<service>/` read-only at `/mnt/keystore` and
starts with `--config /mnt/keystore/config.toml`; that per-node config must
carry the rehearsal contract addresses, the key file path under
`/mnt/keystore`, and storage directory `/mnt/storage` (the persistent
volume). The fleet spans two networks: the internal `rehearsal` network
carries inter-node protocol traffic and evidence probes with no host
publication of any port, while `chain-egress` exists only so nodes can reach
the external `ETH_WS_URL` endpoint.

Every accepted rehearsal run must produce an evidence record conforming to
`rehearsal-evidence.schema.json`: exact source SHA, per-architecture image
digests, chain ID and C, per-stage canonical/callback blocks, permit modes,
gauge snapshots, transaction hashes, and non-secret state checksums.
Screenshots alone are insufficient. `./rehearse.sh validate-evidence` checks
every record under `EVIDENCE_DIR` against the schema, and the
`cutover-rehearsal` workflow (manually dispatched, in
`.github/workflows/cutover-rehearsal.yml`) runs the local proofs on every
dispatch and the container preflight when the image digests and chain inputs
are supplied.

## clientInfo.port 9601 compatibility smoke matrix

### What is proven where

| Layer | Proof | Runnable |
|---|---|---|
| Port resolution (flag/TOML precedence, both explicit-zero paths, custom port) | Go unit/config tests | ✅ locally, no Docker/chain |
| Port → listener decision (`0` disables, nonzero enables) | `pkg/clientinfo` unit tests | ✅ locally, no Docker/chain |
| Runtime image bakes the 9601 default | `clientinfo-port-smoke.sh image-default-check` | ✅ Docker only, no chain |
| Container listens on 9601 / custom, serves meaningful `/metrics` | `clientinfo-port-smoke.sh listener-matrix` | ⚙️ needs Docker **and** a chain endpoint + operator key |
| Testnet scrape from the real monitoring host, 3 consecutive intervals, current revision/epoch | — | 🔲 **manual / ops follow-up** |
| External untrusted-network probe: raw `9601` / `/diagnostics` unreachable unless an authenticated proxy is in front | — | 🔲 **manual / ops follow-up** |

### Unit/config acceptance (fully runnable locally)

```
go test ./cmd/... ./config/... ./pkg/clientinfo/... \
  -run 'ClientInfoPort|TestReadConfig_ClientInfoPortZero|Initialize_'
```

Proves: no flag/TOML resolves to 9601 by default binding while an explicit
`--clientInfo.port 0` (CLI) and `[clientInfo] Port = 0` (TOML) both resolve to
zero; an explicit 9601 and a custom port enable; and `clientinfo.Initialize`
returns `(nil, false)` for port 0 and a registry for a nonzero port.

### Container matrix (this harness)

| Case | Configuration | Expected result |
|---|---|---|
| compatibility default | omit all client-info settings | TCP 9601 listens internally; `GET /metrics` succeeds |
| explicit compatibility | TOML `Port = 9601` | same |
| CLI compatibility | `--clientInfo.port 9601` | same |
| custom | `--clientInfo.port 9137` | only 9137 responds |
| CLI disabled | `--clientInfo.port 0` | no listener; node still starts |
| TOML disabled | `[clientInfo] Port = 0` | no listener; node still starts |

`clientinfo.Initialize` runs only after `ethereum.Connect`, so the listener
cases require a node that can actually start against a chain (developer network
or a testnet RPC + operator key). Provide those and run:

```
IMAGE=keep-client@sha256:<candidate-image-digest> ETH_RPC=... KEY_FILE=... KEY_PASSWORD=... \
  ./clientinfo-port-smoke.sh listener-matrix
```

The harness's `require_digest` rejects a mutable tag: `IMAGE` (and `PROBE_IMAGE`)
MUST be pinned by an immutable `@sha256:` digest so a smoke run tests exactly the
bytes operators will deploy.

The harness runs each case as a node container on a **private user-defined
bridge network** and probes the client-info port from a sibling `curl` container
— never via a published host port. The network is not made Docker `--internal`
because the node must still reach its Ethereum/Electrum backends to start; the
security property this harness proves is container-to-container reachability with
**no host publication of 9601**. Proving that raw `9601`/`/diagnostics` are
unreachable from a genuinely untrusted external network is a separate manual /
ops follow-up (see the matrix above). `compose.yaml` shows the same
private-network topology for the compatibility-default case.

## Guardrails

- 9601 is a **temporary** compatibility default; the follow-up R2 release flips
  it back to `0` after the monitoring migration. Do not treat this harness as
  permission to publish raw `9601`/`/diagnostics` publicly — always reach it over
  a trusted path (firewall/VPN or an authenticated proxy).
- Do not add an unconditional `-p 9601:9601` to any operator-facing Docker
  sample; the listener stays internal to the container unless explicitly
  disabled with `--clientInfo.port 0`.
