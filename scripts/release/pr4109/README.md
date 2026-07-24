# PR #4109 — clientInfo.port 9601 compatibility smoke matrix (Part B, section 14.2)

This directory holds the container smoke harness for the temporary
`clientInfo.port` **9601 compatibility default** restored for the coordinated
security release. It is scoped to Part B; it does **not** exercise the Part A
cutover gate (which is intentionally not implemented in this pass).

## What is proven where

| Layer | Proof | Runnable |
|---|---|---|
| Port resolution (flag/TOML precedence, both explicit-zero paths, custom port) | Go unit/config tests (section 14.1) | ✅ locally, no Docker/chain |
| Port → listener decision (`0` disables, nonzero enables) | `pkg/clientinfo` unit tests | ✅ locally, no Docker/chain |
| Runtime image bakes the 9601 default | `clientinfo-port-smoke.sh image-default-check` | ✅ Docker only, no chain |
| Container listens on 9601 / custom, serves meaningful `/metrics` | `clientinfo-port-smoke.sh listener-matrix` | ⚙️ needs Docker **and** a chain endpoint + operator key |
| Testnet scrape from the real monitoring host, 3 consecutive intervals, current revision/epoch | — | 🔲 **manual / ops follow-up** |
| External untrusted-network probe: raw `9601` / `/diagnostics` unreachable unless an authenticated proxy is in front | — | 🔲 **manual / ops follow-up** |

### Section 14.1 (fully runnable locally)

```
go test ./cmd/... ./config/... ./pkg/clientinfo/... \
  -run 'ClientInfoPort|TestReadConfig_ClientInfoPortZero|Initialize_'
```

Proves: no flag/TOML resolves to 9601 by default binding while an explicit
`--clientInfo.port 0` (CLI) and `[clientInfo] Port = 0` (TOML) both resolve to
zero; an explicit 9601 and a custom port enable; and `clientinfo.Initialize`
returns `(nil, false)` for port 0 and a registry for a nonzero port.

### Section 14.2 matrix (this harness)

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
