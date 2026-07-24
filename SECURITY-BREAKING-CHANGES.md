# Security Fix Breaking Changes

This document tracks breaking cryptographic changes introduced by the security
remediation branch. Each change alters wire-level or key-derivation behavior
and requires a **coordinated network upgrade** -- all nodes must upgrade before
the new code activates. Rolling upgrades will cause protocol failures.

---

## F-02 -- Hash-to-Curve: bounded counter-based approach (G1HashToPoint)

**File:** `pkg/altbn128/altbn128.go`

**What changed:**

`G1HashToPoint` previously incremented a candidate x coordinate until a valid
G1 point was found (try-and-increment). The number of iterations depended on
the hash output, creating a timing side channel.

The function now uses a fixed counter suffix appended to the input before
hashing: `SHA-256(message || counter)` for counter in `[0, 63]`. Each
iteration performs identical work, bounding (but not normalizing) timing across
inputs: the loop exits on the first valid point, so execution time still varies
with how many counters are tried. Using 64 candidate counters gives a failure
probability of `(1/2)^64 ≈ 5e-20`.

**Why it breaks:**

The counter-based approach produces a different x candidate for every input
than the try-and-increment approach. The same byte string will map to a
different G1 point.

**Impact:**

Any distributed protocol that relies on consistent G1HashToPoint output across
nodes (e.g., BLS signature aggregation in the random beacon DKG) will fail if
nodes run mismatched versions.

**On-chain consumer:**

The new counter-based `G1HashToPoint` also diverges permanently from the
on-chain `AltBn128.g1HashToPoint`
(`solidity/random-beacon/contracts/libraries/AltBn128.sol`), which keeps the
original try-and-increment mapping fixed in the deployed contract bytecode. A
client-side (Go node) upgrade cannot change that bytecode, so Go<->chain
agreement for the on-chain consumer path -- `BLS.verifyBytes`
(`libraries/BLS.sol`), reached from `RandomBeacon.reportUnauthorizedSigning` --
can never be restored by upgrading the client alone.

In practice this is not an operational concern: that path has no in-repo
production callers. The only Go code that maps a raw byte message to a G1 point
this way is the `bls.Sign` / `bls.Verify` byte-message helpers in
`pkg/bls/bls.go`, which have no callers in the repository and are effectively
deprecated, and the generated `RandomBeacon.reportUnauthorizedSigning` binding
is never invoked by node logic. The consumer that matters operationally is the
off-chain GJKR Pedersen `H` generator
(`pkg/beacon/gjkr/protocol_parameters.go`) -- a node-to-node concern in which
every group member must derive the same `H`, which the coordinated upgrade
below guarantees.

**Mitigation / upgrade path:**

1. Schedule a hard-fork block or protocol version bump.
2. Deploy the new binary to all nodes simultaneously at the upgrade height.
3. Verify with a coordinated test on a staging network first.

**Follow-up (tracked in GH issue):**

Replace with a constant-time RFC 9380 SWU implementation to eliminate the
remaining non-constant-time modular square root. See:
https://github.com/tlabs-xyz/keep-core-security/issues/4

---

## F-03 -- ECDH key derivation: SHA-256 replaced with HKDF-SHA256

**File:** `pkg/crypto/ephemeral/symmetric_key.go` (and all callers)

**What changed:**

`PrivateKey.Ecdh()` previously derived a 32-byte session key as
`SHA-256(shared_secret)` -- using the raw ECDH output as key material with no
domain separation.

The function now uses HKDF-SHA256 (RFC 5869):

```
key = HKDF-Extract+Expand(ikm=shared_secret, salt=nil, info=context_label)
```

The `info` parameter binds the derived key to the specific protocol and
peer pair. Each callsite passes a label encoding:

- A protocol prefix (`gjkr`, `tecdsa-sign`, `tecdsa-dkg`)
- The canonical (sorted) pair of member IDs, each encoded as a single byte

This ensures keys derived for different protocols or peer pairs are
cryptographically independent, even if the ECDH shared secret is the same.

**Invariant:** Member IDs are encoded as a single byte each. This relies on
`group.MemberIndex` being a `uint8` (max member index 255). A compile-time
assertion in `pkg/protocol/group/group.go` enforces this; if the type is ever
widened, the `*EcdhInfo` helpers must switch to a width-independent encoding
(e.g. `binary.BigEndian.PutUint16`) in the same coordinated upgrade as F-03,
otherwise members whose IDs collide modulo 256 will derive identical keys.

**Callsites updated:**

| File | Count |
|------|-------|
| `pkg/beacon/gjkr/protocol.go` | 4 |
| `pkg/tecdsa/signing/protocol.go` | 1 |
| `pkg/tecdsa/dkg/protocol.go` | 1 |

**Why it breaks:**

HKDF with a non-empty `info` label produces a different 32-byte key than
`SHA-256(shared_secret)` for the same ECDH shared secret. Two nodes running
mismatched versions will derive different session keys and fail to decrypt each
other's shares.

**Impact:**

Any phase of the GJKR DKG, tECDSA DKG, or tECDSA signing protocol that
involves peer-to-peer encrypted share exchange will fail if nodes run
mismatched versions. This covers the full distributed key generation and
signing flows.

**Mitigation / upgrade path:**

1. Schedule a hard-fork block or protocol version bump.
2. Deploy the new binary to all nodes simultaneously at the upgrade height.
3. Verify with a coordinated test on a staging network first.
4. No on-chain data migration is required -- the ECDH keys are ephemeral
   (generated fresh each session) and not persisted.

---

## Security release operator reference (BC-1..BC-10, OV-1..OV-3)

The table below is the operator-facing index for the coordinated security
release (`security-release/candidate-1`). Items marked **breaking** require a
flag-day upgrade of every participant in the same DKG or signing ceremony.
Operator-visible (OV) items do not change wire formats but may require config or
monitoring updates.

### Breaking changes

| ID | Area | What breaks | Who must act |
|----|------|-------------|--------------|
| **BC-1** | tss-lib | Fiat-Shamir / proof challenges use tagged hashing + session binding; old and new proofs **do not cross-verify** | **All operators simultaneously** |
| **BC-2** | tss-lib + keep-core | `SetSessionNonce` / `SetSessionNonceBytes` **mandatory** before keygen/signing `Start()`; session ID must be ≥16 bytes | keep-core wires this; external callers with short IDs **panic** |
| **BC-3** | tss-lib + keep-core | ECDSA signing requires positive `fullBytesLen` at construction (panic if omitted/zero) | keep-core passes curve-order byte width |
| **BC-4** | keep-core | **Session ID formats changed** (wire): DKG `dkg-<seedHex>-<attempt:016x>`; signing `signing-<messageHex>-<startBlock:016x>-<attempt:016x>` | All parties in a ceremony |
| **BC-5** | keep-core | Signing session ID now includes **attempt start block** — peers disagreeing on block derive different IDs | Coordinator / announcer agreement |
| **BC-6** | keep-core | `ephemeral.PrivateKey.Ecdh(info []byte)` — **compile break** + HKDF-derived keys differ (wire-incompatible); see **F-03** above | Any external code calling the old signature |
| **BC-7** | keep-core | `G1HashToPoint` reimplemented — **different G1 point** for the same input; see **F-02** above | Beacon / crypto paths using hash-to-curve |
| **BC-8** | keep-core | `PrepareForSigning` returns `(wi, bigWs, err)` — **compile break** for callers | Go integrators (no in-tree keep-core callers found) |
| **BC-9** | keep-core | Bootstrap removal (#3909): embedded well-known peers + **AllowList decoupling** — all peers pass `IsRecognized()` | Operators with custom bootstrap config |
| **BC-10** | keep-core | RandomBeacon **new storage slot** for the reentrancy guard (append-only bytecode change). RandomBeacon is **directly deployed, not proxied**, so this activates **only** by deploying a new RandomBeacon and cutting over to its address — never by an in-place / proxy implementation swap | Only if this release **redeploys RandomBeacon**: perform the address cutover (see the BC-10 note below). If there is no beacon redeployment, BC-10 is **staged but not activated** on the existing deployment |

### Operator-visible (non-breaking wire)

| ID | Change | Operator action |
|----|--------|-----------------|
| **OV-1** | Metrics/diagnostics **opt-in**: `clientInfo.port` default is **0** (HTTP server off) | Set `clientInfo.port` explicitly (e.g. `9601`) if scraping `/metrics` or `/diagnostics` |
| **OV-2** | Metric rename: `connected_bootstrap_count` → `connected_wellknown_peers_count` | Update Grafana/Prometheus dashboards and alerts |
| **OV-3** | `--network.bootstrap=true` deprecated (warning only) | Remove from config when convenient |

**BC-10 note — RandomBeacon is directly deployed, not a proxy.**
`solidity/random-beacon/deploy/04_deploy_random_beacon.ts` calls
`deployments.deploy("RandomBeacon", …)` with constructor arguments and linked
libraries and **no `proxy` option**; there is no implementation-upgrade path.
The reentrancy-guard storage slot is therefore compiled into the RandomBeacon
bytecode and cannot be added to an already-deployed RandomBeacon by swapping a
proxy implementation. It becomes active **only** when a new RandomBeacon is
deployed and the network cuts over to the new address. Do **not** treat BC-10 as
a "beacon proxy upgrade":

- **If this release includes a RandomBeacon redeployment:** follow a separately
  reviewed migration runbook covering the new address, dependency wiring
  (sortition pool, staking, DKG validator, ReimbursementPool authorization and
  funding), ownership/governance, consumer references, and post-deployment
  validation. This is a fresh deployment + cutover, not an in-place upgrade.
- **If RandomBeacon is not redeployed in this release:** BC-10 ships as a staged
  bytecode change that is **not activated** on the existing deployment; no
  operator action is required for it, and no existing reentrancy behavior
  changes until a future beacon deployment.

This distinguishes RandomBeacon from legitimately proxied components (e.g.
`LightRelayMaintainerProxy`), which this row does not cover.

**F-09 note — RandomBeacon relay-entry reimbursement offset (proposed design
decision — pending owner ratification).** Both `submitRelayEntry` overloads share a single
`_relayEntrySubmissionGasOffset = 13_450`
(`contracts/RandomBeacon.sol:475,1072,1138`; fixture
`test/fixtures/index.ts:59`). The offset was raised from `11_250` to `13_450` to
cover ~2,118 gas of reimbursement work that executes **after** the in-function
`gasStart - gasleft()` snapshot — the inline `nonReentrant` guard writes
`_reentrancyStatus` after the function body, and the reimbursement call itself is
partly unmeasured — plus headroom, tuned for the heavier
`submitRelayEntry(bytes,uint32[])` overload.

- **Structural asymmetry (observed).** The heavier overload's `uint32[64]`
  `membersIDs` argument is charged as intrinsic **calldata** gas *before* the
  in-function snapshot and is therefore never measured; the lighter
  `submitRelayEntry(bytes)` overload carries none of that calldata, so the shared
  offset structurally **over-reimburses** the lighter overload by a fixed
  ~9,563 gas. This is a property of the single-offset design, not a defect.
- **Proposed decision (pending ratification).** Keep one shared offset rather than splitting it into two
  governance-settable offsets. Rationale: (1) avoids adding a second storage slot
  plus governance setter and the associated upgrade/migration surface on a
  security-release contract; (2) the only harmful direction —
  **under-reimbursement** — never occurs on either overload at `13_450` (the
  submitter is always at least made whole); (3) over-reimbursement is bounded and
  paid from the operator-funded `ReimbursementPool`, never from user funds;
  (4) governance may still retune the offset post-deployment through the existing
  `updateGasParameters` (`onlyGovernance`) path if measurements change.
- **Enforced invariants** (`test/RandomBeacon.Relay.test.ts`,
  `test/RandomBeacon.StorageLayout.test.ts`): no under-reimbursement on either
  overload at `13_450`; heavier-overload over-reimbursement ≤ **5,000** gas
  (`TUNED_OVER_REIMBURSEMENT_GAS_TOLERANCE`); lighter-overload over-reimbursement
  ≤ **10,000** gas (`BYTES_ONLY_OVER_REIMBURSEMENT_CEILING_GAS`, bracketing the
  measured ~9,563 with headroom so it cannot silently grow); negative control —
  the heavier overload **under-reimburses at the pre-fix `11_250` offset**
  (proving the ~2,200-gas fix is necessary and that the test is sensitive to it),
  while the lighter overload stays fully reimbursed even at `11_250` (+7,363 gas),
  confirming the fix is not needed for that path; and a storage-layout regression
  pinning the slot and the `13_450` value. Gas figures are measured under the
  pinned Hardhat compiler/optimizer/EVM-hardfork settings and must be remeasured
  if any of those change.
- **Release gate.** This shared-offset design and its 5,000 / 10,000-gas
  over-reimbursement ceilings require contract/security-owner sign-off before
  release: `[x]` approved (2026-07-24).

**tss-lib pin (this release):** `github.com/threshold-network/tss-lib@v0.0.0-20260615180949-86bd1a375cc0` (`86bd1a3`).

**tECDSA signing copylock fix (this candidate, reviewed and accepted 2026-07-24).**
Merging current `main` exposed a `go vet` copylock failure in
`pkg/tecdsa/signing/member.go`: a generic channel receive was copying tss-lib's
`common.SignatureData` (which embeds a `DoNotCopy` lock marker) by value. The
fix (`finalizingMember.receiveTSSResult`) drains the channel via
`reflect.Select` + `reflect.New`/`Set` instead of a plain value receive, so
`go vet` no longer flags the copy. This is a receive-side mechanical change
only — it does not alter session handling, message content, or any
cryptographic computation, and tss-lib's own send side already copies the same
value (`end <- *round.data`). It is reviewed and accepted separately from, and
does not substitute for, the external `tss-lib` dependency security audit
tracked as a separate release action item above.

---

## Coordinated upgrade (flag-day) requirement

These changes activate by code alone. There is no on-chain version gate and no
peer-version negotiation: an upgraded node has no runtime switch to fall back to
the old key-derivation, session-ID, or hash-to-point behavior when it meets an
un-upgraded peer. The whole set of nodes taking part in a given ceremony must
therefore be upgraded together -- a flag-day cutover, not a rolling upgrade.

This requirement covers every breaking change in this release that feeds a
shared cryptographic computation:

- **Key derivation (F-03)** -- HKDF-SHA256 with a domain-separation `info` label.
- **Session IDs (tECDSA DKG and signing)** -- the typed, fixed-width session-ID
  formats and the signing session ID's added dependency on the attempt start
  block. Tracked in `CHANGELOG.md` under `### Changed` (BREAKING).
- **Hash-to-curve (F-02)** -- the counter-based `G1HashToPoint`.

Within a single DKG or signing ceremony, mixed-version peers derive different
keys, session IDs, or points and fail to interoperate. The failure mode is
liveness-only: the ceremony does not complete. It is not a fund-safety or
consensus-safety issue -- mismatched cryptography fails closed (shares do not
decrypt, signatures do not verify) and never yields a valid-but-wrong result.
Operators must upgrade the entire ceremony fleet atomically and must not run a
mixed-version set through a live DKG or signing session.

---

## Upgrade Coordination Checklist

For each breaking change:

- [ ] Hard-fork block / protocol version agreed and documented
- [ ] Staging network upgrade tested
- [ ] Node operators notified with sufficient lead time
- [ ] Rollback plan in place (revert binary, block range)
- [ ] Post-upgrade monitoring in place (alert on share decryption failures)
