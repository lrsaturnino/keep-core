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
| **BC-10** | keep-core | RandomBeacon **new storage slot** for reentrancy guard (append-only, proxy-safe) | Contract deploy / upgrade path **only if** beacon proxy upgraded in same train |

### Operator-visible (non-breaking wire)

| ID | Change | Operator action |
|----|--------|-----------------|
| **OV-1** | Metrics/diagnostics **temporary compatibility default**: `clientInfo.port` stays `9601` for this coordinated release (HTTP server on) so a node's exact revision and stranded-peer evidence stay visible through the cutover; explicit `clientInfo.port = 0` disables it. The follow-up R2 release flips the default back to `0` after the monitoring migration. | Commit an explicit `clientInfo.port` value now, expose it only over a trusted path, and migrate scrape targets before R2 |
| **OV-2** | Metric rename: `connected_bootstrap_count` → `connected_wellknown_peers_count` | Update Grafana/Prometheus dashboards and alerts |
| **OV-3** | `--network.bootstrap=true` deprecated (warning only) | Remove from config when convenient |

**tss-lib pin (this release):** `github.com/threshold-network/tss-lib@v0.0.0-20260615180949-86bd1a375cc0` (`86bd1a3`).

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

### Coordinated release-model context

The mixed-version hazard above is why the coordinated release is _designed_
around a single required operator update and one release-baked cutover block
(`C`): under that design, before `C` participants speak the legacy wire formats
and canonically post-`C` work speaks security-v2. That block-height cutover gate,
and its per-ceremony legacy/security-v2 mode strategies, are a separate,
not-yet-landed change. **This build does not contain the gate and therefore
still requires the atomic flag-day upgrade described in the section above — there
is no runtime height switch yet.** The fail-closed property holds regardless
(mismatched cryptography does not decrypt or verify and never yields a
valid-but-wrong result), so an un-upgraded peer that meets upgraded peers in a
ceremony loses liveness rather than fund safety.

Two supporting changes ship to keep the coordinated release observable and to
identify who has not converged:

- **Client-info compatibility (Part B).** The `clientInfo.port` default is
  retained at `9601` for the release window (see OV-1). This keeps the
  unauthenticated metrics/diagnostics channel — the primary source of a node's
  exact revision and stranded-peer evidence — alive through the cutover.
  Expose it only over a trusted path. R2 flips the default back to `0` after the
  monitoring migration is complete.
- **Stranded/legacy-peer observability.** An announcer session-ID mismatch
  observer classifies each membership-valid announcement as legacy or hardened
  and a node-local, deduplicated cutover peer roster records post-cutover legacy
  sightings by normalized operator address. A separate `cutover-roster`
  aggregator joins those sightings to the authoritative eligible-instance
  inventory so readiness is measured against exact revision/epoch/digest, not
  merely a quiet mismatch counter.

**Release epoch.** The coordinated cutover artifact is identified by the release
epoch `security_v2_cutover`. Exporting that epoch (and the cutover block) as a
`client_info` label and diagnostics field is part of the not-yet-landed gate
change and is NOT present in this build; today the go/no-go evidence is a node's
exact revision (already in `client_info`/diagnostics) plus the stranded-peer
observability below, not the container tag. The `cutover-roster` aggregator's
`--expectedEpoch` flag carries the expected `security_v2_cutover` value as plain
operator-supplied configuration until the gate ships.

---

## Upgrade Coordination Checklist

For each breaking change:

- [ ] Hard-fork block / protocol version agreed and documented
- [ ] Staging network upgrade tested
- [ ] Node operators notified with sufficient lead time
- [ ] Rollback plan in place (revert binary, block range)
- [ ] Post-upgrade monitoring in place (alert on share decryption failures)
