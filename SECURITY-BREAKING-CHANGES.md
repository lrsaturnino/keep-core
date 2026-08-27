# Security Fix Breaking Changes

This document tracks breaking cryptographic changes introduced by the security
remediation branch and the intended release contract still required around
them. Each change requires a **coordinated network upgrade**: every production
process and eligible seat must run R1 before the reviewed cutover block `C`.
The target contract durably seals a compatibility strategy to a verified
canonical work anchor. After R01 restores complete PRIOR transcript
compatibility, pre-`C` R1 work can use that legacy-compatible strategy while
work anchored at or after `C` uses security-v2. The current candidate has only
number-based, process-local permit selection and a nominal-legacy TSS branch
whose ZK/ZKV equations differ from PRIOR; R01, canonical-hash binding, and
restart-safe sealing remain pending. Cross-mode contributions inside one
ceremony do not interoperate; complete fleet/subset behavior remains an
R00-03/R01 qualification requirement.

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
members (e.g., the random beacon DKG) will fail if one ceremony mixes the
legacy and security-v2 mappings.

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

1. Implement the pending canonical-hash/durable binding, then verify both
   homogeneous strategies and the cutover boundary on staging.
2. Deploy the exact R1 artifact to every production process and eligible seat
   before `C`, with zero residual PRIOR participation at the boundary.
3. Under the completed release contract, preserve the durably sealed mode for
   every ceremony and reject mixed-mode input; never switch an in-flight
   ceremony at current head.

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
`SHA-256(shared_secret)` for the same ECDH shared secret. Two members using
different compatibility modes derive different session keys and fail to
decrypt each other's shares.

**Impact:**

Any phase of the GJKR DKG, tECDSA DKG, or tECDSA signing protocol that
involves peer-to-peer encrypted share exchange will fail if a ceremony mixes
legacy and security-v2 members. This covers the full distributed key
generation and signing flows.

**Mitigation / upgrade path:**

1. Verify the exact R1 artifact and cutover schedule on a staging network.
2. Deploy R1 to every production process and eligible seat before the reviewed
   cutover block `C`; prove the residual PRIOR process/seat count is zero.
3. Under the completed release contract, let durably sealed work anchored below
   `C` retain the legacy derivation and require work anchored at or above `C` to
   use the security-v2 derivation. Never mix modes within one ceremony or retry
   security-v2 work as legacy.
4. No on-chain data migration is required -- the ECDH keys are ephemeral
   (generated fresh each session) and not persisted.

---

## Security release operator reference (BC-1..BC-10, OV-1..OV-3)

The table below is the operator-facing index for the target coordinated
security release (`security-release/candidate-1`); it is not a present-readiness
claim. Items marked **breaking** require a homogeneous mode among every
participant in the same DKG or signing ceremony. The fleet must be entirely on
R1 before `C`; only after R01 repairs full transcript compatibility and R03/R04
supply canonical durable sealing may `< C` work use R1's legacy-compatible
strategy.
Operator-visible (OV) items do not change wire formats but may require config or
monitoring updates.

### Breaking changes

| ID | Area | What breaks | Who must act |
|----|------|-------------|--------------|
| **BC-1** | tss-lib | Security-v2 Fiat-Shamir / proof challenges use tagged hashing + session binding; legacy and security-v2 proofs **do not cross-verify** | Every ceremony must use one mode; every eligible seat runs R1 before `C` |
| **BC-2** | tss-lib + keep-core | Security-v2 requires `SetSessionNonce` / `SetSessionNonceBytes` before keygen/signing `Start()` and a session ID ≥16 bytes. The current `d847` nominal-legacy ZK/ZKV equations differ from PRIOR, so historical compatibility is not yet restored | keep-core wires explicit modes; R01 must repair and prove the PRIOR transcript before rollout |
| **BC-3** | tss-lib + keep-core | ECDSA signing requires positive `fullBytesLen` at construction (panic if omitted/zero) | keep-core passes curve-order byte width |
| **BC-4** | keep-core | Security-v2 **session ID formats change** (wire): DKG `dkg-<seedHex>-<attempt:016x>`; signing `signing-<messageHex>-<startBlock:016x>-<attempt:016x>`; legacy retains the prior forms | All parties in a ceremony use one selected mode; durable sealing remains pending R03/R04 |
| **BC-5** | keep-core | The security-v2 signing session ID includes **attempt start block** — peers disagreeing on that shared input derive different IDs | Coordinator / announcer agreement |
| **BC-6** | keep-core | `ephemeral.PrivateKey.Ecdh(info []byte)` is a **compile break**; the security-v2 strategy uses wire-incompatible HKDF while legacy retains the prior derivation; see **F-03** above | Any external code calling the old signature |
| **BC-7** | keep-core | Security-v2 uses the new `G1HashToPoint` result while legacy retains the prior mapping; see **F-02** above | Beacon / crypto paths must carry one selected mode; durable sealing remains pending R03/R04 |
| **BC-8** | keep-core | `PrepareForSigning` returns `(wi, bigWs, err)` — **compile break** for callers | Go integrators (no in-tree keep-core callers found) |
| **BC-9** | keep-core | Bootstrap removal (#3909): embedded well-known peers + **AllowList decoupling** — all peers pass `IsRecognized()` | Operators with custom bootstrap config |
| **BC-10** | keep-core | RandomBeacon **new storage slot** for the reentrancy guard (append-only bytecode change). RandomBeacon is **directly deployed, not proxied**, so this activates **only** by deploying a new RandomBeacon and cutting over to its address — never by an in-place / proxy implementation swap | Only if this release **redeploys RandomBeacon**: perform the address cutover (see the BC-10 note below). If there is no beacon redeployment, BC-10 is **staged but not activated** on the existing deployment |

### Operator-visible (non-breaking wire)

| ID | Change | Operator action |
|----|--------|-----------------|
| **OV-1** | Metrics/diagnostics **temporary compatibility default**: `clientInfo.port` stays `9601` for this coordinated release (HTTP server on) so a node's exact revision and stranded-peer evidence stay visible through the cutover; explicit `clientInfo.port = 0` disables it. The follow-up R2 release flips the default back to `0` after the monitoring migration. | Commit an explicit `clientInfo.port` value now, expose it only over a trusted path, and migrate scrape targets before R2 |
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

**F-09 note — RandomBeacon relay-entry reimbursement offset (design decision,
approved 2026-07-24).** Both `submitRelayEntry` overloads share a single
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
- **Decision (approved 2026-07-24).** Keep one shared offset rather than splitting it into two
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

**tss-lib pin (this release):** `github.com/threshold-network/tss-lib@v0.0.0-20260729021955-d847ce003019` (`d847ce0`). This revision is one commit after `86bd1a3` and adds immutable per-party transcript-mode selection for the legacy/security-v2 cutover.

**tECDSA signing copylock fix (this candidate, reviewed and accepted 2026-07-24).**
Merging current `main` exposed a `go vet` copylock failure in
`pkg/tecdsa/signing/member.go`: tss-lib's `signing.NewLocalParty` requires a
value-typed result channel and delivers via `end <- *round.data`
(`ecdsa/signing/finalize.go`), so every consumer must copy the lock-bearing
`common.SignatureData` (a protobuf message with a `DoNotCopy` marker) on
receive. `finalizingMember.receiveTSSResult` performs that single unavoidable
receive through the type-safe generic helper `receiveFromChannel` (no
reflection), then re-homes only the signature-relevant fields (`Signature`,
`SignatureRecovery`, `R`, `S`, `M`) into a freshly allocated `SignatureData`
built with a composite literal. The returned value owns a brand-new, never-locked
`MessageState`, so `go vet` has nothing to flag, and the transient received
value (with its copied lock) is discarded at the function boundary rather than
propagated. This is a receive-side mechanical change only — it does not alter
session handling, message content, or any cryptographic computation. It is
reviewed and accepted separately from, and does not substitute for, the
external `tss-lib` dependency security audit tracked as a separate release
action item above; the ideal upstream fix (forking tss-lib's channel to a
pointer type) is intentionally out of scope for this release and tracked
separately.

---

## Coordinated upgrade and work-anchor cutover

This candidate contains the chain-clocked participation gate and immutable
per-permit legacy/security-v2 strategy bundles. The currently landed gate
classifies the caller-supplied ceremony start-block number once: numbers below
the cutover block `C` select legacy behavior, while numbers at or above `C`
select security-v2. In-process retries carry that selected mode. Canonical
block-hash/incarnation binding and durable restart inheritance are not yet
implemented; R03 and R04 must add them before this can be called a verified,
restart-safe work-anchor cutover.

The current candidate is intentionally not a deployable mainnet artifact:
`participation.MainnetCutoverBlock` is still the zero release blocker, and
mainnet startup fails closed until a reviewed release commit supplies `C`.
Before that selected block is armed, every production process and every
eligible seat must run the exact R1 artifact; the permitted residual is zero
PRIOR processes and zero PRIOR-eligible seats. This fleet transition is
coordinated. The intended release policy is not a blanket one-instant
cryptographic flag day: after R01 restores the PRIOR transcript, an enumerated,
durably sealed `< C` R1 incarnation may finish with legacy-compatible behavior
while an independently admitted `>= C` incarnation uses security-v2. That
compatibility and durable policy remain release requirements, not claims about
the current nominal-legacy, number-only, process-local permit.

The per-mode differences that feed shared cryptographic computation are:

- **Key derivation (F-03)** -- legacy retains the prior derivation;
  security-v2 uses HKDF-SHA256 with a domain-separation `info` label.
- **Session IDs (tECDSA DKG and signing)** -- legacy retains the prior forms;
  security-v2 uses typed, fixed-width IDs and binds signing to the attempt
  start block. See `CHANGELOG.md` under `### Changed`.
- **Hash-to-curve (F-02)** -- legacy retains the prior mapping; security-v2
  uses the counter-based `G1HashToPoint`.

A single DKG or signing ceremony must remain homogeneous. Mixed R1
nominal-legacy and security-v2 participants derive different keys, session IDs,
or points and fail to interoperate. Separately, the current nominal-legacy
ZK/ZKV transcript does not cross-verify with PRIOR, which is the R01 blocker.
Cross-mode contributions and proofs fail closed: their shares do not decrypt or
their proofs/signatures do not verify, and they may prevent the ceremony from
completing. Whether a larger homogeneous subset can still reach quorum remains
blocked on the exact-binary R00-03/R01 fleet matrix. A mismatch does not
authorize a PRIOR process at `C`, an unsealed legacy session, or a downgrade
retry.

### Coordinated release-model context

The release is designed to carry one compiled mainnet cutover block `C`;
mainnet cannot override it at runtime. Today the participation gate selects a
mode from a supplied start-block number, and the compatibility bundle carries
that decision through session IDs, ECDH, hash-to-curve, and TSS transcript
configuration. A live legacy permit can complete after `C` under the gate's
completion checks, while its new legacy penalty commits are suppressed at or
after `C`; durable restart and canonical-hash fences remain pending R03/R04.
The landed tECDSA and Beacon cryptographic strategy paths fail on mixed-mode
transcripts rather than downgrading. The broader authenticated tBTC
coordination-envelope rejection boundary is not yet implemented and remains a
blocking R00-08/R00B requirement.

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

**Release epoch.** The compiled artifact epoch is `security_v2_cutover`. The
client-info metric and diagnostics expose the release version, exact revision,
and protocol epoch; participation diagnostics expose the resolved cutover block
and live per-mode permit counts. These fields describe the artifact and gate,
not the mode of every ceremony in the process. The `cutover-roster` aggregator
still receives the expected epoch, revision, image digest, and cutover block as
operator-supplied release inputs and must match them against every eligible
instance. With the compiled mainnet `C` still zero, this candidate remains
blocked from mainnet regardless of those operator-supplied values.

---

## Upgrade Coordination Checklist

For each breaking change:

- [ ] Hard-fork block / protocol version agreed and documented
- [ ] Staging network upgrade tested
- [ ] Node operators notified with sufficient lead time
- [ ] Signed rollback plan in place for pre-`C`, pre-R04-enrollment use only
      (authorized artifact and block range); binary downgrade at or after `C`
      is prohibited
- [ ] Post-upgrade monitoring in place (alert on share decryption failures)
