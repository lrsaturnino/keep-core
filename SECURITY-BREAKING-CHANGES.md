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
iteration performs identical work, bounding and normalizing timing across
inputs. The maximum counter value (64) gives a failure probability of
`(1/2)^64 ≈ 5e-20`.

**Why it breaks:**

The counter-based approach produces a different x candidate for every input
than the try-and-increment approach. The same byte string will map to a
different G1 point.

**Impact:**

Any distributed protocol that relies on consistent G1HashToPoint output across
nodes (e.g., BLS signature aggregation in the random beacon DKG) will fail if
nodes run mismatched versions.

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
- The canonical (sorted) pair of member IDs

This ensures keys derived for different protocols or peer pairs are
cryptographically independent, even if the ECDH shared secret is the same.

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

## Upgrade Coordination Checklist

For each breaking change:

- [ ] Hard-fork block / protocol version agreed and documented
- [ ] Staging network upgrade tested
- [ ] Node operators notified with sufficient lead time
- [ ] Rollback plan in place (revert binary, block range)
- [ ] Post-upgrade monitoring in place (alert on share decryption failures)
