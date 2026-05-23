# Cryptographic Review

Summary of all cryptographic primitives and constructions used in keep-core, with security assessment.

## Legend

| Symbol | Meaning |
|--------|---------|
| OK | Standard, well-audited implementation |
| REVIEW | Deserves closer inspection |
| ISSUE | Concrete concern |

---

## 1. BN256 (alt_bn128) Curve Operations

**Location:** `pkg/altbn128/altbn128.go`  
**Library:** `github.com/ethereum/go-ethereum/crypto/bn256/cloudflare`

Operations used:
- G1/G2 scalar multiplication and point addition
- Pairing check: `bn256.PairingCheck()` for BLS verification
- Custom point compression/decompression (`altbn128.go:150-245`)

### 1.1 Hash-to-Curve (Remediated; see F-02)

**Location:** `pkg/altbn128/altbn128.go:120-162`

```go
func G1HashToPoint(m []byte) *bn256.G1 {
    // SHA256(m || counter) for counter in 0..63; first valid x wins
}
```

This is a **counter-based hash-and-try** construction with a bound of 64 attempts. It replaced the original try-and-increment design (increment x until a quadratic residue is found) whose iteration count was geometrically distributed and therefore variable in time.

The counter-based variant still has variable iteration count (the loop exits on the first valid point), but each attempt performs identical work (one SHA-256 + one `big.Int.ModSqrt`) and the iteration count is bounded to at most 64. Per the call-site analysis in `security/findings/F-02.md`, all production callers feed public inputs into this primitive, so the residual timing channel reveals nothing not already public.

Used in:
- `pkg/bls/bls.go:51` -- BLS `Sign()` (message hashing; message is the relay entry, public)
- `pkg/bls/bls.go:63` -- BLS `Verify()` (same public message)
- `pkg/beacon/gjkr/protocol_parameters.go:24` -- Pedersen generator derivation from the public DKG sortition seed

**Open hygiene item:** A constant-time RFC 9380 SWU implementation is tracked as future work in [issue #4](https://github.com/tlabs-xyz/keep-core-security/issues/4). Not required for security; eliminates the residual panic-on-counter-exhaustion class (probability ~5e-20) noted in F-02.md §Limitations.

### 1.2 G2 Square Root (REVIEW)

**Location:** `pkg/altbn128/altbn128.go:272`

Custom `sqrtGfP2()` using a hardcoded exponent. Used for G2 decompression. The exponent should be `(p^2 + 1) / 4` for a BN curve with `p ≡ 3 mod 4`. This should be verified against the actual BN256 field modulus.

---

## 2. BLS Threshold Signatures

**Location:** `pkg/bls/bls.go`  
**Curve:** BN256  
**Scheme:** Custom threshold BLS (not compliant with IETF draft-irtf-cfrg-bls-signature)

### 2.1 Signature and Verification (OK)

Standard BLS signature structure:
- `Sign(secretKey, msg)`: `G1HashToPoint(msg) * secretKey` (`bls.go:48`)
- `Verify(pubKey, msg, sig)`: pairing check `e(sig, G2) == e(H(msg), pubKey)` (`bls.go:60`)

### 2.2 Threshold Reconstruction (REVIEW)

**Location:** `pkg/bls/bls.go:79`

Lagrange interpolation over 1-indexed member positions:

```go
func RecoverSignature(shares map[group.MemberIndex][]byte, threshold int) ([]byte, error)
```

- Members indexed 1..n; Lagrange numerator/denominator computed mod `bn256.Order`
- Modular inverse via `big.Int.ModInverse()` (not constant-time)
- No check that recovered signature actually verifies against the group public key before returning

**Concern:** If an invalid share passes the per-share BLS check (theoretically impossible with correct `VerifyG1`, but worth noting), recovery may silently produce an incorrect signature. The caller at `entry.go:215` does not re-verify the recovered signature.

### 2.3 Share Validation (OK)

**Location:** `pkg/beacon/entry/entry.go:186`

Each individual share is validated before accumulation:
```go
bls.VerifyG1(groupPublicKeyShares[senderID], previousEntry, share)
```

Pairing-based check per share is correct.

### 2.4 Aggregation (REVIEW)

**Location:** `pkg/bls/bls.go:31`

Point addition without enforcing distinct signers. The calling layer enforces one share per member index, but the aggregation function itself does not.

---

## 3. Threshold ECDSA (tECDSA)

**Location:** `pkg/tecdsa/`  
**Library:** `github.com/threshold-network/tss-lib` (forked from `github.com/bnb-chain/tss-lib` v1.3.5, commit `2e712689cfbe`)  
**Scheme:** GG18/GG20 (Gennaro-Goldfeder threshold ECDSA)  
**Curve:** secp256k1

This is the highest-value cryptographic component: compromise yields Bitcoin wallet control.

### 3.1 Pre-Parameters (REVIEW)

**Location:** `pkg/tecdsa/` (generator pool logic)

- Pre-generates Paillier key pairs (2048-bit) before DKG
- Cached in a pool; generation uses `crypto/rand` (correct)
- Stored to disk as protobuf (`pkg/tecdsa/gen/pb/preparams.proto`)

**The tss-lib fork contains custom patches** (see `go.mod` replace directive). The delta between the upstream bnb-chain fork and the threshold-network fork has not been independently audited here. Any local modification to the GG20 implementation is a high-priority review target.

### 3.2 P2P Share Encryption (Remediated; see F-03)

**Location:** `pkg/crypto/ephemeral/symmetric_key.go:24-40`

Each pair of DKG participants derives a shared symmetric key from ECDH on secp256k1 followed by HKDF-SHA256 (RFC 5869):

```go
shared := btcec.GenerateSharedSecret(privKey, pubKey)
kdf := hkdf.New(sha256.New, shared, nil /* salt */, info)
io.ReadFull(kdf, key[:])
```

Domain separation is enforced by the `info` parameter, which encodes both the protocol name and the canonical (sorted) peer-pair IDs:

| Caller | `info` layout | Defined at |
|--------|---------------|------------|
| Beacon GJKR | `"gjkr" || min(id_a,id_b) || max(id_a,id_b)` (each ID one byte) | `pkg/beacon/gjkr/protocol.go` (`gjkrEcdhInfo`) |
| tECDSA DKG | `"tecdsa-dkg" || min || max` | `pkg/tecdsa/dkg/protocol.go` (`dkgEcdhInfo`) |
| tECDSA signing | `"tecdsa-signing" || sessionID || min || max` | `pkg/tecdsa/signing/protocol.go` (`signingEcdhInfo`) |

`MemberIndex` is a `uint8`, pinned by both a compile-time assertion in `pkg/protocol/group/group.go` and a runtime check in `pkg/protocol/group/member_index_test.go`. The encoders are symmetric in `(id_a, id_b)` (sort before append) and injective across distinct sorted pairs, verified by unit tests at `pkg/{beacon/gjkr,tecdsa/dkg,tecdsa/signing}/protocol_ecdh_info_test.go`. The previous bare `sha256.Sum256(shared_secret)` construction is gone; same ECDH output across different protocols or peer pairs now yields cryptographically independent keys.

### 3.3 Private Key Share Storage (Encrypted at Rest; see F-01)

**Location:** `pkg/tecdsa/marshaling.go:24` (serialization), `pkg/storage/storage.go:110-113` (encryption)

tECDSA private key shares are serialized to protobuf and written through `persistence.NewEncryptedProtectedPersistence`, which wraps each write in NaCl `secretbox` (XSalsa20-Poly1305) keyed by `sha256.Sum256([]byte(password))` with a fresh random 24-byte nonce per write. The same password that unlocks the Ethereum keystore (the operator key file password supplied at startup) is used; both files have a consistent attack surface.

Full chain:
1. `cmd/start.go:285-287` -- `storage.Initialize(config, clientConfig.Ethereum.KeyFilePassword)` stores the operator password.
2. `cmd/start.go:303` -- `storage.InitializeKeyStorePersistence("tbtc")` returns a disk handle.
3. `pkg/storage/storage.go:110-113` -- The handle is wrapped with `NewEncryptedProtectedPersistence(diskHandle, s.encryptionPassword)`.
4. `pkg/tbtc/registry.go:55` -- All `saveSigner()` writes go through the encrypted handle.

**Residual concern (tracked separately):** the password-to-key derivation is a bare `sha256.Sum256` -- no salt, no iteration count, no memory-hard KDF. This is in `keep-common`, not `keep-core`, and applies symmetrically to the Ethereum keystore. Operators using strong random passwords or hardware-backed key custody are not materially exposed; for password-based deployments, an Argon2id / scrypt / PBKDF2 upgrade in `keep-common` is the proper fix. See F-01.md §Residual Concern.

### 3.4 tss-lib Dependency (REVIEW)

The forked `tss-lib` implements GG20 which requires Paillier range proofs (ZK proofs of Paillier ciphertext well-formedness). These proofs are computationally expensive and their correct implementation is security-critical. The fork should be diffed against the upstream and against the GG20 academic specification.

---

## 4. GJKR Distributed Key Generation (Beacon)

**Location:** `pkg/beacon/gjkr/`  
**Scheme:** GJKR (Gennaro-Jarchow-Kolesnikov-Rabin)  
**Curve:** BN256

Used for the Random Beacon group key (BLS keypair, not ECDSA).

### 4.1 Pedersen Commitment Generator (REVIEW)

**Location:** `pkg/beacon/gjkr/protocol_parameters.go:23`

The Pedersen commitment generator H is derived as:
```go
H = G1HashToPoint(previousBeaconEntry.Bytes())
```

H must be a generator of unknown discrete log relative to G. Deriving H from a (public) beacon entry is acceptable provided the DLP is hard. The underlying hash-to-curve is now the counter-based variant of §1.1; since the seed is public, the residual timing variation is not exploitable.

### 4.2 Symmetric Encryption (post-F-03)

**Location:** `pkg/beacon/gjkr/member.go` (calls `pkg/crypto/ephemeral/`)

Uses the HKDF-SHA256 derivation from §3.2 with the `"gjkr" || min(id_a,id_b) || max(id_a,id_b)` info label. Underlying authenticated cipher is NaCl `secretbox` (XSalsa20+Poly1305) via `encryption.NewBox()` in `github.com/keep-network/keep-common` -- see F-10.md for the dependency-level confirmation.

---

## 5. Ephemeral Key Pairs

**Location:** `pkg/crypto/ephemeral/private_key.go`  
**Library:** `github.com/btcsuite/btcd/btcec` (secp256k1)

Key generation: `btcec.NewPrivateKey()` → `crypto/rand.Reader` (correct).

ECDH: `btcec.GenerateSharedSecret(privKey, pubKey)` returns compressed X coordinate of shared point. The output is fed through HKDF-SHA256 with a domain-separating `info` label (see §3.2).

---

## 6. Operator Identity Key

**Location:** `pkg/operator/key.go`  
**Curve:** secp256k1  
**Library:** `crypto/ecdsa` with `btcec.S256()` curve

Generation: `ecdsa.GenerateKey(s256, rand.Reader)` (correct).  
Marshaling: compressed (33-byte) and uncompressed (65-byte) formats, consistent with standard secp256k1 encoding.

Stored in an Ethereum keystore file encrypted with the operator's password. The keystore uses the standard go-ethereum scrypt or PBKDF2 KDF.

---

## 7. Randomness

| Usage | Source | Assessment |
|-------|--------|-----------|
| Operator identity key generation | `crypto/rand` | OK |
| Ephemeral DKG/signing keypairs | `crypto/rand` via btcec | OK |
| Paillier key generation (tss-lib) | `crypto/rand` | OK |
| Local network identity (test/local mode) | `math/rand` with `#nosec G404` | OK (non-security use, documented) |
| Retry operator shuffling | `math/rand` seeded from message hash + retry count (`retry.go:60`) | OK (reproducibility intentional, not security-sensitive) |

No use of insecure randomness in cryptographic paths was found.

---

## 8. Hash Functions

| Function | Usage | Assessment |
|----------|-------|-----------|
| SHA256 | Hash-to-curve, HKDF-SHA256 (ECDH KDF), commitment derivation | OK |
| Keccak256 | Ethereum message signing, DKG result hash | OK |
| SHA3-256 | Block simulation, some chain ops | OK |
| MD5, SHA1 | Not found | -- |

---

## 9. External Cryptographic Dependencies

| Package | Version | Purpose | Assessment |
|---------|---------|---------|-----------|
| `github.com/ethereum/go-ethereum` | v1.13.15 | bn256, ECDSA, keccak256, keystore | OK -- widely audited |
| `github.com/threshold-network/tss-lib` | forked at `2e712689` | GG18/GG20 tECDSA | REVIEW -- custom fork, patches vs upstream unknown |
| `github.com/btcsuite/btcd` | v0.23.2 | secp256k1, btcec, Bitcoin parsing | OK |
| `github.com/keep-network/keep-common` | `v1.7.1-0.20240424...` | `encryption.Box`, persistence, keystore | REVIEW -- internal library, encryption implementation not in this repo |
| `golang.org/x/crypto` | v0.32.0 | scrypt, sha3, terminal password read | OK |

