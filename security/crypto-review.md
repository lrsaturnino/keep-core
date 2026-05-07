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

### 1.1 Hash-to-Curve (ISSUE)

**Location:** `pkg/altbn128/altbn128.go:120`

```go
func G1HashToPoint(m []byte) *bn256.G1 {
    // SHA256 of input, then try-and-increment until valid x
}
```

This is a **try-and-increment** hash-to-curve, not the standard Elligator/SWU construction from RFC 9380. Problems:
- Not constant-time: number of iterations leaks information about the hash output (timing side channel)
- If used during signing, can leak bits about the signed message or the hash input
- Non-standard: deviates from IETF BLS draft and RFC 9380

Used in:
- `pkg/bls/bls.go:50` -- BLS `Sign()` (message hashing)
- `pkg/beacon/gjkr/protocol_parameters.go:24` -- Pedersen generator derivation from beacon seed

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

### 3.2 P2P Share Encryption (OK for mechanism; REVIEW for KDF)

**Location:** `pkg/crypto/ephemeral/symmetric_key.go:19`

Each pair of DKG participants derives a shared symmetric key:
```go
sha256.Sum256(btcec.GenerateSharedSecret(privKey, pubKey))
```

This is ECDH on secp256k1 with SHA256 as a KDF.

**Issue:** `sha256.Sum256(shared_secret)` is not a proper KDF:
- No domain separation (same ECDH output → same key across different sessions)
- No input keying material (IKM) or info field
- HKDF-SHA256 (RFC 5869) should be used instead

### 3.3 Private Key Share Storage (ISSUE)

**Location:** `pkg/tecdsa/marshaling.go:24`

tECDSA private key shares are serialized to protobuf and stored in the work directory without additional encryption:

```proto
message PrivateKeyShare {
  bytes paillier_secret_key_n = 1;     // Paillier N
  bytes paillier_secret_key_lambda = 2; // λ(N)
  bytes paillier_secret_key_phi = 3;    // φ(N)
  bytes xi = 4;                         // ECDSA share scalar
  // ... Paillier public keys of all parties
}
```

The Ethereum keystore (operator identity key) is password-encrypted, but tECDSA key shares are not. Filesystem read access to the work directory exposes the Paillier private key and the xi share, which together allow an attacker contributing that one share to the threshold computation.

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

This uses the try-and-increment hash-to-curve (same issue as §1.1). For Pedersen commitments, H must be a generator of unknown discrete log relative to G. Deriving H from a beacon entry is acceptable IF the DLP is hard -- but the derivation method being non-constant-time is a side-channel concern.

### 4.2 Symmetric Encryption (REVIEW)

**Location:** `pkg/beacon/gjkr/member.go` (calls `pkg/crypto/ephemeral/`)

Same ECDH + SHA256 KDF issue as §3.2.  
The actual encryption uses `encryption.NewBox()` from `github.com/keep-network/keep-common`. This is an external dependency whose implementation was not located in this repository. The encryption scheme (whether AES-GCM, ChaCha20-Poly1305, or other) should be independently confirmed.

---

## 5. Ephemeral Key Pairs

**Location:** `pkg/crypto/ephemeral/private_key.go`  
**Library:** `github.com/btcsuite/btcd/btcec` (secp256k1)

Key generation: `btcec.NewPrivateKey()` → `crypto/rand.Reader` (correct).

ECDH: `btcec.GenerateSharedSecret(privKey, pubKey)` returns compressed X coordinate of shared point. Then hashed with SHA256 (KDF issue noted in §3.2).

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
| SHA256 | Hash-to-curve, ECDH KDF, commitment derivation | OK (though KDF usage is substandard) |
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

