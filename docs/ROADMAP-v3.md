# Post-quantum public-key support (`PostQuantum.FileEncryption.Hybrid`)

> **Status: the hybrid combiner (`KeySource = 3`) and multiple recipients (`KeySource = 4`) are
> IMPLEMENTED and tested in the `PostQuantum.FileEncryption.Hybrid` package** (managed
> BouncyCastle for *both* X25519 and ML-KEM-768 — no native ML-KEM requirement). This document
> is now both the spec and the rationale. Remaining future work: KMS/HSM providers (see
> [KEY-MANAGEMENT.md](KEY-MANAGEMENT.md)).

This specifies the public-key upgrade path beyond the symmetric core.

## Where things stand, and the decision

**The stable core (`PostQuantum.FileEncryption`) is symmetric and passphrase-based:**
AES-256-GCM with PBKDF2-HMAC-SHA256 or Argon2id. That is the engine being finalized for
release.

The core also includes an **experimental, platform-gated ML-KEM-768 recipient mode**
(`KeySource = 2`), available only where the platform provides ML-KEM. It is not part of the
stable symmetric surface and may be superseded by the package below.

**Decision:** all post-quantum **public-key** features — the classical+PQ hybrid combiner and
multiple recipients — will ship in a **separate `PostQuantum.FileEncryption.Hybrid` package**,
using **BouncyCastle.Cryptography** for X25519. Rationale:

- .NET has **no built-in X25519** (confirmed on .NET 10), so the combiner needs a dependency.
- Keeping it in a separate package leaves the core **dependency-light** (PBKDF2 in-box;
  Argon2id via Konscious) and lets consumers who only need passphrase encryption avoid pulling
  in BouncyCastle.
- The project rule stands: **no homegrown cryptography** — X25519 comes from a vetted library.

```
PostQuantum.FileEncryption          (core, this repo)
  └─ symmetric passphrase AES-256-GCM        ← stable, released
  └─ experimental ML-KEM-768 recipient       ← platform-gated, may move to Hybrid

PostQuantum.FileEncryption.Hybrid   (future package, depends on BouncyCastle)
  └─ X25519 + ML-KEM-768 hybrid combiner     (KeySource = 3)
  └─ multiple recipients                     (KeySource = 4)
  └─ a stable home for public-key recipient encryption
```

The container format reserves `KeySource` values so the Hybrid package slots in behind the same
`.pqfe` format; the chunk/AEAD core is unchanged.

## 1. Hybrid combiner (`KeySource = 3`)

Combine ML-KEM-768 with X25519 ECDH so the content key stays protected if *either* primitive is
later broken (a future ML-KEM weakness, or a quantum break of X25519).

**Encrypt** (recipient holds an X25519 key pair and an ML-KEM key pair):

```
(kem_ct, ss_pq)     = ML-KEM-768.Encapsulate(recipient_mlkem_pub)
(eph_priv, eph_pub) = X25519.GenerateKeyPair()                       # BouncyCastle
ss_classical        = X25519(eph_priv, recipient_x25519_pub)
KEK                 = HKDF-SHA256(ikm = ss_pq ‖ ss_classical,
                                  info = "PostQuantum.FileEncryption/v3 hybrid kek")
(wrapped, wrap_tag) = AES-256-GCM(KEK, wrap_nonce, CEK, aad = "…/v3 cek-wrap")
```

**`KeyParams` (KeySource = 3):**

```
1   KemId (1 = ML-KEM-768)
2   KemCiphertextLength C (u16)
C   KemCiphertext
32  EphemeralX25519PublicKey
12  WrapNonce
16  WrapTag
32  WrappedKey
```

Decryption reverses it: decapsulate → `ss_pq`; `X25519(recipient_x25519_priv, eph_pub)` →
`ss_classical`; same HKDF; AES-GCM-unwrap. The concatenation order `ss_pq ‖ ss_classical` is
fixed and authenticated (the whole header is chunk AAD, as today).

## 2. Multiple recipients (`KeySource = 4`)

Wrap one random content key to **N** recipients, so any one of them can open the file.

**`KeyParams` (KeySource = 4):**

```
1        RecipientCount N (u8, ≥ 1)
N × {    per-recipient wrap block:
  1        Mode (2 = ML-KEM only, 3 = hybrid)
  2        BlockLength L (u16)
  L        block bytes — exactly the KeySource 2 or 3 KeyParams body above
}
```

Every block wraps the **same** CEK. The decryptor tries its private key against each block and
uses the first that authenticates; if none do, it fails closed with the usual generic error (no
oracle about which recipients are present). A short, non-secret key-id hint may be added later to
avoid trial-decapsulation, but trial order must not leak via timing.

## Package layout & dependencies

| Package | Adds | Dependencies |
| --- | --- | --- |
| `PostQuantum.FileEncryption` | symmetric passphrase engine (+ experimental ML-KEM recipient) | Konscious (Argon2id) |
| `PostQuantum.FileEncryption.Hybrid` | combiner, multi-recipient, hybrid key types | the core + **BouncyCastle.Cryptography** |

The Hybrid package implements only key establishment (X25519 + ML-KEM + HKDF + key-wrap) behind
the core's existing `KeyEstablishment` seam; it does not touch the chunk/AEAD core.

## Implementation & test plan

- Gate on `MLKem.IsSupported`, exactly like the core's experimental recipient mode; round-trip
  tests **self-skip** where ML-KEM is unavailable.
- Generate **known-answer vectors** on an ML-KEM-capable host and add them to
  [TEST-VECTORS.md](TEST-VECTORS.md) and the test suites.
- Bump `FormatVersion` to 3; v3 readers continue to accept v2 containers, or a clean break is
  taken while still in preview (decided at implementation time).
- The Rust/WASM browser core stays passphrase-only unless a maintained X25519 + ML-KEM crate set
  is adopted there.

## Also planned (smaller)

- Freeze the format and the vectors for 1.0; publish them as a stable spec.
- A synchronous `ReadOnlySpan<char>` passphrase entry point for callers that never touch async.

---

*To God be the glory — 1 Corinthians 10:31.*
