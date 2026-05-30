# Roadmap: container format v3 (design)

This is a **design**, not shipped code. It specifies the two recipient-mode features planned
beyond v0.2 — a **classical + post-quantum hybrid combiner** and **multiple recipients** — so
they can be implemented against a concrete target once the open decisions below are made. They
are deliberately deferred because (a) ML-KEM recipient mode is not runtime-testable in every
environment, and (b) the combiner needs an X25519 implementation that .NET does not provide
in-box (confirmed: there is no built-in X25519/Curve25519 type in .NET 10).

Until then, v0.2's single-recipient ML-KEM-768 mode (`KeySource = 2`) remains the recipient
option, and passphrases remain dependency-light (PBKDF2 in-box; Argon2id via Konscious).

## 1. Hybrid combiner (`KeySource = 3`)

Belt-and-suspenders: combine ML-KEM-768 with X25519 ECDH so the content key stays protected if
*either* primitive is later broken (a future ML-KEM weakness, or a quantum break of X25519).

**Encrypt** (recipient holds an X25519 key pair and an ML-KEM key pair):

```
(kem_ct, ss_pq)        = ML-KEM-768.Encapsulate(recipient_mlkem_pub)
(eph_priv, eph_pub)    = X25519.GenerateKeyPair()
ss_classical           = X25519(eph_priv, recipient_x25519_pub)
KEK                    = HKDF-SHA256(ikm = ss_pq ‖ ss_classical,
                                     info = "PostQuantum.FileEncryption/v3 hybrid kek")
(wrapped, wrap_tag)    = AES-256-GCM(KEK, wrap_nonce, CEK, aad = "…/v3 cek-wrap")
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
oracle about which recipients are present). A short, non-secret key-id hint may be added later
to avoid trial-decapsulation, but trial order must not leak via timing.

## Open decision: where does X25519 come from?

.NET has no built-in X25519. Options, with the recommendation first:

1. **A separate `PostQuantum.FileEncryption.Hybrid` package** that depends on
   **BouncyCastle.Cryptography** (pure-managed, broad platform support) and provides the
   combiner. Keeps the core library dependency-light; consumers opt in. **Recommended.**
2. Add BouncyCastle directly to the core library. Simpler, but forces the dependency on everyone.
3. **NSec.Cryptography** (libsodium): fast and well-regarded, but a native dependency with
   platform/runtime constraints — at odds with the current "managed, in-box" posture.

No homegrown X25519 — the project rule (no novel cryptography) stands.

## Implementation & test plan

- Implement behind the existing `KeyEstablishment` seam; no change to the chunk/AEAD core.
- Gate on `MLKem.IsSupported` exactly like v0.2 recipient mode; round-trip tests **self-skip**
  where ML-KEM is unavailable (as the current recipient tests do).
- Generate **known-answer vectors** on an ML-KEM-capable host and add them to
  [TEST-VECTORS.md](TEST-VECTORS.md) and both test suites.
- The Rust/WASM browser core would gain the combiner only if a maintained X25519 + ML-KEM crate
  set is used; otherwise it stays passphrase-only (already documented).
- Bump `FormatVersion` to 3; v3 readers continue to accept v2 containers, or a clean break is
  taken while still in preview (decided at implementation time).

## Also planned (smaller)

- Freeze the format and the vectors for 1.0; publish them as a stable spec.
- A synchronous `ReadOnlySpan<char>` passphrase entry point for callers that never touch async.

---

*To God be the glory — 1 Corinthians 10:31.*
