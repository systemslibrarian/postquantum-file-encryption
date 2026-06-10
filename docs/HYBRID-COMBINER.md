# The Hybrid Combiner — Design Rationale

How `PostQuantum.FileEncryption.Hybrid` combines X25519 and ML-KEM-768, why it is built
the way it is, how it relates to X-Wing, HPKE, and the IETF's PQ/T hybrid terminology
(RFC 9794), and under what conditions an alternative construction would be adopted.

This document explains a construction that is **frozen** for the 1.x line; it changes
only if [docs/FILE-FORMAT.md](FILE-FORMAT.md) changes, which requires a new
`FormatVersion`. Audience: reviewers, auditors, and anyone deciding whether to trust the
scheme.

## The construction, exactly

Per recipient (`KeySource = 3`, or each block of `KeySource = 4`), encryption performs a
standard parallel KEM-DEM composition
(implementation: [`HybridKeyEstablishment.cs`](../src/PostQuantum.FileEncryption.Hybrid/Internal/HybridKeyEstablishment.cs)):

1. **Post-quantum component** — ML-KEM-768 (FIPS 203) encapsulation against the
   recipient's encapsulation key → 32-byte shared secret `ss_pq`, 1088-byte ciphertext.
2. **Traditional component** — a fresh ephemeral X25519 key pair (RFC 7748); ECDH against
   the recipient's static X25519 key → 32-byte shared secret `ss_classical`.
3. **Combiner** — fixed-order concatenation into HKDF-SHA256 (RFC 5869):

   ```
   KEK = HKDF-SHA256(IKM = ss_pq ‖ ss_classical,
                     salt = absent,
                     info = "PostQuantum.FileEncryption/v3 hybrid kek",
                     L    = 32)
   ```

4. **Key wrap** — the random 32-byte content key (CEK) is wrapped with AES-256-GCM under
   the KEK, with a random 96-bit nonce and the fixed AAD label
   `"PostQuantum.FileEncryption/v3 cek-wrap"`.

The `v3` in the labels is the `KeySource` discriminant, not the container version; the
container remains `.pqfe` v2.

The CEK then drives the ordinary chunked AES-256-GCM data plane, and — this matters
below — **every content chunk's AAD includes the complete serialized header**, which
contains every recipient block: the ML-KEM ciphertext, the ephemeral X25519 public key,
the wrap nonce, tag, and wrapped CEK
([`PqContainerEngine.BuildAad`](../src/PostQuantum.FileEncryption/Internal/PqContainerEngine.cs)).

## Why this shape

The project's first rule is **no novel cryptography**: only standard primitives, composed
in standard ways, taken from maintained implementations (ML-KEM and X25519 from
BouncyCastle; HKDF and AES-GCM from .NET). Concatenate-then-KDF is the oldest and most
analyzed hybrid combiner there is — it is the shape recommended by NIST SP 800-56C
(key-derivation from multiple shared secrets) and used, with variations, by everything
from TLS hybrid key exchange (`X25519MLKEM768`) to Signal's PQXDH.

Security goal: the KEK is secret as long as **either** component's shared secret is
secret. Both secrets enter the KDF as input keying material; recovering the KEK requires
breaking ML-KEM-768 *and* X25519. The fixed concatenation order and the domain-separating
`info` label are part of the specification and pinned by cross-implementation test
vectors ([docs/TEST-VECTORS.md](TEST-VECTORS.md)).

## Honest comparison with X-Wing

[X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) is the
best-known purpose-built X25519 + ML-KEM-768 hybrid KEM. Its combiner is:

```
ss = SHA3-256(ss_pq ‖ ss_classical ‖ ct_classical ‖ pk_classical ‖ label)
```

The notable difference: X-Wing feeds the **X25519 ciphertext (ephemeral public key) and
recipient public key into the combiner**, while omitting the ML-KEM ciphertext — safe
because ML-KEM's FO transform already binds its ciphertext into `ss_pq`. The generic
result behind this (Giacon–Heuer–Poettering, and the X-Wing paper) is that a plain
`KDF(ss1 ‖ ss2)` combiner does not, *in general*, inherit IND-CCA security, because a
component ciphertext might be malleable without changing its shared secret.

Where does that leave this scheme? Two layers answer it:

1. **At the KEM layer**, this is the generic concatenation combiner without transcript
   input — the theoretical gap above applies to the combiner *in isolation*.
2. **At the container layer, the gap is closed.** The entire header — every KEM
   ciphertext and every ephemeral X25519 key — is authenticated as AAD on **every
   content chunk**. Any manipulation of any recipient block changes the AAD and every
   chunk fails authentication before a byte of plaintext is released. The thing an
   IND-CCA gap would let an attacker do (craft a *different* container that decrypts
   under the same keys) is exactly what the data plane rejects.

So the binding X-Wing achieves inside its combiner, `.pqfe` achieves at the
container boundary — which is the boundary this library actually exposes. We state this
as a property of the **container**, not of the combiner: the combiner alone should not be
extracted and reused elsewhere as if it were X-Wing. That caveat is the honest price of
composing only pre-built primitives instead of hand-implementing a (then-draft) combiner
— consistent with the no-novel-crypto rule.

## Why not HPKE (RFC 9180)?

HPKE is the right answer when you need an interoperable public-key *message* encryption
API. It was not adopted here because:

- At design time there was no standardized PQ/hybrid KEM for HPKE (X-Wing and the
  `*MLKEM*` KEM registrations were drafts), and .NET has no HPKE implementation —
  adopting it would have meant hand-implementing HPKE's key schedule, against rule one.
- `.pqfe` needs **multi-recipient** wrapping of a single CEK over a *chunked, seekable,
  fail-closed file format* — HPKE single-shot mode doesn't provide that; building a
  multi-recipient chunked format *on top of* HPKE reintroduces all the same design
  decisions one layer up.

Conceptually, `KeySource = 3` is the same shape as HPKE Base mode with a hybrid KEM: KEM
→ KDF → AEAD. If a final, .NET-available hybrid-KEM HPKE materializes, it is a natural
candidate for a future format version (below).

## RFC 9794 terminology mapping

Using the IETF's PQ/T hybrid terminology
([RFC 9794](https://www.rfc-editor.org/rfc/rfc9794)):

| RFC 9794 term | In this scheme |
| --- | --- |
| PQ/T hybrid scheme | `KeySource = 3` / `4` key establishment |
| Post-quantum component algorithm | ML-KEM-768 (FIPS 203) |
| Traditional component algorithm | X25519 ECDH (RFC 7748) |
| Combiner | fixed-order concatenation + HKDF-SHA256 with domain-separating label |
| Composite structure | parallel (both components always run; no negotiation) |

There is no downgrade path: a `KeySource = 3` container *always* requires both
components. A hybrid private key holder cannot be tricked into a classical-only or
PQ-only decryption.

## When an alternative would be adopted

The v2 format is frozen; none of the following can change in 1.x. A future format
version ([docs/ROADMAP-v3.md](ROADMAP-v3.md)) would consider, in order of preference:

1. **X-Wing as published** — if/when it reaches RFC and ships in BouncyCastle or .NET as
   a tested primitive (not hand-implemented here).
2. **HPKE with a standardized hybrid KEM** — same condition: a maintained .NET
   implementation must exist.
3. **ML-KEM-1024 / new component algorithms** — the `KemId` byte and additive
   `KeySource` registry in the header exist precisely so new schemes are *new values*,
   which old readers reject fail-closed, rather than mutations of existing ones.

The bar for all three is the same: a finished standard plus a maintained implementation.
This library composes primitives; it does not implement them.

## What to review

For auditors and reviewers, the security-relevant surfaces are:

- [`HybridKeyEstablishment.cs`](../src/PostQuantum.FileEncryption.Hybrid/Internal/HybridKeyEstablishment.cs)
  — combiner, wrap/unwrap, multi-recipient parsing (range-checked, fail-closed).
- [`PqContainerEngine.cs`](../src/PostQuantum.FileEncryption/Internal/PqContainerEngine.cs)
  — header-as-AAD binding, chunk counters, frame types.
- [docs/FILE-FORMAT.md](FILE-FORMAT.md) — byte-exact layout for `KeySource = 3` and `4`.
- [docs/TEST-VECTORS.md](TEST-VECTORS.md) — known-answer vectors pinning the combiner,
  verified cross-implementation against the Rust/WASM reference.
- The fail-closed test suite: tamper, truncate, wrong-recipient, block-swap cases in
  [`tests/PostQuantum.FileEncryption.Tests`](../tests/PostQuantum.FileEncryption.Tests).

Multi-recipient note: ML-KEM decapsulation never visibly fails (implicit rejection
yields a pseudorandom secret), so trying a block that belongs to another recipient simply
derives the wrong KEK and the AES-GCM unwrap tag mismatches. "Not my block" and
"tampered block" are indistinguishable by design — there is no error oracle.

---

*To God be the glory — 1 Corinthians 10:31.*
