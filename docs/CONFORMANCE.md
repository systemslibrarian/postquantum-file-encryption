# PostQuantum.FileEncryption Conformance Specification — `.pqfe` v2

> **Audience:** anyone implementing a `.pqfe` reader, writer, or both. This document is
> the contract another implementation must meet to claim byte-compatibility with the
> reference .NET library and the reference Rust → WebAssembly implementation
> (`samples/pqfe-wasm/`).

`.pqfe` v2 is **frozen** for `1.x`. The wire layout, the algorithm choices, and the rejection
behavior described here will not change in any `1.x` release. New `KeySource` values may be
added additively in later `1.x` minors; existing readers MUST treat unknown `KeySource` values
as a format error and refuse the file.

The normative wire description is [FILE-FORMAT.md](FILE-FORMAT.md). This document supplements
it with the **conformance obligations** an implementer must satisfy and the
**test-vector checklist** that proves they did.

---

## 1. Producer obligations (writer)

A conforming writer:

1. Emits a `Magic` of exactly `0x50 0x51 0x46 0x45` (`"PQFE"`) at offset 0.
2. Emits `FormatVersion = 2`.
3. Uses one of the algorithm IDs defined in [FILE-FORMAT.md](FILE-FORMAT.md#header). At v2
   that is `AeadId = 1` (AES-256-GCM) only.
4. Generates `NoncePrefix` (4 bytes) and any salt material from a cryptographically secure
   random source. **MUST** never reuse a `NoncePrefix` across two files encrypted under the
   same key.
5. Chooses `ChunkSize` in the range `[1024, 16 * 1024 * 1024]` bytes. The same `ChunkSize`
   applies to every non-final frame in the file. The final frame may be shorter.
6. For each plaintext chunk *i* (0-indexed), constructs the 12-byte AEAD nonce as
   `NoncePrefix || BE_UInt64(i)`.
7. Computes the AAD per frame as defined in [FILE-FORMAT.md](FILE-FORMAT.md#frames) — it
   **MUST** bind the frame's ordinal index and a final-chunk marker. Tampering with either
   value MUST cause the frame to fail authentication.
8. Marks exactly one frame as the final frame. Producing a file with no final-marked frame
   is non-conforming.
9. Writes the `KeyParams` block exactly as specified for the chosen `KeySource`. The block's
   own length is captured in `KeyParamsLength` (uint16, big-endian).
10. Writes no trailing bytes after the final frame.

A writer MAY:
- Use any conforming `KeySource` that the platform supports.
- Choose Argon2id memory/iteration parameters within the published bounds; those parameters
  travel in the `KeyParams` block so decryption does not require them out-of-band.

---

## 2. Consumer obligations (reader)

A conforming reader:

1. Rejects any input whose first four bytes are not `PQFE` with a format error.
2. Rejects any input with `FormatVersion != 2`.
3. Rejects any `AeadId`, `KeySource`, or `Flags` value not defined in this spec at the time
   of the read.
4. Rejects `ChunkSize` outside `[1024, 16 * 1024 * 1024]` bytes.
5. Range-checks every cost parameter read from `KeyParams` (PBKDF2 iteration count, Argon2id
   memory/iterations/parallelism) against the published bounds and rejects out-of-range
   values **before** doing any KDF work. This prevents a hostile header from forcing
   unbounded memory or CPU.
6. Reconstructs each per-frame nonce as `NoncePrefix || BE_UInt64(i)` and verifies each
   frame's authentication tag. **A single failed tag MUST abort the operation**; partial
   plaintext MUST NOT be returned. (For stream APIs that have already emitted earlier
   authentic frames, the final-frame check still MUST fail closed; see
   [KNOWN-GAPS.md](../KNOWN-GAPS.md).)
7. Detects truncation: a container that ends without a final-marked frame MUST be rejected
   as a decryption error, not a format error. (The error type SHOULD be consistent across
   wrong-key / tampered / truncated outcomes, so the library does not become a decryption
   oracle.)
8. Detects splicing: frame *i* used in position *j ≠ i* MUST fail authentication because
   the ordinal is in the AAD.
9. Detects header tampering: any byte of the header is in the per-frame AAD; a single bit
   flip in the header MUST cause every frame to fail authentication.

A reader MAY:
- Refuse `FormatVersion = 1` containers. The reference implementation has done so since
  `0.2.0`.

---

## 3. Test-vector checklist

To claim conformance, an implementation MUST decrypt every vector listed in
[TEST-VECTORS.md](TEST-VECTORS.md) and recover the documented plaintext byte-for-byte. The
reference implementations are cross-checked: the .NET test suite includes
`CrossImplementationTests.cs` which decrypts a Rust-produced container, and the Rust suite
decrypts the .NET-produced known-answer vectors. Adding a third implementation requires
running both directions.

Coverage table:

| `KeySource` | Path                                  | Vector location                           |
| ----------- | ------------------------------------- | ----------------------------------------- |
| `1`         | Passphrase (PBKDF2-HMAC-SHA256)       | `tests/.../KnownAnswerVectorTests.cs`     |
| `1`         | Passphrase (Argon2id)                 | `tests/.../KnownAnswerVectorTests.cs`     |
| `2`         | ML-KEM-768 recipient (experimental)   | `tests/.../RecipientTests.cs` (platform-gated) |
| `3`         | X25519 + ML-KEM-768 hybrid combiner   | `tests/.../HybridTests.cs`                |
| `4`         | Multiple recipients                   | `tests/.../HybridTests.cs`                |
| `5`         | Envelope key provider (`LocalKekContentKeyProvider`) | `tests/.../KeyProviderTests.cs` |

Negative vectors (every implementation MUST reject these the same way):

- Wrong passphrase
- Wrong recipient private key
- Wrong content-key provider
- A single bit flip in the header
- A single bit flip in any frame's ciphertext or tag
- Truncation: drop the final frame entirely, drop the final N bytes of the final tag
- Splicing: swap frame *i* with frame *j*
- Out-of-range KDF parameters in the header (e.g. `Pbkdf2Iterations = 1`)
- Unknown `AeadId`, `KeySource`, or `FormatVersion`

---

## 4. Versioning beyond v2

The `FormatVersion` byte gives readers a discriminator. The library's policy:

- A change that breaks byte-compatibility for **existing** readers requires a new
  `FormatVersion` (`3`, `4`, …) and a new major library version (`2.0`, `3.0`, …).
- Adding a **new `KeySource`** with new `KeyParams` is non-breaking at the format level if
  existing readers continue to reject unknown `KeySource` values (which they MUST). It is
  shipped as a minor library version (`1.x`).
- Renaming or renumbering an existing `KeySource` is a breaking change.

---

*To God be the glory — 1 Corinthians 10:31.*
