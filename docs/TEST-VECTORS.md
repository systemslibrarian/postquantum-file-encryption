# Known-Answer Test Vectors — `.pqfe` v2

These fixed vectors pin the on-disk format. Any independent implementation that decrypts them
to the stated plaintext is reading the container correctly; any change to the format or
cryptography that breaks them is a **deliberate, breaking change** (bump `FormatVersion` and
regenerate).

They are exercised by:

- **.NET** — `tests/.../KnownAnswerVectorTests.cs` and `CrossImplementationTests.cs`
- **Rust → WASM** — `samples/pqfe-wasm/tests/vectors.rs`

The two implementations validate each other: the Rust core decrypts the .NET-produced vectors,
and the .NET library decrypts the Rust-produced vector. CI runs both suites on every change.

All containers are shown as **Base64**. See [FILE-FORMAT.md](FILE-FORMAT.md) for the byte layout.

---

## Vector 1 — passphrase, PBKDF2-HMAC-SHA256

| Field | Value |
| --- | --- |
| Key source | passphrase |
| KDF | PBKDF2-HMAC-SHA256 |
| Iterations | 100,000 |
| Salt length | 16 bytes |
| Chunk size | 1024 bytes |
| Passphrase (UTF-8) | `test-vector-passphrase` |
| Expected plaintext | `PostQuantum.FileEncryption known-answer vector v2.` |

```
UFFGRQIBAQAAAAQAJo6h8gAWARBX1MFqqxklHk56hMpD/FOOAAGGoAEAAAAyj/fP3REMAehh9VkK47SfhqQqgW68lRjDYDqIhW+b+6ytzaFAGCYaqA5JyaVkf24z17nYMoDST2h5xVdPtgEB23Fj
```

## Vector 2 — passphrase, Argon2id

| Field | Value |
| --- | --- |
| Key source | passphrase |
| KDF | Argon2id (version 0x13) |
| Memory | 8192 KiB (8 MiB) |
| Iterations (passes) | 1 |
| Parallelism (lanes) | 1 |
| Salt length | 16 bytes |
| Chunk size | 1024 bytes |
| Passphrase (UTF-8) | `test-vector-passphrase` |
| Expected plaintext | `PostQuantum.FileEncryption known-answer vector v2.` |

```
UFFGRQIBAQAAAAQAS7aXNQAbAhCZBPTffR0AgJ7we1bozxQOAAAgAAAAAAEBAQAAADJOzagbj5vUN9WHVWy1t7KN/pG9O5ab04z0IO4xyV5vRMxDN2TsXQGStrNyW5eC77skRpx0WhB0BC6SxsnfnwherIM=
```

> The Argon2id vector matters cross-implementation: the .NET library (Konscious) and the Rust
> core (RustCrypto `argon2`) must produce **identical** Argon2id output for the same parameters
> — and they do.

## Vector 3 — produced by the Rust/WASM core, read by .NET

| Field | Value |
| --- | --- |
| Produced by | `samples/pqfe-wasm` (browser core) |
| Key source | passphrase |
| KDF | PBKDF2-HMAC-SHA256 |
| Iterations | 600,000 |
| Chunk size | 65536 bytes |
| Passphrase (UTF-8) | `cross-impl-passphrase` |
| Expected plaintext | `Encrypted by the Rust/WASM core, decrypted by .NET.` |

```
UFFGRQIBAQAAAQAAikYbOgAWARDAQkJamtz3O4G2K80C5ZtbAAknwAEAAAAzWyXs57NvJnc4YxIUzCNJW+xE9IyXeQ4Tt5MFvTwMC27G/Dry6A/4bdieeZmpXSTcNsrumLpyzzeTILIOh5eGh+nR9g==
```

---

## Vector 4 — detached signature (`.sig` sidecar v1, verify-only)

Pins the [SIGNATURE-FORMAT.md](SIGNATURE-FORMAT.md) sidecar: layout, domain-separation
context, and SHA-512 pre-hash. ML-DSA signing is **hedged** (randomized per FIPS 204), so the
vector is verify-only — implementations must verify it, not reproduce it byte-for-byte.
Exercised by `tests/.../SigningKnownAnswerVectorTests.cs`.

| Field | Value |
| --- | --- |
| Algorithm | Ed25519 + ML-DSA-65 hybrid (AlgorithmId 1) |
| Signed message (UTF-8) | `PostQuantum.FileEncryption.Signing known-answer vector v1.` |
| Public key | `Ed25519-pk(32) ‖ ML-DSA-65-pk(1952)`, Base64 below |
| Signature | 3,379-byte sidecar, Base64 below |

Public key:

```
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
```

Signature:

```
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
```

---

## How to verify

```bash
# .NET
dotnet test --filter "FullyQualifiedName~KnownAnswerVector|FullyQualifiedName~CrossImplementation"

# Rust
cd samples/pqfe-wasm && cargo test
```

## Negative vectors

Implementations must also **reject** corrupted input. Both suites confirm that each vector
fails closed (a `PqDecryptionException` / `PqError::Decryption`) when:

- the passphrase is wrong,
- any byte of the header, ciphertext, or tag is flipped,
- the container is truncated (any proper prefix), or
- the input is not a container at all (rejected as a format error).

---

*To God be the glory — 1 Corinthians 10:31.*
