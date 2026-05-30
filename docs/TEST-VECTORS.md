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
