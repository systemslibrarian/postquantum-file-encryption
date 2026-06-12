# CLAUDE.md — Conventions for PostQuantum.FileEncryption

Guidance for Claude (and humans) working in this repository. Read this before making
changes.

## What this project is

A high-level, **delightful**, fail-closed wrapper for post-quantum file and stream
encryption on .NET. The public surface is small on purpose: `PqFileEncryptor`,
`PqFileDecryptor`, `PqEncryptionOptions`, `PqProgress`, the key types (`PqKeyPair`,
`PqRecipientPublicKey`, `PqRecipientPrivateKey`), the `PqKdf` enum, and the exception types.
Everything cryptographic lives behind that surface in `Internal/`.

It supports passphrase encryption (PBKDF2 or Argon2id) and ML-KEM-768 recipient (public-key)
encryption. The long-term intent is to wrap **PostQuantum.FileFormat**; until that dependency
exists, the engine is self-contained behind the `IPqContainerCodec` seam. See
[KNOWN-GAPS.md](KNOWN-GAPS.md).

## Non-negotiable principles

1. **No homegrown cryptography.** Use only `System.Security.Cryptography`. If a change seems
   to require inventing a primitive or a construction, stop and reconsider.
2. **Authenticated encryption only.** Never add an unauthenticated path.
3. **Fail closed.** On any doubt about authenticity, throw `PqDecryptionException` and emit
   no plaintext. No partial-success paths, no error oracles — every auth failure looks the
   same to the caller.
4. **Transparency over reassurance.** If you add a limitation, document it in
   [KNOWN-GAPS.md](KNOWN-GAPS.md). If you change the on-disk layout, update
   [docs/FILE-FORMAT.md](docs/FILE-FORMAT.md) in the same change.
5. **Strong defaults, optional tuning.** A caller who supplies no options must get a secure
   result.

## Code conventions

- **Targets:** `net8.0` and `net10.0` (multi-targeted). `Nullable` and `ImplicitUsings` are on.
  The public API surface must stay identical across both targets; net10-only platform crypto
  (e.g. `System.Security.Cryptography.MLKem`) is gated with `#if NET10_0_OR_GREATER` and the
  net8.0 path fails closed with `PlatformNotSupportedException` / `IsSupported == false`.
- **Warnings are errors.** `TreatWarningsAsErrors` and `latest-recommended` analysis are set
  in `Directory.Build.props`. Fix the cause; suppress only with a written justification.
- **Public API is fully XML-documented**, including remarks on security-relevant behavior.
- **Async + cancellation everywhere** for I/O; honor the `CancellationToken`.
- **Zero key material** with `CryptographicOperations.ZeroMemory` in a `finally`.
- Keep the public surface minimal. New knobs go on `PqEncryptionOptions`, not as new method
  overloads, unless there is a clear ergonomic win.

## Layout

```
Directory.Build.props                 — shared build settings (deterministic, analysis, authorship)
src/PostQuantum.FileEncryption/       — the library
  PqFileEncryptor.cs / PqFileDecryptor.cs   — public API (passphrase + recipient overloads)
  PqEncryptionOptions.cs / PqProgress.cs / PqKdf.cs  — configuration, progress, KDF choice
  PqKeyPair.cs                                — ML-KEM recipient key types
  PqEncryptionException.cs                    — exception hierarchy
  Internal/ContainerFormat.cs                 — v2 header constants + (de)serialization
  Internal/KeyEstablishment.cs                — PBKDF2 / Argon2id / ML-KEM KEM-DEM
  Internal/PqContainerEngine.cs               — the chunked AEAD core
  Internal/IPqContainerCodec.cs               — delegation seam (self-contained impl today)
  Internal/PqContainer.cs                     — orchestration (establish key → header → codec)
  Internal/FileIo.cs                          — atomic temp-file write helper
tests/PostQuantum.FileEncryption.Tests/  — round-trip, KDF, recipient, known-answer, fuzz tests
docs/FILE-FORMAT.md                       — the container specification (v2)
```

When you change key establishment, keep the three KDF/KEM paths consistent: encrypt-side
serialization, decrypt-side parsing (with range checks), and a known-answer vector.

## Build, test, pack

```bash
dotnet build -c Release
dotnet test  -c Release
dotnet pack  src/PostQuantum.FileEncryption -c Release
```

## When you touch crypto or the format

- Update [docs/FILE-FORMAT.md](docs/FILE-FORMAT.md) and bump `FormatVersion` if the layout
  changes.
- Add or extend a fail-closed test (tamper, truncate, wrong passphrase, bad format) — these
  are as important as the round-trip tests.
- Re-read [SECURITY.md](SECURITY.md) and keep its "does NOT defend against" list accurate.

*To God be the glory — 1 Corinthians 10:31.*
