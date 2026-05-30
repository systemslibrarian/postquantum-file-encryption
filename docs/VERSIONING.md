# Versioning, Compatibility & API Stability

## Semantic Versioning, with `0.x` caveats

The package follows [SemVer](https://semver.org). While in `0.x` (pre-1.0):

- The **public API** and the **on-disk format** may change between minor versions.
- Breaking changes will be called out in [CHANGELOG.md](../CHANGELOG.md) and the release notes.
- `[Experimental("PQFE001")]` APIs (ML-KEM recipient mode) may change at any time, independent of
  the stability of the symmetric surface.

At `1.0` we commit to: a frozen container format, SemVer-disciplined API changes (no breaking
changes without a major bump), and the guarantees below.

## On-disk format stability

- Every container starts with a 1-byte `FormatVersion` (currently `2`). A reader rejects versions
  it does not understand rather than guessing.
- **Any change to the byte layout bumps `FormatVersion`** and updates
  [FILE-FORMAT.md](FILE-FORMAT.md) and the [test vectors](TEST-VECTORS.md) in the same change.
- The format is pinned by byte-exact known-answer vectors checked by both the .NET and Rust
  implementations, so an accidental format change cannot pass CI.
- **Before `1.0`, do not archive data you must read with a future major version.** At `1.0` the
  format is frozen and forward-readers will continue to accept it.

## Migration policy

- When the format changes pre-1.0, the new reader either (a) continues to accept the older
  version, or (b) ships a one-shot **rewrap/transcode** path (decrypt-then-re-encrypt) when a
  clean break is taken. The chosen approach is stated in the release notes.
- A documented rewrap path also covers key rotation — see [KEY-MANAGEMENT.md](KEY-MANAGEMENT.md).

## API stability discipline

Until a public API baseline can be tracked automatically (the
`Microsoft.CodeAnalysis.PublicApiAnalyzers` baseline, or `EnablePackageValidation` against a
published version), public-API changes are governed by review:

- Public API additions/changes must be described in the PR and recorded in `CHANGELOG.md`.
- Removing or changing a non-experimental public member is a **breaking change** and requires a
  minor bump pre-1.0 (major post-1.0) with a clear note.
- New configuration generally goes on `PqEncryptionOptions` rather than new method overloads.

## Platform support matrix

| Aspect | Requirement |
| --- | --- |
| Runtime | .NET 10 (`net10.0`) |
| OS | Windows, Linux, macOS (anywhere .NET 10 + AES-GCM run; AES-GCM is unavailable in browser WASM) |
| Argon2id | Any (managed) — but **not** FIPS-validated |
| ML-KEM recipient (experimental) | Requires platform ML-KEM (OpenSSL 3.5+ / Windows CNG); gated by `PqKeyPair.IsSupported` |
| Trimming / Native AOT | Compatible (`IsAotCompatible`) |

*To God be the glory — 1 Corinthians 10:31.*
