# Versioning, Compatibility & API Stability

## Semantic Versioning

The package follows [SemVer](https://semver.org). For the `1.x` line:

- The **on-disk `.pqfe` v2 format is FROZEN.** No `1.x` minor or patch may change the byte
  layout — that requires `2.0`.
- The **public API** is governed by `Microsoft.CodeAnalysis.PublicApiAnalyzers` baselines
  (`PublicAPI.Shipped.txt`) and `<EnablePackageValidation>` against the previous published
  version. Removing or changing a public member fails the build.
- **Additive** public API (a new type, a new overload, a new `PqEncryptionOptions` field) is a
  minor bump.
- **`[Obsolete]`** deprecations (e.g. `PQFE002`, the inline ML-KEM-only recipient mode) emit a
  warning and remain source-compatible until removal — and removal requires a major bump.
- Breaking changes are called out in [CHANGELOG.md](../CHANGELOG.md) and the release notes.

## On-disk format stability

- Every container starts with a 1-byte `FormatVersion` (currently `2`). A reader rejects versions
  it does not understand rather than guessing.
- **Any change to the byte layout bumps `FormatVersion`** and updates
  [FILE-FORMAT.md](FILE-FORMAT.md) and the [test vectors](TEST-VECTORS.md) in the same change.
- The format is pinned by byte-exact known-answer vectors checked by both the .NET and Rust
  implementations, so an accidental format change cannot pass CI.
- **`.pqfe` v2 is frozen for the entire `1.x` line.** A file produced by any `1.x` build opens
  in every other `1.x` build, on every supported platform, in either implementation.
- Adding a new `KeySource` (with new `KeyParams`) is non-breaking at the format level —
  existing readers MUST reject unknown `KeySource` values — and ships as a `1.x` minor. See
  [CONFORMANCE.md §4](CONFORMANCE.md).

## Migration policy

- Within `1.x`: no format migration is required, ever. The freeze is the migration policy.
- Across a major (`1.x → 2.0`): the `2.0` release will ship documented migration tooling
  (a `rewrap` / transcode path), and the preceding `1.x` minor continues to receive
  security fixes for at least 12 months after `2.0` is tagged — see [SUPPORT.md](../SUPPORT.md).
- Key rotation within `1.x` uses the same rewrap design — see [KEY-MANAGEMENT.md](KEY-MANAGEMENT.md).

## API stability discipline

Enforced at build time, not by convention:

- **`Microsoft.CodeAnalysis.PublicApiAnalyzers`** baselines every shipped public member in
  `PublicAPI.Shipped.txt` on both packages. A new or removed public member that is not declared
  in `PublicAPI.Unshipped.txt` fails the build.
- **`<EnablePackageValidation>`** is on with `PackageValidationBaselineVersion` set to the
  previous release, so every pack additionally proves binary compatibility against the last
  published `.nupkg`.
- New configuration generally goes on `PqEncryptionOptions` rather than new method overloads.

## Suite versioning — Hybrid lockstep with core

`PostQuantum.FileEncryption.Hybrid` is **always released at the same version as
`PostQuantum.FileEncryption`**. The two packages are one cryptographic unit:

- The **core** (`PostQuantum.FileEncryption`) owns the `.pqfe` container format, the
  chunk/AEAD engine, the symmetric/passphrase API, and the `KeyEstablishment` /
  `IPqContainerCodec` seams.
- The **Hybrid** package (`PostQuantum.FileEncryption.Hybrid`) plugs into those seams to add
  the X25519 + ML-KEM-768 combiner and multi-recipient support — it consumes the core's
  internals (`InternalsVisibleTo`) rather than reimplementing them.

A version skew between the two would mean Hybrid is talking to a different format or engine
than the one it was designed against — the exact class of subtle inconsistency this
discipline is meant to prevent. At pack time, Hybrid's `ProjectReference` resolves to a
same-version `PackageReference` on the core, so `dotnet add package
PostQuantum.FileEncryption.Hybrid --version X.Y.Z` always pulls in
`PostQuantum.FileEncryption X.Y.Z`.

This is enforced operationally by the release workflow
([`.github/workflows/release.yml`](../.github/workflows/release.yml)): a single `v*` tag
triggers a build that packs both packages, publishes the core first, **waits for it to be
indexed on nuget.org**, then publishes Hybrid — so a consumer can never see a Hybrid
version on the feed whose pinned core version is not yet resolvable.

The companion record for each release lives in
[`VERSION-RECONCILIATION.md`](../VERSION-RECONCILIATION.md).

## Platform support matrix

| Aspect | Requirement |
| --- | --- |
| Runtime | .NET 10 (`net10.0`) |
| OS | Windows, Linux, macOS (anywhere .NET 10 + AES-GCM run; AES-GCM is unavailable in browser WASM) |
| Argon2id | Any (managed) — but **not** FIPS-validated |
| ML-KEM recipient (experimental) | Requires platform ML-KEM (OpenSSL 3.5+ / Windows CNG); gated by `PqKeyPair.IsSupported` |
| Trimming / Native AOT | Compatible (`IsAotCompatible`) |

*To God be the glory — 1 Corinthians 10:31.*
