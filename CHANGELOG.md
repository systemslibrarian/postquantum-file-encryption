# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/) — note that `0.x` releases are pre-1.0, so the API
and the on-disk format may change before `1.0`.

## [Unreleased]

## [1.0.0-rc.3] - 2026-06-04

Final polish pass before `1.0.0`. Tracks `PostQuantum.FileEncryption.Hybrid` 1.0.0-rc.3 in
lockstep. The `.pqfe` container format (v2) remains FROZEN. Source- and binary-compatible
with `1.0.0-rc.2`.

### Added
- `docs/MIGRATION.md` — from-other-libraries guide covering age/rage, libsodium
  `secretstream`, OpenSSL `enc`, .NET `AesGcm`, .NET `ProtectedData` (DPAPI), BouncyCastle
  CMS/OpenPGP, and Microsoft Data Protection. Includes a cross-cutting pre-flight
  checklist for production migration.
- `docs/SUPPLY-CHAIN.md` — one-page verification recipe (build-provenance attestation
  verify, CycloneDX SBOM inspection, conformance vector round-trip, deterministic-build
  spot check). Linked prominently from the README.
- `tests/.../NoOracleTests.cs` — explicitly pins the no-decryption-oracle property: wrong
  passphrase, flipped ciphertext, flipped tag, and flipped header bytes must all surface
  as `PqDecryptionException` with the same message. Prevents a future "helpful" error
  message regression from turning the library into an oracle.

### Changed
- `README.md` — restructured for production-grade positioning: new "Why this library" and
  "When to use this" sections, supply-chain visibility surfaced inline with concrete
  verification commands, public-key path explained around the Hybrid package only,
  deprecated inline ML-KEM mode no longer shown as a usage example.
- `ROADMAP.md` — refreshed to reflect 1.0 reality. The pre-`1.0` `v0.4` / "Toward `1.0`"
  sections (cloud KMS scoping, package validation, format freeze) have been replaced with
  a "Now → 1.0.0 → 1.x → 2.0" structure that matches what has already shipped.
- `SECURITY.md` — supported-versions table refreshed (`1.0.x` ✅, `0.x` ❌); language
  updated to reflect the frozen `.pqfe` v2 format; deprecated inline ML-KEM mode framed
  as deprecated rather than experimental; supply-chain artifacts (SBOM, attestation)
  noted explicitly.
- `KNOWN-GAPS.md` — removed stale entries (format-not-frozen, package-validation-not-yet-
  enabled) that were already resolved; release-scope section updated to reflect Hybrid
  shipping and the inline mode being deprecated rather than experimental.
- Package metadata (`PostQuantum.FileEncryption` and `PostQuantum.FileEncryption.Hybrid`):
  Description and PackageTags tightened for clarity and search; ReleaseNotes refreshed
  with the new doc artifacts.
- `Directory.Build.props`: `PackageValidationBaselineVersion` bumped from `1.0.0-rc.1` to
  `1.0.0-rc.2` so rc.3's public surface is validated against the published rc.2 baseline.

### Notes
- No format change. No public-API change. No runtime-dependency change. The published
  1.0.0-rc.2 nupkgs are immutable on nuget.org; rc.3 supersedes them as the final
  candidate before `1.0.0`.

## [1.0.0-rc.2] - 2026-06-01

Tracks `PostQuantum.FileEncryption.Hybrid` 1.0.0-rc.2 in lockstep. The `.pqfe` container
format (v2) remains FROZEN. Source-compatible with 1.0.0-rc.1.

### Deprecated
- **Inline ML-KEM-768-only recipient mode is deprecated** (`PQFE002`). `PqKeyPair`,
  `PqRecipientPublicKey`, `PqRecipientPrivateKey`, `PqKemAlgorithm`, and the recipient
  overloads on `PqFileEncryptor`/`PqFileDecryptor` are now marked `[Obsolete]` (warning,
  not error). Existing callers still build with a deprecation warning. **Migration:** use
  the `PostQuantum.FileEncryption.Hybrid` package (`PqHybridKeyPair`, `PqHybridEncryptor`,
  `PqHybridDecryptor`) — X25519 + ML-KEM-768 hybrid combiner with multi-recipient support
  and no platform ML-KEM gate. Removal of the inline mode is targeted for a future major
  release.

### Added
- I/O failure-mode test coverage pinning the file-API atomic-write contract: disk-full
  mid-write, mid-write cancellation, unwritable-destination, and an explicit
  `Truncation_at_specific_offsets_is_rejected` theory covering header truncation,
  mid-chunk truncation, and final-tag truncation.
- `Round_trip_at_maximum_chunk_size` (16 MiB) exercising
  `PqEncryptionOptions.MaxChunkSizeBytes`, gated as `[Trait("Category", "LongRunning")]`.
  CI's default per-push lane filters `Category!=LongRunning`; an extra Linux-only step
  runs `Category=LongRunning` so the coverage lands without slowing every push.
- `KNOWN-GAPS.md` entry documenting the best-effort temp-file cleanup behaviour
  (destination integrity is preserved either way; only the temp file may linger under
  pathological OS conditions).
- Hybrid package: README rewritten to present this package as the single recommended
  public-key path, with a side-by-side migration snippet from the deprecated inline mode.
  Suite-versioning lockstep note added to `docs/VERSIONING.md`.
- Release workflow hardened: `release.yml` now publishes the core to NuGet first, polls
  the v3-flatcontainer index until the new core version is queryable, then publishes
  Hybrid. Eliminates the indexing-race window where a consumer who installs Hybrid
  immediately after tag-push could get an "unable to resolve PostQuantum.FileEncryption"
  error even though both packages have been pushed.

### Changed
- `Directory.Build.props`: `PackageValidationBaselineVersion` bumped from `0.2.0` to
  `1.0.0-rc.1` so rc.2's public surface is validated against the published rc.1 baseline.

### Notes
- No format change. No public-API change. No runtime-dependency change. The published
  1.0.0-rc.1 nupkgs are immutable on nuget.org; rc.2 supersedes them.

## [1.0.0-rc.1] - 2026-05-31

The **on-disk `.pqfe` container format is now FROZEN at v2** for the `1.x` line. Every byte
is pinned by published conformance vectors; an incompatible change requires `2.0`.

### Added
- **Format conformance spec** — `docs/CONFORMANCE.md` documents what an implementer must
  produce to be byte-compatible with `.pqfe` v2, alongside the existing `docs/FILE-FORMAT.md`
  and `docs/TEST-VECTORS.md`. The Rust → WASM implementation (`samples/pqfe-wasm`) serves as
  the second-implementation conformance witness.
- **Synchronous `ReadOnlySpan<char>` passphrase entry point** — `PqFileEncryptor.EncryptBytes`
  and `PqFileDecryptor.DecryptBytes` for callers that never want to go async. True sync code
  path; no `.GetAwaiter().GetResult()` deadlock risk.
- **`Microsoft.CodeAnalysis.PublicApiAnalyzers`** wired into both packages, with the full
  0.2.0 public surface plus the new 1.0 additions baselined in `PublicAPI.Shipped.txt`.
  Accidental breaking changes now fail the build.
- **`<EnablePackageValidation>` with `PackageValidationBaselineVersion=0.2.0`** in
  `Directory.Build.props`, so every pack compares against the published `0.2.0` surface.
  Intentional breaks are documented in `CompatibilitySuppressions.xml`.
- **Package icon** (`assets/icon.png`) packed into both NuGet packages — the
  `Meziantou.Framework.NuGetPackageValidation` icon-rule exclusion has been removed from
  `release.yml`, which now enforces strict icon-must-be-set.
- **Codecov upload** in `ci.yml` and the corresponding badge in the README.
- **`IProgress<PqProgress>?` on the envelope-key bytes APIs.** `PqFileEncryptor.EncryptBytesAsync`
  and `PqFileDecryptor.DecryptBytesAsync` taking an `IContentKeyProvider` now accept the same
  optional progress callback the passphrase overloads do.

### Changed
- The aspirational `PostQuantum.FileFormat` delegation is no longer in the roadmap. The
  self-contained codec is the permanent implementation; the internal `IPqContainerCodec`
  seam is retained as an internal abstraction but is no longer documented as "to be wired."

### Deprecated
- **Inline ML-KEM-768-only recipient mode is deprecated** (`PQFE002`). `PqKeyPair`,
  `PqRecipientPublicKey`, `PqRecipientPrivateKey`, `PqKemAlgorithm`, and the recipient
  overloads on `PqFileEncryptor`/`PqFileDecryptor` are now marked `[Obsolete]` (warning,
  not error). Source-compatible: existing callers still build with a deprecation warning.
  **Migration:** use the `PostQuantum.FileEncryption.Hybrid` package — `PqHybridKeyPair`,
  `PqHybridEncryptor`, `PqHybridDecryptor` — for the X25519 + ML-KEM-768 hybrid combiner
  with multi-recipient support. Removal of the inline mode is targeted for a future major
  release.

### Notes
- This is **source-compatible** with 0.2.0; existing callers continue to compile unchanged.
- Two binary-level signature changes vs. 0.2.0 are intentionally suppressed in
  `CompatibilitySuppressions.xml`: the `progress` parameter additions to the envelope-key
  `EncryptBytesAsync` / `DecryptBytesAsync` overloads. These are the last allowed binary
  breaks; everything from `1.0.0` onward is binary-stable.

## [0.2.0] - 2026-05-30

### Added
- **`PostQuantum.FileEncryption.Hybrid` companion package** — post-quantum hybrid public-key
  encryption: an **X25519 + ML-KEM-768 combiner** (`KeySource = 3`) and **multiple recipients**
  (`KeySource = 4`), with `PqHybridKeyPair` / `PqHybridEncryptor` / `PqHybridDecryptor`. Fully
  managed via BouncyCastle (both primitives) — no native ML-KEM requirement, runs anywhere.
  Round-trip, multi-recipient, fail-closed, and pinned decrypt-KAT tested.
- **Envelope key management** — `IContentKeyProvider` (the KMS/HSM seam) and a built-in,
  dependency-free `LocalKekContentKeyProvider` (AES-256-GCM key wrap, `KeySource = 5`). Any
  `PqFileEncryptor` / `PqFileDecryptor` file/stream/in-memory overload accepts a provider; the
  master key never enters the process beyond the provider's boundary. Cloud providers (AWS/Azure)
  implement the same interface in separate packages.
- **Continuous coverage-guided fuzzing** for both parsers (cargo-fuzz + SharpFuzz), scheduled
  nightly; OSS-Fuzz integration files.
- **`samples/Pqfe.Cli`** — minimal `pqfe encrypt | decrypt` command-line sample that exercises
  the public API and is published with `PublishAot=true` in CI as the AOT smoke test.
- **Discoverable options helpers** — `PqEncryptionOptions.Argon2id` static preset plus
  `WithArgon2id` / `WithPbkdf2` / `WithChunkSize` fluent methods on the immutable options.

### Changed
- CI matrix now covers Linux, Windows, and macOS; a separate job performs a native-AOT publish
  of the CLI sample and round-trips a real file on every push.
- Release pipeline runs `Meziantou.Framework.NuGetPackageValidation.Tool` against every
  `.nupkg` before `nuget push`, alongside the existing CycloneDX SBOM and SLSA-style
  provenance attestation.
- New OpenSSF Scorecard workflow (weekly + push to main + on demand) with SARIF upload to the
  Security tab and publication to the public Scorecard dashboard.
- `PostQuantum.FileEncryption.Hybrid` metadata brought to parity with the core package
  (`PackageRequireLicenseAcceptance`, packed `LICENSE`, `MinClientVersion`).

## [0.1.0] - 2026-05-30

First release. The **symmetric, passphrase-based engine is production-ready**.

### Added
- `PqFileEncryptor` / `PqFileDecryptor` with file, stream, and in-memory
  (`EncryptBytesAsync` / `DecryptBytesAsync`) APIs.
- AES-256-GCM authenticated encryption; chunked streaming with bounded memory, progress
  reporting (`IProgress<PqProgress>`), and cancellation.
- Passphrase key derivation via PBKDF2-HMAC-SHA256 (default) or Argon2id (`PqKdf`).
- Zeroable `ReadOnlyMemory<byte>` passphrase overloads.
- `DecryptAtomicAsync` — all-or-nothing stream decryption.
- Opt-in, non-sensitive telemetry via the `PostQuantum.FileEncryption` `EventSource`.
- **Experimental** ML-KEM-768 recipient (public-key) mode, platform-gated and marked
  `[Experimental("PQFE001")]`.
- A specified container format (`docs/FILE-FORMAT.md`), pinned by cross-checked and
  byte-exact known-answer vectors, plus an independent Rust → WebAssembly implementation and
  two demos.
- Benchmarks, property-based tests, and a mutation/truncation fuzz harness.
- Trim/AOT compatibility (`IsAotCompatible`); SourceLink and a symbols package.

### Security
- Fail-closed against wrong passphrase, tampering, chunk reordering, splicing, and truncation.
- Bounded work on untrusted headers (KDF cost parameters are range-checked).
- Derived keys, wrapped secrets, and private keys are zeroed after use.

[Unreleased]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.0.0-rc.3...HEAD
[1.0.0-rc.3]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.0.0-rc.2...v1.0.0-rc.3
[1.0.0-rc.2]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.0.0-rc.1...v1.0.0-rc.2
[1.0.0-rc.1]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v0.2.0...v1.0.0-rc.1
[0.2.0]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/systemslibrarian/postquantum-file-encryption/releases/tag/v0.1.0
