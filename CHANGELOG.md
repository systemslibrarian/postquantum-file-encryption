# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/) — note that `0.x` releases are pre-1.0, so the API
and the on-disk format may change before `1.0`.

## [Unreleased]

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

[Unreleased]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/systemslibrarian/postquantum-file-encryption/releases/tag/v0.1.0
