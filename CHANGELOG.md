# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/). From `1.0.0` onward the public API surface is
locked by `Microsoft.CodeAnalysis.PublicApiAnalyzers` baselines and `<EnablePackageValidation>`,
and the `.pqfe` v2 container format is frozen for the entire `1.x` line.

## [Unreleased]

## [1.1.0] - 2026-06-10

Two new packages join the family — the `pqfe` dotnet tool and the dependency-injection
extensions — plus live Rust↔.NET interop CI and a round of key-material-hygiene and
correctness fixes from external review. No format change: `.pqfe` v2 stays frozen.

### Added

- **`pqfe` ships as an installable dotnet tool** — `samples/Pqfe.Cli` is now packed as
  `PostQuantum.FileEncryption.Tool` (`dotnet tool install -g PostQuantum.FileEncryption.Tool`)
  and published by the release workflow with the same SBOM/provenance/validation pipeline
  as the library packages. The project now builds under the repository's strict analysis.
- **Live cross-implementation interop CI** (`ci.yml` → `interop`) — fresh random payloads
  are encrypted by .NET and decrypted by the Rust core (and vice versa) on every push,
  across chunk-boundary sizes, including an Argon2id container and wrong-passphrase
  fail-closed agreement. Adds the native `pqfe_io` example driver to `samples/pqfe-wasm`.
- **Hybrid benchmarks** — `HybridThroughputBenchmarks` (single and 10-recipient
  encrypt/decrypt, key-pair generation) joins the BenchmarkDotNet suite.
- **`PostQuantum.FileEncryption.Extensions.DependencyInjection`** — new NuGet package with
  `AddPqFileEncryption()` / `AddPqHybridFileEncryption()` extension methods registering the
  encryptor/decryptor types as singletons in `Microsoft.Extensions.DependencyInjection`
  hosts. Versioned in lockstep with the core and Hybrid packages; published by the release
  workflow after Hybrid is indexed.
- **Docs:** [docs/HYBRID-COMBINER.md](docs/HYBRID-COMBINER.md) (combiner design rationale
  vs. X-Wing / HPKE / RFC 9794), [docs/GOLD-STANDARD.md](docs/GOLD-STANDARD.md) (public
  self-assessment incl. open gaps), [docs/BENCHMARKS.md](docs/BENCHMARKS.md) (methodology
  and fair-comparison guidance).

### Fixed

- **Key-material hygiene (defense in depth; no exploit, no format or behavior change):**
  the encrypt orchestration now zeroes the content key in a `finally` even when header
  construction throws before the codec (which has always zeroed it) is entered, and the
  hybrid unwrap path zeroes its temporary `byte[]` copies of the ML-KEM and X25519 private
  keys after their last use. BouncyCastle's own internal key copies cannot be zeroized —
  documented in [KNOWN-GAPS.md](KNOWN-GAPS.md).
- **The hybrid multi-recipient limit is enforced as 55, not 255.** Each recipient entry is
  1186 bytes and the whole block must fit the container header's `uint16` key-parameters
  length, so 56+ recipients always failed — but only *after* all the ML-KEM/X25519 wrapping
  work, with a confusing header error. The encryptor now rejects oversized recipient lists
  up front with a clear message, and the cap is documented in
  [docs/FILE-FORMAT.md](docs/FILE-FORMAT.md). (Clarification of an existing format-implied
  limit; no container that could be produced before is affected.)
- **Hybrid encryption zeroes the content key on pre-engine failure paths** — `PqHybridEncryptor`
  now wraps key wrapping and header creation in a `finally` that zeroes the CEK, matching the
  hardening already applied to the core orchestration.
- **Decryption progress now reports the exact plaintext total.** `PqProgress.TotalBytes` was
  fed the ciphertext/container length during decryption, so `Fraction` could never reach 1.0.
  The plaintext total is now derived exactly from the container length (the chunked frame
  layout is deterministic), so decrypt progress is plaintext-vs-plaintext and completes at 1.0.
- **`LocalKekContentKeyProvider.Generate()` zeroes its intermediate KEK copy**, so disposing
  the provider removes every KEK copy the type created.

## [1.0.1] - 2026-06-06

Re-release of `1.0.0` packaged end-to-end by the standard release workflow so the `.nupkg`
bytes published to nuget.org match the SLSA-style build-provenance attestation and verify
cleanly against a clean-room Linux rebuild via `.github/workflows/reproducibility.yml`.

**No library code change since `1.0.0`.** The library, the `.pqfe` v2 format, the public
API surface, and the runtime dependencies are identical.

### Context

`1.0.0` was published via hand-recovery from this maintainer's Windows machine during the
`NUGET_API_KEY` rotation. The release workflow eventually ran successfully, but its publish
steps hit `--skip-duplicate` against the already-uploaded hand-packed bytes. The downstream
effect:

- The `.nupkg` on nuget.org for `1.0.0` was packed on Windows (CRLF line endings in packed
  text files such as `LICENSE`; downstream effects on the Hybrid `.dll` bytes via Roslyn's
  embedded source-file SHA hashes).
- The build-provenance attestation generated by the workflow applies to the workflow's
  *Linux* build of `1.0.0` — which is what was uploaded to the GitHub Release page — not to
  the bytes a user installs from nuget.org.
- The reproducibility workflow ran on the published `1.0.0` bytes and reported a mismatch,
  as designed.

`1.0.1` closes that loop end-to-end: the workflow packs, attests, publishes, and the
reproducibility check then verifies the published bytes byte-for-byte against a clean Linux
rebuild. Users already on `1.0.0` may continue to use it — the code is identical — but new
consumers should pin `1.0.1` so that `gh attestation verify` and the reproducibility check
both succeed against the bytes they install.

### Added

- `.gitattributes` — forces LF line endings repo-wide via `* text=auto eol=lf`, plus a
  short binary allowlist. Without this, Windows checkouts with the default
  `core.autocrlf=true` produced CRLF text files locally, which changed Roslyn's embedded
  source-file SHA in the PDB and propagated into the `.dll` bytes — the silent root cause
  of the `1.0.0` mismatch.

### Changed

- `.github/scripts/verify-reproducibility.sh` — `diff -r` now excludes `*.psmdcp` (NuGet's
  per-pack core-properties file carries a fresh GUID in its name and is never reproducible
  by NuGet's design; including it in the diff was a script bug).
- `docs/REPRODUCIBLE-BUILDS.md` — new section on the cross-OS caveat: Roslyn embeds source
  hashes in PDBs, so different line endings produce different `.dll` bytes even with
  `Deterministic=true`. With `.gitattributes` now normalising line endings on every
  checkout, the cross-OS gap is closed from `1.0.1` forward.
- `Directory.Build.props`: `PackageValidationBaselineVersion` bumped from `1.0.0-rc.3` to
  `1.0.0` so `1.0.1`'s public surface is validated against the published `1.0.0` baseline.

### Notes

- `1.0.0` remains on nuget.org. Its API surface and runtime behaviour are identical to
  `1.0.1`; only the packaging story differs. This entry is the public record of why.

## [1.0.0] - 2026-06-05

The first stable release of PostQuantum.FileEncryption. The `.pqfe` v2 container format is
FROZEN for the `1.x` line. The public API surface is locked.

**No library code change since `1.0.0-rc.3`.** The library, the `.pqfe` v2 format, the public
API surface, and the runtime dependencies are identical to rc.3. This release adds
documentation and supply-chain polish on top of that code and drops the pre-release suffix.

### Added
- `docs/REPRODUCIBLE-BUILDS.md`, `.github/scripts/verify-reproducibility.sh`, and
  `.github/workflows/reproducibility.yml` — third-party-verifiable recipe to rebuild a
  tagged release bit-identically and diff against the published `.nupkg`. The workflow
  runs automatically after every successful Release run (matrixed over both packages) and
  on demand against any historical tag.
- `.github/workflows/benchmarks.yml` — on-demand and weekly BenchmarkDotNet throughput
  runs (encrypt + decrypt over 16 MiB with PBKDF2 and Argon2id). Results uploaded as a
  workflow artifact and posted to the run summary.
- `docs/ANNOUNCE.md` — draft "Why we built this" announcement post.
- `docs/DISCOVERABILITY.md` — pre-flight checklist + awesome-list submission template +
  aggregator etiquette.

### Changed
- `SUPPORT.md` — full rewrite for the `1.x` lifecycle: supported-versions table, LTS intent
  (security fixes on the latest `1.x` minor; at least 12 months of continued support after
  a hypothetical `2.0`), deprecation policy (`PQFE002`), runtime support matrix.
- `docs/THREAT-MODEL.md` — residual risks refreshed (the "format not frozen" and
  "ML-KEM-768 used alone" entries are now obsolete and removed); audit-focus list extended
  to cover the X25519 + ML-KEM-768 combiner, the multi-recipient envelope, and the legacy
  KEM-DEM mode.
- `docs/VERSIONING.md` — dropped pre-1.0 phrasing; describes the `1.x` policy as enforced
  at build time by PublicApiAnalyzers baselines and `<EnablePackageValidation>`.
- `ROADMAP.md` — collapsed the rc.3 / 1.0.0 narrative into a single "Now — `1.0.0`"
  section; reproducible-build verification added to the supply-chain bullets.
- `README.md` — status banner promoted from "1.0.0-rc.3 — final polish" to "1.0.0 — stable
  release"; documentation table picks up `docs/REPRODUCIBLE-BUILDS.md`.
- `docs/SUPPLY-CHAIN.md` — new section pointing at the reproducible-build script and the
  verification workflow.
- `Directory.Build.props`: `PackageValidationBaselineVersion` bumped from `1.0.0-rc.2` to
  `1.0.0-rc.3` so `1.0.0`'s public surface is validated against the published rc.3 baseline.

### Notes
- The published `1.0.0-rc.3` nupkgs remain on nuget.org as the immediate predecessor.
- Reproducible-build verification runs for the first time on this release.

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

[Unreleased]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.0.0-rc.3...v1.0.0
[1.0.0-rc.3]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.0.0-rc.2...v1.0.0-rc.3
[1.0.0-rc.2]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.0.0-rc.1...v1.0.0-rc.2
[1.0.0-rc.1]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v0.2.0...v1.0.0-rc.1
[0.2.0]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/systemslibrarian/postquantum-file-encryption/releases/tag/v0.1.0
