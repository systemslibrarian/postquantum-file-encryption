# Known Gaps

This document is the honest ledger for PostQuantum.FileEncryption. It records what is
incomplete, deferred, or imperfect, so that nobody has to discover it by reading the source
or, worse, in production. If you find a gap not listed here, that itself is a gap — please
open an issue.

Last reviewed against: **`1.0.0-rc.2`**. See [ROADMAP.md](ROADMAP.md) for the forward plan.

## Release scope (read this first)

- **The stable, released engine is symmetric and passphrase-based:** AES-256-GCM with
  PBKDF2-HMAC-SHA256 or Argon2id. AES-256 is quantum-resistant for the *confidentiality of the
  data itself*. This is what is finalized for release.
- **The post-quantum *public-key* (key-establishment) story is not finished in the core.** An
  ML-KEM-768 recipient mode is **included but experimental and platform-gated** (`PqKeyPair`,
  `PqKeyPair.IsSupported`). The productionized path — a hybrid **X25519 + ML-KEM** combiner and
  multiple recipients — is **planned for a separate `PostQuantum.FileEncryption.Hybrid`
  package** (BouncyCastle for X25519); see [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md).

## Resolved since the first symmetric cut

- **Memory-hard KDF** — Argon2id is selectable via `PqEncryptionOptions.Kdf`.
- **Zeroable passphrases** — `ReadOnlyMemory<byte>` passphrase overloads are available.
- **Test vectors and fuzzing** — pinned known-answer vectors and a mutation/truncation fuzz
  harness are in the test suite, cross-checked against the Rust/WASM implementation.

## Resolved in `0.3.0`

- **PublicAPI surface locked** — `Microsoft.CodeAnalysis.PublicApiAnalyzers` is wired into
  both packages with the full 0.2.0 surface baselined (`PublicAPI.Shipped.txt`). Any accidental
  breaking change to a public type, member, or signature now fails the build.
- **Package icon** packed into both packages; the icon-rule exclusion has been removed from
  `release.yml`, so the release pipeline enforces icon-must-be-set strictly.
- **Coverage published.** `ci.yml` uploads coverage to Codecov on the Ubuntu matrix leg and
  the README carries the badge.
- **Bytes-API progress parity.** The envelope-key `EncryptBytesAsync` / `DecryptBytesAsync`
  overloads now accept the same optional `IProgress<PqProgress>?` the passphrase overloads do.

## Resolved in `0.2.0`

- **CLI sample** — `samples/Pqfe.Cli` (`pqfe encrypt | decrypt`) makes the README copy-paste
  runnable and gives the AOT smoke test a real target.
- **Native-AOT smoke test in CI** — the CLI is `dotnet publish -p:PublishAot=true`-ed and
  round-trips a real file on every push, so any regression in the `IsAotCompatible` claim
  fails the build.
- **macOS in the CI matrix** — `ubuntu-latest`, `windows-latest`, *and* `macos-latest`.
- **Pre-publish NuGet validation** — `release.yml` now runs
  `Meziantou.Framework.NuGetPackageValidation.Tool` against every produced `.nupkg`
  (deterministic build, SourceLink wired, README/LICENSE packed, …) before `nuget push`.
- **OpenSSF Scorecard** — weekly + push-to-main + dispatch, with SARIF in the Security tab
  and publish to the public Scorecard dashboard.
- **Discoverable options helpers** — `PqEncryptionOptions.Argon2id` preset and
  `WithArgon2id` / `WithPbkdf2` / `WithChunkSize` fluent methods on the immutable options.

## Still open

### Cryptographic scope

- **The core's inline ML-KEM-only recipient mode is DEPRECATED as of `1.0.0-rc.2`.** It is
  marked `[Obsolete]` with diagnostic id `PQFE002` and retained for source-compatibility
  only — new code must use the **`PostQuantum.FileEncryption.Hybrid`** package (hybrid
  X25519 + ML-KEM-768 combiner with multi-recipient support, managed BouncyCastle for
  both primitives, runs anywhere). Removal of the inline mode is targeted for a future
  major release; until then it continues to honour the existing fail-closed contract.
- **Cloud KMS/HSM providers are not implemented yet.** The **envelope seam is implemented** —
  `IContentKeyProvider` plus the built-in, tested `LocalKekContentKeyProvider` (`KeySource = 5`).
  Cloud providers (AWS KMS, Azure Key Vault, Vault, PKCS#11) implement the same interface in
  separate packages and need their SDKs + live credentials to integration-test. Rewrap/rotation
  tooling is still designed-only. See [docs/KEY-MANAGEMENT.md](docs/KEY-MANAGEMENT.md).
- **Passphrases are still `string` on the convenience overloads.** The zeroable byte overloads
  exist, but the `string` overloads remain for ergonomics and cannot zero the caller's `string`.

### Dependency assurance

- **Argon2id comes from `Konscious.Security.Cryptography`**, a widely used but **not formally
  audited** managed implementation. The default KDF (PBKDF2) avoids this dependency at runtime.

### Format and feature gaps

- **The container format is not frozen.** No cross-version migration tooling exists, and v0.2
  does not read the v0.1 format. Do not store preview-encrypted data you must read with a
  `1.0+` build.
- **Metadata is not protected.** Plaintext length is revealed to within a chunk; file names,
  paths, and timestamps are not encrypted or carried.
- **No streaming all-or-nothing guarantee.** `DecryptAsync(Stream, Stream, …)` authenticates
  each chunk before writing it, but a stream cannot be un-written, so a truncation detected at
  the final frame leaves earlier (authentic) chunks already emitted. The **file** APIs avoid
  this with temp-file-plus-atomic-move; stream callers who need strict atomicity should buffer.
- **No compression, no deduplication, no key files.** Out of scope.
- **Atomic-write temp-file cleanup is best-effort.** The file-API write path stages every byte
  in a sibling temp file and only `File.Move`s it into place on full success; on any failure
  (crypto, format, I/O, cancellation) the temp file's deletion is *attempted* but swallows
  exceptions, so an OS-level lock (AV scanner, parallel handle) can leave the temp behind.
  **Destination integrity is preserved either way** — no partial or corrupted file is ever
  moved to the destination path; only the temp file may linger. Operators who need
  guaranteed cleanup of orphaned `*.tmp-*` files should run a periodic sweep.

### Demos

- **The .NET demo is Blazor Server, not client-side WebAssembly.** .NET's `AesGcm` is
  unsupported in browser WebAssembly, so the library cannot encrypt in-browser; that demo runs
  the crypto on the server (files in memory, never persisted).
- **A fully client-side browser demo exists** (`samples/pqfe-web`) backed by an independent
  **Rust → WASM** re-implementation of the `.pqfe` format (`samples/pqfe-wasm`). Because it is a
  second implementation, it is a separate codebase to keep in step with the format; it is held
  byte-compatible by cross-implementation tests (Rust decrypts the .NET vectors; .NET decrypts a
  Rust-produced container). It currently supports only the **passphrase** key source — **ML-KEM
  recipient mode is not implemented in the Rust/WASM core**.

### Process and assurance gaps

- **`<EnablePackageValidation>` is not yet enabled** with a `PackageValidationBaselineVersion`.
  At `0.x` we still allow binary-breaking changes between minor versions; the right time for
  baseline-driven package validation is the `1.0` freeze. Tracked in
  [ROADMAP.md](ROADMAP.md#toward-10).
- **Not independently audited.** No third-party cryptographic review has been performed.
- **Continuous fuzzing is wired but young.** Coverage-guided fuzzers run for **both** parsers —
  **cargo-fuzz** (Rust) and **SharpFuzz** (.NET) — validated with no crashes (~330k and ~480k
  executions) and scheduled nightly in CI with a cached corpus (`.github/workflows/fuzz.yml`).
  OSS-Fuzz integration files are ready (`oss-fuzz/`) but upstream onboarding is not yet done, and
  the accumulated corpora are still small. See [docs/FUZZING.md](docs/FUZZING.md).
- **Recipient round-trip is not exercised on this CI host**, which lacks platform ML-KEM; those
  tests self-skip there. The capability gating *is* tested everywhere.
- **NuGet author-signing** requires a code-signing certificate (not configured); nuget.org applies
  repository signatures on publish. The release workflow produces an SBOM and a provenance attestation.
- **Single target framework.** `net10.0` only; no down-level support.

---

*Transparency is a feature. To God be the glory — 1 Corinthians 10:31.*
