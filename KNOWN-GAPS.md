# Known Gaps

This document is the honest ledger for PostQuantum.FileEncryption. It records what is
incomplete, deferred, or imperfect, so that nobody has to discover it by reading the source
or, worse, in production. If you find a gap not listed here, that itself is a gap — please
open an issue.

Last reviewed against: **`1.2.0`**. See [ROADMAP.md](ROADMAP.md) for the forward plan.

## Release scope (read this first)

- **The stable, released engine is symmetric and passphrase-based:** AES-256-GCM with
  PBKDF2-HMAC-SHA256 or Argon2id. AES-256 is quantum-resistant for the *confidentiality of
  the data itself*. The `.pqfe` v2 container format is FROZEN for the `1.x` line.
- **Post-quantum *public-key* encryption ships as the production
  `PostQuantum.FileEncryption.Hybrid` package** — X25519 + ML-KEM-768 hybrid combiner with
  multi-recipient support, managed via BouncyCastle (no platform ML-KEM dependency, runs
  anywhere .NET 10 does). See [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md).
- **The inline ML-KEM-768-only recipient mode in the core is deprecated** as of
  `1.0.0-rc.2` (`PQFE002`) and retained only for source-compatibility. New code must use
  the Hybrid package; the inline mode is targeted for removal in a future major release.

## Resolved in `1.2.0`

- **Decrypt-time cost ceilings.** A container's KDF cost parameters and chunk size are
  honored before anything authenticates, so a hostile ~30-byte header could legally demand
  the format maximum — up to 2 GiB of Argon2id memory — on open. Found by a static security
  review (it was a hardening gap, not a contradiction of any documented bound). Now:
  `PqDecryptionLimits` lets callers who decrypt untrusted containers cap PBKDF2/Argon2id
  cost and chunk size (`PqDecryptionLimits.Untrusted` preset, or custom ceilings), with
  over-limit headers rejected as `PqFormatException` before any derivation work; and the
  engine caps its chunk buffers to what a container of known length could actually hold,
  so a tiny container declaring a 16 MiB chunk no longer drives a ~32 MiB allocation.
  Defaults are unchanged — every legal container still opens.

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
  runnable and gives the AOT smoke test a real target. It now also ships as the installable
  `PostQuantum.FileEncryption.Tool` dotnet tool (passphrase mode only — recipient/hybrid
  encryption remains library-only).
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
- **BouncyCastle key objects cannot be zeroized.** The Hybrid package zeroes every temporary
  private-key copy it creates, but BouncyCastle's parameter objects (`MLKemPrivateKeyParameters`,
  `X25519PrivateKeyParameters`) keep their own internal copies of key material with no public
  zeroization API; those copies live until garbage collection. This is a limitation of the
  dependency, shared by everything built on managed BouncyCastle.

### Format and feature gaps

- **The container format is FROZEN at `.pqfe` v2 for the `1.x` line.** No `0.x → 1.x`
  migration tooling exists; if you have any preview-era ciphertext, decrypt it with the
  original `0.x` build and re-encrypt with a `1.x` build. A future major version (`2.0`)
  would carry a new `FormatVersion` and a documented migration path — the candidate feature
  set lives in [docs/ROADMAP-2.0.md](docs/ROADMAP-2.0.md).
- **Metadata is not protected.** Plaintext length is revealed to within a chunk; file names,
  paths, and timestamps are not encrypted or carried. Length-hiding padding and encrypted
  file names are candidates for a future `2.0`.
- **No streaming all-or-nothing guarantee.** `DecryptAsync(Stream, Stream, …)` authenticates
  each chunk before writing it, but a stream cannot be un-written, so a truncation detected at
  the final frame leaves earlier (authentic) chunks already emitted. The **file** APIs avoid
  this with temp-file-plus-atomic-move; stream callers who need strict atomicity should buffer.
- **No compression, no deduplication, no key files.** Out of scope.
- **Signatures are detached, with the standard detached-signature limits.** The Signing
  package (`PostQuantum.FileEncryption.Signing`, Ed25519 + ML-DSA-65 over a SHA-512 pre-hash)
  proves *who signed the bytes*, but a `.sig` sidecar is not bound to a file name, path, or
  time, and it cannot prevent **strip-and-resign**: anyone able to read the bytes can discard
  the sidecar and sign the same bytes with their own key. Authenticity is anchored in which
  public key the verifier trusts — distribute public keys over a trusted channel. Signatures
  *embedded in the container* (which would also authenticate the signer to the decryptor)
  require a format change and are the headline candidate for a future `2.0` — see
  [docs/ROADMAP-2.0.md](docs/ROADMAP-2.0.md) and
  [docs/SIGNATURE-FORMAT.md](docs/SIGNATURE-FORMAT.md).
- **Containers are not sender-authenticated by encryption alone.** AES-GCM proves a container
  was not altered after creation, and recipient encryption proves only that the sender knew
  the recipient's *public* key — which is public. Use the Signing package when "who produced
  this file" matters.
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
  Rust-produced container) **and a live interop CI job** that round-trips fresh random payloads
  in both directions, across chunk boundaries, on every push (`ci.yml` → `interop`). It
  currently supports only the **passphrase** key source — **hybrid/ML-KEM recipient mode is not
  implemented in the Rust/WASM core**.

### Process and assurance gaps

- **Not independently audited.** No third-party cryptographic review has been performed.
  Funded audit engagements are welcome — see [SECURITY.md](SECURITY.md).
- **Continuous fuzzing is wired but young.** Coverage-guided fuzzers run for **both** parsers —
  **cargo-fuzz** (Rust) and **SharpFuzz** (.NET) — validated with no crashes (~330k and ~480k
  executions) and scheduled nightly in CI with a cached corpus (`.github/workflows/fuzz.yml`).
  OSS-Fuzz integration files are ready (`oss-fuzz/`) but upstream onboarding is not yet done, and
  the accumulated corpora are still small. See [docs/FUZZING.md](docs/FUZZING.md).
- **Recipient round-trip is not exercised on this CI host**, which lacks platform ML-KEM; those
  tests self-skip there. The capability gating *is* tested everywhere.
- **NuGet author-signing** requires a code-signing certificate (not configured); nuget.org applies
  repository signatures on publish. The release workflow produces an SBOM and a provenance attestation.
- **Two target frameworks.** `net8.0` and `net10.0`. The public API is identical on both, with
  one behavioral difference: the *deprecated* inline ML-KEM-only recipient mode (PQFE002) relies
  on platform ML-KEM, which ships in .NET 10 — on `net8.0`, `PqKeyPair.IsSupported` is always
  `false` and the mode throws `PlatformNotSupportedException`, exactly as on a .NET 10 host
  without OpenSSL 3.5+/CNG support. The supported path for recipient encryption on either target
  is the Hybrid package, whose ML-KEM-768 and X25519 come from BouncyCastle (fully managed).
  No `netstandard2.0`/`net462` support.

---

*Transparency is a feature. To God be the glory — 1 Corinthians 10:31.*
