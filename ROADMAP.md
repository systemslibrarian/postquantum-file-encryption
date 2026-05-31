# Roadmap

Where PostQuantum.FileEncryption is and where it's going. This is intentionally honest about
what is production-ready versus experimental versus planned. See
[KNOWN-GAPS.md](KNOWN-GAPS.md) for the full ledger and [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md)
for the detailed hybrid design.

## Now — `0.2.0`

**Production-ready and the recommended path:**

- Passphrase-based file, stream, and in-memory encryption with **AES-256-GCM**.
- Key derivation via **PBKDF2-HMAC-SHA256** (default) or **Argon2id** (memory-hard, opt-in),
  with `PqEncryptionOptions.Argon2id` and fluent `With…` helpers for ergonomic tuning.
- Chunked streaming with bounded memory, progress reporting, cancellation, and atomic file output.
- Fail-closed against wrong passphrase, tampering, reordering, splicing, and truncation.
- A self-contained, specified container format ([docs/FILE-FORMAT.md](docs/FILE-FORMAT.md))
  pinned by cross-checked [test vectors](docs/TEST-VECTORS.md), and a fuzz harness.
- **Envelope-encryption seam** (`IContentKeyProvider`) with a built-in
  `LocalKekContentKeyProvider`; cloud KMS adapters belong in separate packages.

**Public-key (recipient) encryption — production package:**

- **`PostQuantum.FileEncryption.Hybrid`** — X25519 + ML-KEM-768 combiner and multi-recipient
  support, managed via BouncyCastle (runs anywhere, no platform ML-KEM required).

**Experimental in the core package** (not part of the stable surface):

- **ML-KEM-768-only recipient mode** — platform-gated via `PqKeyPair.IsSupported`. Superseded
  by the Hybrid package for new code.

**Supply-chain & release assurance** (new in `0.2.0`):

- macOS added to the CI matrix; native-AOT publish + round-trip smoke test on every push.
- Release workflow runs `Meziantou.Framework.NuGetPackageValidation.Tool` before `nuget push`.
- OpenSSF Scorecard workflow (weekly + push to main), with SARIF surfaced in the Security tab.
- CycloneDX SBOMs and a SLSA-style provenance attestation attached to every release tag.

`0.x` means the API and on-disk format may still change before `1.0`.

## Next — `v0.3` (publish-ready polish)

- **`Microsoft.CodeAnalysis.PublicApiAnalyzers`** + `PublicAPI.Shipped.txt` /
  `PublicAPI.Unshipped.txt` baselines on both packages — make accidental breaking changes
  impossible to merge.
- **`<EnablePackageValidation>` + `PackageValidationBaselineVersion`** in
  `Directory.Build.props` to catch binary-breaking changes at pack time, not at install time.
- **Codecov (or Coveralls) upload + README badge.** CI already collects coverage; finish the
  loop so contributors can see it.
- **Package icon** for both packages (so the strict `IconMustBeSet` rule can be turned back on).
- **Hybrid metadata parity** — `PackageRequireLicenseAcceptance`, packed `LICENSE`, and
  `MinClientVersion` to match the core package.
- Synchronous `ReadOnlySpan<char>` passphrase entry point for callers that never go async.
- Optional progress on the in-memory bytes API and additional convenience overloads as the
  API settles.

## Later — `v0.4`

- Continued fuzzing/coverage growth; begin pinning the format toward a freeze.
- Cloud KMS provider packages (AWS KMS, Azure Key Vault, HashiCorp Vault) implementing
  `IContentKeyProvider` in their own NuGet packages, so the core stays dependency-light.
- Rewrap/rotation tooling for envelope-encrypted containers.

## Toward `1.0`

- Freeze the container format and publish the vectors as a stable conformance spec.
- An independent cryptographic review.
- Wire the optional delegation seam to `PostQuantum.FileFormat` if/when that package is published.

---

*To God be the glory — 1 Corinthians 10:31.*
