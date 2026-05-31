# Roadmap

Where PostQuantum.FileEncryption is and where it's going. This is intentionally honest about
what is production-ready versus experimental versus planned. See
[KNOWN-GAPS.md](KNOWN-GAPS.md) for the full ledger and [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md)
for the detailed hybrid design.

## Now — `0.3.0`

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

**Supply-chain & release assurance:**

- macOS added to the CI matrix; native-AOT publish + round-trip smoke test on every push.
- Release workflow runs `Meziantou.Framework.NuGetPackageValidation.Tool` before `nuget push`
  with the strict icon-must-be-set rule re-enabled.
- OpenSSF Scorecard workflow (weekly + push to main), with SARIF surfaced in the Security tab.
- CycloneDX SBOMs and a SLSA-style provenance attestation attached to every release tag.
- Coverage uploaded to Codecov on every push, badge in the README.
- **Public API surface locked** by `Microsoft.CodeAnalysis.PublicApiAnalyzers` with
  `PublicAPI.Shipped.txt` baselines on both packages (106 entries on the core, 26 on the
  Hybrid). Any accidental breaking change to the public surface now fails the build.

`0.x` means the API and on-disk format may still change before `1.0`.

## Next — `v0.4`

- Synchronous `ReadOnlySpan<char>` passphrase entry point for callers that never go async.
- Continued fuzzing/coverage growth; begin pinning the format toward a freeze.
- Cloud KMS provider packages (AWS KMS, Azure Key Vault, HashiCorp Vault) implementing
  `IContentKeyProvider` in their own NuGet packages, so the core stays dependency-light.
- Rewrap/rotation tooling for envelope-encrypted containers.

## Toward `1.0`

- Freeze the container format and publish the vectors as a stable conformance spec.
- Enable `<EnablePackageValidation>` with `PackageValidationBaselineVersion` set to the
  last `0.x` release, so every subsequent pack proves binary compatibility at build time.
  Skipped during `0.x` because binary breaks are still expected and `0.x` baselines would
  cause more friction than value.
- An independent cryptographic review.

---

*To God be the glory — 1 Corinthians 10:31.*
