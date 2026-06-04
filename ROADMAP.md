# Roadmap

Where PostQuantum.FileEncryption is and where it's going. This is intentionally honest about
what is production-ready, what is deprecated, and what comes after `1.0`. See
[KNOWN-GAPS.md](KNOWN-GAPS.md) for the full open-issues ledger and
[docs/ROADMAP-v3.md](docs/ROADMAP-v3.md) for the hybrid design.

## Now — `1.0.0-rc.3` (release candidate)

The library is feature-complete for `1.0`. This release candidate is the same code that will
ship as `1.0.0` after the soak window completes.

**Production-ready and the recommended path:**

- Passphrase-based file, stream, and in-memory encryption with **AES-256-GCM**.
- Key derivation via **PBKDF2-HMAC-SHA256** (default) or **Argon2id** (memory-hard, opt-in),
  with `PqEncryptionOptions.Argon2id` and fluent `With…` helpers for ergonomic tuning.
- Chunked streaming with bounded memory, progress reporting, cancellation, and atomic file
  output.
- Fail-closed against wrong passphrase, tampering, reordering, splicing, and truncation.
- **Envelope-encryption seam** (`IContentKeyProvider`) with a built-in, dependency-free
  `LocalKekContentKeyProvider`; cloud KMS adapters belong in separate packages.
- Synchronous `ReadOnlySpan<char>` passphrase entry point (`EncryptBytes` / `DecryptBytes`)
  for callers that never go async — no `.GetAwaiter().GetResult()` deadlock surface.

**On-disk format — FROZEN at `.pqfe` v2 for the `1.x` line:**

- Every byte is pinned by published cross-checked [test vectors](docs/TEST-VECTORS.md).
- A conformance specification ([docs/CONFORMANCE.md](docs/CONFORMANCE.md)) documents what an
  independent implementer must produce to be byte-compatible.
- A second, independent **Rust → WebAssembly** implementation
  (`samples/pqfe-wasm`) is held byte-compatible by tests in both directions: the Rust suite
  decrypts the .NET vectors, and `CrossImplementationTests.cs` decrypts a Rust-produced
  container.
- Any incompatible format change requires a `2.0` major version.

**Public-key (recipient) encryption — production package:**

- **`PostQuantum.FileEncryption.Hybrid`** — X25519 + ML-KEM-768 combiner with multi-recipient
  support, managed via BouncyCastle (runs anywhere, no platform ML-KEM requirement). The
  content key stays safe if either primitive is later broken.

**Deprecated in the core package** (warning-only; retained for source-compatibility):

- **Inline ML-KEM-768-only recipient mode** — `PqKeyPair`, `PqRecipientPublicKey`,
  `PqRecipientPrivateKey`, and the recipient overloads on
  `PqFileEncryptor`/`PqFileDecryptor`. Marked `[Obsolete]` with diagnostic id `PQFE002`.
  Superseded by the Hybrid package. Removal is targeted for a future major release.

**Supply-chain & release assurance (all in place today):**

- CI matrix: Ubuntu, Windows, macOS, with a separate native-AOT publish-and-round-trip job.
- Release workflow runs `Meziantou.Framework.NuGetPackageValidation.Tool` against every
  `.nupkg` (strict icon-must-be-set, SourceLink wired, README/LICENSE/icon packed,
  deterministic build, PDBs valid) before `nuget push`.
- **CycloneDX SBOMs** and **SLSA-style build-provenance attestations** attached to every
  release artifact (see [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md)).
- **OpenSSF Scorecard** workflow (weekly + push to main + dispatch), SARIF surfaced in the
  Security tab and published to the public Scorecard dashboard.
- **Public API surface locked** by `Microsoft.CodeAnalysis.PublicApiAnalyzers` with
  `PublicAPI.Shipped.txt` baselines on both packages — accidental breaking changes fail the
  build.
- **`<EnablePackageValidation>`** is on, with the published `1.0.0-rc.1` surface as the
  baseline — every subsequent pack proves binary compatibility at build time.
- Coverage uploaded to Codecov on every push.
- Coverage-guided fuzzing for **both** parsers (cargo-fuzz + SharpFuzz) runs nightly with a
  cached corpus; OSS-Fuzz integration files are ready.

## Next — `1.0.0` (final)

When the rc soak window completes and no fixes are needed:

- Tag `v1.0.0`. Same code, dropped pre-release suffix.
- API and `.pqfe` v2 format are binary-stable from that point onward; everything from `1.0.0`
  forward is governed by the [versioning policy](docs/VERSIONING.md) (SemVer with package
  validation against the previous release).

## After `1.0` — `1.x` minor work

Format-compatible additions that fit inside frozen `.pqfe` v2:

- **Cloud KMS provider packages** — AWS KMS, Azure Key Vault, HashiCorp Vault, and a
  PKCS#11/HSM adapter, each as its own NuGet package implementing the existing
  `IContentKeyProvider` interface. The core stays dependency-light.
- **Rewrap / rotation tooling** for envelope-encrypted containers — re-wrap the content key
  to a new KEK or to a new set of recipients without re-encrypting the data plane.
- **Removal of the inline ML-KEM-only recipient mode** in a future major release
  (`2.0`). Until then it continues to honour the existing fail-closed contract; new code
  must use `PostQuantum.FileEncryption.Hybrid`.

Trust-building work that is ongoing:

- **Continuous fuzzing corpus growth** and OSS-Fuzz upstream onboarding.
- **An independent cryptographic review.** Funded engagements are welcome — see
  [SECURITY.md](SECURITY.md).

## Beyond — possible `2.0` directions

Anything that would require a new `FormatVersion` and a major version bump. None of these are
committed; they are recorded so users can plan and so we don't accidentally box them out:

- **Metadata protection** — encrypted file names, optional length-hiding padding.
- **Compression integration** — opt-in, with a documented compression-oracle warning.
- **Format upgrades** for new AEAD or PQ KEM choices as the post-quantum landscape evolves.

---

*To God be the glory — 1 Corinthians 10:31.*
