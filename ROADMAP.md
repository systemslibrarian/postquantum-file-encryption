# Roadmap

Where PostQuantum.FileEncryption is and where it's going. This is intentionally honest about
what is production-ready, what is deprecated, and what comes after `1.0`. See
[KNOWN-GAPS.md](KNOWN-GAPS.md) for the full open-issues ledger and
[docs/ROADMAP-v3.md](docs/ROADMAP-v3.md) for the hybrid design.

## Now — `1.6.0`

The library ships as a **nine-package lockstep family** — the core, `Hybrid`, `Signing`, the
`Aws` / `AzureKeyVault` / `Gcp` KMS adapters, `Extensions.DependencyInjection`, `Analyzers`,
and the `pqfe` CLI tool — all released together at the same version. The `.pqfe` v2 container
format is FROZEN for the entire `1.x` line, the public API surface is locked, and the
supply-chain assurances below are continuous. Every release from `1.0.0` forward is governed
by the [versioning policy](docs/VERSIONING.md) (SemVer with package validation against the
previous release).

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
- **Reproducible-build verification** runs automatically after every release: a clean
  rebuild of the tagged source is diffed against the published `.nupkg` on nuget.org, with
  the workflow and the recipe documented in
  [docs/REPRODUCIBLE-BUILDS.md](docs/REPRODUCIBLE-BUILDS.md).

## `1.x` minor work

Format-compatible additions that fit inside frozen `.pqfe` v2.

**Shipped since `1.0`:**

- **Cloud KMS provider packages** — `Aws` (AWS KMS), `AzureKeyVault`, and `Gcp` (Cloud KMS),
  each as its own NuGet package implementing the existing `IContentKeyProvider` interface.
  The core stays dependency-light.
- **Hybrid recipient encryption and detached hybrid signatures** as the `Hybrid` and
  `Signing` packages, the encrypted `PQKF` key-file format, misuse `Analyzers`, and the
  `pqfe` CLI tool.

**Still open (format-compatible, `1.x`-eligible):**

- **HashiCorp Vault Transit and a PKCS#11/HSM adapter** as further `IContentKeyProvider`
  sibling packages, once the provider contract-test kit is stable.
- **Rotation / transcode tooling** for envelope-encrypted containers — because the serialized
  header is AAD for every content frame, safe provider migration in v2 is a *streaming
  transcode* (fresh CEK and nonces, whole file rewritten), not a header-only rewrap. True
  header-only rewrap needs a future format that separates a mutable wrap area from the stable
  data-plane commitment, so it is a `2.0` item.
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
