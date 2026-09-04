# CLAUDE.md — Conventions for PostQuantum.FileEncryption

Guidance for Claude (and humans) working in this repository. Read this before making
changes.

## What this project is

A high-level, **delightful**, fail-closed wrapper for post-quantum file and stream
encryption on .NET. The public surface is small on purpose: `PqFileEncryptor`,
`PqFileDecryptor`, `PqEncryptionOptions`, `PqProgress`, the key types (`PqKeyPair`,
`PqRecipientPublicKey`, `PqRecipientPrivateKey`), the `PqKdf` enum, and the exception types.
Everything cryptographic lives behind that surface in `Internal/`.

It supports passphrase encryption (PBKDF2 or Argon2id) and ML-KEM-768 recipient (public-key)
encryption. The long-term intent is to wrap **PostQuantum.FileFormat**; until that dependency
exists, the engine is self-contained behind the `IPqContainerCodec` seam. See
[KNOWN-GAPS.md](KNOWN-GAPS.md).

## Non-negotiable principles

1. **No homegrown cryptography.** Use only `System.Security.Cryptography`. If a change seems
   to require inventing a primitive or a construction, stop and reconsider.
2. **Authenticated encryption only.** Never add an unauthenticated path.
3. **Fail closed.** On any doubt about authenticity, throw `PqDecryptionException` and emit
   no plaintext. No partial-success paths, no error oracles — every auth failure looks the
   same to the caller.
4. **Transparency over reassurance.** If you add a limitation, document it in
   [KNOWN-GAPS.md](KNOWN-GAPS.md). If you change the on-disk layout, update
   [docs/FILE-FORMAT.md](docs/FILE-FORMAT.md) in the same change.
5. **Strong defaults, optional tuning.** A caller who supplies no options must get a secure
   result.

## Code conventions

- **Targets:** `net8.0` and `net10.0` (multi-targeted). `Nullable` and `ImplicitUsings` are on.
  The public API surface must stay identical across both targets; net10-only platform crypto
  (e.g. `System.Security.Cryptography.MLKem`) is gated with `#if NET10_0_OR_GREATER` and the
  net8.0 path fails closed with `PlatformNotSupportedException` / `IsSupported == false`.
- **Warnings are errors.** `TreatWarningsAsErrors` and `latest-recommended` analysis are set
  in `Directory.Build.props`. Fix the cause; suppress only with a written justification.
- **Public API is fully XML-documented**, including remarks on security-relevant behavior.
- **Async + cancellation everywhere** for I/O; honor the `CancellationToken`.
- **Zero key material** with `CryptographicOperations.ZeroMemory` in a `finally`.
- Keep the public surface minimal. New knobs go on `PqEncryptionOptions`, not as new method
  overloads, unless there is a clear ergonomic win.

## Layout

```
Directory.Build.props                 — shared build settings (deterministic, analysis, authorship)
src/PostQuantum.FileEncryption/       — the library
  PqFileEncryptor.cs / PqFileDecryptor.cs   — public API (passphrase + recipient overloads)
  PqEncryptionOptions.cs / PqProgress.cs / PqKdf.cs  — configuration, progress, KDF choice
  PqKeyPair.cs                                — ML-KEM recipient key types
  PqEncryptionException.cs                    — exception hierarchy
  Internal/ContainerFormat.cs                 — v2 header constants + (de)serialization
  Internal/KeyEstablishment.cs                — PBKDF2 / Argon2id / ML-KEM KEM-DEM
  Internal/PqContainerEngine.cs               — the chunked AEAD core
  Internal/IPqContainerCodec.cs               — delegation seam (self-contained impl today)
  Internal/PqContainer.cs                     — orchestration (establish key → header → codec)
  Internal/PqKeyFileFormat.cs                 — the PQKF v1 encrypted key-file framing
  Internal/FileIo.cs                          — atomic temp-file write + in-place ordering helper
src/PostQuantum.FileEncryption.{Hybrid,Signing,Aws,AzureKeyVault,Gcp,
    Extensions.DependencyInjection,Analyzers}/ — the lockstep sibling packages
tests/PostQuantum.FileEncryption.Tests/  — round-trip, KDF, recipient, known-answer, boundary, fuzz tests
tests/PostQuantum.FileEncryption.Analyzers.Tests/ — analyzer rule tests
docs/FILE-FORMAT.md                       — the container specification (v2, FROZEN)
```

When you change key establishment, keep the three KDF/KEM paths consistent: encrypt-side
serialization, decrypt-side parsing (with range checks), and a known-answer vector.

## Build, test, pack

```bash
dotnet build -c Release
dotnet test  -c Release
dotnet pack  src/PostQuantum.FileEncryption -c Release
```

## The format freeze — hard rules, read before touching anything byte-shaped

The on-disk formats are **FROZEN for the entire 1.x line**: the `.pqfe` **v2** container
([docs/FILE-FORMAT.md](docs/FILE-FORMAT.md)), the `.sig` **v1** sidecar
([docs/SIGNATURE-FORMAT.md](docs/SIGNATURE-FORMAT.md)), and the `PQKF` **v1** key file
([docs/KEY-FILE-FORMAT.md](docs/KEY-FILE-FORMAT.md)). Frozen cuts both ways:

1. **Never change what bytes mean.** No layout, constant, AAD, nonce, or derivation change,
   however small or "obviously safe". There is no bump-`FormatVersion` move inside 1.x — a
   new format version is a deliberate 2.0 event ([docs/ROADMAP-2.0.md](docs/ROADMAP-2.0.md)),
   never an incidental fix.
2. **Never change what a reader accepts.** Tightening is breaking too: rejecting trailing
   bytes, enforcing the reserved `Flags` byte, or hardening a corner v2 tolerates would make
   working files stop opening and desync the Rust core. Write the urge down in
   [KNOWN-GAPS.md](KNOWN-GAPS.md) as a **format-v3 candidate** instead — that ledger is the
   bank where breaking improvements wait for 2.0.
3. **Never regenerate a pinned known-answer vector to make a failing test pass.** The
   vectors ([docs/TEST-VECTORS.md](docs/TEST-VECTORS.md), `KnownAnswerVectorTests`, the Rust
   `tests/vectors.rs`) are the canary, not test data: a KAT failure means your change broke
   the frozen format — revert the change. Adding new vectors is encouraged; existing ones are
   regenerated only as part of a deliberate major-version format revision.
4. **Ship around the formats, not through them.** The test for every feature: *does it
   change what existing bytes mean, or which byte sequences are accepted?* No → it can ship
   in 1.x (new APIs, decrypt-time limits, tooling, or a new **sibling** format with its own
   magic and version byte, like `PQKF`). Yes → KNOWN-GAPS bank, format v3.
5. **Keep the Rust core in step.** Behavior pinned cross-implementation
   (`samples/pqfe-wasm`) must stay byte-compatible; a change that needs the Rust side
   "fixed to match" is a format change in disguise.

## When you touch crypto (within the freeze)

- Add or extend a fail-closed test (tamper, truncate, wrong passphrase, bad format) — these
  are as important as the round-trip tests.
- Keep the KDF/KEM paths consistent end to end: encrypt-side serialization, decrypt-side
  parsing (with exact-boundary range checks on untrusted header values), and a known-answer
  vector.
- Re-read [SECURITY.md](SECURITY.md) and keep its "does NOT defend against" list accurate.

## When you bump the package version

The nine packages (core, Hybrid, Signing, Aws, AzureKeyVault, Gcp, DI Extensions, Analyzers,
and the `pqfe` Tool) ship in **lockstep**, and the documented version must never lag the
`<Version>` in the `.csproj` files. Bumping the NuGet version is not done until the docs are
swept in the **same change**. After changing `<Version>` in the project files, grep the repo
for the *old* version string and update every user-facing reference:

- All `dotnet add package … --version X.Y.Z` install snippets (root `README.md`, plus each
  package's own `src/**/README.md`).
- The **Status** line near the top of the root `README.md`.
- The supply-chain examples that name an artifact or tag (e.g.
  `gh attestation verify PostQuantum.FileEncryption.X.Y.Z.nupkg`, `gh release download vX.Y.Z`).
- The "NuGet package version → Today" cell in [docs/ROADMAP-2.0.md](docs/ROADMAP-2.0.md).
- Add the new `CHANGELOG.md` section and its compare-link footer.
- The `SECURITY.md` supported-versions cell (current: `X.Y.Z`).
- The "## Now — `X.Y.Z`" heading in `ROADMAP.md` and every "Last reviewed against"
  marker (`KNOWN-GAPS.md`, `docs/GOLD-STANDARD.md`) — re-review the document, don't just
  re-stamp it.
- `PackageValidationBaselineVersion` in `Directory.Build.props` (the previous release becomes
  the new baseline).
- The pinned tag in `docs/AUDIT-SCOPE.md` and the worked verification examples in
  `docs/SUPPLY-CHAIN.md`, `docs/REPRODUCIBLE-BUILDS.md`, and `docs/ANNOUNCE.md`.

Most of these are enforced continuously by `scripts/check-docs-consistency.sh` (run by the
`docs-consistency` workflow on every push and PR) — run it locally before tagging.

Leave **historical** mentions alone — past changelog entries, compare links, and prose like
"shipped `1.3.0`" are facts about earlier releases, not the current version. When in doubt,
`grep -rn '<old-version>'` and decide per hit: install/status/artifact references move,
history stays.

*To God be the glory — 1 Corinthians 10:31.*
