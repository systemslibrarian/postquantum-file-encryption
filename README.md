# PostQuantum.FileEncryption

<!-- Badge images are served via img.shields.io so they render on nuget.org,
     which only displays images from an allow-list of trusted domains. -->
[![CI](https://img.shields.io/github/actions/workflow/status/systemslibrarian/postquantum-file-encryption/ci.yml?branch=main&label=CI)](https://github.com/systemslibrarian/postquantum-file-encryption/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/systemslibrarian/postquantum-file-encryption/codeql.yml?branch=main&label=CodeQL)](https://github.com/systemslibrarian/postquantum-file-encryption/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/systemslibrarian/postquantum-file-encryption?label=openssf%20scorecard)](https://securityscorecards.dev/viewer/?uri=github.com/systemslibrarian/postquantum-file-encryption)
[![codecov](https://codecov.io/gh/systemslibrarian/postquantum-file-encryption/branch/main/graph/badge.svg)](https://codecov.io/gh/systemslibrarian/postquantum-file-encryption)
[![NuGet](https://img.shields.io/nuget/v/PostQuantum.FileEncryption.svg)](https://www.nuget.org/packages/PostQuantum.FileEncryption/)
[![NuGet Hybrid](https://img.shields.io/nuget/v/PostQuantum.FileEncryption.Hybrid.svg?label=nuget%20hybrid)](https://www.nuget.org/packages/PostQuantum.FileEncryption.Hybrid/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/LICENSE)

**A high-level, fail-closed file and stream encryptor for .NET — production-ready, frozen
format, and post-quantum aware.**

Two friendly classes — `PqFileEncryptor` and `PqFileDecryptor` — handle authenticated,
chunked, streaming encryption with strong, modern defaults. You should not have to read a
cryptographic spec to protect a file: call a method, and the library does the careful,
paranoid, fail-closed thing every time.

> **Status: `1.0.1` — stable release.**
> The symmetric, passphrase-based engine is production-ready and the `.pqfe` v2 container
> format is **FROZEN for the `1.x` line**. The companion **`PostQuantum.FileEncryption.Hybrid`**
> package provides production X25519 + ML-KEM-768 hybrid public-key encryption with
> multi-recipient support. The inline ML-KEM-only recipient mode in the core is **deprecated
> (`PQFE002`)** — see [Post-quantum & the upgrade path](#post-quantum--the-upgrade-path).

---

## Why this library

- **Production-ready core.** Authenticated AES-256-GCM with chunked streaming, atomic file
  output, cancellation, progress, and zeroable secrets. 106+ tests, continuous fuzzing,
  byte-compatible Rust/WASM reference, native-AOT smoke-tested in CI.
- **Frozen format.** `.pqfe` v2 is pinned by [cross-checked known-answer
  vectors](docs/TEST-VECTORS.md) and a [conformance specification](docs/CONFORMANCE.md). A
  file you encrypt today opens with every `1.x` build, on every platform, in either
  implementation.
- **Locked public API.** `Microsoft.CodeAnalysis.PublicApiAnalyzers` baselines every public
  member; `<EnablePackageValidation>` checks binary compatibility against the previous
  release at pack time. Accidental breakage fails the build.
- **Honest supply chain.** Every release artifact ships with a [CycloneDX
  SBOM](docs/SUPPLY-CHAIN.md), a [SLSA-style build-provenance
  attestation](docs/SUPPLY-CHAIN.md#verify-build-provenance-attestation), and SourceLink. The
  release workflow runs `Meziantou.Framework.NuGetPackageValidation` against every `.nupkg`
  before publish.
- **Honest about limits.** The [Known Gaps](KNOWN-GAPS.md) ledger lists everything that is
  not yet done. The library has not been independently audited; engagements are welcome.

## When to use this

- You're on **.NET 10** and want a drop-in, fail-closed file/stream encryptor with
  excellent defaults and no FFI.
- You need **post-quantum data confidentiality today** (AES-256 against a harvest-now-
  decrypt-later adversary) and a clear path to **post-quantum public-key encryption** via
  the Hybrid package.
- You want **enterprise affordances**: telemetry, atomic output, a documented format with
  test vectors, a published threat model, signed releases, and a locked API.
- You want a [comparison vs. `age`, libsodium, and OpenSSL](docs/COMPARISON.md) before
  committing.

For a side-by-side with other encryption libraries and migration guidance, see
[docs/MIGRATION.md](docs/MIGRATION.md).

---

## Install

```bash
# Core (passphrase + envelope-key engine)
dotnet add package PostQuantum.FileEncryption --version 1.0.1

# Add this only if you need public-key (recipient) encryption
dotnet add package PostQuantum.FileEncryption.Hybrid --version 1.0.1

# Optional: Microsoft.Extensions.DependencyInjection integration
# (AddPqFileEncryption() / AddPqHybridFileEncryption())
dotnet add package PostQuantum.FileEncryption.Extensions.DependencyInjection --version 1.0.1
```

Targets **.NET 10** (`net10.0`). Core depends only on
`Konscious.Security.Cryptography.Argon2` (and only when you select Argon2id); everything
else is from .NET's `System.Security.Cryptography`. The Hybrid package additionally pulls in
`BouncyCastle.Cryptography` so it runs on every platform without a native ML-KEM dependency.

---

## ▶ Try it

Three ways to drive the library — all produce the same `.pqfe` format:

### 1. Command-line — install the `pqfe` dotnet tool

No code required:

```bash
dotnet tool install -g PostQuantum.FileEncryption.Tool

pqfe encrypt report.pdf report.pdf.pqfe --argon2id     # prompts for a passphrase
pqfe decrypt report.pdf.pqfe report.pdf
```

The source lives at [`samples/Pqfe.Cli`](samples/Pqfe.Cli) and is built on the public
API. It's also the canary that proves `IsAotCompatible=true` end-to-end: CI publishes it
with `PublishAot=true` and round-trips a real file as the smoke test.

```bash
# Run from source via dotnet:
PQFE_PASS='correct horse battery staple' \
  dotnet run -c Release --project samples/Pqfe.Cli -- \
  encrypt report.pdf report.pdf.pqfe --argon2id --passphrase-env PQFE_PASS

# Or publish a single-file native binary:
dotnet publish samples/Pqfe.Cli -c Release -p:PublishAot=true -o ./bin
./bin/pqfe --help
```

### 2. Browser demo — fully client-side (Rust → WebAssembly)

[`samples/pqfe-web`](samples/pqfe-web) is a static page whose **file never leaves your
browser**: a small Rust core compiled to WebAssembly does passphrase-based AES-256-GCM
locally. It's hostable on **GitHub Pages** with no server (see the
[Pages workflow](.github/workflows/pages.yml)).

```bash
cd samples/pqfe-wasm
rustup target add wasm32-unknown-unknown
wasm-pack build --target web --release --out-dir ../pqfe-web/pkg
cd ../pqfe-web && python3 -m http.server 8080   # open http://localhost:8080
```

This Rust core is an independent re-implementation of the format, kept **byte-compatible**
with the .NET library: the Rust tests decrypt the .NET known-answer vectors, and the .NET
tests decrypt a Rust-produced container (`CrossImplementationTests`). A file encrypted in
the browser opens with the library, and vice versa.

### 3. .NET demo — runs the real library (Blazor Server)

[`samples/PostQuantum.FileEncryption.Demo`](samples/PostQuantum.FileEncryption.Demo)
exercises the actual library through a web UI. Files are processed **in memory and never
written to disk**.

```bash
dotnet run --project samples/PostQuantum.FileEncryption.Demo
# then open the printed http://localhost:<port> URL
```

It's a **Blazor Server** app on purpose: .NET's `AesGcm` is unsupported in browser
WebAssembly, so the cryptography runs on the server runtime. (The browser demo above
sidesteps this with the Rust/WASM core.)

---

## Usage

### Quick start — encrypt some bytes in memory

```csharp
using PostQuantum.FileEncryption;

byte[] secret    = "meet me at dawn"u8.ToArray();
byte[] container = await new PqFileEncryptor().EncryptBytesAsync(secret, "correct horse battery staple");
byte[] recovered = await new PqFileDecryptor().DecryptBytesAsync(container, "correct horse battery staple");
// recovered.SequenceEqual(secret) == true
```

That's the whole happy path. Everything below is the same idea for files, streams, and
options.

### Encrypt and decrypt a file with a passphrase

```csharp
using PostQuantum.FileEncryption;

await new PqFileEncryptor().EncryptFileAsync("report.pdf", "report.pdf.pqfe", "correct horse battery staple");
await new PqFileDecryptor().DecryptFileAsync("report.pdf.pqfe", "report.restored.pdf", "correct horse battery staple");
```

### Use Argon2id instead of PBKDF2

```csharp
// Quickest — preset with OWASP-recommended defaults:
await new PqFileEncryptor(PqEncryptionOptions.Argon2id)
    .EncryptFileAsync("in", "out.pqfe", passphrase);

// Or tune the work factor (returns a new options instance — leave the others as-is):
var stronger = PqEncryptionOptions.Default.WithArgon2id(memoryKiB: 64 * 1024);
await new PqFileEncryptor(stronger).EncryptFileAsync("in", "out.pqfe", passphrase);

// Decryption needs no options — the KDF and its parameters travel in the container header.
await new PqFileDecryptor().DecryptFileAsync("out.pqfe", "in.copy", passphrase);
```

`PqEncryptionOptions` is immutable; `WithArgon2id`, `WithPbkdf2`, and `WithChunkSize` each
return a new instance with the requested change and the rest carried through, so you can
compose them without re-stating every field.

### Public-key encryption — use `PostQuantum.FileEncryption.Hybrid`

```csharp
using PostQuantum.FileEncryption.Hybrid;

// Recipient generates a key pair once:
using var keyPair = PqHybridKeyPair.Generate();
byte[] publish = keyPair.PublicKey.Export();   // share this freely

// Sender encrypts to the public key — X25519 + ML-KEM-768 combined:
var recipient = PqHybridPublicKey.Import(publish);
byte[] container = await new PqHybridEncryptor().EncryptBytesAsync(secret, recipient);

// Only the holder of the private key can decrypt:
byte[] plaintext = await new PqHybridDecryptor().DecryptBytesAsync(container, keyPair.PrivateKey);
```

The Hybrid package supports **multiple recipients** in a single container and a **hybrid
combiner** that keeps the content key safe if either X25519 or ML-KEM is later broken. See
[Post-quantum & the upgrade path](#post-quantum--the-upgrade-path) below.

> The inline ML-KEM-768-only recipient overloads on `PqFileEncryptor`/`PqFileDecryptor` in
> the core package are **deprecated (`PQFE002`)** and retained for source-compatibility
> only. Migrate to the Hybrid package shown above.

### Streams

```csharp
await using var source = File.OpenRead("video.mp4");
await using var sink   = File.Create("video.mp4.pqfe");
await new PqFileEncryptor().EncryptAsync(source, sink, passphrase);
```

### Zeroable passphrase (bytes you control)

```csharp
byte[] passphrase = GetPassphraseUtf8Bytes();
try
{
    await new PqFileEncryptor().EncryptFileAsync("in", "out.pqfe", passphrase); // ReadOnlyMemory<byte> overload
}
finally
{
    System.Security.Cryptography.CryptographicOperations.ZeroMemory(passphrase);
}
```

### Synchronous span overload (no async, stack-friendly)

```csharp
// Useful in CLIs and tight loops; the span is UTF-8 encoded into a temporary buffer
// that is zeroed before this method returns. True sync code path — no deadlock surface.
byte[] container = new PqFileEncryptor().EncryptBytes(plaintext, "correct horse battery staple".AsSpan());
byte[] plaintext = new PqFileDecryptor().DecryptBytes(container, "correct horse battery staple".AsSpan());
```

### Report progress

```csharp
var progress = new Progress<PqProgress>(p =>
    Console.WriteLine($"{p.Fraction:P0} ({p.BytesProcessed:N0} bytes)"));
await new PqFileEncryptor().EncryptFileAsync("big.iso", "big.iso.pqfe", passphrase, progress);
```

### Handle failure (fail-closed)

```csharp
try
{
    await new PqFileDecryptor().DecryptFileAsync("in.pqfe", "out.bin", passphrase);
}
catch (PqDecryptionException) { /* wrong key, or altered/corrupted/truncated — no output written */ }
catch (PqFormatException)     { /* not a PostQuantum.FileEncryption container at all */ }
```

Every authentication failure raises the same generic `PqDecryptionException` with the same
message — the library never tells an attacker *why* decryption failed, so it can never act
as a decryption oracle.

### All-or-nothing stream decryption

```csharp
// Writes to `output` only if the WHOLE container authenticates — nothing on a truncated input.
await new PqFileDecryptor().DecryptAtomicAsync(input, output, passphrase);
```

### Envelope encryption (KMS / HSM)

Encrypt under an external key provider so the master key never enters your process. A
built-in, dependency-free local-KEK provider is included; cloud providers (AWS KMS, Azure
Key Vault, …) implement the same `IContentKeyProvider` interface in separate packages — see
the [`1.x` minor roadmap](ROADMAP.md#after-10--1x-minor-work).

```csharp
using var provider = LocalKekContentKeyProvider.Generate();   // or new(kek), or a KMS-backed provider
byte[] container = await new PqFileEncryptor().EncryptBytesAsync(secret, provider);
byte[] plaintext = await new PqFileDecryptor().DecryptBytesAsync(container, provider);
```

See [docs/KEY-MANAGEMENT.md](docs/KEY-MANAGEMENT.md).

### Telemetry (SIEM / OpenTelemetry)

The library emits non-sensitive events on an `EventSource` named
`PostQuantum.FileEncryption` (operation, KDF/key-source label, byte counts, elapsed time,
failure category — **never** keys or plaintext). Subscribe via `EventListener`,
`dotnet-trace`, EventPipe, or OpenTelemetry. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

---

## Security posture

PostQuantum.FileEncryption is built to be **boring and predictable** where it matters:

- **Authenticated encryption everywhere.** Every chunk is sealed with AES-256-GCM. The
  header (key-establishment parameters, chunk size) and each chunk's ordinal position and
  final-chunk marker are bound into the authenticated additional data, so reordering,
  splicing, header tampering, and truncation are all detected as authentication failures.
- **Hybrid KEM-DEM for public-key recipients.** The Hybrid package combines X25519 and
  ML-KEM-768 (FIPS 203) via HKDF-SHA256 to derive a key-wrapping key; AES-256-GCM wraps a
  fresh random content key. The data itself is always AES-256-GCM.
- **Unique nonces by construction**, **fresh key material per file**, and **no decryption
  oracle** — every authentication failure raises the same generic `PqDecryptionException`.
- **Bounded work on untrusted input.** KDF cost parameters read from a container are
  range-checked, so a malicious header cannot force unbounded memory or CPU.
- **Key hygiene.** Derived keys, wrapped secrets, and private keys are zeroed with
  `CryptographicOperations.ZeroMemory`.
- **No novel cryptography.** Primitives come from .NET's `System.Security.Cryptography`,
  the Konscious Argon2id implementation, and BouncyCastle (for the Hybrid package); this
  library only composes them in standard patterns.

For deeper references:

- [SECURITY.md](SECURITY.md) — supported versions, disclosure process, and the explicit
  *"does NOT defend against"* list
- [KNOWN-GAPS.md](KNOWN-GAPS.md) — the honest open-issues ledger
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — assets, adversaries, trust boundaries
- [docs/FILE-FORMAT.md](docs/FILE-FORMAT.md) — the on-disk container specification
- [docs/HYBRID-COMBINER.md](docs/HYBRID-COMBINER.md) — the X25519 + ML-KEM-768 combiner,
  vs. X-Wing / HPKE / RFC 9794
- [docs/CONFORMANCE.md](docs/CONFORMANCE.md) — the contract another implementation must meet
- [docs/TEST-VECTORS.md](docs/TEST-VECTORS.md) — pinned known-answer vectors

> Cryptographic software earns trust slowly. This library has **not been independently
> audited**; please review the code, the format, and [KNOWN-GAPS.md](KNOWN-GAPS.md) before
> depending on it. Funded audit engagements are welcome — contact the maintainer.
> A criteria-by-criteria self-assessment — including what's still missing — is published
> at [docs/GOLD-STANDARD.md](docs/GOLD-STANDARD.md).

---

## Post-quantum & the upgrade path

Be clear-eyed about what *post-quantum* means here today:

- **What's stable now:** the symmetric, passphrase-based engine. AES-256 is
  quantum-resistant for the *confidentiality of your data* (≈128-bit security under
  Grover), so a passphrase-encrypted file is sound against a harvest-now-decrypt-later
  adversary. This is the engine being finalized for `1.0`.
- **What's the recommended public-key path:** the **`PostQuantum.FileEncryption.Hybrid`**
  package — a **hybrid X25519 + ML-KEM-768 combiner** plus **multiple recipients**. Fully
  managed (BouncyCastle for *both* primitives), so it runs **anywhere** with no native
  ML-KEM requirement, and the content key stays safe if *either* X25519 or ML-KEM is later
  broken.
- **What's deprecated:** the inline ML-KEM-768-only recipient mode in the **core**
  (`PqKeyPair`, `PqRecipientPublicKey`, `PqRecipientPrivateKey`, recipient overloads on
  `PqFileEncryptor`/`PqFileDecryptor`). Marked `[Obsolete]` with diagnostic id `PQFE002`
  since `1.0.0-rc.2`, kept for source-compatibility only. Migrate to the Hybrid package.

```bash
dotnet add package PostQuantum.FileEncryption.Hybrid --version 1.0.1
```

```csharp
using PostQuantum.FileEncryption.Hybrid;

using var keyPair = PqHybridKeyPair.Generate();        // recipient
byte[] publish = keyPair.PublicKey.Export();

var recipient = PqHybridPublicKey.Import(publish);     // sender
byte[] container = await new PqHybridEncryptor().EncryptBytesAsync(secret, recipient);

byte[] plaintext = await new PqHybridDecryptor().DecryptBytesAsync(container, keyPair.PrivateKey);
```

Design and format details: [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md).

---

## Supply chain & verification

Every release tag attaches a CycloneDX SBOM and a SLSA-style build-provenance attestation
to the `.nupkg` artifacts. The release workflow runs
`Meziantou.Framework.NuGetPackageValidation` against every produced `.nupkg` *before*
`nuget push`, with the strict icon-must-be-set rule enabled. Coverage-guided fuzzers
(cargo-fuzz + SharpFuzz) run nightly against both parsers with a cached corpus.

Quick verification of any release:

```bash
# Verify the build-provenance attestation on a downloaded .nupkg:
gh attestation verify PostQuantum.FileEncryption.1.0.1.nupkg \
  --owner systemslibrarian

# Inspect the CycloneDX SBOM bundled with the release:
gh release download v1.0.1 -p 'sbom.core.cdx.json' && jq . sbom.core.cdx.json

# Confirm the conformance vectors decrypt locally:
dotnet test --filter "FullyQualifiedName~KnownAnswerVector|FullyQualifiedName~CrossImplementation"
```

The full verification recipe — including how to re-run conformance vectors against the
Rust/WASM reference implementation — is in [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md).

---

## Documentation

| Topic | Doc |
| --- | --- |
| Roadmap (`1.0` / `1.x` / beyond) | [ROADMAP.md](ROADMAP.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |
| Migrating from other libraries (age / libsodium / OpenSSL / .NET) | [docs/MIGRATION.md](docs/MIGRATION.md) |
| Comparison vs. age / libsodium / OpenSSL | [docs/COMPARISON.md](docs/COMPARISON.md) |
| Benchmarks (methodology + reproduce-it-yourself) | [docs/BENCHMARKS.md](docs/BENCHMARKS.md) |
| Security policy & disclosure | [SECURITY.md](SECURITY.md) |
| Threat model (assets, adversaries, audit focus) | [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) |
| Security architecture & crypto inventory (+ FIPS) | [docs/SECURITY-ARCHITECTURE.md](docs/SECURITY-ARCHITECTURE.md) |
| On-disk container format | [docs/FILE-FORMAT.md](docs/FILE-FORMAT.md) |
| Hybrid combiner rationale (vs. X-Wing, HPKE, RFC 9794) | [docs/HYBRID-COMBINER.md](docs/HYBRID-COMBINER.md) |
| Conformance spec (re-implementer's contract) | [docs/CONFORMANCE.md](docs/CONFORMANCE.md) |
| Known-answer test vectors | [docs/TEST-VECTORS.md](docs/TEST-VECTORS.md) |
| Supply chain (SBOM, attestations, verification) | [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md) |
| Gold-standard self-assessment (incl. open gaps) | [docs/GOLD-STANDARD.md](docs/GOLD-STANDARD.md) |
| Reproducible builds (verify the .nupkg against the source) | [docs/REPRODUCIBLE-BUILDS.md](docs/REPRODUCIBLE-BUILDS.md) |
| Deployment & hardening | [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) |
| Versioning & compatibility policy | [docs/VERSIONING.md](docs/VERSIONING.md) |
| Key management (KMS/HSM, rotation) — design | [docs/KEY-MANAGEMENT.md](docs/KEY-MANAGEMENT.md) |
| Hybrid & multi-recipient — design | [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md) |
| Fuzzing (cargo-fuzz + SharpFuzz + OSS-Fuzz) | [docs/FUZZING.md](docs/FUZZING.md) |
| Known gaps (the honest ledger) | [KNOWN-GAPS.md](KNOWN-GAPS.md) |
| Support & lifecycle | [SUPPORT.md](SUPPORT.md) · Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) |

API reference (DocFX) is generated from the XML docs — see `docfx/`.

---

## Performance

Throughput is dominated by two things: the **AES-256-GCM data plane** (which uses hardware
AES and runs at multiple GB/s) and a **one-time key derivation** per file (a deliberate
cost that hardens passphrases). The bigger the file, the more the KDF amortizes.

Indicative end-to-end numbers (16 MiB, *including* one KDF derivation), measured with the
included BenchmarkDotNet project on a shared GitHub Codespace — treat as rough, not
lab-grade:

| Operation | KDF | Approx. throughput |
| --------- | --- | ------------------ |
| Encrypt   | PBKDF2 (100k) | ~210 MiB/s |
| Decrypt   | PBKDF2 (100k) | ~300 MiB/s |
| Encrypt   | Argon2id (8 MiB, 1 pass) | ~390 MiB/s |
| Decrypt   | Argon2id (8 MiB, 1 pass) | ~450 MiB/s |

Run it yourself (and tune the KDF cost):

```bash
dotnet run -c Release --project benchmarks/PostQuantum.FileEncryption.Benchmarks -- --filter '*'
```

The default PBKDF2 cost is 600,000 iterations (OWASP), so small files are KDF-bound by
design; raise/lower it (or pick Argon2id) via `PqEncryptionOptions` to trade hardening for
speed.

Full methodology, hybrid/multi-recipient numbers, and how to compare fairly against
other tools: [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

---

## Project layout

```
src/        PostQuantum.FileEncryption        — the library (symmetric core)
src/        PostQuantum.FileEncryption.Hybrid — X25519 + ML-KEM-768 hybrid public-key package
src/        PostQuantum.FileEncryption.Extensions.DependencyInjection — IServiceCollection integration
tests/      PostQuantum.FileEncryption.Tests  — round-trip, KDF, recipient, hybrid, known-answer, cross-impl, property, fuzz tests
benchmarks/ PostQuantum.FileEncryption.Benchmarks — BenchmarkDotNet throughput suite
samples/    Pqfe.Cli                           — minimal CLI (encrypt/decrypt; AOT-publishable)
samples/    PostQuantum.FileEncryption.Demo   — .NET demo (Blazor Server, runs the library)
samples/    pqfe-wasm                          — Rust → WASM re-implementation of the .pqfe format
samples/    pqfe-web                           — fully client-side browser demo (GitHub Pages)
docs/       *.md                               — format spec, threat model, test vectors, roadmap, supply chain, migration
```

### Why Blazor Server?

A pure client-side WebAssembly demo would be lovely — files would never leave the browser
— but .NET's `AesGcm` is annotated `[UnsupportedOSPlatform("browser")]` and throws in
WebAssembly. Rather than ship a demo that breaks the moment you click *Encrypt*, or quietly
swap in a different (non-library) cipher, the .NET demo runs as **Blazor Server** so the
real library performs the encryption on the server runtime. Uploaded bytes are held in
memory only and are never persisted. The browser demo (`samples/pqfe-web`) sidesteps the
problem with a Rust/WASM core that re-implements the format byte-compatibly.

---

## Building from source

```bash
dotnet build -c Release
dotnet test  -c Release
dotnet pack  src/PostQuantum.FileEncryption -c Release
```

## License

[MIT](LICENSE).

---

*To God be the glory — 1 Corinthians 10:31.*
