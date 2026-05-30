# PostQuantum.FileEncryption

**A high-level, delightful, fail-closed way to encrypt files and streams on .NET.**

PostQuantum.FileEncryption gives you two friendly classes — `PqFileEncryptor` and
`PqFileDecryptor` — that handle authenticated, chunked, streaming encryption with strong,
modern defaults. You should not have to read a cryptographic spec to protect a file. You
just call a method, and the library does the careful, paranoid, fail-closed thing every
time.

> **Status: `0.1.0` — first release.** The **symmetric, passphrase-based engine is
> production-ready** and thoroughly tested. This is a `0.x` release, so the on-disk format may
> still change before `1.0` — don't archive data you must read with a future major version yet.
> Post-quantum *public-key* (recipient) encryption is **experimental** — see
> [Post-quantum & the upgrade path](#post-quantum--the-upgrade-path) and
> [KNOWN-GAPS.md](KNOWN-GAPS.md).

---

## ▶ Try the demo

Two demos, same `.pqfe` format — pick whichever fits:

### 1. Browser demo — fully client-side (Rust → WebAssembly)

[`samples/pqfe-web`](samples/pqfe-web) is a static page whose **file never leaves your
browser**: a small Rust core compiled to WebAssembly does passphrase-based **AES-256-GCM**
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
tests decrypt a Rust-produced container (`CrossImplementationTests`). So a file encrypted in
the browser opens with the library, and vice versa.

### 2. .NET demo — runs the real library (Blazor Server)

[`samples/PostQuantum.FileEncryption.Demo`](samples/PostQuantum.FileEncryption.Demo) exercises
the actual library through a web UI. Files are processed **in memory and never written to disk**.

```bash
dotnet run --project samples/PostQuantum.FileEncryption.Demo
# then open the printed http://localhost:<port> URL
```

It's a **Blazor Server** app on purpose: .NET's AES-GCM is unsupported in browser WebAssembly,
so the cryptography runs on the server runtime. (See ["Why Blazor Server?"](#why-blazor-server)
— and note the browser demo above sidesteps this with a Rust/WASM core.)

---

## What it does

The **stable core is a symmetric, passphrase-based file encryptor**. Post-quantum *public-key*
encryption is on the roadmap as a separate package — see
[Post-quantum & the upgrade path](#post-quantum--the-upgrade-path) below.

- **Passphrase-based encryption** (the stable, recommended path) with your choice of
  key-derivation function:
  - **PBKDF2-HMAC-SHA256** (default, no extra cost), 600,000 iterations.
  - **Argon2id** (memory-hard, opt-in), defaulting to OWASP's 19 MiB / 2-pass setting.
- **AES-256-GCM** for all data encryption — an authenticated cipher whose 256-bit key stays
  strong against a quantum adversary (Grover's algorithm only halves the effective strength).
- **Chunked streaming** so you can encrypt a 50 GB file with bounded memory — with optional
  **progress reporting**.
- **Fail-closed by construction.** A wrong key, a flipped bit, a spliced or truncated
  container, a hostile header demanding gigabytes of KDF memory — all rejected with a
  `PqEncryptionException`, and no plaintext is ever written to your destination.
- **Atomic file output.** File operations write to a temporary sibling file and are moved
  into place only on full success.
- **Zeroable secrets.** Passphrases can be passed as bytes you control and zero yourself;
  derived keys and private keys are wiped from memory after use.

---

## Install

```bash
dotnet add package PostQuantum.FileEncryption --version 0.1.0
```

Targets **.NET 10** (`net10.0`). Depends on `Konscious.Security.Cryptography.Argon2` for the
Argon2id KDF; everything else is from .NET's `System.Security.Cryptography`.

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

That's the whole happy path. Everything below is the same idea for files, streams, and options.

### Encrypt and decrypt a file with a passphrase

```csharp
using PostQuantum.FileEncryption;

await new PqFileEncryptor().EncryptFileAsync("report.pdf", "report.pdf.pqfe", "correct horse battery staple");
await new PqFileDecryptor().DecryptFileAsync("report.pdf.pqfe", "report.restored.pdf", "correct horse battery staple");
```

### Use Argon2id instead of PBKDF2

```csharp
var options = new PqEncryptionOptions { Kdf = PqKdf.Argon2id }; // memory-hard
await new PqFileEncryptor(options).EncryptFileAsync("in", "out.pqfe", passphrase);
// Decryption needs no options — the KDF and its parameters travel in the container header.
await new PqFileDecryptor().DecryptFileAsync("out.pqfe", "in.copy", passphrase);
```

### Encrypt to a recipient's public key (experimental, post-quantum KEM)

> **Experimental & platform-gated.** ML-KEM-768 recipient mode runs only where the platform
> provides ML-KEM (.NET 10 with OpenSSL 3.5+ or Windows CNG); guard with `PqKeyPair.IsSupported`.
> It is **not** part of the stable symmetric surface — the productionized public-key path
> (hybrid X25519 + ML-KEM, multiple recipients) is planned for the separate
> `PostQuantum.FileEncryption.Hybrid` package. See
> [Post-quantum & the upgrade path](#post-quantum--the-upgrade-path).

```csharp
if (PqKeyPair.IsSupported)
{
    using var keyPair = PqKeyPair.Generate();      // the recipient does this once
    byte[] publish   = keyPair.PublicKey.Export(); // share this freely

    // Anyone with the public key can encrypt:
    var recipient = PqRecipientPublicKey.Import(publish);
    await new PqFileEncryptor().EncryptFileAsync("secret.bin", "secret.pqfe", recipient);

    // Only the holder of the private key can decrypt:
    await new PqFileDecryptor().DecryptFileAsync("secret.pqfe", "secret.out", keyPair.PrivateKey);
}
```

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

### All-or-nothing stream decryption

```csharp
// Writes to `output` only if the WHOLE container authenticates — nothing on a truncated input.
await new PqFileDecryptor().DecryptAtomicAsync(input, output, passphrase);
```

### Envelope encryption (KMS / HSM)

Encrypt under an external key provider so the master key never enters your process. A built-in,
dependency-free local-KEK provider is included; cloud providers (AWS KMS, Azure Key Vault, …)
implement the same `IContentKeyProvider` interface in separate packages.

```csharp
using var provider = LocalKekContentKeyProvider.Generate();   // or new(kek), or a KMS-backed provider
byte[] container = await new PqFileEncryptor().EncryptBytesAsync(secret, provider);
byte[] plaintext = await new PqFileDecryptor().DecryptBytesAsync(container, provider);
```

See [docs/KEY-MANAGEMENT.md](docs/KEY-MANAGEMENT.md).

### Telemetry (SIEM / OpenTelemetry)

The library emits non-sensitive events on an `EventSource` named `PostQuantum.FileEncryption`
(operation, KDF/key-source label, byte counts, elapsed time, failure category — **never** keys or
plaintext). Subscribe via `EventListener`, `dotnet-trace`, EventPipe, or OpenTelemetry. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

---

## Security posture

PostQuantum.FileEncryption is built to be **boring and predictable** where it matters:

- **Authenticated encryption everywhere.** Every chunk is sealed with AES-256-GCM. The header
  (key-establishment parameters, chunk size) and each chunk's ordinal position and final-chunk
  marker are bound into the authenticated additional data, so reordering, splicing, header
  tampering, and truncation are all detected as authentication failures.
- **Hybrid KEM-DEM for recipients.** ML-KEM-768 encapsulates a shared secret; HKDF-SHA256
  derives a key-wrapping key; AES-256-GCM wraps a fresh random content key. The data itself is
  always AES-256-GCM.
- **Unique nonces by construction**, **fresh key material per file**, and **no decryption
  oracle** — every authentication failure raises the same generic `PqDecryptionException`.
- **Bounded work on untrusted input.** KDF cost parameters read from a container are range-
  checked, so a malicious header cannot force unbounded memory or CPU.
- **Key hygiene.** Derived keys, wrapped secrets, and private keys are zeroed with
  `CryptographicOperations.ZeroMemory`.
- **No novel cryptography.** Primitives come from .NET's `System.Security.Cryptography` and the
  Konscious Argon2id implementation; this library only composes them.

For the reporting process and current limitations, read [SECURITY.md](SECURITY.md) and
[KNOWN-GAPS.md](KNOWN-GAPS.md). Deeper references:

- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — assets, adversaries, trust boundaries, and what an audit should focus on
- [docs/FILE-FORMAT.md](docs/FILE-FORMAT.md) — the on-disk container specification
- [docs/TEST-VECTORS.md](docs/TEST-VECTORS.md) — pinned known-answer vectors (cross-checked by both implementations)
- [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md) — design for the hybrid combiner and multi-recipient mode

> Cryptographic software earns trust slowly. This is a preview, and it has **not** been
> independently audited. Please review the code, the format, and the gaps before depending on it.

---

## Post-quantum & the upgrade path

Be clear-eyed about what "post-quantum" means here today:

- **What's stable now:** the symmetric, passphrase-based engine. AES-256 is quantum-resistant
  for the *confidentiality of your data* (≈128-bit security under Grover), so a passphrase-
  encrypted file is sound against a harvest-now-decrypt-later adversary. This is the engine
  being finalized for release.
- **What's experimental:** an ML-KEM-768-only recipient mode in the **core**, platform-gated
  (needs native ML-KEM) and not part of the stable surface.
- **What's shipped for public-key:** the **`PostQuantum.FileEncryption.Hybrid`** package — a
  **hybrid X25519 + ML-KEM-768 combiner** plus **multiple recipients**. It's fully managed
  (BouncyCastle for *both* primitives), so it runs **anywhere** with no native ML-KEM
  requirement, and the content key stays safe if *either* X25519 or ML-KEM is later broken.

```bash
dotnet add package PostQuantum.FileEncryption.Hybrid --version 0.1.0
```

```csharp
using PostQuantum.FileEncryption.Hybrid;

using var keyPair = PqHybridKeyPair.Generate();        // recipient
byte[] publish = keyPair.PublicKey.Export();

var recipient = PqHybridPublicKey.Import(publish);     // sender
byte[] container = await new PqHybridEncryptor().EncryptBytesAsync(secret, recipient);

byte[] plaintext = await new PqHybridDecryptor().DecryptBytesAsync(container, keyPair.PrivateKey);
```

So: passphrase encryption is the stable core; **hybrid public-key encryption is available now**
via the Hybrid package; the core's ML-KEM-only recipient mode remains experimental. Design and
format details: [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md).

---

## Documentation

| Topic | Doc |
| --- | --- |
| Roadmap (now / v0.2 / v0.3 / 1.0) | [ROADMAP.md](ROADMAP.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |
| Security policy & disclosure | [SECURITY.md](SECURITY.md) |
| Threat model (assets, adversaries, audit focus) | [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) |
| Security architecture & crypto inventory (+ FIPS) | [docs/SECURITY-ARCHITECTURE.md](docs/SECURITY-ARCHITECTURE.md) |
| On-disk container format | [docs/FILE-FORMAT.md](docs/FILE-FORMAT.md) |
| Known-answer test vectors | [docs/TEST-VECTORS.md](docs/TEST-VECTORS.md) |
| Deployment & hardening | [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) |
| Versioning & compatibility policy | [docs/VERSIONING.md](docs/VERSIONING.md) |
| Key management (KMS/HSM, rotation) — design | [docs/KEY-MANAGEMENT.md](docs/KEY-MANAGEMENT.md) |
| Hybrid & multi-recipient — design | [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md) |
| Fuzzing (cargo-fuzz + SharpFuzz + OSS-Fuzz) | [docs/FUZZING.md](docs/FUZZING.md) |
| Known gaps (the honest ledger) | [KNOWN-GAPS.md](KNOWN-GAPS.md) |
| Comparison vs age / libsodium / OpenSSL | [docs/COMPARISON.md](docs/COMPARISON.md) |
| Support & lifecycle | [SUPPORT.md](SUPPORT.md) · Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) |

API reference (DocFX) is generated from the XML docs — see `docfx/`.

---

## Performance

Throughput is dominated by two things: the **AES-256-GCM data plane** (which uses hardware AES
and runs at multiple GB/s) and a **one-time key derivation** per file (a deliberate cost that
hardens passphrases). The bigger the file, the more the KDF amortizes.

Indicative end-to-end numbers (16 MiB, *including* one KDF derivation), measured with the
included BenchmarkDotNet project on a shared GitHub Codespace — treat as rough, not lab-grade:

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

The default PBKDF2 cost is 600,000 iterations (OWASP), so small files are KDF-bound by design;
raise/lower it (or pick Argon2id) via `PqEncryptionOptions` to trade hardening for speed.

---

## Project layout

```
src/        PostQuantum.FileEncryption        — the library (symmetric core)
src/        PostQuantum.FileEncryption.Hybrid — X25519 + ML-KEM-768 hybrid public-key package
tests/      PostQuantum.FileEncryption.Tests  — round-trip, KDF, recipient, hybrid, known-answer, cross-impl, property, fuzz tests
benchmarks/ PostQuantum.FileEncryption.Benchmarks — BenchmarkDotNet throughput suite
samples/    PostQuantum.FileEncryption.Demo   — .NET demo (Blazor Server, runs the library)
samples/    pqfe-wasm                          — Rust → WASM re-implementation of the .pqfe format
samples/    pqfe-web                           — fully client-side browser demo (GitHub Pages)
docs/       *.md                               — format spec, threat model, test vectors, roadmap, and more
```

### Why Blazor Server?

A pure client-side WebAssembly demo would be lovely — files would never leave the browser —
but .NET's `AesGcm` is annotated `[UnsupportedOSPlatform("browser")]` and throws in
WebAssembly. Rather than ship a demo that breaks the moment you click *Encrypt*, or quietly
swap in a different (non-library) cipher, the demo runs as **Blazor Server** so the real
library performs the encryption on the server runtime. Uploaded bytes are held in memory only
and are never persisted. A fully client-side build would require a browser-native crypto core
(WebCrypto or a WASM crypto module) that re-implements this container format — tracked as a
possible future sample in [KNOWN-GAPS.md](KNOWN-GAPS.md).

## Building from source

```bash
dotnet build -c Release
dotnet test  -c Release
```

## License

[MIT](LICENSE).

---

*To God be the glory — 1 Corinthians 10:31.*
