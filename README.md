# PostQuantum.FileEncryption

**A high-level, delightful, fail-closed way to encrypt files and streams on .NET.**

PostQuantum.FileEncryption gives you two friendly classes — `PqFileEncryptor` and
`PqFileDecryptor` — that handle authenticated, chunked, streaming encryption with strong,
modern defaults. You should not have to read a cryptographic spec to protect a file. You
just call a method, and the library does the careful, paranoid, fail-closed thing every
time.

> **Status: `0.2.0-preview.1` — early preview.** The on-disk container format is not yet
> frozen and may change before `1.0`. Do not use this release for data you must be able to
> decrypt with a future version. See [KNOWN-GAPS.md](KNOWN-GAPS.md) for an honest account of
> what is and is not done.

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

## What it does (v0.2)

- **Passphrase-based encryption** with your choice of key-derivation function:
  - **PBKDF2-HMAC-SHA256** (default, no extra cost), 600,000 iterations.
  - **Argon2id** (memory-hard, opt-in), defaulting to OWASP's 19 MiB / 2-pass setting.
- **Recipient (public-key) encryption** using **ML-KEM-768** (FIPS 203) in a hybrid KEM-DEM
  construction — encrypt to someone's public key; only their private key can open it.
  Available where the platform provides ML-KEM (.NET 10 with OpenSSL 3.5+ or Windows CNG);
  gated cleanly with `PqKeyPair.IsSupported`.
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
dotnet add package PostQuantum.FileEncryption --version 0.2.0-preview.1
```

Targets **.NET 10** (`net10.0`). Depends on `Konscious.Security.Cryptography.Argon2` for the
Argon2id KDF; everything else is from .NET's `System.Security.Cryptography`.

---

## Usage

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

### Encrypt to a recipient's public key (post-quantum KEM)

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

For the threat model, reporting process, and current limitations, read
[SECURITY.md](SECURITY.md) and [KNOWN-GAPS.md](KNOWN-GAPS.md). The on-disk format is specified
in [docs/FILE-FORMAT.md](docs/FILE-FORMAT.md).

> Cryptographic software earns trust slowly. This is a preview, and it has **not** been
> independently audited. Please review the code, the format, and the gaps before depending on it.

---

## Project layout

```
src/      PostQuantum.FileEncryption        — the library
tests/    PostQuantum.FileEncryption.Tests  — round-trip, KDF, recipient, known-answer, cross-impl, and fuzz tests
samples/  PostQuantum.FileEncryption.Demo   — .NET demo (Blazor Server, runs the library)
samples/  pqfe-wasm                          — Rust → WASM re-implementation of the .pqfe format
samples/  pqfe-web                           — fully client-side browser demo (GitHub Pages)
docs/     FILE-FORMAT.md                     — the container specification
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
