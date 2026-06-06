# PostQuantum.FileEncryption.Hybrid

**The single recommended path for public-key file encryption in this suite.** Encrypt files
to a recipient's public key so that only their private key can open them — protected by
**X25519 + ML-KEM-768** together, so your data stays safe even if *either* primitive is
later broken.

Fully managed (BouncyCastle) — **no native ML-KEM / OpenSSL 3.5 requirement**, so it runs anywhere
.NET 10 runs. Produces standard `.pqfe` containers.

```bash
dotnet add package PostQuantum.FileEncryption.Hybrid --version 1.0.1
```

> **Versioning.** This package is intentionally kept in **lockstep** with
> `PostQuantum.FileEncryption`: every release of one ships at the same version as the
> other, and Hybrid's pack pins the matching core version. The two packages are one
> cryptographic unit — the core owns the `.pqfe` container and the chunk/AEAD engine;
> Hybrid plugs into the core's `KeyEstablishment` seam to add the public-key path. A
> version mismatch would mean Hybrid is talking to a different format/engine than the one
> it was designed against. See
> [docs/VERSIONING.md](https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/docs/VERSIONING.md#suite-versioning--hybrid-lockstep-with-core).

## Migrating from the deprecated inline ML-KEM-only mode

If you previously used `PqKeyPair` / `PqRecipientPublicKey` / `PqRecipientPrivateKey` and the
recipient overloads on `PqFileEncryptor` / `PqFileDecryptor` in the core
`PostQuantum.FileEncryption` package, those are **deprecated** (`PQFE002`) as of `1.0.0-rc.2`.
They remain for source-compatibility but emit a deprecation warning; removal is targeted for
a future major release.

```csharp
// Before (deprecated PQFE001 + PQFE002 in the core package, platform-gated by ML-KEM):
using var keyPair = PqKeyPair.Generate();
await new PqFileEncryptor().EncryptFileAsync("plain.bin", "cipher.pqfe", keyPair.PublicKey);
await new PqFileDecryptor().DecryptFileAsync("cipher.pqfe", "out.bin", keyPair.PrivateKey);

// After (this package — hybrid combiner, runs everywhere, no platform gate):
using var keyPair = PqHybridKeyPair.Generate();
await new PqHybridEncryptor().EncryptFileAsync("plain.bin", "cipher.pqfe", keyPair.PublicKey);
await new PqHybridDecryptor().DecryptFileAsync("cipher.pqfe", "out.bin", keyPair.PrivateKey);
```

## Usage

```csharp
using PostQuantum.FileEncryption.Hybrid;

// Recipient: generate once, publish the public key, keep the private key safe.
using var keyPair = PqHybridKeyPair.Generate();
byte[] publish = keyPair.PublicKey.Export();

// Sender: encrypt to the public key.
var recipient = PqHybridPublicKey.Import(publish);
byte[] container = await new PqHybridEncryptor().EncryptBytesAsync(secretBytes, recipient);

// Recipient: decrypt with the private key.
byte[] plaintext = await new PqHybridDecryptor().DecryptBytesAsync(container, keyPair.PrivateKey);
```

### Multiple recipients

```csharp
var recipients = new[] { alice, bob, carol }; // PqHybridPublicKey[]
await new PqHybridEncryptor().EncryptFileToAsync("report.pdf", "report.pqfe", recipients);
// Any one of alice/bob/carol can decrypt with their own private key.
```

File and stream APIs (`EncryptFileAsync`, `EncryptAsync`, `DecryptFileAsync`, `DecryptAsync`) are
also available, with atomic file output and progress reporting.

## How it works

X25519 ECDH and ML-KEM-768 encapsulation each produce a shared secret; HKDF-SHA256 combines them
(`ss_pq ‖ ss_classical`) into a key-wrapping key that AES-256-GCM uses to wrap a random content
key. See [the format spec](https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/docs/FILE-FORMAT.md)
(`KeySource = 3` and `4`) and [docs/ROADMAP-v3.md](https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/docs/ROADMAP-v3.md).

*To God be the glory — 1 Corinthians 10:31.*
