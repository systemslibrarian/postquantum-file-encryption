# PostQuantum.FileEncryption.Hybrid

Post-quantum **hybrid public-key** encryption for
[PostQuantum.FileEncryption](https://www.nuget.org/packages/PostQuantum.FileEncryption): encrypt
files to a recipient's public key so that only their private key can open them — protected by
**X25519 + ML-KEM-768** together, so your data stays safe even if *either* primitive is later
broken.

Fully managed (BouncyCastle) — **no native ML-KEM / OpenSSL 3.5 requirement**, so it runs anywhere
.NET 10 runs. Produces standard `.pqfe` containers.

```bash
dotnet add package PostQuantum.FileEncryption.Hybrid --version 0.1.0
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
