# PostQuantum.FileEncryption.AzureKeyVault

**Envelope encryption with Azure Key Vault or Managed HSM — the key-encryption key never
leaves the vault.** `AzureKeyVaultContentKeyProvider` plugs Key Vault into
[PostQuantum.FileEncryption](https://www.nuget.org/packages/PostQuantum.FileEncryption)'s
`IContentKeyProvider` seam: every file is encrypted under a fresh per-file content key that
the vault wraps (RSA-OAEP-256 by default); decryption sends only the small wrapped blob back
for unwrap.

```bash
dotnet add package PostQuantum.FileEncryption.AzureKeyVault
```

## Usage

```csharp
using Azure.Identity;
using Azure.Security.KeyVault.Keys.Cryptography;
using PostQuantum.FileEncryption;
using PostQuantum.FileEncryption.AzureKeyVault;

// Prefer a VERSIONED key URI so old files stay decryptable across key rotation.
var client = new CryptographyClient(
    new Uri("https://my-vault.vault.azure.net/keys/pqfe-kek/0123456789abcdef0123456789abcdef"),
    new DefaultAzureCredential());
var provider = new AzureKeyVaultContentKeyProvider(client);

await new PqFileEncryptor().EncryptFileAsync("report.pdf", "report.pdf.pqfe", provider);
await new PqFileDecryptor().DecryptFileAsync("report.pdf.pqfe", "report.pdf", provider);
```

On **Managed HSM** with a symmetric key, pick AES key wrap explicitly:

```csharp
var provider = new AzureKeyVaultContentKeyProvider(client, KeyWrapAlgorithm.A256KW);
```

## Security behavior

- **The key-encryption key stays in the vault/HSM.** Only the per-file content key crosses
  the boundary, and only wrapped. Rotation re-wraps the small content key — multi-gigabyte
  payloads are never re-encrypted.
- **Pinned unwrap.** The wrap records the exact (versioned) key id that produced it; unwrap
  requires it to match the configured client's key and always uses the *configured*
  algorithm — an algorithm or key id smuggled into a hostile container header is never
  honored. Cryptographic failures fail closed with `PqDecryptionException`.
- **Operational errors stay operational.** Authentication, authorization, throttling, and
  network failures surface as the Azure SDK's own exceptions, not as decryption failures.
- Key permissions needed: `wrapKey` to encrypt, `unwrapKey` to decrypt.

## Versioning

Kept in **lockstep** with `PostQuantum.FileEncryption`. No change to the `.pqfe` v2 container
format, which remains **FROZEN** for the `1.x` line.

---

*To God be the glory — 1 Corinthians 10:31.*
