# PostQuantum.FileEncryption.Gcp

**Envelope encryption with Google Cloud KMS — your master key never leaves Google Cloud.**
`GcpKmsContentKeyProvider` plugs Cloud KMS into
[PostQuantum.FileEncryption](https://www.nuget.org/packages/PostQuantum.FileEncryption)'s
`IContentKeyProvider` seam: every file is encrypted under a fresh per-file content key that
Cloud KMS `Encrypt` wraps under your key-ring key; decryption sends only the small wrapped
blob back to Cloud KMS `Decrypt`.

```bash
dotnet add package PostQuantum.FileEncryption.Gcp
```

## Usage

```csharp
using Google.Cloud.Kms.V1;
using PostQuantum.FileEncryption;
using PostQuantum.FileEncryption.Gcp;

var kms = await KeyManagementServiceClient.CreateAsync();   // credentials from Application Default Credentials
var provider = new GcpKmsContentKeyProvider(kms,
    "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-app-key");

await new PqFileEncryptor().EncryptFileAsync("report.pdf", "report.pdf.pqfe", provider);
await new PqFileDecryptor().DecryptFileAsync("report.pdf.pqfe", "report.pdf", provider);
```

Optionally bind extra **additional authenticated data** (required to unwrap):

```csharp
var provider = new GcpKmsContentKeyProvider(kms, cryptoKeyName,
    Encoding.UTF8.GetBytes("tenant=contoso"));
```

## Security behavior

- **The master key stays in Cloud KMS.** Cloud KMS has no server-side data-key generation,
  so the per-file content key is generated locally and crosses the boundary once, for
  wrapping — the same envelope pattern Google's Tink library uses. Rotation re-wraps the
  small content key — multi-gigabyte payloads are never re-encrypted — and unwrap works
  across key rotation because the ciphertext itself names the `CryptoKeyVersion`.
- **Bound wraps.** Every wrap carries library-specific additional authenticated data (plus
  your bytes), and unwrap targets only the configured `CryptoKey` — a blob wrapped under a
  different key or AAD fails closed with `PqDecryptionException`, indistinguishable from
  tampering.
- **CRC32C end to end.** The integrity checksums Cloud KMS offers are populated on every
  request and verified on every response (the .NET SDK does not do this for you); a
  mismatch fails the operation instead of trusting a corrupted round-trip.
- **Operational errors stay operational.** Missing keys, permission denial, throttling, and
  network failures surface as the gRPC/SDK's own exceptions, not as decryption failures.
- IAM permission needed: `cloudkms.cryptoKeyVersions.useToEncrypt` to encrypt,
  `cloudkms.cryptoKeyVersions.useToDecrypt` to decrypt (both in
  `roles/cloudkms.cryptoKeyEncrypterDecrypter`).

## Versioning

Kept in **lockstep** with `PostQuantum.FileEncryption`. No change to the `.pqfe` v2 container
format, which remains **FROZEN** for the `1.x` line.

---

*To God be the glory — 1 Corinthians 10:31.*
