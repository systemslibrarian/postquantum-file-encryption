# PostQuantum.FileEncryption.Aws

**Envelope encryption with AWS KMS — your master key never leaves AWS.**
`AwsKmsContentKeyProvider` plugs AWS KMS into
[PostQuantum.FileEncryption](https://www.nuget.org/packages/PostQuantum.FileEncryption)'s
`IContentKeyProvider` seam: every file is encrypted under a fresh per-file content key that
KMS `GenerateDataKey` wraps under your customer master key; decryption sends only the small
wrapped blob back to KMS `Decrypt`.

```bash
dotnet add package PostQuantum.FileEncryption.Aws
```

## Usage

```csharp
using Amazon.KeyManagementService;
using PostQuantum.FileEncryption;
using PostQuantum.FileEncryption.Aws;

var kms = new AmazonKeyManagementServiceClient();          // credentials from the usual AWS chain
var provider = new AwsKmsContentKeyProvider(kms, "alias/my-app-key");

await new PqFileEncryptor().EncryptFileAsync("report.pdf", "report.pdf.pqfe", provider);
await new PqFileDecryptor().DecryptFileAsync("report.pdf.pqfe", "report.pdf", provider);
```

Optionally bind extra **encryption context** (audited by CloudTrail, required to unwrap):

```csharp
var provider = new AwsKmsContentKeyProvider(kms, "alias/my-app-key",
    new Dictionary<string, string> { ["tenant"] = "contoso" });
```

## Security behavior

- **The master key stays in KMS.** Only the per-file content key crosses the boundary, and
  only wrapped. Rotation re-wraps the small content key — multi-gigabyte payloads are never
  re-encrypted.
- **Bound wraps.** Every wrap carries a library-specific encryption context (plus your
  entries), and unwrap pins the configured key id — a blob wrapped under a different key or
  context fails closed with `PqDecryptionException`, indistinguishable from tampering.
- **Operational errors stay operational.** Missing keys, access denial, throttling, and
  network failures surface as the AWS SDK's own exceptions, not as decryption failures.
- IAM permissions needed: `kms:GenerateDataKey` to encrypt, `kms:Decrypt` to decrypt.

## Versioning

Kept in **lockstep** with `PostQuantum.FileEncryption`. No change to the `.pqfe` v2 container
format, which remains **FROZEN** for the `1.x` line.

---

*To God be the glory — 1 Corinthians 10:31.*
