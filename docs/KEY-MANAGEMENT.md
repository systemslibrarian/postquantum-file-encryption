# Key Management: envelope providers (KMS/HSM), Multi-Recipient, Rotation

The **envelope-key seam is implemented** (`KeySource = 5`): `IContentKeyProvider` plus the
built-in, dependency-free `LocalKekContentKeyProvider`. **Cloud providers are SHIPPED** as
separate packages: [`PostQuantum.FileEncryption.Aws`](https://www.nuget.org/packages/PostQuantum.FileEncryption.Aws)
(AWS KMS `GenerateDataKey`/`Decrypt` with a bound encryption context) and
[`PostQuantum.FileEncryption.AzureKeyVault`](https://www.nuget.org/packages/PostQuantum.FileEncryption.AzureKeyVault)
(Key Vault / Managed HSM wrap/unwrap, pinned key id and algorithm). HashiCorp Vault and
PKCS#11 remain future work.

## Envelope encryption with an external provider (IMPLEMENTED)

The container uses envelope encryption: a random **content key (CEK)** encrypts the data, and the
header carries a **wrapped** CEK. A provider supplies the CEK and the opaque `wrapInfo` needed to
recover it — so the master key never enters this process beyond the provider's boundary.

```csharp
public interface IContentKeyProvider
{
    string ProviderId { get; }   // stored in the header; checked on decrypt
    Task<(byte[] contentKey, byte[] wrapInfo)> WrapNewKeyAsync(CancellationToken ct = default);
    Task<byte[]> UnwrapKeyAsync(ReadOnlyMemory<byte> wrapInfo, CancellationToken ct = default);
}
```

Usage (any `PqFileEncryptor` / `PqFileDecryptor` overload accepts a provider):

```csharp
using var provider = LocalKekContentKeyProvider.Generate();        // or new(kekBytes), or a KMS provider
byte[] container = await new PqFileEncryptor().EncryptBytesAsync(secret, provider);
byte[] plain     = await new PqFileDecryptor().DecryptBytesAsync(container, provider);
```

The shipped cloud providers implement the same interface:

```csharp
// AWS KMS — GenerateDataKey/Decrypt; wrap bound to the key id and an encryption context:
var aws = new AwsKmsContentKeyProvider(new AmazonKeyManagementServiceClient(), "alias/my-app-key");

// Azure Key Vault / Managed HSM — wrap/unwrap (RSA-OAEP-256 default, A256KW available);
// unwrap pinned to the configured key id and algorithm:
var akv = new AzureKeyVaultContentKeyProvider(
    new CryptographyClient(new Uri("https://my-vault.vault.azure.net/keys/pqfe-kek/<version>"),
                           new DefaultAzureCredential()));
```

- The master key stays in the KMS/HSM; only the per-file CEK crosses the boundary, wrapped.
- Cloud providers ship as separate packages so the core stays dependency-light — the same
  packaging principle as the Hybrid package.
- They are unit-tested against in-process fakes of the SDK clients that reproduce the
  services' binding semantics; CI carries no cloud credentials, so **live-service integration
  is not exercised by this repo's pipeline** ([KNOWN-GAPS.md](../KNOWN-GAPS.md)).

## Multiple recipients / access groups

Designed as `KeySource = 4` in [ROADMAP-v3.md](ROADMAP-v3.md): one CEK wrapped to N recipients (or
N KMS key IDs), so any authorized party can open the file. Decryption tries each wrap block until
one succeeds, failing closed with no oracle about which recipients are present.

## Rotation & revocation without re-encrypting the file

Because the data is encrypted under the CEK and only the **CEK** is wrapped, you can rotate access
credentials by **re-wrapping the CEK** — no need to re-encrypt multi-gigabyte payloads:

```
rewrap:  CEK     = unwrap(old credential)      # decrypt just the small wrapped key
         wrapped = wrap(new credential / new recipient set)
         rewrite only the container header      # body (the bulk) is untouched
```

- **Revoke** a recipient by re-wrapping to the new recipient set (excluding the revoked one) and
  replacing the header. Already-distributed copies cannot be retroactively un-shared — rotation
  protects future access, not past disclosure.
- A `rewrap` tool/API is planned alongside multi-recipient support; the header-only rewrite is
  cheap and the body's authentication is unaffected (the header is bound as chunk AAD, so a rewrap
  re-derives chunk AAD — meaning rewrap re-authenticates, not just edits bytes; the design account
  for this is part of the implementation work).

## Status

The provider seam, the local-KEK provider, the **AWS KMS provider**, the **Azure Key Vault
provider**, and hybrid multi-recipient encryption (`KeySource = 4`, in the Hybrid package)
are **shipped**. Rewrap/rotation tooling and Vault/PKCS#11 providers remain design-only,
tracked in [KNOWN-GAPS.md](../KNOWN-GAPS.md).

*To God be the glory — 1 Corinthians 10:31.*
