# Key Management: envelope providers (KMS/HSM), Multi-Recipient, Rotation

The **envelope-key seam is implemented** (`KeySource = 5`): `IContentKeyProvider` plus the
built-in, dependency-free `LocalKekContentKeyProvider`. **Cloud providers are SHIPPED** as
separate packages: [`PostQuantum.FileEncryption.Aws`](https://www.nuget.org/packages/PostQuantum.FileEncryption.Aws)
(AWS KMS `GenerateDataKey`/`Decrypt` with a bound encryption context),
[`PostQuantum.FileEncryption.AzureKeyVault`](https://www.nuget.org/packages/PostQuantum.FileEncryption.AzureKeyVault)
(Key Vault / Managed HSM wrap/unwrap, pinned key id and algorithm), and
[`PostQuantum.FileEncryption.Gcp`](https://www.nuget.org/packages/PostQuantum.FileEncryption.Gcp)
(Cloud KMS `Encrypt`/`Decrypt` with bound AAD and end-to-end CRC32C checks). HashiCorp Vault
and PKCS#11 remain future work.

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

> **Contract: the content key MUST be fresh on every call.** Cross-file AES-GCM nonce uniqueness
> rests entirely on per-file key freshness — the on-disk nonce prefix is only 4 random bytes. A
> provider that caches or reuses a data key (a tempting KMS cost optimization) collapses that to a
> 32-bit birthday bound across files (~50% collision odds by ~77k files), and colliding files
> reuse (key, nonce) pairs: keystream XOR leaks plaintext and the GCM authentication key becomes
> recoverable. Never cache or reuse the plaintext CEK.

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

// Google Cloud KMS — Encrypt/Decrypt; CEK generated locally (Cloud KMS has no server-side
// data-key generation), wrap bound to the CryptoKey and library AAD, CRC32C verified both ways:
var gcp = new GcpKmsContentKeyProvider(await KeyManagementServiceClient.CreateAsync(),
    "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/pqfe-kek");
```

- The master key stays in the KMS/HSM; only the per-file CEK crosses the boundary, wrapped.
- Cloud providers ship as separate packages so the core stays dependency-light — the same
  packaging principle as the Hybrid package.
- They are unit-tested against in-process fakes of the SDK clients that reproduce the
  services' binding semantics; CI carries no cloud credentials, so **live-service integration
  is not exercised by this repo's pipeline** ([KNOWN-GAPS.md](../KNOWN-GAPS.md)).

## Multiple recipients / access groups

Shipped as `KeySource = 4` in the Hybrid package (design history in [ROADMAP-v3.md](ROADMAP-v3.md)): one CEK wrapped to N recipients (or
N KMS key IDs), so any authorized party can open the file. Decryption tries each wrap block until
one succeeds, failing closed with no oracle about which recipients are present.

## Rotation & revocation

Rotating credentials on a **format v2** container means **re-encrypting the file as a streaming
transcode** — not a header-only rewrite. That is a consequence of a deliberate v2 design property:
the entire serialized header, including the wrapped CEK, is bound as AAD into **every** content
frame. Replacing the wrap changes every frame's AAD, so every frame must be re-authenticated — and
re-tagging under the *same* CEK and nonces with new AAD would emit a second AES-GCM tag for each
(key, nonce) pair. Old and rotated copies of a file legitimately coexist, and an attacker holding
both could use such tag pairs to recover the GCM authentication key and forge ciphertext. A safe
rotation therefore looks like:

```
rotate:  CEK_old = unwrap(old credential)       # small
         CEK_new = fresh random 32 bytes         # never reuse the old CEK
         stream:  decrypt chunk under CEK_old → re-encrypt under CEK_new
                  (fresh nonce prefix; new header wrapping CEK_new)
         atomically replace the file             # plaintext never persisted
```

- Memory stays bounded (one chunk at a time) and plaintext never touches disk, but the **whole
  file is read and rewritten** — budget rotation as full-file I/O, not a 32-byte edit.
- A detached `.sig` sidecar signs the old bytes and becomes stale after rotation; re-sign the
  rotated file or remove the sidecar explicitly.
- **Revoke** a recipient by rotating to a new recipient set that excludes them.
  Already-distributed copies cannot be retroactively un-shared — rotation protects future access,
  not past disclosure. With cloud KMS, rotating the *master* key inside the KMS often needs no
  file rewrite at all: providers keep old key versions decryptable, so existing wraps still open.
- Rotation tooling is design-only today ([KNOWN-GAPS.md](../KNOWN-GAPS.md)). True header-only
  rewrap requires a format that keeps wrap material *outside* the chunk-AAD commitment — a
  format-v3 candidate, not a v2 patch.

## Status

The provider seam, the local-KEK provider, the **AWS KMS provider**, the **Azure Key Vault
provider**, the **Google Cloud KMS provider**, and hybrid multi-recipient encryption (`KeySource = 4`, in the Hybrid package)
are **shipped**. Rewrap/rotation tooling and Vault/PKCS#11 providers remain design-only,
tracked in [KNOWN-GAPS.md](../KNOWN-GAPS.md).

*To God be the glory — 1 Corinthians 10:31.*
