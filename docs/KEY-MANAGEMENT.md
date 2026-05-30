# Key Management: envelope providers (KMS/HSM), Multi-Recipient, Rotation

The **envelope-key seam is implemented** (`KeySource = 5`): `IContentKeyProvider` plus the
built-in, dependency-free `LocalKekContentKeyProvider`. Cloud-KMS/HSM providers (AWS, Azure,
Vault, PKCS#11) are designed below and ship as separate provider packages.

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

A cloud provider implements the same interface, mapping to `GenerateDataKey` / `Decrypt`:

```
encrypt:  (CEK, wrapInfo) = KMS.GenerateDataKey(keyId)   # wrapInfo = encrypted CEK ‖ keyId
decrypt:  CEK = KMS.Decrypt(wrapInfo)                    # master key stays in the KMS/HSM
```

- The master key stays in the KMS/HSM; only the per-file CEK crosses the boundary, wrapped.
- Cloud providers ship as separate packages (e.g. `PostQuantum.FileEncryption.Aws`) so the core
  stays dependency-light — the same packaging principle as the Hybrid package. They need their
  cloud SDK and live credentials to integration-test; that is the remaining work.

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

All of the above is **design, not shipped**. Tracked in [KNOWN-GAPS.md](../KNOWN-GAPS.md). The
core today provides passphrase envelope encryption; the provider abstraction, multi-recipient
format, and rewrap tooling are future work in separate provider packages.

*To God be the glory — 1 Corinthians 10:31.*
