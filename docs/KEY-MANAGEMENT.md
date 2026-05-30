# Key Management: KMS/HSM, Multi-Recipient, Rotation (design)

Enterprise key management is **not implemented** in the core today (passphrase mode is). This is
the design for how it will work, so the seams are understood and the gaps are honest. It builds
on the recipient/hybrid work in [ROADMAP-v3.md](ROADMAP-v3.md).

## Envelope encryption with an external KMS/HSM

The container already uses envelope encryption internally: a random **content key (CEK)** encrypts
the data, and the header carries a **wrapped** CEK. Today the CEK is wrapped by a passphrase-derived
key or (experimentally) an ML-KEM KEM-DEM. The same seam generalizes to a KMS/HSM:

```
encrypt:  CEK = random 32 bytes
          wrapped = KMS.Encrypt(keyId, CEK)          # AWS KMS / Azure Key Vault / Vault / PKCS#11 HSM
          header carries { providerId, keyId, wrapped }   # the master key never enters local RAM
decrypt:  CEK = KMS.Decrypt(keyId, wrapped)
```

- The master key stays in the KMS/HSM; only the per-file CEK is wrapped/unwrapped there.
- This lands behind the existing `Internal/KeyEstablishment` seam as an `IKeyProvider`-style
  abstraction, in a provider package (e.g. `PostQuantum.FileEncryption.Aws`) so the core stays
  dependency-light — the same packaging principle as the Hybrid package.

Proposed shape:

```csharp
public interface IContentKeyProvider
{
    // Returns a fresh CEK and the opaque wrap bytes to store in the header.
    Task<(byte[] cek, byte[] wrapInfo)> WrapNewKeyAsync(CancellationToken ct);
    // Recovers the CEK from the stored wrap bytes.
    Task<byte[]> UnwrapKeyAsync(ReadOnlyMemory<byte> wrapInfo, CancellationToken ct);
}
```

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
