# PostQuantum.FileEncryption.Signing

**Detached, post-quantum hybrid signatures for files of any size.** Encryption proves a file
wasn't altered; a signature proves **who produced it**. This package signs any file, stream, or
buffer — typically a finished `.pqfe` container — with **Ed25519 + ML-DSA-65 (FIPS 204)
together**, so a signature stays unforgeable even if *either* algorithm is later broken.

Fully managed (BouncyCastle) — runs anywhere .NET 8 or later runs (`net8.0` and `net10.0`
targets). The content is pre-hashed with streaming SHA-512, so signing a 10 GB backup uses
constant memory.

```bash
dotnet add package PostQuantum.FileEncryption.Signing --version 1.4.1
```

## Sign and verify a file

```csharp
using PostQuantum.FileEncryption.Signing;

// Once: generate a key pair; publish PublicKey, guard PrivateKey.
using var keyPair = PqSigningKeyPair.Generate();
byte[] publicKeyBytes = keyPair.PublicKey.Export();   // share this
byte[] privateKeyBytes = keyPair.PrivateKey.Export(); // store this as a secret

// Sign: writes report.pdf.pqfe.sig next to the container (atomic write).
await new PqSigner().SignFileAsync("report.pdf.pqfe", "report.pdf.pqfe.sig", keyPair.PrivateKey);

// Verify: returns on success, throws PqSignatureException on any mismatch.
var publicKey = PqSigningPublicKey.Import(publicKeyBytes);
await new PqVerifier().VerifyFileAsync("report.pdf.pqfe", "report.pdf.pqfe.sig", publicKey);
```

Streams and in-memory buffers work the same way via `SignAsync`/`SignBytes` and
`VerifyAsync`/`VerifyBytes`.

## Fail-closed verification

Verification either succeeds completely or throws. **Both** signatures must verify — the
Ed25519 component *and* the ML-DSA-65 component — and every cryptographic failure raises the
same generic `PqSignatureException`, so there is no oracle revealing which component failed or
why. A structurally invalid signature file (wrong length, bad magic, unknown version) raises
`PqFormatException` before any cryptographic work.

## What a detached signature does — and does not — prove

- ✅ The signed bytes are exactly what the private-key holder signed.
- ✅ Whoever signed them held the private key matching your trusted public key.
- ❌ It does **not** bind the signature to a file name, path, or timestamp.
- ❌ It does **not** stop someone who can read the bytes from discarding your `.sig` and
  signing the same bytes with **their** key — trust is anchored in *whose public key you
  verify with*, so distribute public keys over a trusted channel.

This is the standard contract of detached signatures (GPG `--detach-sign`, minisign,
signify). See [KNOWN-GAPS.md](https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/KNOWN-GAPS.md).

## Format

The `.sig` sidecar is 3,379 bytes, versioned, and byte-exactly specified in
[docs/SIGNATURE-FORMAT.md](https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/docs/SIGNATURE-FORMAT.md):
a 6-byte header (`PQSG`, format version, algorithm id) followed by the Ed25519 signature
(64 bytes) and the ML-DSA-65 signature (3,309 bytes), both over the domain-separated message
`Context ‖ SHA-512(content)`. No change to the `.pqfe` v2 container format, which remains
**FROZEN** for the `1.x` line.

## Versioning

This package is kept in **lockstep** with `PostQuantum.FileEncryption`: every release of one
ships at the same version as the other.

---

*To God be the glory — 1 Corinthians 10:31.*
