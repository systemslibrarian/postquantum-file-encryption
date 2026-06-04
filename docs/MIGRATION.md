# Migrating to PostQuantum.FileEncryption

This guide is for developers coming from another file or stream encryption library who want
to know:

1. What changes in shape — what APIs map to what.
2. What changes in guarantees — what the new code is doing that the old code wasn't (or vice
   versa).
3. What does **not** carry over and needs a plan.

`.pqfe` v2 is a different on-disk format from every library below, so migration means
**re-encrypting** existing ciphertext, not transcoding it. Plan for a one-time migration
window where you decrypt with the old library and re-encrypt with this one.

---

## At a glance

| You're using | Closest entry point here | Notes |
| --- | --- | --- |
| **`age` / `rage`** (passphrase or X25519) | `PqFileEncryptor` (passphrase) · `PqHybridEncryptor` (public-key) | Hybrid combiner adds ML-KEM-768 on top of X25519. |
| **libsodium `secretstream`** (xchacha20-poly1305) | `PqFileEncryptor` stream APIs | We use AES-256-GCM + chunked AAD framing instead. |
| **libsodium `crypto_box` / `crypto_secretbox`** | `PqHybridEncryptor` (boxes ≈ recipient encryption) | Boxes are not streaming; we stream. |
| **OpenSSL `enc -aes-256-gcm`** (CLI) | `samples/Pqfe.Cli` (`pqfe encrypt`) | Specified, vectored format vs. ad-hoc layout. |
| **.NET `AesGcm`** (raw primitive) | `PqFileEncryptor.EncryptBytes` / `EncryptAsync` | We handle chunking, AAD, nonces, and framing. |
| **.NET `ProtectedData`** (DPAPI) | `PqFileEncryptor` + `LocalKekContentKeyProvider` | DPAPI is machine-bound; we are portable. |
| **BouncyCastle `CmsEnvelopedData` / PGP** | `PqHybridEncryptor` (multi-recipient) | New on-wire format; no CMS/PGP compatibility. |
| **Microsoft Data Protection (`IDataProtector`)** | `PqFileEncryptor` + `IContentKeyProvider` | DP is purpose-scoped; this is content-at-rest. |

If the table doesn't list your source, the [comparison
matrix](COMPARISON.md) is the next stop.

---

## From `age` / `rage`

Most `age` use cases map cleanly to one of two paths:

| `age` recipe | Here |
| --- | --- |
| `age -p -o file.age file` (passphrase) | `new PqFileEncryptor().EncryptFileAsync(file, "file.pqfe", passphrase)` |
| `age -r age1… -o file.age file` (X25519 recipient) | `new PqHybridEncryptor().EncryptBytesAsync(plaintext, recipient)` |
| `age -i key.txt -d file.age` (identity decrypt) | `new PqHybridDecryptor().DecryptBytesAsync(container, keyPair.PrivateKey)` |
| Multiple `-r` recipients | `PqHybridEncryptor.EncryptAsync(input, output, IEnumerable<PqHybridPublicKey>)` |

What changes in guarantees:

- **Quantum-resistant key establishment** for the recipient path: Hybrid combines X25519
  *and* ML-KEM-768, so the content key is safe if either primitive is later broken. `age`
  is X25519-only.
- **AES-256-GCM** for the data plane instead of ChaCha20-Poly1305. Both are sound AEADs;
  AES-256-GCM uses hardware AES on every modern CPU and gives ≈128-bit security against a
  Grover attacker.
- **Argon2id is selectable** for passphrase mode (`PqEncryptionOptions.Argon2id`). `age`
  uses scrypt.

What does not carry over:

- The `.age` file format. Re-encrypt your archive once with the .NET (or Rust/WASM) tool.
- `age` identity files (`age1…`). Generate fresh `PqHybridKeyPair`s; the public-key shape is
  different.
- `age` plugins (YubiKey, SSH-style identities, etc.). Not in scope today.

---

## From libsodium `secretstream`

`secretstream` (XChaCha20-Poly1305) is a streaming AEAD primitive; you typically built your
own on-disk framing on top of it. Move both pieces over:

```c
// Before — libsodium pseudo-code
crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
crypto_secretstream_xchacha20poly1305_push(&state, c, &clen, m, mlen, ad, adlen, tag);
// ...you wrote the framing yourself
```

```csharp
// After — .NET, with framing handled for you
await using var input  = File.OpenRead("plain.bin");
await using var output = File.Create("plain.pqfe");
await new PqFileEncryptor().EncryptAsync(input, output, passphrase);
```

What you get for free:

- A **specified, frozen on-disk format** (`.pqfe` v2, [FILE-FORMAT.md](FILE-FORMAT.md)) with
  cross-checked test vectors.
- **Anti-truncation** detection — a missing final frame is a `PqDecryptionException`.
- **Anti-splicing** detection — every frame's ordinal and final-marker is in the AAD.

What you lose:

- The FFI-light, C-friendly API. This is a managed .NET library.
- `secretstream`'s **rekey** primitive. We rotate the *content key per file*, not within a
  stream; rekeying mid-stream is out of scope for the format.

---

## From OpenSSL `enc`

If you have a pipeline like

```bash
openssl enc -aes-256-gcm -pbkdf2 -iter 600000 -in file -out file.enc -pass env:PASS
```

the closest replacement is the bundled CLI sample:

```bash
PQFE_PASS="$PASS" \
  pqfe encrypt file file.pqfe --passphrase-env PQFE_PASS         # PBKDF2 by default
# or memory-hard:
PQFE_PASS="$PASS" \
  pqfe encrypt file file.pqfe --argon2id --passphrase-env PQFE_PASS
```

What changes:

- **Authenticated framing.** OpenSSL `enc` produces a single GCM ciphertext over the whole
  file — bytes after the tag have no integrity check, and truncation looks like the file
  just ended. `.pqfe` chunks the file and binds ordinals into the AAD.
- **A specified format.** OpenSSL's `enc` layout is documented for the specific options you
  passed; it isn't a portable archive format. `.pqfe` is [fully
  specified](FILE-FORMAT.md) and has [conformance vectors](TEST-VECTORS.md).
- **No way to pick a weak mode by accident.** OpenSSL `enc` defaults to legacy unauthenticated
  ciphers if you forget `-aes-256-gcm` and a strong KDF. The .NET API has no
  unauthenticated path.

What does not carry over:

- The OpenSSL ciphertext layout. Decrypt with `openssl enc` once, re-encrypt with `pqfe`.

---

## From `.NET AesGcm` (the raw primitive)

If you've been using `System.Security.Cryptography.AesGcm` directly:

```csharp
// Before — manual nonce, manual framing, AAD if you remembered it
using var gcm = new AesGcm(key, tagSizeInBytes: 16);
gcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData: aad);
```

```csharp
// After — file-, stream-, or bytes-shaped, with chunking, AAD, atomic output, progress
await new PqFileEncryptor().EncryptFileAsync("plain.bin", "out.pqfe", passphrase);
```

What you stop having to write yourself:

- **Nonce management.** A 4-byte random `NoncePrefix` is generated per file; each chunk's
  12-byte nonce is `NoncePrefix || BE_UInt64(chunkIndex)`.
- **Chunked framing.** Plaintext is split into 64 KiB chunks (by default) so peak memory is
  bounded.
- **AAD binding.** Every chunk's AAD includes the full serialized header plus the chunk
  ordinal and final-chunk marker. Header tampering, reorder, splice, and truncation all
  fail authentication.
- **Atomic file output.** File-API writes stage to a sibling temp file and `File.Move`
  into place on full success.

What you keep:

- Direct access to AES-256-GCM in the data plane. The `.pqfe` data plane *is* AES-256-GCM,
  framed.

---

## From `.NET ProtectedData` (DPAPI)

`ProtectedData` is Windows-only and machine-bound. The closest .NET-cross-platform analogue
in this library is:

```csharp
// Before — Windows-only, machine-/user-scoped, no portable ciphertext
byte[] sealed = ProtectedData.Protect(plaintext, optionalEntropy, DataProtectionScope.LocalMachine);
```

```csharp
// After — portable container, machine-independent key under your control
using var provider = LocalKekContentKeyProvider.Generate();      // hold this KEK in your KMS
byte[] container   = await new PqFileEncryptor().EncryptBytesAsync(plaintext, provider);
```

If you previously relied on DPAPI's machine/user scoping, you now own the KEK lifecycle:
generate it on the protected machine and store the encoded KEK wherever you'd store any
other long-term secret (e.g., AWS KMS, Azure Key Vault, an HSM). Cloud KMS adapters that
implement `IContentKeyProvider` are tracked on the [`1.x` minor
roadmap](../ROADMAP.md#after-10--1x-minor-work).

---

## From BouncyCastle CMS / OpenPGP

CMS `EnvelopedData` and OpenPGP both encode a multi-recipient envelope. The closest
analogue here is the Hybrid package:

```csharp
using PostQuantum.FileEncryption.Hybrid;

var recipients = new[] { aliceKey.PublicKey, bobKey.PublicKey, carolKey.PublicKey };
byte[] container = await new PqHybridEncryptor().EncryptBytesAsync(plaintext, recipients);

// Each recipient can decrypt independently with their own private key:
byte[] plaintextForAlice = await new PqHybridDecryptor().DecryptBytesAsync(container, aliceKey.PrivateKey);
```

What changes in guarantees:

- **Post-quantum hybrid** key establishment — neither classical-only (X25519) nor PQ-only
  (ML-KEM) on its own.
- **No certificate machinery.** Recipients are bare public keys; rotation/revocation is
  application-level, not via PKIX.
- **`.pqfe` v2 wire format**, not CMS or OpenPGP packets. No interop with `gpg`, `openssl
  cms`, or BouncyCastle's CMS reader.

---

## From Microsoft Data Protection (`IDataProtector`)

ASP.NET Core's data-protection system is for purpose-scoped, short-lived, in-app secrets
(cookies, tokens, …). PostQuantum.FileEncryption is for **content at rest** that needs to
outlive the app's keyring and travel between machines. They solve different problems:

| Need | Use |
| --- | --- |
| Cookie / antiforgery / temp-data encryption | `IDataProtector` |
| Encrypt a customer document for storage / transit | `PqFileEncryptor` |
| Encrypt a customer document to a recipient's public key | `PqHybridEncryptor` |
| Same as above, but the master key lives in a KMS | `PqFileEncryptor` + `IContentKeyProvider` |

You can run both side by side; they don't conflict.

---

## Cross-cutting checklist for any migration

Before you flip production traffic:

- [ ] Decide the **passphrase vs. KMS** vs. **public-key recipient** path. Passphrase mode
      requires good human secrets; the envelope-key seam (`IContentKeyProvider`) lets you
      pull the master key from AWS KMS / Azure Key Vault / Vault / HSM; the Hybrid package
      handles multi-recipient public-key flows.
- [ ] If you have **multiple recipients**, the Hybrid package's
      `EncryptAsync(IEnumerable<PqHybridPublicKey>)` is the path. Don't roll your own.
- [ ] Pick **PBKDF2** (default, dependency-light) **or Argon2id** (memory-hard). Argon2id
      is the stronger choice for human-chosen passphrases. The choice is encoded in the
      container header, so decryption needs no out-of-band signal.
- [ ] If you're streaming and need a strict all-or-nothing guarantee on partial reads, use
      `DecryptAtomicAsync` instead of `DecryptAsync` (or use the file API, which is already
      atomic via temp-file-and-rename).
- [ ] Plan for **format frozen at `.pqfe` v2**. Containers you produce today open with
      every `1.x` build, on every platform, in either implementation (.NET or Rust/WASM).
- [ ] Wire **telemetry**. The library emits a non-sensitive `EventSource` named
      `PostQuantum.FileEncryption` — subscribe with `EventListener`, `dotnet-trace`, or
      OpenTelemetry to track operation counts, failure categories, and timing in your SIEM.
- [ ] Verify the **release supply chain** before pinning a version — see
      [docs/SUPPLY-CHAIN.md](SUPPLY-CHAIN.md) for the SBOM/attestation/verification
      commands.

---

*To God be the glory — 1 Corinthians 10:31.*
