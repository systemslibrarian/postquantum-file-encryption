# The `PQKF` encrypted key-file format (v1)

This document specifies, byte-exactly, the passphrase-encrypted key file produced by
`PqHybridPrivateKey.ExportEncrypted` and `PqSigningPrivateKey.ExportEncrypted` (and by
`pqfe keygen --encrypt`). It exists so that private keys have a safe at-rest form out of the
box — instead of every application inventing its own storage for the raw bytes that
`Export()` returns.

The format deliberately contains **no new cryptography**. A key file is a five-byte header
followed by a standard `.pqfe` v2 **passphrase container**
([FILE-FORMAT.md](FILE-FORMAT.md)), so every confidentiality, authenticity, KDF-hardening,
and fail-closed property is inherited from the container engine unchanged. This document is
therefore mostly a *framing* specification.

## Layout

| Offset | Size | Field         | Value                                                    |
| -----: | ---: | ------------- | -------------------------------------------------------- |
| 0      | 4    | Magic         | `PQKF` (`0x50 0x51 0x4B 0x46`)                           |
| 4      | 1    | FormatVersion | `1`                                                      |
| 5      | …    | Body          | A `.pqfe` v2 passphrase container (KeySource 1 or 2)     |

The container's **plaintext** — the bytes recovered after successful authenticated
decryption — is:

```
Plaintext = KeyType(1) ‖ KeyBytes
```

| KeyType | Key                                    | KeyBytes length | KeyBytes encoding                     |
| ------: | -------------------------------------- | --------------: | ------------------------------------- |
| `1`     | Hybrid recipient private key           | 2,432           | `X25519(32) ‖ ML-KEM-dk(2400)`        |
| `2`     | Hybrid signing private key             | 4,064           | `Ed25519-seed(32) ‖ ML-DSA-sk(4032)`  |

All other `KeyType` values are reserved. Public keys are never stored in this format — they
are public, and `Export()` suffices.

The `KeyType` byte lives **inside** the encrypted, authenticated plaintext, not in the
header. An attacker therefore cannot flip a signing key file into something a hybrid
importer would accept (or vice versa): changing the type requires forging the container's
authentication.

## Writer rules (normative)

1. Writers MUST emit the magic and version exactly as specified, followed immediately by the
   container — no padding, no trailing bytes.
2. The container MUST be a passphrase container (KeySource `1` = PBKDF2-HMAC-SHA256 or
   `2` = Argon2id). Recipient and key-provider KeySources are not permitted in a key file.
3. The reference implementation defaults the KDF to **Argon2id** (19 MiB memory, 2 passes) —
   key files are small and long-lived, so the KDF is the entire cost of opening one, which is
   exactly the workload memory-hard KDFs exist for. Writers MAY choose PBKDF2 or different
   cost parameters within the container format's bounds.
4. An empty passphrase MUST be rejected.

## Reader rules (normative)

1. Reject input shorter than 6 bytes, or whose first 4 bytes are not `PQKF`, as *not a key
   file* (`PqFormatException`).
2. Reject an unknown `FormatVersion` (`PqFormatException`).
3. Decrypt the body as a `.pqfe` v2 passphrase container, applying that format's reader
   rules in full. A wrong passphrase and a tampered file are indistinguishable
   (`PqDecryptionException` with the container engine's generic message) — the key-file
   framing adds no oracle. Readers SHOULD let callers bound the embedded container's KDF
   cost parameters before deriving (the reference implementation's optional
   `PqDecryptionLimits` on `ImportEncrypted`), since a hostile key file could otherwise
   demand the format-maximum KDF cost before anything authenticates.
4. After successful decryption, reject a plaintext whose `KeyType` or length does not match
   the kind of key being imported (`PqFormatException`). This check runs on *authenticated*
   plaintext, so its distinct message reveals nothing to anyone who lacks the passphrase.
5. Zero the recovered plaintext (and any intermediate key-byte copies) once the key object
   is constructed.

## Versioning

A pinned known-answer vector for this format is published in
[TEST-VECTORS.md](TEST-VECTORS.md) (Vector 5) and exercised in CI.

`FormatVersion` is bumped only for layout changes to this framing. The embedded container
carries its own version and evolves independently under the `.pqfe` rules; a `PQKF` v1 file
whose body is a future container version is opened or rejected according to the container
format's own versioning rules.

## What this format does NOT do

- **It does not rate-limit guessing.** Anyone holding the file can run offline passphrase
  attacks at KDF speed; the passphrase must carry real entropy. For keys whose compromise is
  catastrophic, prefer an HSM/KMS (see [KEY-MANAGEMENT.md](KEY-MANAGEMENT.md)).
- **It does not hide metadata.** The magic bytes identify the file as an encrypted key, and
  the container header reveals the KDF and its cost parameters — by design, as in the parent
  format.
- **It does not bind a file name or purpose.** Renaming a key file does not invalidate it;
  the `KeyType` byte binds only the *kind* of key.

*To God be the glory — 1 Corinthians 10:31.*
