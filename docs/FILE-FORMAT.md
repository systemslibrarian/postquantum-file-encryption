# PostQuantum.FileEncryption Container Format — v2

This is the authoritative specification of the on-disk container produced and consumed by
PostQuantum.FileEncryption `0.2.x`. It is documented so the format can be reviewed and
re-implemented independently.

> **Not frozen.** This format may change before `1.0`. The `FormatVersion` byte exists so a
> future reader can refuse or migrate older containers. (v0.2 does not read the v0.1 format.)

All multi-byte integers are **big-endian**. All cryptography uses .NET's
`System.Security.Cryptography` primitives, plus Argon2id from
`Konscious.Security.Cryptography` when selected.

## Overview

A container is a **header** followed by one or more **frames**. The header carries everything
needed to establish the per-file 32-byte content key; each frame is an independent
AES-256-GCM ciphertext over one plaintext chunk. The final frame is explicitly marked; a
container with no authenticated final frame is rejected as truncated.

```
+----------------+----------------+-----+----------------+
|     Header     |    Frame 0     | ... |  Frame N (final)|
+----------------+----------------+-----+----------------+
```

## Header

| Offset | Size | Field             | Value / meaning                                  |
| -----: | ---: | ----------------- | ------------------------------------------------ |
|      0 |    4 | `Magic`           | ASCII `PQFE` (`0x50 0x51 0x46 0x45`)             |
|      4 |    1 | `FormatVersion`   | `2`                                              |
|      5 |    1 | `AeadId`          | `1` = AES-256-GCM                                |
|      6 |    1 | `KeySource`       | `1` passphrase · `2` ML-KEM · `3` hybrid · `4` multi · `5` key provider |
|      7 |    1 | `Flags`           | reserved, must be `0`                            |
|      8 |    4 | `ChunkSize`       | plaintext bytes per non-final chunk (uint32)     |
|     12 |    4 | `NoncePrefix`     | random per-file nonce prefix                     |
|     16 |    2 | `KeyParamsLength` | length of `KeyParams` in bytes (uint16)          |
|     18 |  *K* | `KeyParams`       | key-establishment parameters (see below)         |

The **entire serialized header** (18 + *K* bytes) is bound into every frame's additional
authenticated data, so any change to the key parameters or chunk size is detected as an
authentication failure.

### KeyParams when `KeySource = 1` (passphrase)

```
0   1   KdfId        1 = PBKDF2-HMAC-SHA256, 2 = Argon2id
1   1   SaltLength S
2   S   Salt         random per-file
```
then, for `KdfId = 1` (PBKDF2):
```
2+S 4   Iterations   (uint32)
```
or, for `KdfId = 2` (Argon2id):
```
2+S   4   MemoryKiB    (uint32)
6+S   4   Iterations   (uint32)
10+S  1   Parallelism  (uint8)
```

Key derivation produces the 32-byte content key directly:

```
PBKDF2:   key = PBKDF2-HMAC-SHA256(passphrase_utf8, Salt, Iterations, dkLen = 32)
Argon2id: key = Argon2id(passphrase_utf8, Salt, MemoryKiB, Iterations, Parallelism, dkLen = 32)
```

A reader **must** reject KDF parameters outside the supported ranges (iteration/memory bounds)
so a hostile header cannot force unbounded CPU or memory use.

### KeyParams when `KeySource = 2` (ML-KEM recipient)

A random 32-byte content key (CEK) is wrapped to the recipient using ML-KEM-768 in the
standard KEM-DEM pattern.

```
0     1    KemId               1 = ML-KEM-768
1     2    KemCiphertextLength C (uint16, 1088 for ML-KEM-768)
3     C    KemCiphertext       ML-KEM encapsulation output
3+C   12   WrapNonce           AES-256-GCM nonce for the key wrap
15+C  16   WrapTag             AES-256-GCM tag for the key wrap
31+C  32   WrappedKey          AES-256-GCM(KEK) over the CEK
```

Establishment and recovery:

```
encrypt: (KemCiphertext, ss) = ML-KEM-768.Encapsulate(recipient_public_key)
         KEK = HKDF-SHA256(ss, info = "PostQuantum.FileEncryption/v2 ml-kem-768 kek")
         (WrappedKey, WrapTag) = AES-256-GCM-Encrypt(KEK, WrapNonce, CEK,
                                                      aad = "PostQuantum.FileEncryption/v2 cek-wrap")

decrypt: ss  = ML-KEM-768.Decapsulate(KemCiphertext, recipient_private_key)
         KEK = HKDF-SHA256(ss, info = ...)
         CEK = AES-256-GCM-Decrypt(KEK, WrapNonce, WrappedKey, WrapTag, aad = ...)
```

A wrap-tag mismatch (wrong recipient key or tampering) is rejected.

### KeyParams when `KeySource = 3` (hybrid recipient)

Provided by the `PostQuantum.FileEncryption.Hybrid` package. The CEK is wrapped under a key
derived from **both** an ML-KEM-768 shared secret and an X25519 shared secret, so it stays safe
if either primitive is broken.

```
0     1    KemId                       1 = ML-KEM-768
1     2    KemCiphertextLength C        (uint16, 1088)
3     C    KemCiphertext
3+C   32   EphemeralX25519PublicKey
35+C  12   WrapNonce
47+C  16   WrapTag
63+C  32   WrappedKey                   AES-256-GCM(KEK) over the CEK
```

```
encrypt: (KemCiphertext, ss_pq) = ML-KEM-768.Encapsulate(recipient_mlkem_pub)
         (eph_priv, eph_pub)     = X25519.GenerateKeyPair()
         ss_classical            = X25519(eph_priv, recipient_x25519_pub)
         KEK = HKDF-SHA256(ss_pq ‖ ss_classical, info = "PostQuantum.FileEncryption/v3 hybrid kek")
         (WrappedKey, WrapTag) = AES-256-GCM(KEK, WrapNonce, CEK, aad = "PostQuantum.FileEncryption/v3 cek-wrap")
```

Decryption reverses it (decapsulate + X25519 agreement → same HKDF → AES-GCM unwrap). The
concatenation order `ss_pq ‖ ss_classical` is fixed and authenticated (the whole header is
chunk AAD).

### KeyParams when `KeySource = 4` (multiple recipients)

The same CEK is wrapped to N recipients; any one private key opens the file.

```
0     1    RecipientCount N (uint8, ≥ 1)
then N times:
  1   Mode (3 = hybrid)
  2   BlockLength L (uint16)
  L   block = a KeySource-3 body (above), wrapping the SAME CEK
```

A decryptor tries each block with its private key and uses the first that authenticates; if none
do, it fails closed with no oracle about which recipients are present.

### KeyParams when `KeySource = 5` (external key provider)

The CEK is wrapped by an external envelope provider (`IContentKeyProvider`: KMS, HSM, or the
built-in local-KEK). The header stores the provider id and the provider's opaque `wrapInfo`; the
library does not interpret `wrapInfo` — only the matching provider does.

```
0     1    ProviderIdLength P (uint8, 1–255)
1     P    ProviderId (UTF-8, e.g. "local-kek", "aws-kms")
1+P   2    WrapInfoLength W (uint16)
3+P   W    WrapInfo (provider-opaque)
```

On decryption the supplied provider's id must match `ProviderId`, then
`UnwrapKeyAsync(WrapInfo)` recovers the CEK. For the built-in `LocalKekContentKeyProvider`,
`WrapInfo` is `Nonce(12) ‖ Tag(16) ‖ AES-256-GCM(KEK)-wrapped CEK(32)`.

## Frames

Frames are written in order, starting at chunk counter `0`. The content key is the 32-byte key
established above; this part of the format is identical regardless of `KeySource`.

| Size | Field         | Meaning                                                      |
| ---: | ------------- | ------------------------------------------------------------ |
|    1 | `FrameType`   | `0` = data (more follow), `1` = final (last chunk)          |
|    4 | `Length`      | plaintext/ciphertext length of this chunk (uint32, ≤ `ChunkSize`) |
| *L*  | `Ciphertext`  | AES-256-GCM ciphertext, `Length` bytes                      |
|   16 | `Tag`         | AES-256-GCM 128-bit authentication tag                      |

For chunk with counter `i`:

```
Nonce_i = NoncePrefix (4 bytes) || uint64_be(i)        // 12 bytes total
Aad_i   = Header || uint64_be(i) || FrameType           // binds order + finality
(Ciphertext_i, Tag_i) = AES-256-GCM-Encrypt(key, Nonce_i, Plaintext_i, Aad_i)
```

The nonce is a fixed random prefix concatenated with a strictly increasing counter, so no
nonce is ever reused under a single per-file key.

### Final frame and empty input

- Exactly one frame — the last — has `FrameType = 1`.
- A zero-byte plaintext is a **single final frame** with `Length = 0`.
- A non-final data chunk always has `Length = ChunkSize`; only the final chunk may be shorter.

## Decryption and verification rules

A reader **must**:

1. Verify `Magic`, `FormatVersion`, `AeadId`, and `KeySource`; reject unknown values
   (`PqFormatException`).
2. Reject a `ChunkSize` or any KDF/KEM parameter outside the supported range.
3. Establish the content key from the passphrase or recipient private key.
4. For each frame, reconstruct `Nonce_i` and `Aad_i` from the counter and the on-disk
   `FrameType`, then AES-256-GCM-decrypt. Any tag mismatch ⇒ reject the whole container
   (`PqDecryptionException`); no plaintext for that or any later chunk is emitted.
5. Stop after the frame with `FrameType = 1`.
6. If end-of-input is reached without an authenticated final frame, reject the container as
   truncated (`PqDecryptionException`).

These rules make bit-flipping, header tampering, chunk reordering, splicing between
containers, and truncation all detectable.

---

*To God be the glory — 1 Corinthians 10:31.*
