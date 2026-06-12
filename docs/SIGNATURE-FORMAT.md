# The `.sig` detached-signature format (v1)

This document specifies, byte-exactly, the detached signature produced by
`PostQuantum.FileEncryption.Signing`. It is a **sidecar** format: the signed content — any
file or stream, typically a `.pqfe` container — is never modified or copied. The `.pqfe` v2
container format ([FILE-FORMAT.md](FILE-FORMAT.md)) is unchanged by signing and remains
FROZEN for the `1.x` line.

A v1 signature is exactly **3,379 bytes**:

| Offset | Size  | Field             | Value                                            |
| -----: | ----: | ----------------- | ------------------------------------------------ |
| 0      | 4     | Magic             | `PQSG` (`0x50 0x51 0x53 0x47`)                   |
| 4      | 1     | FormatVersion     | `1`                                              |
| 5      | 1     | AlgorithmId       | `1` = Ed25519 + ML-DSA-65 hybrid                 |
| 6      | 64    | Ed25519 signature | RFC 8032 Ed25519, over the signed message        |
| 70     | 3,309 | ML-DSA-65 signature | FIPS 204 ML-DSA-65 (hedged), over the signed message |

There are no variable-length fields and no multi-byte integers in v1.

## The signed message

Both algorithms sign the **same** short, domain-separated message:

```
SignedMessage = Context ‖ SHA-512(content)

Context = "PostQuantum.FileEncryption.Signing/v1 ed25519+ml-dsa-65 sha-512"  (UTF-8, 64 bytes)
```

- `content` is the raw byte sequence of the signed file or stream, hashed with streaming
  SHA-512 — signing and verifying run in constant memory for content of any size.
- The `Context` prefix domain-separates these signatures from any other use of the same
  keys, and pins the format version and algorithm suite into the signed message itself: a
  header that has been tampered into a different version or suite cannot redirect
  verification, because the context the verifier reconstructs would no longer match.
- Pre-hashing the content is the standard detached-signature construction (compare
  minisign/signify, Ed25519ph, and HashML-DSA); collision resistance rests on SHA-512.

## Verification (normative)

A verifier MUST proceed in this order and MUST fail closed:

1. If the signature is not exactly 3,379 bytes, reject as a **format error**.
2. If the magic is not `PQSG`, the FormatVersion is not `1`, or the AlgorithmId is not `1`,
   reject as a **format error**.
3. Compute `SignedMessage` from the content.
4. Verify the Ed25519 signature **and** the ML-DSA-65 signature against `SignedMessage`.
   Both MUST verify. If either fails, reject with a single generic error that does not
   reveal which component failed — the hybrid is only as strong as its error discipline.

In the reference implementation, step 1–2 failures raise `PqFormatException` and step 4
failures raise `PqSignatureException` with one fixed message.

## Signing (informative)

- The Ed25519 component is deterministic (RFC 8032).
- The ML-DSA-65 component uses **hedged** signing (FIPS 204's default recommendation), so
  signing the same content twice produces different — equally valid — signatures.

## Key encodings

| Key | Encoding | Length |
| --- | --- | ---: |
| Public (verification) | `Ed25519-pk(32) ‖ ML-DSA-65-pk(1952)` | 1,984 |
| Private (signing) | `Ed25519-seed(32) ‖ ML-DSA-65-sk(4032)` | 4,064 |

## What a detached signature does not provide

- It does not bind the signature to a file **name, path, or timestamp** — only to the bytes.
- It does not prevent **strip-and-resign**: anyone able to read the bytes can discard the
  sidecar and sign the same bytes with their own key. Authenticity is anchored in *which
  public key the verifier trusts*; distribute public keys over a trusted channel.
- It does not provide **timestamping** or revocation. A signature says nothing about *when*
  it was made.

These are the standard properties of detached signatures (GPG `--detach-sign`, minisign,
signify) and are listed in [KNOWN-GAPS.md](../KNOWN-GAPS.md).

## Versioning

Any change to the layout, the context string, the hash, or the algorithm suite requires a
new `FormatVersion` (or a new `AlgorithmId` where the layout permits) and an update to this
document in the same change.

---

*To God be the glory — 1 Corinthians 10:31.*
