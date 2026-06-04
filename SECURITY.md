# Security Policy

PostQuantum.FileEncryption is security-sensitive software. This document describes what it
defends against, what it does not, and how to report a problem. It is written to be honest
rather than reassuring.

## Supported versions

The symmetric, passphrase-based engine is production-ready. The `.pqfe` v2 container format
is **frozen for the `1.x` line** — every byte is pinned by published conformance vectors, and
any incompatible change requires a `2.0` major version.

| Version            | Supported | Notes                                                    |
| ------------------ | --------- | -------------------------------------------------------- |
| `1.0.x` (incl. rc) | ✅        | Current line. Security fixes land here.                  |
| `0.x`              | ❌        | Pre-`1.0`. Format was not yet frozen; please upgrade.    |

A file produced by any `1.x` build is readable by every other `1.x` build. There is no
`0.x` ↔ `1.x` format migration path; re-encrypt with a `1.x` build instead.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**:

- Use **GitHub Security Advisories** ("Report a vulnerability") on the repository, or
- email the maintainer at **systemslibrarian@gmail.com** with `SECURITY` in the subject.

Please include a description, affected version, and a minimal reproduction if you can. We aim
to acknowledge within **5 business days**. Please do not open a public issue for a security
report until a fix is available and coordinated.

## What this library defends against

- **Confidentiality of file contents** against an attacker who obtains the ciphertext but
  not the key, using AES-256-GCM with a unique per-file content key.
- **Integrity and authenticity.** Any modification of the ciphertext, header, or framing is
  detected and rejected. The authenticated additional data binds the key-establishment
  parameters, the chunk ordinal, and the final-chunk marker, defeating bit-flipping, header
  tampering, chunk reordering, splicing between containers, and truncation.
- **Quantum-resistant confidentiality of the data**, via AES-256 (≈128-bit security against
  a Grover attacker). For quantum-resistant *key establishment* with a hybrid combiner that
  remains secure if either primitive is later broken, use the companion
  **`PostQuantum.FileEncryption.Hybrid`** package (X25519 + ML-KEM-768, multi-recipient).
- **Bounded work on untrusted input.** KDF cost parameters carried in a container (PBKDF2
  iterations, Argon2id memory/iterations) are range-checked before use, so a malicious
  header cannot force unbounded memory or CPU — it fails closed as a `PqFormatException`.
- **No decryption oracle.** Every authentication failure (wrong passphrase, tampered
  ciphertext, truncated container, spliced frames) raises the same generic
  `PqDecryptionException` with the same message. The library does not distinguish "wrong
  key" from "tampered data" at the public surface.
- **No partial output on failure.** File APIs stage every byte to a sibling temp file and
  only `File.Move` it into place on full success. Stream callers can opt into the same
  all-or-nothing guarantee via `DecryptAtomicAsync`.

## What this library does NOT defend against

This list is intentionally explicit. See [KNOWN-GAPS.md](KNOWN-GAPS.md) for the open ledger.

- **Weak passphrases.** PBKDF2 and Argon2id raise the cost of guessing, but cannot rescue a
  weak secret. Argon2id (memory-hard) is the stronger choice for human-chosen passphrases.
- **Metadata confidentiality.** The container does not hide the approximate plaintext size
  and does not encrypt file names or paths. Chunk boundaries reveal a coarse size.
- **Endpoint compromise.** A compromised machine or a keylogged passphrase defeats any file
  encryptor. Passphrases passed as `string` may be retained by the runtime beyond our
  control; use the `ReadOnlyMemory<byte>` or `ReadOnlySpan<char>` overloads to keep secrets
  in memory you can zero.
- **Side-channel resistance beyond the platform's.** We rely on the underlying
  implementations (.NET `System.Security.Cryptography`, Konscious Argon2id) for
  constant-time behavior.
- **Independent audit.** This code has **not** been independently audited. Funded
  engagements are welcome — please contact the maintainer.

## Inline ML-KEM-only recipient mode (deprecated)

The core package still carries an inline ML-KEM-768-only recipient mode for
source-compatibility. It is marked `[Obsolete]` with diagnostic id **`PQFE002`** as of
`1.0.0-rc.2` and is retained only so existing callers still build. It is **not** a hybrid
combiner — it relies on ML-KEM-768 alone for the asymmetric step, and its security collapses
to the symmetric core if ML-KEM is later weakened. **New code must use
`PostQuantum.FileEncryption.Hybrid`** (X25519 + ML-KEM-768 combiner, multi-recipient, fully
managed, runs anywhere). Removal of the inline mode is targeted for a future major release.

## Dependencies

- `Konscious.Security.Cryptography.Argon2` provides the Argon2id KDF. It is a widely used
  managed implementation but is **not formally audited**; this is noted in
  [KNOWN-GAPS.md](KNOWN-GAPS.md). The default KDF (PBKDF2) uses only the .NET runtime.
- All symmetric primitives, HKDF, and ML-KEM (when used by the deprecated inline mode) come
  from .NET's `System.Security.Cryptography`.
- The Hybrid package additionally uses `BouncyCastle.Cryptography` for X25519 and ML-KEM,
  selected so the package runs on every .NET 10 platform without a native ML-KEM dependency.

## Cryptographic design principles

- **No homegrown cryptography.** Primitives are composed in standard patterns (KEM-DEM,
  password hashing, AEAD) only.
- **Authenticated encryption only.** There is no unauthenticated mode.
- **Fail closed.** On any doubt about authenticity, the library throws and emits no
  plaintext. There is no partial-success path and no error oracle.
- **Transparent format.** The container is fully specified in
  [docs/FILE-FORMAT.md](docs/FILE-FORMAT.md) and pinned by cross-implementation
  known-answer test vectors, so it can be reviewed and re-implemented independently.

## Supply chain

Every release tag publishes:

- a **CycloneDX SBOM** (`sbom.core.cdx.json`, `sbom.hybrid.cdx.json`),
- a **SLSA-style build-provenance attestation** over the `.nupkg` artifacts (verifiable with
  `gh attestation verify`),
- the `.nupkg` files themselves (also published to nuget.org).

See [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md) for verification commands.

*To God be the glory — 1 Corinthians 10:31.*
