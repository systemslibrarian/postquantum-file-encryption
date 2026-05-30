# Security Policy

PostQuantum.FileEncryption is security-sensitive software, and it is an early preview. This
document describes what it defends against, what it does not, and how to report a problem. It
is written to be honest rather than reassuring.

## Supported versions

| Version            | Supported          |
| ------------------ | ------------------ |
| `0.2.0-preview.*`  | ✅ (preview only)   |
| `< 0.2`            | ❌                  |

The on-disk container format is **not frozen** before `1.0`. A file encrypted by a preview
build is not guaranteed to be decryptable by a later build. v0.2 does not read the v0.1 format.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**:

- Use **GitHub Security Advisories** ("Report a vulnerability") on the repository, or
- email the maintainer at **systemslibrarian@gmail.com** with `SECURITY` in the subject.

Please include a description, affected version, and a minimal reproduction if you can. We aim
to acknowledge within **5 business days**. Please do not open a public issue for a security
report until a fix is available and coordinated.

## What this library defends against

- **Confidentiality of file contents** against an attacker who obtains the ciphertext but not
  the key, using AES-256-GCM with a unique per-file content key.
- **Integrity and authenticity.** Any modification of the ciphertext, header, or framing is
  detected and rejected. The authenticated additional data binds the key-establishment
  parameters, the chunk ordinal, and the final-chunk marker, defeating bit-flipping, header
  tampering, chunk reordering, splicing between containers, and truncation.
- **Quantum-resistant confidentiality of the data**, via AES-256 (≈128-bit security against a
  Grover attacker), and **quantum-resistant key establishment** for recipient mode, via
  ML-KEM-768 (FIPS 203) in a hybrid KEM-DEM construction.
- **Bounded work on untrusted input.** KDF cost parameters carried in a container (PBKDF2
  iterations, Argon2id memory/iterations) are range-checked before use, so a malicious header
  cannot force unbounded memory or CPU — it fails closed as a `PqFormatException`.

## What this library does NOT defend against

This list is intentionally explicit. See [KNOWN-GAPS.md](KNOWN-GAPS.md) for the roadmap.

- **Weak passphrases.** PBKDF2 and Argon2id raise the cost of guessing, but cannot rescue a
  weak secret. Argon2id (memory-hard) is the stronger choice for human-chosen passphrases.
- **Metadata confidentiality.** The container does not hide the approximate plaintext size and
  does not encrypt file names or paths. Chunk boundaries reveal a coarse size.
- **Classical/PQ hybrid key exchange.** Recipient mode is a *KEM-DEM hybrid* (asymmetric KEM
  wrapping a symmetric key), not a *PQ-plus-classical* combiner. It relies on ML-KEM-768 alone
  for the asymmetric step. A combined X25519+ML-KEM mode is a candidate for a future release.
- **Endpoint compromise.** A compromised machine or a keylogged passphrase defeats any file
  encryptor. Passphrases passed as `string` may be retained by the runtime beyond our control;
  use the `ReadOnlyMemory<byte>` overloads to keep secrets in memory you can zero.
- **Side-channel resistance beyond the platform's.** We rely on the underlying implementations
  (.NET `System.Security.Cryptography`, Konscious Argon2id) for constant-time behavior.
- **Independent audit.** This code has **not** been independently audited.

## Dependencies

- `Konscious.Security.Cryptography.Argon2` provides the Argon2id KDF. It is a widely used
  managed implementation but is **not formally audited**; this is noted in
  [KNOWN-GAPS.md](KNOWN-GAPS.md). The default KDF (PBKDF2) uses only the .NET runtime.
- ML-KEM and all symmetric primitives come from .NET's `System.Security.Cryptography`.

## Cryptographic design principles

- **No homegrown cryptography.** Primitives are composed in standard patterns (KEM-DEM,
  password hashing, AEAD) only.
- **Authenticated encryption only.** There is no unauthenticated mode.
- **Fail closed.** On any doubt about authenticity, the library throws and emits no plaintext.
  There is no partial-success path and no error oracle.
- **Transparent format.** The container is fully specified in
  [docs/FILE-FORMAT.md](docs/FILE-FORMAT.md) so it can be reviewed and re-implemented, and is
  pinned by known-answer test vectors.

*To God be the glory — 1 Corinthians 10:31.*
