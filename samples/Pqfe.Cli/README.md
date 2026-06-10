# pqfe — file encryption from the command line

**Encrypt and decrypt `.pqfe` containers without writing a line of C#.** `pqfe` is the
official command-line frontend for
[PostQuantum.FileEncryption](https://www.nuget.org/packages/PostQuantum.FileEncryption):
authenticated AES-256-GCM, PBKDF2-HMAC-SHA256 or Argon2id passphrase derivation, atomic
output files, and fail-closed decryption — a wrong passphrase and a tampered file produce
the same error and emit no plaintext.

```bash
dotnet tool install -g PostQuantum.FileEncryption.Tool
```

Requires the .NET 10 runtime or later.

## Usage

```bash
pqfe encrypt secrets.db secrets.db.pqfe            # prompts for a passphrase (no echo)
pqfe decrypt secrets.db.pqfe secrets.db
```

For scripts and CI, read the passphrase from an environment variable instead of a prompt:

```bash
export PQFE_PASS='correct horse battery staple'
pqfe encrypt backup.tar backup.tar.pqfe --passphrase-env PQFE_PASS
pqfe decrypt backup.tar.pqfe backup.tar --passphrase-env PQFE_PASS
```

### Options

| Option | Effect |
| --- | --- |
| `--argon2id` | Derive the key with Argon2id (memory-hard) instead of PBKDF2-HMAC-SHA256. Decryption reads the KDF from the container header — no flag needed. |
| `--passphrase-env VAR` | Read the passphrase from environment variable `VAR` instead of prompting. |

### Exit codes

Follow `sysexits.h` conventions so failures are scriptable: `0` ok, `64` usage,
`65` data error (wrong passphrase **or** tampered/truncated ciphertext — deliberately
indistinguishable), `66` missing input, `74` I/O error.

## What it writes

Standard [`.pqfe` v2 containers](https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/docs/FILE-FORMAT.md) —
the format is **FROZEN** for the 1.x line and pinned by published cross-implementation
test vectors. Anything `pqfe` encrypts, the library (and any conforming implementation)
can decrypt, and vice versa.

`pqfe` covers passphrase encryption. For public-key (recipient) encryption — hybrid
X25519 + ML-KEM-768, multi-recipient — use the
[PostQuantum.FileEncryption.Hybrid](https://www.nuget.org/packages/PostQuantum.FileEncryption.Hybrid)
library package.

## Source

Lives in the main repository at
[`samples/Pqfe.Cli`](https://github.com/systemslibrarian/postquantum-file-encryption/tree/main/samples/Pqfe.Cli),
built and published by the same release pipeline as the library: deterministic build,
CycloneDX SBOM, and SLSA-style build-provenance attestation on every release.

*To God be the glory — 1 Corinthians 10:31.*
