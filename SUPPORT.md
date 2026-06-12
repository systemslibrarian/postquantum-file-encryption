# Support

This document is the **lifecycle policy** for PostQuantum.FileEncryption. It describes which
versions receive fixes, how long that protection lasts, and where to ask for help. For the
disclosure process and threat statement, see [SECURITY.md](SECURITY.md); for the open ledger,
[KNOWN-GAPS.md](KNOWN-GAPS.md).

## Getting help

- **Questions / usage:** open a [GitHub Discussion or Issue](https://github.com/systemslibrarian/postquantum-file-encryption/issues)
  (use the bug template for defects). Do not include real passphrases, keys, or sensitive files.
- **Security vulnerabilities:** **do not** open a public issue — report privately per
  [SECURITY.md](SECURITY.md) (GitHub Security Advisory or email).

## What's stable

| Surface | Status |
| --- | --- |
| Passphrase encryption (AES-256-GCM, PBKDF2 or Argon2id) — file, stream, in-memory | **Stable** |
| Envelope-encryption seam (`IContentKeyProvider`, `LocalKekContentKeyProvider`) | **Stable** |
| Telemetry `EventSource`, `DecryptAtomicAsync`, synchronous `EncryptBytes`/`DecryptBytes` | **Stable** |
| Hybrid public-key encryption (X25519 + ML-KEM-768) — `PostQuantum.FileEncryption.Hybrid` | **Stable** |
| Multi-recipient containers (`KeySource = 4`) — Hybrid package | **Stable** |
| On-disk `.pqfe` v2 container format | **Frozen for the `1.x` line** |
| Inline ML-KEM-768-only recipient mode in the **core** (`PqKeyPair`, recipient overloads) | **Deprecated (`PQFE002`)** — source-compatible only |

The frozen format means a file produced by any `1.x` build opens in every other `1.x` build,
on every supported platform, in either implementation (the .NET library and the Rust → WASM
reference). Any incompatible format change requires a `2.0` major release.

## Supported versions

| Version | Status | Notes |
| --- | --- | --- |
| `1.x` (current line) | ✅ Supported | Security fixes land on the latest `1.x` minor. |
| `1.0.0-rc.*` | ⚠️ Pre-release | Treated as part of `1.0`; please upgrade to `1.0.0` once it ships. |
| `0.x` | ❌ Unsupported | Pre-`1.0`; format was not yet frozen. No `0.x → 1.x` migration tooling — decrypt with `0.x` and re-encrypt with `1.x`. |

The Hybrid package (`PostQuantum.FileEncryption.Hybrid`) is **always shipped at the same
version as the core**, by design — see [docs/VERSIONING.md](docs/VERSIONING.md). When this
table says "`1.x` is supported," it means both packages together.

### Long-term support intent

This is a single-maintainer project, so a contractual LTS SLA is not on offer. The
**operational commitment** for the `1.x` line is:

- The latest `1.x` minor receives security fixes.
- Format compatibility is preserved across all of `1.x` (the `.pqfe` v2 freeze).
- A `2.0` major would carry a new `FormatVersion` and a documented migration path, and the
  preceding `1.x` minor would continue to receive security fixes for **at least 12 months**
  after `2.0` is tagged.

If a funded support arrangement would be useful for your organisation, please contact the
maintainer.

## Runtime & platform support

| Aspect | Requirement |
| --- | --- |
| Target frameworks | `net8.0` (LTS) and `net10.0`. Identical public API on both; the deprecated inline ML-KEM-only mode (PQFE002) requires platform ML-KEM and reports `IsSupported == false` on `net8.0` — the Hybrid package works on both targets. |
| Operating system | Windows, Linux, macOS — anywhere .NET 8/10 + AES-GCM runs |
| Browser WebAssembly | Not supported (.NET `AesGcm` is `[UnsupportedOSPlatform("browser")]`). Use the Rust → WASM core in `samples/pqfe-wasm` for a fully client-side reader. |
| Trimming / Native AOT | Compatible (`IsAotCompatible=true`, smoke-tested in CI on every push) |
| FIPS mode | Argon2id is not FIPS-validated (Konscious). PBKDF2-HMAC-SHA256 + AES-GCM use platform primitives. |

When .NET ships a new LTS, this library will move to it on a deliberate cadence — never
automatically — and that move will be a minor bump of the `1.x` line, with the previous
target supported for one further minor.

## Deprecation policy

A public-API surface becomes deprecated by being marked `[Obsolete]` with a `PQFExxx`
diagnostic id and a pointer to the replacement.

- A deprecated member emits a build **warning** in the calling project, never an error.
- It continues to honour its existing fail-closed contract for at least **one full minor
  release** after deprecation before removal is even considered.
- Removal is a breaking change and requires a major version bump.

Current deprecations:

| ID | Surface | Replacement | First deprecated |
| --- | --- | --- | --- |
| `PQFE002` | Inline ML-KEM-768-only recipient mode in the core (`PqKeyPair`, `PqRecipientPublicKey`, `PqRecipientPrivateKey`, recipient overloads on `PqFileEncryptor`/`PqFileDecryptor`) | `PostQuantum.FileEncryption.Hybrid` (X25519 + ML-KEM-768 combiner, multi-recipient) | `1.0.0-rc.2` |

Removal of `PQFE002` is targeted for the next major release (`2.0`).

## Security response targets

These are **good-faith targets** for a single-maintainer project, not a contractual SLA:

- **Acknowledge** a vulnerability report within **5 business days**.
- **Triage / severity assessment** within **10 business days**.
- **Fix or mitigation** for high/critical issues as a priority, coordinated with the
  reporter before public disclosure.
- **Public advisory** published via GitHub Security Advisories once a fix ships.

See [SECURITY.md](SECURITY.md) for the full disclosure process.

---

*To God be the glory — 1 Corinthians 10:31.*
