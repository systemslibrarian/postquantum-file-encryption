# Support

## Getting help

- **Questions / usage:** open a [GitHub Discussion or Issue](https://github.com/systemslibrarian/postquantum-file-encryption/issues)
  (use the bug template for defects). Do not include real passphrases, keys, or sensitive files.
- **Security vulnerabilities:** **do not** open a public issue — report privately per
  [SECURITY.md](SECURITY.md) (GitHub Security Advisory or email).

## What's stable vs. experimental

| Surface | Status |
| --- | --- |
| Passphrase encryption (AES-256-GCM, PBKDF2/Argon2id) — file, stream, in-memory | **Stable** (production-ready) |
| Telemetry `EventSource`, `DecryptAtomicAsync` | **Stable** |
| ML-KEM-768 recipient mode (`PqKeyPair`, recipient overloads) | **Experimental** — `[Experimental("PQFE001")]`, platform-gated |
| On-disk container format | `0.x` — may change before `1.0` |

## Supported versions

| Version | Status |
| --- | --- |
| `0.1.x` | Supported (latest minor receives fixes) |
| `< 0.1` | Unsupported |

This is a pre-`1.0` project: only the latest `0.x` minor is supported. A formal Long-Term Support
(LTS) policy aligned with .NET's LTS cadence is planned for `1.0`.

## Security response targets

These are good-faith targets for the maintainer (not a contractual SLA):

- **Acknowledge** a vulnerability report within **5 business days**.
- **Triage / severity assessment** within **10 business days**.
- **Fix or mitigation** for high/critical issues as a priority, coordinated with the reporter
  before public disclosure.

Commercial support, contractual SLAs, and LTS builds are not offered today; this section
documents the **policy**, and the structure is in place should that change.

*To God be the glory — 1 Corinthians 10:31.*
