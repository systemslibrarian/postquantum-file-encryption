# How PostQuantum.FileEncryption compares

Honest positioning against well-known file/stream encryption tools. None of these are "wrong" —
they target different ecosystems and trade-offs. Pick the one that fits.

## At a glance

| | **PostQuantum.FileEncryption** | **age** | **libsodium secretstream** | **OpenSSL `enc`** |
| --- | --- | --- | --- | --- |
| Ecosystem | .NET library | CLI / Go lib | C lib (+ bindings) | CLI / C lib |
| Data cipher | AES-256-GCM | ChaCha20-Poly1305 | XChaCha20-Poly1305 | user-chosen (easy to misuse) |
| Authenticated | Always | Always | Always | Only with `-aead` modes, opt-in |
| Passphrase KDF | PBKDF2 or Argon2id | scrypt | (app's choice) | weak by default (legacy) |
| Public-key recipients | Experimental (ML-KEM-768) | Yes (X25519) | Via box APIs | No |
| Post-quantum | AES-256 data (quantum-safe); PQ KEM experimental | No | No | No |
| Streaming / large files | Yes, chunked, bounded memory | Yes | Yes (designed for it) | Yes |
| Anti-truncation / reorder | Yes (authenticated framing) | Yes | Yes | No (raw modes) |
| Specified, vectored format | Yes (+ cross-impl byte-exact vectors) | Yes | N/A (API, not a file format) | N/A |
| Telemetry / SIEM hooks | Yes (EventSource) | No | No | No |

## When to choose this library

- You're on **.NET** and want a drop-in, fail-closed file/stream encryptor with **excellent
  defaults** and no FFI.
- You care about **post-quantum data confidentiality now** (AES-256) and want an **upgrade path**
  to PQ public-key encryption.
- You want **enterprise affordances**: telemetry, atomic output, a documented format with test
  vectors, threat model, and supply-chain hygiene.

## When another tool fits better

- **age** — you want a battle-tested, audited CLI/format with mature X25519 recipients and a large
  ecosystem, and you're not tied to .NET.
- **libsodium secretstream** — you're in C/C++/native land and want a minimal, audited streaming
  AEAD primitive (and you'll define your own on-disk framing).
- **OpenSSL `enc`** — generally **avoid** for new designs; it's easy to use in unauthenticated or
  weak-KDF modes. Prefer any of the above.

## Honest caveats

This library is **younger** than age and libsodium and has **not been independently audited**
(see [KNOWN-GAPS.md](../KNOWN-GAPS.md)). age and libsodium have years of scrutiny. Where that
scrutiny is the deciding factor today, prefer them — and revisit this library as it matures toward
an audited `1.0`.

*To God be the glory — 1 Corinthians 10:31.*
