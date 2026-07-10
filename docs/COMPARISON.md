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
| Public-key recipients | Yes — hybrid X25519 + ML-KEM-768 (Hybrid package), multi-recipient | Yes (X25519) | Via box APIs | No |
| Post-quantum | AES-256 data (quantum-safe); hybrid PQ recipients (X25519 + ML-KEM-768) | No | No | No |
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

## Versus general-purpose crypto toolkits

A different category worth naming: the broad **"one API for all of cryptography"** .NET libraries —
typically BouncyCastle wrappers that expose a large menu of primitives (many block and stream
ciphers, RSA, hashing, HMAC, TOTP, X.509 certificates, encodings) and, increasingly, the
post-quantum primitives **ML-KEM** and **ML-DSA** as standalone building blocks. Several are MIT
and open, so this is **not** an open-vs-closed distinction — it is a difference of **scope and
altitude**.

- **Primitives vs a finished construction.** A toolkit hands you ML-KEM (and AES, and a KDF) and
  leaves the composition to you: choosing an authenticated mode, combining KEM + DEM correctly,
  managing nonces, deriving keys, framing the output. This library ships **one opinionated,
  finished construction** — an authenticated, chunked, fail-closed file format with the hybrid
  combiner already wired in. There is no unauthenticated path to select and no primitive to
  misassemble.
- **No footguns by omission.** Comprehensive toolkits include legacy primitives (e.g. MD5, SHA-1,
  DES, ECB mode) for completeness. This library deliberately ships none of them; every path is
  AES-256-GCM with authenticated framing. Breadth is their feature; a small, safe surface is ours.
- **Hybrid, not bare Kyber.** Where a toolkit typically exposes ML-KEM alone, the recipient path
  here is a **hybrid X25519 + ML-KEM-768 combiner** — confidentiality survives even if *either*
  primitive is later broken ([HYBRID-COMBINER.md](HYBRID-COMBINER.md)).
- **A verifiable format, not just a library.** A toolkit is an API; this is a **frozen, publicly
  specified container** ([FILE-FORMAT.md](FILE-FORMAT.md)) pinned by cross-implementation
  byte-exact vectors and a second (Rust) implementation, with a published threat model and
  supply-chain provenance. That is the layer a general-purpose library does not set out to provide.

**When a general-purpose toolkit fits better:** you need breadth this library intentionally omits —
certificates, TOTP, RSA, standalone signature or KEM primitives, or a grab-bag of ciphers — or you
are deliberately assembling your own construction and want the building blocks rather than a
finished, frozen format. For **encrypting files against a quantum-capable adversary, safely and
verifiably**, a single-purpose tool that cannot be misused is the better fit.

## Honest caveats

This library is **younger** than age and libsodium and has **not been independently audited**
(see [KNOWN-GAPS.md](../KNOWN-GAPS.md)). age and libsodium have years of scrutiny. Where that
scrutiny is the deciding factor today, prefer them — and revisit this library as it matures toward
an audited `1.0`.

*To God be the glory — 1 Corinthians 10:31.*
