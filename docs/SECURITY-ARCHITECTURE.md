# Security Architecture & Crypto Inventory

A reviewer- and auditor-oriented overview of how the library is built, every cryptographic
primitive it uses and why, and what FIPS-constrained environments need to know. Pair this with
the [THREAT-MODEL.md](THREAT-MODEL.md) and the [FILE-FORMAT.md](FILE-FORMAT.md).

## Architecture at a glance

```
Public API            PqFileEncryptor / PqFileDecryptor       (file, stream, in-memory)
                              │  options, progress, cancellation, telemetry
Orchestration         Internal/PqContainer                     (one funnel; EventSource here)
                       ├── key establishment  Internal/KeyEstablishment  (PBKDF2 / Argon2id / ML-KEM)
                       └── container codec     Internal/IPqContainerCodec → PqContainerEngine
Primitives            System.Security.Cryptography  +  Konscious (Argon2id)
```

- **One funnel.** Every operation passes through `PqContainer`, the single place where key
  establishment meets the chunked AEAD body — the natural seam for review, telemetry, and a
  future `PostQuantum.FileFormat` codec.
- **No homegrown cryptography.** The library composes vetted primitives; it implements none.
- **Fail-closed.** Authentication failures throw a single generic exception and emit no
  plaintext (no decryption oracle).

## Crypto inventory

| Purpose | Algorithm | Source | Parameters / notes |
| --- | --- | --- | --- |
| Data encryption (AEAD) | AES-256-GCM | .NET `AesGcm` | 256-bit key, 96-bit nonce, 128-bit tag |
| Per-chunk nonce | prefix ‖ counter | — | 4-byte random per-file prefix ‖ 8-byte counter; unique per chunk under the key |
| Passphrase KDF (default) | PBKDF2-HMAC-SHA256 | .NET `Rfc2898DeriveBytes` | default 600,000 iterations; per-file 128-bit salt |
| Passphrase KDF (opt-in) | Argon2id (v0x13) | Konscious | default 19 MiB / 2 passes / 1 lane |
| Key wrap (recipient, **experimental**) | HKDF-SHA256 + AES-256-GCM | .NET `HKDF`, `AesGcm` | KEM-DEM |
| KEM (recipient, **experimental**) | ML-KEM-768 (FIPS 203) | .NET `MLKem` | platform-gated; NIST category 3 |
| RNG | OS CSPRNG | .NET `RandomNumberGenerator` | salt, nonce prefix, content keys |

### Why these

- **AES-256-GCM** — authenticated, hardware-accelerated, standardized, and quantum-resistant for
  confidentiality (Grover leaves ≈128-bit security). One primitive for confidentiality + integrity.
- **PBKDF2-HMAC-SHA256** — FIPS-approved and in-box; the safe default. **Argon2id** — memory-hard,
  the better choice against GPU/ASIC cracking where a dependency is acceptable.
- **ML-KEM-768** — NIST-standardized post-quantum KEM for the (experimental) public-key path.
- **HKDF-SHA256** — standard KDF to turn a KEM shared secret into a key-wrapping key.

## FIPS 140-3 considerations

The library performs **no cryptography of its own**, so FIPS posture is inherited from the
modules it calls:

- **FIPS-compatible path:** AES-GCM, PBKDF2-HMAC-SHA256, HKDF-SHA256, ML-KEM-768, and the RNG all
  come from .NET's `System.Security.Cryptography`, which routes to the platform's validated module
  (Windows CNG / OpenSSL) when the OS runs in FIPS mode. **For a FIPS-only deployment, use the
  default PBKDF2 KDF and the platform in FIPS mode.**
- **Not FIPS:** **Argon2id is provided by Konscious**, a managed implementation that is **not a
  FIPS-validated module**. FIPS-constrained deployments must **not** select `PqKdf.Argon2id`.
- We do not claim a FIPS 140-3 validation; we document the path to operating only on validated
  modules. Formal validation is an organizational/lab activity outside this repository.

## Key material lifecycle

- Content keys, derived keys, KEM shared secrets, key-wrapping keys, and the UTF-8 passphrase
  bytes the library allocates are zeroed with `CryptographicOperations.ZeroMemory` in `finally`.
- A caller-supplied `string` passphrase cannot be zeroed by the library; the
  `ReadOnlyMemory<byte>` overloads exist for callers who manage that themselves.
- Recipient private keys (`PqRecipientPrivateKey`) are `IDisposable` and zero on dispose.

---

*To God be the glory — 1 Corinthians 10:31.*
