# Threat Model

This document states what PostQuantum.FileEncryption is designed to defend, against whom, and
under what assumptions. It is written to be useful to a reviewer or auditor — and honest about
what is out of scope. It complements [SECURITY.md](../SECURITY.md) (policy) and
[KNOWN-GAPS.md](../KNOWN-GAPS.md) (open items).

## Assets

1. **Plaintext confidentiality** — the contents of an encrypted file.
2. **Plaintext integrity/authenticity** — assurance that decrypted output is exactly what was
   encrypted, by someone holding the key.
3. **Key material** — passphrases, derived content keys, ML-KEM private keys.

## Actors

- **Owner** — holds the passphrase or recipient private key. Trusted.
- **Network/storage adversary** — can read, copy, modify, reorder, truncate, or replay
  ciphertext at rest or in transit. Cannot break AES-256-GCM, PBKDF2/Argon2id, or ML-KEM-768.
- **Harvest-now-decrypt-later quantum adversary** — records ciphertext today to attack with a
  future quantum computer.
- **Malicious container author** — crafts a hostile `.pqfe` file and gives it to a victim to
  decrypt (e.g., to trigger resource exhaustion or a parser bug).

## Trust boundaries

```
            passphrase / private key
                     │  (trusted input)
   plaintext ──► [ PqFileEncryptor ] ──► .pqfe container ──► untrusted storage/network
                                                                   │
   plaintext ◄── [ PqFileDecryptor ] ◄── .pqfe container ◄────────┘
                     ▲  (everything past this arrow is attacker-controlled)
```

The decryptor treats the **entire container as attacker-controlled** until each chunk's
authentication tag verifies. The host process, RAM, and RNG are trusted.

## Security goals and the mechanisms that meet them

| Goal | Mechanism |
| --- | --- |
| Confidentiality of data | AES-256-GCM with a unique per-file content key |
| Post-quantum confidentiality of data | AES-256 (≈128-bit security under Grover) |
| Post-quantum key establishment (recipient mode) | ML-KEM-768 (FIPS 203) KEM-DEM, HKDF-SHA256 key wrap |
| Integrity / tamper-evidence | Per-chunk GCM tag; header bound as AAD |
| Anti-reordering / anti-splicing | Chunk counter in nonce and AAD |
| Anti-truncation | Final-chunk marker authenticated in AAD; decryption requires it |
| Passphrase-guessing resistance | PBKDF2-HMAC-SHA256 (≥100k) or Argon2id; unique per-file salt |
| No decryption oracle | Every auth failure → identical generic error |
| Bounded work on hostile input | KDF cost parameters range-checked before use |
| All-or-nothing file output | Temp file + atomic rename; partial output deleted on failure |
| Key hygiene | Derived keys, wrapped secrets, private keys zeroed after use |

## Assumptions

1. The platform's `System.Security.Cryptography` (AES-GCM, ML-KEM, HKDF, PBKDF2) and the
   Konscious Argon2id implementation are correct and side-channel-resistant to the degree their
   authors intend. **This library writes no primitive cryptography.**
2. The OS CSPRNG (`RandomNumberGenerator`) is secure.
3. The passphrase has adequate entropy. KDFs raise the cost of guessing but cannot rescue a
   weak secret.
4. The endpoint is not compromised (no malware, no keylogger).

## Explicit non-goals

- Hiding metadata: approximate plaintext size (to within a chunk) is visible; file names,
  paths, and timestamps are not protected.
- Protecting a caller-supplied `string` passphrase from lingering in managed memory (use the
  `ReadOnlyMemory<byte>` or `ReadOnlySpan<char>` overloads to control this).
- Deniability, traffic analysis resistance, or anti-forensics.
- Recipient mode in the **core** package alone — the in-core ML-KEM-768-only mode is
  deprecated (`PQFE002`). Production public-key encryption ships in
  `PostQuantum.FileEncryption.Hybrid` (X25519 + ML-KEM-768 combiner).

## Residual risks (tracked)

- **No independent audit.** The construction is standard, but unaudited. Funded engagements
  are welcome — see [SECURITY.md](../SECURITY.md).
- **Argon2id depends on a third-party managed implementation** (`Konscious.Security.Cryptography`),
  not the platform; the default KDF (PBKDF2) avoids this at runtime.
- **The Hybrid package depends on BouncyCastle** for both X25519 and ML-KEM-768 so it runs
  anywhere .NET 10 does, including hosts without a platform ML-KEM. BouncyCastle.NET is widely
  used and maintained but introduces a non-platform crypto provider into the recipient path.
- **Streaming decryption is not all-or-nothing** (chunks are written as they authenticate); the
  file APIs avoid this with a temp-file + atomic-move staging. See [KNOWN-GAPS.md](../KNOWN-GAPS.md).
- **`string` passphrase overloads** cannot zero the caller's `string`; the zeroable
  `ReadOnlyMemory<byte>` and `ReadOnlySpan<char>` overloads do.

## What an audit should focus on

1. The AAD construction and the claim that it defeats reorder/splice/truncation across all
   edge cases (empty input, single chunk, exact-multiple boundaries).
2. Nonce uniqueness under the per-file key (prefix ‖ counter) and the per-file key uniqueness.
3. The **hybrid combiner** in `PostQuantum.FileEncryption.Hybrid` — the X25519 + ML-KEM-768
   shared-secret combine, HKDF-SHA256 derivation, and AES-GCM content-key wrap — and its
   security claim that the content key remains safe if *either* primitive is later broken.
4. The multi-recipient envelope: per-recipient KEM encapsulation, ordering independence,
   and absence of any oracle when one recipient's slot decrypts but others do not.
5. The legacy KEM-DEM wrap on the deprecated inline ML-KEM-only mode (`PQFE002`), and the
   uniformity of decapsulation-failure handling across that path and the Hybrid path.
6. Parser robustness on hostile headers (covered by the fuzz harness on both the .NET and
   Rust → WASM parsers, but worth manual review).
7. Key-material lifetime and zeroization across encrypt, decrypt, and rewrap paths.

---

*To God be the glory — 1 Corinthians 10:31.*
