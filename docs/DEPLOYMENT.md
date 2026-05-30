# Deployment & Hardening Guide

Practical guidance for using PostQuantum.FileEncryption safely in real systems. See
[SECURITY-ARCHITECTURE.md](SECURITY-ARCHITECTURE.md) for the why and [THREAT-MODEL.md](THREAT-MODEL.md)
for what it does and does not defend.

## Choosing a KDF and cost

| Situation | Recommendation |
| --- | --- |
| Default / FIPS-constrained | PBKDF2-HMAC-SHA256 (the default). Keep iterations ≥ 600,000; raise on fast servers. |
| Human-chosen passphrases, non-FIPS | `PqKdf.Argon2id` (memory-hard). Start at 19 MiB / 2 passes; raise memory as RAM allows. |
| Interactive UX where 600k is too slow | Lower PBKDF2 iterations **consciously** (min 100,000) and document the trade-off. |

The KDF and its parameters travel in the container header, so decryption needs no configuration
and you can raise costs over time without breaking old files.

## Passphrase & secret handling

- Prefer the **`ReadOnlyMemory<byte>` passphrase overloads** so you can zero the bytes yourself;
  the `string` overloads are convenient but the runtime may retain the string.
- Never log passphrases or keys. The library's telemetry is deliberately non-sensitive.
- Recipient private keys (experimental) implement `IDisposable` — dispose them to zero the bytes.

## All-or-nothing output

- The **file APIs are already atomic** (temp file + rename); a failure leaves no partial output.
- For **stream → stream**, the default `DecryptAsync` emits chunks as they authenticate. If a
  consumer must never see partial plaintext on a truncated input, use **`DecryptAtomicAsync`**
  (buffers fully, then emits) or the file API.

## Large files & resource limits

- Streaming keeps memory bounded (one chunk at a time); tune `ChunkSizeBytes` for your I/O.
- When decrypting **untrusted** containers, the library already caps KDF memory/iterations from
  the header. Still, apply your own size/time limits at the call site for defense in depth.
- The in-memory `EncryptBytesAsync`/`DecryptBytesAsync` and `DecryptAtomicAsync` buffer in RAM —
  use the file/stream APIs for very large inputs.

## FIPS mode

Run the OS in FIPS mode and use the **default PBKDF2** KDF. Do **not** select Argon2id (its
Konscious implementation is not FIPS-validated). See [SECURITY-ARCHITECTURE.md](SECURITY-ARCHITECTURE.md).

## Observability

Subscribe to the `PostQuantum.FileEncryption` `EventSource` (via `EventListener`, `dotnet-trace`,
EventPipe, or OpenTelemetry) to pipe operation start/stop/fail, algorithm label, byte counts, and
timing into your SIEM. Events carry **no** secrets. Failures are reported by exception-type name,
not message, so they never leak why decryption failed.

## Upgrade / rollback runbook (pre-1.0)

1. Pin the package version; review [CHANGELOG.md](../CHANGELOG.md) before upgrading.
2. If a release bumps `FormatVersion`, follow the migration note (continue-to-read or rewrap).
3. Keep the previous version available to decrypt any not-yet-migrated containers during rollout.
4. Re-run your own round-trip smoke test on representative files after upgrading.

*To God be the glory — 1 Corinthians 10:31.*
