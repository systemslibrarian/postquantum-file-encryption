# Auditor's Guide

This project has **not** had a funded, independent cryptographic audit
([GOLD-STANDARD.md](GOLD-STANDARD.md) §6 tracks that honestly). This page exists to make
the next-best thing as cheap as possible: it tells a qualified reviewer — whether you have
two hours or two weeks — exactly where the security-critical code is, which invariants to
attack, how to run the existing evidence, and where to look first. If you review any part
of this library, that work is valued and credited; see
[Reporting and credit](#reporting-and-credit).

## The attack surface is small on purpose

Everything cryptographic lives in **~1,700 lines** across eleven files. Nothing outside
these files touches keys, nonces, tags, or container parsing.

### Core package (`src/PostQuantum.FileEncryption/Internal/`)

| File | Lines | What it does — and what to check |
| --- | ---: | --- |
| `PqContainerEngine.cs` | 287 | The chunked AES-256-GCM data plane: nonce construction, AAD binding, frame parsing, the fail-closed decrypt loop |
| `KeyEstablishment.cs` | 276 | PBKDF2 / Argon2id derivation; ML-KEM-768 KEM-DEM (deprecated inline mode); range checks on **untrusted** header parameters |
| `PqContainer.cs` | 192 | Orchestration: establish key → build header → invoke codec; key zeroing on every path including pre-codec failures |
| `ContainerFormat.cs` | 147 | v2 header constants, serialization, and parse-side validation |
| `FileIo.cs` | 56 | Temp-file-plus-atomic-move so a destination file is never partial |
| `IPqContainerCodec.cs` | 50 | The delegation seam (interface only) |
| `PqfeEventSource.cs` | 48 | Telemetry — verify it can never leak key material or plaintext |

### Hybrid package (`src/PostQuantum.FileEncryption.Hybrid/`)

| File | Lines | What it does — and what to check |
| --- | ---: | --- |
| `Internal/HybridKeyEstablishment.cs` | 258 | The X25519 + ML-KEM-768 combiner: encapsulate/agree → HKDF-SHA256 → AES-256-GCM key wrap; the multi-recipient scan loop |
| `PqHybridKeyPair.cs` | 171 | Key generation, import/export, zeroing on dispose |
| `PqHybridEncryptor.cs` | 127 | CEK generation and wrap orchestration; CEK zeroing on failure paths |
| `PqHybridDecryptor.cs` | 68 | Unwrap orchestration |

What you should **not** need to review: the primitives themselves. AES-GCM, PBKDF2, HKDF,
and ML-KEM (core) come from .NET's `System.Security.Cryptography`; ML-KEM and X25519
(Hybrid) from BouncyCastle; Argon2id from Konscious. The full inventory, with versions and
FIPS notes, is in [SECURITY-ARCHITECTURE.md](SECURITY-ARCHITECTURE.md). This library only
*composes* them — the composition is what needs eyes.

## The invariants to attack

Each of these is a claim the library makes. Breaking any one of them is a reportable
finding.

1. **Nonce uniqueness.** Each container gets a fresh random content key and a random
   4-byte nonce prefix; each chunk's nonce is `prefix ‖ big-endian 64-bit counter`
   (`PqContainerEngine.BuildNonce`). Key-wrap nonces are independently random per wrap.
   No nonce may ever repeat under the same key.
2. **AAD binding defeats structural tampering.** Every chunk's AAD is
   `header ‖ counter ‖ frameType` (`PqContainerEngine.BuildAad`), so header tampering,
   chunk reordering, splicing between containers, and truncation must all surface as
   authentication failures. Decryption succeeds only after a chunk marked *final*
   authenticates (`sawFinal`).
3. **Fail closed, no oracle.** Every authenticity failure — wrong key, altered byte,
   truncation — throws the same generic `PqDecryptionException` and emits no plaintext.
   `PqFormatException` is thrown only for malformations detectable *without* any key
   material, so the split reveals nothing an attacker doesn't already know.
4. **Untrusted headers cannot cause unbounded work or out-of-bounds reads.** KDF
   parameters read from a container are range-checked before use
   (`KeyEstablishment.DerivePassphraseKeyAsync`), and a caller-configurable
   `PqDecryptionLimits` can lower those ceilings further for untrusted input — rejection
   happens before any derivation work. Frame lengths are checked against the declared
   chunk size; chunk buffers are additionally capped by the container's known length;
   recipient-block lengths must match exactly.
5. **Key material is zeroed.** Every derived or copied secret (CEK, KEK, shared secrets,
   IKM, private-key copies) is zeroed with `CryptographicOperations.ZeroMemory` in a
   `finally`, on success and failure paths alike. Known, documented exceptions:
   BouncyCastle's internal key copies and `string` passphrases
   ([KNOWN-GAPS.md](../KNOWN-GAPS.md)).
6. **The hybrid combiner needs both secrets.** The key-wrapping key is
   `HKDF-SHA256(ss_mlkem ‖ ss_x25519)` with a domain-separating `info` string
   (`HybridKeyEstablishment.DeriveKek`); recovering the CEK must require breaking *both*
   primitives. Rationale and comparison against X-Wing/HPKE:
   [HYBRID-COMBINER.md](HYBRID-COMBINER.md). Note ML-KEM's implicit rejection: a wrong
   private key yields a pseudorandom secret, so "not my block" is detected only by the
   AES-GCM wrap-tag mismatch — verify that path cannot be distinguished from tampering.

## Suggested first questions

Honest entry points a reviewer might probe — these are the places we would point an
auditor at first:

- The multi-recipient scan loop (`HybridKeyEstablishment.UnwrapFromRecipients`): block
  framing, the recipient count byte, what happens with trailing bytes, and whether a
  hostile container can make one recipient's failure look different from another's.
- The plaintext-total arithmetic (`PqContainerEngine.DerivePlaintextTotal`) — progress
  reporting only, but check it can never influence the decrypt loop.
- The decrypt loop's EOF/truncation handling: a clean EOF is only acceptable *after* an
  authenticated final frame.
- `FileIo.cs`'s temp-file-plus-move under concurrent access and failure injection
  (`AtomicWriteIoFailureTests` covers the known cases).
- The serialization/parse pairs in `KeyEstablishment` and `ContainerFormat` — encode and
  decode are hand-written; check them against [FILE-FORMAT.md](FILE-FORMAT.md) byte by
  byte. The format is FROZEN at v2, so any mismatch is a bug in the code, not the spec.

## Running the evidence

```bash
dotnet build -c Release
dotnet test  -c Release                  # full suite, 150 tests

# Just the adversarial / fail-closed evidence:
dotnet test -c Release --filter "FullyQualifiedName~NoOracle|FullyQualifiedName~Fuzz|FullyQualifiedName~ErrorHandling|FullyQualifiedName~KnownAnswerVector|FullyQualifiedName~CrossImplementation"
```

- **Tamper/truncate/wrong-key tests** live in `tests/PostQuantum.FileEncryption.Tests`
  (`NoOracleTests`, `ErrorHandlingTests`, `FuzzTests`, `AtomicWriteIoFailureTests`, …) and
  are treated as first-class — a new crypto change without a fail-closed test is rejected
  in review.
- **Known-answer vectors** ([TEST-VECTORS.md](TEST-VECTORS.md)) pin the format; an
  independent Rust implementation (`samples/pqfe-wasm`) is held byte-compatible by pinned
  vectors *and* a live interop CI job that round-trips fresh random payloads in both
  directions on every push.
- **Coverage-guided fuzzing** of both parsers (SharpFuzz on .NET, cargo-fuzz on Rust) runs
  nightly with a cached corpus — reproduce locally via [FUZZING.md](FUZZING.md).
- **Threat model**, including the explicit *does-not-defend-against* list:
  [THREAT-MODEL.md](THREAT-MODEL.md).

## Prior external review

Review has found real issues, and they were fixed and disclosed in the changelog rather
than quietly patched — see the `1.1.0` *Fixed* section ([CHANGELOG.md](../CHANGELOG.md)):
key-zeroing gaps on early-failure paths, the multi-recipient cap being enforced late, and
inexact decrypt progress, all from an external reading of the code. Two AI-assisted static
self-reviews of the full tree are published in [audits/](audits/) with a per-finding
disposition table — the `1.2.0` decrypt-time cost ceilings (`PqDecryptionLimits`) came out
of them. That is exactly the kind of review this guide is written to invite.

## Reporting and credit

- **Anything security-sensitive:** use the private channel in [SECURITY.md](../SECURITY.md)
  (GitHub private advisories or email). There is no paid bounty; there is prompt response,
  public credit, and a changelog entry.
- **Everything else** (questions, soft spots, "this was hard to follow"): open an issue.
  A finding of *unclear code in the crypto core* is a real finding.

If you are an auditor, a student, a researcher, or a security team evaluating this library
for adoption: the scoped audit brief is effectively the three documents
[HYBRID-COMBINER.md](HYBRID-COMBINER.md) + [THREAT-MODEL.md](THREAT-MODEL.md) + this page,
and the surface is ~1,700 lines. Funded engagements are welcome — see
[SECURITY.md](../SECURITY.md).

---

*To God be the glory — 1 Corinthians 10:31.*
