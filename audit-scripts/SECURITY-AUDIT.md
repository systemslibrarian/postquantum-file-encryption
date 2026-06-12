# PostQuantum.FileEncryption — Definitive Adversarial Security Audit
**Version 1.0** | .NET 10 (`net10.0`) library family | Post-quantum / hybrid file & stream encryption
**Auditor Role**: Senior red-team penetration tester, applied cryptographer, applied-crypto code reviewer, and .NET secure-coding specialist
**Primary Goal**: Identify confirmed vulnerabilities, realistic abuse paths, cryptographic-construction defects, and format/parsing failures that could break the confidentiality, integrity, or fail-closed guarantee of the `.pqfe` container
**Scope**: Every attack surface discoverable from source — the chunked AEAD core, the four key-establishment paths (passphrase KDF, ML-KEM recipient, X25519+ML-KEM-768 hybrid, external key provider), the v2 on-disk header and its parser, hostile-container handling, key custody/zeroization, the public API, the CLI tool, and the supply-chain / reproducible-build posture
**Audit Standard**: Evidence-first, adversarial, code-aware, hostile-input driven, construction-aware

---

## What is under audit

This is **PostQuantum.FileEncryption**, a high-level, fail-closed, *delightful* wrapper for
post-quantum file and stream encryption on .NET. It is a **library family**, not a service — there is
no server, no network protocol, and no multi-user authorization layer. The trust model is local:
the attacker controls **the ciphertext file on disk** (and may have crafted it), and in some
scenarios controls a recipient public key the sender loads. The security guarantee is the **joint
product** of three concerns, each with its own failure modes:

| Concern | Surface | Guarantee it must uphold |
|---------|---------|--------------------------|
| **AEAD container core** | `Internal/PqContainerEngine.cs`, `Internal/ContainerFormat.cs` | Authenticated encryption only; no plaintext emitted on any auth failure; no reorder/splice/truncation/rollback; nonce uniqueness per key |
| **Key establishment** | `Internal/KeyEstablishment.cs`, `Hybrid/Internal/HybridKeyEstablishment.cs`, `IContentKeyProvider`/`LocalKekContentKeyProvider` | Standard KEM-DEM / password-hashing only; correct combiner binding; bounded cost from untrusted headers; key-class/domain separation |
| **Format & hostile input** | `ContainerHeader.Parse`, every `KeyParams` parser, `FileIo` | Every malformed/oversized/truncated/adversarial container fails closed as `PqFormatException`/`PqDecryptionException` — never OOM, hang, partial-write, or oracle |

A defect in any one collapses the whole guarantee. The packages in lockstep (per project posture,
`.pqfe` v2 frozen for all of 1.x):

- `PostQuantum.FileEncryption` — the core library (passphrase + ML-KEM recipient + key-provider)
- `PostQuantum.FileEncryption.Hybrid` — the X25519 + ML-KEM-768 hybrid (BouncyCastle-backed)
- `PostQuantum.FileEncryption.Extensions.DependencyInjection` — DI wiring
- `Pqfe.Cli` — the packaged `dotnet tool`

**The core design premise: a hostile party controls the input file.** Decryption must be a
*total function over arbitrary bytes* — every input either round-trips authentic plaintext or
throws, with no third outcome, no information leak about *why*, and no unbounded resource use.

Key references (treat as the **spec to test the code against**, not as proof the code is correct):
`docs/FILE-FORMAT.md` (the v2 container spec — authoritative on-disk layout), `CLAUDE.md`
(non-negotiable principles), `SECURITY.md` (the "does NOT defend against" list), `KNOWN-GAPS.md`
(documented limitations), `docs/THREAT-MODEL.md`, `docs/SECURITY-ARCHITECTURE.md`,
`docs/HYBRID-COMBINER.md`, `docs/KEY-MANAGEMENT.md`, `docs/CONFORMANCE.md`, `docs/TEST-VECTORS.md`,
`docs/REPRODUCIBLE-BUILDS.md`, `docs/SUPPLY-CHAIN.md`.

---

## Multi-Concern Testing Mandate — Read First

This audit requires testing across **all three concerns** in every relevant section:

1. **AEAD container core** — `src/PostQuantum.FileEncryption/Internal/PqContainerEngine.cs`,
   `ContainerFormat.cs`, the nonce/AAD construction, the chunk frame state machine
2. **Key establishment** — `KeyEstablishment.cs` (PBKDF2/Argon2id/ML-KEM), `Hybrid/Internal/HybridKeyEstablishment.cs`
   (the X-Wing-style combiner), `LocalKekContentKeyProvider.cs`, and the `IContentKeyProvider` seam
3. **Format & hostile-input handling** — `ContainerHeader.Parse`, every `KeyParams` (de)serializer,
   `PqContainer.cs` orchestration, `FileIo.cs`

**Every finding must state its Concern scope:** `AEAD Core` / `Key Establishment` / `Format/Parser` /
`Public API / Key Custody` / `Supply Chain` / `Cross-Concern`

Before any testing, produce a confirmed **Attack Surface Map** that distinguishes the responsibility
of each concern — specifically, for every guarantee, WHICH code enforces it and whether a hostile
**input file** (it is attacker-controlled — it can lie about every length, parameter, and marker) is
still contained by the parser + AEAD.

---

## OPERATING RULES — READ BEFORE PROCEEDING

**Rule 1 — Map all surfaces first.**
Before testing, inspect the actual codebase and confirm against source (do not trust the line numbers
or constants quoted in this prompt — the tree evolves; **re-verify each**):

- The five `KeySource` values and how each `KeyParams` block is interpreted
  (`ContainerFormat.KeySource*`, `ContainerHeader.Parse`, the per-source parsers)
- The nonce construction (`PqContainerEngine.BuildNonce`: 4-byte random prefix ‖ 8-byte BE counter)
  and the AAD construction (`BuildAad`: `headerBytes ‖ counter ‖ frameType`)
- The chunk frame state machine: `FrameData`/`FrameFinal`, the read-ahead look that decides
  finality, and the `sawFinal` truncation guard on decrypt
- Every bound applied to **untrusted** header fields: chunk size range, salt length, PBKDF2
  iteration range, Argon2id memory/iteration/parallelism range, KEM ciphertext length, KeyParams
  length (the uint16 cap), recipient count
- The passphrase KDF parity between encrypt-side serialization, decrypt-side parsing, and the
  known-answer vectors (`KnownAnswerVectorTests`, `DeterministicVectorTests`)
- The hybrid combiner: HKDF IKM order (`ss_pq ‖ ss_classical`), the `KekInfo`/`WrapAad` domain
  labels, and whether **both** arms bind into the KEK
- ML-KEM implicit-rejection behavior on both the core (`MLKem` from `System.Security.Cryptography`)
  and Hybrid (BouncyCastle `MLKemDecapsulator`) paths
- Zeroization: every `CryptographicOperations.ZeroMemory` in a `finally`, and every sensitive
  `byte[]` copy that BouncyCastle or Konscious forces (and the ones their internals keep that we
  cannot zero — `HybridKeyEstablishment` documents this)
- The atomic temp-file write (`FileIo.WriteViaTempAsync`) and its failure/cleanup path
- The DI registration surface and the CLI argument/stdin/stdout handling (`Pqfe.Cli`)

Do **not** assume any check, bound, or invariant exists unless verified in code. Do **not** assume
the core ML-KEM path (`System.Security.Cryptography.MLKem`) and the Hybrid path (BouncyCastle) agree —
**diff both** wherever they overlap (KEM sizes, HKDF labels, AAD).

**Rule 2 — Classify every finding as one of:**
- **Static** — directly supported by source code or configuration
- **Runtime** — confirmed by executing a test / fuzz target / the CLI against a crafted container
- **Partial** — plausible, but not fully verifiable from source alone; flag for live testing
- **Architectural** — an intentional design choice carrying a security tradeoff

**Rule 3 — No invented findings.**
Do not present speculation as a confirmed vulnerability. `docs/FILE-FORMAT.md` and the ADR-style
docs state the INTENDED behavior — test the code against them, do not assume the code matches. If a
control's proof is not in code, say so.

**Rule 4 — Show the evidence.**
For every finding, cite the exact file, class, method, constant, or test name. State whether the
evidence is the AEAD core, key establishment, the parser, or cross-concern.

**Rule 5 — Escalate each attack realistically.**
Do not accept a "pass" after one obvious payload. Try at least three meaningful variants per attack
class — direct, boundary, evasive. For the container: well-formed-but-tampered tag, truncated mid-frame,
reordered frames, flipped frame-type, oversized declared length, rolled-back format version,
out-of-range KDF cost.

**Rule 6 — Check before you report.**
The AEAD tag check in `PqContainerEngine.DecryptCoreAsync` is the real integrity gate; the header
range-checks in `ContainerHeader.Parse`/`KeyEstablishment` are the *cost/shape* gate. Do not report
"the header isn't authenticated" as a standalone bug **without** first confirming whether `HeaderBytes`
is bound into every chunk's AAD (it is, via `BuildAad`) — meaning any header tampering surfaces as an
auth failure on the first frame. Report only where a header field is **both** unauthenticated **and**
used in a way that escapes that AAD binding (e.g. consumed before the first tag check to drive
allocation or cost).

**Rule 7 — Honor intentional design constraints.**
These are committed decisions, not bugs (verify each against `CLAUDE.md` / `KNOWN-GAPS.md` /
`docs/FILE-FORMAT.md` before reporting a deviation):
- **No homegrown crypto** — only `System.Security.Cryptography` (and BouncyCastle/Konscious for
  primitives .NET lacks on a target platform); KEM-DEM and password-hashing are composed in standard
  patterns only.
- **`.pqfe` v2 is frozen for all of 1.x** — `FormatVersion = 2`; a layout change requires a version
  bump and a `docs/FILE-FORMAT.md` update in the same change.
- **Self-contained codec today** — `IPqContainerCodec` is a delegation seam for a future
  `PostQuantum.FileFormat` backend; the in-repo `SelfContainedContainerCodec` is the only
  implementation. Report seam *gaps* only where they break a guarantee now.
- **Fail-closed everywhere** — no unauthenticated path, no partial-success path, no error oracle;
  every auth failure must look identical to the caller.
- **Best-effort zeroization for managed `byte[]`** — enforced for buffers we own; BouncyCastle/Konscious
  keep internal copies we cannot reach. Report only deviations from this documented posture.

**Rule 8 — Prefer exploit chains.**
Prioritize findings that lead to: plaintext emitted on a tampered/forged container, a nonce
collision under one content key, a combiner defect that silently drops the PQ or classical arm
(a downgrade), an unbounded-cost container (memory/CPU DoS that bypasses the header bounds), key
material reaching a log/exception/disk, a format-confusion that makes one `KeySource` decrypt as
another, or a partial/observable plaintext write before the final-frame check. Isolated trivia
without an exploit path is Low or informational.

**Rule 9 — Identify cross-concern trust-boundary failures.**
Any place where one concern trusts a value another concern (or the input file) produced is a trust
boundary: the declared chunk size driving buffer allocation; the declared `KeyParams` length driving
a read; the declared KEM-ciphertext length; the Argon2id cost parameters from the header; the
provider-id string. Test these explicitly — the file is the adversary.

**Rule 10 — Distinguish defect type.**
Clearly separate Code Defect / Crypto-Construction Defect / Format-Parsing Defect / Key-Custody Defect /
Supply-Chain-Infra Risk when the code is not solely responsible.

---

## PRE-AUDIT DELIVERABLE — REQUIRED BEFORE SECTION TESTING

Produce this **Attack Surface Map** from source before running any tests. Confirm or correct each
item against actual code. **Map surfaces per concern.**

### AEAD Container Core — Confirmed Surfaces

`src/PostQuantum.FileEncryption/Internal/`:
- `PqContainerEngine.cs` — `EncryptCoreAsync` / `DecryptCoreAsync` (the chunked AES-256-GCM core),
  `BuildNonce`, `BuildAad`, `ReadHeaderAsync`, `DerivePlaintextTotal`, `ReadAtMostAsync`/`ReadExactAsync`
- `ContainerFormat.cs` — magic `"PQFE"`, `FormatVersion = 2`, `AeadAes256Gcm = 1`, the `KeySource*`
  and `Kdf*`/`Kem*` ids, `NoncePrefixLength = 4`, `NonceLength = 12`, `TagLength = 16`,
  `KeyLength = 32`, `FrameData`/`FrameFinal`, the fixed-offset header layout, `MaxKeyParamsLength`
- `ContainerHeader` record — `Create` (serialize), `Parse` (validate + range-check)
- `IPqContainerCodec.cs` + `SelfContainedContainerCodec` — the delegation seam
- `PqfeEventSource.cs` — the EventSource telemetry (confirm it emits **no** secret/plaintext)

Invariants to confirm in code:
- **Nonce uniqueness**: `noncePrefix(4 random) ‖ counter(8 BE)` is unique per chunk under one
  per-file content key. Confirm a fresh random prefix per file (`ContainerHeader.Create`) and a
  monotonic counter that cannot wrap within a file (chunk-size & frame-count bounds).
- **AAD binding**: `headerBytes ‖ counter ‖ frameType` binds every chunk to the full header, its
  position, and the final-frame marker — defeating reorder, splice, truncation, header-tamper.
- **Fail-closed truncation**: decrypt throws unless a `FrameFinal` chunk authenticates (`sawFinal`).
- **No plaintext before tag**: `AesGcm.Decrypt` verifies the tag before emitting plaintext; confirm
  no path writes to `destination` before that returns.

### Key Establishment — Confirmed Surfaces

`src/PostQuantum.FileEncryption/Internal/KeyEstablishment.cs`:
- Passphrase: `BuildPassphraseAsync` / `DerivePassphraseKeyAsync`, `DerivePbkdf2`,
  `DeriveArgon2idAsync` (Konscious), `Serialize*Params`. Confirm the **decrypt-side range checks**
  on iterations/memory/parallelism/salt — these bound a hostile container's cost.
- ML-KEM recipient (KeySource 2): `BuildRecipient` / `UnwrapRecipientKey`, `KekInfo`/`WrapAad`
  labels, the `SerializeRecipientParams` layout `KemId(1)|C(2)|KemCt(C)|WrapNonce(12)|WrapTag(16)|WrappedKey(32)`,
  the `c != KemSizes.MlKem768Ciphertext` exact-length check, `EnsureMlKemSupported` (fail-closed if
  the platform lacks ML-KEM — confirm NO weak fallback)

`src/PostQuantum.FileEncryption.Hybrid/Internal/HybridKeyEstablishment.cs`:
- The combiner `DeriveKek` — IKM is `ss_pq ‖ ss_classical` in fixed order, HKDF-SHA256, `KekInfo`
  label `"…/v3 hybrid kek"`, `WrapAad` `"…/v3 cek-wrap"`. **Confirm both arms bind.**
- `WrapToRecipient`/`UnwrapFromRecipient` (KeySource 3), `WrapToRecipients`/`UnwrapFromRecipients`
  (KeySource 4 multi-recipient), `TryUnwrapBlock` (per-block trial unwrap → null on tag mismatch),
  `MaxRecipients` (derived from the uint16 KeyParams cap), the BouncyCastle private-key copy + zero
  discipline, the implicit-rejection comment (decapsulation never fails → wrong KEK → tag mismatch)

External key provider (KeySource 5): `IContentKeyProvider.cs`, `LocalKekContentKeyProvider.cs`
(AES-256-GCM CEK wrap under a 256-bit KEK, `wrapInfo = Nonce(12)‖Tag(16)‖Wrapped(32)`, `ProviderId`
check in `PqContainer.DecryptKeyProviderAsync`).

### Format & Hostile-Input Handling — Confirmed Surfaces

- `ContainerHeader.Parse` — magic, version, AEAD id, key-source whitelist, chunk-size range,
  declared-KeyParams-length-equals-actual check
- Every `KeyParams` parser's bounds: `DerivePassphraseKeyAsync` (salt len ≥ min, PBKDF2/Argon2id
  ranges), `UnwrapRecipientKey` (exact `expected` length), `UnwrapFromRecipients` (count ≥ 1,
  per-block truncation checks), `ParseKeyProviderParams` (id len 1..255, exact total length)
- `PqContainerEngine.ReadHeaderAsync` — reads fixed header, then exactly the declared KeyParams length
- `DerivePlaintextTotal` — progress-total math over an untrusted container length (confirm it cannot
  be coerced into a negative/huge allocation; it only feeds `IProgress`, not allocation — verify)
- `FileIo.WriteViaTempAsync` — sibling temp file, atomic `File.Move(overwrite:true)`, delete-on-failure

### Public API / Key Custody — Confirmed Surfaces

- `PqFileEncryptor` / `PqFileDecryptor` — file, stream, and `byte[]` overloads; passphrase, recipient,
  hybrid, and key-provider entry points; `CancellationToken` honored everywhere
- `PqKeyPair` / `PqRecipientPublicKey` / `PqRecipientPrivateKey` (core), `PqHybridKeyPair` /
  `PqHybridPublicKey` / `PqHybridPrivateKey` (hybrid) — import/export length checks, `Dispose`
  zeroization
- `PqEncryptionOptions` — `Validate()` fail-fast bounds; the internal Min/Max constants
- `PqEncryptionException` hierarchy (`PqFormatException`, `PqDecryptionException`) — confirm no
  message ever carries a secret, plaintext, key byte, or full filesystem path
- `Pqfe.Cli` — argument parsing, passphrase intake (env/stdin/prompt?), stdout/stderr discipline,
  exit codes, whether it ever echoes a passphrase or writes plaintext to a predictable temp path

### Supply Chain / Build — Confirmed Surfaces

- `Directory.Build.props` — deterministic build, `TreatWarningsAsErrors`, analysis level, authorship
- Reproducible-build wiring (`docs/REPRODUCIBLE-BUILDS.md`, `docs/SUPPLY-CHAIN.md`); the
  provenance attestation noted in project memory (Linux build; **never hand-pack on Windows** — CRLF
  breaks reproducibility)
- `.github/workflows/` — build/test/pack gates, the NuGet publish path, KAT/fuzz jobs
- Pinned dependency versions: Konscious (Argon2id), BouncyCastle (Hybrid ML-KEM/X25519) — confirm
  versions and that KATs validate against the actually-referenced versions

---

## TESTING INSTRUCTIONS — APPLY TO ALL SECTIONS

For every test, record:
- **Concern scope**: AEAD Core / Key Establishment / Format-Parser / Public API-Key Custody / Supply Chain / Cross-Concern
- Exact payload / container bytes / call sequence
- Observed behavior (or "Not runtime-verified" if static-only)
- Pass / Fail / Partial
- Severity: Critical / High / Medium / Low
- Root cause with file/method/constant (or test name)
- Concrete remediation

For each attack class, test at minimum:
1. **Direct** — obvious tamper / happy-path bypass attempt
2. **Boundary** — empty input, 1-byte input, max chunk size (16 MiB), min/max KDF cost, 0-recipient,
   max-recipient (`MaxRecipients`+1), KeyParams length 0 and `ushort.MaxValue`
3. **Truncation** — cut mid-header, mid-KeyParams, mid-frame-header, mid-ciphertext, mid-tag, and
   exactly-before the final frame
4. **Tamper** — flip a header byte, a frame-type byte, a tag byte, a counter-relevant byte; reorder
   two data frames; duplicate the final frame; splice a frame from another container
5. **Cost/DoS** — declared chunk size vs actual data, Argon2id memory at the upper bound, a KeyParams
   length that doesn't match its content, a recipient list that maximizes trial unwraps
6. **Cross-implementation** — a container produced by the core ML-KEM path fed to the Hybrid path and
   vice-versa; a KeySource value that mismatches the API entry point used
7. **Platform-missing** — ML-KEM unavailable (`MLKem.IsSupported == false`): confirm fail-closed, no
   weak fallback, clear error

---

# SECTION 1 — AEAD CONTAINER CORE (the integrity & confidentiality root)

**Concern scope**: AEAD Core; Cross-Concern where the header feeds it

## 1.1 Nonce construction & uniqueness (`PqContainerEngine.BuildNonce`)

**T1.1.1 — Per-file prefix freshness**
Confirm `ContainerHeader.Create` draws a fresh 4-byte random `NoncePrefix` per file
(`RandomNumberGenerator.GetBytes`) and that the `noncePrefixOverride` is reachable ONLY from
deterministic conformance tests, never from a public/production path. A reused prefix + reused key =
GCM nonce reuse. **Trace every caller of `Create` and of the override.**

**T1.1.2 — Counter-space exhaustion**
The nonce is `prefix(4) ‖ counter(8 BE)`. Confirm the 64-bit counter cannot wrap within one file
given the chunk-size bounds (1 KiB .. 16 MiB) and any achievable file size — i.e. nonce reuse by
counter overflow is unreachable. State the math.

**T1.1.3 — Prefix collision across files under a SHARED key**
For passphrase/recipient encryption a *new* content key is drawn per file, so a prefix collision is
harmless. But confirm there is NO mode where two files share a content key AND draw independent
4-byte prefixes (birthday collision at ~2^16 files would then be catastrophic). Check the key-provider
path and any "encrypt many with one key" ergonomics. This is a **Critical-class** check.

## 1.2 AAD binding & frame state machine (`BuildAad`, `DecryptCoreAsync`)

**T1.2.1 — Full-header binding**
Confirm `BuildAad` includes the *entire* serialized `HeaderBytes` (magic, version, key-source, chunk
size, nonce prefix, KeyParams) so any header mutation fails the first frame's tag. Tamper one byte of
each header field and confirm `AuthenticationTagMismatchException → PqDecryptionException`.

**T1.2.2 — Frame-type authentication**
`frameType` is the AAD's last byte. Flip a `FrameFinal` to `FrameData` (and vice-versa) on the wire
and confirm the tag rejects it. Confirm a truncated stream that drops the final frame fails via the
`sawFinal` guard, NOT via silent success.

**T1.2.3 — Reorder / splice / replay**
Counter is in the AAD, so swap two data frames, duplicate a frame, and splice a valid frame from a
*different* container (same key impossible, but try same passphrase+salt reuse). Confirm each fails.

**T1.2.4 — No plaintext before authentication**
Statically confirm `DecryptCoreAsync` writes to `destination` only AFTER `aes.Decrypt` returns (tag
verified). Confirm a multi-frame container where frame 3 is tampered does not leave frames 1–2 as an
observable partial plaintext at the destination — and that file output goes through
`FileIo.WriteViaTempAsync` so a mid-stream failure leaves NO file at the destination path. This is the
**partial-plaintext / fail-closed** crux.

**T1.2.5 — Declared frame length vs chunk size**
On decrypt, the frame header carries a uint32 length. Confirm `length > header.ChunkSize` is rejected
*before* the `ReadExact` into `ciphertext` (it is — verify the order), so a hostile length cannot
drive an over-read or oversized allocation.

## 1.3 AES-GCM usage (`AesGcm`, `TagLength = 16`)

**T1.3.1 — Tag length pinned**
Confirm every `new AesGcm(key, ContainerFormat.TagLength)` pins the full 16-byte tag (no truncated
tags anywhere — core, recipient wrap, hybrid wrap, local-KEK wrap).

**T1.3.2 — Key length pinned**
Confirm the content key is always exactly 32 bytes (`KeyLength`) on every path; a short key would be
a silent strength reduction.

**T1.3.3 — Decrypt rejects tamper and fails closed**
Tamper ciphertext, tag, nonce-relevant header bytes; confirm `AuthenticationTagMismatchException` is
caught and re-thrown as a generic `PqDecryptionException` with NO plaintext and NO "which byte was
wrong" oracle. Confirm the message is identical for wrong-key vs altered-file vs truncation.

## 1.4 Telemetry & progress (`PqfeEventSource`, `PqProgress`, `DerivePlaintextTotal`)

**T1.4.1 — No secret in telemetry**
Confirm `PqfeEventSource` events (`OperationStarted/Completed/Failed`) carry only operation name,
key-source label, byte counts, timing, and an exception *type name* — never a passphrase, key,
plaintext, salt, or file path. `PqContainer.InstrumentedAsync` logs `ex.GetType().Name` only — confirm.

**T1.4.2 — Progress math on hostile length**
`DerivePlaintextTotal` does arithmetic over an attacker-controlled container length. Confirm it
cannot produce a value that drives allocation or an out-of-bounds index (it only feeds `IProgress` —
verify nothing else consumes it) and that overflow/negative cases return `null` rather than a bogus total.

---

# SECTION 2 — KEY ESTABLISHMENT (the four paths to the content key)

**Concern scope**: Key Establishment; Cross-Concern with the parser

## 2.1 Passphrase KDF (`KeyEstablishment`, `PqEncryptionOptions`)

**T2.1.1 — Encrypt/decrypt/KAT parity**
The three KDF paths must agree: encrypt-side `Serialize*Params`, decrypt-side `DerivePassphraseKeyAsync`
parsing, and the known-answer vectors. Cross-check `KnownAnswerVectorTests` / `DeterministicVectorTests`
against the live constants. A divergence = silent unwrap failure or a weakened KDF.

**T2.1.2 — Decrypt-side cost bounds (hostile container)**
`DerivePassphraseKeyAsync` reads iterations/memory/parallelism from the **untrusted** header. Confirm
every value is range-checked (`MinPbkdf2Iterations..Max`, `MinArgon2MemoryKiB..Max = 8 MiB..2 GiB`,
`MinArgon2Iterations..Max`, `parallelism ≥ 1`, salt ≥ `MinSaltSizeBytes`) BEFORE the derivation runs.
A hostile header declaring Argon2id at 2 GiB × 10,000 iterations is the DoS to bound — confirm it is
rejected as `PqFormatException`, and assess whether even the *accepted* upper bound (2 GiB) is a
client-OOM risk worth a tighter default cap. (Section 6.)

**T2.1.3 — Salt handling**
Confirm a fresh random salt per file (`SaltSizeBytes` default 16), that the salt is serialized and
re-read faithfully, and that the salt is never reused as the HKDF salt or any other domain's input.
Confirm `saltOverride` is test-only.

**T2.1.4 — Passphrase buffer hygiene**
The Konscious path copies the passphrase to a `byte[]` (`DeriveArgon2idAsync`) and zeroes it in a
`finally`. Confirm. Confirm the passphrase never reaches a log, exception message, or disk, and that
the derived content key is zeroed by the engine's `finally` (`ZeroMemory(contentKey)`).

**T2.1.5 — KDF default strength**
Default is PBKDF2-HMAC-SHA256 at 600,000 iterations (OWASP). Confirm the default is applied when no
options are supplied (`PqEncryptionOptions.Default`) and that Argon2id defaults (19 MiB / t=2 / p=1)
match OWASP. Flag if a caller supplying *no* options could ever get a weaker-than-default result.

## 2.2 ML-KEM recipient path (`BuildRecipient` / `UnwrapRecipientKey`)

**T2.2.1 — KEM-DEM construction**
Confirm: encapsulate → `HKDF-SHA256(sharedSecret, info=KekInfo)` → AES-256-GCM wrap of a random
32-byte content key with `WrapAad`. Confirm the shared secret and KEK are zeroed in `finally`. Confirm
the `KekInfo`/`WrapAad` labels domain-separate this from the passphrase and hybrid paths.

**T2.2.2 — Recipient public-key validation**
`BuildRecipient` imports an attacker-influenceable encapsulation key via `MLKem.ImportEncapsulationKey`.
Confirm the import validates length/well-formedness (or that .NET's import does) so a malformed
recipient key fails closed, not with undefined behavior.

**T2.2.3 — Implicit rejection / no oracle**
Feed a malformed KEM ciphertext to `UnwrapRecipientKey`. ML-KEM decapsulation yields a pseudo-random
secret (implicit reject); the wrong KEK then fails the AES-GCM tag → generic `PqDecryptionException`.
Confirm NO error distinguishes "bad ciphertext" from "wrong key" from "tampered wrap". Confirm the
exact-length check (`c != KemSizes.MlKem768Ciphertext`, `p.Length != expected`) rejects size games
*before* decapsulation.

**T2.2.4 — Platform fail-closed**
`EnsureMlKemSupported` throws `PlatformNotSupportedException` if `!MLKem.IsSupported`. Confirm there
is NO fallback to a weaker construction and NO "encryption disabled" path — this is the analog of the
classic `_encryptionEnabled=false` anti-pattern; confirm it does not exist.

## 2.3 Hybrid combiner (`HybridKeyEstablishment`)

**T2.3.1 — Both arms bind (downgrade resistance)**
`DeriveKek` builds IKM = `ss_pq ‖ ss_classical` (fixed order) and HKDFs it. Confirm BOTH secrets are
present and ordered; a combiner that drops or mis-orders an arm is a silent post-quantum **or**
classical downgrade. Cross-check `docs/HYBRID-COMBINER.md` and `x_wing`-style KAT if present. State
explicitly whether breaking ONLY ML-KEM or ONLY X25519 still protects the CEK.

**T2.3.2 — Ephemeral X25519 freshness**
`WrapToRecipient` generates a fresh ephemeral X25519 keypair per recipient per wrap. Confirm it is not
cached/reused across recipients or files, and the ephemeral public is serialized into the block.

**T2.3.3 — Multi-recipient correctness & trial-unwrap bound (KeySource 4)**
`WrapToRecipients` produces a DISTINCT block per recipient (no shared symmetric key beyond the single
CEK each block independently wraps). `UnwrapFromRecipients` trial-unwraps each block until one matches
(`TryUnwrapBlock` → null on tag mismatch). Confirm: count ≥ 1; each block's declared length is
bounds-checked against the body before slicing; `MaxRecipients` (uint16 cap → ~55 with today's block
size) is enforced on the **write** path; and a hostile container declaring a huge count cannot drive
unbounded work (each block length is read from the body and validated — confirm truncation throws).

**T2.3.4 — BouncyCastle key-copy zeroization**
`TryUnwrapBlock` copies the ML-KEM and X25519 private keys to `byte[]` for BouncyCastle and zeroes
each copy in `finally`. Confirm. Note the documented residual: BouncyCastle parameter objects keep
internal copies that cannot be zeroed — confirm this is the *documented* best-effort posture
(`KNOWN-GAPS.md` / `CLAUDE.md`), not an undocumented leak.

**T2.3.5 — Core-vs-Hybrid label & size divergence**
The core path uses `"…/v2 …"` labels and `System.Security.Cryptography.MLKem`; the hybrid uses
`"…/v3 …"` labels and BouncyCastle. Confirm KEM ciphertext length (1088), encapsulation-key (1184),
decapsulation-key (2400) constants agree across both implementations and the wire layout, so a file
written by one is never silently misparsed by the other. A cross-implementation differential here is
**High/Critical**.

## 2.4 External key provider (`IContentKeyProvider`, `LocalKekContentKeyProvider`)

**T2.4.1 — Provider-id binding**
`DecryptKeyProviderAsync` checks the container's provider-id against the supplied provider's
`ProviderId` (ordinal). Confirm a mismatch fails closed with a clear (non-secret) error, and the id is
length-bounded (1..255 UTF-8) on both serialize and parse.

**T2.4.2 — Local-KEK wrap soundness**
`LocalKekContentKeyProvider` wraps the CEK with AES-256-GCM under a 256-bit KEK,
`wrapInfo = Nonce(12)‖Tag(16)‖Wrapped(32)`, fresh random nonce per wrap, `WrapAad` domain label.
Confirm fresh nonce per `WrapNewKeyAsync` call, the exact `WrapInfoLength` check on unwrap, the
tag-mismatch → `PqDecryptionException` with the CEK zeroed first, and `Dispose` zeroing the KEK.

**T2.4.3 — KEK custody**
`ExportKek` hands back a clone (documented as a secret). Confirm the provider never logs the KEK and
that `Generate()` zeroes its intermediate copy. Flag that a custom `IContentKeyProvider` is a trust
boundary — its `UnwrapKeyAsync` MUST fail closed; document the contract risk.

---

# SECTION 3 — FORMAT & HOSTILE-INPUT HANDLING (the file is the adversary)

**Concern scope**: Format-Parser; Cross-Concern

**T3.1 — Header well-formedness gauntlet** (`ContainerHeader.Parse`)
Feed: bad magic; `FormatVersion` 1 and 3 (rollback/rollforward); unknown AEAD id; unknown
`KeySource` (0, 6, 255); chunk size below `MinChunkSizeBytes` and above `MaxChunkSizeBytes`; a
declared KeyParams length that does NOT equal `fixedAndParams.Length - FixedHeaderLength`. Confirm each
throws `PqFormatException` and NONE reaches key establishment or allocates on the bad value.

**T3.2 — Truncation gauntlet** (`ReadHeaderAsync`, `DecryptCoreAsync`)
Truncate the file at: 0 bytes; mid fixed-header (< 18 bytes); after fixed header but mid-KeyParams;
after header but no frames; mid-frame-header; mid-ciphertext; mid-tag; and exactly after the last
DATA frame but before the FINAL frame. Confirm every case fails closed (`PqFormatException` or
`PqDecryptionException`), never hangs, never emits plaintext, and (for file output) leaves NO
destination file.

**T3.3 — KeyParams parser fuzzing (per KeySource)**
- Passphrase: salt length < min; PBKDF2 params truncated; Argon2id params truncated (< 9 bytes);
  out-of-range costs; unknown KDF id.
- ML-KEM recipient: `p.Length < 3`; wrong `p[0]`; `c != MlKem768Ciphertext`; `p.Length != expected`;
  off-by-one on each field.
- Hybrid multi-recipient: count 0; count 255 with a 2-block body (truncation); block length that
  overruns the body; unknown mode byte (should keep trying, not crash).
- Key-provider: id length 0; id length overruns; wrapInfo length mismatch.
Confirm every malformed case throws a `Pq*Exception` and none indexes out of bounds, allocates on a
bogus length, or leaks. **Reconcile with the existing `FuzzTests` / `NoOracleTests` / `ErrorHandlingTests`
corpus** and note any gap.

**T3.4 — Format-confusion across KeySource**
Encrypt with passphrase, then feed the file to the recipient decrypt entry point (and every other
mismatched pair). Confirm `PqContainer` rejects the mismatch (each decrypt path checks
`header.KeySource` and throws) — no path tries the wrong unwrap and emits garbage. Confirm a
hand-crafted header claiming `KeySourceMultiRecipient` but carrying a passphrase body fails closed.

**T3.5 — Atomic write & I/O failure** (`FileIo.WriteViaTempAsync`)
Confirm: the plaintext/ciphertext is written to a sibling `*.tmp-<guid>` file and atomically moved
only on full success; any thrown exception deletes the temp file; a decrypt that fails mid-stream
leaves NO partial plaintext at the destination. Force an I/O failure (cross-reference
`AtomicWriteIoFailureTests`) and confirm cleanup. Flag any window where the temp file (containing
plaintext on decrypt) is world-readable or left behind on a hard crash (best-effort — document).

**T3.6 — Oversized / boundary allocations**
Max chunk size (16 MiB) drives three `byte[ChunkSize]` buffers per operation. Confirm peak memory is
bounded and predictable, and that the look-ahead double-buffer (`current`/`next`) does not double an
already-large allocation unexpectedly. Confirm a container that *declares* 16 MiB chunks but carries
tiny frames does not pre-allocate based on the declared size in a wasteful/abusable way.

---

# SECTION 4 — PUBLIC API & KEY CUSTODY

**Concern scope**: Public API / Key Custody; Cross-Concern

**T4.1 — Surface minimality & safe defaults**
Confirm the public surface matches `CLAUDE.md` (encryptor/decryptor, options, progress, key types,
`PqKdf`, exceptions, `IContentKeyProvider`/`LocalKekContentKeyProvider`). Confirm a caller passing no
options gets a secure result (`PqEncryptionOptions.Default`), and `Validate()` fail-fasts on bad
options before any work.

**T4.2 — Key type import/export bounds**
`PqHybridPublicKey.Import` requires 1216 bytes, `PqHybridPrivateKey.Import` 2432 bytes; the core
`PqRecipient*` types have their own length checks. Confirm each rejects wrong-length input and that
`Export` round-trips. Confirm private-key `Dispose` zeroes (`PqHybridPrivateKey.Dispose`,
`PqRecipientPrivateKey`).

**T4.3 — Cancellation honored**
Confirm every async file/stream path honors `CancellationToken` (the engine calls
`ThrowIfCancellationRequested` each loop). Confirm a cancelled encrypt leaves no destination file
(temp-file cleanup) and a cancelled decrypt emits no partial plaintext.

**T4.4 — Exception message hygiene**
Grep every `throw new Pq*Exception(...)`. Confirm NO message embeds a passphrase, key byte, plaintext,
salt, or full filesystem path. Confirm wrong-key / altered-file / truncated all surface the SAME
generic decrypt message (no oracle). Cross-reference `NoOracleTests`.

**T4.5 — DI surface** (`PqFileEncryptionServiceCollectionExtensions`)
Confirm the DI registration does not capture or persist key material in a singleton, does not register
a provider with a process-wide KEK by default, and that lifetimes are sane (no accidental shared
mutable secret). Cross-reference `DependencyInjectionTests`.

**T4.6 — CLI tool** (`Pqfe.Cli`)
Confirm: passphrase intake does not echo and is not taken from `argv` in a way that lands in shell
history/process listing without a documented warning; the tool writes ciphertext/plaintext atomically;
it does not write plaintext to a predictable temp path; it returns non-zero on any failure; and it
does not print key material or stack traces with secrets on error. Flag any `--password-on-command-line`
style affordance as an information-disclosure risk and confirm it is documented.

---

# SECTION 5 — SUPPLY CHAIN, BUILD & DEPENDENCIES

**Concern scope**: Supply Chain

**T5.1 — Dependency pinning & provenance**
Confirm Konscious (Argon2id) and BouncyCastle (Hybrid) versions are pinned and that KATs validate
against the *referenced* versions. A silent minor bump that changes Argon2id or ML-KEM behavior would
break interop or weaken the KDF — confirm a KAT would catch it.

**T5.2 — Reproducible build integrity**
Confirm `Directory.Build.props` sets deterministic build + `TreatWarningsAsErrors` + the analysis
level, and that the published packages carry the reproducibility/provenance attestation. Per project
memory: the workflow ships from Linux; **never hand-pack on Windows** (CRLF breaks reproducibility
against the Linux attestation). Confirm the release workflow is the only sanctioned pack path.

**T5.3 — Analyzer-enforced API lock**
Public API is locked by analyzers (project posture). Confirm the four packages move in lockstep and an
accidental public-surface change fails the build, not ships silently.

**T5.4 — CI gate coverage**
Confirm CI runs: build (warnings-as-errors), the full test suite (`tests/`), the KAT/deterministic
vectors, and the fuzz target (`fuzz/`, `oss-fuzz/`). Flag any security-relevant test class that is NOT
wired into a required gate.

---

# SECTION 6 — DENIAL OF SERVICE & RESOURCE BOUNDS

**Concern scope**: All

**T6.1 — Argon2id cost from a hostile header**
The decrypt-side accepts Argon2id up to 2 GiB memory × 10,000 iterations from the container. Confirm
this is the intended upper bound and assess whether opening *someone else's* `.pqfe` should be allowed
to demand 2 GiB. Recommend a caller-overridable decrypt-time cost ceiling if one is absent.

**T6.2 — Chunk-size & buffer bounds**
Confirm 16 MiB max chunk × the fixed number of engine buffers is the worst-case peak, and that it is
independent of the (untrusted) declared file size. Confirm no path allocates `new byte[declaredLength]`
for an attacker-declared length before validating it against the chunk-size bound.

**T6.3 — Multi-recipient trial-unwrap cost**
A KeySource-4 container makes the decryptor trial-unwrap up to `count` blocks (each an ML-KEM
decapsulation + X25519 agreement + GCM). Confirm `count` and per-block lengths are bounded by the body
size so a single small hostile file cannot demand thousands of decapsulations. Quantify the worst case.

**T6.4 — Streaming memory ceiling**
Confirm the engine is constant-memory in the file size (bounded by chunk buffers), and the `byte[]`
API overloads do not defeat that by materializing an unbounded plaintext/ciphertext for a huge input
without a documented size limit.

---

# SECTION 7 — DOC vs CODE DRIFT (the inverted-trust audit)

**Concern scope**: Cross-Concern

**T7.1 — File-format parity** (`docs/FILE-FORMAT.md`)
Confirm the documented v2 layout (offsets, field widths, KeySource/KDF/KEM ids, frame structure, AAD
composition) matches `ContainerFormat.cs` + `PqContainerEngine` + every `KeyParams` (de)serializer
EXACTLY. Any drift is a finding even if individually "secure".

**T7.2 — `SECURITY.md` "does NOT defend against" accuracy**
Confirm each claimed non-defense is still accurate and that no NEW limitation has appeared in code
without a doc update. Confirm no doc over-claims a property the code does not deliver.

**T7.3 — `KNOWN-GAPS.md` honesty**
Cross-check each documented gap against code (e.g. the `IPqContainerCodec` seam being self-contained;
best-effort managed-buffer zeroization; BouncyCastle internal key copies). Confirm none is silently
half-fixed in a way that misleads, and that no *undocumented* gap exists that belongs on the list.

**T7.4 — CLAUDE.md non-negotiables**
Verify in code: no homegrown crypto; authenticated-only (no unauthenticated path anywhere); fail-closed
(no partial-success path); `FormatVersion` bumped iff layout changed; key material zeroed in `finally`.
A code path contradicting a non-negotiable is a finding regardless of exploitability.

---

# SECTION 8 — CHAINED ATTACK SCENARIOS

Attempt only chains credible from the implementation. For each, identify the first broken control and
the downstream impact.

**Chain A — Nonce reuse under a shared key → forgery + plaintext recovery** (Critical)
1. Some mode encrypts two files (or two per-recipient wraps) under the same content key while drawing
   independent 4-byte nonce prefixes, OR reuses a prefix.
2. (key, nonce) repeats under AES-GCM → tag forgery + plaintext recovery with no key compromise.
**First break to verify**: §1.1.1 / §1.1.3 (per-file fresh CEK + prefix; key-provider reuse).

**Chain B — Combiner arm-drop → silent downgrade** (Critical)
1. `DeriveKek` (hybrid) or the core KEM-DEM binds only one secret / mis-orders inputs / uses a wrong
   label.
2. Breaking the un-bound primitive recovers the CEK → the "hybrid" guarantee is a lie.
**First break**: §2.3.1 / §2.2.1.

**Chain C — Tamper accepted → plaintext on a forged container** (Critical)
1. A header or frame mutation is NOT bound into the AAD, or `AesGcm.Decrypt`'s output is consumed
   before the tag check, or `sawFinal` is bypassable.
2. Attacker-controlled plaintext is emitted as if authentic, or a truncated file decrypts "successfully".
**First break**: §1.2.1 / §1.2.4 / §1.2.2.

**Chain D — Hostile header → resource exhaustion** (High)
1. A container declares Argon2id at the max bound (or a KeySource-4 with many blocks) and the
   decrypt-side runs it before (or despite) bounds.
2. Client OOM / CPU exhaustion on opening an untrusted file.
**First break**: §2.1.2 / §6.1 / §6.3.

**Chain E — Format confusion → wrong-path decrypt** (High)
1. A crafted `KeySource` byte routes a body to the wrong unwrap, or one package's container is
   misparsed by the other (core ML-KEM vs Hybrid).
2. Undefined behavior, a confusing partial result, or a bypass of a per-path bound.
**First break**: §3.4 / §2.3.5.

**Chain F — Partial-plaintext leak on mid-stream failure** (High)
1. A multi-frame container fails on a late frame, but earlier frames are already observable at the
   destination (temp-file/atomic-move bypassed, or `byte[]` API returns partial).
2. An attacker learns plaintext prefixes of files that "fail" to decrypt.
**First break**: §1.2.4 / §3.5.

**Chain G — Secret in a log/exception → offline key/passphrase exposure** (High)
1. A passphrase, key, salt, or plaintext reaches `PqfeEventSource`, an exception message, the CLI's
   stderr, or a left-behind temp file.
2. Anyone with log/console/disk access recovers material enabling decryption.
**First break**: §1.4.1 / §4.4 / §4.6 / §3.5.

**Chain H — Supply-chain drift → silent KDF/KEM behavior change** (Medium/High)
1. An unpinned Konscious/BouncyCastle bump changes Argon2id or ML-KEM behavior, OR a Windows hand-pack
   breaks reproducibility, and no KAT/gate catches it.
2. Interop breaks or the KDF weakens without a visible signal.
**First break**: §5.1 / §5.2 / §5.4.

---

# SEVERITY RUBRIC

| Severity | Definition |
|----------|------------|
| Critical | Plaintext emitted on a tampered/forged/truncated container; AES-GCM nonce reuse under one key; hybrid/KEM-DEM combiner defect enabling a silent downgrade (one broken primitive recovers the CEK); a content key, passphrase, or KEK written to disk/log in cleartext; any path that decrypts without verifying the AEAD tag |
| High | Hostile-header resource exhaustion (Argon2id/multi-recipient DoS) bypassing or within over-loose bounds; observable partial-plaintext on a mid-stream failure; format-confusion routing a body to the wrong unwrap or a cross-package misparse; missing fail-closed on a truncation/tamper variant; a secret in an exception message or CLI output |
| Medium | A `KeyParams`/header parser that indexes out of bounds or allocates on an unvalidated length (without reaching plaintext); a doc-vs-code format drift; an over-loose default cost cap; a CLI passphrase-on-argv affordance; a missing required CI gate for a security test |
| Low | Best-effort managed-buffer zeroization gaps that match the documented posture; non-constant-time comparison on a non-secret path; a left-behind temp file only on hard crash; missing telemetry/audit line; weak hardening that does not itself break a guarantee |

---

# REQUIRED OUTPUT FORMAT

Use this exact structure for every finding:

```
Finding ID:       PQFE-###
Evidence Type:    Static / Runtime / Partial / Architectural
Defect Type:      Code Defect / Crypto-Construction Defect / Format-Parsing Defect / Key-Custody Defect / Supply-Chain-Infra Risk
Concern Scope:    AEAD Core / Key Establishment / Format-Parser / Public API-Key Custody / Supply Chain / Cross-Concern
Section:          [e.g. Section 1.2 — AAD binding & frame state machine]
Severity:         Critical / High / Medium / Low
Title:            [Short description]
Affected File(s): [Exact path with method/constant/test name — confirmed from source]
Affected Code:    [Class / method / constant / parser branch]
Attack Input:     [Exact container bytes, options, or call sequence]
Observed Result:  [What happened — or "Not runtime-verified"]
Expected Result:  [What should have happened per docs/FILE-FORMAT.md / CLAUDE.md / spec]
Root Cause:       [Code-level explanation]
Impact:           [Realistic consequence — state explicitly whether confidentiality, integrity, or fail-closed is broken]
Recommendation:   [Specific, actionable fix]
Test Reproduced:  [Yes / No / Partial / Static-only]

EVIDENCE BASIS:
State whether this finding is based on:
- direct code-path confirmation
- cross-file interaction analysis (e.g. encrypt-side serialize ↔ decrypt-side parse ↔ KAT)
- cross-package analysis (core ML-KEM ↔ Hybrid BouncyCastle)
- doc divergence (name the doc and quote the committed behavior)
- static inference with missing runtime/config evidence
```

---

# FINAL DELIVERABLES

At the end of the audit, provide all of the following. Do not pad with generic advice — every
statement must be specific to this codebase.

1. **Attack Surface Map** — confirmed surfaces only, from source, **separated by concern** (AEAD Core / Key Establishment / Format-Parser / Public API-Key Custody / Supply Chain)
2. **Confirmed Findings** — sorted Critical → High → Medium → Low
3. **Partial Findings Requiring Live Verification** — what to test and how (unit test / fuzz target / CLI against a crafted container)
4. **Exploit Chains / Compound Risks** — first broken control identified, and which concern should have contained it
5. **AEAD Integrity Report** — explicit pass/fail on: tag-before-plaintext, full-header AAD binding, frame-type/counter authentication, fail-closed truncation (`sawFinal`), no-partial-plaintext on mid-stream failure, AES-GCM nonce uniqueness per content key
6. **Key-Establishment Report** — per path (passphrase / ML-KEM / hybrid / key-provider): construction correctness, decrypt-side cost bounds, domain separation, zeroization, fail-closed-on-malformed
7. **Format/Parser Robustness Matrix** — per KeySource and per truncation/tamper class: fails-closed?, bounded-allocation?, no-oracle?
8. **Doc Drift Report** — code-vs-`docs/FILE-FORMAT.md` / `SECURITY.md` / `KNOWN-GAPS.md` / `CLAUDE.md` divergences
9. **Top 10 Remediations by Risk Reduction** — ordered by impact/effort ratio
10. **Security Regression Test Recommendations** — new cases per primitive, per parser branch, per fail-closed variant (slot them into the existing `FuzzTests` / `NoOracleTests` / `KnownAnswerVectorTests` / `ErrorHandlingTests` corpus)
11. **What Was Tested vs What Could Not Be Verified** — honest scope boundary
12. **Release Blockers** — only the findings that must be fixed before the next NuGet release

---

*Prepared for: PostQuantum.FileEncryption — a fail-closed, post-quantum file & stream encryption library family for .NET 10 (`PostQuantum.FileEncryption`, `.Hybrid`, `.Extensions.DependencyInjection`, `Pqfe.Cli`).*
*Source of truth: project source, `docs/FILE-FORMAT.md` (v2 container spec), `CLAUDE.md` (non-negotiables), `SECURITY.md`, `KNOWN-GAPS.md`, `docs/HYBRID-COMBINER.md`, `docs/KEY-MANAGEMENT.md`, `docs/THREAT-MODEL.md`, and the round-trip / KAT / fuzz / no-oracle test suites under `tests/`.*
*The trust model is local: the attacker controls the input `.pqfe` file (and may have crafted it). The guarantee is the joint product of the AEAD container core, the key-establishment paths, and the hostile-input parser. Treat the docs as the spec to test the code against, not as proof the code is correct. The tree is actively evolving — correct any prompt assumption (line numbers, constants, layouts) that does not match the actual codebase before proceeding. Do not substitute assumptions for code evidence.*

*To God be the glory — 1 Corinthians 10:31.*
