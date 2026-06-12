> **Provenance:** AI-assisted static self-review (run A of two independent runs),
> commissioned and reviewed by the maintainer against the working tree after commit
> `54df378` (library at released `1.1.0`). This is **self-review, not an independent
> audit** — see [docs/GOLD-STANDARD.md](../GOLD-STANDARD.md) §6 for that honest gap.
> **Disposition:** findings PQFE-001/002/003/004 were remediated in `1.2.0` (commit
> `bdec193`); PQFE-005/006/007 are documented tradeoffs in [KNOWN-GAPS.md](../../KNOWN-GAPS.md).

# PostQuantum.FileEncryption — Security Audit Results (Run A)

**Audit template:** `audit-scripts/SECURITY-AUDIT.md`
**Method:** Static source review of the live tree (no runtime/fuzz execution this pass — all findings marked `Static` or `Architectural`).
**Commit basis:** working tree at audit time (post-`54df378`, library at released `1.1.0`).
**Files examined:** `Internal/ContainerFormat.cs`, `Internal/PqContainerEngine.cs`, `Internal/KeyEstablishment.cs`, `Internal/PqContainer.cs`, `Internal/FileIo.cs`, `Internal/IPqContainerCodec.cs`, `Internal/PqfeEventSource.cs`, `PqFileEncryptor.cs`, `PqFileDecryptor.cs`, `PqKeyPair.cs`, `PqEncryptionOptions.cs`, `PqEncryptionException.cs`, `IContentKeyProvider.cs`, `LocalKekContentKeyProvider.cs`, `Hybrid/Internal/HybridKeyEstablishment.cs`, `Hybrid/PqHybridKeyPair.cs`, `Hybrid/PqHybridEncryptor.cs`, `Hybrid/PqHybridDecryptor.cs`, `Extensions.DependencyInjection/…`, `samples/Pqfe.Cli/Program.cs`, `Directory.Build.props`, `KNOWN-GAPS.md`.

## Headline

The cryptographic core is **sound and fail-closed**. Every high-severity attack class in the template — nonce reuse, tag-bypass, combiner downgrade, partial-plaintext leak at the real destination, format confusion, decrypt-side cost unbounding, oracle leakage — was tested against source and **did not reproduce**. The confirmed findings are all **Medium / Low hardening items**, several of which are already documented as intentional tradeoffs in `KNOWN-GAPS.md`. **No release blockers.**

---

## 1. Attack Surface Map (confirmed from source, by concern)

### AEAD Container Core
- `PqContainerEngine.EncryptCoreAsync` / `DecryptCoreAsync` — chunked AES-256-GCM; nonce = `BuildNonce` (`NoncePrefix(4) ‖ counter(8 BE)`); AAD = `BuildAad` (`HeaderBytes ‖ counter(8 BE) ‖ frameType`). **Confirmed.**
- Frame state machine: `FrameData=0`/`FrameFinal=1`; encrypt uses a one-chunk read-ahead (`current`/`next`) to decide finality; decrypt enforces `sawFinal` before accepting EOF. **Confirmed.**
- `ContainerFormat`: magic `"PQFE"`, `FormatVersion=2`, `AeadAes256Gcm=1`, `NonceLength=12`, `TagLength=16`, `KeyLength=32`, fixed 18-byte header, `MaxKeyParamsLength=65535`. **Confirmed.**
- `IPqContainerCodec` → single impl `SelfContainedContainerCodec` (delegation seam, intentional, `KNOWN-GAPS.md`). **Confirmed.**

### Key Establishment
- Passphrase: `BuildPassphraseAsync` / `DerivePassphraseKeyAsync` (PBKDF2 default 600k; Argon2id via Konscious), decrypt-side range checks present. **Confirmed.**
- ML-KEM recipient (KeySource 2): `BuildRecipient` / `UnwrapRecipientKey`, labels `KekInfo`="…/v2 ml-kem-768 kek", `WrapAad`="…/v2 cek-wrap", exact-length guard `c != KemSizes.MlKem768Ciphertext`. `EnsureMlKemSupported` throws — no weak fallback. **Confirmed. (Deprecated `PQFE002`.)**
- Hybrid (KeySource 3/4): `HybridKeyEstablishment.DeriveKek` IKM = `ss_pq ‖ ss_classical`, labels "…/v3 …". `WrapToRecipient(s)` / `UnwrapFromRecipients` trial-unwrap; `MaxRecipients = (65535-1)/(3+BlockLength) = 55`. **Confirmed.**
- Key provider (KeySource 5): `IContentKeyProvider` + `LocalKekContentKeyProvider` (AES-256-GCM wrap, `wrapInfo=Nonce(12)‖Tag(16)‖Wrapped(32)`). **Confirmed.**

### Format / Hostile-Input Parser
- `ContainerHeader.Parse` (magic, version, AEAD id, KeySource whitelist, chunk-size range, declared-vs-actual KeyParams length) and every per-source KeyParams parser. `PqContainer` per-path `header.KeySource` mismatch checks. `FileIo.WriteViaTempAsync` atomic temp+rename. **Confirmed.**

### Public API / Key Custody
- `PqFileEncryptor`/`PqFileDecryptor` (file/stream/bytes; passphrase/recipient/hybrid/provider; `DecryptAtomicAsync` all-or-nothing buffer). Key types with length-checked import/export + `Dispose` zeroization. `PqEncryptionOptions.Validate()` fail-fast. `PqfeEventSource` (type-name-only failures). **Confirmed.**

### Supply Chain
- `Directory.Build.props`: `Deterministic`, `TreatWarningsAsErrors`, `AnalysisLevel=latest-recommended`, `EnablePackageValidation` baseline `1.1.0`, `ContinuousIntegrationBuild` under CI. **Confirmed.**

### Prompt drift corrected
- The template's "≤256-recipient" figure is the *conceptual* cap; the **actual enforced cap is `MaxRecipients = 55`** (`HybridKeyEstablishment`, surfaced in `PqHybridEncryptor.ValidateRecipients`). Findings below use 55.
- The installable tool ships as **`PostQuantum.FileEncryption.Tool`** (passphrase-only) wrapping `samples/Pqfe.Cli`.

---

## 2. Confirmed Findings (Critical → Low)

### PQFE-001
```
Finding ID:       PQFE-001
Evidence Type:    Static
Defect Type:      Code Defect (resource-bound)
Concern Scope:    Key Establishment / Cross-Concern
Section:          Section 2.1 (T2.1.2) / Section 6 (T6.1) — decrypt-side Argon2id cost
Severity:         Medium
Title:            A hostile container can demand up to 2 GiB × 10,000-iteration Argon2id on decrypt
Affected File(s): src/PostQuantum.FileEncryption/Internal/KeyEstablishment.cs (DerivePassphraseKeyAsync, Argon2id branch);
                  PqEncryptionOptions.cs (MaxArgon2MemoryKiB = 2*1024*1024, MaxArgon2Iterations = 10_000)
Affected Code:    DerivePassphraseKeyAsync → DeriveArgon2idAsync; the decrypt-side range check
Attack Input:     A ~30-byte valid PQFE header (KeySource=passphrase, KdfArgon2id) whose KeyParams
                  declare memoryKiB = 2,097,152 and iterations = 10,000.
Observed Result:  Parameters pass the range check (they are within Min/Max) and the derivation runs
                  BEFORE any ciphertext is authenticated → ~2 GiB allocation + heavy CPU on open.
Expected Result:  Opening an untrusted file should not let the file dictate multi-GiB / multi-second
                  work without a caller-controllable ceiling.
Root Cause:       The Min/Max bounds (correctly) prevent absurd values but the accepted UPPER bound is
                  itself large enough to be a DoS lever; there is no decrypt-time cost cap the caller
                  can lower for untrusted input.
Impact:           Denial of service (memory/CPU) when decrypting attacker-supplied containers. E2EE/
                  confidentiality is NOT broken. Amplification is high (tiny file → GiBs of work).
Recommendation:   Add an opt-in decrypt-time ceiling (e.g. PqDecryptionOptions.MaxArgon2MemoryKiB /
                  MaxKdfWorkFactor) defaulting to a sane value (e.g. 256 MiB) for callers that open
                  files from untrusted sources; reject headers exceeding it with PqFormatException.
Test Reproduced:  Static-only (recommend a unit test feeding a max-cost header and asserting rejection
                  under the new ceiling).

EVIDENCE BASIS: direct code-path confirmation (parser → derivation ordering) + cross-file
(PqEncryptionOptions Min/Max constants ↔ KeyEstablishment decrypt branch).
```

### PQFE-002
```
Finding ID:       PQFE-002
Evidence Type:    Static
Defect Type:      Code Defect (resource-bound / allocation amplification)
Concern Scope:    AEAD Core / Format-Parser
Section:          Section 3 (T3.6) / Section 6 (T6.2) — chunk-buffer allocation
Severity:         Low (Medium under parallel/automated decrypt)
Title:            Declared chunk size drives ~2×chunk allocation before the first frame authenticates
Affected File(s): src/PostQuantum.FileEncryption/Internal/PqContainerEngine.cs (DecryptCoreAsync buffers);
                  ContainerFormat.cs / PqEncryptionOptions.cs (MaxChunkSizeBytes = 16 MiB)
Affected Code:    DecryptCoreAsync allocates ciphertext[ChunkSize] + plaintext[ChunkSize] from the
                  header-declared chunk size (range-checked 1 KiB..16 MiB) before reading any frame.
Attack Input:     A minimal container whose header declares ChunkSize = 16 MiB but carries a 1-byte
                  final frame.
Observed Result:  ~32 MiB allocated per decrypt op regardless of actual content size (encrypt path
                  allocates 3×chunk ≈ 48 MiB). The chunk size IS authenticated via AAD, but allocation
                  precedes the first tag check.
Expected Result:  Bounded — and it is bounded (16 MiB cap is deliberate per the code comment "bounds
                  peak memory"). The residual is a cheap amplification lever (tiny file → tens of MiB).
Root Cause:       Buffers are sized to the declared chunk size up front; the cap (16 MiB) is the only
                  bound, and it is generous for untrusted input.
Impact:           Memory-pressure DoS amplification, worsened by concurrent/automated decryption of
                  many small hostile files. No confidentiality/integrity impact.
Recommendation:   Cap the initial buffer at min(declaredChunkSize, fileLength-derived bound) where the
                  container length is known (file/bytes APIs), or expose a lower decrypt-time chunk
                  ceiling alongside PQFE-001. Document the worst-case peak.
Test Reproduced:  Static-only.

EVIDENCE BASIS: direct code-path confirmation (DecryptCoreAsync buffer sizing vs frame read order).
```

### PQFE-003
```
Finding ID:       PQFE-003
Evidence Type:    Architectural (documented)
Defect Type:      Code Defect (streaming semantics) — DISCLOSED
Concern Scope:    AEAD Core / Public API
Section:          Section 1 (T1.2.4) / Section 8 (Chain F) — partial-plaintext on mid-stream failure
Severity:         Low (disclosed; mitigations shipped)
Title:            Stream-to-stream decrypt emits authentic chunks before a final-frame truncation is detected
Affected File(s): src/PostQuantum.FileEncryption/Internal/PqContainerEngine.cs (DecryptCoreAsync writes
                  each chunk as it authenticates); PqFileDecryptor.cs (DecryptAtomicAsync mitigation);
                  KNOWN-GAPS.md ("No streaming all-or-nothing guarantee")
Affected Code:    DecryptCoreAsync writes plaintext to `destination` per-chunk; for a caller-supplied
                  output Stream those bytes cannot be un-written if a later frame is missing.
Attack Input:     A valid multi-chunk container truncated before its FrameFinal.
Observed Result:  Earlier authentic chunks reach the caller's output stream; then PqDecryptionException
                  ("…truncated…") is thrown. The FILE API and DecryptAtomicAsync do NOT exhibit this
                  (temp-file+rename / full in-memory buffer).
Expected Result:  Per the documented contract: stream callers needing strict atomicity must use the
                  file API or DecryptAtomicAsync. This is a disclosed limitation, not a hidden bug.
Root Cause:       A stream cannot be un-written; per-chunk authentication is correct but emission is
                  incremental.
Impact:           A stream consumer could observe a plaintext PREFIX of a container that ultimately
                  fails to authenticate to completion. No key/tamper bypass; the failure is still raised.
Recommendation:   Keep, but (a) ensure docs/quickstarts steer untrusted-input stream callers to
                  DecryptAtomicAsync / the file API, and (b) consider making DecryptAtomicAsync the
                  default-documented path for Stream→Stream untrusted input.
Test Reproduced:  Static-only (behavior matches KNOWN-GAPS and NoOracle/Atomic test intent).

EVIDENCE BASIS: doc divergence is NONE — KNOWN-GAPS.md explicitly documents this; confirmed in code.
```

### PQFE-004
```
Finding ID:       PQFE-004
Evidence Type:    Static
Defect Type:      Key-Custody Defect (sample-scope)
Concern Scope:    Public API / Key Custody (CLI)
Section:          Section 4 (T4.6) — CLI passphrase handling
Severity:         Low
Title:            CLI passphrase intermediates are unzeroed managed strings; --passphrase-env exposes the passphrase to the environment
Affected File(s): samples/Pqfe.Cli/Program.cs (ReadPassphrase, ReadLineSecret)
Affected Code:    `string first/second` and the StringBuilder in ReadLineSecret hold the passphrase as
                  immutable managed strings that are never (and cannot be) zeroed; --passphrase-env
                  reads the secret from an environment variable.
Attack Input:     n/a (custody/exposure review).
Observed Result:  The CLI correctly zeroes the UTF-8 `byte[]` it passes to the library, but the
                  intermediate `string`/StringBuilder copies linger until GC. Env-var passphrases are
                  visible to child processes and can appear in crash dumps / process inspection.
Expected Result:  Best-effort zeroization per CLAUDE.md; env-var intake documented as a tradeoff.
Root Cause:       Console line reading yields managed strings; env vars are process-global.
Impact:           Minor local key-exposure surface in the sample tool. Library core is unaffected.
Recommendation:   Note the env-var tradeoff in CLI help (already "recommended for scripts/CI" — add
                  the caveat); optionally read the secret char-by-char into a zeroable buffer. Low
                  priority given sample scope.
Test Reproduced:  Static-only.

EVIDENCE BASIS: direct code-path confirmation in the sample CLI.
```

### PQFE-005
```
Finding ID:       PQFE-005
Evidence Type:    Architectural (documented)
Defect Type:      Deployment-Infra Risk — DISCLOSED
Concern Scope:    Format-Parser / Public API
Section:          Section 3 (T3.5) — atomic write & temp-file lifetime
Severity:         Low (disclosed)
Title:            Decrypt temp file may linger with plaintext on hard crash / OS lock; inherits directory ACLs
Affected File(s): src/PostQuantum.FileEncryption/Internal/FileIo.cs (WriteViaTempAsync, TryDelete);
                  KNOWN-GAPS.md ("Atomic-write temp-file cleanup is best-effort")
Affected Code:    Writes to `outputPath + ".tmp-<guid>"` then File.Move(overwrite:true); TryDelete
                  swallows exceptions on failure cleanup.
Observed Result:  Destination integrity is preserved (no partial file ever moved into place). On a
                  failure where the temp can't be deleted (AV lock, crash), a `*.tmp-*` file holding
                  decrypted PLAINTEXT (decrypt path) may remain with the destination directory's ACLs.
Expected Result:  Best-effort cleanup; documented.
Root Cause:       Cross-platform atomic write requires a staging file; deletion can be blocked by the OS.
Impact:           A plaintext remnant could persist in a directory the caller may consider transient.
Recommendation:   Document that operators handling sensitive plaintext should ensure the output
                  directory has appropriate ACLs and run a `*.tmp-*` sweep; consider FileOptions
                  hardening where available. Already in KNOWN-GAPS.
Test Reproduced:  Static-only (AtomicWriteIoFailureTests exercises the failure path).

EVIDENCE BASIS: doc divergence NONE; confirmed in code + KNOWN-GAPS.
```

### PQFE-006
```
Finding ID:       PQFE-006
Evidence Type:    Architectural (documented)
Defect Type:      Key-Custody Defect (dependency) — DISCLOSED
Concern Scope:    Key Establishment (Hybrid)
Section:          Section 2.3 (T2.3.4) — BouncyCastle key-copy zeroization
Severity:         Low (disclosed)
Title:            BouncyCastle parameter objects retain unzeroable private-key copies until GC
Affected File(s): src/PostQuantum.FileEncryption.Hybrid/Internal/HybridKeyEstablishment.cs (TryUnwrapBlock);
                  KNOWN-GAPS.md ("BouncyCastle key objects cannot be zeroized")
Affected Code:    The code zeroes every `byte[]` private-key copy it creates (mlKemKeyCopy /
                  x25519KeyCopy) in finally; BouncyCastle's MLKemPrivateKeyParameters /
                  X25519PrivateKeyParameters keep internal copies with no zeroization API.
Observed Result:  Residual key material lives in managed memory until GC — matches the documented
                  best-effort posture (CLAUDE.md / KNOWN-GAPS).
Expected Result:  Best-effort for managed buffers; the library's own copies ARE zeroed.
Root Cause:       Dependency limitation (managed BouncyCastle).
Impact:           Marginally widens the in-memory key-exposure window for the Hybrid path. Not
                  exploitable without local memory access.
Recommendation:   No code change; keep documented. Revisit if BouncyCastle exposes a clearing API.
Test Reproduced:  Static-only.

EVIDENCE BASIS: direct code-path confirmation + KNOWN-GAPS.
```

### PQFE-007 (Informational)
```
Finding ID:       PQFE-007
Evidence Type:    Architectural (documented)
Defect Type:      Key-Custody (ergonomics) — DISCLOSED
Concern Scope:    Public API / Key Custody
Section:          Section 4 (T4.4) — exception/key hygiene
Severity:         Low / Informational
Title:            `string` passphrase convenience overloads cannot zero the caller's string
Affected File(s): PqFileEncryptor.cs / PqFileDecryptor.cs (string overloads → WithPassphraseBytesAsync)
Observed Result:  The library zeroes the UTF-8 byte copy it derives, but the caller's immutable
                  `string` cannot be cleared. Zeroable ReadOnlyMemory<byte> overloads exist.
Recommendation:   None beyond existing docs; steer security-sensitive callers to the byte overloads.
Test Reproduced:  Static-only.

EVIDENCE BASIS: confirmed in code + KNOWN-GAPS.
```

---

## 3. Partial Findings Requiring Live Verification

| ID | What to test | How |
|----|--------------|-----|
| PQFE-001 | Confirm a max-cost Argon2id header actually allocates ~2 GiB / blocks before any auth | Unit test feeding a crafted header; measure peak working set / time |
| PQFE-002 | Confirm peak allocation for a 16-MiB-chunk / 1-byte-body container | Memory-profiled decrypt of a crafted minimal container |
| PQFE-003 | Confirm exact bytes emitted to a stream before a final-frame truncation throws | Stream→Stream decrypt of a truncated multi-chunk container; capture output |
| (parser) | Exhaustive malformed-KeyParams + truncation sweep across all 5 KeySources | Extend `FuzzTests` / `NoOracleTests` corpus; assert only Pq*Exception, no OOB |
| (interop) | Core-ML-KEM vs Hybrid-BouncyCastle constant agreement (1088/1184/2400) | `CrossImplementationTests` already covers; confirm both directions in CI |

---

## 4. Exploit Chains / Compound Risks

| Chain | Result | First control that holds |
|-------|--------|--------------------------|
| A — Nonce reuse under shared key | **Not reproduced** | Fresh per-file CEK (passphrase derives key from salt+passphrase; recipient/hybrid/provider draw a random 32-byte CEK) + fresh random 4-byte prefix; counter cannot wrap (2^64 chunks × ≥1 KiB). `ContainerHeader.Create`, `BuildNonce`. |
| B — Combiner arm-drop downgrade | **Not reproduced** | `DeriveKek` binds `ss_pq ‖ ss_classical` in fixed order; breaking only one primitive still protects the CEK. |
| C — Tamper accepted / tag bypass | **Not reproduced** | Full `HeaderBytes` + counter + frameType in AAD; `AesGcm.Decrypt` verifies tag before output; `sawFinal` rejects truncation. |
| D — Hostile-header resource exhaustion | **Open (PQFE-001/002)** | Bounds exist but upper limits are generous → DoS lever, no confidentiality loss. |
| E — Format confusion (wrong-path / cross-package) | **Not reproduced** | Each decrypt path checks `header.KeySource` and throws on mismatch; distinct KeySource ids + distinct v2/v3 HKDF labels. |
| F — Partial-plaintext leak | **Contained at the real destination** (PQFE-003 stream caveat documented) | File API temp+rename; `DecryptAtomicAsync` buffers. |
| G — Secret in log/exception | **Not reproduced** | `PqfeEventSource` emits operation/keySource/bytes/timing + exception TYPE name only; generic decrypt message; CLI prints paths/progress, not secrets. |
| H — Supply-chain drift | **Contained** | Deterministic build, warnings-as-errors, package-validation baseline 1.1.0, pinned deps, KAT + interop CI. |

---

## 5. AEAD Integrity Report

| Property | Verdict | Evidence |
|----------|---------|----------|
| Tag verified before plaintext emitted | **PASS** | `DecryptCoreAsync` writes only after `aes.Decrypt` returns |
| Full-header AAD binding | **PASS** | `BuildAad` includes entire `HeaderBytes` |
| Frame-type + counter authenticated | **PASS** | both in AAD; flip/reorder/splice fail the tag |
| Fail-closed truncation | **PASS** | `sawFinal` guard throws on missing FrameFinal |
| No partial plaintext at real destination | **PASS (file/atomic)** / documented caveat (raw stream) | temp+rename; `DecryptAtomicAsync`; PQFE-003 |
| AES-GCM nonce uniqueness per content key | **PASS** | fresh CEK + fresh prefix per file; 64-bit counter non-wrapping |

---

## 6. Key-Establishment Report

| Path | Construction | Decrypt-side bounds | Domain separation | Zeroization | Fail-closed |
|------|--------------|---------------------|-------------------|-------------|-------------|
| Passphrase (PBKDF2/Argon2id) | Standard PBKDF2 / Argon2id → AES-256-GCM | Present; **upper bound generous (PQFE-001)** | Salt per file; not reused as HKDF salt | Passphrase copy + CEK zeroed in finally | PASS |
| ML-KEM recipient (KS2, deprecated) | Encapsulate→HKDF(`v2` label)→GCM wrap | Exact-length guards before decapsulation | `v2` labels distinct | sharedSecret/KEK/CEK zeroed | PASS; `EnsureMlKemSupported` (no weak fallback) |
| Hybrid (KS3/KS4) | `ss_pq‖ss_classical`→HKDF(`v3`)→GCM wrap | count≥1, per-block length bounded by body, `MaxRecipients=55` on write | `v3` labels distinct | own key copies zeroed (BC residual: PQFE-006) | PASS; trial-unwrap bounded |
| Key provider (KS5) | Pluggable; built-in local-KEK AES-256-GCM | Exact `WrapInfoLength`; provider-id length 1..255 | `local-kek` AAD label | KEK zeroed on Dispose; CEK zeroed on tag fail | PASS (custom providers are a caller trust boundary) |

---

## 7. Format/Parser Robustness Matrix

| KeySource / class | Fails closed? | Bounded allocation? | No oracle? |
|-------------------|---------------|---------------------|------------|
| Header (magic/version/AEAD/keysource/chunk/len) | PASS (`PqFormatException`) | PASS (validated before use) | PASS |
| Passphrase KeyParams | PASS | PASS (cost bounds; PQFE-001 caveat) | PASS |
| ML-KEM recipient KeyParams | PASS (exact `expected` length) | PASS | PASS (implicit reject → tag mismatch) |
| Hybrid multi-recipient KeyParams | PASS (count + per-block bounds) | PASS (trial-unwrap ≤ body) | PASS |
| Key-provider KeyParams | PASS (exact total length) | PASS | PASS |
| Truncation (header/frame/tag/pre-final) | PASS | PASS | PASS (generic message) |
| Chunk buffers | PASS | **Bounded but amplifiable (PQFE-002)** | n/a |

---

## 8. Doc Drift Report

- `docs/FILE-FORMAT.md` layout vs `ContainerFormat`/engine/parsers — **no drift observed** in the constants and offsets reviewed.
- `SECURITY.md` / `KNOWN-GAPS.md` — **accurate**; the streaming-atomicity gap (PQFE-003), temp-file lifetime (PQFE-005), BouncyCastle residual (PQFE-006), and `string`-passphrase ergonomics (PQFE-007) are all already disclosed.
- `CLAUDE.md` non-negotiables — **upheld**: no homegrown crypto, authenticated-only, fail-closed, `FormatVersion` frozen at 2, key material zeroed in `finally`.
- **Prompt drift (not a code defect):** the "256-recipient cap" in the template is conceptual; enforced cap is `MaxRecipients=55`.

---

## 9. Top 10 Remediations by Risk Reduction / Effort

1. **PQFE-001** — Add a caller-overridable decrypt-time KDF cost ceiling (default ~256 MiB) for untrusted input. *(High value / low effort.)*
2. **PQFE-002** — When the container length is known, cap the initial chunk buffer to the data-derived bound; otherwise expose a decrypt-time chunk ceiling. *(Med / low.)*
3. **PQFE-003** — Make `DecryptAtomicAsync`/file API the documented default for untrusted Stream→Stream input; add a quickstart note. *(Med / low.)*
4. **PQFE-004** — Add the env-var caveat to CLI help; optionally read the passphrase into a zeroable buffer. *(Low / low.)*
5. Add regression tests asserting rejection of max-cost Argon2id headers under the new ceiling (PQFE-001). *(Med / low.)*
6. Add a memory-profiled test pinning worst-case decrypt allocation (PQFE-002). *(Low / low.)*
7. **PQFE-005** — Document temp-directory ACL guidance + sweep for `*.tmp-*`. *(Low / low.)*
8. Extend the fuzz corpus to systematically cover every KeySource's malformed-KeyParams + truncation matrix. *(Med / med.)*
9. Confirm `CrossImplementationTests` exercises both core↔Hybrid directions and the Rust/WASM interop in CI for KS3/KS4 sizes. *(Low / low.)*
10. **PQFE-006/007** — No code change; keep documented and re-evaluate on dependency updates. *(Informational.)*

---

## 10. Security Regression Tests to Add

- **KDF cost ceiling:** decrypt a header declaring 2 GiB / 10,000-iter Argon2id → expect `PqFormatException` under a configured ceiling (PQFE-001).
- **Allocation bound:** decrypt a 16-MiB-chunk / 1-byte-body container under a memory probe → assert peak ≤ expected (PQFE-002).
- **Stream partial-emission contract:** Stream→Stream decrypt of a pre-final truncation → assert output is empty OR documented-prefix and exception raised (PQFE-003); `DecryptAtomicAsync` of the same → assert zero bytes written.
- **Parser sweep:** per KeySource, every off-by-one / overrun / unknown-id / truncation → assert only `Pq*Exception`, never OOB/hang (extend `FuzzTests`/`NoOracleTests`).
- **Format confusion:** each (encrypt path × mismatched decrypt path) pair → assert clean `PqDecryptionException` (extend `ErrorHandlingTests`).
- **Combiner negative:** a hybrid block with a corrupted single arm → assert unwrap fails closed (no CEK recovered).

---

## 11. What Was Tested vs What Could Not Be Verified

**Tested (static, source-confirmed):** nonce/AAD construction, frame state machine + `sawFinal`, tag-before-plaintext ordering, all four key-establishment constructions and their decrypt-side bounds, every header/KeyParams parser branch, format-confusion routing, telemetry/exception hygiene, atomic write path, DI registration, CLI passphrase handling, build/supply-chain settings, doc accuracy.

**Not verified this pass (requires runtime):** actual peak-memory/time for PQFE-001/002, exact stream byte-emission for PQFE-003, live fuzz execution, platform-ML-KEM recipient round-trip (self-skips on hosts without ML-KEM), Rust/WASM interop job results.

---

## 12. Release Blockers

**None.** All confirmed findings are Medium/Low hardening items; the Medium DoS (PQFE-001) and the allocation amplification (PQFE-002) are availability concerns on untrusted input, not confidentiality/integrity breaks, and the rest are disclosed tradeoffs. Recommend addressing PQFE-001 and the steering for PQFE-003 in the next minor release.

*To God be the glory — 1 Corinthians 10:31.*
