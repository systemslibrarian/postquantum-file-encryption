> **Provenance:** AI-assisted adversarial static self-review (run B of two independent
> runs), commissioned and reviewed by the maintainer against the working tree after
> commit `54df378` (library at released `1.1.0`). This is **self-review, not an
> independent audit** — see [docs/GOLD-STANDARD.md](../GOLD-STANDARD.md) §6.
> **Disposition:** findings PQFE-001/002/003/004 were remediated in `1.2.0` (commit
> `bdec193`); PQFE-005/006/007 are documented tradeoffs in [KNOWN-GAPS.md](../../KNOWN-GAPS.md).

================================================================================
PostQuantum.FileEncryption — Adversarial Security Audit RESULTS (Run B)
Audit template: audit-scripts/ADVERSARIAL-AUDIT.md
Method: Evidence-first static source review of the live tree. No runtime/fuzz
  execution this pass — findings are Static or Architectural (documented).
Basis: working tree post-54df378, library at released 1.1.0.
================================================================================

--------------------------------------------------------------------------------
SUMMARY
--------------------------------------------------------------------------------
The fail-closed contract HOLDS. Every Critical/High attack class in the prompt —
nonce reuse, tag bypass, combiner downgrade, partial plaintext at the real
destination, format confusion, decrypt-side cost unbounding, log/exception oracle
— was driven against source and did NOT reproduce. Confirmed findings are all
Medium/Low hardening items; several are already disclosed in KNOWN-GAPS.md as
intentional tradeoffs. NO release blockers.

Scorecard:
  C1 No homegrown crypto ................ HOLDS
  C2 Authenticated-only / fail-closed ... HOLDS
  C3 .pqfe v2 frozen (FormatVersion=2) .. HOLDS
  C4 Nonce uniqueness per key ........... HOLDS
  C5 Full-header AAD binding ............ HOLDS
  C6 Bounded cost from untrusted header . PARTIAL — bounds exist, upper limits
                                          generous (PQFE-001/002)
  C7 Best-effort zeroization ............ HOLDS (BC residual disclosed, PQFE-006)
  C8 Hybrid binds BOTH arms ............. HOLDS
  C9 Self-contained codec seam .......... HOLDS (single impl, intentional)

================================================================================
1. ATTACK SURFACE MAP (confirmed from live source; drift noted)
================================================================================
AEAD CORE
  PqContainerEngine.{EncryptCoreAsync,DecryptCoreAsync,BuildNonce,BuildAad,
    ReadHeaderAsync,DerivePlaintextTotal,ReadAtMostAsync}. nonce = prefix(4) ‖
    counter(8 BE); AAD = HeaderBytes ‖ counter(8 BE) ‖ frameType; sawFinal guard.
  ContainerFormat: "PQFE", FormatVersion=2, AeadAes256Gcm=1, NonceLength=12,
    TagLength=16, KeyLength=32, FixedHeaderLength=18, MaxKeyParamsLength=65535,
    FrameData=0/FrameFinal=1, KeySource 1..5.  [CONFIRMED]
  IPqContainerCodec -> SelfContainedContainerCodec (only impl).  [CONFIRMED]

KEY ESTABLISHMENT
  KeyEstablishment: BuildPassphraseAsync/DerivePassphraseKeyAsync (PBKDF2 600k def
    / Argon2id via Konscious); BuildRecipient/UnwrapRecipientKey (KS2, v2 labels,
    exact-length guard, EnsureMlKemSupported — no weak fallback).  [CONFIRMED]
  Hybrid/HybridKeyEstablishment: DeriveKek IKM = ss_pq‖ss_classical (v3 labels);
    WrapToRecipient(s)/UnwrapFromRecipients/TryUnwrapBlock; MaxRecipients=55.
    [CONFIRMED]
  IContentKeyProvider + LocalKekContentKeyProvider (KS5; AES-256-GCM CEK wrap,
    wrapInfo = Nonce(12)‖Tag(16)‖Wrapped(32)).  [CONFIRMED]

FORMAT / PARSER
  ContainerHeader.Parse (magic/version/AEAD/keysource-whitelist/chunk-range/
    declared-vs-actual KeyParams len); per-source KeyParams parsers; PqContainer
    per-path header.KeySource mismatch checks; FileIo.WriteViaTempAsync atomic
    temp+rename.  [CONFIRMED]

PUBLIC API / KEY CUSTODY
  PqFileEncryptor/Decryptor (file/stream/bytes; passphrase/recipient/hybrid/
    provider; DecryptAtomicAsync all-or-nothing); Pq{Recipient,Hybrid}* key types
    (length-checked import/export, Dispose zeroization); PqEncryptionOptions.
    Validate(); PqfeEventSource (type-name-only failures); PqEncryptionException
    hierarchy (generic decrypt message).  [CONFIRMED]

SUPPLY CHAIN
  Directory.Build.props: Deterministic, TreatWarningsAsErrors, AnalysisLevel
    latest-recommended, EnablePackageValidation baseline 1.1.0, CI build flag.
    Pinned Konscious + BouncyCastle. KAT + Rust/WASM interop in CI.  [CONFIRMED]

PROMPT DRIFT CORRECTED
  - Recipient cap is MaxRecipients=55 (not 256). Enforced in
    PqHybridEncryptor.ValidateRecipients via HybridKeyEstablishment.MaxRecipients.
  - Installable tool = PostQuantum.FileEncryption.Tool (passphrase-only), wrapping
    samples/Pqfe.Cli.

================================================================================
2. CONFIRMED FINDINGS (Critical -> Low)
================================================================================

Finding ID:       PQFE-001
Evidence Type:    Static
Defect Type:      Code (resource-bound)
Concern:          Key Establishment / Cross-Concern
Section:          §4 (T4.1.2) / §8 (T8.1)
Severity:         Medium
Title:            Hostile container can demand 2 GiB x 10,000-iter Argon2id on decrypt
Affected File(s): Internal/KeyEstablishment.cs (DerivePassphraseKeyAsync Argon2id branch);
                  PqEncryptionOptions.cs (MaxArgon2MemoryKiB=2 GiB, MaxArgon2Iterations=10_000)
Affected Code:    decrypt-side range check -> DeriveArgon2idAsync
Attack Input:     ~30-byte valid header (KeySource=passphrase, KdfArgon2id) declaring
                  memoryKiB=2,097,152, iterations=10,000
Observed Result:  Values pass the Min/Max check and the derivation runs BEFORE any
                  ciphertext authenticates -> multi-GiB / multi-second work on open.
Expected Result:  Opening untrusted input should not let the file dictate that cost
                  without a caller-lowerable ceiling.
Root Cause:       Bounds prevent absurd values but the accepted UPPER bound is itself
                  a DoS lever; no decrypt-time cost cap is exposed.
Impact:           Denial of service (memory/CPU). Confidentiality/integrity NOT broken.
                  High amplification (tiny file -> GiBs of work).
Recommendation:   Add opt-in PqDecryptionOptions.MaxArgon2MemoryKiB / work ceiling
                  (default ~256 MiB) for untrusted input; reject over-limit headers as
                  PqFormatException.
Test Reproduced:  Static-only
Evidence Basis:   direct code-path (parser->derivation order) + Options Min/Max constants
Spec-Drift Note:  none — within documented bounds; this is a hardening gap, not a contradiction

--------------------------------------------------------------------------------
Finding ID:       PQFE-002
Evidence Type:    Static
Defect Type:      Code (allocation amplification)
Concern:          AEAD Core / Format-Parser
Section:          §5 (T5.6) / §8 (T8.2)
Severity:         Low (Medium under parallel/automated decrypt)
Title:            Declared chunk size drives ~2x-chunk allocation before first frame authenticates
Affected File(s): Internal/PqContainerEngine.cs (DecryptCoreAsync buffers);
                  ContainerFormat/PqEncryptionOptions (MaxChunkSizeBytes=16 MiB)
Affected Code:    DecryptCoreAsync allocates ciphertext[ChunkSize]+plaintext[ChunkSize]
                  from the header-declared (range-checked) chunk size before reading frames
Attack Input:     container whose header declares ChunkSize=16 MiB, carrying a 1-byte final frame
Observed Result:  ~32 MiB allocated per decrypt regardless of real size (encrypt path ~48 MiB).
                  Chunk size IS authenticated via AAD, but allocation precedes the first tag check.
Expected Result:  Bounded — and it is (16 MiB cap deliberate, "bounds peak memory"). Residual is
                  a cheap amplification lever.
Root Cause:       Buffers sized to declared chunk size up front; 16 MiB is the only bound.
Impact:           Memory-pressure DoS amplification, worse under concurrent decrypt of many small
                  hostile files. No confidentiality/integrity impact.
Recommendation:   Where container length is known (file/bytes API), cap initial buffer to the
                  data-derived bound; or expose a lower decrypt-time chunk ceiling (with PQFE-001).
Test Reproduced:  Static-only
Evidence Basis:   direct code-path (buffer sizing vs frame-read order)
Spec-Drift Note:  none

--------------------------------------------------------------------------------
Finding ID:       PQFE-003
Evidence Type:    Architectural (DISCLOSED)
Defect Type:      Code (streaming semantics) — documented
Concern:          AEAD Core / Public API
Section:          §3 (T3.2.4) / §10 Chain F
Severity:         Low (mitigations shipped)
Title:            Stream->Stream decrypt emits authentic chunks before final-frame truncation detected
Affected File(s): Internal/PqContainerEngine.cs (per-chunk write); PqFileDecryptor.cs
                  (DecryptAtomicAsync mitigation); KNOWN-GAPS.md
Affected Code:    DecryptCoreAsync writes plaintext per-chunk to the caller's output stream
Attack Input:     valid multi-chunk container truncated before FrameFinal
Observed Result:  earlier authentic chunks reach the output stream, then PqDecryptionException is
                  thrown. FILE API and DecryptAtomicAsync do NOT exhibit this (temp+rename / buffer).
Expected Result:  per documented contract — stream callers needing strict atomicity use the file API
                  or DecryptAtomicAsync. Disclosed limitation, not a hidden bug.
Root Cause:       a stream cannot be un-written; per-chunk auth is correct but emission is incremental.
Impact:           a stream consumer may observe a plaintext PREFIX of a container that ultimately
                  fails to fully authenticate. No key/tamper bypass; failure is still raised.
Recommendation:   steer untrusted Stream->Stream callers to DecryptAtomicAsync / file API in docs;
                  consider making the atomic path the documented default.
Test Reproduced:  Static-only
Evidence Basis:   code + KNOWN-GAPS ("No streaming all-or-nothing guarantee")
Spec-Drift Note:  none — explicitly documented

--------------------------------------------------------------------------------
Finding ID:       PQFE-004
Evidence Type:    Static
Defect Type:      Key-Custody (sample scope)
Concern:          Public API / Key Custody (CLI)
Section:          §6 (T6.6)
Severity:         Low
Title:            CLI passphrase intermediates unzeroed; --passphrase-env exposes secret to environment
Affected File(s): samples/Pqfe.Cli/Program.cs (ReadPassphrase, ReadLineSecret)
Affected Code:    `string first/second` + StringBuilder hold the passphrase as immutable managed
                  strings (never zeroable); --passphrase-env reads from an environment variable
Observed Result:  the CLI correctly zeroes the UTF-8 byte[] handed to the library, but the string/
                  StringBuilder copies linger until GC; env-var passphrases are visible to child
                  processes and crash dumps.
Expected Result:  best-effort zeroization (CLAUDE.md); env-var intake documented as a tradeoff.
Root Cause:       console line reads yield managed strings; env vars are process-global.
Impact:           minor local key-exposure in the sample tool; library core unaffected.
Recommendation:   add env-var caveat to CLI help; optionally read chars into a zeroable buffer.
Test Reproduced:  Static-only
Evidence Basis:   direct code-path in sample CLI
Spec-Drift Note:  none

--------------------------------------------------------------------------------
Finding ID:       PQFE-005
Evidence Type:    Architectural (DISCLOSED)
Defect Type:      Deployment-Infra — documented
Concern:          Format-Parser / Public API
Section:          §5 (T5.5)
Severity:         Low
Title:            Decrypt temp file may linger with plaintext on hard crash / OS lock; inherits dir ACLs
Affected File(s): Internal/FileIo.cs (WriteViaTempAsync, TryDelete); KNOWN-GAPS.md
Affected Code:    writes outputPath + ".tmp-<guid>" then File.Move(overwrite:true); TryDelete
                  swallows cleanup exceptions
Observed Result:  destination integrity preserved (no partial file ever moved into place); on a
                  failure where the temp can't be deleted, a *.tmp-* holding decrypted PLAINTEXT may
                  remain with the destination directory's ACLs.
Expected Result:  best-effort cleanup; documented.
Root Cause:       cross-platform atomic write needs a staging file; deletion can be OS-blocked.
Impact:           plaintext remnant could persist in a directory assumed transient.
Recommendation:   document temp-dir ACL guidance + periodic *.tmp-* sweep; consider FileOptions
                  hardening where available.
Test Reproduced:  Static-only (AtomicWriteIoFailureTests exercises the failure path)
Evidence Basis:   code + KNOWN-GAPS
Spec-Drift Note:  none

--------------------------------------------------------------------------------
Finding ID:       PQFE-006
Evidence Type:    Architectural (DISCLOSED)
Defect Type:      Key-Custody (dependency) — documented
Concern:          Key Establishment (Hybrid)
Section:          §4 (T4.3.4)
Severity:         Low
Title:            BouncyCastle parameter objects keep unzeroable private-key copies until GC
Affected File(s): Hybrid/Internal/HybridKeyEstablishment.cs (TryUnwrapBlock); KNOWN-GAPS.md
Affected Code:    code zeroes its own mlKemKeyCopy/x25519KeyCopy in finally; BC's
                  MLKemPrivateKeyParameters/X25519PrivateKeyParameters keep internal copies with no
                  clearing API
Observed Result:  residual key material lives until GC — matches documented best-effort posture.
Impact:           marginally widens in-memory key-exposure window for the Hybrid path; not
                  exploitable without local memory access.
Recommendation:   no code change; keep documented; revisit if BC adds a clearing API.
Test Reproduced:  Static-only
Evidence Basis:   code + KNOWN-GAPS
Spec-Drift Note:  none

--------------------------------------------------------------------------------
Finding ID:       PQFE-007
Evidence Type:    Architectural (DISCLOSED)
Defect Type:      Key-Custody (ergonomics) — documented
Concern:          Public API / Key Custody
Section:          §6 (T6.4)
Severity:         Low / Informational
Title:            `string` passphrase convenience overloads cannot zero the caller's string
Affected File(s): PqFileEncryptor.cs / PqFileDecryptor.cs (string overloads -> WithPassphraseBytesAsync)
Observed Result:  library zeroes the derived UTF-8 byte copy, but the caller's immutable string can't
                  be cleared; zeroable ReadOnlyMemory<byte> overloads exist.
Recommendation:   none beyond docs; steer sensitive callers to the byte overloads.
Test Reproduced:  Static-only
Evidence Basis:   code + KNOWN-GAPS
Spec-Drift Note:  none

================================================================================
3. PARTIAL FINDINGS REQUIRING RUNTIME/FUZZ/CLI VERIFICATION
================================================================================
  PQFE-001  measure actual peak working-set / wall time for a max-cost Argon2id header
  PQFE-002  memory-profile decrypt of a 16-MiB-chunk / 1-byte-body container
  PQFE-003  capture exact bytes emitted to a stream before a pre-final truncation throws
  parser    run the full malformed-KeyParams + truncation matrix across all 5 KeySources
            through FuzzTests/NoOracleTests (assert only Pq*Exception, no OOB/hang)
  interop   confirm CrossImplementationTests + Rust/WASM interop CI cover KS sizes both ways
  platform  recipient round-trip self-skips where platform ML-KEM is absent — verify on a
            host with OpenSSL 3.5+/Windows CNG

================================================================================
4. EXPLOIT CHAINS — first broken control / containing concern
================================================================================
  A Nonce reuse ............. NOT REPRODUCED. Fresh per-file CEK + fresh random prefix;
                             64-bit counter non-wrapping. (AEAD Core contains it.)
  B Combiner arm-drop ...... NOT REPRODUCED. DeriveKek binds ss_pq‖ss_classical fixed-order.
                             (Key Establishment contains it.)
  C Tamper accepted ........ NOT REPRODUCED. Full-header+counter+frameType AAD; tag-before-
                             plaintext; sawFinal. (AEAD Core contains it.)
  D Hostile-header DoS ...... OPEN (PQFE-001/002). Bounds exist; upper limits generous.
                             Availability only. (Should be contained by Key Establishment /
                             Parser cost caps.)
  E Format confusion ....... NOT REPRODUCED. Per-path header.KeySource check; distinct
                             KeySource ids + v2/v3 labels. (Format-Parser contains it.)
  F Partial plaintext ...... CONTAINED at real destination (file/atomic); raw-stream caveat
                             disclosed (PQFE-003). (Public API contains it.)
  G Secret in log/exception  NOT REPRODUCED. EventSource = type-name only; generic decrypt
                             message; CLI prints paths/progress, not secrets. (All concerns.)
  H Supply-chain drift ..... CONTAINED. Deterministic build, warnings-as-errors, package-
                             validation baseline 1.1.0, pinned deps, KAT+interop CI.

================================================================================
5. FAIL-CLOSED / AEAD INTEGRITY REPORT
================================================================================
  tag-before-plaintext .............. PASS (write only after AesGcm.Decrypt returns)
  full-header AAD binding ........... PASS (BuildAad includes entire HeaderBytes)
  frame-type/counter authenticated .. PASS (both in AAD; flip/reorder/splice fail)
  fail-closed truncation (sawFinal) . PASS (throws on missing FrameFinal)
  no-partial-plaintext (real dest) .. PASS for file/atomic; documented stream caveat (PQFE-003)
  AES-GCM nonce uniqueness per key .. PASS (fresh CEK + fresh prefix; counter non-wrapping)

================================================================================
6. KEY-ESTABLISHMENT REPORT
================================================================================
  Passphrase: standard PBKDF2/Argon2id->GCM. Decrypt bounds PRESENT but upper limit
    generous (PQFE-001). Salt per file, not reused. Passphrase copy + CEK zeroed. FAIL-CLOSED.
  ML-KEM recipient (KS2, deprecated): encapsulate->HKDF(v2)->GCM wrap. Exact-length guards
    before decapsulation. Implicit reject -> tag mismatch -> generic error. No weak fallback
    (EnsureMlKemSupported). FAIL-CLOSED.
  Hybrid (KS3/KS4): ss_pq‖ss_classical->HKDF(v3)->GCM wrap. count>=1, per-block length bounded
    by body, MaxRecipients=55 on write, trial-unwrap bounded. Own key copies zeroed (BC residual
    PQFE-006). FAIL-CLOSED.
  Key provider (KS5): pluggable; local-KEK AES-256-GCM; exact WrapInfoLength; provider-id 1..255;
    KEK zeroed on Dispose; CEK zeroed on tag fail. FAIL-CLOSED. (Custom providers are a caller
    trust boundary — documented.)

================================================================================
7. FORMAT/PARSER ROBUSTNESS MATRIX
================================================================================
  surface                         fails-closed  bounded-alloc  no-oracle
  header (magic/ver/aead/ks/...) .... PASS .......... PASS ........ PASS
  passphrase KeyParams ............. PASS .......... PASS* ....... PASS   (*cost: PQFE-001)
  ml-kem recipient KeyParams ....... PASS .......... PASS ........ PASS
  hybrid multi-recipient KeyParams . PASS .......... PASS ........ PASS
  key-provider KeyParams ........... PASS .......... PASS ........ PASS
  truncation (hdr/frame/tag/pre-fin) PASS .......... PASS ........ PASS
  chunk buffers .................... PASS .......... BOUNDED* .... n/a    (*amplifiable: PQFE-002)

================================================================================
8. DOC DRIFT REPORT
================================================================================
  docs/FILE-FORMAT.md vs code ..... no drift observed in reviewed constants/offsets/layout
  SECURITY.md / KNOWN-GAPS.md ..... accurate; PQFE-003/005/006/007 all already disclosed
  CLAUDE.md non-negotiables ....... upheld (no homegrown crypto; auth-only; fail-closed;
                                    FormatVersion frozen at 2; key material zeroed in finally)
  prompt drift (not code defect) .. "256-recipient cap" is conceptual; enforced cap is 55

================================================================================
9. TOP 10 REMEDIATIONS (risk-reduction / effort)
================================================================================
   1. PQFE-001 — caller-overridable decrypt-time KDF cost ceiling (default ~256 MiB).  [high/low]
   2. PQFE-002 — cap initial chunk buffer to data-derived bound when length known.     [med/low]
   3. PQFE-003 — document DecryptAtomicAsync/file API as default for untrusted streams.[med/low]
   4. PQFE-004 — CLI env-var caveat + optional zeroable passphrase buffer.             [low/low]
   5. regression test: reject max-cost Argon2id header under new ceiling.              [med/low]
   6. regression test: pin worst-case decrypt allocation.                             [low/low]
   7. PQFE-005 — temp-dir ACL guidance + *.tmp-* sweep doc.                            [low/low]
   8. extend fuzz corpus to full per-KeySource malformed+truncation matrix.           [med/med]
   9. confirm core<->Hybrid + Rust/WASM interop both ways in CI for KS3/KS4.           [low/low]
  10. PQFE-006/007 — no code change; keep documented; re-evaluate on dep updates.      [info]

================================================================================
10. SECURITY REGRESSION TESTS TO ADD
================================================================================
  - KDF cost ceiling: max-cost Argon2id header -> expect PqFormatException under ceiling (PQFE-001)
  - allocation bound: 16-MiB-chunk / 1-byte-body container -> assert peak <= expected (PQFE-002)
  - stream contract: pre-final truncation Stream->Stream -> documented-prefix + exception;
    DecryptAtomicAsync of same -> zero bytes written (PQFE-003)
  - parser sweep: per KeySource off-by-one/overrun/unknown-id/truncation -> only Pq*Exception
  - format confusion: each (encrypt path x mismatched decrypt path) -> clean PqDecryptionException
  - combiner negative: hybrid block with one corrupted arm -> unwrap fails closed (no CEK)

================================================================================
11. WHAT WAS TESTED vs WHAT COULD NOT BE VERIFIED
================================================================================
  Tested (static, source-confirmed): nonce/AAD construction; frame state machine + sawFinal;
    tag-before-plaintext ordering; all four key-establishment constructions + decrypt bounds;
    every header/KeyParams parser branch; format-confusion routing; telemetry/exception hygiene;
    atomic write path; DI registration; CLI passphrase handling; build/supply-chain settings;
    doc accuracy.
  Not verified this pass (runtime): peak memory/time for PQFE-001/002; exact stream byte emission
    for PQFE-003; live fuzz execution; platform-ML-KEM recipient round-trip (self-skips without
    ML-KEM); Rust/WASM interop job results.

================================================================================
12. (output format reference) — see §2 finding blocks above
================================================================================
  All findings use the prompt's required block: Finding ID / Evidence Type / Defect Type /
  Concern / Section / Severity / Title / Affected File(s) / Affected Code / Attack Input /
  Observed / Expected / Root Cause / Impact / Recommendation / Test Reproduced / Evidence Basis /
  Spec-Drift Note.

================================================================================
13. RELEASE BLOCKERS
================================================================================
  NONE. All confirmed findings are Medium/Low hardening items. PQFE-001 (Medium DoS) and
  PQFE-002 (allocation amplification) are AVAILABILITY concerns on untrusted input, not
  confidentiality/integrity breaks; the rest are disclosed tradeoffs. Recommend landing
  PQFE-001 and the PQFE-003 doc-steering in the next minor release.

--------------------------------------------------------------------------------
To God be the glory — 1 Corinthians 10:31
--------------------------------------------------------------------------------
