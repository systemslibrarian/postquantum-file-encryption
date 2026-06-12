================================================================================
PostQuantum.FileEncryption — Adversarial Security Audit Prompt
Version 1.0 | .NET 10 library family — post-quantum / hybrid file & stream encryption
Auditor Role: Senior red-team penetration tester, applied cryptographer,
  application security engineer, .NET secure-coding reviewer
Target Repository: postquantum-file-encryption — the fail-closed PQ wrapper for
  file/stream encryption (NuGet: PostQuantum.FileEncryption + .Hybrid +
  .Extensions.DependencyInjection + Pqfe.Cli)
Audit Standard: Evidence-first, adversarial, code-aware, hostile-input driven,
  construction-aware
================================================================================

================================================================================
0. READ THIS FIRST — SCOPE, TRUST MODEL & HOW TO USE THIS PROMPT
================================================================================

This prompt targets a single codebase that is a LIBRARY FAMILY, not a service.
There is no server, no network protocol, and no multi-user authorization layer.
The trust model is local and adversarial-input-centric:

  THE ATTACKER CONTROLS THE INPUT `.pqfe` FILE (and may have crafted every byte).

Decryption must therefore be a TOTAL FUNCTION over arbitrary bytes: every input
either round-trips authentic plaintext or throws — no third outcome, no leak about
WHY it failed, no unbounded resource use. The security of the system is the JOINT
product of three concerns, and a defect in any one collapses the guarantee:

  Concern 1 — AEAD CONTAINER CORE (`src/PostQuantum.FileEncryption/Internal/
    PqContainerEngine.cs`, `ContainerFormat.cs`): chunked AES-256-GCM, the
    nonce = randomPrefix(4) ‖ counter(8 BE) construction, the AAD =
    headerBytes ‖ counter ‖ frameType binding, and the FrameData/FrameFinal state
    machine with the `sawFinal` truncation guard. If a tag check is skipped, a
    nonce repeats under one key, or plaintext escapes before authentication, the
    guarantee is broken regardless of everything else.
  Concern 2 — KEY ESTABLISHMENT (`Internal/KeyEstablishment.cs`,
    `Hybrid/Internal/HybridKeyEstablishment.cs`, `IContentKeyProvider` +
    `LocalKekContentKeyProvider`): four paths to the 32-byte content key —
    passphrase (PBKDF2 / Argon2id), ML-KEM-768 recipient (KEM-DEM), X25519+ML-KEM-768
    hybrid (the combiner), and an external envelope provider. A combiner that drops
    an arm, a missing decrypt-side cost bound, or a domain-separation slip breaks
    confidentiality or downgrades the PQ guarantee.
  Concern 3 — FORMAT & HOSTILE-INPUT HANDLING (`ContainerHeader.Parse`, every
    `KeyParams` parser, `PqContainer.cs`, `FileIo.cs`): the parser is the entire
    defense against a crafted file. Every malformed/oversized/truncated/adversarial
    container must fail closed — never OOM, hang, partial-write, or oracle.

CRITICAL CONTEXT — read before trusting any specific in this document.
  This repository pins its on-disk contract in `docs/FILE-FORMAT.md` (the v2
  container spec) and enforces non-negotiables in `CLAUDE.md`. For an ADVERSARIAL
  audit, treat those docs as the SPEC the code is SUPPOSED to satisfy; your job is
  to prove the CODE actually does. Where code and doc disagree, the gap is itself a
  finding.
    - File paths, class names, method names, and constants below were mapped from
      the live tree and are believed accurate, but CONFIRM each symbol against
      current source as your first step; correct this prompt where it has drifted.
    - The cryptographic CONTRACT is pinned in the docs and the KAT tests:
      AES-256-GCM (128-bit tag), PBKDF2-HMAC-SHA256 (OWASP 600k default), Argon2id
      RFC 9106, ML-KEM-768 (FIPS 203), X25519 (RFC 7748), HKDF-SHA256, and the
      X25519+ML-KEM-768 hybrid combiner (`docs/HYBRID-COMBINER.md`). Treat these as
      the spec to test the implementation AGAINST, not as proof it is correct.

ESTABLISHED CONTRACT (pinned in CLAUDE.md / FILE-FORMAT.md / KNOWN-GAPS.md — verify the code honors it):
  C1. No homegrown cryptography. Only `System.Security.Cryptography` (plus Konscious
      for Argon2id and BouncyCastle for the Hybrid ML-KEM/X25519 where .NET lacks
      them on a target). KEM-DEM and password-hashing are composed in STANDARD
      patterns only. Any invented primitive/construction is a finding.
  C2. Authenticated encryption only — fail closed. No unauthenticated path; no
      partial-success path; no error oracle. Every auth failure must look identical
      to the caller (`PqDecryptionException`, same message for wrong-key vs altered
      vs truncated).
  C3. `.pqfe` v2 is FROZEN for all of 1.x. `ContainerFormat.FormatVersion = 2`. A
      layout change requires a version bump AND a `docs/FILE-FORMAT.md` update in the
      same change.
  C4. Nonce uniqueness per content key. A fresh random 4-byte prefix per file
      (`ContainerHeader.Create`) + an 8-byte monotonic counter that cannot wrap
      within a file. A FRESH content key is drawn per file on the passphrase/recipient
      paths. Reuse of (key, nonce) under AES-GCM is catastrophic.
  C5. Full-header AAD binding. The entire serialized header is bound into every
      chunk's AAD, so any header mutation surfaces as an auth failure on the first
      frame — defeating reorder, splice, truncation, and header tamper.
  C6. Bounded cost from untrusted headers. Chunk size (1 KiB..16 MiB), salt length,
      PBKDF2 iterations (100k..100M), and Argon2id memory/iterations/parallelism
      (8 MiB..2 GiB / 1..10,000 / ≥1) are range-checked on decrypt BEFORE any work,
      so a hostile file fails closed instead of exhausting memory/CPU.
  C7. Best-effort zeroization. Content keys, KEKs, shared secrets, and passphrase
      copies are zeroed in `finally` with `CryptographicOperations.ZeroMemory`.
      Managed `byte[]` is best-effort; BouncyCastle/Konscious keep internal copies
      that cannot be reached — this residual is DOCUMENTED, not a leak.
  C8. Hybrid means BOTH arms. `HybridKeyEstablishment.DeriveKek` combines
      ss_pq ‖ ss_classical (fixed order) via HKDF. The content key must stay
      protected if EITHER primitive is later broken. A combiner that binds only one
      arm is a silent downgrade.
  C9. Self-contained codec today. `IPqContainerCodec` is a delegation seam for a
      future `PostQuantum.FileFormat` backend; the in-repo `SelfContainedContainerCodec`
      is the only implementation. Report seam gaps only where they break a guarantee now.

USER CONSTRAINT: do NOT treat a key/secret present in a test fixture, KAT vector, or
  a deterministic-conformance override (`saltOverride` / `noncePrefixOverride`) as a
  finding — these are expected and the overrides are test-only. CONFIRM they are
  unreachable from production paths, then move on. Focus on logic, construction
  correctness, nonce/IV discipline, decrypt-side bounds, fail-closed behavior,
  parser robustness, key custody/zeroization, format confusion, and supply-chain
  integrity.

================================================================================
1. OPERATING RULES
================================================================================

Rule 1 — Confirm from source before testing. The first deliverable is an Attack
  Surface Map built from the live tree, correcting every name/constant/method in
  this prompt that has drifted.
Rule 2 — Classify each finding: Static / Runtime / Partial / Architectural.
Rule 3 — No invented findings. If a control's proof is not in the code, say so. Do
  not import a doc claim as a code fact — the doc is the spec, the code is the evidence.
Rule 4 — Show evidence: exact file/class/method/constant/test-name.
Rule 5 — Escalate realistically: ≥3 variants per attack class (direct, boundary,
  evasive — e.g. for a container: tampered tag, truncated mid-frame, flipped
  frame-type, oversized declared length, out-of-range KDF cost).
Rule 6 — Distinguish Code Defect / Crypto-Construction Defect / Format-Parsing
  Defect / Key-Custody Defect / Supply-Chain-Infra Risk.
Rule 7 — Prefer chains: nonce reuse → forgery+recovery; combiner arm-drop → silent
  downgrade; tamper accepted → plaintext on a forged container; hostile header →
  resource exhaustion; format confusion → wrong-path decrypt; secret-in-log →
  offline key/passphrase exposure.
Rule 8 — Concern-boundary discipline: a control may live in the AEAD core, in key
  establishment, or in the parser. For each guarantee, identify WHICH code enforces
  it and whether a crafted INPUT FILE (it can lie about every length, parameter, and
  marker) is still contained. "The encrypt side does it right" is not a defense
  against a hand-crafted container fed to the decrypt side.
Rule 9 — Respect the mission but audit the claims: the library markets itself as a
  fail-closed, post-quantum, authenticated-only encryptor. For each path, verify the
  claimed property actually holds in code; a path that under-delivers vs
  `SECURITY.md` / `docs/FILE-FORMAT.md` is a finding.

================================================================================
2. PRE-AUDIT DELIVERABLE — ATTACK SURFACE MAP (build from live source)
================================================================================

Enumerate and CONFIRM each from source:
  - AEAD core: `Internal/PqContainerEngine.cs` (`EncryptCoreAsync`,
    `DecryptCoreAsync`, `BuildNonce`, `BuildAad`, `ReadHeaderAsync`,
    `DerivePlaintextTotal`, `ReadAtMostAsync`/`ReadExactAsync`) and
    `Internal/ContainerFormat.cs` (magic `"PQFE"`, `FormatVersion=2`,
    `AeadAes256Gcm=1`, KeySource ids 1–5, Kdf/Kem ids, `NoncePrefixLength=4`,
    `NonceLength=12`, `TagLength=16`, `KeyLength=32`, `FrameData=0`/`FrameFinal=1`,
    the fixed-offset header layout, `MaxKeyParamsLength`). Confirm the nonce/AAD
    construction and the `sawFinal` truncation guard.
  - Key establishment: `Internal/KeyEstablishment.cs` (passphrase: `BuildPassphraseAsync`
    / `DerivePassphraseKeyAsync` / `DerivePbkdf2` / `DeriveArgon2idAsync` /
    `Serialize*Params`; ML-KEM recipient: `BuildRecipient` / `UnwrapRecipientKey` /
    `SerializeRecipientParams` / `EnsureMlKemSupported`; the `KekInfo`/`WrapAad`
    labels). `Hybrid/Internal/HybridKeyEstablishment.cs` (`DeriveKek` combiner,
    `WrapToRecipient(s)` / `UnwrapFromRecipient(s)` / `TryUnwrapBlock`,
    `MaxRecipients`, the BouncyCastle private-key copy+zero discipline). External
    provider: `IContentKeyProvider.cs`, `LocalKekContentKeyProvider.cs`.
  - Format & parser: `ContainerHeader.Parse` and every `KeyParams` parser branch;
    `PqContainer.cs` orchestration (the per-KeySource `header.KeySource` mismatch
    checks; `SerializeKeyProviderParams`/`ParseKeyProviderParams`); `FileIo.cs`
    atomic temp-file write.
  - Public API & key custody: `PqFileEncryptor` / `PqFileDecryptor` (file/stream/
    `byte[]` overloads); `PqKeyPair`/`PqRecipientPublicKey`/`PqRecipientPrivateKey`;
    `PqHybridKeyPair`/`PqHybridPublicKey`/`PqHybridPrivateKey` (import/export length
    checks, `Dispose` zeroization); `PqEncryptionOptions.Validate()` + the Min/Max
    constants; `PqEncryptionException` hierarchy; `PqfeEventSource` telemetry.
  - DI & CLI: `PqFileEncryptionServiceCollectionExtensions`; `samples/Pqfe.Cli`
    (argument parsing, passphrase intake, stdin/stdout discipline, exit codes).
  - Supply chain: `Directory.Build.props` (deterministic build, warnings-as-errors,
    analysis level, authorship); `docs/REPRODUCIBLE-BUILDS.md`, `docs/SUPPLY-CHAIN.md`;
    `.github/workflows/` (build/test/pack/KAT/fuzz gates and the NuGet publish path);
    pinned Konscious + BouncyCastle versions.
  - Test corpus to reconcile findings against: `tests/` — `RoundTripTests`,
    `KdfTests`, `RecipientTests`, `HybridTests`, `KnownAnswerVectorTests`,
    `DeterministicVectorTests`, `CrossImplementationTests`, `FuzzTests`,
    `NoOracleTests`, `ErrorHandlingTests`, `AtomicWriteIoFailureTests`,
    `CancellationTests`, `StreamingTests`, `PropertyTests`; plus `fuzz/` and `oss-fuzz/`.

================================================================================
3. SECTION — AEAD CONTAINER CORE  (the integrity & confidentiality root)
================================================================================

3.1 Nonce construction & uniqueness (`PqContainerEngine.BuildNonce`, `ContainerHeader.Create`)
  T3.1.1 Per-file prefix freshness: confirm a fresh 4-byte random `NoncePrefix` is
    drawn per file and that `noncePrefixOverride` is reachable ONLY from deterministic
    tests, never a production/public path. Trace every caller of `Create`.
  T3.1.2 Counter-space safety: nonce = prefix(4) ‖ counter(8 BE). Prove the 64-bit
    counter cannot wrap within one file given the 1 KiB..16 MiB chunk bounds. State
    the math.
  T3.1.3 Shared-key reuse: confirm NO mode encrypts two files (or two per-recipient
    wraps) under the same content key while drawing independent prefixes or reusing a
    prefix. Check the key-provider path and any "encrypt many under one key"
    ergonomics. (key, nonce) reuse under AES-GCM is Critical.

3.2 AAD binding & frame state machine (`BuildAad`, `DecryptCoreAsync`)
  T3.2.1 Full-header binding (C5): confirm `BuildAad` includes the ENTIRE
    `HeaderBytes`. Tamper one byte of each header field (version, key-source, chunk
    size, nonce prefix, KeyParams) and confirm the first frame's tag rejects it.
  T3.2.2 Frame-type authentication: `frameType` is the AAD's last byte. Flip
    FrameFinal↔FrameData on the wire; confirm rejection. Drop the final frame;
    confirm the `sawFinal` guard throws (not silent success).
  T3.2.3 Reorder / splice / replay: counter is in the AAD — swap two data frames,
    duplicate a frame, splice a frame from another container; confirm each fails.
  T3.2.4 No plaintext before authentication: statically confirm `DecryptCoreAsync`
    writes to `destination` only AFTER `aes.Decrypt` returns. Confirm a multi-frame
    container failing on a late frame leaves NO observable partial plaintext at the
    destination, and that file output goes through `FileIo.WriteViaTempAsync` so a
    mid-stream failure leaves no destination file. (The fail-closed crux.)
  T3.2.5 Declared frame length: confirm `length > header.ChunkSize` is rejected
    BEFORE the `ReadExact` into the ciphertext buffer, so a hostile length can't
    drive an over-read or oversized allocation.

3.3 AES-GCM usage (`AesGcm`, `TagLength=16`, `KeyLength=32`)
  T3.3.1 Tag length pinned: confirm every `new AesGcm(key, ContainerFormat.TagLength)`
    uses the full 16-byte tag — core, recipient wrap, hybrid wrap, local-KEK wrap.
    No truncated tags anywhere.
  T3.3.2 Key length pinned: confirm the content key is always exactly 32 bytes on
    every path.
  T3.3.3 Fail-closed + no oracle: tamper ciphertext/tag/nonce-relevant header bytes;
    confirm `AuthenticationTagMismatchException` is caught and re-thrown as a generic
    `PqDecryptionException` with NO plaintext and an IDENTICAL message for wrong-key
    vs altered vs truncated. Cross-reference `NoOracleTests`.

3.4 Telemetry & progress (`PqfeEventSource`, `PqContainer.InstrumentedAsync`, `DerivePlaintextTotal`)
  T3.4.1 No secret in telemetry: confirm EventSource events carry only operation
    name, key-source label, byte counts, timing, and an exception TYPE name
    (`ex.GetType().Name`) — never a passphrase, key, plaintext, salt, or path.
  T3.4.2 Progress math on hostile length: confirm `DerivePlaintextTotal` over an
    attacker-controlled container length cannot drive allocation or an OOB index
    (it only feeds `IProgress` — verify nothing else consumes it) and returns `null`
    on overflow/negative cases.

================================================================================
4. SECTION — KEY ESTABLISHMENT  (the four paths to the content key)
================================================================================

4.1 Passphrase KDF (`KeyEstablishment`, `PqEncryptionOptions`)
  T4.1.1 Encrypt/decrypt/KAT parity: the three KDF paths must agree across
    `Serialize*Params`, `DerivePassphraseKeyAsync`, and the known-answer vectors.
    Cross-check `KnownAnswerVectorTests` / `DeterministicVectorTests`.
  T4.1.2 Decrypt-side cost bounds (C6): confirm iterations/memory/parallelism/salt
    read from the UNTRUSTED header are range-checked BEFORE derivation. A header
    declaring Argon2id at 2 GiB × 10,000 must be rejected as `PqFormatException`.
    Assess whether even the accepted upper bound (2 GiB) is an OOM risk worth a
    tighter decrypt-time cap.
  T4.1.3 Salt handling: fresh random salt per file; faithfully serialized/re-read;
    never reused as an HKDF salt or any other domain input; `saltOverride` test-only.
  T4.1.4 Passphrase buffer hygiene: `DeriveArgon2idAsync` copies the passphrase to a
    `byte[]` and zeroes it in `finally`; the engine zeroes the content key in
    `finally`. Confirm the passphrase/key never reach a log, exception, or disk.

4.2 ML-KEM recipient path (`BuildRecipient` / `UnwrapRecipientKey`)
  T4.2.1 KEM-DEM construction: encapsulate → HKDF-SHA256(info=`KekInfo`) →
    AES-256-GCM wrap of a random 32-byte CEK with `WrapAad`. Confirm shared secret
    and KEK zeroed in `finally`; confirm the labels domain-separate this from the
    passphrase and hybrid paths.
  T4.2.2 Recipient key validation: confirm `MLKem.ImportEncapsulationKey` validates
    the attacker-influenceable encapsulation key (length/well-formedness) so a
    malformed recipient key fails closed.
  T4.2.3 Implicit rejection / no oracle: a malformed KEM ciphertext yields a
    pseudo-random secret → wrong KEK → GCM tag mismatch → generic
    `PqDecryptionException`. Confirm the exact-length checks
    (`c != KemSizes.MlKem768Ciphertext`, `p.Length != expected`) reject size games
    BEFORE decapsulation, and no error distinguishes the failure modes.
  T4.2.4 Platform fail-closed: `EnsureMlKemSupported` throws when `!MLKem.IsSupported`.
    Confirm NO weak fallback and NO "encryption disabled" path.

4.3 Hybrid combiner (`HybridKeyEstablishment`)
  T4.3.1 Both arms bind (C8, downgrade resistance): `DeriveKek` IKM = ss_pq ‖
    ss_classical, fixed order, HKDF-SHA256, label `KekInfo`. Confirm both secrets are
    present and ordered. State explicitly whether breaking ONLY ML-KEM or ONLY X25519
    still protects the CEK. Cross-check `docs/HYBRID-COMBINER.md`.
  T4.3.2 Ephemeral X25519 freshness: confirm `WrapToRecipient` generates a fresh
    ephemeral keypair per recipient per wrap (not cached/reused).
  T4.3.3 Multi-recipient & trial-unwrap bound (KeySource 4): `WrapToRecipients`
    produces a distinct block per recipient; `UnwrapFromRecipients` trial-unwraps
    until one matches. Confirm: count ≥ 1; each block's declared length is bounds-
    checked against the body before slicing; `MaxRecipients` enforced on write; a
    hostile count cannot drive unbounded work (truncation throws). Quantify worst-case.
  T4.3.4 BouncyCastle key-copy zeroization (C7): confirm `TryUnwrapBlock` zeroes the
    ML-KEM and X25519 private-key copies in `finally`, and that the documented
    residual (BouncyCastle internal copies) matches `KNOWN-GAPS.md`/`CLAUDE.md`.
  T4.3.5 Core-vs-Hybrid divergence: core uses `"…/v2 …"` labels +
    `System.Security.Cryptography.MLKem`; hybrid uses `"…/v3 …"` labels +
    BouncyCastle. Confirm KEM ciphertext (1088) / encapsulation-key (1184) /
    decapsulation-key (2400) constants agree across both and the wire layout, so a
    file written by one is never silently misparsed by the other. Cross-reference
    `CrossImplementationTests`.

4.4 External key provider (`IContentKeyProvider`, `LocalKekContentKeyProvider`)
  T4.4.1 Provider-id binding: `DecryptKeyProviderAsync` checks the container's
    provider-id (ordinal) against the supplied provider; id length-bounded 1..255 on
    serialize and parse; mismatch fails closed with a non-secret error.
  T4.4.2 Local-KEK wrap soundness: AES-256-GCM CEK wrap, `wrapInfo =
    Nonce(12)‖Tag(16)‖Wrapped(32)`, fresh random nonce per `WrapNewKeyAsync`, exact
    `WrapInfoLength` check on unwrap, tag-mismatch → `PqDecryptionException` with the
    CEK zeroed first, `Dispose` zeroing the KEK.
  T4.4.3 KEK custody: `Generate()` zeroes its intermediate copy; `ExportKek` returns
    a clone documented as a secret; the provider never logs the KEK. Note: a custom
    `IContentKeyProvider` is a trust boundary — its `UnwrapKeyAsync` MUST fail closed;
    document the contract risk.

================================================================================
5. SECTION — FORMAT & HOSTILE-INPUT HANDLING  (the file is the adversary)
================================================================================

T5.1 Header well-formedness gauntlet (`ContainerHeader.Parse`): bad magic;
  FormatVersion 1 and 3; unknown AEAD id; unknown KeySource (0/6/255); chunk size
  below min / above max; declared KeyParams length ≠ actual. Each must throw
  `PqFormatException` before reaching key establishment or allocating on the bad value.
T5.2 Truncation gauntlet (`ReadHeaderAsync`, `DecryptCoreAsync`): truncate at 0
  bytes; mid fixed-header (<18); mid-KeyParams; after header, no frames;
  mid-frame-header; mid-ciphertext; mid-tag; exactly after the last DATA frame but
  before FINAL. Each fails closed, never hangs, never emits plaintext, leaves no
  destination file.
T5.3 KeyParams parser fuzzing (per KeySource): passphrase (salt<min; PBKDF2/Argon2id
  truncated; out-of-range costs; unknown KDF id); ML-KEM recipient (`p.Length<3`;
  wrong `p[0]`; wrong `c`; `p.Length≠expected`; off-by-one per field); hybrid
  multi-recipient (count 0; count 255 w/ short body; block length overrun; unknown
  mode byte → keep trying, not crash); key-provider (id len 0; id overrun; wrapInfo
  mismatch). Reconcile with `FuzzTests`/`NoOracleTests`/`ErrorHandlingTests`; note gaps.
T5.4 Format confusion across KeySource: encrypt with passphrase, feed to the
  recipient/hybrid/key-provider decrypt entry points (every mismatched pair). Confirm
  `PqContainer` rejects via its `header.KeySource` check. Hand-craft a header claiming
  one KeySource but carrying another's body; confirm fail-closed.
T5.5 Atomic write & I/O failure (`FileIo.WriteViaTempAsync`): output written to a
  sibling `*.tmp-<guid>` and atomically moved only on full success; any exception
  deletes the temp; a decrypt failing mid-stream leaves no partial plaintext. Force
  an I/O failure (cross-reference `AtomicWriteIoFailureTests`). Flag any window where
  the temp (plaintext on decrypt) is world-readable or left on a hard crash (document).
T5.6 Oversized / boundary allocations: max chunk (16 MiB) × the fixed engine buffers
  is the worst-case peak; confirm it is bounded and independent of the declared file
  size, and that no path pre-allocates on an attacker-declared length before
  validating it against the chunk-size bound.

================================================================================
6. SECTION — PUBLIC API & KEY CUSTODY
================================================================================

T6.1 Surface minimality & safe defaults: public surface matches `CLAUDE.md`; a
  caller passing no options gets a secure result (`PqEncryptionOptions.Default`);
  `Validate()` fail-fasts on bad options before any work.
T6.2 Key type import/export bounds: `PqHybridPublicKey.Import`=1216,
  `PqHybridPrivateKey.Import`=2432, core `PqRecipient*` own length checks; `Export`
  round-trips; private-key `Dispose` zeroes.
T6.3 Cancellation honored: every async path calls `ThrowIfCancellationRequested`; a
  cancelled encrypt leaves no destination file; a cancelled decrypt emits no partial
  plaintext. Cross-reference `CancellationTests`.
T6.4 Exception message hygiene: grep every `throw new Pq*Exception(...)`; no message
  embeds a passphrase/key/plaintext/salt/full path; wrong-key/altered/truncated share
  one generic decrypt message.
T6.5 DI surface (`PqFileEncryptionServiceCollectionExtensions`): no key material
  captured in a singleton; no process-wide-KEK provider registered by default; sane
  lifetimes. Cross-reference `DependencyInjectionTests`.
T6.6 CLI tool (`Pqfe.Cli`): passphrase intake does not echo and is not silently taken
  from `argv` (flag any `--password` affordance as info-disclosure and confirm it is
  documented); ciphertext/plaintext written atomically to a non-predictable temp;
  non-zero exit on failure; no key material or secret-bearing stack trace printed.

================================================================================
7. SECTION — SUPPLY CHAIN, BUILD & DEPENDENCIES
================================================================================

T7.1 Dependency pinning & provenance: Konscious (Argon2id) and BouncyCastle (Hybrid)
  versions pinned; KATs validate against the REFERENCED versions so a silent minor
  bump that changes behavior is caught.
T7.2 Reproducible build integrity: `Directory.Build.props` sets deterministic build +
  warnings-as-errors + analysis level; published packages carry the provenance
  attestation. Per project posture: the workflow ships from Linux; NEVER hand-pack on
  Windows (CRLF breaks reproducibility against the Linux attestation). Confirm the
  release workflow is the only sanctioned pack path.
T7.3 Analyzer-enforced API lock: the four packages move in lockstep; an accidental
  public-surface change fails the build, not ships silently.
T7.4 CI gate coverage: confirm CI runs build (warnings-as-errors), the full test
  suite, the KAT/deterministic vectors, and the fuzz target. Flag any security-relevant
  test class NOT wired into a required gate.

================================================================================
8. SECTION — DENIAL OF SERVICE & RESOURCE BOUNDS
================================================================================

T8.1 Argon2id cost from a hostile header (mirror T4.1.2): decrypt accepts up to 2 GiB
  × 10,000. Assess whether opening someone else's file should demand that; recommend a
  caller-overridable decrypt-time ceiling if absent.
T8.2 Chunk-size & buffer bounds: 16 MiB max chunk × the fixed buffer count is the
  worst-case peak, independent of declared file size; no `new byte[declaredLength]`
  before validation.
T8.3 Multi-recipient trial-unwrap cost: KeySource-4 forces up to `count` decapsulations.
  Confirm count and per-block lengths are bounded by the body so a small hostile file
  can't demand thousands of decapsulations. Quantify.
T8.4 Streaming memory ceiling: the engine is constant-memory in file size; confirm the
  `byte[]` API overloads don't defeat that by materializing an unbounded buffer without
  a documented limit.

================================================================================
9. SECTION — DOC vs CODE DRIFT  (the inverted-trust audit)
================================================================================

T9.1 File-format parity (`docs/FILE-FORMAT.md`): the documented v2 layout (offsets,
  field widths, KeySource/KDF/KEM ids, frame structure, AAD composition) must match
  `ContainerFormat.cs` + `PqContainerEngine` + every `KeyParams` (de)serializer
  exactly. Any drift is a finding.
T9.2 `SECURITY.md` "does NOT defend against" accuracy: each claimed non-defense still
  accurate; no new limitation appeared in code without a doc update; no doc over-claims
  a property the code lacks.
T9.3 `KNOWN-GAPS.md` honesty: each documented gap (self-contained codec seam,
  best-effort managed-buffer zeroization, BouncyCastle internal key copies) matches
  code; none is silently half-fixed; no undocumented gap belongs on the list.
T9.4 CLAUDE.md non-negotiables (C1–C9): verify in code — no homegrown crypto;
  authenticated-only; fail-closed; FormatVersion bumped iff layout changed; key
  material zeroed in `finally`. A contradiction is a finding regardless of exploitability.

================================================================================
10. CHAINED ATTACK SCENARIOS  (fail-closed collapse as the high-value target)
================================================================================

Chain A — Nonce reuse under a shared key: two files/wraps share a content key with
  independent (or reused) 4-byte prefixes → (key,nonce) repeats under AES-GCM → tag
  forgery + plaintext recovery, no key compromise. First break: §3.1.1 / §3.1.3.
Chain B — Combiner arm-drop: `DeriveKek` (hybrid) or the core KEM-DEM binds only one
  secret / mis-orders / wrong label → breaking the un-bound primitive recovers the CEK
  → the "hybrid"/PQ guarantee is a lie. First break: §4.3.1 / §4.2.1.
Chain C — Tamper accepted: a header/frame mutation isn't bound into the AAD, or
  `AesGcm.Decrypt` output is consumed before the tag check, or `sawFinal` is bypassable
  → attacker-controlled plaintext emitted as authentic, or a truncated file "succeeds".
  First break: §3.2.1 / §3.2.4 / §3.2.2.
Chain D — Hostile header → resource exhaustion: a container declares Argon2id at the
  max bound or a KeySource-4 with many blocks, and decrypt runs it before/despite
  bounds → client OOM/CPU exhaustion. First break: §4.1.2 / §8.1 / §8.3.
Chain E — Format confusion: a crafted KeySource byte routes a body to the wrong unwrap,
  or one package's container is misparsed by the other → undefined behavior / bound
  bypass. First break: §5.4 / §4.3.5.
Chain F — Partial-plaintext leak: a multi-frame container fails on a late frame but
  earlier frames are observable at the destination (atomic-move bypassed, or `byte[]`
  API returns partial) → attacker learns plaintext prefixes of "failed" files. First
  break: §3.2.4 / §5.5.
Chain G — Secret in a log/exception: a passphrase/key/salt/plaintext reaches
  `PqfeEventSource`, an exception message, the CLI's stderr, or a left-behind temp →
  anyone with log/console/disk access recovers material to decrypt. First break:
  §3.4.1 / §6.4 / §6.6 / §5.5.
Chain H — Supply-chain drift: an unpinned Konscious/BouncyCastle bump changes
  Argon2id/ML-KEM behavior, or a Windows hand-pack breaks reproducibility, and no
  KAT/gate catches it → interop breaks or the KDF weakens silently. First break:
  §7.1 / §7.2 / §7.4.

================================================================================
11. SEVERITY RUBRIC
================================================================================

Critical — plaintext emitted on a tampered/forged/truncated container; AES-GCM nonce
  reuse under one key; a hybrid/KEM-DEM combiner defect enabling a silent downgrade
  (one broken primitive recovers the CEK); a content key/passphrase/KEK written to
  disk/log in cleartext; any path that decrypts without verifying the AEAD tag.
High — hostile-header resource exhaustion (Argon2id/multi-recipient) bypassing or
  within over-loose bounds; observable partial-plaintext on mid-stream failure;
  format-confusion routing a body to the wrong unwrap or a cross-package misparse;
  missing fail-closed on a truncation/tamper variant; a secret in an exception or CLI
  output.
Medium — a KeyParams/header parser that indexes out of bounds or allocates on an
  unvalidated length (without reaching plaintext); a doc-vs-code format drift; an
  over-loose default cost cap; a CLI passphrase-on-argv affordance; a missing required
  CI gate for a security test.
Low — best-effort managed-buffer zeroization gaps matching the documented posture;
  non-constant-time comparison on a non-secret path; a left-behind temp only on hard
  crash; missing telemetry/audit line; weak hardening that doesn't itself break a
  guarantee.

================================================================================
12. REQUIRED OUTPUT FORMAT (per finding)
================================================================================

Finding ID:       PQFE-###
Evidence Type:    Static / Runtime / Partial / Architectural
Defect Type:      Code / Crypto-Construction / Format-Parsing / Key-Custody / Supply-Chain-Infra
Concern:          AEAD Core / Key Establishment / Format-Parser / Public API-Key Custody / Supply Chain / Cross-Concern
Section:          [e.g. §3 — AEAD Container Core]
Severity:         Critical / High / Medium / Low
Title:            [short]
Affected File(s): [exact file:method/constant/test-name — confirmed from source]
Affected Code:    [class / method / constant / parser branch]
Attack Input:     [exact container bytes / options / call sequence]
Observed Result:  [what happened — or "Not runtime-verified"]
Expected Result:  [what should happen per docs/FILE-FORMAT.md / CLAUDE.md / spec]
Root Cause:       [code-level explanation]
Impact:           [realistic consequence — be explicit about whether confidentiality,
                   integrity, or fail-closed is broken]
Recommendation:   [specific fix]
Test Reproduced:  [Yes / No / Partial / Static-only]
Evidence Basis:   [source code-path / cross-package analysis / doc cited / KAT vector / static-only]
Spec-Drift Note:  [if this is a code-vs-doc divergence, name the doc and quote the
                   committed behavior the code violates]

================================================================================
13. FINAL DELIVERABLES
================================================================================

1. Attack Surface Map — built from live source across all three concerns; explicitly
   note every name/constant/method in this prompt that was confirmed, corrected, or
   not found.
2. Confirmed Findings — Critical → Low.
3. Partial Findings requiring runtime/fuzz/CLI verification.
4. Exploit Chains — first broken control identified, and which concern should have
   contained it.
5. Fail-Closed / AEAD Integrity Report — explicit pass/fail on: tag-before-plaintext,
   full-header AAD binding, frame-type/counter authentication, fail-closed truncation
   (`sawFinal`), no-partial-plaintext on mid-stream failure, AES-GCM nonce uniqueness
   per content key.
6. Key-Establishment Report — per path (passphrase / ML-KEM / hybrid / key-provider):
   construction correctness, decrypt-side cost bounds, domain separation, zeroization,
   fail-closed-on-malformed.
7. Format/Parser Robustness Matrix — per KeySource and per truncation/tamper class:
   fails-closed?, bounded-allocation?, no-oracle?
8. Doc Drift Report — code-vs-FILE-FORMAT/SECURITY/KNOWN-GAPS/CLAUDE divergences (§9).
9. Top 10 Remediations by risk-reduction / effort.
10. Security regression tests to add (per primitive, per parser branch, per fail-closed
    variant) — slot into the existing FuzzTests / NoOracleTests / KnownAnswerVectorTests
    / ErrorHandlingTests corpus.
11. Release Blockers — must-fix-before-next-NuGet-release only.

--------------------------------------------------------------------------------
Prepared for: PostQuantum.FileEncryption — a fail-closed, post-quantum file & stream
encryption library family for .NET 10 (PostQuantum.FileEncryption, .Hybrid,
.Extensions.DependencyInjection, Pqfe.Cli). The trust model is local: the attacker
controls the input `.pqfe` file. The security guarantee is the JOINT product of the
AEAD container core, the key-establishment paths, and the hostile-input parser.
`docs/FILE-FORMAT.md` and `CLAUDE.md` state the intended behavior; treat them as the
SPEC to test the code against, not as proof the code is correct. Confirm every
file/method/constant/layout against current source before testing — the tree evolves.
Do not substitute doc claims or this prompt's hypotheses for code evidence.

To God be the glory — 1 Corinthians 10:31
--------------------------------------------------------------------------------
