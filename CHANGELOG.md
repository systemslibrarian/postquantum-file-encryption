# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/). From `1.0.0` onward the public API surface is
locked by `Microsoft.CodeAnalysis.PublicApiAnalyzers` baselines and `<EnablePackageValidation>`,
and the `.pqfe` v2 container format is frozen for the entire `1.x` line.

## [Unreleased]

### Added

- **The documentation-consistency CI guard now actually exists.** The `1.7.0` changelog described
  a `docs-consistency` workflow running `scripts/check-docs-consistency.sh` on every push and pull
  request, but the workflow file was never committed — the guard never ran, which is how the
  version markers below drifted. `.github/workflows/docs-consistency.yml` now runs it, the script
  is portable (no GNU-only `grep -P`, so it runs on macOS too), and it additionally checks the
  SECURITY.md supported-versions cell, the ROADMAP-2.0 "Today" cell, the AUDIT-SCOPE pinned tag,
  and artifact-naming examples (`gh attestation verify` / `gh release download` /
  reproducibility-script invocations) against the current version.
- **KNOWN-GAPS.md gains five verified entries:** header-only CEK rewrap as a format-v3 candidate
  (see below), the `IContentKeyProvider` key-freshness contract and its consequences, passphrase
  Unicode normalization, non-interruptible KDF derivation, and default filesystem permissions on
  decrypted output. `IContentKeyProvider.WrapNewKeyAsync`'s docs now state why the fresh-key
  contract is load-bearing (reuse collapses AES-GCM nonce uniqueness across files).

### Changed

- **KEY-MANAGEMENT.md no longer promises header-only CEK rewrap on format v2.** The serialized
  header is bound as AAD into every content frame, so replacing the wrapped CEK forces every frame
  to be re-authenticated — and doing that under the *same* CEK and nonces would emit second GCM
  tags for existing (key, nonce) pairs while old copies of the file still exist, allowing
  authentication-key recovery. Rotation on v2 is now documented as a streaming transcode with a
  fresh CEK and nonce prefix; true header-only rewrap is banked as a format-v3 candidate.
- **Docs version sweep to `1.7.1`** across SECURITY.md (supported-versions cell), ROADMAP.md,
  KNOWN-GAPS.md and GOLD-STANDARD.md review markers, ROADMAP-2.0.md, AUDIT-SCOPE.md (pinned tag),
  README / SUPPLY-CHAIN / REPRODUCIBLE-BUILDS verification examples, and ANNOUNCE.md.
  `PackageValidationBaselineVersion` moves from `1.5.0` to `1.7.1`, and `PackageReleaseNotes`
  are reworded to be version-agnostic so they can no longer silently go stale on nuget.org.
- **SECURITY.md claims recalibrated to exactly what the code does and tests pin:** one exception
  type with byte-identical messages for key-dependent failures (structural diagnostics are
  key-independent), integrity scoped to the authenticated envelope (trailing bytes after the final
  frame are ignored — see KNOWN-GAPS.md), bounded-work noting that tight ceilings are opt-in via
  `PqDecryptionLimits.Untrusted`, Dependencies now naming the Signing package's BouncyCastle use
  and the Rust demo core's RustCrypto crates, and the SBOM list reflecting all eight per-package
  SBOMs. GOLD-STANDARD.md's binary-compatibility row now states that package validation is
  overridden off in the Aws/AzureKeyVault/Gcp/Analyzers packages.
- **Format-doc errata (doc-only; no byte or reader change):** KEY-FILE-FORMAT.md now correctly
  says a PQKF body is a KeySource-1 passphrase container whose KeyParams carry KdfId 1
  (PBKDF2-HMAC-SHA256) or 2 (Argon2id) — the previous wording conflated KeySource with KdfId —
  and FILE-FORMAT.md's KeySource-2 HKDF formulas state `salt = absent` explicitly.

## [1.7.1] — 2026-08-20

Patch: WASM sample crate upgrades. No format change, no public API change, and no change to any
shipped .NET package; a drop-in over 1.7.0.

### Changed

- **`samples/pqfe-wasm` migrated to `aes-gcm` 0.11, `ml-kem` 0.3 and `rand_core` 0.10.** These
  could not move independently: ml-kem 0.2 pins rand_core 0.6 while ml-kem 0.3 requires rand_core
  0.10. rand_core 0.10 also restructured its traits — `RngCore` is now a deprecated stub and
  `Rng`/`CryptoRng` are blanket-implemented over `TryRng`/`TryCryptoRng`.

  The interop-critical detail: in ml-kem 0.3 `DecapsulationKey::KeySize` is `U64`, so `as_bytes()`
  returns the 64-byte **seed** where 0.2 returned the 2400-byte **expanded** key. The wire format
  here is `HYBRID_PRIVATE_KEY_LEN = 2432 = 32 + 2400`, matching BouncyCastle on the .NET side, so
  the expanded encoding is now used explicitly via `to_expanded_bytes`/`from_expanded_bytes`.
  Verified with a debug-profile test run, since the length assertions are `debug_assert_eq!` and
  compiled out in release.

## [1.7.0] - 2026-08-19

Cross-implementation hybrid interop, a machine-readable conformance corpus, and developer-experience
hardening. No change to the frozen `.pqfe` v2 / `PQKF` v1 / `.sig` v1 formats, and no change to the
public API surface of any shipped package — every existing container, key file and signature reads
and writes exactly as it did under `1.6.0`.

### Changed

- **The ASP.NET Core web-upload quickstart now keeps its advertised security boundary at
  runtime, not just in prose.** It requires a recipient public key at startup and never
  generates or stores a private key on the server; it streams each upload with `MultipartReader`
  straight into the encryptor (so a large upload is never spooled to a temporary plaintext file
  by buffered `IFormFile` handling); and it stages ciphertext to a `.partial` file, publishing
  it atomically only when complete and deleting the staged file on every failure path. The
  sample is now built with the misuse `Analyzers` referenced, holding it to the rules consumers
  are told to adopt.
- **Documentation reconciled to the shipped `1.6.0`.** `ROADMAP.md`, `docs/GOLD-STANDARD.md`,
  `KNOWN-GAPS.md`, `docs/DEPLOYMENT.md`, and `docs/COMPARISON.md` no longer carry stale
  pre-`1.0`/`1.2.0`/`1.5.0` version and status markers, and the roadmap now reflects the shipped
  cloud-KMS trio and nine-package family.
- **`docs/CONFORMANCE.md` reader obligations split** into strict reader requirements and a
  documented *frozen v2 reference-reader compatibility profile*. The strict rules no longer
  claim the reader rejects a nonzero reserved `Flags` byte (the frozen v2 reader deliberately
  accepts it, as a format-v3 candidate in `KNOWN-GAPS.md`), and the all-or-nothing wording now
  distinguishes the atomic file APIs from stream APIs. No reader behavior changed.

### Added

- **`Pqfe.QuickStart.WebUpload.Keygen`** — a small offline tool that generates a hybrid
  recipient key pair on a trusted machine, writing the public key and a passphrase-encrypted
  `PQKF` private key, so the web sample's identity is provisioned off-server.
- **`Pqfe.QuickStart.WebUpload.Tests`** — an integration test that uploads a payload above the
  form-buffer threshold and proves the stored bytes are a real `.pqfe` container only the
  private key opens, that a stranger key fails closed, and that a file-less request is rejected
  with nothing written.
- **A machine-readable conformance-vector corpus** at `test-vectors/manifest.json`, pinning
  every vector by SHA-256 with the outcome a conforming reader must produce. Alongside the
  existing positive KATs it commits ~11 **negative** vectors (deterministic mutations of Vector
  1: bad magic/version, unknown AEAD/key-source, out-of-range chunk size and PBKDF2 iterations,
  header/ciphertext tamper, tag/prefix truncation, wrong passphrase) and four **lenient**
  vectors that pin the frozen v2 reader corners from CONFORMANCE.md §2.2 (nonzero reserved
  `Flags`, trailing `KeyParams` bytes, trailing bytes after the final frame, and a block past a
  multi-recipient count). Both implementations run the identical corpus — .NET
  `ConformanceManifestTests` and the Rust core's `tests/conformance.rs` — so an outside
  implementer can prove conformance against the same artifacts. No format change; the frozen
  positive vectors are byte-identical.
- **Continuous documentation-consistency guard** (`scripts/check-docs-consistency.sh`, run by
  the `docs-consistency` workflow on every push and PR): fails if a current-version marker
  (README **Status:**, the ROADMAP "Now" heading, any "Last reviewed against" line) lags the
  core package `<Version>`, or if any relative Markdown link points at a file that does not
  exist. This is the continuous counterpart to the release-time version check, closing the gap
  that let the docs drift between releases.

### Dependencies

- **Shipped-package dependency floors raised.** `BouncyCastle.Cryptography` 2.6.2 → 2.7.0
  (`.Hybrid`), `AWSSDK.KeyManagementService` 4.0.12.9 → 4.0.100.8 (`.Aws`), `Google.Cloud.Kms.V1`
  3.25.0 → 3.26.0 (`.Gcp`), and `Microsoft.Extensions.DependencyInjection.Abstractions`
  10.0.9 → 10.0.11 (`.Extensions.DependencyInjection`). Every one stays inside its current major,
  and each new version still carries `netstandard2.0` and `net8.0` assets, so the `net8.0;net10.0`
  plus `netstandard2.0` target set is unchanged and no consumer is forced across a major boundary.
  No security advisory applies to any of these — the BouncyCastle advisories are all bounded at
  `< 2.3.1`, well below the version already shipped in `1.6.0`.
- **Test and CI toolchain updated** — `Microsoft.NET.Test.Sdk` 18.9.0, `xunit.runner.visualstudio`
  4.0.0, `CsCheck` 4.8.0, `Microsoft.Extensions.DependencyInjection` 10.0.11 (test host), plus
  `actions/setup-dotnet` 6.0.0, `actions/checkout` 7.0.1, `ossf/scorecard-action` 2.4.4,
  `github/codeql-action/upload-sarif` 4.37.6 and `actions/attest-build-provenance` 4.2.2. None of
  these reach a published package.

## [1.6.0] - 2026-07-10

The cloud-provider, security-hardening, and developer-experience release. A Google Cloud KMS
envelope-key provider completes the AWS / Azure / GCP trio; an adversarial multi-zone review
of the engine fixed eight fail-closed-contract bugs; and native CLI binaries, differential
round-trip coverage, committed test vectors, and a crypto-agility guide round out the tooling.
No change to the frozen `.pqfe` v2 / `PQKF` v1 / `.sig` v1 formats.

### Added

- **`PostQuantum.FileEncryption.Gcp`** — a Google Cloud KMS envelope-key provider,
  completing the AWS KMS / Azure Key Vault / Google Cloud KMS trio over the
  `IContentKeyProvider` seam. `GcpKmsContentKeyProvider` generates the per-file content key
  locally (Cloud KMS has no server-side data-key generation — the same envelope pattern as
  the Azure provider and Google's Tink), wraps it with Cloud KMS `Encrypt` bound to
  library-specific additional authenticated data plus optional caller bytes, and unwraps
  against only the configured `CryptoKey` — a tampered, foreign-key, or AAD-mismatched blob
  fails closed with `PqDecryptionException`, indistinguishable from tampering, while
  operational failures propagate as the SDK's own exceptions. The CRC32C integrity fields
  Cloud KMS offers are populated on every request and verified on every response (the .NET
  SDK does not do this itself), pinned by the RFC 3720 check value in tests. Unit-tested
  against an in-process fake reproducing the service's binding and `INVALID_ARGUMENT`
  semantics, like its AWS and Azure siblings. No change to the `.pqfe` v2 container format,
  which remains **FROZEN** for the `1.x` line.

- **Standalone native `pqfe` CLI binaries** are attached to every release for `linux-x64`,
  `win-x64`, and `osx-arm64` — single-file, no .NET runtime required, each with a SHA-256 sum
  and a SLSA-style build-provenance attestation. Built natively per target (AOT does not
  cross-compile) in the release pipeline.
- **Differential round-trip coverage for the Rust core.** A new property test sweeps the
  framing matrix (chunk sizes × data lengths straddling one, two, and three chunks, plus
  per-byte tamper and truncation-at-every-length), catching any encode/decode asymmetry the
  fixed known-answer vectors cannot. The cross-implementation CI harness now also randomizes
  payload sizes each run, so the .NET ↔ Rust agreement is exercised at new points continuously
  rather than at six fixed sizes.

### Fixed

- **Encrypted key files (`PQKF`) now validate options and limits at the boundary.**
  `ExportEncrypted` validates the KDF options before writing, so an out-of-range option (for
  example a salt size or Argon2id parallelism that overflows its single on-disk byte) fails
  fast with `ArgumentOutOfRangeException` instead of silently producing a key file that even
  the correct passphrase could never open. `ImportEncrypted` likewise validates caller-supplied
  `PqDecryptionLimits`, so a below-minimum limit surfaces as the configuration error it is
  rather than as a hostile-file-shaped `PqFormatException`.
- **Exception-contract consistency on recipient key establishment.** A corrupt ML-KEM-768
  recipient key (the public half on encrypt, the private half on decrypt — both validated only
  for length on import) now fails closed inside the library's exception hierarchy
  (`PqEncryptionException` / `PqDecryptionException`) instead of leaking a raw platform or
  BouncyCastle exception, matching the treatment the mirror paths already had.
- **Detached-signature verification validates the sidecar before hashing the content**, per the
  ordering `docs/SIGNATURE-FORMAT.md` mandates, so a structurally invalid signature is rejected
  without a full SHA-512 pass over a large input. The two signature components are now evaluated
  in independent guarded steps, so an unexpected throw from one half can never skip the other —
  both always run and either failing yields the same single generic error.
- **Cancellation is honored immediately before the password KDF.** A token cancelled between
  header parsing and key derivation no longer pays the full (potentially gibibyte-scale)
  Argon2id/PBKDF2 cost first. The KDF itself remains non-interruptible once started (a library
  limitation of the underlying primitives), now noted in `KNOWN-GAPS.md`.
- **`LocalKekContentKeyProvider`** reports a structurally malformed wrapped key as
  `PqFormatException`, aligning with every other parser and keeping `PqDecryptionException`
  reserved for a single generic authentication-failure message.
- **`pqfe encrypt` / `pqfe decrypt` refuse to overwrite an existing output** unless `--force`
  is given (exit code 73), matching `keygen`'s existing "a file silently replaced is a file
  lost" guard.
- **Documentation of frozen-format reader leniencies corrected.** `KNOWN-GAPS.md` now records
  the KeySource-4 (multi-recipient) body's tolerance of trailing bytes and the abort-on-unknown-
  `KemId` scan behavior, the directory-fsync durability boundary, and the `DecryptAtomicAsync`
  in-memory ~2 GiB ceiling — all format-v3 candidates or documented limitations, none a `1.x`
  behavior change.

## [1.5.0] - 2026-07-02

The key-file, hardening, and developer-experience release. Private keys gain a safe at-rest
form (the `PQKF` passphrase-encrypted key file); a full-codebase security review — including
an adversarial multi-angle self-review and a mutation-testing pass — tightened behavior at
the edges; and a new Roslyn analyzers package, cookbook, anti-patterns guide, and compliance
mapping put the library's fail-closed discipline in front of developers. No change to the
existing formats — `.pqfe` v2 and the `.sig` v1 sidecar are byte-identical.

### Added

- **`PostQuantum.FileEncryption.Analyzers`** — a new lockstep package of Roslyn analyzers
  that catch dangerous misuse at compile time, in the IDE: `PQFE101` (a compile-time-constant
  passphrase), `PQFE102` (raw private-key bytes written to disk instead of a
  passphrase-protected key file), `PQFE103` (a discarded encrypt/decrypt/sign/verify task —
  fires in synchronous methods, where the compiler's CS4014 does not), and `PQFE104` (a
  silently swallowed fail-closed exception; probing with `PqFormatException` stays
  legitimate and unflagged). Development-only dependency; each rule links to its
  [docs/ANTI-PATTERNS.md](docs/ANTI-PATTERNS.md) entry, and each ships with flagged-shape
  *and* clean-shape tests so a rule can neither go silent nor turn noisy unnoticed.
- **Developer documentation set** — [docs/COOKBOOK.md](docs/COOKBOOK.md) (complete,
  copy-paste-runnable recipes with the failure handling done right),
  [docs/ANTI-PATTERNS.md](docs/ANTI-PATTERNS.md) (wrong code → why → right code, covering
  both the analyzer-enforced shapes and the ones only a human can catch), and
  [docs/COMPLIANCE.md](docs/COMPLIANCE.md) (an honest mapping to OMB M-23-02, CNSA 2.0,
  FIPS 203/204, FIPS 140-3, and 800-171 — including, stated plainly, what is *not* claimed).
- **Quickstart samples** (`samples/quickstarts/`) — the smallest complete programs for the
  two most common jobs: folder backup encryption (console) and encrypted uploads (ASP.NET
  Core, where the web server holds only the public key and can read nothing it stores).
  Both build in CI.
- **Passphrase-encrypted key files** — `PqHybridPrivateKey` and `PqSigningPrivateKey` gain
  `ExportEncrypted(passphrase, options?)` / `ImportEncrypted(keyFile, passphrase)`, so private
  keys have a safe at-rest form out of the box instead of every application inventing its own
  storage for raw `Export()` bytes. The new `PQKF` v1 file
  ([docs/KEY-FILE-FORMAT.md](docs/KEY-FILE-FORMAT.md)) is a five-byte framing around a
  standard `.pqfe` v2 passphrase container — **no new cryptography**; confidentiality,
  authenticity, and fail-closed behavior are inherited from the container engine, with
  Argon2id as the default KDF (key files are tiny and long-lived, so the KDF is the entire
  cost of opening one). The key *type* travels inside the authenticated plaintext, so a
  signing key file cannot be passed off as a hybrid recipient key file or vice versa. The CLI
  gains `pqfe keygen --encrypt` (with `--passphrase-env` for scripting), and `pqfe sign`
  detects an encrypted key file by its magic and prompts for the passphrase.
  `ImportEncrypted` takes an optional `PqDecryptionLimits` — the same pre-authentication
  gate the container decryptors have — so a hostile key file cannot demand gibibytes of
  Argon2id memory before anything authenticates, and a new `IsEncryptedKeyFile` predicate
  lets consumers route between the raw and encrypted forms without duplicating format
  knowledge. The import/export plumbing drives the container engine directly over buffers it
  owns, so every intermediate copy of the key-bearing plaintext is zeroed. A pinned
  known-answer vector ([docs/TEST-VECTORS.md](docs/TEST-VECTORS.md), Vector 5) locks the
  framing and the type binding.
- **Three new pinned known-answer vectors** ([docs/TEST-VECTORS.md](docs/TEST-VECTORS.md)):
  Vector 6 pins hybrid recipient decryption byte-exactly — the KeySource-3 wrap block, the
  X25519 + ML-KEM-768 agreement, the HKDF combiner, and the AES-256-GCM key unwrap — closing
  the one format path no fixed vector previously covered. Vector 7 is the first *multi-chunk*
  vector, pinning the per-chunk nonce counter and AAD chaining cross-implementation (with a
  chunk-reorder fail-closed test alongside it). Vector 5 pins the `PQKF` key-file framing
  (see above); Vectors 5 and 7 are additionally decrypted by the Rust/WASM core. The .NET
  coverage-guided fuzz harness gains a second target: the `PQKF` key-file parser, run under
  `PqDecryptionLimits.Untrusted` ([docs/FUZZING.md](docs/FUZZING.md)). The CI native-AOT
  smoke test now also exercises the encrypted key-file path (`keygen --encrypt` → `sign` →
  `verify`).
- **Mutation testing drove a batch of exact-boundary tests.** A Stryker.NET run over the
  security-critical core files surfaced surviving mutants in the untrusted-header range
  checks; every KDF-parameter, salt, chunk-size, and header-structure bound is now tested at
  its exact edges (first illegal value rejected, exact legal bound accepted —
  `ParserBoundaryTests`), the no-oracle contract is pinned as message *equality* between
  wrong-passphrase and tampered-container failures, and `LocalKekContentKeyProvider` gained
  use-after-dispose, fresh-nonce, and cancellation pins.
- **Decrypt-time limits through dependency injection** — `AddPqFileEncryption` and
  `AddPqHybridFileEncryption` gain overloads taking a `PqDecryptionLimits`, so hosts that
  decrypt untrusted containers (the DI package's core audience: web services, workers) can
  register capped decryptors in one line instead of hand-constructing them around the
  container. Behavior is pinned by a test that proves a DI-registered ceiling actually
  rejects an over-limit container before any KDF work.
- **`PqHybridDecryptor(PqDecryptionLimits)`** — the hybrid decryptor now enforces the same
  pre-key-establishment chunk-size ceiling as the core `PqFileDecryptor`, closing the last
  documented denial-of-service exposure for containers from untrusted sources (a hostile
  header could demand the format-maximum 16 MiB chunk, ~32 MiB of buffers, on the
  unknown-length stream overload). Only `MaxChunkSizeBytes` applies on this path — key
  unwrap is a fixed-cost KEM operation, so there is no KDF cost to inflate. The default
  constructor is unchanged and every legal container still opens.

### Fixed

- **A misbehaving `IContentKeyProvider` can no longer downgrade encryption.** The engine now
  rejects any provider-returned content key that is not exactly 32 bytes — on encrypt with
  `PqEncryptionException` before any ciphertext exists (previously a 16-byte key would have
  silently produced an AES-128-GCM file while the format promises AES-256), and on decrypt
  with the fail-closed `PqDecryptionException` (previously a raw `CryptographicException`).
- **Empty passphrases are now rejected on encrypt by every overload.** The
  `ReadOnlyMemory<byte>` and sync `ReadOnlySpan<char>` passphrase overloads accepted an empty
  passphrase and produced a trivially decryptable container; they now throw
  `ArgumentException`, matching the `string` overloads. The gate is enforced once at the
  engine choke point (plus an early argument check on the file overload, before any
  filesystem side effect), so every current and future encrypt path inherits it. **Decrypt
  deliberately keeps accepting empty passphrases**: earlier releases could legitimately
  encrypt under one via the byte overloads, and that data must stay openable — a pinned
  backward-compat vector locks this in. Against a container encrypted with a real passphrase,
  an empty passphrase fails closed with the generic `PqDecryptionException`, like any other
  wrong passphrase.
- **In-place file encryption/decryption (`inputPath == outputPath`) now works on Windows**,
  in both the core and the Hybrid package. The input handle stayed open across the final
  atomic rename, which Windows rejects with a sharing-violation `IOException` after all the
  crypto work was done (it happened to work on Linux). All four file APIs now share one
  `FileIo` helper that owns the ordering invariants: the input is opened *before* the
  temporary output file exists (a missing input fails with `FileNotFoundException` and no
  destination side effect) and closed *before* the atomic move (in-place works). A failed
  in-place decrypt still leaves the source untouched.
- **Raw third-party exceptions no longer escape the library's exception contract** on four
  paths: encrypting to a corrupt ML-KEM recipient key (platform `CryptographicException` →
  `PqEncryptionException`); encrypting to a hybrid recipient key whose X25519 half is a
  small-order point, and decrypting a container carrying one (BouncyCastle
  `InvalidOperationException` → `PqEncryptionException` / the generic `PqDecryptionException`);
  signature verification (any unexpected BouncyCastle throw → the generic
  `PqSignatureException`, so no oracle for which half rejected the input — while process-level
  faults such as `OutOfMemoryException`, cancellation, and thread interrupts pass through
  untouched, so infrastructure failure is never reported as a forged signature); and Azure Key Vault
  unwrap with a locally-operating `CryptographyClient` (`CryptographicException` →
  `PqDecryptionException`, matching the remote path).
- **`LocalKekContentKeyProvider` is safe against a `Dispose` racing an in-flight wrap.** The
  race could zero the KEK mid-operation and silently wrap the content key under an all-zero
  key; all KEK uses are now serialized and the race surfaces as `ObjectDisposedException`
  (also checked at method entry, so a use-after-dispose is reported as the lifetime bug it is
  even when the input happens to be malformed too). The KEK's AES key schedule is built once
  per provider instead of per operation, keeping the critical section to the 32-byte GCM pass.
- **A freshly generated recipient content key is zeroed if key establishment throws**
  mid-wrap (previously abandoned un-zeroed on the heap).
- **Hostile header bytes are no longer embedded verbatim in exception messages.** The
  key-provider mismatch message escapes control characters from the (unauthenticated)
  provider id, closing a log/terminal-injection vector.
- **AWS KMS unwrap rejects oversized wrapped blobs client-side** (the KMS `Decrypt` limit is
  6,144 bytes), so a hostile container yields the documented `PqDecryptionException` instead
  of a raw SDK exception after a doomed network round-trip.
- **`docs/SIGNATURE-FORMAT.md` stated the wrong domain-separation context length** (64 bytes;
  the context is 63). Doc-only — the signed bytes are unchanged — but the spec is the interop
  contract for independent implementations.
- **CLI (`pqfe`) hardening:** Ctrl+C is cooperative cancellation (exit `130`, and it cancels
  the passphrase prompt itself rather than leaving the user stuck at it); `keygen` writes the
  private key `0600` on Unix and removes the orphaned private half if writing the public half
  fails; empty and end-of-input passphrases are rejected with distinct messages (a
  single-line piped stdin on encrypt reports "could not read the confirmation" instead of the
  misleading "passphrases do not match"); passphrase-prompt failures unwind as exceptions
  rather than calling `Environment.Exit`, so key-byte zeroing, orphaned-key cleanup, and
  event unhooks in enclosing `finally` blocks always run; `--passphrase-env` is rejected as a
  usage error where it would be silently ignored (`sign` with an unprotected key file,
  `verify`); `UnauthorizedAccessException` and `ArgumentException` map to exit codes instead
  of crashing.
- **The Blazor demo no longer echoes raw exception text to the browser** — unexpected errors
  are logged server-side and reported generically.

### Changed

- **Atomic file writes now flush to stable storage before the rename** (`fsync` semantics),
  so a power failure immediately after an encrypt/decrypt cannot leave a truncated file at
  the destination on filesystems that persist the rename ahead of the data. The device sync
  runs off-thread, so the async file APIs never pin a thread-pool thread on slow media.
- **`DecryptAtomicAsync` documents the exact scope of its all-or-nothing guarantee** (it
  covers authentication; a sink failure during the final copy can still leave a prefix of
  authenticated plaintext).
- **KNOWN-GAPS.md** records four newly catalogued limitations: the hybrid KEK combiner's
  missing transcript binding (protected today by header-as-AAD; a format-v3 item), two
  lenient-but-frozen v2 reader corners (unchecked reserved `Flags` byte, trailing bytes
  tolerated in passphrase KeyParams), and cloud-SDK-held plaintext key copies.

## [1.4.1] - 2026-06-13

A documentation and packaging patch. No code, public API, or format change: `.pqfe` v2 stays
frozen, and the released binaries are byte-identical in behavior to `1.4.0`.

### Fixed

- **Package READMEs cited the wrong install version.** The `1.4.0` packages shipped with
  README install snippets and a status line that still read `--version 1.3.0`, so the
  instructions rendered on the nuget.org package pages pointed at the previous release. All
  user-facing version references — the root and per-package README install snippets, the
  README status line, the supply-chain verification examples, and the "Today" cell in
  [docs/ROADMAP-2.0.md](docs/ROADMAP-2.0.md) — now track the package version. Because a
  published `.nupkg` (and its embedded README) is immutable, the fix ships as `1.4.1`.

### Changed

- **The release workflow now gates on documentation/version drift.** Before anything is
  packed or pushed, it verifies that every packable project's `<Version>`, every README
  `dotnet add package … --version` snippet, and the README status line match the tag being
  released — so a future version bump cannot publish with stale install instructions again.

## [1.4.0] - 2026-06-12

The key-management release: the envelope seam gains production cloud providers, and the
consolidated external-model audit findings were re-verified with a published disposition
([docs/audits/](docs/audits/)). No format change: `.pqfe` v2 stays frozen.

### Added

- **Cloud envelope-key providers** — the `IContentKeyProvider` seam (`KeySource = 5`) gains
  two production implementations, shipping as new lockstep packages:
  - **`PostQuantum.FileEncryption.Aws`** — `AwsKmsContentKeyProvider` over AWS KMS
    `GenerateDataKey`/`Decrypt`. Every wrap is bound to the configured key id and a
    library-reserved encryption context (callers can add entries, e.g. a tenant id); a blob
    wrapped under a different key or context fails closed with `PqDecryptionException`, while
    operational errors (missing key, access denied, throttling) propagate as SDK exceptions
    so they are never mistaken for tampering.
  - **`PostQuantum.FileEncryption.AzureKeyVault`** — `AzureKeyVaultContentKeyProvider` over
    Key Vault / Managed HSM wrap/unwrap (RSA-OAEP-256 default, `A256KW` selectable). The wrap
    records the versioned key id; unwrap requires it to match the configured client and
    always uses the *configured* algorithm — a key id or algorithm smuggled into a hostile
    container header is never honored.
  - In both, the master key never leaves the KMS/HSM, and rotation re-wraps the small content
    key instead of re-encrypting the payload. Unit-tested against in-process fakes of the SDK
    clients that reproduce the services' binding semantics; live-cloud integration is
    deliberately out of CI scope ([KNOWN-GAPS.md](KNOWN-GAPS.md)).
- **Audit-disposition record** —
  [docs/audits/2026-06-12-consolidated-findings-disposition.md](docs/audits/2026-06-12-consolidated-findings-disposition.md)
  re-verifies the six consolidated external-model findings against the current tree (all were
  remediated in `1.1.0`) and records one analogous window the re-review caught in new `1.4.0`
  code before it shipped (the AWS provider now zeroes the KMS-returned data key if wrap-info
  serialization throws).

### Changed

- **Package-validation baselines advanced to `1.3.0`**, and validation is now enabled for the
  Signing and DI packages (their first published baselines exist as of `1.3.0`). The `1.3.0`
  public APIs of Signing and the DI extensions moved from `PublicAPI.Unshipped.txt` to
  `PublicAPI.Shipped.txt`.

## [1.3.0] - 2026-06-12

The reach release: the library family now runs on .NET 8 LTS, and a fifth package adds
sender authenticity. No format change: `.pqfe` v2 stays frozen, and containers remain
byte-identical regardless of which target produced them.

### Added

- **`PostQuantum.FileEncryption.Signing` — detached hybrid signatures.** Encryption proves a
  container wasn't altered; a signature proves *who produced it*. `PqSigner`/`PqVerifier`
  sign any file, stream, or buffer with **Ed25519 + ML-DSA-65 (FIPS 204) together** — both
  components must verify, so a signature stays unforgeable if either algorithm is later
  broken — and write a 3,379-byte detached `.sig` sidecar (atomic file output). The content
  is pre-hashed with streaming SHA-512, so signing runs in constant memory for inputs of any
  size. Verification is fail-closed: structural problems raise `PqFormatException` before any
  cryptographic work, and every cryptographic mismatch raises the same generic
  `PqSignatureException` (no oracle for which component failed). Both primitives come from
  BouncyCastle (fully managed; runs on `net8.0` and `net10.0`). The sidecar format v1 is
  byte-exactly specified in [docs/SIGNATURE-FORMAT.md](docs/SIGNATURE-FORMAT.md); the
  detached-signature limits (no name/path/time binding, strip-and-resign) are recorded in
  [KNOWN-GAPS.md](KNOWN-GAPS.md). A pinned verify-only known-answer vector
  ([docs/TEST-VECTORS.md](docs/TEST-VECTORS.md), Vector 4) locks the sidecar layout, the
  domain-separation context, and the SHA-512 pre-hash.
- **`pqfe keygen` / `pqfe sign` / `pqfe verify`.** The CLI tool produces and checks detached
  signatures: `keygen` writes a key pair (refusing to overwrite an existing private key),
  `sign` writes `<input>.sig` (or `--signature PATH`), and `verify` exits `0` for an
  authentic file and `65` for any rejection. The AOT smoke test in CI now also round-trips
  keygen → sign → verify — including the fail-closed tampered-file branch — under native AOT.
- **`AddPqSigning()`** in the DI extensions package registers `PqSigner`/`PqVerifier` as
  singletons; key material stays in the application's own storage and is passed per call.

- **.NET 8 (LTS) support.** `PostQuantum.FileEncryption`, `PostQuantum.FileEncryption.Hybrid`,
  and `PostQuantum.FileEncryption.Extensions.DependencyInjection` now multi-target `net8.0`
  and `net10.0` with an identical public API on both; the full test suite runs on both
  frameworks in CI. One behavioral difference, by design: the *deprecated* inline ML-KEM-only
  recipient mode (`PQFE002`) depends on platform ML-KEM
  (`System.Security.Cryptography.MLKem`), which ships in .NET 10 — on `net8.0`,
  `PqKeyPair.IsSupported` is always `false` and the mode fails closed with
  `PlatformNotSupportedException`, exactly as on a .NET 10 host without OpenSSL 3.5+/CNG
  support. The supported recipient path, the Hybrid package (X25519 + ML-KEM-768 via fully
  managed BouncyCastle), works identically on both targets. The `pqfe` dotnet tool still
  requires the .NET 10 runtime or later.

### Changed

- **Package descriptions, tags, and README** now lead with what the library actually does
  best — constant-memory streaming for files of any size, the open MIT license, and the
  publicly specified frozen container format with a byte-compatible Rust/WASM reference —
  so package-page readers (human or otherwise) don't have to infer it.
- **`PackageValidationBaselineVersion` bumped to `1.2.1`** (the latest published version),
  per the release convention.

## [1.2.1] - 2026-06-12

Packaging-only patch — no code change; binaries are identical to `1.2.0` apart from the
version stamp.

### Fixed

- **The packed README now renders correctly on nuget.org.** Relative documentation links
  (`docs/*`, `KNOWN-GAPS.md`, `samples/*`) were dead on the package page because nuget.org
  renders the README with no repository context; every link is now an absolute
  `github.com` URL. The codecov badge is now served via `img.shields.io` like the other
  badges, so no image falls outside nuget.org's trusted-domain allow-list.

## [1.2.0] - 2026-06-12

The security-review release: two independent AI-assisted static self-reviews of the full
tree were run, published under [docs/audits/](docs/audits/), and every actionable finding
remediated. The fail-closed contract held against all critical attack classes; what
follows is availability hardening. No format change: `.pqfe` v2 stays frozen.

### Added

- **Security-review transparency record** — [docs/audits/](docs/audits/) publishes both
  self-review reports (clearly labeled as self-review, not an independent audit) with a
  per-finding disposition table, plus [docs/AUDIT-GUIDE.md](docs/AUDIT-GUIDE.md), the
  reviewer-facing entry point: the ~1,700-line attack-surface map, the invariants to
  attack, suggested first questions, and how to run the fail-closed evidence.
- **`PqDecryptionLimits` — decrypt-time cost ceilings for untrusted input.** A container's
  KDF cost and chunk size are read from its (attacker-controllable) header and honored
  before anything authenticates, so a hostile ~30-byte file could legally demand the format
  maximum (2 GiB of Argon2id memory, 10,000 passes) on open. The new
  `PqFileDecryptor(PqDecryptionLimits)` constructor caps PBKDF2 iterations, Argon2id
  memory/iterations, and chunk size; headers above a limit are rejected with
  `PqFormatException` *before* any key-derivation work. `PqDecryptionLimits.Untrusted` is a
  conservative preset; the default constructor keeps the permissive format maxima, so
  existing behavior and every legal container are unchanged. Found by static security
  review (finding PQFE-001).

### Fixed

- **Chunk buffers are now capped by the container's known length** (finding PQFE-002).
  Decryption allocated two buffers of the header-declared chunk size before the first
  frame authenticated, so a tiny hostile container declaring a 16 MiB chunk drove a
  ~32 MiB allocation. When the container's total length is known (file and bytes APIs,
  seekable streams) the buffers are now sized to what the body could actually hold;
  unknown-length streams keep the declared (range-checked) size, optionally lowered via
  `PqDecryptionLimits.MaxChunkSizeBytes`.
- **The `pqfe` CLI's `--passphrase-env` help now states the tradeoff** (finding PQFE-004):
  environment variables are visible to child processes and can surface in crash dumps.
- **The hybrid benchmarks never ran.** `benchmarks/.../Program.cs` registered only
  `ThroughputBenchmarks` with the `BenchmarkSwitcher`, so `HybridThroughputBenchmarks`
  (added in 1.1.0) was silently skipped everywhere, including the weekly benchmark CI.
  Both classes are now registered, and the first measured hybrid numbers are published in
  [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

### Changed

- Package-validation baseline bumped from `1.0.0` to `1.1.0`, so binary compatibility is
  now checked against the most recent published release.
- README performance section now carries same-machine passphrase *and* hybrid numbers,
  including the sub-millisecond per-recipient "hybrid tax" measurement
  ([docs/BENCHMARKS.md](docs/BENCHMARKS.md)).

## [1.1.0] - 2026-06-10

Two new packages join the family — the `pqfe` dotnet tool and the dependency-injection
extensions — plus live Rust↔.NET interop CI and a round of key-material-hygiene and
correctness fixes from external review. No format change: `.pqfe` v2 stays frozen.

### Added

- **`pqfe` ships as an installable dotnet tool** — `samples/Pqfe.Cli` is now packed as
  `PostQuantum.FileEncryption.Tool` (`dotnet tool install -g PostQuantum.FileEncryption.Tool`)
  and published by the release workflow with the same SBOM/provenance/validation pipeline
  as the library packages. The project now builds under the repository's strict analysis.
- **Live cross-implementation interop CI** (`ci.yml` → `interop`) — fresh random payloads
  are encrypted by .NET and decrypted by the Rust core (and vice versa) on every push,
  across chunk-boundary sizes, including an Argon2id container and wrong-passphrase
  fail-closed agreement. Adds the native `pqfe_io` example driver to `samples/pqfe-wasm`.
- **Hybrid benchmarks** — `HybridThroughputBenchmarks` (single and 10-recipient
  encrypt/decrypt, key-pair generation) joins the BenchmarkDotNet suite.
- **`PostQuantum.FileEncryption.Extensions.DependencyInjection`** — new NuGet package with
  `AddPqFileEncryption()` / `AddPqHybridFileEncryption()` extension methods registering the
  encryptor/decryptor types as singletons in `Microsoft.Extensions.DependencyInjection`
  hosts. Versioned in lockstep with the core and Hybrid packages; published by the release
  workflow after Hybrid is indexed.
- **Docs:** [docs/HYBRID-COMBINER.md](docs/HYBRID-COMBINER.md) (combiner design rationale
  vs. X-Wing / HPKE / RFC 9794), [docs/GOLD-STANDARD.md](docs/GOLD-STANDARD.md) (public
  self-assessment incl. open gaps), [docs/BENCHMARKS.md](docs/BENCHMARKS.md) (methodology
  and fair-comparison guidance).

### Fixed

- **Key-material hygiene (defense in depth; no exploit, no format or behavior change):**
  the encrypt orchestration now zeroes the content key in a `finally` even when header
  construction throws before the codec (which has always zeroed it) is entered, and the
  hybrid unwrap path zeroes its temporary `byte[]` copies of the ML-KEM and X25519 private
  keys after their last use. BouncyCastle's own internal key copies cannot be zeroized —
  documented in [KNOWN-GAPS.md](KNOWN-GAPS.md).
- **The hybrid multi-recipient limit is enforced as 55, not 255.** Each recipient entry is
  1186 bytes and the whole block must fit the container header's `uint16` key-parameters
  length, so 56+ recipients always failed — but only *after* all the ML-KEM/X25519 wrapping
  work, with a confusing header error. The encryptor now rejects oversized recipient lists
  up front with a clear message, and the cap is documented in
  [docs/FILE-FORMAT.md](docs/FILE-FORMAT.md). (Clarification of an existing format-implied
  limit; no container that could be produced before is affected.)
- **Hybrid encryption zeroes the content key on pre-engine failure paths** — `PqHybridEncryptor`
  now wraps key wrapping and header creation in a `finally` that zeroes the CEK, matching the
  hardening already applied to the core orchestration.
- **Decryption progress now reports the exact plaintext total.** `PqProgress.TotalBytes` was
  fed the ciphertext/container length during decryption, so `Fraction` could never reach 1.0.
  The plaintext total is now derived exactly from the container length (the chunked frame
  layout is deterministic), so decrypt progress is plaintext-vs-plaintext and completes at 1.0.
- **`LocalKekContentKeyProvider.Generate()` zeroes its intermediate KEK copy**, so disposing
  the provider removes every KEK copy the type created.

## [1.0.1] - 2026-06-06

Re-release of `1.0.0` packaged end-to-end by the standard release workflow so the `.nupkg`
bytes published to nuget.org match the SLSA-style build-provenance attestation and verify
cleanly against a clean-room Linux rebuild via `.github/workflows/reproducibility.yml`.

**No library code change since `1.0.0`.** The library, the `.pqfe` v2 format, the public
API surface, and the runtime dependencies are identical.

### Context

`1.0.0` was published via hand-recovery from this maintainer's Windows machine during the
`NUGET_API_KEY` rotation. The release workflow eventually ran successfully, but its publish
steps hit `--skip-duplicate` against the already-uploaded hand-packed bytes. The downstream
effect:

- The `.nupkg` on nuget.org for `1.0.0` was packed on Windows (CRLF line endings in packed
  text files such as `LICENSE`; downstream effects on the Hybrid `.dll` bytes via Roslyn's
  embedded source-file SHA hashes).
- The build-provenance attestation generated by the workflow applies to the workflow's
  *Linux* build of `1.0.0` — which is what was uploaded to the GitHub Release page — not to
  the bytes a user installs from nuget.org.
- The reproducibility workflow ran on the published `1.0.0` bytes and reported a mismatch,
  as designed.

`1.0.1` closes that loop end-to-end: the workflow packs, attests, publishes, and the
reproducibility check then verifies the published bytes byte-for-byte against a clean Linux
rebuild. Users already on `1.0.0` may continue to use it — the code is identical — but new
consumers should pin `1.0.1` so that `gh attestation verify` and the reproducibility check
both succeed against the bytes they install.

### Added

- `.gitattributes` — forces LF line endings repo-wide via `* text=auto eol=lf`, plus a
  short binary allowlist. Without this, Windows checkouts with the default
  `core.autocrlf=true` produced CRLF text files locally, which changed Roslyn's embedded
  source-file SHA in the PDB and propagated into the `.dll` bytes — the silent root cause
  of the `1.0.0` mismatch.

### Changed

- `.github/scripts/verify-reproducibility.sh` — `diff -r` now excludes `*.psmdcp` (NuGet's
  per-pack core-properties file carries a fresh GUID in its name and is never reproducible
  by NuGet's design; including it in the diff was a script bug).
- `docs/REPRODUCIBLE-BUILDS.md` — new section on the cross-OS caveat: Roslyn embeds source
  hashes in PDBs, so different line endings produce different `.dll` bytes even with
  `Deterministic=true`. With `.gitattributes` now normalising line endings on every
  checkout, the cross-OS gap is closed from `1.0.1` forward.
- `Directory.Build.props`: `PackageValidationBaselineVersion` bumped from `1.0.0-rc.3` to
  `1.0.0` so `1.0.1`'s public surface is validated against the published `1.0.0` baseline.

### Notes

- `1.0.0` remains on nuget.org. Its API surface and runtime behaviour are identical to
  `1.0.1`; only the packaging story differs. This entry is the public record of why.

## [1.0.0] - 2026-06-05

The first stable release of PostQuantum.FileEncryption. The `.pqfe` v2 container format is
FROZEN for the `1.x` line. The public API surface is locked.

**No library code change since `1.0.0-rc.3`.** The library, the `.pqfe` v2 format, the public
API surface, and the runtime dependencies are identical to rc.3. This release adds
documentation and supply-chain polish on top of that code and drops the pre-release suffix.

### Added
- `docs/REPRODUCIBLE-BUILDS.md`, `.github/scripts/verify-reproducibility.sh`, and
  `.github/workflows/reproducibility.yml` — third-party-verifiable recipe to rebuild a
  tagged release bit-identically and diff against the published `.nupkg`. The workflow
  runs automatically after every successful Release run (matrixed over both packages) and
  on demand against any historical tag.
- `.github/workflows/benchmarks.yml` — on-demand and weekly BenchmarkDotNet throughput
  runs (encrypt + decrypt over 16 MiB with PBKDF2 and Argon2id). Results uploaded as a
  workflow artifact and posted to the run summary.
- `docs/ANNOUNCE.md` — draft "Why we built this" announcement post.
- `docs/DISCOVERABILITY.md` — pre-flight checklist + awesome-list submission template +
  aggregator etiquette.

### Changed
- `SUPPORT.md` — full rewrite for the `1.x` lifecycle: supported-versions table, LTS intent
  (security fixes on the latest `1.x` minor; at least 12 months of continued support after
  a hypothetical `2.0`), deprecation policy (`PQFE002`), runtime support matrix.
- `docs/THREAT-MODEL.md` — residual risks refreshed (the "format not frozen" and
  "ML-KEM-768 used alone" entries are now obsolete and removed); audit-focus list extended
  to cover the X25519 + ML-KEM-768 combiner, the multi-recipient envelope, and the legacy
  KEM-DEM mode.
- `docs/VERSIONING.md` — dropped pre-1.0 phrasing; describes the `1.x` policy as enforced
  at build time by PublicApiAnalyzers baselines and `<EnablePackageValidation>`.
- `ROADMAP.md` — collapsed the rc.3 / 1.0.0 narrative into a single "Now — `1.0.0`"
  section; reproducible-build verification added to the supply-chain bullets.
- `README.md` — status banner promoted from "1.0.0-rc.3 — final polish" to "1.0.0 — stable
  release"; documentation table picks up `docs/REPRODUCIBLE-BUILDS.md`.
- `docs/SUPPLY-CHAIN.md` — new section pointing at the reproducible-build script and the
  verification workflow.
- `Directory.Build.props`: `PackageValidationBaselineVersion` bumped from `1.0.0-rc.2` to
  `1.0.0-rc.3` so `1.0.0`'s public surface is validated against the published rc.3 baseline.

### Notes
- The published `1.0.0-rc.3` nupkgs remain on nuget.org as the immediate predecessor.
- Reproducible-build verification runs for the first time on this release.

## [1.0.0-rc.3] - 2026-06-04

Final polish pass before `1.0.0`. Tracks `PostQuantum.FileEncryption.Hybrid` 1.0.0-rc.3 in
lockstep. The `.pqfe` container format (v2) remains FROZEN. Source- and binary-compatible
with `1.0.0-rc.2`.

### Added
- `docs/MIGRATION.md` — from-other-libraries guide covering age/rage, libsodium
  `secretstream`, OpenSSL `enc`, .NET `AesGcm`, .NET `ProtectedData` (DPAPI), BouncyCastle
  CMS/OpenPGP, and Microsoft Data Protection. Includes a cross-cutting pre-flight
  checklist for production migration.
- `docs/SUPPLY-CHAIN.md` — one-page verification recipe (build-provenance attestation
  verify, CycloneDX SBOM inspection, conformance vector round-trip, deterministic-build
  spot check). Linked prominently from the README.
- `tests/.../NoOracleTests.cs` — explicitly pins the no-decryption-oracle property: wrong
  passphrase, flipped ciphertext, flipped tag, and flipped header bytes must all surface
  as `PqDecryptionException` with the same message. Prevents a future "helpful" error
  message regression from turning the library into an oracle.

### Changed
- `README.md` — restructured for production-grade positioning: new "Why this library" and
  "When to use this" sections, supply-chain visibility surfaced inline with concrete
  verification commands, public-key path explained around the Hybrid package only,
  deprecated inline ML-KEM mode no longer shown as a usage example.
- `ROADMAP.md` — refreshed to reflect 1.0 reality. The pre-`1.0` `v0.4` / "Toward `1.0`"
  sections (cloud KMS scoping, package validation, format freeze) have been replaced with
  a "Now → 1.0.0 → 1.x → 2.0" structure that matches what has already shipped.
- `SECURITY.md` — supported-versions table refreshed (`1.0.x` ✅, `0.x` ❌); language
  updated to reflect the frozen `.pqfe` v2 format; deprecated inline ML-KEM mode framed
  as deprecated rather than experimental; supply-chain artifacts (SBOM, attestation)
  noted explicitly.
- `KNOWN-GAPS.md` — removed stale entries (format-not-frozen, package-validation-not-yet-
  enabled) that were already resolved; release-scope section updated to reflect Hybrid
  shipping and the inline mode being deprecated rather than experimental.
- Package metadata (`PostQuantum.FileEncryption` and `PostQuantum.FileEncryption.Hybrid`):
  Description and PackageTags tightened for clarity and search; ReleaseNotes refreshed
  with the new doc artifacts.
- `Directory.Build.props`: `PackageValidationBaselineVersion` bumped from `1.0.0-rc.1` to
  `1.0.0-rc.2` so rc.3's public surface is validated against the published rc.2 baseline.

### Notes
- No format change. No public-API change. No runtime-dependency change. The published
  1.0.0-rc.2 nupkgs are immutable on nuget.org; rc.3 supersedes them as the final
  candidate before `1.0.0`.

## [1.0.0-rc.2] - 2026-06-01

Tracks `PostQuantum.FileEncryption.Hybrid` 1.0.0-rc.2 in lockstep. The `.pqfe` container
format (v2) remains FROZEN. Source-compatible with 1.0.0-rc.1.

### Deprecated
- **Inline ML-KEM-768-only recipient mode is deprecated** (`PQFE002`). `PqKeyPair`,
  `PqRecipientPublicKey`, `PqRecipientPrivateKey`, `PqKemAlgorithm`, and the recipient
  overloads on `PqFileEncryptor`/`PqFileDecryptor` are now marked `[Obsolete]` (warning,
  not error). Existing callers still build with a deprecation warning. **Migration:** use
  the `PostQuantum.FileEncryption.Hybrid` package (`PqHybridKeyPair`, `PqHybridEncryptor`,
  `PqHybridDecryptor`) — X25519 + ML-KEM-768 hybrid combiner with multi-recipient support
  and no platform ML-KEM gate. Removal of the inline mode is targeted for a future major
  release.

### Added
- I/O failure-mode test coverage pinning the file-API atomic-write contract: disk-full
  mid-write, mid-write cancellation, unwritable-destination, and an explicit
  `Truncation_at_specific_offsets_is_rejected` theory covering header truncation,
  mid-chunk truncation, and final-tag truncation.
- `Round_trip_at_maximum_chunk_size` (16 MiB) exercising
  `PqEncryptionOptions.MaxChunkSizeBytes`, gated as `[Trait("Category", "LongRunning")]`.
  CI's default per-push lane filters `Category!=LongRunning`; an extra Linux-only step
  runs `Category=LongRunning` so the coverage lands without slowing every push.
- `KNOWN-GAPS.md` entry documenting the best-effort temp-file cleanup behaviour
  (destination integrity is preserved either way; only the temp file may linger under
  pathological OS conditions).
- Hybrid package: README rewritten to present this package as the single recommended
  public-key path, with a side-by-side migration snippet from the deprecated inline mode.
  Suite-versioning lockstep note added to `docs/VERSIONING.md`.
- Release workflow hardened: `release.yml` now publishes the core to NuGet first, polls
  the v3-flatcontainer index until the new core version is queryable, then publishes
  Hybrid. Eliminates the indexing-race window where a consumer who installs Hybrid
  immediately after tag-push could get an "unable to resolve PostQuantum.FileEncryption"
  error even though both packages have been pushed.

### Changed
- `Directory.Build.props`: `PackageValidationBaselineVersion` bumped from `0.2.0` to
  `1.0.0-rc.1` so rc.2's public surface is validated against the published rc.1 baseline.

### Notes
- No format change. No public-API change. No runtime-dependency change. The published
  1.0.0-rc.1 nupkgs are immutable on nuget.org; rc.2 supersedes them.

## [1.0.0-rc.1] - 2026-05-31

The **on-disk `.pqfe` container format is now FROZEN at v2** for the `1.x` line. Every byte
is pinned by published conformance vectors; an incompatible change requires `2.0`.

### Added
- **Format conformance spec** — `docs/CONFORMANCE.md` documents what an implementer must
  produce to be byte-compatible with `.pqfe` v2, alongside the existing `docs/FILE-FORMAT.md`
  and `docs/TEST-VECTORS.md`. The Rust → WASM implementation (`samples/pqfe-wasm`) serves as
  the second-implementation conformance witness.
- **Synchronous `ReadOnlySpan<char>` passphrase entry point** — `PqFileEncryptor.EncryptBytes`
  and `PqFileDecryptor.DecryptBytes` for callers that never want to go async. True sync code
  path; no `.GetAwaiter().GetResult()` deadlock risk.
- **`Microsoft.CodeAnalysis.PublicApiAnalyzers`** wired into both packages, with the full
  0.2.0 public surface plus the new 1.0 additions baselined in `PublicAPI.Shipped.txt`.
  Accidental breaking changes now fail the build.
- **`<EnablePackageValidation>` with `PackageValidationBaselineVersion=0.2.0`** in
  `Directory.Build.props`, so every pack compares against the published `0.2.0` surface.
  Intentional breaks are documented in `CompatibilitySuppressions.xml`.
- **Package icon** (`assets/icon.png`) packed into both NuGet packages — the
  `Meziantou.Framework.NuGetPackageValidation` icon-rule exclusion has been removed from
  `release.yml`, which now enforces strict icon-must-be-set.
- **Codecov upload** in `ci.yml` and the corresponding badge in the README.
- **`IProgress<PqProgress>?` on the envelope-key bytes APIs.** `PqFileEncryptor.EncryptBytesAsync`
  and `PqFileDecryptor.DecryptBytesAsync` taking an `IContentKeyProvider` now accept the same
  optional progress callback the passphrase overloads do.

### Changed
- The aspirational `PostQuantum.FileFormat` delegation is no longer in the roadmap. The
  self-contained codec is the permanent implementation; the internal `IPqContainerCodec`
  seam is retained as an internal abstraction but is no longer documented as "to be wired."

### Deprecated
- **Inline ML-KEM-768-only recipient mode is deprecated** (`PQFE002`). `PqKeyPair`,
  `PqRecipientPublicKey`, `PqRecipientPrivateKey`, `PqKemAlgorithm`, and the recipient
  overloads on `PqFileEncryptor`/`PqFileDecryptor` are now marked `[Obsolete]` (warning,
  not error). Source-compatible: existing callers still build with a deprecation warning.
  **Migration:** use the `PostQuantum.FileEncryption.Hybrid` package — `PqHybridKeyPair`,
  `PqHybridEncryptor`, `PqHybridDecryptor` — for the X25519 + ML-KEM-768 hybrid combiner
  with multi-recipient support. Removal of the inline mode is targeted for a future major
  release.

### Notes
- This is **source-compatible** with 0.2.0; existing callers continue to compile unchanged.
- Two binary-level signature changes vs. 0.2.0 are intentionally suppressed in
  `CompatibilitySuppressions.xml`: the `progress` parameter additions to the envelope-key
  `EncryptBytesAsync` / `DecryptBytesAsync` overloads. These are the last allowed binary
  breaks; everything from `1.0.0` onward is binary-stable.

## [0.2.0] - 2026-05-30

### Added
- **`PostQuantum.FileEncryption.Hybrid` companion package** — post-quantum hybrid public-key
  encryption: an **X25519 + ML-KEM-768 combiner** (`KeySource = 3`) and **multiple recipients**
  (`KeySource = 4`), with `PqHybridKeyPair` / `PqHybridEncryptor` / `PqHybridDecryptor`. Fully
  managed via BouncyCastle (both primitives) — no native ML-KEM requirement, runs anywhere.
  Round-trip, multi-recipient, fail-closed, and pinned decrypt-KAT tested.
- **Envelope key management** — `IContentKeyProvider` (the KMS/HSM seam) and a built-in,
  dependency-free `LocalKekContentKeyProvider` (AES-256-GCM key wrap, `KeySource = 5`). Any
  `PqFileEncryptor` / `PqFileDecryptor` file/stream/in-memory overload accepts a provider; the
  master key never enters the process beyond the provider's boundary. Cloud providers (AWS/Azure)
  implement the same interface in separate packages.
- **Continuous coverage-guided fuzzing** for both parsers (cargo-fuzz + SharpFuzz), scheduled
  nightly; OSS-Fuzz integration files.
- **`samples/Pqfe.Cli`** — minimal `pqfe encrypt | decrypt` command-line sample that exercises
  the public API and is published with `PublishAot=true` in CI as the AOT smoke test.
- **Discoverable options helpers** — `PqEncryptionOptions.Argon2id` static preset plus
  `WithArgon2id` / `WithPbkdf2` / `WithChunkSize` fluent methods on the immutable options.

### Changed
- CI matrix now covers Linux, Windows, and macOS; a separate job performs a native-AOT publish
  of the CLI sample and round-trips a real file on every push.
- Release pipeline runs `Meziantou.Framework.NuGetPackageValidation.Tool` against every
  `.nupkg` before `nuget push`, alongside the existing CycloneDX SBOM and SLSA-style
  provenance attestation.
- New OpenSSF Scorecard workflow (weekly + push to main + on demand) with SARIF upload to the
  Security tab and publication to the public Scorecard dashboard.
- `PostQuantum.FileEncryption.Hybrid` metadata brought to parity with the core package
  (`PackageRequireLicenseAcceptance`, packed `LICENSE`, `MinClientVersion`).

## [0.1.0] - 2026-05-30

First release. The **symmetric, passphrase-based engine is production-ready**.

### Added
- `PqFileEncryptor` / `PqFileDecryptor` with file, stream, and in-memory
  (`EncryptBytesAsync` / `DecryptBytesAsync`) APIs.
- AES-256-GCM authenticated encryption; chunked streaming with bounded memory, progress
  reporting (`IProgress<PqProgress>`), and cancellation.
- Passphrase key derivation via PBKDF2-HMAC-SHA256 (default) or Argon2id (`PqKdf`).
- Zeroable `ReadOnlyMemory<byte>` passphrase overloads.
- `DecryptAtomicAsync` — all-or-nothing stream decryption.
- Opt-in, non-sensitive telemetry via the `PostQuantum.FileEncryption` `EventSource`.
- **Experimental** ML-KEM-768 recipient (public-key) mode, platform-gated and marked
  `[Experimental("PQFE001")]`.
- A specified container format (`docs/FILE-FORMAT.md`), pinned by cross-checked and
  byte-exact known-answer vectors, plus an independent Rust → WebAssembly implementation and
  two demos.
- Benchmarks, property-based tests, and a mutation/truncation fuzz harness.
- Trim/AOT compatibility (`IsAotCompatible`); SourceLink and a symbols package.

### Security
- Fail-closed against wrong passphrase, tampering, chunk reordering, splicing, and truncation.
- Bounded work on untrusted headers (KDF cost parameters are range-checked).
- Derived keys, wrapped secrets, and private keys are zeroed after use.

[Unreleased]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.7.1...HEAD
[1.7.1]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.4.1...v1.5.0
[1.4.1]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.0.0-rc.3...v1.0.0
[1.0.0-rc.3]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.0.0-rc.2...v1.0.0-rc.3
[1.0.0-rc.2]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v1.0.0-rc.1...v1.0.0-rc.2
[1.0.0-rc.1]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v0.2.0...v1.0.0-rc.1
[0.2.0]: https://github.com/systemslibrarian/postquantum-file-encryption/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/systemslibrarian/postquantum-file-encryption/releases/tag/v0.1.0
