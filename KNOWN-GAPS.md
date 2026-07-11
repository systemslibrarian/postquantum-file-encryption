# Known Gaps

This document is the honest ledger for PostQuantum.FileEncryption. It records what is
incomplete, deferred, or imperfect, so that nobody has to discover it by reading the source
or, worse, in production. If you find a gap not listed here, that itself is a gap — please
open an issue.

Last reviewed against: **`1.5.0`**. See [ROADMAP.md](ROADMAP.md) for the forward plan.

## Release scope (read this first)

- **The stable, released engine is symmetric and passphrase-based:** AES-256-GCM with
  PBKDF2-HMAC-SHA256 or Argon2id. AES-256 is quantum-resistant for the *confidentiality of
  the data itself*. The `.pqfe` v2 container format is FROZEN for the `1.x` line.
- **Post-quantum *public-key* encryption ships as the production
  `PostQuantum.FileEncryption.Hybrid` package** — X25519 + ML-KEM-768 hybrid combiner with
  multi-recipient support, managed via BouncyCastle (no platform ML-KEM dependency, runs
  anywhere .NET 10 does). See [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md).
- **The inline ML-KEM-768-only recipient mode in the core is deprecated** as of
  `1.0.0-rc.2` (`PQFE002`) and retained only for source-compatibility. New code must use
  the Hybrid package; the inline mode is targeted for removal in a future major release.

## Resolved in `1.5.0`

- **Private keys have a safe at-rest form.** "No key files" was a scope gap: `Export()`
  returned raw secret bytes and every application had to invent its own storage.
  `ExportEncrypted`/`ImportEncrypted` on both private-key types (and `pqfe keygen --encrypt`)
  now wrap the key in a passphrase-encrypted, authenticated `.pqfe` container behind a
  five-byte `PQKF` framing ([docs/KEY-FILE-FORMAT.md](docs/KEY-FILE-FORMAT.md)) — no new
  cryptography, Argon2id by default.
- **`PqHybridDecryptor` now accepts `PqDecryptionLimits`.** Previously the hybrid decryptor
  took no limits, so on the unknown-length stream overload a hostile header could demand the
  format-maximum 16 MiB chunk (~32 MiB of buffers) before the first authentication check. A
  limits-accepting constructor now enforces the same pre-key-establishment chunk-size gate as
  the core `PqFileDecryptor` (only `MaxChunkSizeBytes` applies — KEM unwrap is fixed-cost, so
  there is no KDF exposure on this path). See the CHANGELOG's `1.5.0` section for the
  accompanying hardening batch.

## Resolved in `1.2.0`

- **Decrypt-time cost ceilings.** A container's KDF cost parameters and chunk size are
  honored before anything authenticates, so a hostile ~30-byte header could legally demand
  the format maximum — up to 2 GiB of Argon2id memory — on open. Found by a static security
  review (it was a hardening gap, not a contradiction of any documented bound). Now:
  `PqDecryptionLimits` lets callers who decrypt untrusted containers cap PBKDF2/Argon2id
  cost and chunk size (`PqDecryptionLimits.Untrusted` preset, or custom ceilings), with
  over-limit headers rejected as `PqFormatException` before any derivation work; and the
  engine caps its chunk buffers to what a container of known length could actually hold,
  so a tiny container declaring a 16 MiB chunk no longer drives a ~32 MiB allocation.
  Defaults are unchanged — every legal container still opens.

## Resolved since the first symmetric cut

- **Memory-hard KDF** — Argon2id is selectable via `PqEncryptionOptions.Kdf`.
- **Zeroable passphrases** — `ReadOnlyMemory<byte>` passphrase overloads are available.
- **Test vectors and fuzzing** — pinned known-answer vectors and a mutation/truncation fuzz
  harness are in the test suite, cross-checked against the Rust/WASM implementation.

## Resolved in `0.3.0`

- **PublicAPI surface locked** — `Microsoft.CodeAnalysis.PublicApiAnalyzers` is wired into
  both packages with the full 0.2.0 surface baselined (`PublicAPI.Shipped.txt`). Any accidental
  breaking change to a public type, member, or signature now fails the build.
- **Package icon** packed into both packages; the icon-rule exclusion has been removed from
  `release.yml`, so the release pipeline enforces icon-must-be-set strictly.
- **Coverage published.** `ci.yml` uploads coverage to Codecov on the Ubuntu matrix leg and
  the README carries the badge.
- **Bytes-API progress parity.** The envelope-key `EncryptBytesAsync` / `DecryptBytesAsync`
  overloads now accept an optional `IProgress<PqProgress>?`, matching the passphrase
  `EncryptBytesAsync`. (The passphrase `DecryptBytesAsync` overloads remain progress-free —
  in-memory decryption completes too quickly for progress to be useful there.)

## Resolved in `0.2.0`

- **CLI sample** — `samples/Pqfe.Cli` (`pqfe encrypt | decrypt`) makes the README copy-paste
  runnable and gives the AOT smoke test a real target. It now also ships as the installable
  `PostQuantum.FileEncryption.Tool` dotnet tool (passphrase mode only — recipient/hybrid
  encryption remains library-only).
- **Native-AOT smoke test in CI** — the CLI is `dotnet publish -p:PublishAot=true`-ed and
  round-trips a real file on every push, so any regression in the `IsAotCompatible` claim
  fails the build.
- **macOS in the CI matrix** — `ubuntu-latest`, `windows-latest`, *and* `macos-latest`.
- **Pre-publish NuGet validation** — `release.yml` now runs
  `Meziantou.Framework.NuGetPackageValidation.Tool` against every produced `.nupkg`
  (deterministic build, SourceLink wired, README/LICENSE packed, …) before `nuget push`.
- **OpenSSF Scorecard** — weekly + push-to-main + dispatch, with SARIF in the Security tab
  and publish to the public Scorecard dashboard.
- **Discoverable options helpers** — `PqEncryptionOptions.Argon2id` preset and
  `WithArgon2id` / `WithPbkdf2` / `WithChunkSize` fluent methods on the immutable options.

## Still open

### Cryptographic scope

- **Signature schemes never enter the hybrid encryption path — by construction, not by
  schedule.** The hybrid path establishes a content key; its primitives are a KEM (ML-KEM-768)
  and a DH (X25519), combined. ML-DSA and SLH-DSA are *signature* schemes answering "who
  produced this," a separate guarantee owned by **`PostQuantum.FileEncryption.Signing`**.
  Adding a signature algorithm to the hybrid path would conflate confidentiality with sender
  authentication, not broaden the offering. The one place the two legitimately converge is
  **signatures embedded in the container** — bound to the authenticated header — which is a
  format-v3 obligation, not a hybrid-path change. See [docs/ROADMAP-2.0.md](docs/ROADMAP-2.0.md).
- **The core's inline ML-KEM-only recipient mode is DEPRECATED as of `1.0.0-rc.2`.** It is
  marked `[Obsolete]` with diagnostic id `PQFE002` and retained for source-compatibility
  only — new code must use the **`PostQuantum.FileEncryption.Hybrid`** package (hybrid
  X25519 + ML-KEM-768 combiner with multi-recipient support, managed BouncyCastle for
  both primitives, runs anywhere). Removal of the inline mode is targeted for a future
  major release; until then it continues to honour the existing fail-closed contract.
- **Cloud KMS/HSM providers are not integration-tested against live clouds in CI.** The
  envelope seam (`IContentKeyProvider`, `KeySource = 5`) now has four implementations: the
  built-in `LocalKekContentKeyProvider`, **`PostQuantum.FileEncryption.Aws`** (AWS KMS
  GenerateDataKey/Decrypt with a bound encryption context),
  **`PostQuantum.FileEncryption.AzureKeyVault`** (Key Vault / Managed HSM wrap/unwrap, pinned
  key id and algorithm), and **`PostQuantum.FileEncryption.Gcp`** (Cloud KMS Encrypt/Decrypt
  with bound AAD and end-to-end CRC32C verification; the content key is generated locally
  because Cloud KMS has no server-side data-key generation). The cloud providers are
  unit-tested against in-process fakes of the SDK clients that reproduce the services'
  binding semantics — CI has no cloud credentials, so live-service integration is exercised
  by consumers, not by this repo's pipeline.
  HashiCorp Vault and PKCS#11 providers remain unimplemented; rewrap/rotation tooling is
  still designed-only. See [docs/KEY-MANAGEMENT.md](docs/KEY-MANAGEMENT.md).
- **Passphrases are still `string` on the convenience overloads.** The zeroable byte overloads
  exist, but the `string` overloads remain for ergonomics and cannot zero the caller's `string`.

### Dependency assurance

- **Argon2id comes from `Konscious.Security.Cryptography`**, a widely used but **not formally
  audited** managed implementation. The default KDF (PBKDF2) avoids this dependency at runtime.
- **BouncyCastle key objects cannot be zeroized.** The Hybrid package zeroes every temporary
  private-key copy it creates, but BouncyCastle's parameter objects (`MLKemPrivateKeyParameters`,
  `X25519PrivateKeyParameters`) keep their own internal copies of key material with no public
  zeroization API; those copies live until garbage collection. This is a limitation of the
  dependency, shared by everything built on managed BouncyCastle.
- **Cloud SDKs hold un-zeroable copies of the plaintext content key.** The AWS and Azure
  providers zero every plaintext-key buffer they can reach (including the AWS SDK's response
  `MemoryStream` buffer), but the key also transits SDK-internal HTTP buffers and, in the AWS
  case, exists transiently as a base64 `string` inside the JSON reader — a `string` cannot be
  zeroed. The GCP provider likewise zeroes every reachable copy (including the response
  `ByteString`'s backing array), but the key also crosses protobuf/gRPC serialization
  buffers — in *both* directions, since Cloud KMS has no server-side data-key generation and
  the locally generated content key is uploaded for wrapping. Those copies live until
  garbage collection. Same class of limitation as the BouncyCastle entry above.

### Format and feature gaps

- **The container format is FROZEN at `.pqfe` v2 for the `1.x` line.** No `0.x → 1.x`
  migration tooling exists; if you have any preview-era ciphertext, decrypt it with the
  original `0.x` build and re-encrypt with a `1.x` build. A future major version (`2.0`)
  would carry a new `FormatVersion` and a documented migration path — the candidate feature
  set lives in [docs/ROADMAP-2.0.md](docs/ROADMAP-2.0.md).
- **Metadata is not protected.** Plaintext length is revealed to within a chunk; file names,
  paths, and timestamps are not encrypted or carried. Length-hiding padding and encrypted
  file names are candidates for a future `2.0`.
- **No streaming all-or-nothing guarantee.** `DecryptAsync(Stream, Stream, …)` authenticates
  each chunk before writing it, but a stream cannot be un-written, so a truncation detected at
  the final frame leaves earlier (authentic) chunks already emitted. The **file** APIs avoid
  this with temp-file-plus-atomic-move; stream callers who need strict atomicity should buffer.
- **Bytes appended after the final frame are not detected.** The v2 decryption rules stop at
  the authenticated final frame (`FILE-FORMAT.md`, rule 5), so trailing garbage appended to a
  container decrypts successfully and silently. Every byte that *is* decrypted remains fully
  authenticated; only the file's tail past the final frame is outside the envelope. Rejecting
  trailing data would change frozen v2 behavior (and the Rust/WASM implementation in step), so
  it is a format-v3 candidate, not a `1.x` change.
- **Three lenient v2 reader corners are frozen with the format.** (1) The header's reserved
  `Flags` byte is defined "must be 0" but readers do not reject a nonzero value (it is still
  bound into the AAD, so it cannot be *modified* after encryption); (2) the passphrase
  KeyParams parsers tolerate trailing bytes, where the inline recipient parser (KeySource 1/2)
  and the single-recipient hybrid block (KeySource 3) enforce exact length; (3) the
  multi-recipient hybrid body parser (KeySource 4) consumes exactly its declared block count
  and does not check that the body ends there, so trailing bytes or extra blocks past the
  count are ignored. All three are harmless today — the whole header is AAD, so appended bytes
  break every frame's authentication — but each means a nonconforming writer's container can
  decrypt. Tightening any would change frozen v2 reader behavior (and the Rust/WASM
  implementation in step), so all are format-v3 candidates, alongside the trailing-data entry
  above.
- **A malformed hybrid recipient block aborts the multi-recipient scan.** In a KeySource-4
  container, a Mode-3 block whose `KemId` is not the one known value raises `PqFormatException`
  out of the block scan, so a later block that *is* for the caller's key is never tried. This
  is fail-closed (no plaintext, no key-dependent oracle — only the format-vs-decryption
  exception type differs), but it means one malformed block from a nonconforming writer denies
  decryption to every recipient listed after it. Switching abort→skip would make the reader
  *accept* containers it currently rejects — a loosening of frozen v2 behavior — so it, too, is
  a format-v3 candidate (a future `KemId` such as ML-KEM-1024 is exactly when skip-and-continue
  would matter).
- **The hybrid KEK combiner does not bind the DH/KEM transcript.** `HKDF(ss_pq ‖ ss_x25519)`
  omits the KEM ciphertext and the ephemeral/recipient public keys from the derivation, unlike
  X-Wing or HPKE. Today this is fully covered by the container design — the serialized header,
  recipient blocks included, is bound as AAD into every chunk, so any mutation of a wrap block
  fails closed at the first frame. But the wrap block is protected by that envelope, not by its
  own construction: any future feature that re-emits KeySource-3/4 blocks outside the chunk-AAD
  envelope (rewrap/rotation tooling, detached key blocks) would inherit real block malleability.
  The combiner is spec-frozen with v2 (`FILE-FORMAT.md`), so transcript binding is a format-v3
  item, recorded here so no rewrap feature ships without it.
- **The hybrid multi-recipient cap is 55.** Each KeySource-4 recipient entry is 1,186 bytes
  and the v2 header's KeyParams length field is a `ushort`, so ⌊65,534 / 1,186⌋ = 55
  recipients fit. The limit is enforced pre-flight (since `1.5.0`) with a clear message
  rather than failing after the wrapping work. Widening the field is a format-v3 candidate;
  for larger audiences today, wrap to a KMS-held group key via `IContentKeyProvider`.
- **No compression, no deduplication.** Out of scope. (Encrypted private-key *files* left
  this list with the `PQKF` format in `1.5.0` — see "Resolved in `1.5.0`" above — but key
  management beyond that framing remains out of scope.)
- **Signatures are detached, with the standard detached-signature limits.** The Signing
  package (`PostQuantum.FileEncryption.Signing`, Ed25519 + ML-DSA-65 over a SHA-512 pre-hash)
  proves *who signed the bytes*, but a `.sig` sidecar is not bound to a file name, path, or
  time, and it cannot prevent **strip-and-resign**: anyone able to read the bytes can discard
  the sidecar and sign the same bytes with their own key. Authenticity is anchored in which
  public key the verifier trusts — distribute public keys over a trusted channel. Signatures
  *embedded in the container* (which would also authenticate the signer to the decryptor)
  require a format change and are the headline candidate for a future `2.0` — see
  [docs/ROADMAP-2.0.md](docs/ROADMAP-2.0.md) and
  [docs/SIGNATURE-FORMAT.md](docs/SIGNATURE-FORMAT.md).
- **Containers are not sender-authenticated by encryption alone.** AES-GCM proves a container
  was not altered after creation, and recipient encryption proves only that the sender knew
  the recipient's *public* key — which is public. Use the Signing package when "who produced
  this file" matters.
- **Atomic-write temp-file cleanup is best-effort.** The file-API write path stages every byte
  in a sibling temp file and only `File.Move`s it into place on full success; on any failure
  (crypto, format, I/O, cancellation) the temp file's deletion is *attempted* but swallows
  exceptions, so an OS-level lock (AV scanner, parallel handle) can leave the temp behind.
  **Destination integrity is preserved either way** — no partial or corrupted file is ever
  moved to the destination path; only the temp file may linger. Operators who need
  guaranteed cleanup of orphaned `*.tmp-*` files should run a periodic sweep.
- **Rename durability on power loss is not guaranteed.** The file write path fsyncs the temp
  file's data before `File.Move`, so a crash cannot leave a *truncated* file at the
  destination. It does **not** fsync the containing directory after the rename (there is no
  portable BCL API for it; Linux would need a P/Invoked directory `fsync`), so a power loss in
  the seconds after a successful return can, on some filesystems, roll the directory entry
  back to the pre-existing file. The fail-safe still holds — the destination is either the old
  file or the new one, never a partial — but callers requiring the rename itself to survive
  immediate power loss should fsync the directory (or the whole volume) themselves.
- **`DecryptAtomicAsync` buffers the whole plaintext in memory.** The all-or-nothing stream
  overload holds the full decrypted output in a `MemoryStream` until the final frame
  authenticates, so peak memory is proportional to plaintext size and it cannot exceed the
  ~2 GiB single-array limit (a larger valid container throws `IOException`, not a `Pq*`
  exception, and `PqDecryptionLimits` does not bound this buffer). For untrusted or large
  inputs, prefer the file APIs (temp-file staging) or the non-atomic stream overload with a
  bounded destination. This is documented on the method; noted here for completeness.

### Demos

- **The .NET demo is Blazor Server, not client-side WebAssembly.** .NET's `AesGcm` is
  unsupported in browser WebAssembly, so the library cannot encrypt in-browser; that demo runs
  the crypto on the server (files in memory, never persisted).
- **A fully client-side browser demo exists** (`samples/pqfe-web`) backed by an independent
  **Rust → WASM** re-implementation of the `.pqfe` format (`samples/pqfe-wasm`). Because it is a
  second implementation, it is a separate codebase to keep in step with the format; it is held
  byte-compatible by cross-implementation tests (Rust decrypts the .NET vectors; .NET decrypts a
  Rust-produced container) **and a live interop CI job** that round-trips fresh random payloads
  in both directions, across chunk boundaries, on every push (`ci.yml` → `interop`). It
  currently supports only the **passphrase** key source — **hybrid/ML-KEM recipient mode is not
  implemented in the Rust/WASM core**.

### Process and assurance gaps

- **Not independently audited.** No third-party cryptographic review has been performed.
  Funded audit engagements are welcome — see [SECURITY.md](SECURITY.md).
- **Continuous fuzzing is wired but young.** Coverage-guided fuzzers run for **both** parsers —
  **cargo-fuzz** (Rust) and **SharpFuzz** (.NET) — validated with no crashes (~330k and ~480k
  executions) and scheduled nightly in CI with a cached corpus (`.github/workflows/fuzz.yml`).
  OSS-Fuzz integration files are ready (`oss-fuzz/`) but upstream onboarding is not yet done, and
  the accumulated corpora are still small. See [docs/FUZZING.md](docs/FUZZING.md).
- **Recipient round-trip is not exercised on this CI host**, which lacks platform ML-KEM; those
  tests self-skip there. The capability gating *is* tested everywhere.
- **NuGet author-signing** requires a code-signing certificate (not configured); nuget.org applies
  repository signatures on publish. The release workflow produces an SBOM and a provenance attestation.
- **Two target frameworks.** `net8.0` and `net10.0`. The public API is identical on both, with
  one behavioral difference: the *deprecated* inline ML-KEM-only recipient mode (PQFE002) relies
  on platform ML-KEM, which ships in .NET 10 — on `net8.0`, `PqKeyPair.IsSupported` is always
  `false` and the mode throws `PlatformNotSupportedException`, exactly as on a .NET 10 host
  without OpenSSL 3.5+/CNG support. The supported path for recipient encryption on either target
  is the Hybrid package, whose ML-KEM-768 and X25519 come from BouncyCastle (fully managed).
  No `netstandard2.0`/`net462` support.

---

*Transparency is a feature. To God be the glory — 1 Corinthians 10:31.*
