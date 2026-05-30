# Known Gaps

This document is the honest ledger for PostQuantum.FileEncryption. It records what is
incomplete, deferred, or imperfect, so that nobody has to discover it by reading the source
or, worse, in production. If you find a gap not listed here, that itself is a gap — please
open an issue.

Last reviewed against: **`0.1.0`**. See [ROADMAP.md](ROADMAP.md) for the forward plan.

## Release scope (read this first)

- **The stable, released engine is symmetric and passphrase-based:** AES-256-GCM with
  PBKDF2-HMAC-SHA256 or Argon2id. AES-256 is quantum-resistant for the *confidentiality of the
  data itself*. This is what is finalized for release.
- **The post-quantum *public-key* (key-establishment) story is not finished in the core.** An
  ML-KEM-768 recipient mode is **included but experimental and platform-gated** (`PqKeyPair`,
  `PqKeyPair.IsSupported`). The productionized path — a hybrid **X25519 + ML-KEM** combiner and
  multiple recipients — is **planned for a separate `PostQuantum.FileEncryption.Hybrid`
  package** (BouncyCastle for X25519); see [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md).

## Resolved since the first symmetric cut

- **Memory-hard KDF** — Argon2id is selectable via `PqEncryptionOptions.Kdf`.
- **Zeroable passphrases** — `ReadOnlyMemory<byte>` passphrase overloads are available.
- **Test vectors and fuzzing** — pinned known-answer vectors and a mutation/truncation fuzz
  harness are in the test suite, cross-checked against the Rust/WASM implementation.

## Still open

### "Wrapper around PostQuantum.FileFormat" — seam built, not wired

The stated long-term goal is for this library to be a delightful, high-level wrapper over the
lower-level **PostQuantum.FileFormat**. As of this release:

- **PostQuantum.FileFormat is still not published** and is not a referenced dependency.
- v0.2 ships a **self-contained reference container** (see
  [docs/FILE-FORMAT.md](docs/FILE-FORMAT.md)) implemented directly on platform primitives.
- The delegation **seam exists** (`Internal/IPqContainerCodec`, with the orchestration in
  `Internal/PqContainer`). When PostQuantum.FileFormat is available, an alternative codec can
  be dropped in behind the unchanged public API. **This is intentionally not done yet** — there
  is nothing to wire to.

### Cryptographic scope

- **Recipient mode is KEM-DEM, not a PQ+classical combiner.** It relies on ML-KEM-768 alone for
  the asymmetric step. A combined X25519 + ML-KEM hybrid is **designed** in
  [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md) but not implemented — .NET has no built-in X25519, so
  it needs a dependency decision, and it needs an ML-KEM-capable host to test.
- **Single recipient per container.** Multi-recipient is **designed** in
  [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md), not yet implemented.
- **Passphrases are still `string` on the convenience overloads.** The zeroable byte overloads
  exist, but the `string` overloads remain for ergonomics and cannot zero the caller's `string`.

### Dependency assurance

- **Argon2id comes from `Konscious.Security.Cryptography`**, a widely used but **not formally
  audited** managed implementation. The default KDF (PBKDF2) avoids this dependency at runtime.

### Format and feature gaps

- **The container format is not frozen.** No cross-version migration tooling exists, and v0.2
  does not read the v0.1 format. Do not store preview-encrypted data you must read with a
  `1.0+` build.
- **Metadata is not protected.** Plaintext length is revealed to within a chunk; file names,
  paths, and timestamps are not encrypted or carried.
- **No streaming all-or-nothing guarantee.** `DecryptAsync(Stream, Stream, …)` authenticates
  each chunk before writing it, but a stream cannot be un-written, so a truncation detected at
  the final frame leaves earlier (authentic) chunks already emitted. The **file** APIs avoid
  this with temp-file-plus-atomic-move; stream callers who need strict atomicity should buffer.
- **No compression, no deduplication, no key files.** Out of scope.

### Demos

- **The .NET demo is Blazor Server, not client-side WebAssembly.** .NET's `AesGcm` is
  unsupported in browser WebAssembly, so the library cannot encrypt in-browser; that demo runs
  the crypto on the server (files in memory, never persisted).
- **A fully client-side browser demo exists** (`samples/pqfe-web`) backed by an independent
  **Rust → WASM** re-implementation of the `.pqfe` format (`samples/pqfe-wasm`). Because it is a
  second implementation, it is a separate codebase to keep in step with the format; it is held
  byte-compatible by cross-implementation tests (Rust decrypts the .NET vectors; .NET decrypts a
  Rust-produced container). It currently supports only the **passphrase** key source — **ML-KEM
  recipient mode is not implemented in the Rust/WASM core**.

### Process and assurance gaps

- **Not independently audited.** No third-party cryptographic review has been performed.
- **Recipient round-trip is not exercised on this CI host**, which lacks platform ML-KEM; those
  tests self-skip there. The capability gating *is* tested everywhere.
- **Single target framework.** `net10.0` only; no down-level support.

---

*Transparency is a feature. To God be the glory — 1 Corinthians 10:31.*
