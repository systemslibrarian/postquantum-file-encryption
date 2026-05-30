# Roadmap

Where PostQuantum.FileEncryption is and where it's going. This is intentionally honest about
what is production-ready versus experimental versus planned. See
[KNOWN-GAPS.md](KNOWN-GAPS.md) for the full ledger and [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md)
for the detailed hybrid design.

## Now — `0.1.0` (the symmetric engine)

**Production-ready and the recommended path:**

- Passphrase-based file, stream, and in-memory encryption with **AES-256-GCM**.
- Key derivation via **PBKDF2-HMAC-SHA256** (default) or **Argon2id** (memory-hard, opt-in).
- Chunked streaming with bounded memory, progress reporting, cancellation, and atomic file output.
- Fail-closed against wrong passphrase, tampering, reordering, splicing, and truncation.
- A self-contained, specified container format ([docs/FILE-FORMAT.md](docs/FILE-FORMAT.md))
  pinned by cross-checked [test vectors](docs/TEST-VECTORS.md), and a fuzz harness.

**Experimental in the same package** (not part of the stable surface):

- **ML-KEM-768 recipient (public-key) mode** — platform-gated via `PqKeyPair.IsSupported`. Use
  knowingly; the productionized public-key path is below.

`0.x` means the API and on-disk format may still change before `1.0`.

## Next — `v0.2` (hardening & ergonomics)

- Synchronous `ReadOnlySpan<char>` passphrase entry point for callers that never go async.
- Optional progress on the in-memory bytes API and additional convenience overloads as the API
  settles.
- Continued fuzzing/coverage growth; begin pinning the format toward a freeze.

## Later — `v0.3` (post-quantum public-key, in a separate package)

The productionized public-key story ships as **`PostQuantum.FileEncryption.Hybrid`** so the
core stays dependency-light. It will add, behind the same `.pqfe` format:

- **Hybrid X25519 + ML-KEM-768 combiner** (`KeySource = 3`) — secure if *either* primitive is
  later broken. Uses **BouncyCastle** for X25519 (.NET has no built-in X25519).
- **Multiple recipients** (`KeySource = 4`).
- A stable home for public-key recipient encryption (superseding the core's experimental mode).

Full design and the dependency rationale: [docs/ROADMAP-v3.md](docs/ROADMAP-v3.md).

## Toward `1.0`

- Freeze the container format and publish the vectors as a stable conformance spec.
- An independent cryptographic review.
- Wire the optional delegation seam to `PostQuantum.FileFormat` if/when that package is published.

---

*To God be the glory — 1 Corinthians 10:31.*
