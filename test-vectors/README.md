# Committed Test-Vector Artifacts — verify in 30 seconds

These are the **known-answer vectors from [docs/TEST-VECTORS.md](../docs/TEST-VECTORS.md)
as ready-to-use binary files** — the same bytes, Base64-decoded, committed so that "the
.NET and Rust implementations produce identical output" is something you can check, not
something you have to take on faith. They are frozen with the `.pqfe` v2 format for the
entire `1.x` line: these files must never change, and a CI test
(`VectorArtifactTests`) fails if they do.

| File | Vector | What it pins |
| --- | --- | --- |
| `passphrase-pbkdf2.pqfe` | 1 | Passphrase container, PBKDF2-HMAC-SHA256 |
| `passphrase-argon2id.pqfe` | 2 | Passphrase container, Argon2id (cross-implementation KDF agreement) |
| `passphrase-pbkdf2-rustcore.pqfe` | 3 | Produced by the **Rust core**, read by .NET |
| `keyfile.pqkf` | 5 | `PQKF` v1 encrypted key file framing |
| `hybrid-recipient.pqfe` | 6 | X25519 + ML-KEM-768 hybrid wrap block and combiner |

## The machine-readable manifest and the full conformance corpus

[`manifest.json`](manifest.json) is the machine-readable index for the whole corpus — every
vector with its SHA-256, the outcome a conforming reader must produce (`accept`,
`reject-format`, or `reject-decryption`), and, for accepts, the passphrase and expected
plaintext. Alongside the positive vectors above it pins:

- **`negative/`** — malformed containers a conforming reader must **reject**, each a
  single deterministic mutation of `passphrase-pbkdf2.pqfe`: bad magic, bad version, unknown
  AEAD/key-source, out-of-range chunk size and PBKDF2 iterations, header/ciphertext tamper, and
  tag/prefix truncation (plus a wrong-passphrase case that needs no new file).
- **`lenient/`** — well-formed containers that exercise the **frozen v2 reader leniencies**
  documented in [docs/CONFORMANCE.md](../docs/CONFORMANCE.md) §2.2 (a nonzero reserved `Flags`
  byte, trailing bytes in passphrase `KeyParams`, trailing bytes after the final frame, and a
  block past a multi-recipient count). A conforming `1.x` reader must **accept** these; they are
  format-v3 candidates that a future strict profile may tighten.

Both implementations run the identical corpus: the .NET `ConformanceManifestTests` and the Rust
core's `tests/conformance.rs`. To regenerate the corpus after a *deliberate* format revision,
run the generator with `PQFE_REGEN_VECTORS=1` (see `tests/.../ConformanceVectors.cs`) — never to
make a failing test pass.

## Verify in 30 seconds

The three passphrase vectors open with the `pqfe` CLI and the **published** passphrases —
no code required:

```bash
dotnet tool install -g PostQuantum.FileEncryption.Tool

PQFE_PASS='test-vector-passphrase' \
  pqfe decrypt passphrase-pbkdf2.pqfe vector1.txt --passphrase-env PQFE_PASS
cat vector1.txt
# → PostQuantum.FileEncryption known-answer vector v2.
```

(Vector 2 uses the same passphrase; vector 3 uses `cross-impl-passphrase` and was
*encrypted by the Rust implementation* — decrypting it with the .NET tool is the
cross-implementation proof in one command.)

Check the artifacts themselves against their pinned hashes:

```bash
sha256sum -c SHA256SUMS
```

The hybrid and key-file vectors need private keys / typed importers, so they are verified
by the test suites instead:

```bash
dotnet test --filter "FullyQualifiedName~KnownAnswerVector|FullyQualifiedName~VectorArtifact"
cd samples/pqfe-wasm && cargo test    # the independent Rust implementation, same bytes
```

## Provenance

Each file decodes byte-for-byte from the Base64 in
[docs/TEST-VECTORS.md](../docs/TEST-VECTORS.md) (the normative copy), and is byte-identical
to the fuzzing seed corpus (`fuzz/PostQuantum.FileEncryption.Fuzz/seed-corpus/`). The
expected plaintexts, KDF parameters, and (where applicable) private keys are all published
in that document — every key here was generated solely for its vector and protects nothing.

A change to any of these files is a **breaking format change** and cannot happen inside
`1.x` — see the freeze rules in [docs/VERSIONING.md](../docs/VERSIONING.md).

---

*To God be the glory — 1 Corinthians 10:31.*
