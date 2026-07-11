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
