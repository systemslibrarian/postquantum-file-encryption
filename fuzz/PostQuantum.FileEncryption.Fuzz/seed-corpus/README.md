# .NET fuzz seed corpus

Curated, committed starting inputs for the SharpFuzz harness
(`PqFileDecryptor.DecryptBytesAsync` + the `PQKF` key-file parser). These are the
byte-exact known-answer vectors from [docs/TEST-VECTORS.md](../../../docs/TEST-VECTORS.md),
Base64-decoded — every one is a valid, authenticated container, so the fuzzer starts from
real structure (magic, header, KDF/KEM blocks, authenticated frames) instead of
rediscovering the format from zero.

| File | Vector | Exercises |
| --- | --- | --- |
| `passphrase-pbkdf2.pqfe` | 1 | KeySource 0/1, PBKDF2 header |
| `passphrase-argon2id.pqfe` | 2 | Argon2id header parse |
| `passphrase-pbkdf2-rustcore.pqfe` | 3 | Rust-core-produced container (65 KiB chunk) |
| `hybrid-recipient.pqfe` | 6 | KeySource 3 hybrid wrap block |
| `keyfile.pqkf` | 5 | `PQKF` framing + embedded v2 body |

The **working** corpus (`/dotnet-corpus/`, CI-cached, coverage-accumulating) is *not*
committed; CI copies these seeds into it before each run
(`.github/workflows/fuzz.yml`). To reproduce locally, point the libFuzzer driver's corpus
argument at a directory seeded from here — see [docs/FUZZING.md](../../../docs/FUZZING.md).

Regenerate after a (major-version) vector change:
`base64 -d` each block in `docs/TEST-VECTORS.md` whose payload begins with `UFFGRQ`
(`.pqfe`) or `UFFLRg` (`PQKF`).

*To God be the glory — 1 Corinthians 10:31.*
