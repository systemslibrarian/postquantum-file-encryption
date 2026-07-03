# Rust fuzz seed corpus

Curated, committed starting inputs for the `cargo-fuzz` `decrypt` target
(`pqfe_wasm::decrypt_bytes`). These are the byte-exact passphrase known-answer vectors from
[docs/TEST-VECTORS.md](../../../../docs/TEST-VECTORS.md), Base64-decoded — each is a valid,
authenticated container, so the fuzzer starts from real structure instead of rediscovering
the magic bytes and header layout from zero.

Only the **passphrase** key source is seeded here: the Rust core does not implement the
hybrid/ML-KEM recipient mode (see [KNOWN-GAPS.md](../../../../KNOWN-GAPS.md)), so recipient
containers are not reachable decrypt inputs for this target.

| File | Vector | Exercises |
| --- | --- | --- |
| `passphrase-pbkdf2.pqfe` | 1 | PBKDF2 header |
| `passphrase-argon2id.pqfe` | 2 | Argon2id header parse |
| `passphrase-pbkdf2-rustcore.pqfe` | 3 | 65 KiB chunk boundary |

The **working** corpus (`fuzz/corpus/decrypt/`) is `.gitignore`d because it accumulates
fuzzer-discovered inputs across CI runs; CI copies these seeds into it before each run
(`.github/workflows/fuzz.yml`). Locally:

```bash
mkdir -p fuzz/corpus/decrypt && cp fuzz/seed-corpus/* fuzz/corpus/decrypt/
cargo +nightly fuzz run decrypt -- -max_total_time=60
```

*To God be the glory — 1 Corinthians 10:31.*
