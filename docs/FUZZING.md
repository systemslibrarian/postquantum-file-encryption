# Fuzzing

The `.pqfe` parser is the most security-sensitive code that touches **attacker-controlled** bytes,
so it is fuzzed from several angles. The contract under test is **fail-closed robustness**: for
*any* input, decryption must either return the plaintext or a typed `PqEncryptionException` /
`PqError` — never a crash, panic, hang, or unexpected exception.

## Layers

| Layer | Target | Engine | Where |
| --- | --- | --- | --- |
| In-repo randomized tests | both parsers | property/mutation | `FuzzTests.cs`, `PropertyTests.cs`, Rust `tests/vectors.rs` (run every CI build) |
| Coverage-guided (Rust) | `pqfe_wasm::decrypt_bytes` | libFuzzer via **cargo-fuzz** | `samples/pqfe-wasm/fuzz` |
| Coverage-guided (.NET) | `PqFileDecryptor.DecryptBytesAsync` + the `PQKF` key-file parser | libFuzzer via **SharpFuzz** | `fuzz/PostQuantum.FileEncryption.Fuzz` |
| Scheduled / cumulative | both | nightly workflow, cached corpus | `.github/workflows/fuzz.yml` |
| Continuous (upstream) | Rust target | OSS-Fuzz | `oss-fuzz/` (ready to submit) |

## Validation

Both coverage-guided harnesses have been run and found **no crashes**:

- **Rust / cargo-fuzz:** ~330,000 executions (discovered the magic bytes and the Argon2id path).
- **.NET / SharpFuzz:** ~480,000 executions.

## Seed corpus

The repository does **not** commit a corpus: CI accumulates one in the `actions/cache` keyed by
run id (see [Scheduled CI](#scheduled-ci)), which keeps the tree small but means a fresh clone —
or an external audit environment — starts cold. To reproduce meaningful coverage quickly, seed the
corpus from the pinned known-answer vectors in [TEST-VECTORS.md](TEST-VECTORS.md): each is a
Base64-encoded, byte-exact valid container, so the fuzzer starts from real structure (magic,
header, KDF/KEM blocks, authenticated frames) instead of rediscovering it. For example, seeding the
Rust target with Vector 1:

```bash
mkdir -p samples/pqfe-wasm/fuzz/corpus/decrypt
# Vector 1 (passphrase, PBKDF2) from docs/TEST-VECTORS.md — decode Base64 into the corpus dir:
base64 -d > samples/pqfe-wasm/fuzz/corpus/decrypt/vector1.pqfe <<'EOF'
UFFGRQIBAQAAAAQAJo6h8gAWARBX1MFqqxklHk56hMpD/FOOAAGGoAEAAAAyj/fP3REMAehh9VkK47SfhqQqgW68lRjDYDqIhW+b+6ytzaFAGCYaqA5JyaVkf24z17nYMoDST2h5xVdPtgEB23Fj
EOF
```

Repeat for the other vectors (the Argon2id, cross-impl, `PQKF` key-file, and hybrid-recipient
vectors each exercise a different parse path) and point the `.NET` target's `corpus` directory at
the same files. This is optional — both harnesses discover the format unaided (the execution counts
below were reached from an empty corpus) — but seeding turns hours of cold-start discovery into
minutes.

## Run it locally

### Rust (cargo-fuzz)

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cd samples/pqfe-wasm
cargo +nightly fuzz run decrypt -- -max_total_time=60
```

### .NET (SharpFuzz)

Needs `clang` and the `sharpfuzz` tool. One-time driver build:

```bash
dotnet tool install -g SharpFuzz.CommandLine
curl -sSL https://raw.githubusercontent.com/Metalnem/libfuzzer-dotnet/master/libfuzzer-dotnet.cc -o libfuzzer-dotnet.cc
clang -g -O2 -fsanitize=fuzzer libfuzzer-dotnet.cc -o libfuzzer-dotnet

dotnet publish fuzz/PostQuantum.FileEncryption.Fuzz -c Release -o fuzzpub
sharpfuzz fuzzpub/PostQuantum.FileEncryption.dll
./libfuzzer-dotnet --target_path=dotnet --target_arg="$PWD/fuzzpub/PostQuantum.FileEncryption.Fuzz.dll" \
  corpus -max_total_time=60
```

> Harness note: the SharpFuzz harness creates the decryptor **inside** the `Fuzzer.LibFuzzer.Run`
> callback. SharpFuzz only sets up its coverage shared memory once `Run` starts, so calling any
> instrumented method (even a constructor) earlier would crash the harness, not the parser.
> Each iteration feeds the same input to **both** .NET targets — the container parser and the
> `PQKF` encrypted key-file parser (the framing check fails fast on non-`PQKF` input, so the
> second target is nearly free). The key-file target runs under `PqDecryptionLimits.Untrusted`
> so a fuzzer-crafted Argon2id header cannot turn one iteration into a gigabyte-scale KDF.

## Scheduled CI

`.github/workflows/fuzz.yml` runs both targets nightly (and on demand via *Run workflow*), caches
the corpus so coverage accumulates, fails the job on a crash, and uploads the reproducing input as
an artifact.

## OSS-Fuzz

`oss-fuzz/` contains `project.yaml`, `Dockerfile`, and `build.sh` for the Rust target, ready to
submit as a PR to [google/oss-fuzz](https://github.com/google/oss-fuzz) — see
[oss-fuzz/README.md](../oss-fuzz/README.md). Onboarding (acceptance into OSS-Fuzz) is the only
external step.

*To God be the glory — 1 Corinthians 10:31.*
