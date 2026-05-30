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
| Coverage-guided (.NET) | `PqFileDecryptor.DecryptBytesAsync` | libFuzzer via **SharpFuzz** | `fuzz/PostQuantum.FileEncryption.Fuzz` |
| Scheduled / cumulative | both | nightly workflow, cached corpus | `.github/workflows/fuzz.yml` |
| Continuous (upstream) | Rust target | OSS-Fuzz | `oss-fuzz/` (ready to submit) |

## Validation

Both coverage-guided harnesses have been run and found **no crashes**:

- **Rust / cargo-fuzz:** ~330,000 executions (discovered the magic bytes and the Argon2id path).
- **.NET / SharpFuzz:** ~480,000 executions.

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
