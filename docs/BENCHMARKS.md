# Benchmarks

What is measured, how to reproduce it, the latest indicative numbers, and an honest
comparison with neighboring tools. Two rules govern this page:

1. **Every number here was actually measured**, and says where and how. Numbers from
   shared CI runners are regression signals, not datasheets.
2. **No numbers are published for other projects.** Cross-tool throughput depends on
   hardware, settings, and what's included in the loop (KDF? I/O? authentication?);
   instead this page gives you the commands to run a fair comparison on *your* hardware.

## The suite

`benchmarks/PostQuantum.FileEncryption.Benchmarks` (BenchmarkDotNet, `[ShortRunJob]`,
`[MemoryDiagnoser]`):

| Class | What it measures |
| --- | --- |
| `ThroughputBenchmarks` | End-to-end passphrase encrypt/decrypt of a 16 MiB buffer, **including one KDF derivation** (PBKDF2-HMAC-SHA256 100k, or Argon2id 8 MiB/1 pass) |
| `HybridThroughputBenchmarks` | End-to-end hybrid (X25519 + ML-KEM-768) encrypt/decrypt of 16 MiB, 1 and 10 recipients; decryption uses the *last* recipient's key (worst-case block scan); plus key-pair generation |

Run locally:

```bash
dotnet run -c Release --project benchmarks/PostQuantum.FileEncryption.Benchmarks -- --filter '*'
```

CI runs the suite weekly (`.github/workflows/benchmarks.yml`) and attaches full
BenchmarkDotNet JSON/Markdown reports to the run as artifacts — that history is the
regression record.

## Indicative numbers

Measured on a shared GitHub Codespace (x64, hardware AES); 16 MiB payloads, one KDF
derivation included per operation. Treat as rough:

| Operation | Key establishment | Approx. throughput |
| --------- | --- | ------------------ |
| Encrypt | PBKDF2 (100k) | ~210 MiB/s |
| Decrypt | PBKDF2 (100k) | ~300 MiB/s |
| Encrypt | Argon2id (8 MiB, 1 pass) | ~390 MiB/s |
| Decrypt | Argon2id (8 MiB, 1 pass) | ~450 MiB/s |

Hybrid-mode numbers (single and 10-recipient) are produced by the same suite; the first
published set will land with the next weekly CI run — check the latest
[Benchmarks workflow artifacts](https://github.com/systemslibrarian/postquantum-file-encryption/actions/workflows/benchmarks.yml)
for current reports.

## How to read the numbers

- **The data plane is the same everywhere.** Chunked AES-256-GCM with hardware AES runs
  at multiple GB/s; what you measure end-to-end is mostly fixed per-file costs being
  amortized.
- **Passphrase mode: the KDF dominates small files — by design.** The default PBKDF2
  cost is 600,000 iterations (OWASP guidance); the benchmark deliberately uses a lighter
  100k so the data plane is visible. Tune via `PqEncryptionOptions`.
- **Hybrid mode: the per-recipient cost is constant, not proportional to file size.**
  Each recipient adds one ML-KEM-768 encapsulation + one X25519 agreement + one 32-byte
  key wrap (~1.2 KiB of header). Encrypting 16 MiB to 10 recipients costs ~10× the key
  establishment of 1 recipient but the identical data plane.
- **Multi-recipient decryption scans blocks.** A recipient holding the last of N keys
  attempts N unwraps (each a decapsulation + agreement + AES-GCM tag check). This is the
  worst case the benchmark reports.

## Comparing against other tools — fairly

Architectural differences that make naive number comparisons misleading
(see [COMPARISON.md](COMPARISON.md) for the full feature matrix):

| | PostQuantum.FileEncryption | age | OpenSSL `enc` |
| --- | --- | --- | --- |
| Data plane | AES-256-GCM, chunked, per-chunk auth | ChaCha20-Poly1305, chunked | selected cipher, **no authentication** in `enc` |
| Passphrase KDF | PBKDF2 600k / Argon2id (tunable) | scrypt | weak legacy derivation by default |
| PQ recipient mode | hybrid X25519 + ML-KEM-768 | none (X25519) | none |
| Process model | in-process library | child process + pipe | child process + pipe |

A fair like-for-like passphrase comparison on your machine:

```bash
# this library (in-process, incl. PBKDF2 100k)
dotnet run -c Release --project benchmarks/PostQuantum.FileEncryption.Benchmarks -- --filter '*Throughput*'

# age (process spawn + scrypt + ChaCha20-Poly1305)
head -c 16M /dev/urandom > /tmp/bench.bin
time age -p -o /tmp/bench.age /tmp/bench.bin
```

Differences in cipher, KDF cost, and process overhead mean either tool can "win"
depending on what you hold constant. For .NET applications the in-process model is the
structural advantage: no child process, no pipe copies, cancellation and progress flow
through your own async code.

---

*To God be the glory — 1 Corinthians 10:31.*
