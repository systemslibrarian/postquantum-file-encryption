# Gold-Standard Self-Assessment

A public, criteria-based self-assessment of where this project stands against what a
"gold standard" cryptographic library should provide. Self-assessment is not independent
validation — the point of publishing it is that every claim below is checkable, every gap
is named, and the list of what's *missing* is as load-bearing as the list of what's done.

Status legend: ✅ done and verifiable · ⚠️ partial, with the limitation stated · ❌ not
done. Last reviewed against: **`1.0.1`**.

## 1. Cryptographic design

| Criterion | Status | Evidence |
| --- | --- | --- |
| No novel cryptography — standard primitives, standard compositions only | ✅ | [SECURITY-ARCHITECTURE.md](SECURITY-ARCHITECTURE.md); primitives from .NET / BouncyCastle / Konscious |
| Authenticated encryption only; no unauthenticated path exists | ✅ | AES-256-GCM everywhere; [FILE-FORMAT.md](FILE-FORMAT.md) |
| Fail-closed: every authenticity failure is indistinguishable, no plaintext on doubt | ✅ | Tamper/truncate/wrong-key tests; no error oracles ([THREAT-MODEL.md](THREAT-MODEL.md)) |
| PQ/T hybrid (not PQ-only) public-key mode, with rationale published | ✅ | X25519 + ML-KEM-768; [HYBRID-COMBINER.md](HYBRID-COMBINER.md) |
| Byte-exact public format specification | ✅ | [FILE-FORMAT.md](FILE-FORMAT.md) (FROZEN v2) + [CONFORMANCE.md](CONFORMANCE.md) |
| Format stability commitment | ✅ | v2 frozen for the 1.x line; [VERSIONING.md](VERSIONING.md) |
| Known-answer test vectors published | ✅ | [TEST-VECTORS.md](TEST-VECTORS.md) |
| Metadata protection (lengths, names) | ❌ | Out of scope for v2; candidate for a future 2.0 ([KNOWN-GAPS.md](../KNOWN-GAPS.md)) |

## 2. Implementation quality

| Criterion | Status | Evidence |
| --- | --- | --- |
| Warnings as errors, latest-recommended analyzers | ✅ | `Directory.Build.props` |
| Public API surface locked against accidental breaks | ✅ | PublicApiAnalyzers, `PublicAPI.Shipped.txt` in both packages |
| Binary compatibility validated against the published baseline | ✅ | `EnablePackageValidation` vs. 1.0.0 |
| Key material zeroed (`CryptographicOperations.ZeroMemory` in `finally`) | ✅ | Throughout `Internal/`; reviewed per change |
| AOT/trim compatible, proven end-to-end | ✅ | `IsAotCompatible` + CI native-AOT publish & round-trip smoke test |
| Async + cancellation honored on all I/O | ✅ | Public API contract; cancellation cleanup tests |
| `string` passphrase overloads cannot be zeroed | ⚠️ | Zeroable byte overloads exist; `string` kept for ergonomics ([KNOWN-GAPS.md](../KNOWN-GAPS.md)) |

## 3. Testing & verification

| Criterion | Status | Evidence |
| --- | --- | --- |
| Fail-closed suite (tamper, truncate, wrong key, bad format) treated as first-class | ✅ | `tests/PostQuantum.FileEncryption.Tests` |
| Coverage-guided fuzzing of both parsers (.NET and Rust) | ✅ | SharpFuzz + cargo-fuzz, nightly CI with cached corpus ([FUZZING.md](FUZZING.md)) |
| OSS-Fuzz onboarding | ⚠️ | Integration files ready (`oss-fuzz/`); upstream onboarding not yet accepted |
| Independent second implementation, held byte-compatible in CI | ⚠️ | Rust/WASM reference (`samples/pqfe-wasm`): pinned vectors both directions **plus a live interop CI job** (fresh random payloads, both directions, every push) — **passphrase key source only**; hybrid recipient mode is .NET-only |
| Code coverage published | ✅ | Codecov badge in README |
| Performance benchmarks tracked over time | ✅ | `benchmarks/` + weekly benchmark CI |

## 4. Supply chain

| Criterion | Status | Evidence |
| --- | --- | --- |
| Deterministic, reproducible builds — verifiable by anyone | ✅ | [REPRODUCIBLE-BUILDS.md](REPRODUCIBLE-BUILDS.md) + `reproducibility.yml` clean-room rebuild |
| SBOM on every release | ✅ | CycloneDX, attached to GitHub Releases |
| Build provenance attestation | ✅ | SLSA-style GitHub attestation on every `.nupkg` |
| OpenSSF Scorecard, public | ✅ | `scorecard.yml`, weekly + on push |
| CodeQL + dependency review | ✅ | `codeql.yml`, `dependency-review.yml` |
| GitHub Actions pinned to commit SHAs | ✅ | All workflows |
| Pre-publish package validation | ✅ | Meziantou validation in `release.yml` |
| Minimal dependency tree, gaps named | ⚠️ | Konscious Argon2id is widely used but unaudited; default KDF (PBKDF2) avoids it ([KNOWN-GAPS.md](../KNOWN-GAPS.md)) |
| NuGet author signing | ❌ | Requires a code-signing certificate (not configured); nuget.org repository signatures apply |
| OpenSSF Best Practices badge | ❌ | Not yet applied for — next process step |

## 5. Transparency

| Criterion | Status | Evidence |
| --- | --- | --- |
| Honest public ledger of gaps and limitations | ✅ | [KNOWN-GAPS.md](../KNOWN-GAPS.md) — kept current per release |
| Threat model with explicit "does NOT defend against" list | ✅ | [THREAT-MODEL.md](THREAT-MODEL.md), [SECURITY.md](../SECURITY.md) |
| Security policy with private disclosure channel | ✅ | GitHub private advisories + email ([SECURITY.md](../SECURITY.md)) |
| Design rationale for security-critical choices published | ✅ | [HYBRID-COMBINER.md](HYBRID-COMBINER.md), [SECURITY-ARCHITECTURE.md](SECURITY-ARCHITECTURE.md) |
| This self-assessment, including its ❌ rows | ✅ | You are reading it |

## 6. Independent validation — the honest gap

| Criterion | Status | Evidence |
| --- | --- | --- |
| Independent cryptographic audit | ❌ | **Not performed.** The project cannot self-fund one; applications to funded-audit programs (OSTIF, GitHub Secure Open Source Fund) are the active path. A scoped audit brief — combiner, multi-recipient logic, container parsing — is effectively pre-written across [HYBRID-COMBINER.md](HYBRID-COMBINER.md) and [THREAT-MODEL.md](THREAT-MODEL.md). Funded engagements welcome: see [SECURITY.md](../SECURITY.md). |
| External adoption / production case studies | ❌ | None published yet |
| Bug bounty | ❌ | No paid bounty; private disclosure + public credit offered |

## 7. Sustainability

| Criterion | Status | Evidence |
| --- | --- | --- |
| Documented support & lifecycle policy | ✅ | [SUPPORT.md](../SUPPORT.md), [VERSIONING.md](VERSIONING.md) |
| Bus factor | ⚠️ | Solo-maintained. Mitigations: frozen format, full spec, second implementation, reproducible builds — the project is designed to be *forkable and verifiable* without its maintainer |
| Contribution path | ✅ | [CONTRIBUTING.md](../CONTRIBUTING.md), [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) |

## Summary

Engineering rigor, transparency, and supply-chain hygiene are at or near the bar.
The open gaps, in priority order:

1. **Independent audit** — blocked on funding, not willingness.
2. **OSS-Fuzz onboarding** and corpus maturity.
3. **OpenSSF Best Practices badge** — process work, no blocker.
4. **Hybrid recipient mode in the second (Rust) implementation** — today the
   cross-implementation guarantee covers the passphrase path only.
5. **Author signing** — blocked on certificate cost.

When a row above changes, this document changes in the same release.

---

*To God be the glory — 1 Corinthians 10:31.*
