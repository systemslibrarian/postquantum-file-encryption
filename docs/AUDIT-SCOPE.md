# Audit Scope Statement

This is the one-page brief a funded review engagement starts from. Where
[AUDIT-GUIDE.md](AUDIT-GUIDE.md) orients a reviewer *inside* the code, this document fixes
the **target, environment, boundaries, and evidence** so an external team (and the sponsor)
can agree on scope before work begins. It is deliberately terse and links out rather than
restating.

## 1. Target

| | |
| --- | --- |
| Repository | `https://github.com/systemslibrarian/postquantum-file-encryption` |
| Audit revision | latest release tag — **`v1.7.1`**, commit **`f062c10`** |
| On-disk formats under review | `.pqfe` **v2** container, `.sig` **v1** sidecar, `PQKF` **v1** key file — all **frozen** for the entire `1.x` line |

Pin the engagement to the tag, not to `main`:

```bash
git clone https://github.com/systemslibrarian/postquantum-file-encryption
cd postquantum-file-encryption
git checkout v1.7.1        # commit f062c10
# Release provenance: verify the tag's published artifacts against their build-provenance
# attestations instead — see docs/SUPPLY-CHAIN.md ("gh attestation verify").
```

The formats are frozen ([CLAUDE.md](../CLAUDE.md) "format freeze"), so the bytes an auditor
reads at `v1.7.1` are the bytes every `1.x` build reads. A finding that requires changing
frozen bytes is a **format-v3 / 2.0** item ([docs/ROADMAP-2.0.md](ROADMAP-2.0.md)), not a
point fix — flag it as such.

## 2. Build and reproduce

| | |
| --- | --- |
| SDK | pinned in [`global.json`](../global.json) — .NET **10.0.3xx** (`rollForward: latestFeature`) |
| Targets | `net8.0` and `net10.0`; identical public API on both |
| Build | `dotnet build -c Release` (warnings are errors) |
| Test | `dotnet test -c Release` (full suite) |
| Determinism | `ContinuousIntegrationBuild`, deterministic + SourceLink; reproducibility proven by [docs/REPRODUCIBLE-BUILDS.md](REPRODUCIBLE-BUILDS.md) and the `reproducibility.yml` workflow |
| SBOM + provenance | produced by `release.yml`; see [docs/SUPPLY-CHAIN.md](SUPPLY-CHAIN.md) |

The net10-only platform ML-KEM path is gated `#if NET10_0_OR_GREATER`; on `net8.0` the
deprecated inline recipient mode fails closed (`IsSupported == false`). A host without
platform ML-KEM (OpenSSL 3.5+/CNG) self-skips those tests — the supported recipient path is
the Hybrid package (managed BouncyCastle), which runs everywhere.

## 3. In scope

The composition, not the primitives. Everything cryptographic is **~2,400 lines across
sixteen files**, enumerated with a per-file "what to check" in
[AUDIT-GUIDE.md](AUDIT-GUIDE.md#the-attack-surface-is-small-on-purpose):

- **Core** — `src/PostQuantum.FileEncryption/Internal/`: key establishment (PBKDF2 /
  Argon2id / inline ML-KEM), the chunked AES-256-GCM engine, container framing/parse, the
  `PQKF` key-file framing, atomic file I/O, the orchestration layer.
- **Hybrid** — `src/PostQuantum.FileEncryption.Hybrid/`: the X25519 + ML-KEM-768 combiner
  and multi-recipient scan.
- **Signing** — `src/PostQuantum.FileEncryption.Signing/`: Ed25519 + ML-DSA-65 dual
  sign/verify over the domain-separated SHA-512 pre-hash.

Invariants to attack and honest first questions:
[AUDIT-GUIDE.md](AUDIT-GUIDE.md#the-invariants-to-attack). Threat model, with the explicit
*does-not-defend-against* list: [THREAT-MODEL.md](THREAT-MODEL.md). Hybrid combiner rationale
vs. X-Wing/HPKE: [HYBRID-COMBINER.md](HYBRID-COMBINER.md).

## 4. Out of scope

Not because they don't matter — because they are third-party, not-our-code, or non-shipping:

- **Cryptographic primitives.** AES-GCM, PBKDF2, HKDF, SHA-512, platform ML-KEM (.NET BCL);
  ML-KEM/X25519/Ed25519/ML-DSA-65 (BouncyCastle); Argon2id (Konscious). Inventory and
  versions: [SECURITY-ARCHITECTURE.md](SECURITY-ARCHITECTURE.md). This library composes them.
- **Cloud provider internals.** `PostQuantum.FileEncryption.Aws`, `.AzureKeyVault`, and
  `.Gcp` wrap vendor SDKs; the SDKs and live-service semantics are out of scope. The
  **binding logic** (encryption context / pinned key id + algorithm / AAD + CRC32C
  verification) is in scope as part of the envelope seam.
- **The Rust → WASM core** (`samples/pqfe-wasm`) is a second implementation of the same
  format, held byte-compatible by cross-implementation tests + a live interop CI job. It is
  *reference for* the format, not the primary audit subject; its own dependency audit runs in
  `ci.yml`.
- **Demos, samples, benchmarks, tooling** (`samples/pqfe-web`, `samples/Pqfe.Cli`, the `pqfe`
  tool, `docs/`, CI scripts).

## 5. Evidence to lean on

- **Test coverage — see §6 below.**
- **Fuzzing.** Coverage-guided harnesses on both parsers (SharpFuzz / cargo-fuzz), nightly in
  CI with committed seed corpora; OSS-Fuzz files ready. [FUZZING.md](FUZZING.md).
- **Known-answer vectors** pin every frozen byte and are cross-checked against the Rust core:
  [TEST-VECTORS.md](TEST-VECTORS.md).
- **Prior review + disposition.** External reading fixed real issues in `1.1.0` (key-zeroing
  on early-failure paths, late multi-recipient cap, inexact progress); two AI-assisted static
  self-reviews are published with a per-finding disposition table
  ([docs/audits/](audits/)), and `1.2.0`'s `PqDecryptionLimits` came out of them.
- **Honest open ledger.** [KNOWN-GAPS.md](../KNOWN-GAPS.md) records every deferred item,
  including format-v3 candidates and the un-zeroable-dependency limitations.

## 6. Test coverage

Measured on `v1.5.0` (`dotnet test --collect:"XPlat Code Coverage"`, default lane):

| Area | Line coverage |
| --- | ---: |
| Overall | ~94% |
| Core (`PostQuantum.FileEncryption`) | ~93% |
| Hybrid | ~97% |
| Signing | ~98% |
| AWS provider | ~87% |
| Azure Key Vault provider | ~84% |

A **90% floor on the crypto core** (Internal + Hybrid + Signing) and a whole-repo regression
gate are enforced via [`codecov.yml`](../codecov.yml). Deliberately-lower spots, called out
so they are not mistaken for oversight:

- **Cloud providers (~84–87%)** are unit-tested against in-process SDK fakes; CI has no cloud
  credentials, so live-service branches are exercised by consumers, not this pipeline
  (KNOWN-GAPS, "Dependency assurance").
- **`FileIo` (~71%)** — the atomic temp-file-plus-move path is fully covered; the residual is
  best-effort cleanup branches that only fire under OS-level failure injection (KNOWN-GAPS,
  "Atomic-write temp-file cleanup is best-effort").

## 7. Reporting and deliverables

Private disclosure channel, response expectations, and credit policy:
[SECURITY.md](../SECURITY.md). There is no paid bounty from the project; a funded engagement
agrees its own deliverables (report, findings with severities, disposition), and every
confirmed finding lands in [CHANGELOG.md](../CHANGELOG.md) and, where it must wait for 2.0,
in [KNOWN-GAPS.md](../KNOWN-GAPS.md). Transparency is the deal: issues are disclosed and
credited, not quietly patched.

---

*To God be the glory — 1 Corinthians 10:31.*
