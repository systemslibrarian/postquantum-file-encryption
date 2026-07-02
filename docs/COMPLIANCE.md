# Compliance & post-quantum migration mapping

Engineers rarely get to adopt a cryptography library on technical merit alone — someone has
to defend the choice to a compliance officer, an auditor, or a customer questionnaire. This
page maps the library to the frameworks those conversations cite, in both directions:
**what it satisfies, and — stated just as plainly — what it does not.** Overclaiming would
be a disservice to exactly the organizations that most need harvest-now-decrypt-later
protection. Primary sources: [SECURITY-ARCHITECTURE.md](SECURITY-ARCHITECTURE.md) (crypto
inventory, FIPS posture), [THREAT-MODEL.md](THREAT-MODEL.md), and
[KNOWN-GAPS.md](../KNOWN-GAPS.md).

## The threat driving the mandates

**Harvest now, decrypt later (HNDL):** an adversary records encrypted data today and
decrypts it once a cryptographically relevant quantum computer exists. Data whose
confidentiality must outlive that horizon — health records, legal files, government data,
long-lived intellectual property — needs quantum-resistant protection *now*, which is what
the U.S. federal migration mandates are about.

How this library answers it:

- **Symmetric path (passphrase / KMS envelope):** AES-256-GCM. Grover's algorithm halves the
  effective key strength, leaving ≈128-bit post-quantum security — the standard analysis
  behind "AES-256 is quantum-resistant for confidentiality." No migration needed.
- **Public-key path (Hybrid package):** X25519 + **ML-KEM-768 (FIPS 203)** in a combiner
  where an attacker must break *both*. The classical half defends against implementation
  surprises in the young PQ standard; the PQ half defends against the quantum future.
- **Signatures (Signing package):** Ed25519 + **ML-DSA-65 (FIPS 204)**, both required to
  verify.

## Mapping to the frameworks

| Framework / driver | What it asks | Where this library stands |
| --- | --- | --- |
| **OMB M-23-02** (federal PQC migration) | Inventory cryptography; prioritize migration of systems protecting long-lived data. | The full cryptographic inventory is published in [SECURITY-ARCHITECTURE.md](SECURITY-ARCHITECTURE.md) — the artifact an inventory exercise needs. Data-at-rest file encryption with FIPS 203/204 primitives is available today. |
| **NIST FIPS 203 / 204** | Standardized ML-KEM / ML-DSA. | ML-KEM-768 (Hybrid package; also core's experimental inline mode on .NET 10) and ML-DSA-65 (Signing package). Parameter sets are NIST security category 3. |
| **NIST SP 1800-38** (migration practice guide) | Hybrid classical+PQ constructions during transition. | The Hybrid package is exactly this posture: X25519 + ML-KEM-768, with the combiner design published and compared to X-Wing/HPKE in [HYBRID-COMBINER.md](HYBRID-COMBINER.md). |
| **CNSA 2.0** (NSA, for National Security Systems) | ML-KEM-**1024** / ML-DSA-**87**, AES-256, SHA-384/512. | **Partially.** AES-256 and SHA-512 usage align; the KEM/signature parameter sets here are 768/65 (category 3), not the 1024/87 CNSA 2.0 requires. **This library does not claim CNSA 2.0 compliance**; larger parameter sets are a candidate for the 2.0 format ([ROADMAP-2.0.md](ROADMAP-2.0.md)). NSS use is out of scope. |
| **FIPS 140-3** (validated modules) | Cryptography performed by validated modules. | **No validation is claimed.** The core's FIPS-compatible path exists: AES-GCM, PBKDF2, HKDF, and the RNG route to the platform's validated module (Windows CNG / OpenSSL in FIPS mode) with the default PBKDF2 KDF. **Not on that path:** Argon2id (Konscious, managed) and the Hybrid/Signing packages (BouncyCastle, managed). FIPS-constrained deployments: core package, default KDF, platform in FIPS mode — details in [SECURITY-ARCHITECTURE.md](SECURITY-ARCHITECTURE.md). |
| **NIST SP 800-171 / CMMC** (CUI, defense supply chain) | 3.13.11: FIPS-validated cryptography when protecting CUI confidentiality; 3.8.9: protect backups. | The mechanism (AES-256-GCM at rest, via platform modules on the FIPS-compatible path) fits; whether a given deployment *satisfies* 3.13.11 depends on the operating environment and assessor — the module validation belongs to the OS, not this library. |
| **HIPAA / state privacy laws** (breach safe harbor) | Encryption of data at rest per NIST guidance renders lost media unreadable. | Authenticated AES-256-GCM file encryption with strong KDFs is the intended mechanism class. Key management remains the deployer's responsibility ([KEY-MANAGEMENT.md](KEY-MANAGEMENT.md)). |

## What this library does NOT give you

Stated plainly, because a compliance conversation that discovers these later goes badly:

1. **No FIPS 140-3 validation of its own** — and the Hybrid/Signing packages cannot ride the
   platform-module path at all today (BouncyCastle provides their primitives).
2. **Not CNSA 2.0 parameter sets.** ML-KEM-768/ML-DSA-65, not 1024/87.
3. **No independent audit yet.** The self-assessment, external-model review dispositions,
   and reviewer's guide are published ([GOLD-STANDARD.md](GOLD-STANDARD.md),
   [audits/](audits/), [AUDIT-GUIDE.md](AUDIT-GUIDE.md)) — transparency is not the same
   thing as third-party assurance.
4. **Data at rest only.** This is file/stream encryption — not TLS, not messaging, not a
   full key-management system.
5. **Metadata is not protected** (sizes, KDF parameters, recipient counts are visible), and
   compliance obligations about access control, audit logging, and retention live entirely
   outside the envelope.

## Answering the questionnaire

The evidence artifacts, in the order security questionnaires usually ask for them: crypto
inventory ([SECURITY-ARCHITECTURE.md](SECURITY-ARCHITECTURE.md)) · specification and test
vectors ([FILE-FORMAT.md](FILE-FORMAT.md), [TEST-VECTORS.md](TEST-VECTORS.md)) · threat
model ([THREAT-MODEL.md](THREAT-MODEL.md)) · SBOM and signed provenance on every release
([SUPPLY-CHAIN.md](SUPPLY-CHAIN.md)) · reproducible builds
([REPRODUCIBLE-BUILDS.md](REPRODUCIBLE-BUILDS.md)) · vulnerability disclosure policy
([SECURITY.md](../SECURITY.md)) · known limitations ([KNOWN-GAPS.md](../KNOWN-GAPS.md)).

*To God be the glory — 1 Corinthians 10:31.*
