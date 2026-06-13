# Disposition: consolidated external-model audit findings (2026-06-12)

> **What this is.** A consolidated list of six findings was assembled from two earlier
> AI-assisted reviews of this repository (a Gemini review and a chat-session review,
> circulated as `gem4.md` / `chat5.md` / `gem55.md`). This document records the per-finding
> disposition after re-verifying each against the current tree, in the same self-review
> spirit as the run-A/run-B reports: **not an independent audit**.

All six findings were **real when found** and were **remediated in `1.1.0`** (see the 1.1.0
entries in [CHANGELOG.md](../../CHANGELOG.md)); each was re-verified as fixed at the current
head during the `1.4.0` development cycle.

| # | Finding | Disposition |
| --- | --- | --- |
| 1 | CEK left unzeroed if `ContainerHeader.Create` throws before the codec is entered | **Fixed (1.1.0), verified.** Every encrypt path in `Internal/PqContainer.cs` wraps header creation + codec write in `try/finally { CryptographicOperations.ZeroMemory(contentKey) }`. |
| 2 | Long-term private-key copies (`.ToArray()` for BouncyCastle) abandoned on the heap | **Fixed (1.1.0), verified.** `Hybrid/Internal/HybridKeyEstablishment.cs` zeroes the ML-KEM and X25519 key copies in `finally` immediately after last use. BouncyCastle's own internal copies cannot be zeroed — recorded in [KNOWN-GAPS.md](../../KNOWN-GAPS.md). |
| 3 | Multi-recipient validation accepted up to 255 recipients while the format caps at 55 | **Fixed (1.1.0), verified.** `PqHybridEncryptor.ValidateRecipients` enforces `HybridKeyEstablishment.MaxRecipients` (55, derived from the header's `uint16` KeyParams cap) up front with a clear message. |
| 4 | The 56-recipient failure path stranded the generated CEK unzeroed | **Fixed (1.1.0), verified.** `PqHybridEncryptor.EncryptToAsync` wraps key wrapping + header creation in the same `try/finally` zeroing pattern as the core. |
| 5 | Decrypt progress reported ciphertext totals, so `Fraction` never reached 1.0 | **Fixed (1.1.0), verified.** `Internal/PqContainerEngine.cs` derives `totalPlaintextBytes` from the container length (`DerivePlaintextTotal`) and reports plaintext totals; `Fraction` reaches 1.0. |
| 6 | `LocalKekContentKeyProvider.Generate()` left a second, never-zeroed KEK copy | **Fixed (1.1.0), verified.** `Generate()` zeroes the intermediate copy in `finally` after the constructor clones it. |

## Carried forward

Re-reviewing with this lens during `1.4.0` development found one analogous (finding-1-class)
window in new code before it ever shipped: `AwsKmsContentKeyProvider.WrapNewKeyAsync` could
leave the KMS-returned data key unzeroed if serialization of the wrap info threw. Fixed in
the same change that adds this document — the post-`GenerateDataKey` steps are wrapped in a
`catch { ZeroMemory; throw; }` so the caller owns the key only once it is actually returned.

---

*Transparency is a feature. To God be the glory — 1 Corinthians 10:31.*
