# Security reviews

The transparency record of every security review of this library — what was run, what it
found, and what happened to each finding. Self-review is published here with the same
honesty rules as everything else: it is labeled as self-review, and it does not substitute
for the independent audit tracked as the top gap in
[GOLD-STANDARD.md](../GOLD-STANDARD.md) §6.

## 2026-06-12 — AI-assisted static self-review (two independent runs)

Two independent AI-assisted static source reviews of the full tree at `1.1.0`, driven by
adversarial audit templates and verified by the maintainer. No runtime or fuzz execution in
these passes. Both runs agreed: every critical attack class (nonce reuse, tag bypass,
combiner downgrade, format confusion, oracle leakage, partial plaintext at the real
destination) **did not reproduce**, and the confirmed findings were Medium/Low availability
hardening items.

- [Run A — security audit](2026-06-12-static-self-review-run-a.md)
- [Run B — adversarial audit](2026-06-12-static-self-review-run-b.md)

| Finding | Severity | Disposition |
| --- | --- | --- |
| PQFE-001 — hostile header can demand 2 GiB Argon2id before auth | Medium | **Fixed in 1.2.0** — `PqDecryptionLimits` decrypt-time cost ceilings |
| PQFE-002 — declared chunk size drives ~32 MiB allocation | Low | **Fixed in 1.2.0** — buffers capped by the container's known length |
| PQFE-003 — stream decrypt emits authentic prefix before truncation throws | Low (disclosed) | **Docs steered in 1.2.0** — README points untrusted stream callers to `DecryptAtomicAsync` / the file API |
| PQFE-004 — CLI `--passphrase-env` exposure | Low | **Fixed in 1.2.0** — caveat added to CLI help |
| PQFE-005 — temp-file lifetime on hard crash / OS lock | Low (disclosed) | No change — documented in [KNOWN-GAPS.md](../../KNOWN-GAPS.md) |
| PQFE-006 — BouncyCastle key copies unzeroable until GC | Low (disclosed) | No change — dependency limitation, documented |
| PQFE-007 — `string` passphrase overloads cannot be zeroed | Informational | No change — zeroable byte overloads exist, documented |

Want to run your own review? Start at [AUDIT-GUIDE.md](../AUDIT-GUIDE.md) — the
attack-surface map, the invariants to attack, and how to report what you find.

---

*To God be the glory — 1 Corinthians 10:31.*
