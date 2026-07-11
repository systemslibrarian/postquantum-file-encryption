# Crypto-Agility — What Happens When the Algorithms Have to Change

The unspoken question behind every post-quantum library choice: *when ML-KEM-768 needs to
become ML-KEM-1024, when the combiner should become X-Wing, when AES-GCM needs a sibling —
what happens to my files?* This page answers it in one place. The mechanics live in
[VERSIONING.md](VERSIONING.md), [ROADMAP-2.0.md](ROADMAP-2.0.md), and
[HYBRID-COMBINER.md](HYBRID-COMBINER.md); this is the forward story they add up to.

## The mechanism: versioned bytes, additive registries

Agility here is structural, not aspirational:

- **Every container leads with a `FormatVersion` byte** (currently `2`). A reader rejects
  versions it does not understand — it never guesses.
- **Key establishment is a registry, not a hardcode.** The header's `KeySource` byte and
  the hybrid block's `KemId` byte exist precisely so that new algorithms are **new
  values**, which old readers reject fail-closed — never mutations of existing ones.
  Adding a `KeySource` is non-breaking at the format level and ships as a `1.x` minor;
  that is exactly how the Hybrid path, the Signing sidecar, and the `PQKF` key file all
  shipped without touching a single frozen byte.
- **The frozen format is pinned by force, not policy:** byte-exact known-answer vectors
  ([TEST-VECTORS.md](TEST-VECTORS.md), committed as binaries in
  [`test-vectors/`](../test-vectors/)) are checked by two independent implementations on
  every change. An accidental algorithm or layout change cannot pass CI.

## The concrete upgrade paths

**ML-KEM-768 → ML-KEM-1024, or a new component algorithm.** A new `KemId` / `KeySource`
value — additive, shippable in `1.x` if it only *adds* bytes readers can reject. The
adoption bar ([HYBRID-COMBINER.md](HYBRID-COMBINER.md)): a finished standard plus a
maintained .NET implementation. This library composes primitives; it never implements them.

**The combiner → X-Wing or HPKE.** Same bar, but a combiner change alters what existing
bytes *mean*, so it is a format-v3 event, considered in the order of preference documented
in HYBRID-COMBINER.md (X-Wing as published → HPKE with a standardized hybrid KEM →
component swaps).

**A second AEAD (ChaCha20-Poly1305), embedded signatures, metadata protection.** All
change the container layout → format v3, package `2.0`. The candidate set is maintained in
[ROADMAP-2.0.md](ROADMAP-2.0.md); the [KNOWN-GAPS.md](../KNOWN-GAPS.md) ledger is where
breaking improvements wait so they ship deliberately, together, once.

## The guarantee your existing ciphertext gets

- **Within `1.x`: no migration, ever.** The freeze is the migration policy. A file
  encrypted by any `1.x` build opens with every other `1.x` build, in either
  implementation.
- **Across `2.0`:** the new major ships **documented migration tooling** (a
  rewrap/transcode path — re-wrapping the small content key, not re-encrypting terabytes),
  and the last `1.x` minor keeps receiving security fixes for **at least 12 months** after
  `2.0` tags ([SUPPORT.md](../SUPPORT.md)). Your v2 files do not rot on a schedule.

## The harvest-now-decrypt-later answer, plainly

Data confidentiality never rests on one assumption:

- The **data plane is AES-256-GCM** — ≈128-bit security against a Grover adversary,
  independent of any KEM. A passphrase-encrypted file's PQ resistance needs no algorithm
  migration at all.
- The **recipient path is hybrid**: an attacker recording ciphertext today needs to break
  **both** X25519 **and** ML-KEM-768 to ever recover the content key.
- If a component *is* broken someday, the failure is contained to the key-establishment
  layer, the registry mechanism above carries the replacement, and the rewrap path
  re-protects existing files without touching their payload bytes.

## What will never change

Format versions change bytes, not posture. The [non-negotiable
principles](../CLAUDE.md) hold across every version: no homegrown cryptography,
authenticated encryption only, fail closed with no oracles, transparency over reassurance.

---

*To God be the glory — 1 Corinthians 10:31.*
