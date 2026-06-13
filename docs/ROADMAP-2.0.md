# Roadmap — `2.0` (container format v3)

> **Status: planning ledger, not a commitment.** Nothing here is scheduled. The `1.x` line is
> the product; this document exists so that format-level feature requests have somewhere
> honest to accumulate instead of pressuring the frozen format. See
> [When 2.0 happens](#when-20-happens) for the trigger conditions.

## Two version numbers, one rule

There are two version tracks, and conflating them causes confusion:

| Track | Today | At the next major |
| --- | --- | --- |
| **NuGet package version** | `1.4.1` | `2.0.0` |
| **`.pqfe` container `FormatVersion`** (byte 5 of every file) | `2` | `3` |

Format **v2 is what every `1.x`-encrypted file on disk carries today** — it is very much "out
there," in users' backups and pipelines, and it stays decryptable. (Format v1 was the `0.x`
preview era and is already unsupported.) The rule that sorts every feature request:

- **Needs new bytes in the container → belongs here (format v3, package `2.0`).**
- **Doesn't → ships as a `1.x` minor.** New `KeySource` values, new packages (Hybrid,
  Signing), new options, and new sidecar formats have all shipped within `1.x` precisely
  because they never changed the frozen v2 layout.

## The v3 feature set (candidates)

### 1. Embedded signatures — the headline

`PostQuantum.FileEncryption.Signing` (shipped `1.3.0`) produces *detached* `.sig` sidecars,
with the standard detached-signature limits recorded in [KNOWN-GAPS.md](../KNOWN-GAPS.md):
the signature is not bound into the container, and a reader who can access the bytes could
strip the sidecar and re-sign them with their own key. A v3 container could carry the
signature **inside**, bound to the authenticated header, so that:

- the decryptor authenticates *who produced the container* as part of decryption, not as a
  separate step with a separate file to lose;
- strip-and-resign requires producing a new container, not just a new sidecar;
- sender identity joins the fail-closed contract (unverifiable signer ⇒ no plaintext).

### 2. Metadata protection

Format v2 reveals plaintext length to within a chunk and protects no file metadata.
Candidates: **length-hiding padding** (configurable buckets) and an **encrypted metadata
block** (original name, timestamp) inside the authenticated envelope.

### 3. SLH-DSA (FIPS 205)

The stateless hash-based signature scheme, for embedded signatures (and the `.sig` sidecar's
`AlgorithmId` space) — the most conservative security assumptions available, for users with
hash-based-or-nothing compliance requirements.

### 4. A second AEAD: ChaCha20-Poly1305

The header already carries an `AeadId` byte (`1` = AES-256-GCM). Registering `2` =
ChaCha20-Poly1305 helps hardware without AES acceleration and buys algorithm agility.
Whether this strictly requires v3 or can ride the existing byte is a decision for design
time; it is listed here so it ships as part of one coherent revision rather than piecemeal.

### 5. Housecleaning a major allows

- **Delete the deprecated inline ML-KEM-only recipient mode** (`PQFE002`): the obsolete
  types, the `KeySource = 2` parse path, and the platform-ML-KEM dependency that comes with
  them. The Hybrid package is the only recipient path.
- Possibly retire the `string` passphrase convenience overloads in favor of zeroable bytes
  only.

## The obligations that come with it

Per [SUPPORT.md](../SUPPORT.md), a `2.0` is not free:

- A **documented v2 → v3 migration path** and tooling — at minimum, `2.x` reads v2
  containers (or ships a converter that decrypts-with-old / re-encrypts-with-new), because
  the files users hold today must not become hostages.
- The final `1.x` minor receives **security fixes for at least 12 months** after `2.0` tags.
- The full evidence chain regenerates: new known-answer vectors, an updated Rust/WASM
  reference implementation (so cross-implementation CI survives the format change), updated
  [FILE-FORMAT.md](FILE-FORMAT.md), [CONFORMANCE.md](CONFORMANCE.md), and threat-model docs.

## When 2.0 happens

Not on a calendar. The trigger is **two or more of the format-level items above having
independent, real demand** — users actually blocked, not features that would be nice. One
item alone can usually be answered within `1.x` ("use the detached sig", "pad before
encrypting", "use Argon2id"); the day those answers stop satisfying people is the day v3
gets designed — as one coherent format revision, with the whole list on the table.

Until then, `1.x` keeps compounding the promise that *is* the product: frozen, verifiable,
fail-closed, and it never broke you.

## What will not change in 2.0

The [non-negotiable principles](../CLAUDE.md): no homegrown cryptography, authenticated
encryption only, fail closed with no oracles, transparency over reassurance, strong defaults.
A new format version changes the bytes, not the posture.

---

*To God be the glory — 1 Corinthians 10:31.*
