# Version reconciliation — PostQuantum.FileEncryption suite

**Confirmed at:** 2026-06-01 (rc.2 cut)
**Target version (both packages):** `1.0.0-rc.2`

> rc.1 of both packages is already live and immutable on nuget.org (verified via
> `https://api.nuget.org/v3-flatcontainer/{package}/index.json`). rc.2 supersedes rc.1
> and carries the deprecation of the inline ML-KEM-only recipient mode plus added
> I/O failure-mode test coverage. No format, public-API, or runtime-dependency change.

## State of this repo at reconciliation

| Package | File | Declared `<Version>` | Action |
| --- | --- | --- | --- |
| `PostQuantum.FileEncryption` | `src/PostQuantum.FileEncryption/PostQuantum.FileEncryption.csproj` | `1.0.0-rc.2` | bumped from rc.1 |
| `PostQuantum.FileEncryption.Hybrid` | `src/PostQuantum.FileEncryption.Hybrid/PostQuantum.FileEncryption.Hybrid.csproj` | `1.0.0-rc.2` | bumped from rc.1 |

`Directory.Build.props` does not centralize `<Version>`; each project owns its own.
`PackageValidationBaselineVersion` is bumped from `0.2.0` to `1.0.0-rc.1` so rc.2's
public surface is validated against the published rc.1 baseline.

## Dependency constraints

### `PostQuantum.FileEncryption` (core)
Runtime dependencies:
- `Konscious.Security.Cryptography.Argon2 1.3.1`

No reference to `PostQuantum.Cryptography` (or any other `PostQuantum.*` package).
**Invariant holds** — core is independent of the Foundation, so it is not gated by
Foundation maturity.

### `PostQuantum.FileEncryption.Hybrid`
Runtime dependencies:
- `BouncyCastle.Cryptography 2.5.1` (provides *both* X25519 *and* ML-KEM-768)
- `ProjectReference` to `PostQuantum.FileEncryption` (monorepo; resolves to the pinned
  `1.0.0-rc.1` core when packed)

**Divergence flagged, not changed (confirmed correct by suite owner).** The suite-level
instruction expected Hybrid to pin `PostQuantum.Cryptography = 1.0.0-rc.1` for the X-Wing
combiner. This repo does not have that dependency: the combiner is implemented against
BouncyCastle directly (see the package `<Description>` and
`src/PostQuantum.FileEncryption.Hybrid/README.md`), and the `0.2.0` release shipped with
that architecture. The runbook expectation was incorrect for this package; this repo's
actual `.csproj` is authoritative. **No `PostQuantum.Cryptography` pin to add.**

## Invariant check

`Hybrid (1.0.0-rc.2) ≤ FileEncryption (1.0.0-rc.2)` — **holds (equal, lockstep enforced).**

`Hybrid (1.0.0-rc.2) ≤ Cryptography (?)` — **not applicable in this repo**; Hybrid does
not depend on `PostQuantum.Cryptography` (confirmed three times now; BouncyCastle stays).

## Edits made in this pass (rc.2 cut)

- Both `.csproj` files: `<Version>` 1.0.0-rc.1 → 1.0.0-rc.2; added `<FileVersion>` and
  `<InformationalVersion>`; `<PackageReleaseNotes>` updated.
- `Directory.Build.props`: `<PackageValidationBaselineVersion>` 0.2.0 → 1.0.0-rc.1.
- `README.md` (root): status line and both install snippets bumped to 1.0.0-rc.2;
  deprecation messaging updated for the inline ML-KEM-only recipient mode (`PQFE002`).
- `src/PostQuantum.FileEncryption.Hybrid/README.md`: install line bumped to 1.0.0-rc.2;
  rewritten as the single recommended public-key path with a migration note from the
  deprecated inline mode and a lockstep-versioning note pointing at `docs/VERSIONING.md`.
- `docs/VERSIONING.md`: new "Suite versioning — Hybrid lockstep with core" subsection.
- `KNOWN-GAPS.md`: best-effort temp-file cleanup caveat added (honest disclosure, not a
  functional gap — destination integrity is preserved).
- `CHANGELOG.md`: `[1.0.0-rc.2]` entry added with Deprecated/Added/Changed/Notes
  sections; compare links updated.
- Source: `[Obsolete(DiagnosticId="PQFE002")]` on four public types in `PqKeyPair.cs`
  and four recipient overloads across `PqFileEncryptor.cs` / `PqFileDecryptor.cs`.
- `csproj` `NoWarn` additions for PQFE002 in the library and tests projects.
- New test file `tests/PostQuantum.FileEncryption.Tests/AtomicWriteIoFailureTests.cs`
  with eight tests pinning the file-API atomic-write contract under I/O failure modes.
- `RoundTripTests.cs`: added `Truncation_at_specific_offsets_is_rejected` theory and
  `Round_trip_at_maximum_chunk_size` (`LongRunning` trait).
- `.github/workflows/ci.yml`: split into a fast lane (`Category!=LongRunning`, all OSes)
  and a Linux-only LongRunning lane.
- `.github/workflows/release.yml`: hardened publish flow — push core first, poll the v3
  flat-container index until the new core version is queryable, then push Hybrid.

## Pending cleanup (do not act on in this pass)

The core (`PostQuantum.FileEncryption`) still carries the inline ML-KEM-only recipient
mode — `PqKeyPair`, `PqRecipientPublicKey`, `PqRecipientPrivateKey`, the
`PqFileEncryptor`/`PqFileDecryptor` recipient overloads, all annotated
`[Experimental("PQFE001")]` and platform-gated by `PqKeyPair.IsSupported`. This path is
**superseded by the Hybrid package** (X25519 + ML-KEM-768 combiner + multi-recipient,
fully managed, no platform gate). A separate deprecation pass adds `[Obsolete]` with
diagnostic id `PQFE002` and updates README / KNOWN-GAPS.md / ROADMAP.md /
docs/ROADMAP-v3.md / CHANGELOG.md; removal of the inline mode is targeted for a future
major release.

*To God be the glory — 1 Corinthians 10:31.*
