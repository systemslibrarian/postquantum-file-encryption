# Supply Chain & Verification

PostQuantum.FileEncryption ships with the kind of supply-chain hygiene you should expect
from cryptographic software: deterministic builds, an SBOM, a build-provenance attestation,
SourceLink, a locked public API, and pre-publish package validation. This document is the
one-page recipe for **how to verify all of it** for a given release.

If anything below doesn't reproduce, that itself is a finding — please open a security
report (see [SECURITY.md](../SECURITY.md)).

## What every release produces

When a tag `vX.Y.Z` is pushed, [`.github/workflows/release.yml`](../.github/workflows/release.yml)
produces and attaches:

| Artifact | What it is | Where to find it |
| --- | --- | --- |
| `PostQuantum.FileEncryption.X.Y.Z.nupkg` | Core library package | nuget.org and GitHub Release |
| `PostQuantum.FileEncryption.X.Y.Z.snupkg` | Core symbols package | nuget.org and GitHub Release |
| `PostQuantum.FileEncryption.Hybrid.X.Y.Z.nupkg` | Hybrid package | nuget.org and GitHub Release |
| `PostQuantum.FileEncryption.Hybrid.X.Y.Z.snupkg` | Hybrid symbols package | nuget.org and GitHub Release |
| `sbom.core.cdx.json` | CycloneDX SBOM for the core | GitHub Release |
| `sbom.hybrid.cdx.json` | CycloneDX SBOM for the Hybrid package | GitHub Release |
| Build-provenance attestation | SLSA-style attestation over every `.nupkg` | GitHub attestations API |

The release workflow also runs `Meziantou.Framework.NuGetPackageValidation.Tool` against
every produced `.nupkg` **before `nuget push`** — deterministic build, SourceLink wired,
README/LICENSE/icon packed, PDBs valid — so malformed packages are caught before they reach
the (effectively immutable) nuget.org index.

## 1. Verify the build-provenance attestation

GitHub's `attest-build-provenance` action produces a SLSA-style attestation signed via OIDC.
You can verify a downloaded `.nupkg` against it without trusting anything but the repository
owner and the GitHub attestation infrastructure.

```bash
# Download the package you want to verify, then:
gh attestation verify PostQuantum.FileEncryption.1.0.0.nupkg \
  --owner systemslibrarian

# The same command works for the Hybrid package and the .snupkg symbol files.
```

A successful run prints the subject digest, the workflow that produced it, the commit SHA,
and the issuer (`https://token.actions.githubusercontent.com`). If the attestation does not
verify, **do not install the package**.

## 2. Inspect the CycloneDX SBOM

Each release attaches per-package CycloneDX SBOMs. They list every transitive dependency,
its version, and its hash.

```bash
# Pull from the release:
gh release download v1.0.0 -p 'sbom.*.cdx.json'

# Glance at the core's direct + transitive components:
jq '.components | map({name, version})' sbom.core.cdx.json

# Spot-check a high-value dependency (e.g., Argon2id):
jq '.components[] | select(.name|test("Argon2";"i"))' sbom.core.cdx.json
```

The SBOMs are produced inside the release job with the CycloneDX `dotnet` tool, against the
same restored graph that produced the `.nupkg`s — so the components in the SBOM are exactly
what shipped.

## 3. Re-run the conformance vectors

The `.pqfe` v2 format is pinned by published [known-answer
vectors](TEST-VECTORS.md) and a [conformance specification](CONFORMANCE.md). The vectors are
exercised by both the .NET and Rust/WASM implementations on every CI run; you can also run
them locally:

```bash
# .NET — decrypts the documented Base64 vectors and asserts the byte-exact plaintext:
dotnet test --filter "FullyQualifiedName~KnownAnswerVector|FullyQualifiedName~CrossImplementation"

# Rust/WASM — decrypts the .NET-produced vectors:
cd samples/pqfe-wasm && cargo test --release --locked
```

The cross-implementation test (`CrossImplementationTests.cs`) decrypts a **Rust-produced**
container with the .NET library, and the Rust suite decrypts the .NET-produced vectors —
so byte-compatibility is verified in both directions on every CI push.

## 4. Verify the build is reproducible

A clean rebuild of the tagged source produces the bit-identical `.dll`, `.pdb`, and `.xml`
inside the published `.nupkg` (modulo the nuget.org-applied repo signature). The full recipe,
the verification script, and the CI job that runs it on every release tag are in
[REPRODUCIBLE-BUILDS.md](REPRODUCIBLE-BUILDS.md):

```bash
.github/scripts/verify-reproducibility.sh v1.0.0 PostQuantum.FileEncryption
.github/scripts/verify-reproducibility.sh v1.0.0 PostQuantum.FileEncryption.Hybrid
```

A failing run is a finding worth a private security report — see
[SECURITY.md](../SECURITY.md).

## 5. Spot-check SourceLink + deterministic build

The package validation step in the release workflow already enforces this, but you can
double-check by hand:

```bash
# Print the source revision and the deterministic flag baked into the assembly:
dotnet nuget locals all --list   # find your global package cache
# Then in the extracted package:
strings -n 8 lib/net10.0/PostQuantum.FileEncryption.dll | grep -i sourcelink
# or use the package-validation tool directly:
dotnet tool install --global Meziantou.Framework.NuGetPackageValidation.Tool
meziantou.validate-nuget-package PostQuantum.FileEncryption.1.0.0.nupkg --excluded-rules Symbols
```

A green result means the package is deterministic, SourceLink-wired, includes the README,
LICENSE, and icon, has valid PDBs (or a `.snupkg` symbols package alongside), and meets the
other rules `meziantou.validate-nuget-package` enforces.

## 6. Confirm the public API surface

Both packages publish a baselined `PublicAPI.Shipped.txt` for every shipped member
(`Microsoft.CodeAnalysis.PublicApiAnalyzers`). The build fails if a new or removed member is
not declared in `PublicAPI.Unshipped.txt`. To see the full surface of a release:

```bash
# In the source tree at the release tag:
cat src/PostQuantum.FileEncryption/PublicAPI.Shipped.txt
cat src/PostQuantum.FileEncryption.Hybrid/PublicAPI.Shipped.txt
```

`<EnablePackageValidation>` is on with `PackageValidationBaselineVersion` set to the
previous release, so every pack additionally proves binary compatibility at build time.

## Continuous assurance

These checks run automatically on every push (not just on release tags):

| Job | Workflow | What it catches |
| --- | --- | --- |
| .NET build & test (Ubuntu / Windows / macOS) | `ci.yml` | OS-specific regressions, broken tests |
| Long-running tests (Linux only) | `ci.yml` | Big-payload coverage (16 MiB chunks, etc.) |
| AOT publish + round-trip smoke test | `ci.yml` | `IsAotCompatible=true` regressions |
| Rust/WASM test & build | `ci.yml` | Format byte-compatibility (both directions) |
| Rust dependency audit (`cargo audit`) | `ci.yml` | Known vulnerabilities in the WASM core's deps |
| CodeQL analysis | `codeql.yml` | Static-analysis findings on .NET sources |
| Dependency review (PRs) | `dependency-review.yml` | New vulnerable transitive deps |
| Coverage-guided fuzzing (cargo-fuzz + SharpFuzz) | `fuzz.yml` | Parser crashes; nightly with cached corpus |
| OpenSSF Scorecard | `scorecard.yml` | Supply-chain hygiene; SARIF in Security tab |

The Scorecard SARIF is uploaded to the repo's Security tab on every push to `main`, and the
public Scorecard dashboard (linked from the README badge) shows the score history.

---

## Verification cheat sheet (copy-paste)

```bash
# Required CLI tools:
# - gh        (GitHub CLI, for downloads + attestation verify)
# - jq        (SBOM inspection)
# - dotnet    (test run + package validation)

# 1. Pull artifacts:
gh release download v1.0.0

# 2. Verify build provenance on every .nupkg:
for nupkg in PostQuantum.FileEncryption*.nupkg; do
  gh attestation verify "$nupkg" --owner systemslibrarian
done

# 3. Inspect SBOMs:
jq '.components | length' sbom.core.cdx.json
jq '.components | length' sbom.hybrid.cdx.json

# 4. Conformance vectors round-trip locally:
git clone https://github.com/systemslibrarian/postquantum-file-encryption
cd postquantum-file-encryption
dotnet test --filter "FullyQualifiedName~KnownAnswerVector|FullyQualifiedName~CrossImplementation"
```

If any step fails, **do not install the package** — open an issue or a private security
advisory.

---

*To God be the glory — 1 Corinthians 10:31.*
