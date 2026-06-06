# Reproducible Builds

Reproducibility lets a third party — auditor, security team, paranoid downstream — start from
the public source at a release tag, rebuild it on their own machine, and verify that the
result matches the `.nupkg` published to nuget.org. It is the trust spine that ties the
[SBOM](SUPPLY-CHAIN.md#2-inspect-the-cyclonedx-sbom) and the
[build-provenance attestation](SUPPLY-CHAIN.md#1-verify-the-build-provenance-attestation) to
real source code.

This document is the recipe.

## What "reproducible" claims here

A clean rebuild of a tagged release produces:

- **Bit-identical .NET assemblies** (`PostQuantum.FileEncryption.dll`,
  `PostQuantum.FileEncryption.Hybrid.dll`) — same SHA-256 as the assemblies inside the
  corresponding `.nupkg` on nuget.org.
- **Bit-identical portable PDBs**.
- **Bit-identical XML documentation files**.

The `.nupkg` *envelope* (the outer ZIP) is also expected to match, with one exception:
**packages downloaded from nuget.org carry a `.signature.p7s` file** that nuget.org adds at
upload time. The verification script below normalises that away before comparing.

## Why this is true

The project pins every known source of non-determinism:

| Setting | Where | Why it matters |
| --- | --- | --- |
| `<Deterministic>true</Deterministic>` | `Directory.Build.props` | Derives the assembly MVID and timestamps from the source, not the clock. |
| `<ContinuousIntegrationBuild>` (set in CI) | `Directory.Build.props` | Normalises embedded paths and SourceLink URLs to the repo, not the build host. |
| `<EmbedUntrackedSources>true</EmbedUntrackedSources>` | `*.csproj` | Embeds every source the compiler saw, so SourceLink + symbols round-trip. |
| `.gitattributes` with `* text=auto eol=lf` | repo root | Forces LF line endings on every checkout. Roslyn hashes source files and embeds those hashes in the PDB; without `.gitattributes`, a Windows checkout with default `core.autocrlf=true` would store CRLF locally, change the source hash, and produce a different `.dll` than the Linux-built `.nupkg`. |
| Git checkout at a tag | the release recipe | The compiler sees the exact same source bytes. |
| `dotnet pack -c Release` | the release recipe | Identical pack options on every host. |
| Floor-pinned tool versions | `actions/setup-dotnet@…` SHA + `dotnet-version: '10.0.x'` | The same compiler builds the same output. |

What does **not** affect reproducibility (with the above in place):

- The operating system of the *verifier*. With `.gitattributes` normalising source line
  endings on checkout, the source the compiler sees is byte-identical on Linux, macOS, and
  Windows, and `Deterministic=true` then produces byte-identical assemblies.
- Local NuGet caches. The compiler reads from `obj/`, which is regenerated from the same
  inputs.

What **does** matter:

- The verifier must check the repo out at the release tag *after* `.gitattributes` was
  added. Earlier tags (e.g. `v1.0.0`) predate `.gitattributes` and were packed on Windows
  during a release-key recovery — see the [1.0.1 CHANGELOG entry](../CHANGELOG.md#101---2026-06-06)
  for the full history. The reproducibility guarantee in this document applies from
  `v1.0.1` forward.

## Manual recipe

Verifying one release end-to-end:

```bash
# 1. Pull a published version from nuget.org.
NUPKG_DIR=$(mktemp -d)
dotnet nuget locals temp -c >/dev/null
curl -L "https://www.nuget.org/api/v2/package/PostQuantum.FileEncryption/1.0.1" \
  -o "$NUPKG_DIR/published.nupkg"

# 2. Rebuild from source at the same tag.
git clone --branch v1.0.1 --depth 1 \
  https://github.com/systemslibrarian/postquantum-file-encryption /tmp/pqfe-repro
cd /tmp/pqfe-repro
CI=true dotnet pack src/PostQuantum.FileEncryption/PostQuantum.FileEncryption.csproj \
  -c Release -o "$NUPKG_DIR/local"

# 3. Compare the .dll, .pdb, and .xml inside both .nupkgs.
unzip -p "$NUPKG_DIR/published.nupkg" 'lib/net10.0/PostQuantum.FileEncryption.dll' \
  | sha256sum
unzip -p "$NUPKG_DIR/local/PostQuantum.FileEncryption.1.0.1.nupkg" \
  'lib/net10.0/PostQuantum.FileEncryption.dll' | sha256sum

# The two sums must match. Repeat for .pdb and .xml. Repeat for the Hybrid package.
```

A green run means the published binary on nuget.org was built from the source you can read.

## Verify the full envelope

To compare the entire `.nupkg` byte-for-byte (modulo the nuget.org repo signature), use the
verification script that the CI job runs:

```bash
.github/scripts/verify-reproducibility.sh v1.0.1 PostQuantum.FileEncryption
.github/scripts/verify-reproducibility.sh v1.0.1 PostQuantum.FileEncryption.Hybrid
```

The script:

1. Downloads the published `.nupkg` from nuget.org.
2. Rebuilds the package from the tag in a clean working tree.
3. Strips `.signature.p7s` from the published `.nupkg` (nuget.org-applied repo signature) and
   any equivalent author-signature artefact from the local rebuild.
4. Diffs the two trees recursively and exits non-zero on any mismatch.

## Continuous verification in CI

[`.github/workflows/reproducibility.yml`](../.github/workflows/reproducibility.yml) runs the
script automatically after every release tag is published — independently of the release
workflow that produced the artefact — so any divergence between "the source at the tag" and
"the binary on nuget.org" surfaces as a failing build within minutes of publication.

It also runs on `workflow_dispatch` against any historical tag, so you can re-verify older
releases at any time.

## What to do if it fails

A failure means **the public source no longer produces the published binary**. Possible
causes, in rough order of likelihood:

1. The build environment drifted (a different SDK version was used at release time than the
   workflow now pins).
2. A non-deterministic input crept into a project file (an unguarded `[AssemblyVersion]`, a
   timestamped constant, a tool that writes the build host into the assembly).
3. The published artefact was replaced. **This is a supply-chain incident** — open a private
   security advisory immediately (see [SECURITY.md](../SECURITY.md)).

The CI job's output records the SDK version, the tag SHA, and the diff between the two
package trees, so triage starts with a concrete artefact rather than guesswork.

---

*To God be the glory — 1 Corinthians 10:31.*
