#!/usr/bin/env bash
# Verify that the .nupkg published on nuget.org for a given tag and package matches a
# clean rebuild from the same tag's source. See docs/REPRODUCIBLE-BUILDS.md.
#
# Usage: verify-reproducibility.sh <tag> <package-id>
# Example: verify-reproducibility.sh v1.0.1 PostQuantum.FileEncryption
#
# Exit codes:
#   0 — published .nupkg matches the local rebuild (modulo nuget.org repo signature).
#   2 — usage / setup error.
#   3 — content mismatch.

set -euo pipefail

TAG="${1:-}"
PKG="${2:-}"

if [[ -z "$TAG" || -z "$PKG" ]]; then
  echo "usage: $0 <tag> <package-id>" >&2
  exit 2
fi

VERSION="${TAG#v}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Verifying reproducibility for $PKG $VERSION (tag $TAG)"

PUBLISHED="$WORK/published.nupkg"
PUBLISHED_DIR="$WORK/published"
LOCAL_DIR="$WORK/local"
LOCAL_OUT="$WORK/local-pack"

echo "==> Downloading published .nupkg from nuget.org"
curl -fSL "https://www.nuget.org/api/v2/package/${PKG}/${VERSION}" -o "$PUBLISHED"

echo "==> Cloning source at $TAG"
git clone --branch "$TAG" --depth 1 \
  https://github.com/systemslibrarian/postquantum-file-encryption "$WORK/src"

case "$PKG" in
  PostQuantum.FileEncryption)
    CSPROJ="$WORK/src/src/PostQuantum.FileEncryption/PostQuantum.FileEncryption.csproj" ;;
  PostQuantum.FileEncryption.Hybrid)
    CSPROJ="$WORK/src/src/PostQuantum.FileEncryption.Hybrid/PostQuantum.FileEncryption.Hybrid.csproj" ;;
  *) echo "unknown package id: $PKG" >&2; exit 2 ;;
esac

echo "==> Building $PKG from source"
CI=true dotnet pack "$CSPROJ" -c Release -o "$LOCAL_OUT"

LOCAL_NUPKG="$LOCAL_OUT/${PKG}.${VERSION}.nupkg"
if [[ ! -f "$LOCAL_NUPKG" ]]; then
  echo "expected local nupkg not produced: $LOCAL_NUPKG" >&2
  ls -la "$LOCAL_OUT" >&2
  exit 2
fi

echo "==> Unpacking both .nupkgs"
mkdir -p "$PUBLISHED_DIR" "$LOCAL_DIR"
unzip -q "$PUBLISHED" -d "$PUBLISHED_DIR"
unzip -q "$LOCAL_NUPKG" -d "$LOCAL_DIR"

echo "==> Removing nuget.org repo signature from published copy"
rm -f "$PUBLISHED_DIR/.signature.p7s"
rm -f "$LOCAL_DIR/.signature.p7s"

echo "==> Diffing the two trees (excluding pack-time-only metadata)"
# .psmdcp files (NuGet core-properties) carry a fresh GUID in their filename per pack and
# are never reproducible by NuGet's design — exclude them, not the bytes we actually ship.
if diff -r --exclude='*.psmdcp' "$PUBLISHED_DIR" "$LOCAL_DIR" > "$WORK/diff.txt"; then
  echo "==> MATCH — $PKG $VERSION is reproducible from $TAG."
  exit 0
fi

echo "==> MISMATCH — see diff below" >&2
cat "$WORK/diff.txt" >&2
exit 3
