#!/usr/bin/env bash
# Continuous documentation-consistency guard.
#
# The release workflow already fails a *tag* if the README status line or an install snippet
# lags the version being published. That check only runs at release time, so drift can still
# accumulate on main between releases — which is exactly how the SECURITY.md supported-versions
# cell, the "Last reviewed against" markers, and the supply-chain artifact examples went stale
# across the 1.6.0–1.7.1 releases. This script runs on every push and pull request (see
# .github/workflows/docs-consistency.yml) and enforces:
#
#   1. Current-version markers match the core package <Version>:
#        * the root README **Status:** line,
#        * the ROADMAP "## Now — `X`" heading,
#        * every "Last reviewed against: **`X`**" marker in any tracked Markdown file,
#        * the SECURITY.md supported-versions cell ("current: `X`"),
#        * the ROADMAP-2.0 "NuGet package version → Today" cell,
#        * the AUDIT-SCOPE pinned release tag.
#   2. Worked artifact examples name the current version (outside CHANGELOG.md):
#        * `PostQuantum.FileEncryption[.<Pkg>].X.Y.Z.nupkg` artifact names,
#        * `gh release download vX.Y.Z`,
#        * `verify-reproducibility.sh vX.Y.Z`,
#        * `--branch vX.Y.Z` clone examples and nuget.org `/package/<id>/X.Y.Z` URLs,
#        * `dotnet add package … --version X.Y.Z` install snippets in every Markdown file.
#   3. Every relative Markdown link resolves to a file that exists — no dead internal links.
#
# Historical version mentions (CHANGELOG entries, "shipped 1.3.0" prose, the compare-link
# footer) are deliberately NOT matched: they are facts about earlier releases, not the current
# version. See CLAUDE.md, "When you bump the package version".
#
# Portability: uses only POSIX grep -E / sed / perl (for link extraction) — no GNU-only
# `grep -P` — so it runs on macOS (BSD userland) as well as Linux CI.
#
# Run locally:  bash scripts/check-docs-consistency.sh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

core_csproj="src/PostQuantum.FileEncryption/PostQuantum.FileEncryption.csproj"
version="$(sed -n 's/.*<Version>\([^<]*\)<\/Version>.*/\1/p' "$core_csproj" | head -n1)"
if [ -z "${version:-}" ]; then
  echo "::error file=$core_csproj::could not read <Version>" >&2
  exit 1
fi
# Regex-escaped version for use inside grep -E patterns.
ver_re="$(printf '%s' "$version" | sed 's/\./\\./g')"
echo "Canonical package version: $version"

# fail flag lives in a file so it survives the subshells created by `... | while`.
fail_marker="$(mktemp)"
trap 'rm -f "$fail_marker"' EXIT
mark_fail() { printf 'x' >> "$fail_marker"; }

# ------------------------------------------------------------------ 1. version markers

if ! grep -Eq "Status:[[:space:]]*\`${ver_re}\`" README.md; then
  echo "::error file=README.md::the **Status:** line does not name the current version \`${version}\`" >&2
  mark_fail
fi
if ! grep -Eq "^## Now — \`${ver_re}\`" ROADMAP.md; then
  echo "::error file=ROADMAP.md::the \"## Now —\" heading does not name the current version \`${version}\`" >&2
  mark_fail
fi
if ! grep -Eq "current: \`${ver_re}\`" SECURITY.md; then
  echo "::error file=SECURITY.md::the supported-versions cell does not say current: \`${version}\`" >&2
  mark_fail
fi
if ! grep -Eq "\*\*NuGet package version\*\* \| \`${ver_re}\`" docs/ROADMAP-2.0.md; then
  echo "::error file=docs/ROADMAP-2.0.md::the \"NuGet package version → Today\" cell does not say \`${version}\`" >&2
  mark_fail
fi
if ! grep -Eq "latest release tag — \*\*\`v${ver_re}\`\*\*" docs/AUDIT-SCOPE.md; then
  echo "::error file=docs/AUDIT-SCOPE.md::the pinned audit revision does not name \`v${version}\`" >&2
  mark_fail
fi

# Generic: every "Last reviewed against: **`X`**" marker in any Markdown file must equal it.
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  f="${hit%%:*}"
  found="$(printf '%s\n' "$hit" | sed -n 's/.*Last reviewed against: \*\*`\([^`]*\)`.*/\1/p')"
  if [ "$found" != "$version" ]; then
    echo "::error file=$f::stale marker 'Last reviewed against \`$found\`'; the current version is \`$version\`" >&2
    mark_fail
  fi
done < <(git grep -nE 'Last reviewed against: \*\*`[^`]+`\*\*' -- '*.md' || true)

# ------------------------------------------------------------------ 2. artifact examples

# Each entry: <pattern-that-finds-a-versioned-example> <pattern-it-must-also-match>
check_examples() {
  local find_re="$1" want_re="$2" what="$3"
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    local f="${hit%%:*}" rest="${hit#*:}" line="${hit#*:}"
    line="${rest%%:*}"
    if ! printf '%s\n' "$hit" | grep -Eq "$want_re"; then
      echo "::error file=$f,line=$line::stale $what (expected version \`$version\`): ${hit#*:*:}" >&2
      mark_fail
    fi
  done < <(git grep -nE -e "$find_re" -- '*.md' ':!CHANGELOG.md' || true)
}

check_examples 'PostQuantum\.FileEncryption[A-Za-z.]*\.[0-9]+\.[0-9]+\.[0-9]+\.s?nupkg' \
               "\.${ver_re}\.s?nupkg" 'package artifact name'
check_examples 'gh release download v[0-9]+\.[0-9]+\.[0-9]+' \
               "gh release download v${ver_re}" 'release download example'
check_examples 'verify-reproducibility\.sh v[0-9]+\.[0-9]+\.[0-9]+' \
               "verify-reproducibility\.sh v${ver_re}" 'reproducibility example'
check_examples '--branch v[0-9]+\.[0-9]+\.[0-9]+' \
               "[-][-]branch v${ver_re}" 'clone-at-tag example'
check_examples '/package/PostQuantum\.FileEncryption/[0-9]+\.[0-9]+\.[0-9]+' \
               "/package/PostQuantum\.FileEncryption/${ver_re}" 'nuget.org package URL'
check_examples '--version [0-9]+\.[0-9]+\.[0-9]+' \
               "[-][-]version ${ver_re}" 'install snippet'

# ------------------------------------------------------------------ 3. dead internal links

while IFS= read -r mdfile; do
  dir="$(dirname "$mdfile")"
  while IFS= read -r m; do
    [ -z "$m" ] && continue
    lineno="${m%%:*}"
    target="${m#*:}"
    case "$target" in
      http://*|https://*|mailto:*|tel:*|\#*) continue ;;  # external or same-page anchor
    esac
    path="${target%%#*}"   # drop #fragment
    path="${path%%\?*}"    # drop ?query
    [ -z "$path" ] && continue
    if [ ! -e "$dir/$path" ]; then
      echo "::error file=$mdfile,line=$lineno::dead internal link '$target' (no file at '$dir/$path')" >&2
      mark_fail
    fi
  done < <(perl -ne 'while (/\]\(\s*<?([^)\s>]+)>?(?:\s[^)]*)?\)/g) { my $t = $1; $t =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge; print "$.:$t\n" }' "$mdfile" 2>/dev/null || true)
done < <(git ls-files '*.md')

# ------------------------------------------------------------------ verdict

if [ -s "$fail_marker" ]; then
  echo "Documentation consistency check FAILED — see the annotations above." >&2
  exit 1
fi
echo "Documentation consistency check passed."
